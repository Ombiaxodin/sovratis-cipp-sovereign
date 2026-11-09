# Sovratis Phase 1 infrastructure runbook

Script: [infra-sovratis/Deploy-SovratisInfrastructure.ps1](../infra-sovratis/Deploy-SovratisInfrastructure.ps1)
Audience: the engineer/operator provisioning the target environment, plus the HSM key custodians.

**Status of the script:** parse-checked only. It has not been run against any Azure tenant (no Azure CLI in the authoring environment). Treat the first run as the verification run, start with `-WhatIf`, and expect to fix az parameter names marked **[?]**.

## 1. What gets built

```
                    +-----------------------------+
 Function App MI -->| Managed HSM  <prefix>-hsm   |  Local RBAC, per key:
   (system)         |   sov-kek          (RSA-HSM)|  Function App -> Crypto Service Encryption User (/keys/sov-kek)
                    |   sov-storage-cmk  (RSA-HSM)|  Storage UAMI -> Crypto Service Encryption User (/keys/sov-storage-cmk)
                    +-----------------------------+
 Function App MI -->| Key Vault  <prefix>-rdk     |  Function App -> Key Vault Secrets User (READ ONLY)
                    |   secret sovratis-rdk-v1    |  Operator/pipeline -> Secrets Officer (temporary)
                    +-----------------------------+
 Function App ----->| Storage  <prefix>st         |  Table/queue: account-scoped key, wrapped by sov-storage-cmk
                    +-----------------------------+
```

Two independent keys protect two layers (the "double key"): `sov-kek` guards the application-layer root key; `sov-storage-cmk` guards storage-layer encryption. The Function App can use only `sov-kek`, and can only read the RDK vault, so it cannot create or replace root keys.

## 2. Before you start

| Item | Detail |
|---|---|
| Azure CLI | 2.60 or newer, `az login` done. For a sovereign cloud run `az cloud set --name <cloud>` first. |
| Function App | Exists, **system-assigned identity enabled** (`az functionapp identity assign`). |
| Operator rights | Owner or (Contributor + User Access Administrator) on the resource group; permission to read Entra object IDs. |
| HSM administrators | 1+ Entra object IDs (use a group-backed break-glass principal). Set at creation. |
| Custodians | **3 or more** people, each generating an RSA key pair and a certificate (`.cer`) on their own machine. Private keys never leave them. Quorum 2 [?: confirm documented minimums]. |
| Cost | A Managed HSM bills hourly from creation. Do not create "to try" and forget it. |

**Open question to settle first:** the code pins `*.managedhsm.azure.net` and `*.vault.azure.net`. The script prints the cloud's actual DNS suffixes in step 0. If the DELOS cloud uses different suffixes, stop: the provider and store need a configurable suffix (small code change) before anything works.

## 3. Procedure

1. **Dry run.**
   ```powershell
   ./infra-sovratis/Deploy-SovratisInfrastructure.ps1 -SubscriptionId <id> -ResourceGroup rg-sov-prod -Location <region> `
       -NamePrefix sovprod -FunctionAppName <fa> -HsmAdministratorObjectIds <oid> -WhatIf
   ```
2. **Create everything up to activation** (same command without `-WhatIf`). It creates the resource group, the storage identity and the HSM, then stops with exit code 2 because the HSM is not activated yet. HSM provisioning can take 20+ minutes; re-run until it reports activation is needed.
3. **Activation ceremony (Security Domain).** With all custodians present:
   ```powershell
   ./infra-sovratis/Deploy-SovratisInfrastructure.ps1 <same parameters> -ActivateHsm `
       -SecurityDomainCertificates c1.cer,c2.cer,c3.cer -SecurityDomainQuorum 2
   ```
   The script writes `sovratis-hsm-security-domain.json`. **Move it off the machine immediately** and store it separately from the custodians' private keys. The file plus a quorum of private keys is the only recovery path. Without them, losing the HSM means losing every key, and so all encrypted data.
4. **Run to completion** (the same command, again). Idempotent: it creates the two keys, the HSM role assignments, the RDK vault and its read-only role, then the storage account (account-scoped table key) and enables CMK.
5. **Apply app settings** by adding `-ConfigureFunctionAppSettings` (restarts the app), or set them by hand:
   `SOVRATIS_ENC_PROVIDER=AzureManagedHsm`, `SOVRATIS_KEK_REF=https://<hsm>.managedhsm.azure.net/keys/sov-kek`, `SOVRATIS_RDK_VAULT=<prefix>-rdk`, `SOVRATIS_ENC_MODE=Enforce`.
6. **Point `AzureWebJobsStorage` at the new storage account** (manual, deliberately not scripted: it re-targets the entire app). Greenfield only; no data migration.
7. **Provision the first Root Data Key** with an operator identity (never the Function App): add `-ProvisionRootKey`. It grants you temporary wrap and secret-write rights, generates the key, wraps it in the HSM and stores `sovratis-rdk-v1` in the RDK vault. Then revoke: `-RevokeOperatorGrants`.
8. **Verification** runs at the end of every run and prints PASS/FAIL for: HSM purge protection; both keys RSA-HSM with wrap/unwrap only; app can unwrap with `sov-kek`; RDK vault purge protection + RBAC; app is read-only on the vault and holds no write role; storage uses CMK, table key type `Account`, HTTPS-only, TLS 1.2.

## 4. Live integration test (the point of this runbook)

Run from the deployed Function App (managed identity), in this order. Each confirms an item the code marks **[?]**:

| # | Check | Confirms |
|---|---|---|
| 1 | `Invoke-SovratisEncryption -Operation Health` returns `Healthy = True`, `RootKeyProvisioned = True` | HSM **token audience** `https://managedhsm.azure.net` and **api-version 7.4** (key GET + unwrap), Key Vault read via MI |
| 2 | Encrypt then Decrypt a probe with `Context @{TenantId=...; Purpose=...}` | wrap/unwrap path, root key cache |
| 3 | Write and read a `CippReportingDB` row and an `ApiClients` row via the normal wrappers; inspect the raw table (Storage Explorer) | `sov1.` envelopes at rest, plaintext in the API |
| 4 | From the Function App identity attempt to write a secret in the RDK vault | must be **denied** |
| 5 | Edit `ApiClients.Role` directly in the table, then load the client | row must be **dropped** (denied), error names the row, no value |
| 6 | Rotate: create a new `sov-kek` key version | old RDK still unwraps (blob is pinned to its version); new RDK needs `Initialize-SovratisRootKey` |
| 7 | Confirm the storage account's table encryption shows customer-managed key from `sov-storage-cmk` | CMK + account-scoped key on Tables |

If 1 fails with HTTP 401/403 the audience or the role scope is wrong; with 400/404 suspect the api-version or key URL. The provider reports only the HTTP status, never bodies.

## 5. Operational notes

* **Crypto-shredding.** Deleting a tenant's salt row (`TenantProperties`, RowKey `EncSalt`) makes that tenant's encrypted data unreadable. Tenant keys use the partition key as written, so **both the GUID and the domain-name partition keys** for a tenant must have their salts purged. Deliberate, logged, two-step; never automatic.
* **Root key rotation.** `Initialize-SovratisRootKey` (no `-Id`) creates the next version; new writes use it, old versions stay readable.
* **Phase 2 external HSM.** Add the second wrap to the root-key blob and `SOVRATIS_ENC_EXTRA_WRAPS`; no data re-encryption.
* **Do not** grant the Function App `Managed HSM Crypto User`/`Officer`, any RDK-vault write role, or Contributor on either resource. Step 10 fails if it holds one on the vault.
* **Network.** Both resources default to public access (`-PublicNetworkAccess`); production should move them behind private endpoints and set `Disabled`. Private endpoints and DNS are not created by this script.
* **Teardown.** HSM and vault have purge protection. Deleting them only soft-deletes for the retention period (90 days) and the name stays reserved. Never delete the HSM without a decision on the data it protects.

## 6. Unverified items (confirm on the first run)

1. Managed HSM token audience and data-plane api-version used by the provider.
2. Security Domain minimum custodians and quorum.
3. Whether the administrator role alone can create keys (the script grants the operator Crypto Officer to be safe).
4. az parameter names for the account-scoped table/queue key type at storage account creation.
5. Storage CMK pointed at a Managed HSM key URI, and following the latest key version automatically.
6. DNS suffixes of the target (DELOS) cloud versus the pinned Azure suffixes.
7. Managed HSM pricing and any regional availability limits.
