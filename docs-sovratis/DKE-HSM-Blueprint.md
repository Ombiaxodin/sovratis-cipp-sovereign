# Sovratis Phase 1.2 — Double Key Encryption (DKE) & HSM Blueprint

Status: **design for review, no code merged.** Authors' roles: Sovereign Security & Crypto Auditor + Lead Cloud Architect.
Scope: application-layer encryption of sensitive data **before** it is written to Azure Table Storage, behind one abstraction, `Invoke-SovratisEncryption`, with Azure Managed HSM in Phase 1 and a strict external HSM in Phase 2.

Legend: **[V]** verified against Microsoft documentation (sources at the end) · **[R]** verified in this repository · **[?]** not verified, check before relying on it.

---

## 1. Decisions needed before implementation

| # | Decision | Recommendation |
|---|---|---|
| D1 | What does "double key" mean? | **Two independent keys, neither sufficient alone.** Phase 1: (a) application-layer key hierarchy rooted in a Managed HSM key, plus (b) Azure Storage encryption with a *separate* customer-managed key. Phase 2: replace (b) by, or add to it, a second wrap of the same root key under the external HSM (nested wrap, §6). |
| D2 | Managed HSM or Key Vault Premium for Phase 1? | **Managed HSM** (single-tenant, FIPS 140-2 Level 3 [V]). Key Vault Premium is a config-only fallback (§5) when cost is blocking. |
| D3 | Storage account | Table/Queue CMK needs an account created with an **account-scoped encryption key; this cannot be changed afterwards** [V]. The existing `AzureWebJobsStorage` account almost certainly lacks it → plan a **new account + data migration** for tables. |
| D4 | What gets encrypted | Tiered, per-column, by policy file (§7). Needs a data-classification pass first (§10, T0). |
| D5 | Key granularity | Per-(tenant, purpose) DEKs derived from one HSM-wrapped root key (§4). |
| D6 | Migration style | Dual-read (plaintext tolerated) → backfill → strict mode (§8). |
| D7 | Crypto-shredding on tenant removal | Opt-in, irreversible, two-step (§4.4). |

---

## 2. What the repository tells us (auditor's baseline)

* **[R] Key Vault is reached with the Function App's managed identity, not an App Registration.** `Get-CIPPAzIdentityToken` calls `IDENTITY_ENDPOINT` and `Get-CippKeyVaultSecret` uses the Key Vault REST API (api-version 7.4). The SAM App Registration is for Graph only.
  → **No App Registration permissions are required for the HSM path.** Do not add Key Vault API permissions to the SAM app.
* **[R] Table access has two choke points and a bypass.** Wrappers: `Add-CIPPAzDataTableEntity` (≈305 files) / `Get-CIPPAzDataTableEntity` (≈584 files) / `Remove-CIPPAzDataTableEntity` (≈147). Bypass: raw AzBobbyTables cmdlets — `Add-AzDataTableEntity` (21 files), `Update-AzDataTableEntity` (21), `Get-AzDataTableEntity` (35), `Remove-AzDataTableEntity` (17). Anything written through the raw cmdlets **skips encryption** unless it is migrated or blocked.
* **[R] 156 distinct tables.** The sensitive volume is not credentials. `Add-CIPPDbItem` (≈190 callers) writes `CippReportingDB` rows as `PartitionKey = tenant`, `RowKey`, `Type`, `RunId` and **`Data` = the full JSON of tenant objects** (users, devices, policies). That is the largest body of customer data in Azure.
* **[R] In production, refresh tokens and API keys are in Key Vault, not in tables.** The `DevSecrets` table holds them only in the Azurite/dev path. So the "tokens, credentials, secure strings" requirement is mostly about (i) dev parity, (ii) any secret-like values inside `Extensionsconfig`, `ScheduledTasks` (task `Parameters`), `ApiClients`, `webhookTable`/`WebhookIncoming` **[?: contents not yet classified]**, and (iii) tenant data in `CippReportingDB`.
* **[R] Secrets can also leak through logs, not just tables** (for example `Write-Verbose "Request Body: $ExoBody"` in `New-ExoRequest`). Table encryption does not cover this; see finding F4.
* **[R] Entities are split across properties/rows when large** (AzBobbyTables large-entity support, wrapped by the CIPP table helpers). Encryption must happen **before** the split on write and **after** reassembly on read.

### Findings to track

| ID | Finding | Action |
|---|---|---|
| F1 | `DevSecrets` stores secrets in plaintext (dev only) | Keep dev-only; provider `LocalDevelopment` is refused outside `UseDevelopmentStorage=true` |
| F2 | 21 + 21 + 35 + 17 raw table call-sites bypass the wrappers | Migrate, then add a CI check that forbids raw cmdlets outside the wrapper module (same idea as the hard-coded-host check) |
| F3 | Server-side `$filter` cannot see encrypted columns | Encrypt value columns only; never `PartitionKey`, `RowKey` or filter columns (§7) |
| F4 | Secrets in verbose/info logs | Redaction layer for `Write-Verbose/Information` of request bodies; separate task |
| F5 | Secrets live in process environment variables after load (`Set-Item env:`) | Accepted risk, documented; out of scope for 1.2 |
| F6 | A principal that can write the table can *wrap its own key* (RSA public keys are public) | Root key blob is **not** stored in the table (§4.1) |

---

## 3. Threat model (what this does and does not buy)

Protects against: leaked storage keys/SAS; table-level insider or backup exposure; accidental export of tables; cross-row/cross-tenant ciphertext substitution (AAD binding); a compromised storage plane reading customer data.

Does **not** protect against: a compromised Function App (its identity can unwrap by design). Mitigate with least-privilege RBAC on one key, no export, private networking, alerting on unwrap volume, short in-memory key lifetime. Nor against rollback to an older valid ciphertext of the same row (no freshness guarantee). Nor against Microsoft operating the HSM service: that is exactly the residual risk the Phase 2 external HSM addresses.

---

## 4. Key hierarchy and envelope

### 4.1 Hierarchy (recommended)

```
KEK  (Managed HSM key, RSA-HSM, wrapKey/unwrapKey only, non-exportable)      <- Key 1, never leaves the HSM
  └─ wraps ─> RDK  Root Data Key, 256-bit random, one per environment+version
               stored WRAPPED in Key Vault as secret "sovratis-rdk-v{n}"      <- not in Table Storage (F6)
                 └─ HKDF-SHA256(salt = tenantSalt, info = "sov|v1|tenant|purpose|rdkVersion") ─> DEK
                      └─ AES-256-GCM, random 96-bit nonce per value ─> ciphertext property
Storage layer:  Azure Storage account-scoped key, wrapped by a *separate* CMK in the HSM   <- Key 2 (Phase 1)
```

Why derive instead of storing random per-tenant DEKs: a key-store table would let anyone with table-write access substitute a DEK they wrapped themselves (F6) and inject attacker-chosen plaintext. With derivation, forging a valid ciphertext needs the RDK, which only the HSM can unwrap. It also needs one HSM call per process start instead of one per tenant/purpose.

* `tenantSalt`: 32 random bytes in `TenantProperties` (`RowKey='EncSalt'`, same side-car pattern as `CloudEnvironment`). Created on first write with an insert-only (ETag) operation. A substituted salt makes decryption fail; it cannot cause forgery.
* GCM nonce: random 96-bit per value; rotate the RDK version well before 2^32 encryptions per derived key (NIST random-nonce bound). Count conservatively, e.g. rotate the RDK at 2^28 writes or 12 months.
* RSA-OAEP-256 on a 3072-bit key wraps the 32-byte RDK with ample headroom [V: RSA-OAEP-256 is the recommended wrap algorithm; RSA1_5 and SHA-1 OAEP are legacy-only].

### 4.2 Envelope format (self-describing, versioned)

Stored as one string property value, so existing table schemas and the large-entity splitter keep working:

```
sov1.<b64url(JSON header)>.<b64url(nonce)>.<b64url(ciphertext)>.<b64url(tag)>
header = { "v":1, "alg":"A256GCM", "kdf":"HKDF-SHA256", "rdk":"sovratis-rdk-v3", "ctx":"purpose" }
```

AAD (authenticated, not stored — recomputed on read, so moving a value anywhere else fails authentication):

```
"sovratis|v1|<purpose>|<tenantId>|<table>|<partitionKey>|<rowKey>|<property>"
```

The header carries the RDK version, never a key. The *provider and KEK identifier* live with the wrapped RDK, not in every row, so a provider change (Phase 2) re-wraps one blob and touches no data.

### 4.3 Rotation

* **KEK rotation:** new key version in the HSM → re-wrap each RDK blob (a handful of operations). No data re-encryption. [?: confirm Managed HSM auto-rotation policy support for the chosen key type.]
* **RDK rotation:** new version `n+1`; new writes use it, old versions stay readable until a backfill re-encrypts.
* **Provider change (Phase 2):** `Invoke-SovratisEncryption -Operation Rewrap` re-wraps RDK blobs.

### 4.4 Crypto-shredding

Deleting a tenant's `EncSalt` makes every value encrypted for that tenant permanently undecryptable (including in backups made before the deletion only if their salt copy is also gone). It must be a deliberate, logged, two-step action (mark → grace period → delete) wired next to `Remove-SovratisCloudEnvironment` in tenant removal. Never automatic.

---

## 5. Azure resources

| Resource | Setting | Notes |
|---|---|---|
| **Managed HSM** | Soft-delete on, **purge protection on** (required for CMK) [V]; public access disabled + private endpoint; diagnostic setting → Log Analytics (audit events) | Activation needs a Security Domain download and a key quorum [?: check current minimum key count and quorum in the activation docs]. Store the Security Domain offline in two custody locations. Billed as a fixed hourly pool [?: pricing] |
| **Key 1** `sov-kek-<env>-v1` | RSA-HSM 3072 (or 4096), operations limited to `wrapKey`/`unwrapKey`/`get`, non-exportable | App-layer KEK |
| **Key 2** `sov-storage-cmk-<env>` | RSA-HSM, 2048/3072/4096 [V] | Storage CMK. **Separate key, separate role holders** (separation of duties) |
| **Function App identity** | existing system-assigned managed identity | **Managed HSM local RBAC, not Azure RBAC:** role **Managed HSM Crypto Service Encryption User**, scope `/keys/sov-kek-<env>-v1`. That role is get + wrap + unwrap only [V]; do **not** assign *Crypto User* (create/sign/decrypt/etc.) |
| **Key custodians** | separate Entra group | **Managed HSM Crypto Officer**: key lifecycle, role management, no data-plane crypto use [V]. Add an auditor role for read-only review |
| **Key Vault (existing)** | add secret `sovratis-rdk-v{n}` (wrapped RDK) | Function identity already has secret read. Write access only for the deployment/rotation identity |
| **Storage account (new)** | general-purpose v2, **`encryption-key-type-for-table = Account`** (and queue) at creation, CMK = Key 2, user-assigned identity with *Crypto Service Encryption User* on Key 2 | Immutable after creation [V]. Table is billed at a different rate with account-scoped keys [V] |
| **Log Analytics + alerts** | HSM audit events; alert on unwrap failure rate, unwrap volume spikes, role-assignment changes, key delete/purge attempts | The unwrap rate is a good compromise signal given §3 |
| **App settings** (no secrets) | `SOVRATIS_ENC_PROVIDER=AzureManagedHsm`, `SOVRATIS_KEK_REF=https://<hsm>.managedhsm.azure.net/keys/sov-kek-<env>/<version>`, `SOVRATIS_ENC_MODE=Dual|Strict` | Provider can be switched here for Key Vault Premium: `…vault.azure.net/keys/…` |
| **App Registration** | **none** | See §2. Phase 2 external HSM may need its own client credentials |

Network note: the DEK/RDK never touch the network in plaintext; only the wrapped RDK (KV) and wrap/unwrap calls (HSM). Put the HSM behind a private endpoint with the Function App on VNet integration.

---

## 6. Module structure

Own module, separate from routing (`SovratisCloud`): different audit scope and release cadence. `Invoke-SovratisEncryption` moves from `SovratisCloud` into it; nothing calls the stub today.

```
backend/Modules/SovratisCrypto/
  SovratisCrypto.psd1 / .psm1 / build.psd1        (same ModuleBuilder pattern as CIPPPwPush)
  Public/
    Invoke-SovratisEncryption.ps1        facade: Encrypt | Decrypt | Rewrap | Health
    Protect-SovratisEntity.ps1           policy-driven transform used by the table wrappers (write)
    Unprotect-SovratisEntity.ps1         policy-driven transform used by the table wrappers (read)
    Get-SovratisEncryptionPolicy.ps1
    Test-SovratisEncryptionHealth.ps1
    Invoke-SovratisEncryptionBackfill.ps1
    Remove-SovratisTenantKeys.ps1        crypto-shred (two-step)
  Private/
    Envelope/   New-SovratisEnvelope.ps1, Read-SovratisEnvelope.ps1, ConvertTo-SovratisAad.ps1
    Keys/       Get-SovratisRootKey.ps1, Get-SovratisDek.ps1, Get-SovratisTenantSalt.ps1, SovratisKeyCache.ps1
    Providers/  Invoke-SovratisKekProvider.ps1                 (dispatcher)
                Invoke-SovratisKekProvider_AzureManagedHsm.ps1
                Invoke-SovratisKekProvider_AzureKeyVault.ps1   (Premium, same contract)
                Invoke-SovratisKekProvider_LocalDevelopment.ps1 (refused unless dev storage)
                Invoke-SovratisKekProvider_ExternalHsm.ps1     (Phase 2 stub: throws NotImplemented)
    Audit/      Write-SovratisCryptoAudit.ps1                  (never logs plaintext, keys or ciphertext)
  Config/EncryptionPolicy.json
```

### 6.1 Facade (the only entry point core code may call)

```powershell
function Invoke-SovratisEncryption {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Encrypt', 'Decrypt', 'Rewrap', 'Health')][string]$Operation,
        [string]$Data,
        # Required keys: TenantId, Purpose. Bound as AAD when present: Table, PartitionKey, RowKey, Property.
        [hashtable]$Context = @{}
    )
    $Aad = ConvertTo-SovratisAad -Context $Context          # canonical, sorted, throws if TenantId/Purpose missing
    switch ($Operation) {
        'Encrypt' {
            $Root = Get-SovratisRootKey -ForWrite           # newest RDK version, unwrapped via provider, cached
            $Dek  = Get-SovratisDek -Root $Root -TenantId $Context.TenantId -Purpose $Context.Purpose
            New-SovratisEnvelope -Plaintext $Data -Dek $Dek -Aad $Aad -RdkId $Root.Id
        }
        'Decrypt' {
            $Env  = Read-SovratisEnvelope -Text $Data       # validates prefix, version, field sizes
            $Root = Get-SovratisRootKey -Id $Env.Header.rdk
            $Dek  = Get-SovratisDek -Root $Root -TenantId $Context.TenantId -Purpose $Context.Purpose
            Open-SovratisEnvelope -Envelope $Env -Dek $Dek -Aad $Aad   # throws on any authentication failure
        }
        'Rewrap' { Update-SovratisRootKeyWrap }
        'Health' { Test-SovratisEncryptionHealth }
    }
}
```

Rules: fail closed (any error throws, never returns the input); strings only (callers serialise objects); `SecureString` accepted by the entity transform and converted for the shortest possible time.

### 6.2 AEAD core (AES-256-GCM, .NET `AesGcm`)

```powershell
function New-SovratisEnvelope {
    param([string]$Plaintext, [byte[]]$Dek, [byte[]]$Aad, [string]$RdkId)
    $Nonce  = [byte[]]::new(12); [System.Security.Cryptography.RandomNumberGenerator]::Fill($Nonce)
    $Plain  = [System.Text.Encoding]::UTF8.GetBytes($Plaintext)
    $Cipher = [byte[]]::new($Plain.Length); $Tag = [byte[]]::new(16)
    $Aes = [System.Security.Cryptography.AesGcm]::new($Dek, 16)
    try     { $Aes.Encrypt($Nonce, $Plain, $Cipher, $Tag, $Aad) }
    finally { $Aes.Dispose(); [System.Array]::Clear($Plain) }
    $Header = @{ v = 1; alg = 'A256GCM'; kdf = 'HKDF-SHA256'; rdk = $RdkId } | ConvertTo-Json -Compress
    'sov1.{0}.{1}.{2}.{3}' -f (ConvertTo-B64Url ([Text.Encoding]::UTF8.GetBytes($Header))), (ConvertTo-B64Url $Nonce), (ConvertTo-B64Url $Cipher), (ConvertTo-B64Url $Tag)
}
```

DEK derivation: `[System.Security.Cryptography.HKDF]::DeriveKey([HashAlgorithmName]::SHA256, $Rdk, 32, $TenantSalt, [Text.Encoding]::UTF8.GetBytes("sov|v1|$TenantId|$Purpose|$RdkVersion"))`. Key material is held in `byte[]` in a synchronized cache with a short TTL (default 5 minutes, then zeroed); never in environment variables, logs or the pipeline.

### 6.3 Provider contract (what Phase 2 must implement)

PowerShell has no interfaces, so the contract is a function-name convention plus a conformance test suite every provider must pass:

```powershell
# Dispatcher: the provider is chosen by the RDK blob's own metadata, not only by current config,
# so data wrapped under an old provider keeps decrypting after a switch.
function Invoke-SovratisKekProvider {
    param([string]$Provider, [ValidateSet('Wrap', 'Unwrap', 'Info', 'Health')][string]$Operation, [string]$KeyRef, [byte[]]$Data)
    $Fn = "Invoke-SovratisKekProvider_$Provider"
    if (-not (Get-Command $Fn -ErrorAction SilentlyContinue)) { throw "Unknown encryption provider '$Provider'." }
    & $Fn -Operation $Operation -KeyRef $KeyRef -Data $Data
}

function Invoke-SovratisKekProvider_AzureManagedHsm {
    param([string]$Operation, [string]$KeyRef, [byte[]]$Data)
    # KeyRef = https://<hsm>.managedhsm.azure.net/keys/<name>/<version>
    Assert-SovratisKeyRefAllowed -KeyRef $KeyRef -AllowedHostSuffix '.managedhsm.azure.net'   # SSRF guard: pinned host, https only
    $Token = Get-CIPPAzIdentityToken -ResourceUrl 'https://managedhsm.azure.net'               # [?: confirm audience]
    $Action = @{ Wrap = 'wrapkey'; Unwrap = 'unwrapkey' }[$Operation]
    $Body = @{ alg = 'RSA-OAEP-256'; value = (ConvertTo-B64Url $Data) } | ConvertTo-Json -Compress
    $R = Invoke-CIPPRestMethod -Method POST -Uri "$KeyRef/${Action}?api-version=7.4" -ContentType 'application/json' -Body $Body `
         -Headers @{ Authorization = "Bearer $Token" }                                         # [?: confirm api-version for Managed HSM]
    ConvertFrom-B64Url $R.value
}
```

Provider rules: `byte[]` in and out; no logging of data; retries only on 429/5xx honouring `Retry-After`; a hard timeout; `Health` returns key state and the last successful unwrap time. Wrapping can be done locally with the cached public key (the docs describe local wrap as the faster path [V]), leaving only unwrap on the HSM.

**Phase 2 (strict external HSM):** implement `Invoke-SovratisKekProvider_ExternalHsm` against whatever the HSM exposes (a REST/KMIP gateway, or Managed HSM's external key management, which is a preview feature supporting RSA-OAEP/RSA-OAEP-256/A256KW and AES-256 external keys [V, preview]). The RDK blob metadata becomes an ordered list `wraps:[{provider,keyRef}, …]` applied in sequence (nested wrap), so decryption needs **both** the Azure HSM and the external HSM: genuine double-key control. `Rewrap` migrates existing blobs. No data re-encryption, no core changes.

---

## 7. Where encryption is applied: the table wrappers, driven by policy

Hook only the two wrappers (marked `[SOVRATIS OVERRIDE]`), not call sites:

```powershell
# Add-CIPPAzDataTableEntity, before the large-entity split / write
$Entity = Protect-SovratisEntity -Entity $Entity -Table $Context.TableName      # no-op for tables without a policy
# Get-CIPPAzDataTableEntity, after reassembly (and honouring -Property: only decrypt what was selected)
$Result = Unprotect-SovratisEntity -Entity $Result -Table $Context.TableName
```

Policy (illustrative; the real property lists come out of task T0):

```json
{
  "mode": "Dual",
  "tables": {
    "CippReportingDB": { "tier": "T2", "encrypt": ["Data"],          "purpose": "tenant-data" },
    "ScheduledTasks":  { "tier": "T1", "encrypt": ["Parameters"],     "purpose": "task-params" },
    "DevSecrets":      { "tier": "T1", "encrypt": ["*"],              "purpose": "dev-secrets", "devOnly": true }
  }
}
```

Rules: never encrypt `PartitionKey`, `RowKey` or any column used in `$filter` (F3); tenant id for AAD comes from `PartitionKey` where it is a tenant, else from an explicit policy field; entities in unlisted tables are untouched; `Dual` accepts legacy plaintext on read, `Strict` rejects it.

Tiers: **T1** credentials and secret-bearing parameters (must); **T2** bulk tenant data such as `CippReportingDB.Data` (should); **T3** configuration (optional).

---

## 8. Migration and operations

1. **Dual mode:** wrappers encrypt on write and read both formats (a value without the `sov1.` prefix is legacy).
2. **Backfill:** `Invoke-SovratisEncryptionBackfill -Table <t> -Throttle <n>` re-writes rows in batches, resumable, with a per-table progress record. Storage migration (D3) can be combined with it.
3. **Strict mode:** after a clean backfill and a verification scan, flip `SOVRATIS_ENC_MODE=Strict`; plaintext reads then fail.
4. **Failure behaviour:** HSM unreachable → writes to protected tables fail (never fall back to plaintext); reads of cached keys continue until the TTL. Alert on both.
5. **Performance:** one RDK unwrap per process start/TTL expiry; AES-GCM per value is far cheaper than the table I/O it sits next to. Budget and measure: encrypt/decrypt 100k `CippReportingDB` rows and record the overhead before enabling T2 in production.
6. **Backups/DR:** the Managed HSM Security Domain and an HSM backup are part of the recovery plan; losing the HSM without them makes all data unrecoverable. Test the restore.

---

## 9. Test strategy

* Known-answer tests for AES-256-GCM and HKDF (NIST/RFC vectors).
* Tamper tests: flip a bit in nonce/ciphertext/tag; change any AAD field; move a value to another row, table, property or tenant; truncate the envelope; unknown `v`.
* Provider conformance suite (run against `LocalDevelopment` in CI and against a real Managed HSM in a gated job): wrap/unwrap round-trip, bad key ref, `429` + `Retry-After`, timeout, host allow-list rejects non-HSM hosts.
* Fail-closed tests: provider throws → no plaintext written, no plaintext returned.
* Cache tests: TTL expiry zeroes the buffer; a different tenant never gets another tenant's DEK.
* Wrapper tests: policy honoured; `-Property` projections; large entities; legacy plaintext in `Dual`, rejected in `Strict`.
* CI static checks: no raw table cmdlets outside the wrapper module (F2); no hard-coded key material; no logging of `$Plaintext`/`$Dek`.

---

## 10. Work breakdown

| Task | Content | Depends on |
|---|---|---|
| **T0** | Data-classification pass over the 156 tables → fills `EncryptionPolicy.json` (needs decision D4) | none |
| T1 | `SovratisCrypto` module: envelope, HKDF, AES-GCM, cache, `LocalDevelopment` provider, full unit tests (no Azure needed) | D1, D5 |
| T2 | `AzureManagedHsm` / `AzureKeyVault` providers + conformance suite | T1, Azure resources (§5) |
| T3 | Wrapper hooks + policy loader + migration of the raw table call-sites (F2) | T0, T1 |
| T4 | Backfill job, `Dual`→`Strict` switch, health endpoint, alerts | T3 |
| T5 | IaC for §5 (Bicep under `deployment/`), runbooks: activation, rotation, DR | D2, D3 |
| T6 | Log redaction (F4) and crypto-shred workflow (D7) | T3 |

---

## Sources (verified)

* [Managed HSM local RBAC built-in roles](https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/built-in-roles) — *Crypto Service Encryption User* = get/wrap/unwrap; *Crypto User* = broad key operations; *Crypto Officer* = management.
* [Key types, algorithms and operations — Key Vault](https://learn.microsoft.com/en-us/azure/key-vault/keys/about-keys-details) and [— Managed HSM](https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/about-keys-details) — RSA-OAEP-256 recommended; AES-KW on Managed HSM; local wrap is the faster path.
* [wrap Key — REST API](https://learn.microsoft.com/en-us/rest/api/keyvault/keys/wrap-key/wrap-key?view=rest-keyvault-keys-2025-07-01&viewFallbackFrom=rest-keyvault-keys-7.4)
* [Customer-managed keys for account encryption — Azure Storage](https://learn.microsoft.com/en-us/azure/storage/common/customer-managed-keys-overview) and [Create an account that supports customer-managed keys for tables and queues](https://learn.microsoft.com/en-us/azure/storage/common/account-encryption-key-create) — account-scoped key must be chosen at creation; purge protection and RSA 2048/3072/4096 required.
* [Managed HSM external key management key lifecycle (preview)](https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/external-key-management-key-lifecycle)

Not verified (marked **[?]** above): the Managed HSM token audience and data-plane api-version, auto-rotation support for the chosen key type, Security Domain quorum minimums, Managed HSM pricing, and the FIPS validation level of Key Vault Premium.

---

## Addendum: Phase 1.2 implementation decisions

* **Wrapped root key location.** Managed HSM exposes keys only (no secrets API), so the HSM-wrapped Root Data Key is a **secret in a dedicated key-plane Key Vault** (`SOVRATIS_RDK_VAULT`), never in Table Storage. The Function App identity has `Key Vault Secrets User` (read-only) on that vault; only the pipeline/operators write it (`Initialize-SovratisRootKey`). The app cannot create or replace root keys outside local development.
* **Trusted wraps.** A root-key blob is only unwrapped if every wrap names a provider and key (version ignored) the deployment configured (`SOVRATIS_ENC_PROVIDER`, `SOVRATIS_KEK_REF`, optional `SOVRATIS_ENC_EXTRA_WRAPS` for Phase 2).
* **Health** is read-only and idempotent: provider key metadata, a read-only root-key lookup and an unwrap of it. It writes nothing.
* **Scope (D4).** `Config/EncryptionPolicy.json` covers `CippReportingDB.Data` and `ApiClients.Role/IPRange`. `ApiClients` holds no secrets (client secrets live in Key Vault), so the value there is integrity and confidentiality of authorization data.
* **Unverified [?]:** Managed HSM token audience (`https://managedhsm.azure.net`) and data-plane api-version (`7.4`); both are flagged in the provider source.
