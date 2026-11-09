#Requires -Version 7.0
<#
.SYNOPSIS
    Provisions the Sovratis Phase 1 key plane and data plane (Azure CLI based, idempotent).

.DESCRIPTION
    Creates, in dependency order:
      1. Resource group and the user-assigned identity the storage account uses to reach its CMK
      2. Azure Managed HSM (purge protection on, administrators set)
      3. Security Domain activation (quorum ceremony; see -ActivateHsm)
      4. Two HSM keys: sov-kek (wraps the Root Data Key) and sov-storage-cmk (storage-layer CMK)
      5. RBAC: Function App identity  -> 'Managed HSM Crypto Service Encryption User' on /keys/sov-kek
               storage identity       -> 'Managed HSM Crypto Service Encryption User' on /keys/sov-storage-cmk
      6. The dedicated key-plane Key Vault (SOVRATIS_RDK_VAULT), RBAC mode, purge protection on
               Function App identity  -> 'Key Vault Secrets User' (read only) on that vault
      7. The new Storage Account with an ACCOUNT-SCOPED table/queue encryption key (immutable after
         creation) and customer-managed-key encryption backed by sov-storage-cmk
      8. Optionally: the Sovratis app settings, and the first Root Data Key (Initialize-SovratisRootKey)

    Every mutating step is guarded by an existence check, so the script can be re-run. It supports -WhatIf
    for the mutating az calls (read-only lookups still run, so you must be logged in).

    Items marked [?] were NOT verified against Microsoft documentation or a live tenant. They are the things
    to confirm on the first run; the script prints them as it goes. See docs-sovratis/Runbook-Phase1-Infrastructure.md.

.PARAMETER FunctionAppName
    The CIPP Function App. It must already exist and have a SYSTEM-ASSIGNED managed identity enabled.

.PARAMETER HsmAdministratorObjectIds
    Entra object IDs that become Managed HSM administrators at creation (at least one; use a break-glass
    group-backed principal, not a person).

.PARAMETER SecurityDomainCertificates
    Public certificates (.cer) for the Security Domain wrapping keys, with -SecurityDomainQuorum. Generate and
    keep the PRIVATE keys offline with separate custodians. [?] the documented minimum is 3 keys and quorum 2.

.EXAMPLE
    ./Deploy-SovratisInfrastructure.ps1 -SubscriptionId <id> -ResourceGroup rg-sov-prod -Location germanywestcentral `
        -NamePrefix sovprod -FunctionAppName cipp-sov-fa -HsmAdministratorObjectIds <oid> -WhatIf
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)][string]$SubscriptionId,
    [Parameter(Mandatory)][string]$ResourceGroup,
    [Parameter(Mandatory)][string]$Location,
    # 3-11 lowercase letters/digits. Names: <prefix>-hsm, <prefix>-rdk (vault), <prefix>st (storage), <prefix>-stid (identity).
    [Parameter(Mandatory)][ValidatePattern('^[a-z][a-z0-9]{2,10}$')][string]$NamePrefix,
    [Parameter(Mandatory)][string]$FunctionAppName,
    [string]$FunctionAppResourceGroup,
    [Parameter(Mandatory)][string[]]$HsmAdministratorObjectIds,

    [switch]$ActivateHsm,
    [string[]]$SecurityDomainCertificates,
    [int]$SecurityDomainQuorum = 2,
    [string]$SecurityDomainOutFile = './sovratis-hsm-security-domain.json',

    [string]$KekName = 'sov-kek',
    [string]$StorageCmkName = 'sov-storage-cmk',
    [int]$SoftDeleteRetentionDays = 90,
    # Public network access for the two vault-like resources. Set to Disabled once private endpoints exist.
    [ValidateSet('Enabled', 'Disabled')][string]$PublicNetworkAccess = 'Enabled',

    [switch]$ConfigureFunctionAppSettings,
    [switch]$ProvisionRootKey,
    # Revoke the temporary operator grants this script made (run after -ProvisionRootKey succeeded).
    [switch]$RevokeOperatorGrants
)

$ErrorActionPreference = 'Stop'
if (-not $FunctionAppResourceGroup) { $FunctionAppResourceGroup = $ResourceGroup }

$HsmName = "$NamePrefix-hsm"
$VaultName = "$NamePrefix-rdk"
$StorageName = "${NamePrefix}st"
$IdentityName = "$NamePrefix-stid"
if ($VaultName.Length -gt 24 -or $HsmName.Length -gt 24) { throw 'Resource names exceed 24 characters; shorten -NamePrefix.' }

function Invoke-Az {
    # Runs az, returns parsed JSON (or $null), throws with az's stderr on failure. Never prints secrets.
    param([Parameter(Mandatory, ValueFromRemainingArguments)][string[]]$Arguments, [switch]$AllowFailure)
    $Out = & az @Arguments --output json 2>&1
    if ($LASTEXITCODE -ne 0) {
        if ($AllowFailure) { return $null }
        throw "az $($Arguments[0..([math]::Min(3, $Arguments.Count - 1))] -join ' ') failed: $($Out -join ' ')"
    }
    $Text = ($Out | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }) -join "`n"
    if ([string]::IsNullOrWhiteSpace($Text)) { return $null }
    try { $Text | ConvertFrom-Json -Depth 20 } catch { $Text }
}
function Step([string]$Text) { Write-Host "`n=== $Text" -ForegroundColor Cyan }
function Done([string]$Text) { Write-Host "  ok  $Text" -ForegroundColor Green }
function Note([string]$Text) { Write-Host "  [?] $Text" -ForegroundColor Yellow }
function Test-RoleAssignment {
    param([string]$Assignee, [string]$Role, [string]$Scope)
    [bool](Invoke-Az role assignment list --assignee $Assignee --role $Role --scope $Scope --query '[0].id' -AllowFailure)
}
function Grant-ArmRole {
    param([string]$Assignee, [string]$Role, [string]$Scope, [string]$Why)
    if (Test-RoleAssignment -Assignee $Assignee -Role $Role -Scope $Scope) { Done "$Role already assigned ($Why)"; return }
    if ($PSCmdlet.ShouldProcess($Scope, "Assign '$Role' to $Assignee")) {
        $null = Invoke-Az role assignment create --assignee-object-id $Assignee --assignee-principal-type ServicePrincipal --role $Role --scope $Scope
        Done "$Role -> $Why"
    }
}
function Test-HsmRoleAssignment {
    param([string]$Assignee, [string]$Role, [string]$Scope)
    $DefId = Invoke-Az keyvault role definition list --hsm-name $HsmName --query "[?roleName=='$Role'].id | [0]" -AllowFailure
    if (-not $DefId) { return $false }
    $List = Invoke-Az keyvault role assignment list --hsm-name $HsmName --assignee-object-id $Assignee --scope $Scope -AllowFailure
    [bool](@($List) | Where-Object { $_.properties.scope -eq $Scope -and $_.properties.roleDefinitionId -eq $DefId })
}
function Grant-HsmRole {
    # Managed HSM uses its own LOCAL RBAC (data plane), not Azure RBAC.
    param([string]$Assignee, [string]$Role, [string]$Scope, [string]$Why, [string]$PrincipalType = 'ServicePrincipal')
    if (Test-HsmRoleAssignment -Assignee $Assignee -Role $Role -Scope $Scope) { Done "HSM $Role already assigned ($Why)"; return }
    if ($PSCmdlet.ShouldProcess("$HsmName $Scope", "Assign HSM role '$Role' to $Assignee")) {
        $null = Invoke-Az keyvault role assignment create --hsm-name $HsmName --assignee-object-id $Assignee --role $Role --scope $Scope
        Done "HSM $Role on $Scope -> $Why"
    }
}

# ---------------------------------------------------------------- 0. preflight
Step '0. Preflight'
$Account = Invoke-Az account show -AllowFailure
if (-not $Account) { throw 'Not logged in. Run: az login (and az cloud set --name <your cloud> first for a sovereign cloud).' }
$null = Invoke-Az account set --subscription $SubscriptionId
$Cloud = Invoke-Az cloud show
Done "cloud '$($Cloud.name)', subscription $SubscriptionId, signed in as $($Account.user.name)"
Note "Managed HSM / Key Vault DNS suffixes in this cloud: HSM '$($Cloud.suffixes.managedHsmServiceVaultResourceId)', vault '$($Cloud.suffixes.keyvaultDns)'. The Sovratis code pins *.managedhsm.azure.net and *.vault.azure.net; if these differ, STOP and raise a code change."
foreach ($Provider in 'Microsoft.KeyVault', 'Microsoft.Storage', 'Microsoft.ManagedIdentity') {
    $State = Invoke-Az provider show --namespace $Provider --query registrationState
    if ($State -ne 'Registered') { if ($PSCmdlet.ShouldProcess($Provider, 'Register provider')) { $null = Invoke-Az provider register --namespace $Provider --wait } }
}
$OperatorOid = (Invoke-Az ad signed-in-user show --query id -AllowFailure)
if (-not $OperatorOid) { Note 'Could not resolve the signed-in user object id (service principal login?). Operator grants for -ProvisionRootKey will be skipped.' }

$Function = Invoke-Az functionapp show --name $FunctionAppName --resource-group $FunctionAppResourceGroup
$AppOid = $Function.identity.principalId
if (-not $AppOid) { throw "Function App '$FunctionAppName' has no system-assigned managed identity. Enable it first: az functionapp identity assign -n $FunctionAppName -g $FunctionAppResourceGroup" }
Done "Function App identity $AppOid"

# ---------------------------------------------------------------- 1. RG + storage identity
Step '1. Resource group and storage CMK identity'
if (-not (Invoke-Az group show --name $ResourceGroup -AllowFailure)) {
    if ($PSCmdlet.ShouldProcess($ResourceGroup, 'Create resource group')) { $null = Invoke-Az group create --name $ResourceGroup --location $Location; Done "resource group $ResourceGroup" }
} else { Done "resource group $ResourceGroup exists" }
$Identity = Invoke-Az identity show --name $IdentityName --resource-group $ResourceGroup -AllowFailure
if (-not $Identity -and $PSCmdlet.ShouldProcess($IdentityName, 'Create user-assigned identity')) {
    $Identity = Invoke-Az identity create --name $IdentityName --resource-group $ResourceGroup --location $Location
    Done "identity $IdentityName"
} elseif ($Identity) { Done "identity $IdentityName exists" }

# ---------------------------------------------------------------- 2. Managed HSM
Step '2. Azure Managed HSM'
$Hsm = Invoke-Az keyvault show --hsm-name $HsmName --resource-group $ResourceGroup -AllowFailure
if (-not $Hsm) {
    if ($PSCmdlet.ShouldProcess($HsmName, 'Create Managed HSM (billed per hour while it exists)')) {
        $Hsm = Invoke-Az keyvault create --hsm-name $HsmName --resource-group $ResourceGroup --location $Location `
            --administrators @HsmAdministratorObjectIds --retention-days $SoftDeleteRetentionDays --enable-purge-protection true `
            --public-network-access $PublicNetworkAccess
        Done "Managed HSM $HsmName created (provisioning can take 20+ minutes)"
    }
} else { Done "Managed HSM $HsmName exists" }
$HsmUri = "https://$HsmName.managedhsm.azure.net"
if ($Hsm -and -not $Hsm.properties.enablePurgeProtection) { throw "HSM $HsmName does not have purge protection. It cannot be enabled later; recreate it." }

# ---------------------------------------------------------------- 3. Activation
Step '3. Security Domain activation'
$Probe = Invoke-Az keyvault key list --hsm-name $HsmName -AllowFailure
if ($null -eq $Probe -and -not $WhatIfPreference) {
    if (-not $ActivateHsm) {
        Write-Host @"

  The HSM is not activated (or not reachable with your identity). Activation downloads the Security Domain,
  wrapped by $SecurityDomainQuorum-of-N custodian certificates. THIS IS A CEREMONY, not a step to automate:
    - generate N>=3 key pairs on separate machines, give each custodian ONE private key, store them offline
    - re-run this script with:
        -ActivateHsm -SecurityDomainCertificates cert1.cer,cert2.cer,cert3.cer -SecurityDomainQuorum 2
    - the resulting file ($SecurityDomainOutFile) plus a quorum of private keys is the ONLY way to recover
      the HSM. Store them separately. Losing them loses every key in the HSM, and with it all encrypted data.
"@ -ForegroundColor Yellow
        exit 2
    }
    if ($SecurityDomainCertificates.Count -lt 3 -or $SecurityDomainQuorum -lt 2 -or $SecurityDomainQuorum -gt $SecurityDomainCertificates.Count) {
        throw 'Provide at least 3 custodian certificates and a quorum between 2 and the certificate count.'
    }
    if ($PSCmdlet.ShouldProcess($HsmName, 'Download Security Domain (activates the HSM)')) {
        $null = Invoke-Az keyvault security-domain download --hsm-name $HsmName --sd-wrapping-keys @SecurityDomainCertificates --sd-quorum $SecurityDomainQuorum --security-domain-file $SecurityDomainOutFile
        Done "activated; Security Domain written to $SecurityDomainOutFile. Move it off this machine NOW."
    }
} else { Done 'HSM is activated and reachable' }

# ---------------------------------------------------------------- 4. HSM keys
Step '4. HSM keys (RSA-HSM 3072, wrap/unwrap only)'
if ($OperatorOid) {
    # Creating keys needs data-plane rights; the administrator role does not necessarily include it. [?]
    Grant-HsmRole -Assignee $OperatorOid -Role 'Managed HSM Crypto Officer' -Scope '/' -Why 'operator (key management; revoked with -RevokeOperatorGrants)'
}
foreach ($Key in $KekName, $StorageCmkName) {
    if (Invoke-Az keyvault key show --hsm-name $HsmName --name $Key -AllowFailure) { Done "key $Key exists"; continue }
    if ($PSCmdlet.ShouldProcess($Key, 'Create RSA-HSM 3072 key')) {
        $null = Invoke-Az keyvault key create --hsm-name $HsmName --name $Key --kty RSA-HSM --size 3072 --ops wrapKey unwrapKey
        Done "key $Key created (non-exportable)"
    }
}

# ---------------------------------------------------------------- 5. HSM role assignments
Step '5. Managed HSM local RBAC (least privilege, scoped per key)'
$Role = 'Managed HSM Crypto Service Encryption User'
Grant-HsmRole -Assignee $AppOid -Role $Role -Scope "/keys/$KekName" -Why "Function App -> $KekName"
if ($Identity) { Grant-HsmRole -Assignee $Identity.principalId -Role $Role -Scope "/keys/$StorageCmkName" -Why "storage identity -> $StorageCmkName" }

# ---------------------------------------------------------------- 6. RDK vault
Step '6. Key-plane Key Vault for the wrapped Root Data Key (SOVRATIS_RDK_VAULT)'
$Vault = Invoke-Az keyvault show --name $VaultName --resource-group $ResourceGroup -AllowFailure
if (-not $Vault -and $PSCmdlet.ShouldProcess($VaultName, 'Create Key Vault')) {
    $Vault = Invoke-Az keyvault create --name $VaultName --resource-group $ResourceGroup --location $Location --sku standard `
        --enable-rbac-authorization true --enable-purge-protection true --retention-days $SoftDeleteRetentionDays `
        --public-network-access $PublicNetworkAccess
    Done "vault $VaultName created"
} elseif ($Vault) { Done "vault $VaultName exists" }
if ($Vault) {
    if (-not $Vault.properties.enablePurgeProtection) { throw "Vault $VaultName lacks purge protection (cannot be enabled later on some SKUs/configs; recreate)." }
    Grant-ArmRole -Assignee $AppOid -Role 'Key Vault Secrets User' -Scope $Vault.id -Why 'Function App (READ ONLY on the key plane)'
}

# ---------------------------------------------------------------- 7. Storage account
Step '7. Storage account with account-scoped table encryption key + CMK'
Note 'The table/queue encryption key type is chosen at creation and cannot be changed. CLI parameter names for it vary by az version; check: az storage account create -h | grep -i key-type'
$Storage = Invoke-Az storage account show --name $StorageName --resource-group $ResourceGroup -AllowFailure
if (-not $Storage -and $Identity -and $PSCmdlet.ShouldProcess($StorageName, 'Create storage account')) {
    $Storage = Invoke-Az storage account create --name $StorageName --resource-group $ResourceGroup --location $Location `
        --sku Standard_ZRS --kind StorageV2 --min-tls-version TLS1_2 --https-only true --allow-blob-public-access false `
        --encryption-key-type-for-table Account --encryption-key-type-for-queue Account `
        --identity-type UserAssigned --user-identity-id $Identity.id
    Done "storage account $StorageName created"
} elseif ($Storage) { Done "storage account $StorageName exists" }
if ($Storage -and $Identity -and $PSCmdlet.ShouldProcess($StorageName, "Enable CMK ($StorageCmkName in $HsmName)")) {
    # No key version: the account follows the latest version (auto-rotation). [?] confirm for Managed HSM keys.
    $null = Invoke-Az storage account update --name $StorageName --resource-group $ResourceGroup `
        --encryption-key-source Microsoft.Keyvault --encryption-key-vault $HsmUri --encryption-key-name $StorageCmkName `
        --key-vault-user-identity-id $Identity.id
    Done 'CMK configured'
    Note 'Confirm storage CMK against a Managed HSM key URI is supported in this cloud/region; if update fails, the error names the unsupported combination.'
}
Note 'CIPP connects with a connection string (shared key). Keep shared-key access enabled for this account, restrict by network rules, and rotate keys. Point AzureWebJobsStorage at this account manually (not done here: it re-targets the whole app).'

# ---------------------------------------------------------------- 8. App settings
Step '8. Function App settings'
$Kek = Invoke-Az keyvault key show --hsm-name $HsmName --name $KekName -AllowFailure
$KekRef = "$HsmUri/keys/$KekName"
$Settings = @("SOVRATIS_ENC_PROVIDER=AzureManagedHsm", "SOVRATIS_KEK_REF=$KekRef", "SOVRATIS_RDK_VAULT=$VaultName", 'SOVRATIS_ENC_MODE=Enforce')
if ($ConfigureFunctionAppSettings) {
    if ($PSCmdlet.ShouldProcess($FunctionAppName, 'Set SOVRATIS_* app settings (restarts the app)')) {
        $null = Invoke-Az functionapp config appsettings set --name $FunctionAppName --resource-group $FunctionAppResourceGroup --settings @Settings
        Done 'settings applied'
    }
} else { Write-Host "  Not applied (-ConfigureFunctionAppSettings not set). Settings:`n   $($Settings -join "`n   ")" }

# ---------------------------------------------------------------- 9. First root key
if ($ProvisionRootKey) {
    Step '9. First Root Data Key (operator identity, NOT the Function App)'
    if (-not $OperatorOid -or -not $Vault) { throw 'Need a signed-in user and the RDK vault to provision the root key.' }
    Grant-HsmRole -Assignee $OperatorOid -Role $Role -Scope "/keys/$KekName" -Why 'operator wrap (temporary)'
    Grant-ArmRole -Assignee $OperatorOid -Role 'Key Vault Secrets Officer' -Scope $Vault.id -Why 'operator write (temporary)'
    if ($PSCmdlet.ShouldProcess($VaultName, 'Generate, HSM-wrap and store sovratis-rdk-v1')) {
        $HsmToken = (Invoke-Az account get-access-token --resource 'https://managedhsm.azure.net').accessToken    # [?] audience
        $VaultToken = (Invoke-Az account get-access-token --resource 'https://vault.azure.net').accessToken
        Import-Module (Join-Path $PSScriptRoot '../backend/Modules/SovratisCrypto/SovratisCrypto.psd1') -Force
        $env:SOVRATIS_ENC_PROVIDER = 'AzureManagedHsm'; $env:SOVRATIS_KEK_REF = $KekRef; $env:SOVRATIS_RDK_VAULT = $VaultName
        # Initialize-SovratisRootKey calls CIPP's Invoke-CIPPRestMethod; load CIPPCore's helper when running outside the app.
        if (-not (Get-Command Invoke-CIPPRestMethod -ErrorAction SilentlyContinue)) {
            function global:Invoke-CIPPRestMethod { param($Method, $Uri, $Headers, $Body, $ContentType, $TimeoutSec, $ErrorAction) Invoke-RestMethod -Method $Method -Uri $Uri -Headers $Headers -Body $Body -ContentType $ContentType -TimeoutSec $TimeoutSec }
        }
        Initialize-SovratisRootKey -HsmAccessToken $HsmToken -VaultAccessToken $VaultToken
        Done 'root data key provisioned'
    }
}
if ($RevokeOperatorGrants -and $OperatorOid -and $Vault) {
    Step 'Revoking temporary operator grants'
    if ($PSCmdlet.ShouldProcess($VaultName, 'Remove operator Key Vault Secrets Officer')) {
        $null = Invoke-Az role assignment delete --assignee $OperatorOid --role 'Key Vault Secrets Officer' --scope $Vault.id -AllowFailure
        $null = Invoke-Az keyvault role assignment delete --hsm-name $HsmName --assignee-object-id $OperatorOid --role $Role --scope "/keys/$KekName" -AllowFailure
        Done 'operator write/wrap grants removed (HSM Crypto Officer kept for key management; remove when done)'
    }
}

# ---------------------------------------------------------------- 10. Verification
Step '10. Verification'
if (-not $WhatIfPreference) {
    $Checks = [ordered]@{}
    $H = Invoke-Az keyvault show --hsm-name $HsmName --resource-group $ResourceGroup
    $Checks['HSM purge protection'] = [bool]$H.properties.enablePurgeProtection
    foreach ($Key in $KekName, $StorageCmkName) {
        $K = Invoke-Az keyvault key show --hsm-name $HsmName --name $Key -AllowFailure
        $Checks["key $Key is RSA-HSM, wrap/unwrap only"] = [bool]($K -and $K.key.kty -eq 'RSA-HSM' -and ((@($K.key.keyOps) | Sort-Object) -join ',') -eq 'unwrapKey,wrapKey')
    }
    $Checks['Function App can unwrap with sov-kek only'] = Test-HsmRoleAssignment -Assignee $AppOid -Role $Role -Scope "/keys/$KekName"
    $V = Invoke-Az keyvault show --name $VaultName --resource-group $ResourceGroup -AllowFailure
    $Checks['RDK vault: purge protection + RBAC'] = [bool]($V.properties.enablePurgeProtection -and $V.properties.enableRbacAuthorization)
    $Checks['Function App is read-only on RDK vault'] = Test-RoleAssignment -Assignee $AppOid -Role 'Key Vault Secrets User' -Scope $V.id
    $Checks['Function App holds NO write role on RDK vault'] = -not ((Test-RoleAssignment -Assignee $AppOid -Role 'Key Vault Secrets Officer' -Scope $V.id) -or (Test-RoleAssignment -Assignee $AppOid -Role 'Key Vault Administrator' -Scope $V.id) -or (Test-RoleAssignment -Assignee $AppOid -Role 'Contributor' -Scope $V.id))
    $S = Invoke-Az storage account show --name $StorageName --resource-group $ResourceGroup -AllowFailure
    $Checks['Storage: CMK key source'] = [bool]($S -and $S.encryption.keySource -eq 'Microsoft.Keyvault')
    $Checks['Storage: table key type Account'] = [bool]($S -and $S.encryption.services.table.keyType -eq 'Account')
    $Checks['Storage: HTTPS only, TLS 1.2'] = [bool]($S -and $S.enableHttpsTrafficOnly -and $S.minimumTlsVersion -eq 'TLS1_2')
    $Failed = 0
    foreach ($Name in $Checks.Keys) {
        if ($Checks[$Name]) { Write-Host "  PASS  $Name" -ForegroundColor Green } else { Write-Host "  FAIL  $Name" -ForegroundColor Red; $Failed++ }
    }
    Write-Host "`nNext: re-run the app's health check (Invoke-SovratisEncryption -Operation Health) from the Function App, then the live integration tests." -ForegroundColor Cyan
    if ($Failed) { exit 1 }
}
