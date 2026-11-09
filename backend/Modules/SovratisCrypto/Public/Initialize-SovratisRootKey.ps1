function Initialize-SovratisRootKey {
    <#
    .SYNOPSIS
        OPERATOR / pipeline tool: generates a Root Data Key, wraps it in the HSM and stores it as a secret in the
        key-plane Key Vault. Not used by the running application.
    .DESCRIPTION
        The Function App identity is read-only on the key plane, by design: it cannot create or replace root keys.
        Run this once per environment (and once per RDK rotation) with an operator or pipeline identity that has
        'Managed HSM Crypto Service Encryption User' on the KEK and 'Key Vault Secrets Officer' on the key-plane
        vault. Tokens come from e.g. `az account get-access-token --resource https://managedhsm.azure.net` and
        `--resource https://vault.azure.net`. Refuses to overwrite an existing id.
    .PARAMETER Id
        Root key id, sovratis-rdk-v<n>. Defaults to the next free number.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [string]$Id,
        [string]$HsmAccessToken,
        [string]$VaultAccessToken
    )
    $Config = Get-SovratisEncryptionConfig
    if ($Config.Provider -eq 'LocalDevelopment') { throw 'Use the development auto-provisioning; this tool is for HSM-backed environments.' }
    if (-not $Id) {
        $Latest = Invoke-SovratisRootKeyStore -Operation Latest -AccessToken $VaultAccessToken
        $Next = if ($Latest) { [int]($Latest -replace '\D') + 1 } else { 1 }
        $Id = "sovratis-rdk-v$Next"
    }
    if ($Id -notmatch '^sovratis-rdk-v\d{1,6}$') { throw 'Invalid root key id.' }
    if ($PSCmdlet.ShouldProcess($Id, 'Generate, HSM-wrap and store root data key')) {
        $null = New-SovratisRootKey -Id $Id -HsmAccessToken $HsmAccessToken -VaultAccessToken $VaultAccessToken
        [pscustomobject]@{ Id = $Id; Provider = $Config.Provider; Store = 'KeyVault' }
    }
}
