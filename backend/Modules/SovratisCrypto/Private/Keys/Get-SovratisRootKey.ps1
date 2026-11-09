function Get-SovratisRootKey {
    <#
    .SYNOPSIS
        Returns the unwrapped Root Data Key (RDK) as @{ Id; Key = byte[32] }.
    .DESCRIPTION
        The RDK is stored only in WRAPPED form (see Invoke-SovratisRootKeyStore: a Key Vault secret in the
        key-plane vault; a table only in local development). Unwrapping goes through the KEK provider chain, the
        only place the HSM is called. Result is cached for a few minutes.

        The blob lists its wraps in application order (outermost last). Phase 1 has one wrap (the Azure HSM).
        Phase 2 appends a second wrap (external HSM): unwrapping then needs BOTH, applied in reverse order.

        Defence in depth against a tampered store: every wrap in the blob must name a provider and key (version
        ignored) that the deployment configured (Get-SovratisAllowedWraps). A blob pointing at someone else's HSM
        is rejected before any call is made.
    .PARAMETER Id
        A specific RDK version, used on Decrypt (taken from the envelope header).
    .PARAMETER ForWrite
        Use the newest RDK. In local development it is created on first use; anywhere else it must already have
        been provisioned by Initialize-SovratisRootKey (the app identity cannot write the key plane).
    #>
    [CmdletBinding(DefaultParameterSetName = 'ById')]
    param(
        [Parameter(Mandatory, ParameterSetName = 'ById')][string]$Id,
        [Parameter(Mandatory, ParameterSetName = 'ForWrite')][switch]$ForWrite
    )

    if ($ForWrite) {
        $Latest = Invoke-SovratisRootKeyStore -Operation Latest
        if (-not $Latest) {
            if ((Get-SovratisEncryptionConfig).Provider -ne 'LocalDevelopment') {
                throw 'No root data key has been provisioned. Run Initialize-SovratisRootKey as an operator; the application identity cannot create root keys.'
            }
            $Latest = New-SovratisRootKey
        }
        $Id = $Latest
    }
    $Cached = Get-SovratisCachedKey -Name "rdk|$Id"
    if ($Cached) { return @{ Id = $Id; Key = $Cached } }

    $Blob = Invoke-SovratisRootKeyStore -Operation Get -Id $Id
    if (-not $Blob) { throw "Root data key '$Id' was not found." }
    $Wraps = @($Blob.wraps)
    if ($Wraps.Count -eq 0) { throw "Root data key '$Id' has no wraps." }
    $Allowed = Get-SovratisAllowedWraps
    foreach ($Wrap in $Wraps) {
        $Base = Get-SovratisKeyRefBase -KeyRef ([string]$Wrap.keyRef)
        if (-not ($Allowed | Where-Object { $_.Provider -ceq [string]$Wrap.provider -and $_.KeyRef -ceq $Base })) {
            throw "Root data key '$Id' is wrapped by a provider or key that this deployment does not trust."
        }
    }
    $Bytes = ConvertFrom-SovratisB64Url $Blob.wrapped
    for ($i = $Wraps.Count - 1; $i -ge 0; $i--) {
        $Bytes = Invoke-SovratisKekProvider -Provider $Wraps[$i].provider -Operation Unwrap -KeyRef $Wraps[$i].keyRef -Data $Bytes
    }
    if ($Bytes.Length -ne 32) { throw "Root data key '$Id' has an unexpected length after unwrapping." }
    Set-SovratisCachedKey -Name "rdk|$Id" -Key $Bytes
    @{ Id = $Id; Key = $Bytes }
}

function New-SovratisRootKey {
    # Generates a root key, wraps it with the configured provider (version-pinned) and stores the blob.
    # Used directly only in local development; Initialize-SovratisRootKey is the production path.
    [CmdletBinding()]
    param([string]$Id = 'sovratis-rdk-v1', [string]$HsmAccessToken, [string]$VaultAccessToken)
    $Config = Get-SovratisEncryptionConfig
    $Pin = @{}
    if ($HsmAccessToken) { $Pin.AccessToken = $HsmAccessToken }
    $Info = Invoke-SovratisKekProvider -Provider $Config.Provider -Operation Info -KeyRef $Config.KeyRef @Pin
    $PinnedRef = [string]($Info.KeyRef ?? $Config.KeyRef)
    $Rdk = [byte[]]::new(32)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($Rdk)
    try {
        $Wrapped = Invoke-SovratisKekProvider -Provider $Config.Provider -Operation Wrap -KeyRef $PinnedRef -Data $Rdk @Pin
        $Blob = @{
            id      = $Id
            wraps   = @(@{ provider = $Config.Provider; keyRef = $PinnedRef })
            wrapped = (ConvertTo-SovratisB64Url $Wrapped)
            created = [datetime]::UtcNow.ToString('o')
        }
        $StoreArgs = @{ Operation = 'Put'; Id = $Id; Blob = $Blob }
        if ($VaultAccessToken) { $StoreArgs.AccessToken = $VaultAccessToken }
        try { $null = Invoke-SovratisRootKeyStore @StoreArgs } catch {
            if (-not (Invoke-SovratisRootKeyStore -Operation Get -Id $Id)) { throw }
        }
    } finally { [System.Array]::Clear($Rdk, 0, $Rdk.Length) }
    $Id
}
