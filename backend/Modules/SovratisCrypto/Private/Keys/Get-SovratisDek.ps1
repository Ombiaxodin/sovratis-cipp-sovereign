function Get-SovratisDek {
    <#
    .SYNOPSIS
        Derives the 256-bit data-encryption key for one (RDK version, tenant, purpose) with HKDF-SHA256 (RFC 5869).
    .DESCRIPTION
        IKM  = the unwrapped Root Data Key (only obtainable through the KEK provider)
        salt = per-tenant random salt (TenantProperties/EncSalt). Deleting it crypto-shreds the tenant.
        info = length-prefixed ('sovratis-dek', 'v1', rdkId, tenantId, purpose): domain separated from the AAD
               and unambiguous, so different (tenant, purpose) pairs can never share a key.
        Derivation is deterministic and local; nothing is stored, so there is no key table to tamper with.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param(
        [Parameter(Mandatory)]$Root,
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][string]$Purpose
    )
    $Tenant = $TenantId.ToLowerInvariant()
    $CacheName = "dek|$($Root.Id)|$Tenant|$Purpose"
    $Cached = Get-SovratisCachedKey -Name $CacheName
    if ($Cached) { return , $Cached }

    $Salt = Get-SovratisTenantSalt -TenantId $Tenant
    $Info = ConvertTo-SovratisLengthPrefixed -Field @('sovratis-dek', 'v1', $Root.Id, $Tenant, $Purpose)
    $Dek = [System.Security.Cryptography.HKDF]::DeriveKey([System.Security.Cryptography.HashAlgorithmName]::SHA256, $Root.Key, 32, $Salt, $Info)
    Set-SovratisCachedKey -Name $CacheName -Key $Dek
    , $Dek
}
