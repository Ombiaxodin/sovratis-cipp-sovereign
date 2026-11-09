function Get-SovratisTenantSalt {
    <#
    .SYNOPSIS
        Returns the tenant's 32-byte HKDF salt, creating it on first use.
    .DESCRIPTION
        Stored in the TenantProperties side-car table (RowKey 'EncSalt'), same pattern as CloudEnvironment.
        Creation is insert-only: if two workers race, one insert fails and both read the winner's value.
        A substituted or replaced salt makes decryption fail; it cannot be used to forge ciphertext
        because the RDK is still required.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory)][string]$TenantId)

    $Tenant = $TenantId.ToLowerInvariant()
    $CacheName = "salt|$Tenant"
    $Cached = Get-SovratisCachedKey -Name $CacheName
    if ($Cached) { return , $Cached }

    $Table = Get-CippTable -tablename 'TenantProperties'
    $SafeId = ConvertTo-CIPPODataFilterValue -Value $Tenant -Type String
    $Filter = "PartitionKey eq '$SafeId' and RowKey eq 'EncSalt'"
    $Row = Get-CIPPAzDataTableEntity @Table -Filter $Filter
    if (-not $Row -or [string]::IsNullOrWhiteSpace($Row.Value)) {
        $New = [byte[]]::new(32)
        [System.Security.Cryptography.RandomNumberGenerator]::Fill($New)
        try {
            # No -Force: a plain insert, which fails if the row already exists.
            Add-AzDataTableEntity @Table -Entity @{ PartitionKey = $Tenant; RowKey = 'EncSalt'; Value = (ConvertTo-SovratisB64Url $New) }
        } catch {
            Write-Verbose 'Tenant salt insert lost a race or failed; re-reading.'
        } finally { [System.Array]::Clear($New, 0, $New.Length) }
        $Row = Get-CIPPAzDataTableEntity @Table -Filter $Filter
        if (-not $Row -or [string]::IsNullOrWhiteSpace($Row.Value)) { throw 'Could not create or read the tenant encryption salt.' }
    }
    $Salt = ConvertFrom-SovratisB64Url $Row.Value
    if ($Salt.Length -ne 32) { throw 'Tenant encryption salt is malformed.' }
    Set-SovratisCachedKey -Name $CacheName -Key $Salt
    , $Salt
}
