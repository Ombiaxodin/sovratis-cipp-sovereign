function Get-SovratisCloudEnvironment {
    <#
    .SYNOPSIS
        Returns the cloud environment ('Global', 'DELOS', ...) configured for a tenant.
    .DESCRIPTION
        The value lives in the TenantProperties side-car table (PartitionKey = customerId,
        RowKey = 'CloudEnvironment', Value = <name>). It is intentionally NOT a column on the
        Tenants table because Get-Tenants rebuilds those rows and would drop it.

        Defaults to 'Global' when:
          - no tenant is given, or the tenant is the partner tenant ($env:TenantID)
          - the tenant is unknown (not yet onboarded)
          - the tenant has no CloudEnvironment row, which is every tenant onboarded before this
            feature existed

        Fails closed: a stored value that is not in the catalog throws instead of defaulting to
        Global. A corrupt row must never silently send a sovereign tenant's traffic to the
        Global cloud.

        Results are cached per runspace for 5 minutes. Set-SovratisCloudEnvironment invalidates
        the local entry, and other runspaces converge when the TTL expires.
    .PARAMETER TenantFilter
        Tenant GUID or any of its domain names.
    .PARAMETER SkipCache
        Bypass and refresh the cache entry.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [string]$TenantFilter,
        [switch]$SkipCache
    )

    $Default = 'Global'
    if ([string]::IsNullOrWhiteSpace($TenantFilter) -or $TenantFilter -eq $env:TenantID) {
        return $Default
    }

    if (-not $script:SovratisCloudTenantCache) {
        $script:SovratisCloudTenantCache = [hashtable]::Synchronized(@{})
    }
    $CacheKey = $TenantFilter.ToLowerInvariant()
    $Now = [DateTimeOffset]::UtcNow
    if (-not $SkipCache) {
        $Hit = $script:SovratisCloudTenantCache[$CacheKey]
        if ($Hit -and $Hit.Expires -gt $Now) { return $Hit.Value }
    }

    $Tenant = Resolve-SovratisTenantId -TenantFilter $TenantFilter
    if (-not $Tenant) {
        # Unknown tenant: do not cache, it may be onboarded a moment later.
        return $Default
    }
    if ($Tenant.customerId -eq $env:TenantID) {
        return $Default
    }

    $PropertiesTable = Get-CippTable -tablename 'TenantProperties'
    $SafeId = ConvertTo-CIPPODataFilterValue -Value $Tenant.customerId -Type String
    $Row = Get-CIPPAzDataTableEntity @PropertiesTable -Filter "PartitionKey eq '$SafeId' and RowKey eq 'CloudEnvironment'"

    $Value = if ($Row -and -not [string]::IsNullOrWhiteSpace($Row.Value)) { [string]$Row.Value } else { $Default }

    $Catalog = Get-SovratisCloudCatalog
    if (-not $Catalog.ContainsKey($Value)) {
        throw "Tenant $($Tenant.customerId) has unknown CloudEnvironment '$Value'. Known: $($Catalog.Keys -join ', '). Refusing to route."
    }
    # Normalise to the catalog's casing so callers can compare with -eq / switch safely.
    $Value = @($Catalog.Keys).Where({ $_ -eq $Value })[0]

    $Entry = @{ Value = $Value; Expires = $Now.AddSeconds(300) }
    $script:SovratisCloudTenantCache[$CacheKey] = $Entry
    $script:SovratisCloudTenantCache[$Tenant.customerId.ToLowerInvariant()] = $Entry
    return $Value
}
