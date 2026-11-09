function Assert-SovratisServiceSupported {
    <#
    .SYNOPSIS
        Throws when a service is not available in the tenant's cloud environment.
    .DESCRIPTION
        Gate for code paths that cannot be expressed as a simple host swap (the classic admin
        API, Teams service discovery). A service is "supported" in a cloud when the catalog
        defines a host for it. Services that are deliberately unsupported (for example Admin and
        Teams in DELOS phase 1) are simply left out of that cloud's catalog entry. Global
        tenants always pass without touching the catalog.
    .PARAMETER Service
        Catalog service key, for example 'Admin' or 'Teams'.
    .PARAMETER TenantFilter
        Tenant GUID or domain whose cloud is checked. Ignored when -CloudEnvironment is given.
    .PARAMETER CloudEnvironment
        Explicit cloud name.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Service,

        [string]$TenantFilter,
        [string]$CloudEnvironment
    )

    if (-not $CloudEnvironment) {
        $CloudEnvironment = Get-SovratisCloudEnvironment -TenantFilter $TenantFilter
    }
    if ($CloudEnvironment -eq 'Global') { return }

    $Catalog = Get-SovratisCloudCatalog
    if (-not $Catalog.ContainsKey($CloudEnvironment)) {
        throw "Unknown CloudEnvironment '$CloudEnvironment'."
    }
    if ([string]::IsNullOrWhiteSpace($Catalog[$CloudEnvironment][$Service])) {
        throw "The '$Service' service is not supported in the '$CloudEnvironment' cloud environment (tenant $TenantFilter)."
    }
}
