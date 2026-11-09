function Get-SovratisCloudHost {
    <#
    .SYNOPSIS
        Returns the host name of one service in a tenant's (or an explicit) cloud environment.
    .DESCRIPTION
        For code that builds URLs from parts, for example the token endpoint
        ("https://$(Get-SovratisCloudHost -Service Authority ...)/$tenant/oauth2/v2.0/token").
        Throws when the service has no host in the target cloud. It never falls back to Global.
    .PARAMETER Service
        Catalog service key: Authority, Graph, Exchange, Compliance, Arm, KeyVault, ...
    .PARAMETER TenantFilter
        Tenant whose cloud is used. Ignored when -CloudEnvironment is given.
    .PARAMETER CloudEnvironment
        Explicit cloud name, used during onboarding before the tenant has a stored value.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$Service,

        [string]$TenantFilter,
        [string]$CloudEnvironment
    )

    if (-not $CloudEnvironment) {
        $CloudEnvironment = Get-SovratisCloudEnvironment -TenantFilter $TenantFilter
    }
    $Catalog = Get-SovratisCloudCatalog
    if (-not $Catalog.ContainsKey($CloudEnvironment)) {
        throw "Unknown CloudEnvironment '$CloudEnvironment'."
    }
    $HostName = $Catalog[$CloudEnvironment][$Service]
    if ([string]::IsNullOrWhiteSpace($HostName)) {
        throw "CloudEnvironment '$CloudEnvironment' has no '$Service' endpoint in CloudEnvironments.json. Refusing to fall back to another cloud."
    }
    return $HostName
}
