function Resolve-SovratisScope {
    <#
    .SYNOPSIS
        Rewrites URL-style OAuth scopes ('https://graph.microsoft.com/.default') to the tenant's cloud.
    .DESCRIPTION
        Token requests carry the resource host inside the scope. Without this, a DELOS authority
        would be asked for a Global-resource token. Space-separated scope lists are handled per
        entry. Scopes that are not URLs (for example an app-id GUID such as the Teams
        '48ac35b8-.../.default') and the 'ExchangeOnline' sentinel pass through unchanged.
    .PARAMETER Scope
        The scope string.
    .PARAMETER TenantFilter
        Tenant GUID or domain whose cloud decides the mapping.
    .PARAMETER CloudEnvironment
        Explicit cloud name. Overrides the tenant lookup.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Scope,

        [string]$TenantFilter,
        [string]$CloudEnvironment
    )

    if ([string]::IsNullOrWhiteSpace($Scope)) { return $Scope }
    if (-not $CloudEnvironment) {
        $CloudEnvironment = Get-SovratisCloudEnvironment -TenantFilter $TenantFilter
    }
    if ($CloudEnvironment -eq 'Global') { return $Scope }

    $Resolved = foreach ($Entry in ($Scope -split '\s+' | Where-Object { $_ })) {
        Resolve-SovratisUri -Uri $Entry -CloudEnvironment $CloudEnvironment
    }
    return ($Resolved -join ' ')
}
