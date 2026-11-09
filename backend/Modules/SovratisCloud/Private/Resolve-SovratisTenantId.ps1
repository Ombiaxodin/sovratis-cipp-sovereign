function Resolve-SovratisTenantId {
    <#
    .SYNOPSIS
        Maps a tenant filter (customer GUID or any domain) to the tenant row.
    .DESCRIPTION
        Reads the Tenants table directly instead of calling Get-Tenants. Get-Tenants is the hottest
        function in CIPP, can trigger refreshes and applies per-request scoping. The cloud lookup
        sits underneath every API wrapper, so it must stay cheap and side-effect free.
        Get-GraphToken makes the same trade-off for the same reason.

        Returns the Tenants row, or $null when the tenant is unknown.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TenantFilter
    )

    $Safe = ConvertTo-CIPPODataFilterValue -Value $TenantFilter -Type String
    $TenantsTable = Get-CippTable -tablename 'Tenants'
    $Filter = if ($TenantFilter -match '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') {
        "PartitionKey eq 'Tenants' and RowKey eq '$Safe'"
    } else {
        # Parentheses are required: OData 'and' binds tighter than 'or'.
        "PartitionKey eq 'Tenants' and (defaultDomainName eq '$Safe' or initialDomainName eq '$Safe')"
    }
    return @(Get-CIPPAzDataTableEntity @TenantsTable -Filter $Filter)[0]
}
