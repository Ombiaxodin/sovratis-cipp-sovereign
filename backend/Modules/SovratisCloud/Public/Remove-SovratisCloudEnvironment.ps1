function Remove-SovratisCloudEnvironment {
    <#
    .SYNOPSIS
        Deletes a tenant's stored CloudEnvironment row.
    .DESCRIPTION
        CloudEnvironment is immutable once set (see Set-SovratisCloudEnvironment). The only way
        to move a tenant between clouds is to remove the tenant and onboard it again, so tenant
        removal must call this. Otherwise the stale row would block the re-onboarding.

        Takes the customer GUID, not a domain: the Tenants row is usually already gone when this
        runs, so a domain could no longer be resolved.
    .PARAMETER TenantId
        Customer (tenant) GUID.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$TenantId
    )

    $PropertiesTable = Get-CippTable -tablename 'TenantProperties'
    $SafeId = ConvertTo-CIPPODataFilterValue -Value $TenantId -Type String
    $Row = Get-CIPPAzDataTableEntity @PropertiesTable -Filter "PartitionKey eq '$SafeId' and RowKey eq 'CloudEnvironment'"
    if ($Row) {
        Remove-CIPPAzDataTableEntity -Force @PropertiesTable -Entity $Row
    }
    if ($script:SovratisCloudTenantCache) {
        $script:SovratisCloudTenantCache.Remove($TenantId.ToLowerInvariant())
        # Domain-keyed entries for this tenant cannot be enumerated cheaply; they expire with the TTL.
    }
}
