function Get-SovratisCloudEnvironmentMap {
    <#
    .SYNOPSIS
        Returns a hashtable of customerId -> CloudEnvironment for every tenant that has a stored value.
    .DESCRIPTION
        One TenantProperties query for the whole table, for list views that would otherwise do one
        lookup per row. Tenants without an entry are absent: the caller treats them as 'Global',
        matching Get-SovratisCloudEnvironment.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    $Map = @{}
    $PropertiesTable = Get-CippTable -tablename 'TenantProperties'
    foreach ($Row in @(Get-CIPPAzDataTableEntity @PropertiesTable -Filter "RowKey eq 'CloudEnvironment'")) {
        if ($Row.PartitionKey -and $Row.Value) { $Map[[string]$Row.PartitionKey] = [string]$Row.Value }
    }
    return $Map
}
