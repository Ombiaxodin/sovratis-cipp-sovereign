function Invoke-SovratisRootKeyStore_Table {
    # DEVELOPMENT ONLY. A table store lets anyone with table-write access choose the trusted root key (F6),
    # so it is refused outside local development storage.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Operation, [string]$Id, [hashtable]$Blob, [string]$AccessToken)
    if (-not ($env:AzureWebJobsStorage -eq 'UseDevelopmentStorage=true' -or $env:NonLocalHostAzurite -eq 'true')) {
        throw 'The table root key store is only allowed with local development storage.'
    }
    $Table = Get-CippTable -tablename 'SovratisDevKeys'
    switch ($Operation) {
        'Latest' {
            $Rows = @(Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'rdk'")
            $Ids = $Rows | Where-Object { $_.RowKey -match '^sovratis-rdk-v(\d+)$' } | Sort-Object { [int]($_.RowKey -replace '\D') } -Descending
            if ($Ids) { @($Ids)[0].RowKey }
        }
        'Get' {
            if ($Id -notmatch '^sovratis-rdk-v\d{1,6}$') { throw 'Invalid root key id.' }
            $Row = Get-CIPPAzDataTableEntity @Table -Filter "PartitionKey eq 'rdk' and RowKey eq '$Id'"
            if ($Row) { $Row.Blob | ConvertFrom-Json -AsHashtable }
        }
        'Put' {
            Add-AzDataTableEntity @Table -Entity @{ PartitionKey = 'rdk'; RowKey = $Id; Blob = ($Blob | ConvertTo-Json -Depth 5 -Compress) }
        }
    }
}
