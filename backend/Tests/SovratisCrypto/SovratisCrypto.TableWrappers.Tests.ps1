# The REAL Add-/Get-CIPPAzDataTableEntity wrappers with the REAL SovratisCrypto hooks; only the storage cmdlets are faked.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $env:CIPPRootPath = $RepoRoot
    foreach ($File in Get-ChildItem -Path (Join-Path $RepoRoot 'Modules/SovratisCrypto') -Include *.ps1 -Recurse) { . $File.FullName }
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Add-CIPPAzDataTableEntity.ps1')
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/Get-CIPPAzDatatableEntity.ps1')
    function Test-CIPPTableNotFound { param($e) $false }
    function Repair-CIPPTable { param($Context) }
    function Write-LogMessage { param($API, $message, $Sev) }
    function ConvertTo-CIPPODataFilterValue { param($Value, $Type) $Value }
    function Get-CippTable { param($tablename) @{ Context = [pscustomobject]@{ TableName = $tablename } } }
    function Get-CIPPAzDataTableEntity2 {}
    # Fake storage keyed by table|pk|rk. Raw rows are what lands in Azure.
    $script:Raw = @{}
    function Add-AzDataTableLargeEntity { param($Context, $Entity, $CreateTableIfNotExists, $Force, $OperationType)
        foreach ($E in $Entity) { $script:Raw["$($Context.TableName)|$($E.PartitionKey)|$($E.RowKey)"] = [pscustomobject]@{ T = $Context.TableName; Row = ([pscustomobject]$E) } } }
    function Add-AzDataTableEntity { param($Context, $Entity) $script:Raw["$($Context.TableName)|$($Entity.PartitionKey)|$($Entity.RowKey)"] = [pscustomobject]@{ T = $Context.TableName; Row = ([pscustomobject]$Entity) } }
    function Get-AzDataTableLargeEntity { param($Context, $Filter, $Property, $First, $Skip, $Sort, [switch]$Count, $MaxRetries)
        $pk = if ($Filter -match "PartitionKey eq '([^']+)'") { $Matches[1] }
        $script:Raw.Values | Where-Object { $_.T -eq $Context.TableName -and (-not $pk -or $_.Row.PartitionKey -eq $pk) } | ForEach-Object { $_.Row.PSObject.Copy() } }
}

Describe 'Table wrappers with SovratisCrypto hooks' {
    BeforeEach {
        $script:Raw = @{}; $script:SovratisKeyCache = $null; $script:SovratisEncryptionPolicy = $null
        $env:AzureWebJobsStorage = 'UseDevelopmentStorage=true'; $env:SOVRATIS_ENC_MODE = $null
        $env:SOVRATIS_ENC_PROVIDER = 'LocalDevelopment'; $env:SOVRATIS_KEK_REF = 'dev-kek-1'
        $K = [byte[]]::new(32); [System.Security.Cryptography.RandomNumberGenerator]::Fill($K); $env:SOVRATIS_DEV_KEK = ConvertTo-SovratisB64Url $K
    }
    It 'stores CippReportingDB.Data encrypted and returns it decrypted' {
        $T = Get-CippTable -tablename 'CippReportingDB'
        $Entity = @{ PartitionKey = 'contoso.onmicrosoft.com'; RowKey = 'Users-1'; Data = '{"upn":"a@contoso.com"}'; Type = 'Users' }
        Add-CIPPAzDataTableEntity @T -Entity $Entity -Force
        $Entity.Data | Should -Be '{"upn":"a@contoso.com"}'     # caller's object untouched
        $Stored = $script:Raw['CippReportingDB|contoso.onmicrosoft.com|Users-1'].Row
        $Stored.Data | Should -BeLike 'sov1.*'
        $Stored.Data | Should -Not -BeLike '*contoso*'
        $Stored.Type | Should -Be 'Users'
        (Get-CIPPAzDataTableEntity @T -Filter "PartitionKey eq 'contoso.onmicrosoft.com'").Data | Should -Be '{"upn":"a@contoso.com"}'
    }
    It 'works for -Stream reads too' {
        $T = Get-CippTable -tablename 'CippReportingDB'
        Add-CIPPAzDataTableEntity @T -Entity @{ PartitionKey = 'p'; RowKey = 'r'; Data = 'secret' } -Force
        @(Get-CIPPAzDataTableEntity @T -Filter "PartitionKey eq 'p'" -Stream).Data | Should -Be 'secret'
    }
    It 'does not touch any other table' {
        $T = Get-CippTable -tablename 'Tenants'
        Add-CIPPAzDataTableEntity @T -Entity @{ PartitionKey = 'Tenants'; RowKey = 'x'; Data = 'plain' } -Force
        $script:Raw['Tenants|Tenants|x'].Row.Data | Should -Be 'plain'
        (Get-CIPPAzDataTableEntity @T).Data | Should -Be 'plain'
    }
    It 'encrypts ApiClients Role and IPRange but not the name or key' {
        $T = Get-CippTable -tablename 'ApiClients'
        Add-CIPPAzDataTableEntity @T -Entity @{ PartitionKey = 'ApiClients'; RowKey = 'app1'; AppName = 'Reporter'; Role = 'readonly'; IPRange = '["10.0.0.0/8"]'; Enabled = $true } -Force
        $S = $script:Raw['ApiClients|ApiClients|app1'].Row
        $S.Role | Should -BeLike 'sov1.*'; $S.IPRange | Should -BeLike 'sov1.*'
        $S.AppName | Should -Be 'Reporter'; $S.Enabled | Should -BeTrue
        $R = Get-CIPPAzDataTableEntity @T
        $R.Role | Should -Be 'readonly'; $R.IPRange | Should -Be '["10.0.0.0/8"]'
    }
    It 'denies a tampered ApiClients row (role rewritten in the table) instead of returning it' {
        $T = Get-CippTable -tablename 'ApiClients'
        Add-CIPPAzDataTableEntity @T -Entity @{ PartitionKey = 'ApiClients'; RowKey = 'app1'; AppName = 'x'; Role = 'readonly'; IPRange = '[]' } -Force
        $script:Raw['ApiClients|ApiClients|app1'].Row.Role = 'superadmin'
        @(Get-CIPPAzDataTableEntity @T -ErrorAction SilentlyContinue).Count | Should -Be 0
    }
    It 'carries -Count through unchanged' {
        function Get-AzDataTableLargeEntity { param($Context, $Filter, $Property, $First, $Skip, $Sort, [switch]$Count, $MaxRetries) 7 }
        (Get-CIPPAzDataTableEntity -Context ([pscustomobject]@{ TableName = 'CippReportingDB' }) -Count) | Should -Be 7
    }
    It 'fails closed on write when encryption is not configured' {
        $env:SOVRATIS_ENC_PROVIDER = $null
        $T = Get-CippTable -tablename 'CippReportingDB'
        { Add-CIPPAzDataTableEntity @T -Entity @{ PartitionKey = 'p'; RowKey = 'r'; Data = 'secret' } -Force } | Should -Throw '*SOVRATIS_ENC_PROVIDER*'
        $script:Raw.Count | Should -Be 0
    }
}
