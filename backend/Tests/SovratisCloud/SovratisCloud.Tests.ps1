# Pester tests for the SovratisCloud module (cloud catalog, resolver, tenant property)

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $env:CIPPRootPath = Join-Path $RepoRoot ''
    $env:TenantID = '00000000-0000-0000-0000-00000000aaaa'
    $ModuleRoot = Join-Path $RepoRoot 'Modules/SovratisCloud'
    foreach ($File in Get-ChildItem -Path $ModuleRoot -Include *.ps1 -Recurse) { . $File.FullName }

    # CIPPCore dependencies are stubbed so the module is tested in isolation.
    function ConvertTo-CIPPODataFilterValue { param($Value, $Type) $Value -replace "'", "''" }
    function Get-CippTable { param($tablename) @{ Context = $tablename } }
    function Get-CIPPAzDataTableEntity { param($Context, $Filter) }
    function Add-CIPPAzDataTableEntity { param($Context, $Entity, [switch]$Force) }
    function Clear-CippTokenCache { param($TenantFilter, [switch]$Confirm) }
    function Write-LogMessage { param($headers, $API, $tenant, $TenantId, $message, $Sev) }

    $script:DelosGuid = '11111111-1111-1111-1111-111111111111'
}

Describe 'SovratisCloud' {
BeforeEach {
    $script:SovratisCloudCatalog = $null
    $script:SovratisCloudTenantCache = $null
}

Describe 'Get-SovratisCloudCatalog' {
    It 'loads the shipped catalog with Global and DELOS' {
        $Catalog = Get-SovratisCloudCatalog
        $Catalog.Keys | Should -Contain 'Global'
        $Catalog.Keys | Should -Contain 'DELOS'
        $Catalog['DELOS']['Graph'] | Should -Be 'graph.microsoft.delos.cloud'
    }
}

Describe 'Resolve-SovratisUri' {
    It 'leaves Global URIs untouched' {
        $Uri = 'https://graph.microsoft.com/beta/users?$top=5'
        Resolve-SovratisUri -Uri $Uri -CloudEnvironment Global | Should -Be $Uri
    }

    It 'maps <Source> to <Expected> for DELOS' -TestCases @(
        @{ Source = 'https://graph.microsoft.com/beta/users?$top=5'; Expected = 'https://graph.microsoft.delos.cloud/beta/users?$top=5' }
        @{ Source = 'https://graph.microsoft.com/v1.0/$batch'; Expected = 'https://graph.microsoft.delos.cloud/v1.0/$batch' }
        @{ Source = 'https://login.microsoftonline.com/contoso.com/oauth2/v2.0/token'; Expected = 'https://login.microsoftonline.delos.cloud/contoso.com/oauth2/v2.0/token' }
        @{ Source = 'https://outlook.office365.com/adminapi/beta/x/InvokeCommand'; Expected = 'https://outlook.office365.delos.cloud/adminapi/beta/x/InvokeCommand' }
        @{ Source = 'https://ps.compliance.protection.outlook.com'; Expected = 'https://ps.compliance.protection.delos.cloud' }
        @{ Source = 'https://eur01.ps.compliance.protection.outlook.com/adminapi'; Expected = 'https://eur01.ps.compliance.protection.delos.cloud/adminapi' }
        @{ Source = 'https://management.azure.com/subscriptions/1?api-version=2020'; Expected = 'https://management.delos.cloud/subscriptions/1?api-version=2020' }
        @{ Source = 'https://myvault.vault.azure.net/secrets/s'; Expected = 'https://myvault.vault.delos.cloud/secrets/s' }
        @{ Source = 'https://GRAPH.microsoft.com:443/v1.0/me'; Expected = 'https://graph.microsoft.delos.cloud:443/v1.0/me' }
    ) {
        Resolve-SovratisUri -Uri $Source -CloudEnvironment DELOS | Should -Be $Expected
    }

    It 'passes through relative URLs, scope GUIDs and unknown hosts' {
        Resolve-SovratisUri -Uri '/organization?$select=id' -CloudEnvironment DELOS | Should -Be '/organization?$select=id'
        Resolve-SovratisUri -Uri '48ac35b8-9aa8-4d74-927d-1f4a14a0b239/.default' -CloudEnvironment DELOS | Should -Be '48ac35b8-9aa8-4d74-927d-1f4a14a0b239/.default'
        Resolve-SovratisUri -Uri 'https://api.partnercenter.microsoft.com/v1/customers' -CloudEnvironment DELOS | Should -Be 'https://api.partnercenter.microsoft.com/v1/customers'
    }

    It 'fails closed for Admin and Teams hosts in DELOS' -TestCases @(
        @{ Uri = 'https://admin.microsoft.com/admin/api/x' }
        @{ Uri = 'https://api.interfaces.records.teams.microsoft.com/Teams.Tenant/tenants' }
    ) {
        { Resolve-SovratisUri -Uri $Uri -CloudEnvironment DELOS } | Should -Throw '*Refusing*'
    }

    It 'does not match look-alike hosts' {
        $Fake = 'https://notgraph.microsoft.com/v1.0/me'
        Resolve-SovratisUri -Uri $Fake -CloudEnvironment DELOS | Should -Be $Fake
        $Fake2 = 'https://graph.microsoft.com.evil.example/v1.0/me'
        Resolve-SovratisUri -Uri $Fake2 -CloudEnvironment DELOS | Should -Be $Fake2
    }

    It 'is idempotent' {
        $Once = Resolve-SovratisUri -Uri 'https://graph.microsoft.com/v1.0/me' -CloudEnvironment DELOS
        Resolve-SovratisUri -Uri $Once -CloudEnvironment DELOS | Should -Be $Once
    }

    It 'throws for an unknown cloud' {
        { Resolve-SovratisUri -Uri 'https://graph.microsoft.com/v1.0/me' -CloudEnvironment Mars } | Should -Throw '*Unknown CloudEnvironment*'
    }

    It 'fails closed when the target cloud has no endpoint for the service' {
        $script:SovratisCloudCatalog = @{
            Global = @{ Graph = 'graph.microsoft.com'; Exchange = 'outlook.office365.com' }
            Partial = @{ Graph = 'graph.partial.test'; Exchange = '' }
        }
        { Resolve-SovratisUri -Uri 'https://outlook.office365.com/x' -CloudEnvironment Partial } | Should -Throw '*Refusing*'
        Resolve-SovratisUri -Uri 'https://graph.microsoft.com/x' -CloudEnvironment Partial | Should -Be 'https://graph.partial.test/x'
    }
}

Describe 'Resolve-SovratisScope' {
    It 'rewrites URL scopes and keeps GUID scopes' {
        Resolve-SovratisScope -Scope 'https://graph.microsoft.com/.default' -CloudEnvironment DELOS | Should -Be 'https://graph.microsoft.delos.cloud/.default'
        Resolve-SovratisScope -Scope '48ac35b8-9aa8-4d74-927d-1f4a14a0b239/.default' -CloudEnvironment DELOS | Should -Be '48ac35b8-9aa8-4d74-927d-1f4a14a0b239/.default'
        Resolve-SovratisScope -Scope 'ExchangeOnline' -CloudEnvironment DELOS | Should -Be 'ExchangeOnline'
    }
    It 'handles space-separated lists' {
        Resolve-SovratisScope -Scope 'https://graph.microsoft.com/.default offline_access' -CloudEnvironment DELOS | Should -Be 'https://graph.microsoft.delos.cloud/.default offline_access'
    }
}

Describe 'Get-SovratisCloudHost' {
    It 'returns the host for a service' {
        Get-SovratisCloudHost -Service Authority -CloudEnvironment DELOS | Should -Be 'login.microsoftonline.delos.cloud'
    }
    It 'throws for a service missing from the cloud' {
        { Get-SovratisCloudHost -Service Teams -CloudEnvironment DELOS } | Should -Throw '*no ''Teams'' endpoint*'
    }
}

Describe 'Get-SovratisCloudEnvironment' {
    It 'defaults to Global without a tenant, for the partner tenant and for unknown tenants' {
        Get-SovratisCloudEnvironment | Should -Be 'Global'
        Get-SovratisCloudEnvironment -TenantFilter $env:TenantID | Should -Be 'Global'
        Mock Get-CIPPAzDataTableEntity { $null }
        Get-SovratisCloudEnvironment -TenantFilter 'unknown.example' | Should -Be 'Global'
    }

    It 'defaults to Global when a known tenant has no property row' {
        Mock Get-CIPPAzDataTableEntity {
            if ($Context -eq 'Tenants') { [pscustomobject]@{ customerId = $script:DelosGuid; defaultDomainName = 'a.example' } }
        }
        Get-SovratisCloudEnvironment -TenantFilter $script:DelosGuid | Should -Be 'Global'
    }

    It 'reads DELOS from TenantProperties and caches the result' {
        Mock Get-CIPPAzDataTableEntity {
            if ($Context -eq 'Tenants') { [pscustomobject]@{ customerId = $script:DelosGuid; defaultDomainName = 'a.example' } }
            else { [pscustomobject]@{ RowKey = 'CloudEnvironment'; Value = 'delos' } }
        }
        Get-SovratisCloudEnvironment -TenantFilter $script:DelosGuid | Should -Be 'DELOS'
        Get-SovratisCloudEnvironment -TenantFilter 'a.example' | Should -Be 'DELOS'
        Get-SovratisCloudEnvironment -TenantFilter $script:DelosGuid | Should -Be 'DELOS'
        # GUID lookup + domain lookup hit storage once each, third call is served from cache
        Should -Invoke Get-CIPPAzDataTableEntity -Times 4 -Exactly
    }

    It 'fails closed on a corrupt stored value' {
        Mock Get-CIPPAzDataTableEntity {
            if ($Context -eq 'Tenants') { [pscustomobject]@{ customerId = $script:DelosGuid; defaultDomainName = 'a.example' } }
            else { [pscustomobject]@{ RowKey = 'CloudEnvironment'; Value = 'Mars' } }
        }
        { Get-SovratisCloudEnvironment -TenantFilter $script:DelosGuid } | Should -Throw '*Refusing to route*'
    }
}

Describe 'Set-SovratisCloudEnvironment' {
    BeforeEach {
        Mock Add-CIPPAzDataTableEntity { }
        Mock Clear-CippTokenCache { }
        Mock Write-LogMessage { }
    }

    It 'writes the TenantProperties row and clears tokens for a direct tenant' {
        Mock Get-CIPPAzDataTableEntity {
            if ($Context -eq 'Tenants') { [pscustomobject]@{ customerId = $script:DelosGuid; defaultDomainName = 'a.example'; delegatedPrivilegeStatus = 'directTenant' } }
        }
        $Result = Set-SovratisCloudEnvironment -TenantFilter $script:DelosGuid -CloudEnvironment delos
        $Result.CloudEnvironment | Should -Be 'DELOS'
        $Result.PreviousEnvironment | Should -Be 'Global'
        Should -Invoke Add-CIPPAzDataTableEntity -Times 1 -Exactly -ParameterFilter {
            $Context -eq 'TenantProperties' -and $Entity.PartitionKey -eq $script:DelosGuid -and $Entity.RowKey -eq 'CloudEnvironment' -and $Entity.Value -eq 'DELOS'
        }
        Should -Invoke Clear-CippTokenCache -Times 1 -Exactly
    }

    It 'is immutable: refuses to change a stored value' {
        Mock Get-CIPPAzDataTableEntity {
            if ($Context -eq 'Tenants') { [pscustomobject]@{ customerId = $script:DelosGuid; defaultDomainName = 'a.example'; delegatedPrivilegeStatus = 'directTenant' } }
            else { [pscustomobject]@{ RowKey = 'CloudEnvironment'; Value = 'DELOS' } }
        }
        { Set-SovratisCloudEnvironment -TenantFilter $script:DelosGuid -CloudEnvironment Global } | Should -Throw '*immutable*'
        Should -Invoke Add-CIPPAzDataTableEntity -Times 0 -Exactly
    }

    It 'treats re-submitting the stored value as a no-op' {
        Mock Get-CIPPAzDataTableEntity {
            if ($Context -eq 'Tenants') { [pscustomobject]@{ customerId = $script:DelosGuid; defaultDomainName = 'a.example'; delegatedPrivilegeStatus = 'directTenant' } }
            else { [pscustomobject]@{ RowKey = 'CloudEnvironment'; Value = 'DELOS' } }
        }
        (Set-SovratisCloudEnvironment -TenantFilter $script:DelosGuid -CloudEnvironment DELOS).CloudEnvironment | Should -Be 'DELOS'
        Should -Invoke Add-CIPPAzDataTableEntity -Times 0 -Exactly
        Should -Invoke Clear-CippTokenCache -Times 0 -Exactly
    }

    It 'rejects a non-Global cloud for a GDAP tenant' {
        Mock Get-CIPPAzDataTableEntity {
            if ($Context -eq 'Tenants') { [pscustomobject]@{ customerId = $script:DelosGuid; defaultDomainName = 'a.example'; delegatedPrivilegeStatus = 'granularDelegatedAdminPrivileges' } }
        }
        { Set-SovratisCloudEnvironment -TenantFilter $script:DelosGuid -CloudEnvironment DELOS } | Should -Throw '*Direct Tenant*'
        Should -Invoke Add-CIPPAzDataTableEntity -Times 0 -Exactly
    }

    It 'rejects an unknown cloud, an unknown tenant and the partner tenant' {
        { Set-SovratisCloudEnvironment -TenantFilter $script:DelosGuid -CloudEnvironment Mars } | Should -Throw '*Unknown CloudEnvironment*'
        Mock Get-CIPPAzDataTableEntity { $null }
        { Set-SovratisCloudEnvironment -TenantFilter 'nope.example' -CloudEnvironment DELOS } | Should -Throw '*not found*'
        Mock Get-CIPPAzDataTableEntity {
            if ($Context -eq 'Tenants') { [pscustomobject]@{ customerId = $env:TenantID; defaultDomainName = 'p.example'; delegatedPrivilegeStatus = 'directTenant' } }
        }
        { Set-SovratisCloudEnvironment -TenantFilter $env:TenantID -CloudEnvironment DELOS } | Should -Throw '*partner tenant*'
    }
}

Describe 'Remove-SovratisCloudEnvironment' {
    It 'deletes the row so a removed tenant can be onboarded again in another cloud' {
        function Remove-CIPPAzDataTableEntity { param($Context, $Entity, [switch]$Force) }
        Mock Remove-CIPPAzDataTableEntity { }
        Mock Get-CIPPAzDataTableEntity { [pscustomobject]@{ PartitionKey = $script:DelosGuid; RowKey = 'CloudEnvironment'; Value = 'DELOS' } }
        Remove-SovratisCloudEnvironment -TenantId $script:DelosGuid
        Should -Invoke Remove-CIPPAzDataTableEntity -Times 1 -Exactly -ParameterFilter { $Context -eq 'TenantProperties' -and $Entity.RowKey -eq 'CloudEnvironment' }
    }
    It 'does nothing when there is no row' {
        function Remove-CIPPAzDataTableEntity { param($Context, $Entity, [switch]$Force) }
        Mock Remove-CIPPAzDataTableEntity { }
        Mock Get-CIPPAzDataTableEntity { $null }
        Remove-SovratisCloudEnvironment -TenantId $script:DelosGuid
        Should -Invoke Remove-CIPPAzDataTableEntity -Times 0 -Exactly
    }
}

Describe 'Assert-SovratisServiceSupported' {
    It 'passes for Global, and for DELOS services that have an endpoint' {
        { Assert-SovratisServiceSupported -Service Admin -CloudEnvironment Global } | Should -Not -Throw
        { Assert-SovratisServiceSupported -Service Graph -CloudEnvironment DELOS } | Should -Not -Throw
    }
    It 'fails closed for Admin and Teams in DELOS' {
        { Assert-SovratisServiceSupported -Service Admin -CloudEnvironment DELOS } | Should -Throw '*not supported*'
        { Assert-SovratisServiceSupported -Service Teams -CloudEnvironment DELOS } | Should -Throw '*not supported*'
    }
}

Describe 'Get-SovratisCloudCredential' {
    BeforeEach {
        $script:Saved = @{}
        foreach ($Name in 'ApplicationID', 'ApplicationSecret', 'RefreshToken', 'DelosApplicationId', 'DelosApplicationSecret', 'DelosRefreshToken') { $script:Saved[$Name] = [Environment]::GetEnvironmentVariable($Name) }
        $env:ApplicationID = 'sam-app'; $env:ApplicationSecret = 'sam-secret'; $env:RefreshToken = 'sam-refresh'
        $env:DelosApplicationId = 'delos-app'; $env:DelosApplicationSecret = 'delos-secret'; $env:DelosRefreshToken = 'delos-refresh'
    }
    AfterEach {
        foreach ($Name in $script:Saved.Keys) { if ($null -eq $script:Saved[$Name]) { Remove-Item "env:$Name" -ErrorAction SilentlyContinue } else { Set-Item "env:$Name" -Value $script:Saved[$Name] } }
    }

    It 'returns the standard SAM variables for Global' {
        $Cred = Get-SovratisCloudCredential -CloudEnvironment Global
        $Cred.ApplicationId | Should -Be 'sam-app'
        $Cred.ApplicationSecret | Should -Be 'sam-secret'
        $Cred.RefreshToken | Should -Be 'sam-refresh'
    }
    It 'returns the Delos* variables for DELOS' {
        $Cred = Get-SovratisCloudCredential -CloudEnvironment DELOS
        $Cred.ApplicationId | Should -Be 'delos-app'
        $Cred.ApplicationSecret | Should -Be 'delos-secret'
        $Cred.RefreshToken | Should -Be 'delos-refresh'
    }
    It 'treats the refresh token as optional' {
        Remove-Item env:DelosRefreshToken
        (Get-SovratisCloudCredential -CloudEnvironment DELOS).RefreshToken | Should -BeNullOrEmpty
    }
    It 'fails closed when <Missing> is not set, never falling back to Global' -TestCases @(
        @{ Missing = 'DelosApplicationId' }
        @{ Missing = 'DelosApplicationSecret' }
    ) {
        Remove-Item "env:$Missing"
        { Get-SovratisCloudCredential -CloudEnvironment DELOS } | Should -Throw '*Refusing to use the Global credentials*'
    }
    It 'rejects placeholder values and unknown clouds' {
        $env:DelosApplicationId = 'LongApplicationId'
        { Get-SovratisCloudCredential -CloudEnvironment DELOS } | Should -Throw '*no credentials configured*'
        { Get-SovratisCloudCredential -CloudEnvironment Mars } | Should -Throw '*Unknown CloudEnvironment*'
    }
}

Describe 'Get-SovratisCloudEnvironmentList' {
    BeforeEach {
        $script:Saved = @{}
        foreach ($Name in 'DelosApplicationId', 'DelosApplicationSecret') { $script:Saved[$Name] = [Environment]::GetEnvironmentVariable($Name) }
    }
    AfterEach {
        foreach ($Name in $script:Saved.Keys) { if ($null -eq $script:Saved[$Name]) { Remove-Item "env:$Name" -ErrorAction SilentlyContinue } else { Set-Item "env:$Name" -Value $script:Saved[$Name] } }
    }
    It 'lists Global first and reports DELOS as configured with its public client id only' {
        $env:DelosApplicationId = 'delos-app'; $env:DelosApplicationSecret = 'delos-secret'
        $List = @(Get-SovratisCloudEnvironmentList)
        $List[0].name | Should -Be 'Global'
        $List[0].configured | Should -BeTrue
        $Delos = $List | Where-Object name -eq 'DELOS'
        $Delos.configured | Should -BeTrue
        $Delos.applicationId | Should -Be 'delos-app'
        $Delos.authority | Should -Be 'login.microsoftonline.delos.cloud'
        $Delos.graph | Should -Be 'graph.microsoft.delos.cloud'
        ($List | ConvertTo-Json -Depth 4) | Should -Not -Match 'delos-secret'
    }
    It 'reports DELOS as not configured, without leaking an app id, when credentials are missing' {
        Remove-Item env:DelosApplicationSecret -ErrorAction SilentlyContinue
        $env:DelosApplicationId = 'delos-app'
        $Delos = @(Get-SovratisCloudEnvironmentList) | Where-Object name -eq 'DELOS'
        $Delos.configured | Should -BeFalse
        $Delos.applicationId | Should -BeNullOrEmpty
    }
}

Describe 'Get-SovratisCloudEnvironmentMap' {
    It 'maps customerId to the stored cloud with a single query' {
        Mock Get-CIPPAzDataTableEntity {
            [pscustomobject]@{ PartitionKey = 'guid-1'; RowKey = 'CloudEnvironment'; Value = 'DELOS' }
            [pscustomobject]@{ PartitionKey = 'guid-2'; RowKey = 'CloudEnvironment'; Value = 'Global' }
        }
        $Map = Get-SovratisCloudEnvironmentMap
        $Map['guid-1'] | Should -Be 'DELOS'
        $Map['guid-2'] | Should -Be 'Global'
        $Map['guid-3'] | Should -BeNullOrEmpty
        Should -Invoke Get-CIPPAzDataTableEntity -Times 1 -Exactly -ParameterFilter { $Filter -eq "RowKey eq 'CloudEnvironment'" }
    }
}
}
