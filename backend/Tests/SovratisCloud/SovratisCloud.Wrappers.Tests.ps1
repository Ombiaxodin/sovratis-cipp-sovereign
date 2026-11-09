# Pester tests for the [SOVRATIS OVERRIDE] hooks in the core request wrappers.
# A DELOS tenant must reach DELOS hosts through every wrapper, a Global tenant must be left exactly as upstream,
# and services without a DELOS endpoint (Admin, Teams) must fail closed.
# The cloud lookup itself is mocked here; its storage behaviour is covered in SovratisCloud.Tests.ps1.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $env:CIPPRootPath = Join-Path $RepoRoot ''
    if (-not ('CIPP.CIPPTokenCache' -as [type])) {
        Add-Type -Path (Join-Path $RepoRoot 'Shared/CIPPSharp/bin/CIPPSharp.dll')
    }

    # real SovratisCloud code
    foreach ($File in Get-ChildItem -Path (Join-Path $RepoRoot 'Modules/SovratisCloud') -Include *.ps1 -Recurse) { . $File.FullName }

    # CIPPCore dependencies that are not under test
    function Get-AuthorisedRequest { param($Uri, $TenantID) }
    function Get-AuthorisedRequestError { param($TenantID, $Context) 'not authorised' }
    function Get-CIPPAuthentication { $true }
    function Get-CippTable { param($tablename) }
    function Get-CIPPAzDataTableEntity { param($Context, $Filter, $Property) }
    function Add-CIPPAzDataTableEntity { param($Context, $Entity, [switch]$Force) }
    function Update-AzDataTableEntity { param($Context, $Entity, [switch]$Force) }
    function Invoke-CIPPRestMethod { param($Method, $Uri, $Body, $Headers, $ContentType, $ResponseHeadersVariable, $StatusCodeVariable, [switch]$SkipHttpErrorCheck, $TimeoutSec, $MaximumRedirection) }
    function Get-CIPPTextReplacement { param($TenantFilter, $Text, [switch]$EscapeForJson) $Text }
    function Get-CippUserAgent { param([switch]$SharePoint) 'test-agent' }
    function Get-Tenants { param([switch]$IncludeErrors, $TenantFilter) [pscustomobject]@{ customerId = '22222222-2222-2222-2222-222222222222'; initialDomainName = $TenantFilter; defaultDomainName = $TenantFilter; Excluded = $false } }
    function Write-LogMessage { param($headers, $API, $tenant, $TenantId, $message, $Sev) }

    # wrappers under test
    $GraphHelper = Join-Path $RepoRoot 'Modules/CIPPCore/Public/GraphHelper'
    foreach ($Name in 'New-GraphGetRequest', 'New-GraphPOSTRequest', 'New-GraphBulkRequest', 'New-ExoRequest', 'Get-GraphToken', 'Get-ClassicAPIToken', 'New-TeamsRequestV2', 'Clear-CippTokenCache') {
        . (Join-Path $GraphHelper "$Name.ps1")
    }
    . (Join-Path $RepoRoot 'Modules/CIPPCore/Public/ConvertTo-CIPPODataFilterValue.ps1')

    $script:Delos = 'delos.example'
    $script:Global = 'global.example'
}

Describe 'SovratisCloud wrapper routing' {
    BeforeEach {
        Mock Get-SovratisCloudEnvironment { if ($TenantFilter -eq 'delos.example') { 'DELOS' } else { 'Global' } }
        Mock Get-AuthorisedRequest { $true }
        Mock Get-GraphToken { @{ Authorization = 'Bearer test' } }
        Mock Invoke-CIPPRestMethod { [pscustomobject]@{ value = @() } }
        $script:Headers = @{ Authorization = 'Bearer test'; 'User-Agent' = 'test' }
    }

    Context 'New-GraphGetRequest' {
        It 'sends a DELOS tenant to the DELOS Graph host' {
            $null = New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/users?$top=5' -tenantid $Delos -NoAuthCheck $true -Headers $Headers
            Should -Invoke Invoke-CIPPRestMethod -Times 1 -Exactly -ParameterFilter { $Uri -eq 'https://graph.microsoft.delos.cloud/beta/users?$top=5' }
        }
        It 'leaves a Global tenant untouched' {
            $null = New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/users' -tenantid $Global -NoAuthCheck $true -Headers $Headers
            Should -Invoke Invoke-CIPPRestMethod -Times 1 -Exactly -ParameterFilter { $Uri -eq 'https://graph.microsoft.com/beta/users' }
        }
        It 'refuses to fall back to Global for a service with no DELOS endpoint' {
            { New-GraphGetRequest -uri 'https://admin.microsoft.com/admin/api/x' -tenantid $Delos -NoAuthCheck $true -Headers $Headers } | Should -Throw '*Refusing*'
            Should -Invoke Invoke-CIPPRestMethod -Times 0 -Exactly
        }
    }

    Context 'New-GraphPOSTRequest' {
        It 'sends a DELOS tenant to the DELOS Graph host' {
            $null = New-GraphPOSTRequest -uri 'https://graph.microsoft.com/beta/users' -tenantid $Delos -body '{}' -NoAuthCheck $true -headers $Headers
            Should -Invoke Invoke-CIPPRestMethod -Times 1 -Exactly -ParameterFilter { $Uri -eq 'https://graph.microsoft.delos.cloud/beta/users' }
        }
        It 'leaves a Global tenant untouched' {
            $null = New-GraphPOSTRequest -uri 'https://graph.microsoft.com/beta/users' -tenantid $Global -body '{}' -NoAuthCheck $true -headers $Headers
            Should -Invoke Invoke-CIPPRestMethod -Times 1 -Exactly -ParameterFilter { $Uri -eq 'https://graph.microsoft.com/beta/users' }
        }
    }

    Context 'New-GraphBulkRequest' {
        It 'posts the $batch to the DELOS Graph host' {
            Mock Invoke-CIPPRestMethod { [pscustomobject]@{ responses = @([pscustomobject]@{ id = '1'; status = 200; body = [pscustomobject]@{ value = @() } }) } }
            $null = New-GraphBulkRequest -tenantid $Delos -NoAuthCheck $true -Headers $Headers -Requests @(@{ id = '1'; method = 'GET'; url = '/users' })
            Should -Invoke Invoke-CIPPRestMethod -Times 1 -Exactly -ParameterFilter { $Uri -eq 'https://graph.microsoft.delos.cloud/beta/$batch' }
        }
        It 'strips a DELOS nextLink to a relative continuation URL' {
            $script:Bodies = [System.Collections.Generic.List[string]]::new()
            $script:Replies = [System.Collections.Generic.Queue[object]]::new()
            $First = [pscustomobject]@{ id = '1'; status = 200; body = [pscustomobject]@{ value = @(1); '@odata.nextLink' = 'https://graph.microsoft.delos.cloud/beta/users?$skiptoken=abc' } }
            $Second = [pscustomobject]@{ id = '1'; status = 200; body = [pscustomobject]@{ value = @(2) } }
            $script:Replies.Enqueue([pscustomobject]@{ responses = @($First) })
            $script:Replies.Enqueue([pscustomobject]@{ responses = @($Second) })
            Mock Invoke-CIPPRestMethod { $script:Bodies.Add($Body); $script:Replies.Dequeue() }
            $null = New-GraphBulkRequest -tenantid $Delos -NoAuthCheck $true -Headers $Headers -Requests @(@{ id = '1'; method = 'GET'; url = '/users' })
            $script:Bodies.Count | Should -Be 2
            $script:Bodies[1] | Should -BeLike '*"url":"/users?$skiptoken=abc"*'
        }
    }

    Context 'New-ExoRequest' {
        It 'targets the DELOS Exchange host and asks for a DELOS-resource token' {
            $null = New-ExoRequest -cmdlet 'Get-Mailbox' -tenantid $Delos -NoAuthCheck $true
            Should -Invoke Invoke-CIPPRestMethod -Times 1 -Exactly -ParameterFilter { $Uri -eq 'https://outlook.office365.delos.cloud/adminapi/beta/22222222-2222-2222-2222-222222222222/InvokeCommand' }
        }
        It 'targets the DELOS compliance host for -Compliance' {
            Mock Get-Tenants { [pscustomobject]@{ customerId = '22222222-2222-2222-2222-222222222222'; initialDomainName = $TenantFilter; ComplianceUrl = 'https://eur.ps.compliance.protection.delos.cloud' } }
            $null = New-ExoRequest -cmdlet 'Get-DlpCompliancePolicy' -tenantid $Delos -NoAuthCheck $true -Compliance
            Should -Invoke Invoke-CIPPRestMethod -Times 1 -Exactly -ParameterFilter { $Uri -like 'https://eur.ps.compliance.protection.delos.cloud/adminapi/*' }
        }
        It 'leaves a Global tenant untouched' {
            $null = New-ExoRequest -cmdlet 'Get-Mailbox' -tenantid $Global -NoAuthCheck $true
            Should -Invoke Invoke-CIPPRestMethod -Times 1 -Exactly -ParameterFilter { $Uri -like 'https://outlook.office365.com/adminapi/beta/*' }
        }
    }

    Context 'Fail-closed services' {
        It 'blocks the classic admin API for DELOS' {
            { Get-ClassicAPIToken -tenantID $Delos -Resource 'https://admin.microsoft.com' } | Should -Throw '*not supported*'
            Should -Invoke Invoke-CIPPRestMethod -Times 0 -Exactly
        }
        It 'blocks Teams for DELOS' {
            { New-TeamsRequestV2 -TenantFilter $Delos -Path 'Skype.Ncs/locations' } | Should -Throw '*not supported*'
            Should -Invoke Get-GraphToken -Times 0 -Exactly
        }
    }
}

Describe 'Get-GraphToken cloud routing' {
    BeforeEach {
        $script:SavedEnv = @{}
        foreach ($Name in 'CertificateAuthMode', 'ApplicationID', 'ApplicationSecret', 'TenantID', 'RefreshToken', 'SetFromProfile', 'DelosApplicationId', 'DelosApplicationSecret', 'DelosRefreshToken') {
            $script:SavedEnv[$Name] = [Environment]::GetEnvironmentVariable($Name)
        }
        Remove-Item env:CertificateAuthMode -ErrorAction SilentlyContinue
        $env:ApplicationID = 'sam-app-id'
        $env:ApplicationSecret = 'sam-secret'
        $env:TenantID = '11111111-2222-3333-4444-555555555555'
        $env:RefreshToken = 'sam-refresh-token'
        $env:SetFromProfile = 'true'
        $env:DelosApplicationId = 'delos-app'
        $env:DelosApplicationSecret = 'delos-secret'
        $env:DelosRefreshToken = 'delos-refresh'
        $null = [CIPP.CIPPTokenCache]::Clear()

        Mock Get-SovratisCloudEnvironment { if ($TenantFilter -eq 'delos.example') { 'DELOS' } else { 'Global' } }
        Mock Get-CippTable { @{} }
        Mock Get-CIPPAzDataTableEntity { $null }
        Mock Invoke-CIPPRestMethod { @{ access_token = 'tok'; expires_in = 3600 } }
    }

    AfterEach {
        $null = [CIPP.CIPPTokenCache]::Clear()
        foreach ($Name in $script:SavedEnv.Keys) {
            if ($null -eq $script:SavedEnv[$Name]) { Remove-Item "env:$Name" -ErrorAction SilentlyContinue } else { Set-Item "env:$Name" -Value $script:SavedEnv[$Name] }
        }
    }

    It 'asks the DELOS authority for a DELOS-resource token' {
        $null = Get-GraphToken -tenantid $Delos
        Should -Invoke Invoke-CIPPRestMethod -Times 1 -Exactly -ParameterFilter {
            $Uri -eq 'https://login.microsoftonline.delos.cloud/delos.example/oauth2/v2.0/token' -and $Body.scope -eq 'https://graph.microsoft.delos.cloud/.default'
        }
    }
    It 'maps an Exchange scope to the DELOS Exchange resource' {
        $null = Get-GraphToken -tenantid $Delos -scope 'https://outlook.office365.com/.default'
        Should -Invoke Invoke-CIPPRestMethod -Times 1 -Exactly -ParameterFilter { $Body.scope -eq 'https://outlook.office365.delos.cloud/.default' }
    }
    It 'keeps Global tokens on the Global authority' {
        $null = Get-GraphToken -tenantid $Global
        Should -Invoke Invoke-CIPPRestMethod -Times 1 -Exactly -ParameterFilter {
            $Uri -eq 'https://login.microsoftonline.com/global.example/oauth2/v2.0/token' -and $Body.scope -eq 'https://graph.microsoft.com/.default'
        }
    }
    It 'mints a DELOS token with the DELOS app credentials, never the Global ones' {
        $null = Get-GraphToken -tenantid $Delos
        Should -Invoke Invoke-CIPPRestMethod -Times 1 -Exactly -ParameterFilter {
            $Body.client_id -eq 'delos-app' -and $Body.client_secret -eq 'delos-secret' -and $Body.refresh_token -eq 'delos-refresh' -and $Body.grant_type -eq 'refresh_token'
        }
        Should -Invoke Invoke-CIPPRestMethod -Times 0 -Exactly -ParameterFilter { $Body.client_id -eq 'sam-app-id' -or $Body.client_secret -eq 'sam-secret' -or $Body.refresh_token -eq 'sam-refresh-token' }
    }
    It 'uses the DELOS app for app-only (client credentials) tokens' {
        $null = Get-GraphToken -tenantid $Delos -AsApp $true
        Should -Invoke Invoke-CIPPRestMethod -Times 1 -Exactly -ParameterFilter {
            $Body.client_id -eq 'delos-app' -and $Body.client_secret -eq 'delos-secret' -and $Body.grant_type -eq 'client_credentials'
        }
    }
    It 'keeps Global tenants on the Global app credentials' {
        $null = Get-GraphToken -tenantid $Global
        Should -Invoke Invoke-CIPPRestMethod -Times 1 -Exactly -ParameterFilter {
            $Body.client_id -eq 'sam-app-id' -and $Body.client_secret -eq 'sam-secret' -and $Body.refresh_token -eq 'sam-refresh-token'
        }
    }
    It 'prefers the per-tenant direct-tenant refresh token over DelosRefreshToken' {
        $TenantGuid = '33333333-3333-3333-3333-333333333333'
        Set-Item -Path "env:$TenantGuid" -Value 'tenant-refresh'
        try {
            Mock Get-CIPPAzDataTableEntity { [pscustomobject]@{ customerId = '33333333-3333-3333-3333-333333333333'; defaultDomainName = 'delos.example'; delegatedPrivilegeStatus = 'directTenant' } }
            $null = Get-GraphToken -tenantid $Delos
            Should -Invoke Invoke-CIPPRestMethod -Times 1 -Exactly -ParameterFilter { $Body.client_id -eq 'delos-app' -and $Body.refresh_token -eq 'tenant-refresh' }
        } finally {
            Remove-Item "env:$TenantGuid" -ErrorAction SilentlyContinue
        }
    }
    It 'fails closed when the DELOS credentials are not configured, without falling back to Global' {
        Remove-Item env:DelosApplicationSecret
        { Get-GraphToken -tenantid $Delos } | Should -Throw '*no credentials configured*'
        Should -Invoke Invoke-CIPPRestMethod -Times 0 -Exactly
    }
    It 'refuses certificate authentication for a DELOS tenant' {
        { Get-GraphToken -tenantid $Delos -UseCertificate } | Should -Throw '*not supported*'
        Should -Invoke Invoke-CIPPRestMethod -Times 0 -Exactly
    }
    It 'keys the token cache on the DELOS client id' {
        $null = Get-GraphToken -tenantid 'delos.example'
        $Key = [CIPP.CIPPTokenCache]::BuildKey('delos.example', 'https://graph.microsoft.delos.cloud/.default', $false, 'delos-app', 'refresh_token')
        [CIPP.CIPPTokenCache]::Lookup($Key, 0).Found | Should -BeTrue
    }

    It 'never serves a cached Global token for the same tenant name in another cloud' {
        $null = Get-GraphToken -tenantid 'delos.example' -scope 'https://graph.microsoft.com/.default'
        $null = Get-GraphToken -tenantid 'delos.example' -scope 'https://graph.microsoft.com/.default'
        # second call is a cache hit, and the cache key carries the DELOS scope
        Should -Invoke Invoke-CIPPRestMethod -Times 1 -Exactly
        $Key = [CIPP.CIPPTokenCache]::BuildKey('delos.example', 'https://graph.microsoft.com/.default', $false, 'sam-app-id', 'refresh_token')
        [CIPP.CIPPTokenCache]::Lookup($Key, 0).Found | Should -BeFalse
    }
}

Describe 'SOVRATIS OVERRIDE markers' {
    It 'wraps every hook in a matching START/END pair, in every file type' {
        $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
        $Root = Split-Path -Parent $RepoRoot
        $Roots = 'backend/Modules', 'backend/Tests/GraphHelper', 'backend/Tests/CIPP', 'build', 'frontend/src' | ForEach-Object { Join-Path $Root $_ }
        $Files = Get-ChildItem -Path $Roots -Include *.ps1, *.yml, *.jsx, *.js, *.css, Dockerfile, Dockerfile.release -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -notmatch '[\\/](node_modules|\.devmodules|\.devmanifests)[\\/]' }
        $Bad = foreach ($File in $Files) {
            $Text = [string](Get-Content -Raw -LiteralPath $File.FullName)
            if ([string]::IsNullOrEmpty($Text) -or $Text -notmatch 'SOVRATIS OVERRIDE') { continue }
            # comment style differs per language (#, //, {/* */}); the marker text is what matters
            $Start = ([regex]::Matches($Text, '\[SOVRATIS OVERRIDE START\]')).Count
            $End = ([regex]::Matches($Text, '\[SOVRATIS OVERRIDE END\]')).Count
            $Loose = ([regex]::Matches($Text, '\[SOVRATIS OVERRIDE\]')).Count   # a marker without START/END
            if ($Start -ne $End -or $Start -eq 0 -or $Loose -gt 0) { "$($File.FullName): START=$Start END=$End loose=$Loose" }
        }
        $Bad | Should -BeNullOrEmpty
    }

    It 'is present in every core wrapper the routing depends on' -ForEach @(
        'New-GraphGetRequest', 'New-GraphPOSTRequest', 'New-GraphBulkRequest', 'New-GraphMultiTenantBulkRequest', 'New-ExoRequest', 'New-ExoBulkRequest',
        'Get-GraphToken', 'Get-GraphTokenFromCert', 'New-CIPPCertificateAssertion', 'Get-ClassicAPIToken', 'New-TeamsRequestV2'
    ) {
        $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
        Get-Content -Raw -Path (Join-Path $RepoRoot "Modules/CIPPCore/Public/GraphHelper/$_.ps1") | Should -Match '# \[SOVRATIS OVERRIDE START\]'
    }
}
