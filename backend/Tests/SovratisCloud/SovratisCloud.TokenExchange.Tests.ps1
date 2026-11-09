# ExecTokenExchange for sovereign clouds. The token endpoint stays pinned (derived from the server-side catalog, not
# from the caller) and the exchange runs as the cloud's own app. Global behaviour is covered by
# Tests/CIPP/Invoke-ExecTokenExchange.Grant.Tests.ps1.

BeforeAll {
    $BackendRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $env:CIPPRootPath = $BackendRoot
    $FunctionPath = Join-Path $BackendRoot 'Modules/CIPPHTTP/Public/Entrypoints/HTTP Functions/CIPP/Setup/Invoke-ExecTokenExchange.ps1'

    ([PSObject].Assembly.GetType('System.Management.Automation.TypeAccelerators')).GetMethod('Add').Invoke(
        $null, @('HttpStatusCode', [System.Net.HttpStatusCode]))
    class HttpResponseContext {
        [int]$StatusCode
        [object]$Body
        [object]$Headers
    }

    foreach ($File in Get-ChildItem -Path (Join-Path $BackendRoot 'Modules/SovratisCloud') -Include *.ps1 -Recurse) { . $File.FullName }

    function Get-CippKeyVaultName { 'kv' }
    function Get-CIPPAuthentication { $true }
    function Get-CippKeyVaultSecret { param($VaultName, $Name, [switch]$AsPlainText) }
    function Get-CIPPSAMCertificate { param([switch]$SkipCache) throw 'the SAM certificate must never be used for a sovereign cloud' }
    function New-CIPPCertificateAssertion { param($TenantId, $AppId, $Certificate, $Audience) throw 'no assertion for a sovereign cloud' }
    function Write-LogMessage { param($API, $message, $Sev) }

    . $FunctionPath

    $script:GlobalUrl = 'https://login.microsoftonline.com/organizations/oauth2/v2.0/token'
    $script:DelosUrl = 'https://login.microsoftonline.delos.cloud/organizations/oauth2/v2.0/token'

    function New-Req {
        param($Cloud, $TokenUrl, $TokenRequest)
        $Body = [pscustomobject]@{ tokenRequest = $TokenRequest; tokenUrl = $TokenUrl; tenantId = 'app-id' }
        if ($Cloud) { $Body | Add-Member -NotePropertyName cloudEnvironment -NotePropertyValue $Cloud }
        [pscustomobject]@{ Params = @{ CIPPEndpoint = 'ExecTokenExchange' }; Body = $Body }
    }
    $script:Code = [pscustomobject]@{ grant_type = 'authorization_code'; client_id = 'attacker-app'; code = 'c'; redirect_uri = 'https://cipp/authredirect'; code_verifier = 'v' }
}

Describe 'Invoke-ExecTokenExchange sovereign cloud' {
    BeforeEach {
        $script:Saved = @{}
        foreach ($Name in 'ApplicationSecret', 'ApplicationID', 'CertificateAuthMode', 'DelosApplicationId', 'DelosApplicationSecret') { $script:Saved[$Name] = [Environment]::GetEnvironmentVariable($Name) }
        $env:ApplicationSecret = 'sam-secret'
        $env:ApplicationID = '11111111-1111-1111-1111-111111111111'
        $env:DelosApplicationId = 'delos-app'
        $env:DelosApplicationSecret = 'delos-secret'
        Remove-Item Env:\CertificateAuthMode -ErrorAction SilentlyContinue
        $script:Captured = $null
        Mock Invoke-RestMethod { $script:CapturedUri = $Uri; $script:Captured = $Body; @{ access_token = 'token' } }
    }
    AfterEach {
        foreach ($Name in $script:Saved.Keys) { if ($null -eq $script:Saved[$Name]) { Remove-Item "env:$Name" -ErrorAction SilentlyContinue } else { Set-Item "env:$Name" -Value $script:Saved[$Name] } }
    }

    It 'exchanges against the DELOS authority as the DELOS app, ignoring caller-supplied credentials' {
        $Resp = Invoke-ExecTokenExchange -Request (New-Req 'DELOS' $script:DelosUrl $script:Code)
        $Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
        $script:CapturedUri | Should -Be $script:DelosUrl
        $script:Captured['client_id'] | Should -Be 'delos-app'
        $script:Captured['client_secret'] | Should -Be 'delos-secret'
        $script:Captured.Keys | Should -Not -Contain 'client_assertion'
    }

    It 'never uses a certificate assertion for DELOS, even in certificate-exclusive mode' {
        $env:CertificateAuthMode = 'true'
        $Resp = Invoke-ExecTokenExchange -Request (New-Req 'DELOS' $script:DelosUrl $script:Code)
        $Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
        $script:Captured['client_secret'] | Should -Be 'delos-secret'
    }

    It 'rejects the Global endpoint for a DELOS request, so the DELOS secret cannot go to Global' {
        $Resp = Invoke-ExecTokenExchange -Request (New-Req 'DELOS' $script:GlobalUrl $script:Code)
        $Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
    }

    It 'rejects the DELOS endpoint for a Global request, so the SAM secret cannot go to DELOS' {
        $Resp = Invoke-ExecTokenExchange -Request (New-Req $null $script:DelosUrl $script:Code)
        $Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
    }

    It 'rejects an arbitrary host that merely ends like the DELOS authority' {
        $Resp = Invoke-ExecTokenExchange -Request (New-Req 'DELOS' 'https://evil.example/login.microsoftonline.delos.cloud/organizations/oauth2/v2.0/token' $script:Code)
        $Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
    }

    It 'rejects an unknown cloud name' {
        $Resp = Invoke-ExecTokenExchange -Request (New-Req 'Mars' $script:DelosUrl $script:Code)
        $Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::BadRequest)
        $Resp.Body.error_description | Should -BeLike '*Invalid cloudEnvironment*'
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
    }

    It 'fails closed when the DELOS app is not configured and does not use the SAM app instead' {
        Remove-Item Env:\DelosApplicationSecret
        $Resp = Invoke-ExecTokenExchange -Request (New-Req 'DELOS' $script:DelosUrl $script:Code)
        $Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::InternalServerError)
        $Resp.Body.error_description | Should -BeLike '*no credentials configured*'
        Should -Invoke Invoke-RestMethod -Times 0 -Exactly
    }

    It 'still serves Global requests with the SAM app' {
        $Resp = Invoke-ExecTokenExchange -Request (New-Req $null $script:GlobalUrl $script:Code)
        $Resp.StatusCode | Should -Be ([System.Net.HttpStatusCode]::OK)
        $script:CapturedUri | Should -Be $script:GlobalUrl
        $script:Captured['client_id'] | Should -Be '11111111-1111-1111-1111-111111111111'
        $script:Captured['client_secret'] | Should -Be 'sam-secret'
    }
}
