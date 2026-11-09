# Azure Managed HSM provider, Key Vault root-key store, policy and table hooks (all HTTP mocked).

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    $env:CIPPRootPath = $RepoRoot
    foreach ($File in Get-ChildItem -Path (Join-Path $RepoRoot 'Modules/SovratisCrypto') -Include *.ps1 -Recurse) { . $File.FullName }
    function Get-CIPPAzIdentityToken { param($ResourceUrl) "tok-$ResourceUrl" }
    function ConvertTo-CIPPODataFilterValue { param($Value, $Type) $Value }
    function Get-CippTable { param($tablename) @{ TableName = $tablename } }
    function Get-CIPPAzDataTableEntity { param($TableName, $Filter) }
    function Add-AzDataTableEntity { param($TableName, $Entity) }
    $script:Hsm = 'https://myhsm.managedhsm.azure.net/keys/sov-kek'
    $script:Pinned = "$script:Hsm/0123456789abcdef0123456789abcdef"
}

Describe 'Managed HSM provider' {
    It 'rejects key references that are not a managed HSM URL (SSRF guard)' {
        foreach ($Bad in 'http://myhsm.managedhsm.azure.net/keys/k', 'https://evil.example.com/keys/k', 'https://myhsm.managedhsm.azure.net.evil.com/keys/k', 'https://myhsm.managedhsm.azure.net:8443/keys/k', 'https://u@myhsm.managedhsm.azure.net/keys/k', 'https://myhsm.vault.azure.net/keys/k') {
            { Assert-SovratisKeyRefAllowed -KeyRef $Bad } | Should -Throw
        }
        (Assert-SovratisKeyRefAllowed -KeyRef $script:Pinned).Version | Should -Be '0123456789abcdef0123456789abcdef'
    }
    It 'wraps and unwraps via the pinned version with RSA-OAEP-256 and the HSM token' {
        $script:Calls = @()
        function Invoke-CIPPRestMethod { param($Method, $Uri, $Headers, $Body, $ContentType, $TimeoutSec, $ErrorAction)
            $script:Calls += @{ Uri = $Uri; Auth = $Headers.Authorization; Body = $Body }
            [pscustomobject]@{ value = 'AQID' } }
        $Out = Invoke-SovratisKekProvider_AzureManagedHsm -Operation Wrap -KeyRef $script:Pinned -Data ([byte[]](1, 2, 3))
        ($Out -join ',') | Should -Be '1,2,3'
        $script:Calls[0].Uri | Should -BeLike "$script:Pinned/wrapkey?api-version=*"
        $script:Calls[0].Auth | Should -Be 'Bearer tok-https://managedhsm.azure.net'
        ($script:Calls[0].Body | ConvertFrom-Json).alg | Should -Be 'RSA-OAEP-256'
    }
    It 'refuses to unwrap without a version-pinned key' {
        { Invoke-SovratisKekProvider_AzureManagedHsm -Operation Unwrap -KeyRef $script:Hsm -Data ([byte[]](1)) } | Should -Throw '*version-pinned*'
    }
    It 'Info returns the pinned reference; Health is read-only and flags a bad key' {
        $script:Calls = @()
        function Invoke-CIPPRestMethod { param($Method, $Uri, $Headers, $Body, $ContentType, $TimeoutSec, $ErrorAction)
            $script:Calls += $Method
            [pscustomobject]@{ key = [pscustomobject]@{ kid = $script:Pinned; kty = 'RSA-HSM'; key_ops = @('wrapKey') }; attributes = [pscustomobject]@{ enabled = $true } } }
        (Invoke-SovratisKekProvider_AzureManagedHsm -Operation Info -KeyRef $script:Hsm).KeyRef | Should -Be $script:Pinned
        $H = Invoke-SovratisKekProvider_AzureManagedHsm -Operation Health -KeyRef $script:Hsm
        $H.Healthy | Should -BeFalse
        $H.Detail | Should -BeLike '*unwrapKey*'
        ($script:Calls | Select-Object -Unique) | Should -Be 'GET'
    }
}

Describe 'Key Vault root key store' {
    BeforeEach { $env:SOVRATIS_RDK_VAULT = 'sov-keyplane' }
    It 'requires a valid vault name' {
        $env:SOVRATIS_RDK_VAULT = 'evil.com/x'
        { Invoke-SovratisRootKeyStore_KeyVault -Operation Latest } | Should -Throw '*valid Key Vault name*'
    }
    It 'reads the newest enabled sovratis-rdk secret and ignores others' {
        function Invoke-CIPPRestMethod { param($Method, $Uri, $Headers, $Body, $ContentType, $TimeoutSec, $ErrorAction)
            [pscustomobject]@{ value = @(
                    [pscustomobject]@{ id = 'https://sov-keyplane.vault.azure.net/secrets/sovratis-rdk-v2'; attributes = [pscustomobject]@{ enabled = $true } }
                    [pscustomobject]@{ id = 'https://sov-keyplane.vault.azure.net/secrets/sovratis-rdk-v10'; attributes = [pscustomobject]@{ enabled = $true } }
                    [pscustomobject]@{ id = 'https://sov-keyplane.vault.azure.net/secrets/sovratis-rdk-v11'; attributes = [pscustomobject]@{ enabled = $false } }
                    [pscustomobject]@{ id = 'https://sov-keyplane.vault.azure.net/secrets/other'; attributes = [pscustomobject]@{ enabled = $true } }) } }
        Invoke-SovratisRootKeyStore_KeyVault -Operation Latest | Should -Be 'sovratis-rdk-v10'
    }
    It 'rejects a paging link to a different host' {
        function Invoke-CIPPRestMethod { param($Method, $Uri, $Headers, $Body, $ContentType, $TimeoutSec, $ErrorAction)
            [pscustomobject]@{ value = @(); nextLink = 'https://evil.example.com/secrets' } }
        { Invoke-SovratisRootKeyStore_KeyVault -Operation Latest } | Should -Throw '*paging link*'
    }
    It 'refuses to overwrite an existing root key' {
        function Invoke-CIPPRestMethod { param($Method, $Uri, $Headers, $Body, $ContentType, $TimeoutSec, $ErrorAction) [pscustomobject]@{ value = '{}' } }
        { Invoke-SovratisRootKeyStore_KeyVault -Operation Put -Id 'sovratis-rdk-v1' -Blob @{ a = 1 } } | Should -Throw '*already exists*'
    }
    It 'the application path cannot create a root key outside development' {
        $env:AzureWebJobsStorage = 'DefaultEndpointsProtocol=https;AccountName=prod'; $env:NonLocalHostAzurite = $null
        $env:SOVRATIS_ENC_PROVIDER = 'AzureManagedHsm'; $env:SOVRATIS_KEK_REF = $script:Hsm
        function Invoke-CIPPRestMethod { param($Method, $Uri, $Headers, $Body, $ContentType, $TimeoutSec, $ErrorAction) [pscustomobject]@{ value = @() } }
        { Get-SovratisRootKey -ForWrite } | Should -Throw '*Initialize-SovratisRootKey*'
    }
}

Describe 'Policy and table hooks' {
    BeforeEach {
        $script:SovratisEncryptionPolicy = $null
        $script:SovratisKeyCache = $null
        $script:Store = @{}
        $env:AzureWebJobsStorage = 'UseDevelopmentStorage=true'
        $env:SOVRATIS_ENC_PROVIDER = 'LocalDevelopment'; $env:SOVRATIS_KEK_REF = 'dev-kek-1'; $env:SOVRATIS_ENC_MODE = $null
        $K = [byte[]]::new(32); [System.Security.Cryptography.RandomNumberGenerator]::Fill($K); $env:SOVRATIS_DEV_KEK = ConvertTo-SovratisB64Url $K
        function Get-CIPPAzDataTableEntity { param($TableName, $Filter)
            $pk = if ($Filter -match "PartitionKey eq '([^']+)'") { $Matches[1] }; $rk = if ($Filter -match "RowKey eq '([^']+)'") { $Matches[1] }
            $script:Store.Values | Where-Object { $_.T -eq $TableName -and $_.PartitionKey -eq $pk -and (-not $rk -or $_.RowKey -eq $rk) } | ForEach-Object { [pscustomobject]$_ } }
        function Add-AzDataTableEntity { param($TableName, $Entity) $k = "$TableName|$($Entity.PartitionKey)|$($Entity.RowKey)"; if ($script:Store.ContainsKey($k)) { throw 'Conflict' }; $script:Store[$k] = $Entity + @{ T = $TableName } }
    }
    It 'ships a policy limited to CippReportingDB and ApiClients' {
        $P = Get-SovratisEncryptionPolicy
        @($P.Keys | Sort-Object) | Should -Be @('ApiClients', 'CippReportingDB')
        $P.CippReportingDB.Properties | Should -Be @('Data')
    }
    It 'leaves other tables untouched and does not mutate caller objects' {
        $E = @{ PartitionKey = 't'; RowKey = 'r'; Data = 'plain' }
        (Protect-SovratisEntity -Table 'Tenants' -Entity $E).Data | Should -Be 'plain'
        $Out = Protect-SovratisEntity -Table 'CippReportingDB' -Entity $E
        $Out.Data | Should -BeLike 'sov1.*'
        $Out.PartitionKey | Should -Be 't'
        $E.Data | Should -Be 'plain'
    }
    It 'round-trips hashtables and objects, and keeps keys and other columns in clear' {
        $Obj = [pscustomobject]@{ PartitionKey = 'contoso.onmicrosoft.com'; RowKey = 'Users-1'; Data = '{"a":1}'; Type = 'Users'; Count = 5 }
        $Enc = Protect-SovratisEntity -Table 'CippReportingDB' -Entity $Obj
        $Enc.Type | Should -Be 'Users'; $Enc.Count | Should -Be 5
        $Dec = $Enc | Unprotect-SovratisEntity -Table 'CippReportingDB'
        $Dec.Data | Should -Be '{"a":1}'
    }
    It 'skips rows without the protected property (for example Count rows)' {
        $E = [pscustomobject]@{ PartitionKey = 't'; RowKey = 'Users-Count'; DataCount = 3 }
        (Protect-SovratisEntity -Table 'CippReportingDB' -Entity $E).DataCount | Should -Be 3
        ($E | Unprotect-SovratisEntity -Table 'CippReportingDB').DataCount | Should -Be 3
    }
    It 'rejects a non-string value in a protected property' {
        { Protect-SovratisEntity -Table 'ApiClients' -Entity @{ PartitionKey = 'ApiClients'; RowKey = 'a'; Role = 5 } } | Should -Throw '*must be a string*'
    }
    It 'drops a row whose protected value is plaintext (bypass/tamper) with an error, and keeps good rows' {
        $Good = Protect-SovratisEntity -Table 'ApiClients' -Entity @{ PartitionKey = 'ApiClients'; RowKey = 'good'; Role = 'editor'; IPRange = '["Any"]' }
        $Bad = [pscustomobject]@{ PartitionKey = 'ApiClients'; RowKey = 'bad'; Role = 'superadmin'; IPRange = '["Any"]' }
        $Out = @(@([pscustomobject]$Good, $Bad) | Unprotect-SovratisEntity -Table 'ApiClients' -ErrorVariable Err -ErrorAction SilentlyContinue)
        $Out.Count | Should -Be 1
        $Out[0].RowKey | Should -Be 'good'; $Out[0].Role | Should -Be 'editor'
        "$Err" | Should -BeLike "*RowKey 'bad'*"
        "$Err" | Should -Not -BeLike '*superadmin*'
    }
    It 'drops a row whose ciphertext was moved to another row' {
        $A = Protect-SovratisEntity -Table 'ApiClients' -Entity @{ PartitionKey = 'ApiClients'; RowKey = 'a'; Role = 'reader'; IPRange = '[]' }
        $Moved = [pscustomobject]@{ PartitionKey = 'ApiClients'; RowKey = 'admin'; Role = $A.Role; IPRange = $A.IPRange }
        @($Moved | Unprotect-SovratisEntity -Table 'ApiClients' -ErrorAction SilentlyContinue).Count | Should -Be 0
    }
    It 'passes non-entity output such as -Count through' {
        (5 | Unprotect-SovratisEntity -Table 'CippReportingDB') | Should -Be 5
    }
    It 'Disabled mode is honoured only with development storage' {
        $env:SOVRATIS_ENC_MODE = 'Disabled'
        (Protect-SovratisEntity -Table 'CippReportingDB' -Entity @{ PartitionKey = 't'; RowKey = 'r'; Data = 'x' }).Data | Should -Be 'x'
        $env:AzureWebJobsStorage = 'DefaultEndpointsProtocol=https;AccountName=prod'; $env:NonLocalHostAzurite = $null
        { Protect-SovratisEntity -Table 'CippReportingDB' -Entity @{ PartitionKey = 't'; RowKey = 'r'; Data = 'x' } } | Should -Throw '*development storage*'
    }
    It 'refuses a policy that tries to encrypt key columns' {
        $Dir = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid()); New-Item -ItemType Directory -Path "$Dir/Config" | Out-Null
        '{"version":1,"tables":{"Foo":{"purpose":"p","tenantFrom":"PartitionKey","properties":["RowKey"]}}}' | Set-Content "$Dir/Config/EncryptionPolicy.json"
        $Old = $env:CIPPRootPath; $env:CIPPRootPath = $Dir
        try { { Get-SovratisEncryptionPolicy -SkipCache } | Should -Throw '*cannot be encrypted*' } finally { $env:CIPPRootPath = $Old; Remove-Item $Dir -Recurse -Force }
    }
}
