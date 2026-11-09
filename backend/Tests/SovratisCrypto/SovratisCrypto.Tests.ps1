# Pester tests for the SovratisCrypto module (envelope, AAD binding, HKDF, providers). No Azure needed.

BeforeAll {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $PSCommandPath))
    foreach ($File in Get-ChildItem -Path (Join-Path $RepoRoot 'Modules/SovratisCrypto') -Include *.ps1 -Recurse) { . $File.FullName }

    # In-memory stand-ins for CIPP table access
    $script:Store = @{}
    function ConvertTo-CIPPODataFilterValue { param($Value, $Type) $Value }
    function Get-CippTable { param($tablename) @{ TableName = $tablename } }
    function Get-CIPPAzDataTableEntity {
        param($TableName, $Filter)
        $pk = if ($Filter -match "PartitionKey eq '([^']+)'") { $Matches[1] }
        $rk = if ($Filter -match "RowKey eq '([^']+)'") { $Matches[1] }
        $script:Store.Values | Where-Object { $_.T -eq $TableName -and $_.PartitionKey -eq $pk -and (-not $rk -or $_.RowKey -eq $rk) } | ForEach-Object { [pscustomobject]$_ }
    }
    function Add-AzDataTableEntity {
        param($TableName, $Entity)
        $k = "$TableName|$($Entity.PartitionKey)|$($Entity.RowKey)"
        if ($script:Store.ContainsKey($k)) { throw 'Conflict' }
        $script:Store[$k] = $Entity + @{ T = $TableName }
    }
    function Merge-Ctx { param($Base, $Over) $h = $Base.Clone(); foreach ($k in $Over.Keys) { $h[$k] = $Over[$k] }; $h }
    $script:TenantA = 'aaaaaaaa-0000-0000-0000-00000000000a'
    $script:TenantB = 'bbbbbbbb-0000-0000-0000-00000000000b'
}

Describe 'SovratisCrypto' {
    BeforeEach {
        $script:Store = @{}
        $script:SovratisKeyCache = $null
        $env:AzureWebJobsStorage = 'UseDevelopmentStorage=true'
        $env:SOVRATIS_ENC_PROVIDER = 'LocalDevelopment'
        $env:SOVRATIS_KEK_REF = 'dev-kek-1'
        $Kek = [byte[]]::new(32); [System.Security.Cryptography.RandomNumberGenerator]::Fill($Kek)
        $env:SOVRATIS_DEV_KEK = ConvertTo-SovratisB64Url $Kek
        $script:Ctx = @{ TenantId = $script:TenantA; Purpose = 'ReportingData'; Table = 'CippReportingDB'; PartitionKey = 'p'; RowKey = 'r'; Property = 'Data' }
    }

    Describe 'HKDF (RFC 5869 test case 1)' {
        It 'matches the published vector' {
            $Ikm = [byte[]](@(0x0b) * 22)
            $Salt = [byte[]](0..12)
            $Info = [byte[]](0xf0..0xf9)
            $Okm = [System.Security.Cryptography.HKDF]::DeriveKey([System.Security.Cryptography.HashAlgorithmName]::SHA256, $Ikm, 42, $Salt, $Info)
            ([BitConverter]::ToString($Okm) -replace '-').ToLower() | Should -Be '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865'
        }
    }

    Describe 'AAD' {
        It 'is deterministic and tenant-case-insensitive' {
            $a = ConvertTo-SovratisAad -Context $script:Ctx
            $b = ConvertTo-SovratisAad -Context (Merge-Ctx $script:Ctx @{ TenantId = $script:TenantA.ToUpper() })
            [Convert]::ToBase64String($a) | Should -Be ([Convert]::ToBase64String($b))
        }
        It 'does not collide when values contain delimiters' {
            $a = ConvertTo-SovratisAad -Context @{ TenantId = 't'; Purpose = 'p'; PartitionKey = 'a|b'; RowKey = 'c' }
            $b = ConvertTo-SovratisAad -Context @{ TenantId = 't'; Purpose = 'p'; PartitionKey = 'a'; RowKey = 'b|c' }
            [Convert]::ToBase64String($a) | Should -Not -Be ([Convert]::ToBase64String($b))
        }
        It 'requires TenantId and Purpose and rejects unknown keys' {
            { ConvertTo-SovratisAad -Context @{ Purpose = 'p' } } | Should -Throw '*TenantId*'
            { ConvertTo-SovratisAad -Context @{ TenantId = 't' } } | Should -Throw '*Purpose*'
            { ConvertTo-SovratisAad -Context @{ TenantId = 't'; Purpose = 'p'; Tabel = 'x' } } | Should -Throw '*Unsupported*'
        }
    }

    Describe 'Encrypt / Decrypt' {
        It 'round-trips, including empty and unicode strings' {
            foreach ($Text in 'secret-token', '', 'Grüße 🔐 ' + ('x' * 50000)) {
                $Enc = Invoke-SovratisEncryption -Operation Encrypt -Data $Text -Context $script:Ctx
                $Enc | Should -BeLike 'sov1.*'
                (Invoke-SovratisEncryption -Operation Decrypt -Data $Enc -Context $script:Ctx) | Should -Be $Text
            }
        }
        It 'never contains the plaintext and is non-deterministic' {
            $a = Invoke-SovratisEncryption -Operation Encrypt -Data 'topsecret' -Context $script:Ctx
            $b = Invoke-SovratisEncryption -Operation Encrypt -Data 'topsecret' -Context $script:Ctx
            $a | Should -Not -BeLike '*topsecret*'
            $a | Should -Not -Be $b
        }
        It 'fails when the ciphertext is moved to another tenant, table, row or property' {
            $Enc = Invoke-SovratisEncryption -Operation Encrypt -Data 'x' -Context $script:Ctx
            foreach ($Change in @{ TenantId = $script:TenantB }, @{ Table = 'Other' }, @{ PartitionKey = 'q' }, @{ RowKey = 's' }, @{ Property = 'Other' }, @{ Purpose = 'ApiSecret' }) {
                { Invoke-SovratisEncryption -Operation Decrypt -Data $Enc -Context (Merge-Ctx $script:Ctx $Change) } | Should -Throw '*Decryption failed*'
            }
        }
        It 'fails on tampering with any envelope part' {
            $Enc = Invoke-SovratisEncryption -Operation Encrypt -Data 'abcdef' -Context $script:Ctx
            $P = $Enc.Split('.')
            foreach ($i in 2, 3, 4) {
                $Bytes = ConvertFrom-SovratisB64Url $P[$i]; $Bytes[0] = $Bytes[0] -bxor 1
                $Q = $P.Clone(); $Q[$i] = ConvertTo-SovratisB64Url $Bytes
                { Invoke-SovratisEncryption -Operation Decrypt -Data ($Q -join '.') -Context $script:Ctx } | Should -Throw
            }
        }
        It 'fails when the tenant salt is replaced (crypto-shred)' {
            $Enc = Invoke-SovratisEncryption -Operation Encrypt -Data 'x' -Context $script:Ctx
            @($script:Store.Keys) | Where-Object { $_ -like '*EncSalt' } | ForEach-Object { $script:Store.Remove($_) }
            $script:SovratisKeyCache = $null
            { Invoke-SovratisEncryption -Operation Decrypt -Data $Enc -Context $script:Ctx } | Should -Throw '*Decryption failed*'
        }
        It 'derives different keys per tenant and purpose' {
            $Root = Get-SovratisRootKey -ForWrite
            $a = Get-SovratisDek -Root $Root -TenantId $script:TenantA -Purpose 'p1'
            $b = Get-SovratisDek -Root $Root -TenantId $script:TenantB -Purpose 'p1'
            $c = Get-SovratisDek -Root $Root -TenantId $script:TenantA -Purpose 'p2'
            @([Convert]::ToBase64String($a), [Convert]::ToBase64String($b), [Convert]::ToBase64String($c) | Select-Object -Unique).Count | Should -Be 3
        }
        It 'decrypts after the key cache is dropped (RDK is persisted wrapped)' {
            $Enc = Invoke-SovratisEncryption -Operation Encrypt -Data 'persist' -Context $script:Ctx
            Clear-SovratisKeyCache; $script:SovratisKeyCache = $null
            (Invoke-SovratisEncryption -Operation Decrypt -Data $Enc -Context $script:Ctx) | Should -Be 'persist'
        }
        It 'stores the RDK only wrapped' {
            $null = Invoke-SovratisEncryption -Operation Encrypt -Data 'x' -Context $script:Ctx
            $Blob = ($script:Store.Values | Where-Object { $_.T -eq 'SovratisDevKeys' }).Blob | ConvertFrom-Json -AsHashtable
            (ConvertFrom-SovratisB64Url $Blob.wrapped).Length | Should -Be 60   # 12 nonce + 16 tag + 32 key
            $Blob.wraps[0].provider | Should -Be 'LocalDevelopment'
        }
    }

    Describe 'Envelope validation' {
        It 'IsEnvelope is true only for well-formed v1 envelopes' {
            $Enc = Invoke-SovratisEncryption -Operation Encrypt -Data 'x' -Context $script:Ctx
            Invoke-SovratisEncryption -Operation IsEnvelope -Data $Enc | Should -BeTrue
            foreach ($Bad in 'plain text', 'sov1.a.b.c', "sov2.$($Enc.Substring(5))", '', 'sov1....') {
                Invoke-SovratisEncryption -Operation IsEnvelope -Data $Bad | Should -BeFalse
            }
        }
        It 'rejects bad nonce / tag lengths and unknown parameters' {
            $Enc = Invoke-SovratisEncryption -Operation Encrypt -Data 'x' -Context $script:Ctx
            $P = $Enc.Split('.')
            { Read-SovratisEnvelope -Text (($P[0], $P[1], 'AAAA', $P[3], $P[4]) -join '.') } | Should -Throw '*nonce*'
            { Read-SovratisEnvelope -Text (($P[0], $P[1], $P[2], $P[3], 'AAAA') -join '.') } | Should -Throw '*tag*'
            $H = ConvertTo-SovratisB64Url ([Text.Encoding]::UTF8.GetBytes('{"v":1,"alg":"A128CBC","kdf":"HKDF-SHA256","rdk":"x"}'))
            { Read-SovratisEnvelope -Text (($P[0], $H, $P[2], $P[3], $P[4]) -join '.') } | Should -Throw '*Unsupported*'
        }
    }

    Describe 'Fail closed' {
        It 'throws without configuration instead of returning plaintext' {
            $env:SOVRATIS_ENC_PROVIDER = $null
            { Invoke-SovratisEncryption -Operation Encrypt -Data 'x' -Context $script:Ctx } | Should -Throw '*SOVRATIS_ENC_PROVIDER*'
        }
        It 'refuses the LocalDevelopment provider outside development storage' {
            $env:AzureWebJobsStorage = 'DefaultEndpointsProtocol=https;AccountName=prod'
            $env:NonLocalHostAzurite = $null
            { Invoke-SovratisEncryption -Operation Encrypt -Data 'x' -Context $script:Ctx } | Should -Throw '*development storage*'
        }
        It 'rejects unknown and malformed providers' {
            { Invoke-SovratisKekProvider -Provider 'Nope' -Operation Wrap -KeyRef 'k' -Data ([byte[]]@(1)) } | Should -Throw '*Unknown*'
            { Invoke-SovratisKekProvider -Provider 'a;b' -Operation Wrap -KeyRef 'k' -Data ([byte[]]@(1)) } | Should -Throw '*Invalid*'
        }
        It 'the ExternalHsm placeholder is not silently usable' {
            { Invoke-SovratisKekProvider -Provider 'ExternalHsm' -Operation Wrap -KeyRef 'k' -Data ([byte[]]@(1)) } | Should -Throw '*Phase 2*'
        }
    }

    Describe 'Nested wraps (Phase 2 readiness)' {
        It 'unwraps a two-wrap blob in reverse order' {
            function Invoke-SovratisKekProvider_SecondTest { param($Operation, $KeyRef, [byte[]]$Data) $r = [byte[]]($Data | ForEach-Object { $_ -bxor 0x5A }); , $r }
            $Rdk = [byte[]]::new(32); [System.Security.Cryptography.RandomNumberGenerator]::Fill($Rdk)
            $W1 = Invoke-SovratisKekProvider -Provider LocalDevelopment -Operation Wrap -KeyRef 'dev-kek-1' -Data $Rdk
            $W2 = Invoke-SovratisKekProvider -Provider SecondTest -Operation Wrap -KeyRef 'k2' -Data $W1
            $Blob = @{ id = 'sovratis-rdk-v1'; wraps = @(@{ provider = 'LocalDevelopment'; keyRef = 'dev-kek-1' }, @{ provider = 'SecondTest'; keyRef = 'k2' }); wrapped = (ConvertTo-SovratisB64Url $W2) }
            $script:Store['x|rdk|sovratis-rdk-v1'] = @{ T = 'SovratisDevKeys'; PartitionKey = 'rdk'; RowKey = 'sovratis-rdk-v1'; Blob = ($Blob | ConvertTo-Json -Depth 5 -Compress) }
            $env:SOVRATIS_ENC_EXTRA_WRAPS = 'SecondTest=k2'
            $Root = Get-SovratisRootKey -Id 'sovratis-rdk-v1'
            $env:SOVRATIS_ENC_EXTRA_WRAPS = $null
            [Convert]::ToBase64String($Root.Key) | Should -Be ([Convert]::ToBase64String($Rdk))
        }
    }

    Describe 'Untrusted wraps' {
        It 'rejects a root key blob that names an untrusted provider or key' {
            $Blob = @{ id = 'sovratis-rdk-v1'; wraps = @(@{ provider = 'LocalDevelopment'; keyRef = 'attacker-kek' }); wrapped = 'AAAA' }
            $script:Store['x|rdk|sovratis-rdk-v1'] = @{ T = 'SovratisDevKeys'; PartitionKey = 'rdk'; RowKey = 'sovratis-rdk-v1'; Blob = ($Blob | ConvertTo-Json -Depth 5 -Compress) }
            { Get-SovratisRootKey -Id 'sovratis-rdk-v1' } | Should -Throw '*does not trust*'
        }
        It 'accepts a new key version of the same key (KEK rotation)' {
            Get-SovratisKeyRefBase -KeyRef 'https://h.managedhsm.azure.net/keys/k/0123456789abcdef0123456789abcdef' | Should -Be 'https://h.managedhsm.azure.net/keys/k'
        }
    }

    Describe 'Health' {
        It 'is healthy and strictly side-effect free (writes nothing, creates no root key)' {
            $R = Invoke-SovratisEncryption -Operation Health
            $R.Healthy | Should -BeTrue
            $R.RootKeyProvisioned | Should -BeFalse
            $script:Store.Count | Should -Be 0
            # idempotent
            (Invoke-SovratisEncryption -Operation Health).Healthy | Should -BeTrue
            $script:Store.Count | Should -Be 0
        }
        It 'reports a provisioned root key and still writes nothing' {
            $null = Invoke-SovratisEncryption -Operation Encrypt -Data 'x' -Context $script:Ctx
            $Before = $script:Store.Count
            $R = Invoke-SovratisEncryption -Operation Health
            $R.RootKeyProvisioned | Should -BeTrue
            $script:Store.Count | Should -Be $Before
        }
        It 'reports problems instead of throwing when unconfigured' {
            $env:SOVRATIS_ENC_PROVIDER = $null
            $R = Invoke-SovratisEncryption -Operation Health
            $R.Healthy | Should -BeFalse
            $R.Problems | Should -Not -BeNullOrEmpty
        }
    }
}
