function Invoke-SovratisKekProvider_LocalDevelopment {
    <#
    .SYNOPSIS
        DEVELOPMENT ONLY KEK provider. The KEK is a 32-byte key in $env:SOVRATIS_DEV_KEK (base64url).
    .DESCRIPTION
        Exists so the whole stack can be developed and tested without an HSM. It is refused unless the app
        runs against local development storage (Azurite), so it can never be selected in a deployed
        environment by misconfiguration. Wrap = AES-256-GCM(nonce | tag | ciphertext), KeyRef is bound as AAD.
    #>
    [CmdletBinding()]
    param([string]$Operation, [string]$KeyRef, [byte[]]$Data, [string]$AccessToken)

    if (-not ($env:AzureWebJobsStorage -eq 'UseDevelopmentStorage=true' -or $env:NonLocalHostAzurite -eq 'true')) {
        throw 'The LocalDevelopment encryption provider is only allowed with local development storage.'
    }
    switch ($Operation) {
        'Info' { return [pscustomobject]@{ Provider = 'LocalDevelopment'; KeyRef = $KeyRef; Hsm = $false } }
        'Health' {
            $Ok = $false
            try {
                $Probe = [byte[]]::new(32); [System.Security.Cryptography.RandomNumberGenerator]::Fill($Probe)
                $W = Invoke-SovratisKekProvider_LocalDevelopment -Operation Wrap -KeyRef $KeyRef -Data $Probe
                $U = Invoke-SovratisKekProvider_LocalDevelopment -Operation Unwrap -KeyRef $KeyRef -Data $W
                $Ok = ([Convert]::ToBase64String($U) -eq [Convert]::ToBase64String($Probe))
            } catch { $Ok = $false }
            return [pscustomobject]@{ Provider = 'LocalDevelopment'; Healthy = $Ok; Detail = '' }
        }
    }
    if (-not $env:SOVRATIS_DEV_KEK) { throw 'SOVRATIS_DEV_KEK is not set.' }
    $Kek = ConvertFrom-SovratisB64Url $env:SOVRATIS_DEV_KEK
    if ($Kek.Length -ne 32) { throw 'SOVRATIS_DEV_KEK must be 32 bytes (base64url).' }
    $Aad = [System.Text.Encoding]::UTF8.GetBytes("sovratis-dev-kek|$KeyRef")
    $Aes = [System.Security.Cryptography.AesGcm]::new($Kek, 16)
    try {
        if ($Operation -eq 'Wrap') {
            $Nonce = [byte[]]::new(12); [System.Security.Cryptography.RandomNumberGenerator]::Fill($Nonce)
            $Cipher = [byte[]]::new($Data.Length); $Tag = [byte[]]::new(16)
            $Aes.Encrypt($Nonce, $Data, $Cipher, $Tag, $Aad)
            , [byte[]]($Nonce + $Tag + $Cipher)
        } else {
            if ($Data.Length -lt 28) { throw 'Wrapped key is too short.' }
            $Nonce = $Data[0..11]; $Tag = $Data[12..27]; $Cipher = [byte[]]($Data[28..($Data.Length - 1)])
            $Plain = [byte[]]::new($Cipher.Length)
            $Aes.Decrypt([byte[]]$Nonce, $Cipher, [byte[]]$Tag, $Plain, $Aad)
            , $Plain
        }
    } finally { $Aes.Dispose(); [System.Array]::Clear($Kek, 0, $Kek.Length) }
}
