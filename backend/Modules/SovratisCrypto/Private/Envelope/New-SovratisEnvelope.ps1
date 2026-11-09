function New-SovratisEnvelope {
    <#
    .SYNOPSIS
        AES-256-GCM encrypts a string into the self-describing envelope
        sov1.<b64url header>.<b64url nonce>.<b64url ciphertext>.<b64url tag>
    .DESCRIPTION
        A fresh random 96-bit nonce is generated per call. The header carries the RDK id (never key
        material). The AAD is authenticated but not stored.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Plaintext,
        [Parameter(Mandatory)][byte[]]$Dek,
        [Parameter(Mandatory)][byte[]]$Aad,
        [Parameter(Mandatory)][string]$RdkId
    )
    if ($Dek.Length -ne 32) { throw 'DEK must be 32 bytes.' }
    $Nonce = [byte[]]::new(12)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($Nonce)
    $Plain = [System.Text.UTF8Encoding]::new($false, $true).GetBytes($Plaintext)
    $Cipher = [byte[]]::new($Plain.Length)
    $Tag = [byte[]]::new(16)
    $Aes = [System.Security.Cryptography.AesGcm]::new($Dek, 16)
    try {
        $Aes.Encrypt($Nonce, $Plain, $Cipher, $Tag, $Aad)
    } finally {
        $Aes.Dispose()
        [System.Array]::Clear($Plain, 0, $Plain.Length)
    }
    $Header = [ordered]@{ v = 1; alg = 'A256GCM'; kdf = 'HKDF-SHA256'; rdk = $RdkId } | ConvertTo-Json -Compress
    'sov1.{0}.{1}.{2}.{3}' -f (ConvertTo-SovratisB64Url ([System.Text.Encoding]::UTF8.GetBytes($Header))),
    (ConvertTo-SovratisB64Url $Nonce), (ConvertTo-SovratisB64Url $Cipher), (ConvertTo-SovratisB64Url $Tag)
}
