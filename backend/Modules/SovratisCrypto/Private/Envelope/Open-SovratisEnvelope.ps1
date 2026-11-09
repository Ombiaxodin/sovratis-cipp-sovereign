function Open-SovratisEnvelope {
    <#
    .SYNOPSIS
        Authenticates and decrypts a parsed envelope. Any failure (wrong key, wrong AAD, tampering)
        throws one generic error: no oracle about which part failed.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]$Envelope,
        [Parameter(Mandatory)][byte[]]$Dek,
        [Parameter(Mandatory)][byte[]]$Aad
    )
    $Plain = [byte[]]::new($Envelope.Ciphertext.Length)
    $Aes = [System.Security.Cryptography.AesGcm]::new($Dek, 16)
    try {
        try {
            $Aes.Decrypt($Envelope.Nonce, $Envelope.Ciphertext, $Envelope.Tag, $Plain, $Aad)
        } catch {
            throw 'Decryption failed: the data is corrupt, was modified, was moved, or the key does not match.'
        }
        [System.Text.UTF8Encoding]::new($false, $true).GetString($Plain)
    } finally {
        $Aes.Dispose()
        [System.Array]::Clear($Plain, 0, $Plain.Length)
    }
}
