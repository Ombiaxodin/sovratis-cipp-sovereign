function Read-SovratisEnvelope {
    <#
    .SYNOPSIS
        Strictly parses an envelope string. Throws on anything that is not exactly a v1 envelope.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Text)

    $MaxChars = 16MB
    if ($Text.Length -gt $MaxChars) { throw 'Envelope exceeds the maximum size.' }
    $Parts = $Text.Split('.')
    if ($Parts.Count -ne 5 -or $Parts[0] -ne 'sov1') { throw 'Not a Sovratis v1 envelope.' }
    if ($Parts[1].Length -gt 1024) { throw 'Envelope header is too large.' }

    $Header = [System.Text.Encoding]::UTF8.GetString((ConvertFrom-SovratisB64Url $Parts[1])) | ConvertFrom-Json -AsHashtable -ErrorAction Stop
    if ($Header.v -ne 1 -or $Header.alg -ne 'A256GCM' -or $Header.kdf -ne 'HKDF-SHA256') { throw 'Unsupported envelope parameters.' }
    if ([string]$Header.rdk -notmatch '^[A-Za-z0-9._-]{1,64}$') { throw 'Invalid RDK id in envelope.' }

    $Nonce = ConvertFrom-SovratisB64Url $Parts[2]
    $Tag = ConvertFrom-SovratisB64Url $Parts[4]
    if ($Nonce.Length -ne 12) { throw 'Invalid nonce length.' }
    if ($Tag.Length -ne 16) { throw 'Invalid tag length.' }

    [pscustomobject]@{
        Header     = $Header
        Nonce      = $Nonce
        Ciphertext = (ConvertFrom-SovratisB64Url $Parts[3])
        Tag        = $Tag
    }
}
