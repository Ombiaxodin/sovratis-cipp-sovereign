function ConvertTo-SovratisLengthPrefixed {
    <#
    .SYNOPSIS
        Unambiguous, injection-proof encoding of an ordered field list: <utf8 byte length>:<value>;
    .DESCRIPTION
        A plain delimiter (for example '|') would let values that contain the delimiter shift between fields
        and collide. Length prefixes make every distinct field list encode to a distinct byte string.
        Used for both the AAD and the HKDF info, so neither can be confused with the other (each starts with
        its own domain-separation label).
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory)][AllowEmptyString()][string[]]$Field)
    $Utf8 = [System.Text.UTF8Encoding]::new($false, $true)
    $Stream = [System.IO.MemoryStream]::new()
    try {
        foreach ($Value in $Field) {
            $Bytes = $Utf8.GetBytes([string]$Value)
            $Prefix = $Utf8.GetBytes("$($Bytes.Length):")
            $Stream.Write($Prefix, 0, $Prefix.Length)
            $Stream.Write($Bytes, 0, $Bytes.Length)
            $Stream.WriteByte(0x3B) # ';'
        }
        , $Stream.ToArray()
    } finally { $Stream.Dispose() }
}
