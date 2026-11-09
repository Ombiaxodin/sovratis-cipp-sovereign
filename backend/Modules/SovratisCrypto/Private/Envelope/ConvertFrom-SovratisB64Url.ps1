function ConvertFrom-SovratisB64Url {
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Text)
    if ($Text -notmatch '^[A-Za-z0-9_-]*$') { throw 'Invalid base64url text.' }
    $Padded = $Text.Replace('-', '+').Replace('_', '/')
    switch ($Padded.Length % 4) { 2 { $Padded += '==' } 3 { $Padded += '=' } 1 { throw 'Invalid base64url length.' } }
    , [Convert]::FromBase64String($Padded)
}
