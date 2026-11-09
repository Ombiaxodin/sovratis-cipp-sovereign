function ConvertTo-SovratisB64Url {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][AllowEmptyCollection()][byte[]]$Bytes)
    [Convert]::ToBase64String($Bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}
