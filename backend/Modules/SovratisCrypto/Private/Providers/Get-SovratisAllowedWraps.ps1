function Get-SovratisKeyRefBase {
    # Key reference without its version segment, so KEK rotation (new version, same key) stays trusted.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$KeyRef)
    $KeyRef -replace '/[0-9a-f]{32}$', ''
}

function Get-SovratisAllowedWraps {
    <#
    .SYNOPSIS
        The (provider, key) pairs this deployment trusts to wrap root keys.
    .DESCRIPTION
        SOVRATIS_ENC_PROVIDER + SOVRATIS_KEK_REF, plus optional SOVRATIS_ENC_EXTRA_WRAPS ('Provider=KeyRef;Provider=KeyRef')
        for the Phase 2 nested wrap.
    #>
    [CmdletBinding()]
    param()
    $Config = Get-SovratisEncryptionConfig
    $List = @(@{ Provider = $Config.Provider; KeyRef = (Get-SovratisKeyRefBase -KeyRef $Config.KeyRef) })
    foreach ($Pair in @("$env:SOVRATIS_ENC_EXTRA_WRAPS" -split ';' | Where-Object { $_ })) {
        $Provider, $Ref = $Pair -split '=', 2
        if ($Provider -and $Ref) { $List += @{ Provider = $Provider.Trim(); KeyRef = (Get-SovratisKeyRefBase -KeyRef $Ref.Trim()) } }
    }
    $List
}
