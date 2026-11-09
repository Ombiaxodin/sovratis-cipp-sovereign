function Invoke-SovratisKekProvider {
    <#
    .SYNOPSIS
        Dispatcher for KEK providers (the component that holds the Key Encryption Key).
    .DESCRIPTION
        PowerShell has no interfaces, so a provider is a function named Invoke-SovratisKekProvider_<Name>
        with parameters (-Operation Wrap|Unwrap|Info|Health, -KeyRef, -Data [byte[]]) that returns byte[]
        (Wrap/Unwrap) or an object (Info/Health). Phase 2's external HSM is just another such function.
        The provider name is validated before it is used to build a command name.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Provider,
        [Parameter(Mandatory)][ValidateSet('Wrap', 'Unwrap', 'Info', 'Health')][string]$Operation,
        [Parameter(Mandatory)][string]$KeyRef,
        [byte[]]$Data,
        [string]$AccessToken
    )
    if ($Provider -notmatch '^[A-Za-z0-9]{1,40}$') { throw 'Invalid encryption provider name.' }
    $Fn = Get-Command -Name "Invoke-SovratisKekProvider_$Provider" -CommandType Function -ErrorAction SilentlyContinue
    if (-not $Fn) { throw "Unknown encryption provider '$Provider'." }
    $Params = @{ Operation = $Operation; KeyRef = $KeyRef; Data = $Data }
    if ($AccessToken) { $Params.AccessToken = $AccessToken }
    & $Fn @Params
}
