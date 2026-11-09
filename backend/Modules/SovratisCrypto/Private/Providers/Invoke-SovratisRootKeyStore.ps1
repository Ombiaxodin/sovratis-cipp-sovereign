function Invoke-SovratisRootKeyStore {
    <#
    .SYNOPSIS
        Dispatcher for WRAPPED root-key persistence. Operations: Latest | Get | Put (create-only).
    .DESCRIPTION
        LocalDevelopment -> Table store (dev only). Every other provider -> Key Vault secret store in the
        dedicated key-plane vault. Never Azure Tables in a deployed environment.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('Latest', 'Get', 'Put')][string]$Operation,
        [string]$Id,
        [hashtable]$Blob,
        [string]$AccessToken
    )
    $Config = Get-SovratisEncryptionConfig
    $Store = if ($Config.Provider -eq 'LocalDevelopment') { 'Table' } else { 'KeyVault' }
    $Params = @{ Operation = $Operation }
    if ($Id) { $Params.Id = $Id }
    if ($Blob) { $Params.Blob = $Blob }
    if ($AccessToken) { $Params.AccessToken = $AccessToken }
    & "Invoke-SovratisRootKeyStore_$Store" @Params
}
