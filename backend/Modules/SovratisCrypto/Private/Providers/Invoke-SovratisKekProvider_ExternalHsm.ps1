function Invoke-SovratisKekProvider_ExternalHsm {
    # Phase 2 placeholder. Implements the same contract as the Azure provider; added to the RDK blob's wraps list
    # as a second, nested wrap so decryption needs both HSMs.
    [CmdletBinding()]
    param([string]$Operation, [string]$KeyRef, [byte[]]$Data, [string]$AccessToken)
    throw [System.NotImplementedException]::new('The ExternalHsm provider is a Phase 2 deliverable.')
}
