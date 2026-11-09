function Assert-SovratisKeyRefAllowed {
    <#
    .SYNOPSIS
        SSRF / confused-deputy guard: the key reference becomes a URL that receives a managed-identity bearer token.
    .DESCRIPTION
        https only, an exact managed-HSM host (<name>.managedhsm.azure.net), no port, no userinfo, and a
        /keys/<name>[/<version>] path. Returns the parsed parts.
    #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$KeyRef)
    if ($KeyRef -notmatch '^https://(?<host>[a-z0-9][a-z0-9-]{1,22}[a-z0-9])\.managedhsm\.azure\.net/keys/(?<name>[A-Za-z0-9-]{1,127})(?:/(?<version>[0-9a-f]{32}))?$') {
        throw "Key reference is not a valid Managed HSM key URL (expected https://<hsm>.managedhsm.azure.net/keys/<name>[/<version>])."
    }
    @{ Host = "$($Matches.host).managedhsm.azure.net"; Name = $Matches.name; Version = $Matches.version }
}
