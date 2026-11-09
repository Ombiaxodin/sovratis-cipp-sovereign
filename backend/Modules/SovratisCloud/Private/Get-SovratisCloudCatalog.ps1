function Get-SovratisCloudCatalog {
    <#
    .SYNOPSIS
        Loads and validates Config/CloudEnvironments.json.
    .DESCRIPTION
        Returns a hashtable of cloud name -> (service name -> host name). The catalog is the single
        source of truth for every endpoint host. It is cached per runspace.

        Validation is deliberately strict because the catalog drives routing for sovereign tenants:
          - a 'Global' entry must exist (it is the mapping source and the default)
          - hosts are bare host names (no scheme, path or port)
          - a non-Global cloud may leave a service out or blank. That is legal, and
            Resolve-SovratisUri then refuses to route that service for the cloud instead of
            falling back to the Global host.
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [switch]$SkipCache
    )

    if (-not $SkipCache -and $script:SovratisCloudCatalog) {
        return $script:SovratisCloudCatalog
    }

    $Root = $env:CIPPRootPath
    if ([string]::IsNullOrWhiteSpace($Root)) {
        throw 'CIPPRootPath is not set. Cannot locate Config/CloudEnvironments.json.'
    }
    $Path = Join-Path $Root 'Config/CloudEnvironments.json'
    $Raw = Get-Content -Path $Path -Raw -ErrorAction Stop | ConvertFrom-Json -AsHashtable -ErrorAction Stop

    # Re-key into plain (case-insensitive) hashtables so lookups do not depend on JSON casing.
    $Catalog = @{}
    foreach ($CloudName in $Raw.Keys) {
        if ($Raw[$CloudName] -isnot [System.Collections.IDictionary]) {
            throw "CloudEnvironments.json: entry '$CloudName' must be an object of service -> host."
        }
        $Services = @{}
        foreach ($Service in $Raw[$CloudName].Keys) {
            $HostName = [string]$Raw[$CloudName][$Service]
            if (-not [string]::IsNullOrWhiteSpace($HostName) -and $HostName -notmatch '^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$') {
                throw "CloudEnvironments.json: '$CloudName.$Service' must be a bare host name, got '$HostName'."
            }
            $Services[$Service] = $HostName.Trim().ToLowerInvariant()
        }
        $Catalog[$CloudName] = $Services
    }

    if (-not $Catalog.ContainsKey('Global')) {
        throw "CloudEnvironments.json must define a 'Global' environment."
    }
    foreach ($Service in $Catalog['Global'].Keys) {
        if ([string]::IsNullOrWhiteSpace($Catalog['Global'][$Service])) {
            throw "CloudEnvironments.json: 'Global.$Service' must not be empty."
        }
    }

    $script:SovratisCloudCatalog = $Catalog
    return $Catalog
}
