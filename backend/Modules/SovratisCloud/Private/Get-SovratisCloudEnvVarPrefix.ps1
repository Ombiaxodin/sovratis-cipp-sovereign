function Get-SovratisCloudEnvVarPrefix {
    <#
    .SYNOPSIS
        Naming convention for a sovereign cloud's credential environment variables.
    .DESCRIPTION
        'DELOS' -> 'Delos', giving $env:DelosApplicationId, $env:DelosApplicationSecret and
        $env:DelosRefreshToken. Environment variable names are case-sensitive on Linux, so the
        casing here is part of the contract.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)]
        [string]$CloudEnvironment
    )
    return $CloudEnvironment.Substring(0, 1).ToUpperInvariant() + $CloudEnvironment.Substring(1).ToLowerInvariant()
}
