function Get-SovratisCloudCredential {
    <#
    .SYNOPSIS
        Returns the app credentials used to mint tokens in a cloud environment.
    .DESCRIPTION
        An app registration of the Global cloud cannot authenticate against a sovereign identity
        plane, so every non-Global cloud has its own credentials, supplied through dedicated
        environment variables:

          $env:<Cloud>ApplicationId      required   (DELOS: $env:DelosApplicationId)
          $env:<Cloud>ApplicationSecret  required   (DELOS: $env:DelosApplicationSecret)
          $env:<Cloud>RefreshToken       optional   fallback refresh token for flows that have no
                                                    per-tenant refresh token (DELOS: $env:DelosRefreshToken)

        Global returns the standard CIPP SAM variables unchanged.

        Fails closed: a sovereign cloud with a missing or placeholder ApplicationId/ApplicationSecret
        throws. It never falls back to the Global credentials, which would send a Global client id
        and secret to a sovereign authority.
    .PARAMETER CloudEnvironment
        Cloud name from the catalog.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$CloudEnvironment
    )

    if ($CloudEnvironment -eq 'Global') {
        return [pscustomobject]@{
            CloudEnvironment  = 'Global'
            ApplicationId     = $env:ApplicationID
            ApplicationSecret = $env:ApplicationSecret
            RefreshToken      = $env:RefreshToken
        }
    }

    $Catalog = Get-SovratisCloudCatalog
    if (-not $Catalog.ContainsKey($CloudEnvironment)) {
        throw "Unknown CloudEnvironment '$CloudEnvironment'."
    }
    $Prefix = Get-SovratisCloudEnvVarPrefix -CloudEnvironment $CloudEnvironment
    $AppId = [System.Environment]::GetEnvironmentVariable("${Prefix}ApplicationId")
    $Secret = [System.Environment]::GetEnvironmentVariable("${Prefix}ApplicationSecret")
    $Refresh = [System.Environment]::GetEnvironmentVariable("${Prefix}RefreshToken")

    $Placeholder = '^(LongApplicationId|AppSecret|RefreshToken|tenantId)$'
    if ([string]::IsNullOrWhiteSpace($AppId) -or $AppId -match $Placeholder -or [string]::IsNullOrWhiteSpace($Secret) -or $Secret -match $Placeholder) {
        throw "The '$CloudEnvironment' cloud has no credentials configured. Set the ${Prefix}ApplicationId and ${Prefix}ApplicationSecret environment variables. Refusing to use the Global credentials."
    }

    [pscustomobject]@{
        CloudEnvironment  = $CloudEnvironment
        ApplicationId     = $AppId
        ApplicationSecret = $Secret
        RefreshToken      = if ([string]::IsNullOrWhiteSpace($Refresh)) { $null } else { $Refresh }
    }
}
