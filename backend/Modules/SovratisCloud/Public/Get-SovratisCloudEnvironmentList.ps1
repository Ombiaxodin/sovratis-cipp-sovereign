function Get-SovratisCloudEnvironmentList {
    <#
    .SYNOPSIS
        Describes every cloud in the catalog for the UI (onboarding selector and sign-in popup).
    .DESCRIPTION
        Returns name, authority host, Graph host, the client id of the cloud's app registration and
        whether credentials are configured. Only public values are returned: the application id is
        not a secret (it is part of every sign-in URL), the secret and refresh token never leave
        the backend. Global comes first and is always configured.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param()

    $Catalog = Get-SovratisCloudCatalog
    $Names = @('Global') + @($Catalog.Keys | Where-Object { $_ -ne 'Global' } | Sort-Object)
    foreach ($Name in $Names) {
        $Services = $Catalog[$Name]
        if ($Name -eq 'Global') {
            [pscustomobject]@{ name = 'Global'; authority = $Services['Authority']; graph = $Services['Graph']; applicationId = $null; configured = $true }
            continue
        }
        $Prefix = Get-SovratisCloudEnvVarPrefix -CloudEnvironment $Name
        $AppId = [System.Environment]::GetEnvironmentVariable("${Prefix}ApplicationId")
        $Secret = [System.Environment]::GetEnvironmentVariable("${Prefix}ApplicationSecret")
        $Placeholder = '^(LongApplicationId|AppSecret|RefreshToken|tenantId)$'
        $Configured = -not [string]::IsNullOrWhiteSpace($AppId) -and $AppId -notmatch $Placeholder -and
        -not [string]::IsNullOrWhiteSpace($Secret) -and $Secret -notmatch $Placeholder -and
        -not [string]::IsNullOrWhiteSpace($Services['Authority']) -and -not [string]::IsNullOrWhiteSpace($Services['Graph'])
        [pscustomobject]@{
            name          = $Name
            authority     = $Services['Authority']
            graph         = $Services['Graph']
            applicationId = if ($Configured) { $AppId } else { $null }
            configured    = [bool]$Configured
        }
    }
}
