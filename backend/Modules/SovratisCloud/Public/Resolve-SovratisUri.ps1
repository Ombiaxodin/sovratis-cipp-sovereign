function Resolve-SovratisUri {
    <#
    .SYNOPSIS
        Rewrites a Global-cloud URI to the endpoint host of the tenant's cloud environment.
    .DESCRIPTION
        This is the one place where routing happens. The API wrappers call it just before sending
        a request. CIPP call sites pass absolute Global URLs (about 700 files), so the host is
        swapped rather than a base URL prepended.

        Behaviour:
          - Global tenant: the URI is returned untouched without parsing, so upstream behaviour
            and performance are unchanged.
          - The host is matched exactly, or as a subdomain, against the Global column of the
            catalog. Subdomains are preserved: '<region>.ps.compliance.protection.outlook.com'
            becomes '<region>.<DELOS compliance host>', and '<vault>.vault.azure.net' becomes
            '<vault>.<DELOS vault host>'.
          - Path, query, port and scheme are preserved.
          - Relative URLs (for example '/organization' inside a $batch body), non-URL values and
            hosts outside the catalog pass through unchanged. That also makes the function
            idempotent: an already-resolved URI is not rewritten again.
          - Fail closed: if the host is a known Global service but the target cloud defines no
            host for it, this throws. It never falls back to the Global host.
    .PARAMETER Uri
        The URI to resolve. Accepts pipeline input.
    .PARAMETER TenantFilter
        Tenant GUID or domain whose cloud decides the mapping.
    .PARAMETER CloudEnvironment
        Explicit cloud name. Overrides the tenant lookup (used during onboarding).
    .EXAMPLE
        Resolve-SovratisUri -Uri 'https://graph.microsoft.com/beta/users?$top=5' -TenantFilter $tenant
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Uri,

        [string]$TenantFilter,
        [string]$CloudEnvironment
    )

    process {
        if ([string]::IsNullOrWhiteSpace($Uri)) { return $Uri }

        if (-not $CloudEnvironment) {
            $CloudEnvironment = Get-SovratisCloudEnvironment -TenantFilter $TenantFilter
        }
        if ($CloudEnvironment -eq 'Global') { return $Uri }

        $Catalog = Get-SovratisCloudCatalog
        if (-not $Catalog.ContainsKey($CloudEnvironment)) {
            throw "Unknown CloudEnvironment '$CloudEnvironment'."
        }
        $Source = $Catalog['Global']
        $Target = $Catalog[$CloudEnvironment]

        if ($Uri -notmatch '^(?<scheme>https?://)(?<host>[^/:?#]+)(?<rest>[:/?#].*)?$') { return $Uri }
        $UriHost = $Matches['host'].ToLowerInvariant()

        foreach ($Service in $Source.Keys) {
            $GlobalHost = $Source[$Service]
            if ($UriHost -eq $GlobalHost -or $UriHost.EndsWith(".$GlobalHost")) {
                $TargetHost = $Target[$Service]
                if ([string]::IsNullOrWhiteSpace($TargetHost)) {
                    throw "CloudEnvironment '$CloudEnvironment' has no '$Service' endpoint in CloudEnvironments.json. Refusing to send '$UriHost' traffic to the Global cloud."
                }
                $SubdomainPrefix = $UriHost.Substring(0, $UriHost.Length - $GlobalHost.Length)
                return '{0}{1}{2}{3}' -f $Matches['scheme'], $SubdomainPrefix, $TargetHost, $Matches['rest']
            }
        }
        return $Uri
    }
}
