# Pass-through stand-ins for the SovratisCloud functions that the core wrappers call.
# Wrapper tests dot-source one wrapper file in isolation; without these the [SOVRATIS OVERRIDE] hooks would not
# resolve. Everything behaves as a Global tenant, i.e. exactly like upstream CIPP. Cloud routing itself is tested
# in SovratisCloud.Tests.ps1 and SovratisCloud.Wrappers.Tests.ps1.
function Get-SovratisCloudEnvironment { param($TenantFilter, [switch]$SkipCache) 'Global' }
function Resolve-SovratisUri { param($Uri, $TenantFilter, $CloudEnvironment) $Uri }
function Resolve-SovratisScope { param($Scope, $TenantFilter, $CloudEnvironment) $Scope }
function Get-SovratisCloudHost { param($Service, $TenantFilter, $CloudEnvironment) @{ Graph = 'graph.microsoft.com'; Authority = 'login.microsoftonline.com'; Exchange = 'outlook.office365.com' }[$Service] }
function Assert-SovratisServiceSupported { param($Service, $TenantFilter, $CloudEnvironment) }
function Get-SovratisCloudCredential { param($CloudEnvironment) [pscustomobject]@{ ApplicationId = $env:ApplicationID; ApplicationSecret = $env:ApplicationSecret; RefreshToken = $env:RefreshToken } }
# SovratisCrypto pass-throughs used by the table wrappers (Add-/Get-CIPPAzDataTableEntity).
function Protect-SovratisEntity { param($Table, [Parameter(ValueFromPipeline)]$Entity) process { $Entity } }
function Unprotect-SovratisEntity { param($Table, [Parameter(ValueFromPipeline)]$Entity) process { $Entity } }
