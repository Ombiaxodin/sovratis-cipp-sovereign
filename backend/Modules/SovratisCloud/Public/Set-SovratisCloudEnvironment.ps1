function Set-SovratisCloudEnvironment {
    <#
    .SYNOPSIS
        Stores the cloud environment for a tenant in the TenantProperties side-car table.
    .DESCRIPTION
        The value is WRITE-ONCE (immutable after onboarding). Moving a tenant between clouds would
        change how it authenticates (GDAP vs. Direct Tenant) and which credentials apply, so it is
        refused. The supported path is to remove the tenant and onboard it again, which calls
        Remove-SovratisCloudEnvironment. Re-submitting the value that is already stored is a no-op.

        Guard rails:
          - the value must exist in Config/CloudEnvironments.json
          - the partner tenant is always Global
          - a non-Global cloud is only allowed for Direct Tenants. Sovereign clouds do not use GDAP,
            so a GDAP tenant flagged as DELOS would resolve credentials through the wrong flow.

        On the first write the local cache entry and the tenant's cached tokens are dropped.
    .PARAMETER TenantFilter
        Tenant GUID or any of its domain names. The tenant must already exist in the Tenants table.
    .PARAMETER CloudEnvironment
        Name of an environment defined in the catalog, for example 'Global' or 'DELOS'.
    .PARAMETER Headers
        Request headers, forwarded to the audit log entry.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string]$TenantFilter,

        [Parameter(Mandatory)]
        [string]$CloudEnvironment,

        $Headers
    )

    $Catalog = Get-SovratisCloudCatalog
    if (-not $Catalog.ContainsKey($CloudEnvironment)) {
        throw "Unknown CloudEnvironment '$CloudEnvironment'. Valid values: $($Catalog.Keys -join ', ')."
    }
    $CloudEnvironment = @($Catalog.Keys).Where({ $_ -eq $CloudEnvironment })[0]

    $Tenant = Resolve-SovratisTenantId -TenantFilter $TenantFilter
    if (-not $Tenant) {
        throw "Tenant '$TenantFilter' was not found. Onboard the tenant before setting its CloudEnvironment."
    }
    if ($CloudEnvironment -ne 'Global') {
        if ($Tenant.customerId -eq $env:TenantID) {
            throw 'The partner tenant is always part of the Global cloud.'
        }
        if ($Tenant.delegatedPrivilegeStatus -ne 'directTenant') {
            throw "Tenant $($Tenant.defaultDomainName) is not a Direct Tenant. CloudEnvironment '$CloudEnvironment' requires the Direct Tenant flow (no GDAP)."
        }
    }

    # Immutability: an existing row may be confirmed but never changed.
    $PropertiesTable = Get-CippTable -tablename 'TenantProperties'
    $SafeId = ConvertTo-CIPPODataFilterValue -Value $Tenant.customerId -Type String
    $Existing = Get-CIPPAzDataTableEntity @PropertiesTable -Filter "PartitionKey eq '$SafeId' and RowKey eq 'CloudEnvironment'"
    if ($Existing -and -not [string]::IsNullOrWhiteSpace($Existing.Value)) {
        if ($Existing.Value -eq $CloudEnvironment) {
            return [pscustomobject]@{
                customerId          = $Tenant.customerId
                defaultDomainName   = $Tenant.defaultDomainName
                CloudEnvironment    = $CloudEnvironment
                PreviousEnvironment = $Existing.Value
            }
        }
        throw "CloudEnvironment of tenant $($Tenant.defaultDomainName) is '$($Existing.Value)' and is immutable. To move it to '$CloudEnvironment', remove the tenant and onboard it again."
    }

    $Previous = 'Global'
    if (-not $PSCmdlet.ShouldProcess($Tenant.defaultDomainName, "Set CloudEnvironment to $CloudEnvironment")) { return }

    $Entity = @{
        PartitionKey = [string]$Tenant.customerId
        RowKey       = 'CloudEnvironment'
        Value        = $CloudEnvironment
    }
    $null = Add-CIPPAzDataTableEntity @PropertiesTable -Entity $Entity -Force

    # Drop local cache entries (by GUID and by the filter the caller used).
    if ($script:SovratisCloudTenantCache) {
        foreach ($Key in @($Tenant.customerId, $TenantFilter, $Tenant.defaultDomainName, $Tenant.initialDomainName)) {
            if ($Key) { $script:SovratisCloudTenantCache.Remove($Key.ToLowerInvariant()) }
        }
    }
    # Tokens cached while the tenant was still implicitly Global must not outlive the decision.
    $null = Clear-CippTokenCache -TenantFilter $Tenant.customerId -Confirm:$false

    Write-LogMessage -headers $Headers -API 'SovratisCloud' -tenant $Tenant.defaultDomainName -TenantId $Tenant.customerId -message "CloudEnvironment set to '$CloudEnvironment'" -Sev 'Info'

    [pscustomobject]@{
        customerId          = $Tenant.customerId
        defaultDomainName   = $Tenant.defaultDomainName
        CloudEnvironment    = $CloudEnvironment
        PreviousEnvironment = $Previous
    }
}
