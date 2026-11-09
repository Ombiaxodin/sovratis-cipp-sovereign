function Protect-SovratisEntity {
    <#
    .SYNOPSIS
        Write-side hook: returns COPIES of the entities with the policy's properties replaced by envelopes.
    .DESCRIPTION
        Called by Add-CIPPAzDataTableEntity before the write (and before the large-entity split). For a table that
        is not in the policy the input is emitted unchanged. For a protected table:
          - callers' objects are never mutated (they often reuse the entity after the write)
          - null properties are left alone (the table layer strips nulls); a non-string value in a protected
            property throws, because silently storing it in clear would defeat the policy
          - each value is bound to tenant, purpose, table, partition key, row key and property (AAD)
          - a value that merely looks like an envelope is encrypted like any other string
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Table,
        [Parameter(ValueFromPipeline)]$Entity
    )
    begin {
        $Policy = (Get-SovratisEncryptionPolicy)[$Table]
        $Active = $Policy -and ((Get-SovratisEncryptionMode) -eq 'Enforce')
    }
    process {
        if ($null -eq $Entity) { return }
        # An array passed by parameter (not piped) must be processed per element, never as one object.
        if ($Entity -is [System.Collections.IList]) { foreach ($Item in $Entity) { $Item | & $MyInvocation.MyCommand -Table $Table }; return }
        if (-not $Active) { $Entity; return }

        $IsDict = $Entity -is [System.Collections.IDictionary]
        $Copy = if ($IsDict) { $Entity.Clone() } else { $Entity.PSObject.Copy() }
        $Get = { param($Name) if ($IsDict) { $Copy[$Name] } else { $Copy.PSObject.Properties[$Name].Value } }
        $Has = { param($Name) if ($IsDict) { $Copy.Contains($Name) } else { [bool]$Copy.PSObject.Properties[$Name] } }

        $Pk = [string](& $Get 'PartitionKey')
        $Rk = [string](& $Get 'RowKey')
        $TenantId = if ($Policy.TenantFrom) { $Pk } else { $Policy.Tenant }

        foreach ($Property in $Policy.Properties) {
            if (-not (& $Has $Property)) { continue }
            $Value = & $Get $Property
            if ($null -eq $Value) { continue }
            if ($Value -isnot [string]) { throw "Property '$Property' of table '$Table' is protected by policy and must be a string, not $($Value.GetType().Name)." }
            $Context = @{ TenantId = $TenantId; Purpose = $Policy.Purpose; Table = $Table; PartitionKey = $Pk; RowKey = $Rk; Property = $Property }
            $Cipher = Invoke-SovratisEncryption -Operation Encrypt -Data $Value -Context $Context
            if ($IsDict) { $Copy[$Property] = $Cipher } else { $Copy.PSObject.Properties[$Property].Value = $Cipher }
        }
        $Copy
    }
}
