function Unprotect-SovratisEntity {
    <#
    .SYNOPSIS
        Read-side hook: decrypts the policy's properties of entities flowing through the pipeline.
    .DESCRIPTION
        Called by Get-CIPPAzDataTableEntity on the reassembled result (so decryption always sees whole values, never
        split parts). Items that are not entities (for example the integer from -Count) and every row of a table
        that is not in the policy pass through untouched.

        Fail closed per row: a protected property that is not a valid envelope (plaintext written by something that
        bypassed the wrapper, or tampering) or that fails authentication (moved, modified, wrong key) DROPS that row
        and emits a non-terminating error that names the table, keys and property but never any value. A dropped
        ApiClients row means that client is denied, which is the safe direction. This function deliberately does not
        call Write-LogMessage: logging itself reads ApiClients and would recurse.
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
        $IsDict = $Entity -is [System.Collections.IDictionary]
        $IsObject = $Entity -is [pscustomobject]
        if (-not $Active -or $Entity -is [string] -or $Entity -is [ValueType] -or -not ($IsDict -or $IsObject)) { $Entity; return }

        $Names = if ($IsDict) { @($Entity.Keys) } else { @($Entity.PSObject.Properties.Name) }
        $Get = { param($Name) if ($IsDict) { $Entity[$Name] } else { $Entity.PSObject.Properties[$Name].Value } }

        $Pk = [string](& $Get 'PartitionKey')
        $Rk = [string](& $Get 'RowKey')
        $TenantId = if ($Policy.TenantFrom) { $Pk } else { $Policy.Tenant }

        $Decrypted = @{}
        foreach ($Property in $Policy.Properties) {
            if ($Property -notin $Names) { continue }
            $Value = & $Get $Property
            if ($null -eq $Value) { continue }
            try {
                if ($Value -isnot [string] -or -not (Invoke-SovratisEncryption -Operation IsEnvelope -Data $Value)) {
                    throw 'value is not an encrypted envelope'
                }
                $Context = @{ TenantId = $TenantId; Purpose = $Policy.Purpose; Table = $Table; PartitionKey = $Pk; RowKey = $Rk; Property = $Property }
                $Decrypted[$Property] = Invoke-SovratisEncryption -Operation Decrypt -Data $Value -Context $Context
            } catch {
                Write-Error -Message "Sovratis encryption: row skipped. Table '$Table', PartitionKey '$Pk', RowKey '$Rk', property '$Property' could not be decrypted ($($_.Exception.Message))." -ErrorId 'SovratisDecryptFailed'
                return
            }
        }
        # Only mutate after every property succeeded, so a row is never emitted half-decrypted.
        foreach ($Property in $Decrypted.Keys) {
            if ($IsDict) { $Entity[$Property] = $Decrypted[$Property] } else { $Entity.PSObject.Properties[$Property].Value = $Decrypted[$Property] }
        }
        $Entity
    }
}
