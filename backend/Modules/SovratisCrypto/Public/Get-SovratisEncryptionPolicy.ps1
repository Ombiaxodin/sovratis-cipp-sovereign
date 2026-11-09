function Get-SovratisEncryptionPolicy {
    <#
    .SYNOPSIS
        Loads and validates Config/EncryptionPolicy.json (which table properties are encrypted, and how they are bound).
    .DESCRIPTION
        Returns a hashtable: table name -> @{ Purpose; TenantFrom|Tenant; Properties }. Cached per runspace.
        Strict validation, because this file decides what is protected:
          - keys, Timestamp, ETag and odata columns are refused (keys must stay readable for filters, and a
            protected key would corrupt the AAD binding itself)
          - exactly one of tenantFrom='PartitionKey' or a fixed tenant label
          - purpose must be a safe token
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param([switch]$SkipCache)

    if (-not $SkipCache -and $script:SovratisEncryptionPolicy) { return $script:SovratisEncryptionPolicy }
    $Root = $env:CIPPRootPath
    if ([string]::IsNullOrWhiteSpace($Root)) { throw 'CIPPRootPath is not set. Cannot locate Config/EncryptionPolicy.json.' }
    $Raw = Get-Content -Path (Join-Path $Root 'Config/EncryptionPolicy.json') -Raw -ErrorAction Stop | ConvertFrom-Json -AsHashtable -ErrorAction Stop
    if ($Raw.version -ne 1) { throw 'EncryptionPolicy.json: unsupported version.' }

    $Reserved = 'PartitionKey', 'RowKey', 'Timestamp', 'ETag'
    $Policy = @{}
    foreach ($Table in $Raw.tables.Keys) {
        $T = $Raw.tables[$Table]
        if ($Table -notmatch '^[A-Za-z0-9]{3,63}$') { throw "EncryptionPolicy.json: invalid table name '$Table'." }
        if ([string]$T.purpose -notmatch '^[A-Za-z0-9._-]{1,64}$') { throw "EncryptionPolicy.json: table '$Table' needs a valid purpose." }
        $HasFrom = $T.tenantFrom -eq 'PartitionKey'
        $HasFixed = -not [string]::IsNullOrWhiteSpace($T.tenant)
        if ($HasFrom -eq $HasFixed) { throw "EncryptionPolicy.json: table '$Table' needs exactly one of tenantFrom='PartitionKey' or tenant." }
        $Props = @($T.properties)
        if ($Props.Count -eq 0) { throw "EncryptionPolicy.json: table '$Table' lists no properties." }
        foreach ($P in $Props) {
            if ($P -notmatch '^[A-Za-z][A-Za-z0-9_]{0,254}$' -or $P -in $Reserved -or $P -like 'odata*') { throw "EncryptionPolicy.json: property '$P' of '$Table' cannot be encrypted." }
        }
        $Policy[$Table] = @{
            Purpose    = [string]$T.purpose
            TenantFrom = $(if ($HasFrom) { 'PartitionKey' })
            Tenant     = $(if ($HasFixed) { ([string]$T.tenant).ToLowerInvariant() })
            Properties = [string[]]$Props
        }
    }
    $script:SovratisEncryptionPolicy = $Policy
    $Policy
}
