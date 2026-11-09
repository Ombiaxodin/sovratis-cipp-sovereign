function ConvertTo-SovratisAad {
    <#
    .SYNOPSIS
        Builds the Additional Authenticated Data (AAD) that binds a ciphertext to where it lives.
    .DESCRIPTION
        AAD is authenticated by AES-GCM but never stored: it is recomputed from the caller's context on
        every read. A ciphertext copied to another tenant, table, row or property therefore fails
        authentication instead of decrypting.

        TenantId and Purpose are mandatory. Table, PartitionKey, RowKey and Property are optional and are
        bound when present (an absent field and an empty field encode identically, so the caller must pass
        the same set on Encrypt and Decrypt). Unknown keys throw, so a typo can never silently weaken the
        binding. TenantId is lower-cased (GUID casing is not significant); every other value is exact.
    #>
    [CmdletBinding()]
    [OutputType([byte[]])]
    param([Parameter(Mandatory)][hashtable]$Context)

    $Allowed = 'TenantId', 'Purpose', 'Table', 'PartitionKey', 'RowKey', 'Property'
    foreach ($Key in $Context.Keys) {
        if ($Key -notin $Allowed) { throw "Unsupported encryption context key '$Key'. Allowed: $($Allowed -join ', ')." }
    }
    foreach ($Required in 'TenantId', 'Purpose') {
        if ([string]::IsNullOrWhiteSpace([string]$Context[$Required])) { throw "Encryption context requires '$Required'." }
    }
    if ([string]$Context.Purpose -notmatch '^[A-Za-z0-9._-]{1,64}$') { throw 'Encryption context Purpose must match ^[A-Za-z0-9._-]{1,64}$.' }

    $Fields = @('sovratis-aad', 'v1', ([string]$Context.Purpose), ([string]$Context.TenantId).ToLowerInvariant())
    foreach ($Name in 'Table', 'PartitionKey', 'RowKey', 'Property') { $Fields += [string]$Context[$Name] }
    ConvertTo-SovratisLengthPrefixed -Field $Fields
}
