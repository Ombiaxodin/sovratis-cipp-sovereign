function Invoke-SovratisRootKeyStore_KeyVault {
    <#
    .SYNOPSIS
        Root-key store backed by Key Vault SECRETS in a dedicated key-plane vault.
    .DESCRIPTION
        Managed HSM holds KEYS only (no secrets API), so the HSM-wrapped Root Data Key lives as a secret in a
        separate, dedicated Key Vault ($env:SOVRATIS_RDK_VAULT), never in Table Storage. That separates the key
        plane from the data plane:
          - the Function App identity gets 'Key Vault Secrets User' (read only) on THIS vault
          - only the deployment pipeline / operators can write (Initialize-SovratisRootKey)
        The app path therefore can Latest and Get, and cannot create or change root keys. Put exists for the
        provisioning tool and refuses to overwrite.
        The stored value is useless without the HSM, but whoever can write the vault decides which root key is
        trusted, so write access must stay with the pipeline.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Operation,
        [string]$Id,
        [hashtable]$Blob,
        [string]$AccessToken
    )
    $Vault = $env:SOVRATIS_RDK_VAULT
    if ($Vault -notmatch '^[a-z0-9][a-z0-9-]{1,22}[a-z0-9]$') { throw 'SOVRATIS_RDK_VAULT is not set to a valid Key Vault name.' }
    $VaultHost = "$Vault.vault.azure.net"
    $Api = '7.4'
    $Token = if ($AccessToken) { $AccessToken } else { Get-CIPPAzIdentityToken -ResourceUrl 'https://vault.azure.net' }
    $Headers = @{ Authorization = "Bearer $Token" }
    $IdRegex = '^sovratis-rdk-v\d{1,6}$'

    $Call = {
        param($Method, $Uri, $Body)
        try {
            $P = @{ Method = $Method; Uri = $Uri; Headers = $Headers; ErrorAction = 'Stop'; TimeoutSec = 20 }
            if ($Body) { $P.Body = $Body; $P.ContentType = 'application/json' }
            Invoke-CIPPRestMethod @P
        } catch {
            $Status = [int]$_.Exception.Response.StatusCode
            if ($Status -eq 404) { return $null }
            throw "Key Vault $Method failed (HTTP $Status)."
        }
    }

    switch ($Operation) {
        'Latest' {
            $Names = [System.Collections.Generic.List[string]]::new()
            $Uri = "https://$VaultHost/secrets?api-version=$Api"
            while ($Uri) {
                $Page = & $Call 'GET' $Uri $null
                foreach ($Item in @($Page.value)) {
                    $Name = ($Item.id -split '/')[-1]
                    if ($Name -match $IdRegex -and $Item.attributes.enabled) { $Names.Add($Name) }
                }
                $Uri = $Page.nextLink
                if ($Uri -and ([uri]$Uri).Host -ne $VaultHost) { throw 'Key Vault returned an unexpected paging link.' }
            }
            if ($Names.Count) { $Names | Sort-Object { [int]($_ -replace '\D') } -Descending | Select-Object -First 1 }
        }
        'Get' {
            if ($Id -notmatch $IdRegex) { throw 'Invalid root key id.' }
            $Secret = & $Call 'GET' "https://$VaultHost/secrets/${Id}?api-version=$Api" $null
            if ($Secret) { $Secret.value | ConvertFrom-Json -AsHashtable }
        }
        'Put' {
            if ($Id -notmatch $IdRegex) { throw 'Invalid root key id.' }
            if (& $Call 'GET' "https://$VaultHost/secrets/${Id}?api-version=$Api" $null) { throw "Root key '$Id' already exists. Root keys are immutable; create the next version instead." }
            $Body = @{ value = ($Blob | ConvertTo-Json -Depth 5 -Compress); contentType = 'application/vnd.sovratis.rdk+json'; tags = @{ purpose = 'sovratis-rdk' } } | ConvertTo-Json -Compress
            $null = & $Call 'PUT' "https://$VaultHost/secrets/${Id}?api-version=$Api" $Body
        }
    }
}
