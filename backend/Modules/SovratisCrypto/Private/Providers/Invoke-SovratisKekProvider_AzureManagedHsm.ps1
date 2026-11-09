function Invoke-SovratisKekProvider_AzureManagedHsm {
    <#
    .SYNOPSIS
        KEK provider backed by an Azure Managed HSM key (RSA-HSM, wrap/unwrap only, non-exportable).
    .DESCRIPTION
        Contract (see Invoke-SovratisKekProvider): byte[] in, byte[] out.
          Info    resolves the key's CURRENT version and returns the version-pinned KeyRef. The pinned ref is
                  what gets stored with the wrapped root key, so unwrap always targets the exact version.
          Health  read-only: key exists, enabled, RSA-HSM, wrapKey+unwrapKey allowed. Writes nothing.
          Wrap / Unwrap  RSA-OAEP-256 against the HSM.

        Authentication is the Function App managed identity (Get-CIPPAzIdentityToken), so no App Registration
        and no secret exist. The identity needs only the Managed HSM local RBAC role
        'Managed HSM Crypto Service Encryption User' scoped to this one key.

        Values marked [?] are NOT verified against Microsoft docs and must be confirmed in the first
        integration run: the token audience and the data-plane api-version.
    #>
    [CmdletBinding()]
    param(
        [string]$Operation,
        [string]$KeyRef,
        [byte[]]$Data,
        # Operator-supplied token (for the provisioning tool). Defaults to the managed identity.
        [string]$AccessToken
    )

    $Ref = Assert-SovratisKeyRefAllowed -KeyRef $KeyRef
    $ApiVersion = '7.4'                                   # [?] confirm Managed HSM data-plane api-version
    $Token = if ($AccessToken) { $AccessToken } else { Get-CIPPAzIdentityToken -ResourceUrl 'https://managedhsm.azure.net' }   # [?] confirm audience
    $Headers = @{ Authorization = "Bearer $Token" }
    $Base = "https://$($Ref.Host)/keys/$($Ref.Name)"

    $Invoke = {
        param($Method, $Uri, $Body)
        $Attempt = 0
        while ($true) {
            try {
                $Params = @{ Method = $Method; Uri = $Uri; Headers = $Headers; ErrorAction = 'Stop'; TimeoutSec = 20 }
                if ($Body) { $Params.Body = $Body; $Params.ContentType = 'application/json' }
                return Invoke-CIPPRestMethod @Params
            } catch {
                $Status = [int]$_.Exception.Response.StatusCode
                if ($Attempt -lt 3 -and ($Status -eq 429 -or $Status -ge 500)) {
                    $Attempt++
                    $Wait = ($_.Exception.Response.Headers['Retry-After'] -as [int]) ?? [math]::Pow(2, $Attempt)
                    Start-Sleep -Seconds ([math]::Min($Wait, 15))
                    continue
                }
                # Never echo request/response bodies: they can contain key material.
                throw "Managed HSM $Method failed (HTTP $Status)."
            }
        }
    }

    switch ($Operation) {
        'Info' {
            $Uri = if ($Ref.Version) { "$Base/$($Ref.Version)?api-version=$ApiVersion" } else { "${Base}?api-version=$ApiVersion" }
            $Key = & $Invoke 'GET' $Uri $null
            if ($Key.key.kid -notmatch '^https://[a-z0-9-]+\.managedhsm\.azure\.net/keys/[A-Za-z0-9-]+/[0-9a-f]{32}$') { throw 'Managed HSM returned an unexpected key id.' }
            [pscustomobject]@{ Provider = 'AzureManagedHsm'; KeyRef = $Key.key.kid; Hsm = ($Key.key.kty -eq 'RSA-HSM'); Enabled = [bool]$Key.attributes.enabled }
        }
        'Health' {
            $Key = & $Invoke 'GET' "${Base}?api-version=$ApiVersion" $null
            $Ops = @($Key.key.key_ops)
            $Problems = @()
            if (-not $Key.attributes.enabled) { $Problems += 'key is disabled' }
            if ($Key.key.kty -ne 'RSA-HSM') { $Problems += "key type is '$($Key.key.kty)', expected RSA-HSM" }
            foreach ($Op in 'wrapKey', 'unwrapKey') { if ($Op -notin $Ops) { $Problems += "key does not allow $Op" } }
            [pscustomobject]@{ Provider = 'AzureManagedHsm'; Healthy = ($Problems.Count -eq 0); Detail = ($Problems -join '; ') }
        }
        { $_ -in 'Wrap', 'Unwrap' } {
            if (-not $Data -or $Data.Length -eq 0) { throw 'No data supplied.' }
            $Action = if ($Operation -eq 'Wrap') { 'wrapkey' } else { 'unwrapkey' }
            # Unwrap must target the exact version the blob was wrapped with.
            if ($Operation -eq 'Unwrap' -and -not $Ref.Version) { throw 'Unwrap requires a version-pinned key reference.' }
            $Path = if ($Ref.Version) { "$Base/$($Ref.Version)/$Action" } else { "$Base/$Action" }
            $Body = @{ alg = 'RSA-OAEP-256'; value = (ConvertTo-SovratisB64Url $Data) } | ConvertTo-Json -Compress
            $Result = & $Invoke 'POST' "${Path}?api-version=$ApiVersion" $Body
            , (ConvertFrom-SovratisB64Url $Result.value)
        }
        default { throw "Unsupported operation '$Operation'." }
    }
}
