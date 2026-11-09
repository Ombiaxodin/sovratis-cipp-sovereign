function Invoke-SovratisEncryption {
    <#
    .SYNOPSIS
        The ONLY entry point CIPP code may use for application-layer encryption of data at rest.
    .DESCRIPTION
        Envelope encryption: HSM KEK wraps a Root Data Key; HKDF-SHA256 derives a per-(RDK version, tenant,
        purpose) key; AES-256-GCM encrypts with a random nonce and AAD that binds the ciphertext to its tenant,
        purpose and (optionally) table / partition / row / property. See docs-sovratis/DKE-HSM-Blueprint.md.

        Fail closed: every error throws. Nothing here ever returns its input as a fallback.

        Operations
          Encrypt    plaintext string -> 'sov1.…' envelope string
          Decrypt    envelope string  -> plaintext string (context must equal the one used to encrypt)
          IsEnvelope $true if Data is syntactically a Sovratis envelope (no keys involved, no authentication)
          Health     read-only provider and key-store check; never writes anywhere
    .PARAMETER Context
        TenantId and Purpose are required. Table, PartitionKey, RowKey, Property are bound when supplied.
    .FUNCTIONALITY
        Internal
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet('Encrypt', 'Decrypt', 'IsEnvelope', 'Health')]
        [string]$Operation,

        [AllowEmptyString()]
        [string]$Data = '',

        [hashtable]$Context = @{}
    )

    switch ($Operation) {
        'IsEnvelope' {
            if ($Data.Length -gt 16MB -or -not $Data.StartsWith('sov1.', [StringComparison]::Ordinal)) { return $false }
            try { $null = Read-SovratisEnvelope -Text $Data; return $true } catch { return $false }
        }
        'Encrypt' {
            $Aad = ConvertTo-SovratisAad -Context $Context
            $Root = Get-SovratisRootKey -ForWrite
            $Dek = Get-SovratisDek -Root $Root -TenantId $Context.TenantId -Purpose $Context.Purpose
            New-SovratisEnvelope -Plaintext $Data -Dek $Dek -Aad $Aad -RdkId $Root.Id
        }
        'Decrypt' {
            $Aad = ConvertTo-SovratisAad -Context $Context
            $Envelope = Read-SovratisEnvelope -Text $Data
            $Root = Get-SovratisRootKey -Id $Envelope.Header.rdk
            $Dek = Get-SovratisDek -Root $Root -TenantId $Context.TenantId -Purpose $Context.Purpose
            Open-SovratisEnvelope -Envelope $Envelope -Dek $Dek -Aad $Aad
        }
        'Health' {
            # Strictly read-only and idempotent: nothing is written to Table Storage, Key Vault or the HSM.
            #  - provider Health (Managed HSM: reads key metadata; dev provider: in-memory probe)
            #  - read-only root-key lookup (does NOT create one), reported as RootKeyProvisioned, plus an unwrap of it
            #    (an HSM unwrap changes no state; it proves the identity can actually use the key)
            $Problems = [System.Collections.Generic.List[string]]::new()
            $Provider = $null
            try {
                $Config = Get-SovratisEncryptionConfig
                $Provider = $Config.Provider
                $Mode = Get-SovratisEncryptionMode
                $Info = Invoke-SovratisKekProvider -Provider $Config.Provider -Operation Health -KeyRef $Config.KeyRef
                if (-not $Info.Healthy) { $Problems.Add("provider unhealthy: $($Info.Detail)") }
            } catch { $Problems.Add($_.Exception.Message) }
            $Rdk = $null
            try { $Rdk = Invoke-SovratisRootKeyStore -Operation Latest } catch { $Problems.Add("root key store: $($_.Exception.Message)") }
            if ($Rdk) { try { $null = Get-SovratisRootKey -Id $Rdk } catch { $Problems.Add("root key cannot be unwrapped: $($_.Exception.Message)") } }
            [pscustomobject]@{
                Healthy              = ($Problems.Count -eq 0)
                Provider             = $Provider
                Mode                 = $Mode
                RootKeyProvisioned   = [bool]$Rdk
                LatestRootKey        = $Rdk
                Problems             = @($Problems)
            }
        }
    }
}
