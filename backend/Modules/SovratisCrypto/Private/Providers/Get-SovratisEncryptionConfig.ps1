function Get-SovratisDevelopmentStorage {
    [CmdletBinding()]
    [OutputType([bool])]
    param()
    [bool]($env:AzureWebJobsStorage -eq 'UseDevelopmentStorage=true' -or $env:NonLocalHostAzurite -eq 'true')
}

function Get-SovratisEncryptionMode {
    # 'Enforce' (default) or 'Disabled'. Disabled is honoured ONLY against local development storage, so a
    # deployed environment can never run unencrypted by configuration.
    [CmdletBinding()]
    [OutputType([string])]
    param()
    $Mode = if ($env:SOVRATIS_ENC_MODE) { $env:SOVRATIS_ENC_MODE } else { 'Enforce' }
    switch ($Mode) {
        'Enforce' { 'Enforce' }
        'Disabled' {
            if (-not (Get-SovratisDevelopmentStorage)) { throw 'SOVRATIS_ENC_MODE=Disabled is only allowed with local development storage.' }
            'Disabled'
        }
        default { throw "Unknown SOVRATIS_ENC_MODE '$Mode'." }
    }
}

function Get-SovratisEncryptionConfig {
    # Fails closed: encryption is never silently skipped because configuration is missing.
    [CmdletBinding()]
    param()
    $Provider = $env:SOVRATIS_ENC_PROVIDER
    $KeyRef = $env:SOVRATIS_KEK_REF
    if ([string]::IsNullOrWhiteSpace($Provider)) { throw 'SOVRATIS_ENC_PROVIDER is not configured. Refusing to run without encryption.' }
    if ([string]::IsNullOrWhiteSpace($KeyRef)) { throw 'SOVRATIS_KEK_REF is not configured.' }
    @{ Provider = $Provider; KeyRef = $KeyRef }
}
