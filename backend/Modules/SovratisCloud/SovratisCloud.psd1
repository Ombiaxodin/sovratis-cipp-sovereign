@{
    RootModule        = '.\SovratisCloud.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '1b67c430-ad78-450c-9eab-b100b94c4de7'
    Author            = 'Sovratis Consulting'
    CompanyName       = 'Sovratis Consulting'
    Copyright         = '(c) 2026 Sovratis Consulting. All rights reserved.'
    Description       = 'Sovereign cloud routing (Global vs. DELOS) for the Sovratis Sovereign Cloud Manager'
    PowerShellVersion = '7.0'

    FunctionsToExport = @(
        'Get-SovratisCloudEnvironment'
        'Set-SovratisCloudEnvironment'
        'Get-SovratisCloudHost'
        'Resolve-SovratisUri'
        'Resolve-SovratisScope'
        'Assert-SovratisServiceSupported'
        'Remove-SovratisCloudEnvironment'
        'Get-SovratisCloudCredential'
        'Get-SovratisCloudEnvironmentList'
        'Get-SovratisCloudEnvironmentMap'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData       = @{
        PSData = @{
            Tags = @('CIPP', 'Sovereign', 'DELOS')
        }
    }
}
