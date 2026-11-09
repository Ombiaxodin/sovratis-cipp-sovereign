@{
    RootModule        = '.\SovratisCrypto.psm1'
    ModuleVersion     = '0.1.0'
    GUID              = '5d0a3a52-7f0e-4c1f-9a64-3c8f2f6b9e11'
    Author            = 'Sovratis Consulting'
    CompanyName       = 'Sovratis Consulting'
    Copyright         = '(c) 2026 Sovratis Consulting. All rights reserved.'
    Description       = 'Application-layer envelope encryption (Double Key Encryption) abstraction for the Sovratis Sovereign Cloud Manager'
    PowerShellVersion = '7.4'
    FunctionsToExport = @(
        'Invoke-SovratisEncryption'
        'Protect-SovratisEntity'
        'Unprotect-SovratisEntity'
        'Get-SovratisEncryptionPolicy'
        'Initialize-SovratisRootKey'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{ PSData = @{ Tags = @('CIPP', 'Sovereign', 'Encryption') } }
}
