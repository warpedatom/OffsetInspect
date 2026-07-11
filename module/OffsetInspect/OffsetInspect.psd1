@{
    RootModule           = 'OffsetInspect.psm1'
    ModuleVersion        = '2.0.0'
    GUID                 = '2d9f6f83-2c4f-4a6e-8a53-1cf9a5fbc2f6'
    Author               = 'Jared Perry (Velkris)'
    CompanyName          = 'DreadHost Research'
    Copyright            = '(c) 2025-2026 Jared Perry (Velkris). MIT License.'
    Description          = 'A bounded-memory PowerShell toolkit for byte-offset inspection, source context, binary comparison, and defensive AMSI/Microsoft Defender detection-boundary analysis.'
    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')
    FormatsToProcess     = @('OffsetInspect.Format.ps1xml')
    FileList             = @(
        'OffsetInspect.psd1',
        'OffsetInspect.psm1',
        'OffsetInspect.Format.ps1xml',
        'LICENSE',
        'Private/Core.IO.ps1',
        'Private/Core.Inspection.ps1',
        'Private/Core.Output.ps1',
        'Private/Threat.Amsi.ps1',
        'Private/Threat.Defender.ps1',
        'Private/Threat.Search.ps1',
        'Private/Threat.Text.ps1',
        'Public/Invoke-OffsetInspect.ps1',
        'Public/Invoke-OffsetThreatScan.ps1'
    )

    FunctionsToExport = @(
        'Invoke-OffsetInspect',
        'Invoke-OffsetThreatScan'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags = @(
                'PowerShell',
                'Security',
                'DetectionEngineering',
                'MalwareAnalysis',
                'ReverseEngineering',
                'Forensics',
                'Hex',
                'AMSI',
                'MicrosoftDefender',
                'OffsetAnalysis'
            )
            LicenseUri = 'https://github.com/warpedatom/OffsetInspect/blob/main/LICENSE'
            ProjectUri = 'https://github.com/warpedatom/OffsetInspect'
            ReleaseNotes = @'
OffsetInspect 2.0.0
- Rebuilt as a self-contained PowerShell Gallery module.
- Opens each unique file once and gathers requested line context in one bounded-memory streaming pass.
- Adds accurate UTF-8/UTF-16 byte-to-character mapping and implemented context lines.
- Adds stable object, JSON, CSV, and CSV-file output modes.
- Adds Invoke-OffsetThreatScan with independently implemented AMSI and Microsoft Defender providers.
- Adds repeatability checks, provider-error handling, temporary-file cleanup, and boundary confidence.
- Adds isolated package tests, PSScriptAnalyzer, cross-platform PowerShell 7 CI, and Windows PowerShell 5.1 CI.
'@
        }
    }
}
