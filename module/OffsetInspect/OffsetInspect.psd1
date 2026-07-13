@{
    RootModule           = 'OffsetInspect.psm1'
    ModuleVersion        = '3.0.0'
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
        'Private/Core.Entropy.ps1',
        'Private/Core.EntropyAccelerator.ps1',
        'Private/Core.Hash.ps1',
        'Private/Core.IO.ps1',
        'Private/Core.Inspection.ps1',
        'Private/Core.Output.ps1',
        'Private/Core.PE.ps1',
        'Private/Core.String.ps1',
        'Private/Threat.Amsi.ps1',
        'Private/Threat.Batch.ps1',
        'Private/Threat.ClamAV.ps1',
        'Private/Threat.Defender.ps1',
        'Private/Threat.Region.ps1',
        'Private/Threat.Search.ps1',
        'Private/Threat.Text.ps1',
        'Private/Threat.Yara.ps1',
        'Public/Invoke-OffsetInspect.ps1',
        'Public/Invoke-OffsetThreatScan.ps1',
        'Public/Invoke-OffsetThreatScanBatch.ps1',
        'Public/Invoke-OffsetThreatScanRegion.ps1',
        'Public/Invoke-OffsetYaraScan.ps1',
        'Public/Invoke-OffsetClamScan.ps1',
        'Public/Export-OffsetThreatReport.ps1',
        'Public/Compare-OffsetThreatResult.ps1',
        'Public/Get-OffsetEntropy.ps1',
        'Public/Get-OffsetIOC.ps1',
        'Public/Get-OffsetString.ps1',
        'Public/Get-OffsetPEInfo.ps1'
    )

    FunctionsToExport = @(
        'Invoke-OffsetInspect',
        'Invoke-OffsetThreatScan',
        'Invoke-OffsetThreatScanBatch',
        'Invoke-OffsetThreatScanRegion',
        'Invoke-OffsetYaraScan',
        'Invoke-OffsetClamScan',
        'Export-OffsetThreatReport',
        'Compare-OffsetThreatResult',
        'Get-OffsetEntropy',
        'Get-OffsetIOC',
        'Get-OffsetString',
        'Get-OffsetPEInfo'
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
OffsetInspect 3.0.0
- Major-version bump for a large, all-additive capability expansion; existing 2.x commands, parameters, and output-schema field meanings are unchanged.
- Adds a per-probe audit trail: Invoke-OffsetThreatScan results expose ProbeLog (Sequence, PrefixLength, Status, ProviderResult, SignatureName, Cacheable, ElapsedMs, TimestampUtc), streamed live to -Verbose, surfaced as ProbeCount in CSV, and exportable with -ProbeLogPath.
- Adds red-team analysis commands: Export-OffsetThreatReport (Markdown/HTML engagement reports), Invoke-OffsetThreatScanBatch (corpus scanning with a detection matrix), Compare-OffsetThreatResult (detection diff/regression), and Invoke-OffsetThreatScanRegion (multi-region discovery via in-memory AMSI, no disk writes).
- Adds docs/PROVIDER-INTERFACE.md, property/fuzz tests, and an opt-in code-coverage switch.
- Switches the boundary-search memoisation cache to a thread-safe ConcurrentDictionary; probing itself remains sequential. No changes to AMSI/Defender provider behaviour, boundary semantics, or existing output-schema field meanings.

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
