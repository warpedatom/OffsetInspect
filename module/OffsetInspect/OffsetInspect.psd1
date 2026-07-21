@{
    RootModule           = 'OffsetInspect.psm1'
    ModuleVersion        = '3.1.1'
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
        'Private/Threat.Drift.ps1',
        'Private/Threat.Mutation.ps1',
        'Private/Threat.Region.ps1',
        'Private/Threat.Search.ps1',
        'Private/Threat.Text.ps1',
        'Private/Threat.Trigger.ps1',
        'Private/Threat.Yara.ps1',
        'Public/Invoke-OffsetInspect.ps1',
        'Public/Invoke-OffsetMutationTest.ps1',
        'Public/Invoke-OffsetThreatScan.ps1',
        'Public/Invoke-OffsetThreatScanBatch.ps1',
        'Public/Invoke-OffsetThreatScanRegion.ps1',
        'Public/Invoke-OffsetYaraScan.ps1',
        'Public/Invoke-OffsetClamScan.ps1',
        'Public/Export-OffsetThreatReport.ps1',
        'Public/Add-OffsetDriftEntry.ps1',
        'Public/Compare-OffsetThreatResult.ps1',
        'Public/Get-OffsetDetectionTrigger.ps1',
        'Public/Get-OffsetDrift.ps1',
        'Public/Get-OffsetEntropy.ps1',
        'Public/Get-OffsetIOC.ps1',
        'Public/Get-OffsetString.ps1',
        'Public/Get-OffsetPEInfo.ps1'
    )

    FunctionsToExport = @(
        'Invoke-OffsetInspect',
        'Invoke-OffsetMutationTest',
        'Invoke-OffsetThreatScan',
        'Invoke-OffsetThreatScanBatch',
        'Invoke-OffsetThreatScanRegion',
        'Invoke-OffsetYaraScan',
        'Invoke-OffsetClamScan',
        'Export-OffsetThreatReport',
        'Compare-OffsetThreatResult',
        'Add-OffsetDriftEntry',
        'Get-OffsetDetectionTrigger',
        'Get-OffsetDrift',
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
OffsetInspect 3.1.1
- Fixes Get-OffsetString splitting a string that straddles a read-window seam into two truncated halves. A trailing run is now carried into the next window, so results no longer depend on -WindowSize. This also makes Get-OffsetIOC's PrintableStringCount deterministic for files larger than the 1 MiB default window.

OffsetInspect 3.1.0
- All-additive minor release; existing commands, parameters, and output-schema field meanings are unchanged.
- Adds Get-OffsetDetectionTrigger: correlates a detection boundary to the content that most likely produced it (PE section, pre-boundary entropy, and the extracted strings ending at or straddling the boundary as candidate signature content), with a one-line interpretation. Read-only and cross-platform.
- Adds detection-drift journaling: Add-OffsetDriftEntry records append-only NDJSON snapshots (file SHA-256, status, boundary, signature, and the local Defender signature/engine versions), and Get-OffsetDrift explains each change as a file modification, a signature-database update, or a non-deterministic provider result.
- Export-OffsetThreatReport gains -IocJsonPath (source IOC panels from the native OffsetScan engine's JSON instead of re-scanning each file in PowerShell) and -IncludeTrigger (embed detection-trigger analysis in the report).
- Adds Invoke-OffsetMutationTest (authorized engagements only): tests signature robustness by perturbing a detected sample in memory (case inversion, string concatenation, comment insertion, whitespace injection) and re-scanning each variant with AMSI to report which transform classes neutralize detection. No variant is written to disk; requires -AuthorizedEngagement.
- Hardens Windows PowerShell 5.1 module-scope parsing of top-level JSON arrays for the new ingestion path.
- New output objects documented in docs/OUTPUT-SCHEMA.md: DetectionTrigger, DriftEntry, DriftReport.

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
