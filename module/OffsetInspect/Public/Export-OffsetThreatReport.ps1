function Export-OffsetThreatReport {
    <#
    .SYNOPSIS
        Renders one or more threat-scan results into a report-ready Markdown or HTML file.

    .DESCRIPTION
        Consumes the OffsetInspect.ThreatScanResult objects produced by
        Invoke-OffsetThreatScan -PassThru (a single result or a pipeline of many) and writes
        a self-contained detection-boundary report: per-file summary, provider/signature/engine
        metadata for reproducibility, the full ProbeLog audit trail, and any warnings. HTML
        output is self-contained and HTML-encodes every value. The command reads results only
        and never re-scans, so it is fully cross-platform.

    .PARAMETER Result
        One or more threat-scan result objects, typically piped from Invoke-OffsetThreatScan -PassThru.

    .PARAMETER Path
        Destination file path. Written as BOM-less UTF-8.

    .PARAMETER Format
        Markdown (default) or Html.

    .PARAMETER Title
        Report heading.

    .PARAMETER IncludeIoc
        Attach an IOC panel (hashes, entropy, imphash, overlay) to each record. Without
        -IocJsonPath the panel is computed live via Get-OffsetIOC (one PowerShell scan
        per file). With -IocJsonPath it is sourced from the JSON and this switch only
        enables a live fallback for files absent from the JSON.

    .PARAMETER IocJsonPath
        Path to a JSON dump produced by the native OffsetScan engine
        (`offsetscan ioc <corpus> > ioc.json`). IOC panels are matched to each record by
        canonical full path and are schema-identical to Get-OffsetIOC output - but for
        corpus-scale engagements the native engine is orders of magnitude faster than
        re-scanning every file in PowerShell. Supplying this implies IOC enrichment;
        add -IncludeIoc to also fall back to a live scan for unmatched files.

    .PARAMETER IncludeTrigger
        For each record with a detection boundary, attach a detection-trigger analysis: the
        PE section the boundary falls in, the entropy of the run up to it, and the extracted
        strings ending at/straddling it (the likely signature content), with a one-line
        interpretation. Read-only and cross-platform; records without a boundary are untouched.

    .EXAMPLE
        Invoke-OffsetThreatScan .\sample.ps1 -Engine AMSI -PassThru |
            Export-OffsetThreatReport -Path .\report.html -Format Html

    .EXAMPLE
        $results | Export-OffsetThreatReport -Path .\engagement.md

    .EXAMPLE
        # Pre-compute IOCs for a whole corpus with the native engine, then render
        # the report off that JSON instead of re-scanning each file in PowerShell.
        offsetscan ioc C:\Cases\corpus --recurse > C:\Cases\ioc.json
        $results | Export-OffsetThreatReport -Path .\engagement.md -IocJsonPath C:\Cases\ioc.json
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [pscustomobject[]]$Result,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path,

        [ValidateSet('Markdown', 'Html')]
        [string]$Format = 'Markdown',

        [ValidateNotNullOrEmpty()]
        [string]$Title = 'OffsetInspect Detection-Boundary Report',

        [switch]$IncludeIoc,

        [ValidateNotNullOrEmpty()]
        [string]$IocJsonPath,

        [switch]$IncludeTrigger
    )

    begin {
        $collected = New-Object 'System.Collections.Generic.List[object]'
    }

    process {
        foreach ($item in $Result) {
            if ($null -ne $item) { $collected.Add($item) }
        }
    }

    end {
        if ($collected.Count -eq 0) {
            throw 'No threat-scan results were supplied to Export-OffsetThreatReport.'
        }

        $records = $collected.ToArray()

        # Optional IOC index sourced from a native OffsetScan `ioc` JSON dump
        # (offsetscan ioc <corpus> > ioc.json). Panels are schema-identical to
        # Get-OffsetIOC, so they render through the same path - but for corpus-scale
        # reports the native engine is orders of magnitude faster than re-scanning
        # each file in PowerShell. Keyed by canonical full path (case-insensitive).
        $iocIndex = $null
        if (-not [string]::IsNullOrWhiteSpace($IocJsonPath)) {
            $resolvedJson = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($IocJsonPath)
            if (-not (Test-Path -LiteralPath $resolvedJson)) {
                throw "IocJsonPath not found: $resolvedJson"
            }
            $rawJson = [System.IO.File]::ReadAllText($resolvedJson)
            # ConvertFrom-Json's return shape differs across editions: Windows PowerShell 5.1
            # in module scope can hand back a top-level JSON array as a single Object[] that
            # does not enumerate cleanly. Flatten one level so a JSON array (offsetscan's
            # normal output) and a lone object both yield a flat record list on every edition.
            $parsedJson = ConvertFrom-Json -InputObject $rawJson
            $iocRecords = New-Object 'System.Collections.Generic.List[object]'
            foreach ($candidate in @($parsedJson)) {
                if ($candidate -is [System.Collections.IEnumerable] -and $candidate -isnot [string]) {
                    foreach ($inner in $candidate) { $iocRecords.Add($inner) }
                }
                else {
                    $iocRecords.Add($candidate)
                }
            }
            $iocIndex = New-Object 'System.Collections.Generic.Dictionary[string,object]' ([System.StringComparer]::OrdinalIgnoreCase)
            foreach ($entry in $iocRecords) {
                $entryFile = $entry.PSObject.Properties['File']
                if ($null -ne $entryFile -and -not [string]::IsNullOrWhiteSpace([string]$entry.File)) {
                    $key = try { [System.IO.Path]::GetFullPath([string]$entry.File) } catch { [string]$entry.File }
                    $iocIndex[$key] = $entry
                }
            }
            Write-Verbose "Loaded $($iocRecords.Count) IOC record(s) from $resolvedJson"
        }

        if ($IncludeIoc -or $null -ne $iocIndex) {
            foreach ($record in $records) {
                $fileProperty = $record.PSObject.Properties['File']
                if ($null -eq $fileProperty -or [string]::IsNullOrWhiteSpace([string]$record.File)) {
                    continue
                }

                $ioc = $null
                if ($null -ne $iocIndex) {
                    $key = try { [System.IO.Path]::GetFullPath([string]$record.File) } catch { [string]$record.File }
                    if ($iocIndex.ContainsKey($key)) { $ioc = $iocIndex[$key] }
                }

                # Live fallback: only when -IncludeIoc was requested (JSON miss or no JSON at all).
                if ($null -eq $ioc -and $IncludeIoc -and (Test-Path -LiteralPath $record.File)) {
                    try { $ioc = Get-OffsetIOC -FilePath $record.File }
                    catch { Write-Verbose "IOC enrichment failed for $($record.File): $($_.Exception.Message)" }
                }

                if ($null -ne $ioc) {
                    Add-Member -InputObject $record -NotePropertyName 'IocPanel' -NotePropertyValue $ioc -Force
                }
                elseif ($null -ne $iocIndex) {
                    Write-Verbose "No IOC match in JSON for $($record.File)"
                }
            }
        }

        # Optional detection-trigger correlation: for every record with a boundary, attach
        # the content that most likely tripped detection (section, entropy, candidate strings).
        # Read-only and cross-platform; records without a boundary are simply left alone.
        if ($IncludeTrigger) {
            foreach ($record in $records) {
                $fileProperty = $record.PSObject.Properties['File']
                $boundary = Get-OIResultProperty -InputObject $record -Name 'DetectionBoundaryOffset'
                if ($null -eq $fileProperty -or [string]::IsNullOrWhiteSpace([string]$record.File) -or $null -eq $boundary) {
                    continue
                }
                if (-not (Test-Path -LiteralPath $record.File)) {
                    Write-Verbose "Trigger analysis skipped; file not found: $($record.File)"
                    continue
                }
                try {
                    $trigger = $record | Get-OffsetDetectionTrigger
                    if ($null -ne $trigger) {
                        Add-Member -InputObject $record -NotePropertyName 'Trigger' -NotePropertyValue $trigger -Force
                    }
                }
                catch {
                    Write-Verbose "Trigger analysis failed for $($record.File): $($_.Exception.Message)"
                }
            }
        }

        $content = if ($Format -eq 'Html') {
            ConvertTo-OIThreatReportHtml -Result $records -Title $Title
        }
        else {
            ConvertTo-OIThreatReportMarkdown -Result $records -Title $Title
        }

        $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
        [System.IO.File]::WriteAllText($fullPath, $content, (New-Object System.Text.UTF8Encoding($false)))
        Write-Verbose "Threat report ($Format, $($records.Count) record(s)) written to $fullPath"
        return $fullPath
    }
}
