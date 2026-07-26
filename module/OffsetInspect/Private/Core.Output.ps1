function Write-OIBanner {
    [CmdletBinding()]
    param()

    # Draw a square box: the top/bottom borders and every content row are the
    # same width, so the right-hand '*' column always lines up regardless of the
    # text length. Content rows are centered within the inner width.
    $width = 66
    $innerWidth = $width - 3   # leading ' *' prefix plus the trailing '*'
    $centerLine = {
        param([string]$Text)
        if ($Text.Length -ge $innerWidth) { return $Text.Substring(0, $innerWidth) }
        $pad = $innerWidth - $Text.Length
        $left = [int][Math]::Floor($pad / 2)
        (' ' * $left) + $Text + (' ' * ($pad - $left))
    }.GetNewClosure()

    Write-Host ('/' + ('*' * ($width - 1))) -ForegroundColor DarkCyan
    Write-Host (' *' + (& $centerLine 'OffsetInspect') + '*') -ForegroundColor DarkCyan
    Write-Host (' *' + (& $centerLine 'Offset, Context, Diff & Threat Boundary Inspector') + '*') -ForegroundColor DarkCyan
    Write-Host (' *' + (& $centerLine 'DreadHost Research') + '*') -ForegroundColor DarkCyan
    Write-Host (' ' + ('*' * ($width - 2)) + '/') -ForegroundColor DarkCyan
    Write-Host ''
    # Read the running module's version so the banner never drifts from the
    # manifest. Fall back to a literal if the module context is unavailable
    # (e.g. a dot-sourced test harness), guarded for Set-StrictMode.
    $bannerVersion = '3.0.0'
    $bannerModule = $MyInvocation.MyCommand.Module
    if ($null -ne $bannerModule -and $null -ne $bannerModule.Version) {
        $bannerVersion = $bannerModule.Version.ToString()
    }
    Write-Host "    Version:          $bannerVersion" -ForegroundColor Cyan
    Write-Host '    Author:           Jared Perry (Velkris)' -ForegroundColor Cyan
    Write-Host '    GitHub:           https://github.com/warpedatom/OffsetInspect' -ForegroundColor Cyan
    Write-Host ''
}

function Export-OIProbeLog {
    <#
        Writes a threat-scan ProbeLog to a UTF-8 JSON file as a report-ready
        provider audit transcript. Always emits a valid JSON array (including
        for an empty log) and stays Windows PowerShell 5.1 safe by not relying
        on ConvertTo-Json -AsArray (which is PowerShell 7 only).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$ProbeLog,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    $records = @(@($ProbeLog) | Where-Object { $null -ne $_ })
    if ($records.Count -eq 0) {
        $json = '[]'
    }
    else {
        $elements = @($records | ForEach-Object { ConvertTo-Json -InputObject $_ -Depth 5 })
        $json = '[' + [Environment]::NewLine +
            ($elements -join (',' + [Environment]::NewLine)) +
            [Environment]::NewLine + ']'
    }

    # Resolve a possibly-relative, not-yet-existing path against the current
    # filesystem location, and write BOM-less UTF-8 so the JSON round-trips
    # through Windows PowerShell 5.1's ConvertFrom-Json.
    $fullPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    [System.IO.File]::WriteAllText($fullPath, $json, (New-Object System.Text.UTF8Encoding($false)))
    return $fullPath
}

function Get-OIResultProperty {
    # Set-StrictMode-safe property read: returns $Default when the object is null
    # or does not expose the named property, instead of throwing.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $InputObject,

        [Parameter(Mandatory = $true)]
        [string]$Name,

        [AllowNull()]
        $Default = $null
    )

    if ($null -ne $InputObject -and $null -ne $InputObject.PSObject.Properties[$Name]) {
        return $InputObject.$Name
    }
    return $Default
}

function Get-OIThreatReportSummaryField {
    # Ordered name/value summary shared by the Markdown and HTML report builders,
    # so both render the same fields in the same order.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Result
    )

    $probeLog = @(Get-OIResultProperty -InputObject $Result -Name 'ProbeLog' -Default @())
    return [ordered]@{
        'File'                    = Get-OIResultProperty -InputObject $Result -Name 'File'
        'Success'                 = Get-OIResultProperty -InputObject $Result -Name 'Success'
        'SHA-256'                 = Get-OIResultProperty -InputObject $Result -Name 'FileSha256'
        'Scan timestamp (UTC)'    = Get-OIResultProperty -InputObject $Result -Name 'ScanTimestampUtc'
        'Engine / scan mode'      = "$(Get-OIResultProperty -InputObject $Result -Name 'Engine') / $(Get-OIResultProperty -InputObject $Result -Name 'ScanMode')"
        'Initial status'          = Get-OIResultProperty -InputObject $Result -Name 'InitialStatus'
        'Detection prefix length' = Get-OIResultProperty -InputObject $Result -Name 'DetectionPrefixLength'
        'Boundary offset'         = "$(Get-OIResultProperty -InputObject $Result -Name 'DetectionBoundaryOffset') ($(Get-OIResultProperty -InputObject $Result -Name 'DetectionBoundaryHex'))"
        'Known-clean prefix'      = Get-OIResultProperty -InputObject $Result -Name 'KnownCleanPrefixLength'
        'Stable / confidence'     = "$(Get-OIResultProperty -InputObject $Result -Name 'Stable') / $(Get-OIResultProperty -InputObject $Result -Name 'Confidence')"
        'Signature'               = Get-OIResultProperty -InputObject $Result -Name 'SignatureName'
        'Provider probes'         = $probeLog.Count
        'Duration (ms)'           = Get-OIResultProperty -InputObject $Result -Name 'DurationMs'
        'Error'                   = Get-OIResultProperty -InputObject $Result -Name 'Error'
    }
}

function ConvertTo-OIThreatReportMarkdown {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Result,

        [string]$Title = 'OffsetInspect Detection-Boundary Report'
    )

    $lines = New-Object 'System.Collections.Generic.List[string]'
    $lines.Add("# $Title")
    $lines.Add('')
    $lines.Add("_Generated $([DateTime]::UtcNow.ToString('o')) - $($Result.Count) scan record(s)._")
    $lines.Add('')

    $index = 0
    foreach ($record in $Result) {
        $index++
        $file = [string](Get-OIResultProperty -InputObject $record -Name 'File' -Default '(unknown)')
        $lines.Add("## $index. $(Split-Path -Leaf $file)")
        $lines.Add('')

        foreach ($field in (Get-OIThreatReportSummaryField -Result $record).GetEnumerator()) {
            if ($field.Key -eq 'Error' -and [string]::IsNullOrWhiteSpace([string]$field.Value)) { continue }
            $lines.Add("- **$($field.Key):** $($field.Value)")
        }
        $lines.Add('')

        $metadata = Get-OIResultProperty -InputObject $record -Name 'ProviderMetadata'
        if ($null -ne $metadata) {
            $lines.Add('### Provider metadata')
            $lines.Add('')
            foreach ($property in $metadata.PSObject.Properties) {
                $lines.Add("- **$($property.Name):** $($property.Value)")
            }
            $lines.Add('')
        }

        $ioc = Get-OIResultProperty -InputObject $record -Name 'IocPanel'
        if ($null -ne $ioc) {
            $lines.Add('### Indicators')
            $lines.Add('')
            $lines.Add("- **MD5:** $($ioc.MD5)")
            $lines.Add("- **SHA-1:** $($ioc.SHA1)")
            $lines.Add("- **SHA-256:** $($ioc.SHA256)")
            $lines.Add("- **Overall entropy:** $($ioc.OverallEntropy) (high windows: $($ioc.HighEntropyWindows))")
            $lines.Add("- **Printable strings:** $($ioc.PrintableStringCount)")
            if ($ioc.IsPE) {
                $lines.Add("- **PE machine:** $($ioc.Machine)")
                $lines.Add("- **Imphash:** $($ioc.ImpHash)")
                $lines.Add("- **Imported DLLs:** $($ioc.ImportedDllCount)")
                $lines.Add("- **Overlay:** $($ioc.HasOverlay) (size $($ioc.OverlaySize))")
            }
            $lines.Add('')
        }

        $trigger = Get-OIResultProperty -InputObject $record -Name 'Trigger'
        if ($null -ne $trigger) {
            $lines.Add('### Detection trigger')
            $lines.Add('')
            $lines.Add("- **Interpretation:** $($trigger.Interpretation)")
            $lines.Add("- **Boundary:** $($trigger.BoundaryOffset) ($($trigger.BoundaryHex)), byte $($trigger.BoundaryByteHex)")
            if ($null -ne $trigger.Section) { $lines.Add("- **PE section:** $($trigger.Section)") }
            $lines.Add("- **Pre-boundary entropy:** $($trigger.PreBoundaryEntropy) bits/byte")
            $candidates = @(Get-OIResultProperty -InputObject $trigger -Name 'CandidateStrings' -Default @())
            if ($candidates.Count -gt 0) {
                $lines.Add('')
                $lines.Add('| Offset | Enc | Dist | Candidate string |')
                $lines.Add('|---|---|---:|---|')
                foreach ($cand in $candidates) {
                    $val = ([string]$cand.Value) -replace '\|', '\|' -replace '[\r\n]', ' '
                    if ($val.Length -gt 80) { $val = $val.Substring(0, 80) + '...' }
                    $lines.Add("| $($cand.OffsetHex) | $($cand.Encoding) | $($cand.DistanceToBoundary) | $val |")
                }
            }
            $lines.Add('')
        }

        $probeLog = @(Get-OIResultProperty -InputObject $record -Name 'ProbeLog' -Default @())
        if ($probeLog.Count -gt 0) {
            $lines.Add('### Probe log')
            $lines.Add('')
            $lines.Add('| # | Prefix | Status | Elapsed (ms) | Signature |')
            $lines.Add('|---:|---:|---|---:|---|')
            foreach ($probe in $probeLog) {
                $seq = Get-OIResultProperty -InputObject $probe -Name 'Sequence'
                $prefix = Get-OIResultProperty -InputObject $probe -Name 'PrefixLength'
                $status = Get-OIResultProperty -InputObject $probe -Name 'Status'
                $elapsed = Get-OIResultProperty -InputObject $probe -Name 'ElapsedMs'
                $signature = Get-OIResultProperty -InputObject $probe -Name 'SignatureName'
                $lines.Add("| $seq | $prefix | $status | $elapsed | $signature |")
            }
            $lines.Add('')
        }

        $warnings = @(Get-OIResultProperty -InputObject $record -Name 'Warnings' -Default @())
        if ($warnings.Count -gt 0) {
            $lines.Add('### Warnings')
            $lines.Add('')
            foreach ($warning in $warnings) { $lines.Add("- $warning") }
            $lines.Add('')
        }
    }

    return ($lines -join [Environment]::NewLine)
}

function ConvertTo-OIThreatReportHtml {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Result,

        [string]$Title = 'OffsetInspect Detection-Boundary Report'
    )

    $encode = { param($value) [System.Net.WebUtility]::HtmlEncode([string]$value) }
    $builder = New-Object 'System.Text.StringBuilder'
    [void]$builder.AppendLine('<!DOCTYPE html>')
    [void]$builder.AppendLine('<html lang="en"><head><meta charset="utf-8">')
    [void]$builder.AppendLine("<title>$(& $encode $Title)</title>")
    [void]$builder.AppendLine('<style>body{font-family:Segoe UI,Arial,sans-serif;margin:2rem;color:#1b1b1b}h1{border-bottom:2px solid #444}h2{margin-top:2rem}table{border-collapse:collapse;margin:.5rem 0}th,td{border:1px solid #ccc;padding:.25rem .5rem;font-size:.9rem;text-align:left}code{background:#f2f2f2;padding:0 .25rem}</style>')
    [void]$builder.AppendLine('</head><body>')
    [void]$builder.AppendLine("<h1>$(& $encode $Title)</h1>")
    [void]$builder.AppendLine("<p><em>Generated $(& $encode ([DateTime]::UtcNow.ToString('o'))) - $($Result.Count) scan record(s).</em></p>")

    $index = 0
    foreach ($record in $Result) {
        $index++
        $file = [string](Get-OIResultProperty -InputObject $record -Name 'File' -Default '(unknown)')
        [void]$builder.AppendLine("<h2>$index. $(& $encode (Split-Path -Leaf $file))</h2>")
        [void]$builder.AppendLine('<table>')
        foreach ($field in (Get-OIThreatReportSummaryField -Result $record).GetEnumerator()) {
            if ($field.Key -eq 'Error' -and [string]::IsNullOrWhiteSpace([string]$field.Value)) { continue }
            [void]$builder.AppendLine("<tr><th>$(& $encode $field.Key)</th><td>$(& $encode $field.Value)</td></tr>")
        }
        [void]$builder.AppendLine('</table>')

        $metadata = Get-OIResultProperty -InputObject $record -Name 'ProviderMetadata'
        if ($null -ne $metadata) {
            [void]$builder.AppendLine('<h3>Provider metadata</h3><table>')
            foreach ($property in $metadata.PSObject.Properties) {
                [void]$builder.AppendLine("<tr><th>$(& $encode $property.Name)</th><td>$(& $encode $property.Value)</td></tr>")
            }
            [void]$builder.AppendLine('</table>')
        }

        $ioc = Get-OIResultProperty -InputObject $record -Name 'IocPanel'
        if ($null -ne $ioc) {
            [void]$builder.AppendLine('<h3>Indicators</h3><table>')
            [void]$builder.AppendLine("<tr><th>MD5</th><td>$(& $encode $ioc.MD5)</td></tr>")
            [void]$builder.AppendLine("<tr><th>SHA-1</th><td>$(& $encode $ioc.SHA1)</td></tr>")
            [void]$builder.AppendLine("<tr><th>SHA-256</th><td>$(& $encode $ioc.SHA256)</td></tr>")
            [void]$builder.AppendLine("<tr><th>Overall entropy</th><td>$(& $encode $ioc.OverallEntropy) (high windows: $(& $encode $ioc.HighEntropyWindows))</td></tr>")
            [void]$builder.AppendLine("<tr><th>Printable strings</th><td>$(& $encode $ioc.PrintableStringCount)</td></tr>")
            if ($ioc.IsPE) {
                [void]$builder.AppendLine("<tr><th>PE machine</th><td>$(& $encode $ioc.Machine)</td></tr>")
                [void]$builder.AppendLine("<tr><th>Imphash</th><td>$(& $encode $ioc.ImpHash)</td></tr>")
                [void]$builder.AppendLine("<tr><th>Imported DLLs</th><td>$(& $encode $ioc.ImportedDllCount)</td></tr>")
                [void]$builder.AppendLine("<tr><th>Overlay</th><td>$(& $encode $ioc.HasOverlay) (size $(& $encode $ioc.OverlaySize))</td></tr>")
            }
            [void]$builder.AppendLine('</table>')
        }

        $trigger = Get-OIResultProperty -InputObject $record -Name 'Trigger'
        if ($null -ne $trigger) {
            [void]$builder.AppendLine('<h3>Detection trigger</h3><table>')
            [void]$builder.AppendLine("<tr><th>Interpretation</th><td>$(& $encode $trigger.Interpretation)</td></tr>")
            [void]$builder.AppendLine("<tr><th>Boundary</th><td>$(& $encode $trigger.BoundaryOffset) ($(& $encode $trigger.BoundaryHex)), byte $(& $encode $trigger.BoundaryByteHex)</td></tr>")
            if ($null -ne $trigger.Section) { [void]$builder.AppendLine("<tr><th>PE section</th><td>$(& $encode $trigger.Section)</td></tr>") }
            [void]$builder.AppendLine("<tr><th>Pre-boundary entropy</th><td>$(& $encode $trigger.PreBoundaryEntropy) bits/byte</td></tr>")
            [void]$builder.AppendLine('</table>')
            $candidates = @(Get-OIResultProperty -InputObject $trigger -Name 'CandidateStrings' -Default @())
            if ($candidates.Count -gt 0) {
                [void]$builder.AppendLine('<table><tr><th>Offset</th><th>Enc</th><th>Dist</th><th>Candidate string</th></tr>')
                foreach ($cand in $candidates) {
                    [void]$builder.AppendLine("<tr><td>$(& $encode $cand.OffsetHex)</td><td>$(& $encode $cand.Encoding)</td><td>$(& $encode $cand.DistanceToBoundary)</td><td><code>$(& $encode $cand.Value)</code></td></tr>")
                }
                [void]$builder.AppendLine('</table>')
            }
        }

        $probeLog = @(Get-OIResultProperty -InputObject $record -Name 'ProbeLog' -Default @())
        if ($probeLog.Count -gt 0) {
            [void]$builder.AppendLine('<h3>Probe log</h3><table><tr><th>#</th><th>Prefix</th><th>Status</th><th>Elapsed (ms)</th><th>Signature</th></tr>')
            foreach ($probe in $probeLog) {
                $seq = & $encode (Get-OIResultProperty -InputObject $probe -Name 'Sequence')
                $prefix = & $encode (Get-OIResultProperty -InputObject $probe -Name 'PrefixLength')
                $status = & $encode (Get-OIResultProperty -InputObject $probe -Name 'Status')
                $elapsed = & $encode (Get-OIResultProperty -InputObject $probe -Name 'ElapsedMs')
                $signature = & $encode (Get-OIResultProperty -InputObject $probe -Name 'SignatureName')
                [void]$builder.AppendLine("<tr><td>$seq</td><td>$prefix</td><td>$status</td><td>$elapsed</td><td>$signature</td></tr>")
            }
            [void]$builder.AppendLine('</table>')
        }

        $warnings = @(Get-OIResultProperty -InputObject $record -Name 'Warnings' -Default @())
        if ($warnings.Count -gt 0) {
            [void]$builder.AppendLine('<h3>Warnings</h3><ul>')
            foreach ($warning in $warnings) { [void]$builder.AppendLine("<li>$(& $encode $warning)</li>") }
            [void]$builder.AppendLine('</ul>')
        }
    }

    [void]$builder.AppendLine('</body></html>')
    return $builder.ToString()
}

function ConvertTo-OIFlatInspectionResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object]$Result
    )

    process {
        [pscustomobject]@{
            Success                  = $Result.Success
            File                     = $Result.File
            OffsetInput              = $Result.OffsetInput
            OffsetDecimal            = $Result.OffsetDecimal
            OffsetHex                = $Result.OffsetHex
            FileSize                 = $Result.FileSize
            EncodingRequested        = $Result.EncodingRequested
            EncodingDetected         = $Result.EncodingDetected
            LineNumber               = $Result.LineNumber
            CharacterPosition        = $Result.CharacterPosition
            PreviewCharacterPosition = $Result.PreviewCharacterPosition
            BytePositionInLine       = $Result.BytePositionInLine
            TargetByteHex            = $Result.TargetByteHex
            TargetByteDecimal        = $Result.TargetByteDecimal
            CompareFile              = $Result.CompareFile
            CompareByteHex           = $Result.CompareByteHex
            CompareByteDecimal       = $Result.CompareByteDecimal
            BytesDiffer              = $Result.BytesDiffer
            WindowStartOffset        = $Result.WindowStartOffset
            WindowEndOffset          = $Result.WindowEndOffset
            LineText                 = $Result.LineText
            LineTextTruncated        = $Result.LineTextTruncated
            DurationMs               = $Result.DurationMs
            Warnings                 = @($Result.Warnings) -join '; '
            Error                    = $Result.Error
        }
    }
}

function Write-OIHumanInspectionResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Result,

        [Parameter(Mandatory = $true)]
        [int]$Index,

        [Parameter(Mandatory = $true)]
        [int]$Total
    )

    Write-Host ''
    Write-Host ('=' * 100) -ForegroundColor DarkYellow
    Write-Host "Result ($Index/$Total): $($Result.File)" -ForegroundColor Green
    Write-Host "Offset input:      $($Result.OffsetInput)" -ForegroundColor Green
    Write-Host "Offset decimal:    $($Result.OffsetDecimal)" -ForegroundColor Green
    Write-Host "Offset hex:        $($Result.OffsetHex)" -ForegroundColor Green
    Write-Host "File size:         $($Result.FileSize) bytes" -ForegroundColor Green
    Write-Host "Encoding:          $($Result.EncodingDetected) (requested: $($Result.EncodingRequested))" -ForegroundColor Green

    if (-not $Result.Success) {
        Write-Host "Error:             $($Result.Error)" -ForegroundColor Red
        Write-Host ('=' * 100) -ForegroundColor DarkCyan
        return
    }

    Write-Host "Line number:       $($Result.LineNumber)" -ForegroundColor Green
    Write-Host "Byte in line:      $($Result.BytePositionInLine)" -ForegroundColor Green
    if ($null -ne $Result.CharacterPosition) {
        Write-Host "Character index:   $($Result.CharacterPosition)" -ForegroundColor Green
    }
    Write-Host "Target byte:       $($Result.TargetByteHex) ($($Result.TargetByteDecimal))" -ForegroundColor Green

    if ($Result.CompareFile) {
        Write-Host "Compare file:      $($Result.CompareFile)" -ForegroundColor Cyan
        Write-Host "Compare byte:      $($Result.CompareByteHex) ($($Result.CompareByteDecimal))" -ForegroundColor Cyan
        Write-Host "Bytes differ:      $($Result.BytesDiffer)" -ForegroundColor Cyan
    }

    if (@($Result.ContextLines).Count -gt 0) {
        Write-Host ''
        Write-Host ('-' * 40 + ' Source Context ' + '-' * 44) -ForegroundColor DarkYellow
        foreach ($line in $Result.ContextLines) {
            $prefix = ('{0,8} | ' -f $line.LineNumber)
            if ($line.IsTarget) {
                Write-Host -NoNewline $prefix -ForegroundColor Yellow
                Write-Host $line.Text -ForegroundColor Green

                if ($null -ne $Result.PreviewCharacterPosition) {
                    $caretPadding = $prefix.Length + [int]$Result.PreviewCharacterPosition
                    Write-Host ((' ' * $caretPadding) + '^') -ForegroundColor Yellow
                }
            }
            else {
                Write-Host -NoNewline $prefix -ForegroundColor DarkGray
                Write-Host $line.Text -ForegroundColor Gray
            }
        }
    }

    Write-Host ''
    Write-Host ('-' * 43 + ' Hex Dump ' + '-' * 47) -ForegroundColor DarkYellow
    foreach ($row in $Result.HexDump) {
        Write-Host -NoNewline "$($row.Offset)  " -ForegroundColor Green
        foreach ($part in $row.HexParts) {
            if ($part.IsHighlight) {
                Write-Host -NoNewline "$($part.Text) " -ForegroundColor Yellow
            }
            else {
                Write-Host -NoNewline "$($part.Text) " -ForegroundColor Green
            }
        }

        $padding = 3 * (16 - @($row.HexParts).Count)
        if ($padding -gt 0) { Write-Host -NoNewline (' ' * $padding) }
        Write-Host " $($row.Ascii)" -ForegroundColor Green
    }

    foreach ($warning in @($Result.Warnings)) {
        Write-Host "Warning: $warning" -ForegroundColor Yellow
    }

    Write-Host ('=' * 100) -ForegroundColor DarkCyan
}

function Write-OIInspectionOutput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Results,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Human', 'Object', 'Json', 'Csv', 'CsvFile')]
        [string]$Mode,

        [AllowNull()]
        [string]$CsvPath
    )

    switch ($Mode) {
        'Object' {
            return $Results
        }
        'Json' {
            return (ConvertTo-Json -InputObject @($Results) -Depth 12)
        }
        'Csv' {
            return @($Results | ConvertTo-OIFlatInspectionResult | ConvertTo-Csv -NoTypeInformation)
        }
        'CsvFile' {
            $parent = Split-Path -Parent $CsvPath
            if ($parent -and -not (Test-Path -LiteralPath $parent)) {
                $null = New-Item -ItemType Directory -Path $parent -Force
            }
            $Results | ConvertTo-OIFlatInspectionResult | Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
            return (Get-Item -LiteralPath $CsvPath)
        }
        default {
            Write-OIBanner
            for ($index = 0; $index -lt $Results.Count; $index++) {
                Write-OIHumanInspectionResult -Result $Results[$index] -Index ($index + 1) -Total $Results.Count
            }
        }
    }
}
