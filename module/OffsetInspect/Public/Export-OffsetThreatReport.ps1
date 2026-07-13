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

    .EXAMPLE
        Invoke-OffsetThreatScan .\sample.ps1 -Engine AMSI -PassThru |
            Export-OffsetThreatReport -Path .\report.html -Format Html

    .EXAMPLE
        $results | Export-OffsetThreatReport -Path .\engagement.md
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

        [switch]$IncludeIoc
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

        if ($IncludeIoc) {
            foreach ($record in $records) {
                $fileProperty = $record.PSObject.Properties['File']
                if ($null -ne $fileProperty -and -not [string]::IsNullOrWhiteSpace([string]$record.File) -and (Test-Path -LiteralPath $record.File)) {
                    try {
                        $ioc = Get-OffsetIOC -FilePath $record.File
                        Add-Member -InputObject $record -NotePropertyName 'IocPanel' -NotePropertyValue $ioc -Force
                    }
                    catch {
                        Write-Verbose "IOC enrichment failed for $($record.File): $($_.Exception.Message)"
                    }
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
