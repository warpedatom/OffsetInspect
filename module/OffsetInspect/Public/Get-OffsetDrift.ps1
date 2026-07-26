function Get-OffsetDrift {
    <#
    .SYNOPSIS
        Analyzes a drift journal to explain how a file's detectability changed over time.

    .DESCRIPTION
        Reads the NDJSON journal written by Add-OffsetDriftEntry, groups snapshots by file, and
        for each consecutive pair explains the change: whether detection moved because the FILE
        changed (different SHA-256), because Defender's SIGNATURES changed (different signature
        version), or for neither reason (a non-deterministic provider result). This is the
        direct answer to "it was detected before and now it isn't - why?".

        Read-only and cross-platform.

    .PARAMETER JournalPath
        NDJSON journal to read. Defaults to OffsetInspect\drift.ndjson under LocalApplicationData.

    .PARAMETER FilePath
        Only analyze snapshots for this file (matched by canonical full path).

    .PARAMETER FileSha256
        Only analyze snapshots whose recorded SHA-256 matches.

    .EXAMPLE
        Get-OffsetDrift -FilePath .\sample.ps1 | Select-Object -ExpandProperty Transitions

    .EXAMPLE
        Get-OffsetDrift | Where-Object EverChanged
    #>
    [CmdletBinding()]
    [OutputType('OffsetInspect.DriftReport')]
    param(
        [ValidateNotNullOrEmpty()]
        [string]$JournalPath = (Join-Path ([System.Environment]::GetFolderPath('LocalApplicationData')) 'OffsetInspect/drift.ndjson'),

        [AllowNull()]
        [string]$FilePath,

        [AllowNull()]
        [string]$FileSha256
    )

    if (-not (Test-Path -LiteralPath $JournalPath)) {
        throw "Drift journal not found: $JournalPath"
    }

    $filterPath = $null
    if (-not [string]::IsNullOrWhiteSpace($FilePath)) {
        $filterPath = try { [System.IO.Path]::GetFullPath($FilePath) } catch { $FilePath }
    }

    $records = New-Object 'System.Collections.Generic.List[object]'
    foreach ($line in [System.IO.File]::ReadAllLines($JournalPath)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        # Each line is a single JSON object, so ConvertFrom-Json is edition-safe here.
        try { $obj = ConvertFrom-Json -InputObject $line }
        catch { Write-Verbose 'Skipping malformed journal line.'; continue }
        if ($null -eq $obj) { continue }

        $recFile = [string](Get-OIResultProperty -InputObject $obj -Name 'File')
        if ($null -ne $filterPath) {
            $recFull = try { [System.IO.Path]::GetFullPath($recFile) } catch { $recFile }
            if ($recFull -ne $filterPath) { continue }
        }
        if (-not [string]::IsNullOrWhiteSpace($FileSha256)) {
            if ([string](Get-OIResultProperty -InputObject $obj -Name 'FileSha256') -ne $FileSha256) { continue }
        }
        $records.Add($obj)
    }

    if ($records.Count -eq 0) { return }

    $groups = $records | Group-Object -Property { $f = Get-OIResultProperty -InputObject $_ -Name 'File'; try { [System.IO.Path]::GetFullPath([string]$f) } catch { [string]$f } }
    foreach ($group in $groups) {
        $ordered = @($group.Group | Sort-Object -Property TimestampUtc)
        Compare-OIDriftTimeline -Snapshots $ordered
    }
}
