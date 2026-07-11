<#
.SYNOPSIS
    Measures batched OffsetInspect performance against a deterministic text fixture.

.DESCRIPTION
    Creates a temporary file of approximately the requested size, chooses evenly
    distributed byte offsets, and measures one batched Invoke-OffsetInspect call.
    The fixture is removed unless -KeepFile is supplied.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 4096)]
    [int]$FileSizeMiB = 16,

    [ValidateRange(1, 100000)]
    [int]$OffsetCount = 1000,

    [ValidateRange(0, 4096)]
    [int]$ByteWindow = 16,

    [ValidateRange(0, 100)]
    [int]$ContextLines = 0,

    [string]$OutputPath = (Join-Path ([System.IO.Path]::GetTempPath()) 'OffsetInspect-benchmark.txt'),

    [switch]$KeepFile
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
$manifestPath = Join-Path (Join-Path (Join-Path $repoRoot 'module') 'OffsetInspect') 'OffsetInspect.psd1'
$targetLength = [int64]$FileSizeMiB * 1MB
$line = 'OffsetInspect deterministic benchmark line 0123456789 ABCDEFGHIJKLMNOPQRSTUVWXYZ'
$encoding = New-Object System.Text.UTF8Encoding($false)
$writer = $null

try {
    $directory = Split-Path -Parent $OutputPath
    if ($directory -and -not (Test-Path -LiteralPath $directory)) {
        $null = New-Item -ItemType Directory -Path $directory -Force
    }

    $writer = New-Object System.IO.StreamWriter($OutputPath, $false, $encoding, 65536)
    while ($writer.BaseStream.Position -lt $targetLength) {
        $writer.WriteLine($line)
    }
    $writer.Flush()
    $writer.Dispose()
    $writer = $null

    $fileLength = (Get-Item -LiteralPath $OutputPath).Length
    $offsets = New-Object 'System.Collections.Generic.List[string]'
    if ($OffsetCount -eq 1) {
        $offsets.Add([string][Math]::Floor($fileLength / 2))
    }
    else {
        for ($index = 0; $index -lt $OffsetCount; $index++) {
            $fraction = [double]$index / [double]($OffsetCount - 1)
            $offset = [int64][Math]::Floor($fraction * ($fileLength - 1))
            $offsets.Add([string]$offset)
        }
    }

    Import-Module $manifestPath -Force -ErrorAction Stop
    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    $results = @(Invoke-OffsetInspect `
        -FilePaths $OutputPath `
        -OffsetInputs $offsets.ToArray() `
        -ByteWindow $ByteWindow `
        -ContextLines $ContextLines `
        -PassThru `
        -FailOnError)
    $stopwatch.Stop()

    [pscustomobject]@{
        FilePath          = (Resolve-Path -LiteralPath $OutputPath).Path
        FileSizeBytes     = $fileLength
        RequestedOffsets  = $OffsetCount
        ReturnedResults   = $results.Count
        DurationMs        = [Math]::Round($stopwatch.Elapsed.TotalMilliseconds, 2)
        ResultsPerSecond  = if ($stopwatch.Elapsed.TotalSeconds -gt 0) {
            [Math]::Round($results.Count / $stopwatch.Elapsed.TotalSeconds, 2)
        }
        else {
            $null
        }
        ProcessId         = $PID
        PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        Platform          = if ($PSVersionTable.PSEdition -eq 'Desktop') { 'Windows PowerShell' } else { $PSVersionTable.Platform }
    }
}
finally {
    if ($null -ne $writer) {
        $writer.Dispose()
    }
    Remove-Module OffsetInspect -Force -ErrorAction SilentlyContinue
    if (-not $KeepFile) {
        Remove-Item -LiteralPath $OutputPath -Force -ErrorAction SilentlyContinue
    }
}
