<#
.SYNOPSIS
    Command-line wrapper for OffsetInspect threat-boundary analysis.
.DESCRIPTION
    Imports the repository-local module, invokes Invoke-OffsetThreatScan, and returns a process
    exit code suitable for shells and CI. Threat-provider scanning is Windows-only.
#>
[CmdletBinding(DefaultParameterSetName = 'Human')]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$FilePath,

    [ValidateSet('Auto', 'AMSI', 'Defender')]
    [string]$Engine = 'Auto',

    [ValidateSet('Auto', 'RawBytes', 'Text')]
    [string]$ScanMode = 'Auto',

    [ValidateSet('Auto', 'Default', 'UTF8', 'UTF16LE', 'UTF16BE', 'ASCII')]
    [string]$Encoding = 'Auto',

    [ValidateRange(1, 10)]
    [int]$RepeatCount = 2,

    [ValidateRange(1, 600)]
    [int]$TimeoutSeconds = 30,

    [ValidateRange(0, 4096)]
    [int]$ByteWindow = 64,

    [ValidateRange(0, 100)]
    [int]$ContextLines = 3,

    [ValidateRange(1024, 16777216)]
    [int]$MaxLineBytes = 1048576,

    [ValidateScript({ $_ -ge 1 })]
    [int64]$MaxScanBytes = 268435456,

    [switch]$Force,
    [switch]$NoProgress,
    [switch]$IncludeProviderOutput,

    [Parameter(Mandatory = $true, ParameterSetName = 'Object')]
    [switch]$PassThru,

    [Parameter(Mandatory = $true, ParameterSetName = 'Json')]
    [switch]$Json,

    [Parameter(Mandatory = $true, ParameterSetName = 'Csv')]
    [switch]$Csv,

    [Parameter(Mandatory = $true, ParameterSetName = 'CsvFile')]
    [ValidateNotNullOrEmpty()]
    [string]$CsvPath
)

$modulePath = Join-Path (Join-Path (Join-Path $PSScriptRoot 'module') 'OffsetInspect') 'OffsetInspect.psd1'

try {
    Import-Module $modulePath -Force -ErrorAction Stop
    $arguments = @{}
    foreach ($name in $PSBoundParameters.Keys) {
        $arguments[$name] = $PSBoundParameters[$name]
    }
    $arguments.FailOnError = $true
    Invoke-OffsetThreatScan @arguments
    exit 0
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
