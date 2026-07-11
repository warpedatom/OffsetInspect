[CmdletBinding()]
param(
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
    [switch]$SkipAnalyzer
)

$ErrorActionPreference = 'Stop'
$manifestPath = Join-Path (Join-Path (Join-Path $RepoRoot 'module') 'OffsetInspect') 'OffsetInspect.psd1'
$settingsPath = Join-Path $RepoRoot 'PSScriptAnalyzerSettings.psd1'
$testsPath = Join-Path $RepoRoot 'tests'

Write-Host '[1/4] Validating module manifest...'
$manifest = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop

Write-Host '[2/4] Importing isolated module package...'
$tempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('OffsetInspect-Test-' + [guid]::NewGuid().ToString('N'))
$tempModule = Join-Path $tempRoot 'OffsetInspect'
$null = New-Item -ItemType Directory -Path $tempRoot -Force

try {
    Copy-Item -LiteralPath (Split-Path -Parent $manifestPath) -Destination $tempModule -Recurse -Force
    Import-Module (Join-Path $tempModule 'OffsetInspect.psd1') -Force -ErrorAction Stop

    $exports = @(Get-Command -Module OffsetInspect | Select-Object -ExpandProperty Name | Sort-Object)
    $expected = @('Invoke-OffsetInspect', 'Invoke-OffsetThreatScan')
    if (($exports -join ',') -ne ($expected -join ',')) {
        throw "Unexpected exports: $($exports -join ', ')"
    }
}
finally {
    Remove-Module OffsetInspect -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $tempRoot -Recurse -Force -ErrorAction SilentlyContinue
}

if (-not $SkipAnalyzer) {
    Write-Host '[3/4] Running PSScriptAnalyzer...'
    $analyzer = Get-Module -ListAvailable -Name PSScriptAnalyzer |
        Where-Object Version -eq ([version]'1.25.0') |
        Select-Object -First 1
    if ($null -eq $analyzer) {
        throw 'PSScriptAnalyzer 1.25.0 is not installed. Install the pinned version or run with -SkipAnalyzer.'
    }

    Import-Module PSScriptAnalyzer -RequiredVersion 1.25.0 -Force -ErrorAction Stop
    $analysis = @(Invoke-ScriptAnalyzer -Path $RepoRoot -Recurse -Settings $settingsPath)
    if ($analysis.Count -gt 0) {
        $analysis | Format-Table RuleName, Severity, ScriptName, Line, Message -AutoSize | Out-String | Write-Host
        throw "PSScriptAnalyzer reported $($analysis.Count) issue(s)."
    }
}
else {
    Write-Host '[3/4] PSScriptAnalyzer skipped.'
}

Write-Host '[4/4] Running Pester...'
$pester = Get-Module -ListAvailable -Name Pester |
    Where-Object Version -eq ([version]'5.7.1') |
    Select-Object -First 1
if ($null -eq $pester) {
    throw 'Pester 5.7.1 is not installed.'
}

Import-Module Pester -RequiredVersion 5.7.1 -Force -ErrorAction Stop
$config = New-PesterConfiguration
$config.Run.Path = $testsPath
$config.Run.Exit = $false
$config.Run.PassThru = $true
$config.Output.Verbosity = 'Detailed'
$result = Invoke-Pester -Configuration $config

if ($null -eq $result) {
    throw 'Pester did not return a validation result.'
}

if ($result.Result -ne 'Passed') {
    throw (
        'Pester validation failed. Result: {0}; Failed tests: {1}; Failed containers: {2}' -f
        $result.Result,
        $result.FailedCount,
        $result.FailedContainersCount
    )
}

Write-Host "Validated OffsetInspect $($manifest.Version) successfully." -ForegroundColor Green
