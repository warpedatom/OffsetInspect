Set-StrictMode -Version 2.0

$privateScripts = Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -File | Sort-Object Name
$publicScripts = Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' -File | Sort-Object Name

foreach ($scriptFile in @($privateScripts) + @($publicScripts)) {
    . $scriptFile.FullName
}

Export-ModuleMember -Function @(
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
