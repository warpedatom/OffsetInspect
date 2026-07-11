Set-StrictMode -Version 2.0

$privateScripts = Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'Private') -Filter '*.ps1' -File | Sort-Object Name
$publicScripts = Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'Public') -Filter '*.ps1' -File | Sort-Object Name

foreach ($scriptFile in @($privateScripts) + @($publicScripts)) {
    . $scriptFile.FullName
}

Export-ModuleMember -Function @(
    'Invoke-OffsetInspect',
    'Invoke-OffsetThreatScan'
)
