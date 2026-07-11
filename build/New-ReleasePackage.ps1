[CmdletBinding()]
param(
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
    [string]$OutputDirectory = (Join-Path (Split-Path -Parent $PSScriptRoot) 'artifacts'),
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
$moduleSource = Join-Path (Join-Path $RepoRoot 'module') 'OffsetInspect'
$manifestPath = Join-Path $moduleSource 'OffsetInspect.psd1'
$manifest = Test-ModuleManifest -Path $manifestPath -ErrorAction Stop
$version = $manifest.Version.ToString()

if (-not $SkipTests) {
    & (Join-Path $PSScriptRoot 'Test-Module.ps1') -RepoRoot $RepoRoot
}

$forbidden = @(Get-ChildItem -LiteralPath $moduleSource -Recurse -File | Where-Object {
    $_.Extension -in @('.exe', '.dll', '.pdb', '.suo', '.user') -or $_.FullName -match '[\\/](bin|obj|\.vs)[\\/]'
})
if ($forbidden.Count -gt 0) {
    throw "Forbidden build artifacts were found in the module package: $($forbidden.FullName -join ', ')"
}

if (Test-Path -LiteralPath $OutputDirectory) {
    Remove-Item -LiteralPath $OutputDirectory -Recurse -Force
}
$null = New-Item -ItemType Directory -Path $OutputDirectory -Force

$stagingRoot = Join-Path $OutputDirectory 'staging'
$stagedModule = Join-Path $stagingRoot 'OffsetInspect'
$null = New-Item -ItemType Directory -Path $stagingRoot -Force
Copy-Item -LiteralPath $moduleSource -Destination $stagedModule -Recurse -Force

# Validate the exact isolated tree that will be published.
Test-ModuleManifest -Path (Join-Path $stagedModule 'OffsetInspect.psd1') -ErrorAction Stop | Out-Null
Import-Module (Join-Path $stagedModule 'OffsetInspect.psd1') -Force -ErrorAction Stop
Remove-Module OffsetInspect -Force

$archivePath = Join-Path $OutputDirectory ("OffsetInspect-{0}.zip" -f $version)
Add-Type -AssemblyName System.IO.Compression -ErrorAction Stop

$archiveStream = $null
$archive = $null
$fixedTimestamp = [DateTimeOffset]::Parse('2000-01-01T00:00:00+00:00', [Globalization.CultureInfo]::InvariantCulture)
try {
    $archiveStream = [System.IO.File]::Open(
        $archivePath,
        [System.IO.FileMode]::Create,
        [System.IO.FileAccess]::ReadWrite,
        [System.IO.FileShare]::None
    )
    $archive = New-Object -TypeName System.IO.Compression.ZipArchive -ArgumentList @(
        $archiveStream,
        [System.IO.Compression.ZipArchiveMode]::Create,
        $false
    )

    $stagedRoot = (Resolve-Path -LiteralPath $stagingRoot).Path
    foreach ($file in (Get-ChildItem -LiteralPath $stagedModule -Recurse -File | Sort-Object FullName)) {
        $relativePath = $file.FullName.Substring($stagedRoot.Length).TrimStart([char[]]'\/')
        $entryName = $relativePath.Replace('\', '/')
        $entry = $archive.CreateEntry($entryName, [System.IO.Compression.CompressionLevel]::NoCompression)
        $entry.LastWriteTime = $fixedTimestamp

        $entryStream = $null
        $sourceFileStream = $null
        try {
            $entryStream = $entry.Open()
            $sourceFileStream = [System.IO.File]::OpenRead($file.FullName)
            $sourceFileStream.CopyTo($entryStream)
        }
        finally {
            if ($null -ne $sourceFileStream) { $sourceFileStream.Dispose() }
            if ($null -ne $entryStream) { $entryStream.Dispose() }
        }
    }
}
finally {
    if ($null -ne $archive) { $archive.Dispose() }
    if ($null -ne $archiveStream) { $archiveStream.Dispose() }
    Remove-Item -LiteralPath $stagingRoot -Recurse -Force -ErrorAction SilentlyContinue
}

$hash = Get-FileHash -LiteralPath $archivePath -Algorithm SHA256
$checksumPath = Join-Path $OutputDirectory ("OffsetInspect-{0}.sha256" -f $version)
"$($hash.Hash.ToLowerInvariant())  $([System.IO.Path]::GetFileName($archivePath))" | Set-Content -LiteralPath $checksumPath -Encoding ASCII

[pscustomobject]@{
    Version      = $version
    Archive      = $archivePath
    Sha256       = $hash.Hash.ToLowerInvariant()
    ChecksumFile = $checksumPath
}
