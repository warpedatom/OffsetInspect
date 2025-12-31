# Pester tests for OffsetInspect

# Helper to find the module manifest reliably
function Get-OffsetInspectManifestPath {
    param(
        [string]$TestsRoot
    )

    $repoRoot = Split-Path -Parent $TestsRoot

    $manifestItem = Get-ChildItem -Path $repoRoot -Filter 'OffsetInspect.psd1' -Recurse -File |
        Select-Object -First 1

    if (-not $manifestItem) {
        throw "Could not find 'OffsetInspect.psd1' anywhere under '$repoRoot'. " +
              "Make sure your module manifest exists and is committed."
    }

    return $manifestItem.FullName
}

# ---------------- Manifest tests ----------------

Describe 'OffsetInspect module manifest' {

    BeforeAll {
        # Resolve once per Describe, inside Pester’s scope
        $ManifestPath = Get-OffsetInspectManifestPath -TestsRoot $PSScriptRoot
        Write-Host "Using manifest (manifest describe): $ManifestPath"
    }

    It 'exists' {
        Test-Path $ManifestPath | Should -BeTrue
    }

    It 'has a valid manifest' {
        { Test-ModuleManifest -Path $ManifestPath } |
            Should -Not -Throw
    }

    It 'has expected module version' {
        $m = Test-ModuleManifest -Path $ManifestPath
        # Adjust regex if you bump major/minor later
        $m.Version.ToString() | Should -Match '^1\.0\.\d+$'
    }
}

# ---------------- Export tests ----------------

Describe 'OffsetInspect module exports' {

    BeforeAll {
        $ManifestPath = Get-OffsetInspectManifestPath -TestsRoot $PSScriptRoot
        Write-Host "Using manifest (exports describe): $ManifestPath"

        # Import the module; throws if anything is wrong with manifest/module
        $ModuleInfo = Import-Module $ManifestPath -Force -PassThru
    }

    It 'imports without error' {
        { Import-Module $ManifestPath -Force } |
            Should -Not -Throw
    }

    It 'exports Invoke-OffsetInspect' {
        $cmd = Get-Command Invoke-OffsetInspect -Module $ModuleInfo.Name -ErrorAction Stop
        $cmd | Should -Not -BeNullOrEmpty
    }

    It 'FilePaths and OffsetInputs are string[] parameters' {
        $cmd = Get-Command Invoke-OffsetInspect -Module $ModuleInfo.Name -ErrorAction Stop

        $cmd.Parameters['FilePaths'].ParameterType    | Should -Be ([string[]])
        $cmd.Parameters['OffsetInputs'].ParameterType | Should -Be ([string[]])
    }
}