# Pester tests for OffsetInspect module / manifest

# --------------- Path discovery ---------------

# tests folder
$repoRoot = Split-Path -Parent $PSScriptRoot

# Find the first OffsetInspect.psd1 anywhere under the repo
$manifestItem = Get-ChildItem -Path $repoRoot -Filter 'OffsetInspect.psd1' -Recurse -File |
    Select-Object -First 1

if (-not $manifestItem) {
    throw "Could not find 'OffsetInspect.psd1' anywhere under '$repoRoot'. " +
          "Make sure your module manifest exists and is committed."
}

$script:ManifestPath = $manifestItem.FullName

Write-Host "Using manifest at: $script:ManifestPath"

# --------------- Manifest tests ---------------

Describe 'OffsetInspect module manifest' {

    It 'exists' {
        Test-Path $script:ManifestPath | Should -BeTrue
    }

    It 'has a valid manifest' {
        { Test-ModuleManifest -Path $script:ManifestPath } |
            Should -Not -Throw
    }

    It 'has expected module version' {
        $m = Test-ModuleManifest -Path $script:ManifestPath
        # Keep this pattern in sync with your release scheme
        $m.Version.ToString() | Should -Match '^1\.0\.\d+$'
    }
}

# --------------- Export tests ---------------

Describe 'OffsetInspect module exports' {

    BeforeAll {
        $script:ModuleInfo = Import-Module $script:ManifestPath -Force -PassThru
    }

    It 'imports without error' {
        { Import-Module $script:ManifestPath -Force } |
            Should -Not -Throw
    }

    It 'exports Invoke-OffsetInspect' {
        $cmd = Get-Command Invoke-OffsetInspect -Module $script:ModuleInfo.Name -ErrorAction Stop
        $cmd | Should -Not -BeNullOrEmpty
    }

    It 'exposes FilePaths and OffsetInputs as string[] parameters' {
        $cmd = Get-Command Invoke-OffsetInspect -Module $script:ModuleInfo.Name -ErrorAction Stop

        $cmd.Parameters['FilePaths'].ParameterType     | Should -Be ([string[]])
        $cmd.Parameters['OffsetInputs'].ParameterType  | Should -Be ([string[]])
    }
}