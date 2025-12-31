# Pester tests for OffsetInspect module / manifest

# Repo root = parent of /tests
$repoRoot   = Split-Path -Parent $PSScriptRoot
$moduleRoot = Join-Path $repoRoot 'module'

# Manifest lives in /module/OffsetInspect.psd1
$script:ManifestPath = Join-Path $moduleRoot 'OffsetInspect.psd1'

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
        # Keep this in sync with your current release line
        $m.Version.ToString() | Should -Match '^1\.0\.\d+$'
    }
}

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

        $cmd.Parameters['FilePaths'].ParameterType  | Should -Be ([string[]])
        $cmd.Parameters['OffsetInputs'].ParameterType | Should -Be ([string[]])
    }
}