# Basic Pester tests for OffsetInspect

# Repo root (parent of the tests folder)
$root     = Split-Path -Parent $PSScriptRoot
$manifest = Join-Path $root 'OffsetInspect.psd1'

Describe 'OffsetInspect module manifest' {
    It 'exists' {
        Test-Path -Path $manifest | Should -BeTrue
    }
}

Describe 'OffsetInspect module import and exports' {
    It 'imports without error' {
        { Import-Module -Name $manifest -Force } | Should -Not -Throw
    }

    It 'exports Invoke-OffsetInspect' {
        Import-Module -Name $manifest -Force
        Get-Command -Name Invoke-OffsetInspect -ErrorAction Stop |
            Should -Not -BeNullOrEmpty
    }
}
