# Basic Pester tests for OffsetInspect
# (can be expanded later with more detailed checks)

$root     = Split-Path -Parent $PSScriptRoot
$manifest = Join-Path $root 'OffsetInspect.psd1'

Describe 'OffsetInspect module manifest' {
    It 'exists' {
        Test-Path $manifest | Should -BeTrue
    }
}

Describe 'OffsetInspect module import and exports' {
    It 'imports without error' {
        { Import-Module $manifest -Force } | Should -Not -Throw
    }

    It 'exports Invoke-OffsetInspect' {
        Import-Module $manifest -Force
        $cmd = Get-Command Invoke-OffsetInspect -ErrorAction Stop
        $cmd | Should -Not -BeNullOrEmpty
    }
}