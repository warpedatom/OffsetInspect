# Basic Pester tests for OffsetInspect

$root       = Split-Path -Parent $PSScriptRoot
$modulePath = Join-Path $root 'module'
$manifest   = Join-Path $modulePath 'OffsetInspect.psd1'

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
        Get-Command Invoke-OffsetInspect -ErrorAction Stop | Should -Not -BeNullOrEmpty
    }
}