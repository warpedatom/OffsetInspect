# Pester tests for OffsetInspect.
# These tests exercise the CLI script and module wrapper with decimal offsets,
# prefixed hex offsets, plain hex offsets, multi-file handling, and failures.

$RepoRoot   = Split-Path -Parent $PSScriptRoot
$ScriptPath = Join-Path $RepoRoot 'OffsetInspect.ps1'
$ModulePath = Join-Path $RepoRoot 'module/OffsetInspect.psd1'

Describe 'OffsetInspect CLI' {
    BeforeAll {
        $script:TestDir = Join-Path $TestDrive 'OffsetInspectFixtures'
        New-Item -ItemType Directory -Path $script:TestDir -Force | Out-Null

        $script:SampleA = Join-Path $script:TestDir 'sample-a.txt'
        $script:SampleB = Join-Path $script:TestDir 'sample-b.txt'

        Set-Content -LiteralPath $script:SampleA -Value "alpha`nbravo`ncharlie" -NoNewline -Encoding ASCII
        Set-Content -LiteralPath $script:SampleB -Value "red`ngreen`nblue" -NoNewline -Encoding ASCII
    }

    It 'resolves a decimal offset to the expected line number' {
        $output = & $ScriptPath -FilePaths $script:SampleA -OffsetInputs '6' -ByteWindow 4 2>&1 | Out-String
        $LASTEXITCODE | Should -Be 0
        $output | Should -Match 'Offset \(decimal\):\s+6'
        $output | Should -Match 'Line Number:\s+2'
        $output | Should -Match 'Line 2: bravo'
    }

    It 'accepts a 0x-prefixed hexadecimal offset' {
        $output = & $ScriptPath -FilePaths $script:SampleA -OffsetInputs '0x6' -ByteWindow 4 2>&1 | Out-String
        $LASTEXITCODE | Should -Be 0
        $output | Should -Match 'Offset \(decimal\):\s+6'
        $output | Should -Match 'Line Number:\s+2'
    }

    It 'accepts a plain hexadecimal offset containing A-F characters' {
        $output = & $ScriptPath -FilePaths $script:SampleA -OffsetInputs '0A' -ByteWindow 4 2>&1 | Out-String
        $LASTEXITCODE | Should -Be 0
        $output | Should -Match 'Offset \(decimal\):\s+10'
        $output | Should -Match 'Line Number:\s+2'
    }

    It 'reuses a single offset across multiple files' {
        $output = & $ScriptPath -FilePaths $script:SampleA,$script:SampleB -OffsetInputs '1' -ByteWindow 2 2>&1 | Out-String
        $LASTEXITCODE | Should -Be 0
        $output | Should -Match "reusing it for all 2 files"
        $output | Should -Match 'File \(1/2\)'
        $output | Should -Match 'File \(2/2\)'
    }

    It 'returns a non-zero exit code when a file is missing' {
        $missing = Join-Path $script:TestDir 'missing.txt'
        $output = & $ScriptPath -FilePaths $missing -OffsetInputs '1' -ByteWindow 2 2>&1 | Out-String
        $LASTEXITCODE | Should -Be 1
        $output | Should -Match 'File not found'
    }

    It 'returns a non-zero exit code when an offset is outside the file size' {
        $output = & $ScriptPath -FilePaths $script:SampleA -OffsetInputs '9999' -ByteWindow 2 2>&1 | Out-String
        $LASTEXITCODE | Should -Be 1
        $output | Should -Match 'exceeds file size'
    }

    It 'throws when the number of offsets does not match the number of files' {
        { & $ScriptPath -FilePaths $script:SampleA,$script:SampleB -OffsetInputs '1','2','3' -ByteWindow 2 } |
            Should -Throw '*number of offsets provided*'
    }
}

Describe 'OffsetInspect module' {
    BeforeAll {
        $script:TestDir = Join-Path $TestDrive 'OffsetInspectModuleFixtures'
        New-Item -ItemType Directory -Path $script:TestDir -Force | Out-Null

        $script:SampleModuleFile = Join-Path $script:TestDir 'module-sample.txt'
        Set-Content -LiteralPath $script:SampleModuleFile -Value "one`ntwo`nthree" -NoNewline -Encoding ASCII
    }

    It 'imports the module and exports Invoke-OffsetInspect' {
        Import-Module $ModulePath -Force
        Get-Command Invoke-OffsetInspect | Should -Not -BeNullOrEmpty
    }

    It 'invokes the root script through the module wrapper' {
        Import-Module $ModulePath -Force
        $output = Invoke-OffsetInspect -FilePaths $script:SampleModuleFile -OffsetInputs '4' -ByteWindow 3 2>&1 | Out-String
        $LASTEXITCODE | Should -Be 0
        $output | Should -Match 'Offset \(decimal\):\s+4'
        $output | Should -Match 'Line Number:\s+2'
    }
}
