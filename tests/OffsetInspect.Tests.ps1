# Pester discovery and execution occur in separate phases.
# Import the module during discovery so InModuleScope can resolve it.
$DiscoveryRepoRoot = Split-Path -Parent $PSScriptRoot
$DiscoveryModuleDirectory = Join-Path (Join-Path $DiscoveryRepoRoot 'module') 'OffsetInspect'
$DiscoveryManifestPath = Join-Path $DiscoveryModuleDirectory 'OffsetInspect.psd1'

Import-Module $DiscoveryManifestPath -Force -ErrorAction Stop

BeforeAll {
    $script:RepoRoot = Split-Path -Parent $PSScriptRoot
    $script:ModuleDirectory = Join-Path (Join-Path $script:RepoRoot 'module') 'OffsetInspect'
    $script:ManifestPath = Join-Path $script:ModuleDirectory 'OffsetInspect.psd1'
    $script:InspectionCorePath = Join-Path (Join-Path $script:ModuleDirectory 'Private') 'Core.Inspection.ps1'
    $script:InspectionPublicPath = Join-Path (Join-Path $script:ModuleDirectory 'Public') 'Invoke-OffsetInspect.ps1'

    function New-OITestTextFile {
        param(
            [Parameter(Mandatory = $true)]
            [string]$Name,

            [Parameter(Mandatory = $true)]
            [string]$Content,

            [System.Text.Encoding]$Encoding = [System.Text.Encoding]::ASCII
        )

        $Path = Join-Path $TestDrive $Name
        [System.IO.File]::WriteAllText($Path, $Content, $Encoding)
        return $Path
    }

    Import-Module $script:ManifestPath -Force -ErrorAction Stop
}

AfterAll {
    Remove-Module OffsetInspect -Force -ErrorAction SilentlyContinue
}
Describe 'OffsetInspect module package' {
    It 'has a valid 3.0.0 manifest' {
        $manifest = Test-ModuleManifest -Path $ManifestPath -ErrorAction Stop
        $manifest.Version.ToString() | Should -Be '3.0.0'
        $manifest.RootModule | Should -Be 'OffsetInspect.psm1'
    }

    It 'exports only the supported public commands' {
        $commands = @(Get-Command -Module OffsetInspect | Select-Object -ExpandProperty Name | Sort-Object)
        ($commands -join ',') | Should -Be 'Compare-OffsetThreatResult,Export-OffsetThreatReport,Get-OffsetEntropy,Get-OffsetIOC,Get-OffsetPEInfo,Get-OffsetString,Invoke-OffsetClamScan,Invoke-OffsetInspect,Invoke-OffsetThreatScan,Invoke-OffsetThreatScanBatch,Invoke-OffsetThreatScanRegion,Invoke-OffsetYaraScan'
    }

    It 'imports from an isolated Gallery-style folder' {
        $isolatedParent = Join-Path $TestDrive 'isolated'
        $isolatedModule = Join-Path $isolatedParent 'OffsetInspect'
        $null = New-Item -ItemType Directory -Path $isolatedParent -Force
        Copy-Item -LiteralPath $ModuleDirectory -Destination $isolatedModule -Recurse -Force

        Remove-Module OffsetInspect -Force -ErrorAction SilentlyContinue
        { Import-Module (Join-Path $isolatedModule 'OffsetInspect.psd1') -Force -ErrorAction Stop } | Should -Not -Throw
        Get-Command Invoke-OffsetInspect -ErrorAction Stop | Should -Not -BeNullOrEmpty
        Get-Command Invoke-OffsetThreatScan -ErrorAction Stop | Should -Not -BeNullOrEmpty

        Remove-Module OffsetInspect -Force -ErrorAction SilentlyContinue
        Import-Module $ManifestPath -Force -ErrorAction Stop
    }

    It 'ships the repository license in the Gallery package' {
        $rootLicense = Get-Content -LiteralPath (Join-Path $RepoRoot 'LICENSE') -Raw
        $moduleLicense = Get-Content -LiteralPath (Join-Path $ModuleDirectory 'LICENSE') -Raw
        $moduleLicense | Should -BeExactly $rootLicense
    }

    It 'declares every Gallery package file in the manifest FileList' {
        $manifestData = Import-PowerShellDataFile -LiteralPath $ManifestPath
        $declared = @($manifestData.FileList | ForEach-Object { $_.Replace('\', '/') } | Sort-Object)
        $moduleRoot = (Resolve-Path -LiteralPath $ModuleDirectory).Path
        $actual = @(Get-ChildItem -LiteralPath $ModuleDirectory -Recurse -File | ForEach-Object {
            $_.FullName.Substring($moduleRoot.Length).TrimStart([char[]]'\/').Replace('\', '/')
        } | Sort-Object)

        ($declared -join "`n") | Should -BeExactly ($actual -join "`n")
    }

    It 'contains no executable or build artifacts in the Gallery package' {
        $forbidden = @(Get-ChildItem -LiteralPath $ModuleDirectory -Recurse -Force | Where-Object {
            (-not $_.PSIsContainer -and $_.Extension -in @('.exe', '.dll', '.pdb', '.suo', '.user')) -or
            ($_.PSIsContainer -and $_.Name -in @('bin', 'obj', '.vs'))
        })
        $forbidden.Count | Should -Be 0
    }

    It 'keeps whole-file reads out of the offset inspection core' {
        (Get-Content -LiteralPath $InspectionCorePath -Raw) | Should -Not -Match 'ReadAllBytes|ReadAllText'
    }

    It 'does not terminate the host process from module code' {
        $moduleScripts = Get-ChildItem -LiteralPath $ModuleDirectory -Recurse -File -Include '*.ps1', '*.psm1'
        foreach ($script in $moduleScripts) {
            (Get-Content -LiteralPath $script.FullName -Raw) | Should -Not -Match '(?im)^\s*exit(?:\s|$)'
        }
    }

    It 'opens inspection files before resolving encoding from the same stream' {
        $source = Get-Content -LiteralPath $InspectionPublicPath -Raw
        $source | Should -Match 'Open-OIFileContext'
        $source | Should -Not -Match 'Resolve-OIEncoding\s+-Path'
    }
}

Describe 'Invoke-OffsetInspect offset parsing and planning' {
    It 'maps a decimal offset to the correct line and target byte' {
        $sample = New-OITestTextFile -Name 'decimal.txt' -Content "alpha`nbeta`ngamma"
        $result = Invoke-OffsetInspect -FilePaths $sample -OffsetInputs '6' -PassThru

        $result.Success | Should -BeTrue
        $result.OffsetDecimal | Should -Be 6
        $result.OffsetHex | Should -Be '0x6'
        $result.LineNumber | Should -Be 2
        $result.TargetByteHex | Should -Be '62'
    }

    It 'accepts uppercase 0X, an h suffix, and unprefixed hexadecimal containing A-F' {
        $sample = New-OITestTextFile -Name 'hex.txt' -Content '0123456789ABCDEF'
        $results = @(Invoke-OffsetInspect -FilePaths $sample -OffsetInputs '0XA', 'Ah', '0A' -PassThru)

        $results.Count | Should -Be 3
        (@($results.OffsetDecimal | Select-Object -Unique) -join ',') | Should -Be '10'
    }

    It 'treats unprefixed numeric-only offsets as decimal' {
        $sample = New-OITestTextFile -Name 'numeric.txt' -Content '0123456789ABCDEF'
        $result = Invoke-OffsetInspect -FilePaths $sample -OffsetInputs '10' -PassThru
        $result.OffsetDecimal | Should -Be 10
    }

    It 'returns a structured failure for invalid offsets' {
        $sample = New-OITestTextFile -Name 'invalid.txt' -Content 'abcdef'
        $result = Invoke-OffsetInspect -FilePaths $sample -OffsetInputs 'xyz' -PassThru

        $result.Success | Should -BeFalse
        $result.Error | Should -Match 'Invalid offset'
    }


    It 'rejects hexadecimal values outside the signed 64-bit range' {
        $sample = New-OITestTextFile -Name 'overflow.txt' -Content 'abcdef'
        $result = Invoke-OffsetInspect -FilePaths $sample -OffsetInputs '0xFFFFFFFFFFFFFFFF' -PassThru

        $result.Success | Should -BeFalse
        $result.Error | Should -Match 'signed 64-bit range'
    }

    It 'returns a structured failure for out-of-range offsets' {
        $sample = New-OITestTextFile -Name 'range.txt' -Content 'abc'
        $result = Invoke-OffsetInspect -FilePaths $sample -OffsetInputs '3' -PassThru

        $result.Success | Should -BeFalse
        $result.Error | Should -Match 'outside the valid range'
    }

    It 'returns a structured failure for an empty file' {
        $sample = Join-Path $TestDrive 'empty.bin'
        [System.IO.File]::WriteAllBytes($sample, [byte[]]@())
        $result = Invoke-OffsetInspect -FilePaths $sample -OffsetInputs '0' -PassThru

        $result.Success | Should -BeFalse
        $result.Error | Should -Match 'empty'
    }

    It 'rejects ambiguous many-file many-offset plans' {
        $one = New-OITestTextFile -Name 'ambiguous-one.txt' -Content 'abc'
        $two = New-OITestTextFile -Name 'ambiguous-two.txt' -Content 'def'

        { Invoke-OffsetInspect -FilePaths $one, $two -OffsetInputs '0', '1', '2' -PassThru } | Should -Throw
    }
}

Describe 'Invoke-OffsetInspect context and encoding' {
    It 'returns the requested previous and following context lines' {
        $sample = New-OITestTextFile -Name 'context.txt' -Content "one`ntwo`nthree`nfour"
        $result = Invoke-OffsetInspect -FilePaths $sample -OffsetInputs '4' -ContextLines 1 -PassThru

        $result.LineNumber | Should -Be 2
        @($result.ContextLines).Count | Should -Be 3
        (@($result.ContextLines.LineNumber) -join ',') | Should -Be '1,2,3'
        @($result.ContextLines | Where-Object IsTarget).Count | Should -Be 1
    }

    It 'returns only the target line when ContextLines is zero' {
        $sample = New-OITestTextFile -Name 'no-context.txt' -Content "one`ntwo`nthree"
        $result = Invoke-OffsetInspect -FilePaths $sample -OffsetInputs '4' -ContextLines 0 -PassThru

        @($result.ContextLines).Count | Should -Be 1
        $result.ContextLines[0].IsTarget | Should -BeTrue
    }

    It 'maps CRLF lines correctly' {
        $sample = New-OITestTextFile -Name 'crlf.txt' -Content "one`r`ntwo`r`nthree"
        $result = Invoke-OffsetInspect -FilePaths $sample -OffsetInputs '5' -PassThru

        $result.LineNumber | Should -Be 2
        $result.LineText | Should -Be 'two'
    }

    It 'maps UTF-8 multibyte content to byte and character positions correctly' {
        $utf8 = New-Object System.Text.UTF8Encoding($false)
        $content = ([string][char]0x00E9) + "x`n"
        $sample = New-OITestTextFile -Name 'utf8.txt' -Content $content -Encoding $utf8
        $result = Invoke-OffsetInspect -FilePaths $sample -OffsetInputs '2' -Encoding UTF8 -PassThru

        $result.TargetByteHex | Should -Be '78'
        $result.BytePositionInLine | Should -Be 2
        $result.CharacterPosition | Should -Be 1
    }

    It 'does not count an incomplete UTF-8 code point as a complete character' {
        $utf8 = New-Object System.Text.UTF8Encoding($false)
        $content = ([string][char]0x00E9) + 'x'
        $sample = New-OITestTextFile -Name 'utf8-inside.txt' -Content $content -Encoding $utf8
        $result = Invoke-OffsetInspect -FilePaths $sample -OffsetInputs '1' -Encoding UTF8 -PassThru

        $result.TargetByteHex | Should -Be 'A9'
        $result.CharacterPosition | Should -Be 0
    }

    It 'recognizes a UTF-8 BOM when UTF8 is selected explicitly' {
        $utf8Bom = New-Object System.Text.UTF8Encoding($true)
        $sample = New-OITestTextFile -Name 'utf8-bom.txt' -Content 'A' -Encoding $utf8Bom
        $result = Invoke-OffsetInspect -FilePaths $sample -OffsetInputs '3' -Encoding UTF8 -PassThru

        $result.EncodingDetected | Should -Be 'UTF8'
        $result.CharacterPosition | Should -Be 0
        $result.LineText | Should -Be 'A'
    }


    It 'warns when the selected offset lies inside an encoding preamble' {
        $utf8Bom = New-Object System.Text.UTF8Encoding($true)
        $sample = New-OITestTextFile -Name 'utf8-bom-target.txt' -Content 'A' -Encoding $utf8Bom
        $result = Invoke-OffsetInspect -FilePaths $sample -OffsetInputs '1' -Encoding UTF8 -PassThru

        $result.Success | Should -BeTrue
        $result.Warnings -join ' ' | Should -Match 'encoding preamble'
        $result.CharacterPosition | Should -Be 0
    }

    It 'auto-detects UTF-16LE from its byte-order mark' {
        $utf16 = New-Object System.Text.UnicodeEncoding($false, $true)
        $sample = New-OITestTextFile -Name 'utf16.txt' -Content "A`nB" -Encoding $utf16
        $result = Invoke-OffsetInspect -FilePaths $sample -OffsetInputs '6' -Encoding Auto -PassThru

        $result.EncodingDetected | Should -Be 'UTF16LE'
        $result.LineNumber | Should -Be 2
        $result.CharacterPosition | Should -Be 0
    }

    It 'does not count a partial UTF-16 code unit as a complete character' {
        $utf16 = New-Object System.Text.UnicodeEncoding($false, $true)
        $sample = New-OITestTextFile -Name 'utf16-partial.txt' -Content 'AB' -Encoding $utf16
        $result = Invoke-OffsetInspect -FilePaths $sample -OffsetInputs '3' -Encoding Auto -PassThru

        $result.TargetByteHex | Should -Be '00'
        $result.CharacterPosition | Should -Be 0
    }

    It 'bounds previews for exceptionally long lines' {
        $sample = New-OITestTextFile -Name 'longline.txt' -Content ('A' * 5000)
        $result = Invoke-OffsetInspect -FilePaths $sample -OffsetInputs '4500' -MaxLineBytes 1024 -PassThru

        $result.Success | Should -BeTrue
        $result.LineTextTruncated | Should -BeTrue
        $result.Warnings -join ' ' | Should -Match 'bounded window'
        $result.LineText.Length | Should -BeLessOrEqual 1026
    }
}

Describe 'Invoke-OffsetInspect batching and comparison' {
    It 'preserves input order for multiple offsets' {
        $sample = New-OITestTextFile -Name 'order.txt' -Content '0123456789'
        $results = @(Invoke-OffsetInspect -FilePaths $sample -OffsetInputs '7', '1', '5' -PassThru)

        $results.Count | Should -Be 3
        (@($results.OffsetDecimal) -join ',') | Should -Be '7,1,5'
    }

    It 'maps a large batched offset set without changing result order' {
        $content = @((0..999) | ForEach-Object { 'L{0:D4}' -f $_ }) -join "`n"
        $sample = New-OITestTextFile -Name 'large-batch.txt' -Content $content
        $offsets = @((0..99) | ForEach-Object { [string]($_ * 6) })
        $results = @(Invoke-OffsetInspect -FilePaths $sample -OffsetInputs $offsets -ContextLines 1 -PassThru)

        $results.Count | Should -Be 100
        $results[0].LineNumber | Should -Be 1
        $results[99].LineNumber | Should -Be 100
        (@($results.OffsetInput) -join ',') | Should -BeExactly ($offsets -join ',')
    }

    It 'reuses a single offset across multiple files' {
        $one = New-OITestTextFile -Name 'one.txt' -Content 'abcdef'
        $two = New-OITestTextFile -Name 'two.txt' -Content 'uvwxyz'
        $results = @(Invoke-OffsetInspect -FilePaths $one, $two -OffsetInputs '1' -PassThru)

        $results.Count | Should -Be 2
        (@($results.TargetByteHex) -join ',') | Should -Be '62,76'
    }

    It 'pairs equal file and offset counts in input order' {
        $one = New-OITestTextFile -Name 'paired-one.txt' -Content 'abcdef'
        $two = New-OITestTextFile -Name 'paired-two.txt' -Content 'uvwxyz'
        $results = @(Invoke-OffsetInspect -FilePaths $one, $two -OffsetInputs '1', '2' -PassThru)

        (@($results.TargetByteHex) -join ',') | Should -Be '62,77'
    }

    It 'compares the target byte' {
        $before = Join-Path $TestDrive 'before.bin'
        $after = Join-Path $TestDrive 'after.bin'
        [System.IO.File]::WriteAllBytes($before, [byte[]](0x41, 0x42, 0x43))
        [System.IO.File]::WriteAllBytes($after, [byte[]](0x41, 0x90, 0x43))

        $result = Invoke-OffsetInspect -FilePaths $before -OffsetInputs '1' -CompareFile $after -PassThru
        $result.TargetByteHex | Should -Be '42'
        $result.CompareByteHex | Should -Be '90'
        $result.BytesDiffer | Should -BeTrue
    }

    It 'returns a structured comparison failure when the compare file is too small' {
        $before = Join-Path $TestDrive 'compare-large.bin'
        $after = Join-Path $TestDrive 'compare-small.bin'
        [System.IO.File]::WriteAllBytes($before, [byte[]](0x41, 0x42, 0x43))
        [System.IO.File]::WriteAllBytes($after, [byte[]](0x41))

        $result = Invoke-OffsetInspect -FilePaths $before -OffsetInputs '2' -CompareFile $after -PassThru
        $result.Success | Should -BeFalse
        $result.Error | Should -Match 'smaller'
    }
}

Describe 'Invoke-OffsetInspect output contracts' {
    It 'returns the documented core properties' {
        $sample = New-OITestTextFile -Name 'schema.txt' -Content 'abcdef'
        $result = Invoke-OffsetInspect -FilePaths $sample -OffsetInputs '1' -PassThru
        $expected = @(
            'Success', 'File', 'OffsetInput', 'OffsetDecimal', 'OffsetHex', 'FileSize',
            'EncodingRequested', 'EncodingDetected', 'LineNumber', 'LineText',
            'CharacterPosition', 'BytePositionInLine', 'ContextLines', 'TargetByteHex',
            'HexDump', 'DurationMs', 'Warnings', 'Error'
        )

        foreach ($property in $expected) {
            @($result.PSObject.Properties.Name) | Should -Contain $property
        }
    }


    It 'keeps successful and failed inspection result schemas identical' {
        $sample = New-OITestTextFile -Name 'schema-parity.txt' -Content 'abcdef'
        $success = Invoke-OffsetInspect -FilePaths $sample -OffsetInputs '1' -PassThru
        $failure = Invoke-OffsetInspect -FilePaths $sample -OffsetInputs '99' -PassThru

        (@($success.PSObject.Properties.Name) -join ',') |
            Should -BeExactly (@($failure.PSObject.Properties.Name) -join ',')
    }


    It 'always emits a JSON array, including for one result' {
        $sample = New-OITestTextFile -Name 'json.txt' -Content 'abcdef'
        $json = Invoke-OffsetInspect -FilePaths $sample -OffsetInputs '1' -Json
        $json.TrimStart().StartsWith('[') | Should -BeTrue
        @($json | ConvertFrom-Json).Count | Should -Be 1
    }

    It 'writes a UTF-8 CSV file and returns its FileInfo' {
        $sample = New-OITestTextFile -Name 'csv.txt' -Content 'abcdef'
        $destinationDirectory = Join-Path $TestDrive 'results'
        $destination = Join-Path $destinationDirectory 'offsets.csv'
        $file = Invoke-OffsetInspect -FilePaths $sample -OffsetInputs '1' -CsvPath $destination

        $resolvedDestination = (Resolve-Path -LiteralPath $destination).Path
        $file.FullName | Should -Be $resolvedDestination
        (Import-Csv -LiteralPath $destination).OffsetDecimal | Should -Be '1'
    }

    It 'uses mutually exclusive output parameter sets' {
        $sample = New-OITestTextFile -Name 'sets.txt' -Content 'abcdef'
        { Invoke-OffsetInspect -FilePaths $sample -OffsetInputs '1' -Json -Csv } | Should -Throw
    }

    It 'throws after output processing when FailOnError is requested' {
        $sample = New-OITestTextFile -Name 'fail-on-error.txt' -Content 'abc'
        { Invoke-OffsetInspect -FilePaths $sample -OffsetInputs '99' -PassThru -FailOnError } | Should -Throw
    }
}

Describe 'Threat provider normalization and boundary search' {
    InModuleScope OffsetInspect {
        It 'short-circuits zero-length AMSI prefixes as clean baselines' {
            $moduleBase = (
                $ExecutionContext.SessionState.Module.ModuleBase
            )

            $publicPath = Join-Path `
                (Join-Path $moduleBase 'Public') `
                'Invoke-OffsetThreatScan.ps1'

            $publicContent = Get-Content `
                -LiteralPath $publicPath `
                -Raw

            $baselineCount = (
                [regex]::Matches(
                    $publicContent,
                    [regex]::Escape(
                        'Synthetic AMSI empty-prefix baseline.'
                    )
                )
            ).Count

            $baselineCount |
                Should -Be 2
        }
        It 'keeps unbound CsvPath compatible with Windows PowerShell 5.1 closures' {
            $command = Get-Command `
                -Name Invoke-OffsetThreatScan `
                -ErrorAction Stop

            $csvPathParameter = $command.Parameters['CsvPath']

            $incompatibleAttributes = @(
                $csvPathParameter.Attributes |
                    Where-Object {
                        $_.GetType().FullName -eq
                            'System.Management.Automation.ValidateNotNullOrEmptyAttribute'
                    }
            )

            $incompatibleAttributes.Count |
                Should -Be 0

            function New-OIClosureCompatibilityProbe {
                [CmdletBinding(DefaultParameterSetName = 'Human')]
                param(
                    [Parameter(ParameterSetName = 'Human')]
                    [switch]$Human,

                    [Parameter(
                        Mandatory = $true,
                        ParameterSetName = 'CsvFile'
                    )]
                    [string]$CsvPath
                )

                # Read both parameters explicitly so the closure captures
                # the same parameter-state shape used by the public command.
                [void]$Human
                [void]$CsvPath

                {
                    'ClosureCreated'
                }.GetNewClosure()
            }

            $closure = New-OIClosureCompatibilityProbe -Human

            (& $closure) |
                Should -Be 'ClosureCreated'

            {
                Invoke-OffsetThreatScan `
                    -FilePath 'unused.bin' `
                    -CsvPath ''
            } | Should -Throw
        }
        It 'keeps unbound ProbeLogPath compatible with Windows PowerShell 5.1 closures' {
            # An unbound [string] is '' under Windows PowerShell 5.1; a
            # ValidateNotNullOrEmpty attribute on it breaks the scanner's
            # .GetNewClosure() capture. ProbeLogPath must therefore carry no such
            # attribute (the empty case is handled by an IsNullOrWhiteSpace guard).
            $command = Get-Command -Name Invoke-OffsetThreatScan -ErrorAction Stop
            $probeLogPathParameter = $command.Parameters['ProbeLogPath']
            $incompatibleAttributes = @(
                $probeLogPathParameter.Attributes |
                    Where-Object {
                        $_.GetType().FullName -eq
                            'System.Management.Automation.ValidateNotNullOrEmptyAttribute'
                    }
            )
            $incompatibleAttributes.Count | Should -Be 0
        }
        It 'binds module-private helper commands into provider closures' {
            $moduleBase = `
                $ExecutionContext.SessionState.Module.ModuleBase

            $publicPath = Join-Path `
                (Join-Path $moduleBase 'Public') `
                'Invoke-OffsetThreatScan.ps1'

            $publicContent = Get-Content `
                -LiteralPath $publicPath `
                -Raw

            $publicContent |
                Should -Match '\$copyStreamPrefixCommand'

            $publicContent |
                Should -Match '& \$copyStreamPrefixCommand'

            $publicContent |
                Should -Match '\$invokeDefenderFileScanCommand'

            $publicContent |
                Should -Match '& \$invokeDefenderFileScanCommand'

            $sourcePath = Join-Path $TestDrive 'closure-source.bin'
            $destinationPath = Join-Path $TestDrive 'closure-prefix.bin'

            [System.IO.File]::WriteAllBytes(
                $sourcePath,
                [byte[]](0x41, 0x42)
            )

            $stream = [System.IO.File]::OpenRead($sourcePath)
            $copyCommand = Get-Command `
                -Name Copy-OIStreamPrefix `
                -CommandType Function `
                -ErrorAction Stop

            $buffer = New-Object byte[] 32

            $scanner = {
                param([int64]$PrefixLength)

                & $copyCommand `
                    -SourceStream $stream `
                    -DestinationPath $destinationPath `
                    -Length $PrefixLength `
                    -Buffer $buffer

                [pscustomobject]@{
                    Status         = 'Clean'
                    ProviderResult = $null
                    HResult        = $null
                    SignatureName  = $null
                    Message        = $null
                    RawOutput      = $null
                    ExitCode       = 0
                }
            }.GetNewClosure()

            try {
                $search = Invoke-OIPrefixBoundarySearch `
                    -UnitCount 2 `
                    -Scanner $scanner `
                    -RepeatCount 1 `
                    -NoProgress

                $search.Success |
                    Should -BeTrue

                $search.InitialScan.Status |
                    Should -Be 'Clean'

                (Get-Item -LiteralPath $destinationPath).Length |
                    Should -Be 2
            }
            finally {
                $stream.Dispose()
            }
        }
        It 'preserves byte-array results for empty, out-of-range, and single-byte reads' {
            $sourcePath = Join-Path $TestDrive 'range-read.bin'

            [System.IO.File]::WriteAllBytes(
                $sourcePath,
                [byte[]](0x41, 0x42)
            )

            $stream = [System.IO.File]::OpenRead($sourcePath)

            try {
                $empty = Read-OIFileRange `
                    -Stream $stream `
                    -Start 0 `
                    -Length 0

                $pastEnd = Read-OIFileRange `
                    -Stream $stream `
                    -Start 2 `
                    -Length 1

                $single = Read-OIFileRange `
                    -Stream $stream `
                    -Start 0 `
                    -Length 1

                $empty.GetType().FullName |
                    Should -Be 'System.Byte[]'

                $empty.Length |
                    Should -Be 0

                $pastEnd.GetType().FullName |
                    Should -Be 'System.Byte[]'

                $pastEnd.Length |
                    Should -Be 0

                $single.GetType().FullName |
                    Should -Be 'System.Byte[]'

                $single.Length |
                    Should -Be 1

                $single[0] |
                    Should -Be 0x41
            }
            finally {
                $stream.Dispose()
            }
        }

        It 'maps Unicode scalar prefixes without splitting surrogate pairs' {
            $emoji = [char]::ConvertFromUtf32(0x1F600)
            $map = New-OIUnicodeScalarMap -Text ('A' + $emoji + 'B')

            $map.UnicodeScalarCount | Should -Be 3
            (ConvertTo-OIUtf16PrefixLength -ScalarMap $map -UnicodeScalarPrefixLength 0) | Should -Be 0
            (ConvertTo-OIUtf16PrefixLength -ScalarMap $map -UnicodeScalarPrefixLength 1) | Should -Be 1
            (ConvertTo-OIUtf16PrefixLength -ScalarMap $map -UnicodeScalarPrefixLength 2) | Should -Be 3
            (ConvertTo-OIUtf16PrefixLength -ScalarMap $map -UnicodeScalarPrefixLength 3) | Should -Be 4
        }

        It 'classifies unambiguous Defender output without relying on exit code alone' {
            $clean = ConvertFrom-OIDefenderOutput -Output 'No threats were found.' -ExitCode 0
            $detected = ConvertFrom-OIDefenderOutput -Output "Threat was found`nThreat Name: Test.Sample" -ExitCode 2
            $ambiguous = ConvertFrom-OIDefenderOutput -Output "No threats were found.`nThreat was found" -ExitCode 0
            $unknown = ConvertFrom-OIDefenderOutput -Output 'Scan completed.' -ExitCode 0

            $clean.Status | Should -Be 'Clean'
            $detected.Status | Should -Be 'Detected'
            $detected.SignatureName | Should -Be 'Test.Sample'
            $ambiguous.Status | Should -Be 'Indeterminate'
            $unknown.Status | Should -Be 'Indeterminate'
        }

        It 'flattens failed threat results when boundary validation is absent' {
            $failed = [pscustomobject]@{
                Success                         = $false
                File                            = 'sample.bin'
                FileSha256                      = $null
                ScanTimestampUtc                = $null
                Engine                          = 'Defender'
                ScanMode                        = 'RawBytes'
                BoundaryUnit                    = 'Byte'
                Encoding                        = $null
                SearchModel                     = 'MonotonicPrefixTransition'
                InitialStatus                   = $null
                DetectionPrefixLength           = $null
                DetectionBoundaryOffset         = $null
                DetectionBoundaryHex            = $null
                DetectionCharacterIndex         = $null
                DetectionUtf16CodeUnitIndex     = $null
                KnownCleanPrefixLength          = $null
                Stable                          = $false
                Confidence                      = 'None'
                ScanCount                       = 0
                SignatureName                   = $null
                BoundaryValidation              = $null
                DurationMs                      = 1
                Warnings                        = @()
                Error                           = 'failure'
            }

            $flat = ConvertTo-OIFlatThreatResult -Result $failed
            $flat.FullContentStatuses | Should -BeNullOrEmpty
        }

        It 'hashes and copies a stream prefix while preserving the source position' {
            $sourcePath = Join-Path $TestDrive 'stream-source.bin'
            $destinationPath = Join-Path $TestDrive 'stream-prefix.bin'
            [System.IO.File]::WriteAllBytes($sourcePath, [byte[]](0x41, 0x42, 0x43, 0x44))
            $stream = [System.IO.File]::OpenRead($sourcePath)
            try {
                $null = $stream.Seek(2, [System.IO.SeekOrigin]::Begin)
                $hash = Get-OIStreamSha256 -Stream $stream
                $stream.Position | Should -Be 2
                $hash | Should -Be 'e12e115acf4552b2568b55e93cbd39394c4ef81c82447fafc997882a02d23677'

                Copy-OIStreamPrefix -SourceStream $stream -DestinationPath $destinationPath -Length 3 -Buffer (New-Object byte[] 2)
                $stream.Position | Should -Be 2
                ([BitConverter]::ToString([System.IO.File]::ReadAllBytes($destinationPath))) | Should -Be '41-42-43'
            }
            finally {
                $stream.Dispose()
            }
        }


        It 'rejects an oversized prefix and still restores the source position' {
            $sourcePath = Join-Path $TestDrive 'stream-short.bin'
            $destinationPath = Join-Path $TestDrive 'stream-short-prefix.bin'
            [System.IO.File]::WriteAllBytes($sourcePath, [byte[]](0x41, 0x42))
            $stream = [System.IO.File]::OpenRead($sourcePath)
            try {
                $null = $stream.Seek(1, [System.IO.SeekOrigin]::Begin)
                { Copy-OIStreamPrefix -SourceStream $stream -DestinationPath $destinationPath -Length 3 -Buffer (New-Object byte[] 2) } |
                    Should -Throw
                $stream.Position | Should -Be 1
                Test-Path -LiteralPath $destinationPath | Should -BeFalse
            }
            finally {
                $stream.Dispose()
            }
        }


        It 'classifies AMSI malware and administrator-policy ranges separately' {
            $malware = ConvertFrom-OIAmsiResponse -Response ([pscustomobject]@{ HResult = 0; Result = 32768 })
            $blocked = ConvertFrom-OIAmsiResponse -Response ([pscustomobject]@{ HResult = 0; Result = 16384 })

            $malware.Status | Should -Be 'Detected'
            $blocked.Status | Should -Be 'Blocked'
        }

        It 'preserves a failing AMSI HRESULT as an error' {
            $response = ConvertFrom-OIAmsiResponse -Response ([pscustomobject]@{ HResult = -2147467259; Result = 0 })
            $response.Status | Should -Be 'Error'
            $response.HResult | Should -Match '^0x[0-9A-F]{8}$'
        }

        It 'finds the first positive prefix and validates both sides repeatedly' {
            $scanner = {
                param([int64]$Length)
                [pscustomobject]@{
                    Status = if ($Length -ge 11) { 'Detected' } else { 'Clean' }
                    ProviderResult = $null
                    HResult = $null
                    SignatureName = $null
                    Message = $null
                    RawOutput = $null
                }
            }

            $result = Invoke-OIPrefixBoundarySearch -UnitCount 64 -Scanner $scanner -RepeatCount 3 -NoProgress
            $result.Success | Should -BeTrue
            $result.KnownClean | Should -Be 10
            $result.KnownDetected | Should -Be 11
            $result.Stable | Should -BeTrue
            $result.Confidence | Should -Be 'High'
        }

        It 'returns no boundary when the complete content is negative' {
            $scanner = {
                param([int64]$Length)
                [pscustomobject]@{
                    Status = 'Clean'
                    ProviderResult = $Length
                    HResult = $null
                    SignatureName = $null
                    Message = $null
                    RawOutput = $null
                }
            }

            $result = Invoke-OIPrefixBoundarySearch -UnitCount 32 -Scanner $scanner -NoProgress
            $result.Success | Should -BeTrue
            $result.KnownClean | Should -Be 32
            $result.KnownDetected | Should -BeNullOrEmpty
        }

        It 'aborts rather than treating an indeterminate provider response as detection' {
            $scanner = {
                param([int64]$Length)
                $status = if ($Length -eq 0) { 'Clean' } elseif ($Length -eq 32) { 'Detected' } else { 'Indeterminate' }
                [pscustomobject]@{
                    Status = $status
                    ProviderResult = $null
                    HResult = $null
                    SignatureName = $null
                    Message = 'test provider state'
                    RawOutput = $null
                }
            }

            $result = Invoke-OIPrefixBoundarySearch -UnitCount 32 -Scanner $scanner -RepeatCount 2 -NoProgress
            $result.Success | Should -BeFalse
            $result.Error | Should -Match 'Indeterminate'
        }

        It 'reports low confidence when repeated boundary checks disagree' {
            $counts = @{}
            $scanner = {
                param([int64]$Length)
                $key = [string]$Length
                if (-not $counts.ContainsKey($key)) { $counts[$key] = 0 }
                $counts[$key]++
                $status = if ($Length -ge 11) { 'Detected' } else { 'Clean' }
                if ($Length -eq 11 -and $counts[$key] -gt 1) { $status = 'Clean' }

                [pscustomobject]@{
                    Status = $status
                    ProviderResult = $null
                    HResult = $null
                    SignatureName = $null
                    Message = $null
                    RawOutput = $null
                }
            }.GetNewClosure()

            $result = Invoke-OIPrefixBoundarySearch -UnitCount 64 -Scanner $scanner -RepeatCount 2 -NoProgress
            $result.Success | Should -BeTrue
            $result.Stable | Should -BeFalse
            $result.Confidence | Should -Be 'Low'
        }

        It 'surfaces ProbeCount in the flattened result from the ProbeLog' {
            $withLog = [pscustomobject]@{
                Success                         = $true
                File                            = 'sample.bin'
                FileSha256                      = $null
                ScanTimestampUtc                = $null
                Engine                          = 'Defender'
                ScanMode                        = 'RawBytes'
                BoundaryUnit                    = 'Byte'
                Encoding                        = $null
                SearchModel                     = 'MonotonicPrefixTransition'
                InitialStatus                   = 'Detected'
                DetectionPrefixLength           = 11
                DetectionBoundaryOffset         = 10
                DetectionBoundaryHex            = '0xA'
                DetectionCharacterIndex         = $null
                DetectionUtf16CodeUnitIndex     = $null
                KnownCleanPrefixLength          = 10
                Stable                          = $true
                Confidence                      = 'High'
                ScanCount                       = 5
                SignatureName                   = $null
                BoundaryValidation              = $null
                ProbeLog                        = @(
                    [pscustomobject]@{ Sequence = 1; PrefixLength = 0 }
                    [pscustomobject]@{ Sequence = 2; PrefixLength = 32 }
                    [pscustomobject]@{ Sequence = 3; PrefixLength = 11 }
                )
                DurationMs                      = 1
                Warnings                        = @()
                Error                           = $null
            }

            $flat = ConvertTo-OIFlatThreatResult -Result $withLog
            $flat.ProbeCount | Should -Be 3
        }

        It 'sets ProbeCount to null when the result carries no ProbeLog' {
            $noLog = [pscustomobject]@{
                Success                         = $false
                File                            = 'sample.bin'
                FileSha256                      = $null
                ScanTimestampUtc                = $null
                Engine                          = 'Defender'
                ScanMode                        = 'RawBytes'
                BoundaryUnit                    = 'Byte'
                Encoding                        = $null
                SearchModel                     = 'MonotonicPrefixTransition'
                InitialStatus                   = $null
                DetectionPrefixLength           = $null
                DetectionBoundaryOffset         = $null
                DetectionBoundaryHex            = $null
                DetectionCharacterIndex         = $null
                DetectionUtf16CodeUnitIndex     = $null
                KnownCleanPrefixLength          = $null
                Stable                          = $false
                Confidence                      = 'None'
                ScanCount                       = 0
                SignatureName                   = $null
                BoundaryValidation              = $null
                DurationMs                      = 1
                Warnings                        = @()
                Error                           = 'failure'
            }

            $flat = ConvertTo-OIFlatThreatResult -Result $noLog
            $flat.ProbeCount | Should -BeNullOrEmpty
        }

    }
}

Describe 'ProbeLog JSON export' {
    # Export-OIProbeLog is module-private, so the write runs inside InModuleScope,
    # but the JSON is parsed back in the normal test scope: Windows PowerShell 5.1
    # does not enumerate ConvertFrom-Json arrays correctly inside a module session
    # state, whereas real consumers parse the file in their own scope.
    It 'exports an empty ProbeLog as a valid empty JSON array' {
        $path = Join-Path $TestDrive 'probelog-empty.json'
        $returned = InModuleScope OffsetInspect -Parameters @{ TargetPath = $path } {
            param($TargetPath)
            Export-OIProbeLog -ProbeLog @() -Path $TargetPath
        }

        Test-Path -LiteralPath $returned | Should -BeTrue
        (Get-Content -LiteralPath $path -Raw).Trim() | Should -Be '[]'
    }

    It 'exports a single-record ProbeLog as a one-element JSON array' {
        $path = Join-Path $TestDrive 'probelog-one.json'
        InModuleScope OffsetInspect -Parameters @{ TargetPath = $path } {
            param($TargetPath)
            $log = @([pscustomobject]@{ Sequence = 1; PrefixLength = 42; Status = 'Detected' })
            $null = Export-OIProbeLog -ProbeLog $log -Path $TargetPath
        }

        # Assign first, then wrap: Windows PowerShell 5.1 ConvertFrom-Json emits a
        # top-level JSON array as a single non-enumerated object, so @(pipeline)
        # would count it as 1; @($assigned) unrolls it correctly on both editions.
        $parsed = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $parsed = @($parsed)
        $parsed.Count | Should -Be 1
        $parsed[0].PrefixLength | Should -Be 42
        $parsed[0].Status | Should -Be 'Detected'
    }

    It 'exports a multi-record ProbeLog preserving issue order' {
        $path = Join-Path $TestDrive 'probelog-many.json'
        InModuleScope OffsetInspect -Parameters @{ TargetPath = $path } {
            param($TargetPath)
            $log = @(
                [pscustomobject]@{ Sequence = 1; PrefixLength = 0;  Status = 'Clean' }
                [pscustomobject]@{ Sequence = 2; PrefixLength = 32; Status = 'Detected' }
                [pscustomobject]@{ Sequence = 3; PrefixLength = 11; Status = 'Detected' }
            )
            $null = Export-OIProbeLog -ProbeLog $log -Path $TargetPath
        }

        # Assign first, then wrap: Windows PowerShell 5.1 ConvertFrom-Json emits a
        # top-level JSON array as a single non-enumerated object, so @(pipeline)
        # would count it as 1; @($assigned) unrolls it correctly on both editions.
        $parsed = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $parsed = @($parsed)
        $parsed.Count | Should -Be 3
        @($parsed | ForEach-Object { $_.Sequence }) | Should -Be @(1, 2, 3)
        $parsed[1].PrefixLength | Should -Be 32
    }
}

Describe 'Export-OffsetThreatReport' {
    BeforeAll {
        function New-OITestThreatResult {
            param(
                [string]$File = 'sample.ps1',
                [string[]]$Warnings = @()
            )
            [pscustomobject]@{
                Success                 = $true
                File                    = $File
                FileSha256              = 'abc123'
                ScanTimestampUtc        = '2026-07-12T00:00:00.0000000Z'
                Engine                  = 'AMSI'
                ScanMode                = 'Text'
                InitialStatus           = 'Detected'
                DetectionPrefixLength   = 11
                DetectionBoundaryOffset = 10
                DetectionBoundaryHex    = '0xA'
                KnownCleanPrefixLength  = 10
                Stable                  = $true
                Confidence              = 'High'
                SignatureName           = 'Mock/Test'
                ProbeLog                = @(
                    [pscustomobject]@{ Sequence = 1; PrefixLength = 0;  Status = 'Clean';    ElapsedMs = 1.2; SignatureName = $null }
                    [pscustomobject]@{ Sequence = 2; PrefixLength = 11; Status = 'Detected'; ElapsedMs = 3.4; SignatureName = 'Mock/Test' }
                )
                ProviderMetadata        = [pscustomobject]@{ Provider = 'AMSI'; DefenderSignatureVersion = '1.400.1.0' }
                DurationMs              = 5
                Warnings                = $Warnings
                Error                   = $null
            }
        }
    }

    It 'writes a Markdown report with summary, probe log, and warnings' {
        $path = Join-Path $TestDrive 'report.md'
        $returned = New-OITestThreatResult -Warnings @('Manual validation recommended.') |
            Export-OffsetThreatReport -Path $path

        Test-Path -LiteralPath $returned | Should -BeTrue
        $text = Get-Content -LiteralPath $path -Raw
        $text | Should -Match '# OffsetInspect Detection-Boundary Report'
        $text | Should -Match 'sample\.ps1'
        $text | Should -Match 'Detection prefix length:\*\* 11'
        $text | Should -Match 'Provider probes:\*\* 2'
        $text | Should -Match '\| # \| Prefix \| Status \| Elapsed'
        $text | Should -Match 'DefenderSignatureVersion'
        $text | Should -Match 'Manual validation recommended\.'
    }

    It 'writes self-contained HTML and encodes every value' {
        $path = Join-Path $TestDrive 'report.html'
        $null = New-OITestThreatResult -Warnings @('<script>alert(1)</script>') |
            Export-OffsetThreatReport -Path $path -Format Html -Title 'Engagement <Alpha>'

        $html = Get-Content -LiteralPath $path -Raw
        $html | Should -Match '<!DOCTYPE html>'
        $html | Should -Match '<h1>Engagement &lt;Alpha&gt;</h1>'
        $html | Should -Match '&lt;script&gt;alert\(1\)&lt;/script&gt;'
        $html | Should -Not -Match '<script>alert\(1\)'
    }

    It 'aggregates multiple piped results into one report' {
        $path = Join-Path $TestDrive 'multi-report.md'
        $null = @(
            (New-OITestThreatResult -File 'first.ps1'),
            (New-OITestThreatResult -File 'second.bin')
        ) | Export-OffsetThreatReport -Path $path

        $text = Get-Content -LiteralPath $path -Raw
        $text | Should -Match '2 scan record\(s\)'
        $text | Should -Match 'first\.ps1'
        $text | Should -Match 'second\.bin'
    }

    It 'writes BOM-less UTF-8' {
        $path = Join-Path $TestDrive 'bomless.md'
        $null = New-OITestThreatResult | Export-OffsetThreatReport -Path $path
        $bytes = [System.IO.File]::ReadAllBytes($path)
        # First byte must be '#' (0x23), not a UTF-8 BOM (0xEF).
        $bytes[0] | Should -Be 0x23
    }
}

Describe 'Resolve-OIBatchTarget (batch enumeration)' {
    BeforeAll {
        $script:BatchDir = Join-Path $TestDrive 'corpus'
        $script:BatchSub = Join-Path $script:BatchDir 'nested'
        New-Item -ItemType Directory -Path $script:BatchSub -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $script:BatchDir 'alpha.ps1') -Value 'a'
        Set-Content -LiteralPath (Join-Path $script:BatchDir 'beta.bin') -Value 'b'
        Set-Content -LiteralPath (Join-Path $script:BatchSub 'gamma.ps1') -Value 'g'
    }

    It 'enumerates a directory non-recursively' {
        $files = InModuleScope OffsetInspect -Parameters @{ Dir = $script:BatchDir } {
            param($Dir) Resolve-OIBatchTarget -Path $Dir
        }
        @($files).Count | Should -Be 2
    }

    It 'recurses into subdirectories when requested' {
        $files = InModuleScope OffsetInspect -Parameters @{ Dir = $script:BatchDir } {
            param($Dir) Resolve-OIBatchTarget -Path $Dir -Recurse
        }
        @($files).Count | Should -Be 3
    }

    It 'applies a filter' {
        $files = InModuleScope OffsetInspect -Parameters @{ Dir = $script:BatchDir } {
            param($Dir) Resolve-OIBatchTarget -Path $Dir -Filter '*.ps1'
        }
        @($files).Count | Should -Be 1
        @($files)[0] | Should -Match 'alpha\.ps1$'
    }

    It 'de-duplicates a directory plus an explicit member file' {
        $explicit = Join-Path $script:BatchDir 'alpha.ps1'
        $files = InModuleScope OffsetInspect -Parameters @{ Dir = $script:BatchDir; File = $explicit } {
            param($Dir, $File) Resolve-OIBatchTarget -Path @($Dir, $File)
        }
        @($files | Where-Object { $_ -match 'alpha\.ps1$' }).Count | Should -Be 1
    }
}

Describe 'Invoke-OffsetThreatScanBatch (orchestration)' {
    BeforeAll {
        $script:ScanDir = Join-Path $TestDrive 'scans'
        New-Item -ItemType Directory -Path $script:ScanDir -Force | Out-Null
        Set-Content -LiteralPath (Join-Path $script:ScanDir 'one.ps1') -Value '1'
        Set-Content -LiteralPath (Join-Path $script:ScanDir 'two.ps1') -Value '2'
        Set-Content -LiteralPath (Join-Path $script:ScanDir 'boom.ps1') -Value '3'
    }

    It 'scans every file, continues past a failure, and summarises the matrix' {
        $outcome = InModuleScope OffsetInspect -Parameters @{ Dir = $script:ScanDir } {
            param($Dir)

            # Bypass the Windows-only guard and the live provider so the
            # orchestration logic is verified on every platform.
            Mock Test-OIIsWindows { $true }
            Mock Invoke-OffsetThreatScan {
                if ($FilePath -like '*boom.ps1') { throw 'simulated provider failure' }
                [pscustomobject]@{
                    Success                     = $true
                    File                        = $FilePath
                    FileSize                    = 3
                    FileSha256                  = 'h'
                    ScanTimestampUtc            = 't'
                    Engine                      = 'AMSI'
                    ScanMode                    = 'Text'
                    BoundaryUnit                = 'Scalar'
                    SearchModel                 = 'MonotonicPrefixTransition'
                    Encoding                    = 'UTF8'
                    InitialStatus               = 'Detected'
                    DetectionPrefixLength       = 2
                    DetectionBoundaryOffset     = 1
                    DetectionBoundaryHex        = '0x1'
                    DetectionCharacterIndex     = $null
                    DetectionUtf16CodeUnitIndex = $null
                    KnownCleanPrefixLength      = 1
                    Stable                      = $true
                    Confidence                  = 'High'
                    ScanCount                   = 3
                    SignatureName               = 'Mock/Test'
                    ProviderResult              = 1
                    ProviderHResult             = $null
                    ProviderMetadata            = $null
                    BoundaryValidation          = $null
                    ProviderOutput              = $null
                    ProbeLog                    = @(
                        [pscustomobject]@{ Sequence = 1; PrefixLength = 1 }
                        [pscustomobject]@{ Sequence = 2; PrefixLength = 2 }
                    )
                    Inspection                  = $null
                    DurationMs                  = 1
                    Warnings                    = @()
                    Error                       = $null
                }
            }

            $full = @(Invoke-OffsetThreatScanBatch -Path $Dir -NoProgress)
            $summary = @(Invoke-OffsetThreatScanBatch -Path $Dir -Summary -NoProgress)
            [pscustomobject]@{ Full = $full; Summary = $summary }
        }

        @($outcome.Full).Count | Should -Be 3
        @($outcome.Full | Where-Object { -not $_.Success }).Count | Should -Be 1
        @($outcome.Summary).Count | Should -Be 3
        @($outcome.Summary | Where-Object { $_.ProbeCount -eq 2 }).Count | Should -Be 2
    }
}

Describe 'Compare-OffsetThreatResult' {
    BeforeAll {
        function New-OIDiffResult {
            param(
                [string]$File = 'sample.ps1',
                $DetectionPrefixLength = $null,
                [string]$SignatureName = $null,
                [int]$ProbeCount = 0
            )
            $detected = $null -ne $DetectionPrefixLength
            $probe = New-Object 'System.Collections.Generic.List[object]'
            for ($i = 1; $i -le $ProbeCount; $i++) { $probe.Add([pscustomobject]@{ Sequence = $i }) }
            [pscustomobject]@{
                File                    = $File
                InitialStatus           = if ($detected) { 'Detected' } else { 'Clean' }
                DetectionPrefixLength   = $DetectionPrefixLength
                DetectionBoundaryOffset = if ($detected) { $DetectionPrefixLength - 1 } else { $null }
                DetectionBoundaryHex    = $null
                Stable                  = $true
                Confidence              = if ($detected) { 'High' } else { 'None' }
                SignatureName           = $SignatureName
                ProbeLog                = $probe.ToArray()
            }
        }
    }

    It 'classifies a boundary that moved earlier' {
        $diff = Compare-OffsetThreatResult -Reference (New-OIDiffResult -DetectionPrefixLength 20) -Difference (New-OIDiffResult -DetectionPrefixLength 11)
        $diff.Classification | Should -Be 'BoundaryEarlier'
        $diff.BoundaryDelta | Should -Be -9
        @($diff.Changes | ForEach-Object { $_.Field }) | Should -Contain 'DetectionPrefixLength'
    }

    It 'classifies a boundary that moved later' {
        $diff = Compare-OffsetThreatResult -Reference (New-OIDiffResult -DetectionPrefixLength 11) -Difference (New-OIDiffResult -DetectionPrefixLength 20)
        $diff.Classification | Should -Be 'BoundaryLater'
        $diff.BoundaryDelta | Should -Be 9
    }

    It 'classifies newly-detected content' {
        $diff = Compare-OffsetThreatResult -Reference (New-OIDiffResult) -Difference (New-OIDiffResult -DetectionPrefixLength 11)
        $diff.Classification | Should -Be 'NewlyDetected'
        $diff.BoundaryDelta | Should -BeNullOrEmpty
    }

    It 'classifies content that is no longer detected' {
        $diff = Compare-OffsetThreatResult -Reference (New-OIDiffResult -DetectionPrefixLength 11) -Difference (New-OIDiffResult)
        $diff.Classification | Should -Be 'NoLongerDetected'
    }

    It 'reports both-clean with no changes' {
        $diff = Compare-OffsetThreatResult -Reference (New-OIDiffResult) -Difference (New-OIDiffResult)
        $diff.Classification | Should -Be 'BothClean'
        $diff.Unchanged | Should -BeTrue
    }

    It 'flags a signature change at an unchanged boundary' {
        $diff = Compare-OffsetThreatResult -Reference (New-OIDiffResult -DetectionPrefixLength 11 -SignatureName 'Old/Sig') -Difference (New-OIDiffResult -DetectionPrefixLength 11 -SignatureName 'New/Sig')
        $diff.Classification | Should -Be 'BoundaryUnchanged'
        $diff.SignatureChanged | Should -BeTrue
        @($diff.Changes | ForEach-Object { $_.Field }) | Should -Contain 'SignatureName'
    }

    It 'surfaces probe counts from both sides' {
        $diff = Compare-OffsetThreatResult -Reference (New-OIDiffResult -DetectionPrefixLength 11 -ProbeCount 4) -Difference (New-OIDiffResult -DetectionPrefixLength 11 -ProbeCount 6)
        $diff.ReferenceProbeCount | Should -Be 4
        $diff.DifferenceProbeCount | Should -Be 6
    }
}

Describe 'Split-OIByteRange (segmentation)' {
    It 'splits into contiguous, gap-free segments covering the whole range' {
        $segments = InModuleScope OffsetInspect { Split-OIByteRange -TotalLength 103 -SegmentCount 10 }
        @($segments).Count | Should -Be 10
        (@($segments) | Measure-Object -Property Length -Sum).Sum | Should -Be 103

        $expectedStart = 0
        foreach ($segment in @($segments)) {
            $segment.Start | Should -Be $expectedStart
            $expectedStart = $segment.Start + $segment.Length
        }
        $expectedStart | Should -Be 103
    }

    It 'clamps the segment count to the byte length for tiny inputs' {
        $segments = InModuleScope OffsetInspect { Split-OIByteRange -TotalLength 3 -SegmentCount 10 }
        @($segments).Count | Should -Be 3
    }

    It 'returns nothing for an empty range' {
        $segments = InModuleScope OffsetInspect { Split-OIByteRange -TotalLength 0 }
        @($segments).Count | Should -Be 0
    }
}

Describe 'Find-OIDetectionSegment (multi-region core)' {
    BeforeAll {
        # 100 bytes of 'A' with a single detectable marker (0xEE) at offset 55.
        $script:RegionFile = Join-Path $TestDrive 'region-source.bin'
        $regionBytes = New-Object byte[] 100
        for ($i = 0; $i -lt 100; $i++) { $regionBytes[$i] = 0x41 }
        $regionBytes[55] = 0xEE
        [System.IO.File]::WriteAllBytes($script:RegionFile, $regionBytes)
    }

    It 'isolates the detected segment and maps the boundary to an absolute offset' {
        $regions = InModuleScope OffsetInspect -Parameters @{ FilePath = $script:RegionFile } {
            param($FilePath)
            $scanner = {
                param([byte[]]$Bytes, [int]$Length)
                if ([array]::IndexOf($Bytes, [byte]0xEE, 0, $Length) -ge 0) {
                    [pscustomobject]@{ Status = 'Detected'; ProviderResult = 32768; HResult = '0x00000000'; SignatureName = 'Mock/Region'; Message = $null; RawOutput = $null }
                }
                else {
                    [pscustomobject]@{ Status = 'Clean'; ProviderResult = 0; HResult = '0x00000000'; SignatureName = $null; Message = $null; RawOutput = $null }
                }
            }
            $stream = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
            try {
                $segments = Split-OIByteRange -TotalLength $stream.Length -SegmentCount 10
                Find-OIDetectionSegment -Stream $stream -Segment $segments -BufferScanner $scanner -Refine -NoProgress
            }
            finally { $stream.Dispose() }
        }

        @($regions).Count | Should -Be 1
        @($regions)[0].SignatureName | Should -Be 'Mock/Region'
        @($regions)[0].StartOffset | Should -Be 50
        @($regions)[0].EndOffset | Should -Be 59
        # Marker at offset 55 -> boundary bisects to prefix length 6 within the segment -> absolute 56.
        @($regions)[0].AbsoluteBoundaryOffset | Should -Be 56
    }

    It 'reports segment-level hits without a boundary when -Refine is omitted' {
        $regions = InModuleScope OffsetInspect -Parameters @{ FilePath = $script:RegionFile } {
            param($FilePath)
            $scanner = {
                param([byte[]]$Bytes, [int]$Length)
                if ([array]::IndexOf($Bytes, [byte]0xEE, 0, $Length) -ge 0) {
                    [pscustomobject]@{ Status = 'Detected'; ProviderResult = 32768; HResult = '0x00000000'; SignatureName = $null; Message = $null; RawOutput = $null }
                }
                else {
                    [pscustomobject]@{ Status = 'Clean'; ProviderResult = 0; HResult = '0x00000000'; SignatureName = $null; Message = $null; RawOutput = $null }
                }
            }
            $stream = [System.IO.File]::Open($FilePath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
            try {
                $segments = Split-OIByteRange -TotalLength $stream.Length -SegmentCount 10
                Find-OIDetectionSegment -Stream $stream -Segment $segments -BufferScanner $scanner -NoProgress
            }
            finally { $stream.Dispose() }
        }

        @($regions).Count | Should -Be 1
        @($regions)[0].WithinSegmentBoundary | Should -BeNullOrEmpty
        @($regions)[0].AbsoluteBoundaryOffset | Should -BeNullOrEmpty
    }
}

Describe 'Entropy analysis' {
    It 'computes zero entropy for a single repeated byte' {
        $value = InModuleScope OffsetInspect { Get-OIShannonEntropy -Bytes ([byte[]](@(0x41) * 512)) }
        $value | Should -Be 0
    }

    It 'computes one bit for a balanced two-value buffer' {
        $bytes = [byte[]]((@(0x00) * 256) + (@(0x01) * 256))
        $value = InModuleScope OffsetInspect -Parameters @{ B = $bytes } { param($B) Get-OIShannonEntropy -Bytes $B }
        $value | Should -Be 1
    }

    It 'reaches eight bits for a uniform byte distribution' {
        $bytes = [byte[]](0..255)
        $value = InModuleScope OffsetInspect -Parameters @{ B = $bytes } { param($B) Get-OIShannonEntropy -Bytes $B }
        $value | Should -Be 8
    }

    It 'compiles the native accelerator and matches the reference computation' {
        $native = InModuleScope OffsetInspect {
            Initialize-OIEntropyAccelerator
            [OffsetInspect.Native.EntropyCalculator]::Shannon([byte[]](0..255), 256)
        }
        [Math]::Round($native, 6) | Should -Be 8
    }

    It 'flags the high-entropy region of a file' {
        $low = [byte[]](@(0x41) * 512)
        $high = New-Object byte[] 512
        for ($i = 0; $i -lt 512; $i++) { $high[$i] = [byte]($i % 256) }
        $path = Join-Path $TestDrive 'entropy.bin'
        [System.IO.File]::WriteAllBytes($path, [byte[]]($low + $high))

        $result = Get-OffsetEntropy -FilePath $path -WindowSize 256 -HighEntropyThreshold 7.0
        $result.WindowCount | Should -Be 4
        $result.HighWindowCount | Should -Be 2
        @($result.Windows)[0].IsHigh | Should -BeFalse
        @($result.Windows)[3].IsHigh | Should -BeTrue
    }
}

Describe 'String extraction' {
    It 'extracts ASCII and UTF-16LE strings with correct offsets' {
        $ascii = [System.Text.Encoding]::ASCII.GetBytes('HELLO')
        $unicode = [System.Text.Encoding]::Unicode.GetBytes('WORLD')
        $bytes = [byte[]]((@(0x00, 0x00, 0x00)) + $ascii + (@(0x00, 0x00)) + $unicode)

        $found = InModuleScope OffsetInspect -Parameters @{ B = $bytes } { param($B) Get-OIByteString -Bytes $B -MinimumLength 4 }
        $asciiHit = @($found | Where-Object Encoding -eq 'Ascii')
        $unicodeHit = @($found | Where-Object Encoding -eq 'Unicode')

        $asciiHit.Count | Should -Be 1
        $asciiHit[0].Value | Should -Be 'HELLO'
        $asciiHit[0].Offset | Should -Be 3
        $unicodeHit.Count | Should -Be 1
        $unicodeHit[0].Value | Should -Be 'WORLD'
        $unicodeHit[0].Offset | Should -Be 10
    }

    It 'honours the minimum length' {
        # A null byte separates a below-threshold run ('abc', 3) from a kept run ('DEFGH', 5).
        $bytes = [byte[]]([System.Text.Encoding]::ASCII.GetBytes('abc') + (@(0x00)) + [System.Text.Encoding]::ASCII.GetBytes('DEFGH'))
        $found = InModuleScope OffsetInspect -Parameters @{ B = $bytes } { param($B) Get-OIByteString -Bytes $B -MinimumLength 4 -Encoding Ascii }
        @($found).Count | Should -Be 1
        @($found)[0].Value | Should -Be 'DEFGH'
    }

    It 'finds strings in a file with byte offsets through the public command' {
        $bytes = [byte[]]((@(0x00) * 4) + [System.Text.Encoding]::ASCII.GetBytes('MalwareStr'))
        $path = Join-Path $TestDrive 'strings.bin'
        [System.IO.File]::WriteAllBytes($path, $bytes)

        $hits = @(Get-OffsetString -FilePath $path -Encoding Ascii -MinimumLength 4 | Where-Object Value -eq 'MalwareStr')
        $hits.Count | Should -Be 1
        $hits[0].Offset | Should -Be 4
    }
}

Describe 'PE parsing' {
    BeforeAll {
        function New-OITestPEBytes {
            $bytes = New-Object byte[] 1024
            $bytes[0] = 0x4D; $bytes[1] = 0x5A
            [BitConverter]::GetBytes([int32]0x40).CopyTo($bytes, 0x3C)
            $bytes[0x40] = 0x50; $bytes[0x41] = 0x45; $bytes[0x42] = 0x00; $bytes[0x43] = 0x00
            [BitConverter]::GetBytes([uint16]0x8664).CopyTo($bytes, 0x44)
            [BitConverter]::GetBytes([uint16]1).CopyTo($bytes, 0x46)
            [BitConverter]::GetBytes([uint16]0xF0).CopyTo($bytes, 0x54)
            [BitConverter]::GetBytes([uint16]0x20B).CopyTo($bytes, 0x58)
            [BitConverter]::GetBytes([uint32]0x1000).CopyTo($bytes, 0x68)
            [BitConverter]::GetBytes([uint64]0x140000000).CopyTo($bytes, 0x70)
            $section = 0x148
            [System.Text.Encoding]::ASCII.GetBytes('.text').CopyTo($bytes, $section)
            [BitConverter]::GetBytes([uint32]0x150).CopyTo($bytes, $section + 8)
            [BitConverter]::GetBytes([uint32]0x1000).CopyTo($bytes, $section + 12)
            [BitConverter]::GetBytes([uint32]0x200).CopyTo($bytes, $section + 16)
            [BitConverter]::GetBytes([uint32]0x200).CopyTo($bytes, $section + 20)
            return , $bytes
        }

        $script:PEFile = Join-Path $TestDrive 'sample-pe.bin'
        [System.IO.File]::WriteAllBytes($script:PEFile, (New-OITestPEBytes))
    }

    It 'parses machine, bitness, entry point, and sections' {
        $buffer = [System.IO.File]::ReadAllBytes($script:PEFile)
        $image = InModuleScope OffsetInspect -Parameters @{ Buffer = $buffer } { param($Buffer) ConvertTo-OIPEImage -Bytes $Buffer }
        $image.Machine | Should -Be 'x64 (AMD64)'
        $image.IsPE32Plus | Should -BeTrue
        $image.EntryPointRva | Should -Be 0x1000
        $image.SectionCount | Should -Be 1
        @($image.Sections)[0].Name | Should -Be '.text'
        @($image.Sections)[0].PointerToRawData | Should -Be 0x200
    }

    It 'maps file offsets to sections, headers, and gaps' {
        $buffer = [System.IO.File]::ReadAllBytes($script:PEFile)
        $mapping = InModuleScope OffsetInspect -Parameters @{ Buffer = $buffer } {
            param($Buffer)
            $image = ConvertTo-OIPEImage -Bytes $Buffer
            [pscustomobject]@{
                InText    = Get-OIPESectionForOffset -Image $image -Offset 0x250
                InHeaders = Get-OIPESectionForOffset -Image $image -Offset 0x100
                Beyond    = Get-OIPESectionForOffset -Image $image -Offset 0x900
            }
        }
        $mapping.InText | Should -Be '.text'
        $mapping.InHeaders | Should -Be 'headers'
        $mapping.Beyond | Should -BeNullOrEmpty
    }

    It 'rejects a non-PE buffer' {
        $random = New-Object byte[] 128
        { InModuleScope OffsetInspect -Parameters @{ Buffer = $random } { param($Buffer) ConvertTo-OIPEImage -Bytes $Buffer } } | Should -Throw
    }

    It 'exposes PE info and maps an offset through the public command' {
        $info = Get-OffsetPEInfo -FilePath $script:PEFile -Offset 0x250
        $info.Machine | Should -Be 'x64 (AMD64)'
        $info.SectionCount | Should -Be 1
        $info.MappedSection | Should -Be '.text'
    }
}

Describe 'PE imports, overlay, and imphash' {
    It 'computes imphash as MD5 of the lowercased import list' {
        $hash = InModuleScope OffsetInspect { Get-OIImpHash -Entry @('kernel32.createfilea') }
        $hash | Should -Be 'ac5547a4cef5a0a41523374a369ff4b1'
        $empty = InModuleScope OffsetInspect { Get-OIImpHash -Entry @() }
        $empty | Should -BeNullOrEmpty
    }

    It 'maps an RVA to a file offset via the section table' {
        $mapping = InModuleScope OffsetInspect {
            $image = [pscustomobject]@{ Sections = @([pscustomobject]@{ VirtualAddress = 0x1000; VirtualSize = 0x200; SizeOfRawData = 0x200; PointerToRawData = 0x400 }) }
            [pscustomobject]@{
                InSection  = ConvertFrom-OIRvaToOffset -Image $image -Rva 0x1050
                OutOfRange = ConvertFrom-OIRvaToOffset -Image $image -Rva 0x9000
            }
        }
        $mapping.InSection | Should -Be 0x450
        $mapping.OutOfRange | Should -BeNullOrEmpty
    }

    It 'detects an appended overlay' {
        $overlay = InModuleScope OffsetInspect {
            $sections = @([pscustomobject]@{ PointerToRawData = 0x200; SizeOfRawData = 0x200 })
            [pscustomobject]@{
                WithOverlay = Get-OIPEOverlayRange -Section $sections -FileSize 0x500
                NoOverlay   = Get-OIPEOverlayRange -Section $sections -FileSize 0x400
            }
        }
        $overlay.WithOverlay.HasOverlay | Should -BeTrue
        $overlay.WithOverlay.OverlayOffset | Should -Be 0x400
        $overlay.WithOverlay.OverlaySize | Should -Be 0x100
        $overlay.NoOverlay.HasOverlay | Should -BeFalse
    }

    It 'reads a null-terminated ASCII string at an offset' {
        $path = Join-Path $TestDrive 'nullterm.bin'
        $bytes = [byte[]]([System.Text.Encoding]::ASCII.GetBytes('hello') + (@(0)) + [System.Text.Encoding]::ASCII.GetBytes('world') + (@(0)))
        [System.IO.File]::WriteAllBytes($path, $bytes)
        $values = InModuleScope OffsetInspect -Parameters @{ P = $path } {
            param($P)
            $stream = [System.IO.File]::Open($P, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
            try {
                [pscustomobject]@{
                    First  = Read-OINullTerminatedAscii -Stream $stream -Offset 0
                    Second = Read-OINullTerminatedAscii -Stream $stream -Offset 6
                }
            }
            finally { $stream.Dispose() }
        }
        $values.First | Should -Be 'hello'
        $values.Second | Should -Be 'world'
    }
}

Describe 'YARA output parsing' {
    It 'parses rule and string matches with byte offsets' {
        $sample = @'
DemoBenign C:\path\target.txt
0x16:$a: OffsetInspect-marker
0x40:$b: another
'@
        $yaraMatches = InModuleScope OffsetInspect -Parameters @{ O = $sample } { param($O) ConvertFrom-OIYaraOutput -Output $O -FilePath 'C:\path\target.txt' }
        @($yaraMatches).Count | Should -Be 2
        @($yaraMatches)[0].Rule | Should -Be 'DemoBenign'
        @($yaraMatches)[0].StringId | Should -Be '$a'
        @($yaraMatches)[0].Offset | Should -Be 0x16
        @($yaraMatches)[0].Data | Should -Be 'OffsetInspect-marker'
        @($yaraMatches)[1].Offset | Should -Be 0x40
    }

    It 'emits a rule-level record when no strings are reported' {
        $sample = 'RuleNoStrings C:\path\target.txt'
        $yaraMatches = InModuleScope OffsetInspect -Parameters @{ O = $sample } { param($O) ConvertFrom-OIYaraOutput -Output $O -FilePath 'C:\path\target.txt' }
        @($yaraMatches).Count | Should -Be 1
        @($yaraMatches)[0].Rule | Should -Be 'RuleNoStrings'
        @($yaraMatches)[0].Offset | Should -BeNullOrEmpty
    }

    It 'returns nothing for empty output' {
        $yaraMatches = InModuleScope OffsetInspect { ConvertFrom-OIYaraOutput -Output '' -FilePath 'x' }
        @($yaraMatches).Count | Should -Be 0
    }

    It 'groups multiple rules with their own strings' {
        $sample = @'
RuleA C:\t
0x10:$x: aaa
RuleB C:\t
0x20:$y: bbb
0x30:$z: ccc
'@
        $yaraMatches = InModuleScope OffsetInspect -Parameters @{ O = $sample } { param($O) ConvertFrom-OIYaraOutput -Output $O -FilePath 'C:\t' }
        @($yaraMatches).Count | Should -Be 3
        @($yaraMatches | Where-Object Rule -eq 'RuleB').Count | Should -Be 2
    }
}

Describe 'IOC panel and report enrichment' {
    It 'computes MD5, SHA-1, and SHA-256 in a single pass (known vectors)' {
        $path = Join-Path $TestDrive 'abc.bin'
        [System.IO.File]::WriteAllBytes($path, [System.Text.Encoding]::ASCII.GetBytes('abc'))
        $hashes = InModuleScope OffsetInspect -Parameters @{ P = $path } { param($P) Get-OIFileHash -Path $P }
        $hashes.MD5 | Should -Be '900150983cd24fb0d6963f7d28e17f72'
        $hashes.SHA1 | Should -Be 'a9993e364706816aba3e25717850c26c9cd0d89d'
        $hashes.SHA256 | Should -Be 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    }

    It 'produces a consolidated IOC panel for a file' {
        $path = Join-Path $TestDrive 'ioc.bin'
        [System.IO.File]::WriteAllBytes($path, [System.Text.Encoding]::ASCII.GetBytes('the quick brown fox jumps over the lazy dog'))
        $ioc = Get-OffsetIOC -FilePath $path
        $ioc.SHA256.Length | Should -Be 64
        $ioc.FileSize | Should -Be 43
        $ioc.IsPE | Should -BeFalse
        $ioc.PrintableStringCount | Should -BeGreaterThan 0
    }

    It 'enriches a report with an indicators section' {
        $path = Join-Path $TestDrive 'reportfile.bin'
        [System.IO.File]::WriteAllBytes($path, [System.Text.Encoding]::ASCII.GetBytes('abc'))
        $result = [pscustomobject]@{
            Success = $true; File = $path; Engine = 'AMSI'; ScanMode = 'Text'; InitialStatus = 'Detected'
            DetectionPrefixLength = 1; Stable = $true; Confidence = 'High'; ProbeLog = @(); Warnings = @()
        }
        $out = Join-Path $TestDrive 'ioc-report.md'
        $null = $result | Export-OffsetThreatReport -Path $out -IncludeIoc
        $text = Get-Content -LiteralPath $out -Raw
        $text | Should -Match '### Indicators'
        $text | Should -Match '900150983cd24fb0d6963f7d28e17f72'
    }
}

Describe 'ClamAV output parsing' {
    It 'parses a clean result' {
        $result = InModuleScope OffsetInspect { ConvertFrom-OIClamScanOutput -Output 'C:\path\file.bin: OK' -ExitCode 0 -FilePath 'C:\path\file.bin' }
        $result.Status | Should -Be 'Clean'
        $result.SignatureName | Should -BeNullOrEmpty
    }

    It 'parses a detection and captures the signature name' {
        $result = InModuleScope OffsetInspect { ConvertFrom-OIClamScanOutput -Output 'C:\path\file.bin: Win.Test.EICAR_HDB-1 FOUND' -ExitCode 1 -FilePath 'C:\path\file.bin' }
        $result.Status | Should -Be 'Detected'
        $result.SignatureName | Should -Be 'Win.Test.EICAR_HDB-1'
        $result.ProviderResult | Should -Be 1
    }

    It 'falls back to the exit code when no line matches' {
        $result = InModuleScope OffsetInspect { ConvertFrom-OIClamScanOutput -Output '' -ExitCode 1 -FilePath 'x' }
        $result.Status | Should -Be 'Detected'
    }

    It 'reports an error with the stderr message' {
        $result = InModuleScope OffsetInspect { ConvertFrom-OIClamScanOutput -Output '' -ExitCode 2 -FilePath 'x' -RawError 'ERROR: Could not load database' }
        $result.Status | Should -Be 'Error'
        $result.Error | Should -Match 'database'
    }
}
