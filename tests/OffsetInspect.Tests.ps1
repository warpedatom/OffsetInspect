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
    It 'has a valid 2.0.0 manifest' {
        $manifest = Test-ModuleManifest -Path $ManifestPath -ErrorAction Stop
        $manifest.Version.ToString() | Should -Be '2.0.0'
        $manifest.RootModule | Should -Be 'OffsetInspect.psm1'
    }

    It 'exports only the supported public commands' {
        $commands = @(Get-Command -Module OffsetInspect | Select-Object -ExpandProperty Name | Sort-Object)
        ($commands -join ',') | Should -Be 'Invoke-OffsetInspect,Invoke-OffsetThreatScan'
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
    }
}
