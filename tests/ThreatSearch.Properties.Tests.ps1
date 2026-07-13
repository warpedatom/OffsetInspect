#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.0.0' }

<#
    Property / fuzz tests for Invoke-OIPrefixBoundarySearch.

    These exercise the boundary-search invariant with a deterministic in-memory
    mock provider, so they run cross-platform (no Windows, AMSI, or Defender
    required) and are safe to run in the PowerShell 7 Linux CI leg.

    Invariant under test: for a provider whose detection is a monotonic
    clean -> detected step at prefix length B, the search must converge to
    KnownClean = B-1 and KnownDetected = B using a logarithmic number of
    provider probes, and must never report a stable boundary that the mock
    did not actually produce.

    Place under tests/ in the repository so it is picked up by the existing
    Pester run in build/Test-Module.ps1.
#>

BeforeAll {
    Set-StrictMode -Version 2.0

    # Locate Threat.Search.ps1 relative to this test file. Adjust the relative
    # path if the test is not placed directly under tests/.
    $moduleRoot = Join-Path (Split-Path -Parent $PSScriptRoot) 'module/OffsetInspect'
    $searchScript = Join-Path $moduleRoot 'Private/Threat.Search.ps1'
    if (-not (Test-Path -LiteralPath $searchScript)) {
        # Fallback: allow running against a flat module layout.
        $searchScript = Join-Path (Split-Path -Parent $PSScriptRoot) 'OffsetInspect/Private/Threat.Search.ps1'
    }
    . $searchScript

    # Build a monotonic step-function scanner: Clean below $Boundary, Detected
    # at or above it. The closure captures $Boundary at creation time.
    function New-MonotonicScanner {
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', 'Boundary',
            Justification = 'Captured by the returned closure scriptblock; PSScriptAnalyzer does not see usage inside nested scriptblocks.')]
        param([int64]$Boundary)
        return {
            param([int64]$Length)
            if ($Length -ge $Boundary) {
                [pscustomobject]@{ Status = 'Detected'; ProviderResult = 32768; HResult = '0x00000000'; SignatureName = 'Mock/Test'; Message = $null; RawOutput = $null }
            }
            else {
                [pscustomobject]@{ Status = 'Clean'; ProviderResult = 0; HResult = '0x00000000'; SignatureName = $null; Message = $null; RawOutput = $null }
            }
        }.GetNewClosure()
    }
}

Describe 'Invoke-OIPrefixBoundarySearch monotonic convergence' {

    It 'converges to the exact transition for boundary <Boundary> of <UnitCount>' -ForEach @(
        @{ UnitCount = 2;     Boundary = 1 }
        @{ UnitCount = 2;     Boundary = 2 }
        @{ UnitCount = 10;    Boundary = 1 }
        @{ UnitCount = 10;    Boundary = 5 }
        @{ UnitCount = 10;    Boundary = 10 }
        @{ UnitCount = 1024;  Boundary = 1 }
        @{ UnitCount = 1024;  Boundary = 512 }
        @{ UnitCount = 1024;  Boundary = 841 }
        @{ UnitCount = 1024;  Boundary = 1024 }
        @{ UnitCount = 65536; Boundary = 40000 }
    ) {
        $scanner = New-MonotonicScanner -Boundary $Boundary
        $result = Invoke-OIPrefixBoundarySearch -UnitCount $UnitCount -Scanner $scanner -RepeatCount 2 -NoProgress

        $result.Success       | Should -BeTrue
        $result.KnownClean    | Should -Be ($Boundary - 1)
        $result.KnownDetected | Should -Be $Boundary
        $result.Stable        | Should -BeTrue
        $result.Confidence    | Should -Be 'High'
    }

    It 'uses a logarithmic probe budget (boundary <Boundary> of <UnitCount>)' -ForEach @(
        @{ UnitCount = 1024;   Boundary = 841 }
        @{ UnitCount = 65536;  Boundary = 40000 }
        @{ UnitCount = 262144; Boundary = 199999 }
    ) {
        $scanner = New-MonotonicScanner -Boundary $Boundary
        $result = Invoke-OIPrefixBoundarySearch -UnitCount $UnitCount -Scanner $scanner -RepeatCount 2 -NoProgress

        # Distinct prefix lengths actually sent to the provider must be
        # bounded by the bisection depth plus a small constant (baseline +
        # full-content + boundary re-checks). A linear regression would blow
        # far past this.
        $distinctLengths = @($result.ProbeLog | ForEach-Object { $_.PrefixLength } | Sort-Object -Unique)
        $ceilLog2 = [Math]::Ceiling([Math]::Log($UnitCount, 2))
        $distinctLengths.Count | Should -BeLessOrEqual ([int]$ceilLog2 + 6)
    }
}

Describe 'Invoke-OIPrefixBoundarySearch randomized fuzz' {

    It 'holds the convergence invariant across randomized inputs (seed <Seed>)' -ForEach @(
        @{ Seed = 1 }, @{ Seed = 7 }, @{ Seed = 42 }, @{ Seed = 1337 }, @{ Seed = 90210 }
    ) {
        $null = Get-Random -SetSeed $Seed
        1..40 | ForEach-Object {
            $unitCount = Get-Random -Minimum 2 -Maximum 100000
            $boundary  = Get-Random -Minimum 1 -Maximum ($unitCount + 1)

            $scanner = New-MonotonicScanner -Boundary $boundary
            $result = Invoke-OIPrefixBoundarySearch -UnitCount $unitCount -Scanner $scanner -RepeatCount 2 -NoProgress

            $result.Success       | Should -BeTrue -Because "unit=$unitCount boundary=$boundary"
            $result.KnownClean    | Should -Be ($boundary - 1) -Because "unit=$unitCount boundary=$boundary"
            $result.KnownDetected | Should -Be $boundary -Because "unit=$unitCount boundary=$boundary"
        }
    }
}

Describe 'Invoke-OIPrefixBoundarySearch degenerate and adversarial cases' {

    It 'reports no boundary when the full content is clean' {
        # Boundary above UnitCount => never detected.
        $scanner = New-MonotonicScanner -Boundary 5000
        $result = Invoke-OIPrefixBoundarySearch -UnitCount 1024 -Scanner $scanner -RepeatCount 2 -NoProgress

        $result.Success       | Should -BeTrue
        $result.KnownClean    | Should -Be 1024
        $result.KnownDetected | Should -BeNullOrEmpty
    }

    It 'fails cleanly when the empty prefix is already detected' {
        # Boundary 0 => even length-0 baseline would be "detected"; but the
        # search synthesises a length-0 call, so drive detection from length 1
        # while forcing the empty baseline positive via a custom scanner.
        $scanner = {
            param([int64]$Length)
            # Required by the scanner contract; this mock detects unconditionally
            # regardless of prefix length, so $Length is intentionally unused.
            $null = $Length
            [pscustomobject]@{ Status = 'Detected'; ProviderResult = 32768; HResult = '0x00000000'; SignatureName = 'Mock'; Message = $null; RawOutput = $null }
        }
        $result = Invoke-OIPrefixBoundarySearch -UnitCount 1024 -Scanner $scanner -RepeatCount 2 -NoProgress

        $result.Success | Should -BeFalse
        $result.Error   | Should -Match 'empty prefix'
    }

    It 'does not throw and does not claim stability on an indeterminate midpoint' {
        $scanner = {
            param([int64]$Length)
            if ($Length -eq 0)   { return [pscustomobject]@{ Status = 'Clean';        ProviderResult = 0;     HResult = $null; SignatureName = $null; Message = $null; RawOutput = $null } }
            if ($Length -ge 1024){ return [pscustomobject]@{ Status = 'Detected';     ProviderResult = 32768; HResult = $null; SignatureName = $null; Message = $null; RawOutput = $null } }
            return [pscustomobject]@{ Status = 'Indeterminate'; ProviderResult = $null; HResult = $null; SignatureName = $null; Message = 'mock ambiguous'; RawOutput = $null }
        }
        $result = Invoke-OIPrefixBoundarySearch -UnitCount 1024 -Scanner $scanner -RepeatCount 2 -NoProgress

        $result.Success | Should -BeFalse
        $result.Stable  | Should -BeFalse
    }

    It 'surfaces provider errors without throwing' {
        $scanner = {
            param([int64]$Length)
            if ($Length -eq 0)    { return [pscustomobject]@{ Status = 'Clean';    ProviderResult = 0;     HResult = $null; SignatureName = $null; Message = $null; RawOutput = $null } }
            if ($Length -ge 1024) { return [pscustomobject]@{ Status = 'Detected'; ProviderResult = 32768; HResult = $null; SignatureName = $null; Message = $null; RawOutput = $null } }
            throw 'simulated provider crash'
        }
        { Invoke-OIPrefixBoundarySearch -UnitCount 1024 -Scanner $scanner -RepeatCount 2 -NoProgress } | Should -Not -Throw
        $result = Invoke-OIPrefixBoundarySearch -UnitCount 1024 -Scanner $scanner -RepeatCount 2 -NoProgress
        $result.Success | Should -BeFalse
    }
}

Describe 'ProbeLog audit trail integrity' {

    It 'records a well-formed, monotonically sequenced probe log' {
        $scanner = New-MonotonicScanner -Boundary 841
        $result = Invoke-OIPrefixBoundarySearch -UnitCount 1024 -Scanner $scanner -RepeatCount 2 -NoProgress

        $result.ProbeLog | Should -Not -BeNullOrEmpty
        $sequences = @($result.ProbeLog | ForEach-Object { $_.Sequence })
        $sorted = @($sequences | Sort-Object)
        $sequences | Should -Be $sorted   # already in issue order

        foreach ($entry in $result.ProbeLog) {
            $entry.PSObject.Properties['PrefixLength'] | Should -Not -BeNullOrEmpty
            $entry.PSObject.Properties['Status']       | Should -Not -BeNullOrEmpty
            $entry.PSObject.Properties['TimestampUtc']  | Should -Not -BeNullOrEmpty
            $entry.ElapsedMs | Should -BeGreaterOrEqual 0
        }
    }
}
