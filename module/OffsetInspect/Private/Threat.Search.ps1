function Test-OIPositiveScanStatus {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Status)

    return ($Status -eq 'Detected' -or $Status -eq 'Blocked')
}

function Test-OINegativeScanStatus {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Status)

    return ($Status -eq 'Clean' -or $Status -eq 'NotDetected')
}

function Test-OIDefinitiveScanStatus {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Status)

    return (Test-OIPositiveScanStatus -Status $Status) -or (Test-OINegativeScanStatus -Status $Status)
}

function Invoke-OIPrefixBoundarySearch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ $_ -ge 1 })]
        [int64]$UnitCount,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Scanner,

        [ValidateRange(1, 10)]
        [int]$RepeatCount = 2,

        [string]$Activity = 'Locating detection boundary',

        [switch]$NoProgress
    )

    $scannerCallback = $Scanner
    $cache = @{}
    $state = [pscustomobject]@{ ScanCount = 0 }

    $completeProgress = {
        if (-not $NoProgress) {
            Write-Progress -Activity $Activity -Completed
        }
    }.GetNewClosure()

    $invokeScan = {
        param([int64]$Length, [bool]$UseCache)

        $key = [string]$Length
        if ($UseCache -and $cache.ContainsKey($key)) {
            return $cache[$key]
        }

        $state.ScanCount++
        try {
            $scan = & $scannerCallback $Length
            if ($null -eq $scan -or [string]::IsNullOrWhiteSpace([string]$scan.Status)) {
                $scan = [pscustomobject]@{
                    Status         = 'Error'
                    ProviderResult = $null
                    HResult        = $null
                    SignatureName  = $null
                    Message        = 'The scan provider returned no status.'
                    RawOutput      = $null
                }
            }
        }
        catch {
            $scan = [pscustomobject]@{
                Status         = 'Error'
                ProviderResult = $null
                HResult        = $null
                SignatureName  = $null
                Message        = $_.Exception.Message
                RawOutput      = $null
            }
        }

        if ($UseCache) {
            $cache[$key] = $scan
        }
        return $scan
    }.GetNewClosure()

    $emptyScan = & $invokeScan 0 $true
    if (-not (Test-OINegativeScanStatus -Status $emptyScan.Status)) {
        & $completeProgress
        return [pscustomobject]@{
            Success       = $false
            InitialScan   = $null
            EmptyScan     = $emptyScan
            KnownClean    = $null
            KnownDetected = $null
            ScanCount     = $state.ScanCount
            Stable        = $false
            Confidence    = 'None'
            FullChecks    = @()
            LowChecks     = @()
            HighChecks    = @()
            Error         = "The provider did not classify an empty prefix as clean. Status: $($emptyScan.Status). $($emptyScan.Message)"
        }
    }

    $initialScan = & $invokeScan $UnitCount $true
    if (Test-OINegativeScanStatus -Status $initialScan.Status) {
        $fullChecks = New-Object 'System.Collections.Generic.List[object]'
        for ($check = 0; $check -lt $RepeatCount; $check++) {
            $fullChecks.Add((& $invokeScan $UnitCount $false))
        }

        $nonDefinitive = @($fullChecks | Where-Object { -not (Test-OIDefinitiveScanStatus -Status $_.Status) })
        if ($nonDefinitive.Count -gt 0) {
            & $completeProgress
            return [pscustomobject]@{
                Success       = $false
                InitialScan   = $initialScan
                EmptyScan     = $emptyScan
                KnownClean    = $UnitCount
                KnownDetected = $null
                ScanCount     = $state.ScanCount
                Stable        = $false
                Confidence    = 'None'
                FullChecks    = $fullChecks.ToArray()
                LowChecks     = @()
                HighChecks    = @()
                Error         = "A repeated full-content scan returned a non-definitive state: $($nonDefinitive[0].Status). $($nonDefinitive[0].Message)"
            }
        }

        $stable = @($fullChecks | Where-Object { -not (Test-OINegativeScanStatus -Status $_.Status) }).Count -eq 0
        & $completeProgress
        if (-not $stable) {
            return [pscustomobject]@{
                Success       = $false
                InitialScan   = $initialScan
                EmptyScan     = $emptyScan
                KnownClean    = $UnitCount
                KnownDetected = $null
                ScanCount     = $state.ScanCount
                Stable        = $false
                Confidence    = 'None'
                FullChecks    = $fullChecks.ToArray()
                LowChecks     = @()
                HighChecks    = @()
                Error         = 'Repeated full-content scans disagreed, so no reliable boundary can be produced.'
            }
        }

        return [pscustomobject]@{
            Success       = $true
            InitialScan   = $initialScan
            EmptyScan     = $emptyScan
            KnownClean    = $UnitCount
            KnownDetected = $null
            ScanCount     = $state.ScanCount
            Stable        = $true
            Confidence    = if ($RepeatCount -ge 2) { 'High' } else { 'Medium' }
            FullChecks    = $fullChecks.ToArray()
            LowChecks     = @()
            HighChecks    = @()
            Error         = $null
        }
    }

    if (-not (Test-OIPositiveScanStatus -Status $initialScan.Status)) {
        & $completeProgress
        return [pscustomobject]@{
            Success       = $false
            InitialScan   = $initialScan
            EmptyScan     = $emptyScan
            KnownClean    = 0
            KnownDetected = $null
            ScanCount     = $state.ScanCount
            Stable        = $false
            Confidence    = 'None'
            FullChecks    = @()
            LowChecks     = @()
            HighChecks    = @()
            Error         = "The full-content scan was non-definitive. Status: $($initialScan.Status). $($initialScan.Message)"
        }
    }

    $low = [int64]0
    $high = [int64]$UnitCount
    $maximumIterations = 128
    $iteration = 0

    while (($high - $low) -gt 1) {
        if ($iteration -ge $maximumIterations) {
            & $completeProgress
            return [pscustomobject]@{
                Success       = $false
                InitialScan   = $initialScan
                EmptyScan     = $emptyScan
                KnownClean    = $low
                KnownDetected = $high
                ScanCount     = $state.ScanCount
                Stable        = $false
                Confidence    = 'None'
                FullChecks    = @()
                LowChecks     = @()
                HighChecks    = @()
                Error         = "Boundary search exceeded $maximumIterations iterations."
            }
        }

        $midpoint = $low + [int64][Math]::Floor(($high - $low) / 2)
        $scan = & $invokeScan $midpoint $true

        if (Test-OIPositiveScanStatus -Status $scan.Status) {
            $high = $midpoint
        }
        elseif (Test-OINegativeScanStatus -Status $scan.Status) {
            $low = $midpoint
        }
        else {
            & $completeProgress
            return [pscustomobject]@{
                Success       = $false
                InitialScan   = $initialScan
                EmptyScan     = $emptyScan
                KnownClean    = $low
                KnownDetected = $high
                ScanCount     = $state.ScanCount
                Stable        = $false
                Confidence    = 'None'
                FullChecks    = @()
                LowChecks     = @()
                HighChecks    = @()
                Error         = "Provider returned '$($scan.Status)' while scanning prefix length $midpoint. $($scan.Message)"
            }
        }

        $iteration++
        if (-not $NoProgress) {
            $rangeResolved = $UnitCount - ($high - $low)
            $percent = [Math]::Min(99, [int](100 * ($rangeResolved / [double]$UnitCount)))
            Write-Progress -Activity $Activity -Status "Known clean: $low; known detected: $high" -PercentComplete $percent
        }
    }

    & $completeProgress

    $lowChecks = New-Object 'System.Collections.Generic.List[object]'
    $highChecks = New-Object 'System.Collections.Generic.List[object]'

    for ($check = 0; $check -lt $RepeatCount; $check++) {
        $lowChecks.Add((& $invokeScan $low $false))
        $highChecks.Add((& $invokeScan $high $false))
    }

    $allBoundaryChecks = @($lowChecks.ToArray()) + @($highChecks.ToArray())
    $nonDefinitive = @($allBoundaryChecks | Where-Object { -not (Test-OIDefinitiveScanStatus -Status $_.Status) })
    if ($nonDefinitive.Count -gt 0) {
        return [pscustomobject]@{
            Success       = $false
            InitialScan   = $initialScan
            EmptyScan     = $emptyScan
            KnownClean    = $low
            KnownDetected = $high
            ScanCount     = $state.ScanCount
            Stable        = $false
            Confidence    = 'None'
            FullChecks    = @()
            LowChecks     = $lowChecks.ToArray()
            HighChecks    = $highChecks.ToArray()
            Error         = "A repeated boundary scan returned a non-definitive state: $($nonDefinitive[0].Status). $($nonDefinitive[0].Message)"
        }
    }

    $lowStable = @($lowChecks | Where-Object { -not (Test-OINegativeScanStatus -Status $_.Status) }).Count -eq 0
    $highStable = @($highChecks | Where-Object { -not (Test-OIPositiveScanStatus -Status $_.Status) }).Count -eq 0
    $stable = $lowStable -and $highStable
    $confidence = if ($stable -and $RepeatCount -ge 2) { 'High' } elseif ($stable) { 'Medium' } else { 'Low' }

    return [pscustomobject]@{
        Success       = $true
        InitialScan   = $initialScan
        EmptyScan     = $emptyScan
        KnownClean    = $low
        KnownDetected = $high
        ScanCount     = $state.ScanCount
        Stable        = $stable
        Confidence    = $confidence
        FullChecks    = @()
        LowChecks     = $lowChecks.ToArray()
        HighChecks    = $highChecks.ToArray()
        Error         = $null
    }
}

function ConvertTo-OIFlatThreatResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object]$Result
    )

    process {
        $fullContentStatuses = $null
        $knownCleanStatuses = $null
        $knownDetectedStatuses = $null
        if ($null -ne $Result.BoundaryValidation) {
            $fullContentStatuses = @($Result.BoundaryValidation.FullContentStatuses) -join '; '
            $knownCleanStatuses = @($Result.BoundaryValidation.KnownCleanStatuses) -join '; '
            $knownDetectedStatuses = @($Result.BoundaryValidation.KnownDetectedStatuses) -join '; '
        }

        [pscustomobject]@{
            Success                  = $Result.Success
            File                     = $Result.File
            FileSha256               = $Result.FileSha256
            ScanTimestampUtc         = $Result.ScanTimestampUtc
            Engine                   = $Result.Engine
            ScanMode                 = $Result.ScanMode
            BoundaryUnit             = $Result.BoundaryUnit
            Encoding                 = $Result.Encoding
            SearchModel              = $Result.SearchModel
            InitialStatus            = $Result.InitialStatus
            DetectionPrefixLength    = $Result.DetectionPrefixLength
            DetectionBoundaryOffset  = $Result.DetectionBoundaryOffset
            DetectionBoundaryHex     = $Result.DetectionBoundaryHex
            DetectionCharacterIndex  = $Result.DetectionCharacterIndex
            DetectionUtf16CodeUnitIndex = $Result.DetectionUtf16CodeUnitIndex
            KnownCleanPrefixLength   = $Result.KnownCleanPrefixLength
            Stable                   = $Result.Stable
            Confidence               = $Result.Confidence
            ScanCount                = $Result.ScanCount
            SignatureName            = $Result.SignatureName
            FullContentStatuses       = $fullContentStatuses
            KnownCleanStatuses        = $knownCleanStatuses
            KnownDetectedStatuses     = $knownDetectedStatuses
            DurationMs               = $Result.DurationMs
            Warning                  = @($Result.Warnings) -join '; '
            Error                    = $Result.Error
        }
    }
}

function Write-OIHumanThreatResult {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object]$Result)

    Write-OIBanner
    Write-Host ('=' * 100) -ForegroundColor DarkYellow
    Write-Host "Threat boundary scan: $($Result.File)" -ForegroundColor Green
    Write-Host "SHA-256:             $($Result.FileSha256)" -ForegroundColor Green
    Write-Host "Scan time (UTC):     $($Result.ScanTimestampUtc)" -ForegroundColor Green
    Write-Host "Engine:              $($Result.Engine)" -ForegroundColor Green
    Write-Host "Scan mode:           $($Result.ScanMode)" -ForegroundColor Green
    Write-Host "Initial status:      $($Result.InitialStatus)" -ForegroundColor Green
    Write-Host "Scans performed:     $($Result.ScanCount)" -ForegroundColor Green
    Write-Host "Duration:            $($Result.DurationMs) ms" -ForegroundColor Green

    if (-not $Result.Success) {
        Write-Host "Error:               $($Result.Error)" -ForegroundColor Red
        Write-Host ('=' * 100) -ForegroundColor DarkCyan
        return
    }

    if ($null -eq $Result.DetectionPrefixLength) {
        Write-Host 'Detection boundary:  None; the provider did not detect the complete content.' -ForegroundColor Cyan
    }
    else {
        Write-Host "Known clean prefix:  $($Result.KnownCleanPrefixLength)" -ForegroundColor Cyan
        Write-Host "Detected prefix:     $($Result.DetectionPrefixLength)" -ForegroundColor Yellow
        Write-Host "Boundary offset:     $($Result.DetectionBoundaryOffset) ($($Result.DetectionBoundaryHex))" -ForegroundColor Yellow
        if ($null -ne $Result.DetectionCharacterIndex) {
            Write-Host "Unicode scalar index: $($Result.DetectionCharacterIndex)" -ForegroundColor Yellow
            Write-Host "UTF-16 code-unit idx: $($Result.DetectionUtf16CodeUnitIndex)" -ForegroundColor Yellow
        }
        Write-Host "Stable:              $($Result.Stable)" -ForegroundColor Cyan
        Write-Host "Confidence:          $($Result.Confidence)" -ForegroundColor Cyan
        if ($Result.SignatureName) {
            Write-Host "Signature:           $($Result.SignatureName)" -ForegroundColor Cyan
        }
    }

    foreach ($warning in @($Result.Warnings)) {
        Write-Host "Warning: $warning" -ForegroundColor Yellow
    }

    if ($null -ne $Result.Inspection) {
        Write-OIHumanInspectionResult -Result $Result.Inspection -Index 1 -Total 1
    }

    Write-Host ('=' * 100) -ForegroundColor DarkCyan
}

function Write-OIThreatOutput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][object]$Result,
        [Parameter(Mandatory = $true)][ValidateSet('Human', 'Object', 'Json', 'Csv', 'CsvFile')][string]$Mode,
        [AllowNull()][string]$CsvPath
    )

    switch ($Mode) {
        'Object' { return $Result }
        'Json' { return (ConvertTo-Json -InputObject $Result -Depth 14) }
        'Csv' { return @($Result | ConvertTo-OIFlatThreatResult | ConvertTo-Csv -NoTypeInformation) }
        'CsvFile' {
            $parent = Split-Path -Parent $CsvPath
            if ($parent -and -not (Test-Path -LiteralPath $parent)) {
                $null = New-Item -ItemType Directory -Path $parent -Force
            }
            $Result | ConvertTo-OIFlatThreatResult | Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
            return (Get-Item -LiteralPath $CsvPath)
        }
        default { Write-OIHumanThreatResult -Result $Result }
    }
}
