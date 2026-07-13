function Split-OIByteRange {
    <#
        Splits [0, TotalLength) into SegmentCount contiguous, gap-free byte segments
        (the remainder is distributed across the leading segments). Pure arithmetic,
        so it runs on every platform and is unit-tested directly.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ $_ -ge 0 })]
        [int64]$TotalLength,

        [ValidateRange(1, 4096)]
        [int]$SegmentCount = 8
    )

    if ($TotalLength -le 0) { return @() }

    $count = [int][Math]::Min([int64]$SegmentCount, $TotalLength)
    $baseLength = [int64][Math]::Floor($TotalLength / $count)
    $remainder = $TotalLength - ($baseLength * $count)

    $segments = New-Object 'System.Collections.Generic.List[object]'
    $start = [int64]0
    for ($i = 0; $i -lt $count; $i++) {
        $length = $baseLength
        if ($i -lt $remainder) { $length += 1 }
        $segments.Add([pscustomobject]@{ Index = $i; Start = $start; Length = [int64]$length })
        $start += $length
    }

    return $segments.ToArray()
}

function Find-OIDetectionSegment {
    <#
        Scans each supplied byte segment in isolation through an injected buffer
        scanner (a scriptblock: param([byte[]]$Bytes, [int]$Length) -> scan object)
        and returns the segments that independently trigger a positive status. When
        -Refine is set, each hit is bisected within the segment (reusing
        Invoke-OIPrefixBoundarySearch) to map the exact triggering boundary back to
        an absolute file offset. The scanner is injected so this logic is testable
        cross-platform with a mock; the live AMSI session is wired by the caller.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.FileStream]$Stream,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Segment,

        [Parameter(Mandatory = $true)]
        [scriptblock]$BufferScanner,

        [ValidateRange(1, 10)]
        [int]$RepeatCount = 2,

        [switch]$Refine,

        [switch]$NoProgress
    )

    $regions = New-Object 'System.Collections.Generic.List[object]'
    $index = 0
    foreach ($current in $Segment) {
        $index++
        if (-not $NoProgress) {
            Write-Progress -Activity 'Multi-region detection scan' -Status "segment $index/$($Segment.Count)" -PercentComplete ([int](100.0 * $index / [Math]::Max(1, $Segment.Count)))
        }

        $length = [int]$current.Length
        if ($length -le 0) { continue }

        $bytes = Read-OIFileRange -Stream $Stream -Start $current.Start -Length $length
        if ($bytes.Length -eq 0) { continue }

        $scan = & $BufferScanner $bytes $bytes.Length
        if (-not (Test-OIPositiveScanStatus -Status ([string]$scan.Status))) { continue }

        $withinBoundary = $null
        if ($Refine) {
            $segmentBytes = $bytes
            $scannerReference = $BufferScanner
            $prefixScanner = {
                param([int64]$Length)
                $prefixLength = [int]$Length
                if ($prefixLength -le 0) {
                    return [pscustomobject]@{
                        Status = 'Clean'; ProviderResult = 0; HResult = '0x00000000'
                        SignatureName = $null; Message = 'Synthetic empty-prefix baseline.'; RawOutput = $null
                    }
                }
                $slice = New-Object byte[] $prefixLength
                [System.Buffer]::BlockCopy($segmentBytes, 0, $slice, 0, $prefixLength)
                return (& $scannerReference $slice $prefixLength)
            }.GetNewClosure()

            $search = Invoke-OIPrefixBoundarySearch -UnitCount $bytes.Length -Scanner $prefixScanner -RepeatCount $RepeatCount -NoProgress
            if ($search.Success -and $null -ne $search.KnownDetected) {
                $withinBoundary = [int64]$search.KnownDetected
            }
        }

        $absoluteBoundary = if ($null -ne $withinBoundary) { [int64]$current.Start + $withinBoundary } else { $null }
        $regions.Add([pscustomobject]@{
            SegmentIndex           = $current.Index
            StartOffset            = $current.Start
            EndOffset              = $current.Start + $current.Length - 1
            Length                 = $current.Length
            Status                 = $scan.Status
            ProviderResult         = Get-OIResultProperty -InputObject $scan -Name 'ProviderResult'
            SignatureName          = Get-OIResultProperty -InputObject $scan -Name 'SignatureName'
            WithinSegmentBoundary  = $withinBoundary
            AbsoluteBoundaryOffset = $absoluteBoundary
        })
    }

    if (-not $NoProgress) {
        Write-Progress -Activity 'Multi-region detection scan' -Completed
    }

    return $regions.ToArray()
}
