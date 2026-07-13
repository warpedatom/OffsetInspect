function Invoke-OffsetThreatScanRegion {
    <#
    .SYNOPSIS
        Discovers multiple independently-detectable byte regions in a file via in-memory AMSI scanning.

    .DESCRIPTION
        Splits the file into contiguous byte segments and scans each in isolation through AMSI
        (AmsiScanBuffer, entirely in memory - nothing detected is written to disk, so Microsoft
        Defender real-time protection is never triggered and is never altered). Segments that
        independently trigger detection are returned as regions; by default each hit is bisected
        within its segment to map the exact triggering boundary to an absolute file offset.

        This finds regions that trigger on their own. It can miss signatures that only fire in
        full-file context or that straddle a segment boundary, so treat the regions as leads to
        confirm with Invoke-OffsetThreatScan and manual validation, not as a complete list of
        every triggering byte. AMSI (in-memory) is the only supported engine here; Microsoft
        Defender file scanning would require writing detected content to disk.

    .PARAMETER FilePath
        The file to analyse.

    .PARAMETER SegmentCount
        Number of contiguous segments to divide the file into (default 8).

    .PARAMETER NoRefine
        Skip the within-segment boundary bisection; report segment-level hits only.

    .EXAMPLE
        Invoke-OffsetThreatScanRegion .\payload.bin -SegmentCount 16 |
            Select-Object -ExpandProperty DetectedRegions
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateRange(1, 4096)]
        [int]$SegmentCount = 8,

        [ValidateRange(1, 10)]
        [int]$RepeatCount = 2,

        [switch]$NoRefine,

        [switch]$NoProgress
    )

    if (-not (Test-OIIsWindows)) {
        throw 'Threat-provider scanning is supported only on Windows. Offset inspection remains cross-platform.'
    }

    $resolvedPath = (Resolve-Path -LiteralPath $FilePath -ErrorAction Stop).Path
    $item = Get-Item -LiteralPath $resolvedPath -ErrorAction Stop
    if ($item.PSIsContainer) { throw "Path is a directory, not a file: $resolvedPath" }

    $fileSize = $item.Length
    if ($fileSize -gt [int]::MaxValue) {
        throw 'AMSI region scanning supports files up to 2 GB because scan content is represented by managed arrays.'
    }

    Initialize-OIAmsiInterop

    # Capture the private response converter as a command reference so it resolves
    # when the scanner closure runs inside the boundary search (bare private-function
    # names do not resolve in that invocation scope).
    $convertFromAmsiResponseCommand = Get-Command -Name ConvertFrom-OIAmsiResponse -CommandType Function -ErrorAction Stop

    $session = $null
    $stream = $null
    $segments = @()
    $regions = @()
    $fileSha256 = $null
    $errorMessage = $null
    try {
        $session = New-Object OffsetInspect.Interop.AmsiSession('OffsetInspect/3.0')
        $stream = [System.IO.File]::Open(
            $resolvedPath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read
        )
        $fileSha256 = Get-OIStreamSha256 -Stream $stream
        $segments = @(Split-OIByteRange -TotalLength $fileSize -SegmentCount $SegmentCount)

        $sessionReference = $session
        $contentName = $resolvedPath
        $bufferScanner = {
            param([byte[]]$Bytes, [int]$Length)
            return (& $convertFromAmsiResponseCommand -Response $sessionReference.ScanBytePrefix($Bytes, $Length, $contentName))
        }.GetNewClosure()

        $regions = @(Find-OIDetectionSegment `
            -Stream $stream `
            -Segment $segments `
            -BufferScanner $bufferScanner `
            -RepeatCount $RepeatCount `
            -Refine:(-not $NoRefine) `
            -NoProgress:$NoProgress)
    }
    catch {
        $errorMessage = $_.Exception.Message
    }
    finally {
        if ($null -ne $session) {
            try { $session.Dispose() }
            catch { Write-Verbose "AMSI session cleanup failed: $($_.Exception.Message)" }
        }
        if ($null -ne $stream) { $stream.Dispose() }
    }

    $warnings = @(
        'Multi-region discovery reports independently-detectable byte segments via in-memory AMSI scanning. ' +
        'It can miss signatures that only fire in full-file context or that straddle a segment boundary; ' +
        'confirm regions with Invoke-OffsetThreatScan and manual validation.'
    )

    $result = [pscustomobject]@{
        Success             = ($null -eq $errorMessage)
        File                = $resolvedPath
        FileSize            = $fileSize
        FileSha256          = $fileSha256
        Engine              = 'AMSI'
        ScanMode            = 'RawBytes'
        SegmentCount        = @($segments).Count
        DetectedRegionCount = @($regions).Count
        DetectedRegions     = @($regions)
        Warnings            = $warnings
        Error               = $errorMessage
    }
    $result.PSObject.TypeNames.Insert(0, 'OffsetInspect.ThreatRegionResult')
    return $result
}
