function Get-OffsetEntropy {
    <#
    .SYNOPSIS
        Computes per-window Shannon entropy across a file to locate packed or encrypted regions.

    .DESCRIPTION
        Reads the file in fixed-size windows (bounded memory) and reports the entropy of each
        window in bits per byte, flagging windows at or above the high-entropy threshold. High,
        sustained entropy (roughly 7.5-8.0) is a common indicator of compressed, encrypted, or
        packed content. The returned window offsets feed directly into Invoke-OffsetInspect and
        can be cross-referenced with Invoke-OffsetThreatScanRegion detections. Cross-platform.

    .PARAMETER FilePath
        The file to analyse.

    .PARAMETER WindowSize
        Bytes per entropy window (default 256).

    .PARAMETER HighEntropyThreshold
        Bits-per-byte at or above which a window is flagged high entropy (default 7.0).

    .PARAMETER HighOnly
        Return only the flagged high-entropy windows.

    .EXAMPLE
        Get-OffsetEntropy .\sample.bin -WindowSize 512 -HighOnly |
            Select-Object -ExpandProperty Windows
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateRange(16, 16777216)]
        [int]$WindowSize = 256,

        [ValidateRange(0.0, 8.0)]
        [double]$HighEntropyThreshold = 7.0,

        [switch]$HighOnly
    )

    $resolvedPath = (Resolve-Path -LiteralPath $FilePath -ErrorAction Stop).Path
    $item = Get-Item -LiteralPath $resolvedPath -ErrorAction Stop
    if ($item.PSIsContainer) { throw "Path is a directory, not a file: $resolvedPath" }
    $fileSize = $item.Length

    $windows = New-Object 'System.Collections.Generic.List[object]'
    $overallFrequencies = New-Object 'long[]' 256
    $totalBytes = [int64]0
    $windowCount = 0
    $highWindowCount = 0

    $stream = $null
    try {
        $stream = [System.IO.File]::Open(
            $resolvedPath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read
        )

        $start = [int64]0
        while ($start -lt $fileSize) {
            $bytes = Read-OIFileRange -Stream $stream -Start $start -Length $WindowSize
            $length = $bytes.Length
            if ($length -le 0) { break }

            $entropy = Get-OIShannonEntropy -Bytes $bytes -Length $length
            $isHigh = $entropy -ge $HighEntropyThreshold

            for ($i = 0; $i -lt $length; $i++) { $overallFrequencies[$bytes[$i]]++ }
            $totalBytes += $length
            if ($isHigh) { $highWindowCount++ }

            if (-not $HighOnly -or $isHigh) {
                $windows.Add([pscustomobject]@{
                    Index       = $windowCount
                    StartOffset = $start
                    StartHex    = '0x{0:X}' -f $start
                    EndOffset   = $start + $length - 1
                    Length      = $length
                    Entropy     = $entropy
                    IsHigh      = $isHigh
                })
            }

            $windowCount++
            $start += $length
        }
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }

    $overallEntropy = 0.0
    if ($totalBytes -gt 0) {
        foreach ($frequency in $overallFrequencies) {
            if ($frequency -gt 0) {
                $probability = $frequency / $totalBytes
                $overallEntropy -= $probability * [Math]::Log($probability, 2)
            }
        }
        $overallEntropy = [Math]::Round($overallEntropy, 6)
    }

    $result = [pscustomobject]@{
        File                 = $resolvedPath
        FileSize             = $fileSize
        WindowSize           = $WindowSize
        WindowCount          = $windowCount
        OverallEntropy       = $overallEntropy
        HighEntropyThreshold = $HighEntropyThreshold
        HighWindowCount      = $highWindowCount
        Windows              = $windows.ToArray()
    }
    $result.PSObject.TypeNames.Insert(0, 'OffsetInspect.EntropyResult')
    return $result
}
