function Get-OIStringByteEnd {
    # Absolute offset of the LAST byte of an extracted string. ASCII is one byte per
    # char; UTF-16LE is two. Length is the character count from Get-OIByteString.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $StringHit
    )

    $byteLength = if ($StringHit.Encoding -eq 'Unicode') { [int64]$StringHit.Length * 2 } else { [int64]$StringHit.Length }
    return [int64]$StringHit.Offset + $byteLength - 1
}

function Get-OIDetectionTrigger {
    <#
        Correlates a detection boundary to the file content that most likely produced it.

        A prefix boundary means the byte at BoundaryOffset is the LAST byte of the earliest
        detected prefix, so the triggering content is a run of bytes ENDING at that offset.
        Given the already-read region around the boundary, this reports: the PE section it
        falls in, the entropy of the run up to the boundary (plaintext vs packed), and the
        extracted strings that end at or straddle the boundary ranked by proximity - i.e. the
        candidate signature content. Pure and cross-platform; the public wrapper does the I/O.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$RegionBytes,

        [Parameter(Mandatory = $true)]
        [int64]$RegionStart,

        [Parameter(Mandatory = $true)]
        [int64]$BoundaryOffset,

        [Parameter(Mandatory = $true)]
        [int64]$FileSize,

        [ValidateRange(2, 1024)]
        [int]$MinimumLength = 4,

        [int]$MaxCandidates = 8,

        [AllowNull()]
        $Image = $null,

        [AllowNull()]
        [string]$SignatureName = $null,

        [AllowNull()]
        [string]$File = $null
    )

    $regionEnd = $RegionStart + $RegionBytes.Length - 1

    # Entropy of the run up to and including the boundary (the part that flipped the verdict).
    $preLength = [int]([Math]::Max([int64]0, [Math]::Min([int64]$RegionBytes.Length, $BoundaryOffset - $RegionStart + 1)))
    $preBoundaryEntropy = if ($preLength -gt 0) { Get-OIShannonEntropy -Bytes $RegionBytes -Length $preLength } else { 0.0 }

    $section = $null
    if ($null -ne $Image) {
        $section = Get-OIPESectionForOffset -Image $Image -Offset $BoundaryOffset
    }

    $boundaryByte = $null
    $boundaryIndex = [int]($BoundaryOffset - $RegionStart)
    if ($boundaryIndex -ge 0 -and $boundaryIndex -lt $RegionBytes.Length) {
        $boundaryByte = $RegionBytes[$boundaryIndex]
    }

    # Rank extracted strings by how they relate to the boundary: ones containing it first,
    # then ones ending just before it. A string starting AFTER the boundary cannot be the
    # trigger for a prefix that ends at the boundary, so it is excluded.
    $candidates = New-Object 'System.Collections.Generic.List[object]'
    foreach ($hit in (Get-OIByteString -Bytes $RegionBytes -BaseOffset $RegionStart -MinimumLength $MinimumLength -Encoding 'Both')) {
        $endAbs = Get-OIStringByteEnd -StringHit $hit
        $contains = ([int64]$hit.Offset -le $BoundaryOffset -and $BoundaryOffset -le $endAbs)
        if ($contains) {
            $distance = [int64]0
        }
        elseif ($endAbs -lt $BoundaryOffset) {
            $distance = $BoundaryOffset - $endAbs
        }
        else {
            continue
        }

        $candidates.Add([pscustomobject]@{
            Offset             = [int64]$hit.Offset
            OffsetHex          = '0x{0:X}' -f [int64]$hit.Offset
            Encoding           = $hit.Encoding
            Length             = $hit.Length
            Value              = $hit.Value
            EndsAtOffset       = $endAbs
            EndsAtHex          = '0x{0:X}' -f $endAbs
            ContainsBoundary   = $contains
            DistanceToBoundary = $distance
        })
    }

    $ranked = @($candidates |
        Sort-Object -Property @{ Expression = 'ContainsBoundary'; Descending = $true },
                              @{ Expression = 'DistanceToBoundary'; Descending = $false },
                              @{ Expression = 'Length'; Descending = $true } |
        Select-Object -First $MaxCandidates)

    # Heuristic read of what the boundary content most likely is.
    $topString = if ($ranked.Count -gt 0) { $ranked[0] } else { $null }
    $sectionSuffix = if ($null -ne $section) { " in section '$section'" } else { '' }
    $interpretation = if ($null -ne $topString -and ($topString.ContainsBoundary -or $topString.DistanceToBoundary -le 2) -and $preBoundaryEntropy -lt 5.0) {
        $preview = if ($topString.Value.Length -gt 80) { $topString.Value.Substring(0, 80) + '...' } else { $topString.Value }
        "Likely textual signature - content ending at the boundary: '$preview'"
    }
    elseif ($preBoundaryEntropy -ge 7.0) {
        "High-entropy region ($preBoundaryEntropy bits/byte) at the boundary - signature content is likely binary or packed$sectionSuffix"
    }
    else {
        "Binary signature near the boundary$sectionSuffix"
    }

    return [pscustomobject]@{
        PSTypeName          = 'OffsetInspect.DetectionTrigger'
        File                = $File
        SignatureName       = $SignatureName
        BoundaryOffset      = $BoundaryOffset
        BoundaryHex         = '0x{0:X}' -f $BoundaryOffset
        BoundaryByteDecimal = if ($null -ne $boundaryByte) { [int]$boundaryByte } else { $null }
        BoundaryByteHex     = if ($null -ne $boundaryByte) { '0x{0:X2}' -f $boundaryByte } else { $null }
        Section             = $section
        RegionStart         = $RegionStart
        RegionEnd           = $regionEnd
        RegionSize          = $RegionBytes.Length
        PreBoundaryEntropy  = $preBoundaryEntropy
        CandidateStrings    = $ranked
        Interpretation      = $interpretation
        HexDump             = @(Format-OIHexDump -Data $RegionBytes -StartOffset $RegionStart -HighlightOffset $BoundaryOffset -FileSize $FileSize)
    }
}
