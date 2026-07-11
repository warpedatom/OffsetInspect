function New-OIUnicodeScalarMap {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Text
    )

    $pairStarts = New-Object 'System.Collections.Generic.List[System.Int32]'
    $index = 0
    while ($index -lt $Text.Length) {
        if ([char]::IsHighSurrogate($Text[$index]) -and
            ($index + 1) -lt $Text.Length -and
            [char]::IsLowSurrogate($Text[$index + 1])) {
            $pairStarts.Add($index)
            $index += 2
        }
        else {
            $index++
        }
    }

    return [pscustomobject]@{
        TextLength       = [int]$Text.Length
        SurrogatePairs   = $pairStarts.ToArray()
        UnicodeScalarCount = [int64]$Text.Length - [int64]$pairStarts.Count
    }
}

function Get-OISurrogatePairCountBefore {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [int[]]$PairStarts,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ $_ -ge 0 })]
        [int]$Utf16PrefixLength
    )

    $low = 0
    $high = $PairStarts.Length
    while ($low -lt $high) {
        $midpoint = $low + [int][Math]::Floor(($high - $low) / 2)
        if ($PairStarts[$midpoint] -lt $Utf16PrefixLength) {
            $low = $midpoint + 1
        }
        else {
            $high = $midpoint
        }
    }

    return $low
}

function ConvertTo-OIUtf16PrefixLength {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$ScalarMap,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ $_ -ge 0 })]
        [int64]$UnicodeScalarPrefixLength
    )

    if ($UnicodeScalarPrefixLength -gt $ScalarMap.UnicodeScalarCount) {
        throw "Unicode scalar prefix length $UnicodeScalarPrefixLength exceeds content length $($ScalarMap.UnicodeScalarCount)."
    }

    if ($UnicodeScalarPrefixLength -eq 0) { return 0 }

    $pairStarts = [int[]]$ScalarMap.SurrogatePairs
    $low = [int]$UnicodeScalarPrefixLength
    $high = [int]($UnicodeScalarPrefixLength + $pairStarts.Length)

    while ($low -lt $high) {
        $midpoint = $low + [int][Math]::Floor(($high - $low) / 2)
        $pairCount = Get-OISurrogatePairCountBefore -PairStarts $pairStarts -Utf16PrefixLength $midpoint
        $scalarCount = $midpoint - $pairCount

        if ($scalarCount -ge $UnicodeScalarPrefixLength) {
            $high = $midpoint
        }
        else {
            $low = $midpoint + 1
        }
    }

    return $low
}

function Get-OIStrictEncoding {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Text.Encoding]$Encoding
    )

    return [System.Text.Encoding]::GetEncoding(
        $Encoding.CodePage,
        [System.Text.EncoderFallback]::ExceptionFallback,
        [System.Text.DecoderFallback]::ExceptionFallback
    )
}
