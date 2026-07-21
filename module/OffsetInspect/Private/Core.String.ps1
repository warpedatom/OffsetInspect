function Get-OITrailingRunLength {
    <#
        Returns how many bytes at the end of a buffer could belong to a printable run
        that continues into the next window. Get-OffsetString holds these bytes back and
        re-reads them with the following window, so a string straddling a window seam is
        reported once, whole, rather than split into two truncated halves.

        An ASCII run is a trailing sequence of printable bytes; it stops at any non-
        printable byte, so the NUL padding that dominates PE files yields 0 and the
        carry-over stays small. A UTF-16LE run is a trailing sequence of printable/0x00
        pairs, optionally preceded by a lone printable low byte whose 0x00 high byte
        falls in the next window. The larger of the two is returned.

        The result is always < $Bytes.Length so the caller is guaranteed to advance; a
        single run longer than an entire window degenerates to the previous behaviour
        (split at the seam) rather than stalling.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes,

        [ValidateSet('Ascii', 'Unicode', 'Both')]
        [string]$Encoding = 'Both'
    )

    if ($null -eq $Bytes -or $Bytes.Length -eq 0) { return 0 }
    $count = $Bytes.Length

    $asciiRun = 0
    if ($Encoding -eq 'Ascii' -or $Encoding -eq 'Both') {
        $i = $count - 1
        while ($i -ge 0 -and $Bytes[$i] -ge 0x20 -and $Bytes[$i] -le 0x7E) {
            $asciiRun++
            $i--
        }
    }

    $unicodeRun = 0
    if ($Encoding -eq 'Unicode' -or $Encoding -eq 'Both') {
        $i = $count - 1
        if ($Bytes[$i] -ge 0x20 -and $Bytes[$i] -le 0x7E) {
            # Lone low byte; its high byte is the first byte of the next window.
            $unicodeRun++
            $i--
        }
        while ($i -ge 1 -and $Bytes[$i] -eq 0x00 -and $Bytes[$i - 1] -ge 0x20 -and $Bytes[$i - 1] -le 0x7E) {
            $unicodeRun += 2
            $i -= 2
        }
    }

    $carry = [Math]::Max($asciiRun, $unicodeRun)
    if ($carry -ge $count) { $carry = 0 }
    return $carry
}

function Get-OIByteString {
    <#
        Extracts printable ASCII and/or UTF-16LE strings from a byte buffer, tagging
        each with its offset (BaseOffset + position within the buffer). Pure, cross-
        platform, unit-tested directly. Printable = 0x20..0x7E; UTF-16LE runs are a
        printable low byte followed by a 0x00 high byte.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes,

        [int64]$BaseOffset = 0,

        [ValidateRange(2, 1024)]
        [int]$MinimumLength = 4,

        [ValidateSet('Ascii', 'Unicode', 'Both')]
        [string]$Encoding = 'Both'
    )

    $results = New-Object 'System.Collections.Generic.List[object]'

    if ($Encoding -eq 'Ascii' -or $Encoding -eq 'Both') {
        $runStart = -1
        for ($i = 0; $i -le $Bytes.Length; $i++) {
            $printable = $i -lt $Bytes.Length -and $Bytes[$i] -ge 0x20 -and $Bytes[$i] -le 0x7E
            if ($printable) {
                if ($runStart -lt 0) { $runStart = $i }
            }
            elseif ($runStart -ge 0) {
                $length = $i - $runStart
                if ($length -ge $MinimumLength) {
                    $value = [System.Text.Encoding]::ASCII.GetString($Bytes, $runStart, $length)
                    $results.Add([pscustomobject]@{ Offset = $BaseOffset + $runStart; Encoding = 'Ascii'; Length = $length; Value = $value })
                }
                $runStart = -1
            }
        }
    }

    if ($Encoding -eq 'Unicode' -or $Encoding -eq 'Both') {
        $runStart = -1
        $charCount = 0
        $i = 0
        while ($i -lt $Bytes.Length - 1) {
            $printable = $Bytes[$i] -ge 0x20 -and $Bytes[$i] -le 0x7E -and $Bytes[$i + 1] -eq 0x00
            if ($printable) {
                if ($runStart -lt 0) { $runStart = $i; $charCount = 0 }
                $charCount++
                $i += 2
            }
            else {
                if ($runStart -ge 0 -and $charCount -ge $MinimumLength) {
                    $value = [System.Text.Encoding]::Unicode.GetString($Bytes, $runStart, $charCount * 2)
                    $results.Add([pscustomobject]@{ Offset = $BaseOffset + $runStart; Encoding = 'Unicode'; Length = $charCount; Value = $value })
                }
                $runStart = -1
                $charCount = 0
                $i++
            }
        }
        if ($runStart -ge 0 -and $charCount -ge $MinimumLength) {
            $value = [System.Text.Encoding]::Unicode.GetString($Bytes, $runStart, $charCount * 2)
            $results.Add([pscustomobject]@{ Offset = $BaseOffset + $runStart; Encoding = 'Unicode'; Length = $charCount; Value = $value })
        }
    }

    return $results.ToArray()
}
