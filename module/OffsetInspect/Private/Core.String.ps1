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
