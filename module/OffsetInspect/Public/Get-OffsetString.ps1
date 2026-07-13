function Get-OffsetString {
    <#
    .SYNOPSIS
        Extracts printable ASCII and UTF-16LE strings from a file with their byte offsets.

    .DESCRIPTION
        Scans the file in bounded-memory windows and emits each printable string (default
        minimum length 4) tagged with its absolute byte offset and encoding. The offsets feed
        directly into Invoke-OffsetInspect for context. A string that straddles a window
        boundary may be split; raise -WindowSize to reduce that. Cross-platform.

    .PARAMETER FilePath
        The file to scan.

    .PARAMETER MinimumLength
        Minimum character count for a string to be reported (default 4).

    .PARAMETER Encoding
        Ascii, Unicode (UTF-16LE), or Both (default).

    .PARAMETER WindowSize
        Bytes read per window (default 1 MiB).

    .EXAMPLE
        Get-OffsetString .\sample.bin -MinimumLength 6 | Where-Object Value -match 'http|\.exe'
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateRange(2, 1024)]
        [int]$MinimumLength = 4,

        [ValidateSet('Ascii', 'Unicode', 'Both')]
        [string]$Encoding = 'Both',

        [ValidateRange(4096, 67108864)]
        [int]$WindowSize = 1048576
    )

    $resolvedPath = (Resolve-Path -LiteralPath $FilePath -ErrorAction Stop).Path
    $item = Get-Item -LiteralPath $resolvedPath -ErrorAction Stop
    if ($item.PSIsContainer) { throw "Path is a directory, not a file: $resolvedPath" }
    $fileSize = $item.Length

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
            if ($bytes.Length -le 0) { break }

            foreach ($found in (Get-OIByteString -Bytes $bytes -BaseOffset $start -MinimumLength $MinimumLength -Encoding $Encoding)) {
                [pscustomobject]@{
                    Offset    = $found.Offset
                    OffsetHex = '0x{0:X}' -f $found.Offset
                    Encoding  = $found.Encoding
                    Length    = $found.Length
                    Value     = $found.Value
                }
            }

            $start += $bytes.Length
        }
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }
}
