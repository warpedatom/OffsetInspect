function Test-OIIsWindows {
    [CmdletBinding()]
    param()

    $isWindowsVariable = Get-Variable -Name IsWindows -Scope Global -ErrorAction SilentlyContinue
    if ($null -ne $isWindowsVariable) {
        return [bool]$isWindowsVariable.Value
    }

    return ($env:OS -eq 'Windows_NT')
}

function Resolve-OIEncoding {
    [CmdletBinding(DefaultParameterSetName = 'Path')]
    param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Path')]
        [string]$Path,

        [Parameter(Mandatory = $true, ParameterSetName = 'Stream')]
        [System.IO.Stream]$Stream,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Auto', 'Default', 'UTF8', 'UTF16LE', 'UTF16BE', 'ASCII')]
        [string]$Name
    )

    $detectedName = $Name
    $preambleLength = 0
    $header = New-Object byte[] 4
    $read = 0
    $sourceStream = $Stream
    $ownsStream = $false
    $originalPosition = $null

    try {
        if ($PSCmdlet.ParameterSetName -eq 'Path') {
            $sourceStream = [System.IO.File]::Open(
                $Path,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::Read
            )
            $ownsStream = $true
        }
        elseif (-not $sourceStream.CanSeek) {
            throw 'Encoding resolution requires a seekable stream.'
        }

        if (-not $ownsStream) {
            $originalPosition = $sourceStream.Position
        }

        $null = $sourceStream.Seek(0, [System.IO.SeekOrigin]::Begin)
        $read = $sourceStream.Read($header, 0, $header.Length)
    }
    finally {
        if ($ownsStream -and $null -ne $sourceStream) {
            $sourceStream.Dispose()
        }
        elseif ($null -ne $sourceStream -and $null -ne $originalPosition) {
            $null = $sourceStream.Seek([int64]$originalPosition, [System.IO.SeekOrigin]::Begin)
        }
    }

    $hasUtf8Bom = $read -ge 3 -and $header[0] -eq 0xEF -and $header[1] -eq 0xBB -and $header[2] -eq 0xBF
    $hasUtf16LeBom = $read -ge 2 -and $header[0] -eq 0xFF -and $header[1] -eq 0xFE
    $hasUtf16BeBom = $read -ge 2 -and $header[0] -eq 0xFE -and $header[1] -eq 0xFF

    if ($Name -eq 'Auto') {
        if ($hasUtf8Bom) {
            $detectedName = 'UTF8'
        }
        elseif ($hasUtf16LeBom) {
            $detectedName = 'UTF16LE'
        }
        elseif ($hasUtf16BeBom) {
            $detectedName = 'UTF16BE'
        }
        else {
            # UTF-8 is the safest cross-platform default for modern source files.
            $detectedName = 'UTF8'
        }
    }

    if (($detectedName -eq 'UTF8' -and $hasUtf8Bom)) {
        $preambleLength = 3
    }
    elseif ($detectedName -eq 'UTF16LE' -and $hasUtf16LeBom) {
        $preambleLength = 2
    }
    elseif ($detectedName -eq 'UTF16BE' -and $hasUtf16BeBom) {
        $preambleLength = 2
    }

    switch ($detectedName) {
        'UTF8' {
            $encoding = New-Object System.Text.UTF8Encoding($false, $false)
            $newline = [byte[]](0x0A)
            $carriageReturn = [byte[]](0x0D)
            $unitSize = 1
        }
        'UTF16LE' {
            $encoding = New-Object System.Text.UnicodeEncoding($false, $false, $false)
            $newline = [byte[]](0x0A, 0x00)
            $carriageReturn = [byte[]](0x0D, 0x00)
            $unitSize = 2
        }
        'UTF16BE' {
            $encoding = New-Object System.Text.UnicodeEncoding($true, $false, $false)
            $newline = [byte[]](0x00, 0x0A)
            $carriageReturn = [byte[]](0x00, 0x0D)
            $unitSize = 2
        }
        'ASCII' {
            $encoding = [System.Text.Encoding]::ASCII
            $newline = [byte[]](0x0A)
            $carriageReturn = [byte[]](0x0D)
            $unitSize = 1
        }
        default {
            $encoding = [System.Text.Encoding]::Default
            $newline = [byte[]](0x0A)
            $carriageReturn = [byte[]](0x0D)
            $unitSize = 1
            $detectedName = 'Default'
        }
    }

    return [pscustomobject]@{
        RequestedName  = $Name
        DetectedName   = $detectedName
        Encoding       = $encoding
        NewlineBytes   = $newline
        CarriageReturn = $carriageReturn
        UnitSize       = $unitSize
        PreambleLength = $preambleLength
    }
}

function Open-OIFileContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$EncodingName
    )

    $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
    $item = Get-Item -LiteralPath $resolved -ErrorAction Stop

    if ($item.PSIsContainer) {
        throw "Path is a directory, not a file: $resolved"
    }

    $stream = $null
    try {
        $stream = [System.IO.File]::Open(
            $resolved,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read
        )
        $encodingInfo = Resolve-OIEncoding -Stream $stream -Name $EncodingName

        return [pscustomobject]@{
            Path         = $resolved
            Length       = [int64]$stream.Length
            Stream       = $stream
            EncodingInfo = $encodingInfo
        }
    }
    catch {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
        throw
    }
}

function Close-OIFileContext {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [AllowNull()]
        [object]$Context
    )

    process {
        if ($null -ne $Context -and $null -ne $Context.Stream) {
            $Context.Stream.Dispose()
        }
    }
}

function Read-OIFileRange {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.FileStream]$Stream,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ $_ -ge 0 })]
        [int64]$Start,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ $_ -ge 0 })]
        [int]$Length
    )

    if ($Length -eq 0) {
        return ,([byte[]]@())
    }

    if ($Start -ge $Stream.Length) {
        return ,([byte[]]@())
    }

    $available = [int64]$Stream.Length - $Start
    $effectiveLength = [int][Math]::Min([int64]$Length, $available)
    $buffer = New-Object byte[] $effectiveLength

    $null = $Stream.Seek($Start, [System.IO.SeekOrigin]::Begin)
    $total = 0

    while ($total -lt $effectiveLength) {
        $read = $Stream.Read($buffer, $total, $effectiveLength - $total)
        if ($read -le 0) { break }
        $total += $read
    }

    if ($total -eq $effectiveLength) {
        return ,$buffer
    }

    $trimmed = New-Object byte[] $total
    if ($total -gt 0) {
        [System.Buffer]::BlockCopy($buffer, 0, $trimmed, 0, $total)
    }
    return ,$trimmed
}

function Get-OIStreamSha256 {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.Stream]$Stream
    )

    if (-not $Stream.CanSeek -or -not $Stream.CanRead) {
        throw 'SHA-256 calculation requires a readable and seekable stream.'
    }

    $originalPosition = $Stream.Position
    $sha256 = $null
    try {
        $null = $Stream.Seek(0, [System.IO.SeekOrigin]::Begin)
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($Stream)
        return (($hashBytes | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally {
        if ($null -ne $sha256) { $sha256.Dispose() }
        $null = $Stream.Seek($originalPosition, [System.IO.SeekOrigin]::Begin)
    }
}

function Copy-OIStreamPrefix {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.Stream]$SourceStream,

        [Parameter(Mandatory = $true)]
        [string]$DestinationPath,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ $_ -ge 0 })]
        [int64]$Length,

        [ValidateNotNull()]
        [byte[]]$Buffer
    )

    if (-not $SourceStream.CanSeek -or -not $SourceStream.CanRead) {
        throw 'The source stream must be readable and seekable.'
    }

    if ($Length -gt $SourceStream.Length) {
        throw "Requested prefix length $Length exceeds source length $($SourceStream.Length)."
    }

    $destination = $null
    $originalPosition = $SourceStream.Position
    try {
        $destination = [System.IO.File]::Open(
            $DestinationPath,
            [System.IO.FileMode]::Create,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None
        )

        $null = $SourceStream.Seek(0, [System.IO.SeekOrigin]::Begin)
        $remaining = $Length
        if ($null -eq $Buffer -or $Buffer.Length -eq 0) {
            $Buffer = New-Object byte[] (1024 * 1024)
        }

        while ($remaining -gt 0) {
            $toRead = [int][Math]::Min([int64]$Buffer.Length, $remaining)
            $read = $SourceStream.Read($Buffer, 0, $toRead)
            if ($read -le 0) { break }
            $destination.Write($Buffer, 0, $read)
            $remaining -= $read
        }

        if ($remaining -ne 0) {
            throw "The source stream ended before the requested $Length-byte prefix was copied."
        }
    }
    finally {
        if ($null -ne $destination) { $destination.Dispose() }
        $null = $SourceStream.Seek($originalPosition, [System.IO.SeekOrigin]::Begin)
    }
}
