param(
    [Parameter(Mandatory=$true)]
    [string[]]$FilePaths,

    [Parameter(Mandatory=$true)]
    [string[]]$OffsetInputs,

    [int]$ByteWindow = 32,
    [int]$ContextLines = 3
)

# ===============================================================
# Banner
# ===============================================================
Write-Host "/******************************************************************" -ForegroundColor DarkCyan
Write-Host " *                           OffsetInspect                          *" -ForegroundColor DarkCyan
Write-Host " *                  PE Offset & Hex Context Inspector                *" -ForegroundColor DarkCyan
Write-Host " *                       DreadHost Research Tool                     *" -ForegroundColor DarkCyan
Write-Host " ******************************************************************/" -ForegroundColor DarkCyan
Write-Host ""
Write-Host "    Version:          1.0.1" -ForegroundColor Cyan
Write-Host "    Authors:           Jared Perry (Velkris), secretlay3r" -ForegroundColor Cyan
Write-Host "    GitHub:           https://github.com/warpedatom" -ForegroundColor Cyan
Write-Host "    Date:             2025-12-28" -ForegroundColor Cyan
Write-Host ""

# Track whether any file/offset handling failed so the script can return a non-zero exit code
$script:hadError = $false

# ===============================================================
# Helper: parse a string offset into an Int64 with validation
# ===============================================================
function Parse-Offset {
    param(
        [Parameter(Mandatory = $true)]
        [string]$OffsetInput,

        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    # Hex with 0x prefix (e.g. 0x3C)
    if ($OffsetInput -match '^0x[0-9A-Fa-f]+$') {
        return [Convert]::ToInt64($OffsetInput, 16)
    }
    # Plain hex (e.g. 3C or 1A2B)
    elseif ($OffsetInput -match '^[0-9A-Fa-f]+$') {
        if ($OffsetInput -match '[A-Fa-f]') {
            return [Convert]::ToInt64($OffsetInput, 16)
        }
        else {
            return [int64]$OffsetInput
        }
    }
    # Decimal (e.g. 60)
    elseif ($OffsetInput -match '^\d+$') {
        return [int64]$OffsetInput
    }

    Write-Error "Invalid offset format for file '$FilePath': '$OffsetInput'. Use hex (e.g. 0x3C), plain hex, or decimal."
    $script:hadError = $true
    return $null
}

# ===============================================================
# Validate multi-file mapping between FilePaths and OffsetInputs
# ===============================================================
if ($FilePaths.Length -eq 0) {
    Write-Error "At least one FilePath must be provided."
    exit 1
}

if ($OffsetInputs.Count -eq 0) {
    Write-Error "At least one OffsetInput must be provided."
    exit 1
}

$reuseSingleOffset = $false

if ($OffsetInputs.Count -eq 1) {
    $reuseSingleOffset = $true
    if ($FilePaths.Length -gt 1) {
        Write-Host "Note: Single offset '$($OffsetInputs[0])' provided; reusing it for all $($FilePaths.Length) files." -ForegroundColor Yellow
    }
}
elseif ($OffsetInputs.Count -eq $FilePaths.Length) {
    $reuseSingleOffset = $false
}
else {
    throw "The number of offsets provided ($($OffsetInputs.Count)) must be 1 or match the number of file paths ($($FilePaths.Length))."
}

# ===============================================================
# Hex Dump Formatter
# ===============================================================
function Format-HexDump {
    param(
        [byte[]]$Data,
        [int]$StartOffset,
        [int]$HighlightOffset
    )

    $rows = @()

    for ($i = 0; $i -lt $Data.Length; $i += 16) {
        $chunk = $Data[$i..([Math]::Min($i+15, $Data.Length-1))]
        $hexParts = @()
        $asciiParts = @()

        for ($b = 0; $b -lt $chunk.Length; $b++) {
            $byteOffset = $StartOffset + $i + $b
            $hexVal = $chunk[$b].ToString("X2")

            if ($byteOffset -eq $HighlightOffset) {
                $hexParts += @{ Text = $hexVal; Color = "Yellow" }
            }
            else {
                $hexParts += @{ Text = $hexVal; Color = "Green" }
            }

            if ($chunk[$b] -ge 32 -and $chunk[$b] -le 126) {
                $asciiParts += [char]$chunk[$b]
            }
            else {
                $asciiParts += "."
            }
        }

        $offsetLabel = "{0:X8}" -f ($StartOffset + $i)

        $rows += @{
            Offset   = $offsetLabel
            HexParts = $hexParts
            Ascii    = (-join $asciiParts)
        }
    }

    return $rows
}

# ===============================================================
# Process Each File
# ===============================================================
for ($fileIndex = 0; $fileIndex -lt $FilePaths.Length; $fileIndex++) {
    $FilePath    = $FilePaths[$fileIndex]
    $OffsetInput = if ($reuseSingleOffset) { $OffsetInputs[0] } else { $OffsetInputs[$fileIndex] }

    # ===============================================================
    # Validate File
    # ===============================================================
    if (-not (Test-Path $FilePath)) {
        Write-Error "File not found: $FilePath"
        $script:hadError = $true
        continue
    }

    # ===============================================================
    # Parse Offset
    # ===============================================================
    $Offset = Parse-Offset -OffsetInput $OffsetInput -FilePath $FilePath
    if ($null -eq $Offset) {
        # Parse-Offset already logged error and set $script:hadError
        continue
    }

    $bytes = [System.IO.File]::ReadAllBytes($FilePath)
    $FileSize = $bytes.Length

    if ($Offset -ge $FileSize) {
        Write-Error "Offset $Offset exceeds file size ($FileSize bytes) for '$FilePath'."
        $script:hadError = $true
        continue
    }

    $lineNumber = 1
    for ($i = 0; $i -lt $Offset; $i++) {
        if ($bytes[$i] -eq 0x0A) { $lineNumber++ }
    }

    $lines = Get-Content -Path $FilePath

    $startByte = [Math]::Max(0, $Offset - $ByteWindow)
    $endByte   = [Math]::Min($FileSize - 1, $Offset + $ByteWindow)
    $window    = $bytes[$startByte..$endByte]

    $HexDump = Format-HexDump -Data $window -StartOffset $startByte -HighlightOffset $Offset

    Write-Host "`n====================================================================================================" -ForegroundColor DarkYellow
    Write-Host "File ($($fileIndex+1)/$($FilePaths.Length)): $FilePath" -ForegroundColor Green
    Write-Host "Offset (input):    $OffsetInput" -ForegroundColor Green
    Write-Host "Offset (decimal):  $Offset" -ForegroundColor Green
    Write-Host "File Size:         $FileSize bytes" -ForegroundColor Green
    Write-Host "Line Number:       ${lineNumber}" -ForegroundColor Green
    Write-Host ""

    if ($lineNumber -le $lines.Length) {
        Write-Host "---------------------------------------- Line Content ----------------------------------------------" -ForegroundColor DarkYellow
        Write-Host "Line ${lineNumber}: $($lines[$lineNumber - 1])" -ForegroundColor Green

        $charPos = 0
        for ($i = $Offset - 1; $i -ge 0; $i--) {
            if ($bytes[$i] -eq 0x0A) { break }
            $charPos++
        }

        Write-Host (" " * 12) + (" " * $charPos) + "↑" -ForegroundColor Yellow
    }

    Write-Host "`n------------------------------------------ Hex Dump ------------------------------------------------" -ForegroundColor DarkYellow

    foreach ($row in $HexDump) {
        Write-Host -NoNewline "$($row.Offset)  " -ForegroundColor Green

        foreach ($hx in $row.HexParts) {
            Write-Host -NoNewline "$($hx.Text) " -ForegroundColor $hx.Color
        }

        Write-Host "  $($row.Ascii)" -ForegroundColor Green
    }

    Write-Host "`n====================================================================================================" -ForegroundColor DarkCyan
}

# ===============================================================
# Exit code signalling for automation
# ===============================================================
if ($script:hadError) {
    exit 1
}