function Write-OIBanner {
    [CmdletBinding()]
    param()

    Write-Host '/******************************************************************' -ForegroundColor DarkCyan
    Write-Host ' *                           OffsetInspect                        *' -ForegroundColor DarkCyan
    Write-Host ' *          Offset, Context, Diff & Threat Boundary Inspector    *' -ForegroundColor DarkCyan
    Write-Host ' *                       DreadHost Research                      *' -ForegroundColor DarkCyan
    Write-Host ' ******************************************************************/' -ForegroundColor DarkCyan
    Write-Host ''
    Write-Host '    Version:          2.0.0' -ForegroundColor Cyan
    Write-Host '    Author:           Jared Perry (Velkris)' -ForegroundColor Cyan
    Write-Host '    GitHub:           https://github.com/warpedatom/OffsetInspect' -ForegroundColor Cyan
    Write-Host ''
}

function ConvertTo-OIFlatInspectionResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [object]$Result
    )

    process {
        [pscustomobject]@{
            Success                  = $Result.Success
            File                     = $Result.File
            OffsetInput              = $Result.OffsetInput
            OffsetDecimal            = $Result.OffsetDecimal
            OffsetHex                = $Result.OffsetHex
            FileSize                 = $Result.FileSize
            EncodingRequested        = $Result.EncodingRequested
            EncodingDetected         = $Result.EncodingDetected
            LineNumber               = $Result.LineNumber
            CharacterPosition        = $Result.CharacterPosition
            PreviewCharacterPosition = $Result.PreviewCharacterPosition
            BytePositionInLine       = $Result.BytePositionInLine
            TargetByteHex            = $Result.TargetByteHex
            TargetByteDecimal        = $Result.TargetByteDecimal
            CompareFile              = $Result.CompareFile
            CompareByteHex           = $Result.CompareByteHex
            CompareByteDecimal       = $Result.CompareByteDecimal
            BytesDiffer              = $Result.BytesDiffer
            WindowStartOffset        = $Result.WindowStartOffset
            WindowEndOffset          = $Result.WindowEndOffset
            LineText                 = $Result.LineText
            LineTextTruncated        = $Result.LineTextTruncated
            DurationMs               = $Result.DurationMs
            Warnings                 = @($Result.Warnings) -join '; '
            Error                    = $Result.Error
        }
    }
}

function Write-OIHumanInspectionResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Result,

        [Parameter(Mandatory = $true)]
        [int]$Index,

        [Parameter(Mandatory = $true)]
        [int]$Total
    )

    Write-Host ''
    Write-Host ('=' * 100) -ForegroundColor DarkYellow
    Write-Host "Result ($Index/$Total): $($Result.File)" -ForegroundColor Green
    Write-Host "Offset input:      $($Result.OffsetInput)" -ForegroundColor Green
    Write-Host "Offset decimal:    $($Result.OffsetDecimal)" -ForegroundColor Green
    Write-Host "Offset hex:        $($Result.OffsetHex)" -ForegroundColor Green
    Write-Host "File size:         $($Result.FileSize) bytes" -ForegroundColor Green
    Write-Host "Encoding:          $($Result.EncodingDetected) (requested: $($Result.EncodingRequested))" -ForegroundColor Green

    if (-not $Result.Success) {
        Write-Host "Error:             $($Result.Error)" -ForegroundColor Red
        Write-Host ('=' * 100) -ForegroundColor DarkCyan
        return
    }

    Write-Host "Line number:       $($Result.LineNumber)" -ForegroundColor Green
    Write-Host "Byte in line:      $($Result.BytePositionInLine)" -ForegroundColor Green
    if ($null -ne $Result.CharacterPosition) {
        Write-Host "Character index:   $($Result.CharacterPosition)" -ForegroundColor Green
    }
    Write-Host "Target byte:       $($Result.TargetByteHex) ($($Result.TargetByteDecimal))" -ForegroundColor Green

    if ($Result.CompareFile) {
        Write-Host "Compare file:      $($Result.CompareFile)" -ForegroundColor Cyan
        Write-Host "Compare byte:      $($Result.CompareByteHex) ($($Result.CompareByteDecimal))" -ForegroundColor Cyan
        Write-Host "Bytes differ:      $($Result.BytesDiffer)" -ForegroundColor Cyan
    }

    if (@($Result.ContextLines).Count -gt 0) {
        Write-Host ''
        Write-Host ('-' * 40 + ' Source Context ' + '-' * 44) -ForegroundColor DarkYellow
        foreach ($line in $Result.ContextLines) {
            $prefix = ('{0,8} | ' -f $line.LineNumber)
            if ($line.IsTarget) {
                Write-Host -NoNewline $prefix -ForegroundColor Yellow
                Write-Host $line.Text -ForegroundColor Green

                if ($null -ne $Result.PreviewCharacterPosition) {
                    $caretPadding = $prefix.Length + [int]$Result.PreviewCharacterPosition
                    Write-Host ((' ' * $caretPadding) + '^') -ForegroundColor Yellow
                }
            }
            else {
                Write-Host -NoNewline $prefix -ForegroundColor DarkGray
                Write-Host $line.Text -ForegroundColor Gray
            }
        }
    }

    Write-Host ''
    Write-Host ('-' * 43 + ' Hex Dump ' + '-' * 47) -ForegroundColor DarkYellow
    foreach ($row in $Result.HexDump) {
        Write-Host -NoNewline "$($row.Offset)  " -ForegroundColor Green
        foreach ($part in $row.HexParts) {
            if ($part.IsHighlight) {
                Write-Host -NoNewline "$($part.Text) " -ForegroundColor Yellow
            }
            else {
                Write-Host -NoNewline "$($part.Text) " -ForegroundColor Green
            }
        }

        $padding = 3 * (16 - @($row.HexParts).Count)
        if ($padding -gt 0) { Write-Host -NoNewline (' ' * $padding) }
        Write-Host " $($row.Ascii)" -ForegroundColor Green
    }

    foreach ($warning in @($Result.Warnings)) {
        Write-Host "Warning: $warning" -ForegroundColor Yellow
    }

    Write-Host ('=' * 100) -ForegroundColor DarkCyan
}

function Write-OIInspectionOutput {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Results,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Human', 'Object', 'Json', 'Csv', 'CsvFile')]
        [string]$Mode,

        [AllowNull()]
        [string]$CsvPath
    )

    switch ($Mode) {
        'Object' {
            return $Results
        }
        'Json' {
            return (ConvertTo-Json -InputObject @($Results) -Depth 12)
        }
        'Csv' {
            return @($Results | ConvertTo-OIFlatInspectionResult | ConvertTo-Csv -NoTypeInformation)
        }
        'CsvFile' {
            $parent = Split-Path -Parent $CsvPath
            if ($parent -and -not (Test-Path -LiteralPath $parent)) {
                $null = New-Item -ItemType Directory -Path $parent -Force
            }
            $Results | ConvertTo-OIFlatInspectionResult | Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8
            return (Get-Item -LiteralPath $CsvPath)
        }
        default {
            Write-OIBanner
            for ($index = 0; $index -lt $Results.Count; $index++) {
                Write-OIHumanInspectionResult -Result $Results[$index] -Index ($index + 1) -Total $Results.Count
            }
        }
    }
}
