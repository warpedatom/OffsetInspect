function ConvertTo-OIOffset {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$InputValue
    )

    $value = $InputValue.Trim()
    $parsed = $null

    try {
        if ($value -match '(?i)^0x[0-9a-f]+$') {
            $parsed = [Convert]::ToInt64($value.Substring(2), 16)
        }
        elseif ($value -match '(?i)^[0-9a-f]+h$') {
            $parsed = [Convert]::ToInt64($value.Substring(0, $value.Length - 1), 16)
        }
        elseif ($value -match '^[0-9]+$') {
            $parsed = [Convert]::ToInt64($value, 10)
        }
        elseif ($value -match '(?i)^[0-9a-f]+$' -and $value -match '(?i)[a-f]') {
            $parsed = [Convert]::ToInt64($value, 16)
        }
    }
    catch {
        throw "Offset '$InputValue' exceeds the signed 64-bit range."
    }

    if ($null -eq $parsed) {
        throw "Invalid offset '$InputValue'. Use decimal, 0x-prefixed hexadecimal, hexadecimal ending in h, or unprefixed hexadecimal containing A-F."
    }

    if ([int64]$parsed -lt 0) {
        throw "Offset '$InputValue' exceeds the signed 64-bit range."
    }

    return [int64]$parsed
}

function New-OIInspectionPlan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Files,

        [Parameter(Mandatory = $true)]
        [string[]]$Offsets
    )

    $plan = New-Object 'System.Collections.Generic.List[object]'
    $planIndex = 0

    if ($Files.Count -eq 1) {
        foreach ($offset in $Offsets) {
            $plan.Add([pscustomobject]@{ Index = $planIndex; FilePath = $Files[0]; OffsetInput = $offset })
            $planIndex++
        }
        return $plan.ToArray()
    }

    if ($Offsets.Count -eq 1) {
        foreach ($file in $Files) {
            $plan.Add([pscustomobject]@{ Index = $planIndex; FilePath = $file; OffsetInput = $Offsets[0] })
            $planIndex++
        }
        return $plan.ToArray()
    }

    if ($Offsets.Count -eq $Files.Count) {
        for ($index = 0; $index -lt $Files.Count; $index++) {
            $plan.Add([pscustomobject]@{ Index = $index; FilePath = $Files[$index]; OffsetInput = $Offsets[$index] })
        }
        return $plan.ToArray()
    }

    throw "Offset count ($($Offsets.Count)) must be one, equal the file count ($($Files.Count)), or contain multiple offsets for a single file."
}

function Format-OIOffsetHex {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) { return $null }
    return ('0x{0:X}' -f ([int64]$Value))
}

function Format-OIHexDump {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Data,

        [Parameter(Mandatory = $true)]
        [int64]$StartOffset,

        [Parameter(Mandatory = $true)]
        [int64]$HighlightOffset,

        [Parameter(Mandatory = $true)]
        [int64]$FileSize
    )

    $rows = New-Object 'System.Collections.Generic.List[object]'
    $offsetWidth = if ($FileSize -gt [uint32]::MaxValue) { 16 } else { 8 }

    for ($index = 0; $index -lt $Data.Length; $index += 16) {
        $count = [Math]::Min(16, $Data.Length - $index)
        $hexParts = New-Object 'System.Collections.Generic.List[object]'
        $ascii = New-Object System.Text.StringBuilder

        for ($byteIndex = 0; $byteIndex -lt $count; $byteIndex++) {
            $value = $Data[$index + $byteIndex]
            $absoluteOffset = $StartOffset + $index + $byteIndex
            $hexParts.Add([pscustomobject]@{
                Text        = $value.ToString('X2')
                IsHighlight = ($absoluteOffset -eq $HighlightOffset)
            })

            if ($value -ge 32 -and $value -le 126) {
                $null = $ascii.Append([char]$value)
            }
            else {
                $null = $ascii.Append('.')
            }
        }

        $offsetFormat = '{0:X' + $offsetWidth + '}'
        $rows.Add([pscustomobject]@{
            OffsetDecimal = $StartOffset + $index
            Offset        = ($offsetFormat -f ($StartOffset + $index))
            HexParts      = $hexParts.ToArray()
            Hex           = (($hexParts.ToArray() | ForEach-Object { $_.Text }) -join ' ')
            Ascii         = $ascii.ToString()
        })
    }

    return $rows.ToArray()
}

function New-OILineDescriptor {
    [CmdletBinding()]
    param(
        [int64]$Number,
        [int64]$Start,
        [int64]$EndExclusive
    )

    return [pscustomobject]@{
        Number       = $Number
        Start        = $Start
        EndExclusive = $EndExclusive
    }
}

function Complete-OILine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Descriptor,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$CurrentLineRecords,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$PendingNextRecords,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.Queue[object]]$PreviousLines,

        [Parameter(Mandatory = $true)]
        [int]$ContextLines
    )

    if ($PendingNextRecords.Count -gt 0) {
        $stillPending = New-Object 'System.Collections.Generic.List[object]'
        foreach ($record in $PendingNextRecords) {
            $record.NextLines.Add($Descriptor)
            if ($record.NextLines.Count -lt $ContextLines) {
                $stillPending.Add($record)
            }
        }

        $PendingNextRecords.Clear()
        foreach ($record in $stillPending) {
            $PendingNextRecords.Add($record)
        }
    }

    foreach ($record in $CurrentLineRecords) {
        $record.TargetLine = $Descriptor
        if ($ContextLines -gt 0) {
            $PendingNextRecords.Add($record)
        }
    }
    $CurrentLineRecords.Clear()

    if ($ContextLines -gt 0) {
        $PreviousLines.Enqueue($Descriptor)
        while ($PreviousLines.Count -gt $ContextLines) {
            $null = $PreviousLines.Dequeue()
        }
    }
}

function Get-OILineRecords {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Context,

        [Parameter(Mandatory = $true)]
        [int64[]]$Offsets,

        [Parameter(Mandatory = $true)]
        [ValidateRange(0, 100)]
        [int]$ContextLines
    )

    $result = @{}
    if ($Offsets.Count -eq 0 -or $Context.Length -eq 0) { return $result }

    $targets = @($Offsets | Sort-Object -Unique)
    $previousLines = New-Object 'System.Collections.Generic.Queue[object]'
    $currentLineRecords = New-Object 'System.Collections.Generic.List[object]'
    $pendingNextRecords = New-Object 'System.Collections.Generic.List[object]'
    $pattern = $Context.EncodingInfo.NewlineBytes
    $unitSize = [int]$Context.EncodingInfo.UnitSize
    $preambleLength = [int]$Context.EncodingInfo.PreambleLength
    $targetIndex = 0
    $lineNumber = [int64]1
    $lineStart = [int64]0
    $matchIndex = 0
    $absolutePosition = [int64]0
    $buffer = New-Object byte[] (1024 * 1024)
    $stop = $false

    $null = $Context.Stream.Seek(0, [System.IO.SeekOrigin]::Begin)

    while (-not $stop) {
        $read = $Context.Stream.Read($buffer, 0, $buffer.Length)
        if ($read -le 0) { break }

        for ($bufferIndex = 0; $bufferIndex -lt $read; $bufferIndex++) {
            $currentByte = $buffer[$bufferIndex]

            while ($targetIndex -lt $targets.Count -and $targets[$targetIndex] -eq $absolutePosition) {
                $record = [pscustomobject]@{
                    Offset        = [int64]$targets[$targetIndex]
                    LineNumber    = $lineNumber
                    LineStart     = $lineStart
                    PreviousLines = @($previousLines.ToArray())
                    TargetLine    = $null
                    NextLines     = New-Object 'System.Collections.Generic.List[object]'
                }
                $currentLineRecords.Add($record)
                $result[[string]$record.Offset] = $record
                $targetIndex++
            }

            if ($currentByte -eq $pattern[$matchIndex]) {
                $matchIndex++
            }
            elseif ($currentByte -eq $pattern[0]) {
                $matchIndex = 1
            }
            else {
                $matchIndex = 0
            }

            if ($matchIndex -eq $pattern.Length) {
                $sequenceStart = $absolutePosition - $pattern.Length + 1
                $aligned = ($unitSize -eq 1) -or ((($sequenceStart - $preambleLength) % $unitSize) -eq 0)

                if ($aligned) {
                    $descriptor = New-OILineDescriptor -Number $lineNumber -Start $lineStart -EndExclusive $sequenceStart
                    Complete-OILine `
                        -Descriptor $descriptor `
                        -CurrentLineRecords $currentLineRecords `
                        -PendingNextRecords $pendingNextRecords `
                        -PreviousLines $previousLines `
                        -ContextLines $ContextLines
                    $lineNumber++
                    $lineStart = $absolutePosition + 1

                    if ($targetIndex -ge $targets.Count -and $pendingNextRecords.Count -eq 0) {
                        $stop = $true
                    }
                }

                $matchIndex = 0
            }

            $absolutePosition++

            if ($stop) { break }
        }
    }

    if (-not $stop) {
        $finalDescriptor = New-OILineDescriptor -Number $lineNumber -Start $lineStart -EndExclusive $Context.Length
        Complete-OILine `
            -Descriptor $finalDescriptor `
            -CurrentLineRecords $currentLineRecords `
            -PendingNextRecords $pendingNextRecords `
            -PreviousLines $previousLines `
            -ContextLines $ContextLines
    }

    return $result
}

function ConvertFrom-OIByteSequence {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Text.Encoding]$Encoding,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes
    )

    if ($Bytes.Length -eq 0) { return [string]::Empty }

    $decoder = $Encoding.GetDecoder()
    $characters = New-Object char[] ($Encoding.GetMaxCharCount($Bytes.Length))
    $bytesUsed = 0
    $charactersUsed = 0
    $completed = $false
    $decoder.Convert(
        $Bytes,
        0,
        $Bytes.Length,
        $characters,
        0,
        $characters.Length,
        $false,
        [ref]$bytesUsed,
        [ref]$charactersUsed,
        [ref]$completed
    )

    $builder = New-Object System.Text.StringBuilder($charactersUsed)
    $null = $builder.Append($characters, 0, $charactersUsed)
    return $builder.ToString()
}

function Get-OICharacterCount {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Text.Encoding]$Encoding,

        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes,

        [switch]$RemoveLeadingBom
    )

    if ($Bytes.Length -eq 0) { return 0 }

    $decoder = $Encoding.GetDecoder()
    $count = $decoder.GetCharCount($Bytes, 0, $Bytes.Length, $false)

    if ($RemoveLeadingBom -and $count -gt 0) {
        $decoded = ConvertFrom-OIByteSequence -Encoding $Encoding -Bytes $Bytes
        if ($decoded.Length -gt 0 -and $decoded[0] -eq [char]0xFEFF) {
            $count--
        }
    }

    return [Math]::Max(0, $count)
}

function Get-OIAlignedUtf8PreviewStart {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Context,

        [Parameter(Mandatory = $true)]
        [int64]$LineStart,

        [Parameter(Mandatory = $true)]
        [int64]$ProposedStart
    )

    if ($Context.EncodingInfo.DetectedName -ne 'UTF8' -or $ProposedStart -le $LineStart) {
        return $ProposedStart
    }

    $candidate = $ProposedStart
    for ($step = 0; $step -lt 3 -and $candidate -gt $LineStart; $step++) {
        $current = Read-OIFileRange -Stream $Context.Stream -Start $candidate -Length 1
        if ($current.Length -eq 0 -or ($current[0] -band 0xC0) -ne 0x80) {
            break
        }
        $candidate--
    }

    return $candidate
}

function Get-OIDecodedLine {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Context,

        [Parameter(Mandatory = $true)]
        [object]$Descriptor,

        [AllowNull()]
        [object]$TargetOffset,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1024, 16777216)]
        [int]$MaxLineBytes
    )

    $lineLength = [Math]::Max([int64]0, $Descriptor.EndExclusive - $Descriptor.Start)
    $previewStart = [int64]$Descriptor.Start
    $previewLength = [int][Math]::Min([int64]$MaxLineBytes, $lineLength)
    $truncatedBefore = $false
    $truncatedAfter = ($lineLength -gt $MaxLineBytes)

    if ($null -ne $TargetOffset -and $lineLength -gt $MaxLineBytes) {
        $target = [int64]$TargetOffset
        $half = [int64][Math]::Floor($MaxLineBytes / 2)
        $previewStart = [Math]::Max([int64]$Descriptor.Start, $target - $half)
        $maximumStart = [Math]::Max([int64]$Descriptor.Start, $Descriptor.EndExclusive - $MaxLineBytes)
        $previewStart = [Math]::Min($previewStart, $maximumStart)

        $unitSize = [int]$Context.EncodingInfo.UnitSize
        if ($unitSize -gt 1) {
            $relative = $previewStart - $Descriptor.Start
            $previewStart -= ($relative % $unitSize)
        }
        else {
            $previewStart = Get-OIAlignedUtf8PreviewStart -Context $Context -LineStart $Descriptor.Start -ProposedStart $previewStart
        }

        $previewLength = [int][Math]::Min([int64]$MaxLineBytes, $Descriptor.EndExclusive - $previewStart)
        $truncatedBefore = ($previewStart -gt $Descriptor.Start)
        $truncatedAfter = (($previewStart + $previewLength) -lt $Descriptor.EndExclusive)
    }

    $bytes = Read-OIFileRange -Stream $Context.Stream -Start $previewStart -Length $previewLength
    $text = ConvertFrom-OIByteSequence -Encoding $Context.EncodingInfo.Encoding -Bytes $bytes
    $text = $text.TrimEnd([char[]]"`r`n")

    if ($Descriptor.Number -eq 1 -and $text.Length -gt 0 -and $text[0] -eq [char]0xFEFF) {
        $text = $text.Substring(1)
    }

    if ($truncatedBefore) { $text = [string][char]0x2026 + $text }
    if ($truncatedAfter) { $text = $text + [char]0x2026 }

    $characterPosition = $null
    $previewCharacterPosition = $null

    if ($null -ne $TargetOffset) {
        $target = [int64]$TargetOffset
        $bytePosition = [Math]::Max([int64]0, $target - $Descriptor.Start)
        $previewBytePosition = [Math]::Max([int64]0, $target - $previewStart)

        if ($bytePosition -le $MaxLineBytes) {
            $prefixLength = [int][Math]::Min($bytePosition, [int64][int]::MaxValue)
            $prefixBytes = Read-OIFileRange -Stream $Context.Stream -Start $Descriptor.Start -Length $prefixLength
            $characterPosition = Get-OICharacterCount `
                -Encoding $Context.EncodingInfo.Encoding `
                -Bytes $prefixBytes `
                -RemoveLeadingBom:($Descriptor.Number -eq 1)
        }

        if ($previewBytePosition -le $previewLength) {
            $previewPrefixBytes = Read-OIFileRange -Stream $Context.Stream -Start $previewStart -Length ([int]$previewBytePosition)
            $previewCharacterPosition = (Get-OICharacterCount `
                -Encoding $Context.EncodingInfo.Encoding `
                -Bytes $previewPrefixBytes `
                -RemoveLeadingBom:($Descriptor.Number -eq 1 -and $previewStart -eq $Descriptor.Start)) + `
                $(if ($truncatedBefore) { 1 } else { 0 })
        }
    }

    return [pscustomobject]@{
        Text                     = $text
        IsTruncated              = ($truncatedBefore -or $truncatedAfter)
        TruncatedBefore          = $truncatedBefore
        TruncatedAfter           = $truncatedAfter
        PreviewStartByte         = $previewStart
        CharacterPosition        = $characterPosition
        PreviewCharacterPosition = $previewCharacterPosition
    }
}

function Get-OISingleInspectionFromContext {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Context,

        [Parameter(Mandatory = $true)]
        [ValidateScript({ $_ -ge 0 })]
        [int64]$Offset,

        [ValidateRange(0, 4096)]
        [int]$ByteWindow = 32,

        [ValidateRange(0, 100)]
        [int]$ContextLines = 3,

        [ValidateRange(1024, 16777216)]
        [int]$MaxLineBytes = 1048576
    )

    if ($Context.Length -eq 0) {
        throw "File is empty: $($Context.Path)"
    }
    if ($Offset -ge $Context.Length) {
        throw "Offset $Offset is outside the valid range 0-$($Context.Length - 1)."
    }

    $lineRecords = Get-OILineRecords -Context $Context -Offsets @($Offset) -ContextLines $ContextLines
    $lineRecord = $lineRecords[[string]$Offset]
    if ($null -eq $lineRecord -or $null -eq $lineRecord.TargetLine) {
        throw 'Unable to map the offset to a source line.'
    }

    $result = Get-OIInspectionResult `
        -Context $Context `
        -OffsetInput ([string]$Offset) `
        -Offset $Offset `
        -LineRecord $lineRecord `
        -ByteWindow $ByteWindow `
        -CompareContext $null `
        -CompareError $null `
        -CompareRequestedPath $null `
        -MaxLineBytes $MaxLineBytes

    return $result
}

function New-OIErrorResult {
    [CmdletBinding()]
    param(
        [string]$File,
        [string]$OffsetInput,
        [AllowNull()][object]$Offset,
        [AllowNull()][object]$FileSize,
        [string]$EncodingRequested,
        [string]$CompareFile,
        [string]$Message
    )

    $result = [pscustomobject]@{
        Success                 = $false
        File                    = $File
        OffsetInput             = $OffsetInput
        OffsetDecimal           = if ($null -ne $Offset) { [int64]$Offset } else { $null }
        OffsetHex               = Format-OIOffsetHex -Value $Offset
        FileSize                = if ($null -ne $FileSize) { [int64]$FileSize } else { $null }
        EncodingRequested       = $EncodingRequested
        EncodingDetected        = $null
        LineNumber              = $null
        LineText                = $null
        LineTextTruncated       = $false
        CharacterPosition       = $null
        PreviewCharacterPosition = $null
        BytePositionInLine      = $null
        ContextLines            = @()
        TargetByteHex           = $null
        TargetByteDecimal       = $null
        CompareFile             = $CompareFile
        CompareByteHex          = $null
        CompareByteDecimal      = $null
        BytesDiffer             = $null
        WindowStartOffset       = $null
        WindowEndOffset         = $null
        HexDump                 = @()
        DurationMs              = 0
        Warnings                = @()
        Error                   = $Message
    }
    $result.PSObject.TypeNames.Insert(0, 'OffsetInspect.Result')
    return $result
}

function Get-OIInspectionResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Context,

        [Parameter(Mandatory = $true)]
        [string]$OffsetInput,

        [Parameter(Mandatory = $true)]
        [int64]$Offset,

        [Parameter(Mandatory = $true)]
        [object]$LineRecord,

        [Parameter(Mandatory = $true)]
        [int]$ByteWindow,

        [AllowNull()]
        [object]$CompareContext,

        [AllowNull()]
        [string]$CompareError,

        [AllowNull()]
        [string]$CompareRequestedPath,

        [Parameter(Mandatory = $true)]
        [int]$MaxLineBytes
    )

    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $warnings = New-Object 'System.Collections.Generic.List[string]'

    $targetBytes = Read-OIFileRange -Stream $Context.Stream -Start $Offset -Length 1
    $targetByte = $targetBytes[0]
    $start = [Math]::Max([int64]0, $Offset - $ByteWindow)
    $end = [Math]::Min($Context.Length - 1, $Offset + $ByteWindow)
    $windowLength = [int]($end - $start + 1)
    $windowBytes = Read-OIFileRange -Stream $Context.Stream -Start $start -Length $windowLength
    $hexDump = @(Format-OIHexDump -Data $windowBytes -StartOffset $start -HighlightOffset $Offset -FileSize $Context.Length)

    $targetLine = Get-OIDecodedLine -Context $Context -Descriptor $LineRecord.TargetLine -TargetOffset $Offset -MaxLineBytes $MaxLineBytes
    if ($Offset -lt $Context.EncodingInfo.PreambleLength) {
        $warnings.Add('The target offset lies inside the encoding preamble; the source caret is anchored at the beginning of decoded content.')
    }
    if ($targetLine.IsTruncated) {
        $warnings.Add("The target line exceeded $MaxLineBytes bytes and was previewed in a bounded window.")
    }

    $contextOutput = New-Object 'System.Collections.Generic.List[object]'
    foreach ($descriptor in $LineRecord.PreviousLines) {
        $decoded = Get-OIDecodedLine -Context $Context -Descriptor $descriptor -TargetOffset $null -MaxLineBytes $MaxLineBytes
        $contextOutput.Add([pscustomobject]@{
            LineNumber  = $descriptor.Number
            Text        = $decoded.Text
            IsTarget    = $false
            IsTruncated = $decoded.IsTruncated
        })
    }

    $contextOutput.Add([pscustomobject]@{
        LineNumber  = $LineRecord.TargetLine.Number
        Text        = $targetLine.Text
        IsTarget    = $true
        IsTruncated = $targetLine.IsTruncated
    })

    foreach ($descriptor in $LineRecord.NextLines) {
        $decoded = Get-OIDecodedLine -Context $Context -Descriptor $descriptor -TargetOffset $null -MaxLineBytes $MaxLineBytes
        $contextOutput.Add([pscustomobject]@{
            LineNumber  = $descriptor.Number
            Text        = $decoded.Text
            IsTarget    = $false
            IsTruncated = $decoded.IsTruncated
        })
    }

    $compareByte = $null
    $bytesDiffer = $null
    $errorMessage = $CompareError
    $comparePath = $CompareRequestedPath

    if ($null -ne $CompareContext) {
        $comparePath = $CompareContext.Path
        if ($Offset -lt $CompareContext.Length) {
            $compareBytes = Read-OIFileRange -Stream $CompareContext.Stream -Start $Offset -Length 1
            $compareByte = $compareBytes[0]
            $bytesDiffer = ($targetByte -ne $compareByte)
        }
        else {
            $errorMessage = "Compare file is smaller than offset $Offset."
        }
    }


    $watch.Stop()
    $result = [pscustomobject]@{
        Success                  = [string]::IsNullOrEmpty($errorMessage)
        File                     = $Context.Path
        OffsetInput              = $OffsetInput
        OffsetDecimal            = $Offset
        OffsetHex                = Format-OIOffsetHex -Value $Offset
        FileSize                 = $Context.Length
        EncodingRequested        = $Context.EncodingInfo.RequestedName
        EncodingDetected         = $Context.EncodingInfo.DetectedName
        LineNumber               = $LineRecord.LineNumber
        LineText                 = $targetLine.Text
        LineTextTruncated        = $targetLine.IsTruncated
        CharacterPosition        = $targetLine.CharacterPosition
        PreviewCharacterPosition = $targetLine.PreviewCharacterPosition
        BytePositionInLine       = $Offset - $LineRecord.LineStart
        ContextLines             = $contextOutput.ToArray()
        TargetByteHex            = $targetByte.ToString('X2')
        TargetByteDecimal        = [int]$targetByte
        CompareFile              = $comparePath
        CompareByteHex           = if ($null -ne $compareByte) { $compareByte.ToString('X2') } else { $null }
        CompareByteDecimal       = if ($null -ne $compareByte) { [int]$compareByte } else { $null }
        BytesDiffer              = $bytesDiffer
        WindowStartOffset        = $start
        WindowEndOffset          = $end
        HexDump                  = $hexDump
        DurationMs               = [Math]::Round($watch.Elapsed.TotalMilliseconds, 3)
        Warnings                 = $warnings.ToArray()
        Error                    = $errorMessage
    }
    $result.PSObject.TypeNames.Insert(0, 'OffsetInspect.Result')
    return $result
}
