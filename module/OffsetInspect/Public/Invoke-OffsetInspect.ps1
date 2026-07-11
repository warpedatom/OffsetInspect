function Invoke-OffsetInspect {
    <#
    .SYNOPSIS
        Maps one or more byte offsets to bounded binary and source context.

    .DESCRIPTION
        Opens each unique input file once, scans it once for the requested source-line
        context, and reads only the byte windows needed for each result. The command
        supports human-readable, object, JSON, CSV, and CSV-file output.

    .PARAMETER FilePaths
        One or more files to inspect.

    .PARAMETER OffsetInputs
        Decimal or hexadecimal offsets. Numeric-only values are decimal. Hexadecimal
        values may use 0x, an h suffix, or contain A-F.

    .PARAMETER PassThru
        Returns structured OffsetInspect.Result objects.

    .EXAMPLE
        Invoke-OffsetInspect .\sample.bin 0x2A -PassThru

    .EXAMPLE
        Invoke-OffsetInspect .\script.ps1 128,256 -ContextLines 4 -Json
    #>
    [CmdletBinding(DefaultParameterSetName = 'Human')]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [Alias('FilePath')]
        [string[]]$FilePaths,

        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [Alias('OffsetInput', 'Offsets')]
        [string[]]$OffsetInputs,

        [ValidateRange(0, 4096)]
        [int]$ByteWindow = 32,

        [ValidateRange(0, 100)]
        [int]$ContextLines = 3,

        [ValidateSet('Auto', 'Default', 'UTF8', 'UTF16LE', 'UTF16BE', 'ASCII')]
        [string]$Encoding = 'Auto',

        [string]$CompareFile,

        [ValidateRange(1024, 16777216)]
        [int]$MaxLineBytes = 1048576,

        [Parameter(Mandatory = $true, ParameterSetName = 'Object')]
        [switch]$PassThru,

        [Parameter(Mandatory = $true, ParameterSetName = 'Json')]
        [switch]$Json,

        [Parameter(Mandatory = $true, ParameterSetName = 'Csv')]
        [switch]$Csv,

        [Parameter(Mandatory = $true, ParameterSetName = 'CsvFile')]
        [ValidateNotNullOrEmpty()]
        [string]$CsvPath,

        [switch]$FailOnError
    )

    $mode = if ($PassThru) {
        'Object'
    }
    elseif ($Json) {
        'Json'
    }
    elseif ($Csv) {
        'Csv'
    }
    elseif ($PSCmdlet.ParameterSetName -eq 'CsvFile') {
        'CsvFile'
    }
    else {
        'Human'
    }

    $plan = @(New-OIInspectionPlan -Files $FilePaths -Offsets $OffsetInputs)
    $results = New-Object object[] $plan.Count
    $compareContext = $null
    $compareError = $null

    if ($CompareFile) {
        try {
            $compareContext = Open-OIFileContext -Path $CompareFile -EncodingName 'Auto'
        }
        catch {
            $compareError = "Unable to open compare file '$CompareFile': $($_.Exception.Message)"
        }
    }

    try {
        foreach ($group in ($plan | Group-Object -Property FilePath)) {
            $context = $null

            try {
                $context = Open-OIFileContext -Path $group.Name -EncodingName $Encoding
            }
            catch {
                foreach ($item in $group.Group) {
                    $results[$item.Index] = New-OIErrorResult `
                        -File $item.FilePath `
                        -OffsetInput $item.OffsetInput `
                        -Offset $null `
                        -FileSize $null `
                        -EncodingRequested $Encoding `
                        -CompareFile $CompareFile `
                        -Message "Unable to open file '$($item.FilePath)': $($_.Exception.Message)"
                }
                continue
            }

            try {
                if ($context.Length -eq 0) {
                    foreach ($item in $group.Group) {
                        $results[$item.Index] = New-OIErrorResult `
                            -File $context.Path `
                            -OffsetInput $item.OffsetInput `
                            -Offset $null `
                            -FileSize $context.Length `
                            -EncodingRequested $Encoding `
                            -CompareFile $CompareFile `
                            -Message "File is empty: $($context.Path)"
                    }
                    continue
                }

                $validEntries = New-Object 'System.Collections.Generic.List[object]'
                $validOffsets = New-Object 'System.Collections.Generic.List[System.Int64]'

                foreach ($item in $group.Group) {
                    try {
                        $offset = ConvertTo-OIOffset -InputValue $item.OffsetInput
                    }
                    catch {
                        $results[$item.Index] = New-OIErrorResult `
                            -File $context.Path `
                            -OffsetInput $item.OffsetInput `
                            -Offset $null `
                            -FileSize $context.Length `
                            -EncodingRequested $Encoding `
                            -CompareFile $CompareFile `
                            -Message $_.Exception.Message
                        continue
                    }

                    if ($offset -lt 0 -or $offset -ge $context.Length) {
                        $results[$item.Index] = New-OIErrorResult `
                            -File $context.Path `
                            -OffsetInput $item.OffsetInput `
                            -Offset $offset `
                            -FileSize $context.Length `
                            -EncodingRequested $Encoding `
                            -CompareFile $CompareFile `
                            -Message "Offset $offset is outside the valid range 0-$($context.Length - 1)."
                        continue
                    }

                    $entry = [pscustomobject]@{
                        Index       = $item.Index
                        OffsetInput = $item.OffsetInput
                        Offset      = [int64]$offset
                    }
                    $validEntries.Add($entry)
                    $validOffsets.Add([int64]$offset)
                }

                if ($validEntries.Count -eq 0) { continue }

                $lineRecords = Get-OILineRecords `
                    -Context $context `
                    -Offsets $validOffsets.ToArray() `
                    -ContextLines $ContextLines

                foreach ($entry in $validEntries) {
                    $lineRecord = $lineRecords[[string]$entry.Offset]
                    if ($null -eq $lineRecord -or $null -eq $lineRecord.TargetLine) {
                        $results[$entry.Index] = New-OIErrorResult `
                            -File $context.Path `
                            -OffsetInput $entry.OffsetInput `
                            -Offset $entry.Offset `
                            -FileSize $context.Length `
                            -EncodingRequested $Encoding `
                            -CompareFile $CompareFile `
                            -Message 'Unable to map the offset to a source line.'
                        continue
                    }

                    $results[$entry.Index] = Get-OIInspectionResult `
                        -Context $context `
                        -OffsetInput $entry.OffsetInput `
                        -Offset $entry.Offset `
                        -LineRecord $lineRecord `
                        -ByteWindow $ByteWindow `
                        -CompareContext $compareContext `
                        -CompareError $compareError `
                        -CompareRequestedPath $CompareFile `
                        -MaxLineBytes $MaxLineBytes
                }
            }
            finally {
                Close-OIFileContext -Context $context
            }
        }
    }
    finally {
        Close-OIFileContext -Context $compareContext
    }

    $output = Write-OIInspectionOutput -Results $results -Mode $mode -CsvPath $CsvPath
    if ($null -ne $output) {
        Write-Output $output
    }

    $failed = @($results | Where-Object { -not $_.Success })
    if ($FailOnError -and $failed.Count -gt 0) {
        throw "OffsetInspect completed with $($failed.Count) failed result(s)."
    }
}
