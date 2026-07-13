function Invoke-OffsetThreatScan {
    <#
    .SYNOPSIS
        Locates the earliest content prefix that remains detected by AMSI or Microsoft Defender.

    .DESCRIPTION
        Performs a lower-bound binary search over progressively sized content prefixes. The
        resulting boundary is the earliest detected prefix for the selected provider and scan
        mode; it is not asserted to be an exact signature byte or complete malicious range.

        AMSI supports raw-byte and text scanning. Microsoft Defender scans temporary prefix
        files with remediation disabled and never changes Defender configuration or exclusions.

    .PARAMETER Engine
        Auto selects AMSI for recognized script/text extensions and Defender for other files.

    .PARAMETER ScanMode
        Text uses AmsiScanString and reports both a character boundary and the mapped source-file
        byte offset. RawBytes preserves byte-for-byte prefix semantics.

    .PARAMETER ProbeLogPath
        Optional path. When supplied, the per-probe audit trail (ProbeLog) is also written to this
        file as a JSON array, independent of the selected output mode, for attaching to a report.

    .EXAMPLE
        Invoke-OffsetThreatScan .\sample.ps1 -Engine AMSI -ScanMode Text -PassThru

    .EXAMPLE
        Invoke-OffsetThreatScan .\sample.bin -Engine Defender -RepeatCount 3 -Json
    #>
    [CmdletBinding(DefaultParameterSetName = 'Human')]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateSet('Auto', 'AMSI', 'Defender')]
        [string]$Engine = 'Auto',

        [ValidateSet('Auto', 'RawBytes', 'Text')]
        [string]$ScanMode = 'Auto',

        [ValidateSet('Auto', 'Default', 'UTF8', 'UTF16LE', 'UTF16BE', 'ASCII')]
        [string]$Encoding = 'Auto',

        [ValidateRange(1, 10)]
        [int]$RepeatCount = 2,

        [ValidateRange(1, 600)]
        [int]$TimeoutSeconds = 30,

        [ValidateRange(0, 4096)]
        [int]$ByteWindow = 64,

        [ValidateRange(0, 100)]
        [int]$ContextLines = 3,

        [ValidateRange(1024, 16777216)]
        [int]$MaxLineBytes = 1048576,

        [ValidateScript({ $_ -ge 1 })]
        [int64]$MaxScanBytes = 268435456,

        [switch]$Force,

        [switch]$NoProgress,

        [switch]$IncludeProviderOutput,

        # No [ValidateNotNullOrEmpty()]: an unbound [string] is '' (empty) under
        # Windows PowerShell 5.1, and the scanner closures capture this scope via
        # .GetNewClosure(), which rejects an empty value carrying that attribute.
        # The empty case is handled by the IsNullOrWhiteSpace guard before export.
        [string]$ProbeLogPath,

        [Parameter(Mandatory = $true, ParameterSetName = 'Object')]
        [switch]$PassThru,

        [Parameter(Mandatory = $true, ParameterSetName = 'Json')]
        [switch]$Json,

        [Parameter(Mandatory = $true, ParameterSetName = 'Csv')]
        [switch]$Csv,

        [Parameter(Mandatory = $true, ParameterSetName = 'CsvFile')]
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

    if (
        $mode -eq 'CsvFile' -and
        [string]::IsNullOrWhiteSpace($CsvPath)
    ) {
        throw 'CsvPath cannot be null, empty, or whitespace.'
    }

    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $warnings = New-Object 'System.Collections.Generic.List[string]'
    $resolvedPath = $null
    $providerMetadata = $null
    $search = $null
    $inspection = $null
    $signatureName = $null
    $providerOutput = $null
    $selectedEngine = $Engine
    $selectedScanMode = $ScanMode
    $amsiSession = $null
    $temporaryDirectory = $null
    $sourceStream = $null
    $defenderCopyBuffer = $null
    $errorMessage = $null
    $fileSize = $null
    $initialLastWriteTimeUtc = $null
    $fileSha256 = $null
    $scanTimestampUtc = [DateTime]::UtcNow.ToString('o')
    $encodingInfo = $null
    $textContent = $null
    $textEncoding = $null
    $scalarMap = $null
    $detectionUtf16Index = $null
    $boundaryUnit = $null
    $defenderTimeoutSeconds = $TimeoutSeconds
    $convertToUtf16PrefixLengthCommand = Get-Command `
        -Name ConvertTo-OIUtf16PrefixLength `
        -CommandType Function `
        -ErrorAction Stop

    $convertFromAmsiResponseCommand = Get-Command `
        -Name ConvertFrom-OIAmsiResponse `
        -CommandType Function `
        -ErrorAction Stop

    $copyStreamPrefixCommand = Get-Command `
        -Name Copy-OIStreamPrefix `
        -CommandType Function `
        -ErrorAction Stop

    $invokeDefenderFileScanCommand = Get-Command `
        -Name Invoke-OIDefenderFileScan `
        -CommandType Function `
        -ErrorAction Stop

    try {
        if (-not (Test-OIIsWindows)) {
            throw 'Threat-provider scanning is supported only on Windows. Offset inspection remains cross-platform.'
        }

        $resolvedPath = (Resolve-Path -LiteralPath $FilePath -ErrorAction Stop).Path
        $item = Get-Item -LiteralPath $resolvedPath -ErrorAction Stop
        if ($item.PSIsContainer) { throw "Path is a directory, not a file: $resolvedPath" }
        $initialLastWriteTimeUtc = $item.LastWriteTimeUtc
        $sourceStream = [System.IO.File]::Open(
            $resolvedPath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read
        )
        $fileSize = [int64]$sourceStream.Length
        if ($fileSize -eq 0) { throw "File is empty: $resolvedPath" }

        if (-not $Force -and $fileSize -gt $MaxScanBytes) {
            throw "File size $fileSize exceeds MaxScanBytes ($MaxScanBytes). Increase the limit or use -Force after considering provider cost."
        }

        $textExtensions = @('.ps1', '.psm1', '.psd1', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh', '.hta', '.cmd', '.bat', '.txt')
        $extension = [System.IO.Path]::GetExtension($resolvedPath).ToLowerInvariant()
        $isRecognizedText = $textExtensions -contains $extension

        if ($selectedEngine -eq 'Auto') {
            $selectedEngine = if ($isRecognizedText) { 'AMSI' } else { 'Defender' }
        }

        if ($selectedScanMode -eq 'Auto') {
            $selectedScanMode = if ($selectedEngine -eq 'AMSI' -and $isRecognizedText) { 'Text' } else { 'RawBytes' }
        }

        if ($selectedEngine -eq 'Defender' -and $selectedScanMode -ne 'RawBytes') {
            throw 'Microsoft Defender supports RawBytes prefix scanning only. Use AMSI for Text mode.'
        }


        if ($selectedEngine -eq 'AMSI') {
            if ($fileSize -gt [int]::MaxValue) {
                throw 'AMSI scanning currently supports files up to 2 GB because scan content is represented by managed arrays or strings.'
            }

            $fileSha256 = Get-OIStreamSha256 -Stream $sourceStream
            $providerMetadata = Get-OIAmsiProviderMetadata
            Initialize-OIAmsiInterop

            try {
                $amsiSession = New-Object `
                    OffsetInspect.Interop.AmsiSession('OffsetInspect/2.0')
            }
            catch {
                $providerError = $_.Exception.Message

                if (
                    $null -ne $_.Exception.InnerException -and
                    -not [string]::IsNullOrWhiteSpace(
                        $_.Exception.InnerException.Message
                    )
                ) {
                    $providerError = $_.Exception.InnerException.Message
                }

                throw (
                    'AMSI initialization failed. No active AMSI-capable ' +
                    'antimalware provider may be available. Test with an ' +
                    'enabled provider in an isolated Windows environment. ' +
                    "Provider error: $providerError"
                )
            }

            if ($selectedScanMode -eq 'Text') {
                $encodingInfo = Resolve-OIEncoding -Stream $sourceStream -Name $Encoding
                $textEncoding = Get-OIStrictEncoding -Encoding $encodingInfo.Encoding
                $allBytes = Read-OIFileRange -Stream $sourceStream -Start 0 -Length ([int]$fileSize)
                $contentOffset = [int]$encodingInfo.PreambleLength
                $contentLength = $allBytes.Length - $contentOffset
                try {
                    $textContent = $textEncoding.GetString($allBytes, $contentOffset, $contentLength)
                }
                catch {
                    throw "Text decoding failed with the selected encoding. Use the correct encoding or RawBytes mode. $($_.Exception.Message)"
                }

                if ($textContent.IndexOf([char]0) -ge 0) {
                    throw 'Text mode does not accept embedded NUL characters because AmsiScanString uses null-terminated text semantics. Use RawBytes mode.'
                }

                $scalarMap = New-OIUnicodeScalarMap -Text $textContent
                $unitCount = [int64]$scalarMap.UnicodeScalarCount
                if ($unitCount -eq 0) { throw 'The decoded text content is empty.' }

                $scanner = {
                    param([int64]$PrefixLength)
                    if ($PrefixLength -eq 0) {
                        return [pscustomobject]@{
                            Status         = 'Clean'
                            ProviderResult = 0
                            HResult        = '0x00000000'
                            SignatureName  = $null
                            Message        = 'Synthetic AMSI empty-prefix baseline.'
                            RawOutput      = $null
                        }
                    }
                    $utf16PrefixLength = & $convertToUtf16PrefixLengthCommand -ScalarMap $scalarMap -UnicodeScalarPrefixLength $PrefixLength
                    $prefix = if ($utf16PrefixLength -eq 0) { [string]::Empty } else { $textContent.Substring(0, $utf16PrefixLength) }
                    $response = $amsiSession.ScanString($prefix, $resolvedPath)
                    & $convertFromAmsiResponseCommand -Response $response
                }.GetNewClosure()
            }
            else {
                $allBytes = Read-OIFileRange -Stream $sourceStream -Start 0 -Length ([int]$fileSize)
                $unitCount = [int64]$allBytes.Length
                $scanner = {
                    param([int64]$PrefixLength)
                    if ($PrefixLength -eq 0) {
                        return [pscustomobject]@{
                            Status         = 'Clean'
                            ProviderResult = 0
                            HResult        = '0x00000000'
                            SignatureName  = $null
                            Message        = 'Synthetic AMSI empty-prefix baseline.'
                            RawOutput      = $null
                        }
                    }
                    $response = $amsiSession.ScanBytePrefix($allBytes, [int]$PrefixLength, $resolvedPath)
                    & $convertFromAmsiResponseCommand -Response $response
                }.GetNewClosure()
            }
        }
        else {
            $fileSha256 = Get-OIStreamSha256 -Stream $sourceStream
            $commandPath = Get-OIDefenderCommandPath
            $providerMetadata = Get-OIDefenderProviderMetadata -CommandPath $commandPath

            $antivirusEnabledProperty = `
                $providerMetadata.PSObject.Properties['AntivirusEnabled']

            if (
                $null -ne $antivirusEnabledProperty -and
                $providerMetadata.AntivirusEnabled -eq $false
            ) {
                throw (
                    'Microsoft Defender Antivirus is disabled or operating ' +
                    'in passive mode. Use an isolated Windows test system ' +
                    'where Microsoft Defender Antivirus is enabled.'
                )
            }

            $unitCount = $fileSize
            $temporaryDirectory = Join-Path ([System.IO.Path]::GetTempPath()) ('OffsetInspect-' + [guid]::NewGuid().ToString('N'))
            $null = New-Item -ItemType Directory -Path $temporaryDirectory -ErrorAction Stop
            $temporaryExtension = if ($extension -and $extension.Length -le 32) { $extension } else { '.bin' }
            if ($extension -and $temporaryExtension -eq '.bin') {
                $warnings.Add('The original extension exceeded 32 characters; Defender prefixes use the .bin extension.')
            }
            $temporaryFile = Join-Path $temporaryDirectory ('prefix' + $temporaryExtension)
            $defenderCopyBuffer = New-Object byte[] (1024 * 1024)

            $scanner = {
                param([int64]$PrefixLength)
                if ($PrefixLength -eq 0) {
                    return [pscustomobject]@{
                        Status         = 'Clean'
                        ProviderResult = $null
                        HResult        = $null
                        SignatureName  = $null
                        Message        = 'Synthetic empty-prefix baseline.'
                        RawOutput      = $null
                        ExitCode       = $null
                    }
                }

                & $copyStreamPrefixCommand -SourceStream $sourceStream -DestinationPath $temporaryFile -Length $PrefixLength -Buffer $defenderCopyBuffer
                & $invokeDefenderFileScanCommand -CommandPath $commandPath -FilePath $temporaryFile -TimeoutSeconds $defenderTimeoutSeconds
            }.GetNewClosure()
        }

        $search = Invoke-OIPrefixBoundarySearch `
            -UnitCount $unitCount `
            -Scanner $scanner `
            -RepeatCount $RepeatCount `
            -Activity "OffsetInspect $selectedEngine boundary search" `
            -NoProgress:$NoProgress

        if (-not $search.Success) {
            throw $search.Error
        }

        $initialStatus = $search.InitialScan.Status
        if ($search.InitialScan.SignatureName) { $signatureName = $search.InitialScan.SignatureName }
        if ($IncludeProviderOutput) { $providerOutput = $search.InitialScan.RawOutput }

        $detectionPrefixLength = $search.KnownDetected
        $knownCleanPrefixLength = $search.KnownClean
        $boundaryOffset = $null
        $boundaryHex = $null
        $characterBoundary = $null
        $boundaryUnit = if ($selectedScanMode -eq 'Text') { 'UnicodeScalar' } else { 'Byte' }

        if ($null -ne $detectionPrefixLength) {
            if ($selectedScanMode -eq 'Text') {
                $characterBoundary = [int64]$detectionPrefixLength - 1
                $utf16PrefixLength = & $convertToUtf16PrefixLengthCommand -ScalarMap $scalarMap -UnicodeScalarPrefixLength $detectionPrefixLength
                $detectionUtf16Index = [int64]$utf16PrefixLength - 1
                $detectedText = $textContent.Substring(0, $utf16PrefixLength)
                $byteCount = [int64]$textEncoding.GetByteCount($detectedText) + [int64]$encodingInfo.PreambleLength
                $boundaryOffset = [Math]::Max([int64]0, $byteCount - 1)
                $warnings.Add('Text-mode boundary search uses Unicode scalar prefixes; the reported byte offset is mapped through the validated source encoding.')
            }
            else {
                $boundaryOffset = [int64]$detectionPrefixLength - 1
            }

            $boundaryHex = Format-OIOffsetHex -Value $boundaryOffset
            $inspectionEncodingInfo = if ($null -ne $encodingInfo) {
                $encodingInfo
            }
            else {
                Resolve-OIEncoding -Stream $sourceStream -Name $Encoding
            }
            $inspectionContext = [pscustomobject]@{
                Path         = $resolvedPath
                Length       = $fileSize
                Stream       = $sourceStream
                EncodingInfo = $inspectionEncodingInfo
            }
            $inspection = Get-OISingleInspectionFromContext `
                -Context $inspectionContext `
                -Offset $boundaryOffset `
                -ByteWindow $ByteWindow `
                -ContextLines $ContextLines `
                -MaxLineBytes $MaxLineBytes

            $warnings.Add('The boundary is the earliest tested prefix that remained detected; it is not necessarily an exact signature byte or the full malicious range.')
            $warnings.Add('The binary search assumes a monotonic negative-to-positive prefix transition. Context-sensitive or non-monotonic detections require manual validation.')
            if (-not $search.Stable) {
                $warnings.Add('Repeated scans around the boundary were inconsistent. Treat the result as low-confidence and retest in an isolated environment.')
            }
            if ($initialStatus -eq 'Blocked') {
                $warnings.Add('AMSI classified the full content as blocked by administrator policy rather than malware-detected.')
            }

            foreach ($check in @($search.HighChecks)) {
                if (-not $signatureName -and $check.SignatureName) { $signatureName = $check.SignatureName }
            }
        }

        try {
            $finalItem = Get-Item -LiteralPath $resolvedPath -ErrorAction Stop
            if ([int64]$finalItem.Length -ne $fileSize -or $finalItem.LastWriteTimeUtc -ne $initialLastWriteTimeUtc) {
                $warnings.Add('The source file metadata changed during scanning. Treat the hash and boundary as potentially inconsistent and rescan a stable copy.')
            }
        }
        catch {
            $warnings.Add("The source file could not be revalidated after scanning: $($_.Exception.Message)")
        }

        $boundaryValidation = [pscustomobject]@{
            FullContentStatuses   = @($search.FullChecks | ForEach-Object { $_.Status })
            KnownCleanStatuses    = @($search.LowChecks | ForEach-Object { $_.Status })
            KnownDetectedStatuses = @($search.HighChecks | ForEach-Object { $_.Status })
        }

        $watch.Stop()
        $result = [pscustomobject]@{
            Success                  = $true
            File                     = $resolvedPath
            FileSize                 = $fileSize
            FileSha256               = $fileSha256
            ScanTimestampUtc         = $scanTimestampUtc
            Engine                   = $selectedEngine
            ScanMode                 = $selectedScanMode
            BoundaryUnit             = $boundaryUnit
            SearchModel              = 'MonotonicPrefixTransition'
            Encoding                 = if ($null -ne $encodingInfo) { $encodingInfo.DetectedName } else { $null }
            InitialStatus            = $initialStatus
            DetectionPrefixLength    = $detectionPrefixLength
            DetectionBoundaryOffset  = $boundaryOffset
            DetectionBoundaryHex     = $boundaryHex
            DetectionCharacterIndex  = $characterBoundary
            DetectionUtf16CodeUnitIndex = $detectionUtf16Index
            KnownCleanPrefixLength   = $knownCleanPrefixLength
            Stable                   = $search.Stable
            Confidence               = $search.Confidence
            ScanCount                = $search.ScanCount
            SignatureName            = $signatureName
            ProviderResult           = $search.InitialScan.ProviderResult
            ProviderHResult          = $search.InitialScan.HResult
            ProviderMetadata         = $providerMetadata
            BoundaryValidation       = $boundaryValidation
            ProviderOutput           = $providerOutput
            ProbeLog                 = if ($null -ne $search -and $null -ne $search.PSObject.Properties['ProbeLog']) { $search.ProbeLog } else { @() }
            Inspection               = $inspection
            DurationMs               = [Math]::Round($watch.Elapsed.TotalMilliseconds, 3)
            Warnings                 = $warnings.ToArray()
            Error                    = $null
        }
        $result.PSObject.TypeNames.Insert(0, 'OffsetInspect.ThreatScanResult')
    }
    catch {
        $watch.Stop()
        $errorMessage = $_.Exception.Message
        if ($IncludeProviderOutput -and $null -ne $search -and $null -ne $search.InitialScan) {
            $providerOutput = $search.InitialScan.RawOutput
        }
        $result = [pscustomobject]@{
            Success                  = $false
            File                     = if ($resolvedPath) { $resolvedPath } else { $FilePath }
            FileSize                 = $fileSize
            FileSha256               = $fileSha256
            ScanTimestampUtc         = $scanTimestampUtc
            Engine                   = $selectedEngine
            ScanMode                 = $selectedScanMode
            BoundaryUnit             = $boundaryUnit
            SearchModel              = 'MonotonicPrefixTransition'
            Encoding                 = if ($null -ne $encodingInfo) { $encodingInfo.DetectedName } else { $null }
            InitialStatus            = if ($null -ne $search -and $null -ne $search.InitialScan) { $search.InitialScan.Status } else { $null }
            DetectionPrefixLength    = $null
            DetectionBoundaryOffset  = $null
            DetectionBoundaryHex     = $null
            DetectionCharacterIndex  = $null
            DetectionUtf16CodeUnitIndex = $null
            KnownCleanPrefixLength   = if ($null -ne $search) { $search.KnownClean } else { $null }
            Stable                   = $false
            Confidence               = 'None'
            ScanCount                = if ($null -ne $search) { $search.ScanCount } else { 0 }
            SignatureName            = if ($null -ne $search -and $null -ne $search.InitialScan) { $search.InitialScan.SignatureName } else { $null }
            ProviderResult           = if ($null -ne $search -and $null -ne $search.InitialScan) { $search.InitialScan.ProviderResult } else { $null }
            ProviderHResult          = if ($null -ne $search -and $null -ne $search.InitialScan) { $search.InitialScan.HResult } else { $null }
            ProviderMetadata         = $providerMetadata
            BoundaryValidation       = if ($null -ne $search) {
                [pscustomobject]@{
                    FullContentStatuses   = @($search.FullChecks | ForEach-Object { $_.Status })
                    KnownCleanStatuses    = @($search.LowChecks | ForEach-Object { $_.Status })
                    KnownDetectedStatuses = @($search.HighChecks | ForEach-Object { $_.Status })
                }
            } else { $null }
            ProviderOutput           = $providerOutput
            ProbeLog                 = if ($null -ne $search -and $null -ne $search.PSObject.Properties['ProbeLog']) { $search.ProbeLog } else { @() }
            Inspection               = $null
            DurationMs               = [Math]::Round($watch.Elapsed.TotalMilliseconds, 3)
            Warnings                 = $warnings.ToArray()
            Error                    = $errorMessage
        }
        $result.PSObject.TypeNames.Insert(0, 'OffsetInspect.ThreatScanResult')
    }
    finally {
        if ($null -ne $amsiSession) {
            try { $amsiSession.Dispose() }
            catch { Write-Verbose "AMSI session cleanup failed: $($_.Exception.Message)" }
        }
        if ($null -ne $sourceStream) {
            try { $sourceStream.Dispose() }
            catch { Write-Verbose "Source-stream cleanup failed: $($_.Exception.Message)" }
        }
        if ($temporaryDirectory -and (Test-Path -LiteralPath $temporaryDirectory)) {
            try { Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force -ErrorAction Stop }
            catch { Write-Warning "Unable to remove temporary scan directory '$temporaryDirectory': $($_.Exception.Message)" }
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($ProbeLogPath)) {
        $exportedProbeLogPath = Export-OIProbeLog -ProbeLog $result.ProbeLog -Path $ProbeLogPath
        Write-Verbose "Probe log written to $exportedProbeLogPath"
    }

    $output = Write-OIThreatOutput -Result $result -Mode $mode -CsvPath $CsvPath
    if ($null -ne $output) { Write-Output $output }

    if ($FailOnError -and -not $result.Success) {
        throw "Offset threat scan failed: $($result.Error)"
    }
}
