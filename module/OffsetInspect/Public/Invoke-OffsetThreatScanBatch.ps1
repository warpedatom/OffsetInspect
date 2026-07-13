function Invoke-OffsetThreatScanBatch {
    <#
    .SYNOPSIS
        Runs Invoke-OffsetThreatScan across many files and returns the collected results.

    .DESCRIPTION
        Expands the supplied files, directories, and wildcards into a file list, scans each
        with the selected provider, and returns the OffsetInspect.ThreatScanResult objects.
        A per-file scan failure does not abort the batch; it is returned as a result with
        Success = $false. The output pipes directly into Export-OffsetThreatReport. Like the
        single-file command, provider scanning is Windows-only.

    .PARAMETER Path
        One or more files, directories, or wildcard patterns to scan.

    .PARAMETER Recurse
        Recurse into subdirectories when a path resolves to a directory.

    .PARAMETER Filter
        Wildcard filter applied when enumerating directories (default '*').

    .PARAMETER Summary
        Return a flattened detection matrix (one row per file) instead of the full result objects.

    .EXAMPLE
        Invoke-OffsetThreatScanBatch ./payloads -Recurse -Engine AMSI |
            Export-OffsetThreatReport -Path ./engagement.html -Format Html

    .EXAMPLE
        Invoke-OffsetThreatScanBatch ./samples -Summary | Format-Table File, DetectionPrefixLength, Confidence
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Path,

        [switch]$Recurse,

        [ValidateNotNullOrEmpty()]
        [string]$Filter = '*',

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

        [switch]$IncludeProviderOutput,

        [switch]$NoProgress,

        [switch]$Summary
    )

    begin {
        $inputPaths = New-Object 'System.Collections.Generic.List[string]'
    }

    process {
        foreach ($item in $Path) {
            if (-not [string]::IsNullOrWhiteSpace($item)) { $inputPaths.Add($item) }
        }
    }

    end {
        if (-not (Test-OIIsWindows)) {
            throw 'Threat-provider scanning is supported only on Windows. Offset inspection remains cross-platform.'
        }

        $targets = @(Resolve-OIBatchTarget -Path $inputPaths.ToArray() -Recurse:$Recurse -Filter $Filter)
        if ($targets.Count -eq 0) {
            Write-Warning 'No files matched the batch selection.'
            return
        }

        $results = New-Object 'System.Collections.Generic.List[object]'
        $index = 0
        foreach ($target in $targets) {
            $index++
            if (-not $NoProgress) {
                Write-Progress -Activity 'Batch threat scan' -Status $target -PercentComplete ([int](100.0 * $index / $targets.Count))
            }
            Write-Verbose "Scanning ($index/$($targets.Count)): $target"

            $scanParameters = @{
                FilePath       = $target
                Engine         = $Engine
                ScanMode       = $ScanMode
                Encoding       = $Encoding
                RepeatCount    = $RepeatCount
                TimeoutSeconds = $TimeoutSeconds
                NoProgress     = $true
                PassThru       = $true
            }
            if ($IncludeProviderOutput) { $scanParameters.IncludeProviderOutput = $true }

            try {
                $results.Add((Invoke-OffsetThreatScan @scanParameters))
            }
            catch {
                $failure = [pscustomobject]@{
                    Success                     = $false
                    File                        = $target
                    FileSize                    = $null
                    FileSha256                  = $null
                    ScanTimestampUtc            = [DateTime]::UtcNow.ToString('o')
                    Engine                      = $Engine
                    ScanMode                    = $ScanMode
                    BoundaryUnit                = $null
                    SearchModel                 = 'MonotonicPrefixTransition'
                    Encoding                    = $null
                    InitialStatus               = $null
                    DetectionPrefixLength       = $null
                    DetectionBoundaryOffset     = $null
                    DetectionBoundaryHex        = $null
                    DetectionCharacterIndex     = $null
                    DetectionUtf16CodeUnitIndex = $null
                    KnownCleanPrefixLength      = $null
                    Stable                      = $false
                    Confidence                  = 'None'
                    ScanCount                   = 0
                    SignatureName               = $null
                    ProviderResult              = $null
                    ProviderHResult             = $null
                    ProviderMetadata            = $null
                    BoundaryValidation          = $null
                    ProviderOutput              = $null
                    ProbeLog                    = @()
                    Inspection                  = $null
                    DurationMs                  = 0
                    Warnings                    = @()
                    Error                       = $_.Exception.Message
                }
                $failure.PSObject.TypeNames.Insert(0, 'OffsetInspect.ThreatScanResult')
                $results.Add($failure)
            }
        }

        if (-not $NoProgress) {
            Write-Progress -Activity 'Batch threat scan' -Completed
        }

        $collected = $results.ToArray()
        if ($Summary) {
            return @($collected | ForEach-Object { ConvertTo-OIFlatThreatResult -Result $_ })
        }
        return $collected
    }
}
