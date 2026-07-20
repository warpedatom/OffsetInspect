function Get-OffsetDetectionTrigger {
    <#
    .SYNOPSIS
        Correlates a detection boundary to the file content that most likely triggered it.

    .DESCRIPTION
        Turns a detection boundary ("detected at offset 0x4A1") into an actionable finding
        ("the flagged function name ending at 0x49F is the likely trigger"). Because a
        prefix boundary is the last byte of the earliest detected prefix, the triggering
        content is a run ending at that offset. For each boundary this reports the PE section
        it falls in, the entropy of the run up to it (plaintext vs packed/encoded), the
        extracted strings that end at or straddle it ranked by proximity (the candidate
        signature content), a highlighted hex window, and a one-line interpretation.

        Reads file bytes only and never invokes a scanner, so it is fully cross-platform and
        can enrich saved results after the fact. Pipe in Invoke-OffsetThreatScan -PassThru
        results, or point it at a file and offset directly.

    .PARAMETER Result
        One or more OffsetInspect.ThreatScanResult objects (from Invoke-OffsetThreatScan
        -PassThru). Results without a detection boundary are skipped.

    .PARAMETER FilePath
        Analyze a file directly instead of a result object. Requires -BoundaryOffset.

    .PARAMETER BoundaryOffset
        Zero-based file offset of the detection boundary (the last byte of the detected prefix).

    .PARAMETER SignatureName
        Optional provider signature name to carry onto the output (FromFile mode).

    .PARAMETER WindowSize
        Bytes preceding-and-including the boundary to analyze for entropy and strings (default 128).

    .PARAMETER TrailingContext
        Bytes after the boundary to include in the hex window for readability (default 16).

    .PARAMETER MinimumLength
        Minimum string length to consider as a candidate trigger (default 4).

    .EXAMPLE
        Invoke-OffsetThreatScan .\sample.ps1 -Engine AMSI -PassThru | Get-OffsetDetectionTrigger

    .EXAMPLE
        Get-OffsetDetectionTrigger -FilePath .\sample.bin -BoundaryOffset 0x4A1
    #>
    [CmdletBinding(DefaultParameterSetName = 'FromResult')]
    [OutputType('OffsetInspect.DetectionTrigger')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'FromResult')]
        [pscustomobject[]]$Result,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'FromFile')]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [Parameter(Mandatory = $true, ParameterSetName = 'FromFile')]
        [int64]$BoundaryOffset,

        [Parameter(ParameterSetName = 'FromFile')]
        [AllowNull()]
        [string]$SignatureName,

        [ValidateRange(16, 65536)]
        [int]$WindowSize = 128,

        [ValidateRange(0, 4096)]
        [int]$TrailingContext = 16,

        [ValidateRange(2, 1024)]
        [int]$MinimumLength = 4
    )

    begin {
        function New-OITriggerForFile {
            param([string]$Path, [int64]$Boundary, [string]$Sig, [int]$Window, [int]$Trailing, [int]$MinLen)

            $resolved = (Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path
            $item = Get-Item -LiteralPath $resolved -ErrorAction Stop
            if ($item.PSIsContainer) { throw "Path is a directory, not a file: $resolved" }
            $fileSize = [int64]$item.Length
            if ($Boundary -lt 0 -or $Boundary -ge $fileSize) {
                throw "BoundaryOffset $Boundary is outside the file (size $fileSize)."
            }

            $windowStart = [int64][Math]::Max([int64]0, $Boundary - $Window + 1)
            $endInclusive = [int64][Math]::Min($fileSize - 1, $Boundary + $Trailing)
            $length = [int]($endInclusive - $windowStart + 1)

            $stream = $null
            $regionBytes = $null
            $image = $null
            try {
                $stream = [System.IO.File]::Open($resolved, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
                $regionBytes = Read-OIFileRange -Stream $stream -Start $windowStart -Length $length
                # Best-effort PE parse for section mapping; non-PE input just yields no section.
                try {
                    $headerLen = [int][Math]::Min($fileSize, [int64]8192)
                    $headerBytes = Read-OIFileRange -Stream $stream -Start 0 -Length $headerLen
                    $image = ConvertTo-OIPEImage -Bytes $headerBytes
                }
                catch {
                    $image = $null
                }
            }
            finally {
                if ($null -ne $stream) { $stream.Dispose() }
            }

            return Get-OIDetectionTrigger -RegionBytes $regionBytes -RegionStart $windowStart -BoundaryOffset $Boundary -FileSize $fileSize -MinimumLength $MinLen -Image $image -SignatureName $Sig -File $resolved
        }
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'FromFile') {
            New-OITriggerForFile -Path $FilePath -Boundary $BoundaryOffset -Sig $SignatureName -Window $WindowSize -Trailing $TrailingContext -MinLen $MinimumLength
            return
        }

        foreach ($item in $Result) {
            if ($null -eq $item) { continue }
            $file = Get-OIResultProperty -InputObject $item -Name 'File'
            $boundary = Get-OIResultProperty -InputObject $item -Name 'DetectionBoundaryOffset'
            $sig = Get-OIResultProperty -InputObject $item -Name 'SignatureName'

            if ([string]::IsNullOrWhiteSpace([string]$file) -or $null -eq $boundary) {
                Write-Verbose 'Skipping result with no file path or no detection boundary.'
                continue
            }
            if (-not (Test-Path -LiteralPath $file)) {
                Write-Warning "Cannot analyze trigger; file not found: $file"
                continue
            }

            New-OITriggerForFile -Path ([string]$file) -Boundary ([int64]$boundary) -Sig ([string]$sig) -Window $WindowSize -Trailing $TrailingContext -MinLen $MinimumLength
        }
    }
}
