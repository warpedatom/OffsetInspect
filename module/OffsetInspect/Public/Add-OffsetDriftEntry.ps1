function Add-OffsetDriftEntry {
    <#
    .SYNOPSIS
        Records a detection snapshot to an append-only drift journal (NDJSON).

    .DESCRIPTION
        Captures what a scan saw AND what the provider knew at that moment - file SHA-256,
        status, detection boundary, signature name, and the local Microsoft Defender
        signature/engine versions - as one line in an NDJSON journal. Re-running over time
        builds a history that Get-OffsetDrift can analyze to answer the recurring question:
        when detection changes, did the FILE change or did the SIGNATURES change?

        Pipe in Invoke-OffsetThreatScan -PassThru results, or record a file directly. The
        journal is portable (one JSON object per line); Defender version fields are null on
        systems without Defender, but the entry is still written.

    .PARAMETER Result
        One or more OffsetInspect.ThreatScanResult objects (from Invoke-OffsetThreatScan -PassThru).

    .PARAMETER FilePath
        Record a file directly instead of from a result object.

    .PARAMETER Status
        Detection status to record in FromFile mode (e.g. Detected, NotDetected).

    .PARAMETER Engine
        Provider label to record in FromFile mode (e.g. AMSI, Defender).

    .PARAMETER DetectionBoundaryOffset
        Detection boundary offset to record in FromFile mode.

    .PARAMETER SignatureName
        Signature name to record in FromFile mode.

    .PARAMETER JournalPath
        NDJSON journal file. Defaults to OffsetInspect\drift.ndjson under LocalApplicationData.

    .EXAMPLE
        Invoke-OffsetThreatScan .\sample.ps1 -Engine AMSI -PassThru | Add-OffsetDriftEntry

    .EXAMPLE
        Add-OffsetDriftEntry -FilePath .\sample.ps1 -Status Detected -Engine AMSI -SignatureName 'Trojan:PowerShell/X'
    #>
    [CmdletBinding(DefaultParameterSetName = 'FromResult')]
    [OutputType('OffsetInspect.DriftEntry')]
    param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, ParameterSetName = 'FromResult')]
        [pscustomobject[]]$Result,

        [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'FromFile')]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [Parameter(ParameterSetName = 'FromFile')]
        [AllowNull()]
        [string]$Status,

        [Parameter(ParameterSetName = 'FromFile')]
        [AllowNull()]
        [string]$Engine,

        [Parameter(ParameterSetName = 'FromFile')]
        [AllowNull()]
        [object]$DetectionBoundaryOffset,

        [Parameter(ParameterSetName = 'FromFile')]
        [AllowNull()]
        [string]$SignatureName,

        [ValidateNotNullOrEmpty()]
        [string]$JournalPath = (Join-Path ([System.Environment]::GetFolderPath('LocalApplicationData')) 'OffsetInspect/drift.ndjson')
    )

    begin {
        $sigStatus = Get-OIDefenderSignatureStatus
        $dir = Split-Path -Parent $JournalPath
        if (-not [string]::IsNullOrWhiteSpace($dir) -and -not (Test-Path -LiteralPath $dir)) {
            $null = New-Item -ItemType Directory -Path $dir -Force
        }
    }

    process {
        if ($PSCmdlet.ParameterSetName -eq 'FromFile') {
            $resolved = (Resolve-Path -LiteralPath $FilePath -ErrorAction Stop).Path
            $record = New-OIDriftRecord -File $resolved -FileSha256 (Get-OIFileHash -Path $resolved).SHA256 -FileSize (Get-Item -LiteralPath $resolved).Length -Engine $Engine -Status $Status -DetectionBoundaryOffset $DetectionBoundaryOffset -SignatureName $SignatureName -SignatureStatus $sigStatus
            Add-Content -LiteralPath $JournalPath -Value (ConvertTo-Json -InputObject $record -Depth 6 -Compress) -Encoding UTF8
            $record
            return
        }

        foreach ($item in $Result) {
            if ($null -eq $item) { continue }
            $file = [string](Get-OIResultProperty -InputObject $item -Name 'File')
            if ([string]::IsNullOrWhiteSpace($file)) {
                Write-Verbose 'Skipping result with no File.'
                continue
            }
            if (-not (Test-Path -LiteralPath $file)) {
                Write-Warning "Cannot record drift; file not found: $file"
                continue
            }
            $resolved = (Resolve-Path -LiteralPath $file -ErrorAction Stop).Path

            $sha = [string](Get-OIResultProperty -InputObject $item -Name 'FileSha256')
            if ([string]::IsNullOrWhiteSpace($sha)) { $sha = (Get-OIFileHash -Path $resolved).SHA256 }
            $size = Get-OIResultProperty -InputObject $item -Name 'FileSize'
            if ($null -eq $size) { $size = (Get-Item -LiteralPath $resolved).Length }

            $record = New-OIDriftRecord -File $resolved -FileSha256 $sha -FileSize $size `
                -Engine ([string](Get-OIResultProperty -InputObject $item -Name 'Engine')) `
                -Status ([string](Get-OIResultProperty -InputObject $item -Name 'InitialStatus')) `
                -DetectionBoundaryOffset (Get-OIResultProperty -InputObject $item -Name 'DetectionBoundaryOffset') `
                -SignatureName ([string](Get-OIResultProperty -InputObject $item -Name 'SignatureName')) `
                -SignatureStatus $sigStatus
            Add-Content -LiteralPath $JournalPath -Value (ConvertTo-Json -InputObject $record -Depth 6 -Compress) -Encoding UTF8
            $record
        }
    }
}
