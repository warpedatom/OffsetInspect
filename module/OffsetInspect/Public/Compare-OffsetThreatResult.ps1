function Compare-OffsetThreatResult {
    <#
    .SYNOPSIS
        Compares two threat-scan results and classifies how detection changed between them.

    .DESCRIPTION
        Diffs a reference result against a difference result (for example the same file scanned
        before and after a Defender signature-definition update, or two variants of a payload) and
        reports which fields changed, the boundary delta, and an overall classification:
        NewlyDetected, NoLongerDetected, BoundaryEarlier, BoundaryLater, BoundaryUnchanged, or
        BothClean. Operates on result objects only, so it runs on every platform.

    .PARAMETER Reference
        The baseline OffsetInspect.ThreatScanResult.

    .PARAMETER Difference
        The result to compare against the baseline.

    .EXAMPLE
        $before = Invoke-OffsetThreatScan .\sample.ps1 -Engine Defender -PassThru
        # ... update signature definitions ...
        $after  = Invoke-OffsetThreatScan .\sample.ps1 -Engine Defender -PassThru
        Compare-OffsetThreatResult -Reference $before -Difference $after
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [pscustomobject]$Reference,

        [Parameter(Mandatory = $true, Position = 1)]
        [pscustomobject]$Difference
    )

    $comparedFields = @(
        'InitialStatus', 'DetectionPrefixLength', 'DetectionBoundaryOffset',
        'DetectionBoundaryHex', 'Stable', 'Confidence', 'SignatureName'
    )

    $changes = New-Object 'System.Collections.Generic.List[object]'
    foreach ($field in $comparedFields) {
        $referenceValue = Get-OIResultProperty -InputObject $Reference -Name $field
        $differenceValue = Get-OIResultProperty -InputObject $Difference -Name $field
        if ([string]$referenceValue -ne [string]$differenceValue) {
            $changes.Add([pscustomobject]@{
                Field      = $field
                Reference  = $referenceValue
                Difference = $differenceValue
            })
        }
    }

    $referencePrefix = Get-OIResultProperty -InputObject $Reference -Name 'DetectionPrefixLength'
    $differencePrefix = Get-OIResultProperty -InputObject $Difference -Name 'DetectionPrefixLength'
    $referenceDetected = $null -ne $referencePrefix
    $differenceDetected = $null -ne $differencePrefix

    $classification =
        if (-not $referenceDetected -and $differenceDetected) { 'NewlyDetected' }
        elseif ($referenceDetected -and -not $differenceDetected) { 'NoLongerDetected' }
        elseif (-not $referenceDetected -and -not $differenceDetected) { 'BothClean' }
        elseif ([int64]$differencePrefix -lt [int64]$referencePrefix) { 'BoundaryEarlier' }
        elseif ([int64]$differencePrefix -gt [int64]$referencePrefix) { 'BoundaryLater' }
        else { 'BoundaryUnchanged' }

    $boundaryDelta = if ($referenceDetected -and $differenceDetected) {
        [int64]$differencePrefix - [int64]$referencePrefix
    }
    else { $null }

    $result = [pscustomobject]@{
        ReferenceFile        = Get-OIResultProperty -InputObject $Reference -Name 'File'
        DifferenceFile       = Get-OIResultProperty -InputObject $Difference -Name 'File'
        Classification       = $classification
        BoundaryDelta        = $boundaryDelta
        SignatureChanged     = [string](Get-OIResultProperty -InputObject $Reference -Name 'SignatureName') -ne [string](Get-OIResultProperty -InputObject $Difference -Name 'SignatureName')
        ReferenceProbeCount  = @(Get-OIResultProperty -InputObject $Reference -Name 'ProbeLog' -Default @()).Count
        DifferenceProbeCount = @(Get-OIResultProperty -InputObject $Difference -Name 'ProbeLog' -Default @()).Count
        Unchanged            = ($changes.Count -eq 0)
        Changes              = $changes.ToArray()
    }
    $result.PSObject.TypeNames.Insert(0, 'OffsetInspect.ThreatScanDiff')
    return $result
}
