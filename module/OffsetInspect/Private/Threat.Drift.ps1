function Get-OIDefenderSignatureStatus {
    <#
        Returns the local Microsoft Defender signature/engine versions so a drift entry can
        record what the provider knew at scan time. All fields are null when Defender or
        Get-MpComputerStatus is unavailable (non-Windows, no Defender), which keeps the
        journal cross-platform - the entry is still written, just without provider versions.
    #>
    [CmdletBinding()]
    param()

    $result = [pscustomobject]@{
        SignatureVersion     = $null
        SignatureLastUpdated = $null
        EngineVersion        = $null
    }

    $command = Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($null -eq $command) { return $result }

    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        $result.SignatureVersion = $status.AntivirusSignatureVersion
        $lastUpdated = $status.AntivirusSignatureLastUpdated
        if ($null -ne $lastUpdated) { $result.SignatureLastUpdated = ([datetime]$lastUpdated).ToUniversalTime().ToString('o') }
        $result.EngineVersion = $status.AMEngineVersion
    }
    catch {
        Write-Verbose "Defender signature status unavailable: $($_.Exception.Message)"
    }

    return $result
}

function New-OIDriftRecord {
    <#
        Builds one drift snapshot record from already-collected fields. Pure and
        cross-platform; the public wrapper does the file I/O and Defender query.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$File,

        [AllowNull()]
        [string]$FileSha256,

        [AllowNull()]
        [object]$FileSize,

        [AllowNull()]
        [string]$Engine,

        [AllowNull()]
        [string]$Status,

        [AllowNull()]
        [object]$DetectionBoundaryOffset,

        [AllowNull()]
        [string]$SignatureName,

        [AllowNull()]
        $SignatureStatus,

        [AllowNull()]
        [string]$TimestampUtc
    )

    $detected = $false
    if (-not [string]::IsNullOrWhiteSpace($Status)) {
        $detected = ($Status -match '^(?i)detected$')
    }

    return [pscustomobject]@{
        PSTypeName              = 'OffsetInspect.DriftEntry'
        TimestampUtc            = if ([string]::IsNullOrWhiteSpace($TimestampUtc)) { [DateTime]::UtcNow.ToString('o') } else { $TimestampUtc }
        File                    = $File
        FileSha256              = $FileSha256
        FileSize                = $FileSize
        Engine                  = $Engine
        Status                  = $Status
        Detected                = $detected
        DetectionBoundaryOffset = $DetectionBoundaryOffset
        SignatureName           = $SignatureName
        SignatureVersion        = if ($null -ne $SignatureStatus) { $SignatureStatus.SignatureVersion } else { $null }
        EngineVersion           = if ($null -ne $SignatureStatus) { $SignatureStatus.EngineVersion } else { $null }
        Host                    = [System.Environment]::MachineName
    }
}

function Compare-OIDriftTimeline {
    <#
        Given the snapshots for a single file ordered oldest-first, produces a drift timeline
        and, for each consecutive pair, an explanation that disambiguates the crucial question:
        did detection change because the FILE changed, because Defender's SIGNATURES changed,
        or for neither reason (non-deterministic provider result)? Pure and cross-platform.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Snapshots
    )

    $get = { param($o, $n) Get-OIResultProperty -InputObject $o -Name $n }

    $transitions = New-Object 'System.Collections.Generic.List[object]'
    for ($i = 1; $i -lt $Snapshots.Count; $i++) {
        $from = $Snapshots[$i - 1]
        $to = $Snapshots[$i]

        $fromStatus = [string](& $get $from 'Status')
        $toStatus = [string](& $get $to 'Status')
        $fromVer = & $get $from 'SignatureVersion'
        $toVer = & $get $to 'SignatureVersion'

        $statusChanged = ($fromStatus -ne $toStatus)
        $hashChanged = ((& $get $from 'FileSha256') -ne (& $get $to 'FileSha256'))
        $signatureChanged = ((& $get $from 'SignatureName') -ne (& $get $to 'SignatureName'))
        $boundaryChanged = ((& $get $from 'DetectionBoundaryOffset') -ne (& $get $to 'DetectionBoundaryOffset'))
        $sigVerChanged = ($fromVer -ne $toVer)

        $explanation = if ($hashChanged) {
            'File content changed between snapshots (sample modified) - detection differences are not attributable to signatures.'
        }
        elseif ($statusChanged -and $sigVerChanged) {
            "Detection changed with the file unchanged while Defender signatures updated ($fromVer -> $toVer) - signature drift."
        }
        elseif ($statusChanged) {
            'Detection changed with the file unchanged and no signature update - non-deterministic or environmental provider result.'
        }
        elseif ($boundaryChanged) {
            'Detection boundary moved with the file unchanged - signature refinement or provider flux.'
        }
        elseif ($sigVerChanged) {
            "Signatures updated ($fromVer -> $toVer) with no change in detection."
        }
        else {
            'No change.'
        }

        $transitions.Add([pscustomobject]@{
            FromUtc                 = & $get $from 'TimestampUtc'
            ToUtc                   = & $get $to 'TimestampUtc'
            FromStatus              = $fromStatus
            ToStatus                = $toStatus
            StatusChanged           = $statusChanged
            HashChanged             = $hashChanged
            SignatureChanged        = $signatureChanged
            BoundaryChanged         = $boundaryChanged
            SignatureVersionChanged = $sigVerChanged
            FromSignatureVersion    = $fromVer
            ToSignatureVersion      = $toVer
            Explanation             = $explanation
        })
    }

    $distinctHashes = @($Snapshots | ForEach-Object { & $get $_ 'FileSha256' } | Where-Object { -not [string]::IsNullOrWhiteSpace([string]$_) } | Select-Object -Unique)
    $everChanged = @($transitions | Where-Object { $_.StatusChanged -or $_.BoundaryChanged -or $_.HashChanged }).Count -gt 0
    $last = if ($Snapshots.Count -gt 0) { $Snapshots[$Snapshots.Count - 1] } else { $null }

    return [pscustomobject]@{
        PSTypeName     = 'OffsetInspect.DriftReport'
        File           = if ($null -ne $last) { & $get $last 'File' } else { $null }
        SnapshotCount  = $Snapshots.Count
        DistinctHashes = $distinctHashes.Count
        FirstSeenUtc   = if ($Snapshots.Count -gt 0) { & $get $Snapshots[0] 'TimestampUtc' } else { $null }
        LastSeenUtc    = if ($null -ne $last) { & $get $last 'TimestampUtc' } else { $null }
        CurrentStatus  = if ($null -ne $last) { & $get $last 'Status' } else { $null }
        EverChanged    = $everChanged
        Transitions    = $transitions.ToArray()
        Snapshots      = $Snapshots
    }
}
