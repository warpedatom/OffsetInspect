# Telemetry correlation: after a provider scan, determine what Windows telemetry the
# action generated - whether an alert was raised, with what context, and which sources
# were blind. Encodes the "Assume Visibility, Then Validate It" principle. Windows-only.
# See docs/TELEMETRY-CORRELATION-DESIGN.md.

# Sources correlated against, in priority order. Defender is primary and readable
# non-admin; PowerShell script-block logging is secondary; Sysmon/Security are
# environment-dependent and reported as visibility gaps when absent or inaccessible.
$script:OITelemetrySources = @(
    [pscustomobject]@{ Key = 'Defender';   LogName = 'Microsoft-Windows-Windows Defender/Operational'; Ids = @(1116, 1117) }
    [pscustomobject]@{ Key = 'PowerShell'; LogName = 'Microsoft-Windows-PowerShell/Operational';        Ids = @(4104) }
    [pscustomobject]@{ Key = 'Sysmon';     LogName = 'Microsoft-Windows-Sysmon/Operational';            Ids = @(1) }
    [pscustomobject]@{ Key = 'Security';   LogName = 'Security';                                         Ids = @(4688) }
)

function ConvertFrom-OIWinEventDataField {
    <#
        Pure: parse a Windows event's XML (from EventRecord.ToXml()) into a hashtable of its
        named EventData/Data fields. Unit-tested directly against fixture XML - no live provider.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Xml
    )
    $fields = @{}
    try { $doc = [xml]$Xml } catch { return $fields }
    # Windows event XML carries a default namespace, so match Data nodes by local name.
    # Use GetAttribute/InnerText (methods, not property access) so an empty <Data/> element
    # is safe under Set-StrictMode instead of throwing a missing-'#text' error.
    foreach ($d in $doc.SelectNodes('//*[local-name()="Data"]')) {
        $name = $d.GetAttribute('Name')
        if (-not [string]::IsNullOrEmpty($name)) { $fields[$name] = $d.InnerText }
    }
    return $fields
}

function ConvertFrom-OIDefenderDetectionEvent {
    <#
        Pure: shape a parsed Defender 1116/1117 event into a structured detection record.
        Field names follow the Microsoft Defender Operational schema. Unit-tested with fixtures.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Xml,

        [Parameter(Mandatory = $true)]
        [int]$EventId,

        [int64]$RecordId = 0,

        [datetime]$TimeCreated = [datetime]::MinValue
    )
    $f = ConvertFrom-OIWinEventDataField -Xml $Xml
    [pscustomobject]@{
        EventId       = $EventId
        RecordId      = $RecordId
        TimeCreated   = $TimeCreated
        ThreatName    = $f['Threat Name']
        ThreatId      = $f['Threat ID']
        SeverityName  = $f['Severity Name']
        CategoryName  = $f['Category Name']
        SourceName    = $f['Source Name']
        ProcessName   = $f['Process Name']
        DetectionUser = $f['Detection User']
        Path          = $f['Path']
        ActionName    = $f['Action Name']
        FwLink        = $f['FWLink']
    }
}

function Get-OITelemetryEventConfidence {
    <#
        Pure: score how confidently a Defender detection is attributable to this scan.
        High requires both the detection Source matching the provider (AMSI) AND the process
        matching the scanning host, so a coincidental concurrent detection on the box is never
        claimed as High. Medium is source-only; Low is neither. Unit-tested directly.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Event,

        [AllowNull()]
        [string]$ExpectedSource,

        [AllowNull()]
        [string]$HostProcessPath
    )
    $sourceMatch = [string]::IsNullOrEmpty($ExpectedSource) -or ($Event.SourceName -eq $ExpectedSource)
    $procMatch = $false
    if (-not [string]::IsNullOrEmpty($HostProcessPath) -and -not [string]::IsNullOrEmpty($Event.ProcessName)) {
        $ep = $Event.ProcessName.TrimEnd([char]0).ToLowerInvariant()
        $hp = $HostProcessPath.ToLowerInvariant()
        $procMatch = ($ep -eq $hp) -or $ep.Contains($hp) -or $hp.Contains($ep)
    }
    if ($sourceMatch -and $procMatch) { 'High' }
    elseif ($sourceMatch) { 'Medium' }
    else { 'Low' }
}

function Get-OITelemetrySnapshot {
    <#
        Capture, immediately before a scan, which telemetry logs are accessible and the
        highest RecordId currently in each - so correlation can find only events the scan
        produced. Inaccessible/absent logs are recorded as visibility gaps, not failures.
        Runs non-admin (Defender + PowerShell are readable; Security typically needs elevation).
    #>
    [CmdletBinding()]
    param()
    $startUtc = [datetime]::UtcNow
    $accessible = New-Object 'System.Collections.Generic.List[object]'
    $unavailable = New-Object 'System.Collections.Generic.List[object]'

    foreach ($src in $script:OITelemetrySources) {
        try {
            $log = Get-WinEvent -ListLog $src.LogName -ErrorAction Stop
            $lastId = [int64]0
            try {
                $newest = Get-WinEvent -LogName $src.LogName -MaxEvents 1 -ErrorAction Stop
                if ($null -ne $newest) { $lastId = [int64]$newest.RecordId }
            }
            catch {
                # An empty (but present) log: no records yet. Snapshot at 0.
                $lastId = [int64]0
            }
            $accessible.Add([pscustomobject]@{
                Key          = $src.Key
                LogName      = $src.LogName
                Ids          = $src.Ids
                LastRecordId = $lastId
                Enabled      = [bool]$log.IsEnabled
            })
        }
        catch {
            $msg = $_.Exception.Message
            $reason = if ($msg -match 'access is denied|elevat|administrator') { 'requires elevation' }
            elseif ($msg -match 'no events|could not be found|does not exist|Attempted to perform an unauthorized') { 'not present' }
            else { 'not present' }
            $unavailable.Add([pscustomobject]@{ Key = $src.Key; LogName = $src.LogName; Reason = $reason })
        }
    }

    [pscustomobject]@{
        StartTimeUtc = $startUtc
        Accessible   = $accessible.ToArray()
        Unavailable  = $unavailable.ToArray()
    }
}

function Get-OITelemetryCorrelation {
    <#
        After a scan, query each accessible log for events produced since the snapshot and
        correlate them to the action. Confidence is High only when a Defender detection's
        process matches the scanning host (so a coincidental concurrent detection is never
        claimed), Medium on source+window, Low on window alone. Returns an
        OffsetInspect.TelemetryCorrelation object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Snapshot,

        [ValidateSet('AMSI', 'Defender')]
        [string]$Engine = 'AMSI',

        [string]$HostProcessPath,

        [ValidateRange(0, 60)]
        [int]$PollSeconds = 5
    )

    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $defenderEvents = New-Object 'System.Collections.Generic.List[object]'

    $defenderSrc = $Snapshot.Accessible | Where-Object Key -eq 'Defender' | Select-Object -First 1

    # Correlate by RecordId (monotonic, timezone-proof) rather than time: the Get-WinEvent
    # StartTime filter is interpreted in LOCAL time, so a UTC snapshot would silently exclude
    # events. Query the newest detections and keep only those past the pre-scan high-water.
    # Poll because Defender writes its events asynchronously; break once a detection appears.
    $deadline = [datetime]::UtcNow.AddSeconds($PollSeconds)
    do {
        if ($null -ne $defenderSrc -and $defenderEvents.Count -eq 0) {
            try {
                $candidates = Get-WinEvent -FilterHashtable @{
                    LogName = $defenderSrc.LogName
                    Id      = 1116, 1117
                } -MaxEvents 100 -ErrorAction Stop
                foreach ($evt in @($candidates)) {
                    if ([int64]$evt.RecordId -le [int64]$defenderSrc.LastRecordId) { continue }
                    $defenderEvents.Add(
                        (ConvertFrom-OIDefenderDetectionEvent -Xml $evt.ToXml() -EventId ([int]$evt.Id) -RecordId ([int64]$evt.RecordId) -TimeCreated $evt.TimeCreated)
                    )
                }
            }
            catch {
                # Get-WinEvent throws when a filter matches nothing yet; keep polling.
                Write-Verbose "No matching Defender events yet: $($_.Exception.Message)"
            }
        }
        if ($defenderEvents.Count -gt 0) { break }
        if ([datetime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 400 }
    } while ([datetime]::UtcNow -lt $deadline)

    # Correlate: pick the strongest-matching detection and score confidence.
    $alertEvent = $null
    $confidence = 'None'
    $expectedSource = if ($Engine -eq 'AMSI') { 'AMSI' } else { $null }
    foreach ($evt in $defenderEvents) {
        $score = Get-OITelemetryEventConfidence -Event $evt -ExpectedSource $expectedSource -HostProcessPath $HostProcessPath
        # Keep the highest-confidence event.
        if ($null -eq $alertEvent -or
            @{ High = 3; Medium = 2; Low = 1; None = 0 }[$score] -gt @{ High = 3; Medium = 2; Low = 1; None = 0 }[$confidence]) {
            $alertEvent = $evt
            $confidence = $score
        }
    }

    $alertGenerated = $defenderEvents.Count -gt 0
    $findings = New-Object 'System.Collections.Generic.List[string]'
    if ($alertGenerated) {
        if ([string]::IsNullOrWhiteSpace($alertEvent.ThreatName)) {
            $findings.Add('A detection was logged, but without a threat name (alert lacks actionable context).')
        }
        else {
            $findings.Add("Alert generated: $($alertEvent.ThreatName) [$($alertEvent.SeverityName)] via $($alertEvent.SourceName).")
        }
    }
    else {
        $findings.Add('No defender telemetry was generated for this scan action (absence of an alert is a finding).')
    }
    foreach ($gap in @($Snapshot.Unavailable)) {
        $findings.Add("Visibility gap: $($gap.Key) ($($gap.LogName)) $($gap.Reason).")
    }

    $watch.Stop()
    $result = [pscustomobject]@{
        SourcesChecked        = @($script:OITelemetrySources | ForEach-Object { $_.Key })
        SourcesAccessible     = @($Snapshot.Accessible | ForEach-Object { $_.Key })
        SourcesUnavailable    = @($Snapshot.Unavailable)
        AlertGenerated        = $alertGenerated
        Alert                 = $alertEvent
        DefenderEvents        = $defenderEvents.ToArray()
        CorrelationConfidence = $confidence
        Findings              = $findings.ToArray()
        PollDurationMs        = [Math]::Round($watch.Elapsed.TotalMilliseconds, 3)
    }
    $result.PSObject.TypeNames.Insert(0, 'OffsetInspect.TelemetryCorrelation')
    return $result
}
