# Design: Telemetry Correlation (OffsetInspect 3.2.0)

Status: **Draft** · Target: early September 2026 · Author/design: warpedatom

## Goal

Encode the operator principle **"Assume Visibility, Then Validate It"** directly in the tool.
When OffsetInspect performs a provider action (an AMSI or Defender detection-boundary scan),
answer, with evidence:

- Was defensive **telemetry** generated for this action?
- Was an **alert/detection** raised?
- Did the alert carry **actionable context** (threat name, source, severity, process, user)?
- Which telemetry sources were **absent or inaccessible** (a visibility gap is itself a finding)?

This turns a boundary scan from "what does the engine detect" into "what does the *defender*
see when this behavior occurs" — the question that matters for detection validation and
purple-team work.

## Feasibility (validated on a Windows 11 box, 2026-07-21)

Confirmed by recon against a real, non-elevated session with live detections:

| Source | Log | State | Notes |
|---|---|---|---|
| **Microsoft Defender** | `Microsoft-Windows-Windows Defender/Operational` | present, enabled, **readable non-admin** | Primary. 1116 = detection, 1117 = action taken. |
| **PowerShell** | `Microsoft-Windows-PowerShell/Operational` | present, enabled, readable | 4104 script block, 4103 module — the AMSI/script side. |
| Sysmon | `Microsoft-Windows-Sysmon/Operational` | **not installed here** | Optional; report as a gap when absent. |
| AMSI | `Microsoft-Windows-AMSI/Operational` | not present | AMSI detections surface via Defender (Source Name = AMSI). |
| Security | `Security` | **needs elevation** | Report as inaccessible when non-admin. |

A real Defender `1116` event from an AMSI scan this session exposed these structured fields
(from `event.ToXml()` → `EventData/Data`):

```
Detection ID     {10AF100A-...}          Threat Name    Trojan:Win32/Kepavll!rfn
Detection Time   2026-07-20T21:41:01.973Z Severity Name  Severe
Source Name      AMSI                     Category Name  Trojan
Process Name     ...Microsoft.PowerShell... Detection User ATK-01\Velkris
Path             amsi:_\Device\...        Action Name    Not Applicable
```

`Source Name = AMSI` + `Process Name = pwsh` + `Detection Time` give a strong, unambiguous
correlation to the scan that produced it.

## Correlation approach

1. **Snapshot** immediately before the scan: capture `TimeCreated` and the highest `RecordId`
   for each accessible log (RecordId is monotonic — cheaper and more reliable than time alone
   for "events since").
2. **Run** the provider action (existing `Invoke-OffsetThreatScan` path).
3. **Poll** each accessible log for records with `RecordId > snapshot` (Defender writes events
   asynchronously — allow a short bounded poll, e.g. up to ~5 s, before concluding "no
   telemetry").
4. **Match** candidates to the action by, in order of strength:
   - `Process Name` == the OffsetInspect host process,
   - `Source Name` == the provider used (AMSI scan → `AMSI`; Defender file scan → real-time /
     on-demand + `MpCmdRun` process),
   - `Detection Time` within the scan window,
   - `Path` / threat identity where available.
5. **Score** correlation confidence (High: process + source + window; Medium: window + source;
   Low: window only) and record it, so a coincidental concurrent detection is not silently
   claimed.

## Public API (proposed)

Enrichment switch on the existing scan, matching the `-ProbeLog` / drift-journal pattern:

```powershell
Invoke-OffsetThreatScan .\sample.ps1 -Engine AMSI -CaptureTelemetry -PassThru
```

Adds a `Telemetry` property (`OffsetInspect.TelemetryCorrelation`):

```
SourcesChecked        [Defender, PowerShell, Sysmon, Security]
SourcesAccessible     [Defender, PowerShell]
SourcesUnavailable    [Sysmon (not installed), Security (requires elevation)]   # visibility gaps
AlertGenerated        $true
Alert                 { ThreatName; Severity; SourceName; CategoryName; DetectionTime;
                        ProcessName; DetectionUser; FwLink }
DefenderEvents        [ { Id; RecordId; TimeCreated; ...fields } ]
ScriptEvents          [ { Id=4104; RecordId; TimeCreated } ]
CorrelationConfidence High | Medium | Low
Findings              [ "Alert generated with full context",
                        "Sysmon not present — process-creation telemetry unavailable" ]
```

`Findings` renders the principle literally: no alert → *"Absence of an alert is a finding"*;
alert with sparse fields → *"alert without actionable context"*; missing source → visibility gap.

Report integration: `Export-OffsetThreatReport -IncludeTelemetry` adds a per-result section.

## Permissions

Runs **non-admin** (Defender + PowerShell logs are readable) and states plainly which sources
elevation would unlock (Security, some ETW). Never requires elevation to produce a useful
result; degraded coverage is reported, not fatal.

## Test plan

- **Reliable trigger:** EICAR test string via AMSI (safe, universally detected) to force a
  Defender `1116`; assert the correlation finds it with `SourceName = AMSI` and High confidence.
- **Negative case:** a clean scan → `AlertGenerated = $false`, a "no telemetry generated"
  finding, no false positive.
- **Gap handling:** with Sysmon absent and non-admin, assert `SourcesUnavailable` is populated
  and the run still succeeds.
- **Timing:** verify the bounded poll tolerates Defender's async event write without flaking.
- **No regression:** `-CaptureTelemetry` off leaves `ThreatScanResult` byte-identical to today.
- Pure event-parsing helpers unit-tested against captured event XML fixtures (no live provider).

## Open questions / risks

- Defender event **write latency** — the poll window needs tuning; too short flakes, too long
  slows the scan. Measure on real detections.
- **Correlation false positives** under concurrent activity — confidence scoring mitigates;
  consider requiring process match for High.
- Defender **event schema drift** across engine versions — parse defensively by field `Name`,
  not positional index; fixture tests pin the fields we rely on.
- Non-admin **Security-log** blindness — documented as a known limitation, not worked around.

## Milestones (~6 weeks)

- **Wk 1–2:** finalize schema; `Get-OIWinEventSnapshot` + query helpers; Defender/PS event
  parsers with XML fixtures + unit tests.
- **Wk 3–4:** correlation engine + confidence scoring + `OffsetInspect.TelemetryCorrelation`
  object; wire `-CaptureTelemetry` into the scan.
- **Wk 5:** `Export-OffsetThreatReport -IncludeTelemetry`; EICAR-based end-to-end tests;
  gap/negative/timing cases.
- **Wk 6:** docs (`OUTPUT-SCHEMA.md` entry, README), hardening, PSGallery release **3.2.0**.
