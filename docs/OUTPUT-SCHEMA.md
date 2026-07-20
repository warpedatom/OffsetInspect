# Output schema

OffsetInspect keeps public property names stable within major version 2. Additive properties may appear in minor releases; removals or semantic changes require a major version.

## `OffsetInspect.Result`

| Property | Type | Meaning |
|---|---|---|
| `Success` | Boolean | Whether inspection and optional comparison completed for this item |
| `File` | String | Canonical source path when resolution succeeded |
| `OffsetInput` | String | Original user-supplied offset |
| `OffsetDecimal` / `OffsetHex` | Int64 / String | Normalized byte offset |
| `FileSize` | Int64 | Source length in bytes |
| `EncodingRequested` / `EncodingDetected` | String | Requested and resolved text mapping |
| `LineNumber` | Int64 | One-based source line containing the byte |
| `LineText` | String | Bounded decoded preview |
| `LineTextTruncated` | Boolean | Whether the preview omits line content |
| `BytePositionInLine` | Int64 | Zero-based byte position |
| `CharacterPosition` | Int32 or null | Zero-based complete-character count before the target byte |
| `PreviewCharacterPosition` | Int32 or null | Caret position inside the displayed preview |
| `ContextLines` | Object[] | Previous, target, and following line previews |
| `TargetByteHex` / `TargetByteDecimal` | String / Int32 | Byte at the requested offset |
| `Compare*` / `BytesDiffer` | Mixed | Optional comparison result |
| `WindowStartOffset` / `WindowEndOffset` | Int64 | Inclusive hex-window bounds |
| `HexDump` | Object[] | Structured rows and highlighted byte parts |
| `DurationMs` | Double | Per-result processing time |
| `Warnings` | String[] | Non-fatal limitations |
| `Error` | String or null | Failure reason |

## `OffsetInspect.ThreatScanResult`

| Property | Type | Meaning |
|---|---|---|
| `Success` | Boolean | Whether provider scanning produced a valid result |
| `FileSha256` / `ScanTimestampUtc` | String | Reproducibility hash and ISO-8601 scan timestamp |
| `Engine` / `ScanMode` | String | Selected provider and scan mode |
| `BoundaryUnit` / `Encoding` | String | Prefix-search unit and resolved text encoding when applicable |
| `SearchModel` | String | Explicit prefix-search assumption (`MonotonicPrefixTransition`) |
| `InitialStatus` | String | Full-content normalized provider state |
| `DetectionPrefixLength` | Int64 or null | Smallest tested positive prefix under the monotonic-search model |
| `DetectionBoundaryOffset` / `DetectionBoundaryHex` | Int64 / String | Last source-file byte included in the earliest positive prefix |
| `DetectionCharacterIndex` | Int64 or null | Text-mode zero-based Unicode-scalar boundary |
| `DetectionUtf16CodeUnitIndex` | Int64 or null | Corresponding zero-based .NET UTF-16 code-unit index |
| `KnownCleanPrefixLength` | Int64 | Adjacent known-negative prefix |
| `Stable` / `Confidence` | Boolean / String | Repeatability assessment around the boundary |
| `ScanCount` | Int32 | Total prefix evaluations, including the synthetic empty-prefix baseline used by Defender |
| `ProbeLog` | Object[] | Per-probe audit trail: one record per distinct provider invocation (cache misses only), each with `Sequence`, `PrefixLength`, `Status`, `ProviderResult`, `SignatureName`, `Cacheable`, `ElapsedMs`, `TimestampUtc`. Added in 3.0.0. |
| `SignatureName` | String or null | Provider-reported name when available |
| `ProviderResult` / `ProviderHResult` | Mixed | Raw normalized status values |
| `ProviderMetadata` | Object | Engine, platform, and signature metadata when available |
| `BoundaryValidation` | Object | Repeated full, known-clean, and known-detected normalized statuses |
| `ProviderOutput` | String or null | Optional raw provider output |
| `Inspection` | `OffsetInspect.Result` or null | Nested context at the mapped boundary |
| `Warnings` / `Error` | String[] / String | Interpretation notes or failure reason |

## `OffsetInspect.DetectionTrigger`

Produced by `Get-OffsetDetectionTrigger` (and attached as the `Trigger` property of a
`ThreatScanResult` when `Export-OffsetThreatReport -IncludeTrigger` is used). Correlates a
detection boundary to the file content that most likely produced it. Read-only and
cross-platform (no scanner invocation). Added in 3.1.0.

| Property | Type | Meaning |
|---|---|---|
| `File` | String | Canonical path analyzed |
| `SignatureName` | String or null | Provider signature carried from the source result |
| `BoundaryOffset` / `BoundaryHex` | Int64 / String | Last byte of the earliest detected prefix |
| `BoundaryByteDecimal` / `BoundaryByteHex` | Int32 / String or null | Value of the boundary byte |
| `Section` | String or null | PE section containing the boundary (`headers`/name), null for non-PE |
| `RegionStart` / `RegionEnd` / `RegionSize` | Int64 / Int64 / Int | Inclusive bounds of the analyzed window |
| `PreBoundaryEntropy` | Double | Shannon entropy (bits/byte) of the run up to the boundary — low suggests plaintext, high suggests packed/encoded |
| `CandidateStrings` | Object[] | Extracted strings ending at or straddling the boundary, ranked by proximity. Each has `Offset`, `OffsetHex`, `Encoding`, `Length`, `Value`, `EndsAtOffset`, `EndsAtHex`, `ContainsBoundary`, `DistanceToBoundary` |
| `Interpretation` | String | One-line heuristic read of the likely trigger |
| `HexDump` | Object[] | Structured hex rows for the window with the boundary byte highlighted |

## `OffsetInspect.DriftEntry`

One append-only snapshot written to the NDJSON drift journal by `Add-OffsetDriftEntry` (one
JSON object per line). Records both what the scan saw and what the provider knew, so detection
changes can later be attributed to the file or to the signatures. Added in 3.1.0.

| Property | Type | Meaning |
|---|---|---|
| `TimestampUtc` | String | ISO-8601 time the snapshot was recorded |
| `File` | String | Canonical file path |
| `FileSha256` | String | Content hash (distinguishes a modified sample from a signature change) |
| `FileSize` | Int64 | File length in bytes |
| `Engine` | String or null | Provider label (AMSI/Defender/...) |
| `Status` | String or null | Recorded detection status |
| `Detected` | Boolean | Whether `Status` is a positive detection |
| `DetectionBoundaryOffset` | Int64 or null | Boundary offset at scan time |
| `SignatureName` | String or null | Provider signature name |
| `SignatureVersion` | String or null | Defender antivirus signature version (null off Windows / no Defender) |
| `EngineVersion` | String or null | Defender AM engine version |
| `Host` | String | Machine name the snapshot was taken on |

## `OffsetInspect.DriftReport`

Produced by `Get-OffsetDrift` — one per file, summarizing its journal history and explaining
each transition. Added in 3.1.0.

| Property | Type | Meaning |
|---|---|---|
| `File` | String | File the report covers |
| `SnapshotCount` | Int32 | Number of journal entries for the file |
| `DistinctHashes` | Int32 | Distinct SHA-256 values seen (>1 means the sample changed over time) |
| `FirstSeenUtc` / `LastSeenUtc` | String | Bounds of the recorded history |
| `CurrentStatus` | String or null | Status of the most recent snapshot |
| `EverChanged` | Boolean | Whether any status/boundary/hash change occurred |
| `Transitions` | Object[] | Per-consecutive-pair analysis. Each has `From*`/`To*` fields, the boolean change flags (`StatusChanged`, `HashChanged`, `SignatureChanged`, `BoundaryChanged`, `SignatureVersionChanged`), and an `Explanation` disambiguating file-change vs signature-drift vs non-deterministic |
| `Snapshots` | Object[] | The ordered `DriftEntry` records |

## `OffsetInspect.MutationTestResult`

Produced by `Invoke-OffsetMutationTest` (authorized engagements only). Reports how robust a
signature is by perturbing a detected sample in memory and re-scanning each variant with AMSI.
No variant is written to disk. Added in 3.1.0.

| Property | Type | Meaning |
|---|---|---|
| `File` | String | Sample tested |
| `Engine` | String | Always `AMSI` (in-memory) |
| `BaselineStatus` | String | AMSI status of the unmodified sample |
| `BaselineDetected` | Boolean | Whether the baseline is a positive detection (results are only meaningful when true) |
| `TargetToken` | String or null | Longest distinctive token the string transforms perturb |
| `TransformsTested` | String[] | Transform classes applied |
| `Results` | Object[] | One per transform: `Transform`, `VariantStatus`, `Evaded` (baseline detected but variant not), `Note` |
| `EvasionCount` | Int32 | How many transform classes neutralized detection |
| `RobustnessSummary` | String | One-line read of signature brittleness |

## Serialization

- `Invoke-OffsetInspect -Json` always emits an array.
- Threat-scan JSON emits one object because the command accepts one file per invocation.
- CSV output is intentionally flattened and omits nested context and provider metadata. The full `ProbeLog` array is replaced by a scalar `ProbeCount` column (its record count) so the true provider probe cost is preserved in tabular output. Added in 3.0.0.
- Use object or JSON output when preserving nested structures matters.
