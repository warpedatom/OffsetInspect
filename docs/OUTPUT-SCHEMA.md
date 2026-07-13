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

## Serialization

- `Invoke-OffsetInspect -Json` always emits an array.
- Threat-scan JSON emits one object because the command accepts one file per invocation.
- CSV output is intentionally flattened and omits nested context and provider metadata. The full `ProbeLog` array is replaced by a scalar `ProbeCount` column (its record count) so the true provider probe cost is preserved in tabular output. Added in 3.0.0.
- Use object or JSON output when preserving nested structures matters.
