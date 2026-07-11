# Threat scanning design

## Purpose

`Invoke-OffsetThreatScan` identifies the lower boundary between a prefix classified as clean/not detected and the next prefix classified as detected/blocked. It is designed for defensive analysis and detection-engineering workflows.

The implementation is native to OffsetInspect. No ThreatCheck executable, binary artifact, or source file is bundled. Each scan holds one read-only source stream so the SHA-256 hash and tested prefixes refer to the same file image. See [PROVENANCE.md](./PROVENANCE.md) for attribution and implementation boundaries.

## Provider contract

Every provider scan returns one of these states:

| State | Meaning | Boundary-search behavior |
|---|---|---|
| `Clean` | Provider explicitly classified content as clean | Negative |
| `NotDetected` | No detection was returned | Negative |
| `Detected` | Malware-range provider result or explicit detection marker | Positive |
| `Blocked` | AMSI administrator-policy block range | Positive, separately identified |
| `Timeout` | Provider did not finish within the limit | Abort |
| `Indeterminate` | Provider response could not be classified safely | Abort |
| `Error` | API/process failure | Abort |

A timeout or error is never treated as a detection or clean result.

## Search algorithm

1. Establish the empty prefix as a known-negative baseline. Provider adapters synthesize this result when the underlying API rejects zero-length input.
2. Scan the complete content.
3. Return without a boundary when the complete content is negative.
4. When the complete content is positive, set:
   - `low = 0`, a known-negative prefix length.
   - `high = full length`, a known-positive prefix length.
5. Repeatedly test the midpoint until `high - low = 1`.
6. Rescan both sides `RepeatCount` times.
7. Return stability and confidence with the boundary.

The implementation caches midpoint results during the search but bypasses the cache for repeatability checks. It reports the search model as `MonotonicPrefixTransition`: binary search assumes a single negative-to-positive transition. Context-sensitive or non-monotonic provider behavior can violate that assumption and requires manual validation.

## AMSI provider

The AMSI provider uses direct Windows API interop:

- `AmsiInitialize`
- `AmsiOpenSession`
- `AmsiScanBuffer`
- `AmsiScanString`
- `AmsiCloseSession`
- `AmsiUninitialize`

AMSI malware classification follows the documented result range: values at or above 32768 are malware results. Administrator-policy block values are retained as the separate `Blocked` state.

### Text mode

Text mode:

1. Resolves the source encoding.
2. Removes a recognized byte-order mark from the decoded content.
3. Validates decoding with strict encoder/decoder fallbacks.
4. Searches Unicode-scalar prefixes with `AmsiScanString` without splitting surrogate pairs.
5. Converts the detected prefix back to the last source-file byte included in that prefix.
6. Inspects the mapped byte boundary with `Invoke-OffsetInspect`.

The character-to-byte mapping is encoding-aware, but the provider decision is still contextual and should not be interpreted as an exact signature range. Text mode rejects embedded NUL characters because `AmsiScanString` uses null-terminated text semantics; use raw-byte mode for such content.

### RawBytes mode

Raw-byte mode scans byte-for-byte prefixes with `AmsiScanBuffer`. Managed array limits restrict this mode to files smaller than 2 GB.

## Microsoft Defender provider

The Defender provider:

1. Selects the newest versioned executable under the Defender platform directory.
2. Falls back to the legacy program-files path.
3. Creates a unique temporary directory under the current user's temporary path.
4. Copies only the requested prefix to a temporary file while preserving the original extension.
5. Invokes a custom scan with remediation disabled.
6. Classifies explicit English detection/clean markers conservatively; localized or unknown output remains `Indeterminate`.
7. Requires an explicit clean or detection marker; ambiguous responses are `Indeterminate`.
8. Removes the temporary directory in a `finally` block.

OffsetInspect does not create exclusions, change preferences, disable protection, or request remediation.

## Stability and confidence

| Confidence | Condition |
|---|---|
| `High` | Both sides of the boundary remained consistent across at least two repeated scans |
| `Medium` | Both sides remained consistent with one repeat |
| `Low` | At least one repeated scan disagreed |
| `None` | No valid boundary was produced |

Provider signatures and behavior can change after security-intelligence or platform updates. Record `ProviderMetadata`, the scan date, and the file hash when reproducing results.

## Recommended laboratory workflow

- Use only files you are authorized to analyze.
- Prefer an isolated Windows analysis VM.
- Record the sample hash before scanning.
- Use `-RepeatCount 3` or higher for unstable detections.
- Save JSON output with provider metadata.
- Validate the surrounding source context manually.
- Do not describe the returned boundary as an exact malicious byte without additional evidence.
