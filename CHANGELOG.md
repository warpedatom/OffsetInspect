# Changelog

All notable changes to OffsetInspect are documented in this file. The project follows semantic versioning.

## [Unreleased]

### Planned

- Additional provider adapters after the v2 provider contract has received field testing.
- Published benchmark baselines for representative text and binary corpora.

## [3.1.2] - 2026-07-20

Bug-fix release. No command, parameter, or output-schema changes.

### Fixed

- **`Get-OffsetPEInfo` and `Get-OffsetIOC` returned a null `ImpHash` and zero imports for
  every 32-bit (PE32) binary.** The ordinal-import flag was constructed as
  `[uint64]0x80000000`, but PowerShell parses the literal `0x80000000` as the negative
  `Int32` value `-2147483648`, and casting a negative number to `UInt64` throws. Import
  parsing therefore aborted on its first statement for all PE32 files; the exception was
  caught and recorded only in the `Warnings` collection, which `Get-OffsetIOC` does not
  surface — so the failure was invisible. The PE32+ (x64) branch already used a hex-string
  conversion to sidestep the same overflow class; the PE32 branch now does too. Verified
  against `SysWOW64\kernel32.dll` (imphash `5c665927b146db2f5155688ad978e69f`, 102 imports)
  and a 32-bit .NET assembly, both matching the native OffsetScan engine field-for-field.

### Impact

- imphash is a primary indicator for malware clustering, and a large fraction of malware
  ships as 32-bit PE32. Prior versions silently produced no imphash for those samples, so a
  triage row or report could omit the single most useful correlation key with no error
  shown. Any 32-bit sample analyzed with 3.0.0–3.1.1 should be re-run.

### Added

- A regression test that builds a minimal but complete PE32 with a real import directory and
  asserts a populated imphash and import list with no warnings. The previous PE test corpus
  was entirely PE32+ (x64), so the 32-bit import path had no coverage.

## [3.1.1] - 2026-07-20

Bug-fix release. No command, parameter, or output-schema changes.

### Fixed

- **`Get-OffsetString` split a string straddling a read-window seam into two truncated
  halves.** The file is scanned in bounded-memory windows (1 MiB by default); a run that
  reached the end of a window was emitted as-is and the remainder reported separately as a
  new string. An indicator spanning a seam — a URL, C2 domain, or mutex name — was therefore
  reported as two fragments, and a filter such as `Where-Object Value -match 'http'` could
  miss it entirely. A trailing run is now held back and scanned with the following window,
  so a straddling string is reported once, whole. The one remaining exception is a string
  longer than an entire window, which is still split rather than stalling the read.
- **`Get-OffsetString` results no longer depend on `-WindowSize`.** Because seam splits
  inflated the count, the same file returned different results at different window sizes.
  Verified on `ntdll.dll` (2,517,928 bytes): 32,506 strings at every window size from 4 KiB
  to 64 MiB, previously 32,507 at the 1 MiB default versus 32,506 unwindowed.
- **`Get-OffsetIOC`'s `PrintableStringCount` is now deterministic** for files larger than the
  default window. It calls `Get-OffsetString` and exposes no `-WindowSize`, so it inherited
  the seam-split inflation with no way for a caller to control it.

### Changed

- Cross-engine parity with the native [OffsetScan](https://github.com/warpedatom/OffsetScan)
  engine is now exact for string extraction. `Get-OffsetString` and `offsetscan strings`
  return set-identical results (offset, encoding, and value) on `ntdll.dll` — 32,506 hits,
  zero entries unique to either engine, holding even at a 4 KiB window (~600 seams).
  OffsetScan 0.1.1 fixes the corresponding defect on its side.

### Added

- Regression tests for ASCII and UTF-16LE strings straddling a window seam, window-size
  independence of the result set, and the trailing-run measurement itself (including the
  NUL-padding and run-fills-the-buffer cases that keep the carry-over bounded).

## [3.1.0] - 2026-07-19

All-additive minor release. Existing commands, parameters, and output-schema field
meanings are unchanged.

### Added

- `Get-OffsetDetectionTrigger` — correlates a detection boundary to the content that most
  likely produced it. Because a prefix boundary is the last byte of the earliest detected
  prefix, the trigger is a run ending at that offset; the command reports the PE section the
  boundary falls in, the entropy of the run up to it (plaintext vs packed/encoded), and the
  extracted strings ending at or straddling the boundary ranked by proximity (the candidate
  signature content), with a one-line interpretation. Works on a `ThreatScanResult` pipeline
  or a `-FilePath`/`-BoundaryOffset` pair. Read-only and cross-platform. New output object
  `OffsetInspect.DetectionTrigger`.
- Detection-drift journaling. `Add-OffsetDriftEntry` records append-only NDJSON snapshots
  (file SHA-256, status, boundary, signature name, and the local Microsoft Defender
  signature/engine versions) from a result pipeline or a file. `Get-OffsetDrift` reads the
  journal and, for each file, explains every transition as a **file modification** (SHA-256
  changed), a **signature-database update** (Defender signature version changed with the file
  unchanged), or a **non-deterministic** provider result. New output objects
  `OffsetInspect.DriftEntry` and `OffsetInspect.DriftReport`.
- `Export-OffsetThreatReport -IocJsonPath` — sources IOC panels from the native OffsetScan
  engine's JSON (`offsetscan ioc <corpus> > ioc.json`) instead of re-scanning each file in
  PowerShell; `-IncludeIoc` becomes the live fallback for files absent from the JSON.
- `Export-OffsetThreatReport -IncludeTrigger` — embeds detection-trigger analysis in the
  Markdown and HTML reports.
- `Invoke-OffsetMutationTest` — for authorized engagements, tests how robust a signature is by
  applying standard perturbations (case inversion, string-literal concatenation, comment
  insertion, whitespace injection) to a detected sample and re-scanning each variant with AMSI
  to report which transform classes neutralize detection. Everything runs in memory; no variant
  is written to disk, and the command refuses to run without `-AuthorizedEngagement`. New output
  object `OffsetInspect.MutationTestResult`.

### Fixed

- Hardened Windows PowerShell 5.1 module-scope parsing of top-level JSON arrays, which the
  new `-IocJsonPath` ingestion path depends on.

## [3.0.0] - 2026-07-12

### Added

- Per-probe audit trail. `Invoke-OffsetThreatScan` results now expose a `ProbeLog`
  property recording every distinct provider invocation (`Sequence`, `PrefixLength`,
  `Status`, `ProviderResult`, `SignatureName`, `Cacheable`, `ElapsedMs`,
  `TimestampUtc`). The same records stream to `-Verbose` in real time, and
  `ProbeLog.Count` is surfaced in human output and as `ProbeCount` in CSV output.
  This gives a report-ready transcript of the exact provider cost of a scan.
- `docs/PROVIDER-INTERFACE.md` documenting the scanner contract, status-token
  semantics, how to add a new provider without touching the search core, and the
  resource isolation required before prefix probing can be parallelised.
- Property/fuzz tests (`tests/ThreatSearch.Properties.Tests.ps1`) validating the
  monotonic-transition invariant, logarithmic probe budget, and graceful handling
  of indeterminate/erroring providers against a cross-platform mock. Runs in the
  PowerShell 7 Linux CI leg (no Windows/AMSI/Defender required).
- `Invoke-OffsetThreatScan -ProbeLogPath <file>` writes the `ProbeLog` to a JSON
  file as a report-ready provider audit transcript, independent of the selected
  output mode.
- New public command `Export-OffsetThreatReport` renders one or more threat-scan
  results (piped from `Invoke-OffsetThreatScan -PassThru`) into a self-contained
  Markdown or HTML detection-boundary report: per-file summary, provider/signature/
  engine metadata, the full ProbeLog, and warnings. Read-only and cross-platform.
- New public command `Invoke-OffsetThreatScanBatch` scans a corpus of files,
  directories, and wildcards (with `-Recurse`/`-Filter`), returning one result per
  file and continuing past per-file failures. `-Summary` returns a flattened
  detection matrix; the full results pipe directly into `Export-OffsetThreatReport`.
- New public command `Compare-OffsetThreatResult` diffs two scan results (for
  example the same file before and after a signature-definition update) into a
  classified `OffsetInspect.ThreatScanDiff`: NewlyDetected, NoLongerDetected,
  BoundaryEarlier, BoundaryLater, BoundaryUnchanged, or BothClean, with the boundary
  delta, changed fields, and a signature-change flag.
- New public command `Invoke-OffsetThreatScanRegion` discovers multiple
  independently-detectable byte regions by splitting a file into segments and
  scanning each in isolation through AMSI entirely in memory (no detected content is
  written to disk, so Defender real-time protection is never triggered or altered).
  Each hit is bisected within its segment to map the exact triggering boundary to an
  absolute offset. It reports regions that trigger on their own and can miss
  full-context or boundary-straddling signatures; confirm with `Invoke-OffsetThreatScan`.
- New cross-platform static-triage commands: `Get-OffsetEntropy` (per-window Shannon
  entropy to locate packed/encrypted regions), `Get-OffsetString` (ASCII and UTF-16LE
  strings with byte offsets), and `Get-OffsetPEInfo` (PE machine/bitness, entry point,
  section table, imports and imphash, appended-overlay detection, resource-directory
  size, and `-Offset` mapping a byte offset to its section).
- New command `Invoke-OffsetYaraScan` runs the YARA engine against a file with
  analyst-authored rules and returns each match with its byte offset (rule, string id,
  offset, matched data), feeding offsets into `Invoke-OffsetInspect`. Requires the YARA
  engine on PATH (for example `winget install VirusTotal.YARA`); it is resolved
  automatically or via `-YaraPath`.
- New command `Get-OffsetIOC` returns a consolidated indicator panel for a file
  (MD5/SHA-1/SHA-256 computed in a single pass, size, overall entropy, printable-string
  count, and PE machine/imphash/overlay when applicable). `Export-OffsetThreatReport
  -IncludeIoc` folds this panel into each report entry.
- New command `Invoke-OffsetClamScan` scans a file with the ClamAV on-demand engine and
  returns a normalized result (Clean/Detected/Error plus signature name). It is a
  single-file detector, not a boundary-search provider - clamscan loads its full signature
  database per invocation, so bisection would require the clamd daemon. Requires ClamAV
  installed with databases (`winget install Cisco.ClamAV`, then `freshclam`).

### Changed

- The boundary-search memoisation cache is now a
  `System.Collections.Concurrent.ConcurrentDictionary`, removing one blocker to a
  future parallel probing mode. Probing itself remains sequential (see
  `docs/PROVIDER-INTERFACE.md` §4).
- `Get-OffsetEntropy` now computes its byte-frequency pass in a compiled .NET helper
  (~95x faster on large inputs, identical results), falling back to the pure-PowerShell
  computation if the helper cannot be compiled.

### Notes

- No changes to the AMSI or Defender provider behaviour, boundary semantics, or
  output schema field meanings; `ProbeLog`/`ProbeCount` are additive.

## [2.0.0] - 2026-07-10

### Added

- `Invoke-OffsetThreatScan` with independently implemented AMSI and Microsoft Defender providers.
- Lower-bound prefix search with explicit clean, detected, blocked, timeout, indeterminate, and error states.
- Repeatability checks and `Stable`/`Confidence` output for detection boundaries.
- Automatic boundary enrichment through `Invoke-OffsetInspect`.
- Human, object, JSON, CSV, and CSV-file output modes with stable schemas.
- UTF-8, UTF-16LE, UTF-16BE, ASCII, host-default, and BOM-aware auto encoding modes.
- Source context through `-ContextLines` and bounded long-line previews through `-MaxLineBytes`.
- Binary comparison through `-CompareFile`.
- Isolated package tests, PSScriptAnalyzer, Pester, dependency review, and release publishing workflows.
- Deterministic module packaging with SHA-256 checksum generation.
- A reproducible benchmark harness for batched offset-inspection measurements.

### Changed

- Rebuilt the project as a self-contained PowerShell Gallery module.
- Grouped requests by file and replaced per-offset whole-file reads with one streaming line-mapping pass plus bounded range reads.
- Replaced all-record-per-line scans with current-line and bounded pending-context queues for large offset batches.
- Reused one source buffer for AMSI raw-byte scans and one source stream for Defender prefix scans.
- Defined unprefixed numeric offsets as decimal; hexadecimal may use `0x`, `0X`, an `h` suffix, or A-F characters.
- JSON inspection output now always uses an array shape, including for one result.
- Repository-root scripts are thin CLI adapters; module commands never terminate the caller with `exit`.

### Fixed

- PowerShell Gallery installations no longer depend on a script outside the published module directory.
- `ContextLines` now returns actual previous and following source lines.
- UTF-8 and UTF-16 byte offsets map correctly to character positions, including offsets inside multibyte code units.
- BOM handling is consistent in automatic and explicitly selected Unicode encodings.
- Compare files are opened once instead of reread for every result.
- AMSI malware-range and administrator-policy results are classified separately.
- Provider failures and timeouts can no longer be interpreted as clean or detected results.
- Temporary Defender scan workspaces are cleaned up in a `finally` path and cleanup failures are surfaced.

### Security

- Threat scanning does not create exclusions, disable protection, change Defender preferences, or request remediation.
- The release package rejects executable, debug, IDE, and build artifacts.
- Signing automation now accepts only a valid Authenticode result.

### Breaking changes

- Consumers relying on v1 internals must use the exported module commands instead of dot-sourcing implementation files.
- Numeric-only offset strings are decimal by design.
- JSON output uses a stable array contract.

## [1.0.2] - 2026-06-24

### Improved

- Refined PowerShell module path resolution.
- Simplified module wrapper implementation.
- Improved module loading consistency.

## [1.0.1] - 2025-12-29

### Added

- Multi-file inspection support.
- Matching offsets for multiple files.
- Sequential output blocks per file.

### Improved

- Centralized offset parsing.
- Improved validation and error messaging.
- Non-zero exit behavior for automation.
