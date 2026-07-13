# Changelog

All notable changes to OffsetInspect are documented in this file. The project follows semantic versioning.

## [Unreleased]

### Planned

- Additional provider adapters after the v2 provider contract has received field testing.
- Published benchmark baselines for representative text and binary corpora.

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
