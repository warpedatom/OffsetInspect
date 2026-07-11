# Changelog

All notable changes to OffsetInspect are documented in this file. The project follows semantic versioning.

## [Unreleased]

### Planned

- Additional provider adapters after the v2 provider contract has received field testing.
- Published benchmark baselines for representative text and binary corpora.

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
