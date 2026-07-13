<p align="center">
  <img src="./assets/Dread-Host-Banner.png" alt="Dread Host Research" width="800">
</p>

<p align="center">
  <a href="https://github.com/warpedatom/OffsetInspect/releases"><img src="https://img.shields.io/github/v/release/warpedatom/OffsetInspect" alt="Release"></a>
  <a href="./LICENSE"><img src="https://img.shields.io/github/license/warpedatom/OffsetInspect" alt="License"></a>
  <img src="https://img.shields.io/badge/PowerShell-5.1%20%7C%207.x-5391FE" alt="PowerShell 5.1 and 7.x">
  <img src="https://img.shields.io/badge/Core-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey" alt="Cross-platform core">
  <img src="https://img.shields.io/badge/Threat%20Providers-Windows-0078D4" alt="Windows threat providers">
  <img src="https://img.shields.io/github/actions/workflow/status/warpedatom/OffsetInspect/ci.yml?branch=main&label=CI" alt="CI">
  <a href="./SECURITY.md"><img src="https://img.shields.io/badge/Security-Policy-green" alt="Security policy"></a>
</p>

# OffsetInspect

**A bounded-memory PowerShell toolkit for byte-offset inspection, source correlation, binary comparison, and defensive detection-boundary analysis.**

OffsetInspect answers a practical analyst question:

> What content is present at this byte offset, and what source or binary context surrounds it?

It also provides an OffsetInspect-native detection-boundary workflow inspired by the same analyst problem addressed by ThreatCheck, without bundling its source or binaries: it locates the earliest content prefix that AMSI or Microsoft Defender still detects, validates the boundary repeatedly, and feeds the resulting offset straight into the context inspector. On top of that core, it adds a red-team analysis and static-triage suite — multi-region discovery, corpus scanning, detection diffing, engagement reports, entropy analysis, string extraction, and PE/imphash parsing — all read-only, and without ever disabling or reconfiguring endpoint protection.

## Highlights

- Opens each unique inspection file through a stable read handle and processes all requested offsets together.
- Uses a bounded-memory streaming pass for line mapping instead of rereading the complete file for every offset.
- Reads only the requested byte windows for hex output and comparison.
- Maps UTF-8 and UTF-16 byte offsets to source lines and character positions.
- Implements previous and following source context through `-ContextLines`.
- Supports human, object, JSON, CSV, and CSV-file output contracts.
- Supports one-to-many, many-to-one, and paired file/offset plans.
- Compares the target byte against a second file without repeatedly loading that file.
- Adds an independently implemented AMSI and Microsoft Defender provider layer with explicit error, timeout, blocked, and indeterminate states.
- Records a per-probe audit trail (`ProbeLog`/`ProbeCount`) of every distinct provider invocation, streamed live to `-Verbose`, for a report-ready transcript of a scan's true provider cost.
- Discovers multiple independently-detectable regions in one file via in-memory AMSI scanning (nothing detected is written to disk) and maps each boundary to an absolute offset.
- Scans a corpus into a consolidated detection matrix, diffs detection between two scans, and exports Markdown/HTML engagement reports.
- Adds static malware-triage helpers: per-window entropy (packed/encrypted regions), ASCII/UTF-16LE string extraction with offsets, and PE header/section/import parsing with imphash and overlay detection.
- Never changes Defender exclusions, real-time protection, or system security configuration.
- Ships as a self-contained PowerShell Gallery package with no external runtime dependencies (YARA scanning is the one optional exception, requiring the YARA engine).

## Commands

| Command | Purpose | Platform |
|---|---|---|
| `Invoke-OffsetInspect` | Map byte offsets to source/binary context, hex, and comparison | Cross-platform |
| `Invoke-OffsetThreatScan` | AMSI/Defender detection-boundary search for one file | Windows |
| `Invoke-OffsetThreatScanBatch` | Scan a corpus of files; `-Summary` returns a detection matrix | Windows |
| `Invoke-OffsetThreatScanRegion` | Multi-region discovery via in-memory AMSI (no disk writes) | Windows |
| `Compare-OffsetThreatResult` | Diff two scan results (e.g. across signature-definition updates) | Cross-platform |
| `Export-OffsetThreatReport` | Render scan results into a Markdown/HTML engagement report | Cross-platform |
| `Invoke-OffsetYaraScan` | Match a file against YARA rules; return hits with byte offsets | Cross-platform¹ |
| `Invoke-OffsetClamScan` | Scan a file with the ClamAV engine; normalized detection result | Cross-platform¹ |
| `Get-OffsetEntropy` | Per-window Shannon entropy to locate packed/encrypted regions | Cross-platform |
| `Get-OffsetString` | Extract ASCII/UTF-16LE strings with byte offsets | Cross-platform |
| `Get-OffsetPEInfo` | PE headers, sections, imports/imphash, overlay, offset→section | Cross-platform |
| `Get-OffsetIOC` | Consolidated indicator panel: hashes, entropy, PE/imphash, strings | Cross-platform |

¹ These two commands have optional external dependencies: `Invoke-OffsetYaraScan` needs the YARA engine (`winget install VirusTotal.YARA`), and `Invoke-OffsetClamScan` needs ClamAV with signature databases (`winget install Cisco.ClamAV`, then `freshclam`). Every other command is self-contained. ClamAV is a single-file detector here, not a boundary-search engine — `clamscan` loads its full database per invocation, so bisection would require the `clamd` daemon.

The offset-inspection core and all static-triage helpers are cross-platform (Windows, Linux, macOS); the AMSI/Defender threat providers are Windows-only.

## Installation

### PowerShell Gallery

```powershell
Install-Module OffsetInspect -Scope CurrentUser
Import-Module OffsetInspect
```

### Repository checkout

```powershell
git clone https://github.com/warpedatom/OffsetInspect.git
cd OffsetInspect
Import-Module ./module/OffsetInspect/OffsetInspect.psd1 -Force
```

The repository also includes thin CLI wrappers:

```powershell
./OffsetInspect.ps1 <file> <offset>
./OffsetThreatScan.ps1 <file> -Engine AMSI
```

## Offset inspection

### Human-readable output

```powershell
Invoke-OffsetInspect ./sample.bin 0x200
```

```powershell
$inspectParameters = @{
    FilePaths    = './script.ps1'
    OffsetInputs = 128, 256, 512
    ByteWindow   = 64
    ContextLines = 4
}
Invoke-OffsetInspect @inspectParameters
```

### Structured objects

```powershell
$inspectParameters = @{
    FilePaths    = './script.ps1'
    OffsetInputs = 0x80, 0x100
    PassThru     = $true
}
$results = Invoke-OffsetInspect @inspectParameters

$results | Where-Object BytesDiffer
```

### JSON and CSV

```powershell
Invoke-OffsetInspect ./sample.bin 0x200 -Json
Invoke-OffsetInspect ./sample.bin 0x200 -Csv
Invoke-OffsetInspect ./sample.bin 0x200 -CsvPath ./artifacts/offsets.csv
```

JSON mode always emits an array, including for a single result.

### Binary comparison

```powershell
$compareParameters = @{
    FilePaths    = './before.bin'
    OffsetInputs = 0x200
    CompareFile  = './after.bin'
    PassThru     = $true
}
Invoke-OffsetInspect @compareParameters
```

### Offset formats

| Input | Interpretation |
|---|---:|
| `512` | Decimal 512 |
| `0x200` or `0X200` | Hexadecimal 0x200 |
| `200h` | Hexadecimal 0x200 |
| `E1AB1` | Unprefixed hexadecimal because it contains A-F |

Numeric-only values without a prefix or suffix are intentionally treated as decimal.

### Encoding modes

| Mode | Behavior |
|---|---|
| `Auto` | Detects UTF-8/UTF-16 BOMs; otherwise uses UTF-8 |
| `Default` | Uses the host operating system default encoding |
| `UTF8` | UTF-8 source mapping |
| `UTF16LE` | Little-endian UTF-16 source mapping |
| `UTF16BE` | Big-endian UTF-16 source mapping |
| `ASCII` | ASCII source mapping |

The output reports both `BytePositionInLine` and `CharacterPosition`. This distinction matters when a source file contains multibyte characters.

## Threat boundary analysis

Threat-provider analysis is Windows-only. The normal offset inspection command remains cross-platform.

### AMSI text scan

```powershell
$scanParameters = @{
    FilePath    = './script.ps1'
    Engine      = 'AMSI'
    ScanMode    = 'Text'
    RepeatCount = 3
    PassThru    = $true
}
$result = Invoke-OffsetThreatScan @scanParameters
```

Text mode uses `AmsiScanString`, searches Unicode-scalar prefixes without splitting surrogate pairs, maps the detected prefix through the validated source encoding, and returns Unicode-scalar, UTF-16 code-unit, and source-file byte indexes. Embedded NUL characters are rejected in text mode; use raw-byte mode for those files.

### AMSI raw-byte scan

```powershell
Invoke-OffsetThreatScan ./content.bin -Engine AMSI -ScanMode RawBytes
```

### Microsoft Defender scan

```powershell
$scanParameters = @{
    FilePath       = './sample.bin'
    Engine         = 'Defender'
    RepeatCount    = 3
    TimeoutSeconds = 45
}
Invoke-OffsetThreatScan @scanParameters
```

The Defender provider:

- Resolves the newest installed `MpCmdRun.exe` platform path.
- Writes prefixes to a unique user temporary directory.
- Uses a custom scan with `-DisableRemediation`.
- Treats timeouts, provider errors, localized/unknown output, and ambiguous markers as non-definitive.
- Deletes the temporary workspace when scanning completes.

### Boundary semantics

A result such as `DetectionPrefixLength = 841` means:

- Prefix length 840 was classified as clean/not detected.
- Prefix length 841 was classified as detected/blocked.
- Repeated checks determine whether that transition is stable.

It does **not** prove that byte 840 is the complete signature, the only contributing byte, or the full malicious range. Antivirus decisions may depend on tokenization, surrounding context, file type, provider state, and signature updates.

See [Threat scanning design](./docs/THREAT-SCANNING.md) for the provider contract and interpretation guidance, [provider interface](./docs/PROVIDER-INTERFACE.md) for the scanner contract and how to add a provider without touching the search core, [threat-scanning provenance](./docs/PROVENANCE.md) for implementation boundaries and attribution, and [output schema](./docs/OUTPUT-SCHEMA.md) for the versioned object contract.

### Detection-boundary reports

`Export-OffsetThreatReport` turns one or more scan results into a self-contained Markdown or HTML report — per-file summary, provider/signature/engine metadata, the full `ProbeLog` audit trail, and warnings — for attaching to an engagement writeup. It reads results only and never re-scans, so it runs cross-platform. Add `-IncludeIoc` to fold a hash/entropy/PE indicator panel (the same data as `Get-OffsetIOC`) into each report entry.

```powershell
Invoke-OffsetThreatScan ./sample.ps1 -Engine AMSI -ScanMode Text -PassThru |
    Export-OffsetThreatReport -Path ./report.html -Format Html

# Aggregate many scans into one report, with an indicators panel per file:
$results | Export-OffsetThreatReport -Path ./engagement.md -IncludeIoc
```

### Batch / corpus scanning

`Invoke-OffsetThreatScanBatch` expands files, directories, and wildcards into a file list, scans each (continuing past per-file failures), and returns one result per file. `-Summary` returns a flattened detection matrix; the full results pipe straight into the report generator. Provider scanning is Windows-only.

```powershell
Invoke-OffsetThreatScanBatch ./payloads -Recurse -Engine AMSI |
    Export-OffsetThreatReport -Path ./engagement.html -Format Html

Invoke-OffsetThreatScanBatch ./samples -Summary |
    Format-Table File, DetectionPrefixLength, Confidence, ProbeCount
```

### Detection diff / regression

`Compare-OffsetThreatResult` diffs two scan results — for example the same file before and after a signature-definition update — and classifies the change (`NewlyDetected`, `NoLongerDetected`, `BoundaryEarlier`, `BoundaryLater`, `BoundaryUnchanged`, `BothClean`) with the boundary delta and changed fields.

```powershell
$before = Invoke-OffsetThreatScan ./sample.ps1 -Engine Defender -PassThru
# ... update Defender signature definitions ...
$after  = Invoke-OffsetThreatScan ./sample.ps1 -Engine Defender -PassThru
Compare-OffsetThreatResult -Reference $before -Difference $after
```

### Multi-region discovery

The prefix search finds the *first* detection boundary. `Invoke-OffsetThreatScanRegion` finds *multiple* independently-detectable regions by splitting the file into segments and scanning each in isolation through AMSI **entirely in memory** — nothing detected is written to disk, so Defender real-time protection is never triggered or reconfigured. Each hit is bisected within its segment to map the exact triggering boundary to an absolute file offset.

```powershell
Invoke-OffsetThreatScanRegion ./payload.bin -SegmentCount 16 |
    Select-Object -ExpandProperty DetectedRegions |
    Format-Table SegmentIndex, StartOffset, EndOffset, AbsoluteBoundaryOffset, SignatureName
```

This reports regions that trigger on their own; it can miss signatures that only fire in full-file context or that straddle a segment boundary, so treat the regions as leads to confirm with `Invoke-OffsetThreatScan` and manual validation. AMSI (in-memory) is the only engine supported here — Defender file scanning would require writing detected content to disk.

## Static triage helpers

Three cross-platform static-analysis commands support malware triage and compose with the offset core:

- `Get-OffsetEntropy` — per-window Shannon entropy (bits/byte) to locate packed or encrypted regions; cross-reference the flagged windows with `Invoke-OffsetThreatScanRegion` detections.
- `Get-OffsetString` — printable ASCII and UTF-16LE strings with byte offsets; pipe offsets into `Invoke-OffsetInspect` for context.
- `Get-OffsetPEInfo` — PE machine/bitness, entry point, section table, **imports and imphash**, appended-**overlay** detection, and resource size, with `-Offset` mapping a byte offset to its section (`.text`, `.rsrc`, ...). Imphash uses the standard `library.function` MD5; ordinal-only imports render as `ordNNN` (special-library ordinal resolution is not applied, so ordinal-heavy imphashes may differ from pefile's).
- `Get-OffsetIOC` — one-shot indicator panel combining the above: MD5/SHA-1/SHA-256 (single-pass), overall entropy, printable-string count, and PE machine/imphash/overlay when applicable.

```powershell
Get-OffsetEntropy ./sample.bin -HighOnly | Select-Object -ExpandProperty Windows
Get-OffsetString ./sample.bin -MinimumLength 6 | Where-Object Value -match 'http|\.dll'
Get-OffsetPEInfo ./sample.exe | Select-Object Machine, EntryPointHex, ImpHash, ImportedDllCount, HasOverlay, OverlaySize
Get-OffsetIOC ./sample.exe | Format-List
```

### YARA scanning

`Invoke-OffsetYaraScan` runs analyst-authored YARA rules and returns each match with its byte offset — complementing the AMSI/Defender detection-boundary view with signatures you control, and needing no antivirus installed (only the YARA engine, e.g. `winget install VirusTotal.YARA`). Offsets feed straight into the inspector.

```powershell
Invoke-OffsetYaraScan ./sample.bin -RulePath ./rules/malware.yar |
    ForEach-Object { Invoke-OffsetInspect $_.File $_.Offset -ContextLines 2 }
```

### ClamAV scanning

`Invoke-OffsetClamScan` scans a file with the ClamAV on-demand engine and returns a normalized result (`Clean` / `Detected` / `Error`, plus the signature name). Because `clamscan` loads its full signature database on every call, it is a single-file detector, not a boundary-search engine (that would require the `clamd` daemon). It needs ClamAV installed **and** its signature databases downloaded — `freshclam` will not run until a config file exists:

```powershell
# One-time setup: create the freshclam config (remove the sample's "Example" line), then fetch databases.
Copy-Item "$env:ProgramFiles\ClamAV\conf_examples\freshclam.conf.sample" "$env:ProgramFiles\ClamAV\freshclam.conf"
(Get-Content "$env:ProgramFiles\ClamAV\freshclam.conf") -notmatch '^\s*Example\s*$' |
    Set-Content "$env:ProgramFiles\ClamAV\freshclam.conf"   # requires admin to write under Program Files
& "$env:ProgramFiles\ClamAV\freshclam.exe"

Invoke-OffsetClamScan ./sample.bin
```

Use `-DatabasePath` to point at a signature directory in a writable (non-admin) location, and `-ClamScanPath` if `clamscan` is not on `PATH`.

## Result objects

`Invoke-OffsetInspect -PassThru` returns `OffsetInspect.Result` objects containing:

- Canonical file path, file size, decimal and hexadecimal offsets.
- Requested and detected encoding.
- Line number, source preview, context lines, byte position, and character position.
- Target byte and bounded hex dump.
- Optional comparison byte and difference state.
- Warnings, duration, success state, and error message.

`Invoke-OffsetThreatScan -PassThru` returns `OffsetInspect.ThreatScanResult` objects containing:

- File SHA-256, UTC scan timestamp, engine, scan mode, initial provider status, and provider metadata.
- Known-clean and known-detected prefix lengths.
- Byte and optional character boundary.
- Stability, confidence, scan count, repeated boundary statuses, and signature name when available.
- A `ProbeLog` audit trail of every distinct provider probe (surfaced as `ProbeCount` in CSV output, and exportable to a JSON transcript with `-ProbeLogPath`); see [output schema](./docs/OUTPUT-SCHEMA.md).
- Nested `OffsetInspect.Result` context at the mapped boundary.

## Performance model

The v1-style implementation reread and decoded a complete file for every offset. Version 2 groups work by file:

```text
Previous approach: approximately O(file size × offset count)
Version 2:         approximately O(file bytes scanned once + requested windows)
```

Source mapping uses a streaming state machine and retains only the previous/following line descriptors required for requested offsets. Extremely long individual lines are displayed through a bounded preview controlled by `-MaxLineBytes`.

## Repository layout

```text
OffsetInspect.ps1                 Thin offset-inspection CLI wrapper
OffsetThreatScan.ps1              Thin threat-scan CLI wrapper
module/OffsetInspect/             Complete Gallery package
  OffsetInspect.psd1
  OffsetInspect.psm1
  OffsetInspect.Format.ps1xml
  Public/
  Private/
tests/                            Pester tests
benchmarks/                       Reproducible performance harness
build/                            Validation, packaging, signing, publishing
.github/workflows/                CI, dependency review, release publishing
docs/                             Architecture, schemas, provider design, release checklist
```

## Development

Install the pinned validation tools:

```powershell
Install-Module Pester -RequiredVersion 5.7.1 -Scope CurrentUser
Install-Module PSScriptAnalyzer -RequiredVersion 1.25.0 -Scope CurrentUser
```

Run the complete local gate:

```powershell
./build/Test-Module.ps1
```

Run the deterministic benchmark harness:

```powershell
./benchmarks/Measure-OffsetInspect.ps1 -FileSizeMiB 64 -OffsetCount 5000
```

Benchmark results vary by storage, host load, PowerShell edition, and file shape. Record those inputs when comparing commits.

Build a deterministic release archive and SHA-256 file:

```powershell
./build/New-ReleasePackage.ps1
```

CI validates PowerShell 7 on Windows and Linux, Windows PowerShell 5.1, PSScriptAnalyzer, isolated module packaging, and the release archive. Release maintainers should also follow the [release checklist](./docs/RELEASE-CHECKLIST.md).

## Security and responsible use

OffsetInspect is intended for authorized defensive research, detection engineering, reverse engineering, malware analysis, and security testing. Threat-provider functions analyze content but do not disable, bypass, or reconfigure endpoint protections.

Review [SECURITY.md](./SECURITY.md) before reporting a vulnerability. Do not submit sensitive samples through public GitHub issues.

## License

OffsetInspect is released under the [MIT License](./LICENSE).
