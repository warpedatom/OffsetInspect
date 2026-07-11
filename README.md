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

Version 2.0 also adds an OffsetInspect-native detection-boundary workflow inspired by the same analyst problem addressed by ThreatCheck, without bundling its source or binaries. It can locate the earliest content prefix that remains detected by AMSI or Microsoft Defender, validate the boundary repeatedly, and feed the resulting offset directly into the normal context inspector.

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
- Never changes Defender exclusions, real-time protection, or system security configuration.
- Ships as a self-contained PowerShell Gallery package.

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

See [Threat scanning design](./docs/THREAT-SCANNING.md) for the provider contract and interpretation guidance, [threat-scanning provenance](./docs/PROVENANCE.md) for implementation boundaries and attribution, and [output schema](./docs/OUTPUT-SCHEMA.md) for the versioned object contract.

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
