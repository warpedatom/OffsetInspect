<p align="center">
  <img src="./assets/Dread-Host-Banner.png" alt="Dread Host Banner" width="800">
</p>

<p align="center">
  <a href="https://github.com/warpedatom/OffsetInspect/releases">
    <img src="https://img.shields.io/github/v/release/warpedatom/OffsetInspect" alt="Release">
  </a>
  <a href="./LICENSE">
    <img src="https://img.shields.io/github/license/warpedatom/OffsetInspect" alt="License">
  </a>
  <img src="https://img.shields.io/badge/PowerShell-5.1%2F7.x-blue" alt="PowerShell Support">
  <img src="https://img.shields.io/badge/Platform-Windows-lightgrey" alt="Platform">
  <img src="https://img.shields.io/github/repo-size/warpedatom/OffsetInspect" alt="Repo Size">
  <img src="https://img.shields.io/github/last-commit/warpedatom/OffsetInspect" alt="Last Commit">
  <img src="https://img.shields.io/github/actions/workflow/status/warpedatom/OffsetInspect/ci.yml?branch=main&label=CI" alt="CI Status">
  <img src="https://img.shields.io/badge/Security-Policy-green" alt="Security Policy">
  <img src="https://img.shields.io/badge/Use-Red%20Team-darkred" alt="Use Case">
</p>

---

# OffsetInspect

**PowerShell-based offset inspection utility for malware analysis, detection engineering, reverse engineering, and red team research.**

OffsetInspect maps raw byte offsets back to meaningful source code and binary context, helping analysts quickly determine what exists at a reported detection location.

---

## Screenshot

![OffsetInspect Screenshot](./assets/OffsetInspectScreen.png)

---

## Overview

OffsetInspect is a lightweight PowerShell-based hex-context inspection utility designed for red team operators, malware analysts, detection engineers, and security researchers who require precise insight into file offsets.

It functions as a terminal-native, HxD-inspired viewer that:

* Highlights the byte located at a specified offset
* Displays surrounding context bytes
* Maps raw offsets back to file line numbers
* Shows aligned ASCII representations
* Positions a caret indicating the approximate character location within a source line
* Provides configurable context window sizes
* Supports inspection across multiple files

OffsetInspect is intended for fast, accurate validation of static indicators during offensive security operations, malware analysis, and detection research.

---

## Why OffsetInspect Exists

During red team operations and detection engineering, analysts frequently encounter detections that reference raw byte offsets rather than readable source context.

GUI hex editors provide visibility, but they often lack:

* Scriptability
* Repeatability
* Terminal-first workflows
* Fast offset-to-line correlation

OffsetInspect bridges this gap by enabling operators to quickly answer a critical question:

> What is actually at this offset?

The tool is deliberately scoped to inspection and validation, allowing analysts to correlate byte-level indicators back to meaningful source constructs without abstraction or side effects.

---

## Real-World Security Workflow

OffsetInspect is commonly used when:

* Microsoft Defender reports a byte offset
* A YARA rule triggers on a binary
* A static AV detection references a specific location
* An obfuscation change shifts offsets
* A payload requires validation after modification
* Detection engineers need to understand exactly what triggered an alert

Instead of manually opening a hex editor and searching for a location, OffsetInspect provides terminal-native inspection and source correlation.

---

## Features

* Exact byte highlighting at user-specified offsets
* Mapping of raw offsets to file line numbers
* Multi-file inspection support
* Configurable byte window size
* Structured hex + ASCII output
* Color-coded terminal rendering
* Read-only operation
* No external dependencies
* Windows PowerShell 5.1 support
* PowerShell 7.x support

---

## Installation

### Clone Repository

```powershell
git clone https://github.com/warpedatom/OffsetInspect.git
cd OffsetInspect
```

### Latest Release

Download the latest version here:

[Latest Release](https://github.com/warpedatom/OffsetInspect/releases/latest)

---

## Integrity Verification

All releases include an automatically generated checksum file.

Verify a downloaded release using:

```powershell
Get-FileHash -Algorithm SHA256 .\OffsetInspect.ps1
```

---

## PowerShell Script Usage

Basic example:

```powershell
.\OffsetInspect.ps1 C:\AD\PowerView.ps1 0xE1AB1
```

Decimal offset example:

```powershell
.\OffsetInspect.ps1 payload.bin 1024
```

Adjust byte window size:

```powershell
.\OffsetInspect.ps1 file.bin 0x200 -ByteWindow 64
```

Inspect multiple files:

```powershell
.\OffsetInspect.ps1 `
    -FilePaths file1.bin,file2.bin `
    -OffsetInputs 0x100
```

---

## PowerShell Module Usage

Import the module:

```powershell
Import-Module ./module/OffsetInspect.psm1
```

Run inspection through the module:

```powershell
Invoke-OffsetInspect `
    -FilePaths C:\AD\PowerView.ps1 `
    -OffsetInputs 0xE1AB1
```

---

## Output Explanation

### File Information

```text
File:              C:\AD\PowerView.ps1
Offset (input):    0xE1AB1
Offset (decimal):  924337
File Size:         924339 bytes
Line Number:       24810
```

Displays:

* File metadata
* Normalized offset values
* Decimal conversion
* File size
* Source line correlation

---

### Line Content Preview

```text
Line 24810: Set-Alias Get-DomainPolicy Get-DomainPolicyData
                       ^
```

Displays:

* The source line containing the target byte
* Approximate byte-to-character position
* Immediate source context

> Note: Offsets are byte-based while source lines are character-based. The caret represents a best-effort positional mapping.

---

### Hex Dump

```text
000E1A91  6F 6D 61 69 6E 50 6F 6C 69 63 79 20 47 65 74 2D   omainPolicy Get-
000E1AA1  44 6F 6D 61 69 6E 50 6F 6C 69 63 79 44 61 74 61   DomainPolicyData
000E1AB1  0D 0A                                                ..
```

Displays:

* Contextual hex dump centered on the target offset
* Eight-digit hexadecimal addresses
* Highlighted target byte
* ASCII representation
* Aligned terminal output

---

## Detection Engineering & Research

OffsetInspect supports workflows where precision matters more than automation.

Common scenarios include:

* Investigating static detections referencing byte offsets
* Validating offset drift after obfuscation or packing
* Identifying which semantic construct triggers detection
* Performing targeted modifications instead of blind mutation
* Comparing detection behavior across payload revisions

This enables operators to preserve functionality while testing detection resilience.

---

## Workflow Reference

For a complete static detection and obfuscation workflow:

[PowerView Static Detection & Obfuscation Workflow](./docs/PowerView-Static-Detection-Analysis-and-Obfuscation-Workflow.pdf)

---

## Design Philosophy

OffsetInspect is intentionally:

* Terminal-native
* Read-only
* Dependency-free
* Lightweight
* Scriptable
* Focused on accuracy over abstraction

It is designed to complement existing tooling such as:

* YARA
* Static AV/EDR detections
* Obfuscators
* Packers
* Reverse engineering workflows

---

## Future Roadmap

Planned enhancements under consideration:

* JSON output mode
* CSV export support
* Improved Unicode handling
* Binary diff support
* Offset range analysis
* Pipeline-friendly structured output
* PowerShell Gallery publication

---

## Testing

Run the Pester test suite from the repository root:

```powershell
Invoke-Pester ./tests/OffsetInspect.Tests.ps1
```

---

## Project Status

OffsetInspect is actively maintained and intended for authorized security research, malware analysis, detection engineering, and red team operations.

Community feedback, bug reports, and pull requests are welcome.

---

## Disclaimer

This tool is intended for authorized security testing, research, and educational purposes only.

The author assumes no responsibility for misuse, unauthorized activity, or policy violations.

---

## License

OffsetInspect is released under the MIT License.

Attribution is appreciated but not required.

---

<p align="center">
  <sub>© 2026 Velkris — Educational Red Team Research | MIT Licensed</sub><br>
  <sub>All testing conducted in isolated lab environments for research and training purposes only.</sub>
</p>
