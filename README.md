---

![Dread-Host-Banner](./assets/Dread-Host-Banner.png)

![Release](https://img.shields.io/github/v/release/warpedatom/OffsetInspect)
![License](https://img.shields.io/github/license/warpedatom/OffsetInspect)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2F7.x-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)
![Repo Size](https://img.shields.io/github/repo-size/warpedatom/OffsetInspect)
![Last Commit](https://img.shields.io/github/last-commit/warpedatom/OffsetInspect)
![Security Policy](https://img.shields.io/badge/Security-Policy-green)
![Use Case](https://img.shields.io/badge/Use-Red%20Team-darkred)

# OffsetInspect

---

## Overview

OffsetInspect is a lightweight PowerShell-based hex-context inspection utility designed for red team operators, malware analysts, and security researchers who require precise insight into file offsets.

It functions as a terminal-native, HxD-inspired viewer that:

- Highlights the byte located at a specified offset  
- Displays surrounding context bytes  
- Maps raw offsets back to file line numbers  
- Shows aligned ASCII representations  
- Positions a caret indicating the **approximate** character location within a source line  
- Provides configurable context window sizes  

OffsetInspect is intended for fast, accurate validation of static indicators during offensive security operations and detection research.

---

## Why OffsetInspect Exists

During red team operations and detection engineering, analysts frequently encounter detections that reference **raw byte offsets** rather than readable source context.

GUI hex editors provide visibility, but they often lack:
- Scriptability
- Repeatability
- Terminal-first workflows
- Fast offset-to-line correlation

OffsetInspect bridges this gap by enabling operators to quickly answer a critical question:

> *What is actually at this offset?*

The tool is deliberately scoped to inspection and validation, allowing analysts to correlate byte-level indicators back to meaningful source constructs without abstraction or side effects.

---

## Features

- Exact byte highlighting at user-specified offsets  
- Mapping of raw offsets to file line numbers
- Check multiple files at once  
- Configurable byte window size  
- Structured hex + ASCII output  
- Color-coded terminal rendering for clarity  
- Read-only operation with no external dependencies  
- Compatible with Windows PowerShell 5.1 and PowerShell 7  

---

## Screenshot

![OffsetInspect Screenshot](./assets/OffsetInspectScreen.png)

---

## Download the Latest Release

https://github.com/warpedatom/OffsetInspect/releases/latest

---

## Installation

Clone the repository:

```powershell
git clone https://github.com/warpedatom/OffsetInspect.git
cd OffsetInspect
```

---

## Integrity Verification

All releases include an automatically generated checksums.txt file created by GitHub Actions.

Verify using:
```powershell
Get-FileHash -Algorithm SHA256 .\OffsetInspect.ps1
```

---

Run
```powershell
.\OffsetInspect.ps1 <FilePath> <Offset>
```

---

## PowerShell Script Usage

Basic Example:
```powershell
.\OffsetInspect.ps1 C:\AD\PowerView.ps1 0xE1AB1
```

Decimal Offset Example:
```powershell
.\OffsetInspect.ps1 payload.bin 1024
```
Adjust Byte Window Size:
```powershell
.\OffsetInspect.ps1 file.bin 0x200 -ByteWindow 64
```

---

## PowerShell Module Usage

OffsetInspect can also be used as an importable module:
```powershell
Import-Module ./module/OffsetInspect.psm1
```
Invoke-OffsetInspect -FilePath C:\AD\PowerView.ps1 -OffsetInput 0xE1AB1

---

## Output Explanation

File Information

```powershell
File:              C:\AD\PowerView.ps1
Offset (input):    0xE1AB1
Offset (decimal):  924337
File Size:         924339 bytes
Line Number:       24810
```
- Displays metadata for the inspected file

- Normalizes and converts the provided offset

- Maps the raw byte offset back to a source line

---

## Line Content Preview
```powershell
Line 24810: Set-Alias Get-DomainPolicy Get-DomainPolicyData
                       ^
```
- Prints the full source line containing the target byte

- The caret indicates the approximate character position corresponding to the offset

- Useful for quickly identifying affected strings, aliases, or instructions


> Note: Offsets are byte-based while source lines are character-based. The caret represents a best-effort positional mapping.

---

```powershell
Hex Dump

000E1A91  6F 6D 61 69 6E 50 6F 6C 69 63 79 20 47 65 74 2D   omainPolicy Get-
000E1AA1  44 6F 6D 61 69 6E 50 6F 6C 69 63 79 44 61 74 61   DomainPolicyData
000E1AB1  0D 0A                                                ..
```
- Contextual hex dump centered around the inspected offset

- Offsets displayed as eight-digit hexadecimal values

- Target byte is visually highlighted in supported terminals

- Surrounding bytes rendered in a secondary color

- ASCII output aligned to the right for readability


---

## Intended Use Cases

OffsetInspect is well suited for:

- Red team operations
- Malware analysis and reverse engineering
- Script and payload debugging
- Identifying offset-based indicators
- Inspecting PE, binary, shellcode, PowerShell, or encoded data
- Forensic analysis of embedded byte sequences
- Low-level troubleshooting during security research

---

## Detection & Adversary Simulation Use

OffsetInspect supports workflows where precision matters more than automation.

Common scenarios include:

- Investigating static detections referencing byte offsets
- Validating offset drift after obfuscation or packing
- Identifying which semantic construct triggers detection
- Performing targeted modifications rather than blind mutation


This enables operators to preserve functionality while testing detection resilience.

---

## Design Philosophy

OffsetInspect is intentionally:

- Terminal-native
- Read-only
- Dependency-free
- Focused on accuracy over abstraction


It is designed to complement existing tooling such as:

- YARA rules
- Static AV/EDR detections
- Obfuscators and packers
- Reverse engineering workflows

---

## Future Work / Roadmap

Planned enhancements under consideration:

- Support for inspecting multiple offsets in a single invocation
- Offset range diffing between two files
- Improved handling of non-ASCII encodings
- Optional structured output (JSON) for pipeline integration
- Optional symbol or function boundary hints when available

---

## Workflow for Static Detection & Obfuscation of Programmable Executable

[PowerView Static Detection & Obfuscation Workflow](./docs/PowerView-Static-Detection-Analysis-and-Obfuscation-Workflow.pdf)

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
  <sub>© 2025 Velkris — Educational Red Team Research | MIT Licensed</sub><br>
  <sub>All testing conducted in isolated lab environments for research and training purposes only.</sub>
</p>
