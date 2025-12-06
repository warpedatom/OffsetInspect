![Dread-Host-Banner](./assets/Dread-Host-Banner.png)

![Release](https://img.shields.io/github/v/release/warpedatom/OffsetInspect)
![License](https://img.shields.io/github/license/warpedatom/OffsetInspect)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2F7.x-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey)
![Repo Size](https://img.shields.io/github/repo-size/warpedatom/OffsetInspect)
![Last Commit](https://img.shields.io/github/last-commit/warpedatom/OffsetInspect)

# OffsetInspect  

---

## Overview

OffsetInspect is a lightweight PowerShell-based hex-context inspection utility designed for red team operators, malware analysts, and researchers who require precise insight into file offsets.

It functions as a terminal-friendly, HxD-inspired viewer that:

- Highlights the exact byte at a given offset  
- Displays surrounding context bytes  
- Maps offsets back to line numbers  
- Shows ASCII representations  
- Positions a caret indicating the exact character location in a source line  
- Provides configurable window sizes around the offset  

OffsetInspect is designed for quick, accurate offset validation during offensive security engagements and binary/script analysis.

---

## Features

- Exact byte highlighting  
- Mapping of raw byte offsets to file line numbers  
- Configurable context window around the inspected offset  
- Combined hex and ASCII display in a structured layout  
- Color-coded terminal output for clarity  
- No external dependencies  
- Compatible with Windows PowerShell and PowerShell 7  

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
All releases include an automatically generated `checksums.txt` file created by GitHub Actions.

Verify using:

```powershell
Get-FileHash -Algorithm SHA256 .\OffsetInspect.ps1
```

## Run

```powershell
.\OffsetInspect.ps1 <FilePath> <Offset>
```

## PowerShell Script Usage 

Basic Example
```powershell
.\OffsetInspect.ps1 C:\AD\PowerView.ps1 0xE1AB1
```
Decimal Offset Example
```powershell
.\OffsetInspect.ps1 payload.bin 1024
```
Adjust Byte Window Size
```powershell
.\OffsetInspect.ps1 file.bin 0x200 -ByteWindow 64
```

---

## PowerShell Module Usage

OffsetInspect can also be used as an importable module:

```powershell
Import-Module ./module/OffsetInspect.psm1
```
```powershell
Invoke-OffsetInspect -FilePath C:\AD\PowerView.ps1 -OffsetInput 0xE1AB1
```

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

Line Content Preview
- The tool identifies which file line contains the byte:
```powershell
Line 24810: Set-Alias Get-DomainPolicy Get-DomainPolicyData
                       ↑
```
- The caret indicates the exact character position corresponding to the target byte.

Hex Dump
- A contextual hex dump is shown, centered around the offset:
```powershell
000E1A91  6F 6D 61 69 6E 50 6F 6C 69 63 79 20 47 65 74 2D  omainPolicy Get-
000E1AA1  44 6F 6D 61 69 6E 50 6F 6C 69 63 79 44 61 74 61  DomainPolicyData
000E1AB1  0D 0A                                            ..
               ^^
```
- The highlighted byte is shown in yellow
- Normal bytes appear in green
- ASCII output is aligned to the right
- Offsets appear as eight-digit hex values

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

## Workflow for Static Detection & Obfuscation of Programmable Executable

[PowerView Static Detection & Obfuscation Workflow](./docs/PowerView-Static-Detection-Analysis-and-Obfuscation-Workflow.pdf)

---

## Disclaimer

This tool is intended for authorized security testing, research, and educational purposes only.
The author assumes no responsibility for misuse, unauthorized activity, or policy violations that occur through the use of this script.

---

## License
OffsetInspect is released under the MIT License.
Attribution is appreciated but not required.
