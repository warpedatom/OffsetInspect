# Security policy

## Supported versions

| Version | Security support |
|---|---|
| 2.x | Supported |
| 1.x | End of life |
| < 1.0 | Unsupported |

Security fixes are released against the latest 2.x version. Upgrade before reporting an issue that may already be resolved.

## Reporting a vulnerability

Use GitHub Private Vulnerability Reporting for this repository or email **warped.atom@proton.me**. Do not disclose a suspected vulnerability, sensitive sample, provider output, or proof of concept in a public issue.

Include, when possible:

- Affected OffsetInspect and PowerShell versions.
- Operating system and architecture.
- Minimal reproduction steps.
- Expected and observed behavior.
- Security impact and realistic attack preconditions.
- Sanitized logs or a non-sensitive reproducer.

## Response targets

| Stage | Target |
|---|---:|
| Acknowledgment | 2 business days |
| Initial triage | 5 business days |
| Remediation decision | 10 business days |
| Coordinated release | As soon as a validated fix is available |

Targets are not guarantees, but good-faith status updates will be provided during coordinated disclosure.

## In scope

- Arbitrary command or code execution caused by parsing attacker-controlled input.
- Path handling, temporary-file, or symlink issues that cross a trust boundary.
- Incorrect provider-state handling that reports an error or timeout as a definitive result.
- Secret leakage through logs, CI, packaging, or release automation.
- Supply-chain tampering or unexpected executable content in published artifacts.
- Unsafe cleanup or file replacement outside the intended temporary workspace.

## Out of scope

- Vulnerabilities in PowerShell, Windows, AMSI, Microsoft Defender, or third-party platforms themselves.
- Detection quality changes caused solely by provider or signature updates.
- Running modified forks or using the tool outside an authorized environment.
- Publicly disclosed reports submitted before a reasonable remediation window.

## Release integrity

Official release artifacts include a SHA-256 checksum. Validate the checksum before use and install Gallery releases only from the expected publisher. The module package intentionally excludes executables, compiled libraries, PDBs, IDE state, and build directories.

## Handling samples safely

OffsetInspect does not execute inspected content. Threat-provider analysis can still trigger endpoint-security controls when temporary prefixes are written or scanned. Use an authorized, isolated Windows analysis environment for suspicious samples, preserve hashes and provider metadata, and never upload sensitive samples to public issue trackers.
