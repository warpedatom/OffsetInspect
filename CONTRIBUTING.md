# Contributing to OffsetInspect

Contributions are welcome for correctness, performance, provider reliability, documentation, and tests.

## Development requirements

- Windows PowerShell 5.1 or PowerShell 7.x.
- Pester 5.7.1.
- PSScriptAnalyzer 1.25.0.

```powershell
Install-Module Pester -RequiredVersion 5.7.1 -Scope CurrentUser
Install-Module PSScriptAnalyzer -RequiredVersion 1.25.0 -Scope CurrentUser
```

## Workflow

1. Fork the repository and create a focused branch.
2. Make the smallest coherent change.
3. Add or update Pester coverage.
4. Run `./build/Test-Module.ps1`.
5. Update documentation and `CHANGELOG.md` when behavior changes.
6. Open a pull request using the repository template.

## Engineering standards

- Preserve Windows PowerShell 5.1 compatibility unless a major-version decision changes it.
- Keep the Gallery package self-contained under `module/OffsetInspect`.
- Do not add binaries, generated build output, IDE state, or sample malware to the repository.
- Do not use `exit` inside module functions.
- Return structured failures for per-item inspection errors; reserve terminating errors for command-level failures or `-FailOnError`.
- Keep provider timeout, error, blocked, detected, and indeterminate states distinct.
- Treat a prefix transition as a contextual detection boundary, not an exact signature byte.
- Avoid changes that disable, bypass, weaken, or automatically mutate endpoint protections or analyzed content.
- Document public parameters and maintain stable output properties within a major version.
- Use approved PowerShell verbs and clear `OI`-prefixed names for private helpers.

## Tests

Pull requests should cover:

- Offset parsing and range validation.
- UTF-8/UTF-16 byte-to-character mapping.
- Context-line behavior and bounded long-line previews.
- Output schemas and parameter-set exclusivity.
- Isolated installation from only the Gallery package directory.
- Provider normalization and boundary-search behavior without requiring live malware samples.

Live AMSI or Defender tests must be opt-in, run only on authorized Windows infrastructure, and use benign test fixtures. CI must remain safe and deterministic.

## Security reports

Do not open a public issue for a vulnerability. Follow [SECURITY.md](./SECURITY.md).
