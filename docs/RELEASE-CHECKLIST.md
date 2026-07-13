# Release checklist

## Version and documentation

- [ ] Manifest, banner, changelog, and release tag use the same semantic version.
- [ ] Public parameter and output changes are documented.
- [ ] `SECURITY.md` support table is current.

## Validation

- [ ] `./build/Test-Module.ps1` passes on Windows PowerShell 5.1.
- [ ] `./build/Test-Module.ps1` passes on current PowerShell 7 for Windows and Linux.
- [ ] PSScriptAnalyzer reports no configured errors or warnings.
- [ ] The exact isolated Gallery directory imports and exports only documented commands.
- [ ] Optional live provider smoke tests pass in an authorized Windows analysis VM.

## Packaging and supply chain

- [ ] `./build/New-ReleasePackage.ps1` creates the archive and SHA-256 file.
- [ ] Two package builds from identical source produce the same SHA-256 archive hash.
- [ ] The archive contains only `OffsetInspect/` and required module files.
- [ ] No executable, DLL, PDB, IDE, `bin`, `obj`, `.vs`, secret, or sample artifact is present.
- [ ] Authenticode signing is optional; when required, apply it via `./build/Sign-And-Publish.ps1 -CertificateThumbprint <thumbprint>` before publishing, and confirm every signature reports `Valid`. The automated `publish-offsetinspect.yml` Gallery publish is unsigned unless that script is used.
- [ ] GitHub release tag matches the manifest version.
- [ ] PowerShell Gallery API key is supplied through the protected release environment.

## Post-release

- [ ] Install from the Gallery in a clean profile.
- [ ] Verify both exported commands and help content.
- [ ] Verify the GitHub artifact checksum.
- [ ] Create the next `Unreleased` changelog section.
