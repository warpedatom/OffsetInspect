@{
    RootModule      = 'OffsetInspect.psm1'
    ModuleVersion   = '1.0.1'
    GUID            = '2d9f6f83-2c4f-4a6e-8a53-1cf9a5fbc2f6'
    Author          = 'Jared Perry (Velkris)'
    CompanyName     = 'DreadHost Research'
    Copyright       = '(c) 2025, Jared Perry. MIT License.'

    Description = 'OffsetInspect: A PE offset and hex-context inspector designed for red team operations, reverse engineering, and binary analysis. Provides offset-to-line mapping, highlighted hex dumps, and ASCII contextual output.'

    PowerShellVersion    = '5.1'
    CompatiblePSEditions = @('Desktop', 'Core')

    FunctionsToExport = @('Invoke-OffsetInspect')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags = @(
                'powershell',
                'redteam',
                'hex',
                'reverse-engineering',
                'security',
                'forensics',
                'malware-analysis',
                'binary-analysis'
            )

            LicenseUri = 'https://github.com/warpedatom/OffsetInspect/blob/main/LICENSE'
            ProjectUri = 'https://github.com/warpedatom/OffsetInspect'
            IconUri    = ''

            ReleaseNotes = @"
OffsetInspect V1.0.1 – Multi-File Capability + Review-Driven Refinement

This release combines functional upgrades and review-driven improvements from both a contributor and Sorcery-AI feedback.

Added
------
- Multi-file inspection support
- FilePaths now accepts multiple targets
- OffsetInputs accepts matching offsets
- Runs sequentially and outputs independent blocks per file

Changed
--------
- Enforced one-to-one mapping between FilePaths and OffsetInputs
- Single offset may be reused (explicitly noted); otherwise lengths must match
- Centralized offset parsing via new Parse-Offset helper
- Improved validation and error messaging

CI / Automation-Friendly
-------------------------
- Added non-zero exit code behavior when failures occur, enabling pipeline detection
- `$script:hadError` flag tracks processing errors across multiple files

Documentation
--------------
- README updated with new usage examples
- Typo fix ("multiple")

Contributor
------------
- Feature PR by @secretlay3r (#1)
"@
        }
    }
}This release combines functional upgrades and review-driven improvements from both a contributor and Sorcery-AI feedback.

Added
------
- Multi-file inspection support
- FilePaths now accepts multiple targets
- OffsetInputs accepts matching offsets
- Runs sequentially and outputs independent blocks per file

Changed
--------
- Enforced one-to-one mapping between FilePaths and OffsetInputs
- Single offset may be reused (explicitly noted); otherwise lengths must match
- Centralized offset parsing via new Parse-Offset helper
- Improved validation and error messaging

CI / Automation-Friendly
-------------------------
- Added non-zero exit code behavior when failures occur, enabling pipeline detection
- `$script:hadError` flag tracks processing errors across multiple files

Documentation
--------------
- README updated with new usage examples
- Typo fix ("multiple")

Contributor
------------
- Feature PR by @secretlay3r (#1)
"@
        }
    }
}
