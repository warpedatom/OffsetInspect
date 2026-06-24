<#
.SYNOPSIS
    Module wrapper for OffsetInspect — PE Offset & Hex Context Inspector.

.DESCRIPTION
    Exposes Invoke-OffsetInspect, which wraps OffsetInspect.ps1 in the repository
    root and supports multi-file inspection.

.AUTHOR
    Jared Perry (Velkris)
#>

function Invoke-OffsetInspect {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string[]]$FilePaths,

        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string[]]$OffsetInputs,

        [ValidateRange(0, 4096)]
        [int]$ByteWindow = 32,

        [ValidateRange(0, 100)]
        [int]$ContextLines = 3
    )

    # Resolve the CLI script relative to this module folder.
    # Expected repository layout:
    #   /OffsetInspect.ps1
    #   /module/OffsetInspect.psm1
    $scriptPath = Join-Path -Path (Split-Path -Parent $PSScriptRoot) -ChildPath 'OffsetInspect.ps1'

    if (-not (Test-Path -LiteralPath $scriptPath)) {
        throw "OffsetInspect.ps1 not found at expected location: $scriptPath"
    }

    & $scriptPath `
        -FilePaths $FilePaths `
        -OffsetInputs $OffsetInputs `
        -ByteWindow $ByteWindow `
        -ContextLines $ContextLines
}

Export-ModuleMember -Function Invoke-OffsetInspect
