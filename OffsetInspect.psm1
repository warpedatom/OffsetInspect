<#
.SYNOPSIS
    Module wrapper for OffsetInspect — PE Offset & Hex Context Inspector

.DESCRIPTION
    Exposes Invoke-OffsetInspect, which wraps OffsetInspect.ps1 in the repo root
    and supports multi-file inspection.

.AUTHOR
    Jared Perry (Velkris)
#>

function Invoke-OffsetInspect {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string[]]$FilePaths,

        [Parameter(Mandatory = $true, Position = 1)]
        [string[]]$OffsetInputs,

        [int]$ByteWindow   = 32,
        [int]$ContextLines = 3
    )

    # Resolve tool path relative to the module directory
    $scriptPath = Join-Path -Path $PSScriptRoot -ChildPath 'OffsetInspect.ps1'

    if (-not (Test-Path -LiteralPath $scriptPath)) {
        throw "OffsetInspect.ps1 not found at expected location: $scriptPath"
    }

    & $scriptPath `
        -FilePaths    $FilePaths `
        -OffsetInputs $OffsetInputs `
        -ByteWindow   $ByteWindow `
        -ContextLines $ContextLines
}

Export-ModuleMember -Function Invoke-OffsetInspect
