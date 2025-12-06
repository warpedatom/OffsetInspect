<#
.SYNOPSIS
    Module wrapper for OffsetInspect — PE Offset & Hex Context Inspector

.DESCRIPTION
    This module exposes the Invoke-OffsetInspect function, which acts as a wrapper
    around OffsetInspect.ps1 located in the repository root.

    Users can import this module and call the tool like a standard PowerShell function.

.AUTHOR
    Jared Perry (Velkris)
#>

function Invoke-OffsetInspect {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,

        [Parameter(Mandatory=$true)]
        [string]$OffsetInput,

        [int]$ByteWindow = 32,
        [int]$ContextLines = 3
    )

    # Resolve tool path relative to module directory
    $scriptPath = Join-Path $PSScriptRoot "..\OffsetInspect.ps1"

    if (-not (Test-Path $scriptPath)) {
        throw "OffsetInspect.ps1 not found at expected location: $scriptPath"
    }

    # Invoke the actual script with parameters
    & $scriptPath -FilePath $FilePath -OffsetInput $OffsetInput -ByteWindow $ByteWindow -ContextLines $ContextLines
}

Export-ModuleMember -Function Invoke-OffsetInspect
