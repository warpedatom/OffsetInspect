function Invoke-OffsetInspect {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$FilePaths,

        [Parameter(Mandatory=$true)]
        [string[]]$OffsetInputs,

        [int]$ByteWindow = 32,
        [int]$ContextLines = 3
    )

    # Resolve script path relative to module
    $scriptPath = Join-Path $PSScriptRoot "..\OffsetInspect.ps1"

    if (-not (Test-Path $scriptPath)) {
        throw "OffsetInspect.ps1 not found at expected location: $scriptPath"
    }

    & $scriptPath -FilePaths $FilePaths -OffsetInputs $OffsetInputs -ByteWindow $ByteWindow -ContextLines $ContextLines
}

Export-ModuleMember -Function Invoke-OffsetInspect
