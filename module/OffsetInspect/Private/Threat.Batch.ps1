function Resolve-OIBatchTarget {
    <#
        Expands one or more path inputs (files, directories, or wildcards) into a
        de-duplicated, ordered list of file paths for batch scanning. Directories
        are enumerated with the supplied filter and optional recursion. This is a
        pure filesystem operation with no provider dependency, so it runs on every
        platform and is unit-tested directly.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Path,

        [switch]$Recurse,

        [ValidateNotNullOrEmpty()]
        [string]$Filter = '*'
    )

    $files = New-Object 'System.Collections.Generic.List[string]'
    foreach ($candidate in $Path) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }

        $resolved = @(Resolve-Path -Path $candidate -ErrorAction Stop)
        foreach ($entry in $resolved) {
            $item = Get-Item -LiteralPath $entry.Path -ErrorAction Stop
            if ($item.PSIsContainer) {
                $children = @(Get-ChildItem -LiteralPath $item.FullName -File -Filter $Filter -Recurse:$Recurse -ErrorAction Stop)
                foreach ($child in $children) { $files.Add($child.FullName) }
            }
            else {
                $files.Add($item.FullName)
            }
        }
    }

    return @($files | Select-Object -Unique)
}
