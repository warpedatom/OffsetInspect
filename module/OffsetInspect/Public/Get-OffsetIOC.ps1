function Get-OffsetIOC {
    <#
    .SYNOPSIS
        Produces a consolidated indicator panel for a file (hashes, entropy, PE details, strings).

    .DESCRIPTION
        Collects the common triage indicators for a file into one object: MD5/SHA-1/SHA-256,
        file size, overall entropy, printable-string count, and - when the file is a PE - machine
        type, imphash, and overlay presence. Read-only and cross-platform. Useful for logging an
        IOC row per sample or for enriching a report.

    .PARAMETER FilePath
        The file to summarise.

    .PARAMETER MinimumStringLength
        Minimum length for the printable-string count (default 6).

    .EXAMPLE
        Get-OffsetIOC .\sample.exe | Format-List
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateRange(2, 1024)]
        [int]$MinimumStringLength = 6
    )

    $resolvedPath = (Resolve-Path -LiteralPath $FilePath -ErrorAction Stop).Path
    $item = Get-Item -LiteralPath $resolvedPath -ErrorAction Stop
    if ($item.PSIsContainer) { throw "Path is a directory, not a file: $resolvedPath" }

    $hashes = Get-OIFileHash -Path $resolvedPath
    $entropy = Get-OffsetEntropy -FilePath $resolvedPath -WindowSize 256
    $stringCount = @(Get-OffsetString -FilePath $resolvedPath -MinimumLength $MinimumStringLength).Count

    $pe = $null
    try { $pe = Get-OffsetPEInfo -FilePath $resolvedPath }
    catch { $pe = $null }

    $result = [pscustomobject]@{
        File                 = $resolvedPath
        FileSize             = $item.Length
        MD5                  = $hashes.MD5
        SHA1                 = $hashes.SHA1
        SHA256               = $hashes.SHA256
        OverallEntropy       = $entropy.OverallEntropy
        HighEntropyWindows   = $entropy.HighWindowCount
        PrintableStringCount = $stringCount
        IsPE                 = ($null -ne $pe)
        Machine              = if ($null -ne $pe) { $pe.Machine } else { $null }
        ImpHash              = if ($null -ne $pe) { $pe.ImpHash } else { $null }
        ImportedDllCount     = if ($null -ne $pe) { $pe.ImportedDllCount } else { $null }
        HasOverlay           = if ($null -ne $pe) { $pe.HasOverlay } else { $null }
        OverlaySize          = if ($null -ne $pe) { $pe.OverlaySize } else { $null }
    }
    $result.PSObject.TypeNames.Insert(0, 'OffsetInspect.IOC')
    return $result
}
