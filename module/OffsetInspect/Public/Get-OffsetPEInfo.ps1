function Get-OffsetPEInfo {
    <#
    .SYNOPSIS
        Parses a PE file's headers and sections, optionally mapping a byte offset to its section.

    .DESCRIPTION
        Reads the PE (Portable Executable) header region and returns the machine type, bitness,
        entry-point RVA, image base, and the section table (name, virtual address/size, raw
        pointer/size). With -Offset, it also reports which section that file offset falls in -
        useful for placing a detection boundary or a high-entropy region (.text, .rsrc, ...).
        Cross-platform; reads only the header region.

    .PARAMETER FilePath
        The PE file to parse.

    .PARAMETER Offset
        Optional file offset to map to a section.

    .EXAMPLE
        Get-OffsetPEInfo .\sample.exe | Select-Object -ExpandProperty Sections

    .EXAMPLE
        (Get-OffsetPEInfo .\sample.exe -Offset 0x1234).MappedSection
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [ValidateScript({ $_ -ge 0 })]
        [int64]$Offset = -1
    )

    $resolvedPath = (Resolve-Path -LiteralPath $FilePath -ErrorAction Stop).Path
    $item = Get-Item -LiteralPath $resolvedPath -ErrorAction Stop
    if ($item.PSIsContainer) { throw "Path is a directory, not a file: $resolvedPath" }
    $fileSize = $item.Length

    $headerLength = [int][Math]::Min([int64]0x10000, $fileSize)
    $warnings = New-Object 'System.Collections.Generic.List[string]'
    $importInfo = [pscustomobject]@{ Imports = @(); ImpHash = $null }
    $image = $null

    $stream = $null
    try {
        $stream = [System.IO.File]::Open(
            $resolvedPath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read
        )
        $headerBytes = Read-OIFileRange -Stream $stream -Start 0 -Length $headerLength
        $image = ConvertTo-OIPEImage -Bytes $headerBytes

        try {
            $importInfo = Get-OIPEImport -Image $image -Stream $stream
        }
        catch {
            $warnings.Add("Import table parse failed: $($_.Exception.Message)")
        }
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
    }

    $overlay = Get-OIPEOverlayRange -Section $image.Sections -FileSize $fileSize
    $mappedSection = if ($Offset -ge 0) { Get-OIPESectionForOffset -Image $image -Offset $Offset } else { $null }

    $result = [pscustomobject]@{
        File             = $resolvedPath
        FileSize         = $fileSize
        Machine          = $image.Machine
        IsPE32Plus       = $image.IsPE32Plus
        EntryPointRva    = $image.EntryPointRva
        EntryPointHex    = '0x{0:X}' -f $image.EntryPointRva
        ImageBase        = $image.ImageBase
        SectionCount     = $image.SectionCount
        Sections         = $image.Sections
        ImportedDllCount = @($importInfo.Imports).Count
        Imports          = $importInfo.Imports
        ImpHash          = $importInfo.ImpHash
        ResourceSize     = $image.ResourceSize
        HasOverlay       = $overlay.HasOverlay
        OverlayOffset    = $overlay.OverlayOffset
        OverlaySize      = $overlay.OverlaySize
        MappedOffset     = if ($Offset -ge 0) { $Offset } else { $null }
        MappedSection    = $mappedSection
        Warnings         = $warnings.ToArray()
    }
    $result.PSObject.TypeNames.Insert(0, 'OffsetInspect.PEInfo')
    return $result
}
