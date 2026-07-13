function ConvertTo-OIPEImage {
    <#
        Parses a PE (Portable Executable) header from a byte buffer that contains at
        least the DOS header, PE header, and section table. Returns machine, bitness,
        entry point, image base, and the section table. Throws if the buffer is not a
        PE image or is truncated before the section table. Pure and cross-platform.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes
    )

    $requireBytes = {
        param([int64]$Needed)
        if ($Needed -gt $Bytes.Length) {
            throw "The header buffer is truncated before offset $Needed; provide more header bytes."
        }
    }

    & $requireBytes 0x40
    if ($Bytes[0] -ne 0x4D -or $Bytes[1] -ne 0x5A) {
        throw 'Not a PE image: missing MZ (DOS) signature.'
    }

    $peHeaderOffset = [BitConverter]::ToInt32($Bytes, 0x3C)
    if ($peHeaderOffset -le 0) { throw 'Not a PE image: invalid PE header offset.' }

    & $requireBytes ($peHeaderOffset + 24)
    if ($Bytes[$peHeaderOffset] -ne 0x50 -or $Bytes[$peHeaderOffset + 1] -ne 0x45 -or
        $Bytes[$peHeaderOffset + 2] -ne 0x00 -or $Bytes[$peHeaderOffset + 3] -ne 0x00) {
        throw 'Not a PE image: missing PE signature.'
    }

    $coffOffset = $peHeaderOffset + 4
    $machineId = [BitConverter]::ToUInt16($Bytes, $coffOffset)
    $sectionCount = [BitConverter]::ToUInt16($Bytes, $coffOffset + 2)
    $optionalHeaderSize = [BitConverter]::ToUInt16($Bytes, $coffOffset + 16)

    $optionalOffset = $coffOffset + 20
    & $requireBytes ($optionalOffset + 28)
    $magic = [BitConverter]::ToUInt16($Bytes, $optionalOffset)
    $isPe32Plus = ($magic -eq 0x20B)
    $entryPointRva = [BitConverter]::ToUInt32($Bytes, $optionalOffset + 16)
    $imageBase = if ($isPe32Plus) {
        [BitConverter]::ToUInt64($Bytes, $optionalOffset + 24)
    }
    else {
        [uint64][BitConverter]::ToUInt32($Bytes, $optionalOffset + 28)
    }

    # Data directories live after the fixed optional-header fields: offset 96 for
    # PE32, 112 for PE32+, with NumberOfRvaAndSizes in the uint32 just before them.
    $dataDirectoryBase = if ($isPe32Plus) { $optionalOffset + 112 } else { $optionalOffset + 96 }
    $rvaAndSizeCount = 0
    if (($dataDirectoryBase - 4 + 4) -le $Bytes.Length) {
        $rvaAndSizeCount = [BitConverter]::ToUInt32($Bytes, $dataDirectoryBase - 4)
    }
    $readDataDirectory = {
        param([int]$Index)
        $offset = $dataDirectoryBase + ($Index * 8)
        if ($Index -lt $rvaAndSizeCount -and ($offset + 8) -le $Bytes.Length) {
            return [pscustomobject]@{ Rva = [BitConverter]::ToUInt32($Bytes, $offset); Size = [BitConverter]::ToUInt32($Bytes, $offset + 4) }
        }
        return [pscustomobject]@{ Rva = [uint32]0; Size = [uint32]0 }
    }.GetNewClosure()
    $exportDirectory = & $readDataDirectory 0
    $importDirectory = & $readDataDirectory 1
    $resourceDirectory = & $readDataDirectory 2

    $machineName = switch ($machineId) {
        0x014C { 'x86 (I386)' }
        0x8664 { 'x64 (AMD64)' }
        0xAA64 { 'ARM64' }
        0x01C0 { 'ARM' }
        0x01C4 { 'ARMNT' }
        default { '0x{0:X4}' -f $machineId }
    }

    $sectionTableOffset = $optionalOffset + $optionalHeaderSize
    $sections = New-Object 'System.Collections.Generic.List[object]'
    for ($i = 0; $i -lt $sectionCount; $i++) {
        $entry = $sectionTableOffset + ($i * 40)
        & $requireBytes ($entry + 40)
        $rawName = [System.Text.Encoding]::ASCII.GetString($Bytes, $entry, 8).TrimEnd([char]0)
        $sections.Add([pscustomobject]@{
            Name             = $rawName
            VirtualSize      = [BitConverter]::ToUInt32($Bytes, $entry + 8)
            VirtualAddress   = [BitConverter]::ToUInt32($Bytes, $entry + 12)
            SizeOfRawData    = [BitConverter]::ToUInt32($Bytes, $entry + 16)
            PointerToRawData = [BitConverter]::ToUInt32($Bytes, $entry + 20)
        })
    }

    return [pscustomobject]@{
        IsPE            = $true
        MachineId       = $machineId
        Machine         = $machineName
        IsPE32Plus      = $isPe32Plus
        EntryPointRva   = $entryPointRva
        ImageBase       = $imageBase
        SectionCount    = [int]$sectionCount
        Sections        = $sections.ToArray()
        ExportRva       = $exportDirectory.Rva
        ExportSize      = $exportDirectory.Size
        ImportRva       = $importDirectory.Rva
        ImportSize      = $importDirectory.Size
        ResourceRva     = $resourceDirectory.Rva
        ResourceSize    = $resourceDirectory.Size
    }
}

function Get-OIPESectionForOffset {
    <#
        Returns the name of the section whose raw data contains the given file offset,
        'headers' when the offset falls before the first section's raw data, or $null
        when it maps to no section.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Image,

        [Parameter(Mandatory = $true)]
        [int64]$Offset
    )

    foreach ($section in $Image.Sections) {
        $rawStart = [int64]$section.PointerToRawData
        $rawEnd = $rawStart + [int64]$section.SizeOfRawData
        if ($section.SizeOfRawData -gt 0 -and $Offset -ge $rawStart -and $Offset -lt $rawEnd) {
            return $section.Name
        }
    }

    $firstRaw = @($Image.Sections | Where-Object { $_.PointerToRawData -gt 0 } | Sort-Object PointerToRawData | Select-Object -First 1)
    if ($firstRaw.Count -gt 0 -and $Offset -lt [int64]$firstRaw[0].PointerToRawData) {
        return 'headers'
    }
    return $null
}

function ConvertFrom-OIRvaToOffset {
    # Maps a relative virtual address to a raw file offset using the section table,
    # or returns $null when the RVA falls outside every section.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Image,

        [Parameter(Mandatory = $true)]
        [int64]$Rva
    )

    foreach ($section in $Image.Sections) {
        $virtualAddress = [int64]$section.VirtualAddress
        $virtualSpan = [int64][Math]::Max([int64]$section.VirtualSize, [int64]$section.SizeOfRawData)
        if ($Rva -ge $virtualAddress -and $Rva -lt ($virtualAddress + $virtualSpan)) {
            return ($Rva - $virtualAddress + [int64]$section.PointerToRawData)
        }
    }
    return $null
}

function Read-OINullTerminatedAscii {
    # Reads an ASCII string terminated by a null byte, starting at a file offset.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.FileStream]$Stream,

        [Parameter(Mandatory = $true)]
        [int64]$Offset,

        [ValidateRange(1, 4096)]
        [int]$MaxLength = 256
    )

    $bytes = Read-OIFileRange -Stream $Stream -Start $Offset -Length $MaxLength
    if ($bytes.Length -eq 0) { return '' }
    $terminator = [array]::IndexOf($bytes, [byte]0)
    $length = if ($terminator -ge 0) { $terminator } else { $bytes.Length }
    if ($length -le 0) { return '' }
    return [System.Text.Encoding]::ASCII.GetString($bytes, 0, $length)
}

function Get-OIPEOverlayRange {
    # An overlay is file data appended after the last section's raw data - common
    # in installers and some malware. Returns its offset and size.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Section,

        [Parameter(Mandatory = $true)]
        [int64]$FileSize
    )

    $overlayStart = [int64]0
    foreach ($entry in $Section) {
        if ($entry.SizeOfRawData -gt 0) {
            $end = [int64]$entry.PointerToRawData + [int64]$entry.SizeOfRawData
            if ($end -gt $overlayStart) { $overlayStart = $end }
        }
    }
    $overlaySize = if ($FileSize -gt $overlayStart) { $FileSize - $overlayStart } else { [int64]0 }
    return [pscustomobject]@{
        HasOverlay    = ($overlaySize -gt 0)
        OverlayOffset = if ($overlaySize -gt 0) { $overlayStart } else { $null }
        OverlaySize   = $overlaySize
    }
}

function Get-OIImpHash {
    # Imphash = MD5 of the comma-joined, lower-cased "library.function" import list
    # (library extension stripped). Ordinal-only imports are rendered as ordNNN;
    # unlike pefile this does not resolve ordinals to names for special libraries,
    # so imphashes of ordinal-heavy binaries may differ from pefile's.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [string[]]$Entry
    )

    if ($Entry.Count -eq 0) { return $null }

    $joined = ($Entry -join ',')
    $md5 = [System.Security.Cryptography.MD5]::Create()
    try {
        $hashBytes = $md5.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($joined))
        return (($hashBytes | ForEach-Object { $_.ToString('x2') }) -join '')
    }
    finally {
        $md5.Dispose()
    }
}

function Get-OIPEImport {
    # Parses the PE import directory from the stream (reads on demand at mapped
    # RVAs, so imports outside the header region are handled) and computes the
    # imphash. Returns @{ Imports; ImpHash }.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Image,

        [Parameter(Mandatory = $true)]
        [System.IO.FileStream]$Stream
    )

    $imports = New-Object 'System.Collections.Generic.List[object]'
    $imphashEntries = New-Object 'System.Collections.Generic.List[string]'

    if ([int64]$Image.ImportRva -le 0) {
        return [pscustomobject]@{ Imports = @(); ImpHash = $null }
    }
    $descriptorOffset = ConvertFrom-OIRvaToOffset -Image $Image -Rva ([int64]$Image.ImportRva)
    if ($null -eq $descriptorOffset) {
        return [pscustomobject]@{ Imports = @(); ImpHash = $null }
    }

    $pointerSize = if ($Image.IsPE32Plus) { 8 } else { 4 }
    # Build the ordinal-import flag via a hex string to avoid the 0x8000000000000000
    # literal overflowing Int64 during parsing.
    $ordinalFlag = if ($Image.IsPE32Plus) { [System.Convert]::ToUInt64('8000000000000000', 16) } else { [uint64]0x80000000 }

    $descriptorIndex = 0
    while ($descriptorIndex -lt 4096) {
        $descriptor = Read-OIFileRange -Stream $Stream -Start ($descriptorOffset + ($descriptorIndex * 20)) -Length 20
        if ($descriptor.Length -lt 20) { break }

        $originalFirstThunk = [BitConverter]::ToUInt32($descriptor, 0)
        $nameRva = [BitConverter]::ToUInt32($descriptor, 12)
        $firstThunk = [BitConverter]::ToUInt32($descriptor, 16)
        if ($originalFirstThunk -eq 0 -and $nameRva -eq 0 -and $firstThunk -eq 0) { break }

        $libraryName = ''
        $nameOffset = ConvertFrom-OIRvaToOffset -Image $Image -Rva ([int64]$nameRva)
        if ($null -ne $nameOffset) {
            $libraryName = Read-OINullTerminatedAscii -Stream $Stream -Offset $nameOffset
        }

        $libraryBase = $libraryName.ToLowerInvariant()
        foreach ($extension in @('.dll', '.ocx', '.sys')) {
            if ($libraryBase.EndsWith($extension)) {
                $libraryBase = $libraryBase.Substring(0, $libraryBase.Length - $extension.Length)
                break
            }
        }

        $functions = New-Object 'System.Collections.Generic.List[string]'
        $thunkRva = if ($originalFirstThunk -ne 0) { $originalFirstThunk } else { $firstThunk }
        $thunkOffset = ConvertFrom-OIRvaToOffset -Image $Image -Rva ([int64]$thunkRva)
        if ($null -ne $thunkOffset) {
            $thunkIndex = 0
            while ($thunkIndex -lt 100000) {
                $thunkBytes = Read-OIFileRange -Stream $Stream -Start ($thunkOffset + ($thunkIndex * $pointerSize)) -Length $pointerSize
                if ($thunkBytes.Length -lt $pointerSize) { break }
                $thunkValue = if ($pointerSize -eq 8) { [BitConverter]::ToUInt64($thunkBytes, 0) } else { [uint64][BitConverter]::ToUInt32($thunkBytes, 0) }
                if ($thunkValue -eq 0) { break }

                if (($thunkValue -band $ordinalFlag) -ne 0) {
                    $functionName = 'ord' + [int]($thunkValue -band 0xFFFF)
                }
                else {
                    $byNameOffset = ConvertFrom-OIRvaToOffset -Image $Image -Rva ([int64]($thunkValue -band 0xFFFFFFFF))
                    $functionName = if ($null -ne $byNameOffset) { Read-OINullTerminatedAscii -Stream $Stream -Offset ($byNameOffset + 2) } else { '' }
                }

                if (-not [string]::IsNullOrEmpty($functionName)) {
                    $functions.Add($functionName)
                    $imphashEntries.Add($libraryBase + '.' + $functionName.ToLowerInvariant())
                }
                $thunkIndex++
            }
        }

        $imports.Add([pscustomobject]@{ Dll = $libraryName; Functions = $functions.ToArray() })
        $descriptorIndex++
    }

    return [pscustomobject]@{
        Imports = $imports.ToArray()
        ImpHash = (Get-OIImpHash -Entry $imphashEntries.ToArray())
    }
}
