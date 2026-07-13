function Get-OIFileHash {
    <#
        Computes MD5, SHA-1, and SHA-256 for a file in a single bounded-memory pass
        (the stream is read once and fed to all three incremental hashers). Cross-
        platform, unit-tested against known vectors.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    $md5 = [System.Security.Cryptography.MD5]::Create()
    $sha1 = [System.Security.Cryptography.SHA1]::Create()
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    $stream = $null
    try {
        $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::Read)
        $buffer = New-Object byte[] (1024 * 1024)
        while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $null = $md5.TransformBlock($buffer, 0, $read, $null, 0)
            $null = $sha1.TransformBlock($buffer, 0, $read, $null, 0)
            $null = $sha256.TransformBlock($buffer, 0, $read, $null, 0)
        }
        $null = $md5.TransformFinalBlock($buffer, 0, 0)
        $null = $sha1.TransformFinalBlock($buffer, 0, 0)
        $null = $sha256.TransformFinalBlock($buffer, 0, 0)

        return [pscustomobject]@{
            MD5    = ([BitConverter]::ToString($md5.Hash) -replace '-', '').ToLowerInvariant()
            SHA1   = ([BitConverter]::ToString($sha1.Hash) -replace '-', '').ToLowerInvariant()
            SHA256 = ([BitConverter]::ToString($sha256.Hash) -replace '-', '').ToLowerInvariant()
        }
    }
    finally {
        if ($null -ne $stream) { $stream.Dispose() }
        $md5.Dispose()
        $sha1.Dispose()
        $sha256.Dispose()
    }
}
