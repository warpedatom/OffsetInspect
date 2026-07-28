function Get-OffsetSignature {
    <#
    .SYNOPSIS
        Reports a file's Authenticode signature and whether it is valid and trusted (Windows-only).

    .DESCRIPTION
        Wraps the platform's real Authenticode verification (Get-AuthenticodeSignature /
        WinVerifyTrust) to answer a provenance question static parsing cannot: is this binary
        signed, is the signature valid against this machine's trust store, who signed it, is it
        embedded- or catalog-signed, and is it a Windows OS binary? Returns an
        OffsetInspect.SignatureInfo.

        This complements the build-toolchain fingerprints (imphash, and OffsetScan's Rich-header
        RichHash): imports vs toolchain vs signer. An unsigned binary wearing a system-DLL name,
        or a signature that is present but not Valid/trusted, is a triage signal.

        Windows-only: Authenticode trust validation needs the Windows trust store, so on other
        platforms this throws (mirroring the AMSI/Defender threat providers). The signature is
        checked against the trust state of the machine it runs on; run it in your analysis
        environment, not the target's.

    .PARAMETER FilePath
        The file to verify.

    .EXAMPLE
        Get-OffsetSignature .\sample.exe

    .EXAMPLE
        Get-ChildItem *.exe |
            ForEach-Object { Get-OffsetSignature $_.FullName } |
            Where-Object { -not $_.IsSigned -or $_.Status -ne 'Valid' }

        Surface every unsigned or not-validly-signed executable in a folder.
    #>
    [CmdletBinding()]
    [OutputType('OffsetInspect.SignatureInfo')]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath
    )

    if (-not (Test-OIIsWindows)) {
        throw 'Get-OffsetSignature requires Windows: Authenticode trust validation uses the Windows trust store (Get-AuthenticodeSignature).'
    }

    $resolvedPath = (Resolve-Path -LiteralPath $FilePath -ErrorAction Stop).Path
    $item = Get-Item -LiteralPath $resolvedPath -ErrorAction Stop
    if ($item.PSIsContainer) { throw "Path is a directory, not a file: $resolvedPath" }

    $signature = Get-AuthenticodeSignature -LiteralPath $resolvedPath -ErrorAction Stop
    return ConvertTo-OISignatureInfo -Signature $signature -File $resolvedPath -FileSize $item.Length
}
