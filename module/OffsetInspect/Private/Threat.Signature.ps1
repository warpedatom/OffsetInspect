# Authenticode signature verification (Windows-native). Get-OffsetSignature wraps the
# platform's real trust validation (Get-AuthenticodeSignature / WinVerifyTrust) and shapes an
# OffsetInspect.SignatureInfo. The shaping (ConvertTo-OISignatureInfo) is a pure function
# unit-tested against fixture objects, so it runs cross-platform in CI without a live signature;
# only the live provider call in the public cmdlet is Windows-only. This answers a provenance
# question static parsing cannot: not just "is there a cert" but "is the signature valid and
# trusted on this machine, and who signed it" - a complement to imphash and the Rich-header
# RichHash (imports vs build toolchain vs signer).

function Get-OIMemberValue {
    # StrictMode-safe property read: returns the member's value, or $null when the object lacks
    # it. Works on real .NET objects (Signature, X509Certificate2) and pscustomobject fixtures,
    # and tolerates PowerShell versions where SignatureType/IsOSBinary may be absent.
    [CmdletBinding()]
    param(
        [AllowNull()]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name
    )
    if ($null -eq $InputObject) { return $null }
    $member = $InputObject.PSObject.Properties[$Name]
    if ($member) { return $member.Value }
    return $null
}

function Get-OICommonName {
    # Pull the CN (common name) out of an X.500 subject/issuer for a readable label, falling
    # back to the full distinguished name.
    [CmdletBinding()]
    param([AllowNull()][string]$DistinguishedName)
    if ([string]::IsNullOrWhiteSpace($DistinguishedName)) { return $null }
    foreach ($part in $DistinguishedName -split ',') {
        $trimmed = $part.Trim()
        if ($trimmed -match '^CN=(.+)$') { return $Matches[1].Trim() }
    }
    return $DistinguishedName.Trim()
}

function ConvertTo-OISignatureInfo {
    <#
        Pure: shape a Get-AuthenticodeSignature result (or any compatible object) into an
        OffsetInspect.SignatureInfo. Every optional member is read defensively so it is safe
        under Set-StrictMode and across PowerShell versions. Unit-tested with fixtures - no live
        signature required.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        $Signature,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$File,

        [int64]$FileSize = -1
    )

    $status = [string](Get-OIMemberValue -InputObject $Signature -Name 'Status')
    if ([string]::IsNullOrEmpty($status)) { $status = 'UnknownError' }

    $signerCert = Get-OIMemberValue -InputObject $Signature -Name 'SignerCertificate'
    $tsaCert = Get-OIMemberValue -InputObject $Signature -Name 'TimeStamperCertificate'

    # A signer certificate is present for both embedded and catalog signatures (even when the
    # status is not Valid, e.g. NotTrusted/HashMismatch), and absent when there is no signature
    # (NotSigned) or the format can't be checked - so it is the reliable "is it signed" signal.
    $isSigned = ($null -ne $signerCert)

    $signerSubject = Get-OIMemberValue -InputObject $signerCert -Name 'Subject'
    $signerNotAfter = Get-OIMemberValue -InputObject $signerCert -Name 'NotAfter'
    $signerExpired = $null
    if ($signerNotAfter -is [datetime]) { $signerExpired = ((Get-Date) -gt $signerNotAfter) }

    $signatureType = Get-OIMemberValue -InputObject $Signature -Name 'SignatureType'
    $signatureTypeString = if ($null -ne $signatureType) { [string]$signatureType } else { $null }
    $isOsBinary = Get-OIMemberValue -InputObject $Signature -Name 'IsOSBinary'

    $result = [pscustomobject]@{
        File             = $File
        FileSize         = $FileSize
        IsSigned         = $isSigned
        Status           = $status
        StatusMessage    = Get-OIMemberValue -InputObject $Signature -Name 'StatusMessage'
        SignatureType    = $signatureTypeString
        IsCatalogSigned  = ($signatureTypeString -eq 'Catalog')
        IsOSBinary       = if ($null -ne $isOsBinary) { [bool]$isOsBinary } else { $null }
        SignerName       = Get-OICommonName -DistinguishedName $signerSubject
        SignerSubject    = $signerSubject
        SignerIssuer     = Get-OIMemberValue -InputObject $signerCert -Name 'Issuer'
        SignerThumbprint = Get-OIMemberValue -InputObject $signerCert -Name 'Thumbprint'
        SignerSerial     = Get-OIMemberValue -InputObject $signerCert -Name 'SerialNumber'
        SignerNotBefore  = Get-OIMemberValue -InputObject $signerCert -Name 'NotBefore'
        SignerNotAfter   = $signerNotAfter
        SignerExpired    = $signerExpired
        IsTimestamped    = [bool]$tsaCert
        TimestamperName  = Get-OICommonName -DistinguishedName (Get-OIMemberValue -InputObject $tsaCert -Name 'Subject')
        Warnings         = @()
    }
    $result.PSObject.TypeNames.Insert(0, 'OffsetInspect.SignatureInfo')
    return $result
}
