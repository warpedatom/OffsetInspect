[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [string]$RepoRoot = (Split-Path -Parent $PSScriptRoot),
    [SecureString]$GalleryApiKey,
    [string]$CertificateThumbprint,
    [switch]$SkipSigning,
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
$modulePath = Join-Path (Join-Path $RepoRoot 'module') 'OffsetInspect'
$manifestPath = Join-Path $modulePath 'OffsetInspect.psd1'

if (-not $SkipTests) {
    & (Join-Path $PSScriptRoot 'Test-Module.ps1') -RepoRoot $RepoRoot
}

if (-not $SkipSigning) {
    $certificates = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert
    if ($CertificateThumbprint) {
        $certificate = $certificates | Where-Object Thumbprint -eq $CertificateThumbprint | Select-Object -First 1
    }
    else {
        $certificate = $certificates | Sort-Object NotAfter -Descending | Select-Object -First 1
    }

    if ($null -eq $certificate) {
        throw 'No matching code-signing certificate was found in Cert:\CurrentUser\My.'
    }

    foreach ($file in (Get-ChildItem -LiteralPath $modulePath -Recurse -File | Where-Object Extension -in @('.ps1', '.psm1', '.psd1'))) {
        if ($PSCmdlet.ShouldProcess($file.FullName, 'Apply Authenticode signature')) {
            $signature = Set-AuthenticodeSignature -LiteralPath $file.FullName -Certificate $certificate -HashAlgorithm SHA256
            if ($signature.Status -ne 'Valid') {
                throw "Signing failed for '$($file.FullName)': $($signature.StatusMessage)"
            }
        }
    }

    Test-ModuleManifest -Path $manifestPath -ErrorAction Stop | Out-Null
}

if ($null -eq $GalleryApiKey) {
    $GalleryApiKey = Read-Host -Prompt 'PowerShell Gallery API key' -AsSecureString
}

$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($GalleryApiKey)
try {
    $plainGalleryApiKey = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    if ($PSCmdlet.ShouldProcess('PowerShell Gallery', "Publish OffsetInspect $((Test-ModuleManifest -Path $manifestPath).Version)")) {
        Publish-Module -Path $modulePath -Repository PSGallery -NuGetApiKey $plainGalleryApiKey -Force -Verbose
    }
}
finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    Remove-Variable -Name plainGalleryApiKey -ErrorAction SilentlyContinue
}
