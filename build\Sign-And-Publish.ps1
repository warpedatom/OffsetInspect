param(
    [string]$ModulePath = (Resolve-Path '..'),
    [string]$GalleryApiKey
)

if (-not $GalleryApiKey) {
    $GalleryApiKey = Read-Host -AsSecureString "Enter PSGallery API key"
}

Write-Host "[*] Testing module manifest..."
$manifest = Join-Path $ModulePath 'OffsetInspect.psd1'
Test-ModuleManifest -Path $manifest | Out-Null

Write-Host "[*] Importing module for sanity check..."
Import-Module $manifest -Force

Write-Host "[*] Running Pester tests..."
Invoke-Pester -Path (Join-Path $ModulePath 'tests') -Output Summary -EnableExit

Write-Host "[*] Locating code-signing certificate..."
$cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1
if (-not $cert) {
    throw "No code-signing certificate found in Cert:\CurrentUser\My. Create or import one first."
}

$filesToSign = @(
    'OffsetInspect.psm1',
    'OffsetInspect.ps1'
) | ForEach-Object { Join-Path $ModulePath $_ }

foreach ($file in $filesToSign) {
    Write-Host "[*] Signing $file"
    Set-AuthenticodeSignature -FilePath $file -Certificate $cert | Out-String | Write-Host
}

Write-Host "[*] Publishing OffsetInspect to PSGallery..."
Publish-Module -Path $ModulePath `
               -Repository PSGallery `
               -NuGetApiKey $GalleryApiKey `
               -Verbose

Write-Host "[+] Done."