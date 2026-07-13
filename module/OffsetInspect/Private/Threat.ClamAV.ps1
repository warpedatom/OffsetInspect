function Resolve-OIClamScanExecutable {
    <#
        Locates the ClamAV on-demand scanner (clamscan): an explicit -ClamScanPath, then
        'clamscan' on PATH, then the default Windows install location. Throws with an install
        hint if none is found.
    #>
    [CmdletBinding()]
    param(
        [string]$ClamScanPath
    )

    if (-not [string]::IsNullOrWhiteSpace($ClamScanPath)) {
        if (Test-Path -LiteralPath $ClamScanPath) { return (Resolve-Path -LiteralPath $ClamScanPath).Path }
        throw "ClamAV scanner not found at '$ClamScanPath'."
    }

    $command = Get-Command 'clamscan' -CommandType Application -ErrorAction SilentlyContinue
    if ($null -ne $command) { return $command.Source }

    $candidates = @(
        (Join-Path $env:ProgramFiles 'ClamAV\clamscan.exe'),
        (Join-Path ${env:ProgramFiles(x86)} 'ClamAV\clamscan.exe')
    )
    foreach ($candidate in $candidates) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path -LiteralPath $candidate)) { return $candidate }
    }

    throw 'ClamAV (clamscan) not found. Install ClamAV (e.g. "winget install Cisco.ClamAV") and run freshclam, or pass -ClamScanPath.'
}

function ConvertFrom-OIClamScanOutput {
    <#
        Parses `clamscan --no-summary` output into a normalized status. Per-file lines are
        "<path>: OK" (clean) or "<path>: <Signature> FOUND" (detected), otherwise falling
        back to the process return code (0 = clean, 1 = detected, else error). Pure string
        parsing, cross-platform, unit-tested directly.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Output,

        [Parameter(Mandatory = $true)]
        [int]$ExitCode,

        [string]$FilePath,

        [string]$RawError
    )

    $status = 'Error'
    $signature = $null

    foreach ($rawLine in ($Output -split "`n")) {
        $line = $rawLine.TrimEnd([char]13)
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        if ($line -match '(\S+)\s+FOUND\s*$') {
            $status = 'Detected'
            $signature = $matches[1]
            break
        }
        elseif ($line -match ':\s*OK\s*$') {
            $status = 'Clean'
            break
        }
    }

    if ($status -eq 'Error') {
        if ($ExitCode -eq 0) { $status = 'Clean' }
        elseif ($ExitCode -eq 1) { $status = 'Detected' }
    }

    $result = [pscustomobject]@{
        File           = $FilePath
        Status         = $status
        SignatureName  = $signature
        ProviderResult = $ExitCode
        Error          = if ($status -eq 'Error') { if ([string]::IsNullOrWhiteSpace($RawError)) { 'ClamAV returned an error.' } else { $RawError.Trim() } } else { $null }
    }
    $result.PSObject.TypeNames.Insert(0, 'OffsetInspect.ClamScanResult')
    return $result
}
