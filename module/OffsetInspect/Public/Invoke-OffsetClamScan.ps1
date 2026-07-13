function Invoke-OffsetClamScan {
    <#
    .SYNOPSIS
        Scans a file with the ClamAV on-demand engine and returns a normalized detection result.

    .DESCRIPTION
        Runs clamscan against a file and returns a result object with Status (Clean, Detected, or
        Error), the reported signature name, and the raw provider exit code. This adds a
        cross-platform, antivirus-independent detection lens alongside AMSI/Defender and YARA.
        Because clamscan loads its full signature database on every invocation, this is a
        single-file detector, not a boundary-search provider (that would require the clamd
        daemon). Requires ClamAV installed with signature databases (freshclam).

    .PARAMETER FilePath
        The file to scan.

    .PARAMETER ClamScanPath
        Optional explicit path to clamscan (otherwise resolved from PATH / default install).

    .PARAMETER DatabasePath
        Optional signature-database directory passed to clamscan --database.

    .PARAMETER TimeoutSeconds
        Maximum seconds to wait for the scan (default 120).

    .EXAMPLE
        Invoke-OffsetClamScan .\sample.bin
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [string]$ClamScanPath,

        [string]$DatabasePath,

        [ValidateRange(1, 3600)]
        [int]$TimeoutSeconds = 120
    )

    $resolvedFile = (Resolve-Path -LiteralPath $FilePath -ErrorAction Stop).Path
    $clamScan = Resolve-OIClamScanExecutable -ClamScanPath $ClamScanPath

    $arguments = New-Object 'System.Collections.Generic.List[string]'
    $arguments.Add('--no-summary')
    if (-not [string]::IsNullOrWhiteSpace($DatabasePath)) {
        $arguments.Add('--database=' + (Resolve-Path -LiteralPath $DatabasePath -ErrorAction Stop).Path)
    }
    $arguments.Add($resolvedFile)

    # Single quoted argument string (WinPS 5.1's ProcessStartInfo has no ArgumentList).
    $quoted = @($arguments | ForEach-Object {
        if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
    })

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $clamScan
    $startInfo.Arguments = ($quoted -join ' ')
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true

    $process = $null
    try {
        $process = [System.Diagnostics.Process]::Start($startInfo)
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try { $process.Kill() } catch { Write-Verbose "clamscan kill failed: $($_.Exception.Message)" }
            throw "ClamAV scan timed out after $TimeoutSeconds seconds."
        }
        $stdout = $stdoutTask.Result
        $stderr = $stderrTask.Result
        $exitCode = $process.ExitCode
    }
    finally {
        if ($null -ne $process) { $process.Dispose() }
    }

    return (ConvertFrom-OIClamScanOutput -Output $stdout -ExitCode $exitCode -FilePath $resolvedFile -RawError $stderr)
}
