function Invoke-OffsetYaraScan {
    <#
    .SYNOPSIS
        Scans a file with the YARA engine and returns matches with their byte offsets.

    .DESCRIPTION
        Runs the YARA command-line engine against a file using one or more rule files and returns
        one record per matched string (rule, string id, byte offset, matched data), or one record
        per matched rule when strings are not requested. The offsets feed directly into
        Invoke-OffsetInspect for context. This complements the AMSI/Defender detection-boundary
        view with analyst-authored signatures and needs no antivirus installed - only the YARA
        engine (for example `winget install VirusTotal.YARA`). Cross-platform where YARA is present.

    .PARAMETER FilePath
        The file to scan.

    .PARAMETER RulePath
        One or more YARA rule files.

    .PARAMETER YaraPath
        Optional explicit path to the YARA executable (otherwise resolved from PATH / winget).

    .PARAMETER NoStrings
        Report matched rules only, without per-string offsets (faster).

    .PARAMETER TimeoutSeconds
        Maximum seconds to wait for the scan (default 60).

    .EXAMPLE
        Invoke-OffsetYaraScan .\sample.bin -RulePath .\rules\malware.yar

    .EXAMPLE
        Invoke-OffsetYaraScan .\sample.bin -RulePath .\rules.yar |
            ForEach-Object { Invoke-OffsetInspect $_.File $_.Offset -ContextLines 2 }
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$RulePath,

        [string]$YaraPath,

        [switch]$NoStrings,

        [ValidateRange(1, 3600)]
        [int]$TimeoutSeconds = 60
    )

    $resolvedFile = (Resolve-Path -LiteralPath $FilePath -ErrorAction Stop).Path
    $resolvedRules = @(foreach ($rule in $RulePath) { (Resolve-Path -LiteralPath $rule -ErrorAction Stop).Path })
    $yaraExecutable = Resolve-OIYaraExecutable -YaraPath $YaraPath

    $arguments = New-Object 'System.Collections.Generic.List[string]'
    if (-not $NoStrings) { $arguments.Add('-s') }
    foreach ($rule in $resolvedRules) { $arguments.Add($rule) }
    $arguments.Add($resolvedFile)

    # WinPS 5.1's .NET Framework ProcessStartInfo has no ArgumentList, so build a
    # single quoted argument string that is safe on both editions.
    $quoted = @($arguments | ForEach-Object {
        if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
    })

    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $yaraExecutable
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
            try { $process.Kill() } catch { Write-Verbose "YARA process kill failed: $($_.Exception.Message)" }
            throw "YARA scan timed out after $TimeoutSeconds seconds."
        }
        $stdout = $stdoutTask.Result
        $stderr = $stderrTask.Result
        $exitCode = $process.ExitCode
    }
    finally {
        if ($null -ne $process) { $process.Dispose() }
    }

    if ($exitCode -ne 0 -and -not [string]::IsNullOrWhiteSpace($stderr)) {
        throw "YARA reported an error (exit $exitCode): $($stderr.Trim())"
    }

    return (ConvertFrom-OIYaraOutput -Output $stdout -FilePath $resolvedFile)
}
