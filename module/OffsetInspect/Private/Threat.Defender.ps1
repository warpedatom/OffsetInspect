function Get-OIDefenderCommandPath {
    [CmdletBinding()]
    param()

    if (-not (Test-OIIsWindows)) {
        throw 'Microsoft Defender scanning is available only on Windows.'
    }

    $candidates = New-Object 'System.Collections.Generic.List[object]'
    $platformRoot = if ([string]::IsNullOrWhiteSpace($env:ProgramData)) { $null } else { Join-Path $env:ProgramData 'Microsoft\Windows Defender\Platform' }

    if ($platformRoot -and (Test-Path -LiteralPath $platformRoot)) {
        foreach ($directory in (Get-ChildItem -LiteralPath $platformRoot -Directory -ErrorAction SilentlyContinue)) {
            $command = Join-Path $directory.FullName 'MpCmdRun.exe'
            if (-not (Test-Path -LiteralPath $command)) { continue }

            $parsedVersion = $null
            try { $parsedVersion = [version]$directory.Name } catch { Write-Verbose "Ignoring non-version Defender platform directory: $($directory.Name)" }
            $candidates.Add([pscustomobject]@{
                Path    = $command
                Version = $parsedVersion
                Name    = $directory.Name
            })
        }
    }

    $selected = $candidates |
        Sort-Object -Property { if ($null -ne $_.Version) { $_.Version } else { [version]'0.0' } } -Descending |
        Select-Object -First 1

    if ($null -ne $selected) {
        return $selected.Path
    }

    $fallbacks = New-Object 'System.Collections.Generic.List[string]'
    if (-not [string]::IsNullOrWhiteSpace($env:ProgramFiles)) {
        $fallbacks.Add((Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'))
    }
    if (-not [string]::IsNullOrWhiteSpace(${env:ProgramFiles(x86)})) {
        $fallbacks.Add((Join-Path ${env:ProgramFiles(x86)} 'Windows Defender\MpCmdRun.exe'))
    }

    foreach ($fallback in $fallbacks) {
        if (Test-Path -LiteralPath $fallback) {
            return $fallback
        }
    }

    throw 'MpCmdRun.exe was not found in the Defender platform or legacy installation directories.'
}

function Get-OIDefenderSignatureName {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$Output
    )

    if ([string]::IsNullOrWhiteSpace($Output)) { return $null }

    $patterns = @(
        '(?im)^\s*Threat(?:\s+Name)?\s*:\s*(?<name>[^\r\n]+)',
        '(?im)^\s*Detected\s+threat\s*:\s*(?<name>[^\r\n]+)',
        '(?im)^\s*Threat\s+\d+\s*:\s*(?<name>[^\r\n]+)'
    )

    foreach ($pattern in $patterns) {
        $match = [regex]::Match($Output, $pattern)
        if ($match.Success) {
            return $match.Groups['name'].Value.Trim()
        }
    }

    return $null
}

function ConvertFrom-OIDefenderOutput {
    [CmdletBinding()]
    param(
        [AllowNull()]
        [string]$Output,

        [Parameter(Mandatory = $true)]
        [int]$ExitCode
    )

    $normalizedOutput = if ($null -eq $Output) { [string]::Empty } else { $Output.Trim() }
    $signatureName = Get-OIDefenderSignatureName -Output $normalizedOutput
    $detectedPattern = '(?im)(threat\s+(?:was\s+)?found|found\s+(?:a\s+)?threat|detected\s+threat|Threat(?:\s+Name)?\s*:|Threat\s+\d+\s*:)'
    $cleanPattern = '(?im)(no\s+threats?\s+(?:(?:was|were)\s+)?found|found\s+no\s+threats?)'
    $hasDetectionMarker = $normalizedOutput -match $detectedPattern
    $hasCleanMarker = $normalizedOutput -match $cleanPattern

    if ($hasDetectionMarker -and $hasCleanMarker) {
        $status = 'Indeterminate'
        $message = 'MpCmdRun.exe output contained both clean and detection markers.'
    }
    elseif ($hasDetectionMarker) {
        $status = 'Detected'
        $message = $null
    }
    elseif ($ExitCode -eq 0 -and $hasCleanMarker) {
        $status = 'Clean'
        $message = $null
    }
    else {
        $status = 'Indeterminate'
        $message = "MpCmdRun.exe returned exit code $ExitCode without an unambiguous clean or detection marker."
    }

    return [pscustomobject]@{
        Status        = $status
        SignatureName = $signatureName
        Message       = $message
    }
}

function Invoke-OIDefenderFileScan {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CommandPath,

        [Parameter(Mandatory = $true)]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [ValidateRange(1, 600)]
        [int]$TimeoutSeconds
    )

    if (-not (Test-Path -LiteralPath $FilePath)) {
        return [pscustomobject]@{
            Status         = 'Error'
            ProviderResult = $null
            HResult        = $null
            SignatureName  = $null
            Message        = "Temporary scan file was not found: $FilePath"
            RawOutput      = $null
            ExitCode       = $null
        }
    }

    $process = New-Object System.Diagnostics.Process
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $CommandPath
    $startInfo.Arguments = '-Scan -ScanType 3 -File "{0}" -DisableRemediation' -f $FilePath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process.StartInfo = $startInfo

    try {
        if (-not $process.Start()) {
            throw 'The Defender process did not start.'
        }

        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $completed = $process.WaitForExit($TimeoutSeconds * 1000)

        if (-not $completed) {
            try {
                $process.Kill()
                $null = $process.WaitForExit(5000)
            }
            catch {
                Write-Verbose "Unable to terminate timed-out Defender process cleanly: $($_.Exception.Message)"
            }
            return [pscustomobject]@{
                Status         = 'Timeout'
                ProviderResult = $null
                HResult        = $null
                SignatureName  = $null
                Message        = "Microsoft Defender exceeded the $TimeoutSeconds-second scan timeout."
                RawOutput      = $null
                ExitCode       = $null
            }
        }

        $process.WaitForExit()
        $stdout = $stdoutTask.Result
        $stderr = $stderrTask.Result
        $combined = (($stdout, $stderr) -join [Environment]::NewLine).Trim()
        $exitCode = $process.ExitCode
        $classification = ConvertFrom-OIDefenderOutput -Output $combined -ExitCode $exitCode

        return [pscustomobject]@{
            Status         = $classification.Status
            ProviderResult = $exitCode
            HResult        = $null
            SignatureName  = $classification.SignatureName
            Message        = $classification.Message
            RawOutput      = $combined
            ExitCode       = $exitCode
        }
    }
    catch {
        return [pscustomobject]@{
            Status         = 'Error'
            ProviderResult = $null
            HResult        = $null
            SignatureName  = $null
            Message        = $_.Exception.Message
            RawOutput      = $null
            ExitCode       = $null
        }
    }
    finally {
        $process.Dispose()
    }
}

function Get-OIDefenderProviderMetadata {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$CommandPath
    )

    $metadata = [ordered]@{
        Provider          = 'Microsoft Defender'
        CommandPath       = $CommandPath
        OutputParser      = 'Conservative English marker parser'
        LocalizationNote  = 'Unrecognized or localized output is returned as Indeterminate rather than Clean.'
    }

    try {
        $metadata.CommandVersion = (Get-Item -LiteralPath $CommandPath).VersionInfo.FileVersion
    }
    catch {
        $metadata.CommandVersionWarning = $_.Exception.Message
    }

    $command = Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        try {
            $status = Get-MpComputerStatus -ErrorAction Stop
            $metadata.AntivirusEnabled = $status.AntivirusEnabled
            $metadata.RealTimeProtectionEnabled = $status.RealTimeProtectionEnabled
            $metadata.AntivirusSignatureVersion = $status.AntivirusSignatureVersion
            $metadata.AntivirusSignatureLastUpdated = $status.AntivirusSignatureLastUpdated
            $metadata.AMEngineVersion = $status.AMEngineVersion
            $metadata.AMProductVersion = $status.AMProductVersion
        }
        catch {
            $metadata.MetadataWarning = $_.Exception.Message
        }
    }

    return [pscustomobject]$metadata
}
