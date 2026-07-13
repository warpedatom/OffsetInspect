function Resolve-OIYaraExecutable {
    <#
        Locates the YARA command-line engine: an explicit -YaraPath, then 'yara'/'yara64'
        on PATH, then the default winget install location on Windows. Throws with an
        install hint if none is found.
    #>
    [CmdletBinding()]
    param(
        [string]$YaraPath
    )

    if (-not [string]::IsNullOrWhiteSpace($YaraPath)) {
        if (Test-Path -LiteralPath $YaraPath) { return (Resolve-Path -LiteralPath $YaraPath).Path }
        throw "YARA executable not found at '$YaraPath'."
    }

    foreach ($name in @('yara', 'yara64')) {
        $command = Get-Command $name -CommandType Application -ErrorAction SilentlyContinue
        if ($null -ne $command) { return $command.Source }
    }

    $localAppData = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    if (-not [string]::IsNullOrWhiteSpace($localAppData)) {
        $packageRoot = Join-Path $localAppData 'Microsoft\WinGet\Packages'
        if (Test-Path -LiteralPath $packageRoot) {
            $candidate = Get-ChildItem -LiteralPath $packageRoot -Recurse -Include 'yara64.exe', 'yara.exe' -ErrorAction SilentlyContinue |
                Select-Object -First 1
            if ($null -ne $candidate) { return $candidate.FullName }
        }
    }

    throw 'YARA executable not found. Install YARA (e.g. "winget install VirusTotal.YARA") or pass -YaraPath.'
}

function ConvertFrom-OIYaraOutput {
    <#
        Parses `yara -s` output into structured match records. Rule-match lines are
        "<RuleName> <filepath>"; string-match lines (with -s) are "0x<offset>:$<id>: <data>".
        A rule that matches without any reported strings yields one record with a null
        offset. Pure string parsing, cross-platform, unit-tested directly.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Output,

        [string]$FilePath
    )

    $ruleOrder = New-Object 'System.Collections.Generic.List[string]'
    $ruleStrings = @{}
    $currentRule = $null

    foreach ($rawLine in ($Output -split "`n")) {
        $line = $rawLine.TrimEnd([char]13)
        if ([string]::IsNullOrWhiteSpace($line)) { continue }

        if ($line -match '^0x([0-9A-Fa-f]+):\$([^:]+):\s?(.*)$') {
            if ($null -ne $currentRule) {
                $ruleStrings[$currentRule].Add([pscustomobject]@{
                    File      = $FilePath
                    Rule      = $currentRule
                    StringId  = '$' + $matches[2]
                    Offset    = [Convert]::ToInt64($matches[1], 16)
                    OffsetHex = '0x' + $matches[1].ToLowerInvariant()
                    Data      = $matches[3]
                })
            }
        }
        elseif ($line -match '^([A-Za-z_][A-Za-z0-9_]*)\s+(.+)$') {
            $currentRule = $matches[1]
            if (-not $ruleStrings.ContainsKey($currentRule)) {
                $ruleStrings[$currentRule] = New-Object 'System.Collections.Generic.List[object]'
                $ruleOrder.Add($currentRule)
            }
        }
    }

    $results = New-Object 'System.Collections.Generic.List[object]'
    foreach ($rule in $ruleOrder) {
        $strings = $ruleStrings[$rule]
        if ($strings.Count -eq 0) {
            $results.Add([pscustomobject]@{
                File = $FilePath; Rule = $rule; StringId = $null; Offset = $null; OffsetHex = $null; Data = $null
            })
        }
        else {
            foreach ($stringMatch in $strings) { $results.Add($stringMatch) }
        }
    }

    return $results.ToArray()
}
