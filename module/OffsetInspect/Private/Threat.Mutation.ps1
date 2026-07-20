function Get-OILongestTokenSpan {
    <#
        Returns the start/length/value of the longest alphanumeric run in the content - a
        heuristic for the distinctive token a literal signature most likely keys on. Returns
        $null when no run of at least MinimumLength is present. Pure and cross-platform.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Content,

        [int]$MinimumLength = 4
    )

    $best = $null
    foreach ($match in [regex]::Matches($Content, '[A-Za-z0-9]+')) {
        if ($match.Length -ge $MinimumLength -and ($null -eq $best -or $match.Length -gt $best.Length)) {
            $best = [pscustomobject]@{ Start = $match.Index; Length = $match.Length; Value = $match.Value }
        }
    }
    return $best
}

function Get-OIMutationVariant {
    <#
        Produces one perturbed variant of the content for a named transform class. These are
        the standard signature-robustness perturbations detection engineers test against: an
        exact-literal signature breaks under them, a robust one does not. String-targeting
        transforms perturb the longest distinctive token (via TokenSpan). Pure and
        cross-platform; returns the content unchanged when a transform has nothing to act on.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Content,

        [Parameter(Mandatory = $true)]
        [ValidateSet('CaseInversion', 'StringConcatenation', 'CommentInsertion', 'WhitespaceInjection')]
        [string]$Transform,

        [AllowNull()]
        $TokenSpan
    )

    if ($Transform -eq 'CaseInversion') {
        $sb = New-Object System.Text.StringBuilder
        foreach ($ch in $Content.ToCharArray()) {
            if ($ch -ge 'a' -and $ch -le 'z') { [void]$sb.Append([char]([int][char]$ch - 32)) }
            elseif ($ch -ge 'A' -and $ch -le 'Z') { [void]$sb.Append([char]([int][char]$ch + 32)) }
            else { [void]$sb.Append($ch) }
        }
        return $sb.ToString()
    }

    if ($null -eq $TokenSpan) { return $Content }

    $mid = [int]$TokenSpan.Start + [int][Math]::Floor([int]$TokenSpan.Length / 2)
    $insert = switch ($Transform) {
        'StringConcatenation' { "'+'" }
        'CommentInsertion' { '<##>' }
        'WhitespaceInjection' { ' ' }
    }
    return $Content.Substring(0, $mid) + $insert + $Content.Substring($mid)
}

function Test-OIMutationSet {
    <#
        Runs the baseline scan and one scan per transform through an injected scanner
        scriptblock ({ param($text) -> status string }), and reports which transforms
        neutralized detection. Pure with respect to the provider (the scanner is injected),
        so it is unit-tested cross-platform with a fake scanner. The public wrapper supplies
        the real in-memory AMSI scanner.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Content,

        [Parameter(Mandatory = $true)]
        [string[]]$Transforms,

        [Parameter(Mandatory = $true)]
        [scriptblock]$Scanner
    )

    $isPositive = { param($s) ($s -eq 'Detected' -or $s -eq 'Blocked') }

    $baselineStatus = & $Scanner $Content
    $baselineDetected = [bool](& $isPositive $baselineStatus)
    $token = Get-OILongestTokenSpan -Content $Content

    $results = New-Object 'System.Collections.Generic.List[object]'
    foreach ($transform in $Transforms) {
        $variant = Get-OIMutationVariant -Content $Content -Transform $transform -TokenSpan $token
        # Case-sensitive: CaseInversion changes only letter case, which -eq would miss.
        $unchanged = ($variant -ceq $Content)
        $status = if ($unchanged) { $baselineStatus } else { & $Scanner $variant }
        $evaded = $baselineDetected -and -not [bool](& $isPositive $status)

        $note = if ($unchanged) { 'Transform had no target in this content (no distinctive token); not exercised.' } else { $null }
        $results.Add([pscustomobject]@{
            Transform     = $transform
            VariantStatus = $status
            Evaded        = $evaded
            Note          = $note
        })
    }

    $evasions = @($results | Where-Object { $_.Evaded })
    return [pscustomobject]@{
        BaselineStatus   = $baselineStatus
        BaselineDetected = $baselineDetected
        TargetToken      = if ($null -ne $token) { $token.Value } else { $null }
        Results          = $results.ToArray()
        EvasionCount     = $evasions.Count
    }
}
