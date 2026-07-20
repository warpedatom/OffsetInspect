function Invoke-OffsetMutationTest {
    <#
    .SYNOPSIS
        Tests how robust a signature is by perturbing a detected sample in memory and re-scanning.

    .DESCRIPTION
        For authorized detection-engineering and red-team engagements. Given a sample that AMSI
        currently detects, this applies a set of standard signature-robustness perturbations
        (case inversion, string-literal concatenation, comment insertion, whitespace injection)
        and re-scans each variant with AMSI to report which transform CLASSES neutralize
        detection. That tells you whether the signature is a brittle exact-literal match or is
        robust to common obfuscation - the core detection-engineering question, and the same
        insight an authorized operator needs to assess a control.

        Everything happens IN MEMORY: variants are scanned via AMSI's in-process interface and
        are never written to disk, so no evasive artifacts are produced and Defender real-time
        protection is not involved. AMSI only (Defender file scanning would require disk writes).
        The command refuses to run without -AuthorizedEngagement.

    .PARAMETER FilePath
        The sample to test. Must currently be detected by AMSI for the results to be meaningful.

    .PARAMETER AuthorizedEngagement
        Required acknowledgement that you are authorized to test this sample. The command will
        not run without it.

    .PARAMETER Transform
        Which robustness transform classes to test (default: all four).

    .EXAMPLE
        Invoke-OffsetMutationTest -FilePath .\flagged.ps1 -AuthorizedEngagement

    .EXAMPLE
        Invoke-OffsetMutationTest .\flagged.ps1 -AuthorizedEngagement -Transform CaseInversion, StringConcatenation
    #>
    [CmdletBinding()]
    [OutputType('OffsetInspect.MutationTestResult')]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath,

        [Parameter(Mandatory = $true)]
        [switch]$AuthorizedEngagement,

        [ValidateSet('CaseInversion', 'StringConcatenation', 'CommentInsertion', 'WhitespaceInjection')]
        [string[]]$Transform = @('CaseInversion', 'StringConcatenation', 'CommentInsertion', 'WhitespaceInjection')
    )

    if (-not $AuthorizedEngagement) {
        throw 'Invoke-OffsetMutationTest generates detection-evasion variants and is for authorized engagements only. Re-run with -AuthorizedEngagement to confirm you are authorized to test this sample.'
    }
    Write-Warning 'Signature-robustness testing: evasion variants are generated and scanned IN MEMORY (nothing is written to disk). Use only against samples you are authorized to test.'

    if (-not (Test-OIIsWindows)) {
        throw 'Invoke-OffsetMutationTest requires Windows (it uses the in-memory AMSI interface).'
    }

    $resolved = (Resolve-Path -LiteralPath $FilePath -ErrorAction Stop).Path
    if ((Get-Item -LiteralPath $resolved).PSIsContainer) { throw "Path is a directory, not a file: $resolved" }
    $content = [System.IO.File]::ReadAllText($resolved)

    Initialize-OIAmsiInterop
    $session = New-Object 'OffsetInspect.Interop.AmsiSession' -ArgumentList 'OffsetInspect.MutationTest'
    try {
        $scanner = {
            param($text)
            $response = $session.ScanString($text, 'OffsetInspect.MutationTest')
            (ConvertFrom-OIAmsiResponse -Response $response).Status
        }
        $set = Test-OIMutationSet -Content $content -Transforms $Transform -Scanner $scanner
    }
    finally {
        $session.Dispose()
    }

    $summary = if (-not $set.BaselineDetected) {
        "Baseline is $($set.BaselineStatus) under AMSI - nothing to test (the sample is not currently detected)."
    }
    elseif ($set.EvasionCount -eq 0) {
        "Signature is robust to the $($Transform.Count) tested transform class(es); none neutralized detection."
    }
    else {
        $names = @($set.Results | Where-Object { $_.Evaded } | ForEach-Object { $_.Transform }) -join ', '
        "Signature is brittle: neutralized by $($set.EvasionCount) of $($Transform.Count) transform class(es) - $names."
    }

    return [pscustomobject]@{
        PSTypeName        = 'OffsetInspect.MutationTestResult'
        File              = $resolved
        Engine            = 'AMSI'
        BaselineStatus    = $set.BaselineStatus
        BaselineDetected  = $set.BaselineDetected
        TargetToken       = $set.TargetToken
        TransformsTested  = $Transform
        Results           = $set.Results
        EvasionCount      = $set.EvasionCount
        RobustnessSummary = $summary
    }
}
