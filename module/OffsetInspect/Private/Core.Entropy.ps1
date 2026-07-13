function Get-OIShannonEntropy {
    <#
        Shannon entropy of a byte buffer in bits per byte (0.0 = single value,
        8.0 = uniform over all 256 values). Pure arithmetic, cross-platform,
        unit-tested directly.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [byte[]]$Bytes,

        [int]$Length = -1
    )

    $count = if ($Length -lt 0) { $Bytes.Length } else { [Math]::Min($Length, $Bytes.Length) }
    if ($count -le 0) { return 0.0 }

    # Prefer the compiled accelerator (tight native frequency loop); fall back to the
    # pure-PowerShell computation if it cannot be compiled. Both produce identical results.
    try {
        Initialize-OIEntropyAccelerator
        return [Math]::Round([OffsetInspect.Native.EntropyCalculator]::Shannon($Bytes, $count), 6)
    }
    catch {
        Write-Verbose "Entropy accelerator unavailable, using PowerShell fallback: $($_.Exception.Message)"
        $frequencies = New-Object 'int[]' 256
        for ($i = 0; $i -lt $count; $i++) {
            $frequencies[$Bytes[$i]]++
        }

        $entropy = 0.0
        foreach ($frequency in $frequencies) {
            if ($frequency -gt 0) {
                $probability = $frequency / $count
                $entropy -= $probability * [Math]::Log($probability, 2)
            }
        }

        return [Math]::Round($entropy, 6)
    }
}
