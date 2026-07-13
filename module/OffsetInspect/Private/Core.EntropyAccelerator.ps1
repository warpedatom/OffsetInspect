function Initialize-OIEntropyAccelerator {
    <#
        Compiles a small .NET helper that computes Shannon entropy in a tight native
        loop, so the byte-frequency pass runs at compiled speed instead of interpreted
        PowerShell. Compiled once per session (guarded like Initialize-OIAmsiInterop);
        callers fall back to the pure-PowerShell path if compilation is unavailable.
    #>
    [CmdletBinding()]
    param()

    if ('OffsetInspect.Native.EntropyCalculator' -as [type]) {
        return
    }

    $source = @'
namespace OffsetInspect.Native
{
    public static class EntropyCalculator
    {
        public static double Shannon(byte[] buffer, int length)
        {
            if (buffer == null || length <= 0)
            {
                return 0.0;
            }
            if (length > buffer.Length)
            {
                length = buffer.Length;
            }

            int[] frequencies = new int[256];
            for (int i = 0; i < length; i++)
            {
                frequencies[buffer[i]]++;
            }

            double entropy = 0.0;
            double total = (double)length;
            for (int value = 0; value < 256; value++)
            {
                if (frequencies[value] > 0)
                {
                    double probability = frequencies[value] / total;
                    entropy -= probability * System.Math.Log(probability, 2.0);
                }
            }

            return entropy;
        }
    }
}
'@

    Add-Type -TypeDefinition $source -Language CSharp -ErrorAction Stop
}
