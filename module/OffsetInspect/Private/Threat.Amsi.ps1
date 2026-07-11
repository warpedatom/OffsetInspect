function Initialize-OIAmsiInterop {
    [CmdletBinding()]
    param()

    if (-not (Test-OIIsWindows)) {
        throw 'AMSI is available only on Windows.'
    }

    if ('OffsetInspect.Interop.AmsiSession' -as [type]) {
        return
    }

    $source = @'
using System;
using System.Runtime.InteropServices;

namespace OffsetInspect.Interop
{
    public sealed class AmsiScanResponse
    {
        public int HResult { get; private set; }
        public int Result { get; private set; }

        public AmsiScanResponse(int hResult, int result)
        {
            HResult = hResult;
            Result = result;
        }
    }

    public sealed class AmsiSession : IDisposable
    {
        private IntPtr _context;
        private IntPtr _session;
        private bool _disposed;

        [DllImport("amsi.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
        private static extern int AmsiInitialize(string appName, out IntPtr amsiContext);

        [DllImport("amsi.dll", CallingConvention = CallingConvention.Winapi)]
        private static extern int AmsiOpenSession(IntPtr amsiContext, out IntPtr amsiSession);

        [DllImport("amsi.dll", CallingConvention = CallingConvention.Winapi)]
        private static extern void AmsiCloseSession(IntPtr amsiContext, IntPtr amsiSession);

        [DllImport("amsi.dll", CallingConvention = CallingConvention.Winapi)]
        private static extern void AmsiUninitialize(IntPtr amsiContext);

        [DllImport("amsi.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
        private static extern int AmsiScanBuffer(
            IntPtr amsiContext,
            byte[] buffer,
            uint length,
            string contentName,
            IntPtr amsiSession,
            out int result);

        [DllImport("amsi.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Winapi)]
        private static extern int AmsiScanString(
            IntPtr amsiContext,
            string content,
            string contentName,
            IntPtr amsiSession,
            out int result);

        public AmsiSession(string appName)
        {
            int hr = AmsiInitialize(appName, out _context);
            if (hr < 0)
            {
                Marshal.ThrowExceptionForHR(hr);
            }

            hr = AmsiOpenSession(_context, out _session);
            if (hr < 0)
            {
                AmsiUninitialize(_context);
                _context = IntPtr.Zero;
                Marshal.ThrowExceptionForHR(hr);
            }
        }

        public AmsiScanResponse ScanBytes(byte[] buffer, string contentName)
        {
            return ScanBytePrefix(buffer, buffer == null ? 0 : buffer.Length, contentName);
        }

        public AmsiScanResponse ScanBytePrefix(byte[] buffer, int length, string contentName)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException("AmsiSession");
            }

            if (buffer == null)
            {
                buffer = new byte[0];
            }

            if (length < 0 || length > buffer.Length)
            {
                throw new ArgumentOutOfRangeException("length");
            }

            int result;
            int hr = AmsiScanBuffer(_context, buffer, (uint)length, contentName, _session, out result);
            return new AmsiScanResponse(hr, result);
        }

        public AmsiScanResponse ScanString(string content, string contentName)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException("AmsiSession");
            }

            if (content == null)
            {
                content = String.Empty;
            }

            int result;
            int hr = AmsiScanString(_context, content, contentName, _session, out result);
            return new AmsiScanResponse(hr, result);
        }

        public void Dispose()
        {
            if (_disposed)
            {
                return;
            }

            if (_session != IntPtr.Zero && _context != IntPtr.Zero)
            {
                AmsiCloseSession(_context, _session);
                _session = IntPtr.Zero;
            }

            if (_context != IntPtr.Zero)
            {
                AmsiUninitialize(_context);
                _context = IntPtr.Zero;
            }

            _disposed = true;
            GC.SuppressFinalize(this);
        }

        ~AmsiSession()
        {
            Dispose();
        }
    }
}
'@

    Add-Type -TypeDefinition $source -Language CSharp -ErrorAction Stop
}

function ConvertFrom-OIAmsiResponse {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Response
    )

    $hresult = [int]$Response.HResult
    $providerResult = [int]$Response.Result

    if ($hresult -lt 0) {
        $unsignedHResult = [BitConverter]::ToUInt32([BitConverter]::GetBytes($hresult), 0)
        $hresultText = '0x{0:X8}' -f $unsignedHResult
        return [pscustomobject]@{
            Status         = 'Error'
            ProviderResult = $providerResult
            HResult        = $hresultText
            SignatureName  = $null
            Message        = "AMSI returned HRESULT $hresultText."
            RawOutput      = $null
        }
    }

    if ($providerResult -ge 32768) {
        $status = 'Detected'
    }
    elseif ($providerResult -ge 16384 -and $providerResult -le 20479) {
        $status = 'Blocked'
    }
    elseif ($providerResult -eq 0) {
        $status = 'Clean'
    }
    else {
        $status = 'NotDetected'
    }

    return [pscustomobject]@{
        Status         = $status
        ProviderResult = $providerResult
        HResult        = '0x00000000'
        SignatureName  = $null
        Message        = $null
        RawOutput      = $null
    }
}

function Get-OIAmsiProviderMetadata {
    [CmdletBinding()]
    param()

    $metadata = [ordered]@{
        Provider = 'AMSI'
        Platform = 'Windows'
        MetadataNote = 'Defender status fields are supplemental and do not prove which AMSI provider handled the scan.'
    }

    $command = Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue
    if ($null -ne $command) {
        try {
            $status = Get-MpComputerStatus -ErrorAction Stop
            $metadata.DefenderAntivirusEnabled = $status.AntivirusEnabled
            $metadata.DefenderRealTimeProtectionEnabled = $status.RealTimeProtectionEnabled
            $metadata.DefenderSignatureVersion = $status.AntivirusSignatureVersion
            $metadata.DefenderEngineVersion = $status.AMEngineVersion
            $metadata.DefenderProductVersion = $status.AMProductVersion
        }
        catch {
            $metadata.MetadataWarning = $_.Exception.Message
        }
    }

    return [pscustomobject]$metadata
}
