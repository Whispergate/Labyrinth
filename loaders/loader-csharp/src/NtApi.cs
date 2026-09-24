using System;
using System.Runtime.InteropServices;

static class NtApi
{
    internal const uint MemCommit = 0x1000;
    internal const uint MemReserve = 0x2000;
    internal const uint PageReadWrite = 0x04;
    internal const uint PageExecuteRead = 0x20;
    internal const uint PageExecuteReadWrite = 0x40;
    internal const uint SecCommit = 0x8000000;
    internal const uint SectionAllAccess = 0xF001F;
    internal const uint ThreadAllAccess = 0x1FFFFF;

    internal static readonly IntPtr CurrentProcess = new IntPtr(-1);
    internal static readonly IntPtr CurrentThread = new IntPtr(-2);

    internal static bool NtSuccess(int status) => status >= 0;

    [DllImport("ntdll.dll")]
    internal static extern int NtAllocateVirtualMemory(
        IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits,
        ref IntPtr RegionSize, uint AllocationType, uint Protect);

    [DllImport("ntdll.dll")]
    internal static extern int NtProtectVirtualMemory(
        IntPtr ProcessHandle, ref IntPtr BaseAddress, ref IntPtr RegionSize,
        uint NewProtect, out uint OldProtect);

    [DllImport("ntdll.dll")]
    internal static extern int NtCreateThreadEx(
        out IntPtr ThreadHandle, uint DesiredAccess, IntPtr ObjectAttributes,
        IntPtr ProcessHandle, IntPtr StartRoutine, IntPtr Argument,
        uint CreateFlags, IntPtr ZeroBits, IntPtr StackSize,
        IntPtr MaximumStackSize, IntPtr AttributeList);

    [DllImport("ntdll.dll")]
    internal static extern int NtWaitForSingleObject(
        IntPtr Handle, byte Alertable, IntPtr Timeout);

    [DllImport("ntdll.dll")]
    internal static extern int NtQueueApcThread(
        IntPtr ThreadHandle, IntPtr ApcRoutine,
        IntPtr ApcArgument1, IntPtr ApcArgument2, IntPtr ApcArgument3);

    [DllImport("ntdll.dll")]
    internal static extern int NtTestAlert();

    [DllImport("ntdll.dll")]
    internal static extern int NtCreateSection(
        out IntPtr SectionHandle, uint DesiredAccess, IntPtr ObjectAttributes,
        ref long MaximumSize, uint SectionPageProtection,
        uint AllocationAttributes, IntPtr FileHandle);

    [DllImport("ntdll.dll")]
    internal static extern int NtMapViewOfSection(
        IntPtr SectionHandle, IntPtr ProcessHandle, ref IntPtr BaseAddress,
        IntPtr ZeroBits, IntPtr CommitSize, IntPtr SectionOffset,
        ref IntPtr ViewSize, uint InheritDisposition,
        uint AllocationType, uint Win32Protect);

    [DllImport("kernel32.dll")]
    internal static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll")]
    internal static extern bool CloseHandle(IntPtr hObject);

    internal delegate bool EnumWindowsProc(IntPtr hwnd, IntPtr lParam);

    [DllImport("user32.dll")]
    internal static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);
}
