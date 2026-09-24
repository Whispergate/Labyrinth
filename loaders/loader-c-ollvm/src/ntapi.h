#ifndef NTAPI_H
#define NTAPI_H

#include "config.h"
#include <windows.h>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

typedef NTSTATUS (NTAPI *fnNtAllocateVirtualMemory)(
    HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits,
    PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

typedef NTSTATUS (NTAPI *fnNtProtectVirtualMemory)(
    HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize,
    ULONG NewProtect, PULONG OldProtect);

typedef NTSTATUS (NTAPI *fnNtCreateThreadEx)(
    PHANDLE ThreadHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, HANDLE ProcessHandle,
    PVOID StartRoutine, PVOID Argument, ULONG CreateFlags,
    SIZE_T ZeroBits, SIZE_T StackSize, SIZE_T MaxStackSize,
    PVOID AttributeList);

typedef NTSTATUS (NTAPI *fnNtQueueApcThread)(
    HANDLE ThreadHandle, PVOID ApcRoutine,
    PVOID ApcArgument1, PVOID ApcArgument2, PVOID ApcArgument3);

typedef NTSTATUS (NTAPI *fnNtTestAlert)(VOID);

typedef NTSTATUS (NTAPI *fnNtWaitForSingleObject)(
    HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);

typedef NTSTATUS (NTAPI *fnNtCreateSection)(
    PHANDLE SectionHandle, ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes, PLARGE_INTEGER MaximumSize,
    ULONG SectionPageProtection, ULONG AllocationAttributes,
    HANDLE FileHandle);

typedef NTSTATUS (NTAPI *fnNtMapViewOfSection)(
    HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress,
    ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType,
    ULONG Win32Protect);

/*
 * Resolve an NT API function by name.
 *
 * When USE_INDIRECT_SYSCALLS is defined, this returns a pointer to
 * the corresponding indirect-syscall wrapper (e.g. IndirectNtAllocateVirtualMemory).
 * The caller must still call syscalls_init() once before using ntapi_resolve().
 *
 * Without USE_INDIRECT_SYSCALLS, this uses GetProcAddress on ntdll.dll
 * as before.
 */
FARPROC ntapi_resolve(const char *name);

#if USE_INDIRECT_SYSCALLS
#include "syscalls.h"
#endif

#endif /* NTAPI_H */
