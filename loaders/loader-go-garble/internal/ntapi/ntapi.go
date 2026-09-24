package ntapi

import "syscall"

var (
	ntdll    = syscall.NewLazyDLL("ntdll.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")
	user32   = syscall.NewLazyDLL("user32.dll")
)

var (
	NtAllocateVirtualMemory = ntdll.NewProc("NtAllocateVirtualMemory")
	NtProtectVirtualMemory  = ntdll.NewProc("NtProtectVirtualMemory")
	NtCreateThreadEx        = ntdll.NewProc("NtCreateThreadEx")
	NtWaitForSingleObject   = ntdll.NewProc("NtWaitForSingleObject")
	NtQueueApcThread        = ntdll.NewProc("NtQueueApcThread")
	NtTestAlert             = ntdll.NewProc("NtTestAlert")
	NtCreateSection         = ntdll.NewProc("NtCreateSection")
	NtMapViewOfSection      = ntdll.NewProc("NtMapViewOfSection")
	ResumeThread            = kernel32.NewProc("ResumeThread")
	EnumWindows             = user32.NewProc("EnumWindows")
)
