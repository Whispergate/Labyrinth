package techniques

const (
	memCommit            = 0x1000
	memReserve           = 0x2000
	pageReadWrite        = 0x04
	pageExecuteRead      = 0x20
	pageExecuteReadWrite = 0x40
	secCommit            = 0x8000000
	sectionAllAccess     = 0xF001F
	threadAllAccess      = 0x1FFFFF
	currentProcess       = ^uintptr(0)
	currentThread        = ^uintptr(1)
)

type InjectFn func(sc []byte) bool

type Technique struct {
	Name string
	Fn   InjectFn
}

var Registry = []Technique{
	{"nt_thread", NtThread},
	{"nt_apc", NtApc},
	{"nt_section", NtSection},
	{"nt_callback", NtCallback},
	{"nt_suspended", NtSuspended},
}

func ntSuccess(status uintptr) bool {
	return int32(status) >= 0
}
