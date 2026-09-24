use std::ffi::c_void;

pub type Handle = isize;
pub type NtStatus = i32;

extern "system" {
    fn GetModuleHandleA(module_name: *const u8) -> isize;
    fn GetProcAddress(module: isize, proc_name: *const u8) -> *const c_void;
    pub fn CloseHandle(handle: Handle) -> i32;
}

pub unsafe fn resolve(module: &[u8], name: &[u8]) -> *const c_void {
    let h = GetModuleHandleA(module.as_ptr());
    if h == 0 {
        return std::ptr::null();
    }
    GetProcAddress(h, name.as_ptr())
}

pub fn nt_success(status: NtStatus) -> bool {
    status >= 0
}

pub const CURRENT_PROCESS: Handle = -1;
pub const CURRENT_THREAD: Handle = -2;

pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_RESERVE: u32 = 0x2000;
pub const PAGE_READWRITE: u32 = 0x04;
pub const PAGE_EXECUTE_READ: u32 = 0x20;
pub const PAGE_EXECUTE_READWRITE: u32 = 0x40;
pub const SEC_COMMIT: u32 = 0x8000000;
pub const SECTION_ALL_ACCESS: u32 = 0xF001F;
pub const THREAD_ALL_ACCESS: u32 = 0x1FFFFF;
pub const CREATE_SUSPENDED: u32 = 0x1;

pub type NtAllocateVirtualMemoryFn = unsafe extern "system" fn(
    process: Handle, base: *mut *mut c_void, zero_bits: usize,
    size: *mut usize, alloc_type: u32, protect: u32,
) -> NtStatus;

pub type NtProtectVirtualMemoryFn = unsafe extern "system" fn(
    process: Handle, base: *mut *mut c_void, size: *mut usize,
    new_protect: u32, old_protect: *mut u32,
) -> NtStatus;

pub type NtCreateThreadExFn = unsafe extern "system" fn(
    thread: *mut Handle, access: u32, obj_attrs: *const c_void,
    process: Handle, start: *const c_void, arg: *const c_void,
    flags: u32, zero_bits: usize, stack_size: usize,
    max_stack_size: usize, attr_list: *const c_void,
) -> NtStatus;

pub type NtWaitForSingleObjectFn = unsafe extern "system" fn(
    handle: Handle, alertable: u8, timeout: *const i64,
) -> NtStatus;

pub type NtQueueApcThreadFn = unsafe extern "system" fn(
    thread: Handle, routine: *const c_void,
    arg1: *const c_void, arg2: *const c_void, arg3: *const c_void,
) -> NtStatus;

pub type NtTestAlertFn = unsafe extern "system" fn() -> NtStatus;

pub type NtCreateSectionFn = unsafe extern "system" fn(
    section: *mut Handle, access: u32, obj_attrs: *const c_void,
    max_size: *const i64, page_prot: u32, alloc_attrs: u32, file: Handle,
) -> NtStatus;

pub type NtMapViewOfSectionFn = unsafe extern "system" fn(
    section: Handle, process: Handle, base: *mut *mut c_void,
    zero_bits: usize, commit_size: usize, offset: *const i64,
    view_size: *mut usize, inherit: u32, alloc_type: u32, protect: u32,
) -> NtStatus;

pub type ResumeThreadFn = unsafe extern "system" fn(thread: Handle) -> u32;

pub type EnumWindowsFn = unsafe extern "system" fn(
    callback: unsafe extern "system" fn(isize, isize) -> i32,
    lparam: isize,
) -> i32;
