use binaryninjacore_sys::BNLlvmServicesDisasmInstruction;
use std::ffi::CStr;

pub fn disas_instruction(triplet: &str, data: &[u8], address64: u64) -> Option<(usize, String)> {
    unsafe {
        let mut buf = vec![0; 256];
        let instr_len = BNLlvmServicesDisasmInstruction(
            triplet.as_ptr() as *const i8,
            data.as_ptr() as *mut u8,
            data.len() as i32,
            address64,
            buf.as_mut_ptr() as *mut i8,
            buf.len(),
        );
        if instr_len > 0 {
            let cstr = CStr::from_ptr(buf.as_ptr() as *const i8);
            let string = cstr.to_str().unwrap().to_string();
            Some((instr_len as usize, string))
        } else {
            None
        }
    }
}
