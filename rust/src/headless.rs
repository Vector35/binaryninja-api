use std::env;
use std::mem;
use std::os::raw;
use std::ffi::{OsStr, CString, CStr};
use std::path::PathBuf;

#[repr(C)]
struct DlInfo {
  dli_fname: *const raw::c_char,
  dli_fbase: *mut raw::c_void,
  dli_sname: *const raw::c_char,
  dli_saddr: *mut raw::c_void
}

#[cfg(not(target_os = "windows"))]
fn binja_path() -> PathBuf {
    use std::os::unix::ffi::OsStrExt;

    if let Ok(p) = env::var("BINJA_DIR") {
        return PathBuf::from(p);
    }

    extern {
        fn dladdr(addr: *mut raw::c_void, info: *mut DlInfo) -> raw::c_int;
    }
    
    unsafe {
        let mut info: DlInfo = mem::uninitialized();

        if dladdr(BNSetBundledPluginDirectory as *mut _, &mut info) == 0 {
            panic!("Failed to find libbinaryninjacore path!");
        }

        if info.dli_fname.is_null() {
            panic!("Failed to find libbinaryninjacore path!");
        }

        let path = CStr::from_ptr(info.dli_fname);
        let path = OsStr::from_bytes(path.to_bytes());
        let mut path = PathBuf::from(path);

        path.pop();
        path
    }
}


#[cfg(target_os = "windows")]
fn binja_path() -> PathBuf {
    PathBuf::from(env::var("PROGRAMFILES").unwrap()).join("Vector35\\BinaryNinja\\")
}

use binaryninjacore_sys::{BNSetBundledPluginDirectory,
                          BNInitCorePlugins,
                          BNInitUserPlugins,
                          BNInitRepoPlugins};

pub fn init() {
    unsafe {
        let path = binja_path().join("plugins").into_os_string();
        let path = CString::new(path.into_string().unwrap()).unwrap();

        BNSetBundledPluginDirectory(path.as_ptr());
        BNInitCorePlugins();
        BNInitUserPlugins();
        BNInitRepoPlugins();
    }
}
