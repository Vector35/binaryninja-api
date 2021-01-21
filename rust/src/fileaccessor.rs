use binaryninjacore_sys::BNFileAccessor;
use std::io::{Read, Write, Seek, SeekFrom};
use std::marker::PhantomData;
use std::slice;

pub struct FileAccessor<'a>
{
    pub(crate) api_object: BNFileAccessor,
    _ref: PhantomData<&'a mut ()>,
}

impl<'a> FileAccessor<'a>
{
    pub fn new<F>(f: &'a mut F) -> Self
    where
        F: 'a + Read + Write + Seek + Sized
    {
        use std::os::raw::c_void;

        extern "C" fn cb_get_length<F>(ctxt: *mut c_void) -> u64
        where
            F: Read + Write + Seek + Sized
        {
            let f = unsafe { &mut *(ctxt as *mut F) };

            match f.seek(SeekFrom::End(0)) {
                Ok(len) => len,
                Err(_) => 0,
            }
        }

        extern "C" fn cb_read<F>(ctxt: *mut c_void, dest: *mut c_void, offset: u64, len: usize) -> usize
        where
            F: Read + Write + Seek + Sized
        {
            let f = unsafe { &mut *(ctxt as *mut F) };
            let dest = unsafe { slice::from_raw_parts_mut(dest as *mut u8, len) };

            if !f.seek(SeekFrom::Start(offset)).is_ok() {
                debug!("Failed to seek to offset {:x}", offset);
                return 0;
            }

            match f.read(dest) {
                Ok(len) => len,
                Err(_) => 0,
            }
        }

        extern "C" fn cb_write<F>(ctxt: *mut c_void, offset: u64, src: *const c_void, len: usize) -> usize
        where
            F: Read + Write + Seek + Sized
        {
            let f = unsafe { &mut *(ctxt as *mut F) };
            let src = unsafe { slice::from_raw_parts(src as *const u8, len) };

            if !f.seek(SeekFrom::Start(offset)).is_ok() {
                return 0;
            }

            match f.write(src) {
                Ok(len) => len,
                Err(_) => 0,
            }
        }

        Self {
            api_object: BNFileAccessor {
                context: f as *mut F as *mut _,
                getLength: Some(cb_get_length::<F>),
                read: Some(cb_read::<F>),
                write: Some(cb_write::<F>),
            },
            _ref: PhantomData,
        }
    }
}

