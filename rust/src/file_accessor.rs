// Copyright 2021-2025 Vector 35 Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use binaryninjacore_sys::BNFileAccessor;
use std::io::{ErrorKind, Read, Seek, SeekFrom, Write};
use std::marker::PhantomData;
use std::slice;

pub trait Accessor: Read + Write + Seek + Sized {}

impl<T: Read + Write + Seek + Sized> Accessor for T {}

pub struct FileAccessor<A: Accessor> {
    pub(crate) raw: BNFileAccessor,
    accessor: PhantomData<A>,
}

impl<A: Accessor> FileAccessor<A> {
    pub fn new(accessor: A) -> Self {
        use std::os::raw::c_void;

        extern "C" fn cb_get_length<A: Accessor>(ctxt: *mut c_void) -> u64 {
            let f = unsafe { &mut *(ctxt as *mut A) };

            f.seek(SeekFrom::End(0)).unwrap_or(0)
        }

        extern "C" fn cb_read<A: Accessor>(
            ctxt: *mut c_void,
            dest: *mut c_void,
            offset: u64,
            len: usize,
        ) -> usize {
            let f = unsafe { &mut *(ctxt as *mut A) };
            let dest = unsafe { slice::from_raw_parts_mut(dest as *mut u8, len) };

            if f.seek(SeekFrom::Start(offset)).is_err() {
                log::debug!("Failed to seek to offset {:x}", offset);
                0
            } else {
                f.read(dest).unwrap_or(0)
            }
        }

        extern "C" fn cb_write<A: Accessor>(
            ctxt: *mut c_void,
            offset: u64,
            src: *const c_void,
            len: usize,
        ) -> usize {
            let f = unsafe { &mut *(ctxt as *mut A) };
            let src = unsafe { slice::from_raw_parts(src as *const u8, len) };

            if f.seek(SeekFrom::Start(offset)).is_err() {
                0
            } else {
                f.write(src).unwrap_or(0)
            }
        }

        let boxed_accessor = Box::new(accessor);
        let leaked_accessor = Box::leak(boxed_accessor);

        Self {
            raw: BNFileAccessor {
                context: leaked_accessor as *mut A as *mut _,
                getLength: Some(cb_get_length::<A>),
                read: Some(cb_read::<A>),
                write: Some(cb_write::<A>),
            },
            accessor: PhantomData,
        }
    }

    pub fn read(&self, addr: u64, len: usize) -> Result<Vec<u8>, ErrorKind> {
        let cb_read = self.raw.read.unwrap();
        let mut buf = vec![0; len];
        let read_len = unsafe { cb_read(self.raw.context, buf.as_mut_ptr() as *mut _, addr, len) };
        if read_len != len {
            return Err(ErrorKind::UnexpectedEof);
        }
        Ok(buf)
    }

    pub fn write(&self, addr: u64, data: &[u8]) -> usize {
        let cb_write = self.raw.write.unwrap();
        unsafe {
            cb_write(
                self.raw.context,
                addr,
                data.as_ptr() as *const _,
                data.len(),
            )
        }
    }

    pub fn length(&self) -> u64 {
        let cb_get_length = self.raw.getLength.unwrap();
        unsafe { cb_get_length(self.raw.context) }
    }
}

impl<A: Accessor> Drop for FileAccessor<A> {
    fn drop(&mut self) {
        unsafe {
            let _ = Box::from_raw(self.raw.context as *mut A);
        }
    }
}
