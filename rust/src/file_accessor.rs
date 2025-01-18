// Copyright 2021-2024 Vector 35 Inc.
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
use std::io::{Read, Seek, SeekFrom, Write};
use std::marker::PhantomData;
use std::slice;

pub struct FileAccessor<'a> {
    pub(crate) api_object: BNFileAccessor,
    _ref: PhantomData<&'a mut ()>,
}

impl<'a> FileAccessor<'a> {
    pub fn new<F>(f: &'a mut F) -> Self
    where
        F: 'a + Read + Write + Seek + Sized,
    {
        use std::os::raw::c_void;

        extern "C" fn cb_get_length<F>(ctxt: *mut c_void) -> u64
        where
            F: Read + Write + Seek + Sized,
        {
            let f = unsafe { &mut *(ctxt as *mut F) };

            f.seek(SeekFrom::End(0)).unwrap_or(0)
        }

        extern "C" fn cb_read<F>(
            ctxt: *mut c_void,
            dest: *mut c_void,
            offset: u64,
            len: usize,
        ) -> usize
        where
            F: Read + Write + Seek + Sized,
        {
            let f = unsafe { &mut *(ctxt as *mut F) };
            let dest = unsafe { slice::from_raw_parts_mut(dest as *mut u8, len) };

            if f.seek(SeekFrom::Start(offset)).is_err() {
                log::debug!("Failed to seek to offset {:x}", offset);
                0
            } else {
                f.read(dest).unwrap_or(0)
            }
        }

        extern "C" fn cb_write<F>(
            ctxt: *mut c_void,
            offset: u64,
            src: *const c_void,
            len: usize,
        ) -> usize
        where
            F: Read + Write + Seek + Sized,
        {
            let f = unsafe { &mut *(ctxt as *mut F) };
            let src = unsafe { slice::from_raw_parts(src as *const u8, len) };

            if f.seek(SeekFrom::Start(offset)).is_err() {
                0
            } else {
                f.write(src).unwrap_or(0)
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
