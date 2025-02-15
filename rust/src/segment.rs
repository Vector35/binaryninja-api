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

//! Labeled segments in a binary file that aren't loaded in to memory

use binaryninjacore_sys::*;
use std::fmt::{Debug, Formatter};

use std::ops::Range;

use crate::binary_view::BinaryView;
use crate::rc::*;

#[must_use]
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct SegmentBuilder {
    ea: Range<u64>,
    parent_backing: Option<Range<u64>>,
    flags: SegmentFlags,
    is_auto: bool,
}

impl SegmentBuilder {
    pub fn new(ea: Range<u64>) -> Self {
        SegmentBuilder {
            ea,
            parent_backing: None,
            flags: Default::default(),
            is_auto: false,
        }
    }

    pub fn parent_backing(mut self, parent_backing: Range<u64>) -> Self {
        self.parent_backing = Some(parent_backing);
        self
    }

    pub fn flags(mut self, flags: SegmentFlags) -> Self {
        self.flags = flags;
        self
    }

    pub fn is_auto(mut self, is_auto: bool) -> Self {
        self.is_auto = is_auto;
        self
    }

    pub(crate) fn create(self, view: &BinaryView) {
        let ea_start = self.ea.start;
        let ea_len = self.ea.end.wrapping_sub(ea_start);
        let (b_start, b_len) = self
            .parent_backing
            .map_or((0, 0), |s| (s.start, s.end.wrapping_sub(s.start)));

        unsafe {
            if self.is_auto {
                BNAddAutoSegment(
                    view.handle,
                    ea_start,
                    ea_len,
                    b_start,
                    b_len,
                    self.flags.into_raw(),
                );
            } else {
                BNAddUserSegment(
                    view.handle,
                    ea_start,
                    ea_len,
                    b_start,
                    b_len,
                    self.flags.into_raw(),
                );
            }
        }
    }
}

#[derive(PartialEq, Eq, Hash)]
pub struct Segment {
    handle: *mut BNSegment,
}

impl Segment {
    pub(crate) unsafe fn from_raw(handle: *mut BNSegment) -> Self {
        assert!(!handle.is_null());
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: *mut BNSegment) -> Ref<Self> {
        assert!(!handle.is_null());
        Ref::new(Self { handle })
    }

    /// You need to create a segment builder, customize that segment, then add it to a binary view:
    ///
    /// ```no_run
    /// # use binaryninja::segment::{Segment, SegmentFlags};
    /// # use binaryninja::binary_view::BinaryViewExt;
    /// let bv = binaryninja::load("example").unwrap();
    /// let segment_flags = SegmentFlags::new().writable(true).readable(true);
    /// bv.add_segment(Segment::builder(0..0x1000).flags(segment_flags))
    /// ```
    pub fn builder(ea_range: Range<u64>) -> SegmentBuilder {
        SegmentBuilder::new(ea_range)
    }

    pub fn address_range(&self) -> Range<u64> {
        let start = unsafe { BNSegmentGetStart(self.handle) };
        let end = unsafe { BNSegmentGetEnd(self.handle) };
        start..end
    }

    pub fn parent_backing(&self) -> Option<Range<u64>> {
        let start = unsafe { BNSegmentGetDataOffset(self.handle) };
        let end = unsafe { BNSegmentGetDataEnd(self.handle) };

        if start != end {
            Some(start..end)
        } else {
            None
        }
    }

    pub fn flags(&self) -> SegmentFlags {
        let raw_flags = unsafe { BNSegmentGetFlags(self.handle) };
        SegmentFlags::from_raw(raw_flags)
    }

    pub fn executable(&self) -> bool {
        self.flags().executable
    }

    pub fn writable(&self) -> bool {
        self.flags().writable
    }

    pub fn readable(&self) -> bool {
        self.flags().readable
    }

    pub fn contains_data(&self) -> bool {
        self.flags().contains_data
    }

    pub fn contains_code(&self) -> bool {
        self.flags().contains_code
    }

    pub fn deny_write(&self) -> bool {
        self.flags().deny_write
    }

    pub fn deny_execute(&self) -> bool {
        self.flags().deny_execute
    }

    pub fn auto_defined(&self) -> bool {
        unsafe { BNSegmentIsAutoDefined(self.handle) }
    }
}

impl Debug for Segment {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Segment")
            .field("address_range", &self.address_range())
            .field("parent_backing", &self.parent_backing())
            .field("auto_defined", &self.auto_defined())
            .field("flags", &self.flags())
            .finish()
    }
}

impl ToOwned for Segment {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for Segment {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewSegmentReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeSegment(handle.handle);
    }
}

impl CoreArrayProvider for Segment {
    type Raw = *mut BNSegment;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Segment>;
}

unsafe impl CoreArrayProviderInner for Segment {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeSegmentList(raw, count);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        Guard::new(Segment::from_raw(*raw), context)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct SegmentFlags {
    pub executable: bool,
    pub writable: bool,
    pub readable: bool,
    pub contains_data: bool,
    pub contains_code: bool,
    pub deny_write: bool,
    pub deny_execute: bool,
}

impl SegmentFlags {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn executable(mut self, executable: bool) -> Self {
        self.executable = executable;
        self
    }

    pub fn writable(mut self, writable: bool) -> Self {
        self.writable = writable;
        self
    }

    pub fn readable(mut self, readable: bool) -> Self {
        self.readable = readable;
        self
    }

    pub fn contains_data(mut self, contains_data: bool) -> Self {
        self.contains_data = contains_data;
        self
    }

    pub fn contains_code(mut self, contains_code: bool) -> Self {
        self.contains_code = contains_code;
        self
    }

    pub fn deny_write(mut self, deny_write: bool) -> Self {
        self.deny_write = deny_write;
        self
    }

    pub fn deny_execute(mut self, deny_execute: bool) -> Self {
        self.deny_execute = deny_execute;
        self
    }

    pub(crate) fn from_raw(flags: u32) -> Self {
        Self {
            executable: flags & 0x01 != 0,
            writable: flags & 0x02 != 0,
            readable: flags & 0x04 != 0,
            contains_data: flags & 0x08 != 0,
            contains_code: flags & 0x10 != 0,
            deny_write: flags & 0x20 != 0,
            deny_execute: flags & 0x40 != 0,
        }
    }

    pub(crate) fn into_raw(&self) -> u32 {
        (self.executable as u32)
            | (self.writable as u32) << 1
            | (self.readable as u32) << 2
            | (self.contains_data as u32) << 3
            | (self.contains_code as u32) << 4
            | (self.deny_write as u32) << 5
            | (self.deny_execute as u32) << 6
    }
}
