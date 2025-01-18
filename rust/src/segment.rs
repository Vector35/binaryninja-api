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

fn set_bit(val: u32, bit_mask: u32, new_val: bool) -> u32 {
    (val & !bit_mask) | if new_val { bit_mask } else { 0 }
}

#[must_use]
pub struct SegmentBuilder {
    ea: Range<u64>,
    parent_backing: Option<Range<u64>>,
    flags: u32,
    is_auto: bool,
}

impl SegmentBuilder {
    pub fn new(ea: Range<u64>) -> Self {
        SegmentBuilder {
            ea,
            parent_backing: None,
            flags: 0,
            is_auto: false,
        }
    }

    pub fn parent_backing(mut self, parent_backing: Range<u64>) -> Self {
        self.parent_backing = Some(parent_backing);
        self
    }

    pub fn executable(mut self, executable: bool) -> Self {
        self.flags = set_bit(self.flags, 0x01, executable);
        self
    }

    pub fn writable(mut self, writable: bool) -> Self {
        self.flags = set_bit(self.flags, 0x02, writable);
        self
    }

    pub fn readable(mut self, readable: bool) -> Self {
        self.flags = set_bit(self.flags, 0x04, readable);
        self
    }

    pub fn contains_data(mut self, contains_data: bool) -> Self {
        self.flags = set_bit(self.flags, 0x08, contains_data);
        self
    }

    pub fn contains_code(mut self, contains_code: bool) -> Self {
        self.flags = set_bit(self.flags, 0x10, contains_code);
        self
    }

    pub fn deny_write(mut self, deny_write: bool) -> Self {
        self.flags = set_bit(self.flags, 0x20, deny_write);
        self
    }

    pub fn deny_execute(mut self, deny_execute: bool) -> Self {
        self.flags = set_bit(self.flags, 0x40, deny_execute);
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
                BNAddAutoSegment(view.handle, ea_start, ea_len, b_start, b_len, self.flags);
            } else {
                BNAddUserSegment(view.handle, ea_start, ea_len, b_start, b_len, self.flags);
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
    /// # use binaryninja::segment::Segment;
    /// # use binaryninja::binary_view::BinaryViewExt;
    /// let bv = binaryninja::load("example").unwrap();
    /// bv.add_segment(Segment::builder(0..0x1000).writable(true).readable(true))
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

    fn flags(&self) -> u32 {
        unsafe { BNSegmentGetFlags(self.handle) }
    }

    pub fn executable(&self) -> bool {
        self.flags() & 0x01 != 0
    }

    pub fn writable(&self) -> bool {
        self.flags() & 0x02 != 0
    }

    pub fn readable(&self) -> bool {
        self.flags() & 0x04 != 0
    }

    pub fn contains_data(&self) -> bool {
        self.flags() & 0x08 != 0
    }

    pub fn contains_code(&self) -> bool {
        self.flags() & 0x10 != 0
    }

    pub fn deny_write(&self) -> bool {
        self.flags() & 0x20 != 0
    }

    pub fn deny_execute(&self) -> bool {
        self.flags() & 0x40 != 0
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
            .field("executable", &self.executable())
            .field("writable", &self.writable())
            .field("readable", &self.readable())
            .field("contains_data", &self.contains_data())
            .field("contains_code", &self.contains_code())
            .field("deny_write", &self.deny_write())
            .field("deny_execute", &self.deny_execute())
            .field("auto_defined", &self.auto_defined())
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
