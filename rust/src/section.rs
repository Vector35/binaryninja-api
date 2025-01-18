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

//! Sections are [crate::segment::Segment]s that are loaded into memory at run time

use std::fmt;
use std::ops::Range;

use binaryninjacore_sys::*;

use crate::binary_view::BinaryView;
use crate::rc::*;
use crate::string::*;

#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum Semantics {
    DefaultSection,
    ReadOnlyCode,
    ReadOnlyData,
    ReadWriteData,
    External,
}

impl From<BNSectionSemantics> for Semantics {
    fn from(bn: BNSectionSemantics) -> Self {
        use self::BNSectionSemantics::*;

        match bn {
            DefaultSectionSemantics => Semantics::DefaultSection,
            ReadOnlyCodeSectionSemantics => Semantics::ReadOnlyCode,
            ReadOnlyDataSectionSemantics => Semantics::ReadOnlyData,
            ReadWriteDataSectionSemantics => Semantics::ReadWriteData,
            ExternalSectionSemantics => Semantics::External,
        }
    }
}

impl From<Semantics> for BNSectionSemantics {
    fn from(semantics: Semantics) -> Self {
        use self::BNSectionSemantics::*;

        match semantics {
            Semantics::DefaultSection => DefaultSectionSemantics,
            Semantics::ReadOnlyCode => ReadOnlyCodeSectionSemantics,
            Semantics::ReadOnlyData => ReadOnlyDataSectionSemantics,
            Semantics::ReadWriteData => ReadWriteDataSectionSemantics,
            Semantics::External => ExternalSectionSemantics,
        }
    }
}

#[derive(PartialEq, Eq, Hash)]
pub struct Section {
    handle: *mut BNSection,
}

impl Section {
    unsafe fn from_raw(handle: *mut BNSection) -> Self {
        debug_assert!(!handle.is_null());
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: *mut BNSection) -> Ref<Self> {
        debug_assert!(!handle.is_null());
        Ref::new(Self { handle })
    }

    /// You need to create a section builder, customize that section, then add it to a binary view:
    ///
    /// ```no_run
    /// # use binaryninja::section::Section;
    /// # use binaryninja::binary_view::BinaryViewExt;
    /// let bv = binaryninja::load("example").unwrap();
    /// bv.add_section(Section::builder("example", 0..1024).align(4).entry_size(4))
    /// ```
    pub fn builder<S: BnStrCompatible>(name: S, range: Range<u64>) -> SectionBuilder<S> {
        SectionBuilder::new(name, range)
    }

    pub fn name(&self) -> BnString {
        unsafe { BnString::from_raw(BNSectionGetName(self.handle)) }
    }

    pub fn section_type(&self) -> BnString {
        unsafe { BnString::from_raw(BNSectionGetType(self.handle)) }
    }

    pub fn start(&self) -> u64 {
        unsafe { BNSectionGetStart(self.handle) }
    }

    pub fn end(&self) -> u64 {
        unsafe { BNSectionGetEnd(self.handle) }
    }

    pub fn len(&self) -> usize {
        unsafe { BNSectionGetLength(self.handle) as usize }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn address_range(&self) -> Range<u64> {
        self.start()..self.end()
    }

    pub fn semantics(&self) -> Semantics {
        unsafe { BNSectionGetSemantics(self.handle).into() }
    }

    pub fn linked_section(&self) -> BnString {
        unsafe { BnString::from_raw(BNSectionGetLinkedSection(self.handle)) }
    }

    pub fn info_section(&self) -> BnString {
        unsafe { BnString::from_raw(BNSectionGetInfoSection(self.handle)) }
    }

    pub fn info_data(&self) -> u64 {
        unsafe { BNSectionGetInfoData(self.handle) }
    }

    pub fn align(&self) -> u64 {
        unsafe { BNSectionGetAlign(self.handle) }
    }

    pub fn entry_size(&self) -> usize {
        unsafe { BNSectionGetEntrySize(self.handle) as usize }
    }

    pub fn auto_defined(&self) -> bool {
        unsafe { BNSectionIsAutoDefined(self.handle) }
    }
}

impl fmt::Debug for Section {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Section")
            .field("name", &self.name())
            .field("address_range", &self.address_range())
            .field("section_type", &self.section_type())
            .field("semantics", &self.semantics())
            .field("linked_section", &self.linked_section())
            .field("align", &self.align())
            .field("entry_size", &self.entry_size())
            .field("auto_defined", &self.auto_defined())
            .finish()
    }
}

impl ToOwned for Section {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for Section {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewSectionReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeSection(handle.handle);
    }
}

impl CoreArrayProvider for Section {
    type Raw = *mut BNSection;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Section>;
}

unsafe impl CoreArrayProviderInner for Section {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeSectionList(raw, count);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        Guard::new(Section::from_raw(*raw), context)
    }
}

#[must_use]
pub struct SectionBuilder<S: BnStrCompatible> {
    is_auto: bool,
    name: S,
    range: Range<u64>,
    semantics: Semantics,
    _ty: Option<S>,
    align: u64,
    entry_size: u64,
    linked_section: Option<S>,
    info_section: Option<S>,
    info_data: u64,
}

impl<S: BnStrCompatible> SectionBuilder<S> {
    pub fn new(name: S, range: Range<u64>) -> Self {
        Self {
            is_auto: false,
            name,
            range,
            semantics: Semantics::DefaultSection,
            _ty: None,
            align: 1,
            entry_size: 1,
            linked_section: None,
            info_section: None,
            info_data: 0,
        }
    }

    pub fn semantics(mut self, semantics: Semantics) -> Self {
        self.semantics = semantics;
        self
    }

    pub fn section_type(mut self, ty: S) -> Self {
        self._ty = Some(ty);
        self
    }

    pub fn align(mut self, align: u64) -> Self {
        self.align = align;
        self
    }

    pub fn entry_size(mut self, entry_size: u64) -> Self {
        self.entry_size = entry_size;
        self
    }

    pub fn linked_section(mut self, linked_section: S) -> Self {
        self.linked_section = Some(linked_section);
        self
    }

    pub fn info_section(mut self, info_section: S) -> Self {
        self.info_section = Some(info_section);
        self
    }

    pub fn info_data(mut self, info_data: u64) -> Self {
        self.info_data = info_data;
        self
    }

    pub fn is_auto(mut self, is_auto: bool) -> Self {
        self.is_auto = is_auto;
        self
    }

    pub(crate) fn create(self, view: &BinaryView) {
        let name = self.name.into_bytes_with_nul();
        let ty = self._ty.map(|s| s.into_bytes_with_nul());
        let linked_section = self.linked_section.map(|s| s.into_bytes_with_nul());
        let info_section = self.info_section.map(|s| s.into_bytes_with_nul());

        let start = self.range.start;
        let len = self.range.end.wrapping_sub(start);

        unsafe {
            let nul_str = c"".as_ptr();
            let name_ptr = name.as_ref().as_ptr() as *mut _;
            let ty_ptr = ty.map_or(nul_str, |s| s.as_ref().as_ptr() as *mut _);
            let linked_section_ptr =
                linked_section.map_or(nul_str, |s| s.as_ref().as_ptr() as *mut _);
            let info_section_ptr = info_section.map_or(nul_str, |s| s.as_ref().as_ptr() as *mut _);

            if self.is_auto {
                BNAddAutoSection(
                    view.handle,
                    name_ptr,
                    start,
                    len,
                    self.semantics.into(),
                    ty_ptr,
                    self.align,
                    self.entry_size,
                    linked_section_ptr,
                    info_section_ptr,
                    self.info_data,
                );
            } else {
                BNAddUserSection(
                    view.handle,
                    name_ptr,
                    start,
                    len,
                    self.semantics.into(),
                    ty_ptr,
                    self.align,
                    self.entry_size,
                    linked_section_ptr,
                    info_section_ptr,
                    self.info_data,
                );
            }
        }
    }
}
