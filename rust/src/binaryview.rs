// Copyright 2021 Vector 35 Inc.
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

use binaryninjacore_sys::*;

pub use binaryninjacore_sys::BNModificationStatus as ModificationStatus;

use std::ops;
use std::ptr;
use std::result;

use crate::architecture::Architecture;
use crate::architecture::CoreArchitecture;
use crate::basicblock::BasicBlock;
use crate::databuffer::DataBuffer;
use crate::fileaccessor::FileAccessor;
use crate::filemetadata::FileMetadata;
use crate::flowgraph::FlowGraph;
use crate::function::{Function, NativeBlock};
use crate::platform::Platform;
use crate::section::{Section, SectionBuilder};
use crate::segment::{Segment, SegmentBuilder};
use crate::symbol::{Symbol, SymbolType};
use crate::types::{QualifiedName, Type};
use crate::Endianness;

use crate::rc::*;
use crate::string::*;

// TODO : general reorg of modules related to bv

pub type Result<R> = result::Result<R, ()>;

pub trait BinaryViewBase: AsRef<BinaryView> {
    fn read(&self, _buf: &mut [u8], _offset: u64) -> usize {
        0
    }
    fn write(&self, _offset: u64, _data: &[u8]) -> usize {
        0
    }
    fn insert(&self, _offset: u64, _data: &[u8]) -> usize {
        0
    }
    fn remove(&self, _offset: u64, _len: usize) -> usize {
        0
    }

    fn offset_valid(&self, offset: u64) -> bool {
        let mut buf = [0u8; 1];

        // don't use self.read so that if segments were used we
        // check against those as well
        self.as_ref().read(&mut buf[..], offset) == buf.len()
    }

    fn offset_readable(&self, offset: u64) -> bool {
        self.offset_valid(offset)
    }

    fn offset_writable(&self, offset: u64) -> bool {
        self.offset_valid(offset)
    }

    fn offset_executable(&self, offset: u64) -> bool {
        self.offset_valid(offset)
    }

    fn offset_backed_by_file(&self, offset: u64) -> bool {
        self.offset_valid(offset)
    }

    fn next_valid_offset_after(&self, offset: u64) -> u64 {
        let start = self.as_ref().start();

        if offset < start {
            start
        } else {
            offset
        }
    }

    #[allow(unused)]
    fn modification_status(&self, offset: u64) -> ModificationStatus {
        ModificationStatus::Original
    }

    fn start(&self) -> u64 {
        0
    }
    fn len(&self) -> usize {
        0
    }

    fn executable(&self) -> bool {
        true
    }
    fn relocatable(&self) -> bool {
        true
    }

    fn entry_point(&self) -> u64;
    fn default_endianness(&self) -> Endianness;
    fn address_size(&self) -> usize;

    // TODO saving fileaccessor
    fn save(&self) -> bool {
        self.as_ref()
            .parent_view()
            .map(|bv| bv.save())
            .unwrap_or(false)
    }
}

pub trait BinaryViewExt: BinaryViewBase {
    fn metadata(&self) -> Ref<FileMetadata> {
        unsafe {
            let raw = BNGetFileForView(self.as_ref().handle);

            Ref::new(FileMetadata::from_raw(raw))
        }
    }

    fn parent_view(&self) -> Result<Ref<BinaryView>> {
        let handle = unsafe { BNGetParentView(self.as_ref().handle) };

        if handle.is_null() {
            return Err(());
        }

        unsafe { Ok(Ref::new(BinaryView { handle })) }
    }

    /// Reads up to `len` bytes from address `offset`
    fn read_vec(&self, offset: u64, len: usize) -> Vec<u8> {
        let mut ret = Vec::with_capacity(len);

        unsafe {
            let res;

            {
                let dest_slice = ret.get_unchecked_mut(0..len);
                res = self.read(dest_slice, offset);
            }

            ret.set_len(res);
        }

        ret
    }

    /// Appends up to `len` bytes from address `offset` into `dest`
    fn read_into_vec(&self, dest: &mut Vec<u8>, offset: u64, len: usize) -> usize {
        let starting_len = dest.len();
        let space = dest.capacity() - starting_len;

        if space < len {
            dest.reserve(len - space);
        }

        unsafe {
            let res;

            {
                let dest_slice = dest.get_unchecked_mut(starting_len..starting_len + len);
                res = self.read(dest_slice, offset);
            }

            if res > 0 {
                dest.set_len(starting_len + res);
            }

            res
        }
    }

    fn notify_data_written(&self, offset: u64, len: usize) {
        unsafe {
            BNNotifyDataWritten(self.as_ref().handle, offset, len);
        }
    }

    fn notify_data_inserted(&self, offset: u64, len: usize) {
        unsafe {
            BNNotifyDataInserted(self.as_ref().handle, offset, len);
        }
    }

    fn notify_data_removed(&self, offset: u64, len: usize) {
        unsafe {
            BNNotifyDataRemoved(self.as_ref().handle, offset, len as u64);
        }
    }

    fn offset_has_code_semantics(&self, offset: u64) -> bool {
        unsafe { BNIsOffsetCodeSemantics(self.as_ref().handle, offset) }
    }

    fn offset_has_writable_semantics(&self, offset: u64) -> bool {
        unsafe { BNIsOffsetWritableSemantics(self.as_ref().handle, offset) }
    }

    fn end(&self) -> u64 {
        unsafe { BNGetEndOffset(self.as_ref().handle) }
    }

    fn update_analysis_and_wait(&self) {
        unsafe {
            BNUpdateAnalysisAndWait(self.as_ref().handle);
        }
    }

    fn default_arch(&self) -> Option<CoreArchitecture> {
        unsafe {
            let raw = BNGetDefaultArchitecture(self.as_ref().handle);

            if raw.is_null() {
                return None;
            }

            Some(CoreArchitecture::from_raw(raw))
        }
    }

    fn set_default_arch<A: Architecture>(&self, arch: &A) {
        unsafe {
            BNSetDefaultArchitecture(self.as_ref().handle, arch.as_ref().0);
        }
    }

    fn default_platform(&self) -> Option<Ref<Platform>> {
        unsafe {
            let raw = BNGetDefaultPlatform(self.as_ref().handle);

            if raw.is_null() {
                return None;
            }

            Some(Ref::new(Platform::from_raw(raw)))
        }
    }

    fn set_default_platform(&self, plat: &Platform) {
        unsafe {
            BNSetDefaultPlatform(self.as_ref().handle, plat.handle);
        }
    }

    fn get_instruction_len<A: Architecture>(&self, arch: &A, addr: u64) -> Option<usize> {
        unsafe {
            let size = BNGetInstructionLength(self.as_ref().handle, arch.as_ref().0, addr);

            if size > 0 {
                Some(size)
            } else {
                None
            }
        }
    }

    fn symbol_by_address(&self, addr: u64) -> Result<Ref<Symbol>> {
        unsafe {
            let raw_sym = BNGetSymbolByAddress(self.as_ref().handle, addr, ptr::null_mut());

            if raw_sym.is_null() {
                return Err(());
            }

            Ok(Ref::new(Symbol::from_raw(raw_sym)))
        }
    }

    fn symbol_by_raw_name<S: BnStrCompatible>(&self, raw_name: S) -> Result<Ref<Symbol>> {
        let raw_name = raw_name.as_bytes_with_nul();

        unsafe {
            let raw_sym = BNGetSymbolByRawName(
                self.as_ref().handle,
                raw_name.as_ref().as_ptr() as *mut _,
                ptr::null_mut(),
            );

            if raw_sym.is_null() {
                return Err(());
            }

            Ok(Ref::new(Symbol::from_raw(raw_sym)))
        }
    }

    fn symbols(&self) -> Array<Symbol> {
        unsafe {
            let mut count = 0;
            let handles = BNGetSymbols(self.as_ref().handle, &mut count, ptr::null_mut());

            Array::new(handles, count, ())
        }
    }

    fn symbols_by_name<S: BnStrCompatible>(&self, name: S) -> Array<Symbol> {
        let raw_name = name.as_bytes_with_nul();

        unsafe {
            let mut count = 0;
            let handles = BNGetSymbolsByName(
                self.as_ref().handle,
                raw_name.as_ref().as_ptr() as *mut _,
                &mut count,
                ptr::null_mut(),
            );

            Array::new(handles, count, ())
        }
    }

    fn symbols_in_range(&self, range: ops::Range<u64>) -> Array<Symbol> {
        unsafe {
            let mut count = 0;
            let len = range.end.wrapping_sub(range.start);
            let handles = BNGetSymbolsInRange(
                self.as_ref().handle,
                range.start,
                len,
                &mut count,
                ptr::null_mut(),
            );

            Array::new(handles, count, ())
        }
    }

    fn symbols_of_type(&self, ty: SymbolType) -> Array<Symbol> {
        unsafe {
            let mut count = 0;
            let handles =
                BNGetSymbolsOfType(self.as_ref().handle, ty.into(), &mut count, ptr::null_mut());

            Array::new(handles, count, ())
        }
    }

    fn symbols_of_type_in_range(&self, ty: SymbolType, range: ops::Range<u64>) -> Array<Symbol> {
        unsafe {
            let mut count = 0;
            let len = range.end.wrapping_sub(range.start);
            let handles = BNGetSymbolsOfTypeInRange(
                self.as_ref().handle,
                ty.into(),
                range.start,
                len,
                &mut count,
                ptr::null_mut(),
            );

            Array::new(handles, count, ())
        }
    }

    fn define_auto_symbol(&self, sym: &Symbol) {
        unsafe {
            BNDefineAutoSymbol(self.as_ref().handle, sym.handle);
        }
    }

    fn define_auto_symbol_with_type<'a, T: Into<Option<&'a Type>>>(
        &self,
        sym: &Symbol,
        plat: &Platform,
        ty: T,
    ) {
        let raw_type = if let Some(t) = ty.into() {
            t.handle
        } else {
            ptr::null_mut()
        };

        unsafe {
            BNDefineAutoSymbolAndVariableOrFunction(
                self.as_ref().handle,
                plat.handle,
                sym.handle,
                raw_type,
            );
        }
    }

    fn undefine_auto_symbol(&self, sym: &Symbol) {
        unsafe {
            BNUndefineAutoSymbol(self.as_ref().handle, sym.handle);
        }
    }

    fn define_user_symbol(&self, sym: &Symbol) {
        unsafe {
            BNDefineUserSymbol(self.as_ref().handle, sym.handle);
        }
    }

    fn undefine_user_symbol(&self, sym: &Symbol) {
        unsafe {
            BNUndefineUserSymbol(self.as_ref().handle, sym.handle);
        }
    }

    fn define_user_type<S: BnStrCompatible>(&self, name: S, type_obj: &Type) {
        unsafe {
            let mut qualified_name = QualifiedName::from(name);
            BNDefineUserAnalysisType(self.as_ref().handle, &mut qualified_name.0, type_obj.handle)
        }
    }

    fn segments(&self) -> Array<Segment> {
        unsafe {
            let mut count = 0;
            let segs = BNGetSegments(self.as_ref().handle, &mut count);

            Array::new(segs, count, ())
        }
    }

    fn segment_at(&self, addr: u64) -> Option<Segment> {
        unsafe {
            let raw_seg = BNGetSegmentAt(self.as_ref().handle, addr);
            if !raw_seg.is_null() {
                Some(Segment::from_raw(raw_seg))
            } else {
                None
            }
        }
    }

    fn add_segment(&self, segment: SegmentBuilder) {
        segment.create(self.as_ref());
    }

    fn add_section<S: BnStrCompatible>(&self, section: SectionBuilder<S>) {
        section.create(self.as_ref());
    }

    fn remove_auto_section<S: BnStrCompatible>(&self, name: S) {
        let name = name.as_bytes_with_nul();
        let name_ptr = name.as_ref().as_ptr() as *mut _;

        unsafe {
            BNRemoveAutoSection(self.as_ref().handle, name_ptr);
        }
    }

    fn remove_user_section<S: BnStrCompatible>(&self, name: S) {
        let name = name.as_bytes_with_nul();
        let name_ptr = name.as_ref().as_ptr() as *mut _;

        unsafe {
            BNRemoveUserSection(self.as_ref().handle, name_ptr);
        }
    }

    fn section_by_name<S: BnStrCompatible>(&self, name: S) -> Result<Section> {
        unsafe {
            let raw_name = name.as_bytes_with_nul();
            let name_ptr = raw_name.as_ref().as_ptr() as *mut _;
            let raw_section = BNGetSectionByName(self.as_ref().handle, name_ptr);

            if raw_section.is_null() {
                return Err(());
            }

            Ok(Section::from_raw(raw_section))
        }
    }

    fn sections(&self) -> Array<Section> {
        unsafe {
            let mut count = 0;
            let sections = BNGetSections(self.as_ref().handle, &mut count);

            Array::new(sections, count, ())
        }
    }

    fn sections_at(&self, addr: u64) -> Array<Section> {
        unsafe {
            let mut count = 0;
            let sections = BNGetSectionsAt(self.as_ref().handle, addr, &mut count);

            Array::new(sections, count, ())
        }
    }

    fn add_auto_function(&self, plat: &Platform, addr: u64) {
        unsafe {
            BNAddFunctionForAnalysis(self.as_ref().handle, plat.handle, addr);
        }
    }

    fn add_entry_point(&self, plat: &Platform, addr: u64) {
        unsafe {
            BNAddEntryPointForAnalysis(self.as_ref().handle, plat.handle, addr);
        }
    }

    fn create_user_function(&self, plat: &Platform, addr: u64) {
        unsafe {
            BNCreateUserFunction(self.as_ref().handle, plat.handle, addr);
        }
    }

    fn has_functions(&self) -> bool {
        unsafe { BNHasFunctions(self.as_ref().handle) }
    }

    fn entry_point_function(&self) -> Result<Ref<Function>> {
        unsafe {
            let func = BNGetAnalysisEntryPoint(self.as_ref().handle);

            if func.is_null() {
                return Err(());
            }

            Ok(Ref::new(Function::from_raw(func)))
        }
    }

    fn functions(&self) -> Array<Function> {
        unsafe {
            let mut count = 0;
            let functions = BNGetAnalysisFunctionList(self.as_ref().handle, &mut count);

            Array::new(functions, count, ())
        }
    }

    /// List of functions *starting* at `addr`
    fn functions_at(&self, addr: u64) -> Array<Function> {
        unsafe {
            let mut count = 0;
            let functions =
                BNGetAnalysisFunctionsForAddress(self.as_ref().handle, addr, &mut count);

            Array::new(functions, count, ())
        }
    }

    fn function_at(&self, platform: &Platform, addr: u64) -> Result<Ref<Function>> {
        unsafe {
            let handle = BNGetAnalysisFunction(self.as_ref().handle, platform.handle, addr);

            if handle.is_null() {
                return Err(());
            }

            Ok(Ref::new(Function::from_raw(handle)))
        }
    }

    fn basic_blocks_containing(&self, addr: u64) -> Array<BasicBlock<NativeBlock>> {
        unsafe {
            let mut count = 0;
            let blocks = BNGetBasicBlocksForAddress(self.as_ref().handle, addr, &mut count);

            Array::new(blocks, count, NativeBlock::new())
        }
    }

    fn basic_blocks_starting_at(&self, addr: u64) -> Array<BasicBlock<NativeBlock>> {
        unsafe {
            let mut count = 0;
            let blocks = BNGetBasicBlocksStartingAtAddress(self.as_ref().handle, addr, &mut count);

            Array::new(blocks, count, NativeBlock::new())
        }
    }

    fn is_new_auto_function_analysis_suppressed(&self) -> bool {
        unsafe { BNGetNewAutoFunctionAnalysisSuppressed(self.as_ref().handle) }
    }

    fn set_new_auto_function_analysis_suppressed(&self, suppress: bool) {
        unsafe {
            BNSetNewAutoFunctionAnalysisSuppressed(self.as_ref().handle, suppress);
        }
    }

    fn read_buffer(&self, offset: u64, len: usize) -> Result<DataBuffer> {
        let read_buffer = unsafe { BNReadViewBuffer(self.as_ref().handle, offset, len) };
        if read_buffer.is_null() {
            Err(())
        } else {
            Ok(DataBuffer::from_raw(read_buffer))
        }
    }

    fn show_graph_report<S: BnStrCompatible>(&self, raw_name: S, graph: FlowGraph) {
        let raw_name = raw_name.as_bytes_with_nul();
        unsafe {
            BNShowGraphReport(
                self.as_ref().handle,
                raw_name.as_ref().as_ptr() as *mut _,
                graph.as_ref().handle,
            );
        }
    }
}

impl<T: BinaryViewBase> BinaryViewExt for T {}

#[derive(PartialEq, Eq, Hash)]
pub struct BinaryView {
    pub(crate) handle: *mut BNBinaryView,
}

impl BinaryView {
    pub unsafe fn from_raw(handle: *mut BNBinaryView) -> Self {
        debug_assert!(!handle.is_null());

        Self { handle }
    }

    pub fn from_filename<S: BnStrCompatible>(
        meta: &FileMetadata,
        filename: S,
    ) -> Result<Ref<Self>> {
        let file = filename.as_bytes_with_nul();

        let handle = unsafe {
            BNCreateBinaryDataViewFromFilename(meta.handle, file.as_ref().as_ptr() as *mut _)
        };

        if handle.is_null() {
            return Err(());
        }

        unsafe { Ok(Ref::new(Self { handle })) }
    }

    pub fn from_accessor(meta: &FileMetadata, file: &mut FileAccessor) -> Result<Ref<Self>> {
        let handle =
            unsafe { BNCreateBinaryDataViewFromFile(meta.handle, &mut file.api_object as *mut _) };

        if handle.is_null() {
            return Err(());
        }

        unsafe { Ok(Ref::new(Self { handle })) }
    }

    pub fn from_data(meta: &FileMetadata, data: &[u8]) -> Result<Ref<Self>> {
        let handle = unsafe {
            BNCreateBinaryDataViewFromData(meta.handle, data.as_ptr() as *mut _, data.len())
        };

        if handle.is_null() {
            return Err(());
        }

        unsafe { Ok(Ref::new(Self { handle })) }
    }
}

impl BinaryViewBase for BinaryView {
    fn read(&self, buf: &mut [u8], offset: u64) -> usize {
        unsafe { BNReadViewData(self.handle, buf.as_mut_ptr() as *mut _, offset, buf.len()) }
    }

    fn write(&self, offset: u64, data: &[u8]) -> usize {
        unsafe { BNWriteViewData(self.handle, offset, data.as_ptr() as *const _, data.len()) }
    }

    fn insert(&self, offset: u64, data: &[u8]) -> usize {
        unsafe { BNInsertViewData(self.handle, offset, data.as_ptr() as *const _, data.len()) }
    }

    fn remove(&self, offset: u64, len: usize) -> usize {
        unsafe { BNRemoveViewData(self.handle, offset, len as u64) }
    }

    fn modification_status(&self, offset: u64) -> ModificationStatus {
        unsafe { BNGetModification(self.handle, offset) }
    }

    fn offset_valid(&self, offset: u64) -> bool {
        unsafe { BNIsValidOffset(self.handle, offset) }
    }

    fn offset_readable(&self, offset: u64) -> bool {
        unsafe { BNIsOffsetReadable(self.handle, offset) }
    }

    fn offset_writable(&self, offset: u64) -> bool {
        unsafe { BNIsOffsetWritable(self.handle, offset) }
    }

    fn offset_executable(&self, offset: u64) -> bool {
        unsafe { BNIsOffsetExecutable(self.handle, offset) }
    }

    fn offset_backed_by_file(&self, offset: u64) -> bool {
        unsafe { BNIsOffsetBackedByFile(self.handle, offset) }
    }

    fn next_valid_offset_after(&self, offset: u64) -> u64 {
        unsafe { BNGetNextValidOffset(self.handle, offset) }
    }

    fn default_endianness(&self) -> Endianness {
        unsafe { BNGetDefaultEndianness(self.handle) }
    }

    fn relocatable(&self) -> bool {
        unsafe { BNIsRelocatable(self.handle) }
    }

    fn address_size(&self) -> usize {
        unsafe { BNGetViewAddressSize(self.handle) }
    }

    fn start(&self) -> u64 {
        unsafe { BNGetStartOffset(self.handle) }
    }

    fn len(&self) -> usize {
        unsafe { BNGetViewLength(self.handle) as usize }
    }

    fn entry_point(&self) -> u64 {
        unsafe { BNGetEntryPoint(self.handle) }
    }

    fn executable(&self) -> bool {
        unsafe { BNIsExecutableView(self.handle) }
    }
}

unsafe impl RefCountable for BinaryView {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewViewReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeBinaryView(handle.handle);
    }
}

impl AsRef<BinaryView> for BinaryView {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl ToOwned for BinaryView {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl Send for BinaryView {}
unsafe impl Sync for BinaryView {}
