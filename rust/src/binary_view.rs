// Copyright 2021-2026 Vector 35 Inc.
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

//! A view on binary data and queryable interface of a binary files analysis.

use binaryninjacore_sys::*;

// Used for documentation
#[allow(unused)]
pub use crate::workflow::AnalysisContext;

use crate::architecture::{Architecture, CoreArchitecture};
use crate::base_detection::BaseAddressDetection;
use crate::basic_block::BasicBlock;
use crate::binary_view::search::SearchQuery;
use crate::component::Component;
use crate::confidence::Conf;
use crate::data_buffer::DataBuffer;
use crate::debuginfo::DebugInfo;
use crate::disassembly::DisassemblySettings;
use crate::external_library::{ExternalLibrary, ExternalLocation};
use crate::file_accessor::{Accessor, FileAccessor};
use crate::file_metadata::FileMetadata;
use crate::flowgraph::FlowGraph;
use crate::function::{Function, FunctionViewType, Location, NativeBlock};
use crate::linear_view::{LinearDisassemblyLine, LinearViewCursor};
use crate::metadata::Metadata;
use crate::platform::Platform;
use crate::progress::{NoProgressCallback, ProgressCallback};
use crate::project::file::ProjectFile;
use crate::rc::*;
use crate::references::{CodeReference, DataReference};
use crate::relocation::Relocation;
use crate::section::{Section, SectionBuilder};
use crate::segment::{Segment, SegmentBuilder};
use crate::settings::Settings;
use crate::string::*;
use crate::symbol::{Symbol, SymbolType};
use crate::tags::{Tag, TagReference, TagType};
use crate::types::{
    NamedTypeReference, QualifiedName, QualifiedNameAndType, QualifiedNameTypeAndId, Type,
    TypeArchive, TypeArchiveId, TypeContainer, TypeLibrary,
};
use crate::variable::DataVariable;
use crate::workflow::Workflow;
use crate::{Endianness, BN_FULL_CONFIDENCE};
use std::collections::{BTreeMap, HashMap};
use std::ffi::{c_char, c_void, CString};
use std::fmt::{Display, Formatter};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::{result, slice};

pub mod memory_map;
pub mod reader;
pub mod search;
pub mod writer;

pub use memory_map::{MemoryMap, MemoryRegionInfo, ResolvedRange};
pub use reader::BinaryReader;
pub use writer::BinaryWriter;

pub type Result<R> = result::Result<R, ()>;
pub type BinaryViewEventType = BNBinaryViewEventType;
pub type AnalysisState = BNAnalysisState;
pub type ModificationStatus = BNModificationStatus;
pub type StringType = BNStringType;
pub type FindFlag = BNFindFlag;

#[allow(clippy::len_without_is_empty)]
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

    /// Check if the offset is valid for the current view.
    fn offset_valid(&self, offset: u64) -> bool {
        let mut buf = [0u8; 1];

        // don't use self.read so that if segments were used we
        // check against those as well
        self.as_ref().read(&mut buf[..], offset) == buf.len()
    }

    /// Check if the offset is readable for the current view.
    fn offset_readable(&self, offset: u64) -> bool {
        self.offset_valid(offset)
    }

    /// Check if the offset is writable for the current view.
    fn offset_writable(&self, offset: u64) -> bool {
        self.offset_valid(offset)
    }

    /// Check if the offset is executable for the current view.
    fn offset_executable(&self, offset: u64) -> bool {
        self.offset_valid(offset)
    }

    /// Check if the offset is backed by the original file and not added after the fact.
    fn offset_backed_by_file(&self, offset: u64) -> bool {
        self.offset_valid(offset)
    }

    /// Get the next valid offset after the provided `offset`, useful if you need to iterate over all
    /// readable offsets in the view.
    fn next_valid_offset_after(&self, offset: u64) -> u64 {
        let start = self.as_ref().start();

        if offset < start {
            start
        } else {
            offset
        }
    }

    /// Whether the data at the given `offset` been modified (patched).
    fn modification_status(&self, _offset: u64) -> ModificationStatus {
        ModificationStatus::Original
    }

    /// The lowest address in the view.
    fn start(&self) -> u64 {
        0
    }

    /// The length of the view.
    fn len(&self) -> u64 {
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

    fn save(&self) -> bool {
        self.as_ref()
            .parent_view()
            .map(|view| view.save())
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone)]
pub struct ActiveAnalysisInfo {
    pub func: Ref<Function>,
    pub analysis_time: u64,
    pub update_count: usize,
    pub submit_count: usize,
}

#[derive(Debug, Clone)]
pub struct AnalysisInfo {
    pub state: AnalysisState,
    pub analysis_time: u64,
    pub active_info: Vec<ActiveAnalysisInfo>,
}

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum AnalysisProgress {
    Initial,
    Hold,
    Idle,
    Discovery,
    Disassembling(usize, usize),
    Analyzing(usize, usize),
    ExtendedAnalysis,
}

impl Display for AnalysisProgress {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            AnalysisProgress::Initial => {
                write!(f, "Initial")
            }
            AnalysisProgress::Hold => {
                write!(f, "Hold")
            }
            AnalysisProgress::Idle => {
                write!(f, "Idle")
            }
            AnalysisProgress::Discovery => {
                write!(f, "Discovery")
            }
            AnalysisProgress::Disassembling(count, total) => {
                write!(f, "Disassembling ({count}/{total})")
            }
            AnalysisProgress::Analyzing(count, total) => {
                write!(f, "Analyzing ({count}/{total})")
            }
            AnalysisProgress::ExtendedAnalysis => {
                write!(f, "Extended Analysis")
            }
        }
    }
}

impl From<BNAnalysisProgress> for AnalysisProgress {
    fn from(value: BNAnalysisProgress) -> Self {
        match value.state {
            BNAnalysisState::InitialState => Self::Initial,
            BNAnalysisState::HoldState => Self::Hold,
            BNAnalysisState::IdleState => Self::Idle,
            BNAnalysisState::DiscoveryState => Self::Discovery,
            BNAnalysisState::DisassembleState => Self::Disassembling(value.count, value.total),
            BNAnalysisState::AnalyzeState => Self::Analyzing(value.count, value.total),
            BNAnalysisState::ExtendedAnalyzeState => Self::ExtendedAnalysis,
        }
    }
}

pub trait BinaryViewExt: BinaryViewBase {
    fn file(&self) -> Ref<FileMetadata> {
        unsafe {
            let raw = BNGetFileForView(self.as_ref().handle);
            FileMetadata::ref_from_raw(raw)
        }
    }

    fn parent_view(&self) -> Option<Ref<BinaryView>> {
        let raw_view_ptr = unsafe { BNGetParentView(self.as_ref().handle) };
        match raw_view_ptr.is_null() {
            false => Some(unsafe { BinaryView::ref_from_raw(raw_view_ptr) }),
            true => None,
        }
    }

    fn raw_view(&self) -> Option<Ref<BinaryView>> {
        self.file().view_of_type("Raw")
    }

    fn view_type(&self) -> String {
        let ptr: *mut c_char = unsafe { BNGetViewType(self.as_ref().handle) };
        unsafe { BnString::into_string(ptr) }
    }

    /// Reads up to `len` bytes from address `offset`
    fn read_vec(&self, offset: u64, len: usize) -> Vec<u8> {
        let mut ret = vec![0; len];
        let size = self.read(&mut ret, offset);
        ret.truncate(size);
        ret
    }

    /// Appends up to `len` bytes from address `offset` into `dest`
    fn read_into_vec(&self, dest: &mut Vec<u8>, offset: u64, len: usize) -> usize {
        let starting_len = dest.len();
        dest.resize(starting_len + len, 0);
        let read_size = self.read(&mut dest[starting_len..], offset);
        dest.truncate(starting_len + read_size);
        read_size
    }

    /// Reads up to `len` bytes from the address `offset` returning a `CString` if available.
    fn read_c_string_at(&self, offset: u64, len: usize) -> Option<CString> {
        let mut buf = vec![0; len];
        let size = self.read(&mut buf, offset);
        let string = CString::new(buf[..size].to_vec()).ok()?;
        Some(string)
    }

    /// Reads up to `len` bytes from the address `offset` returning a `String` if available.
    fn read_utf8_string_at(&self, offset: u64, len: usize) -> Option<String> {
        let mut buf = vec![0; len];
        let size = self.read(&mut buf, offset);
        let string = String::from_utf8(buf[..size].to_vec()).ok()?;
        Some(string)
    }

    /// Search the view using the query options.
    ///
    /// In the `on_match` callback return `false` to stop searching.
    fn search<C: FnMut(u64, &DataBuffer) -> bool>(&self, query: &SearchQuery, on_match: C) -> bool {
        self.search_with_progress(query, on_match, NoProgressCallback)
    }

    /// Search the view using the query options.
    ///
    /// In the `on_match` callback return `false` to stop searching.
    fn search_with_progress<P: ProgressCallback, C: FnMut(u64, &DataBuffer) -> bool>(
        &self,
        query: &SearchQuery,
        mut on_match: C,
        mut progress: P,
    ) -> bool {
        unsafe extern "C" fn cb_on_match<C: FnMut(u64, &DataBuffer) -> bool>(
            ctx: *mut c_void,
            offset: u64,
            data: *mut BNDataBuffer,
        ) -> bool {
            let f = ctx as *mut C;
            let buffer = DataBuffer::from_raw(data);
            (*f)(offset, &buffer)
        }

        let query = query.to_json().to_cstr();
        unsafe {
            BNSearch(
                self.as_ref().handle,
                query.as_ptr(),
                &mut progress as *mut P as *mut c_void,
                Some(P::cb_progress_callback),
                &mut on_match as *const C as *mut c_void,
                Some(cb_on_match::<C>),
            )
        }
    }

    fn find_next_data(&self, start: u64, end: u64, data: &DataBuffer) -> Option<u64> {
        self.find_next_data_with_opts(
            start,
            end,
            data,
            FindFlag::FindCaseInsensitive,
            NoProgressCallback,
        )
    }

    /// # Warning
    ///
    /// This function is likely to be changed to take in a "query" structure. Or deprecated entirely.
    fn find_next_data_with_opts<P: ProgressCallback>(
        &self,
        start: u64,
        end: u64,
        data: &DataBuffer,
        flag: FindFlag,
        mut progress: P,
    ) -> Option<u64> {
        let mut result: u64 = 0;
        let found = unsafe {
            BNFindNextDataWithProgress(
                self.as_ref().handle,
                start,
                end,
                data.as_raw(),
                &mut result,
                flag,
                &mut progress as *mut P as *mut c_void,
                Some(P::cb_progress_callback),
            )
        };

        if found {
            Some(result)
        } else {
            None
        }
    }

    fn find_next_constant(
        &self,
        start: u64,
        end: u64,
        constant: u64,
        view_type: FunctionViewType,
    ) -> Option<u64> {
        // TODO: What are the best "default" settings?
        let settings = DisassemblySettings::new();
        self.find_next_constant_with_opts(
            start,
            end,
            constant,
            &settings,
            view_type,
            NoProgressCallback,
        )
    }

    /// # Warning
    ///
    /// This function is likely to be changed to take in a "query" structure.
    fn find_next_constant_with_opts<P: ProgressCallback>(
        &self,
        start: u64,
        end: u64,
        constant: u64,
        disasm_settings: &DisassemblySettings,
        view_type: FunctionViewType,
        mut progress: P,
    ) -> Option<u64> {
        let mut result: u64 = 0;
        let raw_view_type = FunctionViewType::into_raw(view_type);
        let found = unsafe {
            BNFindNextConstantWithProgress(
                self.as_ref().handle,
                start,
                end,
                constant,
                &mut result,
                disasm_settings.handle,
                raw_view_type,
                &mut progress as *mut P as *mut c_void,
                Some(P::cb_progress_callback),
            )
        };
        FunctionViewType::free_raw(raw_view_type);

        if found {
            Some(result)
        } else {
            None
        }
    }

    fn find_next_text(
        &self,
        start: u64,
        end: u64,
        text: &str,
        view_type: FunctionViewType,
    ) -> Option<u64> {
        // TODO: What are the best "default" settings?
        let settings = DisassemblySettings::new();
        self.find_next_text_with_opts(
            start,
            end,
            text,
            &settings,
            FindFlag::FindCaseInsensitive,
            view_type,
            NoProgressCallback,
        )
    }

    /// # Warning
    ///
    /// This function is likely to be changed to take in a "query" structure.
    fn find_next_text_with_opts<P: ProgressCallback>(
        &self,
        start: u64,
        end: u64,
        text: &str,
        disasm_settings: &DisassemblySettings,
        flag: FindFlag,
        view_type: FunctionViewType,
        mut progress: P,
    ) -> Option<u64> {
        let text = text.to_cstr();
        let raw_view_type = FunctionViewType::into_raw(view_type);
        let mut result: u64 = 0;
        let found = unsafe {
            BNFindNextTextWithProgress(
                self.as_ref().handle,
                start,
                end,
                text.as_ptr(),
                &mut result,
                disasm_settings.handle,
                flag,
                raw_view_type,
                &mut progress as *mut P as *mut c_void,
                Some(P::cb_progress_callback),
            )
        };
        FunctionViewType::free_raw(raw_view_type);

        if found {
            Some(result)
        } else {
            None
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

    /// Consults the [`Section`]'s current [`crate::section::Semantics`] to determine if the
    /// offset has code semantics.
    fn offset_has_code_semantics(&self, offset: u64) -> bool {
        unsafe { BNIsOffsetCodeSemantics(self.as_ref().handle, offset) }
    }

    /// Check if the offset is within a [`Section`] with [`crate::section::Semantics::External`].
    fn offset_has_extern_semantics(&self, offset: u64) -> bool {
        unsafe { BNIsOffsetExternSemantics(self.as_ref().handle, offset) }
    }

    /// Consults the [`Section`]'s current [`crate::section::Semantics`] to determine if the
    /// offset has writable semantics.
    fn offset_has_writable_semantics(&self, offset: u64) -> bool {
        unsafe { BNIsOffsetWritableSemantics(self.as_ref().handle, offset) }
    }

    /// Consults the [`Section`]'s current [`crate::section::Semantics`] to determine if the
    /// offset has read only semantics.
    fn offset_has_read_only_semantics(&self, offset: u64) -> bool {
        unsafe { BNIsOffsetReadOnlySemantics(self.as_ref().handle, offset) }
    }

    fn image_base(&self) -> u64 {
        unsafe { BNGetImageBase(self.as_ref().handle) }
    }

    fn original_image_base(&self) -> u64 {
        unsafe { BNGetOriginalImageBase(self.as_ref().handle) }
    }

    fn set_original_image_base(&self, image_base: u64) {
        unsafe { BNSetOriginalImageBase(self.as_ref().handle, image_base) }
    }

    /// The highest address in the view.
    fn end(&self) -> u64 {
        unsafe { BNGetEndOffset(self.as_ref().handle) }
    }

    fn add_analysis_option(&self, name: &str) {
        let name = name.to_cstr();
        unsafe { BNAddAnalysisOption(self.as_ref().handle, name.as_ptr()) }
    }

    fn has_initial_analysis(&self) -> bool {
        unsafe { BNHasInitialAnalysis(self.as_ref().handle) }
    }

    fn set_analysis_hold(&self, enable: bool) {
        unsafe { BNSetAnalysisHold(self.as_ref().handle, enable) }
    }

    /// Runs the analysis pipeline, analyzing any data that has been marked for updates.
    ///
    /// You can explicitly mark a function to be updated with:
    /// - [`Function::mark_updates_required`]
    /// - [`Function::mark_caller_updates_required`]
    ///
    /// NOTE: This is a **non-blocking** call, use [`BinaryViewExt::update_analysis_and_wait`] if you
    /// require analysis to have completed before moving on.
    fn update_analysis(&self) {
        unsafe {
            BNUpdateAnalysis(self.as_ref().handle);
        }
    }

    /// Runs the analysis pipeline, analyzing any data that has been marked for updates.
    ///
    /// You can explicitly mark a function to be updated with:
    /// - [`Function::mark_updates_required`]
    /// - [`Function::mark_caller_updates_required`]
    ///
    /// NOTE: This is a **blocking** call, use [`BinaryViewExt::update_analysis`] if you do not
    /// need to wait for the analysis update to finish.
    fn update_analysis_and_wait(&self) {
        unsafe {
            BNUpdateAnalysisAndWait(self.as_ref().handle);
        }
    }

    /// Causes **all** functions to be reanalyzed.
    ///
    /// Use [`BinaryViewExt::update_analysis`] or [`BinaryViewExt::update_analysis_and_wait`] instead
    /// if you want to incrementally update analysis.
    ///
    /// NOTE: This function does not wait for the analysis to finish.
    fn reanalyze(&self) {
        unsafe {
            BNReanalyzeAllFunctions(self.as_ref().handle);
        }
    }

    fn abort_analysis(&self) {
        unsafe { BNAbortAnalysis(self.as_ref().handle) }
    }

    fn analysis_is_aborted(&self) -> bool {
        unsafe { BNAnalysisIsAborted(self.as_ref().handle) }
    }

    fn workflow(&self) -> Ref<Workflow> {
        unsafe {
            let raw_ptr = BNGetWorkflowForBinaryView(self.as_ref().handle);
            let nonnull = NonNull::new(raw_ptr).expect("All views must have a workflow");
            Workflow::ref_from_raw(nonnull)
        }
    }

    fn analysis_info(&self) -> AnalysisInfo {
        let info_ptr = unsafe { BNGetAnalysisInfo(self.as_ref().handle) };
        assert!(!info_ptr.is_null());
        let info = unsafe { *info_ptr };
        let active_infos = unsafe { slice::from_raw_parts(info.activeInfo, info.count) };

        let mut active_info_list = vec![];
        for active_info in active_infos {
            let func = unsafe { Function::from_raw(active_info.func).to_owned() };
            active_info_list.push(ActiveAnalysisInfo {
                func,
                analysis_time: active_info.analysisTime,
                update_count: active_info.updateCount,
                submit_count: active_info.submitCount,
            });
        }

        let result = AnalysisInfo {
            state: info.state,
            analysis_time: info.analysisTime,
            active_info: active_info_list,
        };

        unsafe { BNFreeAnalysisInfo(info_ptr) };
        result
    }

    fn analysis_progress(&self) -> AnalysisProgress {
        let progress_raw = unsafe { BNGetAnalysisProgress(self.as_ref().handle) };
        AnalysisProgress::from(progress_raw)
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
            BNSetDefaultArchitecture(self.as_ref().handle, arch.as_ref().handle);
        }
    }

    fn default_platform(&self) -> Option<Ref<Platform>> {
        unsafe {
            let raw = BNGetDefaultPlatform(self.as_ref().handle);

            if raw.is_null() {
                return None;
            }

            Some(Platform::ref_from_raw(raw))
        }
    }

    fn set_default_platform(&self, plat: &Platform) {
        unsafe {
            BNSetDefaultPlatform(self.as_ref().handle, plat.handle);
        }
    }

    fn base_address_detection(&self) -> Option<BaseAddressDetection> {
        unsafe {
            let handle = BNCreateBaseAddressDetection(self.as_ref().handle);
            NonNull::new(handle).map(|base| BaseAddressDetection::from_raw(base))
        }
    }

    fn instruction_len<A: Architecture>(&self, arch: &A, addr: u64) -> Option<usize> {
        unsafe {
            let size = BNGetInstructionLength(self.as_ref().handle, arch.as_ref().handle, addr);

            if size > 0 {
                Some(size)
            } else {
                None
            }
        }
    }

    fn symbol_by_address(&self, addr: u64) -> Option<Ref<Symbol>> {
        unsafe {
            let raw_sym_ptr =
                BNGetSymbolByAddress(self.as_ref().handle, addr, std::ptr::null_mut());
            match raw_sym_ptr.is_null() {
                false => Some(Symbol::ref_from_raw(raw_sym_ptr)),
                true => None,
            }
        }
    }

    fn symbol_by_raw_name(&self, raw_name: impl IntoCStr) -> Option<Ref<Symbol>> {
        let raw_name = raw_name.to_cstr();

        unsafe {
            let raw_sym_ptr = BNGetSymbolByRawName(
                self.as_ref().handle,
                raw_name.as_ptr(),
                std::ptr::null_mut(),
            );
            match raw_sym_ptr.is_null() {
                false => Some(Symbol::ref_from_raw(raw_sym_ptr)),
                true => None,
            }
        }
    }

    fn symbols(&self) -> Array<Symbol> {
        unsafe {
            let mut count = 0;
            let handles = BNGetSymbols(self.as_ref().handle, &mut count, std::ptr::null_mut());

            Array::new(handles, count, ())
        }
    }

    fn symbols_by_name(&self, name: impl IntoCStr) -> Array<Symbol> {
        let raw_name = name.to_cstr();

        unsafe {
            let mut count = 0;
            let handles = BNGetSymbolsByName(
                self.as_ref().handle,
                raw_name.as_ptr(),
                &mut count,
                std::ptr::null_mut(),
            );

            Array::new(handles, count, ())
        }
    }

    fn symbols_in_range(&self, range: Range<u64>) -> Array<Symbol> {
        unsafe {
            let mut count = 0;
            let len = range.end.wrapping_sub(range.start);
            let handles = BNGetSymbolsInRange(
                self.as_ref().handle,
                range.start,
                len,
                &mut count,
                std::ptr::null_mut(),
            );

            Array::new(handles, count, ())
        }
    }

    fn symbols_of_type(&self, ty: SymbolType) -> Array<Symbol> {
        unsafe {
            let mut count = 0;
            let handles = BNGetSymbolsOfType(
                self.as_ref().handle,
                ty.into(),
                &mut count,
                std::ptr::null_mut(),
            );

            Array::new(handles, count, ())
        }
    }

    fn symbols_of_type_in_range(&self, ty: SymbolType, range: Range<u64>) -> Array<Symbol> {
        unsafe {
            let mut count = 0;
            let len = range.end.wrapping_sub(range.start);
            let handles = BNGetSymbolsOfTypeInRange(
                self.as_ref().handle,
                ty.into(),
                range.start,
                len,
                &mut count,
                std::ptr::null_mut(),
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
    ) -> Result<Ref<Symbol>> {
        let mut type_with_conf = BNTypeWithConfidence {
            type_: if let Some(t) = ty.into() {
                t.handle
            } else {
                std::ptr::null_mut()
            },
            confidence: BN_FULL_CONFIDENCE,
        };

        unsafe {
            let raw_sym = BNDefineAutoSymbolAndVariableOrFunction(
                self.as_ref().handle,
                plat.handle,
                sym.handle,
                &mut type_with_conf,
            );

            if raw_sym.is_null() {
                return Err(());
            }

            Ok(Symbol::ref_from_raw(raw_sym))
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

    fn data_variables(&self) -> Array<DataVariable> {
        unsafe {
            let mut count = 0;
            let vars = BNGetDataVariables(self.as_ref().handle, &mut count);
            Array::new(vars, count, ())
        }
    }

    fn data_variable_at_address(&self, addr: u64) -> Option<DataVariable> {
        let mut dv = BNDataVariable::default();
        unsafe {
            if BNGetDataVariableAtAddress(self.as_ref().handle, addr, &mut dv) {
                Some(DataVariable::from_owned_raw(dv))
            } else {
                None
            }
        }
    }

    fn define_auto_data_var<'a, T: Into<Conf<&'a Type>>>(&self, addr: u64, ty: T) {
        let mut owned_raw_ty = Conf::<&Type>::into_raw(ty.into());
        unsafe {
            BNDefineDataVariable(self.as_ref().handle, addr, &mut owned_raw_ty);
        }
    }

    /// You likely would also like to call [`BinaryViewExt::define_user_symbol`] to bind this data variable with a name
    fn define_user_data_var<'a, T: Into<Conf<&'a Type>>>(&self, addr: u64, ty: T) {
        let mut owned_raw_ty = Conf::<&Type>::into_raw(ty.into());
        unsafe {
            BNDefineUserDataVariable(self.as_ref().handle, addr, &mut owned_raw_ty);
        }
    }

    fn undefine_auto_data_var(&self, addr: u64, blacklist: Option<bool>) {
        unsafe {
            BNUndefineDataVariable(self.as_ref().handle, addr, blacklist.unwrap_or(true));
        }
    }

    fn undefine_user_data_var(&self, addr: u64) {
        unsafe {
            BNUndefineUserDataVariable(self.as_ref().handle, addr);
        }
    }

    fn define_auto_type<T: Into<QualifiedName>>(
        &self,
        name: T,
        source: &str,
        type_obj: &Type,
    ) -> QualifiedName {
        let mut raw_name = QualifiedName::into_raw(name.into());
        let source_str = source.to_cstr();
        let name_handle = unsafe {
            let id_str =
                BNGenerateAutoTypeId(source_str.as_ref().as_ptr() as *const _, &mut raw_name);
            BNDefineAnalysisType(self.as_ref().handle, id_str, &mut raw_name, type_obj.handle)
        };
        QualifiedName::free_raw(raw_name);
        QualifiedName::from_owned_raw(name_handle)
    }

    fn define_auto_type_with_id<T: Into<QualifiedName>>(
        &self,
        name: T,
        id: &str,
        type_obj: &Type,
    ) -> QualifiedName {
        let mut raw_name = QualifiedName::into_raw(name.into());
        let id_str = id.to_cstr();
        let result_raw_name = unsafe {
            BNDefineAnalysisType(
                self.as_ref().handle,
                id_str.as_ref().as_ptr() as *const _,
                &mut raw_name,
                type_obj.handle,
            )
        };
        QualifiedName::free_raw(raw_name);
        QualifiedName::from_owned_raw(result_raw_name)
    }

    fn define_user_type<T: Into<QualifiedName>>(&self, name: T, type_obj: &Type) {
        let mut raw_name = QualifiedName::into_raw(name.into());
        unsafe { BNDefineUserAnalysisType(self.as_ref().handle, &mut raw_name, type_obj.handle) }
        QualifiedName::free_raw(raw_name);
    }

    fn define_auto_types<T, I>(&self, names_sources_and_types: T) -> HashMap<String, QualifiedName>
    where
        T: Iterator<Item = I>,
        I: Into<QualifiedNameTypeAndId>,
    {
        self.define_auto_types_with_progress(names_sources_and_types, NoProgressCallback)
    }

    fn define_auto_types_with_progress<T, I, P>(
        &self,
        names_sources_and_types: T,
        mut progress: P,
    ) -> HashMap<String, QualifiedName>
    where
        T: Iterator<Item = I>,
        I: Into<QualifiedNameTypeAndId>,
        P: ProgressCallback,
    {
        let mut types: Vec<BNQualifiedNameTypeAndId> = names_sources_and_types
            .map(Into::into)
            .map(QualifiedNameTypeAndId::into_raw)
            .collect();
        let mut result_ids: *mut *mut c_char = std::ptr::null_mut();
        let mut result_names: *mut BNQualifiedName = std::ptr::null_mut();

        let result_count = unsafe {
            BNDefineAnalysisTypes(
                self.as_ref().handle,
                types.as_mut_ptr(),
                types.len(),
                Some(P::cb_progress_callback),
                &mut progress as *mut P as *mut c_void,
                &mut result_ids as *mut _,
                &mut result_names as *mut _,
            )
        };

        for ty in types {
            QualifiedNameTypeAndId::free_raw(ty);
        }

        let id_array = unsafe { Array::<BnString>::new(result_ids, result_count, ()) };
        let name_array = unsafe { Array::<QualifiedName>::new(result_names, result_count, ()) };
        id_array
            .into_iter()
            .zip(&name_array)
            .map(|(id, name)| (id.to_owned(), name))
            .collect()
    }

    fn define_user_types<T, I>(&self, names_and_types: T)
    where
        T: Iterator<Item = I>,
        I: Into<QualifiedNameAndType>,
    {
        self.define_user_types_with_progress(names_and_types, NoProgressCallback);
    }

    fn define_user_types_with_progress<T, I, P>(&self, names_and_types: T, mut progress: P)
    where
        T: Iterator<Item = I>,
        I: Into<QualifiedNameAndType>,
        P: ProgressCallback,
    {
        let mut types: Vec<BNQualifiedNameAndType> = names_and_types
            .map(Into::into)
            .map(QualifiedNameAndType::into_raw)
            .collect();

        unsafe {
            BNDefineUserAnalysisTypes(
                self.as_ref().handle,
                types.as_mut_ptr(),
                types.len(),
                Some(P::cb_progress_callback),
                &mut progress as *mut P as *mut c_void,
            )
        };

        for ty in types {
            QualifiedNameAndType::free_raw(ty);
        }
    }

    fn undefine_auto_type(&self, id: &str) {
        let id_str = id.to_cstr();
        unsafe {
            BNUndefineAnalysisType(self.as_ref().handle, id_str.as_ref().as_ptr() as *const _);
        }
    }

    fn undefine_user_type<T: Into<QualifiedName>>(&self, name: T) {
        let mut raw_name = QualifiedName::into_raw(name.into());
        unsafe { BNUndefineUserAnalysisType(self.as_ref().handle, &mut raw_name) }
        QualifiedName::free_raw(raw_name);
    }

    fn types(&self) -> Array<QualifiedNameAndType> {
        unsafe {
            let mut count = 0usize;
            let types = BNGetAnalysisTypeList(self.as_ref().handle, &mut count);
            Array::new(types, count, ())
        }
    }

    fn dependency_sorted_types(&self) -> Array<QualifiedNameAndType> {
        unsafe {
            let mut count = 0usize;
            let types = BNGetAnalysisDependencySortedTypeList(self.as_ref().handle, &mut count);
            Array::new(types, count, ())
        }
    }

    fn type_by_name<T: Into<QualifiedName>>(&self, name: T) -> Option<Ref<Type>> {
        let mut raw_name = QualifiedName::into_raw(name.into());
        unsafe {
            let type_handle = BNGetAnalysisTypeByName(self.as_ref().handle, &mut raw_name);
            QualifiedName::free_raw(raw_name);
            if type_handle.is_null() {
                return None;
            }
            Some(Type::ref_from_raw(type_handle))
        }
    }

    fn type_by_ref(&self, ref_: &NamedTypeReference) -> Option<Ref<Type>> {
        unsafe {
            let type_handle = BNGetAnalysisTypeByRef(self.as_ref().handle, ref_.handle);
            if type_handle.is_null() {
                return None;
            }
            Some(Type::ref_from_raw(type_handle))
        }
    }

    fn type_by_id(&self, id: &str) -> Option<Ref<Type>> {
        let id_str = id.to_cstr();
        unsafe {
            let type_handle = BNGetAnalysisTypeById(self.as_ref().handle, id_str.as_ptr());
            if type_handle.is_null() {
                return None;
            }
            Some(Type::ref_from_raw(type_handle))
        }
    }

    fn type_name_by_id(&self, id: &str) -> Option<QualifiedName> {
        let id_str = id.to_cstr();
        unsafe {
            let name_handle = BNGetAnalysisTypeNameById(self.as_ref().handle, id_str.as_ptr());
            let name = QualifiedName::from_owned_raw(name_handle);
            // The core will return an empty qualified name if no type name was found.
            match name.items.is_empty() {
                true => None,
                false => Some(name),
            }
        }
    }

    fn type_id_by_name<T: Into<QualifiedName>>(&self, name: T) -> Option<String> {
        let mut raw_name = QualifiedName::into_raw(name.into());
        unsafe {
            let id_cstr = BNGetAnalysisTypeId(self.as_ref().handle, &mut raw_name);
            QualifiedName::free_raw(raw_name);
            let id = BnString::into_string(id_cstr);
            match id.is_empty() {
                true => None,
                false => Some(id),
            }
        }
    }

    fn is_type_auto_defined<T: Into<QualifiedName>>(&self, name: T) -> bool {
        let mut raw_name = QualifiedName::into_raw(name.into());
        let result = unsafe { BNIsAnalysisTypeAutoDefined(self.as_ref().handle, &mut raw_name) };
        QualifiedName::free_raw(raw_name);
        result
    }

    fn segments(&self) -> Array<Segment> {
        unsafe {
            let mut count = 0;
            let raw_segments = BNGetSegments(self.as_ref().handle, &mut count);
            Array::new(raw_segments, count, ())
        }
    }

    fn segment_at(&self, addr: u64) -> Option<Ref<Segment>> {
        unsafe {
            let raw_seg = BNGetSegmentAt(self.as_ref().handle, addr);
            match raw_seg.is_null() {
                false => Some(Segment::ref_from_raw(raw_seg)),
                true => None,
            }
        }
    }

    /// Adds a segment to the view.
    ///
    /// NOTE: Consider using [BinaryViewExt::begin_bulk_add_segments] and [BinaryViewExt::end_bulk_add_segments]
    /// if you plan on adding a number of segments all at once, to avoid unnecessary MemoryMap updates.
    fn add_segment(&self, segment: SegmentBuilder) {
        segment.create(self.as_ref());
    }

    // TODO: Replace with BulkModify guard.
    /// Start adding segments in bulk. Useful for adding large numbers of segments.
    ///
    /// After calling this any call to [BinaryViewExt::add_segment] will be uncommitted until a call to
    /// [BinaryViewExt::end_bulk_add_segments]
    ///
    /// If you wish to discard the uncommitted segments you can call [BinaryViewExt::cancel_bulk_add_segments].
    ///
    /// NOTE: This **must** be paired with a later call to [BinaryViewExt::end_bulk_add_segments] or
    /// [BinaryViewExt::cancel_bulk_add_segments], otherwise segments added after this call will stay uncommitted.
    fn begin_bulk_add_segments(&self) {
        unsafe { BNBeginBulkAddSegments(self.as_ref().handle) }
    }

    // TODO: Replace with BulkModify guard.
    /// Commit all auto and user segments that have been added since the call to [Self::begin_bulk_add_segments].
    ///
    /// NOTE: This **must** be paired with a prior call to [Self::begin_bulk_add_segments], otherwise this
    /// does nothing and segments are added individually.
    fn end_bulk_add_segments(&self) {
        unsafe { BNEndBulkAddSegments(self.as_ref().handle) }
    }

    // TODO: Replace with BulkModify guard.
    /// Flushes the auto and user segments that have yet to be committed.
    ///
    /// This is to be used in conjunction with [Self::begin_bulk_add_segments]
    /// and [Self::end_bulk_add_segments], where the latter will commit the segments
    /// which have been added since [Self::begin_bulk_add_segments], this function
    /// will discard them so that they do not get added to the view.
    fn cancel_bulk_add_segments(&self) {
        unsafe { BNCancelBulkAddSegments(self.as_ref().handle) }
    }

    fn add_section(&self, section: SectionBuilder) {
        section.create(self.as_ref());
    }

    fn remove_auto_section(&self, name: impl IntoCStr) {
        let raw_name = name.to_cstr();
        let raw_name_ptr = raw_name.as_ptr();
        unsafe {
            BNRemoveAutoSection(self.as_ref().handle, raw_name_ptr);
        }
    }

    fn remove_user_section(&self, name: impl IntoCStr) {
        let raw_name = name.to_cstr();
        let raw_name_ptr = raw_name.as_ptr();
        unsafe {
            BNRemoveUserSection(self.as_ref().handle, raw_name_ptr);
        }
    }

    fn section_by_name(&self, name: impl IntoCStr) -> Option<Ref<Section>> {
        unsafe {
            let raw_name = name.to_cstr();
            let name_ptr = raw_name.as_ptr();
            let raw_section_ptr = BNGetSectionByName(self.as_ref().handle, name_ptr);
            match raw_section_ptr.is_null() {
                false => Some(Section::ref_from_raw(raw_section_ptr)),
                true => None,
            }
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

    fn memory_map(&self) -> MemoryMap {
        MemoryMap::new(self.as_ref().to_owned())
    }

    /// Add an auto function at the given `address` with the views default platform.
    ///
    /// Use [`BinaryViewExt::add_auto_function_with_platform`] if you wish to specify a platform.
    ///
    /// NOTE: The default platform **must** be set for this view!
    fn add_auto_function(&self, address: u64) -> Option<Ref<Function>> {
        let platform = self.default_platform()?;
        self.add_auto_function_with_platform(address, &platform)
    }

    /// Add an auto function at the given `address` with the `platform`.
    ///
    /// Use [`BinaryViewExt::add_auto_function_ext`] if you wish to specify a function type.
    ///
    /// NOTE: If the view's default platform is not set, this will set it to `platform`.
    fn add_auto_function_with_platform(
        &self,
        address: u64,
        platform: &Platform,
    ) -> Option<Ref<Function>> {
        self.add_auto_function_ext(address, platform, None)
    }

    /// Add an auto function at the given `address` with the `platform` and function type.
    ///
    /// NOTE: If the view's default platform is not set, this will set it to `platform`.
    fn add_auto_function_ext(
        &self,
        address: u64,
        platform: &Platform,
        func_type: Option<&Type>,
    ) -> Option<Ref<Function>> {
        unsafe {
            let func_type = match func_type {
                Some(func_type) => func_type.handle,
                None => std::ptr::null_mut(),
            };

            let handle = BNAddFunctionForAnalysis(
                self.as_ref().handle,
                platform.handle,
                address,
                true,
                func_type,
            );

            if handle.is_null() {
                return None;
            }

            Some(Function::ref_from_raw(handle))
        }
    }

    /// Remove an auto function from the view.
    ///
    /// Pass `true` for `update_refs` to update all references of the function.
    ///
    /// NOTE: Unlike [`BinaryViewExt::remove_user_function`], this will NOT prohibit the function from
    /// being re-added in the future, use [`BinaryViewExt::remove_user_function`] to blacklist the
    /// function from being automatically created.
    fn remove_auto_function(&self, func: &Function, update_refs: bool) {
        unsafe {
            BNRemoveAnalysisFunction(self.as_ref().handle, func.handle, update_refs);
        }
    }

    /// Add a user function at the given `address` with the views default platform.
    ///
    /// Use [`BinaryViewExt::add_user_function_with_platform`] if you wish to specify a platform.
    ///
    /// NOTE: The default platform **must** be set for this view!
    fn add_user_function(&self, addr: u64) -> Option<Ref<Function>> {
        let platform = self.default_platform()?;
        self.add_user_function_with_platform(addr, &platform)
    }

    /// Add an auto function at the given `address` with the `platform`.
    ///
    /// NOTE: If the view's default platform is not set, this will set it to `platform`.
    fn add_user_function_with_platform(
        &self,
        addr: u64,
        platform: &Platform,
    ) -> Option<Ref<Function>> {
        unsafe {
            let func = BNCreateUserFunction(self.as_ref().handle, platform.handle, addr);
            if func.is_null() {
                return None;
            }
            Some(Function::ref_from_raw(func))
        }
    }

    /// Removes the function from the view and blacklists it from being created automatically.
    ///
    /// NOTE: If you call [`BinaryViewExt::add_user_function`], it will override the blacklist.
    fn remove_user_function(&self, func: &Function) {
        unsafe { BNRemoveUserFunction(self.as_ref().handle, func.handle) }
    }

    fn has_functions(&self) -> bool {
        unsafe { BNHasFunctions(self.as_ref().handle) }
    }

    /// Add an entry point at the given `address` with the view's default platform.
    ///
    /// NOTE: The default platform **must** be set for this view!
    fn add_entry_point(&self, addr: u64) {
        if let Some(platform) = self.default_platform() {
            self.add_entry_point_with_platform(addr, &platform);
        }
    }

    /// Add an entry point at the given `address` with the `platform`.
    ///
    /// NOTE: If the view's default platform is not set, this will set it to `platform`.
    fn add_entry_point_with_platform(&self, addr: u64, platform: &Platform) {
        unsafe {
            BNAddEntryPointForAnalysis(self.as_ref().handle, platform.handle, addr);
        }
    }

    fn entry_point_function(&self) -> Option<Ref<Function>> {
        unsafe {
            let raw_func_ptr = BNGetAnalysisEntryPoint(self.as_ref().handle);
            match raw_func_ptr.is_null() {
                false => Some(Function::ref_from_raw(raw_func_ptr)),
                true => None,
            }
        }
    }

    /// This list contains the analysis entry function, and functions like init_array, fini_array,
    /// and TLS callbacks etc.
    ///
    /// We see `entry_functions` as good starting points for analysis, these functions normally don't
    /// have internal references. Exported functions in a dll/so file are not included.
    fn entry_point_functions(&self) -> Array<Function> {
        unsafe {
            let mut count = 0;
            let functions = BNGetAllEntryFunctions(self.as_ref().handle, &mut count);

            Array::new(functions, count, ())
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

    /// List of functions containing `addr`
    fn functions_containing(&self, addr: u64) -> Array<Function> {
        unsafe {
            let mut count = 0;
            let functions =
                BNGetAnalysisFunctionsContainingAddress(self.as_ref().handle, addr, &mut count);

            Array::new(functions, count, ())
        }
    }

    /// List of functions with the given name.
    ///
    /// There is one special case where if you pass a string of the form `sub_[0-9a-f]+` then it will lookup all
    /// functions defined at the address matched by the regular expression if that symbol is not defined in the
    /// database.
    ///
    /// # Params
    /// - `name`: Name that the function should have
    /// - `plat`: Optional platform that the function should be defined for. Defaults to all platforms if `None` passed.
    fn functions_by_name(
        &self,
        name: impl IntoCStr,
        plat: Option<&Platform>,
    ) -> Vec<Ref<Function>> {
        let name = name.to_cstr();
        let symbols = self.symbols_by_name(&*name);
        let mut addresses: Vec<u64> = symbols.into_iter().map(|s| s.address()).collect();
        if addresses.is_empty() && name.to_bytes().starts_with(b"sub_") {
            if let Ok(str) = name.to_str() {
                if let Ok(address) = u64::from_str_radix(&str[4..], 16) {
                    addresses.push(address);
                }
            }
        }

        let mut functions = Vec::new();

        for address in addresses {
            let funcs = self.functions_at(address);
            for func in funcs.into_iter() {
                if func.start() == address && plat.is_none_or(|p| p == func.platform().as_ref()) {
                    functions.push(func.clone());
                }
            }
        }

        functions
    }

    fn function_at(&self, platform: &Platform, addr: u64) -> Option<Ref<Function>> {
        unsafe {
            let raw_func_ptr = BNGetAnalysisFunction(self.as_ref().handle, platform.handle, addr);
            match raw_func_ptr.is_null() {
                false => Some(Function::ref_from_raw(raw_func_ptr)),
                true => None,
            }
        }
    }

    fn function_start_before(&self, addr: u64) -> u64 {
        unsafe { BNGetPreviousFunctionStartBeforeAddress(self.as_ref().handle, addr) }
    }

    fn function_start_after(&self, addr: u64) -> u64 {
        unsafe { BNGetNextFunctionStartAfterAddress(self.as_ref().handle, addr) }
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

    // TODO: Should this instead be implemented on [`Function`] considering `src_func`? `Location` is local to the source function.
    fn should_skip_target_analysis(
        &self,
        src_loc: impl Into<Location>,
        src_func: &Function,
        src_end: u64,
        target: impl Into<Location>,
    ) -> bool {
        let src_loc = src_loc.into();
        let target = target.into();
        unsafe {
            BNShouldSkipTargetAnalysis(
                self.as_ref().handle,
                &mut src_loc.into(),
                src_func.handle,
                src_end,
                &mut target.into(),
            )
        }
    }

    fn read_buffer(&self, offset: u64, len: usize) -> Option<DataBuffer> {
        let read_buffer = unsafe { BNReadViewBuffer(self.as_ref().handle, offset, len) };
        if read_buffer.is_null() {
            None
        } else {
            Some(DataBuffer::from_raw(read_buffer))
        }
    }

    fn debug_info(&self) -> Ref<DebugInfo> {
        unsafe { DebugInfo::ref_from_raw(BNGetDebugInfo(self.as_ref().handle)) }
    }

    fn set_debug_info(&self, debug_info: &DebugInfo) {
        unsafe { BNSetDebugInfo(self.as_ref().handle, debug_info.handle) }
    }

    fn apply_debug_info(&self, debug_info: &DebugInfo) {
        unsafe { BNApplyDebugInfo(self.as_ref().handle, debug_info.handle) }
    }

    fn show_plaintext_report(&self, title: &str, plaintext: &str) {
        let title = title.to_cstr();
        let plaintext = plaintext.to_cstr();
        unsafe {
            BNShowPlainTextReport(
                self.as_ref().handle,
                title.as_ref().as_ptr() as *mut _,
                plaintext.as_ref().as_ptr() as *mut _,
            )
        }
    }

    fn show_markdown_report(&self, title: &str, contents: &str, plaintext: &str) {
        let title = title.to_cstr();
        let contents = contents.to_cstr();
        let plaintext = plaintext.to_cstr();
        unsafe {
            BNShowMarkdownReport(
                self.as_ref().handle,
                title.as_ref().as_ptr() as *mut _,
                contents.as_ref().as_ptr() as *mut _,
                plaintext.as_ref().as_ptr() as *mut _,
            )
        }
    }

    fn show_html_report(&self, title: &str, contents: &str, plaintext: &str) {
        let title = title.to_cstr();
        let contents = contents.to_cstr();
        let plaintext = plaintext.to_cstr();
        unsafe {
            BNShowHTMLReport(
                self.as_ref().handle,
                title.as_ref().as_ptr() as *mut _,
                contents.as_ref().as_ptr() as *mut _,
                plaintext.as_ref().as_ptr() as *mut _,
            )
        }
    }

    fn show_graph_report(&self, raw_name: &str, graph: &FlowGraph) {
        let raw_name = raw_name.to_cstr();
        unsafe {
            BNShowGraphReport(self.as_ref().handle, raw_name.as_ptr(), graph.handle);
        }
    }

    fn load_settings(&self, view_type_name: &str) -> Result<Ref<Settings>> {
        let view_type_name = view_type_name.to_cstr();
        let settings_handle =
            unsafe { BNBinaryViewGetLoadSettings(self.as_ref().handle, view_type_name.as_ptr()) };

        if settings_handle.is_null() {
            Err(())
        } else {
            Ok(unsafe { Settings::ref_from_raw(settings_handle) })
        }
    }

    fn set_load_settings(&self, view_type_name: &str, settings: &Settings) {
        let view_type_name = view_type_name.to_cstr();

        unsafe {
            BNBinaryViewSetLoadSettings(
                self.as_ref().handle,
                view_type_name.as_ptr(),
                settings.handle,
            )
        };
    }

    /// Creates a new [TagType] and adds it to the view.
    ///
    /// # Arguments
    /// * `name` - the name for the tag
    /// * `icon` - the icon (recommended 1 emoji or 2 chars) for the tag
    fn create_tag_type(&self, name: &str, icon: &str) -> Ref<TagType> {
        let tag_type = TagType::create(self.as_ref(), name, icon);
        unsafe {
            BNAddTagType(self.as_ref().handle, tag_type.handle);
        }
        tag_type
    }

    /// Removes a [TagType] and all tags that use it
    fn remove_tag_type(&self, tag_type: &TagType) {
        unsafe { BNRemoveTagType(self.as_ref().handle, tag_type.handle) }
    }

    /// Get a tag type by its name.
    fn tag_type_by_name(&self, name: &str) -> Option<Ref<TagType>> {
        let name = name.to_cstr();
        unsafe {
            let handle = BNGetTagType(self.as_ref().handle, name.as_ptr());
            if handle.is_null() {
                return None;
            }
            Some(TagType::ref_from_raw(handle))
        }
    }

    /// Get all tags in all scopes
    fn tags_all_scopes(&self) -> Array<TagReference> {
        let mut count = 0;
        unsafe {
            let tag_references = BNGetAllTagReferences(self.as_ref().handle, &mut count);
            Array::new(tag_references, count, ())
        }
    }

    /// Get all tag types present for the view
    fn tag_types(&self) -> Array<TagType> {
        let mut count = 0;
        unsafe {
            let tag_types_raw = BNGetTagTypes(self.as_ref().handle, &mut count);
            Array::new(tag_types_raw, count, ())
        }
    }

    /// Get all tag references of a specific type
    fn tags_by_type(&self, tag_type: &TagType) -> Array<TagReference> {
        let mut count = 0;
        unsafe {
            let tag_references =
                BNGetAllTagReferencesOfType(self.as_ref().handle, tag_type.handle, &mut count);
            Array::new(tag_references, count, ())
        }
    }

    /// Get a tag by its id.
    ///
    /// Note this does not tell you anything about where it is used.
    fn tag_by_id(&self, id: &str) -> Option<Ref<Tag>> {
        let id = id.to_cstr();
        unsafe {
            let handle = BNGetTag(self.as_ref().handle, id.as_ptr());
            if handle.is_null() {
                return None;
            }
            Some(Tag::ref_from_raw(handle))
        }
    }

    /// Creates and adds a tag to an address
    ///
    /// User tag creations will be added to the undo buffer
    fn add_tag(&self, addr: u64, t: &TagType, data: &str, user: bool) {
        let tag = Tag::new(t, data);

        unsafe { BNAddTag(self.as_ref().handle, tag.handle, user) }

        if user {
            unsafe { BNAddUserDataTag(self.as_ref().handle, addr, tag.handle) }
        } else {
            unsafe { BNAddAutoDataTag(self.as_ref().handle, addr, tag.handle) }
        }
    }

    /// removes a Tag object at a data address.
    fn remove_auto_data_tag(&self, addr: u64, tag: &Tag) {
        unsafe { BNRemoveAutoDataTag(self.as_ref().handle, addr, tag.handle) }
    }

    /// removes a Tag object at a data address.
    /// Since this removes a user tag, it will be added to the current undo buffer.
    fn remove_user_data_tag(&self, addr: u64, tag: &Tag) {
        unsafe { BNRemoveUserDataTag(self.as_ref().handle, addr, tag.handle) }
    }

    /// Retrieves a list of comment addresses, the comments themselves can then be queried with
    /// the function [`BinaryViewExt::comment_at`].
    ///
    /// If you would rather retrieve the contents of **all** comments at once you can do so with
    /// the helper function [`BinaryViewExt::comments`].
    fn comment_references(&self) -> Array<CommentReference> {
        let mut count = 0;
        let addresses_raw =
            unsafe { BNGetGlobalCommentedAddresses(self.as_ref().handle, &mut count) };
        unsafe { Array::new(addresses_raw, count, ()) }
    }

    /// Retrieves a map of comment addresses to their contents.
    ///
    /// This is a helper function that eagerly reads the contents of all comments within the
    /// view, use [`BinaryViewExt::comment_references`] instead if you do not wish to read all the comments.
    fn comments(&self) -> BTreeMap<u64, String> {
        self.comment_references()
            .iter()
            .filter_map(|cmt_ref| Some((cmt_ref.start, self.comment_at(cmt_ref.start)?)))
            .collect()
    }

    fn comment_at(&self, addr: u64) -> Option<String> {
        unsafe {
            let comment_raw = BNGetGlobalCommentForAddress(self.as_ref().handle, addr);
            match comment_raw.is_null() {
                false => Some(BnString::into_string(comment_raw)),
                true => None,
            }
        }
    }

    /// Sets a comment for the [`BinaryView`] at the address specified.
    ///
    /// NOTE: This is different from setting a comment at the function-level. To set a comment in a
    /// function use [`Function::set_comment_at`]
    fn set_comment_at(&self, addr: u64, comment: &str) {
        let comment_raw = comment.to_cstr();
        unsafe { BNSetGlobalCommentForAddress(self.as_ref().handle, addr, comment_raw.as_ptr()) }
    }

    /// Retrieves a list of the next disassembly lines.
    ///
    /// Retrieves an [`Array`] over [`LinearDisassemblyLine`] objects for the
    /// next disassembly lines, and updates the [`LinearViewCursor`] passed in. This function can be called
    /// repeatedly to get more lines of linear disassembly.
    ///
    /// # Arguments
    /// * `pos` - Position to retrieve linear disassembly lines from
    fn get_next_linear_disassembly_lines(
        &self,
        pos: &mut LinearViewCursor,
    ) -> Array<LinearDisassemblyLine> {
        let mut result = unsafe { Array::new(std::ptr::null_mut(), 0, ()) };

        while result.is_empty() {
            result = pos.lines();
            if !pos.next() {
                return result;
            }
        }

        result
    }

    /// Retrieves a list of the previous disassembly lines.
    ///
    /// `get_previous_linear_disassembly_lines` retrieves an [Array] over [LinearDisassemblyLine] objects for the
    /// previous disassembly lines, and updates the [LinearViewCursor] passed in. This function can be called
    /// repeatedly to get more lines of linear disassembly.
    ///
    /// # Arguments
    /// * `pos` - Position to retrieve linear disassembly lines relative to
    fn get_previous_linear_disassembly_lines(
        &self,
        pos: &mut LinearViewCursor,
    ) -> Array<LinearDisassemblyLine> {
        let mut result = unsafe { Array::new(std::ptr::null_mut(), 0, ()) };
        while result.is_empty() {
            if !pos.previous() {
                return result;
            }

            result = pos.lines();
        }

        result
    }

    fn query_metadata(&self, key: &str) -> Option<Ref<Metadata>> {
        let key = key.to_cstr();
        let value: *mut BNMetadata =
            unsafe { BNBinaryViewQueryMetadata(self.as_ref().handle, key.as_ptr()) };
        if value.is_null() {
            None
        } else {
            Some(unsafe { Metadata::ref_from_raw(value) })
        }
    }

    /// Retrieve the metadata as the type `T`.
    ///
    /// Fails if the metadata does not exist, or if the metadata failed to coerce to type `T`.
    fn get_metadata<T>(&self, key: &str) -> Option<Result<T>>
    where
        T: for<'a> TryFrom<&'a Metadata>,
    {
        self.query_metadata(key)
            .map(|md| T::try_from(md.as_ref()).map_err(|_| ()))
    }

    fn store_metadata<V>(&self, key: &str, value: V, is_auto: bool)
    where
        V: Into<Ref<Metadata>>,
    {
        let md = value.into();
        let key = key.to_cstr();
        unsafe {
            BNBinaryViewStoreMetadata(
                self.as_ref().handle,
                key.as_ptr(),
                md.as_ref().handle,
                is_auto,
            )
        };
    }

    fn remove_metadata(&self, key: &str) {
        let key = key.to_cstr();
        unsafe { BNBinaryViewRemoveMetadata(self.as_ref().handle, key.as_ptr()) };
    }

    /// Retrieves a list of [CodeReference]s pointing to a given address.
    fn code_refs_to_addr(&self, addr: u64) -> Array<CodeReference> {
        unsafe {
            let mut count = 0;
            let handle = BNGetCodeReferences(self.as_ref().handle, addr, &mut count, false, 0);
            Array::new(handle, count, ())
        }
    }

    /// Retrieves a list of [CodeReference]s pointing into a given [Range].
    fn code_refs_into_range(&self, range: Range<u64>) -> Array<CodeReference> {
        unsafe {
            let mut count = 0;
            let handle = BNGetCodeReferencesInRange(
                self.as_ref().handle,
                range.start,
                range.end - range.start,
                &mut count,
                false,
                0,
            );
            Array::new(handle, count, ())
        }
    }

    /// Retrieves a list of addresses pointed to by a given address.
    fn code_refs_from_addr(&self, addr: u64, func: Option<&Function>) -> Vec<u64> {
        unsafe {
            let mut count = 0;
            let code_ref =
                CodeReference::new(addr, func.map(|f| f.to_owned()), func.map(|f| f.arch()));
            let mut raw_code_ref = CodeReference::into_owned_raw(&code_ref);
            let addresses =
                BNGetCodeReferencesFrom(self.as_ref().handle, &mut raw_code_ref, &mut count);
            let res = std::slice::from_raw_parts(addresses, count).to_vec();
            BNFreeAddressList(addresses);
            res
        }
    }

    /// Retrieves a list of [DataReference]s pointing to a given address.
    fn data_refs_to_addr(&self, addr: u64) -> Array<DataReference> {
        unsafe {
            let mut count = 0;
            let handle = BNGetDataReferences(self.as_ref().handle, addr, &mut count, false, 0);
            Array::new(handle, count, ())
        }
    }

    /// Retrieves a list of [DataReference]s pointing into a given [Range].
    fn data_refs_into_range(&self, range: Range<u64>) -> Array<DataReference> {
        unsafe {
            let mut count = 0;
            let handle = BNGetDataReferencesInRange(
                self.as_ref().handle,
                range.start,
                range.end - range.start,
                &mut count,
                false,
                0,
            );
            Array::new(handle, count, ())
        }
    }

    /// Retrieves a list of [DataReference]s originating from a given address.
    fn data_refs_from_addr(&self, addr: u64) -> Array<DataReference> {
        unsafe {
            let mut count = 0;
            let handle = BNGetDataReferencesFrom(self.as_ref().handle, addr, &mut count);
            Array::new(handle, count, ())
        }
    }

    /// Retrieves a list of [CodeReference]s for locations in code that use a given named type.
    fn code_refs_using_type_name<T: Into<QualifiedName>>(&self, name: T) -> Array<CodeReference> {
        let mut raw_name = QualifiedName::into_raw(name.into());
        unsafe {
            let mut count = 0;
            let handle = BNGetCodeReferencesForType(
                self.as_ref().handle,
                &mut raw_name,
                &mut count,
                false,
                0,
            );
            QualifiedName::free_raw(raw_name);
            Array::new(handle, count, ())
        }
    }

    /// Retrieves a list of [DataReference]s for locations in data that use a given named type.
    fn data_refs_using_type_name<T: Into<QualifiedName>>(&self, name: T) -> Array<DataReference> {
        let mut raw_name = QualifiedName::into_raw(name.into());
        unsafe {
            let mut count = 0;
            let handle = BNGetDataReferencesForType(
                self.as_ref().handle,
                &mut raw_name,
                &mut count,
                false,
                0,
            );
            QualifiedName::free_raw(raw_name);
            Array::new(handle, count, ())
        }
    }

    fn relocations_at(&self, addr: u64) -> Array<Relocation> {
        unsafe {
            let mut count = 0;
            let handle = BNGetRelocationsAt(self.as_ref().handle, addr, &mut count);
            Array::new(handle, count, ())
        }
    }

    fn relocation_ranges(&self) -> Vec<Range<u64>> {
        let ranges = unsafe {
            let mut count = 0;
            let reloc_ranges_ptr = BNGetRelocationRanges(self.as_ref().handle, &mut count);
            let ranges = std::slice::from_raw_parts(reloc_ranges_ptr, count).to_vec();
            BNFreeRelocationRanges(reloc_ranges_ptr);
            ranges
        };

        // TODO: impl From BNRange for Range?
        ranges
            .iter()
            .map(|range| Range {
                start: range.start,
                end: range.end,
            })
            .collect()
    }

    fn component_by_guid(&self, guid: &str) -> Option<Ref<Component>> {
        let name = guid.to_cstr();
        let result = unsafe { BNGetComponentByGuid(self.as_ref().handle, name.as_ptr()) };
        NonNull::new(result).map(|h| unsafe { Component::ref_from_raw(h) })
    }

    fn root_component(&self) -> Option<Ref<Component>> {
        let result = unsafe { BNGetRootComponent(self.as_ref().handle) };
        NonNull::new(result).map(|h| unsafe { Component::ref_from_raw(h) })
    }

    fn component_by_path(&self, path: &str) -> Option<Ref<Component>> {
        let path = path.to_cstr();
        let result = unsafe { BNGetComponentByPath(self.as_ref().handle, path.as_ptr()) };
        NonNull::new(result).map(|h| unsafe { Component::ref_from_raw(h) })
    }

    fn remove_component(&self, component: &Component) -> bool {
        unsafe { BNRemoveComponent(self.as_ref().handle, component.handle.as_ptr()) }
    }

    fn remove_component_by_guid(&self, guid: &str) -> bool {
        let path = guid.to_cstr();
        unsafe { BNRemoveComponentByGuid(self.as_ref().handle, path.as_ptr()) }
    }

    fn data_variable_parent_components(&self, data_variable: &DataVariable) -> Array<Component> {
        let mut count = 0;
        let result = unsafe {
            BNGetDataVariableParentComponents(
                self.as_ref().handle,
                data_variable.address,
                &mut count,
            )
        };
        unsafe { Array::new(result, count, ()) }
    }

    fn external_libraries(&self) -> Array<ExternalLibrary> {
        let mut count = 0;
        let result = unsafe { BNBinaryViewGetExternalLibraries(self.as_ref().handle, &mut count) };
        unsafe { Array::new(result, count, ()) }
    }

    fn external_library(&self, name: &str) -> Option<Ref<ExternalLibrary>> {
        let name_ptr = name.to_cstr();
        let result =
            unsafe { BNBinaryViewGetExternalLibrary(self.as_ref().handle, name_ptr.as_ptr()) };
        let result_ptr = NonNull::new(result)?;
        Some(unsafe { ExternalLibrary::ref_from_raw(result_ptr) })
    }

    fn remove_external_library(&self, name: &str) {
        let name_ptr = name.to_cstr();
        unsafe { BNBinaryViewRemoveExternalLibrary(self.as_ref().handle, name_ptr.as_ptr()) };
    }

    fn add_external_library(
        &self,
        name: &str,
        backing_file: Option<&ProjectFile>,
        auto: bool,
    ) -> Option<Ref<ExternalLibrary>> {
        let name_ptr = name.to_cstr();
        let result = unsafe {
            BNBinaryViewAddExternalLibrary(
                self.as_ref().handle,
                name_ptr.as_ptr(),
                backing_file
                    .map(|b| b.handle.as_ptr())
                    .unwrap_or(std::ptr::null_mut()),
                auto,
            )
        };
        NonNull::new(result).map(|h| unsafe { ExternalLibrary::ref_from_raw(h) })
    }

    fn external_locations(&self) -> Array<ExternalLocation> {
        let mut count = 0;
        let result = unsafe { BNBinaryViewGetExternalLocations(self.as_ref().handle, &mut count) };
        unsafe { Array::new(result, count, ()) }
    }

    fn external_location_from_symbol(&self, symbol: &Symbol) -> Option<Ref<ExternalLocation>> {
        let result =
            unsafe { BNBinaryViewGetExternalLocation(self.as_ref().handle, symbol.handle) };
        let result_ptr = NonNull::new(result)?;
        Some(unsafe { ExternalLocation::ref_from_raw(result_ptr) })
    }

    fn remove_external_location(&self, location: &ExternalLocation) {
        self.remove_external_location_from_symbol(&location.source_symbol())
    }

    fn remove_external_location_from_symbol(&self, symbol: &Symbol) {
        unsafe { BNBinaryViewRemoveExternalLocation(self.as_ref().handle, symbol.handle) };
    }

    // TODO: This is awful, rewrite this.
    fn add_external_location(
        &self,
        symbol: &Symbol,
        library: &ExternalLibrary,
        target_symbol_name: &str,
        target_address: Option<u64>,
        target_is_auto: bool,
    ) -> Option<Ref<ExternalLocation>> {
        let target_symbol_name = target_symbol_name.to_cstr();
        let target_address_ptr = target_address
            .map(|a| a as *mut u64)
            .unwrap_or(std::ptr::null_mut());
        let result = unsafe {
            BNBinaryViewAddExternalLocation(
                self.as_ref().handle,
                symbol.handle,
                library.handle.as_ptr(),
                target_symbol_name.as_ptr(),
                target_address_ptr,
                target_is_auto,
            )
        };
        NonNull::new(result).map(|h| unsafe { ExternalLocation::ref_from_raw(h) })
    }

    /// Type container for all types (user and auto) in the Binary View.
    ///
    /// NOTE: Modifying an auto type will promote it to a user type.
    fn type_container(&self) -> TypeContainer {
        let type_container_ptr =
            NonNull::new(unsafe { BNGetAnalysisTypeContainer(self.as_ref().handle) });
        // NOTE: I have no idea how this isn't a UAF, see the note in `TypeContainer::from_raw`
        unsafe { TypeContainer::from_raw(type_container_ptr.unwrap()) }
    }

    /// Type container for user types in the Binary View.
    fn user_type_container(&self) -> TypeContainer {
        let type_container_ptr =
            NonNull::new(unsafe { BNGetAnalysisUserTypeContainer(self.as_ref().handle) });
        // NOTE: I have no idea how this isn't a UAF, see the note in `TypeContainer::from_raw`
        unsafe { TypeContainer::from_raw(type_container_ptr.unwrap()) }.clone()
    }

    /// Type container for auto types in the Binary View.
    ///
    /// NOTE: Unlike [`Self::type_container`] modification of auto types will **NOT** promote it to a user type.
    fn auto_type_container(&self) -> TypeContainer {
        let type_container_ptr =
            NonNull::new(unsafe { BNGetAnalysisAutoTypeContainer(self.as_ref().handle) });
        // NOTE: I have no idea how this isn't a UAF, see the note in `TypeContainer::from_raw`
        unsafe { TypeContainer::from_raw(type_container_ptr.unwrap()) }
    }

    fn type_libraries(&self) -> Array<TypeLibrary> {
        let mut count = 0;
        let result = unsafe { BNGetBinaryViewTypeLibraries(self.as_ref().handle, &mut count) };
        unsafe { Array::new(result, count, ()) }
    }

    /// Make the contents of a type library available for type/import resolution
    fn add_type_library(&self, library: &TypeLibrary) {
        unsafe { BNAddBinaryViewTypeLibrary(self.as_ref().handle, library.as_raw()) }
    }

    fn type_library_by_name(&self, name: &str) -> Option<Ref<TypeLibrary>> {
        let name = name.to_cstr();
        let result = unsafe { BNGetBinaryViewTypeLibrary(self.as_ref().handle, name.as_ptr()) };
        NonNull::new(result).map(|h| unsafe { TypeLibrary::ref_from_raw(h) })
    }

    /// Should be called by custom [`BinaryView`] implementations when they have successfully
    /// imported an object from a type library (eg a symbol's type). Values recorded with this
    /// function will then be queryable via [`BinaryViewExt::lookup_imported_object_library`].
    ///
    /// * `lib` - Type Library containing the imported type
    /// * `name` - Name of the object in the type library
    /// * `addr` - address of symbol at import site
    /// * `platform` - Platform of symbol at import site
    fn record_imported_object_library<T: Into<QualifiedName>>(
        &self,
        lib: &TypeLibrary,
        name: T,
        addr: u64,
        platform: &Platform,
    ) {
        let mut raw_name = QualifiedName::into_raw(name.into());
        unsafe {
            BNBinaryViewRecordImportedObjectLibrary(
                self.as_ref().handle,
                platform.handle,
                addr,
                lib.as_raw(),
                &mut raw_name,
            )
        }
        QualifiedName::free_raw(raw_name);
    }

    /// Recursively imports a type from the specified type library, or, if no library was
    /// explicitly provided, the first type library associated with the current [`BinaryView`] that
    /// provides the name requested.
    ///
    /// This may have the impact of loading other type libraries as dependencies on other type
    /// libraries are lazily resolved when references to types provided by them are first encountered.
    ///
    /// Note that the name actually inserted into the view may not match the name as it exists in
    /// the type library in the event of a name conflict. To aid in this, the [`Type`] object
    /// returned is a `NamedTypeReference` to the deconflicted name used.
    fn import_type_library_type<T: Into<QualifiedName>>(
        &self,
        name: T,
        lib: Option<&TypeLibrary>,
    ) -> Option<Ref<Type>> {
        let mut lib_ref = lib
            .as_ref()
            .map(|l| unsafe { l.as_raw() } as *mut _)
            .unwrap_or(std::ptr::null_mut());
        let mut raw_name = QualifiedName::into_raw(name.into());
        let result = unsafe {
            BNBinaryViewImportTypeLibraryType(self.as_ref().handle, &mut lib_ref, &mut raw_name)
        };
        QualifiedName::free_raw(raw_name);
        (!result.is_null()).then(|| unsafe { Type::ref_from_raw(result) })
    }

    /// Recursively imports an object (function) from the specified type library, or, if no library was
    /// explicitly provided, the first type library associated with the current [`BinaryView`] that
    /// provides the name requested.
    ///
    /// This may have the impact of loading other type libraries as dependencies on other type
    /// libraries are lazily resolved when references to types provided by them are first encountered.
    ///
    /// NOTE: If you are implementing a custom [`BinaryView`] and use this method to import object types,
    /// you should then call [BinaryViewExt::record_imported_object_library] with the details of
    /// where the object is located.
    fn import_type_library_object<T: Into<QualifiedName>>(
        &self,
        name: T,
        lib: Option<&TypeLibrary>,
    ) -> Option<Ref<Type>> {
        let mut lib_ref = lib
            .as_ref()
            .map(|l| unsafe { l.as_raw() } as *mut _)
            .unwrap_or(std::ptr::null_mut());
        let mut raw_name = QualifiedName::into_raw(name.into());
        let result = unsafe {
            BNBinaryViewImportTypeLibraryObject(self.as_ref().handle, &mut lib_ref, &mut raw_name)
        };
        QualifiedName::free_raw(raw_name);
        (!result.is_null()).then(|| unsafe { Type::ref_from_raw(result) })
    }

    /// Recursively imports a [`Type`] given its GUID from available type libraries.
    fn import_type_by_guid(&self, guid: &str) -> Option<Ref<Type>> {
        let guid = guid.to_cstr();
        let result =
            unsafe { BNBinaryViewImportTypeLibraryTypeByGuid(self.as_ref().handle, guid.as_ptr()) };
        (!result.is_null()).then(|| unsafe { Type::ref_from_raw(result) })
    }

    /// Recursively exports `type_obj` into `lib` as a type with name `name`.
    ///
    /// As other referenced types are encountered, they are either copied into the destination type library or
    /// else the type library that provided the referenced type is added as a dependency for the destination library.
    fn export_type_to_library<T: Into<QualifiedName>>(
        &self,
        lib: &TypeLibrary,
        name: T,
        type_obj: &Type,
    ) {
        let mut raw_name = QualifiedName::into_raw(name.into());
        unsafe {
            BNBinaryViewExportTypeToTypeLibrary(
                self.as_ref().handle,
                lib.as_raw(),
                &mut raw_name,
                type_obj.handle,
            )
        }
        QualifiedName::free_raw(raw_name);
    }

    /// Recursively exports `type_obj` into `lib` as a type with name `name`.
    ///
    /// As other referenced types are encountered, they are either copied into the destination type library or
    /// else the type library that provided the referenced type is added as a dependency for the destination library.
    fn export_object_to_library<T: Into<QualifiedName>>(
        &self,
        lib: &TypeLibrary,
        name: T,
        type_obj: &Type,
    ) {
        let mut raw_name = QualifiedName::into_raw(name.into());
        unsafe {
            BNBinaryViewExportObjectToTypeLibrary(
                self.as_ref().handle,
                lib.as_raw(),
                &mut raw_name,
                type_obj.handle,
            )
        }
        QualifiedName::free_raw(raw_name);
    }

    /// Gives you details of which type library and name was used to determine
    /// the type of a symbol at a given address
    ///
    /// * `addr` - address of symbol at import site
    /// * `platform` - Platform of symbol at import site
    fn lookup_imported_object_library(
        &self,
        addr: u64,
        platform: &Platform,
    ) -> Option<(Ref<TypeLibrary>, QualifiedName)> {
        let mut result_lib = std::ptr::null_mut();
        let mut result_name = BNQualifiedName::default();
        let success = unsafe {
            BNBinaryViewLookupImportedObjectLibrary(
                self.as_ref().handle,
                platform.handle,
                addr,
                &mut result_lib,
                &mut result_name,
            )
        };
        if !success {
            return None;
        }
        let lib = unsafe { TypeLibrary::ref_from_raw(NonNull::new(result_lib)?) };
        let name = QualifiedName::from_owned_raw(result_name);
        Some((lib, name))
    }

    /// Gives you details of from which type library and name a given type in the analysis was imported.
    ///
    /// * `name` - Name of type in analysis
    fn lookup_imported_type_library<T: Into<QualifiedName>>(
        &self,
        name: T,
    ) -> Option<(Ref<TypeLibrary>, QualifiedName)> {
        let raw_name = QualifiedName::into_raw(name.into());
        let mut result_lib = std::ptr::null_mut();
        let mut result_name = BNQualifiedName::default();
        let success = unsafe {
            BNBinaryViewLookupImportedTypeLibrary(
                self.as_ref().handle,
                &raw_name,
                &mut result_lib,
                &mut result_name,
            )
        };
        QualifiedName::free_raw(raw_name);
        if !success {
            return None;
        }
        let lib = unsafe { TypeLibrary::ref_from_raw(NonNull::new(result_lib)?) };
        let name = QualifiedName::from_owned_raw(result_name);
        Some((lib, name))
    }

    /// Retrieve all known strings in the binary.
    ///
    /// NOTE: This returns a list of [`StringReference`] as strings may not be representable
    /// as a [`String`] or even a [`BnString`]. It is the caller's responsibility to read the underlying
    /// data and convert it to a representable form.
    ///
    /// Some helpers for reading strings are available:
    ///
    /// - [`BinaryViewExt::read_c_string_at`]
    /// - [`BinaryViewExt::read_utf8_string_at`]
    ///
    /// NOTE: This returns discovered strings and is therefore governed by `analysis.limits.minStringLength`
    /// and other settings.
    fn strings(&self) -> Array<StringReference> {
        unsafe {
            let mut count = 0;
            let strings = BNGetStrings(self.as_ref().handle, &mut count);
            Array::new(strings, count, ())
        }
    }

    /// Retrieve the string that falls on a given virtual address.
    ///
    /// NOTE: This returns a [`StringReference`] and since strings may not be representable as a Rust
    /// [`String`] or even a [`BnString`]. It is the caller's responsibility to read the underlying
    /// data and convert it to a representable form.
    ///
    /// Some helpers for reading strings are available:
    ///
    /// - [`BinaryViewExt::read_c_string_at`]
    /// - [`BinaryViewExt::read_utf8_string_at`]
    ///
    /// NOTE: This returns discovered strings and is therefore governed by `analysis.limits.minStringLength`
    /// and other settings.
    fn string_at(&self, addr: u64) -> Option<StringReference> {
        let mut str_ref = BNStringReference::default();
        let success = unsafe { BNGetStringAtAddress(self.as_ref().handle, addr, &mut str_ref) };
        if success {
            Some(str_ref.into())
        } else {
            None
        }
    }

    /// Retrieve all known strings within the provided `range`.
    ///
    /// NOTE: This returns a list of [`StringReference`] as strings may not be representable
    /// as a [`String`] or even a [`BnString`]. It is the caller's responsibility to read the underlying
    /// data and convert it to a representable form.
    ///
    /// Some helpers for reading strings are available:
    ///
    /// - [`BinaryViewExt::read_c_string_at`]
    /// - [`BinaryViewExt::read_utf8_string_at`]
    ///
    /// NOTE: This returns discovered strings and is therefore governed by `analysis.limits.minStringLength`
    /// and other settings.
    fn strings_in_range(&self, range: Range<u64>) -> Array<StringReference> {
        unsafe {
            let mut count = 0;
            let strings = BNGetStringsInRange(
                self.as_ref().handle,
                range.start,
                range.end - range.start,
                &mut count,
            );
            Array::new(strings, count, ())
        }
    }

    /// Retrieve the attached type archives as their [`TypeArchiveId`].
    ///
    /// Using the returned id you can retrieve the [`TypeArchive`] with [`BinaryViewExt::type_archive_by_id`].
    fn attached_type_archives(&self) -> Vec<TypeArchiveId> {
        let mut ids: *mut *mut c_char = std::ptr::null_mut();
        let mut paths: *mut *mut c_char = std::ptr::null_mut();
        let count =
            unsafe { BNBinaryViewGetTypeArchives(self.as_ref().handle, &mut ids, &mut paths) };
        // We discard the path here, you can retrieve it later with [`BinaryViewExt::type_archive_path_by_id`],
        // this is so we can simplify the return type which will commonly just want to query through to the type
        // archive itself.
        let _path_list = unsafe { Array::<BnString>::new(paths, count, ()) };
        let id_list = unsafe { Array::<BnString>::new(ids, count, ()) };
        id_list
            .into_iter()
            .map(|id| TypeArchiveId(id.to_string()))
            .collect()
    }

    /// Look up a connected [`TypeArchive`] by its `id`.
    ///
    /// NOTE: A [`TypeArchive`] can be attached but not connected, returning `None`.
    fn type_archive_by_id(&self, id: &TypeArchiveId) -> Option<Ref<TypeArchive>> {
        let id = id.0.as_str().to_cstr();
        let result = unsafe { BNBinaryViewGetTypeArchive(self.as_ref().handle, id.as_ptr()) };
        let result_ptr = NonNull::new(result)?;
        Some(unsafe { TypeArchive::ref_from_raw(result_ptr) })
    }

    /// Look up the path for an attached (but not necessarily connected) [`TypeArchive`] by its `id`.
    fn type_archive_path_by_id(&self, id: &TypeArchiveId) -> Option<PathBuf> {
        let id = id.0.as_str().to_cstr();
        let result = unsafe { BNBinaryViewGetTypeArchivePath(self.as_ref().handle, id.as_ptr()) };
        if result.is_null() {
            return None;
        }
        let path_str = unsafe { BnString::into_string(result) };
        Some(PathBuf::from(path_str))
    }
}

impl<T: BinaryViewBase> BinaryViewExt for T {}

/// Represents the "whole view" of the binary and its analysis.
///
/// Analysis information:
///
/// - [`BinaryViewExt::functions`]
/// - [`BinaryViewExt::data_variables`]
/// - [`BinaryViewExt::strings`]
///
/// Annotation information:
///
/// - [`BinaryViewExt::symbols`]
/// - [`BinaryViewExt::tags_all_scopes`]
/// - [`BinaryViewExt::comments`]
///
/// Data representation and binary information:
///
/// - [`BinaryViewExt::types`]
/// - [`BinaryViewExt::segments`]
/// - [`BinaryViewExt::sections`]
///
/// # Cleaning up
///
/// [`BinaryView`] has a cyclic relationship with the associated [`FileMetadata`], each holds a strong
/// reference to one another, so to properly clean up/free the [`BinaryView`], you must manually close the
/// file using [`FileMetadata::close`], this is not fixable in the general case, until [`FileMetadata`]
/// has only a weak reference to the [`BinaryView`].
#[derive(PartialEq, Eq, Hash)]
pub struct BinaryView {
    pub handle: *mut BNBinaryView,
}

impl BinaryView {
    pub unsafe fn from_raw(handle: *mut BNBinaryView) -> Self {
        debug_assert!(!handle.is_null());
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: *mut BNBinaryView) -> Ref<Self> {
        debug_assert!(!handle.is_null());
        Ref::new(Self { handle })
    }

    /// Construct the raw binary view from the given metadata.
    ///
    /// Before calling this, make sure you have a valid file path set for the [`FileMetadata`]. It is
    /// required that the [`FileMetadata::file_path`] exist in the local filesystem.
    pub fn from_metadata(meta: &FileMetadata) -> Result<Ref<Self>> {
        if !meta.file_path().exists() {
            return Err(());
        }
        let file = meta.file_path().to_cstr();
        let handle =
            unsafe { BNCreateBinaryDataViewFromFilename(meta.handle, file.as_ptr() as *mut _) };
        if handle.is_null() {
            return Err(());
        }
        unsafe { Ok(Ref::new(Self { handle })) }
    }

    /// Construct the raw binary view from the given `file_path` and metadata.
    ///
    /// This will implicitly set the metadata file path and then construct the view. If the metadata
    /// already has the desired file path, use [`BinaryView::from_metadata`] instead.
    pub fn from_path(meta: &FileMetadata, file_path: impl AsRef<Path>) -> Result<Ref<Self>> {
        meta.set_file_path(file_path.as_ref());
        Self::from_metadata(meta)
    }

    // TODO: Provide an API that manages the lifetime of the accessor and the view.
    /// Construct the raw binary view from the given `accessor` and metadata.
    ///
    /// It is the responsibility of the caller to keep the accessor alive for the lifetime of the view;
    /// because of this, we mark the function as unsafe.
    pub unsafe fn from_accessor<A: Accessor>(
        meta: &FileMetadata,
        accessor: &mut FileAccessor<A>,
    ) -> Result<Ref<Self>> {
        let handle = unsafe { BNCreateBinaryDataViewFromFile(meta.handle, &mut accessor.raw) };
        if handle.is_null() {
            return Err(());
        }
        unsafe { Ok(Ref::new(Self { handle })) }
    }

    /// Construct the raw binary view from the given `data` and metadata.
    ///
    /// The data will be copied into the view, so the caller does not need to keep the data alive.
    pub fn from_data(meta: &FileMetadata, data: &[u8]) -> Ref<Self> {
        let handle = unsafe {
            BNCreateBinaryDataViewFromData(meta.handle, data.as_ptr() as *mut _, data.len())
        };
        assert!(
            !handle.is_null(),
            "BNCreateBinaryDataViewFromData should always succeed"
        );
        unsafe { Ref::new(Self { handle }) }
    }

    /// Save the original binary file to the provided `file_path` along with any modifications.
    ///
    /// WARNING: Currently there is a possibility to deadlock if the analysis has queued up a main thread action
    /// that tries to take the [`FileMetadata`] lock of the current view, and is executed while we
    /// are executing in this function.
    ///
    /// To avoid the above issue use [`crate::main_thread::execute_on_main_thread_and_wait`] to verify there
    /// are no queued up main thread actions.
    pub fn save_to_path(&self, file_path: impl AsRef<Path>) -> bool {
        let file = file_path.as_ref().to_cstr();
        unsafe { BNSaveToFilename(self.handle, file.as_ptr() as *mut _) }
    }

    /// Save the original binary file to the provided [`FileAccessor`] along with any modifications.
    ///
    /// WARNING: Currently there is a possibility to deadlock if the analysis has queued up a main thread action
    /// that tries to take the [`FileMetadata`] lock of the current view, and is executed while we
    /// are executing in this function.
    ///
    /// To avoid the above issue use [`crate::main_thread::execute_on_main_thread_and_wait`] to verify there
    /// are no queued up main thread actions.
    pub fn save_to_accessor<A: Accessor>(&self, file: &mut FileAccessor<A>) -> bool {
        unsafe { BNSaveToFile(self.handle, &mut file.raw) }
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

    fn modification_status(&self, offset: u64) -> ModificationStatus {
        unsafe { BNGetModification(self.handle, offset) }
    }

    fn start(&self) -> u64 {
        unsafe { BNGetStartOffset(self.handle) }
    }

    fn len(&self) -> u64 {
        unsafe { BNGetViewLength(self.handle) }
    }

    fn executable(&self) -> bool {
        unsafe { BNIsExecutableView(self.handle) }
    }

    fn relocatable(&self) -> bool {
        unsafe { BNIsRelocatable(self.handle) }
    }

    fn entry_point(&self) -> u64 {
        unsafe { BNGetEntryPoint(self.handle) }
    }

    fn default_endianness(&self) -> Endianness {
        unsafe { BNGetDefaultEndianness(self.handle) }
    }

    fn address_size(&self) -> usize {
        unsafe { BNGetViewAddressSize(self.handle) }
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

impl std::fmt::Debug for BinaryView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BinaryView")
            .field("view_type", &self.view_type())
            .field("file", &self.file())
            .field("original_image_base", &self.original_image_base())
            .field("start", &self.start())
            .field("end", &self.end())
            .field("len", &self.len())
            .field("default_platform", &self.default_platform())
            .field("default_arch", &self.default_arch())
            .field("default_endianness", &self.default_endianness())
            .field("entry_point", &self.entry_point())
            .field(
                "entry_point_functions",
                &self.entry_point_functions().to_vec(),
            )
            .field("address_size", &self.address_size())
            .field("sections", &self.sections().to_vec())
            .field("segments", &self.segments().to_vec())
            .finish()
    }
}

pub trait BinaryViewEventHandler: 'static + Sync {
    fn on_event(&self, binary_view: &BinaryView);
}

impl<F: Fn(&BinaryView) + 'static + Sync> BinaryViewEventHandler for F {
    fn on_event(&self, binary_view: &BinaryView) {
        self(binary_view);
    }
}

/// Registers an event listener for binary view events.
///
/// # Example
///
/// ```no_run
/// use binaryninja::binary_view::{
///     register_binary_view_event, BinaryView, BinaryViewEventHandler, BinaryViewEventType,
/// };
///
/// struct EventHandlerContext {
///     // Context holding state available to event handler
/// }
///
/// impl BinaryViewEventHandler for EventHandlerContext {
///     fn on_event(&self, binary_view: &BinaryView) {
///         // handle event
///     }
/// }
///
/// #[no_mangle]
/// pub extern "C" fn CorePluginInit() {
///     let context = EventHandlerContext {};
///
///     register_binary_view_event(
///         BinaryViewEventType::BinaryViewInitialAnalysisCompletionEvent,
///         context,
///     );
/// }
/// ```
pub fn register_binary_view_event<Handler>(event_type: BinaryViewEventType, handler: Handler)
where
    Handler: BinaryViewEventHandler,
{
    unsafe extern "C" fn on_event<Handler: BinaryViewEventHandler>(
        ctx: *mut ::std::os::raw::c_void,
        view: *mut BNBinaryView,
    ) {
        ffi_wrap!("EventHandler::on_event", {
            let context = unsafe { &*(ctx as *const Handler) };
            context.on_event(&BinaryView::ref_from_raw(BNNewViewReference(view)));
        })
    }

    let boxed = Box::new(handler);
    let raw = Box::into_raw(boxed);

    unsafe {
        BNRegisterBinaryViewEvent(
            event_type,
            Some(on_event::<Handler>),
            raw as *mut ::std::os::raw::c_void,
        );
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct CommentReference {
    pub start: u64,
}

impl From<u64> for CommentReference {
    fn from(start: u64) -> Self {
        Self { start }
    }
}

impl CoreArrayProvider for CommentReference {
    type Raw = u64;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for CommentReference {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeAddressList(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::from(*raw)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct StringReference {
    pub ty: StringType,
    pub start: u64,
    pub length: usize,
}

impl From<BNStringReference> for StringReference {
    fn from(raw: BNStringReference) -> Self {
        Self {
            ty: raw.type_,
            start: raw.start,
            length: raw.length,
        }
    }
}

impl From<StringReference> for BNStringReference {
    fn from(raw: StringReference) -> Self {
        Self {
            type_: raw.ty,
            start: raw.start,
            length: raw.length,
        }
    }
}

impl CoreArrayProvider for StringReference {
    type Raw = BNStringReference;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for StringReference {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeStringReferenceList(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::from(*raw)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct AddressRange {
    pub start: u64,
    pub end: u64,
}

impl From<BNAddressRange> for AddressRange {
    fn from(raw: BNAddressRange) -> Self {
        Self {
            start: raw.start,
            end: raw.end,
        }
    }
}

impl From<AddressRange> for BNAddressRange {
    fn from(raw: AddressRange) -> Self {
        Self {
            start: raw.start,
            end: raw.end,
        }
    }
}

impl CoreArrayProvider for AddressRange {
    type Raw = BNAddressRange;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for AddressRange {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeAddressRanges(raw);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::from(*raw)
    }
}
