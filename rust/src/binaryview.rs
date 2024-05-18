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

//! A view on binary data and queryable interface of a binary file.
//!
//! One key job of BinaryView is file format parsing which allows Binary Ninja to read, write, insert, remove portions of the file given a virtual address. For the purposes of this documentation we define a virtual address as the memory address that the various pieces of the physical file will be loaded at.
//! TODO : Mirror the Python docs for this

use binaryninjacore_sys::*;

pub use binaryninjacore_sys::BNAnalysisState as AnalysisState;
pub use binaryninjacore_sys::BNModificationStatus as ModificationStatus;

use std::collections::HashMap;
use std::ffi::c_void;
use std::ops::Range;
use std::os::raw::c_char;
use std::ptr;
use std::result;
use std::{ops, slice};

use crate::architecture::Architecture;
use crate::architecture::CoreArchitecture;
use crate::basicblock::BasicBlock;
use crate::databuffer::DataBuffer;
use crate::debuginfo::DebugInfo;
use crate::fileaccessor::FileAccessor;
use crate::filemetadata::FileMetadata;
use crate::flowgraph::FlowGraph;
use crate::function::{Function, NativeBlock};
use crate::linearview::LinearDisassemblyLine;
use crate::linearview::LinearViewCursor;
use crate::metadata::Metadata;
use crate::platform::Platform;
use crate::relocation::Relocation;
use crate::section::{Section, SectionBuilder};
use crate::segment::{Segment, SegmentBuilder};
use crate::settings::Settings;
use crate::symbol::{Symbol, SymbolType};
use crate::tags::{Tag, TagType};
use crate::types::{
    Conf, DataVariable, NamedTypeReference, QualifiedName, QualifiedNameAndType, Type,
};
use crate::Endianness;

use crate::rc::*;
use crate::references::{CodeReference, DataReference};
use crate::string::*;

// TODO : general reorg of modules related to bv

pub type Result<R> = result::Result<R, ()>;

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

#[derive(Debug, Clone)]
pub struct AnalysisProgress {
    pub state: AnalysisState,
    pub count: usize,
    pub total: usize,
}

// TODO: Copied from debuginfo.rs, this should be consolidated
struct ProgressContext(Option<Box<dyn Fn(usize, usize) -> Result<()>>>);

extern "C" fn cb_progress(ctxt: *mut c_void, cur: usize, max: usize) -> bool {
    ffi_wrap!("BinaryViewExt::cb_progress", unsafe {
        let progress = ctxt as *mut ProgressContext;
        match &(*progress).0 {
            Some(func) => (func)(cur, max).is_ok(),
            None => true,
        }
    })
}

pub trait BinaryViewExt: BinaryViewBase {
    fn file(&self) -> Ref<FileMetadata> {
        unsafe {
            let raw = BNGetFileForView(self.as_ref().handle);

            Ref::new(FileMetadata::from_raw(raw))
        }
    }

    fn type_name(&self) -> BnString {
        let ptr: *mut c_char = unsafe { BNGetViewType(self.as_ref().handle) };
        unsafe { BnString::from_raw(ptr) }
    }

    fn parent_view(&self) -> Result<Ref<BinaryView>> {
        let handle = unsafe { BNGetParentView(self.as_ref().handle) };

        if handle.is_null() {
            return Err(());
        }

        unsafe { Ok(BinaryView::from_raw(handle)) }
    }

    fn raw_view(&self) -> Result<Ref<BinaryView>> {
        let raw = "Raw".into_bytes_with_nul();

        let handle =
            unsafe { BNGetFileViewOfType(self.file().as_ref().handle, raw.as_ptr() as *mut _) };

        if handle.is_null() {
            return Err(());
        }

        unsafe { Ok(BinaryView::from_raw(handle)) }
    }

    fn view_type(&self) -> BnString {
        let ptr: *mut c_char = unsafe { BNGetViewType(self.as_ref().handle) };
        unsafe { BnString::from_raw(ptr) }
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

    fn add_analysis_option(&self, name: impl BnStrCompatible) {
        unsafe {
            BNAddAnalysisOption(
                self.as_ref().handle,
                name.into_bytes_with_nul().as_ref().as_ptr() as *mut _,
            )
        }
    }

    fn has_initial_analysis(&self) -> bool {
        unsafe { BNHasInitialAnalysis(self.as_ref().handle) }
    }

    fn set_analysis_hold(&self, enable: bool) {
        unsafe { BNSetAnalysisHold(self.as_ref().handle, enable) }
    }

    fn update_analysis(&self) {
        unsafe {
            BNUpdateAnalysis(self.as_ref().handle);
        }
    }

    fn update_analysis_and_wait(&self) {
        unsafe {
            BNUpdateAnalysisAndWait(self.as_ref().handle);
        }
    }

    fn abort_analysis(&self) {
        unsafe { BNAbortAnalysis(self.as_ref().handle) }
    }

    fn analysis_info(&self) -> Result<AnalysisInfo> {
        let info_ref = unsafe { BNGetAnalysisInfo(self.as_ref().handle) };
        if info_ref.is_null() {
            return Err(());
        }
        let info = unsafe { *info_ref };
        let active_infos = unsafe { slice::from_raw_parts(info.activeInfo, info.count) };

        let mut active_info_list = vec![];
        for active_info in active_infos {
            let func = unsafe { Function::from_raw(BNNewFunctionReference(active_info.func)) };
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
            active_info: vec![],
        };

        unsafe { BNFreeAnalysisInfo(info_ref) };
        Ok(result)
    }

    fn analysis_progress(&self) -> AnalysisProgress {
        let progress = unsafe { BNGetAnalysisProgress(self.as_ref().handle) };
        AnalysisProgress {
            state: progress.state,
            count: progress.count,
            total: progress.total,
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

            Some(Platform::ref_from_raw(raw))
        }
    }

    fn set_default_platform(&self, plat: &Platform) {
        unsafe {
            BNSetDefaultPlatform(self.as_ref().handle, plat.handle);
        }
    }

    fn instruction_len<A: Architecture>(&self, arch: &A, addr: u64) -> Option<usize> {
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

            Ok(Symbol::ref_from_raw(raw_sym))
        }
    }

    fn symbol_by_raw_name<S: BnStrCompatible>(&self, raw_name: S) -> Result<Ref<Symbol>> {
        let raw_name = raw_name.into_bytes_with_nul();

        unsafe {
            let raw_sym = BNGetSymbolByRawName(
                self.as_ref().handle,
                raw_name.as_ref().as_ptr() as *mut _,
                ptr::null_mut(),
            );

            if raw_sym.is_null() {
                return Err(());
            }

            Ok(Symbol::ref_from_raw(raw_sym))
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
        let raw_name = name.into_bytes_with_nul();

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
    ) -> Result<Ref<Symbol>> {
        let raw_type = if let Some(t) = ty.into() {
            t.handle
        } else {
            ptr::null_mut()
        };

        unsafe {
            let raw_sym = BNDefineAutoSymbolAndVariableOrFunction(
                self.as_ref().handle,
                plat.handle,
                sym.handle,
                raw_type,
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

    fn define_auto_data_var<'a, T: Into<Conf<&'a Type>>>(&self, addr: u64, ty: T) {
        unsafe {
            BNDefineDataVariable(self.as_ref().handle, addr, &mut ty.into().into());
        }
    }

    /// You likely would also like to call [`Self::define_user_symbol`] to bind this data variable with a name
    fn define_user_data_var<'a, T: Into<Conf<&'a Type>>>(&self, addr: u64, ty: T) {
        unsafe {
            BNDefineUserDataVariable(self.as_ref().handle, addr, &mut ty.into().into());
        }
    }

    fn undefine_auto_data_var(&self, addr: u64) {
        unsafe {
            BNUndefineDataVariable(self.as_ref().handle, addr);
        }
    }

    fn undefine_user_data_var(&self, addr: u64) {
        unsafe {
            BNUndefineUserDataVariable(self.as_ref().handle, addr);
        }
    }

    fn define_auto_type<S: BnStrCompatible>(
        &self,
        name: S,
        source: S,
        type_obj: &Type,
    ) -> QualifiedName {
        let mut qualified_name = QualifiedName::from(name);
        let source_str = source.into_bytes_with_nul();
        let name_handle = unsafe {
            let id_str = BNGenerateAutoTypeId(
                source_str.as_ref().as_ptr() as *const _,
                &mut qualified_name.0,
            );
            BNDefineAnalysisType(
                self.as_ref().handle,
                id_str,
                &mut qualified_name.0,
                type_obj.handle,
            )
        };
        QualifiedName(name_handle)
    }

    fn define_user_type<S: BnStrCompatible>(&self, name: S, type_obj: &Type) {
        let mut qualified_name = QualifiedName::from(name);
        unsafe {
            BNDefineUserAnalysisType(self.as_ref().handle, &mut qualified_name.0, type_obj.handle)
        }
    }

    fn define_auto_types<S: BnStrCompatible>(
        &self,
        names_sources_and_types: Vec<(S, S, &Type)>,
        progress: Option<Box<dyn Fn(usize, usize) -> Result<()>>>,
    ) -> HashMap<String, QualifiedName> {
        let mut names = vec![];
        let mut ids = vec![];
        let mut types = vec![];
        let mut api_types =
            Vec::<BNQualifiedNameTypeAndId>::with_capacity(names_sources_and_types.len());
        for (name, source, type_obj) in names_sources_and_types.into_iter() {
            names.push(QualifiedName::from(name));
            ids.push(source.into_bytes_with_nul());
            types.push(type_obj);
        }

        for ((name, source), type_obj) in names.iter().zip(ids.iter()).zip(types.iter()) {
            api_types.push(BNQualifiedNameTypeAndId {
                name: name.0,
                id: source.as_ref().as_ptr() as *mut _,
                type_: type_obj.handle,
            });
        }

        let mut progress_raw = ProgressContext(progress);
        let mut result_ids: *mut *mut c_char = ptr::null_mut();
        let mut result_names: *mut BNQualifiedName = ptr::null_mut();
        let result_count = unsafe {
            BNDefineAnalysisTypes(
                self.as_ref().handle,
                api_types.as_mut_ptr(),
                api_types.len(),
                Some(cb_progress),
                &mut progress_raw as *mut _ as *mut c_void,
                &mut result_ids as *mut _,
                &mut result_names as *mut _,
            )
        };

        let mut result = HashMap::with_capacity(result_count);

        let id_array = unsafe { Array::<BnString>::new(result_ids, result_count, ()) };
        let name_array = unsafe { Array::<QualifiedName>::new(result_names, result_count, ()) };

        for (id, name) in id_array.iter().zip(name_array.iter()) {
            result.insert(id.to_owned(), name.clone());
        }

        result
    }

    fn define_user_types<S: BnStrCompatible>(
        &self,
        names_and_types: Vec<(S, &Type)>,
        progress: Option<Box<dyn Fn(usize, usize) -> Result<()>>>,
    ) {
        let mut names = vec![];
        let mut types = vec![];
        let mut api_types = Vec::<BNQualifiedNameAndType>::with_capacity(names_and_types.len());
        for (name, type_obj) in names_and_types.into_iter() {
            names.push(QualifiedName::from(name));
            types.push(type_obj);
        }

        for (name, type_obj) in names.iter().zip(types.iter()) {
            api_types.push(BNQualifiedNameAndType {
                name: name.0,
                type_: type_obj.handle,
            });
        }

        let mut progress_raw = ProgressContext(progress);
        unsafe {
            BNDefineUserAnalysisTypes(
                self.as_ref().handle,
                api_types.as_mut_ptr(),
                api_types.len(),
                Some(cb_progress),
                &mut progress_raw as *mut _ as *mut c_void,
            )
        };
    }

    fn undefine_auto_type<S: BnStrCompatible>(&self, id: S) {
        let id_str = id.into_bytes_with_nul();
        unsafe {
            BNUndefineAnalysisType(self.as_ref().handle, id_str.as_ref().as_ptr() as *const _);
        }
    }

    fn undefine_user_type<S: BnStrCompatible>(&self, name: S) {
        let mut qualified_name = QualifiedName::from(name);
        unsafe { BNUndefineUserAnalysisType(self.as_ref().handle, &mut qualified_name.0) }
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

    fn get_type_by_name<S: BnStrCompatible>(&self, name: S) -> Option<Ref<Type>> {
        unsafe {
            let mut qualified_name = QualifiedName::from(name);
            let type_handle = BNGetAnalysisTypeByName(self.as_ref().handle, &mut qualified_name.0);
            if type_handle.is_null() {
                return None;
            }
            Some(Type::ref_from_raw(type_handle))
        }
    }

    fn get_type_by_ref(&self, ref_: &NamedTypeReference) -> Option<Ref<Type>> {
        unsafe {
            let type_handle = BNGetAnalysisTypeByRef(self.as_ref().handle, ref_.handle);
            if type_handle.is_null() {
                return None;
            }
            Some(Type::ref_from_raw(type_handle))
        }
    }

    fn get_type_by_id<S: BnStrCompatible>(&self, id: S) -> Option<Ref<Type>> {
        unsafe {
            let id_str = id.into_bytes_with_nul();
            let type_handle =
                BNGetAnalysisTypeById(self.as_ref().handle, id_str.as_ref().as_ptr() as *mut _);
            if type_handle.is_null() {
                return None;
            }
            Some(Type::ref_from_raw(type_handle))
        }
    }

    fn get_type_name_by_id<S: BnStrCompatible>(&self, id: S) -> Option<QualifiedName> {
        unsafe {
            let id_str = id.into_bytes_with_nul();
            let name_handle =
                BNGetAnalysisTypeNameById(self.as_ref().handle, id_str.as_ref().as_ptr() as *mut _);
            let name = QualifiedName(name_handle);
            if name.strings().is_empty() {
                return None;
            }
            Some(name)
        }
    }

    fn get_type_id<S: BnStrCompatible>(&self, name: S) -> Option<BnString> {
        unsafe {
            let mut qualified_name = QualifiedName::from(name);
            let id_cstr = BNGetAnalysisTypeId(self.as_ref().handle, &mut qualified_name.0);
            let id = BnString::from_raw(id_cstr);
            if id.is_empty() {
                return None;
            }
            Some(id)
        }
    }

    fn is_type_auto_defined<S: BnStrCompatible>(&self, name: S) -> bool {
        unsafe {
            let mut qualified_name = QualifiedName::from(name);
            BNIsAnalysisTypeAutoDefined(self.as_ref().handle, &mut qualified_name.0)
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
        let name = name.into_bytes_with_nul();
        let name_ptr = name.as_ref().as_ptr() as *mut _;

        unsafe {
            BNRemoveAutoSection(self.as_ref().handle, name_ptr);
        }
    }

    fn remove_user_section<S: BnStrCompatible>(&self, name: S) {
        let name = name.into_bytes_with_nul();
        let name_ptr = name.as_ref().as_ptr() as *mut _;

        unsafe {
            BNRemoveUserSection(self.as_ref().handle, name_ptr);
        }
    }

    fn section_by_name<S: BnStrCompatible>(&self, name: S) -> Result<Section> {
        unsafe {
            let raw_name = name.into_bytes_with_nul();
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

    fn add_auto_function(&self, plat: &Platform, addr: u64) -> Option<Ref<Function>> {
        unsafe {
            let handle = BNAddFunctionForAnalysis(
                self.as_ref().handle,
                plat.handle,
                addr,
                false,
                ptr::null_mut(),
            );

            if handle.is_null() {
                return None;
            }

            Some(Function::from_raw(handle))
        }
    }

    fn add_function_with_type(
        &self,
        plat: &Platform,
        addr: u64,
        auto_discovered: bool,
        func_type: Option<&Type>,
    ) -> Option<Ref<Function>> {
        unsafe {
            let func_type = match func_type {
                Some(func_type) => func_type.handle,
                None => ptr::null_mut(),
            };

            let handle = BNAddFunctionForAnalysis(
                self.as_ref().handle,
                plat.handle,
                addr,
                auto_discovered,
                func_type,
            );

            if handle.is_null() {
                return None;
            }

            Some(Function::from_raw(handle))
        }
    }

    fn add_entry_point(&self, plat: &Platform, addr: u64) {
        unsafe {
            BNAddEntryPointForAnalysis(self.as_ref().handle, plat.handle, addr);
        }
    }

    fn create_user_function(&self, plat: &Platform, addr: u64) -> Result<Ref<Function>> {
        unsafe {
            let func = BNCreateUserFunction(self.as_ref().handle, plat.handle, addr);

            if func.is_null() {
                return Err(());
            }

            Ok(Function::from_raw(func))
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

            Ok(Function::from_raw(func))
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

    // List of functions containing `addr`
    fn functions_containing(&self, addr: u64) -> Array<Function> {
        unsafe {
            let mut count = 0;
            let functions =
                BNGetAnalysisFunctionsContainingAddress(self.as_ref().handle, addr, &mut count);

            Array::new(functions, count, ())
        }
    }

    fn function_at(&self, platform: &Platform, addr: u64) -> Result<Ref<Function>> {
        unsafe {
            let handle = BNGetAnalysisFunction(self.as_ref().handle, platform.handle, addr);

            if handle.is_null() {
                return Err(());
            }

            Ok(Function::from_raw(handle))
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

    fn debug_info(&self) -> Ref<DebugInfo> {
        unsafe { DebugInfo::from_raw(BNGetDebugInfo(self.as_ref().handle)) }
    }

    fn set_debug_info(&self, debug_info: &DebugInfo) {
        unsafe { BNSetDebugInfo(self.as_ref().handle, debug_info.handle) }
    }

    fn apply_debug_info(&self, debug_info: &DebugInfo) {
        unsafe { BNApplyDebugInfo(self.as_ref().handle, debug_info.handle) }
    }

    fn show_graph_report<S: BnStrCompatible>(&self, raw_name: S, graph: &FlowGraph) {
        let raw_name = raw_name.into_bytes_with_nul();
        unsafe {
            BNShowGraphReport(
                self.as_ref().handle,
                raw_name.as_ref().as_ptr() as *mut _,
                graph.handle,
            );
        }
    }

    fn load_settings<S: BnStrCompatible>(&self, view_type_name: S) -> Result<Ref<Settings>> {
        let view_type_name = view_type_name.into_bytes_with_nul();
        let settings_handle = unsafe {
            BNBinaryViewGetLoadSettings(
                self.as_ref().handle,
                view_type_name.as_ref().as_ptr() as *mut _,
            )
        };

        if settings_handle.is_null() {
            Err(())
        } else {
            Ok(unsafe { Settings::from_raw(settings_handle) })
        }
    }

    fn set_load_settings<S: BnStrCompatible>(&self, view_type_name: S, settings: &Settings) {
        let view_type_name = view_type_name.into_bytes_with_nul();

        unsafe {
            BNBinaryViewSetLoadSettings(
                self.as_ref().handle,
                view_type_name.as_ref().as_ptr() as *mut _,
                settings.handle,
            )
        };
    }

    /// Creates a new [TagType] and adds it to the view.
    ///
    /// # Arguments
    /// * `name` - the name for the tag
    /// * `icon` - the icon (recommended 1 emoji or 2 chars) for the tag
    fn create_tag_type<N: BnStrCompatible, I: BnStrCompatible>(
        &self,
        name: N,
        icon: I,
    ) -> Ref<TagType> {
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
    fn get_tag_type<S: BnStrCompatible>(&self, name: S) -> Option<Ref<TagType>> {
        let name = name.into_bytes_with_nul();

        unsafe {
            let handle = BNGetTagType(self.as_ref().handle, name.as_ref().as_ptr() as *mut _);
            if handle.is_null() {
                return None;
            }
            Some(TagType::from_raw(handle))
        }
    }

    /// Get a tag by its id.
    ///
    /// Note this does not tell you anything about where it is used.
    fn get_tag<S: BnStrCompatible>(&self, id: S) -> Option<Ref<Tag>> {
        let id = id.into_bytes_with_nul();
        unsafe {
            let handle = BNGetTag(self.as_ref().handle, id.as_ref().as_ptr() as *mut _);
            if handle.is_null() {
                return None;
            }
            Some(Tag::from_raw(handle))
        }
    }

    /// Creates and adds a tag to an address
    ///
    /// User tag creations will be added to the undo buffer
    fn add_tag<S: BnStrCompatible>(&self, addr: u64, t: &TagType, data: S, user: bool) {
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

    /// Retrieves a list of the next disassembly lines.
    ///
    /// `get_next_linear_disassembly_lines` retrieves an [Array] over [LinearDisassemblyLine] objects for the
    /// next disassembly lines, and updates the [LinearViewCursor] passed in. This function can be called
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

    fn query_metadata<S: BnStrCompatible>(&self, key: S) -> Option<Ref<Metadata>> {
        let value: *mut BNMetadata = unsafe {
            BNBinaryViewQueryMetadata(
                self.as_ref().handle,
                key.into_bytes_with_nul().as_ref().as_ptr() as *const c_char,
            )
        };
        if value.is_null() {
            None
        } else {
            Some(unsafe { Metadata::ref_from_raw(value) })
        }
    }

    fn get_metadata<T, S: BnStrCompatible>(&self, key: S) -> Option<Result<T>>
    where
        T: for<'a> TryFrom<&'a Metadata>,
    {
        self.query_metadata(key)
            .map(|md| T::try_from(md.as_ref()).map_err(|_| ()))
    }

    fn store_metadata<V, S: BnStrCompatible>(&self, key: S, value: V, is_auto: bool)
    where
        V: Into<Ref<Metadata>>,
    {
        let md = value.into();
        unsafe {
            BNBinaryViewStoreMetadata(
                self.as_ref().handle,
                key.into_bytes_with_nul().as_ref().as_ptr() as *const c_char,
                md.as_ref().handle,
                is_auto,
            )
        };
    }

    fn remove_metadata<S: BnStrCompatible>(&self, key: S) {
        unsafe {
            BNBinaryViewRemoveMetadata(
                self.as_ref().handle,
                key.into_bytes_with_nul().as_ref().as_ptr() as *const c_char,
            )
        };
    }

    /// Retrieves a list of [CodeReference]s pointing to a given address.
    fn get_code_refs(&self, addr: u64) -> Array<CodeReference> {
        unsafe {
            let mut count = 0;
            let handle = BNGetCodeReferences(self.as_ref().handle, addr, &mut count);
            Array::new(handle, count, ())
        }
    }

    /// Retrieves a list of [CodeReference]s pointing into a given [Range].
    fn get_code_refs_in_range(&self, range: Range<u64>) -> Array<CodeReference> {
        unsafe {
            let mut count = 0;
            let handle = BNGetCodeReferencesInRange(
                self.as_ref().handle,
                range.start,
                range.end - range.start,
                &mut count,
            );
            Array::new(handle, count, ())
        }
    }

    /// Retrieves a list of [DataReference]s pointing to a given address.
    fn get_data_refs(&self, addr: u64) -> Array<DataReference> {
        unsafe {
            let mut count = 0;
            let handle = BNGetDataReferences(self.as_ref().handle, addr, &mut count);
            Array::new(handle, count, ())
        }
    }

    /// Retrieves a list of [DataReference]s originating from a given address.
    fn get_data_refs_from(&self, addr: u64) -> Array<DataReference> {
        unsafe {
            let mut count = 0;
            let handle = BNGetDataReferencesFrom(self.as_ref().handle, addr, &mut count);
            Array::new(handle, count, ())
        }
    }

    /// Retrieves a list of [DataReference]s pointing into a given [Range].
    fn get_data_refs_in_range(&self, range: Range<u64>) -> Array<DataReference> {
        unsafe {
            let mut count = 0;
            let handle = BNGetDataReferencesInRange(
                self.as_ref().handle,
                range.start,
                range.end - range.start,
                &mut count,
            );
            Array::new(handle, count, ())
        }
    }

    /// Retrieves a list of [CodeReference]s for locations in code that use a given named type.
    ///
    /// TODO: It might be cleaner if this used an already allocated type from the core and
    /// used its name instead of this slightly-gross [QualifiedName] hack. Since the returned
    /// object doesn't have any [QualifiedName], I'm assuming the core does not alias
    /// the [QualifiedName] we pass to it and it is safe to destroy it on [Drop], as in this function.
    fn get_code_refs_for_type<B: BnStrCompatible>(&self, name: B) -> Array<CodeReference> {
        unsafe {
            let mut count = 0;
            let q_name = &mut QualifiedName::from(name).0;
            let handle = BNGetCodeReferencesForType(
                self.as_ref().handle,
                q_name as *mut BNQualifiedName,
                &mut count,
            );
            Array::new(handle, count, ())
        }
    }
    /// Retrieves a list of [DataReference]s instances of a given named type in data.
    ///
    /// TODO: It might be cleaner if this used an already allocated type from the core and
    /// used its name instead of this slightly-gross [QualifiedName] hack. Since the returned
    /// object doesn't have any [QualifiedName], I'm assuming the core does not alias
    /// the [QualifiedName] we pass to it and it is safe to destroy it on [Drop], as in this function.
    fn get_data_refs_for_type<B: BnStrCompatible>(&self, name: B) -> Array<DataReference> {
        unsafe {
            let mut count = 0;
            let q_name = &mut QualifiedName::from(name).0;
            let handle = BNGetDataReferencesForType(
                self.as_ref().handle,
                q_name as *mut BNQualifiedName,
                &mut count,
            );
            Array::new(handle, count, ())
        }
    }

    fn get_relocations_at(&self, addr: u64) -> Array<Relocation> {
        unsafe {
            let mut count = 0;
            let handle = BNGetRelocationsAt(self.as_ref().handle, addr, &mut count);
            Array::new(handle, count, ())
        }
    }
}

impl<T: BinaryViewBase> BinaryViewExt for T {}

#[derive(PartialEq, Eq, Hash)]
pub struct BinaryView {
    pub(crate) handle: *mut BNBinaryView,
}

impl BinaryView {
    pub(crate) unsafe fn from_raw(handle: *mut BNBinaryView) -> Ref<Self> {
        debug_assert!(!handle.is_null());

        Ref::new(Self { handle })
    }

    pub fn from_filename<S: BnStrCompatible>(
        meta: &mut FileMetadata,
        filename: S,
    ) -> Result<Ref<Self>> {
        let file = filename.into_bytes_with_nul();

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

impl std::fmt::Debug for BinaryView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "BinaryView (type: `{}`): '{}', len {:#x}",
            self.view_type(),
            self.file().filename(),
            self.len()
        )
    }
}

pub trait BinaryViewEventHandler: 'static + Sync {
    fn on_event(&self, binary_view: &BinaryView);
}

pub type BinaryViewEventType = BNBinaryViewEventType;

/// Registers an event listener for binary view events.
///
/// # Example
///
/// ```no_run
/// use binaryninja::binaryview::{BinaryView, BinaryViewEventHandler, BinaryViewEventType, register_binary_view_event};
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
///     let context = EventHandlerContext { };
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
            context.on_event(&BinaryView::from_raw(BNNewViewReference(view)));
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
