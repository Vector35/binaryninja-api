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
//! One key job of BinaryView is file format parsing which allows Binary Ninja to read, write,
//! insert, remove portions of the file given a virtual address.
//!
//! For the purposes of this documentation we define a virtual address as the memory address that
//! the various pieces of the physical file will be loaded at.
//! TODO : Mirror the Python docs for this

use binaryninjacore_sys::*;

use crate::architecture::{Architecture, CoreArchitecture};
use crate::basic_block::BasicBlock;
use crate::component::{Component, IntoComponentGuid};
use crate::confidence::Conf;
use crate::data_buffer::DataBuffer;
use crate::debuginfo::DebugInfo;
use crate::external_library::{ExternalLibrary, ExternalLocation};
use crate::file_accessor::FileAccessor;
use crate::file_metadata::FileMetadata;
use crate::flowgraph::FlowGraph;
use crate::function::{Function, NativeBlock};
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
use crate::tags::{Tag, TagType};
use crate::type_container::TypeContainer;
use crate::type_library::TypeLibrary;
use crate::types::{
    NamedTypeReference, QualifiedName, QualifiedNameAndType, QualifiedNameTypeAndId, Type,
};
use crate::variable::DataVariable;
use crate::Endianness;
use std::collections::HashMap;
use std::ffi::{c_char, c_void};
use std::ops::Range;
use std::path::Path;
use std::ptr::NonNull;
use std::{result, slice};
// TODO : general reorg of modules related to bv

pub type Result<R> = result::Result<R, ()>;
pub type BinaryViewEventType = BNBinaryViewEventType;
pub type AnalysisState = BNAnalysisState;
pub type ModificationStatus = BNModificationStatus;

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

#[derive(Debug, Clone)]
pub struct AnalysisProgress {
    pub state: AnalysisState,
    pub count: usize,
    pub total: usize,
}

pub trait BinaryViewExt: BinaryViewBase {
    fn file(&self) -> Ref<FileMetadata> {
        unsafe {
            let raw = BNGetFileForView(self.as_ref().handle);
            FileMetadata::ref_from_raw(raw)
        }
    }

    fn type_name(&self) -> BnString {
        let ptr: *mut c_char = unsafe { BNGetViewType(self.as_ref().handle) };
        unsafe { BnString::from_raw(ptr) }
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

    fn original_image_base(&self) -> u64 {
        unsafe { BNGetOriginalImageBase(self.as_ref().handle) }
    }

    fn set_original_image_base(&self, image_base: u64) {
        unsafe { BNSetOriginalImageBase(self.as_ref().handle, image_base) }
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
            let func = unsafe { Function::ref_from_raw(active_info.func) };
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

    fn symbol_by_raw_name<S: BnStrCompatible>(&self, raw_name: S) -> Option<Ref<Symbol>> {
        let raw_name = raw_name.into_bytes_with_nul();

        unsafe {
            let raw_sym_ptr = BNGetSymbolByRawName(
                self.as_ref().handle,
                raw_name.as_ref().as_ptr() as *mut _,
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

    fn symbols_by_name<S: BnStrCompatible>(&self, name: S) -> Array<Symbol> {
        let raw_name = name.into_bytes_with_nul();

        unsafe {
            let mut count = 0;
            let handles = BNGetSymbolsByName(
                self.as_ref().handle,
                raw_name.as_ref().as_ptr() as *mut _,
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
        let raw_type = if let Some(t) = ty.into() {
            t.handle
        } else {
            std::ptr::null_mut()
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

    /// You likely would also like to call [`Self::define_user_symbol`] to bind this data variable with a name
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

    fn define_auto_type<T: Into<QualifiedName>, S: BnStrCompatible>(
        &self,
        name: T,
        source: S,
        type_obj: &Type,
    ) -> QualifiedName {
        let mut raw_name = QualifiedName::into_raw(name.into());
        let source_str = source.into_bytes_with_nul();
        let name_handle = unsafe {
            let id_str =
                BNGenerateAutoTypeId(source_str.as_ref().as_ptr() as *const _, &mut raw_name);
            BNDefineAnalysisType(self.as_ref().handle, id_str, &mut raw_name, type_obj.handle)
        };
        QualifiedName::free_raw(raw_name);
        QualifiedName::from_owned_raw(name_handle)
    }

    fn define_auto_type_with_id<T: Into<QualifiedName>, S: BnStrCompatible>(
        &self,
        name: T,
        id: S,
        type_obj: &Type,
    ) -> QualifiedName {
        let mut raw_name = QualifiedName::into_raw(name.into());
        let id_str = id.into_bytes_with_nul();
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

    fn undefine_auto_type<S: BnStrCompatible>(&self, id: S) {
        let id_str = id.into_bytes_with_nul();
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

    fn type_by_id<S: BnStrCompatible>(&self, id: S) -> Option<Ref<Type>> {
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

    fn type_name_by_id<S: BnStrCompatible>(&self, id: S) -> Option<QualifiedName> {
        unsafe {
            let id_str = id.into_bytes_with_nul();
            let name_handle =
                BNGetAnalysisTypeNameById(self.as_ref().handle, id_str.as_ref().as_ptr() as *mut _);
            let name = QualifiedName::from_owned_raw(name_handle);
            // The core will return an empty qualified name if no type name was found.
            match name.items.is_empty() {
                true => None,
                false => Some(name),
            }
        }
    }

    fn type_id_by_name<T: Into<QualifiedName>>(&self, name: T) -> Option<BnString> {
        let mut raw_name = QualifiedName::into_raw(name.into());
        unsafe {
            let id_cstr = BNGetAnalysisTypeId(self.as_ref().handle, &mut raw_name);
            QualifiedName::free_raw(raw_name);
            let id = BnString::from_raw(id_cstr);
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

    fn add_section<S: BnStrCompatible>(&self, section: SectionBuilder<S>) {
        section.create(self.as_ref());
    }

    fn remove_auto_section<S: BnStrCompatible>(&self, name: S) {
        let raw_name = name.into_bytes_with_nul();
        let raw_name_ptr = raw_name.as_ref().as_ptr() as *mut _;
        unsafe {
            BNRemoveAutoSection(self.as_ref().handle, raw_name_ptr);
        }
    }

    fn remove_user_section<S: BnStrCompatible>(&self, name: S) {
        let raw_name = name.into_bytes_with_nul();
        let raw_name_ptr = raw_name.as_ref().as_ptr() as *mut _;
        unsafe {
            BNRemoveUserSection(self.as_ref().handle, raw_name_ptr);
        }
    }

    fn section_by_name<S: BnStrCompatible>(&self, name: S) -> Option<Ref<Section>> {
        unsafe {
            let raw_name = name.into_bytes_with_nul();
            let name_ptr = raw_name.as_ref().as_ptr() as *mut _;
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

    fn add_auto_function(&self, plat: &Platform, addr: u64) -> Option<Ref<Function>> {
        unsafe {
            let handle = BNAddFunctionForAnalysis(
                self.as_ref().handle,
                plat.handle,
                addr,
                false,
                std::ptr::null_mut(),
            );

            if handle.is_null() {
                return None;
            }

            Some(Function::ref_from_raw(handle))
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
                None => std::ptr::null_mut(),
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

            Some(Function::ref_from_raw(handle))
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

            Ok(Function::ref_from_raw(func))
        }
    }

    fn has_functions(&self) -> bool {
        unsafe { BNHasFunctions(self.as_ref().handle) }
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

    // List of functions containing `addr`
    fn functions_containing(&self, addr: u64) -> Array<Function> {
        unsafe {
            let mut count = 0;
            let functions =
                BNGetAnalysisFunctionsContainingAddress(self.as_ref().handle, addr, &mut count);

            Array::new(functions, count, ())
        }
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

    fn read_buffer(&self, offset: u64, len: usize) -> Result<DataBuffer> {
        let read_buffer = unsafe { BNReadViewBuffer(self.as_ref().handle, offset, len) };
        if read_buffer.is_null() {
            Err(())
        } else {
            Ok(DataBuffer::from_raw(read_buffer))
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
    fn tag_type_by_name<S: BnStrCompatible>(&self, name: S) -> Option<Ref<TagType>> {
        let name = name.into_bytes_with_nul();
        unsafe {
            let handle = BNGetTagType(self.as_ref().handle, name.as_ref().as_ptr() as *mut _);
            if handle.is_null() {
                return None;
            }
            Some(TagType::ref_from_raw(handle))
        }
    }

    /// Get a tag by its id.
    ///
    /// Note this does not tell you anything about where it is used.
    fn tag_by_id<S: BnStrCompatible>(&self, id: S) -> Option<Ref<Tag>> {
        let id = id.into_bytes_with_nul();
        unsafe {
            let handle = BNGetTag(self.as_ref().handle, id.as_ref().as_ptr() as *mut _);
            if handle.is_null() {
                return None;
            }
            Some(Tag::ref_from_raw(handle))
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
    fn code_refs_to_addr(&self, addr: u64) -> Array<CodeReference> {
        unsafe {
            let mut count = 0;
            let handle = BNGetCodeReferences(self.as_ref().handle, addr, &mut count);
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
            let handle = BNGetDataReferences(self.as_ref().handle, addr, &mut count);
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
            let handle =
                BNGetCodeReferencesForType(self.as_ref().handle, &mut raw_name, &mut count);
            QualifiedName::free_raw(raw_name);
            Array::new(handle, count, ())
        }
    }

    /// Retrieves a list of [DataReference]s for locations in data that use a given named type.
    fn data_refs_using_type_name<T: Into<QualifiedName>>(&self, name: T) -> Array<DataReference> {
        let mut raw_name = QualifiedName::into_raw(name.into());
        unsafe {
            let mut count = 0;
            let handle =
                BNGetDataReferencesForType(self.as_ref().handle, &mut raw_name, &mut count);
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

    fn component_by_guid<S: BnStrCompatible>(&self, guid: S) -> Option<Ref<Component>> {
        let name = guid.into_bytes_with_nul();
        let result = unsafe {
            BNGetComponentByGuid(
                self.as_ref().handle,
                name.as_ref().as_ptr() as *const c_char,
            )
        };
        NonNull::new(result).map(|h| unsafe { Component::ref_from_raw(h) })
    }

    fn root_component(&self) -> Option<Ref<Component>> {
        let result = unsafe { BNGetRootComponent(self.as_ref().handle) };
        NonNull::new(result).map(|h| unsafe { Component::ref_from_raw(h) })
    }

    fn component_by_path<P: BnStrCompatible>(&self, path: P) -> Option<Ref<Component>> {
        let path = path.into_bytes_with_nul();
        let result = unsafe {
            BNGetComponentByPath(
                self.as_ref().handle,
                path.as_ref().as_ptr() as *const c_char,
            )
        };
        NonNull::new(result).map(|h| unsafe { Component::ref_from_raw(h) })
    }

    fn remove_component(&self, component: &Component) -> bool {
        unsafe { BNRemoveComponent(self.as_ref().handle, component.handle.as_ptr()) }
    }

    fn remove_component_by_guid<P: IntoComponentGuid>(&self, guid: P) -> bool {
        let path = guid.component_guid();
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

    fn external_library<S: BnStrCompatible>(&self, name: S) -> Option<Ref<ExternalLibrary>> {
        let name_ptr = name.into_bytes_with_nul();
        let result = unsafe {
            BNBinaryViewGetExternalLibrary(
                self.as_ref().handle,
                name_ptr.as_ref().as_ptr() as *const c_char,
            )
        };
        let result_ptr = NonNull::new(result)?;
        Some(unsafe { ExternalLibrary::ref_from_raw(result_ptr) })
    }

    fn remove_external_library<S: BnStrCompatible>(&self, name: S) {
        let name_ptr = name.into_bytes_with_nul();
        unsafe {
            BNBinaryViewRemoveExternalLibrary(
                self.as_ref().handle,
                name_ptr.as_ref().as_ptr() as *const c_char,
            )
        };
    }

    fn add_external_library<S: BnStrCompatible>(
        &self,
        name: S,
        backing_file: Option<&ProjectFile>,
        auto: bool,
    ) -> Option<Ref<ExternalLibrary>> {
        let name_ptr = name.into_bytes_with_nul();
        let result = unsafe {
            BNBinaryViewAddExternalLibrary(
                self.as_ref().handle,
                name_ptr.as_ref().as_ptr() as *const c_char,
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
    fn add_external_location<S: BnStrCompatible>(
        &self,
        symbol: &Symbol,
        library: &ExternalLibrary,
        target_symbol_name: S,
        target_address: Option<u64>,
        target_is_auto: bool,
    ) -> Option<Ref<ExternalLocation>> {
        let target_symbol_name = target_symbol_name.into_bytes_with_nul();
        let target_address_ptr = target_address
            .map(|a| a as *mut u64)
            .unwrap_or(std::ptr::null_mut());
        let result = unsafe {
            BNBinaryViewAddExternalLocation(
                self.as_ref().handle,
                symbol.handle,
                library.handle.as_ptr(),
                target_symbol_name.as_ref().as_ptr() as *const c_char,
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

    /// Make the contents of a type library available for type/import resolution
    fn add_type_library(&self, library: &TypeLibrary) {
        unsafe { BNAddBinaryViewTypeLibrary(self.as_ref().handle, library.as_raw()) }
    }

    fn type_library_by_name<S: BnStrCompatible>(&self, name: S) -> Option<TypeLibrary> {
        let name = name.into_bytes_with_nul();
        let result = unsafe {
            BNGetBinaryViewTypeLibrary(
                self.as_ref().handle,
                name.as_ref().as_ptr() as *const c_char,
            )
        };
        NonNull::new(result).map(|h| unsafe { TypeLibrary::from_raw(h) })
    }

    /// Should be called by custom py:py:class:`BinaryView` implementations
    /// when they have successfully imported an object from a type library (eg a symbol's type).
    /// Values recorded with this function will then be queryable via [BinaryViewExt::lookup_imported_object_library].
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

    /// Recursively imports a type from the specified type library, or, if
    /// no library was explicitly provided, the first type library associated with the current [BinaryView]
    /// that provides the name requested.
    ///
    /// This may have the impact of loading other type libraries as dependencies on other type libraries are lazily resolved
    /// when references to types provided by them are first encountered.
    ///
    /// Note that the name actually inserted into the view may not match the name as it exists in the type library in
    /// the event of a name conflict. To aid in this, the [Type] object returned is a `NamedTypeReference` to
    /// the deconflicted name used.
    fn import_type_library<T: Into<QualifiedName>>(
        &self,
        name: T,
        mut lib: Option<TypeLibrary>,
    ) -> Option<Ref<Type>> {
        let mut lib_ref = lib
            .as_mut()
            .map(|l| unsafe { l.as_raw() } as *mut _)
            .unwrap_or(std::ptr::null_mut());
        let mut raw_name = QualifiedName::into_raw(name.into());
        let result = unsafe {
            BNBinaryViewImportTypeLibraryType(self.as_ref().handle, &mut lib_ref, &mut raw_name)
        };
        QualifiedName::free_raw(raw_name);
        (!result.is_null()).then(|| unsafe { Type::ref_from_raw(result) })
    }

    /// Recursively imports an object from the specified type library, or, if
    /// no library was explicitly provided, the first type library associated with the current [BinaryView]
    /// that provides the name requested.
    ///
    /// This may have the impact of loading other type libraries as dependencies on other type libraries are lazily resolved
    /// when references to types provided by them are first encountered.
    ///
    /// .. note:: If you are implementing a custom BinaryView and use this method to import object types,
    /// you should then call [BinaryViewExt::record_imported_object_library] with the details of where the object is located.
    fn import_type_object<T: Into<QualifiedName>>(
        &self,
        name: T,
        mut lib: Option<TypeLibrary>,
    ) -> Option<Ref<Type>> {
        let mut lib_ref = lib
            .as_mut()
            .map(|l| unsafe { l.as_raw() } as *mut _)
            .unwrap_or(std::ptr::null_mut());
        let mut raw_name = QualifiedName::into_raw(name.into());
        let result = unsafe {
            BNBinaryViewImportTypeLibraryObject(self.as_ref().handle, &mut lib_ref, &mut raw_name)
        };
        QualifiedName::free_raw(raw_name);
        (!result.is_null()).then(|| unsafe { Type::ref_from_raw(result) })
    }

    /// Recursively imports a type interface given its GUID.
    ///
    /// .. note:: To support this type of lookup a type library must have
    ///     contain a metadata key called "type_guids" which is a map
    ///     Dict[string_guid, string_type_name] or
    ///     Dict[string_guid, Tuple[string_type_name, type_library_name]]
    fn import_type_by_guid<S: BnStrCompatible>(&self, guid: S) -> Option<Ref<Type>> {
        let guid = guid.into_bytes_with_nul();
        let result = unsafe {
            BNBinaryViewImportTypeLibraryTypeByGuid(
                self.as_ref().handle,
                guid.as_ref().as_ptr() as *const c_char,
            )
        };
        (!result.is_null()).then(|| unsafe { Type::ref_from_raw(result) })
    }

    /// Recursively exports `type_obj` into `lib` as a type with name `name`
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

    /// Recursively exports `type_obj` into `lib` as a type with name `name`
    ///
    /// As other referenced types are encountered, they are either copied into the destination type library or
    ///     else the type library that provided the referenced type is added as a dependency for the destination library.
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
    ) -> Option<(TypeLibrary, QualifiedName)> {
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
        let lib = unsafe { TypeLibrary::from_raw(NonNull::new(result_lib)?) };
        let name = QualifiedName::from_owned_raw(result_name);
        Some((lib, name))
    }

    /// Gives you details of from which type library and name a given type in the analysis was imported.
    ///
    /// * `name` - Name of type in analysis
    fn lookup_imported_type_library<T: Into<QualifiedName>>(
        &self,
        name: T,
    ) -> Option<(TypeLibrary, QualifiedName)> {
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
        let lib = unsafe { TypeLibrary::from_raw(NonNull::new(result_lib)?) };
        let name = QualifiedName::from_owned_raw(result_name);
        Some((lib, name))
    }
    //
    // fn type_archives(&self) -> Array<TypeArchive> {
    //     let mut ids: *mut *mut c_char = std::ptr::null_mut();
    //     let mut paths: *mut *mut c_char = std::ptr::null_mut();
    //     let count = unsafe { BNBinaryViewGetTypeArchives(self.as_ref().handle, &mut ids, &mut paths) };
    //     let path_list = unsafe { Array::<BnString>::new(paths, count, ()) };
    //     let ids_list = unsafe { std::slice::from_raw_parts(ids, count).to_vec() };
    //     let archives = ids_list.iter().filter_map(|id| {
    //         let archive_raw = unsafe { BNBinaryViewGetTypeArchive(self.as_ref().handle, *id) };
    //         match archive_raw.is_null() {
    //             true => None,
    //             false => Some(archive_raw)
    //         }
    //     }).collect();
    //     unsafe { BNFreeStringList(ids, count) };
    //     Array::new(archives)
    // }
}

impl<T: BinaryViewBase> BinaryViewExt for T {}

#[derive(PartialEq, Eq, Hash)]
pub struct BinaryView {
    pub(crate) handle: *mut BNBinaryView,
}

impl BinaryView {
    pub(crate) unsafe fn from_raw(handle: *mut BNBinaryView) -> Self {
        debug_assert!(!handle.is_null());
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: *mut BNBinaryView) -> Ref<Self> {
        debug_assert!(!handle.is_null());
        Ref::new(Self { handle })
    }

    pub fn from_path(meta: &mut FileMetadata, file_path: impl AsRef<Path>) -> Result<Ref<Self>> {
        let file = file_path.as_ref().into_bytes_with_nul();
        let handle =
            unsafe { BNCreateBinaryDataViewFromFilename(meta.handle, file.as_ptr() as *mut _) };

        if handle.is_null() {
            return Err(());
        }

        unsafe { Ok(Ref::new(Self { handle })) }
    }

    pub fn from_accessor(meta: &FileMetadata, file: &mut FileAccessor) -> Result<Ref<Self>> {
        let handle = unsafe { BNCreateBinaryDataViewFromFile(meta.handle, &mut file.api_object) };

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

    /// Save the original binary file to the provided `file_path` along with any modifications.
    ///
    /// WARNING: Currently there is a possibility to deadlock if the analysis has queued up a main thread action
    /// that tries to take the [`FileMetadata`] lock of the current view, and is executed while we
    /// are executing in this function.
    ///
    /// To avoid the above issue use [`crate::main_thread::execute_on_main_thread_and_wait`] to verify there
    /// are no queued up main thread actions.
    pub fn save_to_path(&self, file_path: impl AsRef<Path>) -> bool {
        let file = file_path.as_ref().into_bytes_with_nul();
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
    pub fn save_to_accessor(&self, file: &mut FileAccessor) -> bool {
        unsafe { BNSaveToFile(self.handle, &mut file.api_object) }
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
            .field("type_name", &self.type_name())
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
