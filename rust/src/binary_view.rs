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
//!
//! The main analysis object is [`BinaryView`], and custom implementations can be implemented with [`CustomBinaryView`].

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
    FunctionParameter, NamedTypeReference, QualifiedName, QualifiedNameAndType,
    QualifiedNameTypeAndId, ReturnValue, Type, TypeArchive, TypeArchiveId, TypeContainer,
    TypeLibrary,
};
use crate::variable::DataVariable;
use crate::workflow::Workflow;
use crate::{Endianness, BN_FULL_CONFIDENCE};
use std::collections::{BTreeMap, HashMap};
use std::ffi::{c_char, c_void, CString};
use std::fmt::{Debug, Display, Formatter};
use std::mem::MaybeUninit;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::ptr::NonNull;

pub mod memory_map;
pub mod reader;
pub mod search;
pub mod writer;

pub use memory_map::{MemoryMap, MemoryRegionInfo, ResolvedRange};
pub use reader::BinaryReader;
pub use writer::BinaryWriter;

pub type BinaryViewEventType = BNBinaryViewEventType;
pub type AnalysisState = BNAnalysisState;
pub type ModificationStatus = BNModificationStatus;
pub type StringType = BNStringType;
pub type FindFlag = BNFindFlag;

/// Registers a new binary view type.
pub fn register_binary_view_type<T>(view_type: T) -> (&'static T, BinaryViewType)
where
    T: CustomBinaryViewType,
{
    let name = T::NAME.to_cstr();
    let long_name = T::LONG_NAME.to_cstr();
    let leaked_type = Box::leak(Box::new(view_type));

    let result = unsafe {
        BNRegisterBinaryViewType(
            name.as_ref().as_ptr() as *const _,
            long_name.as_ref().as_ptr() as *const _,
            &mut BNCustomBinaryViewType {
                context: leaked_type as *mut _ as *mut std::os::raw::c_void,
                create: Some(cb_create::<T>),
                parse: Some(cb_parse::<T>),
                isValidForData: Some(cb_valid::<T>),
                isDeprecated: Some(cb_deprecated::<T>),
                isForceLoadable: Some(cb_force_loadable::<T>),
                getLoadSettingsForData: Some(cb_load_settings::<T>),
                hasNoInitialContent: Some(cb_has_no_initial_content::<T>),
            },
        )
    };

    assert!(
        !result.is_null(),
        "BNRegisterBinaryViewType always returns a non-null handle"
    );
    let core_view_type = unsafe { BinaryViewType::from_raw(result) };
    (leaked_type, core_view_type)
}

/// Interface for creating custom binary views of a given type, analogous to [`BinaryViewType`].
pub trait CustomBinaryViewType: 'static + Sync {
    /// The associated [`BinaryViewBase`] for which this type creates with [`CustomBinaryViewType::create_binary_view`].
    type CustomBinaryView: CustomBinaryView;

    /// The name of the binary view type.
    const NAME: &'static str;

    /// The longer name of the binary view type, defaults to [`CustomBinaryViewType::NAME`].
    const LONG_NAME: &'static str = Self::NAME;

    /// Is this [`CustomBinaryViewType`] deprecated and should not be used?
    ///
    /// We specify this such that the view type may still be used by existing databases, but not
    /// newly created views.
    const DEPRECATED: bool = false;

    /// Is this [`CustomBinaryViewType`] able to be loaded forcefully?
    ///
    /// If so, it will be shown in the drop-down when a user opens a file with options.
    const FORCE_LOADABLE: bool = false;

    /// Do instances of this [`CustomBinaryViewType`] start with no loaded content?
    ///
    /// When true, the view has no meaningful default state: the user must make a
    /// selection (e.g. load images from a shared cache) before any content exists.
    ///
    /// Callers can use this to suppress restoring the previously saved view state for
    /// files not being loaded from a database, since a saved layout would reference
    /// content that isn't available on reopening.
    const HAS_NO_INITIAL_CONTENT: bool = false;

    /// Constructs the custom binary view instance.
    fn create_binary_view(&self, data: &BinaryView) -> Result<Self::CustomBinaryView, ()>;

    /// Constructs the custom binary view instance to be used for configuration.
    ///
    /// This is the path that is used when opening a binary with "Open With Options", and is what populates
    /// the sections and segments of the dialog along with settings like the image base (start) address.
    ///
    /// The default implementation for this will construct a new instance identical to that of [`CustomBinaryViewType::create_binary_view`].
    ///
    /// Overriding this is encouraged as you can skip actually applying data to the view such as functions,
    /// symbols, and other data not required for configuration, especially because this binary view is created
    /// only temporarily and will be discarded after configuration is complete.
    fn create_binary_view_for_parse(
        &self,
        data: &BinaryView,
    ) -> Result<Self::CustomBinaryView, ()> {
        self.create_binary_view(data)
    }

    /// Is this [`BinaryViewType`] valid for the given the raw [`BinaryView`]?
    ///
    /// Typical implementations will read the magic bytes (e.g. 'MZ'), this is a performance-sensitive
    /// path so prefer inexpensive checks rather than comprehensive ones.
    fn is_valid_for(&self, data: &BinaryView) -> bool;

    fn load_settings_for_data(&self, _data: &BinaryView) -> Ref<Settings> {
        Settings::new()
    }
}

/// A [`BinaryViewType`] acts as a factory for [`BinaryView`] objects.
///
/// Each file format will have its own type, such as PE, ELF, or Mach-O.
///
/// Custom view types can be implemented using [`CustomBinaryViewType`].
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct BinaryViewType {
    pub handle: *mut BNBinaryViewType,
}

impl BinaryViewType {
    pub(crate) unsafe fn from_raw(handle: *mut BNBinaryViewType) -> Self {
        debug_assert!(!handle.is_null());
        Self { handle }
    }

    pub fn list_all() -> Array<BinaryViewType> {
        unsafe {
            let mut count: usize = 0;
            let types = BNGetBinaryViewTypes(&mut count as *mut _);
            Array::new(types, count, ())
        }
    }

    /// Enumerates all view types and checks to see if the given raw [`BinaryView`] is valid,
    /// returning only those that are.
    pub fn valid_types_for_data(data: &BinaryView) -> Array<BinaryViewType> {
        unsafe {
            let mut count: usize = 0;
            let types = BNGetBinaryViewTypesForData(data.handle, &mut count as *mut _);
            Array::new(types, count, ())
        }
    }

    /// Looks up a binary view type by its name (_not_ the long name).
    pub fn by_name(name: &str) -> Option<Self> {
        let bytes = name.to_cstr();
        let handle = unsafe { BNGetBinaryViewTypeByName(bytes.as_ref().as_ptr() as *const _) };
        if handle.is_null() {
            None
        } else {
            Some(unsafe { BinaryViewType::from_raw(handle) })
        }
    }

    /// The given name for the binary view type.
    pub fn name(&self) -> String {
        unsafe { BnString::into_string(BNGetBinaryViewTypeName(self.handle)) }
    }

    /// The given long name for the binary view type.
    pub fn long_name(&self) -> String {
        unsafe { BnString::into_string(BNGetBinaryViewTypeLongName(self.handle)) }
    }

    /// Register an architecture for selection via the `id` and `endianness`.
    ///
    /// If you need to peak at the [`BinaryView`] to determine the architecture, use [`BinaryViewType::register_platform_recognizer`]
    /// instead of this.
    pub fn register_arch<A: Architecture>(&self, id: u32, endianness: Endianness, arch: &A) {
        unsafe {
            BNRegisterArchitectureForViewType(self.handle, id, endianness, arch.as_ref().handle);
        }
    }

    /// Register a platform for selection via the `id`.
    ///
    /// If you need to peak at the [`BinaryView`] to determine the platform, use [`BinaryViewType::register_platform_recognizer`]
    /// instead of this.
    pub fn register_platform(&self, id: u32, plat: &Platform) {
        let arch = plat.arch();
        unsafe {
            BNRegisterPlatformForViewType(self.handle, id, arch.handle, plat.handle);
        }
    }

    /// Expanded identification of [`Platform`] for [`BinaryViewType`]'s. Supersedes [`BinaryViewType::register_arch`]
    /// and [`BinaryViewType::register_platform`], as these have certain edge cases (overloaded elf families, for example)
    /// that can't be represented.
    ///
    /// The callback returns a [`Platform`] object or `None` (failure), and most recently added callbacks are called first
    /// to allow plugins to override any default behaviors. When a callback returns a platform, architecture will be
    /// derived from the identified platform.
    ///
    /// The [`BinaryView`] is the *parent* view (usually 'Raw') that the [`BinaryView`] is being created for. This
    /// means that generally speaking, the callbacks need to be aware of the underlying file format. However, the
    /// [`BinaryView`] implementation may have created data variables in the 'Raw' view by the time the callback is invoked.
    /// Behavior regarding when this callback is invoked and what has been made available in the [`BinaryView`] passed as an
    /// argument to the callback is up to the discretion of the [`BinaryView`] implementation.
    ///
    /// The `id` ind `endian` arguments are used as a filter to determine which registered [`Platform`] recognizer callbacks
    /// are invoked.
    ///
    /// Support for this API tentatively requires explicit support in the [`BinaryView`] implementation.
    pub fn register_platform_recognizer<R>(&self, id: u32, endian: Endianness, recognizer: R)
    where
        R: 'static + Fn(&BinaryView, &Metadata) -> Option<Ref<Platform>> + Send + Sync,
    {
        #[repr(C)]
        struct PlatformRecognizerHandlerContext<R>
        where
            R: 'static + Fn(&BinaryView, &Metadata) -> Option<Ref<Platform>> + Send + Sync,
        {
            recognizer: R,
        }

        extern "C" fn cb_recognize_low_level_il<R>(
            ctxt: *mut std::os::raw::c_void,
            bv: *mut BNBinaryView,
            metadata: *mut BNMetadata,
        ) -> *mut BNPlatform
        where
            R: 'static + Fn(&BinaryView, &Metadata) -> Option<Ref<Platform>> + Send + Sync,
        {
            let context = unsafe { &*(ctxt as *mut PlatformRecognizerHandlerContext<R>) };
            let bv = unsafe { BinaryView::from_raw(bv).to_owned() };
            let metadata = unsafe { Metadata::from_raw(metadata).to_owned() };
            match (context.recognizer)(&bv, &metadata) {
                Some(plat) => unsafe { Ref::into_raw(plat).handle },
                None => std::ptr::null_mut(),
            }
        }

        let recognizer = PlatformRecognizerHandlerContext { recognizer };
        let raw = Box::into_raw(Box::new(recognizer));
        unsafe {
            BNRegisterPlatformRecognizerForViewType(
                self.handle,
                id as u64,
                endian,
                Some(cb_recognize_low_level_il::<R>),
                raw as *mut std::os::raw::c_void,
            )
        }
    }

    /// Creates a new instance of the binary view for this given type, constructed with `data` as
    /// the parent view.
    ///
    /// This will also call the initialization routine for the view, after calling this you should
    /// be able to use the view as normal and ready to start analysis with [`BinaryView::update_analysis`].
    pub fn create(&self, data: &BinaryView) -> Result<Ref<BinaryView>, ()> {
        let handle = unsafe { BNCreateBinaryViewOfType(self.handle, data.handle) };
        if handle.is_null() {
            // TODO: Proper Result, possibly introduce BNSetError to populate.
            return Err(());
        }
        unsafe { Ok(BinaryView::ref_from_raw(handle)) }
    }

    /// Creates a new instance of the binary view for parsing, this is a "specialize" version of the
    /// regular [`BinaryViewType::create`] and is expected to be used when you only want to have the
    /// view parsed and populated with information required for configuration, like with open with options.
    pub fn parse(&self, data: &BinaryView) -> Result<Ref<BinaryView>, ()> {
        let handle = unsafe { BNParseBinaryViewOfType(self.handle, data.handle) };
        if handle.is_null() {
            // TODO: Proper Result, possibly introduce BNSetError to populate.
            return Err(());
        }
        unsafe { Ok(BinaryView::ref_from_raw(handle)) }
    }

    /// Is this [`BinaryViewType`] valid for the given the raw [`BinaryView`]?
    ///
    /// Typical implementations will read the magic bytes (e.g. 'MZ'), this is a performance-sensitive
    /// path so prefer inexpensive checks rather than comprehensive ones.
    pub fn is_valid_for(&self, data: &BinaryView) -> bool {
        unsafe { BNIsBinaryViewTypeValidForData(self.handle, data.handle) }
    }

    /// Is this [`BinaryViewType`] deprecated and should not be used?
    ///
    /// We specify this such that the view type may still be used by existing databases, but not
    /// newly created views.
    pub fn is_deprecated(&self) -> bool {
        unsafe { BNIsBinaryViewTypeDeprecated(self.handle) }
    }

    /// Is this [`BinaryViewType`] able to be loaded forcefully?
    ///
    /// If so, it will be shown in the drop-down when a user opens a file with options.
    pub fn is_force_loadable(&self) -> bool {
        unsafe { BNIsBinaryViewTypeForceLoadable(self.handle) }
    }

    /// Do instances of this [`BinaryViewType`] start with no loaded content?
    ///
    /// When true, the view has no meaningful default state: the user must make a
    /// selection (e.g. load images from a shared cache) before any content exists.
    ///
    /// Callers can use this to suppress restoring the previously saved view state for
    /// files not being loaded from a database, since a saved layout would reference
    /// content that isn't available on reopening.
    pub fn has_no_initial_content(&self) -> bool {
        unsafe { BNBinaryViewTypeHasNoInitialContent(self.handle) }
    }

    pub fn load_settings_for_data(&self, data: &BinaryView) -> Option<Ref<Settings>> {
        let settings_handle =
            unsafe { BNGetBinaryViewLoadSettingsForData(self.handle, data.handle) };

        if settings_handle.is_null() {
            None
        } else {
            unsafe { Some(Settings::ref_from_raw(settings_handle)) }
        }
    }
}

impl Debug for BinaryViewType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BinaryViewType")
            .field("name", &self.name())
            .field("long_name", &self.long_name())
            .finish()
    }
}

impl CoreArrayProvider for BinaryViewType {
    type Raw = *mut BNBinaryViewType;
    type Context = ();
    type Wrapped<'a> = Guard<'a, BinaryViewType>;
}

unsafe impl CoreArrayProviderInner for BinaryViewType {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeBinaryViewTypeList(raw);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Guard::new(BinaryViewType::from_raw(*raw), &())
    }
}

unsafe impl Send for BinaryViewType {}
unsafe impl Sync for BinaryViewType {}

/// Implemented for custom views, responsible for setting up the view state once the binary is open.
pub trait CustomBinaryView: BinaryViewBase {
    /// Initializes the opened binary view state.
    ///
    /// Use this to populate the [`BinaryView`] with sections, segments, and other view data.
    ///
    /// NOTE: You must add **at least** one segment to the view, otherwise calls to [`BinaryViewType::create`]
    /// will fail.
    ///
    /// NOTE: This will be called on every subsequent open of a database, any view data applied here
    /// should be expected to be regenerated on every open.
    fn initialize(&mut self, view: &BinaryView) -> bool;

    /// Called after deserialization of the current database snapshot has completed and all the
    /// view data inside that snapshot has been applied to the view (like sections and segments).
    ///
    /// Useful if you need to regenerate temporary data based on the view state.
    fn on_after_snapshot_data_applied(&mut self) {}
}

/// Wrapper around `C` when being passed to the custom view constructor so that we have the core
/// view available to [`CustomBinaryView::initialize`], called from [`cb_init`].
struct CustomBinaryViewContext<C: CustomBinaryView> {
    // This is not ref-counted because we do not want to impact the lifetime of the core view, the lifetime
    // of which is already bound to the lifetime of the custom view (to be freed when the custom view is freed).
    core_view: MaybeUninit<BinaryView>,
    view: C,
}

#[allow(clippy::len_without_is_empty)]
pub trait BinaryViewBase {
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
        self.read(&mut buf[..], offset) == buf.len()
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
        let start = self.start();
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
        false
    }

    fn entry_point(&self) -> u64 {
        0
    }

    fn default_endianness(&self) -> Endianness;

    fn address_size(&self) -> usize;

    // TODO: Needs to take file accessor?
    fn save(&self) -> bool {
        false
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

/// Represents the "whole view" of the binary and its analysis.
///
/// Analysis information:
///
/// - [`BinaryView::functions`]
/// - [`BinaryView::data_variables`]
/// - [`BinaryView::strings`]
///
/// Annotation information:
///
/// - [`BinaryView::symbols`]
/// - [`BinaryView::tags_all_scopes`]
/// - [`BinaryView::comments`]
///
/// Data representation and binary information:
///
/// - [`BinaryView::types`]
/// - [`BinaryView::segments`]
/// - [`BinaryView::sections`]
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

    /// Create a core instance of the [`CustomBinaryView`].
    pub fn from_custom<C: CustomBinaryView>(
        view_type_name: &str,
        file: &FileMetadata,
        parent_view: &BinaryView,
        view: C,
    ) -> Result<Ref<Self>, ()> {
        let type_name = view_type_name.to_cstr();
        // We need to pass the core BinaryView when initializing the custom view state with [`CustomBinaryView::initialize`],
        // and to do that we need to store the returned core view handle after creating the custom view.
        let custom_context = CustomBinaryViewContext {
            core_view: MaybeUninit::uninit(),
            view,
        };
        // We leak to be freed in `cb_free_object`.
        let leaked_view = Box::leak(Box::new(custom_context));
        let handle = unsafe {
            BNCreateCustomBinaryView(
                type_name.as_ptr(),
                file.handle,
                parent_view.handle,
                &mut BNCustomBinaryView {
                    context: leaked_view as *mut CustomBinaryViewContext<C> as *mut _,
                    init: Some(cb_init::<C>),
                    freeObject: Some(cb_free_object::<C>),
                    externalRefTaken: None,
                    externalRefReleased: None,
                    read: Some(cb_read::<C>),
                    write: Some(cb_write::<C>),
                    insert: Some(cb_insert::<C>),
                    remove: Some(cb_remove::<C>),
                    getModification: Some(cb_modification::<C>),
                    isValidOffset: Some(cb_offset_valid::<C>),
                    isOffsetReadable: Some(cb_offset_readable::<C>),
                    isOffsetWritable: Some(cb_offset_writable::<C>),
                    isOffsetExecutable: Some(cb_offset_executable::<C>),
                    isOffsetBackedByFile: Some(cb_offset_backed_by_file::<C>),
                    getNextValidOffset: Some(cb_next_valid_offset::<C>),
                    getStart: Some(cb_start::<C>),
                    getLength: Some(cb_length::<C>),
                    getEntryPoint: Some(cb_entry_point::<C>),
                    isExecutable: Some(cb_executable::<C>),
                    getDefaultEndianness: Some(cb_endianness::<C>),
                    isRelocatable: Some(cb_relocatable::<C>),
                    getAddressSize: Some(cb_address_size::<C>),
                    save: Some(cb_save::<C>),
                    onAfterSnapshotDataApplied: Some(cb_on_after_snapshot_data_applied::<C>),
                },
            )
        };
        if handle.is_null() {
            // We need to free the custom context manually.
            let _ = unsafe { Box::from_raw(leaked_view) };
            return Err(());
        }
        leaked_view.core_view = unsafe { MaybeUninit::new(BinaryView::from_raw(handle)) };
        unsafe { Ok(Ref::new(Self { handle })) }
    }

    /// Construct the raw binary view from the given metadata.
    ///
    /// Before calling this, make sure you have a valid file path set for the [`FileMetadata`]. It is
    /// required that the [`FileMetadata::file_path`] exist in the local filesystem.
    pub fn from_metadata(meta: &FileMetadata) -> Result<Ref<Self>, ()> {
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
    pub fn from_path(meta: &FileMetadata, file_path: impl AsRef<Path>) -> Result<Ref<Self>, ()> {
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
    ) -> Result<Ref<Self>, ()> {
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
    /// WARNING: Currently, there is a possibility to deadlock if the analysis has queued up a main thread action
    /// that tries to take the [`FileMetadata`] lock of the current view and is executed while we
    /// are executing in this function.
    ///
    /// To avoid the above issue, use [`crate::main_thread::execute_on_main_thread_and_wait`] to verify there
    /// are no queued up main thread actions.
    pub fn save_to_path(&self, file_path: impl AsRef<Path>) -> bool {
        let file = file_path.as_ref().to_cstr();
        unsafe { BNSaveToFilename(self.handle, file.as_ptr() as *mut _) }
    }

    /// Save the original binary file to the provided [`FileAccessor`] along with any modifications.
    ///
    /// WARNING: Currently, there is a possibility to deadlock if the analysis has queued up a main thread action
    /// that tries to take the [`FileMetadata`] lock of the current view and is executed while we
    /// are executing in this function.
    ///
    /// To avoid the above issue, use [`crate::main_thread::execute_on_main_thread_and_wait`] to verify there
    /// are no queued up main thread actions.
    pub fn save_to_accessor<A: Accessor>(&self, file: &mut FileAccessor<A>) -> bool {
        unsafe { BNSaveToFile(self.handle, &mut file.raw) }
    }

    pub fn file(&self) -> Ref<FileMetadata> {
        unsafe {
            let raw = BNGetFileForView(self.handle);
            FileMetadata::ref_from_raw(raw)
        }
    }

    pub fn parent_view(&self) -> Option<Ref<BinaryView>> {
        let raw_view_ptr = unsafe { BNGetParentView(self.handle) };
        match raw_view_ptr.is_null() {
            false => Some(unsafe { BinaryView::ref_from_raw(raw_view_ptr) }),
            true => None,
        }
    }

    pub fn raw_view(&self) -> Option<Ref<BinaryView>> {
        self.file().view_of_type("Raw")
    }

    pub fn view_type(&self) -> String {
        let ptr: *mut c_char = unsafe { BNGetViewType(self.handle) };
        unsafe { BnString::into_string(ptr) }
    }

    /// Reads up to `len` bytes from address `offset`
    pub fn read_vec(&self, offset: u64, len: usize) -> Vec<u8> {
        let mut ret = vec![0; len];
        let size = self.read(&mut ret, offset);
        ret.truncate(size);
        ret
    }

    /// Appends up to `len` bytes from address `offset` into `dest`
    pub fn read_into_vec(&self, dest: &mut Vec<u8>, offset: u64, len: usize) -> usize {
        let starting_len = dest.len();
        dest.resize(starting_len + len, 0);
        let read_size = self.read(&mut dest[starting_len..], offset);
        dest.truncate(starting_len + read_size);
        read_size
    }

    /// Reads up to `len` bytes from the address `offset` returning a `CString` if available.
    pub fn read_c_string_at(&self, offset: u64, len: usize) -> Option<CString> {
        let mut buf = vec![0; len];
        let size = self.read(&mut buf, offset);
        let string = CString::new(buf[..size].to_vec()).ok()?;
        Some(string)
    }

    /// Reads up to `len` bytes from the address `offset` returning a `String` if available.
    pub fn read_utf8_string_at(&self, offset: u64, len: usize) -> Option<String> {
        let mut buf = vec![0; len];
        let size = self.read(&mut buf, offset);
        let string = String::from_utf8(buf[..size].to_vec()).ok()?;
        Some(string)
    }

    /// Search the view using the query options.
    ///
    /// In the `on_match` callback return `false` to stop searching.
    pub fn search<C: FnMut(u64, &DataBuffer) -> bool>(
        &self,
        query: &SearchQuery,
        on_match: C,
    ) -> bool {
        self.search_with_progress(query, on_match, NoProgressCallback)
    }

    /// Search the view using the query options.
    ///
    /// In the `on_match` callback return `false` to stop searching.
    pub fn search_with_progress<P: ProgressCallback, C: FnMut(u64, &DataBuffer) -> bool>(
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
                self.handle,
                query.as_ptr(),
                &mut progress as *mut P as *mut c_void,
                Some(P::cb_progress_callback),
                &mut on_match as *const C as *mut c_void,
                Some(cb_on_match::<C>),
            )
        }
    }

    pub fn find_next_data(&self, start: u64, end: u64, data: &DataBuffer) -> Option<u64> {
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
    pub fn find_next_data_with_opts<P: ProgressCallback>(
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
                self.handle,
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

    pub fn find_next_constant(
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
    pub fn find_next_constant_with_opts<P: ProgressCallback>(
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
                self.handle,
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

    pub fn find_next_text(
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
    pub fn find_next_text_with_opts<P: ProgressCallback>(
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
                self.handle,
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

    pub fn notify_data_written(&self, offset: u64, len: usize) {
        unsafe {
            BNNotifyDataWritten(self.handle, offset, len);
        }
    }

    pub fn notify_data_inserted(&self, offset: u64, len: usize) {
        unsafe {
            BNNotifyDataInserted(self.handle, offset, len);
        }
    }

    pub fn notify_data_removed(&self, offset: u64, len: usize) {
        unsafe {
            BNNotifyDataRemoved(self.handle, offset, len as u64);
        }
    }

    /// Consults the [`Section`]'s current [`crate::section::Semantics`] to determine if the
    /// offset has code semantics.
    pub fn offset_has_code_semantics(&self, offset: u64) -> bool {
        unsafe { BNIsOffsetCodeSemantics(self.handle, offset) }
    }

    /// Check if the offset is within a [`Section`] with [`crate::section::Semantics::External`].
    pub fn offset_has_extern_semantics(&self, offset: u64) -> bool {
        unsafe { BNIsOffsetExternSemantics(self.handle, offset) }
    }

    /// Consults the [`Section`]'s current [`crate::section::Semantics`] to determine if the
    /// offset has writable semantics.
    pub fn offset_has_writable_semantics(&self, offset: u64) -> bool {
        unsafe { BNIsOffsetWritableSemantics(self.handle, offset) }
    }

    /// Consults the [`Section`]'s current [`crate::section::Semantics`] to determine if the
    /// offset has read only semantics.
    pub fn offset_has_read_only_semantics(&self, offset: u64) -> bool {
        unsafe { BNIsOffsetReadOnlySemantics(self.handle, offset) }
    }

    pub fn image_base(&self) -> u64 {
        unsafe { BNGetImageBase(self.handle) }
    }

    pub fn original_image_base(&self) -> u64 {
        unsafe { BNGetOriginalImageBase(self.handle) }
    }

    pub fn set_original_image_base(&self, image_base: u64) {
        unsafe { BNSetOriginalImageBase(self.handle, image_base) }
    }

    /// The highest address in the view.
    pub fn end(&self) -> u64 {
        unsafe { BNGetEndOffset(self.handle) }
    }

    pub fn add_analysis_option(&self, name: &str) {
        let name = name.to_cstr();
        unsafe { BNAddAnalysisOption(self.handle, name.as_ptr()) }
    }

    pub fn has_initial_analysis(&self) -> bool {
        unsafe { BNHasInitialAnalysis(self.handle) }
    }

    pub fn set_analysis_hold(&self, enable: bool) {
        unsafe { BNSetAnalysisHold(self.handle, enable) }
    }

    /// Runs the analysis pipeline, analyzing any data that has been marked for updates.
    ///
    /// You can explicitly mark a function to be updated with:
    /// - [`Function::mark_updates_required`]
    /// - [`Function::mark_caller_updates_required`]
    ///
    /// NOTE: This is a **non-blocking** call, use [`BinaryView::update_analysis_and_wait`] if you
    /// require analysis to have completed before moving on.
    pub fn update_analysis(&self) {
        unsafe {
            BNUpdateAnalysis(self.handle);
        }
    }

    /// Runs the analysis pipeline, analyzing any data that has been marked for updates.
    ///
    /// You can explicitly mark a function to be updated with:
    /// - [`Function::mark_updates_required`]
    /// - [`Function::mark_caller_updates_required`]
    ///
    /// NOTE: This is a **blocking** call, use [`BinaryView::update_analysis`] if you do not
    /// need to wait for the analysis update to finish.
    pub fn update_analysis_and_wait(&self) {
        unsafe {
            BNUpdateAnalysisAndWait(self.handle);
        }
    }

    /// Causes **all** functions to be reanalyzed.
    ///
    /// Use [`BinaryView::update_analysis`] or [`BinaryView::update_analysis_and_wait`] instead
    /// if you want to incrementally update analysis.
    ///
    /// NOTE: This function does not wait for the analysis to finish.
    pub fn reanalyze(&self) {
        unsafe {
            BNReanalyzeAllFunctions(self.handle);
        }
    }

    pub fn abort_analysis(&self) {
        unsafe { BNAbortAnalysis(self.handle) }
    }

    pub fn analysis_is_aborted(&self) -> bool {
        unsafe { BNAnalysisIsAborted(self.handle) }
    }

    pub fn workflow(&self) -> Ref<Workflow> {
        unsafe {
            let raw_ptr = BNGetWorkflowForBinaryView(self.handle);
            let nonnull = NonNull::new(raw_ptr).expect("All views must have a workflow");
            Workflow::ref_from_raw(nonnull)
        }
    }

    pub fn analysis_info(&self) -> AnalysisInfo {
        let info_ptr = unsafe { BNGetAnalysisInfo(self.handle) };
        assert!(!info_ptr.is_null());
        let info = unsafe { *info_ptr };
        let active_infos = unsafe { std::slice::from_raw_parts(info.activeInfo, info.count) };

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

    pub fn analysis_progress(&self) -> AnalysisProgress {
        let progress_raw = unsafe { BNGetAnalysisProgress(self.handle) };
        AnalysisProgress::from(progress_raw)
    }

    pub fn default_arch(&self) -> Option<CoreArchitecture> {
        unsafe {
            let raw = BNGetDefaultArchitecture(self.handle);

            if raw.is_null() {
                return None;
            }

            Some(CoreArchitecture::from_raw(raw))
        }
    }

    pub fn set_default_arch<A: Architecture>(&self, arch: &A) {
        unsafe {
            BNSetDefaultArchitecture(self.handle, arch.as_ref().handle);
        }
    }

    pub fn default_platform(&self) -> Option<Ref<Platform>> {
        unsafe {
            let raw = BNGetDefaultPlatform(self.handle);

            if raw.is_null() {
                return None;
            }

            Some(Platform::ref_from_raw(raw))
        }
    }

    pub fn set_default_platform(&self, plat: &Platform) {
        unsafe {
            BNSetDefaultPlatform(self.handle, plat.handle);
        }
    }

    pub fn base_address_detection(&self) -> Option<BaseAddressDetection> {
        unsafe {
            let handle = BNCreateBaseAddressDetection(self.handle);
            NonNull::new(handle).map(|base| BaseAddressDetection::from_raw(base))
        }
    }

    pub fn instruction_len<A: Architecture>(&self, arch: &A, addr: u64) -> Option<usize> {
        unsafe {
            let size = BNGetInstructionLength(self.handle, arch.as_ref().handle, addr);

            if size > 0 {
                Some(size)
            } else {
                None
            }
        }
    }

    pub fn symbol_by_address(&self, addr: u64) -> Option<Ref<Symbol>> {
        unsafe {
            let raw_sym_ptr = BNGetSymbolByAddress(self.handle, addr, std::ptr::null_mut());
            match raw_sym_ptr.is_null() {
                false => Some(Symbol::ref_from_raw(raw_sym_ptr)),
                true => None,
            }
        }
    }

    pub fn symbol_by_raw_name(&self, raw_name: impl IntoCStr) -> Option<Ref<Symbol>> {
        let raw_name = raw_name.to_cstr();

        unsafe {
            let raw_sym_ptr =
                BNGetSymbolByRawName(self.handle, raw_name.as_ptr(), std::ptr::null_mut());
            match raw_sym_ptr.is_null() {
                false => Some(Symbol::ref_from_raw(raw_sym_ptr)),
                true => None,
            }
        }
    }

    pub fn symbols(&self) -> Array<Symbol> {
        unsafe {
            let mut count = 0;
            let handles = BNGetSymbols(self.handle, &mut count, std::ptr::null_mut());

            Array::new(handles, count, ())
        }
    }

    pub fn symbols_by_name(&self, name: impl IntoCStr) -> Array<Symbol> {
        let raw_name = name.to_cstr();

        unsafe {
            let mut count = 0;
            let handles = BNGetSymbolsByName(
                self.handle,
                raw_name.as_ptr(),
                &mut count,
                std::ptr::null_mut(),
            );

            Array::new(handles, count, ())
        }
    }

    pub fn symbols_in_range(&self, range: Range<u64>) -> Array<Symbol> {
        unsafe {
            let mut count = 0;
            let len = range.end.wrapping_sub(range.start);
            let handles = BNGetSymbolsInRange(
                self.handle,
                range.start,
                len,
                &mut count,
                std::ptr::null_mut(),
            );

            Array::new(handles, count, ())
        }
    }

    pub fn symbols_of_type(&self, ty: SymbolType) -> Array<Symbol> {
        unsafe {
            let mut count = 0;
            let handles =
                BNGetSymbolsOfType(self.handle, ty.into(), &mut count, std::ptr::null_mut());

            Array::new(handles, count, ())
        }
    }

    pub fn symbols_of_type_in_range(&self, ty: SymbolType, range: Range<u64>) -> Array<Symbol> {
        unsafe {
            let mut count = 0;
            let len = range.end.wrapping_sub(range.start);
            let handles = BNGetSymbolsOfTypeInRange(
                self.handle,
                ty.into(),
                range.start,
                len,
                &mut count,
                std::ptr::null_mut(),
            );

            Array::new(handles, count, ())
        }
    }

    pub fn define_auto_symbol(&self, sym: &Symbol) {
        unsafe {
            BNDefineAutoSymbol(self.handle, sym.handle);
        }
    }

    /// Defines the symbol as well as the analysis object associated with the given symbol type, such as
    /// the data variable for a [`SymbolType::Data`], or the function for a [`SymbolType::Function`].
    /// Returns the symbol, as it was applied to the binary view.
    pub fn define_auto_symbol_with_type<'a, T: Into<Option<&'a Type>>>(
        &self,
        sym: &Symbol,
        plat: &Platform,
        ty: T,
    ) -> Ref<Symbol> {
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
                self.handle,
                plat.handle,
                sym.handle,
                &mut type_with_conf,
            );
            // We should always get the symbol back as it is defined.
            debug_assert!(
                !raw_sym.is_null(),
                "BNDefineAutoSymbolAndVariableOrFunction should not return null"
            );
            Symbol::ref_from_raw(raw_sym)
        }
    }

    pub fn undefine_auto_symbol(&self, sym: &Symbol) {
        unsafe {
            BNUndefineAutoSymbol(self.handle, sym.handle);
        }
    }

    pub fn define_user_symbol(&self, sym: &Symbol) {
        unsafe {
            BNDefineUserSymbol(self.handle, sym.handle);
        }
    }

    pub fn undefine_user_symbol(&self, sym: &Symbol) {
        unsafe {
            BNUndefineUserSymbol(self.handle, sym.handle);
        }
    }

    pub fn data_variables(&self) -> Array<DataVariable> {
        unsafe {
            let mut count = 0;
            let vars = BNGetDataVariables(self.handle, &mut count);
            Array::new(vars, count, ())
        }
    }

    pub fn data_variable_at_address(&self, addr: u64) -> Option<DataVariable> {
        let mut dv = BNDataVariable::default();
        unsafe {
            if BNGetDataVariableAtAddress(self.handle, addr, &mut dv) {
                Some(DataVariable::from_owned_raw(dv))
            } else {
                None
            }
        }
    }

    pub fn define_auto_data_var<'a, T: Into<Conf<&'a Type>>>(&self, addr: u64, ty: T) {
        let mut owned_raw_ty = Conf::<&Type>::into_raw(ty.into());
        unsafe {
            BNDefineDataVariable(self.handle, addr, &mut owned_raw_ty);
        }
    }

    /// You likely would also like to call [`BinaryView::define_user_symbol`] to bind this data variable with a name
    pub fn define_user_data_var<'a, T: Into<Conf<&'a Type>>>(&self, addr: u64, ty: T) {
        let mut owned_raw_ty = Conf::<&Type>::into_raw(ty.into());
        unsafe {
            BNDefineUserDataVariable(self.handle, addr, &mut owned_raw_ty);
        }
    }

    pub fn undefine_auto_data_var(&self, addr: u64, blacklist: Option<bool>) {
        unsafe {
            BNUndefineDataVariable(self.handle, addr, blacklist.unwrap_or(true));
        }
    }

    pub fn undefine_user_data_var(&self, addr: u64) {
        unsafe {
            BNUndefineUserDataVariable(self.handle, addr);
        }
    }

    pub fn define_auto_type<T: Into<QualifiedName>>(
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
            BNDefineAnalysisType(self.handle, id_str, &mut raw_name, type_obj.handle)
        };
        QualifiedName::free_raw(raw_name);
        QualifiedName::from_owned_raw(name_handle)
    }

    pub fn define_auto_type_with_id<T: Into<QualifiedName>>(
        &self,
        name: T,
        id: &str,
        type_obj: &Type,
    ) -> QualifiedName {
        let mut raw_name = QualifiedName::into_raw(name.into());
        let id_str = id.to_cstr();
        let result_raw_name = unsafe {
            BNDefineAnalysisType(
                self.handle,
                id_str.as_ref().as_ptr() as *const _,
                &mut raw_name,
                type_obj.handle,
            )
        };
        QualifiedName::free_raw(raw_name);
        QualifiedName::from_owned_raw(result_raw_name)
    }

    pub fn define_user_type<T: Into<QualifiedName>>(&self, name: T, type_obj: &Type) {
        let mut raw_name = QualifiedName::into_raw(name.into());
        unsafe { BNDefineUserAnalysisType(self.handle, &mut raw_name, type_obj.handle) }
        QualifiedName::free_raw(raw_name);
    }

    pub fn define_auto_types<T, I>(
        &self,
        names_sources_and_types: T,
    ) -> HashMap<String, QualifiedName>
    where
        T: Iterator<Item = I>,
        I: Into<QualifiedNameTypeAndId>,
    {
        self.define_auto_types_with_progress(names_sources_and_types, NoProgressCallback)
    }

    pub fn define_auto_types_with_progress<T, I, P>(
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
                self.handle,
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

    pub fn define_user_types<T, I>(&self, names_and_types: T)
    where
        T: Iterator<Item = I>,
        I: Into<QualifiedNameAndType>,
    {
        self.define_user_types_with_progress(names_and_types, NoProgressCallback);
    }

    pub fn define_user_types_with_progress<T, I, P>(&self, names_and_types: T, mut progress: P)
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
                self.handle,
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

    pub fn undefine_auto_type(&self, id: &str) {
        let id_str = id.to_cstr();
        unsafe {
            BNUndefineAnalysisType(self.handle, id_str.as_ref().as_ptr() as *const _);
        }
    }

    pub fn undefine_user_type<T: Into<QualifiedName>>(&self, name: T) {
        let mut raw_name = QualifiedName::into_raw(name.into());
        unsafe { BNUndefineUserAnalysisType(self.handle, &mut raw_name) }
        QualifiedName::free_raw(raw_name);
    }

    pub fn types(&self) -> Array<QualifiedNameAndType> {
        unsafe {
            let mut count = 0usize;
            let types = BNGetAnalysisTypeList(self.handle, &mut count);
            Array::new(types, count, ())
        }
    }

    pub fn dependency_sorted_types(&self) -> Array<QualifiedNameAndType> {
        unsafe {
            let mut count = 0usize;
            let types = BNGetAnalysisDependencySortedTypeList(self.handle, &mut count);
            Array::new(types, count, ())
        }
    }

    pub fn type_by_name<T: Into<QualifiedName>>(&self, name: T) -> Option<Ref<Type>> {
        let mut raw_name = QualifiedName::into_raw(name.into());
        unsafe {
            let type_handle = BNGetAnalysisTypeByName(self.handle, &mut raw_name);
            QualifiedName::free_raw(raw_name);
            if type_handle.is_null() {
                return None;
            }
            Some(Type::ref_from_raw(type_handle))
        }
    }

    pub fn type_by_ref(&self, ref_: &NamedTypeReference) -> Option<Ref<Type>> {
        unsafe {
            let type_handle = BNGetAnalysisTypeByRef(self.handle, ref_.handle);
            if type_handle.is_null() {
                return None;
            }
            Some(Type::ref_from_raw(type_handle))
        }
    }

    pub fn type_by_id(&self, id: &str) -> Option<Ref<Type>> {
        let id_str = id.to_cstr();
        unsafe {
            let type_handle = BNGetAnalysisTypeById(self.handle, id_str.as_ptr());
            if type_handle.is_null() {
                return None;
            }
            Some(Type::ref_from_raw(type_handle))
        }
    }

    pub fn type_name_by_id(&self, id: &str) -> Option<QualifiedName> {
        let id_str = id.to_cstr();
        unsafe {
            let name_handle = BNGetAnalysisTypeNameById(self.handle, id_str.as_ptr());
            let name = QualifiedName::from_owned_raw(name_handle);
            // The core will return an empty qualified name if no type name was found.
            match name.items.is_empty() {
                true => None,
                false => Some(name),
            }
        }
    }

    pub fn type_id_by_name<T: Into<QualifiedName>>(&self, name: T) -> Option<String> {
        let mut raw_name = QualifiedName::into_raw(name.into());
        unsafe {
            let id_cstr = BNGetAnalysisTypeId(self.handle, &mut raw_name);
            QualifiedName::free_raw(raw_name);
            let id = BnString::into_string(id_cstr);
            match id.is_empty() {
                true => None,
                false => Some(id),
            }
        }
    }

    pub fn is_type_auto_defined<T: Into<QualifiedName>>(&self, name: T) -> bool {
        let mut raw_name = QualifiedName::into_raw(name.into());
        let result = unsafe { BNIsAnalysisTypeAutoDefined(self.handle, &mut raw_name) };
        QualifiedName::free_raw(raw_name);
        result
    }

    pub fn segments(&self) -> Array<Segment> {
        unsafe {
            let mut count = 0;
            let raw_segments = BNGetSegments(self.handle, &mut count);
            Array::new(raw_segments, count, ())
        }
    }

    pub fn segment_at(&self, addr: u64) -> Option<Ref<Segment>> {
        unsafe {
            let raw_seg = BNGetSegmentAt(self.handle, addr);
            match raw_seg.is_null() {
                false => Some(Segment::ref_from_raw(raw_seg)),
                true => None,
            }
        }
    }

    /// Adds a segment to the view.
    ///
    /// NOTE: Consider using [BinaryView::begin_bulk_add_segments] and [BinaryView::end_bulk_add_segments]
    /// if you plan on adding a number of segments all at once, to avoid unnecessary MemoryMap updates.
    pub fn add_segment(&self, segment: SegmentBuilder) {
        segment.create(self.as_ref());
    }

    // TODO: Replace with BulkModify guard.
    /// Start adding segments in bulk. Useful for adding large numbers of segments.
    ///
    /// After calling this any call to [BinaryView::add_segment] will be uncommitted until a call to
    /// [BinaryView::end_bulk_add_segments]
    ///
    /// If you wish to discard the uncommitted segments you can call [BinaryView::cancel_bulk_add_segments].
    ///
    /// NOTE: This **must** be paired with a later call to [BinaryView::end_bulk_add_segments] or
    /// [BinaryView::cancel_bulk_add_segments], otherwise segments added after this call will stay uncommitted.
    pub fn begin_bulk_add_segments(&self) {
        unsafe { BNBeginBulkAddSegments(self.handle) }
    }

    // TODO: Replace with BulkModify guard.
    /// Commit all auto and user segments that have been added since the call to [Self::begin_bulk_add_segments].
    ///
    /// NOTE: This **must** be paired with a prior call to [Self::begin_bulk_add_segments], otherwise this
    /// does nothing and segments are added individually.
    pub fn end_bulk_add_segments(&self) {
        unsafe { BNEndBulkAddSegments(self.handle) }
    }

    // TODO: Replace with BulkModify guard.
    /// Flushes the auto and user segments that have yet to be committed.
    ///
    /// This is to be used in conjunction with [Self::begin_bulk_add_segments]
    /// and [Self::end_bulk_add_segments], where the latter will commit the segments
    /// which have been added since [Self::begin_bulk_add_segments], this function
    /// will discard them so that they do not get added to the view.
    pub fn cancel_bulk_add_segments(&self) {
        unsafe { BNCancelBulkAddSegments(self.handle) }
    }

    pub fn add_section(&self, section: SectionBuilder) {
        section.create(self.as_ref());
    }

    pub fn remove_auto_section(&self, name: impl IntoCStr) {
        let raw_name = name.to_cstr();
        let raw_name_ptr = raw_name.as_ptr();
        unsafe {
            BNRemoveAutoSection(self.handle, raw_name_ptr);
        }
    }

    pub fn remove_user_section(&self, name: impl IntoCStr) {
        let raw_name = name.to_cstr();
        let raw_name_ptr = raw_name.as_ptr();
        unsafe {
            BNRemoveUserSection(self.handle, raw_name_ptr);
        }
    }

    pub fn section_by_name(&self, name: impl IntoCStr) -> Option<Ref<Section>> {
        unsafe {
            let raw_name = name.to_cstr();
            let name_ptr = raw_name.as_ptr();
            let raw_section_ptr = BNGetSectionByName(self.handle, name_ptr);
            match raw_section_ptr.is_null() {
                false => Some(Section::ref_from_raw(raw_section_ptr)),
                true => None,
            }
        }
    }

    pub fn sections(&self) -> Array<Section> {
        unsafe {
            let mut count = 0;
            let sections = BNGetSections(self.handle, &mut count);
            Array::new(sections, count, ())
        }
    }

    pub fn sections_at(&self, addr: u64) -> Array<Section> {
        unsafe {
            let mut count = 0;
            let sections = BNGetSectionsAt(self.handle, addr, &mut count);
            Array::new(sections, count, ())
        }
    }

    pub fn memory_map(&self) -> MemoryMap {
        MemoryMap::new(self.as_ref().to_owned())
    }

    /// Add an auto function at the given `address` with the views default platform.
    ///
    /// Use [`BinaryView::add_auto_function_with_platform`] if you wish to specify a platform.
    ///
    /// NOTE: The default platform **must** be set for this view!
    pub fn add_auto_function(&self, address: u64) -> Option<Ref<Function>> {
        let platform = self.default_platform()?;
        self.add_auto_function_with_platform(address, &platform)
    }

    /// Add an auto function at the given `address` with the `platform`.
    ///
    /// Use [`BinaryView::add_auto_function_ext`] if you wish to specify a function type.
    ///
    /// NOTE: If the view's default platform is not set, this will set it to `platform`.
    pub fn add_auto_function_with_platform(
        &self,
        address: u64,
        platform: &Platform,
    ) -> Option<Ref<Function>> {
        self.add_auto_function_ext(address, platform, None, false)
    }

    /// Add an auto function at the given `address` with the `platform` and function type.
    ///
    /// The `auto_discovered` flag is used to prevent or allow this created function to be deleted if
    /// it is never used (the function has no xrefs), if you are confident that this is a valid function
    /// set this to `false`.
    ///
    /// NOTE: If the view's default platform is not set, this will set it to `platform`.
    pub fn add_auto_function_ext(
        &self,
        address: u64,
        platform: &Platform,
        func_type: Option<&Type>,
        auto_discovered: bool,
    ) -> Option<Ref<Function>> {
        unsafe {
            let func_type = match func_type {
                Some(func_type) => func_type.handle,
                None => std::ptr::null_mut(),
            };

            let handle = BNAddFunctionForAnalysis(
                self.handle,
                platform.handle,
                address,
                auto_discovered,
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
    /// NOTE: Unlike [`BinaryView::remove_user_function`], this will NOT prohibit the function from
    /// being re-added in the future, use [`BinaryView::remove_user_function`] to blacklist the
    /// function from being automatically created.
    pub fn remove_auto_function(&self, func: &Function, update_refs: bool) {
        unsafe {
            BNRemoveAnalysisFunction(self.handle, func.handle, update_refs);
        }
    }

    /// Add a user function at the given `address` with the views default platform.
    ///
    /// Use [`BinaryView::add_user_function_with_platform`] if you wish to specify a platform.
    ///
    /// NOTE: The default platform **must** be set for this view!
    pub fn add_user_function(&self, addr: u64) -> Option<Ref<Function>> {
        let platform = self.default_platform()?;
        self.add_user_function_with_platform(addr, &platform)
    }

    /// Add an auto function at the given `address` with the `platform`.
    ///
    /// NOTE: If the view's default platform is not set, this will set it to `platform`.
    pub fn add_user_function_with_platform(
        &self,
        addr: u64,
        platform: &Platform,
    ) -> Option<Ref<Function>> {
        unsafe {
            let func = BNCreateUserFunction(self.handle, platform.handle, addr);
            if func.is_null() {
                return None;
            }
            Some(Function::ref_from_raw(func))
        }
    }

    /// Removes the function from the view and blacklists it from being created automatically.
    ///
    /// NOTE: If you call [`BinaryView::add_user_function`], it will override the blacklist.
    pub fn remove_user_function(&self, func: &Function) {
        unsafe { BNRemoveUserFunction(self.handle, func.handle) }
    }

    pub fn has_functions(&self) -> bool {
        unsafe { BNHasFunctions(self.handle) }
    }

    /// Add an entry point at the given `address` with the view's default platform.
    ///
    /// NOTE: The default platform **must** be set for this view!
    pub fn add_entry_point(&self, addr: u64) {
        if let Some(platform) = self.default_platform() {
            self.add_entry_point_with_platform(addr, &platform);
        }
    }

    /// Add an entry point at the given `address` with the `platform`.
    ///
    /// NOTE: If the view's default platform is not set, this will set it to `platform`.
    pub fn add_entry_point_with_platform(&self, addr: u64, platform: &Platform) {
        unsafe {
            BNAddEntryPointForAnalysis(self.handle, platform.handle, addr);
        }
    }

    pub fn entry_point_function(&self) -> Option<Ref<Function>> {
        unsafe {
            let raw_func_ptr = BNGetAnalysisEntryPoint(self.handle);
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
    pub fn entry_point_functions(&self) -> Array<Function> {
        unsafe {
            let mut count = 0;
            let functions = BNGetAllEntryFunctions(self.handle, &mut count);

            Array::new(functions, count, ())
        }
    }

    pub fn functions(&self) -> Array<Function> {
        unsafe {
            let mut count = 0;
            let functions = BNGetAnalysisFunctionList(self.handle, &mut count);

            Array::new(functions, count, ())
        }
    }

    /// List of functions *starting* at `addr`
    pub fn functions_at(&self, addr: u64) -> Array<Function> {
        unsafe {
            let mut count = 0;
            let functions = BNGetAnalysisFunctionsForAddress(self.handle, addr, &mut count);

            Array::new(functions, count, ())
        }
    }

    /// List of functions containing `addr`
    pub fn functions_containing(&self, addr: u64) -> Array<Function> {
        unsafe {
            let mut count = 0;
            let functions = BNGetAnalysisFunctionsContainingAddress(self.handle, addr, &mut count);

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
    pub fn functions_by_name(
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

    pub fn function_at(&self, platform: &Platform, addr: u64) -> Option<Ref<Function>> {
        unsafe {
            let raw_func_ptr = BNGetAnalysisFunction(self.handle, platform.handle, addr);
            match raw_func_ptr.is_null() {
                false => Some(Function::ref_from_raw(raw_func_ptr)),
                true => None,
            }
        }
    }

    pub fn function_start_before(&self, addr: u64) -> u64 {
        unsafe { BNGetPreviousFunctionStartBeforeAddress(self.handle, addr) }
    }

    pub fn function_start_after(&self, addr: u64) -> u64 {
        unsafe { BNGetNextFunctionStartAfterAddress(self.handle, addr) }
    }

    pub fn basic_blocks_containing(&self, addr: u64) -> Array<BasicBlock<NativeBlock>> {
        unsafe {
            let mut count = 0;
            let blocks = BNGetBasicBlocksForAddress(self.handle, addr, &mut count);
            Array::new(blocks, count, NativeBlock::new())
        }
    }

    pub fn basic_blocks_starting_at(&self, addr: u64) -> Array<BasicBlock<NativeBlock>> {
        unsafe {
            let mut count = 0;
            let blocks = BNGetBasicBlocksStartingAtAddress(self.handle, addr, &mut count);
            Array::new(blocks, count, NativeBlock::new())
        }
    }

    pub fn is_new_auto_function_analysis_suppressed(&self) -> bool {
        unsafe { BNGetNewAutoFunctionAnalysisSuppressed(self.handle) }
    }

    pub fn set_new_auto_function_analysis_suppressed(&self, suppress: bool) {
        unsafe {
            BNSetNewAutoFunctionAnalysisSuppressed(self.handle, suppress);
        }
    }

    // TODO: Should this instead be implemented on [`Function`] considering `src_func`? `Location` is local to the source function.
    pub fn should_skip_target_analysis(
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
                self.handle,
                &mut src_loc.into(),
                src_func.handle,
                src_end,
                &mut target.into(),
            )
        }
    }

    pub fn read_buffer(&self, offset: u64, len: usize) -> Option<DataBuffer> {
        let read_buffer = unsafe { BNReadViewBuffer(self.handle, offset, len) };
        if read_buffer.is_null() {
            None
        } else {
            Some(DataBuffer::from_raw(read_buffer))
        }
    }

    pub fn debug_info(&self) -> Ref<DebugInfo> {
        unsafe { DebugInfo::ref_from_raw(BNGetDebugInfo(self.handle)) }
    }

    pub fn set_debug_info(&self, debug_info: &DebugInfo) {
        unsafe { BNSetDebugInfo(self.handle, debug_info.handle) }
    }

    pub fn apply_debug_info(&self, debug_info: &DebugInfo) {
        unsafe { BNApplyDebugInfo(self.handle, debug_info.handle) }
    }

    pub fn show_plaintext_report(&self, title: &str, plaintext: &str) {
        let title = title.to_cstr();
        let plaintext = plaintext.to_cstr();
        unsafe {
            BNShowPlainTextReport(
                self.handle,
                title.as_ref().as_ptr() as *mut _,
                plaintext.as_ref().as_ptr() as *mut _,
            )
        }
    }

    pub fn show_markdown_report(&self, title: &str, contents: &str, plaintext: &str) {
        let title = title.to_cstr();
        let contents = contents.to_cstr();
        let plaintext = plaintext.to_cstr();
        unsafe {
            BNShowMarkdownReport(
                self.handle,
                title.as_ref().as_ptr() as *mut _,
                contents.as_ref().as_ptr() as *mut _,
                plaintext.as_ref().as_ptr() as *mut _,
            )
        }
    }

    pub fn show_html_report(&self, title: &str, contents: &str, plaintext: &str) {
        let title = title.to_cstr();
        let contents = contents.to_cstr();
        let plaintext = plaintext.to_cstr();
        unsafe {
            BNShowHTMLReport(
                self.handle,
                title.as_ref().as_ptr() as *mut _,
                contents.as_ref().as_ptr() as *mut _,
                plaintext.as_ref().as_ptr() as *mut _,
            )
        }
    }

    pub fn show_graph_report(&self, raw_name: &str, graph: &FlowGraph) {
        let raw_name = raw_name.to_cstr();
        unsafe {
            BNShowGraphReport(self.handle, raw_name.as_ptr(), graph.handle);
        }
    }

    pub fn load_settings(&self, view_type_name: &str) -> Option<Ref<Settings>> {
        let view_type_name = view_type_name.to_cstr();
        let settings_handle =
            unsafe { BNBinaryViewGetLoadSettings(self.handle, view_type_name.as_ptr()) };
        match settings_handle.is_null() {
            true => None,
            false => Some(unsafe { Settings::ref_from_raw(settings_handle) }),
        }
    }

    pub fn set_load_settings(&self, view_type_name: &str, settings: &Settings) {
        let view_type_name = view_type_name.to_cstr();

        unsafe {
            BNBinaryViewSetLoadSettings(self.handle, view_type_name.as_ptr(), settings.handle)
        };
    }

    /// Creates a new [`TagType`] and adds it to the view.
    ///
    /// # Arguments
    /// * `name` - the name for the tag
    /// * `icon` - the icon (recommended 1 emoji or 2 chars) for the tag
    pub fn create_tag_type(&self, name: &str, icon: &str) -> Ref<TagType> {
        let tag_type = TagType::create(self, name, icon);
        unsafe {
            BNAddTagType(self.handle, tag_type.handle);
        }
        tag_type
    }

    /// Removes a [TagType] and all tags that use it
    pub fn remove_tag_type(&self, tag_type: &TagType) {
        unsafe { BNRemoveTagType(self.handle, tag_type.handle) }
    }

    /// Get a tag type by its name.
    pub fn tag_type_by_name(&self, name: &str) -> Option<Ref<TagType>> {
        let name = name.to_cstr();
        unsafe {
            let handle = BNGetTagType(self.handle, name.as_ptr());
            if handle.is_null() {
                return None;
            }
            Some(TagType::ref_from_raw(handle))
        }
    }

    /// Get all tags in all scopes
    pub fn tags_all_scopes(&self) -> Array<TagReference> {
        let mut count = 0;
        unsafe {
            let tag_references = BNGetAllTagReferences(self.handle, &mut count);
            Array::new(tag_references, count, ())
        }
    }

    /// Get all tag types present for the view
    pub fn tag_types(&self) -> Array<TagType> {
        let mut count = 0;
        unsafe {
            let tag_types_raw = BNGetTagTypes(self.handle, &mut count);
            Array::new(tag_types_raw, count, ())
        }
    }

    /// Get all tag references of a specific type
    pub fn tags_by_type(&self, tag_type: &TagType) -> Array<TagReference> {
        let mut count = 0;
        unsafe {
            let tag_references =
                BNGetAllTagReferencesOfType(self.handle, tag_type.handle, &mut count);
            Array::new(tag_references, count, ())
        }
    }

    /// Get a tag by its id.
    ///
    /// Note this does not tell you anything about where it is used.
    pub fn tag_by_id(&self, id: &str) -> Option<Ref<Tag>> {
        let id = id.to_cstr();
        unsafe {
            let handle = BNGetTag(self.handle, id.as_ptr());
            if handle.is_null() {
                return None;
            }
            Some(Tag::ref_from_raw(handle))
        }
    }

    /// Creates and adds a tag to an address
    ///
    /// User tag creations will be added to the undo buffer
    pub fn add_tag(&self, addr: u64, t: &TagType, data: &str, user: bool) {
        let tag = Tag::new(t, data);

        unsafe { BNAddTag(self.handle, tag.handle, user) }

        if user {
            unsafe { BNAddUserDataTag(self.handle, addr, tag.handle) }
        } else {
            unsafe { BNAddAutoDataTag(self.handle, addr, tag.handle) }
        }
    }

    /// removes a Tag object at a data address.
    pub fn remove_auto_data_tag(&self, addr: u64, tag: &Tag) {
        unsafe { BNRemoveAutoDataTag(self.handle, addr, tag.handle) }
    }

    /// removes a Tag object at a data address.
    /// Since this removes a user tag, it will be added to the current undo buffer.
    pub fn remove_user_data_tag(&self, addr: u64, tag: &Tag) {
        unsafe { BNRemoveUserDataTag(self.handle, addr, tag.handle) }
    }

    /// Retrieves a list of comment addresses, the comments themselves can then be queried with
    /// the function [`BinaryView::comment_at`].
    ///
    /// If you would rather retrieve the contents of **all** comments at once you can do so with
    /// the helper function [`BinaryView::comments`].
    pub fn comment_references(&self) -> Array<CommentReference> {
        let mut count = 0;
        let addresses_raw = unsafe { BNGetGlobalCommentedAddresses(self.handle, &mut count) };
        unsafe { Array::new(addresses_raw, count, ()) }
    }

    /// Retrieves a map of comment addresses to their contents.
    ///
    /// This is a helper function that eagerly reads the contents of all comments within the
    /// view, use [`BinaryView::comment_references`] instead if you do not wish to read all the comments.
    pub fn comments(&self) -> BTreeMap<u64, String> {
        self.comment_references()
            .iter()
            .filter_map(|cmt_ref| Some((cmt_ref.start, self.comment_at(cmt_ref.start)?)))
            .collect()
    }

    pub fn comment_at(&self, addr: u64) -> Option<String> {
        unsafe {
            let comment_raw = BNGetGlobalCommentForAddress(self.handle, addr);
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
    pub fn set_comment_at(&self, addr: u64, comment: &str) {
        let comment_raw = comment.to_cstr();
        unsafe { BNSetGlobalCommentForAddress(self.handle, addr, comment_raw.as_ptr()) }
    }

    /// Retrieves a list of the next disassembly lines.
    ///
    /// Retrieves an [`Array`] over [`LinearDisassemblyLine`] objects for the
    /// next disassembly lines, and updates the [`LinearViewCursor`] passed in. This function can be called
    /// repeatedly to get more lines of linear disassembly.
    ///
    /// # Arguments
    /// * `pos` - Position to retrieve linear disassembly lines from
    pub fn get_next_linear_disassembly_lines(
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
    pub fn get_previous_linear_disassembly_lines(
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

    pub fn query_metadata(&self, key: &str) -> Option<Ref<Metadata>> {
        let key = key.to_cstr();
        let value: *mut BNMetadata =
            unsafe { BNBinaryViewQueryMetadata(self.handle, key.as_ptr()) };
        if value.is_null() {
            None
        } else {
            Some(unsafe { Metadata::ref_from_raw(value) })
        }
    }

    /// Retrieve the metadata as the type `T`.
    ///
    /// Fails if the metadata does not exist, or if the metadata failed to coerce to type `T`.
    pub fn get_metadata<T>(&self, key: &str) -> Option<T>
    where
        T: for<'a> TryFrom<&'a Metadata>,
    {
        self.query_metadata(key)
            .and_then(|md| T::try_from(md.as_ref()).ok())
    }

    pub fn store_metadata<V>(&self, key: &str, value: V, is_auto: bool)
    where
        V: Into<Ref<Metadata>>,
    {
        let md = value.into();
        let key = key.to_cstr();
        unsafe {
            BNBinaryViewStoreMetadata(self.handle, key.as_ptr(), md.as_ref().handle, is_auto)
        };
    }

    pub fn remove_metadata(&self, key: &str) {
        let key = key.to_cstr();
        unsafe { BNBinaryViewRemoveMetadata(self.handle, key.as_ptr()) };
    }

    /// Retrieves a list of [CodeReference]s pointing to a given address.
    pub fn code_refs_to_addr(&self, addr: u64) -> Array<CodeReference> {
        unsafe {
            let mut count = 0;
            let handle = BNGetCodeReferences(self.handle, addr, &mut count, false, 0);
            Array::new(handle, count, ())
        }
    }

    /// Retrieves a list of [CodeReference]s pointing into a given [Range].
    pub fn code_refs_into_range(&self, range: Range<u64>) -> Array<CodeReference> {
        unsafe {
            let mut count = 0;
            let handle = BNGetCodeReferencesInRange(
                self.handle,
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
    pub fn code_refs_from_addr(&self, addr: u64, func: Option<&Function>) -> Vec<u64> {
        unsafe {
            let mut count = 0;
            let code_ref =
                CodeReference::new(addr, func.map(|f| f.to_owned()), func.map(|f| f.arch()));
            let mut raw_code_ref = CodeReference::into_owned_raw(&code_ref);
            let addresses = BNGetCodeReferencesFrom(self.handle, &mut raw_code_ref, &mut count);
            let res = std::slice::from_raw_parts(addresses, count).to_vec();
            BNFreeAddressList(addresses);
            res
        }
    }

    /// Retrieves a list of [DataReference]s pointing to a given address.
    pub fn data_refs_to_addr(&self, addr: u64) -> Array<DataReference> {
        unsafe {
            let mut count = 0;
            let handle = BNGetDataReferences(self.handle, addr, &mut count, false, 0);
            Array::new(handle, count, ())
        }
    }

    /// Retrieves a list of [DataReference]s pointing into a given [Range].
    pub fn data_refs_into_range(&self, range: Range<u64>) -> Array<DataReference> {
        unsafe {
            let mut count = 0;
            let handle = BNGetDataReferencesInRange(
                self.handle,
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
    pub fn data_refs_from_addr(&self, addr: u64) -> Array<DataReference> {
        unsafe {
            let mut count = 0;
            let handle = BNGetDataReferencesFrom(self.handle, addr, &mut count);
            Array::new(handle, count, ())
        }
    }

    /// Retrieves a list of [CodeReference]s for locations in code that use a given named type.
    pub fn code_refs_using_type_name<T: Into<QualifiedName>>(
        &self,
        name: T,
    ) -> Array<CodeReference> {
        let mut raw_name = QualifiedName::into_raw(name.into());
        unsafe {
            let mut count = 0;
            let handle =
                BNGetCodeReferencesForType(self.handle, &mut raw_name, &mut count, false, 0);
            QualifiedName::free_raw(raw_name);
            Array::new(handle, count, ())
        }
    }

    /// Retrieves a list of [DataReference]s for locations in data that use a given named type.
    pub fn data_refs_using_type_name<T: Into<QualifiedName>>(
        &self,
        name: T,
    ) -> Array<DataReference> {
        let mut raw_name = QualifiedName::into_raw(name.into());
        unsafe {
            let mut count = 0;
            let handle =
                BNGetDataReferencesForType(self.handle, &mut raw_name, &mut count, false, 0);
            QualifiedName::free_raw(raw_name);
            Array::new(handle, count, ())
        }
    }

    pub fn relocations_at(&self, addr: u64) -> Array<Relocation> {
        unsafe {
            let mut count = 0;
            let handle = BNGetRelocationsAt(self.handle, addr, &mut count);
            Array::new(handle, count, ())
        }
    }

    pub fn relocation_ranges(&self) -> Vec<Range<u64>> {
        let ranges = unsafe {
            let mut count = 0;
            let reloc_ranges_ptr = BNGetRelocationRanges(self.handle, &mut count);
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

    pub fn component_by_guid(&self, guid: &str) -> Option<Ref<Component>> {
        let name = guid.to_cstr();
        let result = unsafe { BNGetComponentByGuid(self.handle, name.as_ptr()) };
        NonNull::new(result).map(|h| unsafe { Component::ref_from_raw(h) })
    }

    pub fn root_component(&self) -> Option<Ref<Component>> {
        let result = unsafe { BNGetRootComponent(self.handle) };
        NonNull::new(result).map(|h| unsafe { Component::ref_from_raw(h) })
    }

    pub fn component_by_path(&self, path: &str) -> Option<Ref<Component>> {
        let path = path.to_cstr();
        let result = unsafe { BNGetComponentByPath(self.handle, path.as_ptr()) };
        NonNull::new(result).map(|h| unsafe { Component::ref_from_raw(h) })
    }

    pub fn remove_component(&self, component: &Component) -> bool {
        unsafe { BNRemoveComponent(self.handle, component.handle.as_ptr()) }
    }

    pub fn remove_component_by_guid(&self, guid: &str) -> bool {
        let path = guid.to_cstr();
        unsafe { BNRemoveComponentByGuid(self.handle, path.as_ptr()) }
    }

    pub fn data_variable_parent_components(
        &self,
        data_variable: &DataVariable,
    ) -> Array<Component> {
        let mut count = 0;
        let result = unsafe {
            BNGetDataVariableParentComponents(self.handle, data_variable.address, &mut count)
        };
        unsafe { Array::new(result, count, ()) }
    }

    pub fn external_libraries(&self) -> Array<ExternalLibrary> {
        let mut count = 0;
        let result = unsafe { BNBinaryViewGetExternalLibraries(self.handle, &mut count) };
        unsafe { Array::new(result, count, ()) }
    }

    pub fn external_library(&self, name: &str) -> Option<Ref<ExternalLibrary>> {
        let name_ptr = name.to_cstr();
        let result = unsafe { BNBinaryViewGetExternalLibrary(self.handle, name_ptr.as_ptr()) };
        let result_ptr = NonNull::new(result)?;
        Some(unsafe { ExternalLibrary::ref_from_raw(result_ptr) })
    }

    pub fn remove_external_library(&self, name: &str) {
        let name_ptr = name.to_cstr();
        unsafe { BNBinaryViewRemoveExternalLibrary(self.handle, name_ptr.as_ptr()) };
    }

    pub fn add_external_library(
        &self,
        name: &str,
        backing_file: Option<&ProjectFile>,
        auto: bool,
    ) -> Option<Ref<ExternalLibrary>> {
        let name_ptr = name.to_cstr();
        let result = unsafe {
            BNBinaryViewAddExternalLibrary(
                self.handle,
                name_ptr.as_ptr(),
                backing_file
                    .map(|b| b.handle.as_ptr())
                    .unwrap_or(std::ptr::null_mut()),
                auto,
            )
        };
        NonNull::new(result).map(|h| unsafe { ExternalLibrary::ref_from_raw(h) })
    }

    pub fn external_locations(&self) -> Array<ExternalLocation> {
        let mut count = 0;
        let result = unsafe { BNBinaryViewGetExternalLocations(self.handle, &mut count) };
        unsafe { Array::new(result, count, ()) }
    }

    pub fn external_location_from_symbol(&self, symbol: &Symbol) -> Option<Ref<ExternalLocation>> {
        let result = unsafe { BNBinaryViewGetExternalLocation(self.handle, symbol.handle) };
        let result_ptr = NonNull::new(result)?;
        Some(unsafe { ExternalLocation::ref_from_raw(result_ptr) })
    }

    pub fn remove_external_location(&self, location: &ExternalLocation) {
        self.remove_external_location_from_symbol(&location.source_symbol())
    }

    pub fn remove_external_location_from_symbol(&self, symbol: &Symbol) {
        unsafe { BNBinaryViewRemoveExternalLocation(self.handle, symbol.handle) };
    }

    // TODO: This is awful, rewrite this.
    pub fn add_external_location(
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
                self.handle,
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
    pub fn type_container(&self) -> TypeContainer {
        let type_container_ptr = NonNull::new(unsafe { BNGetAnalysisTypeContainer(self.handle) });
        // NOTE: I have no idea how this isn't a UAF, see the note in `TypeContainer::from_raw`
        unsafe { TypeContainer::from_raw(type_container_ptr.unwrap()) }
    }

    /// Type container for user types in the Binary View.
    pub fn user_type_container(&self) -> TypeContainer {
        let type_container_ptr =
            NonNull::new(unsafe { BNGetAnalysisUserTypeContainer(self.handle) });
        // NOTE: I have no idea how this isn't a UAF, see the note in `TypeContainer::from_raw`
        unsafe { TypeContainer::from_raw(type_container_ptr.unwrap()) }.clone()
    }

    /// Type container for auto types in the Binary View.
    ///
    /// NOTE: Unlike [`Self::type_container`] modification of auto types will **NOT** promote it to a user type.
    pub fn auto_type_container(&self) -> TypeContainer {
        let type_container_ptr =
            NonNull::new(unsafe { BNGetAnalysisAutoTypeContainer(self.handle) });
        // NOTE: I have no idea how this isn't a UAF, see the note in `TypeContainer::from_raw`
        unsafe { TypeContainer::from_raw(type_container_ptr.unwrap()) }
    }

    pub fn type_libraries(&self) -> Array<TypeLibrary> {
        let mut count = 0;
        let result = unsafe { BNGetBinaryViewTypeLibraries(self.handle, &mut count) };
        unsafe { Array::new(result, count, ()) }
    }

    /// Make the contents of a type library available for type/import resolution
    pub fn add_type_library(&self, library: &TypeLibrary) {
        unsafe { BNAddBinaryViewTypeLibrary(self.handle, library.as_raw()) }
    }

    pub fn type_library_by_name(&self, name: &str) -> Option<Ref<TypeLibrary>> {
        let name = name.to_cstr();
        let result = unsafe { BNGetBinaryViewTypeLibrary(self.handle, name.as_ptr()) };
        NonNull::new(result).map(|h| unsafe { TypeLibrary::ref_from_raw(h) })
    }

    /// Should be called by custom [`BinaryView`] implementations when they have successfully
    /// imported an object from a type library (eg a symbol's type). Values recorded with this
    /// function will then be queryable via [`BinaryView::lookup_imported_object_library`].
    ///
    /// * `lib` - Type Library containing the imported type
    /// * `name` - Name of the object in the type library
    /// * `addr` - address of symbol at import site
    /// * `platform` - Platform of symbol at import site
    pub fn record_imported_object_library<T: Into<QualifiedName>>(
        &self,
        lib: &TypeLibrary,
        name: T,
        addr: u64,
        platform: &Platform,
    ) {
        let mut raw_name = QualifiedName::into_raw(name.into());
        unsafe {
            BNBinaryViewRecordImportedObjectLibrary(
                self.handle,
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
    pub fn import_type_library_type<T: Into<QualifiedName>>(
        &self,
        name: T,
        lib: Option<&TypeLibrary>,
    ) -> Option<Ref<Type>> {
        let mut lib_ref = lib
            .as_ref()
            .map(|l| unsafe { l.as_raw() } as *mut _)
            .unwrap_or(std::ptr::null_mut());
        let mut raw_name = QualifiedName::into_raw(name.into());
        let result =
            unsafe { BNBinaryViewImportTypeLibraryType(self.handle, &mut lib_ref, &mut raw_name) };
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
    /// you should then call [BinaryView::record_imported_object_library] with the details of
    /// where the object is located.
    pub fn import_type_library_object<T: Into<QualifiedName>>(
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
            BNBinaryViewImportTypeLibraryObject(self.handle, &mut lib_ref, &mut raw_name)
        };
        QualifiedName::free_raw(raw_name);
        (!result.is_null()).then(|| unsafe { Type::ref_from_raw(result) })
    }

    /// Recursively imports a [`Type`] given its GUID from available type libraries.
    pub fn import_type_by_guid(&self, guid: &str) -> Option<Ref<Type>> {
        let guid = guid.to_cstr();
        let result = unsafe { BNBinaryViewImportTypeLibraryTypeByGuid(self.handle, guid.as_ptr()) };
        (!result.is_null()).then(|| unsafe { Type::ref_from_raw(result) })
    }

    /// Recursively exports `type_obj` into `lib` as a type with name `name`.
    ///
    /// As other referenced types are encountered, they are either copied into the destination type library or
    /// else the type library that provided the referenced type is added as a dependency for the destination library.
    pub fn export_type_to_library<T: Into<QualifiedName>>(
        &self,
        lib: &TypeLibrary,
        name: T,
        type_obj: &Type,
    ) {
        let mut raw_name = QualifiedName::into_raw(name.into());
        unsafe {
            BNBinaryViewExportTypeToTypeLibrary(
                self.handle,
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
    pub fn export_object_to_library<T: Into<QualifiedName>>(
        &self,
        lib: &TypeLibrary,
        name: T,
        type_obj: &Type,
    ) {
        let mut raw_name = QualifiedName::into_raw(name.into());
        unsafe {
            BNBinaryViewExportObjectToTypeLibrary(
                self.handle,
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
    pub fn lookup_imported_object_library(
        &self,
        addr: u64,
        platform: &Platform,
    ) -> Option<(Ref<TypeLibrary>, QualifiedName)> {
        let mut result_lib = std::ptr::null_mut();
        let mut result_name = BNQualifiedName::default();
        let success = unsafe {
            BNBinaryViewLookupImportedObjectLibrary(
                self.handle,
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
    pub fn lookup_imported_type_library<T: Into<QualifiedName>>(
        &self,
        name: T,
    ) -> Option<(Ref<TypeLibrary>, QualifiedName)> {
        let raw_name = QualifiedName::into_raw(name.into());
        let mut result_lib = std::ptr::null_mut();
        let mut result_name = BNQualifiedName::default();
        let success = unsafe {
            BNBinaryViewLookupImportedTypeLibrary(
                self.handle,
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
    /// - [`BinaryView::read_c_string_at`]
    /// - [`BinaryView::read_utf8_string_at`]
    ///
    /// NOTE: This returns discovered strings and is therefore governed by `analysis.limits.minStringLength`
    /// and other settings.
    pub fn strings(&self) -> Array<StringReference> {
        unsafe {
            let mut count = 0;
            let strings = BNGetStrings(self.handle, &mut count);
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
    /// - [`BinaryView::read_c_string_at`]
    /// - [`BinaryView::read_utf8_string_at`]
    ///
    /// NOTE: This returns discovered strings and is therefore governed by `analysis.limits.minStringLength`
    /// and other settings.
    pub fn string_at(&self, addr: u64) -> Option<StringReference> {
        let mut str_ref = BNStringReference::default();
        let success = unsafe { BNGetStringAtAddress(self.handle, addr, &mut str_ref) };
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
    /// - [`BinaryView::read_c_string_at`]
    /// - [`BinaryView::read_utf8_string_at`]
    ///
    /// NOTE: This returns discovered strings and is therefore governed by `analysis.limits.minStringLength`
    /// and other settings.
    pub fn strings_in_range(&self, range: Range<u64>) -> Array<StringReference> {
        unsafe {
            let mut count = 0;
            let strings = BNGetStringsInRange(
                self.handle,
                range.start,
                range.end - range.start,
                &mut count,
            );
            Array::new(strings, count, ())
        }
    }

    /// Retrieve the attached type archives as their [`TypeArchiveId`].
    ///
    /// Using the returned id you can retrieve the [`TypeArchive`] with [`BinaryView::type_archive_by_id`].
    pub fn attached_type_archives(&self) -> Vec<TypeArchiveId> {
        let mut ids: *mut *mut c_char = std::ptr::null_mut();
        let mut paths: *mut *mut c_char = std::ptr::null_mut();
        let count = unsafe { BNBinaryViewGetTypeArchives(self.handle, &mut ids, &mut paths) };
        // We discard the path here, you can retrieve it later with [`BinaryView::type_archive_path_by_id`].
        // This is so we can simplify the return type which will commonly just want to query through to the type
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
    pub fn type_archive_by_id(&self, id: &TypeArchiveId) -> Option<Ref<TypeArchive>> {
        let id = id.0.as_str().to_cstr();
        let result = unsafe { BNBinaryViewGetTypeArchive(self.handle, id.as_ptr()) };
        let result_ptr = NonNull::new(result)?;
        Some(unsafe { TypeArchive::ref_from_raw(result_ptr) })
    }

    /// Look up the path for an attached (but not necessarily connected) [`TypeArchive`] by its `id`.
    pub fn type_archive_path_by_id(&self, id: &TypeArchiveId) -> Option<PathBuf> {
        let id = id.0.as_str().to_cstr();
        let result = unsafe { BNBinaryViewGetTypeArchivePath(self.handle, id.as_ptr()) };
        if result.is_null() {
            return None;
        }
        let path_str = unsafe { BnString::into_string(result) };
        Some(PathBuf::from(path_str))
    }

    pub fn deref_return_value_named_type_references(
        &self,
        return_value: &ReturnValue,
    ) -> ReturnValue {
        ReturnValue {
            ty: Conf::new(
                return_value.ty.contents.deref_named_type_reference(self),
                return_value.ty.confidence,
            ),
            location: return_value.location.clone(),
        }
    }

    pub fn deref_parameter_named_type_references(
        &self,
        params: &[FunctionParameter],
    ) -> Vec<FunctionParameter> {
        params
            .iter()
            .map(|param| FunctionParameter {
                ty: Conf::new(
                    param.ty.contents.deref_named_type_reference(self),
                    param.ty.confidence,
                ),
                name: param.name.clone(),
                location: param.location.clone(),
            })
            .collect()
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
        ctx: *mut c_void,
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
        BNRegisterBinaryViewEvent(event_type, Some(on_event::<Handler>), raw as *mut c_void);
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

extern "C" fn cb_valid<T>(ctxt: *mut c_void, data: *mut BNBinaryView) -> bool
where
    T: CustomBinaryViewType,
{
    let view_type = unsafe { &*(ctxt as *mut T) };
    let data = unsafe { BinaryView::ref_from_raw(BNNewViewReference(data)) };
    let _span = ffi_span!("CustomBinaryViewType::is_valid_for", data);
    view_type.is_valid_for(&data)
}

extern "C" fn cb_deprecated<T>(_ctxt: *mut c_void) -> bool
where
    T: CustomBinaryViewType,
{
    T::DEPRECATED
}

extern "C" fn cb_force_loadable<T>(_ctxt: *mut c_void) -> bool
where
    T: CustomBinaryViewType,
{
    T::FORCE_LOADABLE
}

extern "C" fn cb_has_no_initial_content<T>(_ctxt: *mut c_void) -> bool
where
    T: CustomBinaryViewType,
{
    T::HAS_NO_INITIAL_CONTENT
}

extern "C" fn cb_create<T>(ctxt: *mut c_void, data: *mut BNBinaryView) -> *mut BNBinaryView
where
    T: CustomBinaryViewType,
{
    ffi_wrap!("CustomBinaryViewType::create", unsafe {
        let view_type = &*(ctxt as *mut T);
        let data = BinaryView::from_raw(data);
        let _span = ffi_span!("CustomBinaryViewType::create", data);
        match view_type.create_binary_view(&data) {
            Ok(custom_view) => {
                match BinaryView::from_custom(T::NAME, &data.file(), &data, custom_view) {
                    Ok(custom_view) => Ref::into_raw(custom_view).handle,
                    Err(_) => std::ptr::null_mut(),
                }
            }
            Err(_) => std::ptr::null_mut(),
        }
    })
}

extern "C" fn cb_parse<T>(ctxt: *mut c_void, data: *mut BNBinaryView) -> *mut BNBinaryView
where
    T: CustomBinaryViewType,
{
    ffi_wrap!("CustomBinaryViewType::parse", unsafe {
        let view_type = &*(ctxt as *mut T);
        let data = BinaryView::from_raw(data);
        let _span = ffi_span!("CustomBinaryViewType::parse", data);
        match view_type.create_binary_view_for_parse(&data) {
            Ok(custom_view) => {
                match BinaryView::from_custom(T::NAME, &data.file(), &data, custom_view) {
                    Ok(custom_view) => Ref::into_raw(custom_view).handle,
                    Err(_) => std::ptr::null_mut(),
                }
            }
            Err(_) => std::ptr::null_mut(),
        }
    })
}

extern "C" fn cb_load_settings<T>(ctxt: *mut c_void, data: *mut BNBinaryView) -> *mut BNSettings
where
    T: CustomBinaryViewType,
{
    ffi_wrap!("CustomBinaryViewType::load_settings", unsafe {
        let view_type = &*(ctxt as *mut T);
        let data = BinaryView::from_raw(data);

        let _span = ffi_span!("CustomBinaryViewType::load_settings", data);
        let settings = view_type.load_settings_for_data(&data);
        Ref::into_raw(settings).handle
    })
}

extern "C" fn cb_init<C>(ctxt: *mut c_void) -> bool
where
    C: CustomBinaryView,
{
    ffi_wrap!("BinaryViewBase::init", unsafe {
        let context = &mut *(ctxt as *mut CustomBinaryViewContext<C>);
        // SAFETY: The core view has been initialized by [`BinaryView::from_custom`], so it should be valid.
        // SAFETY: The custom view is not being touched by anything else at the point this function is called,
        // so it should be safe to mutably borrow it.
        context.view.initialize(context.core_view.assume_init_ref())
    })
}

extern "C" fn cb_on_after_snapshot_data_applied<C>(ctxt: *mut c_void)
where
    C: CustomBinaryView,
{
    ffi_wrap!("BinaryViewBase::onAfterSnapshotDataApplied", unsafe {
        let context = &mut *(ctxt as *mut CustomBinaryViewContext<C>);
        // SAFETY: The custom view is not being touched by anything else at the point this function is called,
        // so it should be safe to mutably borrow it.
        context.view.on_after_snapshot_data_applied();
    })
}

extern "C" fn cb_free_object<C>(ctxt: *mut c_void)
where
    C: CustomBinaryView,
{
    ffi_wrap!("BinaryViewBase::freeObject", unsafe {
        let context = ctxt as *mut CustomBinaryViewContext<C>;
        let _context = Box::from_raw(context);
    })
}

extern "C" fn cb_read<C>(ctxt: *mut c_void, dest: *mut c_void, offset: u64, len: usize) -> usize
where
    C: CustomBinaryView,
{
    ffi_wrap!("BinaryViewBase::read", unsafe {
        let context = &*(ctxt as *mut CustomBinaryViewContext<C>);
        let dest = std::slice::from_raw_parts_mut(dest as *mut u8, len);
        context.view.read(dest, offset)
    })
}

extern "C" fn cb_write<C>(ctxt: *mut c_void, offset: u64, src: *const c_void, len: usize) -> usize
where
    C: CustomBinaryView,
{
    ffi_wrap!("BinaryViewBase::write", unsafe {
        let context = &*(ctxt as *mut CustomBinaryViewContext<C>);
        let src = std::slice::from_raw_parts(src as *const u8, len);
        context.view.write(offset, src)
    })
}

extern "C" fn cb_insert<C>(ctxt: *mut c_void, offset: u64, src: *const c_void, len: usize) -> usize
where
    C: CustomBinaryView,
{
    ffi_wrap!("BinaryViewBase::insert", unsafe {
        let context = &*(ctxt as *mut CustomBinaryViewContext<C>);
        let src = std::slice::from_raw_parts(src as *const u8, len);
        context.view.insert(offset, src)
    })
}

extern "C" fn cb_remove<C>(ctxt: *mut c_void, offset: u64, len: u64) -> usize
where
    C: CustomBinaryView,
{
    ffi_wrap!("BinaryViewBase::remove", unsafe {
        let context = &*(ctxt as *mut CustomBinaryViewContext<C>);
        context.view.remove(offset, len as usize)
    })
}

extern "C" fn cb_modification<C>(ctxt: *mut c_void, offset: u64) -> ModificationStatus
where
    C: CustomBinaryView,
{
    ffi_wrap!("BinaryViewBase::modification_status", unsafe {
        let context = &*(ctxt as *mut CustomBinaryViewContext<C>);
        context.view.modification_status(offset)
    })
}

extern "C" fn cb_offset_valid<C>(ctxt: *mut c_void, offset: u64) -> bool
where
    C: CustomBinaryView,
{
    ffi_wrap!("BinaryViewBase::offset_valid", unsafe {
        let context = &*(ctxt as *mut CustomBinaryViewContext<C>);
        context.view.offset_valid(offset)
    })
}

extern "C" fn cb_offset_readable<C>(ctxt: *mut c_void, offset: u64) -> bool
where
    C: CustomBinaryView,
{
    ffi_wrap!("BinaryViewBase::readable", unsafe {
        let context = &*(ctxt as *mut CustomBinaryViewContext<C>);
        context.view.offset_readable(offset)
    })
}

extern "C" fn cb_offset_writable<C>(ctxt: *mut c_void, offset: u64) -> bool
where
    C: CustomBinaryView,
{
    ffi_wrap!("BinaryViewBase::writable", unsafe {
        let context = &*(ctxt as *mut CustomBinaryViewContext<C>);
        context.view.offset_writable(offset)
    })
}

extern "C" fn cb_offset_executable<C>(ctxt: *mut c_void, offset: u64) -> bool
where
    C: CustomBinaryView,
{
    ffi_wrap!("BinaryViewBase::offset_executable", unsafe {
        let context = &*(ctxt as *mut CustomBinaryViewContext<C>);
        context.view.offset_executable(offset)
    })
}

extern "C" fn cb_offset_backed_by_file<C>(ctxt: *mut c_void, offset: u64) -> bool
where
    C: CustomBinaryView,
{
    ffi_wrap!("BinaryViewBase::offset_backed_by_file", unsafe {
        let context = &*(ctxt as *mut CustomBinaryViewContext<C>);
        context.view.offset_backed_by_file(offset)
    })
}

extern "C" fn cb_next_valid_offset<C>(ctxt: *mut c_void, offset: u64) -> u64
where
    C: CustomBinaryView,
{
    ffi_wrap!("BinaryViewBase::next_valid_offset_after", unsafe {
        let context = &*(ctxt as *mut CustomBinaryViewContext<C>);
        context.view.next_valid_offset_after(offset)
    })
}

extern "C" fn cb_start<C>(ctxt: *mut c_void) -> u64
where
    C: CustomBinaryView,
{
    ffi_wrap!("BinaryViewBase::start", unsafe {
        let context = &*(ctxt as *mut CustomBinaryViewContext<C>);
        context.view.start()
    })
}

extern "C" fn cb_length<C>(ctxt: *mut c_void) -> u64
where
    C: CustomBinaryView,
{
    ffi_wrap!("BinaryViewBase::len", unsafe {
        let context = &*(ctxt as *mut CustomBinaryViewContext<C>);
        context.view.len()
    })
}

extern "C" fn cb_entry_point<C>(ctxt: *mut c_void) -> u64
where
    C: CustomBinaryView,
{
    ffi_wrap!("BinaryViewBase::entry_point", unsafe {
        let context = &*(ctxt as *mut CustomBinaryViewContext<C>);
        context.view.entry_point()
    })
}

extern "C" fn cb_executable<C>(ctxt: *mut c_void) -> bool
where
    C: CustomBinaryView,
{
    ffi_wrap!("BinaryViewBase::executable", unsafe {
        let context = &*(ctxt as *mut CustomBinaryViewContext<C>);
        context.view.executable()
    })
}

extern "C" fn cb_endianness<C>(ctxt: *mut c_void) -> Endianness
where
    C: CustomBinaryView,
{
    ffi_wrap!("BinaryViewBase::default_endianness", unsafe {
        let context = &*(ctxt as *mut CustomBinaryViewContext<C>);
        context.view.default_endianness()
    })
}

extern "C" fn cb_relocatable<C>(ctxt: *mut c_void) -> bool
where
    C: CustomBinaryView,
{
    ffi_wrap!("BinaryViewBase::relocatable", unsafe {
        let context = &*(ctxt as *mut CustomBinaryViewContext<C>);
        context.view.relocatable()
    })
}

extern "C" fn cb_address_size<C>(ctxt: *mut c_void) -> usize
where
    C: CustomBinaryView,
{
    ffi_wrap!("BinaryViewBase::address_size", unsafe {
        let context = &*(ctxt as *mut CustomBinaryViewContext<C>);
        context.view.address_size()
    })
}

extern "C" fn cb_save<C>(ctxt: *mut c_void, _file: *mut BNFileAccessor) -> bool
where
    C: CustomBinaryView,
{
    ffi_wrap!("BinaryViewBase::save", unsafe {
        let context = &*(ctxt as *mut CustomBinaryViewContext<C>);
        // TODO: Need to pass file accessor to save to.
        // let file = FileAccessor::from_raw(file);
        context.view.save()
    })
}
