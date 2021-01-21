use binaryninjacore_sys::*;

pub use binaryninjacore_sys::BNModificationStatus as ModificationStatus;

use std::result;
use std::slice;
use std::ops;
use std::marker::PhantomData;

use std::os::raw::{c_void, c_char};
use std::mem;
use std::ptr;

use crate::Endianness;

use crate::architecture::Architecture;
use crate::architecture::CoreArchitecture;
use crate::platform::Platform;
use crate::filemetadata::FileMetadata;
use crate::fileaccessor::FileAccessor;
use crate::symbol::{SymType, Symbol};
use crate::segment::{Segment, SegmentBuilder};
use crate::section::{Section, SectionBuilder};
use crate::function::{Function, NativeBlock};
use crate::basicblock::BasicBlock;
use crate::types::Type;
use crate::settings::Settings;

use crate::string::*;
use crate::rc::*;

// TODO
// merge filemetadata/fileaccessor under here?
// general reorg of modules related to bv

pub type Result<R> = result::Result<R, ()>;

pub trait BinaryViewBase: AsRef<BinaryView> {
    fn read(&self, _buf: &mut [u8], _offset: u64) -> usize { 0 }
    fn write(&self, _offset: u64, _data: &[u8]) -> usize { 0 }
    fn insert(&self, _offset: u64, _data: &[u8]) -> usize { 0 }
    fn remove(&self, _offset: u64, _len: usize) -> usize { 0 }

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

    fn start(&self) -> u64 { 0 }
    fn len(&self) -> usize { 0 }

    fn executable(&self) -> bool { true }
    fn relocatable(&self) -> bool { true }

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
                let dest_slice = ret.get_unchecked_mut(0 .. len);
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
                let dest_slice = dest.get_unchecked_mut(starting_len .. starting_len + len);
                res = self.read(dest_slice, offset);
            }

            if res > 0 {
                dest.set_len(starting_len + res);
            }

            res
        }
    }

    fn notify_data_written(&self, offset: u64, len: usize) {
        unsafe { BNNotifyDataWritten(self.as_ref().handle, offset, len); }
    }

    fn notify_data_inserted(&self, offset: u64, len: usize) {
        unsafe { BNNotifyDataInserted(self.as_ref().handle, offset, len); }
    }

    fn notify_data_removed(&self, offset: u64, len: usize) {
        unsafe { BNNotifyDataRemoved(self.as_ref().handle, offset, len as u64); }
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
        unsafe { BNUpdateAnalysisAndWait(self.as_ref().handle); }
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
            let raw_sym = BNGetSymbolByRawName(self.as_ref().handle, raw_name.as_ref().as_ptr() as *mut _, ptr::null_mut());

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
            let handles = BNGetSymbolsByName(self.as_ref().handle, raw_name.as_ref().as_ptr() as *mut _, &mut count, ptr::null_mut());

            Array::new(handles, count, ())
        }
    }

    fn symbols_in_range(&self, range: ops::Range<u64>) -> Array<Symbol> {
        unsafe {
            let mut count = 0;
            let len = range.end.wrapping_sub(range.start);
            let handles = BNGetSymbolsInRange(self.as_ref().handle, range.start, len, &mut count, ptr::null_mut());

            Array::new(handles, count, ())
        }
    }

    fn symbols_of_type(&self, ty: SymType) -> Array<Symbol> {
        unsafe {
            let mut count = 0;
            let handles = BNGetSymbolsOfType(self.as_ref().handle, ty.into(), &mut count, ptr::null_mut());

            Array::new(handles, count, ())
        }
    }

    fn symbols_of_type_in_range(&self, ty: SymType, range: ops::Range<u64>) -> Array<Symbol> {
        unsafe {
            let mut count = 0;
            let len = range.end.wrapping_sub(range.start);
            let handles = BNGetSymbolsOfTypeInRange(self.as_ref().handle, ty.into(), range.start, len, &mut count, ptr::null_mut());

            Array::new(handles, count, ())
        }
    }

    fn define_auto_symbol(&self, sym: &Symbol) {
        unsafe { BNDefineAutoSymbol(self.as_ref().handle, sym.handle); }
    }

    fn define_auto_symbol_with_type<'a, T: Into<Option<&'a Type>>>(&self, sym: &Symbol, plat: &Platform, ty: T) {
        let raw_type = if let Some(t) = ty.into() {
            t.handle
        } else {
            ptr::null_mut()
        };

        unsafe { BNDefineAutoSymbolAndVariableOrFunction(self.as_ref().handle, plat.handle, sym.handle, raw_type); }
    }

    fn undefine_auto_symbol(&self, sym: &Symbol) {
        unsafe { BNUndefineAutoSymbol(self.as_ref().handle, sym.handle); }
    }

    fn define_user_symbol(&self, sym: &Symbol) {
        unsafe { BNDefineUserSymbol(self.as_ref().handle, sym.handle); }
    }

    fn undefine_user_symbol(&self, sym: &Symbol) {
        unsafe { BNUndefineUserSymbol(self.as_ref().handle, sym.handle); }
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
            let raw_seg =  BNGetSegmentAt(self.as_ref().handle, addr);
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

        unsafe { BNRemoveAutoSection(self.as_ref().handle, name_ptr); }
    }

    fn remove_user_section<S: BnStrCompatible>(&self, name: S) {
        let name = name.as_bytes_with_nul();
        let name_ptr = name.as_ref().as_ptr() as *mut _;

        unsafe { BNRemoveUserSection(self.as_ref().handle, name_ptr); }
    }

    fn section_by_name<S: BnStrCompatible>(&self, name: S) -> Result<Section> {
        unsafe {
            let raw_name = name.as_bytes_with_nul();
            let name_ptr = raw_name.as_ref().as_ptr() as * mut _;
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
        unsafe { BNAddFunctionForAnalysis(self.as_ref().handle, plat.handle, addr); }
    }

    fn add_entry_point(&self, plat: &Platform, addr: u64) {
        unsafe { BNAddEntryPointForAnalysis(self.as_ref().handle, plat.handle, addr); }
    }

    fn create_user_function(&self, plat: &Platform, addr: u64) {
        unsafe { BNCreateUserFunction(self.as_ref().handle, plat.handle, addr); }
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
            let functions = BNGetAnalysisFunctionsForAddress(self.as_ref().handle, addr, &mut count);

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
        unsafe { BNSetNewAutoFunctionAnalysisSuppressed(self.as_ref().handle, suppress); }
    }
}

impl<T: BinaryViewBase> BinaryViewExt for T {}

#[derive(PartialEq, Eq, Hash)]
pub struct BinaryView {
    pub(crate) handle: *mut BNBinaryView,
}

unsafe impl Send for BinaryView {}
unsafe impl Sync for BinaryView {}

impl BinaryView {
    pub(crate) unsafe fn from_raw(handle: *mut BNBinaryView) -> Self {
        debug_assert!(!handle.is_null());

        Self { handle }
    }

    pub fn from_filename<S: BnStrCompatible>(meta: &FileMetadata, filename: S) -> Result<Ref<Self>> {
        let file = filename.as_bytes_with_nul();

        let handle = unsafe { BNCreateBinaryDataViewFromFilename(meta.handle, file.as_ref().as_ptr() as *mut _) };

        if handle.is_null() {
            return Err(());
        }

        unsafe { Ok(Ref::new(Self { handle })) }
    }

    pub fn from_accessor(meta: &FileMetadata, file: &mut FileAccessor) -> Result<Ref<Self>> {
        let handle = unsafe { BNCreateBinaryDataViewFromFile(meta.handle, &mut file.api_object as *mut _) };

        if handle.is_null() {
            return Err(());
        }

        unsafe { Ok(Ref::new(Self { handle })) }
    }

    pub fn from_data(meta: &FileMetadata, data: &[u8]) -> Result<Ref<Self>> {
        let handle = unsafe { BNCreateBinaryDataViewFromData(meta.handle, data.as_ptr() as *mut _, data.len()) };

        if handle.is_null() {
            return Err(());
        }

        unsafe { Ok(Ref::new(Self { handle })) }
    }
}

impl AsRef<BinaryView> for BinaryView {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl BinaryViewBase for BinaryView {
    fn read(&self, buf: &mut [u8], offset: u64) -> usize {
        unsafe {
            BNReadViewData(self.handle, buf.as_mut_ptr() as *mut _, offset, buf.len())
        }
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

impl ToOwned for BinaryView {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
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

pub trait BinaryViewTypeBase: AsRef<BinaryViewType> {
    fn is_valid_for(&self, data: &BinaryView) -> bool;

    fn load_settings_for_data(&self, data: &BinaryView) -> Ref<Settings> {
        unsafe {
            Ref::new(Settings::from_raw(BNGetBinaryViewDefaultLoadSettingsForData(self.as_ref().0, data.handle)))
        }
    }
}

pub trait BinaryViewTypeExt: BinaryViewTypeBase {
    fn name(&self) -> BnString {
        unsafe {
            BnString::from_raw(BNGetBinaryViewTypeName(self.as_ref().0))
        }
    }

    fn long_name(&self) -> BnString {
        unsafe {
            BnString::from_raw(BNGetBinaryViewTypeLongName(self.as_ref().0))
        }
    }

    fn register_arch<A: Architecture>(&self, id: u32, endianness: Endianness, arch: &A)
    {
        unsafe {
            BNRegisterArchitectureForViewType(self.as_ref().0, id, endianness, arch.as_ref().0);
        }
    }

    fn register_platform(&self, id: u32, plat: &Platform)
    {
        let arch = plat.arch();

        unsafe {
            BNRegisterPlatformForViewType(self.as_ref().0, id, arch.0, plat.handle);
        }
    }

    fn open(&self, data: &BinaryView) -> Result<Ref<BinaryView>> {
        let handle = unsafe { BNCreateBinaryViewOfType(self.as_ref().0, data.handle) };

        if handle.is_null() {
            error!("failed to create BinaryView of BinaryViewType '{}'", self.name());
            return Err(());
        }

        unsafe {
            Ok(Ref::new(BinaryView::from_raw(handle)))
        }
    }
}

impl<T: BinaryViewTypeBase> BinaryViewTypeExt for T {}

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct BinaryViewType(*mut BNBinaryViewType);

unsafe impl Send for BinaryViewType {}
unsafe impl Sync for BinaryViewType {}

impl BinaryViewType {
    pub fn list_all() -> Array<BinaryViewType> {
        unsafe {
            let mut count: usize = 0;
            let types = BNGetBinaryViewTypes(&mut count as *mut _);

            Array::new(types, count, ())
        }
    }

    pub fn list_valid_types_for(data: &BinaryView) -> Array<BinaryViewType> {
        unsafe {
            let mut count: usize = 0;
            let types = BNGetBinaryViewTypesForData(data.handle, &mut count as *mut _);

            Array::new(types, count, ())
        }
    }

    /// Looks up a BinaryViewType by its short name
    pub fn by_name<N: BnStrCompatible>(name: N) -> Result<Self> {
        let bytes = name.as_bytes_with_nul();

        let res = unsafe { BNGetBinaryViewTypeByName(bytes.as_ref().as_ptr() as *const _) };

        match res.is_null() {
            false => Ok(BinaryViewType(res)),
            true => Err(()),
        }
    }

}

impl AsRef<BinaryViewType> for BinaryViewType {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl BinaryViewTypeBase for BinaryViewType {
    fn is_valid_for(&self, data: &BinaryView) -> bool {
        unsafe { BNIsBinaryViewTypeValidForData(self.0, data.handle) }
    }

    fn load_settings_for_data(&self, data: &BinaryView) -> Ref<Settings> {
        unsafe {
            Ref::new(Settings::from_raw(BNGetBinaryViewLoadSettingsForData(self.0, data.handle)))
        }
    }
}

unsafe impl CoreOwnedArrayProvider for BinaryViewType {
    type Raw = *mut BNBinaryViewType;
    type Context = ();

    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeBinaryViewTypeList(raw);
    }
}

unsafe impl<'a> CoreOwnedArrayWrapper<'a> for BinaryViewType {
    type Wrapped = BinaryViewType;

    unsafe fn wrap_raw(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped {
        BinaryViewType(*raw)
    }
}

pub unsafe trait CustomBinaryView: 'static + BinaryViewBase + Sync + Sized {
    type Args: Send;

    fn new(handle: BinaryView, args: &Self::Args) -> Result<Self>;
    fn init(&self, args: Self::Args) -> Result<()>;
}

pub trait CustomBinaryViewType: 'static + BinaryViewTypeBase + Sync {
    fn create_custom_view<'builder>(&self, data: &BinaryView, builder: CustomViewBuilder<'builder, Self>) -> Result<CustomView<'builder>>;
}

/// Represents a request from the core to instantiate a custom BinaryView
pub struct CustomViewBuilder<'a, T: CustomBinaryViewType + ?Sized> {
    view_type: &'a T,
    actual_parent: &'a BinaryView,
}

/// Represents a partially initialized custom `BinaryView` that should be returned to the core
/// from the `create_custom_view` method of a `CustomBinaryViewType`.
#[must_use]
pub struct CustomView<'builder> {
    // this object can't actually be treated like a real
    // BinaryView as it isn't fully initialized until the
    // core receives it from the BNCustomBinaryViewType::create
    // callback.
    handle: Ref<BinaryView>,
    _builder: PhantomData<&'builder ()>,
}


/// Registers a custom `BinaryViewType` with the core.
///
/// The `constructor` argument is called immediately after successful registration of the type with
/// the core. The `BinaryViewType` argument passed to `constructor` is the object that the
/// `AsRef<BinaryViewType>`
/// implementation of the `CustomBinaryViewType` must return.
pub fn register_view_type<S, T, F>(name: S, long_name: S, constructor: F) -> &'static T
where
    S: BnStrCompatible,
    T: CustomBinaryViewType,
    F: FnOnce(BinaryViewType) -> T,
{
    extern "C" fn cb_valid<T>(ctxt: *mut c_void, data: *mut BNBinaryView) -> bool
    where
        T: CustomBinaryViewType
    {
        ffi_wrap!("BinaryViewTypeBase::is_valid_for", unsafe {
            let view_type = &*(ctxt as *mut T);
            let data = BinaryView::from_raw(data);

            view_type.is_valid_for(&data)
        })
    }

    extern "C" fn cb_create<T>(ctxt: *mut c_void, data: *mut BNBinaryView) -> *mut BNBinaryView
    where
        T: CustomBinaryViewType
    {
        ffi_wrap!("BinaryViewTypeBase::create", unsafe {
            let view_type = &*(ctxt as *mut T);
            let data = BinaryView::from_raw(data);

            let builder = CustomViewBuilder {
                view_type: view_type,
                actual_parent: &data,
            };

            if let Ok(bv) = view_type.create_custom_view(&data, builder) {
                // force a leak of the Ref; failure to do this would result
                // in the refcount going to 0 in the process of returning it
                // to the core -- we're transferring ownership of the Ref here
                Ref::into_raw(bv.handle).handle
            } else {
                error!("CustomBinaryViewType::create_custom_view returned Err");

                ptr::null_mut()
            }
        })
    }

    extern "C" fn cb_parse<T>(ctxt: *mut c_void, data: *mut BNBinaryView) -> *mut BNBinaryView
    where
        T: CustomBinaryViewType
    {
        ffi_wrap!("BinaryViewTypeBase::parse", unsafe {
            ptr::null_mut()
        })
    }

    extern "C" fn cb_load_settings<T>(ctxt: *mut c_void, data: *mut BNBinaryView) -> *mut BNSettings
    where
        T: CustomBinaryViewType
    {
        ffi_wrap!("BinaryViewTypeBase::load_settings", unsafe {
            let view_type = &*(ctxt as *mut T);
            let data = BinaryView::from_raw(data);

            Ref::into_raw(view_type.load_settings_for_data(&data)).handle
        })
    }

    let name = name.as_bytes_with_nul();
    let name_ptr = name.as_ref().as_ptr() as *mut _;

    let long_name = long_name.as_bytes_with_nul();
    let long_name_ptr = long_name.as_ref().as_ptr() as *mut _;

    let ctxt = Box::new(unsafe { mem::uninitialized::<T>() });
    let ctxt = Box::into_raw(ctxt);

    let mut bn_obj = BNCustomBinaryViewType {
        context: ctxt as *mut _,
        create: Some(cb_create::<T>),
        parse: Some(cb_parse::<T>),
        isValidForData: Some(cb_valid::<T>),
        getLoadSettingsForData: Some(cb_load_settings::<T>),
    };

    unsafe {
        let res = BNRegisterBinaryViewType(name_ptr, long_name_ptr, &mut bn_obj as *mut _);

        if res.is_null() {
            // avoid leaking the space allocated for the type, but also
            // avoid running its Drop impl (if any -- not that there should
            // be one since view types live for the life of the process)
            mem::forget(*Box::from_raw(ctxt));

            panic!("bvt registration failed");
        }

        ptr::write(ctxt, constructor(BinaryViewType(res)));

        &*ctxt
    }
}

impl<'a, T: CustomBinaryViewType> CustomViewBuilder<'a, T> {
    /// Begins creating a custom BinaryView.
    ///
    /// This function may only be called from the `create_custom_view` function of a
    /// `CustomBinaryViewType`.
    ///
    /// `parent` specifies the view that the core will treat as the parent view, that
    /// Segments created against the created view will be backed by `parent`. It will
    /// usually be (but is not required to be) the `data` argument of the `create_custom_view`
    /// callback.
    ///
    /// `constructor` will not be called until well after the value returned by this function
    /// has been returned by `create_custom_view` callback to the core, and may not ever
    /// be called if the value returned by this function is dropped or leaked.
    ///
    /// # Errors
    ///
    /// This function will fail if the `FileMetadata` object associated with the *expected* parent
    /// (i.e., the `data` argument passed to the `create_custom_view` function) already has an
    /// associated `BinaryView` of the same `CustomBinaryViewType`. Multiple `BinaryView` objects
    /// of the same `BinaryViewType` belonging to the same `FileMetadata` object is prohibited and
    /// can cause strange, delayed segmentation faults.
    ///
    /// # Safety
    ///
    /// `constructor` should avoid doing anything with the object it returns, especially anything
    /// that would cause the core to invoke any of the `BinaryViewBase` methods. The core isn't
    /// going to consider the object fully initialized until after that callback has run.
    ///
    /// The `BinaryView` argument passed to the constructor function is the object that is expected
    /// to be returned by the `AsRef<BinaryView>` implementation required by the `BinaryViewBase` trait.
    ///  TODO FIXME welp this is broke going to need 2 init callbacks
    pub fn create<V>(self, parent: &BinaryView, view_args: V::Args) -> Result<CustomView<'a>>
    where
        V: CustomBinaryView,
    {
        let file = self.actual_parent.metadata();
        let view_type = self.view_type;

        let view_name = view_type.name();

        if let Ok(bv) = file.get_view_of_type(view_name.as_cstr()) {
            // while it seems to work most of the time, you can get really unlucky
            // if the a free of the existing view of the same type kicks off while
            // BNCreateBinaryViewOfType is still running. the freeObject callback
            // will run for the new view before we've even finished initializing,
            // and that's all she wrote.
            //
            // even if we deal with it gracefully in cb_free_object,
            // BNCreateBinaryViewOfType is still going to crash, so we're just
            // going to try and stop this from happening in the first place.
            error!("attempt to create duplicate view of type '{}' (existing: {:?})", view_name.as_str(), bv.handle);

            return Err(());
        }

        // wildly unsafe struct representing the context of a BNCustomBinaryView
        // this type should *never* be allowed to drop as the fields are in varying
        // states of uninitialized/already consumed throughout the life of the object.
        struct CustomViewContext<V>
        where
            V: CustomBinaryView,
        {
            view: V,
            raw_handle: *mut BNBinaryView,
            initialized: bool,
            args: V::Args,
        }

        extern "C" fn cb_init<V>(ctxt: *mut c_void) -> bool
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::init", unsafe {
                let context = &mut *(ctxt as *mut CustomViewContext<V>);
                let handle = BinaryView::from_raw(context.raw_handle);

                if let Ok(v) = V::new(handle, &context.args) {
                    ptr::write(&mut context.view, v);
                    context.initialized = true;

                    if context.view.init(ptr::read(&context.args)).is_ok() {
                        true
                    } else {
                        error!("CustomBinaryView::init failed; custom view returned Err");
                        false
                    }
                } else {
                    error!("CustomBinaryView::new failed; custom view returned Err");
                    false
                }
            })
        }

        extern "C" fn cb_free_object<V>(ctxt: *mut c_void)
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::freeObject", unsafe {
                let context = ctxt as *mut CustomViewContext<V>;
                let context = *Box::from_raw(context);

                if context.initialized {
                    mem::forget(context.args); // already consumed
                    mem::drop(context.view); // cb_init was called
                } else {
                    mem::drop(context.args); // never consumed
                    mem::forget(context.view); // cb_init was not called, is uninit

                    if context.raw_handle.is_null() {
                        // being called here is essentially a guarantee that BNCreateBinaryViewOfType
                        // is above above us on the call stack somewhere -- no matter what we do, a crash
                        // is pretty much certain at this point.
                        //
                        // this has been observed when two views of the same BinaryViewType are created
                        // against the same BNFileMetaData object, and one of the views gets freed while
                        // the second one is being initialized -- somehow the partially initialized one
                        // gets freed before BNCreateBinaryViewOfType returns.
                        //
                        // multiples views of the same BinaryViewType in a BNFileMetaData object are
                        // prohibited, so an API contract was violated in order to get here.
                        //
                        // if we're here, it's too late to do anything about it, though we can at least not
                        // run the destructor on the custom view since that memory is unitialized.
                        error!("BinaryViewBase::freeObject called on partially initialized object! crash imminent!");
                    } else if !context.initialized {
                        // making it here means somebody went out of their way to leak a BinaryView
                        // after calling BNCreateCustomView and never gave the BNBinaryView handle
                        // to the core (which would have called cb_init)
                        //
                        // the result is a half-initialized BinaryView that the core will happily hand out
                        // references to via BNGetFileViewofType even though it was never initialized
                        // all the way.
                        //
                        // TODO update when this corner case gets fixed in the core?
                        //
                        // we can't do anything to prevent this, but we can at least have the crash
                        // not be our fault.
                        error!("BinaryViewBase::freeObject called on leaked/never initialized custom view!");
                    }
                }
            })
        }

        extern "C" fn cb_read<V>(ctxt: *mut c_void, dest: *mut c_void, offset: u64, len: usize) -> usize
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::read", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);
                let dest = slice::from_raw_parts_mut(dest as *mut u8, len);

                context.view.read(dest, offset)
            })
        }

        extern "C" fn cb_write<V>(ctxt: *mut c_void, offset: u64, src: *const c_void, len: usize) -> usize
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::write", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);
                let src = slice::from_raw_parts(src as *const u8, len);

                context.view.write(offset, src)
            })
        }

        extern "C" fn cb_insert<V>(ctxt: *mut c_void, offset: u64, src: *const c_void, len: usize) -> usize
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::insert", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);
                let src = slice::from_raw_parts(src as *const u8, len);

                context.view.insert(offset, src)
            })
        }

        extern "C" fn cb_remove<V>(ctxt: *mut c_void, offset: u64, len: u64) -> usize
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::remove", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);

                context.view.remove(offset, len as usize)
            })
        }

        extern "C" fn cb_modification<V>(ctxt: *mut c_void, offset: u64) -> ModificationStatus
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::modification_status", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);

                context.view.modification_status(offset)
            })
        }

        extern "C" fn cb_offset_valid<V>(ctxt: *mut c_void, offset: u64) -> bool
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::offset_valid", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);

                context.view.offset_valid(offset)
            })
        }

        extern "C" fn cb_offset_readable<V>(ctxt: *mut c_void, offset: u64) -> bool
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::readable", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);

                context.view.offset_readable(offset)
            })
        }

        extern "C" fn cb_offset_writable<V>(ctxt: *mut c_void, offset: u64) -> bool
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::writable", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);

                context.view.offset_writable(offset)
            })
        }

        extern "C" fn cb_offset_executable<V>(ctxt: *mut c_void, offset: u64) -> bool
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::offset_executable", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);

                context.view.offset_executable(offset)
            })
        }

        extern "C" fn cb_offset_backed_by_file<V>(ctxt: *mut c_void, offset: u64) -> bool
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::offset_backed_by_file", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);

                context.view.offset_backed_by_file(offset)
            })
        }

        extern "C" fn cb_next_valid_offset<V>(ctxt: *mut c_void, offset: u64) -> u64
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::next_valid_offset_after", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);

                context.view.next_valid_offset_after(offset)
            })
        }

        extern "C" fn cb_start<V>(ctxt: *mut c_void) -> u64
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::start", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);

                context.view.start()
            })
        }

        extern "C" fn cb_length<V>(ctxt: *mut c_void) -> u64
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::len", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);

                context.view.len() as u64
            })
        }

        extern "C" fn cb_entry_point<V>(ctxt: *mut c_void) -> u64
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::entry_point", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);

                context.view.entry_point()
            })
        }

        extern "C" fn cb_executable<V>(ctxt: *mut c_void) -> bool
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::executable", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);

                context.view.executable()
            })
        }

        extern "C" fn cb_endianness<V>(ctxt: *mut c_void) -> Endianness
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::default_endianness", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);

                context.view.default_endianness()
            })
        }

        extern "C" fn cb_relocatable<V>(ctxt: *mut c_void) -> bool
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::relocatable", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);

                context.view.relocatable()
            })
        }

        extern "C" fn cb_address_size<V>(ctxt: *mut c_void) -> usize
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::address_size", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);

                context.view.address_size()
            })
        }

        extern "C" fn cb_save<V>(ctxt: *mut c_void, _fa: *mut BNFileAccessor) -> bool
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::save", unsafe {
                let _context = &*(ctxt as *mut CustomViewContext<V>);
                false
            })
        }

        let ctxt = Box::new(CustomViewContext::<V> {
            view: unsafe { mem::uninitialized() },
            raw_handle: ptr::null_mut(),
            initialized: false,
            args: view_args,
        });

        let ctxt = Box::into_raw(ctxt);

        let mut bn_obj = BNCustomBinaryView {
            context: ctxt as *mut _,
            init: Some(cb_init::<V>),
            freeObject: Some(cb_free_object::<V>),
            externalRefTaken: None,
            externalRefReleased: None,
            read: Some(cb_read::<V>),
            write: Some(cb_write::<V>),
            insert: Some(cb_insert::<V>),
            remove: Some(cb_remove::<V>),
            getModification: Some(cb_modification::<V>),
            isValidOffset: Some(cb_offset_valid::<V>),
            isOffsetReadable: Some(cb_offset_readable::<V>),
            isOffsetWritable: Some(cb_offset_writable::<V>),
            isOffsetExecutable: Some(cb_offset_executable::<V>),
            isOffsetBackedByFile: Some(cb_offset_backed_by_file::<V>),
            getNextValidOffset: Some(cb_next_valid_offset::<V>),
            getStart: Some(cb_start::<V>),
            getLength: Some(cb_length::<V>),
            getEntryPoint: Some(cb_entry_point::<V>),
            isExecutable: Some(cb_executable::<V>),
            getDefaultEndianness: Some(cb_endianness::<V>),
            isRelocatable: Some(cb_relocatable::<V>),
            getAddressSize: Some(cb_address_size::<V>),
            save: Some(cb_save::<V>),
        };

        unsafe {
            let res = BNCreateCustomBinaryView(view_name.as_cstr().as_ptr(), file.handle, parent.handle, &mut bn_obj);

            if res.is_null() {
                // TODO not sure when this can even happen, let alone what we're supposed to do about
                // it. cb_init isn't normally called until later, and cb_free_object definitely won't
                // have been called, so we'd at least be on the hook for freeing that stuff...
                // probably.
                //
                // no idea how to force this to fail so I can test this, so just going to do the
                // reasonable thing and panic.
                panic!("failed to create custom binary view!");
            }

            (*ctxt).raw_handle = res;

            Ok(CustomView {
                handle: Ref::new(BinaryView::from_raw(res)),
                _builder: PhantomData,
            })
        }
    }

    pub fn wrap_existing(self, wrapped_view: Ref<BinaryView>) -> Result<CustomView<'a>>
    {
        Ok(CustomView {
            handle: wrapped_view,
            _builder: PhantomData,
        })
    }
}

