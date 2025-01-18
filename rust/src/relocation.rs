use crate::low_level_il::RegularLowLevelILFunction;
use crate::rc::Guard;
use crate::string::BnStrCompatible;
use crate::{
    architecture::CoreArchitecture,
    binary_view::BinaryView,
    rc::{CoreArrayProvider, CoreArrayProviderInner, Ref, RefCountable},
    symbol::Symbol,
};
use binaryninjacore_sys::*;
use std::borrow::Borrow;
use std::mem::MaybeUninit;
use std::os::raw::c_void;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RelocationType {
    ELFGlobalRelocationType,
    ELFCopyRelocationType,
    ELFJumpSlotRelocationType,
    StandardRelocationType,
    IgnoredRelocation,
    UnhandledRelocation,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RelocationOperand {
    Operand(usize),
    AutocoerceExternPtr,
    NocoerceExternPtr,
    Invalid,
}

impl From<BNRelocationType> for RelocationType {
    fn from(t: BNRelocationType) -> Self {
        match t {
            BNRelocationType::ELFGlobalRelocationType => RelocationType::ELFGlobalRelocationType,
            BNRelocationType::ELFCopyRelocationType => RelocationType::ELFCopyRelocationType,
            BNRelocationType::ELFJumpSlotRelocationType => {
                RelocationType::ELFJumpSlotRelocationType
            }
            BNRelocationType::StandardRelocationType => RelocationType::StandardRelocationType,
            BNRelocationType::IgnoredRelocation => RelocationType::IgnoredRelocation,
            BNRelocationType::UnhandledRelocation => RelocationType::UnhandledRelocation,
        }
    }
}

impl From<RelocationType> for BNRelocationType {
    fn from(t: RelocationType) -> Self {
        match t {
            RelocationType::ELFGlobalRelocationType => BNRelocationType::ELFGlobalRelocationType,
            RelocationType::ELFCopyRelocationType => BNRelocationType::ELFCopyRelocationType,
            RelocationType::ELFJumpSlotRelocationType => {
                BNRelocationType::ELFJumpSlotRelocationType
            }
            RelocationType::StandardRelocationType => BNRelocationType::StandardRelocationType,
            RelocationType::IgnoredRelocation => BNRelocationType::IgnoredRelocation,
            RelocationType::UnhandledRelocation => BNRelocationType::UnhandledRelocation,
        }
    }
}

impl From<usize> for RelocationOperand {
    fn from(operand: usize) -> Self {
        match operand {
            0xfffffffd => RelocationOperand::AutocoerceExternPtr,
            0xfffffffe => RelocationOperand::NocoerceExternPtr,
            0xffffffff => RelocationOperand::Invalid,
            _ => RelocationOperand::Operand(operand),
        }
    }
}

impl From<RelocationOperand> for usize {
    fn from(operand: RelocationOperand) -> Self {
        match operand {
            RelocationOperand::Operand(operand) => operand,
            RelocationOperand::AutocoerceExternPtr => 0xfffffffd,
            RelocationOperand::NocoerceExternPtr => 0xfffffffe,
            RelocationOperand::Invalid => 0xffffffff,
        }
    }
}

// TODO: How to handle related relocation linked lists?
#[derive(Clone)]
pub struct RelocationInfo {
    pub type_: RelocationType,
    pub pc_relative: bool,
    pub base_relative: bool,
    pub base: u64,
    pub size: usize,
    pub truncate_size: usize,
    pub native_type: u64,
    pub addend: usize,
    pub has_sign: bool,
    pub implicit_addend: bool,
    pub external: bool,
    pub symbol_index: usize,
    pub section_index: usize,
    pub address: u64,
    pub target: u64,
    pub data_relocation: bool,
    relocation_data_cache: [u8; MAX_RELOCATION_SIZE as usize],
}

impl RelocationInfo {
    pub fn new() -> Self {
        RelocationInfo {
            type_: RelocationType::UnhandledRelocation,
            pc_relative: false,
            base_relative: false,
            base: 0,
            size: 0,
            truncate_size: 0,
            native_type: 0,
            addend: 0,
            has_sign: false,
            implicit_addend: false,
            external: false,
            symbol_index: 0,
            section_index: 0,
            address: 0,
            target: 0,
            data_relocation: false,
            relocation_data_cache: [0; MAX_RELOCATION_SIZE as usize],
        }
    }

    pub(crate) fn from_raw(reloc: &BNRelocationInfo) -> Self {
        RelocationInfo {
            type_: reloc.type_.into(),
            pc_relative: reloc.pcRelative,
            base_relative: reloc.baseRelative,
            base: reloc.base,
            size: reloc.size,
            truncate_size: reloc.truncateSize,
            native_type: reloc.nativeType,
            addend: reloc.addend,
            has_sign: reloc.hasSign,
            implicit_addend: reloc.implicitAddend,
            external: reloc.external,
            symbol_index: reloc.symbolIndex,
            section_index: reloc.sectionIndex,
            address: reloc.address,
            target: reloc.target,
            data_relocation: reloc.dataRelocation,
            relocation_data_cache: reloc.relocationDataCache,
        }
    }

    pub(crate) fn as_raw(&self) -> BNRelocationInfo {
        BNRelocationInfo {
            type_: self.type_.into(),
            pcRelative: self.pc_relative,
            baseRelative: self.base_relative,
            base: self.base,
            size: self.size,
            truncateSize: self.truncate_size,
            nativeType: self.native_type,
            addend: self.addend,
            hasSign: self.has_sign,
            implicitAddend: self.implicit_addend,
            external: self.external,
            symbolIndex: self.symbol_index,
            sectionIndex: self.section_index,
            address: self.address,
            target: self.target,
            dataRelocation: self.data_relocation,
            relocationDataCache: self.relocation_data_cache,
            // TODO: How to handle this?
            prev: core::ptr::null_mut(),
            next: core::ptr::null_mut(),
        }
    }
}

impl Default for RelocationInfo {
    fn default() -> Self {
        Self::new()
    }
}

// TODO: There is NO freeing of the relocation
// TODO: A quick look it seem that the relocation ptr is always not owned so this is _fine_
// TODO: REALLY need to come back to this at some point.
pub struct Relocation(*mut BNRelocation);

impl Relocation {
    pub(crate) unsafe fn from_raw(reloc: *mut BNRelocation) -> Self {
        Relocation(reloc)
    }

    pub fn info(&self) -> RelocationInfo {
        RelocationInfo::from_raw(unsafe { &BNRelocationGetInfo(self.0) })
    }

    pub fn architecture(&self) -> Option<CoreArchitecture> {
        let raw = unsafe { BNRelocationGetArchitecture(self.0) };
        if raw.is_null() {
            return None;
        }

        Some(unsafe { CoreArchitecture::from_raw(raw) })
    }

    pub fn target(&self) -> u64 {
        unsafe { BNRelocationGetTarget(self.0) }
    }

    pub fn address(&self) -> u64 {
        unsafe { BNRelocationGetReloc(self.0) }
    }

    pub fn symbol(&self) -> Option<Ref<Symbol>> {
        let raw = unsafe { BNRelocationGetSymbol(self.0) };
        if raw.is_null() {
            return None;
        }

        Some(unsafe { Symbol::ref_from_raw(raw) })
    }
}

impl CoreArrayProvider for Relocation {
    type Raw = *mut BNRelocation;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Relocation>;
}

unsafe impl CoreArrayProviderInner for Relocation {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeRelocationList(raw, count);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Guard::new(Relocation(*raw), &())
    }
}

pub trait RelocationHandler: 'static + Sized + AsRef<CoreRelocationHandler> {
    type Handle: Borrow<Self>;

    fn get_relocation_info(
        &self,
        _bv: &BinaryView,
        _arch: &CoreArchitecture,
        _info: &mut [RelocationInfo],
    ) -> bool {
        false
    }

    fn apply_relocation(
        &self,
        bv: &BinaryView,
        arch: &CoreArchitecture,
        reloc: &Relocation,
        dest: &mut [u8],
    ) -> bool {
        self.default_apply_relocation(bv, arch, reloc, dest)
    }

    fn get_operand_for_external_relocation(
        &self,
        _data: &[u8],
        _addr: u64,
        // TODO: Are we sure this is not a liftedilfunction?
        _il: &RegularLowLevelILFunction<CoreArchitecture>,
        _reloc: &Relocation,
    ) -> RelocationOperand {
        RelocationOperand::AutocoerceExternPtr
    }

    fn handle(&self) -> Self::Handle;
}

pub trait RelocationHandlerExt: RelocationHandler {
    fn default_apply_relocation(
        &self,
        bv: &BinaryView,
        arch: &CoreArchitecture,
        reloc: &Relocation,
        dest: &mut [u8],
    ) -> bool {
        unsafe {
            BNRelocationHandlerDefaultApplyRelocation(
                self.as_ref().0,
                bv.handle,
                arch.handle,
                reloc.0,
                dest.as_mut_ptr(),
                dest.len(),
            )
        }
    }
}

impl<T: RelocationHandler> RelocationHandlerExt for T {}

#[derive(Eq, PartialEq, Hash, Debug)]
pub struct CoreRelocationHandler(*mut BNRelocationHandler);

unsafe impl Send for CoreRelocationHandler {}
unsafe impl Sync for CoreRelocationHandler {}

impl CoreRelocationHandler {
    pub(crate) unsafe fn ref_from_raw(raw: *mut BNRelocationHandler) -> Ref<Self> {
        unsafe { Ref::new(CoreRelocationHandler(raw)) }
    }
}

impl AsRef<CoreRelocationHandler> for CoreRelocationHandler {
    fn as_ref(&self) -> &Self {
        self
    }
}

impl RelocationHandler for CoreRelocationHandler {
    type Handle = Self;

    fn get_relocation_info(
        &self,
        bv: &BinaryView,
        arch: &CoreArchitecture,
        info: &mut [RelocationInfo],
    ) -> bool {
        let mut raw_info = info.iter().map(|i| i.as_raw()).collect::<Vec<_>>();
        let res = unsafe {
            BNRelocationHandlerGetRelocationInfo(
                self.0,
                bv.handle,
                arch.handle,
                raw_info.as_mut_ptr(),
                raw_info.len(),
            )
        };
        for (info, raw) in info.iter_mut().zip(raw_info.iter()) {
            *info = RelocationInfo::from_raw(raw);
        }
        res
    }

    fn apply_relocation(
        &self,
        bv: &BinaryView,
        arch: &CoreArchitecture,
        reloc: &Relocation,
        dest: &mut [u8],
    ) -> bool {
        unsafe {
            BNRelocationHandlerApplyRelocation(
                self.0,
                bv.handle,
                arch.handle,
                reloc.0,
                dest.as_mut_ptr(),
                dest.len(),
            )
        }
    }

    fn get_operand_for_external_relocation(
        &self,
        data: &[u8],
        addr: u64,
        il: &RegularLowLevelILFunction<CoreArchitecture>,
        reloc: &Relocation,
    ) -> RelocationOperand {
        unsafe {
            BNRelocationHandlerGetOperandForExternalRelocation(
                self.0,
                data.as_ptr(),
                addr,
                data.len(),
                il.handle,
                reloc.0,
            )
            .into()
        }
    }

    fn handle(&self) -> CoreRelocationHandler {
        CoreRelocationHandler(self.0)
    }
}

impl ToOwned for CoreRelocationHandler {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for CoreRelocationHandler {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self(BNNewRelocationHandlerReference(handle.0)))
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeRelocationHandler(handle.0);
    }
}

pub(crate) fn register_relocation_handler<S, R, F>(arch: &CoreArchitecture, name: S, func: F)
where
    S: BnStrCompatible,
    R: 'static + RelocationHandler<Handle = CustomRelocationHandlerHandle<R>> + Send + Sync + Sized,
    F: FnOnce(CustomRelocationHandlerHandle<R>, CoreRelocationHandler) -> R,
{
    #[repr(C)]
    struct RelocationHandlerBuilder<R>
    where
        R: 'static + RelocationHandler<Handle = CustomRelocationHandlerHandle<R>> + Send + Sync,
    {
        handler: R,
    }

    extern "C" fn cb_free<R>(ctxt: *mut c_void)
    where
        R: 'static + RelocationHandler<Handle = CustomRelocationHandlerHandle<R>> + Send + Sync,
    {
        unsafe {
            let _handler = Box::from_raw(ctxt as *mut RelocationHandlerBuilder<R>);
        }
    }

    extern "C" fn cb_get_relocation_info<R>(
        ctxt: *mut c_void,
        bv: *mut BNBinaryView,
        arch: *mut BNArchitecture,
        result: *mut BNRelocationInfo,
        count: usize,
    ) -> bool
    where
        R: 'static + RelocationHandler<Handle = CustomRelocationHandlerHandle<R>> + Send + Sync,
    {
        let custom_handler = unsafe { &*(ctxt as *mut R) };
        let bv = unsafe { BinaryView::ref_from_raw(BNNewViewReference(bv)) };
        let arch = unsafe { CoreArchitecture::from_raw(arch) };
        let result = unsafe { core::slice::from_raw_parts_mut(result, count) };
        let mut info = result
            .iter()
            .map(RelocationInfo::from_raw)
            .collect::<Vec<_>>();
        let ok =
            custom_handler.get_relocation_info(bv.as_ref(), arch.as_ref(), info.as_mut_slice());
        for (result, info) in result.iter_mut().zip(info.iter()) {
            *result = info.as_raw();
        }
        ok
    }

    extern "C" fn cb_apply_relocation<R>(
        ctxt: *mut c_void,
        bv: *mut BNBinaryView,
        arch: *mut BNArchitecture,
        reloc: *mut BNRelocation,
        dest: *mut u8,
        len: usize,
    ) -> bool
    where
        R: 'static + RelocationHandler<Handle = CustomRelocationHandlerHandle<R>> + Send + Sync,
    {
        let custom_handler = unsafe { &*(ctxt as *mut R) };
        let bv = unsafe { BinaryView::ref_from_raw(BNNewViewReference(bv)) };
        let arch = unsafe { CoreArchitecture::from_raw(arch) };
        let reloc = unsafe { Relocation::from_raw(reloc) };
        let dest = unsafe { core::slice::from_raw_parts_mut(dest, len) };
        custom_handler.apply_relocation(bv.as_ref(), arch.as_ref(), &reloc, dest)
    }

    extern "C" fn cb_get_operand_for_external_relocation<R>(
        ctxt: *mut c_void,
        data: *const u8,
        addr: u64,
        len: usize,
        il: *mut BNLowLevelILFunction,
        reloc: *mut BNRelocation,
    ) -> usize
    where
        R: 'static + RelocationHandler<Handle = CustomRelocationHandlerHandle<R>> + Send + Sync,
    {
        let custom_handler = unsafe { &*(ctxt as *mut R) };
        let data = unsafe { core::slice::from_raw_parts(data, len) };
        let reloc = unsafe { Relocation::from_raw(reloc) };

        let func = unsafe { BNGetLowLevelILOwnerFunction(il) };
        if func.is_null() {
            return RelocationOperand::Invalid.into();
        }

        let arch = unsafe { BNGetFunctionArchitecture(func) };
        unsafe { BNFreeFunction(func) };
        if arch.is_null() {
            return RelocationOperand::Invalid.into();
        }
        let arch = unsafe { CoreArchitecture::from_raw(arch) };
        let il = unsafe { RegularLowLevelILFunction::from_raw(arch, il) };

        custom_handler
            .get_operand_for_external_relocation(data, addr, &il, &reloc)
            .into()
    }

    let name = name.into_bytes_with_nul();

    let raw = Box::leak(Box::new(
        MaybeUninit::<RelocationHandlerBuilder<_>>::zeroed(),
    ));
    let mut custom_handler = BNCustomRelocationHandler {
        context: raw.as_mut_ptr() as *mut _,
        freeObject: Some(cb_free::<R>),
        getRelocationInfo: Some(cb_get_relocation_info::<R>),
        applyRelocation: Some(cb_apply_relocation::<R>),
        getOperandForExternalRelocation: Some(cb_get_operand_for_external_relocation::<R>),
    };

    let handle_raw = unsafe { BNCreateRelocationHandler(&mut custom_handler) };
    assert!(!handle_raw.is_null());
    let handle = CoreRelocationHandler(handle_raw);
    let custom_handle = CustomRelocationHandlerHandle {
        handle: raw.as_mut_ptr() as *mut R,
    };
    unsafe {
        raw.write(RelocationHandlerBuilder {
            handler: func(custom_handle, CoreRelocationHandler(handle.0)),
        });

        BNArchitectureRegisterRelocationHandler(
            arch.handle,
            name.as_ref().as_ptr() as *const _,
            handle.handle().as_ref().0,
        );
    }
}

pub struct CustomRelocationHandlerHandle<R>
where
    R: 'static + RelocationHandler<Handle = CustomRelocationHandlerHandle<R>> + Send + Sync,
{
    handle: *mut R,
}

unsafe impl<R> Send for CustomRelocationHandlerHandle<R> where
    R: 'static + RelocationHandler<Handle = CustomRelocationHandlerHandle<R>> + Send + Sync
{
}

unsafe impl<R> Sync for CustomRelocationHandlerHandle<R> where
    R: 'static + RelocationHandler<Handle = CustomRelocationHandlerHandle<R>> + Send + Sync
{
}

impl<R> Clone for CustomRelocationHandlerHandle<R>
where
    R: 'static + RelocationHandler<Handle = Self> + Send + Sync,
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<R> Copy for CustomRelocationHandlerHandle<R> where
    R: 'static + RelocationHandler<Handle = Self> + Send + Sync
{
}

impl<R> Borrow<R> for CustomRelocationHandlerHandle<R>
where
    R: 'static + RelocationHandler<Handle = Self> + Send + Sync,
{
    fn borrow(&self) -> &R {
        unsafe { &*self.handle }
    }
}
