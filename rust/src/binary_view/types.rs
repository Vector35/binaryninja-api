//! Interaction with [`CoreBinaryViewType`] and registration of custom view types with [`BinaryViewType`].

use std::ffi::c_void;
use std::mem::MaybeUninit;

use binaryninjacore_sys::*;

use crate::architecture::Architecture;
use crate::binary_view::custom::{CustomView, CustomViewBuilder};
use crate::binary_view::BinaryView;
use crate::metadata::Metadata;
use crate::platform::Platform;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Guard, Ref};
use crate::settings::Settings;
use crate::string::{BnString, IntoCStr};
use crate::Endianness;

/// Registers a custom `BinaryViewType` with the core.
///
/// The `constructor` argument is called immediately after successful registration of the type with
/// the core. The `BinaryViewType` argument passed to `constructor` is the object that the
/// `AsRef<BinaryViewType>`
/// implementation of the `CustomBinaryViewType` must return.
pub fn register_view_type<T, F>(name: &str, long_name: &str, constructor: F) -> &'static T
where
    T: BinaryViewType,
    F: FnOnce(CoreBinaryViewType) -> T,
{
    extern "C" fn cb_valid<T>(ctxt: *mut c_void, data: *mut BNBinaryView) -> bool
    where
        T: BinaryViewType,
    {
        ffi_wrap!("BinaryViewTypeBase::is_valid_for", unsafe {
            let view_type = &*(ctxt as *mut T);
            let data = BinaryView::from_raw(data);
            view_type.is_valid_for(&data)
        })
    }

    extern "C" fn cb_deprecated<T>(ctxt: *mut c_void) -> bool
    where
        T: BinaryViewType,
    {
        ffi_wrap!("BinaryViewTypeBase::is_deprecated", unsafe {
            let view_type = &*(ctxt as *mut T);
            view_type.is_deprecated()
        })
    }

    extern "C" fn cb_force_loadable<T>(ctxt: *mut c_void) -> bool
    where
        T: BinaryViewType,
    {
        ffi_wrap!("BinaryViewTypeBase::is_force_loadable", unsafe {
            let view_type = &*(ctxt as *mut T);
            view_type.is_force_loadable()
        })
    }

    extern "C" fn cb_create<T>(ctxt: *mut c_void, data: *mut BNBinaryView) -> *mut BNBinaryView
    where
        T: BinaryViewType,
    {
        ffi_wrap!("BinaryViewTypeBase::create", unsafe {
            let view_type = &*(ctxt as *mut T);
            let data = BinaryView::from_raw(data);

            let builder = CustomViewBuilder {
                view_type,
                actual_parent: &data,
            };

            match view_type.create_custom_view(&data, builder) {
                Ok(bv) => {
                    // force a leak of the Ref; failure to do this would result
                    // in the refcount going to 0 in the process of returning it
                    // to the core -- we're transferring ownership of the Ref here
                    Ref::into_raw(bv.handle).handle
                }
                Err(_) => {
                    log::error!("CustomBinaryViewType::create_custom_view returned Err");
                    std::ptr::null_mut()
                }
            }
        })
    }

    extern "C" fn cb_parse<T>(ctxt: *mut c_void, data: *mut BNBinaryView) -> *mut BNBinaryView
    where
        T: BinaryViewType,
    {
        ffi_wrap!("BinaryViewTypeBase::parse", unsafe {
            let view_type = &*(ctxt as *mut T);
            let data = BinaryView::from_raw(data);

            let builder = CustomViewBuilder {
                view_type,
                actual_parent: &data,
            };

            match view_type.parse_custom_view(&data, builder) {
                Ok(bv) => {
                    // force a leak of the Ref; failure to do this would result
                    // in the refcount going to 0 in the process of returning it
                    // to the core -- we're transferring ownership of the Ref here
                    Ref::into_raw(bv.handle).handle
                }
                Err(_) => {
                    log::error!("CustomBinaryViewType::parse returned Err");
                    std::ptr::null_mut()
                }
            }
        })
    }

    extern "C" fn cb_load_settings<T>(ctxt: *mut c_void, data: *mut BNBinaryView) -> *mut BNSettings
    where
        T: BinaryViewType,
    {
        ffi_wrap!("BinaryViewTypeBase::load_settings", unsafe {
            let view_type = &*(ctxt as *mut T);
            let data = BinaryView::ref_from_raw(BNNewViewReference(data));

            match view_type.load_settings_for_data(&data) {
                Some(settings) => Ref::into_raw(settings).handle,
                None => std::ptr::null_mut() as *mut _,
            }
        })
    }

    let name = name.to_cstr();
    let name_ptr = name.as_ptr();

    let long_name = long_name.to_cstr();
    let long_name_ptr = long_name.as_ptr();

    let ctxt = Box::leak(Box::new(MaybeUninit::zeroed()));

    let mut bn_obj = BNCustomBinaryViewType {
        context: ctxt.as_mut_ptr() as *mut _,
        create: Some(cb_create::<T>),
        parse: Some(cb_parse::<T>),
        isValidForData: Some(cb_valid::<T>),
        isDeprecated: Some(cb_deprecated::<T>),
        isForceLoadable: Some(cb_force_loadable::<T>),
        getLoadSettingsForData: Some(cb_load_settings::<T>),
    };

    unsafe {
        let handle = BNRegisterBinaryViewType(name_ptr, long_name_ptr, &mut bn_obj as *mut _);
        if handle.is_null() {
            // avoid leaking the space allocated for the type, but also
            // avoid running its Drop impl (if any -- not that there should
            // be one since view types live for the life of the process) as
            // MaybeUninit suppress the Drop implementation of it's inner type
            drop(Box::from_raw(ctxt));

            panic!("bvt registration failed");
        }

        ctxt.write(constructor(CoreBinaryViewType { handle }));
        ctxt.assume_init_mut()
    }
}

pub trait BinaryViewTypeBase: AsRef<CoreBinaryViewType> {
    fn is_valid_for(&self, data: &BinaryView) -> bool;

    fn is_deprecated(&self) -> bool {
        false
    }

    fn is_force_loadable(&self) -> bool {
        false
    }

    fn default_load_settings_for_data(&self, data: &BinaryView) -> Option<Ref<Settings>> {
        let settings_handle =
            unsafe { BNGetBinaryViewDefaultLoadSettingsForData(self.as_ref().handle, data.handle) };

        if settings_handle.is_null() {
            None
        } else {
            unsafe { Some(Settings::ref_from_raw(settings_handle)) }
        }
    }

    fn load_settings_for_data(&self, _data: &BinaryView) -> Option<Ref<Settings>> {
        None
    }
}

pub trait BinaryViewTypeExt: BinaryViewTypeBase {
    fn name(&self) -> String {
        unsafe { BnString::into_string(BNGetBinaryViewTypeName(self.as_ref().handle)) }
    }

    fn long_name(&self) -> String {
        unsafe { BnString::into_string(BNGetBinaryViewTypeLongName(self.as_ref().handle)) }
    }

    fn register_arch<A: Architecture>(&self, id: u32, endianness: Endianness, arch: &A) {
        unsafe {
            BNRegisterArchitectureForViewType(
                self.as_ref().handle,
                id,
                endianness,
                arch.as_ref().handle,
            );
        }
    }

    fn register_platform(&self, id: u32, plat: &Platform) {
        let arch = plat.arch();

        unsafe {
            BNRegisterPlatformForViewType(self.as_ref().handle, id, arch.handle, plat.handle);
        }
    }

    /// Expanded identification of [`Platform`] for [`CoreBinaryViewType`]'s. Supersedes [`BinaryViewTypeExt::register_arch`]
    /// and [`BinaryViewTypeExt::register_platform`], as these have certain edge cases (overloaded elf families, for example)
    /// that can't be represented.
    ///
    /// The callback returns a [`Platform`] object or `None` (failure), and most recently added callbacks are called first
    /// to allow plugins to override any default behaviors. When a callback returns a platform, architecture will be
    /// derived from the identified platform.
    ///
    /// The [`BinaryView`] is the *parent* view (usually 'Raw') that the [`BinaryView`] is being created for. This
    /// means that generally speaking the callbacks need to be aware of the underlying file format, however the
    /// [`BinaryView`] implementation may have created datavars in the 'Raw' view by the time the callback is invoked.
    /// Behavior regarding when this callback is invoked and what has been made available in the [`BinaryView`] passed as an
    /// argument to the callback is up to the discretion of the [`BinaryView`] implementation.
    ///
    /// The `id` ind `endian` arguments are used as a filter to determine which registered [`Platform`] recognizer callbacks
    /// are invoked.
    ///
    /// Support for this API tentatively requires explicit support in the [`BinaryView`] implementation.
    fn register_platform_recognizer<R>(&self, id: u32, endian: Endianness, recognizer: R)
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
            ctxt: *mut c_void,
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
        // TODO: Currently we leak `recognizer`.
        let raw = Box::into_raw(Box::new(recognizer));

        unsafe {
            BNRegisterPlatformRecognizerForViewType(
                self.as_ref().handle,
                id as u64,
                endian,
                Some(cb_recognize_low_level_il::<R>),
                raw as *mut c_void,
            )
        }
    }

    fn open(&self, data: &BinaryView) -> crate::binary_view::Result<Ref<BinaryView>> {
        let handle = unsafe { BNCreateBinaryViewOfType(self.as_ref().handle, data.handle) };

        if handle.is_null() {
            log::error!(
                "failed to create BinaryView of BinaryViewType '{}'",
                self.name()
            );
            return Err(());
        }

        unsafe { Ok(BinaryView::ref_from_raw(handle)) }
    }

    fn parse(&self, data: &BinaryView) -> crate::binary_view::Result<Ref<BinaryView>> {
        let handle = unsafe { BNParseBinaryViewOfType(self.as_ref().handle, data.handle) };

        if handle.is_null() {
            log::error!(
                "failed to parse BinaryView of BinaryViewType '{}'",
                self.name()
            );
            return Err(());
        }

        unsafe { Ok(BinaryView::ref_from_raw(handle)) }
    }
}

impl<T: BinaryViewTypeBase> BinaryViewTypeExt for T {}

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct CoreBinaryViewType {
    pub handle: *mut BNBinaryViewType,
}

impl CoreBinaryViewType {
    pub(crate) unsafe fn from_raw(handle: *mut BNBinaryViewType) -> Self {
        debug_assert!(!handle.is_null());
        Self { handle }
    }

    pub fn list_all() -> Array<CoreBinaryViewType> {
        unsafe {
            let mut count: usize = 0;
            let types = BNGetBinaryViewTypes(&mut count as *mut _);
            Array::new(types, count, ())
        }
    }

    pub fn list_valid_types_for(data: &BinaryView) -> Array<CoreBinaryViewType> {
        unsafe {
            let mut count: usize = 0;
            let types = BNGetBinaryViewTypesForData(data.handle, &mut count as *mut _);
            Array::new(types, count, ())
        }
    }

    /// Looks up a BinaryViewType by its short name
    pub fn by_name(name: &str) -> Option<Self> {
        let bytes = name.to_cstr();
        let handle = unsafe { BNGetBinaryViewTypeByName(bytes.as_ref().as_ptr() as *const _) };
        match handle.is_null() {
            false => Some(unsafe { CoreBinaryViewType::from_raw(handle) }),
            true => None,
        }
    }
}

impl BinaryViewTypeBase for CoreBinaryViewType {
    fn is_valid_for(&self, data: &BinaryView) -> bool {
        unsafe { BNIsBinaryViewTypeValidForData(self.handle, data.handle) }
    }

    fn is_deprecated(&self) -> bool {
        unsafe { BNIsBinaryViewTypeDeprecated(self.handle) }
    }

    fn is_force_loadable(&self) -> bool {
        unsafe { BNIsBinaryViewTypeForceLoadable(self.handle) }
    }

    fn load_settings_for_data(&self, data: &BinaryView) -> Option<Ref<Settings>> {
        let settings_handle =
            unsafe { BNGetBinaryViewLoadSettingsForData(self.handle, data.handle) };

        if settings_handle.is_null() {
            None
        } else {
            unsafe { Some(Settings::ref_from_raw(settings_handle)) }
        }
    }
}

impl CoreArrayProvider for CoreBinaryViewType {
    type Raw = *mut BNBinaryViewType;
    type Context = ();
    type Wrapped<'a> = Guard<'a, CoreBinaryViewType>;
}

unsafe impl CoreArrayProviderInner for CoreBinaryViewType {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeBinaryViewTypeList(raw);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Guard::new(CoreBinaryViewType::from_raw(*raw), &())
    }
}

impl AsRef<CoreBinaryViewType> for CoreBinaryViewType {
    fn as_ref(&self) -> &Self {
        self
    }
}

unsafe impl Send for CoreBinaryViewType {}
unsafe impl Sync for CoreBinaryViewType {}

pub trait BinaryViewType: 'static + BinaryViewTypeBase + Sync {
    fn create_custom_view<'builder>(
        &self,
        data: &BinaryView,
        builder: CustomViewBuilder<'builder, Self>,
    ) -> crate::binary_view::Result<CustomView<'builder>>;

    fn parse_custom_view<'builder>(
        &self,
        data: &BinaryView,
        builder: CustomViewBuilder<'builder, Self>,
    ) -> crate::binary_view::Result<CustomView<'builder>> {
        // TODO: Check to make sure data.type_name is not Self::type_name ?
        self.create_custom_view(data, builder)
    }
}
