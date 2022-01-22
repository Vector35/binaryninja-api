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

use std::marker::PhantomData;
use std::mem;
use std::os::raw::c_void;
use std::ptr;
use std::slice;

use crate::architecture::Architecture;
use crate::binaryview::{BinaryView, BinaryViewBase, BinaryViewExt, Result};
use crate::platform::Platform;
use crate::settings::Settings;
use crate::Endianness;

use crate::rc::*;
use crate::string::*;

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
        T: CustomBinaryViewType,
    {
        ffi_wrap!("BinaryViewTypeBase::is_valid_for", unsafe {
            let view_type = &*(ctxt as *mut T);
            let data = BinaryView::from_raw(data);

            view_type.is_valid_for(&data)
        })
    }

    extern "C" fn cb_create<T>(ctxt: *mut c_void, data: *mut BNBinaryView) -> *mut BNBinaryView
    where
        T: CustomBinaryViewType,
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

    extern "C" fn cb_parse<T>(_ctxt: *mut c_void, _data: *mut BNBinaryView) -> *mut BNBinaryView
    where
        T: CustomBinaryViewType,
    {
        ffi_wrap!("BinaryViewTypeBase::parse", ptr::null_mut())
    }

    extern "C" fn cb_load_settings<T>(ctxt: *mut c_void, data: *mut BNBinaryView) -> *mut BNSettings
    where
        T: CustomBinaryViewType,
    {
        ffi_wrap!("BinaryViewTypeBase::load_settings", unsafe {
            let view_type = &*(ctxt as *mut T);
            let data = BinaryView::from_raw(data);

            match view_type.load_settings_for_data(&data) {
                Ok(settings) => Ref::into_raw(settings).handle,
                _ => ptr::null_mut() as *mut _,
            }
        })
    }

    let name = name.as_bytes_with_nul();
    let name_ptr = name.as_ref().as_ptr() as *mut _;

    let long_name = long_name.as_bytes_with_nul();
    let long_name_ptr = long_name.as_ref().as_ptr() as *mut _;

    let ctxt = Box::new(unsafe { mem::zeroed() });
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

pub trait BinaryViewTypeBase: AsRef<BinaryViewType> {
    fn is_valid_for(&self, data: &BinaryView) -> bool;

    fn load_settings_for_data(&self, data: &BinaryView) -> Result<Ref<Settings>> {
        let settings_handle =
            unsafe { BNGetBinaryViewDefaultLoadSettingsForData(self.as_ref().0, data.handle) };

        if settings_handle.is_null() {
            Err(())
        } else {
            unsafe { Ok(Settings::from_raw(settings_handle)) }
        }
    }
}

pub trait BinaryViewTypeExt: BinaryViewTypeBase {
    fn name(&self) -> BnString {
        unsafe { BnString::from_raw(BNGetBinaryViewTypeName(self.as_ref().0)) }
    }

    fn long_name(&self) -> BnString {
        unsafe { BnString::from_raw(BNGetBinaryViewTypeLongName(self.as_ref().0)) }
    }

    fn register_arch<A: Architecture>(&self, id: u32, endianness: Endianness, arch: &A) {
        unsafe {
            BNRegisterArchitectureForViewType(self.as_ref().0, id, endianness, arch.as_ref().0);
        }
    }

    fn register_platform(&self, id: u32, plat: &Platform) {
        let arch = plat.arch();

        unsafe {
            BNRegisterPlatformForViewType(self.as_ref().0, id, arch.0, plat.handle);
        }
    }

    fn open(&self, data: &BinaryView) -> Result<Ref<BinaryView>> {
        let handle = unsafe { BNCreateBinaryViewOfType(self.as_ref().0, data.handle) };

        if handle.is_null() {
            error!(
                "failed to create BinaryView of BinaryViewType '{}'",
                self.name()
            );
            return Err(());
        }

        unsafe { Ok(BinaryView::from_raw(handle)) }
    }
}

impl<T: BinaryViewTypeBase> BinaryViewTypeExt for T {}

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct BinaryViewType(pub *mut BNBinaryViewType);

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

impl BinaryViewTypeBase for BinaryViewType {
    fn is_valid_for(&self, data: &BinaryView) -> bool {
        unsafe { BNIsBinaryViewTypeValidForData(self.0, data.handle) }
    }

    fn load_settings_for_data(&self, data: &BinaryView) -> Result<Ref<Settings>> {
        let settings_handle =
            unsafe { BNGetBinaryViewDefaultLoadSettingsForData(self.as_ref().0, data.handle) };

        if settings_handle.is_null() {
            Err(())
        } else {
            unsafe { Ok(Settings::from_raw(settings_handle)) }
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

impl AsRef<BinaryViewType> for BinaryViewType {
    fn as_ref(&self) -> &Self {
        self
    }
}

unsafe impl Send for BinaryViewType {}
unsafe impl Sync for BinaryViewType {}

pub trait CustomBinaryViewType: 'static + BinaryViewTypeBase + Sync {
    fn create_custom_view<'builder>(
        &self,
        data: &BinaryView,
        builder: CustomViewBuilder<'builder, Self>,
    ) -> Result<CustomView<'builder>>;
}

/// Represents a request from the core to instantiate a custom BinaryView
pub struct CustomViewBuilder<'a, T: CustomBinaryViewType + ?Sized> {
    view_type: &'a T,
    actual_parent: &'a BinaryView,
}

pub unsafe trait CustomBinaryView: 'static + BinaryViewBase + Sync + Sized {
    type Args: Send;

    fn new(handle: &BinaryView, args: &Self::Args) -> Result<Self>;
    fn init(&self, args: Self::Args) -> Result<()>;
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
            error!(
                "attempt to create duplicate view of type '{}' (existing: {:?})",
                view_name.as_str(),
                bv.handle
            );

            return Err(());
        }

        // wildly unsafe struct representing the context of a BNCustomBinaryView
        // this type should *never* be allowed to drop as the fields are in varying
        // states of uninitialized/already consumed throughout the life of the object.
        struct CustomViewContext<V>
        where
            V: CustomBinaryView,
        {
            view: mem::MaybeUninit<V>,
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

                match V::new(handle.as_ref(), &context.args) {
                    Ok(v) => {
                        ptr::write(&mut context.view, mem::MaybeUninit::new(v));
                        context.initialized = true;

                        match context
                            .view
                            .assume_init_ref()
                            .init(ptr::read(&context.args))
                        {
                            Ok(_) => true,
                            Err(_) => {
                                error!("CustomBinaryView::init failed; custom view returned Err");
                                false
                            }
                        }
                    }
                    Err(_) => {
                        error!("CustomBinaryView::new failed; custom view returned Err");
                        false
                    }
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
                        error!(
              "BinaryViewBase::freeObject called on partially initialized object! crash imminent!"
            );
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

        extern "C" fn cb_read<V>(
            ctxt: *mut c_void,
            dest: *mut c_void,
            offset: u64,
            len: usize,
        ) -> usize
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::read", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);
                let dest = slice::from_raw_parts_mut(dest as *mut u8, len);

                context.view.assume_init_ref().read(dest, offset)
            })
        }

        extern "C" fn cb_write<V>(
            ctxt: *mut c_void,
            offset: u64,
            src: *const c_void,
            len: usize,
        ) -> usize
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::write", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);
                let src = slice::from_raw_parts(src as *const u8, len);

                context.view.assume_init_ref().write(offset, src)
            })
        }

        extern "C" fn cb_insert<V>(
            ctxt: *mut c_void,
            offset: u64,
            src: *const c_void,
            len: usize,
        ) -> usize
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::insert", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);
                let src = slice::from_raw_parts(src as *const u8, len);

                context.view.assume_init_ref().insert(offset, src)
            })
        }

        extern "C" fn cb_remove<V>(ctxt: *mut c_void, offset: u64, len: u64) -> usize
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::remove", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);

                context.view.assume_init_ref().remove(offset, len as usize)
            })
        }

        extern "C" fn cb_modification<V>(ctxt: *mut c_void, offset: u64) -> ModificationStatus
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::modification_status", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);

                context.view.assume_init_ref().modification_status(offset)
            })
        }

        extern "C" fn cb_offset_valid<V>(ctxt: *mut c_void, offset: u64) -> bool
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::offset_valid", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);

                context.view.assume_init_ref().offset_valid(offset)
            })
        }

        extern "C" fn cb_offset_readable<V>(ctxt: *mut c_void, offset: u64) -> bool
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::readable", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);

                context.view.assume_init_ref().offset_readable(offset)
            })
        }

        extern "C" fn cb_offset_writable<V>(ctxt: *mut c_void, offset: u64) -> bool
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::writable", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);

                context.view.assume_init_ref().offset_writable(offset)
            })
        }

        extern "C" fn cb_offset_executable<V>(ctxt: *mut c_void, offset: u64) -> bool
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::offset_executable", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);

                context.view.assume_init_ref().offset_executable(offset)
            })
        }

        extern "C" fn cb_offset_backed_by_file<V>(ctxt: *mut c_void, offset: u64) -> bool
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::offset_backed_by_file", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);

                context.view.assume_init_ref().offset_backed_by_file(offset)
            })
        }

        extern "C" fn cb_next_valid_offset<V>(ctxt: *mut c_void, offset: u64) -> u64
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::next_valid_offset_after", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);

                context
                    .view
                    .assume_init_ref()
                    .next_valid_offset_after(offset)
            })
        }

        extern "C" fn cb_start<V>(ctxt: *mut c_void) -> u64
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::start", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);

                context.view.assume_init_ref().start()
            })
        }

        extern "C" fn cb_length<V>(ctxt: *mut c_void) -> u64
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::len", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);

                context.view.assume_init_ref().len() as u64
            })
        }

        extern "C" fn cb_entry_point<V>(ctxt: *mut c_void) -> u64
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::entry_point", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);

                context.view.assume_init_ref().entry_point()
            })
        }

        extern "C" fn cb_executable<V>(ctxt: *mut c_void) -> bool
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::executable", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);

                context.view.assume_init_ref().executable()
            })
        }

        extern "C" fn cb_endianness<V>(ctxt: *mut c_void) -> Endianness
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::default_endianness", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);

                context.view.assume_init_ref().default_endianness()
            })
        }

        extern "C" fn cb_relocatable<V>(ctxt: *mut c_void) -> bool
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::relocatable", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);

                context.view.assume_init_ref().relocatable()
            })
        }

        extern "C" fn cb_address_size<V>(ctxt: *mut c_void) -> usize
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::address_size", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);

                context.view.assume_init_ref().address_size()
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
            view: mem::MaybeUninit::uninit(),
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
            let res = BNCreateCustomBinaryView(
                view_name.as_cstr().as_ptr(),
                file.handle,
                parent.handle,
                &mut bn_obj,
            );

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
                handle: BinaryView::from_raw(res),
                _builder: PhantomData,
            })
        }
    }

    pub fn wrap_existing(self, wrapped_view: Ref<BinaryView>) -> Result<CustomView<'a>> {
        Ok(CustomView {
            handle: wrapped_view,
            _builder: PhantomData,
        })
    }
}
