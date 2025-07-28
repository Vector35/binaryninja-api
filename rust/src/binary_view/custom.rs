// Copyright 2021-2025 Vector 35 Inc.
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

//! An interface for providing your own [`BinaryView`]s to Binary Ninja.

use binaryninjacore_sys::*;

pub use binaryninjacore_sys::BNModificationStatus as ModificationStatus;

use std::marker::PhantomData;
use std::os::raw::c_void;
use std::ptr;
use std::slice;

use crate::binary_view::types::{BinaryViewType, BinaryViewTypeExt};
use crate::binary_view::{BinaryView, BinaryViewBase, BinaryViewExt, Result};
use crate::rc::*;
use crate::string::*;
use crate::Endianness;

/// Represents a request from the core to instantiate a custom BinaryView
pub struct CustomViewBuilder<'a, T: BinaryViewType + ?Sized> {
    pub(crate) view_type: &'a T,
    pub(crate) actual_parent: &'a BinaryView,
}

pub unsafe trait CustomBinaryView: 'static + BinaryViewBase + Sync + Sized {
    type Args: Send;

    fn new(handle: &BinaryView, args: &Self::Args) -> Result<Self>;
    fn init(&mut self, args: Self::Args) -> Result<()>;
}

/// Represents a partially initialized custom `BinaryView` that should be returned to the core
/// from the `create_custom_view` method of a `CustomBinaryViewType`.
#[must_use]
pub struct CustomView<'builder> {
    // this object can't actually be treated like a real
    // BinaryView as it isn't fully initialized until the
    // core receives it from the BNCustomBinaryViewType::create
    // callback.
    pub(crate) handle: Ref<BinaryView>,
    _builder: PhantomData<&'builder ()>,
}

impl<'a, T: BinaryViewType> CustomViewBuilder<'a, T> {
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
    ///  TODO FIXME whelp this is broke going to need 2 init callbacks
    pub fn create<V>(self, parent: &BinaryView, view_args: V::Args) -> Result<CustomView<'a>>
    where
        V: CustomBinaryView,
    {
        let file = self.actual_parent.file();
        let view_type = self.view_type;

        let view_name = view_type.name();

        if let Some(bv) = file.view_of_type(&view_name) {
            // while it seems to work most of the time, you can get really unlucky
            // if the a free of the existing view of the same type kicks off while
            // BNCreateBinaryViewOfType is still running. the freeObject callback
            // will run for the new view before we've even finished initializing,
            // and that's all she wrote.
            //
            // even if we deal with it gracefully in cb_free_object,
            // BNCreateBinaryViewOfType is still going to crash, so we're just
            // going to try and stop this from happening in the first place.
            log::error!(
                "attempt to create duplicate view of type '{}' (existing: {:?})",
                view_name,
                bv.handle
            );

            return Err(());
        }

        // struct representing the context of a BNCustomBinaryView. Can be safely
        // dropped at any moment.
        struct CustomViewContext<V>
        where
            V: CustomBinaryView,
        {
            raw_handle: *mut BNBinaryView,
            state: CustomViewContextState<V>,
        }

        enum CustomViewContextState<V>
        where
            V: CustomBinaryView,
        {
            Uninitialized { args: V::Args },
            Initialized { view: V },
            // dummy state, used as a helper to change states, only happen if the
            // `new` or `init` function fails.
            None,
        }

        impl<V: CustomBinaryView> CustomViewContext<V> {
            fn assume_init_ref(&self) -> &V {
                let CustomViewContextState::Initialized { view } = &self.state else {
                    panic!("CustomViewContextState in invalid state");
                };
                view
            }
        }

        extern "C" fn cb_init<V>(ctxt: *mut c_void) -> bool
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::init", unsafe {
                let context = &mut *(ctxt as *mut CustomViewContext<V>);
                let handle = BinaryView::ref_from_raw(context.raw_handle);

                // take the uninitialized state and use the args to call init
                let mut state = CustomViewContextState::None;
                core::mem::swap(&mut context.state, &mut state);
                let CustomViewContextState::Uninitialized { args } = state else {
                    panic!("CustomViewContextState in invalid state");
                };
                match V::new(handle.as_ref(), &args) {
                    Ok(mut view) => match view.init(args) {
                        Ok(_) => {
                            // put the initialized state
                            context.state = CustomViewContextState::Initialized { view };
                            true
                        }
                        Err(_) => {
                            log::error!("CustomBinaryView::init failed; custom view returned Err");
                            false
                        }
                    },
                    Err(_) => {
                        log::error!("CustomBinaryView::new failed; custom view returned Err");
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
                let context = Box::from_raw(context);

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
                    // run the destructor on the custom view since that memory is uninitialized.
                    log::error!(
                      "BinaryViewBase::freeObject called on partially initialized object! crash imminent!"
                    );
                } else if matches!(
                    &context.state,
                    CustomViewContextState::None | CustomViewContextState::Uninitialized { .. }
                ) {
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
                    log::error!("BinaryViewBase::freeObject called on leaked/never initialized custom view!");
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
                context.assume_init_ref().read(dest, offset)
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
                context.assume_init_ref().write(offset, src)
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
                context.assume_init_ref().insert(offset, src)
            })
        }

        extern "C" fn cb_remove<V>(ctxt: *mut c_void, offset: u64, len: u64) -> usize
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::remove", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);
                context.assume_init_ref().remove(offset, len as usize)
            })
        }

        extern "C" fn cb_modification<V>(ctxt: *mut c_void, offset: u64) -> ModificationStatus
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::modification_status", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);
                context.assume_init_ref().modification_status(offset)
            })
        }

        extern "C" fn cb_offset_valid<V>(ctxt: *mut c_void, offset: u64) -> bool
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::offset_valid", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);
                context.assume_init_ref().offset_valid(offset)
            })
        }

        extern "C" fn cb_offset_readable<V>(ctxt: *mut c_void, offset: u64) -> bool
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::readable", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);
                context.assume_init_ref().offset_readable(offset)
            })
        }

        extern "C" fn cb_offset_writable<V>(ctxt: *mut c_void, offset: u64) -> bool
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::writable", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);
                context.assume_init_ref().offset_writable(offset)
            })
        }

        extern "C" fn cb_offset_executable<V>(ctxt: *mut c_void, offset: u64) -> bool
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::offset_executable", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);
                context.assume_init_ref().offset_executable(offset)
            })
        }

        extern "C" fn cb_offset_backed_by_file<V>(ctxt: *mut c_void, offset: u64) -> bool
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::offset_backed_by_file", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);
                context.assume_init_ref().offset_backed_by_file(offset)
            })
        }

        extern "C" fn cb_next_valid_offset<V>(ctxt: *mut c_void, offset: u64) -> u64
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::next_valid_offset_after", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);
                context.assume_init_ref().next_valid_offset_after(offset)
            })
        }

        extern "C" fn cb_start<V>(ctxt: *mut c_void) -> u64
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::start", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);
                context.assume_init_ref().start()
            })
        }

        extern "C" fn cb_length<V>(ctxt: *mut c_void) -> u64
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::len", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);
                context.assume_init_ref().len()
            })
        }

        extern "C" fn cb_entry_point<V>(ctxt: *mut c_void) -> u64
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::entry_point", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);
                context.assume_init_ref().entry_point()
            })
        }

        extern "C" fn cb_executable<V>(ctxt: *mut c_void) -> bool
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::executable", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);
                context.assume_init_ref().executable()
            })
        }

        extern "C" fn cb_endianness<V>(ctxt: *mut c_void) -> Endianness
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::default_endianness", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);

                context.assume_init_ref().default_endianness()
            })
        }

        extern "C" fn cb_relocatable<V>(ctxt: *mut c_void) -> bool
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::relocatable", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);

                context.assume_init_ref().relocatable()
            })
        }

        extern "C" fn cb_address_size<V>(ctxt: *mut c_void) -> usize
        where
            V: CustomBinaryView,
        {
            ffi_wrap!("BinaryViewBase::address_size", unsafe {
                let context = &*(ctxt as *mut CustomViewContext<V>);

                context.assume_init_ref().address_size()
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
            raw_handle: ptr::null_mut(),
            state: CustomViewContextState::Uninitialized { args: view_args },
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

        let view_name = view_name.to_cstr();
        unsafe {
            let res = BNCreateCustomBinaryView(
                view_name.as_ptr(),
                file.handle,
                parent.handle,
                &mut bn_obj,
            );
            assert!(!res.is_null(), "BNCreateCustomBinaryView failed");
            (*ctxt).raw_handle = res;
            Ok(CustomView {
                handle: BinaryView::ref_from_raw(res),
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
