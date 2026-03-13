//! Register callbacks for when core objects like [`BinaryView`]s or [`Function`]s are destroyed.

use crate::binary_view::BinaryView;
use crate::file_metadata::FileMetadata;
use crate::function::Function;
use binaryninjacore_sys::*;
use std::ffi::c_void;

/// Registers a destructor which will be called when certain core objects are about to be destroyed.
///
/// Returns a handle to the registered destructor. The destructor will be unregistered when the handle is dropped.
///
/// To keep the destructor alive forever, move the [`ObjectDestructorHandle`] into [`std::mem::ManuallyDrop`].
#[must_use = "The destructor will be unregistered when the handle is dropped"]
pub fn register_object_destructor<'a, D: ObjectDestructor>(
    destructor: D,
) -> ObjectDestructorHandle<'a, D> {
    let destructor = Box::leak(Box::new(destructor));
    let callbacks = BNObjectDestructionCallbacks {
        context: destructor as *mut _ as *mut c_void,
        destructBinaryView: Some(cb_destruct_binary_view::<D>),
        destructFileMetadata: Some(cb_destruct_file_metadata::<D>),
        destructFunction: Some(cb_destruct_function::<D>),
    };
    let mut handle = ObjectDestructorHandle {
        callbacks,
        _life: std::marker::PhantomData,
    };
    unsafe { BNRegisterObjectDestructionCallbacks(&mut handle.callbacks) };
    handle
}

/// The handle for the [`ObjectDestructor`].
///
/// Once this handle is dropped, the destructor will be unregistered and the associated resources will be cleaned up.
pub struct ObjectDestructorHandle<'a, D: ObjectDestructor> {
    callbacks: BNObjectDestructionCallbacks,
    _life: std::marker::PhantomData<&'a D>,
}

impl<D: ObjectDestructor> Drop for ObjectDestructorHandle<'_, D> {
    fn drop(&mut self) {
        unsafe { BNUnregisterObjectDestructionCallbacks(&mut self.callbacks) };
        let _ = unsafe { Box::from_raw(self.callbacks.context as *mut D) };
    }
}

/// The trait required for receiving core object destruction callbacks.
///
/// This is useful for cleaning up resources which are associated with a given core object.
pub trait ObjectDestructor: 'static + Sync + Sized {
    /// Called when a [`BinaryView`] is about to be destroyed.
    fn destruct_view(&self, _view: &BinaryView) {}

    /// Called when a [`FileMetadata`] is about to be destroyed.
    fn destruct_file_metadata(&self, _metadata: &FileMetadata) {}

    /// Called when a [`Function`] is about to be destroyed.
    fn destruct_function(&self, _func: &Function) {}
}

unsafe extern "C" fn cb_destruct_binary_view<D: ObjectDestructor>(
    ctxt: *mut c_void,
    view: *mut BNBinaryView,
) {
    ffi_wrap!("ObjectDestructor::destruct_view", {
        let destructor = &*(ctxt as *mut D);
        let view = BinaryView { handle: view };
        destructor.destruct_view(&view);
    })
}

unsafe extern "C" fn cb_destruct_file_metadata<D: ObjectDestructor>(
    ctxt: *mut c_void,
    file: *mut BNFileMetadata,
) {
    ffi_wrap!("ObjectDestructor::destruct_file_metadata", {
        let destructor = &*(ctxt as *mut D);
        let file = FileMetadata::from_raw(file);
        destructor.destruct_file_metadata(&file);
    })
}

unsafe extern "C" fn cb_destruct_function<D: ObjectDestructor>(
    ctxt: *mut c_void,
    func: *mut BNFunction,
) {
    ffi_wrap!("ObjectDestructor::destruct_function", {
        let destructor = &*(ctxt as *mut D);
        let func = Function { handle: func };
        destructor.destruct_function(&func);
    })
}
