//! Receive notifications for many types of core events.

use std::ffi::{c_char, c_void, CStr};
use std::ptr::NonNull;

use binaryninjacore_sys::*;

use crate::binary_view::{BinaryView, StringType};
use crate::component::Component;
use crate::database::undo::UndoEntry;
use crate::external_library::{ExternalLibrary, ExternalLocation};
use crate::function::Function;
use crate::rc::Ref;
use crate::section::Section;
use crate::segment::Segment;
use crate::symbol::Symbol;
use crate::tags::{TagReference, TagType};
use crate::types::{QualifiedName, Type, TypeArchive};
use crate::variable::DataVariable;

macro_rules! trait_handler {
(
    $(
        $ffi_param_name:ident => $fun_name:ident(
            $(
                $arg_name:ident:
                $raw_arg_type:ty:
                $arg_type:ty =
                $value_calculated:expr
            ),* $(,)?
        ) $(-> $ret_type:ty)?
    ),* $(,)?
) => {
    /// Used to describe which call should be triggered. By default, all calls are disabled.
    ///
    /// Used by [`CustomDataNotification::register`]
    #[derive(Default)]
    pub struct DataNotificationTriggers {
        $($fun_name: bool,)*
    }

    impl DataNotificationTriggers {
    $(
        pub fn $fun_name(mut self) -> Self {
            self.$fun_name = true;
            self
        }
    )*
    }

    pub trait CustomDataNotification: Sync + Send {
        $(
        #[inline]
        #[allow(unused_variables)]
        fn $fun_name(&mut self, $($arg_name: $arg_type),*) $(-> $ret_type)* {
            $( <$ret_type as Default>::default() )*
        }
        )*

        fn register<'a>(
            self,
            view: &BinaryView,
            triggers: DataNotificationTriggers,
        ) -> DataNotificationHandle<'a, Self> where Self: 'a + Sized {
            register_data_notification(view, self, triggers)
        }
    }

    $(
    unsafe extern "C" fn $fun_name<H: CustomDataNotification>(
        ctxt: *mut ::std::os::raw::c_void,
        $($arg_name: $raw_arg_type),*
    ) $(-> $ret_type)* {
        let handle: &mut H = &mut *(ctxt as *mut H);
        handle.$fun_name($($value_calculated),*)
    }
    )*

    fn register_data_notification<'a, H: CustomDataNotification + 'a>(
        view: &BinaryView,
        notify: H,
        triggers: DataNotificationTriggers,
    ) -> DataNotificationHandle<'a, H> {
        // SAFETY: this leak is undone on drop
        let leak_notify = Box::leak(Box::new(notify));
        let handle = BNBinaryDataNotification {
            context: leak_notify as *mut _ as *mut c_void,
            $($ffi_param_name: triggers.$fun_name.then_some($fun_name::<H>)),*,
            // TODO: Require all BNBinaryDataNotification's to be implemented?
            // Since core developers are not required to write Rust bindings (yet) we do not
            // force new binary data notifications callbacks to be written here.of core developers who do not wish to write
            ..Default::default()
        };
        // Box it to prevent a copy being returned in `DataNotificationHandle`.
        let mut boxed_handle = Box::new(handle);
        unsafe { BNRegisterDataNotification(view.handle, boxed_handle.as_mut()) };
        DataNotificationHandle {
            bv: view.to_owned(),
            handle: boxed_handle,
            _life: std::marker::PhantomData,
        }
    }

    /// Implement closures that will be called by on the event of data modification.
    ///
    /// Once dropped the closures will stop being called.
    ///
    /// NOTE: Closures are not executed on the same thread as the event that occurred, you must not depend
    /// on any serial behavior
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use binaryninja::data_notification::DataNotificationClosure;
    /// # use binaryninja::function::Function;
    /// # use binaryninja::binary_view::BinaryView;
    /// # let bv: BinaryView = todo!();
    /// let custom = DataNotificationClosure::default()
    ///     .function_updated(|_bv: &BinaryView, _func: &Function| todo!() )
    ///     // other calls should be added here
    ///     .register(&bv);
    /// ```
    pub struct DataNotificationClosure<'a> {
    $(
        $fun_name: Option<Box<
            dyn FnMut($($arg_type),*) $(-> $ret_type)* + Sync + Send + 'a
        >>,
    )*
    }

    impl Default for DataNotificationClosure<'_>  {
        fn default() -> Self {
            Self { $($fun_name: None,)* }
        }
    }

    impl<'a> DataNotificationClosure<'a> {
        pub fn new() -> Self {
            Default::default()
        }
    $(
        pub fn $fun_name<F: FnMut(
            $($arg_type),*
        ) $(-> $ret_type)* + Sync + Send + 'a>(mut self, param: F) -> Self {
            self.$fun_name = Some(Box::new(param));
            self
        }
    )*

        /// Register the closures to be notified up until the [`DataNotificationHandle`] is dropped.
        pub fn register(
            self,
            view: &BinaryView,
        ) -> DataNotificationHandle<'a, Self> {
            let mut triggers = DataNotificationTriggers::default();
            $(
            if self.$fun_name.is_some() {
                triggers = triggers.$fun_name();
            }
            )*
            register_data_notification(view, self, triggers)
        }
    }

    impl CustomDataNotification for DataNotificationClosure<'_> {
    $(
        fn $fun_name(&mut self, $($arg_name: $arg_type),*) $(-> $ret_type)* {
            let Some(handle) = self.$fun_name.as_mut() else {
                unreachable!();
            };
            handle($($arg_name),*)
        }
    )*
   }
};
}

trait_handler! {
    notificationBarrier => notification_barrier(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
    ) -> u64,
    dataWritten => data_written(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        offset: u64: u64 = offset,
        len: usize: usize = len,
    ),
    dataInserted => data_inserted(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        offset: u64: u64 = offset,
        len: usize: usize = len,
    ),
    dataRemoved => data_removed(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        offset: u64: u64 = offset,
        // TODO why the len is u64 here? Maybe is a bug on CoreAPI
        len: u64: u64 = len,
    ),
    functionAdded => function_added(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        func: *mut BNFunction: &Function = &Function::from_raw(func),
    ),
    functionRemoved => function_removed(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        func: *mut BNFunction: &Function = &Function::from_raw(func),
    ),
    functionUpdated => function_updated(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        func: *mut BNFunction: &Function = &Function::from_raw(func),
    ),
    functionUpdateRequested => function_update_requested(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        func: *mut BNFunction: &Function = &Function::from_raw(func),
    ),
    dataVariableAdded => data_variable_added(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        var: *mut BNDataVariable: &DataVariable = &DataVariable::from_raw(&*var),
    ),
    dataVariableRemoved => data_variable_removed(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        var: *mut BNDataVariable: &DataVariable = &DataVariable::from_raw(&*var),
    ),
    dataVariableUpdated => data_variable_updated(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        var: *mut BNDataVariable: &DataVariable = &DataVariable::from_raw(&*var),
    ),
    dataMetadataUpdated => data_metadata_updated(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        offset: u64: u64 = offset,
    ),
    tagTypeUpdated => tag_type_updated(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        tag_type: *mut BNTagType: &TagType = &TagType{ handle: tag_type },
    ),
    tagAdded => tag_added(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        tag_ref: *mut BNTagReference: &TagReference = &TagReference::from(&*tag_ref),
    ),
    tagRemoved => tag_removed(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        tag_ref: *mut BNTagReference: &TagReference = &TagReference::from(&*tag_ref),
    ),
    tagUpdated => tag_updated(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        tag_ref: *mut BNTagReference: &TagReference = &TagReference::from(&*tag_ref),
    ),
    symbolAdded => symbol_added(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        sym: *mut BNSymbol: &Symbol = &Symbol::from_raw(sym),
    ),
    symbolRemoved => symbol_removed(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        sym: *mut BNSymbol: &Symbol = &Symbol::from_raw(sym),
    ),
    symbolUpdated => symbol_updated(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        sym: *mut BNSymbol: &Symbol = &Symbol::from_raw(sym),
    ),
    stringFound => string_found(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        type_: BNStringType: StringType = type_,
        offset: u64: u64 = offset,
        len: usize: usize = len,
    ),
    stringRemoved => string_removed(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        type_: BNStringType: StringType = type_,
        offset: u64: u64 = offset,
        len: usize: usize = len,
    ),
    typeDefined => type_defined(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        name: *mut BNQualifiedName: &QualifiedName = &QualifiedName::from_raw(&*name),
        type_: *mut BNType: &Type = &Type::from_raw(type_),
    ),
    typeUndefined => type_undefined(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        name: *mut BNQualifiedName: &QualifiedName = &QualifiedName::from_raw(&*name),
        type_: *mut BNType: &Type = &Type::from_raw(type_),
    ),
    typeReferenceChanged => type_reference_changed(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        name: *mut BNQualifiedName: &QualifiedName = &QualifiedName::from_raw(&*name),
        type_: *mut BNType: &Type = &Type::from_raw(type_),
    ),
    typeFieldReferenceChanged => type_field_reference_changed(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        name: *mut BNQualifiedName: &QualifiedName = &QualifiedName::from_raw(&*name),
        offset: u64: u64 = offset,
    ),
    segmentAdded => segment_added(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        segment: *mut BNSegment: &Segment = &Segment::from_raw(segment),
    ),
    segmentRemoved => segment_removed(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        segment: *mut BNSegment: &Segment = &Segment::from_raw(segment),
    ),
    segmentUpdated => segment_updated(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        segment: *mut BNSegment: &Segment = &Segment::from_raw(segment),
    ),
    sectionAdded => section_added(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        section: *mut BNSection: &Section = &Section::from_raw(section),
    ),
    sectionRemoved => section_removed(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        section: *mut BNSection: &Section = &Section::from_raw(section),
    ),
    sectionUpdated => section_updated(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        section: *mut BNSection: &Section = &Section::from_raw(section),
    ),
    componentNameUpdated => component_name_updated(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        previous_name: *mut c_char: &str = CStr::from_ptr(previous_name).to_str().unwrap(),
        component: *mut BNComponent: &Component = &Component::from_raw(NonNull::new(component).unwrap()),
    ),
    componentAdded => component_added(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        component: *mut BNComponent: &Component = &Component::from_raw(NonNull::new(component).unwrap()),
    ),
    componentMoved => component_moved(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        former_parent: *mut BNComponent: &Component = &Component::from_raw(NonNull::new(former_parent).unwrap()),
        new_parent: *mut BNComponent: &Component = &Component::from_raw(NonNull::new(new_parent).unwrap()),
        component: *mut BNComponent: &Component = &Component::from_raw(NonNull::new(component).unwrap()),
    ),
    componentRemoved => component_removed(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        former_parent: *mut BNComponent: &Component = &Component::from_raw(NonNull::new(former_parent).unwrap()),
        component: *mut BNComponent: &Component = &Component::from_raw(NonNull::new(component).unwrap()),
    ),
    componentFunctionAdded => component_function_added(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        component: *mut BNComponent: &Component = &Component::from_raw(NonNull::new(component).unwrap()),
        function: *mut BNFunction: &Function = &Function::from_raw(function),
    ),
    componentFunctionRemoved => component_function_removed(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        component: *mut BNComponent: &Component = &Component::from_raw(NonNull::new(component).unwrap()),
        function: *mut BNFunction: &Function = &Function::from_raw(function),
    ),
    componentDataVariableAdded => component_data_variable_added(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        component: *mut BNComponent: &Component = &Component::from_raw(NonNull::new(component).unwrap()),
        var: *mut BNDataVariable: &DataVariable = &DataVariable::from_raw(&*var),
        ),
    componentDataVariableRemoved => component_data_variable_removed(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        component: *mut BNComponent: &Component = &Component::from_raw(NonNull::new(component).unwrap()),
        var: *mut BNDataVariable: &DataVariable = &DataVariable::from_raw(&*var),
    ),
    externalLibraryAdded => external_library_added(
        data: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(data),
        library: *mut BNExternalLibrary: &ExternalLibrary = &ExternalLibrary::from_raw(NonNull::new(library).unwrap()),
    ),
    externalLibraryUpdated => external_library_updated(
        data: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(data),
        library: *mut BNExternalLibrary: &ExternalLibrary = &ExternalLibrary::from_raw(NonNull::new(library).unwrap()),
    ),
    externalLibraryRemoved => external_library_removed(
        data: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(data),
        library: *mut BNExternalLibrary: &ExternalLibrary = &ExternalLibrary::from_raw(NonNull::new(library).unwrap()),
    ),
    externalLocationAdded => external_location_added(
        data: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(data),
        location: *mut BNExternalLocation: &ExternalLocation = &ExternalLocation::from_raw(NonNull::new(location).unwrap()),
    ),
    externalLocationUpdated => external_location_updated(
        data: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(data),
        location: *mut BNExternalLocation: &ExternalLocation = &ExternalLocation::from_raw(NonNull::new(location).unwrap()),
    ),
    externalLocationRemoved => external_location_removed(
        data: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(data),
        location: *mut BNExternalLocation: &ExternalLocation = &ExternalLocation::from_raw(NonNull::new(location).unwrap()),
    ),
    typeArchiveAttached => type_archive_attached(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        id: *const c_char: &str = CStr::from_ptr(id).to_str().unwrap(),
        path: *const c_char: &[u8] = CStr::from_ptr(path).to_bytes(),
    ),
    typeArchiveDetached => type_archive_detached(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        id: *const c_char: &str = CStr::from_ptr(id).to_str().unwrap(),
        path: *const c_char: &[u8] = CStr::from_ptr(path).to_bytes(),
    ),
    typeArchiveConnected => type_archive_connected(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        archive: *mut BNTypeArchive: &TypeArchive = &TypeArchive::from_raw(NonNull::new(archive).unwrap()),
    ),
    typeArchiveDisconnected => type_archive_disconnected(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        archive: *mut BNTypeArchive: &TypeArchive = &TypeArchive::from_raw(NonNull::new(archive).unwrap()),
    ),
    undoEntryAdded => undo_entry_added(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        entry: *mut BNUndoEntry: &UndoEntry = &UndoEntry::from_raw(NonNull::new(entry).unwrap()),
    ),
    undoEntryTaken => undo_entry_taken(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        entry: *mut BNUndoEntry: &UndoEntry = &UndoEntry::from_raw(NonNull::new(entry).unwrap()),
    ),
    redoEntryTaken => redo_entry_taken(
        view: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(view),
        entry: *mut BNUndoEntry: &UndoEntry = &UndoEntry::from_raw(NonNull::new(entry).unwrap()),
    ),
    rebased => rebased(
        oldview: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(oldview),
        newview: *mut BNBinaryView: &BinaryView = &BinaryView::from_raw(newview),
    ),
}

pub struct DataNotificationHandle<'a, T: CustomDataNotification>
where
    T: 'a,
{
    bv: Ref<BinaryView>,
    handle: Box<BNBinaryDataNotification>,
    _life: std::marker::PhantomData<&'a T>,
}

impl<T: CustomDataNotification> DataNotificationHandle<'_, T> {
    unsafe fn unregister_bv(&mut self) {
        BNUnregisterDataNotification(self.bv.handle, self.handle.as_mut())
    }

    unsafe fn extract_context(&mut self) -> Box<T> {
        Box::from_raw(self.handle.context as *mut T)
    }

    pub fn unregister(self) -> T {
        // NOTE don't drop the ctxt, return it
        let mut slf = core::mem::ManuallyDrop::new(self);
        unsafe { slf.unregister_bv() };
        unsafe { *slf.extract_context() }
    }
}

impl<T: CustomDataNotification> Drop for DataNotificationHandle<'_, T> {
    fn drop(&mut self) {
        unsafe { self.unregister_bv() };
        // drop context, avoid memory leak
        let _ctxt = unsafe { self.extract_context() };
    }
}
