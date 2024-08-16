use core::{ffi, mem, ptr};

use crate::binaryview::{BinaryView, BinaryViewBase, BinaryViewExt};
use crate::function::Function;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Ref};
use crate::string::{BnStrCompatible, BnString};
use crate::types::{ComponentReferencedTypes, DataVariable};

use binaryninjacore_sys::*;

pub struct ComponentBuilder {
    bv: *mut BNBinaryView,
    parent: Option<BnString>,
    name: Option<BnString>,
}

impl ComponentBuilder {
    pub(crate) fn new_from_raw(bv: *mut BNBinaryView) -> Self {
        Self {
            bv,
            parent: None,
            name: None,
        }
    }
    pub fn new<I: BinaryViewBase>(bv: &I) -> Self {
        Self {
            bv: bv.as_ref().handle,
            parent: None,
            name: None,
        }
    }

    pub fn parent<G: IntoComponentGuid>(mut self, parent: G) -> Self {
        self.parent = Some(parent.component_guid());
        self
    }

    pub fn name<S: BnStrCompatible>(mut self, name: S) -> Self {
        self.name = Some(BnString::new(name));
        self
    }

    pub fn finalize(self) -> Component {
        let result = match (&self.parent, &self.name) {
            (None, None) => unsafe { BNCreateComponent(self.bv) },
            (None, Some(name)) => unsafe { BNCreateComponentWithName(self.bv, name.as_ptr()) },
            (Some(guid), None) => unsafe { BNCreateComponentWithParent(self.bv, guid.as_ptr()) },
            (Some(guid), Some(name)) => unsafe {
                BNCreateComponentWithParentAndName(self.bv, guid.as_ptr(), name.as_ptr())
            },
        };
        unsafe { Component::from_raw(ptr::NonNull::new(result).unwrap()) }
    }
}

/// Components are objects that can contain Functions, Data Variables, and other Components.
///
/// They can be queried for information about the items contained within them.
///
/// Components have a Guid, which persistent across saves and loads of the database, and should be
/// used for retrieving components when such is required and a reference to the Component cannot be held.
#[repr(transparent)]
pub struct Component {
    handle: ptr::NonNull<BNComponent>,
}

impl Component {
    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNComponent {
        &mut *self.handle.as_ptr()
    }

    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNComponent>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &*mut BNComponent) -> &Self {
        assert!(!handle.is_null());
        mem::transmute(handle)
    }

    pub fn guid(&self) -> BnString {
        let result = unsafe { BNComponentGetGuid(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Add function to this component.
    pub fn add_function(&self, func: &Function) -> bool {
        unsafe { BNComponentAddFunctionReference(self.as_raw(), func.handle) }
    }

    /// Check whether this component contains a function.
    pub fn contains_function(&self, func: &Function) -> bool {
        unsafe { BNComponentContainsFunction(self.as_raw(), func.handle) }
    }

    /// Remove function from this component.
    pub fn remove_function(&self, func: &Function) -> bool {
        unsafe { BNComponentRemoveFunctionReference(self.as_raw(), func.handle) }
    }

    /// Move component to this component. This will remove it from the old parent.
    pub fn add_component(&self, component: &Component) -> bool {
        unsafe { BNComponentAddComponent(self.as_raw(), component.as_raw()) }
    }

    /// Check whether this component contains a component.
    pub fn contains_component(&self, component: &Component) -> bool {
        unsafe { BNComponentContainsComponent(self.as_raw(), component.as_raw()) }
    }

    /// Remove a component from the current component, moving it to the root.
    ///
    /// This function has no effect when used from the root component.
    /// Use `BinaryView.remove_component` to Remove a component from the tree entirely.
    pub fn remove_component(&self, component: &Component) -> bool {
        self.view()
            .unwrap()
            .root_component()
            .unwrap()
            .add_component(component)
    }

    /// Add data variable to this component.
    pub fn add_data_variable(&self, data_variable: &DataVariable) -> bool {
        unsafe { BNComponentAddDataVariable(self.as_raw(), data_variable.address()) }
    }

    /// Check whether this component contains a data variable.
    pub fn contains_data_variable(&self, data_variable: &DataVariable) -> bool {
        unsafe { BNComponentContainsDataVariable(self.as_raw(), data_variable.address()) }
    }

    /// Remove data variable from this component.
    pub fn remove_data_variable(&self, data_variable: &DataVariable) -> bool {
        unsafe { BNComponentRemoveDataVariable(self.as_raw(), data_variable.address()) }
    }

    /// Original name of the component
    pub fn display_name(&self) -> BnString {
        let result = unsafe { BNComponentGetDisplayName(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Original name set for this component

    /// :note: The `.display_name` property should be used for `bv.get_component_by_path()` lookups.

    /// This can differ from the .display_name property if one of its sibling components has the same .original_name; In that
    /// case, .name will be an automatically generated unique name (e.g. "MyComponentName (1)") while .original_name will
    /// remain what was originally set (e.g. "MyComponentName")

    /// If this component has a duplicate name and is moved to a component where none of its siblings share its name,
    /// .name will return the original "MyComponentName"
    pub fn name(&self) -> BnString {
        let result = unsafe { BNComponentGetOriginalName(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    pub fn set_name<S: BnStrCompatible>(&self, name: S) {
        let name = name.into_bytes_with_nul();
        unsafe { BNComponentSetName(self.as_raw(), name.as_ref().as_ptr() as *const ffi::c_char) }
    }

    /// The component that contains this component, if it exists.
    pub fn parent(&self) -> Option<Component> {
        let result = unsafe { BNComponentGetParent(self.as_raw()) };
        ptr::NonNull::new(result).map(|h| unsafe { Self::from_raw(h) })
    }

    pub fn view(&self) -> Option<Ref<BinaryView>> {
        let result = unsafe { BNComponentGetView(self.as_raw()) };
        (!result.is_null()).then(|| unsafe { BinaryView::from_raw(result) })
    }

    /// Is an iterator for all Components contained within this Component
    pub fn components(&self) -> Array<Component> {
        let mut count = 0;
        let result = unsafe { BNComponentGetContainedComponents(self.as_raw(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// List of all Functions contained within this Component
    pub fn functions(&self) -> Array<Function> {
        let mut count = 0;
        let result = unsafe { BNComponentGetContainedFunctions(self.as_raw(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// List of all Data Variables contained within this Component
    pub fn data_variables(&self) -> Array<DataVariable> {
        let mut count = 0;
        let result = unsafe { BNComponentGetContainedDataVariables(self.as_raw(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Get data variables referenced by this component
    ///
    /// * `recursive` - Get all DataVariables referenced by this component and subcomponents.
    pub fn get_referenced_data_variables(&self, recursive: bool) -> Array<DataVariable> {
        let mut count = 0;
        let result = if recursive {
            unsafe { BNComponentGetReferencedDataVariablesRecursive(self.as_raw(), &mut count) }
        } else {
            unsafe { BNComponentGetReferencedDataVariables(self.as_raw(), &mut count) }
        };
        unsafe { Array::new(result, count, ()) }
    }

    /// Get Types referenced by this component
    ///
    /// * `recursive` - Get all Types referenced by this component and subcomponents.
    pub fn get_referenced_types(&self, recursive: bool) -> Array<ComponentReferencedTypes> {
        let mut count = 0;
        let result = if recursive {
            unsafe { BNComponentGetReferencedTypesRecursive(self.as_raw(), &mut count) }
        } else {
            unsafe { BNComponentGetReferencedTypes(self.as_raw(), &mut count) }
        };
        unsafe { Array::new(result, count, ()) }
    }

    pub fn remove_all_functions(&self) {
        unsafe { BNComponentRemoveAllFunctions(self.as_raw()) }
    }

    pub fn add_all_members_from(&self, component: &Component) {
        unsafe { BNComponentAddAllMembersFromComponent(self.as_raw(), component.as_raw()) }
    }
}

impl PartialEq for Component {
    fn eq(&self, other: &Self) -> bool {
        unsafe { BNComponentsEqual(self.as_raw(), other.as_raw()) }
    }

    #[allow(clippy::partialeq_ne_impl)]
    fn ne(&self, other: &Self) -> bool {
        unsafe { BNComponentsNotEqual(self.as_raw(), other.as_raw()) }
    }
}

impl Eq for Component {}

impl Drop for Component {
    fn drop(&mut self) {
        unsafe { BNFreeComponent(self.as_raw()) }
    }
}

impl Clone for Component {
    fn clone(&self) -> Self {
        unsafe {
            Self::from_raw(ptr::NonNull::new(BNNewComponentReference(self.as_raw())).unwrap())
        }
    }
}

impl CoreArrayProvider for Component {
    type Raw = *mut BNComponent;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for Component {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeComponents(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::ref_from_raw(raw)
    }
}

pub trait IntoComponentGuid {
    fn component_guid(self) -> BnString;
}

impl IntoComponentGuid for &Component {
    fn component_guid(self) -> BnString {
        self.guid()
    }
}

impl<S: BnStrCompatible> IntoComponentGuid for S {
    fn component_guid(self) -> BnString {
        BnString::new(self)
    }
}
