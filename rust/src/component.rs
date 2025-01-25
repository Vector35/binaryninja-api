use crate::binary_view::{BinaryView, BinaryViewExt};
use crate::function::Function;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable};
use crate::string::{BnStrCompatible, BnString};
use crate::types::ComponentReferencedType;
use std::ffi::c_char;
use std::fmt::Debug;
use std::ptr::NonNull;

use crate::variable::DataVariable;
use binaryninjacore_sys::*;

pub struct ComponentBuilder {
    view: Ref<BinaryView>,
    parent: Option<String>,
    name: Option<String>,
}

impl ComponentBuilder {
    pub fn new(view: Ref<BinaryView>) -> Self {
        Self {
            view,
            parent: None,
            name: None,
        }
    }

    pub fn parent(mut self, parent_guid: impl Into<String>) -> Self {
        self.parent = Some(parent_guid.into());
        self
    }

    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn finalize(self) -> Ref<Component> {
        let result = match (&self.parent, &self.name) {
            (None, None) => unsafe { BNCreateComponent(self.view.handle) },
            (None, Some(name)) => {
                let name_raw = name.into_bytes_with_nul();
                unsafe {
                    BNCreateComponentWithName(self.view.handle, name_raw.as_ptr() as *mut c_char)
                }
            }
            (Some(guid), None) => {
                let guid_raw = guid.into_bytes_with_nul();
                unsafe {
                    BNCreateComponentWithParent(self.view.handle, guid_raw.as_ptr() as *mut c_char)
                }
            }
            (Some(guid), Some(name)) => {
                let guid_raw = guid.into_bytes_with_nul();
                let name_raw = name.into_bytes_with_nul();
                unsafe {
                    BNCreateComponentWithParentAndName(
                        self.view.handle,
                        guid_raw.as_ptr() as *mut c_char,
                        name_raw.as_ptr() as *mut c_char,
                    )
                }
            }
        };
        unsafe { Component::ref_from_raw(NonNull::new(result).unwrap()) }
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
    pub(crate) handle: NonNull<BNComponent>,
}

impl Component {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNComponent>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: NonNull<BNComponent>) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    pub fn guid(&self) -> BnString {
        let result = unsafe { BNComponentGetGuid(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Add function to this component.
    pub fn add_function(&self, func: &Function) -> bool {
        unsafe { BNComponentAddFunctionReference(self.handle.as_ptr(), func.handle) }
    }

    /// Check whether this component contains a function.
    pub fn contains_function(&self, func: &Function) -> bool {
        unsafe { BNComponentContainsFunction(self.handle.as_ptr(), func.handle) }
    }

    /// Remove function from this component.
    pub fn remove_function(&self, func: &Function) -> bool {
        unsafe { BNComponentRemoveFunctionReference(self.handle.as_ptr(), func.handle) }
    }

    /// Move component to this component. This will remove it from the old parent.
    pub fn add_component(&self, component: &Component) -> bool {
        unsafe { BNComponentAddComponent(self.handle.as_ptr(), component.handle.as_ptr()) }
    }

    /// Check whether this component contains a component.
    pub fn contains_component(&self, component: &Component) -> bool {
        unsafe { BNComponentContainsComponent(self.handle.as_ptr(), component.handle.as_ptr()) }
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
        unsafe { BNComponentAddDataVariable(self.handle.as_ptr(), data_variable.address) }
    }

    /// Check whether this component contains a data variable.
    pub fn contains_data_variable(&self, data_variable: &DataVariable) -> bool {
        unsafe { BNComponentContainsDataVariable(self.handle.as_ptr(), data_variable.address) }
    }

    /// Remove data variable from this component.
    pub fn remove_data_variable(&self, data_variable: &DataVariable) -> bool {
        unsafe { BNComponentRemoveDataVariable(self.handle.as_ptr(), data_variable.address) }
    }

    /// Original name of the component
    pub fn display_name(&self) -> BnString {
        let result = unsafe { BNComponentGetDisplayName(self.handle.as_ptr()) };
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
        let result = unsafe { BNComponentGetOriginalName(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    pub fn set_name<S: BnStrCompatible>(&self, name: S) {
        let name = name.into_bytes_with_nul();
        unsafe {
            BNComponentSetName(
                self.handle.as_ptr(),
                name.as_ref().as_ptr() as *const c_char,
            )
        }
    }

    /// The component that contains this component, if it exists.
    pub fn parent(&self) -> Option<Ref<Component>> {
        let result = unsafe { BNComponentGetParent(self.handle.as_ptr()) };
        NonNull::new(result).map(|h| unsafe { Self::ref_from_raw(h) })
    }

    pub fn view(&self) -> Option<Ref<BinaryView>> {
        let result = unsafe { BNComponentGetView(self.handle.as_ptr()) };
        (!result.is_null()).then(|| unsafe { BinaryView::ref_from_raw(result) })
    }

    /// Is an iterator for all Components contained within this Component
    pub fn components(&self) -> Array<Component> {
        let mut count = 0;
        let result = unsafe { BNComponentGetContainedComponents(self.handle.as_ptr(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// List of all Functions contained within this Component
    pub fn functions(&self) -> Array<Function> {
        let mut count = 0;
        let result = unsafe { BNComponentGetContainedFunctions(self.handle.as_ptr(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// List of all Data Variables contained within this Component
    pub fn data_variables(&self) -> Array<DataVariable> {
        let mut count = 0;
        let result =
            unsafe { BNComponentGetContainedDataVariables(self.handle.as_ptr(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Get data variables referenced by this component
    ///
    /// * `recursive` - Get all DataVariables referenced by this component and subcomponents.
    pub fn referenced_data_variables(&self, recursive: bool) -> Array<DataVariable> {
        let mut count = 0;
        let result = if recursive {
            unsafe {
                BNComponentGetReferencedDataVariablesRecursive(self.handle.as_ptr(), &mut count)
            }
        } else {
            unsafe { BNComponentGetReferencedDataVariables(self.handle.as_ptr(), &mut count) }
        };
        unsafe { Array::new(result, count, ()) }
    }

    /// Get Types referenced by this component
    ///
    /// * `recursive` - Get all Types referenced by this component and subcomponents.
    pub fn referenced_types(&self, recursive: bool) -> Array<ComponentReferencedType> {
        let mut count = 0;
        let result = if recursive {
            unsafe { BNComponentGetReferencedTypesRecursive(self.handle.as_ptr(), &mut count) }
        } else {
            unsafe { BNComponentGetReferencedTypes(self.handle.as_ptr(), &mut count) }
        };
        unsafe { Array::new(result, count, ()) }
    }

    pub fn remove_all_functions(&self) {
        unsafe { BNComponentRemoveAllFunctions(self.handle.as_ptr()) }
    }

    pub fn add_all_members_from(&self, component: &Component) {
        unsafe {
            BNComponentAddAllMembersFromComponent(self.handle.as_ptr(), component.handle.as_ptr())
        }
    }
}

impl Debug for Component {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Component")
            .field("guid", &self.guid())
            .field("display_name", &self.display_name())
            .field("name", &self.name())
            .field("components", &self.components().to_vec())
            .finish()
    }
}

impl PartialEq for Component {
    fn eq(&self, other: &Self) -> bool {
        unsafe { BNComponentsEqual(self.handle.as_ptr(), other.handle.as_ptr()) }
    }

    #[allow(clippy::partialeq_ne_impl)]
    fn ne(&self, other: &Self) -> bool {
        unsafe { BNComponentsNotEqual(self.handle.as_ptr(), other.handle.as_ptr()) }
    }
}

impl Eq for Component {}

impl ToOwned for Component {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for Component {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: NonNull::new(BNNewComponentReference(handle.handle.as_ptr())).unwrap(),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeComponent(handle.handle.as_ptr());
    }
}

impl CoreArrayProvider for Component {
    type Raw = *mut BNComponent;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Self>;
}

unsafe impl CoreArrayProviderInner for Component {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeComponents(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        let raw_ptr = NonNull::new(*raw).unwrap();
        Guard::new(Self::from_raw(raw_ptr), context)
    }
}

// TODO: Should we keep this?
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
