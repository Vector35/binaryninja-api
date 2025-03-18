// TODO: Add these!
// The `TypeContainer` class should not generally be instantiated directly. Instances
// can be retrieved from the following properties and methods in the API:
// * [BinaryView::type_container]
// * [BinaryView::auto_type_container]
// * [BinaryView::user_type_container]
// * [Platform::type_container]
// * [TypeLibrary::type_container]
// * [DebugInfo::get_type_container]

use crate::platform::Platform;
use crate::progress::{NoProgressCallback, ProgressCallback};
use crate::rc::{Array, Ref};
use crate::string::{raw_to_string, BnStrCompatible, BnString};
use crate::type_parser::{TypeParserError, TypeParserResult};
use crate::types::{QualifiedName, QualifiedNameAndType, Type};
use binaryninjacore_sys::*;
use std::collections::HashMap;
use std::ffi::{c_char, c_void};
use std::fmt::{Debug, Formatter};
use std::ptr::NonNull;

pub type TypeContainerType = BNTypeContainerType;

/// A `TypeContainer` is a generic interface to access various Binary Ninja models
/// that contain types. Types are stored with both a unique id and a unique name.
#[repr(transparent)]
pub struct TypeContainer {
    pub handle: NonNull<BNTypeContainer>,
}

impl TypeContainer {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNTypeContainer>) -> Self {
        // NOTE: There does not seem to be any shared ref counting for type containers, it seems if the
        // NOTE: binary view is freed the type container will be freed and cause this to become invalid
        // NOTE: but this is how the C++ and Python bindings operate so i guess its fine?
        // TODO: I really dont get how some of the usage of the TypeContainer doesnt free the underlying container.
        // TODO: So for now we always duplicate the type container
        let cloned_ptr = NonNull::new(BNDuplicateTypeContainer(handle.as_ptr()));
        Self {
            handle: cloned_ptr.unwrap(),
        }
    }

    /// Get an id string for the Type Container. This will be unique within a given
    /// analysis session, but may not be globally unique.
    pub fn id(&self) -> BnString {
        let result = unsafe { BNTypeContainerGetId(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Get a user-friendly name for the Type Container.
    pub fn name(&self) -> BnString {
        let result = unsafe { BNTypeContainerGetName(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Get the type of underlying model the Type Container is accessing.
    pub fn container_type(&self) -> TypeContainerType {
        unsafe { BNTypeContainerGetType(self.handle.as_ptr()) }
    }

    /// If the Type Container supports mutable operations (add, rename, delete)
    pub fn is_mutable(&self) -> bool {
        unsafe { BNTypeContainerIsMutable(self.handle.as_ptr()) }
    }

    /// Get the Platform object associated with this Type Container. All Type Containers
    /// have exactly one associated Platform (as opposed to, e.g. Type Libraries).
    pub fn platform(&self) -> Ref<Platform> {
        let result = unsafe { BNTypeContainerGetPlatform(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { Platform::ref_from_raw(result) }
    }

    /// Add or update types to a Type Container. If the Type Container already contains
    /// a type with the same name as a type being added, the existing type will be
    /// replaced with the definition given to this function, and references will be
    /// updated in the source model.
    pub fn add_types<I, T>(&self, types: I) -> bool
    where
        I: IntoIterator<Item = T>,
        T: Into<QualifiedNameAndType>,
    {
        self.add_types_with_progress(types, NoProgressCallback)
    }

    pub fn add_types_with_progress<I, T, P>(&self, types: I, mut progress: P) -> bool
    where
        I: IntoIterator<Item = T>,
        T: Into<QualifiedNameAndType>,
        P: ProgressCallback,
    {
        // TODO: I dislike how this iter unzip looks like... but its how to avoid allocating again...
        let (raw_names, mut raw_types): (Vec<BNQualifiedName>, Vec<_>) = types
            .into_iter()
            .map(|t| {
                let t = t.into();
                // Leaked to be freed after the call to core.
                (
                    QualifiedName::into_raw(t.name),
                    unsafe { Ref::into_raw(t.ty) }.handle,
                )
            })
            .unzip();

        let mut result_names = std::ptr::null_mut();
        let mut result_ids = std::ptr::null_mut();
        let mut result_count = 0;

        let success = unsafe {
            BNTypeContainerAddTypes(
                self.handle.as_ptr(),
                raw_names.as_ptr(),
                raw_types.as_mut_ptr(),
                raw_types.len(),
                Some(P::cb_progress_callback),
                &mut progress as *mut P as *mut c_void,
                &mut result_names,
                &mut result_ids,
                &mut result_count,
            )
        };

        for name in raw_names {
            QualifiedName::free_raw(name);
        }
        for ty in raw_types {
            let _ = unsafe { Type::ref_from_raw(ty) };
        }
        success
    }

    /// Rename a type in the Type Container. All references to this type will be updated
    /// (by id) to use the new name.
    ///
    /// Returns true if the type was renamed.
    pub fn rename_type<T: Into<QualifiedName>, S: BnStrCompatible>(
        &self,
        name: T,
        type_id: S,
    ) -> bool {
        let type_id = type_id.into_bytes_with_nul();
        let raw_name = QualifiedName::into_raw(name.into());
        let success = unsafe {
            BNTypeContainerRenameType(
                self.handle.as_ptr(),
                type_id.as_ref().as_ptr() as *const c_char,
                &raw_name,
            )
        };
        QualifiedName::free_raw(raw_name);
        success
    }

    /// Delete a type in the Type Container. Behavior of references to this type is
    /// not specified and you may end up with broken references if any still exist.
    ///
    /// Returns true if the type was deleted.
    pub fn delete_type<S: BnStrCompatible>(&self, type_id: S) -> bool {
        let type_id = type_id.into_bytes_with_nul();
        unsafe {
            BNTypeContainerDeleteType(
                self.handle.as_ptr(),
                type_id.as_ref().as_ptr() as *const c_char,
            )
        }
    }

    /// Get the unique id of the type in the Type Container with the given name.
    ///
    /// If no type with that name exists, returns None.
    pub fn type_id<T: Into<QualifiedName>>(&self, name: T) -> Option<BnString> {
        let mut result = std::ptr::null_mut();
        let raw_name = QualifiedName::into_raw(name.into());
        let success =
            unsafe { BNTypeContainerGetTypeId(self.handle.as_ptr(), &raw_name, &mut result) };
        QualifiedName::free_raw(raw_name);
        success.then(|| unsafe { BnString::from_raw(result) })
    }

    /// Get the unique name of the type in the Type Container with the given id.
    ///
    /// If no type with that id exists, returns None.
    pub fn type_name<S: BnStrCompatible>(&self, type_id: S) -> Option<QualifiedName> {
        let type_id = type_id.into_bytes_with_nul();
        let mut result = BNQualifiedName::default();
        let success = unsafe {
            BNTypeContainerGetTypeName(
                self.handle.as_ptr(),
                type_id.as_ref().as_ptr() as *const c_char,
                &mut result,
            )
        };
        success.then(|| QualifiedName::from_owned_raw(result))
    }

    /// Get the definition of the type in the Type Container with the given id.
    ///
    /// If no type with that id exists, returns None.
    pub fn type_by_id<S: BnStrCompatible>(&self, type_id: S) -> Option<Ref<Type>> {
        let type_id = type_id.into_bytes_with_nul();
        let mut result = std::ptr::null_mut();
        let success = unsafe {
            BNTypeContainerGetTypeById(
                self.handle.as_ptr(),
                type_id.as_ref().as_ptr() as *const c_char,
                &mut result,
            )
        };
        success.then(|| unsafe { Type::ref_from_raw(result) })
    }

    /// Get the definition of the type in the Type Container with the given name.
    ///
    /// If no type with that name exists, returns None.
    pub fn type_by_name<T: Into<QualifiedName>>(&self, name: T) -> Option<Ref<Type>> {
        let mut result = std::ptr::null_mut();
        let raw_name = QualifiedName::into_raw(name.into());
        let success =
            unsafe { BNTypeContainerGetTypeByName(self.handle.as_ptr(), &raw_name, &mut result) };
        QualifiedName::free_raw(raw_name);
        success.then(|| unsafe { Type::ref_from_raw(result) })
    }

    /// Get a mapping of all types in a Type Container.
    pub fn types(&self) -> Option<HashMap<String, (QualifiedName, Ref<Type>)>> {
        let mut type_ids = std::ptr::null_mut();
        let mut type_names = std::ptr::null_mut();
        let mut type_types = std::ptr::null_mut();
        let mut type_count = 0;
        let success = unsafe {
            BNTypeContainerGetTypes(
                self.handle.as_ptr(),
                &mut type_ids,
                &mut type_names,
                &mut type_types,
                &mut type_count,
            )
        };
        success.then(|| unsafe {
            let raw_ids = std::slice::from_raw_parts(type_ids, type_count);
            let raw_names = std::slice::from_raw_parts(type_names, type_count);
            let raw_types = std::slice::from_raw_parts(type_types, type_count);
            let mut map = HashMap::new();
            for (idx, raw_id) in raw_ids.iter().enumerate() {
                let id = raw_to_string(*raw_id).expect("Valid string");
                // Take the qualified name as a ref as the name should not be freed.
                let name = QualifiedName::from_raw(&raw_names[idx]);
                // Take the type as an owned ref, as the returned type was not already incremented.
                let ty = Type::from_raw(raw_types[idx]).to_owned();
                map.insert(id, (name, ty));
            }
            BNFreeStringList(type_ids, type_count);
            BNFreeTypeNameList(type_names, type_count);
            BNFreeTypeList(type_types, type_count);
            map
        })
    }

    /// Get all type ids in a Type Container.
    pub fn type_ids(&self) -> Option<Array<BnString>> {
        let mut type_ids = std::ptr::null_mut();
        let mut type_count = 0;
        let success = unsafe {
            BNTypeContainerGetTypeIds(self.handle.as_ptr(), &mut type_ids, &mut type_count)
        };
        success.then(|| unsafe { Array::new(type_ids, type_count, ()) })
    }

    /// Get all type names in a Type Container.
    pub fn type_names(&self) -> Option<Array<QualifiedName>> {
        let mut type_ids = std::ptr::null_mut();
        let mut type_count = 0;
        let success = unsafe {
            BNTypeContainerGetTypeNames(self.handle.as_ptr(), &mut type_ids, &mut type_count)
        };
        success.then(|| unsafe { Array::new(type_ids, type_count, ()) })
    }

    /// Get a mapping of all type ids and type names in a Type Container.
    pub fn type_names_and_ids(&self) -> Option<(Array<BnString>, Array<QualifiedName>)> {
        let mut type_ids = std::ptr::null_mut();
        let mut type_names = std::ptr::null_mut();
        let mut type_count = 0;
        let success = unsafe {
            BNTypeContainerGetTypeNamesAndIds(
                self.handle.as_ptr(),
                &mut type_ids,
                &mut type_names,
                &mut type_count,
            )
        };
        success.then(|| unsafe {
            let ids = Array::new(type_ids, type_count, ());
            let names = Array::new(type_names, type_count, ());
            (ids, names)
        })
    }

    /// Parse a single type and name from a string containing their definition, with
    /// knowledge of the types in the Type Container.
    ///
    /// * `source` - Source code to parse
    /// * `import_dependencies` - If Type Library / Type Archive types should be imported during parsing
    pub fn parse_type_string<S: BnStrCompatible>(
        &self,
        source: S,
        import_dependencies: bool,
    ) -> Result<QualifiedNameAndType, Array<TypeParserError>> {
        let source = source.into_bytes_with_nul();
        let mut result = BNQualifiedNameAndType::default();
        let mut errors = std::ptr::null_mut();
        let mut error_count = 0;
        let success = unsafe {
            BNTypeContainerParseTypeString(
                self.handle.as_ptr(),
                source.as_ref().as_ptr() as *const c_char,
                import_dependencies,
                &mut result,
                &mut errors,
                &mut error_count,
            )
        };
        if success {
            Ok(QualifiedNameAndType::from_owned_raw(result))
        } else {
            assert!(!errors.is_null());
            Err(unsafe { Array::new(errors, error_count, ()) })
        }
    }

    /// Parse an entire block of source into types, variables, and functions, with
    /// knowledge of the types in the Type Container.
    ///
    /// * `source` - Source code to parse
    /// * `file_name` - Name of the file containing the source (optional: exists on disk)
    /// * `options` - String arguments to pass as options, e.g. command line arguments
    /// * `include_dirs` - List of directories to include in the header search path
    /// * `auto_type_source` - Source of types if used for automatically generated types
    /// * `import_dependencies` - If Type Library / Type Archive types should be imported during parsing
    pub fn parse_types_from_source<S, F, O, D, A>(
        &self,
        source: S,
        filename: F,
        options: O,
        include_directories: D,
        auto_type_source: A,
        import_dependencies: bool,
    ) -> Result<TypeParserResult, Array<TypeParserError>>
    where
        S: BnStrCompatible,
        F: BnStrCompatible,
        O: IntoIterator,
        O::Item: BnStrCompatible,
        D: IntoIterator,
        D::Item: BnStrCompatible,
        A: BnStrCompatible,
    {
        let source = source.into_bytes_with_nul();
        let filename = filename.into_bytes_with_nul();
        let options: Vec<_> = options
            .into_iter()
            .map(|o| o.into_bytes_with_nul())
            .collect();
        let options_raw: Vec<*const c_char> = options
            .iter()
            .map(|o| o.as_ref().as_ptr() as *const c_char)
            .collect();
        let include_directories: Vec<_> = include_directories
            .into_iter()
            .map(|d| d.into_bytes_with_nul())
            .collect();
        let include_directories_raw: Vec<*const c_char> = include_directories
            .iter()
            .map(|d| d.as_ref().as_ptr() as *const c_char)
            .collect();
        let auto_type_source = auto_type_source.into_bytes_with_nul();
        let mut raw_result = BNTypeParserResult::default();
        let mut errors = std::ptr::null_mut();
        let mut error_count = 0;
        let success = unsafe {
            BNTypeContainerParseTypesFromSource(
                self.handle.as_ptr(),
                source.as_ref().as_ptr() as *const c_char,
                filename.as_ref().as_ptr() as *const c_char,
                options_raw.as_ptr(),
                options_raw.len(),
                include_directories_raw.as_ptr(),
                include_directories_raw.len(),
                auto_type_source.as_ref().as_ptr() as *const c_char,
                import_dependencies,
                &mut raw_result,
                &mut errors,
                &mut error_count,
            )
        };
        if success {
            let result = TypeParserResult::from_raw(&raw_result);
            // NOTE: This is safe because the core allocated the TypeParserResult
            TypeParserResult::free_raw(raw_result);
            Ok(result)
        } else {
            assert!(!errors.is_null());
            Err(unsafe { Array::new(errors, error_count, ()) })
        }
    }
}

impl Debug for TypeContainer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TypeContainer")
            .field("id", &self.id())
            .field("name", &self.name())
            .field("container_type", &self.container_type())
            .field("is_mutable", &self.is_mutable())
            .field("type_names", &self.type_names().unwrap().to_vec())
            .finish()
    }
}

impl Drop for TypeContainer {
    fn drop(&mut self) {
        unsafe { BNFreeTypeContainer(self.handle.as_ptr()) }
    }
}

impl Clone for TypeContainer {
    fn clone(&self) -> Self {
        unsafe {
            let cloned_ptr = NonNull::new(BNDuplicateTypeContainer(self.handle.as_ptr()));
            Self {
                handle: cloned_ptr.unwrap(),
            }
        }
    }
}
