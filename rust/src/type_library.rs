use binaryninjacore_sys::*;

use core::{ffi, mem, ptr};

use crate::{
    architecture::CoreArchitecture,
    metadata::Metadata,
    platform::Platform,
    rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Ref},
    string::{BnStrCompatible, BnString},
    types::{QualifiedName, QualifiedNameAndType, Type},
};

#[repr(transparent)]
pub struct TypeLibrary {
    handle: ptr::NonNull<BNTypeLibrary>,
}

impl TypeLibrary {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNTypeLibrary>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &*mut BNTypeLibrary) -> &Self {
        assert!(!handle.is_null());
        mem::transmute(handle)
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNTypeLibrary {
        &mut *self.handle.as_ptr()
    }

    pub fn new_reference(&self) -> Self {
        unsafe {
            Self::from_raw(ptr::NonNull::new(BNNewTypeLibraryReference(self.as_raw())).unwrap())
        }
    }

    pub fn new_duplicated(&self) -> Self {
        unsafe { Self::from_raw(ptr::NonNull::new(BNDuplicateTypeLibrary(self.as_raw())).unwrap()) }
    }

    /// Creates an empty type library object with a random GUID and the provided name.
    pub fn new<S: BnStrCompatible>(arch: CoreArchitecture, name: S) -> TypeLibrary {
        let name = name.into_bytes_with_nul();
        let new_lib =
            unsafe { BNNewTypeLibrary(arch.handle, name.as_ref().as_ptr() as *const ffi::c_char) };
        unsafe { TypeLibrary::from_raw(ptr::NonNull::new(new_lib).unwrap()) }
    }

    pub fn all(arch: CoreArchitecture) -> Array<TypeLibrary> {
        let mut count = 0;
        let result = unsafe { BNGetArchitectureTypeLibraries(arch.handle, &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Decompresses a type library file to a file on disk.
    pub fn decompress_to_file<P: BnStrCompatible, O: BnStrCompatible>(path: P, output: O) -> bool {
        let path = path.into_bytes_with_nul();
        let output = output.into_bytes_with_nul();
        unsafe {
            BNTypeLibraryDecompressToFile(
                path.as_ref().as_ptr() as *const ffi::c_char,
                output.as_ref().as_ptr() as *const ffi::c_char,
            )
        }
    }

    /// Loads a finalized type library instance from file
    pub fn load_from_file<S: BnStrCompatible>(path: S) -> Option<TypeLibrary> {
        let path = path.into_bytes_with_nul();
        let handle =
            unsafe { BNLoadTypeLibraryFromFile(path.as_ref().as_ptr() as *const ffi::c_char) };
        ptr::NonNull::new(handle).map(|h| unsafe { TypeLibrary::from_raw(h) })
    }

    /// Saves a finalized type library instance to file
    pub fn write_to_file<S: BnStrCompatible>(&self, path: S) -> bool {
        let path = path.into_bytes_with_nul();
        unsafe {
            BNWriteTypeLibraryToFile(self.as_raw(), path.as_ref().as_ptr() as *const ffi::c_char)
        }
    }

    /// Looks up the first type library found with a matching name. Keep in mind that names are not
    /// necessarily unique.
    pub fn from_name<S: BnStrCompatible>(arch: CoreArchitecture, name: S) -> Option<TypeLibrary> {
        let name = name.into_bytes_with_nul();
        let handle = unsafe {
            BNLookupTypeLibraryByName(arch.handle, name.as_ref().as_ptr() as *const ffi::c_char)
        };
        ptr::NonNull::new(handle).map(|h| unsafe { TypeLibrary::from_raw(h) })
    }

    /// Attempts to grab a type library associated with the provided Architecture and GUID pair
    pub fn from_guid<S: BnStrCompatible>(arch: CoreArchitecture, guid: S) -> Option<TypeLibrary> {
        let guid = guid.into_bytes_with_nul();
        let handle = unsafe {
            BNLookupTypeLibraryByGuid(arch.handle, guid.as_ref().as_ptr() as *const ffi::c_char)
        };
        ptr::NonNull::new(handle).map(|h| unsafe { TypeLibrary::from_raw(h) })
    }

    /// The Architecture this type library is associated with
    pub fn arch(&self) -> CoreArchitecture {
        let arch = unsafe { BNGetTypeLibraryArchitecture(self.as_raw()) };
        assert!(!arch.is_null());
        unsafe { CoreArchitecture::from_raw(arch) }
    }

    /// The primary name associated with this type library
    pub fn name(&self) -> Option<BnString> {
        let result = unsafe { BNGetTypeLibraryName(self.as_raw()) };
        (!result.is_null()).then(|| unsafe { BnString::from_raw(result) })
    }

    /// Sets the name of a type library instance that has not been finalized
    pub fn set_name<S: BnStrCompatible>(&self, value: S) {
        let value = value.into_bytes_with_nul();
        unsafe {
            BNSetTypeLibraryName(self.as_raw(), value.as_ref().as_ptr() as *const ffi::c_char)
        }
    }

    /// The `dependency_name` of a library is the name used to record dependencies across
    /// type libraries. This allows, for example, a library with the name "musl_libc" to have
    /// dependencies on it recorded as "libc_generic", allowing a type library to be used across
    /// multiple platforms where each has a specific libc that also provides the name "libc_generic"
    /// as an `alternate_name`.
    pub fn dependency_name(&self) -> Option<BnString> {
        let result = unsafe { BNGetTypeLibraryDependencyName(self.as_raw()) };
        (!result.is_null()).then(|| unsafe { BnString::from_raw(result) })
    }

    /// Sets the dependency name of a type library instance that has not been finalized
    pub fn set_dependency_name<S: BnStrCompatible>(&self, value: S) {
        let value = value.into_bytes_with_nul();
        unsafe {
            BNSetTypeLibraryDependencyName(
                self.as_raw(),
                value.as_ref().as_ptr() as *const ffi::c_char,
            )
        }
    }

    /// Returns the GUID associated with the type library
    pub fn guid(&self) -> Option<BnString> {
        let result = unsafe { BNGetTypeLibraryGuid(self.as_raw()) };
        (!result.is_null()).then(|| unsafe { BnString::from_raw(result) })
    }

    /// Sets the GUID of a type library instance that has not been finalized
    pub fn set_guid<S: BnStrCompatible>(&self, value: S) {
        let value = value.into_bytes_with_nul();
        unsafe {
            BNSetTypeLibraryGuid(self.as_raw(), value.as_ref().as_ptr() as *const ffi::c_char)
        }
    }

    /// A list of extra names that will be considered a match by [Platform::get_type_libraries_by_name]
    pub fn alternate_names(&self) -> Array<BnString> {
        let mut count = 0;
        let result = unsafe { BNGetTypeLibraryAlternateNames(self.as_raw(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Adds an extra name to this type library used during library lookups and dependency resolution
    pub fn add_alternate_name<S: BnStrCompatible>(&self, value: S) {
        let value = value.into_bytes_with_nul();
        unsafe {
            BNAddTypeLibraryAlternateName(
                self.as_raw(),
                value.as_ref().as_ptr() as *const ffi::c_char,
            )
        }
    }

    /// Returns a list of all platform names that this type library will register with during platform
    /// type registration.
    ///
    /// This returns strings, not Platform objects, as type libraries can be distributed with support for
    /// Platforms that may not be present.
    pub fn platform_names(&self) -> Array<BnString> {
        let mut count = 0;
        let result = unsafe { BNGetTypeLibraryPlatforms(self.as_raw(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Associate a platform with a type library instance that has not been finalized.
    ///
    /// This will cause the library to be searchable by [Platform::get_type_libraries_by_name]
    /// when loaded.
    ///
    /// This does not have side affects until finalization of the type library.
    pub fn add_platform(&self, plat: &Platform) {
        unsafe { BNAddTypeLibraryPlatform(self.as_raw(), plat.handle) }
    }

    /// Clears the list of platforms associated with a type library instance that has not been finalized
    pub fn clear_platforms(&self) {
        unsafe { BNClearTypeLibraryPlatforms(self.as_raw()) }
    }

    /// Flags a newly created type library instance as finalized and makes it available for Platform and Architecture
    /// type library searches
    pub fn finalize(&self) -> bool {
        unsafe { BNFinalizeTypeLibrary(self.as_raw()) }
    }

    /// Retrieves a metadata associated with the given key stored in the type library
    pub fn query_metadata<S: BnStrCompatible>(&self, key: S) -> Option<Metadata> {
        let key = key.into_bytes_with_nul();
        let result = unsafe {
            BNTypeLibraryQueryMetadata(self.as_raw(), key.as_ref().as_ptr() as *const ffi::c_char)
        };
        (!result.is_null()).then(|| unsafe { Metadata::from_raw(result) })
    }

    /// Stores an object for the given key in the current type library. Objects stored using
    /// `store_metadata` can be retrieved from any reference to the library. Objects stored are not arbitrary python
    /// objects! The values stored must be able to be held in a Metadata object. See [Metadata]
    /// for more information. Python objects could obviously be serialized using pickle but this intentionally
    /// a task left to the user since there is the potential security issues.
    ///
    /// This is primarily intended as a way to store Platform specific information relevant to BinaryView implementations;
    /// for example the PE BinaryViewType uses type library metadata to retrieve ordinal information, when available.
    ///
    /// * `key` - key value to associate the Metadata object with
    /// * `md` - object to store.
    pub fn store_metadata<S: BnStrCompatible>(&self, key: S, md: &Metadata) {
        let key = key.into_bytes_with_nul();
        unsafe {
            BNTypeLibraryStoreMetadata(
                self.as_raw(),
                key.as_ref().as_ptr() as *const ffi::c_char,
                md.handle,
            )
        }
    }

    /// Removes the metadata associated with key from the current type library.
    pub fn remove_metadata<S: BnStrCompatible>(&self, key: S) {
        let key = key.into_bytes_with_nul();
        unsafe {
            BNTypeLibraryRemoveMetadata(self.as_raw(), key.as_ref().as_ptr() as *const ffi::c_char)
        }
    }

    /// Retrieves the metadata associated with the current type library.
    pub fn metadata(&self) -> Metadata {
        let md_handle = unsafe { BNTypeLibraryGetMetadata(self.as_raw()) };
        assert!(!md_handle.is_null());
        unsafe { Metadata::from_raw(md_handle) }
    }

    // TODO: implement TypeContainer
    // /// Type Container for all TYPES within the Type Library. Objects are not included.
    // /// The Type Container's Platform will be the first platform associated with the Type Library.
    // pub fn type_container(&self) -> TypeContainer {
    //     let result = unsafe{ BNGetTypeLibraryTypeContainer(self.as_raw())};
    //     unsafe{TypeContainer::from_raw(ptr::NonNull::new(result).unwrap())}
    // }

    /// Directly inserts a named object into the type library's object store.
    /// This is not done recursively, so care should be taken that types referring to other types
    /// through NamedTypeReferences are already appropriately prepared.
    ///
    /// To add types and objects from an existing BinaryView, it is recommended to use
    /// `export_object_to_library <binaryview.BinaryView.export_object_to_library>`, which will automatically pull in
    /// all referenced types and record additional dependencies as needed.
    pub fn add_named_object(&self, name: QualifiedName, type_: &Type) {
        let mut raw_name = QualifiedName::into_raw(name);
        unsafe { BNAddTypeLibraryNamedObject(self.as_raw(), &mut raw_name, type_.handle) }
        QualifiedName::free_raw(raw_name);
    }

    /// Directly inserts a named object into the type library's object store.
    /// This is not done recursively, so care should be taken that types referring to other types
    /// through NamedTypeReferences are already appropriately prepared.
    ///
    /// To add types and objects from an existing BinaryView, it is recommended to use
    /// `export_type_to_library <binaryview.BinaryView.export_type_to_library>`, which will automatically pull in
    /// all referenced types and record additional dependencies as needed.
    pub fn add_named_type(&self, name: QualifiedName, type_: &Type) {
        let mut raw_name = QualifiedName::into_raw(name);
        unsafe { BNAddTypeLibraryNamedType(self.as_raw(), &mut raw_name, type_.handle) }
        QualifiedName::free_raw(raw_name);
    }

    /// Manually flag NamedTypeReferences to the given QualifiedName as originating from another source
    /// TypeLibrary with the given dependency name.
    ///
    /// <div class="warning">
    ///
    /// Use this api with extreme caution.
    ///
    /// </div>
    pub fn add_type_source<S: BnStrCompatible>(&self, name: QualifiedName, source: S) {
        let source = source.into_bytes_with_nul();
        let mut raw_name = QualifiedName::into_raw(name);
        unsafe {
            BNAddTypeLibraryNamedTypeSource(
                self.as_raw(),
                &mut raw_name,
                source.as_ref().as_ptr() as *const ffi::c_char,
            )
        }
        QualifiedName::free_raw(raw_name);
    }

    /// Direct extracts a reference to a contained object -- when
    /// attempting to extract types from a library into a BinaryView, consider using
    /// `import_library_object <binaryview.BinaryView.import_library_object>` instead.
    pub fn get_named_object(&self, name: QualifiedName) -> Option<Ref<Type>> {
        let mut raw_name = QualifiedName::into_raw(name);
        let t = unsafe { BNGetTypeLibraryNamedObject(self.as_raw(), &mut raw_name) };
        QualifiedName::free_raw(raw_name);
        (!t.is_null()).then(|| unsafe { Type::ref_from_raw(t) })
    }

    /// Direct extracts a reference to a contained type -- when
    /// attempting to extract types from a library into a BinaryView, consider using
    /// `import_library_type <binaryview.BinaryView.import_library_type>` instead.
    pub fn get_named_type(&self, name: QualifiedName) -> Option<Ref<Type>> {
        let mut raw_name = QualifiedName::into_raw(name);
        let t = unsafe { BNGetTypeLibraryNamedType(self.as_raw(), &mut raw_name) };
        QualifiedName::free_raw(raw_name);
        (!t.is_null()).then(|| unsafe { Type::ref_from_raw(t) })
    }

    /// A dict containing all named objects (functions, exported variables) provided by a type library
    pub fn named_objects(&self) -> Array<QualifiedNameAndType> {
        let mut count = 0;
        let result = unsafe { BNGetTypeLibraryNamedObjects(self.as_raw(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// A dict containing all named types provided by a type library
    pub fn named_types(&self) -> Array<QualifiedNameAndType> {
        let mut count = 0;
        let result = unsafe { BNGetTypeLibraryNamedTypes(self.as_raw(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }
}

impl Drop for TypeLibrary {
    fn drop(&mut self) {
        unsafe { BNFreeTypeLibrary(self.as_raw()) }
    }
}

impl CoreArrayProvider for TypeLibrary {
    type Raw = *mut BNTypeLibrary;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for TypeLibrary {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeTypeLibraryList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::ref_from_raw(raw)
    }
}
