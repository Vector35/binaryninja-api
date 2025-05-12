use binaryninjacore_sys::*;
use std::fmt::{Debug, Formatter};

use crate::rc::{Guard, RefCountable};
use crate::{
    architecture::CoreArchitecture,
    metadata::Metadata,
    platform::Platform,
    rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Ref},
    string::{BnString, IntoCStr},
    types::{QualifiedName, QualifiedNameAndType, Type},
};
use std::path::Path;
use std::ptr::NonNull;

#[repr(transparent)]
pub struct TypeLibrary {
    handle: NonNull<BNTypeLibrary>,
}

impl TypeLibrary {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNTypeLibrary>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: NonNull<BNTypeLibrary>) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNTypeLibrary {
        &mut *self.handle.as_ptr()
    }

    pub fn new_duplicated(&self) -> Ref<Self> {
        unsafe { Self::ref_from_raw(NonNull::new(BNDuplicateTypeLibrary(self.as_raw())).unwrap()) }
    }

    /// Creates an empty type library object with a random GUID and the provided name.
    pub fn new(arch: CoreArchitecture, name: &str) -> Ref<TypeLibrary> {
        let name = name.to_cstr();
        let new_lib = unsafe { BNNewTypeLibrary(arch.handle, name.as_ptr()) };
        unsafe { TypeLibrary::ref_from_raw(NonNull::new(new_lib).unwrap()) }
    }

    pub fn all(arch: CoreArchitecture) -> Array<TypeLibrary> {
        let mut count = 0;
        let result = unsafe { BNGetArchitectureTypeLibraries(arch.handle, &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Decompresses a type library file to a file on disk.
    pub fn decompress_to_file(path: &Path, output_path: &Path) -> bool {
        let path = path.to_cstr();
        let output = output_path.to_cstr();
        unsafe { BNTypeLibraryDecompressToFile(path.as_ptr(), output.as_ptr()) }
    }

    /// Loads a finalized type library instance from file
    pub fn load_from_file(path: &Path) -> Option<Ref<TypeLibrary>> {
        let path = path.to_cstr();
        let handle = unsafe { BNLoadTypeLibraryFromFile(path.as_ptr()) };
        NonNull::new(handle).map(|h| unsafe { TypeLibrary::ref_from_raw(h) })
    }

    /// Saves a finalized type library instance to file
    pub fn write_to_file(&self, path: &Path) -> bool {
        let path = path.to_cstr();
        unsafe { BNWriteTypeLibraryToFile(self.as_raw(), path.as_ptr()) }
    }

    /// Looks up the first type library found with a matching name. Keep in mind that names are not
    /// necessarily unique.
    ///
    /// NOTE: If the type library architecture's associated platform has not been initialized, this will
    /// return `None`. To make sure that the platform has been initialized, one should instead get the type
    /// libraries through [`Platform::get_type_libraries_by_name`].
    pub fn from_name(arch: CoreArchitecture, name: &str) -> Option<Ref<TypeLibrary>> {
        let name = name.to_cstr();
        let handle = unsafe { BNLookupTypeLibraryByName(arch.handle, name.as_ptr()) };
        NonNull::new(handle).map(|h| unsafe { TypeLibrary::ref_from_raw(h) })
    }

    /// Attempts to grab a type library associated with the provided Architecture and GUID pair.
    ///
    /// NOTE: If the associated platform for the architecture has not been initialized,  
    /// this will return `None`. Avoid calling this outside of a view context.
    pub fn from_guid(arch: CoreArchitecture, guid: &str) -> Option<Ref<TypeLibrary>> {
        let guid = guid.to_cstr();
        let handle = unsafe { BNLookupTypeLibraryByGuid(arch.handle, guid.as_ptr()) };
        NonNull::new(handle).map(|h| unsafe { TypeLibrary::ref_from_raw(h) })
    }

    /// The Architecture this type library is associated with
    pub fn arch(&self) -> CoreArchitecture {
        let arch = unsafe { BNGetTypeLibraryArchitecture(self.as_raw()) };
        assert!(!arch.is_null());
        unsafe { CoreArchitecture::from_raw(arch) }
    }

    /// The primary name associated with this type library
    pub fn name(&self) -> String {
        let result = unsafe { BNGetTypeLibraryName(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::into_string(result) }
    }

    /// Sets the name of a type library instance that has not been finalized
    pub fn set_name(&self, value: &str) {
        let value = value.to_cstr();
        unsafe { BNSetTypeLibraryName(self.as_raw(), value.as_ptr()) }
    }

    /// The `dependency_name` of a library is the name used to record dependencies across
    /// type libraries. This allows, for example, a library with the name "musl_libc" to have
    /// dependencies on it recorded as "libc_generic", allowing a type library to be used across
    /// multiple platforms where each has a specific libc that also provides the name "libc_generic"
    /// as an `alternate_name`.
    pub fn dependency_name(&self) -> String {
        let result = unsafe { BNGetTypeLibraryDependencyName(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::into_string(result) }
    }

    /// Sets the dependency name of a type library instance that has not been finalized
    pub fn set_dependency_name(&self, value: &str) {
        let value = value.to_cstr();
        unsafe { BNSetTypeLibraryDependencyName(self.as_raw(), value.as_ptr()) }
    }

    /// Returns the GUID associated with the type library
    pub fn guid(&self) -> String {
        let result = unsafe { BNGetTypeLibraryGuid(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::into_string(result) }
    }

    /// Sets the GUID of a type library instance that has not been finalized
    pub fn set_guid(&self, value: &str) {
        let value = value.to_cstr();
        unsafe { BNSetTypeLibraryGuid(self.as_raw(), value.as_ptr()) }
    }

    /// A list of extra names that will be considered a match by [Platform::get_type_libraries_by_name]
    pub fn alternate_names(&self) -> Array<BnString> {
        let mut count = 0;
        let result = unsafe { BNGetTypeLibraryAlternateNames(self.as_raw(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Adds an extra name to this type library used during library lookups and dependency resolution
    pub fn add_alternate_name(&self, value: &str) {
        let value = value.to_cstr();
        unsafe { BNAddTypeLibraryAlternateName(self.as_raw(), value.as_ptr()) }
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
    pub fn query_metadata(&self, key: &str) -> Option<Ref<Metadata>> {
        let key = key.to_cstr();
        let result = unsafe { BNTypeLibraryQueryMetadata(self.as_raw(), key.as_ptr()) };
        (!result.is_null()).then(|| unsafe { Metadata::ref_from_raw(result) })
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
    pub fn store_metadata(&self, key: &str, md: &Metadata) {
        let key = key.to_cstr();
        unsafe { BNTypeLibraryStoreMetadata(self.as_raw(), key.as_ptr(), md.handle) }
    }

    /// Removes the metadata associated with key from the current type library.
    pub fn remove_metadata(&self, key: &str) {
        let key = key.to_cstr();
        unsafe { BNTypeLibraryRemoveMetadata(self.as_raw(), key.as_ptr()) }
    }

    /// Retrieves the metadata associated with the current type library.
    pub fn metadata(&self) -> Ref<Metadata> {
        let md_handle = unsafe { BNTypeLibraryGetMetadata(self.as_raw()) };
        assert!(!md_handle.is_null());
        unsafe { Metadata::ref_from_raw(md_handle) }
    }

    // TODO: implement TypeContainer
    // /// Type Container for all TYPES within the Type Library. Objects are not included.
    // /// The Type Container's Platform will be the first platform associated with the Type Library.
    // pub fn type_container(&self) -> TypeContainer {
    //     let result = unsafe{ BNGetTypeLibraryTypeContainer(self.as_raw())};
    //     unsafe{TypeContainer::from_raw(NonNull::new(result).unwrap())}
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
    pub fn add_type_source(&self, name: QualifiedName, source: &str) {
        let source = source.to_cstr();
        let mut raw_name = QualifiedName::into_raw(name);
        unsafe { BNAddTypeLibraryNamedTypeSource(self.as_raw(), &mut raw_name, source.as_ptr()) }
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

impl Debug for TypeLibrary {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TypeLibrary")
            .field("name", &self.name())
            .field("dependency_name", &self.dependency_name())
            .field("arch", &self.arch())
            .field("guid", &self.guid())
            .field("alternate_names", &self.alternate_names().to_vec())
            .field("platform_names", &self.platform_names().to_vec())
            .field("metadata", &self.metadata())
            // These two are too verbose.
            // .field("named_objects", &self.named_objects().to_vec())
            // .field("named_types", &self.named_types().to_vec())
            .finish()
    }
}

unsafe impl RefCountable for TypeLibrary {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: NonNull::new(BNNewTypeLibraryReference(handle.handle.as_ptr())).unwrap(),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeTypeLibrary(handle.handle.as_ptr());
    }
}

impl ToOwned for TypeLibrary {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

impl CoreArrayProvider for TypeLibrary {
    type Raw = *mut BNTypeLibrary;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Self>;
}

unsafe impl CoreArrayProviderInner for TypeLibrary {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeTypeLibraryList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        Guard::new(Self::from_raw(NonNull::new(*raw).unwrap()), context)
    }
}
