use crate::rc::{Guard, RefCountable};
use crate::types::TypeContainer;
use crate::{
    architecture::CoreArchitecture,
    metadata::Metadata,
    platform::Platform,
    rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Ref},
    string::{BnString, IntoCStr},
    types::{QualifiedName, QualifiedNameAndType, Type},
};
use binaryninjacore_sys::*;
use std::fmt::{Debug, Formatter};
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::ptr::NonNull;

// Used for doc comments
#[allow(unused_imports)]
use crate::binary_view::BinaryView;

// TODO: Introduce a FinalizedImportLibrary that cannot be mutated, so we do not have APIs that are unusable.

/// An [`ImportLibrary`] is a collection of function symbols and their associated types and metadata that
/// correspond to a shared library or are used in conjunction with a shared library. Import libraries
/// are the main way external functions in a binary view are annotated and are crucial to allowing
/// proper analysis of the binary.
///
/// Import libraries can share common types between them by forwarding named type references to a specified
/// source import library. If an import library is made available to a view, it may also pull in other import
/// libraries, it is important to not treat an import library as a complete source of information.
#[repr(transparent)]
pub struct ImportLibrary {
    handle: NonNull<BNImportLibrary>,
}

impl ImportLibrary {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNImportLibrary>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: NonNull<BNImportLibrary>) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNImportLibrary {
        &mut *self.handle.as_ptr()
    }

    /// Duplicate the import library. This creates a new, non-finalized import library object that shares
    /// the same underlying name and architecture.
    ///
    /// IMPORTANT: This does not *actually* duplicate the import library currently, you still need to
    /// copy over the named types, named objects, platforms, and metadata.
    pub fn duplicate(&self) -> Ref<Self> {
        unsafe {
            Self::ref_from_raw(NonNull::new(BNDuplicateImportLibrary(self.as_raw())).unwrap())
        }
    }

    /// Creates an empty import library object with a random GUID and the provided name.
    pub fn new(arch: CoreArchitecture, name: &str) -> Ref<ImportLibrary> {
        let name = name.to_cstr();
        let new_lib = unsafe { BNNewImportLibrary(arch.handle, name.as_ptr()) };
        unsafe { ImportLibrary::ref_from_raw(NonNull::new(new_lib).unwrap()) }
    }

    pub fn all(arch: CoreArchitecture) -> Array<ImportLibrary> {
        let mut count = 0;
        let result = unsafe { BNGetArchitectureImportLibraries(arch.handle, &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Loads a finalized import library instance from the given `path`.
    ///
    /// The returned import library cannot be modified.
    pub fn load_from_file(path: &Path) -> Option<Ref<ImportLibrary>> {
        let path = path.to_cstr();
        let handle = unsafe { BNLoadImportLibraryFromFile(path.as_ptr()) };
        NonNull::new(handle).map(|h| unsafe { ImportLibrary::ref_from_raw(h) })
    }

    /// Saves an import library at the given `path` on disk, overwriting any existing file.
    ///
    /// The path must be writable, and the parent directory must exist.
    pub fn write_to_file(&self, path: &Path) -> bool {
        let path = path.to_cstr();
        unsafe { BNWriteImportLibraryToFile(self.as_raw(), path.as_ptr()) }
    }

    /// Decompresses the import library file to a JSON file at the given `output_path`.
    pub fn decompress_to_file(&self, output_path: &Path) -> bool {
        let path = output_path.to_cstr();
        unsafe { BNImportLibraryDecompressToFile(self.handle.as_ptr(), path.as_ptr()) }
    }

    /// Looks up the first import library found with a matching name. Keep in mind that names are not
    /// necessarily unique.
    ///
    /// NOTE: If the import library architecture's associated platform has not been initialized, this will
    /// return `None`. To make sure that the platform has been initialized, one should instead get the import
    /// libraries through [`Platform::get_import_libraries_by_name`].
    pub fn from_name(arch: CoreArchitecture, name: &str) -> Option<Ref<ImportLibrary>> {
        let name = name.to_cstr();
        let handle = unsafe { BNLookupImportLibraryByName(arch.handle, name.as_ptr()) };
        NonNull::new(handle).map(|h| unsafe { ImportLibrary::ref_from_raw(h) })
    }

    /// Attempts to grab an import library associated with the provided Architecture and GUID pair.
    ///
    /// NOTE: If the associated platform for the architecture has not been initialized,  
    /// this will return `None`. Avoid calling this outside of a view context.
    pub fn from_guid(arch: CoreArchitecture, guid: &str) -> Option<Ref<ImportLibrary>> {
        let guid = guid.to_cstr();
        let handle = unsafe { BNLookupImportLibraryByGuid(arch.handle, guid.as_ptr()) };
        NonNull::new(handle).map(|h| unsafe { ImportLibrary::ref_from_raw(h) })
    }

    /// The [`CoreArchitecture`] this import library is associated with.
    ///
    /// Import libraries will always have a single architecture associated with it. It can have multiple
    /// platforms associated with it, see [`ImportLibrary::platform_names`] for more detail.
    pub fn arch(&self) -> CoreArchitecture {
        let arch = unsafe { BNGetImportLibraryArchitecture(self.as_raw()) };
        assert!(!arch.is_null());
        unsafe { CoreArchitecture::from_raw(arch) }
    }

    /// The primary name associated with this import library, this will not be used to automatically import
    /// libraries into a binary view, that is the job of [`ImportLibrary::dependency_name`].
    pub fn name(&self) -> String {
        let result = unsafe { BNGetImportLibraryName(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::into_string(result) }
    }

    /// Sets the name of an import library that has not been finalized.
    pub fn set_name(&self, value: &str) {
        let value = value.to_cstr();
        unsafe { BNSetImportLibraryName(self.as_raw(), value.as_ptr()) }
    }

    /// The `dependency_name` of a library is the name used to record dependencies across
    /// import libraries. This allows, for example, a library with the name "musl_libc" to have
    /// dependencies on it recorded as "libc_generic", allowing an import library to be used across
    /// multiple platforms where each has a specific libc that also provides the name "libc_generic"
    /// as an `alternate_name`.
    pub fn dependency_name(&self) -> String {
        let result = unsafe { BNGetImportLibraryDependencyName(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::into_string(result) }
    }

    /// Sets the dependency name of an import library instance that has not been finalized
    pub fn set_dependency_name(&self, value: &str) {
        let value = value.to_cstr();
        unsafe { BNSetImportLibraryDependencyName(self.as_raw(), value.as_ptr()) }
    }

    /// Returns the GUID associated with the import library
    pub fn guid(&self) -> String {
        let result = unsafe { BNGetImportLibraryGuid(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::into_string(result) }
    }

    /// Sets the GUID of an import library instance that has not been finalized.
    pub fn set_guid(&self, value: &str) {
        let value = value.to_cstr();
        unsafe { BNSetImportLibraryGuid(self.as_raw(), value.as_ptr()) }
    }

    /// A list of extra names that will be considered a match by [`Platform::get_import_libraries_by_name`]
    pub fn alternate_names(&self) -> Array<BnString> {
        let mut count = 0;
        let result = unsafe { BNGetImportLibraryAlternateNames(self.as_raw(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Adds an extra name to this import library used during library lookups and dependency resolution
    pub fn add_alternate_name(&self, value: &str) {
        let value = value.to_cstr();
        unsafe { BNAddImportLibraryAlternateName(self.as_raw(), value.as_ptr()) }
    }

    /// Removes an extra name from this import library used during library lookups and dependency resolution
    pub fn remove_alternate_name(&self, value: &str) {
        let value = value.to_cstr();
        unsafe { BNRemoveImportLibraryAlternateName(self.as_raw(), value.as_ptr()) }
    }

    /// Returns a list of all platform names that this import library will register with during platform
    /// type registration.
    ///
    /// Because import libraries can be distributed with platforms that do not exist, we return the names.
    pub fn platform_names(&self) -> Array<BnString> {
        let mut count = 0;
        let result = unsafe { BNGetImportLibraryPlatforms(self.as_raw(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Associate a platform with an import library instance that has not been finalized.
    ///
    /// This will cause the library to be searchable by [`Platform::get_import_libraries_by_name`]
    /// when loaded.
    ///
    /// This does not have side effects until finalization of the import library.
    pub fn add_platform(&self, plat: &Platform) {
        unsafe { BNAddImportLibraryPlatform(self.as_raw(), plat.handle) }
    }

    /// Clears the list of platforms associated with an import library instance that has not been finalized.
    pub fn clear_platforms(&self) {
        unsafe { BNClearImportLibraryPlatforms(self.as_raw()) }
    }

    /// Flags a newly created import library instance as finalized and makes it available for Platform
    /// and Architecture import library searches.
    pub fn finalize(&self) -> bool {
        unsafe { BNFinalizeImportLibrary(self.as_raw()) }
    }

    /// Make a created or loaded Import Library available for Platforms to use when loading binaries.
    pub fn register(&self) {
        unsafe { BNRegisterImportLibrary(self.as_raw()) }
    }

    /// Retrieves the metadata associated with the given key stored in the import library.
    pub fn query_metadata(&self, key: &str) -> Option<Ref<Metadata>> {
        let key = key.to_cstr();
        let result = unsafe { BNImportLibraryQueryMetadata(self.as_raw(), key.as_ptr()) };
        (!result.is_null()).then(|| unsafe { Metadata::ref_from_raw(result) })
    }

    /// Stores a [`Metadata`] object in the given key for the import library.
    ///
    /// This is primarily intended as a way to store Platform specific information relevant to BinaryView implementations;
    /// for example, the PE BinaryViewType uses import library metadata to retrieve ordinal information, when available.
    pub fn store_metadata(&self, key: &str, md: &Metadata) {
        let key = key.to_cstr();
        unsafe { BNImportLibraryStoreMetadata(self.as_raw(), key.as_ptr(), md.handle) }
    }

    /// Removes the metadata associated with key from the import library.
    pub fn remove_metadata(&self, key: &str) {
        let key = key.to_cstr();
        unsafe { BNImportLibraryRemoveMetadata(self.as_raw(), key.as_ptr()) }
    }

    /// Retrieves the metadata associated with the import library.
    pub fn metadata(&self) -> Ref<Metadata> {
        let md_handle = unsafe { BNImportLibraryGetMetadata(self.as_raw()) };
        assert!(!md_handle.is_null());
        unsafe { Metadata::ref_from_raw(md_handle) }
    }

    pub fn type_container(&self) -> TypeContainer {
        let result = unsafe { BNGetImportLibraryTypeContainer(self.as_raw()) };
        unsafe { TypeContainer::from_raw(NonNull::new(result).unwrap()) }
    }

    /// Directly inserts a named object into the import library's object store.
    ///
    /// Referenced types will not automatically be added, so make sure to add referenced types to the
    /// library or use [`ImportLibrary::add_type_source`] to mark the references originating source.
    ///
    /// To add objects from a binary view, prefer using [`BinaryView::export_object_to_library`] which
    /// will automatically pull in all referenced types and record additional dependencies as needed.
    pub fn add_named_object(&self, name: QualifiedName, type_: &Type) {
        let mut raw_name = QualifiedName::into_raw(name);
        unsafe { BNAddImportLibraryNamedObject(self.as_raw(), &mut raw_name, type_.handle) }
        QualifiedName::free_raw(raw_name);
    }

    pub fn remove_named_object(&self, name: QualifiedName) {
        let mut raw_name = QualifiedName::into_raw(name);
        unsafe { BNRemoveImportLibraryNamedObject(self.as_raw(), &mut raw_name) }
        QualifiedName::free_raw(raw_name);
    }

    /// Directly inserts a named type into the import library's type store.
    ///
    /// Referenced types will not automatically be added, so make sure to add referenced types to the
    /// library or use [`ImportLibrary::add_type_source`] to mark the references originating source.
    ///
    /// To add types from a binary view, prefer using [`BinaryView::export_type_to_library`] which
    /// will automatically pull in all referenced types and record additional dependencies as needed.
    pub fn add_named_type(&self, name: QualifiedName, type_: &Type) {
        let mut raw_name = QualifiedName::into_raw(name);
        unsafe { BNAddImportLibraryNamedType(self.as_raw(), &mut raw_name, type_.handle) }
        QualifiedName::free_raw(raw_name);
    }

    pub fn remove_named_type(&self, name: QualifiedName) {
        let mut raw_name = QualifiedName::into_raw(name);
        unsafe { BNRemoveImportLibraryNamedType(self.as_raw(), &mut raw_name) }
        QualifiedName::free_raw(raw_name);
    }

    /// Flag any outgoing named type reference with the given `name` as belonging to the `source` import library.
    ///
    /// This allows import libraries to share types between them, automatically pulling in dependencies
    /// into the binary view as needed.
    pub fn add_type_source(&self, name: QualifiedName, source: &str) {
        let source = source.to_cstr();
        let mut raw_name = QualifiedName::into_raw(name);
        unsafe { BNAddImportLibraryNamedTypeSource(self.as_raw(), &mut raw_name, source.as_ptr()) }
        QualifiedName::free_raw(raw_name);
    }

    /// Retrieve the source import library associated with the given named type, if any.
    pub fn get_named_type_source(&self, name: QualifiedName) -> Option<String> {
        let mut raw_name = QualifiedName::into_raw(name);
        let result = unsafe { BNGetImportLibraryNamedTypeSource(self.as_raw(), &mut raw_name) };
        QualifiedName::free_raw(raw_name);
        let str = unsafe { BnString::into_string(result) };
        if str.is_empty() {
            None
        } else {
            Some(str)
        }
    }

    /// Get the object (function) associated with the given name, if any.
    ///
    /// Prefer [`BinaryView::import_object_from_library`] as it will recursively import types required.
    pub fn get_named_object(&self, name: QualifiedName) -> Option<Ref<Type>> {
        let mut raw_name = QualifiedName::into_raw(name);
        let t = unsafe { BNGetImportLibraryNamedObject(self.as_raw(), &mut raw_name) };
        QualifiedName::free_raw(raw_name);
        (!t.is_null()).then(|| unsafe { Type::ref_from_raw(t) })
    }

    /// Get the type associated with the given name, if any.
    ///
    /// Prefer [`BinaryView::import_type_from_library`] as it will recursively import types required.
    pub fn get_named_type(&self, name: QualifiedName) -> Option<Ref<Type>> {
        let mut raw_name = QualifiedName::into_raw(name);
        let t = unsafe { BNGetImportLibraryNamedType(self.as_raw(), &mut raw_name) };
        QualifiedName::free_raw(raw_name);
        (!t.is_null()).then(|| unsafe { Type::ref_from_raw(t) })
    }

    /// The list of all named objects provided by an import library
    pub fn named_objects(&self) -> Array<QualifiedNameAndType> {
        let mut count = 0;
        let result = unsafe { BNGetImportLibraryNamedObjects(self.as_raw(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// The list of all named types provided by an import library
    pub fn named_types(&self) -> Array<QualifiedNameAndType> {
        let mut count = 0;
        let result = unsafe { BNGetImportLibraryNamedTypes(self.as_raw(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }
}

impl Debug for ImportLibrary {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImportLibrary")
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

impl PartialEq for ImportLibrary {
    fn eq(&self, other: &Self) -> bool {
        self.guid() == other.guid()
    }
}

impl Eq for ImportLibrary {}

impl Hash for ImportLibrary {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.guid().hash(state);
    }
}

unsafe impl RefCountable for ImportLibrary {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: NonNull::new(BNNewImportLibraryReference(handle.handle.as_ptr())).unwrap(),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeImportLibrary(handle.handle.as_ptr());
    }
}

impl ToOwned for ImportLibrary {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

impl CoreArrayProvider for ImportLibrary {
    type Raw = *mut BNImportLibrary;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Self>;
}

unsafe impl CoreArrayProviderInner for ImportLibrary {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeImportLibraryList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        Guard::new(Self::from_raw(NonNull::new(*raw).unwrap()), context)
    }
}

unsafe impl Send for ImportLibrary {}
unsafe impl Sync for ImportLibrary {}
