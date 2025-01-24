use crate::progress::{NoProgressCallback, ProgressCallback};
use binaryninjacore_sys::*;
use std::ffi::{c_char, c_void, CStr};
use std::fmt::{Debug, Display, Formatter};
use std::hash::Hash;
use std::path::{Path, PathBuf};
use std::ptr::NonNull;

use crate::data_buffer::DataBuffer;
use crate::metadata::Metadata;
use crate::platform::Platform;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable};
use crate::string::{raw_to_string, BnStrCompatible, BnString};
use crate::type_container::TypeContainer;
use crate::types::{QualifiedName, QualifiedNameAndType, QualifiedNameTypeAndId, Type};

#[repr(transparent)]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypeArchiveSnapshotId(pub String);

impl TypeArchiveSnapshotId {
    pub fn unset() -> Self {
        Self("".to_string())
    }
}

impl Display for TypeArchiveSnapshotId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}", self.0))
    }
}

impl CoreArrayProvider for TypeArchiveSnapshotId {
    type Raw = *mut c_char;
    type Context = ();
    type Wrapped<'a> = TypeArchiveSnapshotId;
}

unsafe impl CoreArrayProviderInner for TypeArchiveSnapshotId {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeStringList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        let str = CStr::from_ptr(*raw).to_str().unwrap().to_string();
        TypeArchiveSnapshotId(str)
    }
}

/// Type Archives are a collection of types which can be shared between different analysis
/// sessions and are backed by a database file on disk. Their types can be modified, and
/// a history of previous versions of types is stored in snapshots in the archive.
pub struct TypeArchive {
    pub(crate) handle: NonNull<BNTypeArchive>,
}

impl TypeArchive {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNTypeArchive>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: NonNull<BNTypeArchive>) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    /// Open the Type Archive at the given path, if it exists.
    pub fn open(path: impl AsRef<Path>) -> Option<Ref<TypeArchive>> {
        let raw_path = path.as_ref().into_bytes_with_nul();
        let handle = unsafe { BNOpenTypeArchive(raw_path.as_ptr() as *const c_char) };
        NonNull::new(handle).map(|handle| unsafe { TypeArchive::ref_from_raw(handle) })
    }

    /// Create a Type Archive at the given path, returning `None` if it could not be created.
    ///
    /// If the file has already been created and is not a valid type archive this will return `None`.
    pub fn create(path: impl AsRef<Path>, platform: &Platform) -> Option<Ref<TypeArchive>> {
        let raw_path = path.as_ref().into_bytes_with_nul();
        let handle =
            unsafe { BNCreateTypeArchive(raw_path.as_ptr() as *const c_char, platform.handle) };
        NonNull::new(handle).map(|handle| unsafe { TypeArchive::ref_from_raw(handle) })
    }

    /// Create a Type Archive at the given path and id, returning None if it could not be created.
    ///
    /// If the file has already been created and is not a valid type archive this will return `None`.
    pub fn create_with_id<I: BnStrCompatible>(
        path: impl AsRef<Path>,
        id: I,
        platform: &Platform,
    ) -> Option<Ref<TypeArchive>> {
        let raw_path = path.as_ref().into_bytes_with_nul();
        let id = id.into_bytes_with_nul();
        let handle = unsafe {
            BNCreateTypeArchiveWithId(
                raw_path.as_ptr() as *const c_char,
                platform.handle,
                id.as_ref().as_ptr() as *const c_char,
            )
        };
        NonNull::new(handle).map(|handle| unsafe { TypeArchive::ref_from_raw(handle) })
    }

    /// Get a reference to the Type Archive with the known id, if one exists.
    pub fn lookup_by_id<S: BnStrCompatible>(id: S) -> Option<Ref<TypeArchive>> {
        let id = id.into_bytes_with_nul();
        let handle = unsafe { BNLookupTypeArchiveById(id.as_ref().as_ptr() as *const c_char) };
        NonNull::new(handle).map(|handle| unsafe { TypeArchive::ref_from_raw(handle) })
    }

    /// Get the path to the Type Archive's file
    pub fn path(&self) -> Option<PathBuf> {
        let result = unsafe { BNGetTypeArchivePath(self.handle.as_ptr()) };
        match result.is_null() {
            false => {
                let bn_res = unsafe { BnString::from_raw(result) };
                Some(PathBuf::from(bn_res.to_string()))
            }
            true => None,
        }
    }

    /// Get the guid for a Type Archive
    pub fn id(&self) -> Option<BnString> {
        let result = unsafe { BNGetTypeArchiveId(self.handle.as_ptr()) };
        (!result.is_null()).then(|| unsafe { BnString::from_raw(result) })
    }

    /// Get the associated Platform for a Type Archive
    pub fn platform(&self) -> Ref<Platform> {
        let result = unsafe { BNGetTypeArchivePlatform(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { Platform::ref_from_raw(result) }
    }

    /// Get the id of the current snapshot in the type archive
    pub fn current_snapshot_id(&self) -> TypeArchiveSnapshotId {
        let result = unsafe { BNGetTypeArchiveCurrentSnapshotId(self.handle.as_ptr()) };
        assert!(!result.is_null());
        TypeArchiveSnapshotId(unsafe { BnString::from_raw(result) }.to_string())
    }

    /// Revert the type archive's current snapshot to the given snapshot
    pub fn set_current_snapshot_id(&self, id: &TypeArchiveSnapshotId) {
        unsafe {
            BNSetTypeArchiveCurrentSnapshot(self.handle.as_ptr(), id.0.as_ptr() as *const c_char)
        }
    }

    /// Get a list of every snapshot's id
    pub fn all_snapshot_ids(&self) -> Array<TypeArchiveSnapshotId> {
        let mut count = 0;
        let result = unsafe { BNGetTypeArchiveAllSnapshotIds(self.handle.as_ptr(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Get the ids of the parents to the given snapshot
    pub fn get_snapshot_parent_ids<S: BnStrCompatible>(
        &self,
        snapshot: &TypeArchiveSnapshotId,
    ) -> Option<Array<BnString>> {
        let mut count = 0;
        let result = unsafe {
            BNGetTypeArchiveSnapshotParentIds(
                self.handle.as_ptr(),
                snapshot.0.as_ptr() as *const c_char,
                &mut count,
            )
        };
        (!result.is_null()).then(|| unsafe { Array::new(result, count, ()) })
    }

    /// Get the ids of the children to the given snapshot
    pub fn get_snapshot_child_ids<S: BnStrCompatible>(
        &self,
        snapshot: &TypeArchiveSnapshotId,
    ) -> Option<Array<BnString>> {
        let mut count = 0;
        let result = unsafe {
            BNGetTypeArchiveSnapshotChildIds(
                self.handle.as_ptr(),
                snapshot.0.as_ptr() as *const c_char,
                &mut count,
            )
        };
        (!result.is_null()).then(|| unsafe { Array::new(result, count, ()) })
    }

    /// Add a named type to the type archive. Type must have all dependant named types added
    /// prior to being added, or this function will fail.
    /// If the type already exists, it will be overwritten.
    ///
    /// * `named_type` - Named type to add
    pub fn add_type(&self, named_type: QualifiedNameAndType) -> bool {
        self.add_types(vec![named_type])
    }

    /// Add named types to the type archive. Types must have all dependant named
    /// types prior to being added, or included in the list, or this function will fail.
    /// Types already existing with any added names will be overwritten.
    ///
    /// * `named_types` - Names and definitions of new types
    pub fn add_types(&self, named_types: Vec<QualifiedNameAndType>) -> bool {
        let new_types_raw: Vec<_> = named_types
            .into_iter()
            .map(QualifiedNameAndType::into_raw)
            .collect();
        let result = unsafe {
            BNAddTypeArchiveTypes(
                self.handle.as_ptr(),
                new_types_raw.as_ptr(),
                new_types_raw.len(),
            )
        };
        for new_type in new_types_raw {
            QualifiedNameAndType::free_raw(new_type);
        }
        result
    }

    /// Change the name of an existing type in the type archive. Returns false if failed.
    ///
    /// * `old_name` - Old type name in archive
    /// * `new_name` - New type name
    pub fn rename_type(&self, old_name: QualifiedName, new_name: QualifiedName) -> bool {
        if let Some(id) = self.get_type_id(old_name) {
            self.rename_type_by_id(id, new_name)
        } else {
            false
        }
    }

    /// Change the name of an existing type in the type archive. Returns false if failed.
    ///
    /// * `id` - Old id of type in archive
    /// * `new_name` - New type name
    pub fn rename_type_by_id<S: BnStrCompatible>(&self, id: S, new_name: QualifiedName) -> bool {
        let id = id.into_bytes_with_nul();
        let raw_name = QualifiedName::into_raw(new_name);
        let result = unsafe {
            BNRenameTypeArchiveType(
                self.handle.as_ptr(),
                id.as_ref().as_ptr() as *const c_char,
                &raw_name,
            )
        };
        QualifiedName::free_raw(raw_name);
        result
    }

    /// Delete an existing type in the type archive.
    pub fn delete_type(&self, name: QualifiedName) -> bool {
        if let Some(type_id) = self.get_type_id(name) {
            self.delete_type_by_id(type_id)
        } else {
            false
        }
    }

    /// Delete an existing type in the type archive.
    pub fn delete_type_by_id<S: BnStrCompatible>(&self, id: S) -> bool {
        let id = id.into_bytes_with_nul();
        let result = unsafe {
            BNDeleteTypeArchiveType(self.handle.as_ptr(), id.as_ref().as_ptr() as *const c_char)
        };
        result
    }

    /// Retrieve a stored type in the archive
    ///
    /// * `name` - Type name
    pub fn get_type_by_name<S: BnStrCompatible>(&self, name: QualifiedName) -> Option<Ref<Type>> {
        self.get_type_by_name_from_snapshot(name, &TypeArchiveSnapshotId::unset())
    }

    /// Retrieve a stored type in the archive
    ///
    /// * `name` - Type name
    /// * `snapshot` - Snapshot id to search for types
    pub fn get_type_by_name_from_snapshot(
        &self,
        name: QualifiedName,
        snapshot: &TypeArchiveSnapshotId,
    ) -> Option<Ref<Type>> {
        let raw_name = QualifiedName::into_raw(name);
        let result = unsafe {
            BNGetTypeArchiveTypeByName(
                self.handle.as_ptr(),
                &raw_name,
                snapshot.0.as_ptr() as *const c_char,
            )
        };
        QualifiedName::free_raw(raw_name);
        (!result.is_null()).then(|| unsafe { Type::ref_from_raw(result) })
    }

    /// Retrieve a stored type in the archive by id
    ///
    /// * `id` - Type id
    pub fn get_type_by_id<I: BnStrCompatible>(&self, id: I) -> Option<Ref<Type>> {
        self.get_type_by_id_from_snapshot(id, &TypeArchiveSnapshotId::unset())
    }

    /// Retrieve a stored type in the archive by id
    ///
    /// * `id` - Type id
    /// * `snapshot` - Snapshot id to search for types
    pub fn get_type_by_id_from_snapshot<I: BnStrCompatible>(
        &self,
        id: I,
        snapshot: &TypeArchiveSnapshotId,
    ) -> Option<Ref<Type>> {
        let id = id.into_bytes_with_nul();
        let result = unsafe {
            BNGetTypeArchiveTypeById(
                self.handle.as_ptr(),
                id.as_ref().as_ptr() as *const c_char,
                snapshot.0.as_ptr() as *const c_char,
            )
        };
        (!result.is_null()).then(|| unsafe { Type::ref_from_raw(result) })
    }

    /// Retrieve a type's name by its id
    ///
    /// * `id` - Type id
    pub fn get_type_name_by_id<I: BnStrCompatible>(&self, id: I) -> QualifiedName {
        self.get_type_name_by_id_from_snapshot(id, &TypeArchiveSnapshotId::unset())
    }

    /// Retrieve a type's name by its id
    ///
    /// * `id` - Type id
    /// * `snapshot` - Snapshot id to search for types
    pub fn get_type_name_by_id_from_snapshot<I: BnStrCompatible>(
        &self,
        id: I,
        snapshot: &TypeArchiveSnapshotId,
    ) -> QualifiedName {
        let id = id.into_bytes_with_nul();
        let result = unsafe {
            BNGetTypeArchiveTypeName(
                self.handle.as_ptr(),
                id.as_ref().as_ptr() as *const c_char,
                snapshot.0.as_ptr() as *const c_char,
            )
        };
        QualifiedName::from_owned_raw(result)
    }

    /// Retrieve a type's id by its name
    ///
    /// * `name` - Type name
    pub fn get_type_id(&self, name: QualifiedName) -> Option<BnString> {
        self.get_type_id_from_snapshot(name, &TypeArchiveSnapshotId::unset())
    }

    /// Retrieve a type's id by its name
    ///
    /// * `name` - Type name
    /// * `snapshot` - Snapshot id to search for types
    pub fn get_type_id_from_snapshot(
        &self,
        name: QualifiedName,
        snapshot: &TypeArchiveSnapshotId,
    ) -> Option<BnString> {
        let raw_name = QualifiedName::into_raw(name);
        let result = unsafe {
            BNGetTypeArchiveTypeId(
                self.handle.as_ptr(),
                &raw_name,
                snapshot.0.as_ptr() as *const c_char,
            )
        };
        QualifiedName::free_raw(raw_name);
        (!result.is_null()).then(|| unsafe { BnString::from_raw(result) })
    }

    /// Retrieve all stored types in the archive at a snapshot
    pub fn get_types_and_ids(&self) -> Array<QualifiedNameTypeAndId> {
        self.get_types_and_ids_from_snapshot(&TypeArchiveSnapshotId::unset())
    }

    /// Retrieve all stored types in the archive at a snapshot
    ///
    /// * `snapshot` - Snapshot id to search for types
    pub fn get_types_and_ids_from_snapshot(
        &self,
        snapshot: &TypeArchiveSnapshotId,
    ) -> Array<QualifiedNameTypeAndId> {
        let mut count = 0;
        let result = unsafe {
            BNGetTypeArchiveTypes(
                self.handle.as_ptr(),
                snapshot.0.as_ptr() as *const c_char,
                &mut count,
            )
        };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Get a list of all types' ids in the archive at a snapshot
    pub fn get_type_ids(&self) -> Array<BnString> {
        self.get_type_ids_from_snapshot(&TypeArchiveSnapshotId::unset())
    }

    /// Get a list of all types' ids in the archive at a snapshot
    ///
    /// * `snapshot` - Snapshot id to search for types
    pub fn get_type_ids_from_snapshot(&self, snapshot: &TypeArchiveSnapshotId) -> Array<BnString> {
        let mut count = 0;
        let result = unsafe {
            BNGetTypeArchiveTypeIds(
                self.handle.as_ptr(),
                snapshot.0.as_ptr() as *const c_char,
                &mut count,
            )
        };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Get a list of all types' names in the archive at a snapshot
    pub fn get_type_names(&self) -> Array<QualifiedName> {
        self.get_type_names_from_snapshot(&TypeArchiveSnapshotId::unset())
    }

    /// Get a list of all types' names in the archive at a snapshot
    ///
    /// * `snapshot` - Snapshot id to search for types
    pub fn get_type_names_from_snapshot(
        &self,
        snapshot: &TypeArchiveSnapshotId,
    ) -> Array<QualifiedName> {
        let mut count = 0;
        let result = unsafe {
            BNGetTypeArchiveTypeNames(
                self.handle.as_ptr(),
                snapshot.0.as_ptr() as *const c_char,
                &mut count,
            )
        };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Get a list of all types' names and ids in the archive at the latest snapshot
    pub fn get_type_names_and_ids(&self) -> (Array<QualifiedName>, Array<BnString>) {
        self.get_type_names_and_ids_from_snapshot(&TypeArchiveSnapshotId::unset())
    }

    /// Get a list of all types' names and ids in the archive at a specific snapshot
    ///
    /// * `snapshot` - Snapshot id to search for types
    pub fn get_type_names_and_ids_from_snapshot(
        &self,
        snapshot: &TypeArchiveSnapshotId,
    ) -> (Array<QualifiedName>, Array<BnString>) {
        let mut count = 0;
        let mut names = std::ptr::null_mut();
        let mut ids = std::ptr::null_mut();
        let result = unsafe {
            BNGetTypeArchiveTypeNamesAndIds(
                self.handle.as_ptr(),
                snapshot.0.as_ptr() as *const c_char,
                &mut names,
                &mut ids,
                &mut count,
            )
        };
        assert!(result);
        (unsafe { Array::new(names, count, ()) }, unsafe {
            Array::new(ids, count, ())
        })
    }

    /// Get all types a given type references directly
    ///
    /// * `id` - Source type id
    pub fn get_outgoing_direct_references<I: BnStrCompatible>(&self, id: I) -> Array<BnString> {
        self.get_outgoing_direct_references_from_snapshot(id, &TypeArchiveSnapshotId::unset())
    }

    /// Get all types a given type references directly
    ///
    /// * `id` - Source type id
    /// * `snapshot` - Snapshot id to search for types
    pub fn get_outgoing_direct_references_from_snapshot<I: BnStrCompatible>(
        &self,
        id: I,
        snapshot: &TypeArchiveSnapshotId,
    ) -> Array<BnString> {
        let id = id.into_bytes_with_nul();
        let mut count = 0;
        let result = unsafe {
            BNGetTypeArchiveOutgoingDirectTypeReferences(
                self.handle.as_ptr(),
                id.as_ref().as_ptr() as *const c_char,
                snapshot.0.as_ptr() as *const c_char,
                &mut count,
            )
        };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Get all types a given type references, and any types that the referenced types reference
    ///
    /// * `id` - Source type id
    pub fn get_outgoing_recursive_references<I: BnStrCompatible>(&self, id: I) -> Array<BnString> {
        self.get_outgoing_recursive_references_from_snapshot(id, &TypeArchiveSnapshotId::unset())
    }

    /// Get all types a given type references, and any types that the referenced types reference
    ///
    /// * `id` - Source type id
    /// * `snapshot` - Snapshot id to search for types
    pub fn get_outgoing_recursive_references_from_snapshot<I: BnStrCompatible>(
        &self,
        id: I,
        snapshot: &TypeArchiveSnapshotId,
    ) -> Array<BnString> {
        let id = id.into_bytes_with_nul();
        let mut count = 0;
        let result = unsafe {
            BNGetTypeArchiveOutgoingRecursiveTypeReferences(
                self.handle.as_ptr(),
                id.as_ref().as_ptr() as *const c_char,
                snapshot.0.as_ptr() as *const c_char,
                &mut count,
            )
        };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Get all types that reference a given type
    ///
    /// * `id` - Target type id
    pub fn get_incoming_direct_references<I: BnStrCompatible>(&self, id: I) -> Array<BnString> {
        self.get_incoming_direct_references_with_snapshot(id, &TypeArchiveSnapshotId::unset())
    }

    /// Get all types that reference a given type
    ///
    /// * `id` - Target type id
    /// * `snapshot` - Snapshot id to search for types
    pub fn get_incoming_direct_references_with_snapshot<I: BnStrCompatible>(
        &self,
        id: I,
        snapshot: &TypeArchiveSnapshotId,
    ) -> Array<BnString> {
        let id = id.into_bytes_with_nul();
        let mut count = 0;
        let result = unsafe {
            BNGetTypeArchiveIncomingDirectTypeReferences(
                self.handle.as_ptr(),
                id.as_ref().as_ptr() as *const c_char,
                snapshot.0.as_ptr() as *const c_char,
                &mut count,
            )
        };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Get all types that reference a given type, and all types that reference them, recursively
    ///
    /// * `id` - Target type id
    pub fn get_incoming_recursive_references<I: BnStrCompatible>(&self, id: I) -> Array<BnString> {
        self.get_incoming_recursive_references_with_snapshot(id, &TypeArchiveSnapshotId::unset())
    }

    /// Get all types that reference a given type, and all types that reference them, recursively
    ///
    /// * `id` - Target type id
    /// * `snapshot` - Snapshot id to search for types, or empty string to search the latest snapshot
    pub fn get_incoming_recursive_references_with_snapshot<I: BnStrCompatible>(
        &self,
        id: I,
        snapshot: &TypeArchiveSnapshotId,
    ) -> Array<BnString> {
        let id = id.into_bytes_with_nul();
        let mut count = 0;
        let result = unsafe {
            BNGetTypeArchiveIncomingRecursiveTypeReferences(
                self.handle.as_ptr(),
                id.as_ref().as_ptr() as *const c_char,
                snapshot.0.as_ptr() as *const c_char,
                &mut count,
            )
        };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Look up a metadata entry in the archive
    pub fn query_metadata<S: BnStrCompatible>(&self, key: S) -> Option<Ref<Metadata>> {
        let key = key.into_bytes_with_nul();
        let result = unsafe {
            BNTypeArchiveQueryMetadata(self.handle.as_ptr(), key.as_ref().as_ptr() as *const c_char)
        };
        (!result.is_null()).then(|| unsafe { Metadata::ref_from_raw(result) })
    }

    /// Store a key/value pair in the archive's metadata storage
    ///
    /// * `key` - key value to associate the Metadata object with
    /// * `md` - object to store.
    pub fn store_metadata<S: BnStrCompatible>(&self, key: S, md: &Metadata) {
        let key = key.into_bytes_with_nul();
        let result = unsafe {
            BNTypeArchiveStoreMetadata(
                self.handle.as_ptr(),
                key.as_ref().as_ptr() as *const c_char,
                md.handle,
            )
        };
        assert!(result);
    }

    /// Delete a given metadata entry in the archive from the `key`
    pub fn remove_metadata<S: BnStrCompatible>(&self, key: S) -> bool {
        let key = key.into_bytes_with_nul();
        unsafe {
            BNTypeArchiveRemoveMetadata(
                self.handle.as_ptr(),
                key.as_ref().as_ptr() as *const c_char,
            )
        }
    }

    /// Turn a given `snapshot` id into a data stream
    pub fn serialize_snapshot<S: BnStrCompatible>(
        &self,
        snapshot: &TypeArchiveSnapshotId,
    ) -> DataBuffer {
        let result = unsafe {
            BNTypeArchiveSerializeSnapshot(
                self.handle.as_ptr(),
                snapshot.0.as_ptr() as *const c_char,
            )
        };
        assert!(!result.is_null());
        DataBuffer::from_raw(result)
    }

    /// Take a serialized snapshot `data` stream and create a new snapshot from it
    pub fn deserialize_snapshot(&self, data: &DataBuffer) -> TypeArchiveSnapshotId {
        let result =
            unsafe { BNTypeArchiveDeserializeSnapshot(self.handle.as_ptr(), data.as_raw()) };
        assert!(!result.is_null());
        TypeArchiveSnapshotId(unsafe { BnString::from_raw(result) }.to_string())
    }

    /// Register a notification listener
    pub fn register_notification_callback<T: TypeArchiveNotificationCallback>(
        &self,
        callback: T,
    ) -> TypeArchiveCallbackHandle<T> {
        // SAFETY free on [TypeArchiveCallbackHandle::Drop]
        let callback = Box::leak(Box::new(callback));
        let mut notification = BNTypeArchiveNotification {
            context: callback as *mut T as *mut c_void,
            typeAdded: Some(cb_type_added::<T>),
            typeUpdated: Some(cb_type_updated::<T>),
            typeRenamed: Some(cb_type_renamed::<T>),
            typeDeleted: Some(cb_type_deleted::<T>),
        };
        unsafe { BNRegisterTypeArchiveNotification(self.handle.as_ptr(), &mut notification) }
        TypeArchiveCallbackHandle {
            callback,
            type_archive: self.to_owned(),
        }
    }

    // NOTE NotificationClosure is left private, there is no need for the user
    // to know or use it.
    #[allow(private_interfaces)]
    pub fn register_notification_closure<A, U, R, D>(
        &self,
        type_added: A,
        type_updated: U,
        type_renamed: R,
        type_deleted: D,
    ) -> TypeArchiveCallbackHandle<NotificationClosure<A, U, R, D>>
    where
        A: FnMut(&TypeArchive, &str, &Type),
        U: FnMut(&TypeArchive, &str, &Type, &Type),
        R: FnMut(&TypeArchive, &str, &QualifiedName, &QualifiedName),
        D: FnMut(&TypeArchive, &str, &Type),
    {
        self.register_notification_callback(NotificationClosure {
            fun_type_added: type_added,
            fun_type_updated: type_updated,
            fun_type_renamed: type_renamed,
            fun_type_deleted: type_deleted,
        })
    }

    /// Close a type archive, disconnecting it from any active views and closing
    /// any open file handles
    pub fn close(&self) {
        unsafe { BNCloseTypeArchive(self.handle.as_ptr()) }
    }

    // TODO: Make this AsRef<Path>?
    /// Determine if `file` is a Type Archive
    pub fn is_type_archive<P: BnStrCompatible>(file: P) -> bool {
        let file = file.into_bytes_with_nul();
        unsafe { BNIsTypeArchive(file.as_ref().as_ptr() as *const c_char) }
    }

    ///// Get the TypeContainer interface for this Type Archive, presenting types
    ///// at the current snapshot in the archive.
    pub fn type_container(&self) -> TypeContainer {
        let result = unsafe { BNGetTypeArchiveTypeContainer(self.handle.as_ptr()) };
        unsafe { TypeContainer::from_raw(NonNull::new(result).unwrap()) }
    }

    /// Do some function in a transaction making a new snapshot whose id is passed to func. If func throws,
    /// the transaction will be rolled back and the snapshot will not be created.
    ///
    /// * `func` - Function to call
    /// * `parents` - Parent snapshot ids
    ///
    /// Returns Created snapshot id
    pub fn new_snapshot_transaction<P, F>(
        &self,
        mut function: F,
        parents: &[TypeArchiveSnapshotId],
    ) -> TypeArchiveSnapshotId
    where
        P: BnStrCompatible,
        F: FnMut(&TypeArchiveSnapshotId) -> bool,
    {
        unsafe extern "C" fn cb_callback<F: FnMut(&TypeArchiveSnapshotId) -> bool>(
            ctxt: *mut c_void,
            id: *const c_char,
        ) -> bool {
            let fun: &mut F = &mut *(ctxt as *mut F);
            let id_str = raw_to_string(id).unwrap();
            fun(&TypeArchiveSnapshotId(id_str))
        }

        // SAFETY TypeArchiveSnapshotId and `*const c_char` are transparent
        let parents_raw = parents.as_ptr() as *const *const c_char;

        let result = unsafe {
            BNTypeArchiveNewSnapshotTransaction(
                self.handle.as_ptr(),
                Some(cb_callback::<F>),
                &mut function as *mut F as *mut c_void,
                parents_raw,
                parents.len(),
            )
        };
        assert!(!result.is_null());
        let id_str = unsafe { BnString::from_raw(result) };
        TypeArchiveSnapshotId(id_str.to_string())
    }

    /// Merge two snapshots in the archive to produce a new snapshot
    ///
    /// * `base_snapshot` - Common ancestor of snapshots
    /// * `first_snapshot` - First snapshot to merge
    /// * `second_snapshot` - Second snapshot to merge
    /// * `merge_conflicts` - List of all conflicting types, id <-> target snapshot
    /// * `progress` - Function to call for progress updates
    ///
    /// Returns Snapshot id, if merge was successful, otherwise the List of
    /// conflicting type ids
    pub fn merge_snapshots<B, F, S, M, MI, MK>(
        &self,
        base_snapshot: B,
        first_snapshot: F,
        second_snapshot: S,
        merge_conflicts: M,
    ) -> Result<BnString, Array<BnString>>
    where
        B: BnStrCompatible,
        F: BnStrCompatible,
        S: BnStrCompatible,
        M: IntoIterator<Item = (MI, MK)>,
        MI: BnStrCompatible,
        MK: BnStrCompatible,
    {
        self.merge_snapshots_with_progress(
            base_snapshot,
            first_snapshot,
            second_snapshot,
            merge_conflicts,
            NoProgressCallback,
        )
    }

    /// Merge two snapshots in the archive to produce a new snapshot
    ///
    /// * `base_snapshot` - Common ancestor of snapshots
    /// * `first_snapshot` - First snapshot to merge
    /// * `second_snapshot` - Second snapshot to merge
    /// * `merge_conflicts` - List of all conflicting types, id <-> target snapshot
    /// * `progress` - Function to call for progress updates
    ///
    /// Returns Snapshot id, if merge was successful, otherwise the List of
    /// conflicting type ids
    pub fn merge_snapshots_with_progress<B, F, S, M, MI, MK, P>(
        &self,
        base_snapshot: B,
        first_snapshot: F,
        second_snapshot: S,
        merge_conflicts: M,
        mut progress: P,
    ) -> Result<BnString, Array<BnString>>
    where
        B: BnStrCompatible,
        F: BnStrCompatible,
        S: BnStrCompatible,
        M: IntoIterator<Item = (MI, MK)>,
        MI: BnStrCompatible,
        MK: BnStrCompatible,
        P: ProgressCallback,
    {
        let base_snapshot = base_snapshot.into_bytes_with_nul();
        let first_snapshot = first_snapshot.into_bytes_with_nul();
        let second_snapshot = second_snapshot.into_bytes_with_nul();
        let (merge_keys, merge_values): (Vec<BnString>, Vec<BnString>) = merge_conflicts
            .into_iter()
            .map(|(k, v)| (BnString::new(k), BnString::new(v)))
            .unzip();
        // SAFETY BnString and `*const c_char` are transparent
        let merge_keys_raw = merge_keys.as_ptr() as *const *const c_char;
        let merge_values_raw = merge_values.as_ptr() as *const *const c_char;

        let mut conflicts_errors = std::ptr::null_mut();
        let mut conflicts_errors_count = 0;

        let mut result = std::ptr::null_mut();

        let success = unsafe {
            BNTypeArchiveMergeSnapshots(
                self.handle.as_ptr(),
                base_snapshot.as_ref().as_ptr() as *const c_char,
                first_snapshot.as_ref().as_ptr() as *const c_char,
                second_snapshot.as_ref().as_ptr() as *const c_char,
                merge_keys_raw,
                merge_values_raw,
                merge_keys.len(),
                &mut conflicts_errors,
                &mut conflicts_errors_count,
                &mut result,
                Some(P::cb_progress_callback),
                &mut progress as *mut P as *mut c_void,
            )
        };

        if success {
            assert!(!result.is_null());
            Ok(unsafe { BnString::from_raw(result) })
        } else {
            assert!(!conflicts_errors.is_null());
            Err(unsafe { Array::new(conflicts_errors, conflicts_errors_count, ()) })
        }
    }
}

impl ToOwned for TypeArchive {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for TypeArchive {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: NonNull::new(BNNewTypeArchiveReference(handle.handle.as_ptr())).unwrap(),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeTypeArchiveReference(handle.handle.as_ptr());
    }
}

impl PartialEq for TypeArchive {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}
impl Eq for TypeArchive {}

impl Hash for TypeArchive {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        (self.handle.as_ptr() as usize).hash(state);
    }
}

impl Debug for TypeArchive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TypeArchive")
            .field("id", &self.id())
            .field("path", &self.path())
            .field("current_snapshot_id", &self.current_snapshot_id())
            .field("platform", &self.platform())
            .finish()
    }
}

impl CoreArrayProvider for TypeArchive {
    type Raw = *mut BNTypeArchive;
    type Context = ();
    type Wrapped<'a> = Guard<'a, TypeArchive>;
}

unsafe impl CoreArrayProviderInner for TypeArchive {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeTypeArchiveList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        let raw_ptr = NonNull::new(*raw).unwrap();
        Guard::new(Self::from_raw(raw_ptr), context)
    }
}

pub struct TypeArchiveCallbackHandle<T: TypeArchiveNotificationCallback> {
    callback: *mut T,
    type_archive: Ref<TypeArchive>,
}

impl<T: TypeArchiveNotificationCallback> Drop for TypeArchiveCallbackHandle<T> {
    fn drop(&mut self) {
        let mut notification = BNTypeArchiveNotification {
            context: self.callback as *mut c_void,
            typeAdded: Some(cb_type_added::<T>),
            typeUpdated: Some(cb_type_updated::<T>),
            typeRenamed: Some(cb_type_renamed::<T>),
            typeDeleted: Some(cb_type_deleted::<T>),
        };
        // unregister the notification callback
        unsafe {
            BNUnregisterTypeArchiveNotification(
                self.type_archive.handle.as_ptr(),
                &mut notification,
            )
        }
        // free the context created at [TypeArchive::register_notification_callback]
        drop(unsafe { Box::from_raw(self.callback) });
    }
}

pub trait TypeArchiveNotificationCallback {
    /// Called when a type is added to the archive
    ///
    /// * `archive` - Source Type archive
    /// * `id` - Id of type added
    /// * `definition` - Definition of type
    fn type_added(&mut self, _archive: &TypeArchive, _id: &str, _definition: &Type) {}

    /// Called when a type in the archive is updated to a new definition
    ///
    /// * `archive` - Source Type archive
    /// * `id` - Id of type
    /// * `old_definition` - Previous definition
    /// * `new_definition` - Current definition
    fn type_updated(
        &mut self,
        _archive: &TypeArchive,
        _id: &str,
        _old_definition: &Type,
        _new_definition: &Type,
    ) {
    }

    /// Called when a type in the archive is renamed
    ///
    /// * `archive` - Source Type archive
    /// * `id` - Type id
    /// * `old_name` - Previous name
    /// * `new_name` - Current name
    fn type_renamed(
        &mut self,
        _archive: &TypeArchive,
        _id: &str,
        _old_name: &QualifiedName,
        _new_name: &QualifiedName,
    ) {
    }

    /// Called when a type in the archive is deleted from the archive
    ///
    /// * `archive` - Source Type archive
    /// * `id` - Id of type deleted
    /// * `definition` - Definition of type deleted
    fn type_deleted(&mut self, _archive: &TypeArchive, _id: &str, _definition: &Type) {}
}

struct NotificationClosure<A, U, R, D>
where
    A: FnMut(&TypeArchive, &str, &Type),
    U: FnMut(&TypeArchive, &str, &Type, &Type),
    R: FnMut(&TypeArchive, &str, &QualifiedName, &QualifiedName),
    D: FnMut(&TypeArchive, &str, &Type),
{
    fun_type_added: A,
    fun_type_updated: U,
    fun_type_renamed: R,
    fun_type_deleted: D,
}

impl<A, U, R, D> TypeArchiveNotificationCallback for NotificationClosure<A, U, R, D>
where
    A: FnMut(&TypeArchive, &str, &Type),
    U: FnMut(&TypeArchive, &str, &Type, &Type),
    R: FnMut(&TypeArchive, &str, &QualifiedName, &QualifiedName),
    D: FnMut(&TypeArchive, &str, &Type),
{
    fn type_added(&mut self, archive: &TypeArchive, id: &str, definition: &Type) {
        (self.fun_type_added)(archive, id, definition)
    }

    fn type_updated(
        &mut self,
        archive: &TypeArchive,
        id: &str,
        old_definition: &Type,
        new_definition: &Type,
    ) {
        (self.fun_type_updated)(archive, id, old_definition, new_definition)
    }

    fn type_renamed(
        &mut self,
        archive: &TypeArchive,
        id: &str,
        old_name: &QualifiedName,
        new_name: &QualifiedName,
    ) {
        (self.fun_type_renamed)(archive, id, old_name, new_name)
    }

    fn type_deleted(&mut self, archive: &TypeArchive, id: &str, definition: &Type) {
        (self.fun_type_deleted)(archive, id, definition)
    }
}

unsafe extern "C" fn cb_type_added<T: TypeArchiveNotificationCallback>(
    ctxt: *mut ::std::os::raw::c_void,
    archive: *mut BNTypeArchive,
    id: *const ::std::os::raw::c_char,
    definition: *mut BNType,
) {
    let ctxt: &mut T = &mut *(ctxt as *mut T);
    // `archive` is owned by the caller.
    let archive = unsafe { TypeArchive::from_raw(NonNull::new(archive).unwrap()) };
    ctxt.type_added(
        &archive,
        unsafe { CStr::from_ptr(id).to_string_lossy().as_ref() },
        &Type { handle: definition },
    )
}
unsafe extern "C" fn cb_type_updated<T: TypeArchiveNotificationCallback>(
    ctxt: *mut ::std::os::raw::c_void,
    archive: *mut BNTypeArchive,
    id: *const ::std::os::raw::c_char,
    old_definition: *mut BNType,
    new_definition: *mut BNType,
) {
    let ctxt: &mut T = &mut *(ctxt as *mut T);
    // `archive` is owned by the caller.
    let archive = unsafe { TypeArchive::from_raw(NonNull::new(archive).unwrap()) };
    ctxt.type_updated(
        &archive,
        unsafe { CStr::from_ptr(id).to_string_lossy().as_ref() },
        &Type {
            handle: old_definition,
        },
        &Type {
            handle: new_definition,
        },
    )
}
unsafe extern "C" fn cb_type_renamed<T: TypeArchiveNotificationCallback>(
    ctxt: *mut ::std::os::raw::c_void,
    archive: *mut BNTypeArchive,
    id: *const ::std::os::raw::c_char,
    old_name: *const BNQualifiedName,
    new_name: *const BNQualifiedName,
) {
    let ctxt: &mut T = &mut *(ctxt as *mut T);
    // `old_name` is freed by the caller
    let old_name = QualifiedName::from_raw(&*old_name);
    // `new_name` is freed by the caller
    let new_name = QualifiedName::from_raw(&*new_name);
    // `archive` is owned by the caller.
    let archive = unsafe { TypeArchive::from_raw(NonNull::new(archive).unwrap()) };
    ctxt.type_renamed(
        &archive,
        unsafe { CStr::from_ptr(id).to_string_lossy().as_ref() },
        &old_name,
        &new_name,
    )
}
unsafe extern "C" fn cb_type_deleted<T: TypeArchiveNotificationCallback>(
    ctxt: *mut ::std::os::raw::c_void,
    archive: *mut BNTypeArchive,
    id: *const ::std::os::raw::c_char,
    definition: *mut BNType,
) {
    let ctxt: &mut T = &mut *(ctxt as *mut T);
    // `archive` is owned by the caller.
    let archive = unsafe { TypeArchive::from_raw(NonNull::new(archive).unwrap()) };
    ctxt.type_deleted(
        &archive,
        unsafe { CStr::from_ptr(id).to_string_lossy().as_ref() },
        &Type { handle: definition },
    )
}

#[repr(transparent)]
pub struct TypeArchiveMergeConflict {
    handle: NonNull<BNTypeArchiveMergeConflict>,
}

impl TypeArchiveMergeConflict {
    pub(crate) unsafe fn from_raw(handle: NonNull<BNTypeArchiveMergeConflict>) -> Self {
        Self { handle }
    }

    #[allow(unused)]
    pub(crate) unsafe fn ref_from_raw(handle: NonNull<BNTypeArchiveMergeConflict>) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    pub fn get_type_archive(&self) -> Option<Ref<TypeArchive>> {
        let value = unsafe { BNTypeArchiveMergeConflictGetTypeArchive(self.handle.as_ptr()) };
        NonNull::new(value).map(|handle| unsafe { TypeArchive::ref_from_raw(handle) })
    }

    pub fn type_id(&self) -> BnString {
        let value = unsafe { BNTypeArchiveMergeConflictGetTypeId(self.handle.as_ptr()) };
        assert!(!value.is_null());
        unsafe { BnString::from_raw(value) }
    }

    pub fn base_snapshot_id(&self) -> TypeArchiveSnapshotId {
        let value = unsafe { BNTypeArchiveMergeConflictGetBaseSnapshotId(self.handle.as_ptr()) };
        assert!(!value.is_null());
        let id = unsafe { BnString::from_raw(value) }.to_string();
        TypeArchiveSnapshotId(id)
    }

    pub fn first_snapshot_id(&self) -> TypeArchiveSnapshotId {
        let value = unsafe { BNTypeArchiveMergeConflictGetFirstSnapshotId(self.handle.as_ptr()) };
        assert!(!value.is_null());
        let id = unsafe { BnString::from_raw(value) }.to_string();
        TypeArchiveSnapshotId(id)
    }

    pub fn second_snapshot_id(&self) -> TypeArchiveSnapshotId {
        let value = unsafe { BNTypeArchiveMergeConflictGetSecondSnapshotId(self.handle.as_ptr()) };
        assert!(!value.is_null());
        let id = unsafe { BnString::from_raw(value) }.to_string();
        TypeArchiveSnapshotId(id)
    }

    // TODO: This needs documentation!
    pub fn success<S: BnStrCompatible>(&self, value: S) -> bool {
        let value = value.into_bytes_with_nul();
        unsafe {
            BNTypeArchiveMergeConflictSuccess(
                self.handle.as_ptr(),
                value.as_ref().as_ptr() as *const c_char,
            )
        }
    }
}

impl Debug for TypeArchiveMergeConflict {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TypeArchiveMergeConflict")
            .field("type_id", &self.type_id())
            .field("base_snapshot_id", &self.base_snapshot_id())
            .field("first_snapshot_id", &self.first_snapshot_id())
            .field("second_snapshot_id", &self.second_snapshot_id())
            .finish()
    }
}

impl ToOwned for TypeArchiveMergeConflict {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for TypeArchiveMergeConflict {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: NonNull::new(BNNewTypeArchiveMergeConflictReference(
                handle.handle.as_ptr(),
            ))
            .unwrap(),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeTypeArchiveMergeConflict(handle.handle.as_ptr());
    }
}

impl CoreArrayProvider for TypeArchiveMergeConflict {
    type Raw = *mut BNTypeArchiveMergeConflict;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Self>;
}

unsafe impl CoreArrayProviderInner for TypeArchiveMergeConflict {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeTypeArchiveMergeConflictList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        let raw_ptr = NonNull::new(*raw).unwrap();
        Guard::new(Self::from_raw(raw_ptr), context)
    }
}
