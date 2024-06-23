use core::{ffi, mem, ptr};

use binaryninjacore_sys::*;

use crate::databuffer::DataBuffer;
use crate::metadata::Metadata;
use crate::platform::Platform;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Ref};
use crate::string::{BnStrCompatible, BnString};
use crate::types::{QualifiedName, QualifiedNameAndType, QualifiedNameTypeAndId, Type};

/// Type Archives are a collection of types which can be shared between different analysis
/// sessions and are backed by a database file on disk. Their types can be modified, and
/// a history of previous versions of types is stored in snapshots in the archive.
#[repr(transparent)]
pub struct TypeArchive {
    handle: ptr::NonNull<BNTypeArchive>,
}

impl Drop for TypeArchive {
    fn drop(&mut self) {
        unsafe { BNFreeTypeArchiveReference(self.as_raw()) }
    }
}

impl Clone for TypeArchive {
    fn clone(&self) -> Self {
        unsafe {
            Self::from_raw(ptr::NonNull::new(BNNewTypeArchiveReference(self.as_raw())).unwrap())
        }
    }
}

impl PartialEq for TypeArchive {
    fn eq(&self, other: &Self) -> bool {
        self.id() == other.id()
    }
}
impl Eq for TypeArchive {}

impl core::hash::Hash for TypeArchive {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        (self.handle.as_ptr() as usize).hash(state);
    }
}

impl core::fmt::Debug for TypeArchive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let path = self.path().map(|x| x.to_string());
        f.debug_struct("TypeArchive").field("path", &path).finish()
    }
}

impl TypeArchive {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNTypeArchive>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &*mut BNTypeArchive) -> &Self {
        assert!(!handle.is_null());
        mem::transmute(handle)
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNTypeArchive {
        &mut *self.handle.as_ptr()
    }

    /// Open the Type Archive at the given path, if it exists.
    pub fn open<S: BnStrCompatible>(path: S) -> Option<TypeArchive> {
        let path = path.into_bytes_with_nul();
        let handle = unsafe { BNOpenTypeArchive(path.as_ref().as_ptr() as *const ffi::c_char) };
        ptr::NonNull::new(handle).map(|handle| unsafe { TypeArchive::from_raw(handle) })
    }

    /// Create a Type Archive at the given path, returning None if it could not be created.
    pub fn create<S: BnStrCompatible>(path: S, platform: &Platform) -> Option<TypeArchive> {
        let path = path.into_bytes_with_nul();
        let handle = unsafe {
            BNCreateTypeArchive(
                path.as_ref().as_ptr() as *const ffi::c_char,
                platform.handle,
            )
        };
        ptr::NonNull::new(handle).map(|handle| unsafe { TypeArchive::from_raw(handle) })
    }

    /// Create a Type Archive at the given path and id, returning None if it could not be created.
    pub fn create_with_id<P: BnStrCompatible, I: BnStrCompatible>(
        path: P,
        id: I,
        platform: &Platform,
    ) -> Option<TypeArchive> {
        let path = path.into_bytes_with_nul();
        let id = id.into_bytes_with_nul();
        let handle = unsafe {
            BNCreateTypeArchiveWithId(
                path.as_ref().as_ptr() as *const ffi::c_char,
                platform.handle,
                id.as_ref().as_ptr() as *const ffi::c_char,
            )
        };
        ptr::NonNull::new(handle).map(|handle| unsafe { TypeArchive::from_raw(handle) })
    }

    /// Get a reference to the Type Archive with the known id, if one exists.
    pub fn lookup_by_id<S: BnStrCompatible>(id: S) -> Option<TypeArchive> {
        let id = id.into_bytes_with_nul();
        let handle = unsafe { BNLookupTypeArchiveById(id.as_ref().as_ptr() as *const ffi::c_char) };
        ptr::NonNull::new(handle).map(|handle| unsafe { TypeArchive::from_raw(handle) })
    }

    /// Get the path to the Type Archive's file
    pub fn path(&self) -> Option<BnString> {
        let result = unsafe { BNGetTypeArchivePath(self.as_raw()) };
        (!result.is_null()).then(|| unsafe { BnString::from_raw(result) })
    }

    /// Get the guid for a Type Archive
    pub fn id(&self) -> Option<BnString> {
        let result = unsafe { BNGetTypeArchiveId(self.as_raw()) };
        (!result.is_null()).then(|| unsafe { BnString::from_raw(result) })
    }

    /// Get the associated Platform for a Type Archive
    pub fn platform(&self) -> Ref<Platform> {
        let result = unsafe { BNGetTypeArchivePlatform(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { Platform::ref_from_raw(result) }
    }

    /// Get the id of the current snapshot in the type archive
    pub fn current_snapshot_id(&self) -> BnString {
        let result = unsafe { BNGetTypeArchiveCurrentSnapshotId(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Revert the type archive's current snapshot to the given snapshot
    pub fn set_current_snapshot_id<S: BnStrCompatible>(&self, id: S) {
        let id = id.into_bytes_with_nul();
        unsafe {
            BNSetTypeArchiveCurrentSnapshot(
                self.as_raw(),
                id.as_ref().as_ptr() as *const ffi::c_char,
            )
        }
    }

    /// Get a list of every snapshot's id
    pub fn all_snapshot_ids(&self) -> Array<BnString> {
        let mut count = 0;
        let result = unsafe { BNGetTypeArchiveAllSnapshotIds(self.as_raw(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Get the ids of the parents to the given snapshot
    pub fn get_snapshot_parent_ids<S: BnStrCompatible>(
        &self,
        snapshot: S,
    ) -> Option<Array<BnString>> {
        let snapshot = snapshot.into_bytes_with_nul();
        let mut count = 0;
        let result = unsafe {
            BNGetTypeArchiveSnapshotParentIds(
                self.as_raw(),
                snapshot.as_ref().as_ptr() as *const ffi::c_char,
                &mut count,
            )
        };
        (!result.is_null()).then(|| unsafe { Array::new(result, count, ()) })
    }

    /// Get the ids of the children to the given snapshot
    pub fn get_snapshot_child_ids<S: BnStrCompatible>(
        &self,
        snapshot: S,
    ) -> Option<Array<BnString>> {
        let snapshot = snapshot.into_bytes_with_nul();
        let mut count = 0;
        let result = unsafe {
            BNGetTypeArchiveSnapshotChildIds(
                self.as_raw(),
                snapshot.as_ref().as_ptr() as *const ffi::c_char,
                &mut count,
            )
        };
        (!result.is_null()).then(|| unsafe { Array::new(result, count, ()) })
    }

    /// Add named types to the type archive. Type must have all dependant named types added
    /// prior to being added, or this function will fail.
    /// If the type already exists, it will be overwritten.
    ///
    /// * `name` - Name of new type
    /// * `type` - Definition of new type
    pub fn add_type(&self, name: &QualifiedNameAndType) {
        self.add_types(core::slice::from_ref(name))
    }

    /// Add named types to the type archive. Types must have all dependant named
    /// types prior to being added, or included in the list, or this function will fail.
    /// Types already existing with any added names will be overwritten.
    ///
    /// * `new_types` - Names and definitions of new types
    pub fn add_types(&self, new_types: &[QualifiedNameAndType]) {
        // SAFETY BNQualifiedNameAndType and QualifiedNameAndType are transparent
        let new_types_raw: &[BNQualifiedNameAndType] = unsafe { mem::transmute(new_types) };
        let result = unsafe {
            BNAddTypeArchiveTypes(self.as_raw(), new_types_raw.as_ptr(), new_types.len())
        };
        assert!(result);
    }

    /// Change the name of an existing type in the type archive.
    ///
    /// * `old_name` - Old type name in archive
    /// * `new_name` - New type name
    pub fn rename_type(&self, old_name: &QualifiedName, new_name: &QualifiedNameAndType) {
        let id = self
            .get_type_id(old_name, self.current_snapshot_id())
            .unwrap();
        return self.rename_type_by_id(id, new_name.name());
    }

    /// Change the name of an existing type in the type archive.
    ///
    /// * `id` - Old id of type in archive
    /// * `new_name` - New type name
    pub fn rename_type_by_id<S: BnStrCompatible>(&self, id: S, new_name: &QualifiedName) {
        let id = id.into_bytes_with_nul();
        let result = unsafe {
            BNRenameTypeArchiveType(
                self.as_raw(),
                id.as_ref().as_ptr() as *const ffi::c_char,
                &new_name.0,
            )
        };
        assert!(result);
    }

    /// Delete an existing type in the type archive.
    pub fn delete_type(&self, name: &QualifiedName) {
        let id = self.get_type_id(name, self.current_snapshot_id());
        let Some(id) = id else {
            panic!("Unknown type {}", name.string())
        };
        self.delete_type_by_id(id);
    }

    /// Delete an existing type in the type archive.
    pub fn delete_type_by_id<S: BnStrCompatible>(&self, id: S) {
        let id = id.into_bytes_with_nul();
        let result = unsafe {
            BNDeleteTypeArchiveType(self.as_raw(), id.as_ref().as_ptr() as *const ffi::c_char)
        };
        assert!(result);
    }

    /// Retrieve a stored type in the archive
    ///
    /// * `name` - Type name
    /// * `snapshot` - Snapshot id to search for types
    pub fn get_type_by_name<S: BnStrCompatible>(
        &self,
        name: &QualifiedName,
        snapshot: S,
    ) -> Option<Ref<Type>> {
        let snapshot = snapshot.into_bytes_with_nul();
        let result = unsafe {
            BNGetTypeArchiveTypeByName(
                self.as_raw(),
                &name.0,
                snapshot.as_ref().as_ptr() as *const ffi::c_char,
            )
        };
        (!result.is_null()).then(|| unsafe { Type::ref_from_raw(result) })
    }

    /// Retrieve a stored type in the archive by id
    ///
    /// * `id` - Type id
    /// * `snapshot` - Snapshot id to search for types
    pub fn get_type_by_id<I: BnStrCompatible, S: BnStrCompatible>(
        &self,
        id: I,
        snapshot: S,
    ) -> Option<Ref<Type>> {
        let snapshot = snapshot.into_bytes_with_nul();
        let id = id.into_bytes_with_nul();
        let result = unsafe {
            BNGetTypeArchiveTypeById(
                self.as_raw(),
                id.as_ref().as_ptr() as *const ffi::c_char,
                snapshot.as_ref().as_ptr() as *const ffi::c_char,
            )
        };
        (!result.is_null()).then(|| unsafe { Type::ref_from_raw(result) })
    }

    /// Retrieve a type's name by its id
    ///
    /// * `id` - Type id
    /// * `snapshot` - Snapshot id to search for types
    pub fn get_type_name_by_id<I: BnStrCompatible, S: BnStrCompatible>(
        &self,
        id: I,
        snapshot: S,
    ) -> QualifiedName {
        let snapshot = snapshot.into_bytes_with_nul();
        let id = id.into_bytes_with_nul();
        let result = unsafe {
            BNGetTypeArchiveTypeName(
                self.as_raw(),
                id.as_ref().as_ptr() as *const ffi::c_char,
                snapshot.as_ref().as_ptr() as *const ffi::c_char,
            )
        };
        QualifiedName(result)
    }

    /// Retrieve a type's id by its name
    ///
    /// * `name` - Type name
    /// * `snapshot` - Snapshot id to search for types
    pub fn get_type_id<S: BnStrCompatible>(
        &self,
        name: &QualifiedName,
        snapshot: S,
    ) -> Option<BnString> {
        let snapshot = snapshot.into_bytes_with_nul();
        let result = unsafe {
            BNGetTypeArchiveTypeId(
                self.as_raw(),
                &name.0,
                snapshot.as_ref().as_ptr() as *const ffi::c_char,
            )
        };
        (!result.is_null()).then(|| unsafe { BnString::from_raw(result) })
    }

    /// Retrieve all stored types in the archive at a snapshot
    ///
    /// * `snapshot` - Snapshot id to search for types
    pub fn get_types_and_ids<S: BnStrCompatible>(
        &self,
        snapshot: S,
    ) -> Array<QualifiedNameTypeAndId> {
        let snapshot = snapshot.into_bytes_with_nul();
        let mut count = 0;
        let result = unsafe {
            BNGetTypeArchiveTypes(
                self.as_raw(),
                snapshot.as_ref().as_ptr() as *const ffi::c_char,
                &mut count,
            )
        };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Get a list of all types' ids in the archive at a snapshot
    ///
    /// * `snapshot` - Snapshot id to search for types
    pub fn get_type_ids<S: BnStrCompatible>(&self, snapshot: S) -> Array<BnString> {
        let snapshot = snapshot.into_bytes_with_nul();
        let mut count = 0;
        let result = unsafe {
            BNGetTypeArchiveTypeIds(
                self.as_raw(),
                snapshot.as_ref().as_ptr() as *const ffi::c_char,
                &mut count,
            )
        };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Get a list of all types' names in the archive at a snapshot
    ///
    /// * `snapshot` - Snapshot id to search for types
    pub fn get_type_names<S: BnStrCompatible>(&self, snapshot: S) -> Array<QualifiedName> {
        let snapshot = snapshot.into_bytes_with_nul();
        let mut count = 0;
        let result = unsafe {
            BNGetTypeArchiveTypeNames(
                self.as_raw(),
                snapshot.as_ref().as_ptr() as *const ffi::c_char,
                &mut count,
            )
        };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Get a list of all types' names and ids in the archive at a current snapshot

    /// * `snapshot` - Snapshot id to search for types
    pub fn get_type_names_and_ids<S: BnStrCompatible>(
        &self,
        snapshot: S,
    ) -> (Array<QualifiedName>, Array<BnString>) {
        let snapshot = snapshot.into_bytes_with_nul();
        let mut count = 0;
        let mut names = ptr::null_mut();
        let mut ids = ptr::null_mut();
        let result = unsafe {
            BNGetTypeArchiveTypeNamesAndIds(
                self.as_raw(),
                snapshot.as_ref().as_ptr() as *const ffi::c_char,
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
    /// * `snapshot` - Snapshot id to search for types
    pub fn get_outgoing_direct_references<I: BnStrCompatible, S: BnStrCompatible>(
        &self,
        id: I,
        snapshot: S,
    ) -> Array<BnString> {
        let snapshot = snapshot.into_bytes_with_nul();
        let id = id.into_bytes_with_nul();
        let mut count = 0;
        let result = unsafe {
            BNGetTypeArchiveOutgoingDirectTypeReferences(
                self.as_raw(),
                id.as_ref().as_ptr() as *const ffi::c_char,
                snapshot.as_ref().as_ptr() as *const ffi::c_char,
                &mut count,
            )
        };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Get all types a given type references, and any types that the referenced types reference
    ///
    /// :param id: Source type id
    /// :param snapshot: Snapshot id to search for types
    pub fn get_outgoing_recursive_references<I: BnStrCompatible, S: BnStrCompatible>(
        &self,
        id: I,
        snapshot: S,
    ) -> Array<BnString> {
        let snapshot = snapshot.into_bytes_with_nul();
        let id = id.into_bytes_with_nul();
        let mut count = 0;
        let result = unsafe {
            BNGetTypeArchiveOutgoingRecursiveTypeReferences(
                self.as_raw(),
                id.as_ref().as_ptr() as *const ffi::c_char,
                snapshot.as_ref().as_ptr() as *const ffi::c_char,
                &mut count,
            )
        };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Get all types that reference a given type
    ///
    /// * `id` - Target type id
    /// * `snapshot` - Snapshot id to search for types
    pub fn get_incoming_direct_references<I: BnStrCompatible, S: BnStrCompatible>(
        &self,
        id: I,
        snapshot: S,
    ) -> Array<BnString> {
        let snapshot = snapshot.into_bytes_with_nul();
        let id = id.into_bytes_with_nul();
        let mut count = 0;
        let result = unsafe {
            BNGetTypeArchiveIncomingDirectTypeReferences(
                self.as_raw(),
                id.as_ref().as_ptr() as *const ffi::c_char,
                snapshot.as_ref().as_ptr() as *const ffi::c_char,
                &mut count,
            )
        };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Get all types that reference a given type, and all types that reference them, recursively
    ///
    /// * `id` - Target type id
    /// * `snapshot` - Snapshot id to search for types, or empty string to search the latest snapshot
    pub fn get_incoming_recursive_references<I: BnStrCompatible, S: BnStrCompatible>(
        &self,
        id: I,
        snapshot: S,
    ) -> Array<BnString> {
        let snapshot = snapshot.into_bytes_with_nul();
        let id = id.into_bytes_with_nul();
        let mut count = 0;
        let result = unsafe {
            BNGetTypeArchiveIncomingRecursiveTypeReferences(
                self.as_raw(),
                id.as_ref().as_ptr() as *const ffi::c_char,
                snapshot.as_ref().as_ptr() as *const ffi::c_char,
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
            BNTypeArchiveQueryMetadata(self.as_raw(), key.as_ref().as_ptr() as *const ffi::c_char)
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
                self.as_raw(),
                key.as_ref().as_ptr() as *const ffi::c_char,
                md.handle,
            )
        };
        assert!(result);
    }

    /// Delete a given metadata entry in the archive from the `key`
    pub fn remove_metadata<S: BnStrCompatible>(&self, key: S) -> bool {
        let key = key.into_bytes_with_nul();
        unsafe {
            BNTypeArchiveRemoveMetadata(self.as_raw(), key.as_ref().as_ptr() as *const ffi::c_char)
        }
    }

    /// Turn a given `snapshot` id into a data stream
    pub fn serialize_snapshot<S: BnStrCompatible>(&self, snapshot: S) -> DataBuffer {
        let snapshot = snapshot.into_bytes_with_nul();
        let result = unsafe {
            BNTypeArchiveSerializeSnapshot(
                self.as_raw(),
                snapshot.as_ref().as_ptr() as *const ffi::c_char,
            )
        };
        assert!(!result.is_null());
        DataBuffer::from_raw(result)
    }

    /// Take a serialized snapshot `data` stream and create a new snapshot from it
    pub fn deserialize_snapshot(&self, data: &DataBuffer) -> BnString {
        let result = unsafe { BNTypeArchiveDeserializeSnapshot(self.as_raw(), data.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    /// Register a notification listener
    pub fn register_notification_callback<T: TypeArchiveNotificationCallback>(
        &self,
        callback: T,
    ) -> TypeArchiveCallbackHandle<T> {
        // SAFETY free on [TypeArchiveCallbackHandle::Drop]
        let callback = Box::leak(Box::new(callback));
        let mut notification = BNTypeArchiveNotification {
            context: callback as *mut T as *mut ffi::c_void,
            typeAdded: Some(cb_type_added::<T>),
            typeUpdated: Some(cb_type_updated::<T>),
            typeRenamed: Some(cb_type_renamed::<T>),
            typeDeleted: Some(cb_type_deleted::<T>),
        };
        unsafe { BNRegisterTypeArchiveNotification(self.as_raw(), &mut notification) }
        TypeArchiveCallbackHandle {
            callback,
            type_archive: self.clone(),
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
    pub fn close(self) {
        unsafe { BNCloseTypeArchive(self.as_raw()) }
        // NOTE self must be dropped after, don't make it `&self`
    }

    /// Determine if `file` is a Type Archive
    pub fn is_type_archive<P: BnStrCompatible>(file: P) -> bool {
        let file = file.into_bytes_with_nul();
        unsafe { BNIsTypeArchive(file.as_ref().as_ptr() as *const ffi::c_char) }
    }

    // TODO implement TypeContainer
    ///// Get the TypeContainer interface for this Type Archive, presenting types
    ///// at the current snapshot in the archive.
    //pub fn type_container(&self) -> TypeContainer {
    //    let result = unsafe { BNGetTypeArchiveTypeContainer(self.as_raw()) };
    //    unsafe { TypeContainer::from_raw(ptr::NonNull::new(result).unwrap()) }
    //}

    /// Do some function in a transaction making a new snapshot whose id is passed to func. If func throws,
    /// the transaction will be rolled back and the snapshot will not be created.
    ///
    /// * `func` - Function to call
    /// * `parents` - Parent snapshot ids
    ///
    /// Returns Created snapshot id
    pub fn new_snapshot_transaction<P, F>(&self, mut function: F, parents: &[BnString]) -> BnString
    where
        P: BnStrCompatible,
        F: FnMut(&str) -> bool,
    {
        unsafe extern "C" fn cb_callback<F: FnMut(&str) -> bool>(
            ctxt: *mut ffi::c_void,
            id: *const ffi::c_char,
        ) -> bool {
            let fun: &mut F = &mut *(ctxt as *mut F);
            fun(&ffi::CStr::from_ptr(id).to_string_lossy())
        }

        // SAFETY BnString and `*const ffi::c_char` are transparent
        let parents_raw = parents.as_ptr() as *const *const ffi::c_char;

        let result = unsafe {
            BNTypeArchiveNewSnapshotTransaction(
                self.as_raw(),
                Some(cb_callback::<F>),
                &mut function as *mut F as *mut ffi::c_void,
                parents_raw,
                parents.len(),
            )
        };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
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
    pub fn merge_snapshots<B, F, S, P, M, MI, MK>(
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
        P: FnMut(usize, usize) -> bool,
        M: IntoIterator<Item = (MI, MK)>,
        MI: BnStrCompatible,
        MK: BnStrCompatible,
    {
        unsafe extern "C" fn cb_callback<F: FnMut(usize, usize) -> bool>(
            ctxt: *mut ffi::c_void,
            progress: usize,
            total: usize,
        ) -> bool {
            let ctxt: &mut F = &mut *(ctxt as *mut F);
            ctxt(progress, total)
        }

        let base_snapshot = base_snapshot.into_bytes_with_nul();
        let first_snapshot = first_snapshot.into_bytes_with_nul();
        let second_snapshot = second_snapshot.into_bytes_with_nul();
        let (merge_keys, merge_values): (Vec<BnString>, Vec<BnString>) = merge_conflicts
            .into_iter()
            .map(|(k, v)| (BnString::new(k), BnString::new(v)))
            .unzip();
        // SAFETY BnString and `*const ffi::c_char` are transparent
        let merge_keys_raw = merge_keys.as_ptr() as *const *const ffi::c_char;
        let merge_values_raw = merge_values.as_ptr() as *const *const ffi::c_char;

        let mut conflicts_errors = ptr::null_mut();
        let mut conflicts_errors_count = 0;

        let mut result = ptr::null_mut();

        let success = unsafe {
            BNTypeArchiveMergeSnapshots(
                self.as_raw(),
                base_snapshot.as_ref().as_ptr() as *const ffi::c_char,
                first_snapshot.as_ref().as_ptr() as *const ffi::c_char,
                second_snapshot.as_ref().as_ptr() as *const ffi::c_char,
                merge_keys_raw,
                merge_values_raw,
                merge_keys.len(),
                &mut conflicts_errors,
                &mut conflicts_errors_count,
                &mut result,
                Some(cb_callback::<P>),
                (&mut progress) as *mut P as *mut ffi::c_void,
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

impl CoreArrayProvider for TypeArchive {
    type Raw = *mut BNTypeArchive;
    type Context = ();
    type Wrapped<'a> = &'a TypeArchive;
}

unsafe impl CoreArrayProviderInner for TypeArchive {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeTypeArchiveList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::ref_from_raw(raw)
    }
}

pub struct TypeArchiveCallbackHandle<T: TypeArchiveNotificationCallback> {
    callback: *mut T,
    type_archive: TypeArchive,
}

impl<T: TypeArchiveNotificationCallback> Drop for TypeArchiveCallbackHandle<T> {
    fn drop(&mut self) {
        let mut notification = BNTypeArchiveNotification {
            context: self.callback as *mut ffi::c_void,
            typeAdded: Some(cb_type_added::<T>),
            typeUpdated: Some(cb_type_updated::<T>),
            typeRenamed: Some(cb_type_renamed::<T>),
            typeDeleted: Some(cb_type_deleted::<T>),
        };
        // unregister the notification callback
        unsafe {
            BNUnregisterTypeArchiveNotification(self.type_archive.as_raw(), &mut notification)
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
    ctxt: *mut ffi::c_void,
    archive: *mut BNTypeArchive,
    id: *const ffi::c_char,
    definition: *mut BNType,
) {
    let ctxt: &mut T = &mut *(ctxt as *mut T);
    ctxt.type_added(
        unsafe { TypeArchive::ref_from_raw(&archive) },
        unsafe { ffi::CStr::from_ptr(id).to_string_lossy().as_ref() },
        &Type { handle: definition },
    )
}
unsafe extern "C" fn cb_type_updated<T: TypeArchiveNotificationCallback>(
    ctxt: *mut ffi::c_void,
    archive: *mut BNTypeArchive,
    id: *const ffi::c_char,
    old_definition: *mut BNType,
    new_definition: *mut BNType,
) {
    let ctxt: &mut T = &mut *(ctxt as *mut T);
    ctxt.type_updated(
        unsafe { TypeArchive::ref_from_raw(&archive) },
        unsafe { ffi::CStr::from_ptr(id).to_string_lossy().as_ref() },
        &Type {
            handle: old_definition,
        },
        &Type {
            handle: new_definition,
        },
    )
}
unsafe extern "C" fn cb_type_renamed<T: TypeArchiveNotificationCallback>(
    ctxt: *mut ffi::c_void,
    archive: *mut BNTypeArchive,
    id: *const ffi::c_char,
    old_name: *const BNQualifiedName,
    new_name: *const BNQualifiedName,
) {
    let ctxt: &mut T = &mut *(ctxt as *mut T);
    let old_name = mem::ManuallyDrop::new(QualifiedName(*old_name));
    let new_name = mem::ManuallyDrop::new(QualifiedName(*new_name));
    ctxt.type_renamed(
        unsafe { TypeArchive::ref_from_raw(&archive) },
        unsafe { ffi::CStr::from_ptr(id).to_string_lossy().as_ref() },
        &old_name,
        &new_name,
    )
}
unsafe extern "C" fn cb_type_deleted<T: TypeArchiveNotificationCallback>(
    ctxt: *mut ffi::c_void,
    archive: *mut BNTypeArchive,
    id: *const ffi::c_char,
    definition: *mut BNType,
) {
    let ctxt: &mut T = &mut *(ctxt as *mut T);
    ctxt.type_deleted(
        unsafe { TypeArchive::ref_from_raw(&archive) },
        unsafe { ffi::CStr::from_ptr(id).to_string_lossy().as_ref() },
        &Type { handle: definition },
    )
}
