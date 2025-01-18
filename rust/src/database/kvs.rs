use crate::data_buffer::DataBuffer;
use crate::rc::{Array, Ref, RefCountable};
use crate::string::{BnStrCompatible, BnString};
use binaryninjacore_sys::{
    BNBeginKeyValueStoreNamespace, BNEndKeyValueStoreNamespace, BNFreeKeyValueStore,
    BNGetKeyValueStoreBuffer, BNGetKeyValueStoreDataSize, BNGetKeyValueStoreKeys,
    BNGetKeyValueStoreNamespaceSize, BNGetKeyValueStoreSerializedData, BNGetKeyValueStoreValueSize,
    BNGetKeyValueStoreValueStorageSize, BNIsKeyValueStoreEmpty, BNKeyValueStore,
    BNNewKeyValueStoreReference, BNSetKeyValueStoreBuffer,
};
use std::collections::HashMap;
use std::ffi::c_char;
use std::fmt::Debug;
use std::ptr::NonNull;

#[repr(transparent)]
pub struct KeyValueStore {
    pub(crate) handle: NonNull<BNKeyValueStore>,
}

impl KeyValueStore {
    pub(crate) unsafe fn ref_from_raw(handle: NonNull<BNKeyValueStore>) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    pub fn to_hashmap(&self) -> HashMap<String, DataBuffer> {
        let mut hashmap = HashMap::with_capacity(self.keys().len());
        for key in self.keys().iter() {
            if let Some(value) = self.value(key) {
                hashmap.insert(key.to_string(), value);
            }
        }
        hashmap
    }

    /// Get a list of all keys stored in the kvs
    pub fn keys(&self) -> Array<BnString> {
        let mut count = 0;
        let result = unsafe { BNGetKeyValueStoreKeys(self.handle.as_ptr(), &mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    /// Get the value for a single key
    pub fn value<S: BnStrCompatible>(&self, key: S) -> Option<DataBuffer> {
        let key_raw = key.into_bytes_with_nul();
        let key_ptr = key_raw.as_ref().as_ptr() as *const c_char;
        let result = unsafe { BNGetKeyValueStoreBuffer(self.handle.as_ptr(), key_ptr) };
        NonNull::new(result).map(|_| DataBuffer::from_raw(result))
    }

    /// Set the value for a single key
    pub fn set_value<S: BnStrCompatible>(&self, key: S, value: &DataBuffer) -> bool {
        let key_raw = key.into_bytes_with_nul();
        let key_ptr = key_raw.as_ref().as_ptr() as *const c_char;
        unsafe { BNSetKeyValueStoreBuffer(self.handle.as_ptr(), key_ptr, value.as_raw()) }
    }

    /// Get the stored representation of the kvs
    pub fn serialized_data(&self) -> DataBuffer {
        let result = unsafe { BNGetKeyValueStoreSerializedData(self.handle.as_ptr()) };
        assert!(!result.is_null());
        DataBuffer::from_raw(result)
    }

    /// Begin storing new keys into a namespace
    pub fn begin_namespace<S: BnStrCompatible>(&self, name: S) {
        let name_raw = name.into_bytes_with_nul();
        let name_ptr = name_raw.as_ref().as_ptr() as *const c_char;
        unsafe { BNBeginKeyValueStoreNamespace(self.handle.as_ptr(), name_ptr) }
    }

    /// End storing new keys into a namespace
    pub fn end_namespace(&self) {
        unsafe { BNEndKeyValueStoreNamespace(self.handle.as_ptr()) }
    }

    /// If the kvs is empty
    pub fn is_empty(&self) -> bool {
        unsafe { BNIsKeyValueStoreEmpty(self.handle.as_ptr()) }
    }

    /// Number of values in the kvs
    pub fn value_size(&self) -> usize {
        unsafe { BNGetKeyValueStoreValueSize(self.handle.as_ptr()) }
    }

    /// Length of serialized data
    pub fn data_size(&self) -> usize {
        unsafe { BNGetKeyValueStoreDataSize(self.handle.as_ptr()) }
    }

    /// Size of all data in storage
    pub fn value_storage_size(&self) -> usize {
        unsafe { BNGetKeyValueStoreValueStorageSize(self.handle.as_ptr()) }
    }

    /// Number of namespaces pushed with begin_namespace
    pub fn namespace_size(&self) -> usize {
        unsafe { BNGetKeyValueStoreNamespaceSize(self.handle.as_ptr()) }
    }
}

impl ToOwned for KeyValueStore {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for KeyValueStore {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: NonNull::new(BNNewKeyValueStoreReference(handle.handle.as_ptr())).unwrap(),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeKeyValueStore(handle.handle.as_ptr());
    }
}

impl Debug for KeyValueStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyValueStore")
            .field("keys", &self.keys().to_vec())
            .field("is_empty", &self.is_empty())
            .field("value_size", &self.value_size())
            .field("data_size", &self.data_size())
            .field("value_storage_size", &self.value_storage_size())
            .field("namespace_size", &self.namespace_size())
            .finish()
    }
}
