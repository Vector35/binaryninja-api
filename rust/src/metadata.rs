use crate::rc::{Array, CoreArrayProvider, CoreArrayWrapper, CoreOwnedArrayProvider};
use crate::string::{BnStrCompatible, BnString};
use binaryninjacore_sys::*;
use std::collections::HashMap;
use std::os::raw::c_char;
use std::slice;

pub type MetadataType = BNMetadataType;

#[repr(transparent)]
pub struct Metadata {
    pub(crate) handle: *mut BNMetadata,
}

impl Metadata {
    pub(crate) unsafe fn from_raw(handle: *mut BNMetadata) -> Self {
        debug_assert!(!handle.is_null());

        Self { handle }
    }

    pub fn new_of_type(metadata_type: MetadataType) -> Self {
        unsafe { Self::from_raw(BNCreateMetadataOfType(metadata_type)) }
    }

    pub fn get_type(&self) -> MetadataType {
        unsafe { BNMetadataGetType(self.handle) }
    }

    pub fn get_boolean(&self) -> Result<bool, ()> {
        match self.get_type() {
            MetadataType::BooleanDataType => Ok(unsafe { BNMetadataGetBoolean(self.handle) }),
            _ => Err(()),
        }
    }

    pub fn get_unsigned_integer(&self) -> Result<u64, ()> {
        match self.get_type() {
            MetadataType::UnsignedIntegerDataType => {
                Ok(unsafe { BNMetadataGetUnsignedInteger(self.handle) })
            }
            _ => Err(()),
        }
    }

    pub fn get_signed_integer(&self) -> Result<i64, ()> {
        match self.get_type() {
            MetadataType::SignedIntegerDataType => {
                Ok(unsafe { BNMetadataGetSignedInteger(self.handle) })
            }
            _ => Err(()),
        }
    }

    pub fn get_double(&self) -> Result<f64, ()> {
        match self.get_type() {
            MetadataType::DoubleDataType => Ok(unsafe { BNMetadataGetDouble(self.handle) }),
            _ => Err(()),
        }
    }

    pub fn get_string(&self) -> Result<BnString, ()> {
        match self.get_type() {
            MetadataType::StringDataType => {
                let ptr: *mut c_char = unsafe { BNMetadataGetString(self.handle) };
                if ptr.is_null() {
                    return Err(());
                }
                Ok(unsafe { BnString::from_raw(ptr) })
            }
            _ => Err(()),
        }
    }

    pub fn get_boolean_list(&self) -> Result<Vec<bool>, ()> {
        match self.get_type() {
            MetadataType::ArrayDataType => {
                let mut size: usize = 0;
                let ptr: *mut bool = unsafe { BNMetadataGetBooleanList(self.handle, &mut size) };
                if ptr.is_null() {
                    return Err(());
                }
                let list = unsafe { slice::from_raw_parts(ptr, size) };
                let vec = Vec::from(list);
                unsafe { BNFreeMetadataBooleanList(ptr, size) };
                Ok(vec)
            }
            _ => Err(()),
        }
    }

    pub fn get_unsigned_integer_list(&self) -> Result<Vec<u64>, ()> {
        match self.get_type() {
            MetadataType::ArrayDataType => {
                let mut size: usize = 0;
                let ptr: *mut u64 =
                    unsafe { BNMetadataGetUnsignedIntegerList(self.handle, &mut size) };
                if ptr.is_null() {
                    return Err(());
                }
                let list = unsafe { slice::from_raw_parts(ptr, size) };
                let vec = Vec::from(list);
                unsafe { BNFreeMetadataUnsignedIntegerList(ptr, size) };
                Ok(vec)
            }
            _ => Err(()),
        }
    }

    pub fn get_signed_integer_list(&self) -> Result<Vec<i64>, ()> {
        match self.get_type() {
            MetadataType::ArrayDataType => {
                let mut size: usize = 0;
                let ptr: *mut i64 =
                    unsafe { BNMetadataGetSignedIntegerList(self.handle, &mut size) };
                if ptr.is_null() {
                    return Err(());
                }
                let list = unsafe { slice::from_raw_parts(ptr, size) };
                let vec = Vec::from(list);
                unsafe { BNFreeMetadataSignedIntegerList(ptr, size) };
                Ok(vec)
            }
            _ => Err(()),
        }
    }

    pub fn get_double_list(&self) -> Result<Vec<f64>, ()> {
        match self.get_type() {
            MetadataType::ArrayDataType => {
                let mut size: usize = 0;
                let ptr: *mut f64 = unsafe { BNMetadataGetDoubleList(self.handle, &mut size) };
                if ptr.is_null() {
                    return Err(());
                }
                let list = unsafe { slice::from_raw_parts(ptr, size) };
                let vec = Vec::from(list);
                unsafe { BNFreeMetadataDoubleList(ptr, size) };
                Ok(vec)
            }
            _ => Err(()),
        }
    }

    pub fn get_string_list(&self) -> Result<Vec<BnString>, ()> {
        match self.get_type() {
            MetadataType::ArrayDataType => {
                let mut size: usize = 0;
                let ptr: *mut *mut c_char =
                    unsafe { BNMetadataGetStringList(self.handle, &mut size) };
                if ptr.is_null() {
                    return Err(());
                }
                let list = unsafe { slice::from_raw_parts(ptr, size) };
                let vec = list
                    .iter()
                    .map(|ptr| unsafe { BnString::from_raw(*ptr) })
                    .collect::<Vec<_>>();
                unsafe { BNFreeMetadataStringList(ptr, size) };
                Ok(vec)
            }
            _ => Err(()),
        }
    }

    pub fn get_raw(&self) -> Result<Vec<u8>, ()> {
        match self.get_type() {
            MetadataType::RawDataType => {
                let mut size: usize = 0;
                let ptr: *mut u8 = unsafe { BNMetadataGetRaw(self.handle, &mut size) };
                if ptr.is_null() {
                    return Err(());
                }

                let list = unsafe { slice::from_raw_parts(ptr, size) };
                let vec = Vec::from(list);
                unsafe { BNFreeMetadataRaw(ptr) };
                Ok(vec)
            }
            _ => Err(()),
        }
    }

    pub fn get_array(&self) -> Result<Array<Metadata>, ()> {
        match self.get_type() {
            MetadataType::ArrayDataType => {
                let mut size: usize = 0;
                let ptr: *mut *mut BNMetadata =
                    unsafe { BNMetadataGetArray(self.handle, &mut size) };
                if ptr.is_null() {
                    return Err(());
                }

                Ok(unsafe { Array::new(ptr, size, ()) })
            }
            _ => Err(()),
        }
    }

    pub fn get_value_store(&self) -> Result<HashMap<BnString, Metadata>, ()> {
        match self.get_type() {
            MetadataType::KeyValueDataType => {
                let ptr: *mut BNMetadataValueStore =
                    unsafe { BNMetadataGetValueStore(self.handle) };
                if ptr.is_null() {
                    return Err(());
                }

                let size = unsafe { (*ptr).size };
                let keys_ptr: *mut *mut c_char = unsafe { (*ptr).keys };
                let keys = unsafe { slice::from_raw_parts(keys_ptr, size) };
                let values_ptr: *mut *mut BNMetadata = unsafe { (*ptr).values };
                let values: &[*mut BNMetadata] = unsafe { slice::from_raw_parts(values_ptr, size) };

                let map = keys
                    .iter()
                    .zip(values.iter())
                    .map(|(key, value)| {
                        let key = unsafe { BnString::from_raw(*key) };

                        let value = unsafe { Self::from_raw(BNNewMetadataReference(*value)) };
                        (key, value)
                    })
                    .collect();

                Ok(map)
            }
            _ => Err(()),
        }
    }

    pub fn len(&self) -> usize {
        unsafe { BNMetadataSize(self.handle) }
    }

    pub fn is_empty(&self) -> bool {
        unsafe { BNMetadataSize(self.handle) == 0 }
    }

    // TODO is this return owned or should be asscoiated the self lifetime?
    pub fn index(&self, index: usize) -> Result<Option<Metadata>, ()> {
        if self.get_type() != MetadataType::ArrayDataType {
            return Err(());
        }
        let ptr: *mut BNMetadata = unsafe { BNMetadataGetForIndex(self.handle, index) };
        if ptr.is_null() {
            return Ok(None);
        }
        Ok(Some(unsafe { Self::from_raw(ptr) }))
    }

    // TODO is this return owned or should be asscoiated the self lifetime?
    pub fn get<S: BnStrCompatible>(&self, key: S) -> Result<Option<Metadata>, ()> {
        if self.get_type() != MetadataType::KeyValueDataType {
            return Err(());
        }
        let ptr: *mut BNMetadata = unsafe {
            BNMetadataGetForKey(
                self.handle,
                key.into_bytes_with_nul().as_ref().as_ptr() as *const c_char,
            )
        };
        if ptr.is_null() {
            return Ok(None);
        }
        Ok(Some(unsafe { Self::from_raw(ptr) }))
    }

    pub fn push(&self, value: &Metadata) -> Result<(), ()> {
        if self.get_type() != MetadataType::ArrayDataType {
            return Err(());
        }
        unsafe { BNMetadataArrayAppend(self.handle, value.handle) };
        Ok(())
    }

    pub fn insert<S: BnStrCompatible>(&self, key: S, value: &Metadata) -> Result<(), ()> {
        if self.get_type() != MetadataType::KeyValueDataType {
            return Err(());
        }

        unsafe {
            BNMetadataSetValueForKey(
                self.handle,
                key.into_bytes_with_nul().as_ref().as_ptr() as *const c_char,
                value.handle,
            )
        };
        Ok(())
    }

    pub fn remove_index(&self, index: usize) -> Result<(), ()> {
        if self.get_type() != MetadataType::ArrayDataType {
            return Err(());
        }

        unsafe { BNMetadataRemoveIndex(self.handle, index) };
        Ok(())
    }

    pub fn remove_key<S: BnStrCompatible>(&self, key: S) -> Result<(), ()> {
        if self.get_type() != MetadataType::KeyValueDataType {
            return Err(());
        }

        unsafe {
            BNMetadataRemoveKey(
                self.handle,
                key.into_bytes_with_nul().as_ref().as_ptr() as *const c_char,
            )
        };
        Ok(())
    }
}

unsafe impl Sync for Metadata {}
unsafe impl Send for Metadata {}

impl Clone for Metadata {
    fn clone(&self) -> Self {
        unsafe { Self::from_raw(BNNewMetadataReference(self.handle)) }
    }
}

impl Drop for Metadata {
    fn drop(&mut self) {
        unsafe { BNFreeMetadata(self.handle) }
    }
}

impl CoreArrayProvider for Metadata {
    type Raw = *mut BNMetadata;
    type Context = ();
}

unsafe impl CoreOwnedArrayProvider for Metadata {
    unsafe fn free(raw: *mut *mut BNMetadata, _count: usize, _context: &()) {
        BNFreeMetadataArray(raw);
    }
}

unsafe impl<'a> CoreArrayWrapper<'a> for Metadata {
    type Wrapped = &'a Metadata;

    unsafe fn wrap_raw(raw: &'a *mut BNMetadata, _context: &'a ()) -> &'a Metadata {
        &*((*raw) as *mut Self)
    }
}

impl From<bool> for Metadata {
    fn from(value: bool) -> Self {
        unsafe { Metadata::from_raw(BNCreateMetadataBooleanData(value)) }
    }
}

impl From<u64> for Metadata {
    fn from(value: u64) -> Self {
        unsafe { Metadata::from_raw(BNCreateMetadataUnsignedIntegerData(value)) }
    }
}

impl From<i64> for Metadata {
    fn from(value: i64) -> Self {
        unsafe { Metadata::from_raw(BNCreateMetadataSignedIntegerData(value)) }
    }
}

impl From<f64> for Metadata {
    fn from(value: f64) -> Self {
        unsafe { Metadata::from_raw(BNCreateMetadataDoubleData(value)) }
    }
}

impl From<String> for Metadata {
    fn from(value: String) -> Self {
        unsafe {
            Metadata::from_raw(BNCreateMetadataStringData(
                value.into_bytes_with_nul().as_ptr() as *const c_char,
            ))
        }
    }
}

impl From<&str> for Metadata {
    fn from(value: &str) -> Self {
        unsafe {
            Metadata::from_raw(BNCreateMetadataStringData(
                value.into_bytes_with_nul().as_ptr() as *const c_char,
            ))
        }
    }
}

impl<T: Into<Metadata>> From<&T> for Metadata {
    fn from(value: &T) -> Self {
        value.into()
    }
}

impl From<&Vec<u8>> for Metadata {
    fn from(value: &Vec<u8>) -> Self {
        unsafe { Metadata::from_raw(BNCreateMetadataRawData(value.as_ptr(), value.len())) }
    }
}

impl From<&Vec<Metadata>> for Metadata {
    fn from(value: &Vec<Metadata>) -> Self {
        let mut pointers: Vec<*mut BNMetadata> = vec![];
        for v in value.iter() {
            pointers.push(v.handle);
        }
        unsafe { Metadata::from_raw(BNCreateMetadataArray(pointers.as_mut_ptr(), pointers.len())) }
    }
}

impl From<&Array<Metadata>> for Metadata {
    fn from(value: &Array<Metadata>) -> Self {
        let mut pointers: Vec<*mut BNMetadata> = vec![];
        for v in value.iter() {
            pointers.push(v.handle);
        }
        unsafe { Metadata::from_raw(BNCreateMetadataArray(pointers.as_mut_ptr(), pointers.len())) }
    }
}

impl<S: BnStrCompatible> From<HashMap<S, Metadata>> for Metadata {
    fn from(value: HashMap<S, Metadata>) -> Self {
        let mut key_refs: Vec<S::Result> = vec![];
        let mut keys: Vec<*const c_char> = vec![];
        let mut values: Vec<*mut BNMetadata> = vec![];
        for (k, v) in value.into_iter() {
            key_refs.push(k.into_bytes_with_nul());
            values.push(v.handle);
        }
        for k in &key_refs {
            keys.push(k.as_ref().as_ptr() as *const c_char);
        }

        unsafe {
            Metadata::from_raw(BNCreateMetadataValueStore(
                keys.as_mut_ptr(),
                values.as_mut_ptr(),
                keys.len(),
            ))
        }
    }
}

impl<S: BnStrCompatible + Copy, T: Into<Metadata>> From<&[(S, T)]> for Metadata {
    fn from(value: &[(S, T)]) -> Self {
        let mut key_refs: Vec<S::Result> = vec![];
        let mut keys: Vec<*const c_char> = vec![];
        let mut values: Vec<*mut BNMetadata> = vec![];
        for (k, v) in value.iter() {
            key_refs.push(k.into_bytes_with_nul());
            let value_metadata: Metadata = v.into();
            values.push(value_metadata.handle);
        }
        for k in &key_refs {
            keys.push(k.as_ref().as_ptr() as *const c_char);
        }

        unsafe {
            Metadata::from_raw(BNCreateMetadataValueStore(
                keys.as_mut_ptr(),
                values.as_mut_ptr(),
                keys.len(),
            ))
        }
    }
}

impl<S: BnStrCompatible + Copy, T: Into<Metadata>, const N: usize> From<[(S, T); N]> for Metadata {
    fn from(value: [(S, T); N]) -> Self {
        let mut key_refs: Vec<S::Result> = vec![];
        let mut keys: Vec<*const c_char> = vec![];
        let mut values: Vec<*mut BNMetadata> = vec![];
        for (k, v) in value.into_iter() {
            key_refs.push(k.into_bytes_with_nul());
            let value_metadata: Metadata = v.into();
            values.push(value_metadata.handle);
        }
        for k in &key_refs {
            keys.push(k.as_ref().as_ptr() as *const c_char);
        }

        unsafe {
            Metadata::from_raw(BNCreateMetadataValueStore(
                keys.as_mut_ptr(),
                values.as_mut_ptr(),
                keys.len(),
            ))
        }
    }
}

impl From<&Vec<bool>> for Metadata {
    fn from(value: &Vec<bool>) -> Self {
        unsafe {
            Metadata::from_raw(BNCreateMetadataBooleanListData(
                value.as_ptr() as *mut bool,
                value.len(),
            ))
        }
    }
}

impl From<&Vec<u64>> for Metadata {
    fn from(value: &Vec<u64>) -> Self {
        unsafe {
            Metadata::from_raw(BNCreateMetadataUnsignedIntegerListData(
                value.as_ptr() as *mut u64,
                value.len(),
            ))
        }
    }
}

impl From<&Vec<i64>> for Metadata {
    fn from(value: &Vec<i64>) -> Self {
        unsafe {
            Metadata::from_raw(BNCreateMetadataSignedIntegerListData(
                value.as_ptr() as *mut i64,
                value.len(),
            ))
        }
    }
}

impl From<&Vec<f64>> for Metadata {
    fn from(value: &Vec<f64>) -> Self {
        unsafe {
            Metadata::from_raw(BNCreateMetadataDoubleListData(
                value.as_ptr() as *mut f64,
                value.len(),
            ))
        }
    }
}

impl<S: BnStrCompatible> From<Vec<S>> for Metadata {
    fn from(value: Vec<S>) -> Self {
        let mut refs = vec![];
        for v in value {
            refs.push(v.into_bytes_with_nul());
        }
        let mut pointers = vec![];
        for r in &refs {
            pointers.push(r.as_ref().as_ptr() as *const c_char);
        }
        unsafe {
            Metadata::from_raw(BNCreateMetadataStringListData(
                pointers.as_ptr() as *mut *const c_char,
                pointers.len(),
            ))
        }
    }
}

impl PartialEq for Metadata {
    fn eq(&self, other: &Self) -> bool {
        unsafe { BNMetadataIsEqual(self.handle, other.handle) }
    }
}

impl Eq for Metadata {}

impl TryFrom<&Metadata> for bool {
    type Error = ();

    fn try_from(value: &Metadata) -> Result<Self, Self::Error> {
        value.get_boolean()
    }
}

impl TryFrom<&Metadata> for u64 {
    type Error = ();

    fn try_from(value: &Metadata) -> Result<Self, Self::Error> {
        value.get_unsigned_integer()
    }
}

impl TryFrom<&Metadata> for i64 {
    type Error = ();

    fn try_from(value: &Metadata) -> Result<Self, Self::Error> {
        value.get_signed_integer()
    }
}

impl TryFrom<&Metadata> for f64 {
    type Error = ();

    fn try_from(value: &Metadata) -> Result<Self, Self::Error> {
        value.get_double()
    }
}

impl TryFrom<&Metadata> for BnString {
    type Error = ();

    fn try_from(value: &Metadata) -> Result<Self, Self::Error> {
        value.get_string()
    }
}

impl TryFrom<&Metadata> for String {
    type Error = ();

    fn try_from(value: &Metadata) -> Result<Self, Self::Error> {
        value.get_string().map(|s| s.to_string())
    }
}

impl TryFrom<&Metadata> for Vec<bool> {
    type Error = ();

    fn try_from(value: &Metadata) -> Result<Self, Self::Error> {
        value.get_boolean_list()
    }
}

impl TryFrom<&Metadata> for Vec<u64> {
    type Error = ();

    fn try_from(value: &Metadata) -> Result<Self, Self::Error> {
        value.get_unsigned_integer_list()
    }
}

impl TryFrom<&Metadata> for Vec<i64> {
    type Error = ();

    fn try_from(value: &Metadata) -> Result<Self, Self::Error> {
        value.get_signed_integer_list()
    }
}

impl TryFrom<&Metadata> for Vec<f64> {
    type Error = ();

    fn try_from(value: &Metadata) -> Result<Self, Self::Error> {
        value.get_double_list()
    }
}

impl TryFrom<&Metadata> for Vec<BnString> {
    type Error = ();

    fn try_from(value: &Metadata) -> Result<Self, Self::Error> {
        value.get_string_list()
    }
}

impl TryFrom<&Metadata> for Vec<String> {
    type Error = ();

    fn try_from(value: &Metadata) -> Result<Self, Self::Error> {
        value
            .get_string_list()
            .map(|v| v.into_iter().map(|s| s.to_string()).collect())
    }
}

impl TryFrom<&Metadata> for Vec<u8> {
    type Error = ();

    fn try_from(value: &Metadata) -> Result<Self, Self::Error> {
        value.get_raw()
    }
}

impl TryFrom<&Metadata> for Array<Metadata> {
    type Error = ();

    fn try_from(value: &Metadata) -> Result<Self, Self::Error> {
        value.get_array()
    }
}

impl TryFrom<&Metadata> for HashMap<BnString, Metadata> {
    type Error = ();

    fn try_from(value: &Metadata) -> Result<Self, Self::Error> {
        value.get_value_store()
    }
}

impl TryFrom<&Metadata> for HashMap<String, Metadata> {
    type Error = ();

    fn try_from(value: &Metadata) -> Result<Self, Self::Error> {
        value
            .get_value_store()
            .map(|m| m.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }
}
