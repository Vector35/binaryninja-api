use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Guard, Ref, RefCountable};
use crate::string::{BnStrCompatible, BnString, IntoJson};
use binaryninjacore_sys::*;
use std::collections::HashMap;
use std::os::raw::c_char;
use std::slice;

pub type MetadataType = BNMetadataType;

pub struct Metadata {
    pub(crate) handle: *mut BNMetadata,
}

impl Metadata {
    pub(crate) unsafe fn from_raw(handle: *mut BNMetadata) -> Self {
        debug_assert!(!handle.is_null());

        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: *mut BNMetadata) -> Ref<Self> {
        Ref::new(Self::from_raw(handle))
    }

    pub fn new_of_type(metadata_type: MetadataType) -> Ref<Self> {
        unsafe { Self::ref_from_raw(BNCreateMetadataOfType(metadata_type)) }
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

    pub fn get_json_string(&self) -> Result<BnString, ()> {
        match self.get_type() {
            MetadataType::StringDataType => {
                let ptr: *mut c_char = unsafe { BNMetadataGetJsonString(self.handle) };
                if ptr.is_null() {
                    return Err(());
                }
                Ok(unsafe { BnString::from_raw(ptr) })
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

    pub fn get_value_store(&self) -> Result<HashMap<BnString, Ref<Metadata>>, ()> {
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

                let mut map = HashMap::new();
                for i in 0..size {
                    let key = unsafe { BnString::from_raw(keys[i]) };

                    let value = unsafe {
                        Ref::<Metadata>::new(Self {
                            handle: BNNewMetadataReference(values[i]),
                        })
                    };
                    map.insert(key, value);
                }

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

    pub fn index(&self, index: usize) -> Result<Option<Ref<Metadata>>, ()> {
        if self.get_type() != MetadataType::ArrayDataType {
            return Err(());
        }
        let ptr: *mut BNMetadata = unsafe { BNMetadataGetForIndex(self.handle, index) };
        if ptr.is_null() {
            return Ok(None);
        }
        Ok(Some(unsafe { Self::ref_from_raw(ptr) }))
    }

    pub fn get<S: BnStrCompatible>(&self, key: S) -> Result<Option<Ref<Metadata>>, ()> {
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
        Ok(Some(unsafe { Self::ref_from_raw(ptr) }))
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

unsafe impl RefCountable for Metadata {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewMetadataReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeMetadata(handle.handle);
    }
}

impl CoreArrayProvider for Metadata {
    type Raw = *mut BNMetadata;
    type Context = ();
    type Wrapped<'a> = Guard<'a, Metadata>;
}

unsafe impl CoreArrayProviderInner for Metadata {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        // TODO: `count` is not passed into the core here...
        BNFreeMetadataArray(raw);
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, context: &'a Self::Context) -> Self::Wrapped<'a> {
        Guard::new(Self::from_raw(*raw), context)
    }
}

impl ToOwned for Metadata {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

impl From<bool> for Ref<Metadata> {
    fn from(value: bool) -> Self {
        unsafe { Metadata::ref_from_raw(BNCreateMetadataBooleanData(value)) }
    }
}

impl From<u64> for Ref<Metadata> {
    fn from(value: u64) -> Self {
        unsafe { Metadata::ref_from_raw(BNCreateMetadataUnsignedIntegerData(value)) }
    }
}

impl From<i64> for Ref<Metadata> {
    fn from(value: i64) -> Self {
        unsafe { Metadata::ref_from_raw(BNCreateMetadataSignedIntegerData(value)) }
    }
}

impl From<f64> for Ref<Metadata> {
    fn from(value: f64) -> Self {
        unsafe { Metadata::ref_from_raw(BNCreateMetadataDoubleData(value)) }
    }
}

impl From<String> for Ref<Metadata> {
    fn from(value: String) -> Self {
        unsafe {
            Metadata::ref_from_raw(BNCreateMetadataStringData(
                value.into_bytes_with_nul().as_ptr() as *const c_char,
            ))
        }
    }
}

impl From<&str> for Ref<Metadata> {
    fn from(value: &str) -> Self {
        unsafe {
            Metadata::ref_from_raw(BNCreateMetadataStringData(
                value.into_bytes_with_nul().as_ptr() as *const c_char,
            ))
        }
    }
}

impl From<&Vec<u8>> for Ref<Metadata> {
    fn from(value: &Vec<u8>) -> Self {
        unsafe { Metadata::ref_from_raw(BNCreateMetadataRawData(value.as_ptr(), value.len())) }
    }
}

impl From<&Vec<Ref<Metadata>>> for Ref<Metadata> {
    fn from(value: &Vec<Ref<Metadata>>) -> Self {
        let mut pointers: Vec<*mut BNMetadata> = vec![];
        for v in value.iter() {
            pointers.push(v.as_ref().handle);
        }
        unsafe {
            Metadata::ref_from_raw(BNCreateMetadataArray(pointers.as_mut_ptr(), pointers.len()))
        }
    }
}

impl From<&Array<Metadata>> for Ref<Metadata> {
    fn from(value: &Array<Metadata>) -> Self {
        let mut pointers: Vec<*mut BNMetadata> = vec![];
        for v in value.iter() {
            pointers.push(v.as_ref().handle);
        }
        unsafe {
            Metadata::ref_from_raw(BNCreateMetadataArray(pointers.as_mut_ptr(), pointers.len()))
        }
    }
}

impl<S: BnStrCompatible> From<HashMap<S, Ref<Metadata>>> for Ref<Metadata> {
    fn from(value: HashMap<S, Ref<Metadata>>) -> Self {
        let data: Vec<(S::Result, Ref<Metadata>)> = value
            .into_iter()
            .map(|(k, v)| (k.into_bytes_with_nul(), v))
            .collect();
        let mut keys: Vec<*const c_char> = data
            .iter()
            .map(|(k, _)| k.as_ref().as_ptr() as *const c_char)
            .collect();
        let mut values: Vec<*mut BNMetadata> = data.iter().map(|(_, v)| v.handle).collect();

        unsafe {
            Metadata::ref_from_raw(BNCreateMetadataValueStore(
                keys.as_mut_ptr(),
                values.as_mut_ptr(),
                keys.len(),
            ))
        }
    }
}

impl<S, T> From<&[(S, T)]> for Ref<Metadata>
where
    S: BnStrCompatible + Copy,
    for<'a> &'a T: Into<Ref<Metadata>>,
{
    fn from(value: &[(S, T)]) -> Self {
        let data: Vec<(S::Result, Ref<Metadata>)> = value
            .iter()
            .map(|(k, v)| (k.into_bytes_with_nul(), v.into()))
            .collect();
        let mut keys: Vec<*const c_char> = data
            .iter()
            .map(|(k, _)| k.as_ref().as_ptr() as *const c_char)
            .collect();
        let mut values: Vec<*mut BNMetadata> = data.iter().map(|(_, v)| v.handle).collect();

        unsafe {
            Metadata::ref_from_raw(BNCreateMetadataValueStore(
                keys.as_mut_ptr(),
                values.as_mut_ptr(),
                keys.len(),
            ))
        }
    }
}

impl<S, T, const N: usize> From<[(S, T); N]> for Ref<Metadata>
where
    S: BnStrCompatible + Copy,
    for<'a> &'a T: Into<Ref<Metadata>>,
{
    fn from(value: [(S, T); N]) -> Self {
        let slice = &value[..];
        // use the `impl From<&[(S, T)]>`
        slice.into()
    }
}

impl From<&Vec<bool>> for Ref<Metadata> {
    fn from(value: &Vec<bool>) -> Self {
        unsafe {
            Metadata::ref_from_raw(BNCreateMetadataBooleanListData(
                value.as_ptr() as *mut bool,
                value.len(),
            ))
        }
    }
}

impl From<&Vec<u64>> for Ref<Metadata> {
    fn from(value: &Vec<u64>) -> Self {
        unsafe {
            Metadata::ref_from_raw(BNCreateMetadataUnsignedIntegerListData(
                value.as_ptr() as *mut u64,
                value.len(),
            ))
        }
    }
}

impl From<&Vec<i64>> for Ref<Metadata> {
    fn from(value: &Vec<i64>) -> Self {
        unsafe {
            Metadata::ref_from_raw(BNCreateMetadataSignedIntegerListData(
                value.as_ptr() as *mut i64,
                value.len(),
            ))
        }
    }
}

impl From<&Vec<f64>> for Ref<Metadata> {
    fn from(value: &Vec<f64>) -> Self {
        unsafe {
            Metadata::ref_from_raw(BNCreateMetadataDoubleListData(
                value.as_ptr() as *mut f64,
                value.len(),
            ))
        }
    }
}

impl<S: BnStrCompatible> From<Vec<S>> for Ref<Metadata> {
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
            Metadata::ref_from_raw(BNCreateMetadataStringListData(
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

impl Eq for Ref<Metadata> {}

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

impl TryFrom<&Metadata> for HashMap<BnString, Ref<Metadata>> {
    type Error = ();

    fn try_from(value: &Metadata) -> Result<Self, Self::Error> {
        value.get_value_store()
    }
}

impl TryFrom<&Metadata> for HashMap<String, Ref<Metadata>> {
    type Error = ();

    fn try_from(value: &Metadata) -> Result<Self, Self::Error> {
        value
            .get_value_store()
            .map(|m| m.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }
}

impl IntoJson for &Metadata {
    type Output = BnString;
    fn get_json_string(self) -> Result<BnString, ()> {
        Metadata::get_json_string(self)
    }
}

impl IntoJson for Ref<Metadata> {
    type Output = BnString;
    fn get_json_string(self) -> Result<BnString, ()> {
        Metadata::get_json_string(&self)
    }
}
