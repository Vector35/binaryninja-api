mod changeset;
mod databasesync;
mod file;
mod folder;
mod group;
mod merge;
mod permission;
mod project;
mod remote;
mod snapshot;
mod user;

pub use changeset::*;
pub use databasesync::*;
pub use file::*;
pub use folder::*;
pub use group::*;
pub use merge::*;
pub use permission::*;
pub use project::*;
pub use remote::*;
pub use snapshot::*;
pub use user::*;

use core::{ffi, ptr};

use binaryninjacore_sys::*;

use crate::rc::Array;
use crate::string::{BnStrCompatible, BnString};

// TODO it's unclear where should preventivelly call things like `open`, `pull_files`, `pull_folders`, etc
// and where should let the user do it.

/// Get the single actively connected Remote (for ux simplification), if any
pub fn active_remote() -> Option<Remote> {
    let value = unsafe { BNCollaborationGetActiveRemote() };
    ptr::NonNull::new(value).map(|h| unsafe { Remote::from_raw(h) })
}

/// Set the single actively connected Remote
pub fn set_active_remote(remote: Option<&Remote>) {
    let remote_ptr = remote.map_or(ptr::null_mut(), |r| unsafe { r.as_raw() } as *mut _);
    unsafe { BNCollaborationSetActiveRemote(remote_ptr) }
}

pub fn store_data_in_keychain<K, I, DK, DV>(key: K, data: I) -> bool
where
    K: BnStrCompatible,
    I: IntoIterator<Item = (DK, DV)>,
    DK: BnStrCompatible,
    DV: BnStrCompatible,
{
    let key = key.into_bytes_with_nul();
    let (data_keys, data_values): (Vec<DK::Result>, Vec<DV::Result>) = data
        .into_iter()
        .map(|(k, v)| (k.into_bytes_with_nul(), v.into_bytes_with_nul()))
        .unzip();
    let data_keys_ptr: Box<[*const ffi::c_char]> = data_keys
        .iter()
        .map(|k| k.as_ref().as_ptr() as *const ffi::c_char)
        .collect();
    let data_values_ptr: Box<[*const ffi::c_char]> = data_values
        .iter()
        .map(|v| v.as_ref().as_ptr() as *const ffi::c_char)
        .collect();
    unsafe {
        BNCollaborationStoreDataInKeychain(
            key.as_ref().as_ptr() as *const ffi::c_char,
            data_keys_ptr.as_ptr() as *mut _,
            data_values_ptr.as_ptr() as *mut _,
            data_keys.len(),
        )
    }
}

pub fn has_data_in_keychain<K: BnStrCompatible>(key: K) -> bool {
    let key = key.into_bytes_with_nul();
    unsafe { BNCollaborationHasDataInKeychain(key.as_ref().as_ptr() as *const ffi::c_char) }
}

pub fn get_data_from_keychain<K: BnStrCompatible>(
    key: K,
) -> Option<(Array<BnString>, Array<BnString>)> {
    let key = key.into_bytes_with_nul();
    let mut keys = ptr::null_mut();
    let mut values = ptr::null_mut();
    let count = unsafe {
        BNCollaborationGetDataFromKeychain(
            key.as_ref().as_ptr() as *const ffi::c_char,
            &mut keys,
            &mut values,
        )
    };
    let keys = (!keys.is_null()).then(|| unsafe { Array::new(keys, count, ()) });
    let values = (!values.is_null()).then(|| unsafe { Array::new(values, count, ()) });
    keys.zip(values)
}

pub fn delete_data_from_keychain<K: BnStrCompatible>(key: K) -> bool {
    let key = key.into_bytes_with_nul();
    unsafe { BNCollaborationDeleteDataFromKeychain(key.as_ref().as_ptr() as *const ffi::c_char) }
}

/// Load the list of known Remotes from local Settings
pub fn load_remotes() -> Result<(), ()> {
    let success = unsafe { BNCollaborationLoadRemotes() };
    success.then_some(()).ok_or(())
}

/// List of known/connected Remotes
pub fn known_remotes() -> Array<Remote> {
    let mut count = 0;
    let value = unsafe { BNCollaborationGetRemotes(&mut count) };
    assert!(!value.is_null());
    unsafe { Array::new(value, count, ()) }
}

/// Get Remote by unique `id`
pub fn get_remote_by_id<S: BnStrCompatible>(id: S) -> Option<Remote> {
    let id = id.into_bytes_with_nul();
    let value = unsafe { BNCollaborationGetRemoteById(id.as_ref().as_ptr() as *const ffi::c_char) };
    ptr::NonNull::new(value).map(|h| unsafe { Remote::from_raw(h) })
}

/// Get Remote by `address`
pub fn get_remote_by_address<S: BnStrCompatible>(address: S) -> Option<Remote> {
    let address = address.into_bytes_with_nul();
    let value = unsafe {
        BNCollaborationGetRemoteByAddress(address.as_ref().as_ptr() as *const ffi::c_char)
    };
    ptr::NonNull::new(value).map(|h| unsafe { Remote::from_raw(h) })
}

/// Get Remote by `name`
pub fn get_remote_by_name<S: BnStrCompatible>(name: S) -> Option<Remote> {
    let name = name.into_bytes_with_nul();
    let value =
        unsafe { BNCollaborationGetRemoteByName(name.as_ref().as_ptr() as *const ffi::c_char) };
    ptr::NonNull::new(value).map(|h| unsafe { Remote::from_raw(h) })
}

/// Remove a Remote from the list of known remotes (saved to Settings)
pub fn remove_known_remote(remote: &Remote) {
    unsafe { BNCollaborationRemoveRemote(remote.as_raw()) }
}

/// Save the list of known Remotes to local Settings
pub fn save_remotes() {
    unsafe { BNCollaborationSaveRemotes() }
}
