#![allow(dead_code)]
use std::ffi::{c_char, c_void};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::progress::{NoProgressCallback, ProgressCallback};
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner};
use crate::string::{raw_to_string, BnString};
use binaryninjacore_sys::*;

pub type UpdateResult = BNUpdateResult;

pub fn auto_updates_enabled() -> bool {
    unsafe { BNAreAutoUpdatesEnabled() }
}

pub fn set_auto_updates_enabled(enabled: bool) {
    unsafe { BNSetAutoUpdatesEnabled(enabled) }
}

pub fn time_since_last_update_check() -> Duration {
    Duration::from_secs(unsafe { BNGetTimeSinceLastUpdateCheck() })
}

/// Whether an update has been downloaded and is waiting installation
pub fn is_update_installation_pending() -> bool {
    unsafe { BNIsUpdateInstallationPending() }
}

/// Installs any pending updates
pub fn install_pending_update() -> Result<(), BnString> {
    let mut errors = std::ptr::null_mut();
    unsafe { BNInstallPendingUpdate(&mut errors) };
    if !errors.is_null() {
        Err(unsafe { BnString::from_raw(errors) })
    } else {
        Ok(())
    }
}

pub fn updates_checked() {
    unsafe { BNUpdatesChecked() }
}

#[derive(Clone, Debug)]
pub struct UpdateChannel {
    pub name: String,
    pub description: String,
    pub latest_version: String,
}

impl UpdateChannel {
    pub(crate) fn from_raw(value: &BNUpdateChannel) -> Self {
        Self {
            name: raw_to_string(value.name as *mut _).unwrap(),
            description: raw_to_string(value.description as *mut _).unwrap(),
            latest_version: raw_to_string(value.latestVersion as *mut _).unwrap(),
        }
    }

    pub(crate) fn from_owned_raw(value: BNUpdateChannel) -> Self {
        let owned = Self::from_raw(&value);
        Self::free_raw(value);
        owned
    }

    pub(crate) fn into_raw(value: Self) -> BNUpdateChannel {
        let bn_name = BnString::new(value.name);
        let bn_description = BnString::new(value.description);
        let bn_latest_version = BnString::new(value.latest_version);
        BNUpdateChannel {
            name: BnString::into_raw(bn_name),
            description: BnString::into_raw(bn_description),
            latestVersion: BnString::into_raw(bn_latest_version),
        }
    }

    pub(crate) fn free_raw(value: BNUpdateChannel) {
        let _ = unsafe { BnString::from_raw(value.name) };
        let _ = unsafe { BnString::from_raw(value.description) };
        let _ = unsafe { BnString::from_raw(value.latestVersion) };
    }

    pub fn all() -> Result<Array<UpdateChannel>, BnString> {
        let mut count = 0;
        let mut errors = std::ptr::null_mut();
        let result = unsafe { BNGetUpdateChannels(&mut count, &mut errors) };
        if !errors.is_null() {
            Err(unsafe { BnString::from_raw(errors) })
        } else {
            assert!(!result.is_null());
            Ok(unsafe { Array::new(result, count, ()) })
        }
    }

    /// List of versions
    pub fn versions(&self) -> Result<Array<UpdateVersion>, BnString> {
        let mut count = 0;
        let mut errors = std::ptr::null_mut();
        let result = unsafe {
            BNGetUpdateChannelVersions(self.name.as_ptr() as *const c_char, &mut count, &mut errors)
        };
        if !errors.is_null() {
            Err(unsafe { BnString::from_raw(errors) })
        } else {
            assert!(!result.is_null());
            Ok(unsafe { Array::new(result, count, ()) })
        }
    }

    /// Latest version
    pub fn latest_version(&self) -> Result<UpdateVersion, BnString> {
        let last_version = &self.latest_version;
        let versions = self.versions()?;
        for version in &versions {
            if &version.version == last_version {
                return Ok(version);
            }
        }
        Err(BnString::new("Could not find latest version"))
    }

    /// Whether updates are available
    pub fn updates_available(&self) -> Result<bool, BnString> {
        let mut errors = std::ptr::null_mut();
        let result = unsafe {
            BNAreUpdatesAvailable(
                self.name.as_ptr() as *const c_char,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &mut errors,
            )
        };
        if !errors.is_null() {
            Err(unsafe { BnString::from_raw(errors) })
        } else {
            Ok(result)
        }
    }

    pub fn update_to_latest(&self) -> Result<UpdateResult, BnString> {
        self.update_to_latest_with_progress(NoProgressCallback)
    }

    pub fn update_to_latest_with_progress<P: ProgressCallback>(
        &self,
        mut progress: P,
    ) -> Result<UpdateResult, BnString> {
        let mut errors = std::ptr::null_mut();

        let result = unsafe {
            BNUpdateToLatestVersion(
                self.name.as_ptr() as *const c_char,
                &mut errors,
                Some(P::cb_progress_callback),
                &mut progress as *mut P as *mut c_void,
            )
        };

        if !errors.is_null() {
            Err(unsafe { BnString::from_raw(errors) })
        } else {
            Ok(result)
        }
    }

    pub fn update(&self, version: &UpdateVersion) -> Result<UpdateResult, BnString> {
        self.update_with_progress(version, NoProgressCallback)
    }

    pub fn update_with_progress<P: ProgressCallback>(
        &self,
        version: &UpdateVersion,
        mut progress: P,
    ) -> Result<UpdateResult, BnString> {
        let mut errors = std::ptr::null_mut();

        let result = unsafe {
            BNUpdateToVersion(
                self.name.as_ptr() as *const c_char,
                version.version.as_ptr() as *const c_char,
                &mut errors,
                Some(P::cb_progress_callback),
                &mut progress as *mut P as *mut c_void,
            )
        };

        if !errors.is_null() {
            Err(unsafe { BnString::from_raw(errors) })
        } else {
            Ok(result)
        }
    }
}

impl CoreArrayProvider for UpdateChannel {
    type Raw = BNUpdateChannel;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for UpdateChannel {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeUpdateChannelList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        UpdateChannel::from_raw(raw)
    }
}

#[derive(Clone)]
pub struct UpdateVersion {
    pub version: String,
    pub notes: String,
    pub time: SystemTime,
}

impl UpdateVersion {
    pub(crate) fn from_raw(value: &BNUpdateVersion) -> Self {
        Self {
            version: raw_to_string(value.version as *mut _).unwrap(),
            notes: raw_to_string(value.notes as *mut _).unwrap(),
            time: UNIX_EPOCH + Duration::from_secs(value.time),
        }
    }

    pub(crate) fn from_owned_raw(value: BNUpdateVersion) -> Self {
        let owned = Self::from_raw(&value);
        Self::free_raw(value);
        owned
    }

    pub(crate) fn into_raw(value: Self) -> BNUpdateVersion {
        let bn_version = BnString::new(value.version);
        let bn_notes = BnString::new(value.notes);
        let epoch = value.time.duration_since(UNIX_EPOCH).unwrap();
        BNUpdateVersion {
            version: BnString::into_raw(bn_version),
            notes: BnString::into_raw(bn_notes),
            time: epoch.as_secs(),
        }
    }

    pub(crate) fn free_raw(value: BNUpdateVersion) {
        let _ = unsafe { BnString::from_raw(value.version) };
        let _ = unsafe { BnString::from_raw(value.notes) };
    }
}

impl CoreArrayProvider for UpdateVersion {
    type Raw = BNUpdateVersion;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for UpdateVersion {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeUpdateChannelVersionList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        UpdateVersion::from_raw(raw)
    }
}
