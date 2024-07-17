use core::{ffi, mem, ptr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use binaryninjacore_sys::*;

use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner};
use crate::string::BnString;

pub type UpdateResult = BNUpdateResult;

#[repr(C)]
pub struct UpdateChannel {
    pub name: BnString,
    pub description: BnString,
    pub latest_version: BnString,
    // NOTE don't allow the user to create his own UpdateChannel
    _lock: core::marker::PhantomData<()>,
}

impl UpdateChannel {
    pub(crate) unsafe fn ref_from_raw(handle: &BNUpdateChannel) -> &Self {
        mem::transmute(handle)
    }

    pub fn all() -> Result<Array<UpdateChannel>, BnString> {
        let mut count = 0;
        let mut errors = ptr::null_mut();
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
        let mut errors = ptr::null_mut();
        let result =
            unsafe { BNGetUpdateChannelVersions(self.name.as_ptr(), &mut count, &mut errors) };
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
                return Ok(version.clone());
            }
        }
        panic!();
    }

    /// Whether updates are available
    pub fn updates_available(&self) -> Result<bool, BnString> {
        let mut errors = ptr::null_mut();
        let result = unsafe {
            BNAreUpdatesAvailable(
                self.name.as_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
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
        let mut errors = ptr::null_mut();
        let result = unsafe {
            BNUpdateToLatestVersion(
                self.name.as_ptr(),
                &mut errors,
                Some(cb_progress_nop),
                ptr::null_mut(),
            )
        };
        if !errors.is_null() {
            Err(unsafe { BnString::from_raw(errors) })
        } else {
            Ok(result)
        }
    }

    pub fn update_to_latest_with_progress<F>(
        &self,
        mut progress: F,
    ) -> Result<UpdateResult, BnString>
    where
        F: FnMut(u64, u64) -> bool,
    {
        let mut errors = ptr::null_mut();
        let result = unsafe {
            BNUpdateToLatestVersion(
                self.name.as_ptr(),
                &mut errors,
                Some(cb_progress::<F>),
                &mut progress as *mut _ as *mut ffi::c_void,
            )
        };
        if !errors.is_null() {
            Err(unsafe { BnString::from_raw(errors) })
        } else {
            Ok(result)
        }
    }

    pub fn update(&self, version: &UpdateVersion) -> Result<UpdateResult, BnString> {
        let mut errors = ptr::null_mut();
        let result = unsafe {
            BNUpdateToVersion(
                self.name.as_ptr(),
                version.version.as_ptr(),
                &mut errors,
                Some(cb_progress_nop),
                ptr::null_mut(),
            )
        };
        if !errors.is_null() {
            Err(unsafe { BnString::from_raw(errors) })
        } else {
            Ok(result)
        }
    }

    pub fn update_with_progress<F>(
        &self,
        version: &UpdateVersion,
        mut progress: F,
    ) -> Result<UpdateResult, BnString>
    where
        F: FnMut(u64, u64) -> bool,
    {
        let mut errors = ptr::null_mut();
        let result = unsafe {
            BNUpdateToVersion(
                self.name.as_ptr(),
                version.version.as_ptr(),
                &mut errors,
                Some(cb_progress::<F>),
                &mut progress as *mut _ as *mut ffi::c_void,
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
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for UpdateChannel {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeUpdateChannelList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        UpdateChannel::ref_from_raw(raw)
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct UpdateVersion {
    pub version: BnString,
    pub notes: BnString,
    time: u64,
    // NOTE don't allow the user to create his own UpdateVersion
    _lock: core::marker::PhantomData<()>,
}

impl UpdateVersion {
    pub(crate) unsafe fn ref_from_raw(handle: &BNUpdateVersion) -> &Self {
        mem::transmute(handle)
    }

    pub fn time(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.time)
    }

    pub fn set_time(&mut self, time: SystemTime) {
        let epoch = time.duration_since(UNIX_EPOCH).unwrap();
        self.time = epoch.as_secs();
    }
}

impl CoreArrayProvider for UpdateVersion {
    type Raw = BNUpdateVersion;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for UpdateVersion {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        BNFreeUpdateChannelVersionList(raw, count)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        UpdateVersion::ref_from_raw(raw)
    }
}

/// queries if auto updates are enabled.
pub fn are_auto_updates_enabled() -> bool {
    unsafe { BNAreAutoUpdatesEnabled() }
}

/// sets auto update enabled status.
pub fn set_auto_updates_enabled(enabled: bool) {
    unsafe { BNSetAutoUpdatesEnabled(enabled) }
}

/// returns the time stamp for the last time updates were checked.
pub fn get_time_since_last_update_check() -> u64 {
    unsafe { BNGetTimeSinceLastUpdateCheck() }
}

/// whether an update has been downloaded and is waiting installation
pub fn is_update_installation_pending() -> bool {
    unsafe { BNIsUpdateInstallationPending() }
}

/// installs any pending updates
pub fn install_pending_update() -> Result<(), BnString> {
    let mut errors = ptr::null_mut();
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

unsafe extern "C" fn cb_progress_nop(_ctxt: *mut ffi::c_void, _progress: u64, _total: u64) -> bool {
    true
}

unsafe extern "C" fn cb_progress<F: FnMut(u64, u64) -> bool>(
    ctxt: *mut ffi::c_void,
    progress: u64,
    total: u64,
) -> bool {
    let ctxt: &mut F = &mut *(ctxt as *mut F);
    ctxt(progress, total)
}
