use std::marker::PhantomData;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::rc::Array;
use crate::string::{AsCStr, BnString};

pub fn server_username() -> BnString {
    unsafe { BnString::from_raw(binaryninjacore_sys::BNGetEnterpriseServerUsername()) }
}

pub fn server_url() -> BnString {
    unsafe { BnString::from_raw(binaryninjacore_sys::BNGetEnterpriseServerUrl()) }
}

pub fn set_server_url(url: impl AsCStr) -> Result<(), ()> {
    let result = unsafe { binaryninjacore_sys::BNSetEnterpriseServerUrl(url.as_cstr().as_ptr()) };
    if result {
        Ok(())
    } else {
        Err(())
    }
}

pub fn server_name() -> BnString {
    unsafe { BnString::from_raw(binaryninjacore_sys::BNGetEnterpriseServerName()) }
}

pub fn server_id() -> BnString {
    unsafe { BnString::from_raw(binaryninjacore_sys::BNGetEnterpriseServerId()) }
}

pub fn server_version() -> u64 {
    unsafe { binaryninjacore_sys::BNGetEnterpriseServerVersion() }
}

pub fn server_build_id() -> BnString {
    unsafe { BnString::from_raw(binaryninjacore_sys::BNGetEnterpriseServerBuildId()) }
}

pub fn server_token() -> BnString {
    unsafe { BnString::from_raw(binaryninjacore_sys::BNGetEnterpriseServerToken()) }
}

pub fn license_duration() -> Duration {
    Duration::from_secs(unsafe { binaryninjacore_sys::BNGetEnterpriseServerLicenseDuration() })
}

pub fn license_expiration_time() -> SystemTime {
    let m = Duration::from_secs(unsafe {
        binaryninjacore_sys::BNGetEnterpriseServerLicenseExpirationTime()
    });
    UNIX_EPOCH + m
}

pub fn server_reservation_time_limit() -> Duration {
    Duration::from_secs(unsafe { binaryninjacore_sys::BNGetEnterpriseServerReservationTimeLimit() })
}

pub fn is_server_floating_license() -> bool {
    unsafe { binaryninjacore_sys::BNIsEnterpriseServerFloatingLicense() }
}

pub fn is_server_license_still_activated() -> bool {
    unsafe { binaryninjacore_sys::BNIsEnterpriseServerLicenseStillActivated() }
}

pub fn authenticate_server_with_credentials(
    username: impl AsCStr,
    password: impl AsCStr,
    remember: bool,
) -> bool {
    unsafe {
        binaryninjacore_sys::BNAuthenticateEnterpriseServerWithCredentials(
            username.as_cstr().as_ptr(),
            password.as_cstr().as_ptr(),
            remember,
        )
    }
}

pub fn authenticate_server_with_method(method: impl AsCStr, remember: bool) -> bool {
    unsafe {
        binaryninjacore_sys::BNAuthenticateEnterpriseServerWithMethod(
            method.as_cstr().as_ptr(),
            remember,
        )
    }
}

pub fn connect_server() -> bool {
    unsafe { binaryninjacore_sys::BNConnectEnterpriseServer() }
}

pub fn deauthenticate_server() -> bool {
    unsafe { binaryninjacore_sys::BNDeauthenticateEnterpriseServer() }
}

pub fn cancel_server_authentication() {
    unsafe { binaryninjacore_sys::BNCancelEnterpriseServerAuthentication() }
}

pub fn update_server_license(timeout: Duration) -> bool {
    unsafe { binaryninjacore_sys::BNUpdateEnterpriseServerLicense(timeout.as_secs()) }
}

pub fn release_server_license() -> bool {
    unsafe { binaryninjacore_sys::BNReleaseEnterpriseServerLicense() }
}

pub fn is_server_connected() -> bool {
    unsafe { binaryninjacore_sys::BNIsEnterpriseServerConnected() }
}

pub fn is_server_authenticated() -> bool {
    unsafe { binaryninjacore_sys::BNIsEnterpriseServerAuthenticated() }
}

pub fn is_server_initialized() -> bool {
    unsafe { binaryninjacore_sys::BNIsEnterpriseServerInitialized() }
}

pub fn server_last_error() -> BnString {
    unsafe { BnString::from_raw(binaryninjacore_sys::BNGetEnterpriseServerLastError()) }
}

pub fn server_authentication_methods() -> (Array<BnString>, Array<BnString>) {
    let mut methods = core::ptr::null_mut();
    let mut names = core::ptr::null_mut();
    let count = unsafe {
        binaryninjacore_sys::BNGetEnterpriseServerAuthenticationMethods(&mut methods, &mut names)
    };
    unsafe { (Array::new(methods, count, ()), Array::new(names, count, ())) }
}

// NOTE don't implement Clone, Copy, so each callback can only be
// register/unregistered only once
#[repr(transparent)]
#[derive(Debug)]
pub struct EnterpriseServerCallback<'a> {
    handle: binaryninjacore_sys::BNEnterpriseServerCallbacks,
    lifetime: PhantomData<&'a ()>,
}

pub fn register_license_changed_callback<'a, F: FnMut(bool) + 'a>(
    callback: F,
) -> EnterpriseServerCallback<'a> {
    unsafe extern "C" fn cb_license_status_changed<F: FnMut(bool)>(
        ctxt: *mut ::std::os::raw::c_void,
        still_valid: bool,
    ) {
        let ctxt: &mut F = &mut *(ctxt as *mut F);
        ctxt(still_valid)
    }
    let mut handle = binaryninjacore_sys::BNEnterpriseServerCallbacks {
        context: Box::leak(Box::new(callback)) as *mut F as *mut core::ffi::c_void,
        licenseStatusChanged: Some(cb_license_status_changed::<F>),
    };
    unsafe { binaryninjacore_sys::BNRegisterEnterpriseServerNotification(&mut handle) }
    EnterpriseServerCallback {
        handle,
        lifetime: PhantomData,
    }
}

pub fn unregister_license_changed_callback(mut callback_handle: EnterpriseServerCallback) {
    unsafe {
        binaryninjacore_sys::BNUnregisterEnterpriseServerNotification(&mut callback_handle.handle)
    }
}

impl<'a> EnterpriseServerCallback<'a> {
    /// register the license changed callback
    pub fn register<F: FnMut(bool) + 'a>(callback: F) -> Self {
        register_license_changed_callback(callback)
    }

    /// deregister the license changed callback, equivalent to drop the struct
    pub fn deregister(self) {
        // Nothing, just drop self
    }
}

impl Drop for EnterpriseServerCallback<'_> {
    fn drop(&mut self) {
        unregister_license_changed_callback(EnterpriseServerCallback {
            handle: self.handle,
            lifetime: PhantomData,
        })
    }
}
