use crate::rc::Array;
use crate::string::{BnStrCompatible, BnString};
use std::marker::PhantomData;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EnterpriseCheckoutError {
    #[error("enterprise server returned error: {0}")]
    ServerError(String),
    #[error("no username set for credential authentication")]
    NoUsername,
    #[error("no password set for credential authentication")]
    NoPassword,
    #[error("failed to authenticate with username and password")]
    NotAuthenticated,
    #[error("failed to refresh expired license")]
    RefreshExpiredLicenseFailed,
}

/// Initialize the enterprise server connection to check out a floating license.
pub fn checkout_license(duration: Duration) -> Result<(), EnterpriseCheckoutError> {
    if crate::is_ui_enabled() {
        // We only need to check out a license if running headlessly.
        return Ok(());
    }

    #[allow(clippy::collapsible_if)]
    if !is_server_initialized() {
        // We need to first initialize the server.
        if !initialize_server() && is_server_floating_license() {
            let last_error = server_last_error().to_string();
            return Err(EnterpriseCheckoutError::ServerError(last_error));
        }
    }

    if is_server_floating_license() {
        if !is_server_connected() && !connect_server() {
            let last_error = server_last_error().to_string();
            return Err(EnterpriseCheckoutError::ServerError(last_error));
        }

        #[allow(clippy::collapsible_if)]
        if !is_server_authenticated() {
            // We have yet to authenticate with the server, we should try all available authentication methods.
            if !authenticate_server_with_method("Keychain", false) {
                // We could not authenticate with the system keychain, we should try with credentials.
                let username = std::env::var("BN_ENTERPRISE_USERNAME")
                    .map_err(|_| EnterpriseCheckoutError::NoUsername)?;
                let password = std::env::var("BN_ENTERPRISE_PASSWORD")
                    .map_err(|_| EnterpriseCheckoutError::NoPassword)?;
                if !authenticate_server_with_credentials(username, password, true) {
                    return Err(EnterpriseCheckoutError::NotAuthenticated);
                }
            }
        }
    }

    #[allow(clippy::collapsible_if)]
    if !is_server_license_still_activated()
        || (!is_server_floating_license() && crate::license_expiration_time() < SystemTime::now())
    {
        // If the license is expired we should refresh the license.
        if !update_server_license(duration) {
            return Err(EnterpriseCheckoutError::RefreshExpiredLicenseFailed);
        }
    }

    Ok(())
}

pub fn release_license() {
    if !crate::is_ui_enabled() {
        // This might look dumb, why would we want to connect to the server, would that not just mean
        // we don't need to release the license? Well no, you could have run a script, acquired a license for 10 hours
        // then you WOULD want to call release license, and your expectation is that acquired license
        // will now be released. To release that you must have an active connection which is what this does.
        if !is_server_initialized() {
            initialize_server();
        }
        if !is_server_connected() {
            connect_server();
        }
        // We should only release the license if we are running headlessly.
        release_server_license();
    }
}

// TODO: If "" string return None
pub fn server_username() -> BnString {
    unsafe { BnString::from_raw(binaryninjacore_sys::BNGetEnterpriseServerUsername()) }
}

// TODO: If "" string return None
pub fn server_url() -> BnString {
    unsafe { BnString::from_raw(binaryninjacore_sys::BNGetEnterpriseServerUrl()) }
}

pub fn set_server_url<S: BnStrCompatible>(url: S) -> Result<(), ()> {
    let url = url.into_bytes_with_nul();
    let result = unsafe {
        binaryninjacore_sys::BNSetEnterpriseServerUrl(
            url.as_ref().as_ptr() as *const std::os::raw::c_char
        )
    };
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

pub fn authenticate_server_with_credentials<U, P>(username: U, password: P, remember: bool) -> bool
where
    U: BnStrCompatible,
    P: BnStrCompatible,
{
    let username = username.into_bytes_with_nul();
    let password = password.into_bytes_with_nul();
    unsafe {
        binaryninjacore_sys::BNAuthenticateEnterpriseServerWithCredentials(
            username.as_ref().as_ptr() as *const std::os::raw::c_char,
            password.as_ref().as_ptr() as *const std::os::raw::c_char,
            remember,
        )
    }
}

pub fn authenticate_server_with_method<S: BnStrCompatible>(method: S, remember: bool) -> bool {
    let method = method.into_bytes_with_nul();
    unsafe {
        binaryninjacore_sys::BNAuthenticateEnterpriseServerWithMethod(
            method.as_ref().as_ptr() as *const std::os::raw::c_char,
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

pub fn initialize_server() -> bool {
    unsafe { binaryninjacore_sys::BNInitializeEnterpriseServer() }
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
