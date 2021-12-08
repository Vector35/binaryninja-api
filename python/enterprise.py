import ctypes
from typing import Tuple, List, Optional

import binaryninja._binaryninjacore as core
import binaryninja

if core.BNGetProduct() != "Binary Ninja Enterprise Client":
	# None of these functions exist on other builds, so just raise here to notify anyone who tries to use this
	raise RuntimeError("Cannot use Binary Ninja Enterprise client functionality with a non-Enterprise client.")


def connect():
	"""
	Connect to the Enterprise Server.
	"""
	if not core.BNConnectEnterpriseServer():
		raise RuntimeError(last_error())


def is_connected() -> bool:
	"""
	Determine if the Enterprise Server is currently connected.
	:return: True if connected
	"""
	return core.BNIsEnterpriseServerConnected()


def authenticate_with_credentials(username: str, password: str, remember: bool = True):
	"""
	Authenticate to the Enterprise Server with username/password credentials.
	:param str username: Username to use.
	:param str password: Password to use.
	:param bool remember: Remember token in keychain
	"""
	if not core.BNAuthenticateEnterpriseServerWithCredentials(username, password, remember):
		raise RuntimeError(last_error())


def authenticate_with_method(method: str, remember: bool = True):
	"""
	Authenticate to the Enterprise Server with a non-password method. Note that many of these will
	open a URL for a browser-based login prompt, which may not be usable on headless installations.
	See :func:`authentication_methods` for a list of accepted methods.
	:param str method: Name of method to use.
	:param bool remember: Remember token in keychain
	"""
	if not core.BNAuthenticateEnterpriseServerWithMethod(method, remember):
		raise RuntimeError(last_error())


def authentication_methods() -> List[Tuple[str, str]]:
	"""
	Get a list of authentication methods accepted by the Enterprise Server.
	:return: List of (<method name>, <method display name>) tuples
	"""
	methods = ctypes.POINTER(ctypes.c_char_p)()
	names = ctypes.POINTER(ctypes.c_char_p)()
	count = core.BNGetEnterpriseServerAuthenticationMethods(methods, names)
	results = []
	for i in range(count):
		results.append((core.pyNativeStr(methods[i]), core.pyNativeStr(names[i])))
	core.BNFreeStringList(methods, count)
	core.BNFreeStringList(names, count)
	return results


def deauthenticate():
	"""
	Deauthenticate from the Enterprise server, clearing any cached credentials.
	"""
	if not core.BNDeauthenticateEnterpriseServer():
		raise RuntimeError(last_error())


def cancel_authentication():
	"""
	Cancel a call to :func:`authenticate_with_credentials` or :func:`authenticate_with_method`.
	Note those functions are blocking, so this must be called on a separate thread.
	"""
	core.BNCancelEnterpriseServerAuthentication()


def is_authenticated() -> bool:
	"""
	Determine if you have authenticated to the Enterprise Server.
	:return: True if you are authenticated
	"""
	return core.BNIsEnterpriseServerAuthenticated()


def username() -> Optional[str]:
	"""
	Get the username of the currently authenticated user to the Enterprise Server.
	:return: Username, if authenticated. None, otherwise.
	"""
	value = core.BNGetEnterpriseServerUsername()
	if value == "":
		return None
	return value


def server_name() -> Optional[str]:
	"""
	Get the display name of the currently connected server
	:return: Display name of the currently connected server, if connected. None, otherwise
	"""
	value = core.BNGetEnterpriseServerName()
	if value == "":
		return None
	return value


def server_id() -> Optional[str]:
	"""
	Get the internal id of the currently connected server
	:return: Id of the currently connected server, if connected. None, otherwise
	"""
	value = core.BNGetEnterpriseServerId()
	if value == "":
		return None
	return value


def server_version() -> Optional[int]:
	"""
	Get the version number of the currently connected server
	:return: Version of the currently connected server, if connected. None, otherwise
	"""
	value = core.BNGetEnterpriseServerVersion()
	if value == 0:
		return None
	return value


def server_build_id() -> Optional[str]:
	"""
	Get the build id string of the currently connected server
	:return: Build id of the currently connected server, if connected. None, otherwise
	"""
	value = core.BNGetEnterpriseServerBuildId()
	if value == "":
		return None
	return value


def reservation_time_limit() -> int:
	"""
	Get the maximum checkout duration allowed by the Enterprise Server.
	.. note:: You must authenticate with the Enterprise Server before calling this.

	:return: Duration, in seconds, of the maximum time you are allowed to checkout a license.
	"""
	return core.BNGetEnterpriseServerReservationTimeLimit()


def acquire_license(duration, cache=False):
	"""
	Check out and activate a license from the Enterprise Server.
	If ``cache`` is True, the checkout will be saved to a local secrets storage. This is platform-dependent:
	- macOS: Saved to the user's keychain
	- Windows: Saved to the credential store
	- Linux: Saved with dbus's Secret Service API

	.. note:: You must authenticate with the Enterprise Server before calling this.

	.. warning:: If ``cache`` is False, you must remember to call :func:`release_license` before the process
	exits to release the uncached license back to the server. If you forget to do so, you will
	have to either wait for the checkout to expire or have an administrator revoke the checkout.

	:param int duration: Desired length of license checkout, in seconds.
	:param bool cache: If true, the license will be saved to a local secrets storage.
	"""
	if not core.BNAcquireEnterpriseServerLicense(duration, cache):
		raise RuntimeError(last_error())


def release_license():
	"""
	Release the currently checked out license back to the Enterprise Server.

	.. note:: You must authenticate with the Enterprise Server before calling this.

	.. note:: This will deactivate the Binary Ninja Enterprise client. You must call :func:`acquire_license`
	again to continue using Binary Ninja Enterprise in the current process.
	"""
	if not core.BNReleaseEnterpriseServerLicense():
		raise RuntimeError(last_error())


def license_expiration_time() -> int:
	"""
	Get the expiry time of the current license checkout.
	:return: Expiry time as a Unix epoch, or 0 if no license is checked out.
	"""
	return core.BNGetEnterpriseServerLicenseExpirationTime()


def license_duration() -> int:
	"""
	Get the duration of the current license checkout.
	:return: Duration, in seconds, of the total time of the current checkout.
	"""
	return core.BNGetEnterpriseServerLicenseDuration()


def is_license_still_activated() -> bool:
	"""
	Determine if your current license checkout is still valid.
	:return: True if your current checkout is still valid.
	"""
	return core.BNIsEnterpriseServerLicenseStillActivated()


def last_error() -> str:
	"""
	Get a text representation the last error encountered by the Enterprise Client
	:return: Last error message, or empty string if there is none.
	"""
	return core.BNGetEnterpriseServerLastError()


class LicenseCheckout:
	"""
	Helper class for scripts to make use of a license checkout in a scope.

	:Example:
		enterprise.connect()
		enterprise.authenticate_with_credentials("username", "password")
		with enterprise.LicenseCheckout():
			# Do some operation
			with open_view("/bin/ls") as bv: # e.g.
				print(hex(bv.start))
		# License is released at end of scope

	"""

	def __init__(self, duration=900, cache=False):
		self.desired_duration = duration
		self.desired_cache = cache

	def __enter__(self):
		# UI builds have their own license manager
		if binaryninja.core_ui_enabled():
			return
		if not is_connected():
			connect()
		if not is_authenticated():
			raise RuntimeError(
				"Could not checkout a license: Not authenticated. "
				"Please use binaryninja.enterprise.authenticate_with_credentials or authenticate_with_method first!")
		acquire_license(self.desired_duration, self.desired_cache)

	def __exit__(self, exc_type, exc_val, exc_tb):
		# UI builds have their own license manager
		if binaryninja.core_ui_enabled():
			return
		release_license()
