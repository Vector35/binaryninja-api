"""
.. note: This module is only available in the Ultimate edition of Binary Ninja.
"""

import ctypes
import os
from time import gmtime
from typing import Tuple, List, Optional

import binaryninja._binaryninjacore as core
import binaryninja

from . import decorators
from . import deprecation

if core.BNGetProduct() != "Binary Ninja Enterprise Client" and core.BNGetProduct() != "Binary Ninja Ultimate":
	# None of these functions exist on other builds, so just raise here to notify anyone who tries to use this
	raise RuntimeError("Binary Ninja Enterprise client functionality requires the Binary Ninja Ultimate edition.")


def is_initialized() -> bool:
	"""
	Determine if the Enterprise Client has been initialized yet.

	:return: True if :py:func:`initialize` has been called
	"""
	return core.BNIsEnterpriseServerInitialized()


def initialize():
	"""
	Initialize the Enterprise Client
	"""
	if not core.BNInitializeEnterpriseServer():
		raise RuntimeError(last_error())


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
	if not is_connected():
		connect()
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
	if not is_connected():
		connect()
	if not core.BNAuthenticateEnterpriseServerWithMethod(method, remember):
		raise RuntimeError(last_error())


def authentication_methods() -> List[Tuple[str, str]]:
	"""
	Get a list of authentication methods accepted by the Enterprise Server.

	:return: List of (<method name>, <method display name>) tuples
	"""
	if not is_connected():
		connect()
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
	if not is_connected():
		raise RuntimeError("Not connected but calling deauthenticate. This is likely an error in your script!")
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
	if value is None:
		raise RuntimeError(last_error())
	return value


def token() -> Optional[str]:
	"""
	Get the token of the currently authenticated user to the Enterprise Server.

	:return: Token, if authenticated. None, otherwise.
	"""
	value = core.BNGetEnterpriseServerToken()
	if value is None:
		raise RuntimeError(last_error())
	return value


def server_url() -> str:
	"""
	Get the url of the Enterprise Server.

	:return: The current url
	"""
	value = core.BNGetEnterpriseServerUrl()
	if value is None:
		raise RuntimeError(last_error())
	return value


def set_server_url(url: str):
	"""
	Set the url of the Enterprise Server.

	.. note:: This will raise an Exception if the server is already initialized

	:param url: New Enterprise Server url
	"""
	if not core.BNSetEnterpriseServerUrl(url):
		raise RuntimeError(last_error())


def server_name() -> str:
	"""
	Get the display name of the server

	:return: Display name of the server
	"""
	if not is_connected():
		connect()
	value = core.BNGetEnterpriseServerName()
	if value is None:
		raise RuntimeError(last_error())
	return value


def server_id() -> str:
	"""
	Get the internal id of the server

	:return: Id of the server
	"""
	if not is_connected():
		connect()
	value = core.BNGetEnterpriseServerId()
	if value is None:
		raise RuntimeError(last_error())
	return value


def server_version() -> int:
	"""
	Get the version number of the server

	:return: Version of the server
	"""
	if not is_connected():
		connect()
	value = core.BNGetEnterpriseServerVersion()
	if value == 0:
		raise RuntimeError(last_error())
	return value


def server_build_id() -> str:
	"""
	Get the build id string of the server

	:return: Build id of the server
	"""
	if not is_connected():
		connect()
	value = core.BNGetEnterpriseServerBuildId()
	if value is None:
		raise RuntimeError(last_error())
	return value


def reservation_time_limit() -> int:
	"""
	Get the maximum checkout duration allowed by the Enterprise Server.

	.. note:: You must authenticate with the Enterprise Server before calling this.

	:return: Duration, in seconds, of the maximum time you are allowed to checkout a license.
	"""
	return core.BNGetEnterpriseServerReservationTimeLimit()


def update_license(duration, _cache=True):
	"""
	Acquire or refresh a floating license from the Enterprise server.

	.. note:: You must authenticate with the Enterprise server before calling this.

	:param int duration: Desired length of license checkout, in seconds.
	:param bool _cache: Deprecated but left in for compatibility
	"""
	if not core.BNUpdateEnterpriseServerLicense(duration):
		raise RuntimeError(last_error())


def release_license():
	"""
	Release the currently checked out license back to the Enterprise Server.

	.. note:: You must authenticate with the Enterprise Server before calling this.

	.. note:: This will deactivate the Binary Ninja Enterprise client. You must call :func:`acquire_license` \
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


def is_floating_license() -> bool:
	"""
	Determine if a floating license is currently active

	:return: True if a floating license is active
	"""
	return core.BNIsEnterpriseServerFloatingLicense()


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


@decorators.enterprise
class LicenseCheckout:
	"""
	Helper class for scripts to make use of a license checkout in a scope.

	:param duration: Duration between refreshes
	:param _cache: Deprecated but left in for compatibility
	:param release: If the license should be released at the end of scope. If `False`, you
					can either manually release it later or it will expire after `duration`.

	:Example:
		>>> enterprise.connect()
		>>> enterprise.authenticate_with_credentials("username", "password")
		>>> with enterprise.LicenseCheckout():
		... 	# Do some operation
		... 	with load("/bin/ls") as bv: # e.g.
		... 		print(hex(bv.start))
		# License is released at end of scope
	"""
	def __init__(self, duration=900, _cache=True, release=True):
		"""
		Get a new license checkout

		:param duration: Duration between refreshes
		:param _cache: Deprecated but left in for compatibility
		:param release: If the license should be released at the end of scope. If `False`, you
		                can either manually release it later or it will expire after `duration`.
		"""
		self.desired_duration = duration
		self.acquired_license = False
		self.desired_release = release

	def __del__(self):
		self.release()

	def __enter__(self) -> None:
		self.acquire()

	def __exit__(self, exc_type, exc_val, exc_tb):
		self.release()

	def acquire(self):
		# UI builds have their own license manager
		if binaryninja.core_ui_enabled():
			return
		if not is_initialized():
			try:
				initialize()
			except:
				# Named/computer licenses don't need this flow at all
				if not is_floating_license():
					return
				# Floating licenses though, this is an error. Probably the error
				# for needing to set enterprise.server.url in settings.json
				raise
		if not is_floating_license():
			return
		if not is_connected():
			connect()
		got_auth = False
		if not is_authenticated():
			try:
				# Try Keychain
				authenticate_with_method("Keychain", False)
				got_auth = True
			except RuntimeError:
				pass

			if not got_auth and \
				os.environ.get('BN_ENTERPRISE_USERNAME') is not None and \
				os.environ.get('BN_ENTERPRISE_PASSWORD') is not None:
				try:
					authenticate_with_credentials(os.environ['BN_ENTERPRISE_USERNAME'], os.environ['BN_ENTERPRISE_PASSWORD'])
					got_auth = True
				except RuntimeError:
					pass

			if not got_auth:
				raise RuntimeError(
					"Could not checkout a license: Not authenticated. Try one of the following: \n"
					" - Log in and check out a license for an extended time\n"
					" - Set BN_ENTERPRISE_USERNAME and BN_ENTERPRISE_PASSWORD environment variables\n"
					" - Use binaryninja.enterprise.authenticate_with_credentials or authenticate_with_method in your code"
				)

		# Keychain auth can activate a license if we have one in the keychain
		# If we have an expired named license, try to get a fresh floating one
		if not is_license_still_activated() or (not is_floating_license() and binaryninja.core_expires() < gmtime()):
			update_license(self.desired_duration)
			self.acquired_license = True

	def release(self):
		# UI builds have their own license manager
		if binaryninja.core_ui_enabled():
			return
		# Don't release if we got one from keychain
		if self.acquired_license and self.desired_release:
			release_license()
			self.acquired_license = False
