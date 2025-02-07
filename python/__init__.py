# Copyright (c) 2015-2024 Vector 35 Inc
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

import atexit
import sys
import ctypes
from time import gmtime, struct_time
import os
from typing import Mapping, Optional
import functools

# Binary Ninja components
import binaryninja._binaryninjacore as core
__version__ = core.BNGetVersionString()
import binaryninja
from .enums import *
from .databuffer import *
from .filemetadata import *
from .fileaccessor import *
from .binaryview import *
from .transform import *
from .architecture import *
from .basicblock import *
from .function import *
from .lowlevelil import *
from .mediumlevelil import *
from .highlevelil import *
from .types import *
from .typelibrary import *
from .functionrecognizer import *
from .update import *
from .plugin import *
from .callingconvention import *
from .platform import *
from .demangle import *
from .mainthread import *
from .interaction import *
from .lineardisassembly import *
from .highlight import *
from .scriptingprovider import *
from .downloadprovider import *
from .pluginmanager import *
from .settings import *
from .metadata import *
from .flowgraph import *
from .datarender import *
from .variable import *
from .websocketprovider import *
from .workflow import *
from .commonil import *
from .database import *
from .secretsprovider import *
from .typeparser import *
from .typeprinter import *
from .component import *
from .typearchive import *
from .typecontainer import *
from .exceptions import *
from .project import *
from .basedetection import *
from .debuginfo import *
from .externallibrary import *
from .undo import *
from .fileaccessor import *
from .languagerepresentation import *
from .lineformatter import *
from .renderlayer import *
# We import each of these by name to prevent conflicts between
# log.py and the function 'log' which we don't import below
from .log import (
    redirect_output_to_log, is_output_redirected_to_log, log_debug, log_info, log_warn, log_error, log_alert,
    log_to_stdout, log_to_stderr, log_to_file, close_logs
)
from .log import log as log_at_level
from .deprecation import *
import warnings
# We must alter the filter settings for DeprecatedWarning. Otherwise, it will never show up.
# https://docs.python.org/3/library/warnings.html#default-warning-filter
warnings.filterwarnings('once', '', DeprecatedWarning)

# Only load Enterprise Client support on Ultimate builds
if core.BNGetProduct() == "Binary Ninja Enterprise Client" or core.BNGetProduct() == "Binary Ninja Ultimate":
	from .enterprise import *
	from .firmwareninja import *


def shutdown():
	"""
	``shutdown`` cleanly shuts down the core, stopping all workers and closing all log files.

	.. note:: This will be called automatically on script exit if you import the binaryninja module.
	"""

	# Release license if we have one
	global _enterprise_license_checkout
	_enterprise_license_checkout = None

	core.BNShutdown()


atexit.register(shutdown)


@functools.total_ordering
@dataclass
class CoreVersionInfo:
	"""
	Structure representing the Binary Ninja Version.

	Use :py:func:`core_version_info` to look up the current version of Binary Ninja loaded.
	"""

	major: int
	"""Major version number, e.g. 4.0.5000-dev would be 4"""

	minor: int
	"""Minor version number, e.g. 4.0.5000-dev would be 0"""

	build: int
	"""Build version number, e.g. 4.0.5000-dev would be 5000"""

	channel: str
	"""Release channel name, e.g. "dev" or "Stable" """

	def __init__(self, major, minor = None, build = None, channel = None):
		self.major = 0
		self.minor = 0
		self.build = 0
		self.channel = ""
		if isinstance(major, str) and minor is None and build is None and channel is None:
			core_version_info = core.BNParseVersionString(major)
			self.major = core_version_info.major
			self.minor = core_version_info.minor
			self.build = core_version_info.build
			if core_version_info.channel is not None:
				self.channel = core_version_info.channel
			core.BNFreeString(core_version_info.channel)
		else:
			self.major = major
			if minor is not None:
				self.minor = minor
			if build is not None:
				self.build = build
			self.channel = channel

	def __str__(self):
		if self.channel == "":
			return f"{self.major}.{self.minor}.{self.build}"
		else:
			return f"{self.major}.{self.minor}.{self.build}-{self.channel}"

	def __eq__(self, other):
		if isinstance(other, CoreVersionInfo):
			return self.major == other.major and self.minor == other.minor and self.build == other.build # channel doesn't matter
		if isinstance(other, str):
			return self == CoreVersionInfo(other)
		return False

	def _versionCompare(self, other):
		a = core.BNVersionInfo()
		a.major = self.major
		a.minor = self.minor
		a.build = self.build
		b = core.BNVersionInfo()
		b.major = other.major
		b.minor = other.minor
		b.build = other.build
		return core.BNVersionLessThan(a, b)

	def __lt__(self, other):
		if isinstance(other, CoreVersionInfo):
			return self._versionCompare(other)
		if isinstance(other, str):
			return self._versionCompare(CoreVersionInfo(other))
		return False

def get_unique_identifier():
	"""
	Generate a GUID

	:return: A GUID string
	"""
	return core.BNGetUniqueIdentifierString()


def get_install_directory():
	"""
	``get_install_directory`` returns a string pointing to the installed binary currently running

	.. warning:: ONLY for use within the Binary Ninja UI, behavior is undefined and unreliable if run headlessly
	"""
	return core.BNGetInstallDirectory()


class _DestructionCallbackHandler:
	def __init__(self):
		self._cb = core.BNObjectDestructionCallbacks()
		self._cb.context = 0
		self._cb.destructBinaryView = self._cb.destructBinaryView.__class__(self.destruct_binary_view)
		self._cb.destructFileMetadata = self._cb.destructFileMetadata.__class__(self.destruct_file_metadata)
		self._cb.destructFunction = self._cb.destructFunction.__class__(self.destruct_function)
		core.BNRegisterObjectDestructionCallbacks(self._cb)

	def destruct_binary_view(self, ctxt, view):
		binaryninja.binaryview.BinaryView._unregister(view)

	def destruct_file_metadata(self, ctxt, f):
		binaryninja.filemetadata.FileMetadata._unregister(f)

	def destruct_function(self, ctxt, func):
		binaryninja.function.Function._unregister(func)


_enable_default_log = True
_plugin_init = False
_enterprise_license_checkout = None


def _init_plugins():
	global _enable_default_log
	global _plugin_init
	global _enterprise_license_checkout

	if not _plugin_init:
		if not core_ui_enabled() and (core.BNGetProduct() == "Binary Ninja Enterprise Client" or core.BNGetProduct() == "Binary Ninja Ultimate"):
			# Enterprise client needs to reserve a license or else BNInitPlugins will fail
			_enterprise_license_checkout = enterprise.LicenseCheckout()
			_enterprise_license_checkout.acquire()

		# The first call to BNInitCorePlugins returns True for successful initialization and True in this context indicates headless operation.
		# The result is pulled from BNInitPlugins as that now wraps BNInitCorePlugins.
		is_headless_init_once = core.BNInitPlugins(not os.environ.get('BN_DISABLE_USER_PLUGINS'))
		min_level = Settings().get_string("python.log.minLevel")
		if _enable_default_log and is_headless_init_once and min_level in LogLevel.__members__ and not core_ui_enabled(
		) and sys.stderr.isatty():
			log_to_stderr(LogLevel[min_level])
		core.BNInitRepoPlugins()
	if core.BNIsLicenseValidated():
		_plugin_init = True
	else:
		raise RuntimeError("License is not valid. Please supply a valid license.")


_destruct_callbacks = _DestructionCallbackHandler()


def disable_default_log() -> None:
	'''Disable default logging in headless mode for the current session. By default, logging in headless operation is controlled by the 'python.log.minLevel' settings.'''
	global _enable_default_log
	_enable_default_log = False
	close_logs()


def bundled_plugin_path() -> Optional[str]:
	"""
		``bundled_plugin_path`` returns a string containing the current plugin path inside the `install path <https://docs.binary.ninja/guide/#binary-path>`_

		:return: current bundled plugin path
		:rtype: str, or None on failure
	"""
	return core.BNGetBundledPluginDirectory()


def user_plugin_path() -> Optional[str]:
	"""
		``user_plugin_path`` returns a string containing the current plugin path inside the `user directory <https://docs.binary.ninja/guide/#user-folder>`_

		:return: current user plugin path
		:rtype: str, or None on failure
	"""
	return core.BNGetUserPluginDirectory()


def user_directory() -> Optional[str]:
	"""
		``user_directory`` returns a string containing the path to the `user directory <https://docs.binary.ninja/guide/#user-folder>`_

		:return: current user path
		:rtype: str, or None on failure
	"""
	return core.BNGetUserDirectory()


def core_version() -> Optional[str]:
	"""
		``core_version`` returns a string containing the current version

		:return: current version
		:rtype: str, or None on failure
	"""
	return core.BNGetVersionString()

def core_version_info() -> CoreVersionInfo:
	"""
		``core_version_info`` returns a CoreVersionInfo containing the current version information

		:return: current version information
		:rtype: CoreVersionInfo
	"""
	handle = core.BNGetVersionInfo()
	return CoreVersionInfo(major=handle.major, minor=handle.minor, build=handle.build, channel=handle.channel)

def core_build_id() -> int:
	"""
		``core_build_id`` returns a integer containing the current build id

		:return: current build id
		:rtype: int
	"""
	return core.BNGetBuildId()


def core_serial() -> Optional[str]:
	"""
		``core_serial`` returns a string containing the current serial number

		:return: current serial
		:rtype: str, or None on failure
	"""
	return core.BNGetSerialNumber()


def core_expires() -> struct_time:
	'''License Expiration'''
	return gmtime(core.BNGetLicenseExpirationTime())


def core_product() -> Optional[str]:
	'''Product string from the license file'''
	return core.BNGetProduct()


def core_product_type() -> Optional[str]:
	'''Product type from the license file'''
	return core.BNGetProductType()


def core_license_count() -> int:
	'''License count from the license file'''
	return core.BNGetLicenseCount()


def core_ui_enabled() -> bool:
	'''Indicates that a UI exists and the UI has invoked BNInitUI'''
	return core.BNIsUIEnabled()


def core_set_license(licenseData: str) -> None:
	'''
		``core_set_license`` is used to initialize the core with a license file that doesn't necessarily reside on a file system. This is especially useful for headless environments such as docker where loading the license file via an environment variable allows for greater security of the license file itself.

		:param str licenseData: string containing the full contents of a license file
		:rtype: None
		:Example:

			>>> import os
			>>> core_set_license(os.environ['BNLICENSE']) #Do this before creating any BinaryViews
			>>> with load("/bin/ls") as bv:
			...		print(len(list(bv.functions)))
			128
	'''
	core.BNSetLicense(licenseData)


def get_memory_usage_info() -> Mapping[str, int]:
	"""
	Get counts of various Binary Ninja objects in memory.

	:return: Dictionary of {class name: count} for objects in memory
	"""
	count = ctypes.c_ulonglong()
	info = core.BNGetMemoryUsageInfo(count)
	assert info is not None, "core.BNGetMemoryUsageInfo returned None"
	result = {}
	for i in range(0, count.value):
		result[info[i].name] = info[i].value
	core.BNFreeMemoryUsageInfo(info, count.value)
	return result


def load(*args, **kwargs) -> BinaryView:
	"""
	Opens a BinaryView object.

	:param Union[str, bytes, bytearray, 'databuffer.DataBuffer', 'os.PathLike'] source: a file or byte stream to load into a virtual memory space
	:param bool update_analysis: whether or not to run :func:`update_analysis_and_wait` after opening a :py:class:`BinaryView`, defaults to ``True``
	:param callback progress_func: optional function to be called with the current progress and total count for BNDB files only
	:param dict options: a dictionary in the form {setting identifier string : object value}
	:return: returns a :py:class:`BinaryView` object for the given filename
	:rtype: :py:class:`BinaryView`
	:raises Exception: When a BinaryView could not be created

	.. note:: The progress_func callback **must** return True to continue the load operation, False will abort the load operation.

	.. warning:: The progress_func will **only** be called for BNDB files, not for any other file format due to a `design limitation <https://docs.binary.ninja/guide/debugger/index.html#navigating-the-binary>`_.

	:Example:
		>>> from binaryninja import *
		>>> with load("/bin/ls") as bv:
		...     print(len(list(bv.functions)))
		...
		134

		>>> with load(bytes.fromhex('5054ebfe'), options={'loader.platform' : 'x86'}) as bv:
		...     print(len(list(bv.functions)))
		...
		1
	"""
	bv = BinaryView.load(*args, **kwargs)
	if bv is None:
		raise Exception("Unable to create new BinaryView")
	return bv


def connect_pycharm_debugger(port=5678):
	"""
	Connect to PyCharm (Professional Edition) for debugging.

	.. note:: See the `user documentation <https://docs.binary.ninja/dev/plugins.html#remote-debugging-with-intellij-pycharm>`_ for step-by-step instructions on how to set up Python debugging.

	:param port: Port number for connecting to the debugger.
	"""
	# Get pip install string from PyCharm's Python Debug Server Configuration
	# e.g. for PyCharm 2021.1.1 #PY-7142.13:
	# pip install --user pydevd-pycharm~=211.7142.13
	import pydevd_pycharm  # type: ignore
	pydevd_pycharm.settrace('localhost', port=port, stdoutToServer=True, stderrToServer=True, suspend=False)


def connect_vscode_debugger(port=5678):
	"""
	Connect to Visual Studio Code for debugging. This function blocks until the debugger
	is connected! Not recommended for use in startup.py

	.. note:: See the `user documentation <https://docs.binary.ninja/dev/plugins.html#remote-debugging-with-vscode>`_ for step-by-step instructions on how to set up Python debugging.

	:param port: Port number for connecting to the debugger.
	"""
	# pip install --user debugpy
	import debugpy  # type: ignore
	import sys
	if sys.platform == "win32":
		debugpy.configure(python=f"{sys.base_exec_prefix}/python", qt="pyside2")
	else:
		debugpy.configure(python=f"{sys.base_exec_prefix}/bin/python3", qt="pyside2")
	debugpy.listen(("127.0.0.1", port))
	debugpy.wait_for_client()
	execute_on_main_thread(lambda: debugpy.debug_this_thread())


class UIPluginInHeadlessError(Exception):
	"""
	Error thrown when trying to load a UI plugin in a headless Binary Ninja installation.
	"""
	def __init__(self, *args, **kwargs):
		Exception.__init__(self, *args, **kwargs)


def fuzzy_match_single(target, query) -> Optional[int]:
	"""
	Fuzzy match a string against a query string. Returns a score that is higher for
	a more confident match, or None if the query does not match the target string.

	:param target: Target (larger) string
	:param query: Query (smaller) string
	:return: Confidence of match, or None if the string doesn't match
	"""
	result = core.BNFuzzyMatchSingle(target, query)
	if result == 0:
		return None
	return result


# Load Collaboration scripts from Ultimate (they are bundled in shipping builds)
try:
	from . import collaboration
except ImportError:
	pass
