# Copyright (c) 2015-2017 Vector 35 LLC
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
from time import gmtime

# Binary Ninja components
import _binaryninjacore as core
from .enums import *
from .databuffer import *
from .filemetadata import *
from .fileaccessor import *
from .binaryview import *
from .transform import *
from .architecture import *
from .basicblock import *
from .function import *
from .log import *
from .lowlevelil import *
from .mediumlevelil import *
from .types import *
from .functionrecognizer import *
from .update import *
from .plugin import *
from .callingconvention import *
from .platform import *
from .demangle import *
from .mainthread import *
from .interaction import *
from .lineardisassembly import *
from .undoaction import *
from .highlight import *
from .scriptingprovider import *
from .downloadprovider import *
from .pluginmanager import *
from .setting import *
from .metadata import *


def shutdown():
	"""
	``shutdown`` cleanly shuts down the core, stopping all workers and closing all log files.
	"""
	core.BNShutdown()


atexit.register(shutdown)


def get_unique_identifier():
	return core.BNGetUniqueIdentifierString()


def get_install_directory():
	"""
	``get_install_directory`` returns a string pointing to the installed binary currently running

	..warning:: ONLY for use within the Binary Ninja UI, behavior is undefined and unreliable if run headlessly
	"""
	return core.BNGetInstallDirectory()


_plugin_api_name = "python2"


class PluginManagerLoadPluginCallback(object):
	"""Callback for BNLoadPluginForApi("python2", ...), dynamicly loads python plugins."""
	def __init__(self):
		self.cb = ctypes.CFUNCTYPE(
			ctypes.c_bool,
			ctypes.c_char_p,
			ctypes.c_char_p,
			ctypes.c_void_p)(self._load_plugin)

	def _load_plugin(self, repo_path, plugin_path, ctx):
		try:
			repo = RepositoryManager()[repo_path]
			plugin = repo[plugin_path]

			if plugin.api != _plugin_api_name:
				raise ValueError("Plugin api name is not " + _plugin_api_name)

			if not plugin.installed:
				plugin.installed = True

			if repo.full_path not in sys.path:
				sys.path.append(repo.full_path)

			__import__(plugin.path)
			log_info("Successfully loaded plugin: {}/{}: ".format(repo_path, plugin_path))
			return True
		except KeyError:
			log_error("Failed to find python plugin: {}/{}".format(repo_path, plugin_path))
		except ImportError as ie:
			log_error("Failed to import python plugin: {}/{}: {}".format(repo_path, plugin_path, ie))
		return False


load_plugin = PluginManagerLoadPluginCallback()
core.BNRegisterForPluginLoading(_plugin_api_name, load_plugin.cb, 0)


class _DestructionCallbackHandler(object):
	def __init__(self):
		self._cb = core.BNObjectDestructionCallbacks()
		self._cb.context = 0
		self._cb.destructBinaryView = self._cb.destructBinaryView.__class__(self.destruct_binary_view)
		self._cb.destructFileMetadata = self._cb.destructFileMetadata.__class__(self.destruct_file_metadata)
		self._cb.destructFunction = self._cb.destructFunction.__class__(self.destruct_function)
		core.BNRegisterObjectDestructionCallbacks(self._cb)

	def destruct_binary_view(self, ctxt, view):
		BinaryView._unregister(view)

	def destruct_file_metadata(self, ctxt, f):
		FileMetadata._unregister(f)

	def destruct_function(self, ctxt, func):
		Function._unregister(func)


_destruct_callbacks = _DestructionCallbackHandler()

bundled_plugin_path = core.BNGetBundledPluginDirectory()
user_plugin_path = core.BNGetUserPluginDirectory()

core_version = core.BNGetVersionString()
'''Core version'''

core_build_id = core.BNGetBuildId()
'''Build ID'''

core_serial = core.BNGetSerialNumber()
'''Serial Number'''

core_expires = gmtime(core.BNGetLicenseExpirationTime())
'''License Expiration'''

core_product = core.BNGetProduct()
'''Product string from the license file'''

core_product_type = core.BNGetProductType()
'''Product type from the license file'''

core_license_count = core.BNGetLicenseCount()
'''License count from the license file'''
