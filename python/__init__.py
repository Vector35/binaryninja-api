# Copyright (c) 2015-2016 Vector 35 LLC
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


def shutdown():
	"""
	``shutdown`` cleanly shuts down the core, stopping all workers and closing all log files.
	"""
	core.BNShutdown()


def get_unique_identifier():
	return core.BNGetUniqueIdentifierString()


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

core_product = core.BNGetProduct()
'''Product string from the license file'''

core_product_type = core.BNGetProductType()
'''Product type from the license file'''

core_license_count = core.BNGetLicenseCount()
'''License count from the license file'''
