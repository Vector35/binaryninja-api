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

import traceback

# Binary Ninja components
import _binaryninjacore as core
import function
import filemetadata
import binaryview
import lowlevelil
import log


class FunctionRecognizer(object):
	_instance = None

	def __init__(self):
		self._cb = core.BNFunctionRecognizer()
		self._cb.context = 0
		self._cb.recognizeLowLevelIL = self._cb.recognizeLowLevelIL.__class__(self._recognize_low_level_il)

	@classmethod
	def register_global(cls):
		if cls._instance is None:
			cls._instance = cls()
		core.BNRegisterGlobalFunctionRecognizer(cls._instance._cb)

	@classmethod
	def register_arch(cls, arch):
		if cls._instance is None:
			cls._instance = cls()
		core.BNRegisterArchitectureFunctionRecognizer(arch.handle, cls._instance._cb)

	def _recognize_low_level_il(self, ctxt, data, func, il):
		try:
			file_metadata = filemetadata.FileMetadata(handle = core.BNGetFileForView(data))
			view = binaryview.BinaryView(file_metadata = file_metadata, handle = core.BNNewViewReference(data))
			func = function.Function(view, handle = core.BNNewFunctionReference(func))
			il = lowlevelil.LowLevelILFunction(func.arch, handle = core.BNNewLowLevelILFunctionReference(il))
			return self.recognize_low_level_il(view, func, il)
		except:
			log.log_error(traceback.format_exc())
			return False

	def recognize_low_level_il(self, data, func, il):
		return False
