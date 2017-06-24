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

import ctypes

# Binary Ninja components
import _binaryninjacore as core


class Setting(object):
	def __init__(self, plugin_name="core"):
		self.plugin_name = plugin_name

	def get_bool(self, name, default_value=False):
		return core.BNSettingGetBool(self.plugin_name, name, default_value)

	def get_integer(self, name, default_value=0):
		return core.BNSettingGetInteger(self.plugin_name, name, default_value)

	def get_string(self, name, default_value=""):
		return core.BNSettingGetString(self.plugin_name, name, default_value)

	def get_integer_list(self, name):
		length = ctypes.c_ulonglong()
		length.value = 0
		default_list = ctypes.POINTER(ctypes.c_ulonglong)()
		result = core.BNSettingGetIntegerList(self.plugin_name, name, default_list, ctypes.byref(length))
		out_list = []
		for i in xrange(length.value):
			out_list.append(result[i])
		core.BNFreeSettingIntegerList(result, length)
		return out_list

	def get_string_list(self, name):
		length = ctypes.c_ulonglong()
		length.value = 0
		default_list = ctypes.POINTER(ctypes.c_char_p)()
		result = core.BNSettingGetStringList(self.plugin_name, name, default_list, ctypes.byref(length))
		out_list = []
		for i in xrange(length.value):
			out_list.append(result[i])
		core.BNFreeSettingStringList(result, length)
		return out_list

	def get_double(self, name, default_value=0.0):
		return core.BNSettingGetDouble(self.plugin_name, name, default_value)

	def is_bool(self, name):
		return core.BNSettingIsBool(self.plugin_name, name)

	def is_integer(self, name):
		return core.BNSettingIsInteger(self.plugin_name, name)

	def is_string(self, name):
		return core.BNSettingIsString(self.plugin_name, name)

	def is_string_list(self, name):
		return core.BNSettingIsStringList(self.plugin_name, name)

	def is_integer_list(self, name):
		return core.BNSettingIsIntegerList(self.plugin_name, name)

	def is_double(self, name):
		return core.BNSettingIsDouble(self.plugin_name, name)

	def is_present(self, name):
		return core.BNSettingIsPresent(self.plugin_name, name)

	def set_bool(self, name, value, auto_flush=True):
		return core.BNSettingSetBool(self.plugin_name, name, value, auto_flush)

	def set_integer(self, name, value, auto_flush=True):
		return core.BNSettingSetInteger(self.plugin_name, name, value, auto_flush)

	def set_string(self, name, value, auto_flush=True):
		return core.BNSettingSetString(self.plugin_name, name, value, auto_flush)

	def set_integerList(self, name, value, auto_flush=True):
		length = ctypes.c_ulonglong()
		length.value = len(value)
		default_list = (ctypes.c_ulonglong * len(value))()
		for i in xrange(len(value)):
			default_list[i] = value[i]

		return core.BNSettingSetIntegerList(self.plugin_name, name, default_list, length, auto_flush)

	def set_stringList(self, name, value, auto_flush=True):
		length = ctypes.c_ulonglong()
		length.value = len(value)
		default_list = (ctypes.c_char_p * len(value))()
		for i in xrange(len(value)):
			default_list[i] = str(value[i])

		return core.BNSettingSetStringList(self.plugin_name, name, default_list, length, auto_flush)

	def set_double(self, name, value, auto_flush=True):
		return core.BNSettingSetDouble(self.plugin_name, name, value, auto_flush)
