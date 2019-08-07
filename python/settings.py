# Copyright (c) 2015-2019 Vector 35 Inc
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
from binaryninja import _binaryninjacore as core

# 2-3 compatibility
from binaryninja import range
from binaryninja import pyNativeStr
from binaryninja.enums import SettingsScope


class Settings(object):
	handle = core.BNCreateSettings("default")

	def __init__(self, instance_id = "default", handle = None):
		if handle is None:
			if instance_id is None or instance_id is "":
				instance_id = "default"
			self._instance_id = instance_id
			if instance_id == "default":
				self.handle = Settings.handle
			else:
				self.handle = core.BNCreateSettings(instance_id)
		else:
			instance_id = core.BNGetUniqueIdentifierString()
			self.handle = handle

	def __del__(self):
		if self.handle is not Settings.handle and self.handle is not None:
			core.BNFreeSettings(self.handle)

	def __eq__(self, value):
		if not isinstance(value, Settings):
			return False
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(value.handle.contents)

	def __ne__(self, value):
		if not isinstance(value, Settings):
			return True
		return ctypes.addressof(self.handle.contents) != ctypes.addressof(value.handle.contents)

	def __hash__(self):
		return hash((self.instance_id, self.handle))

	@property
	def instance_id(self):
		"""(read-only)"""
		return self._instance_id

	def register_group(self, group, title):
		"""
		``register_group`` registers a group for use with this Settings instance. Groups provide a simple way to organize settings.

		:param str group: a unique identifier
		:param str title: a user friendly name appropriate for UI presentation
		:return: True on success, False on failure.
		:rtype: bool
		:Example:

			>>> Settings().register_group("solver", "Solver")
			True
			>>>
		"""
		return core.BNSettingsRegisterGroup(self.handle, group, title)

	def register_setting(self, key, properties):
		"""
		``register_setting`` registers a new setting with this Settings instance.

		:param str key: a unique setting identifier in the form <group>.<name>
		:param str properties: a JSON string describes the setting schema
		:return: True on success, False on failure.
		:rtype: bool
		:Example:

			>>> Settings().register_group("solver", "Solver")
			True
			>>> Settings().register_setting("solver.basicBlockSlicing", '{"description" : "Enable the basic block slicing in the solver.", "title" : "Basic Block Slicing", "default" : true, "type" : "boolean"}')
			True
		"""
		return core.BNSettingsRegisterSetting(self.handle, key, properties)

	def contains(self, key):
		return core.BNSettingsContains(self.handle, key)

	def query_property_string_list(self, key, property_name):
		length = ctypes.c_ulonglong()
		result = core.BNSettingsQueryPropertyStringList(self.handle, key, property_name, ctypes.byref(length))
		out_list = []
		for i in range(length.value):
			out_list.append(pyNativeStr(result[i]))
		core.BNFreeStringList(result, length)
		return out_list

	def update_property(self, key, setting_property):
		return core.BNSettingsUpdateProperty(self.handle, key, setting_property)

	def deserialize_schema(self, schema, scope = SettingsScope.SettingsAutoScope, merge = True):
		return core.BNSettingsDeserializeSchema(self.handle, schema, scope, merge)

	def serialize_schema(self):
		return core.BNSettingsSerializeSchema(self.handle)

	def copy_values_from(self, source, scope = SettingsScope.SettingsAutoScope):
		return core.BNSettingsCopyValuesFrom(self.handle, source.handle, scope)

	def reset(self, key, view = None, scope = SettingsScope.SettingsAutoScope):
		if view is not None:
			view = view.handle
		return core.BNSettingsReset(self.handle, key, view, scope)

	def reset_all(self, view = None, scope = SettingsScope.SettingsAutoScope):
		if view is not None:
			view = view.handle
		return core.BNSettingsResetAll(self.handle, view, scope)

	def get_bool(self, key, view = None):
		if view is not None:
			view = view.handle
		return core.BNSettingsGetBool(self.handle, key, view, None)

	def get_double(self, key, view = None):
		if view is not None:
			view = view.handle
		return core.BNSettingsGetDouble(self.handle, key, view, None)

	def get_integer(self, key, view = None):
		if view is not None:
			view = view.handle
		return core.BNSettingsGetUInt64(self.handle, key, view, None)

	def get_string(self, key, view = None):
		if view is not None:
			view = view.handle
		return core.BNSettingsGetString(self.handle, key, view, None)

	def get_string_list(self, key, view = None):
		if view is not None:
			view = view.handle
		length = ctypes.c_ulonglong()
		result = core.BNSettingsGetStringList(self.handle, key, view, None, ctypes.byref(length))
		out_list = []
		for i in range(length.value):
			out_list.append(pyNativeStr(result[i]))
		core.BNFreeStringList(result, length)
		return out_list

	def get_bool_with_scope(self, key, view = None, scope = SettingsScope.SettingsAutoScope):
		if view is not None:
			view = view.handle
		c_scope = core.SettingsScopeEnum(scope)
		result = core.BNSettingsGetBool(self.handle, key, view, ctypes.byref(c_scope))
		return (result, SettingsScope(c_scope.value))

	def get_double_with_scope(self, key, view = None, scope = SettingsScope.SettingsAutoScope):
		if view is not None:
			view = view.handle
		c_scope = core.SettingsScopeEnum(scope)
		result = core.BNSettingsGetDouble(self.handle, key, view, ctypes.byref(c_scope))
		return (result, SettingsScope(c_scope.value))

	def get_integer_with_scope(self, key, view = None, scope = SettingsScope.SettingsAutoScope):
		if view is not None:
			view = view.handle
		c_scope = core.SettingsScopeEnum(scope)
		result = core.BNSettingsGetUInt64(self.handle, key, view, ctypes.byref(c_scope))
		return (result, SettingsScope(c_scope.value))

	def get_string_with_scope(self, key, view = None, scope = SettingsScope.SettingsAutoScope):
		if view is not None:
			view = view.handle
		c_scope = core.SettingsScopeEnum(scope)
		result = core.BNSettingsGetString(self.handle, key, view, ctypes.byref(c_scope))
		return (result, SettingsScope(c_scope.value))

	def get_string_list_with_scope(self, key, view = None, scope = SettingsScope.SettingsAutoScope):
		if view is not None:
			view = view.handle
		c_scope = core.SettingsScopeEnum(scope)
		length = ctypes.c_ulonglong()
		result = core.BNSettingsGetStringList(self.handle, key, view, ctypes.byref(c_scope), ctypes.byref(length))
		out_list = []
		for i in range(length.value):
			out_list.append(pyNativeStr(result[i]))
		core.BNFreeStringList(result, length)
		return (out_list, SettingsScope(c_scope.value))

	def set_bool(self, key, value, view = None, scope = SettingsScope.SettingsAutoScope):
		if view is not None:
			view = view.handle
		return core.BNSettingsSetBool(self.handle, view, scope, key, value)

	def set_double(self, key, value, view = None, scope = SettingsScope.SettingsAutoScope):
		if view is not None:
			view = view.handle
		return core.BNSettingsSetDouble(self.handle, view, scope, key, value)

	def set_integer(self, key, value, view = None, scope = SettingsScope.SettingsAutoScope):
		if view is not None:
			view = view.handle
		return core.BNSettingsSetUInt64(self.handle, view, scope, key, value)

	def set_string(self, key, value, view = None, scope = SettingsScope.SettingsAutoScope):
		if view is not None:
			view = view.handle
		return core.BNSettingsSetString(self.handle, view, scope, key, value)

	def set_string_list(self, key, value, view = None, scope = SettingsScope.SettingsAutoScope):
		if view is not None:
			view = view.handle
		length = ctypes.c_ulonglong()
		length.value = len(value)
		string_list = (ctypes.c_char_p * len(value))()
		for i in range(len(value)):
			string_list[i] = value[i].encode('charmap')
		return core.BNSettingsSetStringList(self.handle, view, scope, key, string_list, length)
