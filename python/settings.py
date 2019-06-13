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
	def __init__(self, registry_id = "default"):
		self._registry_id = registry_id

	@property
	def registry_id(self):
		"""(read-only)"""
		return self._registry_id

	def register_group(self, group, title):
		"""
		``register_group`` registers a group for use with this Settings registry. Groups provide a simple way to organize settings.

		:param str group: a unique identifier
		:param str title: a user friendly name appropriate for UI presentation
		:return: True on success, False on failure.
		:rtype: bool
		:Example:

			>>> Settings().register_group("solver", "Solver")
			True
			>>>
		"""
		return core.BNSettingsRegisterGroup(self._registry_id, group, title)

	def register_setting(self, id, properties):
		"""
		``register_setting`` registers a new setting with this Settings registry.

		:param str id: a unique setting identifier in the form <group>.<id>
		:param str properties: a JSON string describes the setting schema
		:return: True on success, False on failure.
		:rtype: bool
		:Example:

			>>> Settings().register_group("solver", "Solver")
			True
			>>> Settings().register_setting("solver.basicBlockSlicing", '{"description" : "Enable the basic block slicing in the solver.", "title" : "Basic Block Slicing", "default" : true, "type" : "boolean", "id" : "basicBlockSlicing"}')
			True
		"""
		return core.BNSettingsRegisterSetting(self._registry_id, id, properties)

	def query_property_string_list(self, id, property_name):
		length = ctypes.c_ulonglong()
		result = core.BNSettingsQueryPropertyStringList(self._registry_id, id, property_name, ctypes.byref(length))
		out_list = []
		for i in range(length.value):
			out_list.append(pyNativeStr(result[i]))
		core.BNFreeStringList(result, length)
		return out_list

	def update_property(self, id, setting_property):
		return core.BNSettingsUpdateProperty(self.registry_id, id, setting_property)

	def deserialize_schema(self, schema):
		return core.BNSettingsDeserializeSchema(self.registry_id, schema)

	def serialize_schema(self):
		return core.BNSettingsSerializeSchema(self.registry_id)

	def copy_value(self, dest_registry_id, id):
		return core.BNSettingsCopyValue(self._registry_id, dest_registry_id, id)

	def reset(self, id, view = None, scope = SettingsScope.SettingsAutoScope):
		if view is not None:
			view = view.handle
		return core.BNSettingsReset(self._registry_id, id, view, scope)

	def reset_all(self, view = None, scope = SettingsScope.SettingsAutoScope):
		if view is not None:
			view = view.handle
		return core.BNSettingsResetAll(self._registry_id, view, scope)

	def get_bool(self, id, view = None):
		if view is not None:
			view = view.handle
		return core.BNSettingsGetBool(self._registry_id, id, view, None)

	def get_double(self, id, view = None):
		if view is not None:
			view = view.handle
		return core.BNSettingsGetDouble(self._registry_id, id, view, None)

	def get_integer(self, id, view = None):
		if view is not None:
			view = view.handle
		return core.BNSettingsGetUInt64(self._registry_id, id, view, None)

	def get_string(self, id, view = None):
		if view is not None:
			view = view.handle
		return core.BNSettingsGetString(self._registry_id, id, view, None)

	def get_string_list(self, id, view = None):
		if view is not None:
			view = view.handle
		length = ctypes.c_ulonglong()
		result = core.BNSettingsGetStringList(self._registry_id, id, view, None, ctypes.byref(length))
		out_list = []
		for i in range(length.value):
			out_list.append(pyNativeStr(result[i]))
		core.BNFreeStringList(result, length)
		return out_list

	def get_bool_with_scope(self, id, view = None, scope = SettingsScope.SettingsAutoScope):
		if view is not None:
			view = view.handle
		c_scope = core.SettingsScopeEnum(scope)
		result = core.BNSettingsGetBool(self._registry_id, id, view, ctypes.byref(c_scope))
		return (result, SettingsScope(c_scope.value))

	def get_double_with_scope(self, id, view = None, scope = SettingsScope.SettingsAutoScope):
		if view is not None:
			view = view.handle
		c_scope = core.SettingsScopeEnum(scope)
		result = core.BNSettingsGetDouble(self._registry_id, id, view, ctypes.byref(c_scope))
		return (result, SettingsScope(c_scope.value))

	def get_integer_with_scope(self, id, view = None, scope = SettingsScope.SettingsAutoScope):
		if view is not None:
			view = view.handle
		c_scope = core.SettingsScopeEnum(scope)
		result = core.BNSettingsGetUInt64(self._registry_id, id, view, ctypes.byref(c_scope))
		return (result, SettingsScope(c_scope.value))

	def get_string_with_scope(self, id, view = None, scope = SettingsScope.SettingsAutoScope):
		if view is not None:
			view = view.handle
		c_scope = core.SettingsScopeEnum(scope)
		result = core.BNSettingsGetString(self._registry_id, id, view, ctypes.byref(c_scope))
		return (result, SettingsScope(c_scope.value))

	def get_string_list_with_scope(self, id, view = None, scope = SettingsScope.SettingsAutoScope):
		if view is not None:
			view = view.handle
		c_scope = core.SettingsScopeEnum(scope)
		length = ctypes.c_ulonglong()
		result = core.BNSettingsGetStringList(self._registry_id, id, view, ctypes.byref(c_scope), ctypes.byref(length))
		out_list = []
		for i in range(length.value):
			out_list.append(pyNativeStr(result[i]))
		core.BNFreeStringList(result, length)
		return (out_list, SettingsScope(c_scope.value))

	def set_bool(self, id, value, view = None, scope = SettingsScope.SettingsAutoScope):
		if view is not None:
			view = view.handle
		return core.BNSettingsSetBool(self._registry_id, view, scope, id, value)

	def set_double(self, id, value, view = None, scope = SettingsScope.SettingsAutoScope):
		if view is not None:
			view = view.handle
		return core.BNSettingsSetDouble(self._registry_id, view, scope, id, value)

	def set_integer(self, id, value, view = None, scope = SettingsScope.SettingsAutoScope):
		if view is not None:
			view = view.handle
		return core.BNSettingsSetUInt64(self._registry_id, view, scope, id, value)

	def set_string(self, id, value, view = None, scope = SettingsScope.SettingsAutoScope):
		if view is not None:
			view = view.handle
		return core.BNSettingsSetString(self._registry_id, view, scope, id, value)

	def set_string_list(self, id, value, view = None, scope = SettingsScope.SettingsAutoScope):
		if view is not None:
			view = view.handle
		length = ctypes.c_ulonglong()
		length.value = len(value)
		string_list = (ctypes.c_char_p * len(value))()
		for i in range(len(value)):
			string_list[i] = value[i].encode('charmap')
		return core.BNSettingsSetStringList(self._registry_id, view, scope, id, string_list, length)
