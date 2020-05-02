# Copyright (c) 2015-2020 Vector 35 Inc
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
	"""
	``class Settings`` Provides a way to define and access settings in a hierarchical fashion. The value of a setting can \
	be defined for each hierarchical level, where each level overrides the preceding level. The backing-store for setting \
	values is also configurable and can be different for each level. This allows for ephemeral or platform-independent \
	persistent settings storage for components within Binary Ninja or consumers of the Binary Ninja API.

	Each :class:`Settings` instance has a unique ``instance_id`` and a settings schema that define the contents for the settings \
	repository. By default, a new :class:`Settings` instance contains an empty schema. A schema can be built up by using the \
	:func:`register_group` and func:`register_setting` methods, or by deserializing an existing schema with :func:`deserialize_schema`. \
	Binary Ninja provides a default :class:`Settings` instance identified as *'default'*. The *'default'* settings repository defines \
	all of the settings available for the active Binary Ninja components.

	.. note:: The Binary Ninja Application provides many settings that are only applicable to the UI, and thus would not be \
	defined in the *'default'* settings schema for Binary Ninja headless.

	Except for *default* setting values, setting values are optional for other levels and stored separately from the schema in a \
	backing store. The backing store can be different for each level. When querying setting values, the values returned or modified \
	are in order of preference (i.e. ``SettingsAutoScope``). It is possible to override the scope by specifying the desired ``SettingsScope``.

		================= ========================== ============== ================================ ===============================
		Setting Level     Settings Scope             Preference     Backing Store ('default')        Backing Store (Other)
		================= ========================== ============== ================================ ===============================
		Default           SettingsDefaultScope       Lowest         Settings Schema                  Settings Schema
		User              SettingsUserScope          -              <User Directory>/settings.json   <TBD>
		Workspace         SettingsWorkspaceScope     -              <TBD>                            <TBD>
		Context           SettingsContextScope       Highest        BinaryView (Storage in bndb)     BinaryView (Storage in bndb)
		================= ========================== ============== ================================ ===============================

	Individual settings are identified by a key, which is a string in the form of **'<group>.<name>'**. Groups provide a simple way \
	to categorize settings. Additionally, sub-categories can be expressed directly in the name part of the key with a similar dot notation.
	"""
	handle = core.BNCreateSettings("default")

	def __init__(self, instance_id = "default", handle = None):
		if handle is None:
			if instance_id is None or instance_id == "":
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

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(other.handle.contents)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash((self.instance_id, ctypes.addressof(self.handle.contents)))

	@property
	def instance_id(self):
		"""Returns the ``instance_id`` for this :class:`Settings` repository (read-only)"""
		return self._instance_id

	def set_resource_id(self, resource_id = None):
		"""
		``set_resource_id`` Sets the resource identifier for this class:`Settings` instance. When accessing setting values at the \
		``SettingsContextScope`` level, the resource identifier is passed along through the backing store interface.

		.. note:: Currently the only available backing store for ``SettingsContextScope`` is a :class:`BinaryView` object. In the context \
		of a :class:`BinaryView` the resource identifier is the :class:`BinaryViewType` name. All settings for this type of backing store \
		are saved in the *'Raw'* :class:`BinaryViewType`. This enables the configuration of setting values such that they are available \
		during :class:`BinaryView` creation and initialization.

		:param str resource_id: a unique identifier
		:rtype: None
		"""
		if resource_id is None:
			resource_id = ""
		core.BNSettingsSetResourceId(self.handle, resource_id)

	def register_group(self, group, title):
		"""
		``register_group`` registers a group in the schema for this :class:`Settings` instance

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
		``register_setting`` registers a new setting with this :class:`Settings` instance

		:param str key: a unique setting identifier in the form **'<group>.<name>'**
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
		"""
		``contains`` determine if a setting identifier exists in the active settings schema

		:param str key: the setting identifier
		:return: True if the identifier exists in this active settings schema, False otherwise
		:rtype: bool
		"""
		return core.BNSettingsContains(self.handle, key)

	def is_empty(self):
		"""
		``is_empty`` determine if the active settings schema is empty

		:return: True if the active settings schema is empty, False otherwise
		:rtype: bool
		"""
		return core.BNSettingsIsEmpty(self.handle)

	def keys(self):
		"""
		``keys`` retrieve the list of setting identifiers in the active settings schema

		:return: list of setting identifiers
		:rtype: list(str)
		"""
		length = ctypes.c_ulonglong()
		result = core.BNSettingsKeysList(self.handle, ctypes.byref(length))
		out_list = []
		for i in range(length.value):
			out_list.append(pyNativeStr(result[i]))
		core.BNFreeStringList(result, length)
		return out_list

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

	def get_json(self, key, view = None):
		if view is not None:
			view = view.handle
		return core.BNSettingsGetJson(self.handle, key, view, None)

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

	def get_json_with_scope(self, key, view = None, scope = SettingsScope.SettingsAutoScope):
		if view is not None:
			view = view.handle
		c_scope = core.SettingsScopeEnum(scope)
		result = core.BNSettingsGetJson(self.handle, key, view, ctypes.byref(c_scope))
		return (result, SettingsScope(c_scope.value))

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

	def set_json(self, key, value, view = None, scope = SettingsScope.SettingsAutoScope):
		if view is not None:
			view = view.handle
		return core.BNSettingsSetJson(self.handle, view, scope, key, value)
