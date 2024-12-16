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

import ctypes

# Binary Ninja components
from . import _binaryninjacore as core
from .enums import SettingsScope
from . import binaryview
from . import function

from typing import List, Optional, Union

class Settings:
	"""
	:class:`Settings` provides a way to define and access settings in a hierarchical fashion. The value of a setting can \
	be defined for each hierarchical level, where each level overrides the preceding level. The backing-store for setting \
	values at each level is also configurable. This allows for ephemeral or platform-independent persistent settings storage \
	for components within Binary Ninja or consumers of the Binary Ninja API.

	Each :class:`Settings` instance has an ``instance_id`` which identifies a schema. The schema defines the settings contents  \
	and the way in which settings are retrieved and manipulated. A new :class:`Settings` instance defaults to using a value of *'default'* \
	for the ``instance_id``. The *'default'* settings schema defines all of the settings available for the active Binary Ninja components \
	which include at a minimum, the settings defined by the Binary Ninja core. The *'default'* schema may additionally define settings \
	for the UI and/or installed plugins. Extending existing schemas, or defining new ones is accomplished by calling :func:`register_group` \
	and :func:`register_setting` methods, or by deserializing an existing schema with :func:`deserialize_schema`.

	.. note:: All settings in the *'default'* settings schema are rendered with UI elements in the Settings View of Binary Ninja UI.

	Allowing setting overrides is an important feature and Binary Ninja accomplishes this by allowing one to override a setting at various \
	levels. The levels and their associated storage are shown in the following table. Default setting values are optional, and if specified, \
	saved in the schema itself.

		================= ========================== ============== ==============================================
		Setting Level     Settings Scope             Preference     Storage
		================= ========================== ============== ==============================================
		Default           SettingsDefaultScope       Lowest         Settings Schema
		User              SettingsUserScope          -              <User Directory>/settings.json
		Project           SettingsProjectScope       -              <Project Directory>/settings.json
		Resource          SettingsResourceScope      Highest        Raw BinaryView (Storage in BNDB)
		================= ========================== ============== ==============================================

	Settings are identified by a key, which is a string in the form of **'<group>.<name>'** or **'<group>.<subGroup>.<name>'**. Groups provide \
	a simple way to categorize settings. Sub-groups are optional and multiple sub-groups are allowed. When defining a settings group, the \
	:func:`register_group` method allows for specifying a UI friendly title for use in the Binary Ninja UI. Defining a new setting requires a \
	unique setting key and a JSON string of property, value pairs. The following table describes the available properties and values.

		===================   ======================================   ==================   ========   =======================================================================
		Property              JSON Data Type                           Prerequisite         Optional   {Allowed Values} and Notes
		===================   ======================================   ==================   ========   =======================================================================
		"title"               string                                   None                 No         Concise Setting Title
		"type"                string                                   None                 No         {"array", "boolean", "number", "string", "object"}
		"sorted"              boolean                                  "type" is "array"    Yes        Automatically sort list items (default is false)
		"isSerialized"        boolean                                  "type" is "string"   Yes        Treat the string as a serialized JSON object
		"enum"                array : {string}                         "type" is "string"   Yes        Enumeration definitions
		"enumDescriptions"    array : {string}                         "type" is "string"   Yes        Enumeration descriptions that match "enum" array
		"minValue"            number                                   "type" is "number"   Yes        Specify 0 to infer unsigned (default is signed)
		"maxValue"            number                                   "type" is "number"   Yes        Values less than or equal to INT_MAX result in a QSpinBox UI element
		"precision"           number                                   "type" is "number"   Yes        Specify precision for a QDoubleSpinBox
		"default"             {array, boolean, number, string, null}   None                 Yes        Specify optimal default value
		"aliases"             array : {string}                         None                 Yes        Array of deprecated setting key(s)
		"description"         string                                   None                 No         Detailed setting description
		"ignore"              array : {string}                         None                 Yes        {"SettingsUserScope", "SettingsProjectScope", "SettingsResourceScope"}
		"message"             string                                   None                 Yes        An optional message with additional emphasis
		"readOnly"            boolean                                  None                 Yes        Only enforced by UI elements
		"optional"            boolean                                  None                 Yes        Indicates setting can be null
		"hidden"              bool                                     "type" is "string"   Yes        Indicates the UI should conceal the content. The "ignore" property is required to specify the applicable storage scopes
		"requiresRestart      boolean                                  None                 Yes        Enable restart notification in the UI upon change
		"uiSelectionAction"   string                                   "type" is "string"   Yes        {"file", "directory", <Registered UIAction Name>} Informs the UI to add a button to open a selection dialog or run a registered UIAction
		===================   ======================================   ==================   ========   =======================================================================

	.. note:: In order to facilitate deterministic analysis results, settings from the *'default'* schema that impact analysis are serialized \
	from Default, User, and Project scope into Resource scope during initial BinaryView analysis. This allows an analysis database to be opened \
	at a later time with the same settings, regardless if Default, User, or Project settings have been modified.

	.. note:: Settings that do not impact analysis (e.g. many UI settings) should use the *"ignore"* property to exclude \
		*"SettingsProjectScope"* and *"SettingsResourceScope"* from the applicable scopes for the setting.

	Example analysis plugin setting:

		>>> my_settings = Settings()
		>>> title = "My Pre-Analysis Plugin"
		>>> description = "Enable extra analysis before core analysis."
		>>> properties = f'{{"title" : "{title}", "description" : "{description}", "type" : "boolean", "default" : false}}'
		>>> my_settings.register_group("myPlugin", "My Plugin")
		True
		>>> my_settings.register_setting("myPlugin.enablePreAnalysis", properties)
		True
		>>> my_bv = load("/bin/ls", options={'myPlugin.enablePreAnalysis' : True})
		>>> Settings().get_bool("myPlugin.enablePreAnalysis")
		False
		>>> Settings().get_bool("myPlugin.enablePreAnalysis", my_bv)
		True

	Example UI plugin setting:

		>>> my_settings = Settings()
		>>> title = "My UI Plugin"
		>>> description = "Enable My UI Plugin table display."
		>>> properties = f'{{"title" : "{title}", "description" : "{description}", "type" : "boolean", "default" : true, "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]}}'
		>>> my_settings.register_group("myPlugin", "My Plugin")
		True
		>>> my_settings.register_setting("myPlugin.enableTableView", properties)
		True
		>>> my_bv = load("/bin/ls", options={'myPlugin.enableTableView' : True})
		>>> Settings().get_bool("myPlugin.enableTableView")
		True

	"""
	default_handle = core.BNCreateSettings("default")

	def __init__(self, instance_id: Optional[str] = None, handle=None):
		if handle is None:
			if instance_id is None or instance_id == "":
				instance_id = "default"
			self._instance_id = instance_id
			if instance_id == "default":
				assert Settings.default_handle is not None
				_handle = Settings.default_handle
			else:
				_handle = core.BNCreateSettings(instance_id)
		else:
			instance_id = core.BNGetUniqueIdentifierString()
			_handle = handle
		assert _handle is not None
		self.handle = _handle

	def __del__(self):
		if self.handle is not Settings.default_handle:
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
	def instance_id(self) -> str:
		"""Returns the ``instance_id`` for this :class:`Settings` repository (read-only)"""
		return self._instance_id

		"""
		``load_settings_file`` Sets the file that this class:`Settings` instance uses when initially loading, and modifying \
		settings for the specified scope.

		.. note:: At times it may be useful to make ephemeral changes to settings that are not saved to file. This can be accomplished \
		by calling :func:`load_settings_file` without specifying a filename. This action also resets settings to their default value.

		:param str filename: the settings filename
		:param scope: the SettingsScope
		:param BinaryView view: a BinaryView object
		:rtype: bool
		"""
	def load_settings_file(self, filename: str = '', scope: 'SettingsScope' = SettingsScope.SettingsAutoScope, view: Optional['binaryview.BinaryView'] = None) -> bool:
		if filename is None:
			filename = ""
		if view is not None:
			view = view.handle
		return core.BNLoadSettingsFile(self.handle, filename, scope, view)

	def set_resource_id(self, resource_id: str = ''):
		"""
		``set_resource_id`` Sets the resource identifier for this class:`Settings` instance. When accessing setting values at the \
		``SettingsResourceScope`` level, the resource identifier is passed along through the backing store interface.

		.. note:: Currently the only available backing store for ``SettingsResourceScope`` is a :class:`BinaryView` object. In the context \
		of a :class:`BinaryView` the resource identifier is the :class:`BinaryViewType` name. All settings for this type of backing store \
		are saved in the *'Raw'* :class:`BinaryViewType`. This enables the configuration of setting values such that they are available \
		during :class:`BinaryView` creation and initialization.

		:param str resource_id: a unique identifier
		:rtype: None
		"""
		if resource_id is None:
			resource_id = ""
		core.BNSettingsSetResourceId(self.handle, resource_id)

	def register_group(self, group: str, title: str) -> bool:
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

	def register_setting(self, key: str, properties: str) -> bool:
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

	def contains(self, key: str) -> bool:
		"""
		``contains`` determine if a setting identifier exists in the active settings schema

		:param str key: the setting identifier
		:return: True if the identifier exists in this active settings schema, False otherwise
		:rtype: bool
		"""
		return core.BNSettingsContains(self.handle, key)

	def is_empty(self) -> bool:
		"""
		``is_empty`` determine if the active settings schema is empty

		:return: True if the active settings schema is empty, False otherwise
		:rtype: bool
		"""
		return core.BNSettingsIsEmpty(self.handle)

	def keys(self) -> List[str]:
		"""
		``keys`` retrieve the list of setting identifiers in the active settings schema

		:return: list of setting identifiers
		:rtype: list(str)
		"""
		length = ctypes.c_ulonglong()
		result = core.BNSettingsKeysList(self.handle, ctypes.byref(length))
		assert result is not None, "core.BNSettingsKeysList returned None"
		out_list = []
		for i in range(length.value):
			out_list.append(result[i].decode('utf8'))
		core.BNFreeStringList(result, length)
		return out_list

	def query_property_string(self, key: str, property_name: str) -> str:
		return core.BNSettingsQueryPropertyString(self.handle, key, property_name)

	def query_property_string_list(self, key: str, property_name: str) -> List[str]:
		length = ctypes.c_ulonglong()
		result = core.BNSettingsQueryPropertyStringList(self.handle, key, property_name, ctypes.byref(length))
		assert result is not None, "core.BNSettingsQueryPropertyStringList returned None"
		out_list = []
		for i in range(length.value):
			out_list.append(result[i].decode('utf8'))
		core.BNFreeStringList(result, length)
		return out_list

	def update_property(self, key: str, setting_property: str) -> bool:
		return core.BNSettingsUpdateProperty(self.handle, key, setting_property)

	def deserialize_schema(self, schema: str, scope: 'SettingsScope' = SettingsScope.SettingsAutoScope, merge: bool = True) -> bool:
		return core.BNSettingsDeserializeSchema(self.handle, schema, scope, merge)

	def serialize_schema(self) -> str:
		return core.BNSettingsSerializeSchema(self.handle)

	def deserialize_settings(self, contents: str, resource: Optional[Union['binaryview.BinaryView', 'function.Function']] = None, scope: 'SettingsScope' = SettingsScope.SettingsAutoScope) -> bool:
		view_handle = None
		func_handle = None
		if resource is not None:
			if isinstance(resource, binaryview.BinaryView):
				view_handle = resource.handle
			elif isinstance(resource, function.Function):
				func_handle = resource.handle
			else:
				raise TypeError("Expected resource to be either a BinaryView or a Function.")
		return core.BNDeserializeSettings(self.handle, contents, view_handle, func_handle, scope)

	def serialize_settings(self, resource: Optional[Union['binaryview.BinaryView', 'function.Function']] = None, scope: 'SettingsScope' = SettingsScope.SettingsAutoScope) -> str:
		view_handle = None
		func_handle = None
		if resource is not None:
			if isinstance(resource, binaryview.BinaryView):
				view_handle = resource.handle
			elif isinstance(resource, function.Function):
				func_handle = resource.handle
			else:
				raise TypeError("Expected resource to be either a BinaryView or a Function.")
		return core.BNSerializeSettings(self.handle, view_handle, func_handle, scope)

	def reset(self, key: str, resource: Optional[Union['binaryview.BinaryView', 'function.Function']] = None, scope: 'SettingsScope' = SettingsScope.SettingsAutoScope) -> bool:
		view_handle = None
		func_handle = None
		if resource is not None:
			if isinstance(resource, binaryview.BinaryView):
				view_handle = resource.handle
			elif isinstance(resource, function.Function):
				func_handle = resource.handle
			else:
				raise TypeError("Expected resource to be either a BinaryView or a Function.")
		return core.BNSettingsReset(self.handle, key, view_handle, func_handle, scope)

	def reset_all(self, resource: Optional[Union['binaryview.BinaryView', 'function.Function']] = None, scope: 'SettingsScope' = SettingsScope.SettingsAutoScope, schema_only=True) -> bool:
		view_handle = None
		func_handle = None
		if resource is not None:
			if isinstance(resource, binaryview.BinaryView):
				view_handle = resource.handle
			elif isinstance(resource, function.Function):
				func_handle = resource.handle
			else:
				raise TypeError("Expected resource to be either a BinaryView or a Function.")
		return core.BNSettingsResetAll(self.handle, view_handle, func_handle, scope, schema_only)

	def get_bool(self, key: str, resource: Optional[Union['binaryview.BinaryView', 'function.Function']] = None) -> bool:
		view_handle = None
		func_handle = None
		if resource is not None:
			if isinstance(resource, binaryview.BinaryView):
				view_handle = resource.handle
			elif isinstance(resource, function.Function):
				func_handle = resource.handle
			else:
				raise TypeError("Expected resource to be either a BinaryView or a Function.")
		return core.BNSettingsGetBool(self.handle, key, view_handle, func_handle, None)

	def get_double(self, key: str, resource: Optional[Union['binaryview.BinaryView', 'function.Function']] = None) -> float:
		view_handle = None
		func_handle = None
		if resource is not None:
			if isinstance(resource, binaryview.BinaryView):
				view_handle = resource.handle
			elif isinstance(resource, function.Function):
				func_handle = resource.handle
			else:
				raise TypeError("Expected resource to be either a BinaryView or a Function.")
		return core.BNSettingsGetDouble(self.handle, key, view_handle, func_handle, None)

	def get_integer(self, key: str, resource: Optional[Union['binaryview.BinaryView', 'function.Function']] = None) -> int:
		view_handle = None
		func_handle = None
		if resource is not None:
			if isinstance(resource, binaryview.BinaryView):
				view_handle = resource.handle
			elif isinstance(resource, function.Function):
				func_handle = resource.handle
			else:
				raise TypeError("Expected resource to be either a BinaryView or a Function.")
		return core.BNSettingsGetUInt64(self.handle, key, view_handle, func_handle, None)

	def get_string(self, key: str, resource: Optional[Union['binaryview.BinaryView', 'function.Function']] = None) -> str:
		view_handle = None
		func_handle = None
		if resource is not None:
			if isinstance(resource, binaryview.BinaryView):
				view_handle = resource.handle
			elif isinstance(resource, function.Function):
				func_handle = resource.handle
			else:
				raise TypeError("Expected resource to be either a BinaryView or a Function.")
		return core.BNSettingsGetString(self.handle, key, view_handle, func_handle, None)

	def get_string_list(self, key: str, resource: Optional[Union['binaryview.BinaryView', 'function.Function']] = None) -> List[str]:
		view_handle = None
		func_handle = None
		if resource is not None:
			if isinstance(resource, binaryview.BinaryView):
				view_handle = resource.handle
			elif isinstance(resource, function.Function):
				func_handle = resource.handle
			else:
				raise TypeError("Expected resource to be either a BinaryView or a Function.")
		length = ctypes.c_ulonglong()
		result = core.BNSettingsGetStringList(self.handle, key, view_handle, func_handle, None, ctypes.byref(length))
		assert result is not None, "core.BNSettingsGetStringList returned None"
		out_list = []
		for i in range(length.value):
			out_list.append(result[i].decode('utf8'))
		core.BNFreeStringList(result, length)
		return out_list

	def get_json(self, key: str, resource: Optional[Union['binaryview.BinaryView', 'function.Function']] = None) -> str:
		view_handle = None
		func_handle = None
		if resource is not None:
			if isinstance(resource, binaryview.BinaryView):
				view_handle = resource.handle
			elif isinstance(resource, function.Function):
				func_handle = resource.handle
			else:
				raise TypeError("Expected resource to be either a BinaryView or a Function.")
		return core.BNSettingsGetJson(self.handle, key, view_handle, func_handle, None)

	def get_bool_with_scope(self, key: str, resource: Optional[Union['binaryview.BinaryView', 'function.Function']] = None, scope: 'SettingsScope' = SettingsScope.SettingsAutoScope) -> (bool, SettingsScope):
		view_handle = None
		func_handle = None
		if resource is not None:
			if isinstance(resource, binaryview.BinaryView):
				view_handle = resource.handle
			elif isinstance(resource, function.Function):
				func_handle = resource.handle
			else:
				raise TypeError("Expected resource to be either a BinaryView or a Function.")
		c_scope = core.SettingsScopeEnum(scope)
		result = core.BNSettingsGetBool(self.handle, key, view_handle, func_handle, ctypes.byref(c_scope))
		return (result, SettingsScope(c_scope.value))

	def get_double_with_scope(self, key: str, resource: Optional[Union['binaryview.BinaryView', 'function.Function']] = None, scope: 'SettingsScope' = SettingsScope.SettingsAutoScope) -> (float, SettingsScope):
		view_handle = None
		func_handle = None
		if resource is not None:
			if isinstance(resource, binaryview.BinaryView):
				view_handle = resource.handle
			elif isinstance(resource, function.Function):
				func_handle = resource.handle
			else:
				raise TypeError("Expected resource to be either a BinaryView or a Function.")
		c_scope = core.SettingsScopeEnum(scope)
		result = core.BNSettingsGetDouble(self.handle, key, view_handle, func_handle, ctypes.byref(c_scope))
		return (result, SettingsScope(c_scope.value))

	def get_integer_with_scope(self, key: str, resource: Optional[Union['binaryview.BinaryView', 'function.Function']] = None, scope: 'SettingsScope' = SettingsScope.SettingsAutoScope) -> (int, SettingsScope):
		view_handle = None
		func_handle = None
		if resource is not None:
			if isinstance(resource, binaryview.BinaryView):
				view_handle = resource.handle
			elif isinstance(resource, function.Function):
				func_handle = resource.handle
			else:
				raise TypeError("Expected resource to be either a BinaryView or a Function.")
		c_scope = core.SettingsScopeEnum(scope)
		result = core.BNSettingsGetUInt64(self.handle, key, view_handle, func_handle, ctypes.byref(c_scope))
		return (result, SettingsScope(c_scope.value))

	def get_string_with_scope(self, key: str, resource: Optional[Union['binaryview.BinaryView', 'function.Function']] = None, scope: 'SettingsScope' = SettingsScope.SettingsAutoScope) -> (str, SettingsScope):
		view_handle = None
		func_handle = None
		if resource is not None:
			if isinstance(resource, binaryview.BinaryView):
				view_handle = resource.handle
			elif isinstance(resource, function.Function):
				func_handle = resource.handle
			else:
				raise TypeError("Expected resource to be either a BinaryView or a Function.")
		c_scope = core.SettingsScopeEnum(scope)
		result = core.BNSettingsGetString(self.handle, key, view_handle, func_handle, ctypes.byref(c_scope))
		return (result, SettingsScope(c_scope.value))

	def get_string_list_with_scope(self, key: str, resource: Optional[Union['binaryview.BinaryView', 'function.Function']] = None, scope: 'SettingsScope' = SettingsScope.SettingsAutoScope) -> (List[str], SettingsScope):
		view_handle = None
		func_handle = None
		if resource is not None:
			if isinstance(resource, binaryview.BinaryView):
				view_handle = resource.handle
			elif isinstance(resource, function.Function):
				func_handle = resource.handle
			else:
				raise TypeError("Expected resource to be either a BinaryView or a Function.")
		c_scope = core.SettingsScopeEnum(scope)
		length = ctypes.c_ulonglong()
		result = core.BNSettingsGetStringList(self.handle, key, view_handle, func_handle, ctypes.byref(c_scope), ctypes.byref(length))
		assert result is not None, "core.BNSettingsGetStringList returned None"
		out_list = []
		for i in range(length.value):
			out_list.append(result[i].decode('utf8'))
		core.BNFreeStringList(result, length)
		return (out_list, SettingsScope(c_scope.value))

	def get_json_with_scope(self, key: str, resource: Optional[Union['binaryview.BinaryView', 'function.Function']] = None, scope: 'SettingsScope' = SettingsScope.SettingsAutoScope) -> (str, SettingsScope):
		view_handle = None
		func_handle = None
		if resource is not None:
			if isinstance(resource, binaryview.BinaryView):
				view_handle = resource.handle
			elif isinstance(resource, function.Function):
				func_handle = resource.handle
			else:
				raise TypeError("Expected resource to be either a BinaryView or a Function.")
		c_scope = core.SettingsScopeEnum(scope)
		result = core.BNSettingsGetJson(self.handle, key, view_handle, func_handle, ctypes.byref(c_scope))
		return (result, SettingsScope(c_scope.value))

	def set_bool(self, key: str, value: bool, resource: Optional[Union['binaryview.BinaryView', 'function.Function']] = None, scope: 'SettingsScope' = SettingsScope.SettingsAutoScope) -> bool:
		view_handle = None
		func_handle = None
		if resource is not None:
			if isinstance(resource, binaryview.BinaryView):
				view_handle = resource.handle
			elif isinstance(resource, function.Function):
				func_handle = resource.handle
			else:
				raise TypeError("Expected resource to be either a BinaryView or a Function.")
		return core.BNSettingsSetBool(self.handle, view_handle, func_handle, scope, key, value)

	def set_double(self, key: str, value: float, resource: Optional[Union['binaryview.BinaryView', 'function.Function']] = None, scope: 'SettingsScope' = SettingsScope.SettingsAutoScope) -> bool:
		view_handle = None
		func_handle = None
		if resource is not None:
			if isinstance(resource, binaryview.BinaryView):
				view_handle = resource.handle
			elif isinstance(resource, function.Function):
				func_handle = resource.handle
			else:
				raise TypeError("Expected resource to be either a BinaryView or a Function.")
		return core.BNSettingsSetDouble(self.handle, view_handle, func_handle, scope, key, value)

	def set_integer(self, key: str, value: int, resource: Optional[Union['binaryview.BinaryView', 'function.Function']] = None, scope: 'SettingsScope' = SettingsScope.SettingsAutoScope) -> bool:
		view_handle = None
		func_handle = None
		if resource is not None:
			if isinstance(resource, binaryview.BinaryView):
				view_handle = resource.handle
			elif isinstance(resource, function.Function):
				func_handle = resource.handle
			else:
				raise TypeError("Expected resource to be either a BinaryView or a Function.")
		return core.BNSettingsSetUInt64(self.handle, view_handle, func_handle, scope, key, value)

	def set_string(self, key: str, value: str, resource: Optional[Union['binaryview.BinaryView', 'function.Function']] = None, scope: 'SettingsScope' = SettingsScope.SettingsAutoScope) -> bool:
		view_handle = None
		func_handle = None
		if resource is not None:
			if isinstance(resource, binaryview.BinaryView):
				view_handle = resource.handle
			elif isinstance(resource, function.Function):
				func_handle = resource.handle
			else:
				raise TypeError("Expected resource to be either a BinaryView or a Function.")
		return core.BNSettingsSetString(self.handle, view_handle, func_handle, scope, key, value)

	def set_string_list(self, key: str, value: List[str], resource: Optional[Union['binaryview.BinaryView', 'function.Function']] = None, scope: 'SettingsScope' = SettingsScope.SettingsAutoScope) -> bool:
		view_handle = None
		func_handle = None
		if resource is not None:
			if isinstance(resource, binaryview.BinaryView):
				view_handle = resource.handle
			elif isinstance(resource, function.Function):
				func_handle = resource.handle
			else:
				raise TypeError("Expected resource to be either a BinaryView or a Function.")
		length = ctypes.c_ulonglong()
		length.value = len(value)
		string_list = (ctypes.c_char_p * len(value))()
		for i in range(len(value)):
			string_list[i] = value[i].encode('charmap')
		return core.BNSettingsSetStringList(self.handle, view_handle, func_handle, scope, key, string_list, length)

	def set_json(self, key: str, value: str, resource: Optional[Union['binaryview.BinaryView', 'function.Function']] = None, scope: 'SettingsScope' = SettingsScope.SettingsAutoScope) -> bool:
		view_handle = None
		func_handle = None
		if resource is not None:
			if isinstance(resource, binaryview.BinaryView):
				view_handle = resource.handle
			elif isinstance(resource, function.Function):
				func_handle = resource.handle
			else:
				raise TypeError("Expected resource to be either a BinaryView or a Function.")
		return core.BNSettingsSetJson(self.handle, view_handle, func_handle, scope, key, value)
