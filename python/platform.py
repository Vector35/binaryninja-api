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
import binaryninja
from binaryninja import _binaryninjacore as core
from binaryninja import types

# 2-3 compatibility
from binaryninja import range
from binaryninja import with_metaclass


class _PlatformMetaClass(type):

	def __iter__(self):
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		platforms = core.BNGetPlatformList(count)
		try:
			for i in range(0, count.value):
				yield Platform(handle = core.BNNewPlatformReference(platforms[i]))
		finally:
			core.BNFreePlatformList(platforms, count.value)

	def __getitem__(cls, value):
		binaryninja._init_plugins()
		platform = core.BNGetPlatformByName(str(value))
		if platform is None:
			raise KeyError("'%s' is not a valid platform" % str(value))
		return Platform(handle = platform)

	@property
	def list(self):
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		platforms = core.BNGetPlatformList(count)
		result = []
		for i in range(0, count.value):
			result.append(Platform(handle = core.BNNewPlatformReference(platforms[i])))
		core.BNFreePlatformList(platforms, count.value)
		return result

	@property
	def os_list(self):
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		platforms = core.BNGetPlatformOSList(count)
		result = []
		for i in range(0, count.value):
			result.append(str(platforms[i]))
		core.BNFreePlatformOSList(platforms, count.value)
		return result

	def get_list(cls, os = None, arch = None):
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		if os is None:
			platforms = core.BNGetPlatformList(count)
		elif arch is None:
			platforms = core.BNGetPlatformListByOS(os)
		else:
			platforms = core.BNGetPlatformListByArchitecture(os, arch.handle)
		result = []
		for i in range(0, count.value):
			result.append(Platform(handle = core.BNNewPlatformReference(platforms[i])))
		core.BNFreePlatformList(platforms, count.value)
		return result


class Platform(with_metaclass(_PlatformMetaClass, object)):
	"""
	``class Platform`` contains all information related to the execution environment of the binary, mainly the
	calling conventions used.
	"""
	name = None

	def __init__(self, arch = None, handle = None):
		if handle is None:
			if arch is None:
				self.handle = None
				raise ValueError("platform must have an associated architecture")
			self._arch = arch
			self.handle = core.BNCreatePlatform(arch.handle, self.__class__.name)
		else:
			self.handle = handle
			self.__dict__["name"] = core.BNGetPlatformName(self.handle)
			self._arch = binaryninja.architecture.CoreArchitecture._from_cache(core.BNGetPlatformArchitecture(self.handle))

	def __del__(self):
		if self.handle is not None:
			core.BNFreePlatform(self.handle)

	def __repr__(self):
		return "<platform: %s>" % self.name

	def __str__(self):
		return self.name

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(other.handle.contents)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	@property
	def list(self):
		"""Allow tab completion to discover metaclass list property"""
		pass

	@property
	def default_calling_convention(self):
		"""
		Default calling convention.

		:getter: returns a CallingConvention object for the default calling convention.
		:setter: sets the default calling convention
		:type: CallingConvention
		"""
		result = core.BNGetPlatformDefaultCallingConvention(self.handle)
		if result is None:
			return None
		return binaryninja.callingconvention.CallingConvention(handle=result)

	@default_calling_convention.setter
	def default_calling_convention(self, value):
		core.BNRegisterPlatformDefaultCallingConvention(self.handle, value.handle)

	@property
	def cdecl_calling_convention(self):
		"""
		Cdecl calling convention.

		:getter: returns a CallingConvention object for the cdecl calling convention.
		:setter sets the cdecl calling convention
		:type: CallingConvention
		"""
		result = core.BNGetPlatformCdeclCallingConvention(self.handle)
		if result is None:
			return None
		return binaryninja.callingconvention.CallingConvention(handle=result)

	@cdecl_calling_convention.setter
	def cdecl_calling_convention(self, value):
		core.BNRegisterPlatformCdeclCallingConvention(self.handle, value.handle)

	@property
	def stdcall_calling_convention(self):
		"""
		Stdcall calling convention.

		:getter: returns a CallingConvention object for the stdcall calling convention.
		:setter sets the stdcall calling convention
		:type: CallingConvention
		"""
		result = core.BNGetPlatformStdcallCallingConvention(self.handle)
		if result is None:
			return None
		return binaryninja.callingconvention.CallingConvention(handle=result)

	@stdcall_calling_convention.setter
	def stdcall_calling_convention(self, value):
		core.BNRegisterPlatformStdcallCallingConvention(self.handle, value.handle)

	@property
	def fastcall_calling_convention(self):
		"""
		Fastcall calling convention.

		:getter: returns a CallingConvention object for the fastcall calling convention.
		:setter sets the fastcall calling convention
		:type: CallingConvention
		"""
		result = core.BNGetPlatformFastcallCallingConvention(self.handle)
		if result is None:
			return None
		return binaryninja.callingconvention.CallingConvention(handle=result)

	@fastcall_calling_convention.setter
	def fastcall_calling_convention(self, value):
		core.BNRegisterPlatformFastcallCallingConvention(self.handle, value.handle)

	@property
	def system_call_convention(self):
		"""
		System call convention.

		:getter: returns a CallingConvention object for the system call convention.
		:setter sets the system call convention
		:type: CallingConvention
		"""
		result = core.BNGetPlatformSystemCallConvention(self.handle)
		if result is None:
			return None
		return binaryninja.callingconvention.CallingConvention(handle=result)

	@system_call_convention.setter
	def system_call_convention(self, value):
		core.BNSetPlatformSystemCallConvention(self.handle, value.handle)

	@property
	def calling_conventions(self):
		"""
		List of platform CallingConvention objects (read-only)

		:getter: returns the list of supported CallingConvention objects
		:type: list(CallingConvention)
		"""
		count = ctypes.c_ulonglong()
		cc = core.BNGetPlatformCallingConventions(self.handle, count)
		result = []
		for i in range(0, count.value):
			result.append(binaryninja.callingconvention.CallingConvention(handle=core.BNNewCallingConventionReference(cc[i])))
		core.BNFreeCallingConventionList(cc, count.value)
		return result

	@property
	def types(self):
		"""List of platform-specific types (read-only)"""
		count = ctypes.c_ulonglong(0)
		type_list = core.BNGetPlatformTypes(self.handle, count)
		result = {}
		for i in range(0, count.value):
			name = types.QualifiedName._from_core_struct(type_list[i].name)
			result[name] = types.Type(core.BNNewTypeReference(type_list[i].type), platform = self)
		core.BNFreeTypeList(type_list, count.value)
		return result

	@property
	def variables(self):
		"""List of platform-specific variable definitions (read-only)"""
		count = ctypes.c_ulonglong(0)
		type_list = core.BNGetPlatformVariables(self.handle, count)
		result = {}
		for i in range(0, count.value):
			name = types.QualifiedName._from_core_struct(type_list[i].name)
			result[name] = types.Type(core.BNNewTypeReference(type_list[i].type), platform = self)
		core.BNFreeTypeList(type_list, count.value)
		return result

	@property
	def functions(self):
		"""List of platform-specific function definitions (read-only)"""
		count = ctypes.c_ulonglong(0)
		type_list = core.BNGetPlatformFunctions(self.handle, count)
		result = {}
		for i in range(0, count.value):
			name = types.QualifiedName._from_core_struct(type_list[i].name)
			result[name] = types.Type(core.BNNewTypeReference(type_list[i].type), platform = self)
		core.BNFreeTypeList(type_list, count.value)
		return result

	@property
	def system_calls(self):
		"""List of system calls for this platform (read-only)"""
		count = ctypes.c_ulonglong(0)
		call_list = core.BNGetPlatformSystemCalls(self.handle, count)
		result = {}
		for i in range(0, count.value):
			name = types.QualifiedName._from_core_struct(call_list[i].name)
			t = types.Type(core.BNNewTypeReference(call_list[i].type), platform = self)
			result[call_list[i].number] = (name, t)
		core.BNFreeSystemCallList(call_list, count.value)
		return result

	@property
	def type_libraries(self):
		count = ctypes.c_ulonglong(0)
		libs = core.BNGetPlatformTypeLibraries(self.handle, count)
		result = []
		for i in range(0, count.value):
			result.append(binaryninja.TypeLibrary(core.BNNewTypeLibraryReference(libs[i])))
		core.BNFreeTypeLibraryList(libs, count.value)
		return result

	def get_type_libraries_by_name(self, name):
		count = ctypes.c_ulonglong(0)
		libs = core.BNGetPlatformTypeLibrariesByName(self.handle, name, count)
		result = []
		for i in range(0, count.value):
			result.append(binaryninja.TypeLibrary(core.BNNewTypeLibraryReference(libs[i])))
		core.BNFreeTypeLibraryList(libs, count.value)
		return result

	def register(self, os):
		"""
		``register`` registers the platform for given OS name.

		:param str os: OS name to register
		:rtype: None
		"""
		core.BNRegisterPlatform(os, self.handle)

	def register_calling_convention(self, cc):
		"""
		``register_calling_convention`` register a new calling convention.

		:param CallingConvention cc: a CallingConvention object to register
		:rtype: None
		"""
		core.BNRegisterPlatformCallingConvention(self.handle, cc.handle)

	def get_related_platform(self, arch):
		result = core.BNGetRelatedPlatform(self.handle, arch.handle)
		if not result:
			return None
		return Platform(handle = result)

	def add_related_platform(self, arch, platform):
		core.BNAddRelatedPlatform(self.handle, arch.handle, platform.handle)

	def get_associated_platform_by_address(self, addr):
		new_addr = ctypes.c_ulonglong()
		new_addr.value = addr
		result = core.BNGetAssociatedPlatformByAddress(self.handle, new_addr)
		return Platform(handle = result), new_addr.value

	def get_type_by_name(self, name):
		name = types.QualifiedName(name)._get_core_struct()
		obj = core.BNGetPlatformTypeByName(self.handle, name)
		if not obj:
			return None
		return types.Type(obj, platform = self)

	def get_variable_by_name(self, name):
		name = types.QualifiedName(name)._get_core_struct()
		obj = core.BNGetPlatformVariableByName(self.handle, name)
		if not obj:
			return None
		return types.Type(obj, platform = self)

	def get_function_by_name(self, name, exactMatch=False):
		name = types.QualifiedName(name)._get_core_struct()
		obj = core.BNGetPlatformFunctionByName(self.handle, name, exactMatch)
		if not obj:
			return None
		return types.Type(obj, platform = self)

	def get_system_call_name(self, number):
		return core.BNGetPlatformSystemCallName(self.handle, number)

	def get_system_call_type(self, number):
		obj = core.BNGetPlatformSystemCallType(self.handle, number)
		if not obj:
			return None
		return types.Type(obj, platform = self)

	def generate_auto_platform_type_id(self, name):
		name = types.QualifiedName(name)._get_core_struct()
		return core.BNGenerateAutoPlatformTypeId(self.handle, name)

	def generate_auto_platform_type_ref(self, type_class, name):
		type_id = self.generate_auto_platform_type_id(name)
		return types.NamedTypeReference(type_class, type_id, name)

	def get_auto_platform_type_id_source(self):
		return core.BNGetAutoPlatformTypeIdSource(self.handle)

	def parse_types_from_source(self, source, filename=None, include_dirs=[], auto_type_source=None):
		"""
		``parse_types_from_source`` parses the source string and any needed headers searching for them in
		the optional list of directories provided in ``include_dirs``.

		:param str source: source string to be parsed
		:param str filename: optional source filename
		:param include_dirs: optional list of string filename include directories
		:type include_dirs: list(str)
		:param str auto_type_source: optional source of types if used for automatically generated types
		:return: :py:class:`TypeParserResult` (a SyntaxError is thrown on parse error)
		:rtype: TypeParserResult
		:Example:

			>>> platform.parse_types_from_source('int foo;\\nint bar(int x);\\nstruct bas{int x,y;};\\n')
			({types: {'bas': <type: struct bas>}, variables: {'foo': <type: int32_t>}, functions:{'bar':
			<type: int32_t(int32_t x)>}}, '')
			>>>
		"""

		if filename is None:
			filename = "input"
		dir_buf = (ctypes.c_char_p * len(include_dirs))()
		for i in range(0, len(include_dirs)):
			dir_buf[i] = include_dirs[i].encode('charmap')
		parse = core.BNTypeParserResult()
		errors = ctypes.c_char_p()
		result = core.BNParseTypesFromSource(self.handle, source, filename, parse, errors, dir_buf,
			len(include_dirs), auto_type_source)
		error_str = errors.value
		core.BNFreeString(ctypes.cast(errors, ctypes.POINTER(ctypes.c_byte)))
		if not result:
			raise SyntaxError(error_str)
		type_dict = {}
		variables = {}
		functions = {}
		for i in range(0, parse.typeCount):
			name = types.QualifiedName._from_core_struct(parse.types[i].name)
			type_dict[name] = types.Type(core.BNNewTypeReference(parse.types[i].type), platform = self)
		for i in range(0, parse.variableCount):
			name = types.QualifiedName._from_core_struct(parse.variables[i].name)
			variables[name] = types.Type(core.BNNewTypeReference(parse.variables[i].type), platform = self)
		for i in range(0, parse.functionCount):
			name = types.QualifiedName._from_core_struct(parse.functions[i].name)
			functions[name] = types.Type(core.BNNewTypeReference(parse.functions[i].type), platform = self)
		core.BNFreeTypeParserResult(parse)
		return types.TypeParserResult(type_dict, variables, functions)

	def parse_types_from_source_file(self, filename, include_dirs=[], auto_type_source=None):
		"""
		``parse_types_from_source_file`` parses the source file ``filename`` and any needed headers searching for them in
		the optional list of directories provided in ``include_dirs``.

		:param str filename: filename of file to be parsed
		:param include_dirs: optional list of string filename include directories
		:type include_dirs: list(str)
		:param str auto_type_source: optional source of types if used for automatically generated types
		:return: :py:class:`TypeParserResult` (a SyntaxError is thrown on parse error)
		:rtype: TypeParserResult
		:Example:

			>>> file = "/Users/binja/tmp.c"
			>>> open(file).read()
			'int foo;\\nint bar(int x);\\nstruct bas{int x,y;};\\n'
			>>> platform.parse_types_from_source_file(file)
			({types: {'bas': <type: struct bas>}, variables: {'foo': <type: int32_t>}, functions:
			{'bar': <type: int32_t(int32_t x)>}}, '')
			>>>
		"""
		dir_buf = (ctypes.c_char_p * len(include_dirs))()
		for i in range(0, len(include_dirs)):
			dir_buf[i] = include_dirs[i].encode('charmap')
		parse = core.BNTypeParserResult()
		errors = ctypes.c_char_p()
		result = core.BNParseTypesFromSourceFile(self.handle, filename, parse, errors, dir_buf,
			len(include_dirs), auto_type_source)
		error_str = errors.value
		core.BNFreeString(ctypes.cast(errors, ctypes.POINTER(ctypes.c_byte)))
		if not result:
			raise SyntaxError(error_str)
		type_dict = {}
		variables = {}
		functions = {}
		for i in range(0, parse.typeCount):
			name = types.QualifiedName._from_core_struct(parse.types[i].name)
			type_dict[name] = types.Type(core.BNNewTypeReference(parse.types[i].type), platform = self)
		for i in range(0, parse.variableCount):
			name = types.QualifiedName._from_core_struct(parse.variables[i].name)
			variables[name] = types.Type(core.BNNewTypeReference(parse.variables[i].type), platform = self)
		for i in range(0, parse.functionCount):
			name = types.QualifiedName._from_core_struct(parse.functions[i].name)
			functions[name] = types.Type(core.BNNewTypeReference(parse.functions[i].type), platform = self)
		core.BNFreeTypeParserResult(parse)
		return types.TypeParserResult(type_dict, variables, functions)

	@property
	def arch(self):
		""" """
		return self._arch

	@arch.setter
	def arch(self, value):
		self._arch = value
