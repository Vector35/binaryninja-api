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

import os
import ctypes
import traceback
from typing import List, Dict, Optional

# Binary Ninja components
import binaryninja
from . import _binaryninjacore as core
from . import types
from . import typeparser
from . import callingconvention
from . import typelibrary
from . import architecture
from . import typecontainer
from . import binaryview
from .log import log_error


class _PlatformMetaClass(type):
	def __iter__(self):
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		platforms = core.BNGetPlatformList(count)
		assert platforms is not None, "core.BNGetPlatformList returned None"
		try:
			for i in range(0, count.value):
				yield Platform(handle=core.BNNewPlatformReference(platforms[i]))
		finally:
			core.BNFreePlatformList(platforms, count.value)

	def __getitem__(cls, value):
		binaryninja._init_plugins()
		platform = core.BNGetPlatformByName(str(value))
		if platform is None:
			raise KeyError("'%s' is not a valid platform" % str(value))
		return Platform(handle=platform)


class Platform(metaclass=_PlatformMetaClass):
	"""
	``class Platform`` contains all information related to the execution environment of the binary, mainly the
	calling conventions used.
	"""
	name = None
	type_file_path = None  # path to platform types file
	type_include_dirs = []  # list of directories available to #include from type_file_path
	global_regs = [] # list of global registers. if empty, it populated with the arch global reg list
	global_reg_types = {} # opportunity for plugin to provide default types for the entry value of global registers

	_registered_platforms = []

	def __init__(self, arch: Optional['architecture.Architecture'] = None, handle=None):
		if handle is None:
			if arch is None:
				raise ValueError("platform must have an associated architecture")
			assert self.__class__.name is not None, "Can not instantiate Platform directly, you probably want arch.standalone_platform"
			_arch = arch
			if len(self.global_regs) == 0:
				self.__dict__["global_regs"] = arch.global_regs
			self._cb = core.BNCustomPlatform()
			self._cb.context = 0
			self._cb.init = self._cb.init.__class__(self._init)
			self._cb.viewInit = self._cb.viewInit.__class__(self._view_init)
			self._cb.getGlobalRegisters = self._cb.getGlobalRegisters.__class__(self._get_global_regs)
			self._cb.freeRegisterList = self._cb.freeRegisterList.__class__(self._free_register_list)
			self._cb.getGlobalRegisterType = self._cb.getGlobalRegisterType.__class__(self._get_global_reg_type)
			self._pending_reg_lists = {}
			if self.__class__.type_file_path is None:
				_handle = core.BNCreateCustomPlatform(arch.handle, self.__class__.name, self._cb)
				assert _handle is not None
			else:
				dir_buf = (ctypes.c_char_p * len(self.__class__.type_include_dirs))()
				for (i, dir) in enumerate(self.__class__.type_include_dirs):
					dir_buf[i] = dir.encode('charmap')
				_handle = core.BNCreateCustomPlatformWithTypes(
				    arch.handle, self.__class__.name, self._cb, self.__class__.type_file_path, dir_buf,
				    len(self.__class__.type_include_dirs)
				)
				assert _handle is not None
				self.__class__._registered_platforms.append(self)
		else:
			_handle = handle
			_arch = architecture.CoreArchitecture._from_cache(core.BNGetPlatformArchitecture(_handle))
			count = ctypes.c_ulonglong()
			regs = core.BNGetPlatformGlobalRegisters(handle, count)
			result = []
			for i in range(0, count.value):
				result.append(_arch.get_reg_name(regs[i]))
			core.BNFreeRegisterList(regs)
			self.__dict__["global_regs"] = result
		assert _handle is not None
		assert _arch is not None
		self.handle: ctypes.POINTER(core.BNPlatform) = _handle
		self._arch = _arch
		self._name = None

	def _init(self, ctxt):
		pass

	def _view_init(self, ctxt, view):
		try:
			view_obj = binaryview.BinaryView(handle=core.BNNewViewReference(view))
			self.view_init(view)
		except:
			log_error(traceback.format_exc())

	def _get_global_regs(self, ctxt, count):
		try:
			regs = self.global_regs
			count[0] = len(regs)
			reg_buf = (ctypes.c_uint * len(regs))()
			for i in range(0, len(regs)):
				reg_buf[i] = self.arch.regs[regs[i]].index
			result = ctypes.cast(reg_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, reg_buf)
			return result.value
		except:
			log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _free_register_list(self, ctxt, regs, size):
		try:
			buf = ctypes.cast(regs, ctypes.c_void_p)
			if buf.value not in self._pending_reg_lists:
				raise ValueError("freeing register list that wasn't allocated")
			del self._pending_reg_lists[buf.value]
		except:
			log_error(traceback.format_exc())

	def _get_global_reg_type(self, ctxt, reg):
		try:
			reg_name = self.arch.get_reg_name(reg)
			if reg_name in self.global_reg_types:
				type_obj = self.global_reg_types[reg_name]
				log_error(f"aaaa {type_obj}")
				handle = core.BNNewTypeReference(type_obj.handle)
				return ctypes.cast(handle, ctypes.c_void_p).value
			return None
		except:
			log_error(traceback.format_exc())
			return None

	def __del__(self):
		if core is not None:
			core.BNFreePlatform(self.handle)

	def __repr__(self):
		return f"<platform: {self.name}>"

	def __str__(self):
		return self.name

	def __eq__(self, other: 'Platform'):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(other.handle.contents)

	def __ne__(self, other: 'Platform'):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash(ctypes.addressof(self.handle.contents))

	@property
	def name(self) -> str:
		if self._name is None:
			self._name = core.BNGetPlatformName(self.handle)
		return self._name

	@classmethod
	@property
	def os_list(cls) -> List[str]:
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		platforms = core.BNGetPlatformOSList(count)
		assert platforms is not None, "core.BNGetPlatformOSList returned None"
		result:List[str] = []
		for i in range(count.value):
			result.append(str(platforms[i]))
		core.BNFreePlatformOSList(platforms, count.value)
		return result

	@classmethod
	def get_list(cls, os=None, arch=None):
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		if os is None:
			platforms = core.BNGetPlatformList(count)
			assert platforms is not None, "core.BNGetPlatformList returned None"
		elif arch is None:
			platforms = core.BNGetPlatformListByOS(os, count)
			assert platforms is not None, "core.BNGetPlatformListByOS returned None"
		else:
			platforms = core.BNGetPlatformListByArchitecture(arch.handle, count)
			assert platforms is not None, "core.BNGetPlatformListByArchitecture returned None"
		result = []
		for i in range(0, count.value):
			result.append(Platform(handle=core.BNNewPlatformReference(platforms[i])))
		core.BNFreePlatformList(platforms, count.value)
		return result

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
		return callingconvention.CallingConvention(handle=result)

	@default_calling_convention.setter
	def default_calling_convention(self, value):
		core.BNRegisterPlatformDefaultCallingConvention(self.handle, value.handle)

	@property
	def cdecl_calling_convention(self):
		"""
		CallingConvention object for the cdecl calling convention
		"""
		result = core.BNGetPlatformCdeclCallingConvention(self.handle)
		if result is None:
			return None
		return callingconvention.CallingConvention(handle=result)

	@cdecl_calling_convention.setter
	def cdecl_calling_convention(self, value):
		"""
		Sets the cdecl calling convention
		"""
		core.BNRegisterPlatformCdeclCallingConvention(self.handle, value.handle)

	@property
	def stdcall_calling_convention(self):
		"""
		CallingConvention object for the stdcall calling convention
		"""
		result = core.BNGetPlatformStdcallCallingConvention(self.handle)
		if result is None:
			return None
		return callingconvention.CallingConvention(handle=result)

	@stdcall_calling_convention.setter
	def stdcall_calling_convention(self, value):
		"""
		Sets the stdcall calling convention
		"""
		core.BNRegisterPlatformStdcallCallingConvention(self.handle, value.handle)

	@property
	def fastcall_calling_convention(self):
		"""
		CallingConvention object for the fastcall calling convention
		"""
		result = core.BNGetPlatformFastcallCallingConvention(self.handle)
		if result is None:
			return None
		return callingconvention.CallingConvention(handle=result)

	@fastcall_calling_convention.setter
	def fastcall_calling_convention(self, value):
		"""
		Sets the fastcall calling convention
		"""
		core.BNRegisterPlatformFastcallCallingConvention(self.handle, value.handle)

	@property
	def system_call_convention(self):
		"""
		CallingConvention object for the system call convention
		"""
		result = core.BNGetPlatformSystemCallConvention(self.handle)
		if result is None:
			return None
		return callingconvention.CallingConvention(handle=result)

	@system_call_convention.setter
	def system_call_convention(self, value):
		"""
		Sets the system call convention
		"""
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
		assert cc is not None, "core.BNGetPlatformCallingConventions returned None"
		result = []
		for i in range(0, count.value):
			result.append(callingconvention.CallingConvention(handle=core.BNNewCallingConventionReference(cc[i])))
		core.BNFreeCallingConventionList(cc, count.value)
		return result

	def get_global_register_type(self, reg: 'architecture.RegisterType'):
		reg = self.arch.get_reg_index(reg)
		type_obj = core.BNGetPlatformGlobalRegisterType(self.handle, reg)
		if type_obj is None:
			return None
		return types.Type.create(type_obj, platform=self)

	def view_init(self, view):
		pass
		#raise NotImplementedError


	@property
	def types(self):
		"""List of platform-specific types (read-only)"""
		count = ctypes.c_ulonglong(0)
		type_list = core.BNGetPlatformTypes(self.handle, count)
		assert type_list is not None, "core.BNGetPlatformTypes returned None"
		result = {}
		for i in range(0, count.value):
			name = types.QualifiedName._from_core_struct(type_list[i].name)
			result[name] = types.Type.create(core.BNNewTypeReference(type_list[i].type), platform=self)
		core.BNFreeTypeAndNameList(type_list, count.value)
		return result

	@property
	def variables(self):
		"""List of platform-specific variable definitions (read-only)"""
		count = ctypes.c_ulonglong(0)
		type_list = core.BNGetPlatformVariables(self.handle, count)
		assert type_list is not None, "core.BNGetPlatformVariables returned None"
		result = {}
		for i in range(0, count.value):
			name = types.QualifiedName._from_core_struct(type_list[i].name)
			result[name] = types.Type.create(core.BNNewTypeReference(type_list[i].type), platform=self)
		core.BNFreeTypeAndNameList(type_list, count.value)
		return result

	@property
	def functions(self):
		"""List of platform-specific function definitions (read-only)"""
		count = ctypes.c_ulonglong(0)
		type_list = core.BNGetPlatformFunctions(self.handle, count)
		assert type_list is not None, "core.BNGetPlatformFunctions returned None"
		result = {}
		for i in range(0, count.value):
			name = types.QualifiedName._from_core_struct(type_list[i].name)
			result[name] = types.Type.create(core.BNNewTypeReference(type_list[i].type), platform=self)
		core.BNFreeTypeAndNameList(type_list, count.value)
		return result

	@property
	def system_calls(self):
		"""List of system calls for this platform (read-only)"""
		count = ctypes.c_ulonglong(0)
		call_list = core.BNGetPlatformSystemCalls(self.handle, count)
		assert call_list is not None, "core.BNGetPlatformSystemCalls returned None"
		result = {}
		for i in range(0, count.value):
			name = types.QualifiedName._from_core_struct(call_list[i].name)
			t = types.Type.create(core.BNNewTypeReference(call_list[i].type), platform=self)
			result[call_list[i].number] = (name, t)
		core.BNFreeSystemCallList(call_list, count.value)
		return result

	@property
	def type_libraries(self) -> List['typelibrary.TypeLibrary']:
		count = ctypes.c_ulonglong(0)
		libs = core.BNGetPlatformTypeLibraries(self.handle, count)
		assert libs is not None, "core.BNGetPlatformTypeLibraries returned None"
		result = []
		for i in range(0, count.value):
			result.append(typelibrary.TypeLibrary(core.BNNewTypeLibraryReference(libs[i])))
		core.BNFreeTypeLibraryList(libs, count.value)
		return result

	def get_type_libraries_by_name(self, name) -> List['typelibrary.TypeLibrary']:
		count = ctypes.c_ulonglong(0)
		libs = core.BNGetPlatformTypeLibrariesByName(self.handle, name, count)
		assert libs is not None, "core.BNGetPlatformTypeLibrariesByName returned None"
		result = []
		for i in range(0, count.value):
			result.append(typelibrary.TypeLibrary(core.BNNewTypeLibraryReference(libs[i])))
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
		return Platform(handle=result)

	def add_related_platform(self, arch, platform):
		core.BNAddRelatedPlatform(self.handle, arch.handle, platform.handle)

	def get_associated_platform_by_address(self, addr):
		new_addr = ctypes.c_ulonglong()
		new_addr.value = addr
		result = core.BNGetAssociatedPlatformByAddress(self.handle, new_addr)
		return Platform(handle=result), new_addr.value

	@property
	def type_container(self) -> 'typecontainer.TypeContainer':
		"""
		Type Container for all registered types in the Platform.
		:return: Platform types Type Container
		"""
		return typecontainer.TypeContainer(core.BNGetPlatformTypeContainer(self.handle))

	def get_type_by_name(self, name):
		name = types.QualifiedName(name)._to_core_struct()
		obj = core.BNGetPlatformTypeByName(self.handle, name)
		if not obj:
			return None
		return types.Type.create(obj, platform=self)

	def get_variable_by_name(self, name):
		name = types.QualifiedName(name)._to_core_struct()
		obj = core.BNGetPlatformVariableByName(self.handle, name)
		if not obj:
			return None
		return types.Type.create(obj, platform=self)

	def get_function_by_name(self, name, exactMatch=False):
		name = types.QualifiedName(name)._to_core_struct()
		obj = core.BNGetPlatformFunctionByName(self.handle, name, exactMatch)
		if not obj:
			return None
		return types.Type.create(obj, platform=self)

	def get_system_call_name(self, number):
		return core.BNGetPlatformSystemCallName(self.handle, number)

	def get_system_call_type(self, number):
		obj = core.BNGetPlatformSystemCallType(self.handle, number)
		if not obj:
			return None
		return types.Type.create(obj, platform=self)

	def generate_auto_platform_type_id(self, name):
		name = types.QualifiedName(name)._to_core_struct()
		return core.BNGenerateAutoPlatformTypeId(self.handle, name)

	def generate_auto_platform_type_ref(self, type_class, name):
		type_id = self.generate_auto_platform_type_id(name)
		return types.NamedTypeReferenceBuilder.create(type_class, type_id, name)

	def get_auto_platform_type_id_source(self):
		return core.BNGetAutoPlatformTypeIdSource(self.handle)

	def parse_types_from_source(
	    self, source, filename=None, include_dirs: Optional[List[str]] = None, auto_type_source=None
	):
		"""
		``parse_types_from_source`` parses the source string and any needed headers searching for them in
		the optional list of directories provided in ``include_dirs``. Note that this API does not allow
		the source to rely on existing types that only exist in a specific view. Use :py:meth:`BinaryView.parse_type_string` instead.

		:param str source: source string to be parsed
		:param str filename: optional source filename
		:param include_dirs: optional list of string filename include directories
		:type include_dirs: list(str)
		:param str auto_type_source: optional source of types if used for automatically generated types
		:return: :py:class:`BasicTypeParserResult` (a SyntaxError is thrown on parse error)
		:rtype: BasicTypeParserResult
		:Example:

			>>> platform.parse_types_from_source('int foo;\\nint bar(int x);\\nstruct bas{int x,y;};\\n')
			({types: {'bas': <type: struct bas>}, variables: {'foo': <type: int32_t>}, functions:{'bar':
			<type: int32_t(int32_t x)>}}, '')
			>>>
		"""

		if filename is None:
			filename = "input"
		if not isinstance(source, str):
			raise AttributeError("Source must be a string")
		if include_dirs is None:
			include_dirs = []
		dir_buf = (ctypes.c_char_p * len(include_dirs))()
		for i in range(0, len(include_dirs)):
			dir_buf[i] = include_dirs[i].encode('charmap')
		parse = core.BNTypeParserResult()
		errors = ctypes.c_char_p()
		result = core.BNParseTypesFromSource(
		    self.handle, source, filename, parse, errors, dir_buf, len(include_dirs), auto_type_source
		)
		assert errors.value is not None, "core.BNParseTypesFromSource returned errors set to None"
		error_str = errors.value.decode("utf-8")
		core.free_string(errors)
		if not result:
			raise SyntaxError(error_str)
		type_dict: Dict[types.QualifiedName, types.Type] = {}
		variables: Dict[types.QualifiedName, types.Type] = {}
		functions: Dict[types.QualifiedName, types.Type] = {}
		for i in range(0, parse.typeCount):
			name = types.QualifiedName._from_core_struct(parse.types[i].name)
			type_dict[name] = types.Type.create(core.BNNewTypeReference(parse.types[i].type), platform=self)
		for i in range(0, parse.variableCount):
			name = types.QualifiedName._from_core_struct(parse.variables[i].name)
			variables[name] = types.Type.create(core.BNNewTypeReference(parse.variables[i].type), platform=self)
		for i in range(0, parse.functionCount):
			name = types.QualifiedName._from_core_struct(parse.functions[i].name)
			functions[name] = types.Type.create(core.BNNewTypeReference(parse.functions[i].type), platform=self)
		core.BNFreeTypeParserResult(parse)
		return typeparser.BasicTypeParserResult(type_dict, variables, functions)

	def parse_types_from_source_file(self, filename, include_dirs: Optional[List[str]] = None, auto_type_source=None):
		"""
		``parse_types_from_source_file`` parses the source file ``filename`` and any needed headers searching for them in
		the optional list of directories provided in ``include_dirs``. Note that this API does not allow
		the source to rely on existing types that only exist in a specific view. Use :py:meth:`BinaryView.parse_type_string` instead.

		:param str filename: filename of file to be parsed
		:param include_dirs: optional list of string filename include directories
		:type include_dirs: list(str)
		:param str auto_type_source: optional source of types if used for automatically generated types
		:return: :py:class:`BasicTypeParserResult` (a SyntaxError is thrown on parse error)
		:rtype: BasicTypeParserResult
		:Example:

			>>> file = "/Users/binja/tmp.c"
			>>> open(file).read()
			'int foo;\\nint bar(int x);\\nstruct bas{int x,y;};\\n'
			>>> platform.parse_types_from_source_file(file)
			({types: {'bas': <type: struct bas>}, variables: {'foo': <type: int32_t>}, functions:
			{'bar': <type: int32_t(int32_t x)>}}, '')
			>>>
		"""
		if not (isinstance(filename, str) and os.path.isfile(filename) and os.access(filename, os.R_OK)):
			raise AttributeError("File {} doesn't exist or isn't readable".format(filename))
		if include_dirs is None:
			include_dirs = []
		dir_buf = (ctypes.c_char_p * len(include_dirs))()
		for i in range(0, len(include_dirs)):
			dir_buf[i] = include_dirs[i].encode('charmap')
		parse = core.BNTypeParserResult()
		errors = ctypes.c_char_p()
		result = core.BNParseTypesFromSourceFile(
		    self.handle, filename, parse, errors, dir_buf, len(include_dirs), auto_type_source
		)
		assert errors.value is not None, "core.BNParseTypesFromSourceFile returned errors set to None"
		error_str = errors.value.decode("utf-8")
		core.free_string(errors)
		if not result:
			raise SyntaxError(error_str)
		type_dict = {}
		variables = {}
		functions = {}
		for i in range(0, parse.typeCount):
			name = types.QualifiedName._from_core_struct(parse.types[i].name)
			type_dict[name] = types.Type.create(core.BNNewTypeReference(parse.types[i].type), platform=self)
		for i in range(0, parse.variableCount):
			name = types.QualifiedName._from_core_struct(parse.variables[i].name)
			variables[name] = types.Type.create(core.BNNewTypeReference(parse.variables[i].type), platform=self)
		for i in range(0, parse.functionCount):
			name = types.QualifiedName._from_core_struct(parse.functions[i].name)
			functions[name] = types.Type.create(core.BNNewTypeReference(parse.functions[i].type), platform=self)
		core.BNFreeTypeParserResult(parse)
		return typeparser.BasicTypeParserResult(type_dict, variables, functions)

	@property
	def arch(self):
		return self._arch
