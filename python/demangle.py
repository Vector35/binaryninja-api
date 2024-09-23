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
import traceback

# Binary Ninja components
import binaryninja
from . import _binaryninjacore as core
from . import binaryview
from . import types
from .log import log_error
from .architecture import Architecture, CoreArchitecture
from .platform import Platform
from typing import Iterable, List, Optional, Union, Tuple


def get_qualified_name(names: Iterable[str]):
	"""
	``get_qualified_name`` gets a qualified name for the provided name list.

	:param names: name list to qualify
	:type names: list(str)
	:return: a qualified name
	:rtype: str
	:Example:

		>>> type, name = demangle_ms(Architecture["x86_64"], "?testf@Foobar@@SA?AW4foo@1@W421@@Z")
		>>> get_qualified_name(name)
		'Foobar::testf'
		>>>
	"""
	return "::".join(names)


def demangle_generic(
		archOrPlatform: Union[Architecture, Platform],
		mangled_name: str,
		view: Optional['binaryview.BinaryView'] = None,
		simplify: bool = False
) -> Optional[Tuple[Optional['types.Type'], List[str]]]:
	"""
	``demangle_generic`` demangles a mangled symbol name to a Type object.

	:param Union[Architecture, Platform] archOrPlatform: Architecture or Platform for the symbol. Required for pointer/integer sizes and calling conventions.
	:param str mangled_name: a mangled symbol name
	:param view: (optional) view of the binary containing the mangled name
	:param simplify: (optional) Whether to simplify demangled names
	:return: returns tuple of (Optional[Type], demangled_name) or None on error
	:rtype: Tuple
	:Example:

		>>> demangle_generic(Architecture["x86_64"], "?testf@Foobar@@SA?AW4foo@1@W421@@Z")
		(<type: public: static enum Foobar::foo __cdecl (enum Foobar::foo)>, ['Foobar', 'testf'])
		>>> demangle_generic(Architecture["x86_64"], "__ZN20ArmCallingConvention27GetIntegerArgumentRegistersEv")
		(<type: immutable:FunctionTypeClass 'int64_t()'>, ['ArmCallingConvention', 'GetIntegerArgumentRegisters'])
		>>>
	"""
	arch = None
	if isinstance(archOrPlatform, Architecture):
		arch = archOrPlatform
	elif isinstance(archOrPlatform, Platform):
		arch = archOrPlatform.arch
	else:
		raise TypeError("Unexpected arch or platform type")

	out_type = ctypes.POINTER(core.BNType)()
	out_var_name = core.BNQualifiedName()

	view_handle = None
	if view is not None:
		view_handle = view.handle

	if not core.BNDemangleGeneric(arch.handle, mangled_name, out_type, out_var_name, view_handle, simplify):
		return None, [mangled_name]

	result_type = None
	if out_type:
		result_type = types.Type.create(handle=out_type)
	result_var_name = types.QualifiedName._from_core_struct(out_var_name)
	core.BNFreeQualifiedName(out_var_name)
	return result_type, result_var_name.name


def demangle_llvm(mangled_name: str, options: Optional[Union[bool, binaryview.BinaryView]] = None) -> Optional[List[str]]:
	"""
	``demangle_llvm`` demangles a mangled name using the LLVM demangler.

	:param str mangled_name: a mangled (msvc/itanium/rust/dlang) name
	:param options: (optional) Whether to simplify demangled names : None falls back to user settings, a BinaryView uses that BinaryView's settings, or a boolean to set it directly
	:type options: Optional[Union[bool, BinaryView]]
	:return: returns demangled name or None on error
	:rtype: Optional[List[str]]
 	:Example:

   		>>> demangle_llvm("?testf@Foobar@@SA?AW4foo@1@W421@@Z")
		['public: static enum Foobar::foo __cdecl Foobar::testf(enum Foobar::foo)']
  		>>>
	"""
	outName = ctypes.POINTER(ctypes.c_char_p)()
	outSize = ctypes.c_ulonglong()
	names = []
	if (
			isinstance(options, binaryview.BinaryView) and core.BNDemangleLLVMWithOptions(
		mangled_name, ctypes.byref(outName), ctypes.byref(outSize), options.handle
	)
	) or (
			isinstance(options, bool) and core.BNDemangleLLVM(
		mangled_name, ctypes.byref(outName), ctypes.byref(outSize), options
	)
	) or (
			options is None and core.BNDemangleLLVMWithOptions(
		mangled_name, ctypes.byref(outName), ctypes.byref(outSize), None
	)
	):
		for i in range(outSize.value):
			names.append(outName[i].decode('utf8'))  # type: ignore
		core.BNFreeDemangledName(ctypes.byref(outName), outSize.value)
		return names
	return None


def demangle_ms(archOrPlatform: Union[Architecture, Platform], mangled_name: str, options: Optional[Union[bool, binaryview.BinaryView]] = False):
	"""
	``demangle_ms`` demangles a mangled Microsoft Visual Studio C++ name to a Type object.

	:param Union[Architecture, Platform] archOrPlatform: Architecture or Platform for the symbol. Required for pointer/integer sizes and calling conventions.
	:param str mangled_name: a mangled Microsoft Visual Studio C++ name
	:param options: (optional) Whether to simplify demangled names : None falls back to user settings, a BinaryView uses that BinaryView's settings, or a boolean to set it directly
	:type options: Optional[Union[bool, BinaryView]]
	:return: returns tuple of (Type, demangled_name) or (None, mangled_name) on error
	:rtype: Tuple[Optional[Type], Union[str, List[str]]]
	:Example:

		>>> demangle_ms(Platform["x86_64"], "?testf@Foobar@@SA?AW4foo@1@W421@@Z")
		(<type: public: static enum Foobar::foo __cdecl (enum Foobar::foo)>, ['Foobar', 'testf'])
		>>>
	"""
	handle = ctypes.POINTER(core.BNType)()
	outName = ctypes.POINTER(ctypes.c_char_p)()
	outSize = ctypes.c_ulonglong()
	names = []

	demangle = core.BNDemangleMS
	demangleWithOptions = core.BNDemangleMSWithOptions

	if isinstance(archOrPlatform, Platform):
		demangle = core.BNDemangleMSPlatform

	if (
	    isinstance(options, binaryview.BinaryView) and demangleWithOptions(
	        archOrPlatform.handle, mangled_name, ctypes.byref(handle), ctypes.byref(outName), ctypes.byref(outSize), options.handle
	    )
	) or (
	    isinstance(options, bool) and demangle(
	        archOrPlatform.handle, mangled_name, ctypes.byref(handle), ctypes.byref(outName), ctypes.byref(outSize), options
	    )
	) or (
	    options is None and demangleWithOptions(
	        archOrPlatform.handle, mangled_name, ctypes.byref(handle), ctypes.byref(outName), ctypes.byref(outSize), None
	    )
	):
		for i in range(outSize.value):
			names.append(outName[i].decode('utf8'))  # type: ignore
		core.BNFreeDemangledName(ctypes.byref(outName), outSize.value)
		if not handle:
			return (None, names)
		return (types.Type.create(handle), names)
	return (None, mangled_name)


def demangle_gnu3(arch, mangled_name: str, options: Optional[Union[bool, binaryview.BinaryView]] = None):
	"""
	``demangle_gnu3`` demangles a mangled name to a Type object.

	:param Architecture arch: Architecture for the symbol. Required for pointer and integer sizes.
	:param str mangled_name: a mangled GNU3 name
	:param options: (optional) Whether to simplify demangled names : None falls back to user settings, a BinaryView uses that BinaryView's settings, or a boolean to set it directly
	:type options: Optional[Union[bool, BinaryView]]
	:return: returns tuple of (Type, demangled_name) or (None, mangled_name) on error
	:rtype: Tuple[Optional[Type], Union[str, List[str]]]
	"""
	handle = ctypes.POINTER(core.BNType)()
	outName = ctypes.POINTER(ctypes.c_char_p)()
	outSize = ctypes.c_ulonglong()
	names = []
	if (
	    isinstance(options, binaryview.BinaryView) and core.BNDemangleGNU3WithOptions(
	        arch.handle, mangled_name, ctypes.byref(handle), ctypes.byref(outName), ctypes.byref(outSize), options.handle
	    )
	) or (
	    isinstance(options, bool) and core.BNDemangleGNU3(
	        arch.handle, mangled_name, ctypes.byref(handle), ctypes.byref(outName), ctypes.byref(outSize), options
	    )
	) or (
	    options is None and core.BNDemangleGNU3WithOptions(
	        arch.handle, mangled_name, ctypes.byref(handle), ctypes.byref(outName), ctypes.byref(outSize), None
	    )
	):
		for i in range(outSize.value):
			names.append(outName[i].decode('utf8'))  # type: ignore
		core.BNFreeDemangledName(ctypes.byref(outName), outSize.value)
		if not handle:
			return (None, names)
		return (types.Type.create(handle), names)
	return (None, mangled_name)


def simplify_name_to_string(input_name: Union[str, types.QualifiedName]):
	"""
	``simplify_name_to_string`` simplifies a templated C++ name with default arguments and returns a string

	:param input_name: String or qualified name to be simplified
	:type input_name: Union[str, QualifiedName]
	:return: simplified name (or original name if simplifier fails/cannot simplify)
	:rtype: str
	:Example:

		>>> demangle.simplify_name_to_string("std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >")
		'std::string'
		>>>
	"""
	result = None
	if isinstance(input_name, str):
		result = core.BNRustSimplifyStrToStr(input_name)
	elif isinstance(input_name, types.QualifiedName):
		result = core.BNRustSimplifyStrToStr(str(input_name))
	else:
		raise TypeError("Parameter must be of type `str` or `types.QualifiedName`")
	return result


def simplify_name_to_qualified_name(input_name: Union[str, types.QualifiedName], simplify: bool = True):
	"""
	``simplify_name_to_qualified_name`` simplifies a templated C++ name with default arguments and returns a qualified name. This can also tokenize a string to a qualified name with/without simplifying it

	:param input_name: String or qualified name to be simplified
	:type input_name: Union[str, QualifiedName]
	:param bool simplify: (optional) Whether to simplify input string (no effect if given a qualified name; will always simplify)
	:return: simplified name (or one-element array containing the input if simplifier fails/cannot simplify)
	:rtype: QualifiedName
	:Example:

		>>> demangle.simplify_name_to_qualified_name(QualifiedName(["std", "__cxx11", "basic_string<wchar, std::char_traits<wchar>, std::allocator<wchar> >"]), True)
		'std::wstring'
		>>>
	"""
	name = None
	if isinstance(input_name, str):
		name = core.BNRustSimplifyStrToFQN(input_name, simplify)
		assert name is not None, "core.BNRustSimplifyStrToFQN returned None"
	elif isinstance(input_name, types.QualifiedName):
		name = core.BNRustSimplifyStrToFQN(str(input_name), True)
		assert name is not None, "core.BNRustSimplifyStrToFQN returned None"
	else:
		raise TypeError("Parameter must be of type `str` or `types.QualifiedName`")

	result = types.QualifiedName._from_core_struct(name)
	core.BNFreeQualifiedName(name)
	if len(result) == 0:
		return None
	return result


class _DemanglerMetaclass(type):
	def __iter__(self):
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		types = core.BNGetDemanglerList(count)
		try:
			for i in range(0, count.value):
				yield CoreDemangler(types[i])
		finally:
			core.BNFreeDemanglerList(types)

	def __getitem__(self, value):
		binaryninja._init_plugins()
		handle = core.BNGetDemanglerByName(str(value))
		if handle is None:
			raise KeyError(f"'{value}' is not a valid Demangler")
		return CoreDemangler(handle)


class Demangler(metaclass=_DemanglerMetaclass):
	"""
	Pluggable name demangling interface. See :py:func:`register` and :py:func:`demangle`
	for details on the process of this interface.

	The list of Demanglers can be queried:

		>>> list(Demangler)
		[<Demangler: MS>, <Demangler: GNU3>]
	"""

	name = None
	_registered_demanglers = []
	_cached_name = None

	def __init__(self, handle=None):
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNDemangler)
			self.__dict__["name"] = core.BNGetDemanglerName(handle)
		else:
			self.handle = None

	@classmethod
	def register(cls):
		"""
		Register a custom Demangler. Newly registered demanglers will get priority over
		previously registered demanglers and built-in demanglers.
		"""
		demangler = cls()

		assert demangler.__class__.name is not None
		assert demangler.handle is None

		demangler._cb = core.BNDemanglerCallbacks()
		demangler._cb.context = 0
		demangler._cb.isMangledString = demangler._cb.isMangledString.__class__(demangler._is_mangled_string)
		demangler._cb.demangle = demangler._cb.demangle.__class__(demangler._demangle)
		demangler._cb.freeVarName = demangler._cb.freeVarName.__class__(demangler._free_var_name)
		demangler.handle = core.BNRegisterDemangler(cls.name, demangler._cb)
		cls._registered_demanglers.append(demangler)

	@classmethod
	def promote(cls, demangler):
		"""
		Promote a demangler to the highest-priority position.

			>>> list(Demangler)
			[<Demangler: MS>, <Demangler: GNU3>]
			>>> Demangler.promote(list(Demangler)[0])
			>>> list(Demangler)
			[<Demangler: GNU3>, <Demangler: MS>]

		:param demangler: Demangler to promote
		"""
		core.BNPromoteDemangler(demangler.handle)

	def __eq__(self, other):
		if not isinstance(other, Demangler):
			return False
		return self.name == other.name

	def __str__(self):
		return f'<Demangler: {self.name}>'

	def __repr__(self):
		return f'<Demangler: {self.name}>'

	def _is_mangled_string(self, ctxt, name):
		try:
			return self.is_mangled_string(core.pyNativeStr(name))
		except:
			log_error(traceback.format_exc())
			return False

	def _demangle(self, ctxt, arch, name, out_type, out_var_name, view):
		try:
			api_arch = CoreArchitecture._from_cache(arch)
			api_view = None
			if view is not None:
				api_view = binaryview.BinaryView(handle=core.BNNewViewReference(view))

			result = self.demangle(api_arch, core.pyNativeStr(name), api_view)
			if result is None:
				return False
			type, var_name = result

			if not isinstance(var_name, types.QualifiedName):
				var_name = types.QualifiedName(var_name)

			Demangler._cached_name = var_name._to_core_struct()
			if type:
				out_type[0] = core.BNNewTypeReference(type.handle)
			else:
				out_type[0] = None
			out_var_name[0] = Demangler._cached_name
			return True
		except:
			log_error(traceback.format_exc())
			return False

	def _free_var_name(self, ctxt, name):
		try:
			Demangler._cached_name = None
		except:
			log_error(traceback.format_exc())

	def is_mangled_string(self, name: str) -> bool:
		"""
		Determine if a given name is mangled and this demangler can process it

		The most recently registered demangler that claims a name is a mangled string
		(returns true from this function), and then returns a value from
		:py:func:`demangle` will determine the result of a call to :py:func:`demangle_generic`.
		Returning True from this does not require the demangler to succeed the call to
		:py:func:`demangle`, but simply implies that it may succeed.

		:param name: Raw mangled name string
		:return: True if the demangler thinks it can handle the name
		"""
		raise NotImplementedError()

	def demangle(
			self,
			arch: Architecture,
			name: str,
			view: Optional['binaryview.BinaryView'] = None
	) -> Optional[Tuple['types.Type', 'types.QualifiedName']]:
		"""
		Demangle a raw name into a Type and QualifiedName.

		The result of this function is a (Type, QualifiedName) tuple for the demangled
		name's details.

		Any unresolved named types referenced by the resulting Type will be created as
		empty structures or void typedefs in the view, if the result is used on
		a data structure in the view. Given this, the call to :py:func:`demangle`
		should NOT cause any side-effects creating types in the view trying to resolve this
		and instead just return a type with unresolved named type references.

		The most recently registered demangler that claims a name is a mangled string
		(returns true from :py:func:`is_mangled_string`), and then returns a value from
		this function will determine the result of a call to :py:func:`demangle_generic`.
		If this call returns None, the next most recently used demangler(s) will be tried instead.

		If the mangled name has no type information, but a name is still possible to extract,
		this function may return a successful (None, <name>) result, which will be accepted.

		:param arch: Architecture for context in which the name exists, eg for pointer sizes
		:param name: Raw mangled name
		:param view: (Optional) BinaryView context in which the name exists, eg for type lookup
		:return: Tuple of (Type, Name) if successful, None if not. Type may be None if only
		         a demangled name can be recovered from the raw name.
		"""
		raise NotImplementedError()


class CoreDemangler(Demangler):

	def is_mangled_string(self, name: str) -> bool:
		return core.BNIsDemanglerMangledName(self.handle, name)

	def demangle(self, arch: Architecture, name: str, view: Optional['binaryview.BinaryView'] = None) -> Optional[Tuple[Optional['types.Type'], 'types.QualifiedName']]:
		out_type = ctypes.POINTER(core.BNType)()
		out_var_name = core.BNQualifiedName()

		view_handle = None
		if view is not None:
			view_handle = view.handle

		if not core.BNDemanglerDemangle(self.handle, arch.handle, name, out_type, out_var_name, view_handle):
			return None

		result_type = None
		if out_type:
			result_type = types.Type.create(handle=out_type)
		result_var_name = types.QualifiedName._from_core_struct(out_var_name)
		core.BNFreeQualifiedName(out_var_name)
		return result_type, result_var_name
