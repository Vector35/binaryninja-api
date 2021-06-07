# Copyright (c) 2015-2021 Vector 35 Inc
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
from . import binaryview
from . import types


def get_qualified_name(names):
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


def demangle_ms(arch, mangled_name, options = False):
	"""
	``demangle_ms`` demangles a mangled Microsoft Visual Studio C++ name to a Type object.

	:param Architecture arch: Architecture for the symbol. Required for pointer and integer sizes.
	:param str mangled_name: a mangled Microsoft Visual Studio C++ name
	:param options: (optional) Whether to simplify demangled names : None falls back to user settings, a BinaryView uses that BinaryView's settings, or a boolean to set it directly
	:type options: Tuple[bool, BinaryView, None]
	:return: returns tuple of (Type, demangled_name) or (None, mangled_name) on error
	:rtype: Tuple
	:Example:

		>>> demangle_ms(Architecture["x86_64"], "?testf@Foobar@@SA?AW4foo@1@W421@@Z")
		(<type: public: static enum Foobar::foo __cdecl (enum Foobar::foo)>, ['Foobar', 'testf'])
		>>>
	"""
	handle = ctypes.POINTER(core.BNType)()
	outName = ctypes.POINTER(ctypes.c_char_p)()
	outSize = ctypes.c_ulonglong()
	names = []
	if (isinstance(options, binaryview.BinaryView) and core.BNDemangleMSWithOptions(arch.handle, mangled_name, ctypes.byref(handle), ctypes.byref(outName), ctypes.byref(outSize), options)) or \
		(isinstance(options, bool) and core.BNDemangleMS(arch.handle, mangled_name, ctypes.byref(handle), ctypes.byref(outName), ctypes.byref(outSize), options)) or \
		(options is None and core.BNDemangleMSWithOptions(arch.handle, mangled_name, ctypes.byref(handle), ctypes.byref(outName), ctypes.byref(outSize), None)):
		for i in range(outSize.value):
			names.append(outName[i].decode('utf8'))
		core.BNFreeDemangledName(ctypes.byref(outName), outSize.value)
		return (types.Type(handle), names)
	return (None, mangled_name)


def demangle_gnu3(arch, mangled_name, options = None):
	"""
	``demangle_gnu3`` demangles a mangled name to a Type object.

	:param Architecture arch: Architecture for the symbol. Required for pointer and integer sizes.
	:param str mangled_name: a mangled GNU3 name
	:param options: (optional) Whether to simplify demangled names : None falls back to user settings, a BinaryView uses that BinaryView's settings, or a boolean to set it directly
	:type options: Tuple[bool, BinaryView, None]
	:return: returns tuple of (Type, demangled_name) or (None, mangled_name) on error
	:rtype: Tuple
	"""
	handle = ctypes.POINTER(core.BNType)()
	outName = ctypes.POINTER(ctypes.c_char_p)()
	outSize = ctypes.c_ulonglong()
	names = []
	if (isinstance(options, binaryview.BinaryView) and core.BNDemangleGNU3WithOptions(arch.handle, mangled_name, ctypes.byref(handle), ctypes.byref(outName), ctypes.byref(outSize), options)) or \
		(isinstance(options, bool) and core.BNDemangleGNU3(arch.handle, mangled_name, ctypes.byref(handle), ctypes.byref(outName), ctypes.byref(outSize), options)) or \
		(options is None and core.BNDemangleGNU3WithOptions(arch.handle, mangled_name, ctypes.byref(handle), ctypes.byref(outName), ctypes.byref(outSize), None)):
		for i in range(outSize.value):
			names.append(outName[i].decode('utf8'))
		core.BNFreeDemangledName(ctypes.byref(outName), outSize.value)
		if not handle:
			return (None, names)
		return (types.Type(handle), names)
	return (None, mangled_name)


def simplify_name_to_string(input_name):
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


def simplify_name_to_qualified_name(input_name, simplify = True):
	"""
	``simplify_name_to_qualified_name`` simplifies a templated C++ name with default arguments and returns a qualified name.  This can also tokenize a string to a qualified name with/without simplifying it

	:param input_name: String or qualified name to be simplified
	:type input_name: Union[str, QualifiedName]
	:param bool simplify_name: (optional) Whether to simplify input string (no effect if given a qualified name; will always simplify)
	:return: simplified name (or one-element array containing the input if simplifier fails/cannot simplify)
	:rtype: QualifiedName
	:Example:

		>>> demangle.simplify_name_to_qualified_name(QualifiedName(["std", "__cxx11", "basic_string<wchar, std::char_traits<wchar>, std::allocator<wchar> >"]), True)
		'std::wstring'
		>>>
	"""
	result = None
	if isinstance(input_name, str):
		result = core.BNRustSimplifyStrToFQN(input_name, simplify)
		assert result is not None, "core.BNRustSimplifyStrToFQN returned None"
	elif isinstance(input_name, types.QualifiedName):
		result = core.BNRustSimplifyStrToFQN(str(input_name), True)
		assert result is not None, "core.BNRustSimplifyStrToFQN returned None"
	else:
		raise TypeError("Parameter must be of type `str` or `types.QualifiedName`")

	native_result = []
	for name in result:
		if name == b'':
			break
		native_result.append(name.decode("utf-8"))
	name_count = len(native_result)

	native_result = types.QualifiedName(native_result)
	core.BNRustFreeStringArray(result, name_count+1)
	return native_result
