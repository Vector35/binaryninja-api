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
from binaryninja import types

# 2-3 compatibility
from binaryninja import range
from binaryninja import pyNativeStr


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


def demangle_ms(arch, mangled_name):
	"""
	``demangle_ms`` demangles a mangled Microsoft Visual Studio C++ name to a Type object.

	:param Architecture arch: Architecture for the symbol. Required for pointer and integer sizes.
	:param str mangled_name: a mangled Microsoft Visual Studio C++ name
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
	if core.BNDemangleMS(arch.handle, mangled_name, ctypes.byref(handle), ctypes.byref(outName), ctypes.byref(outSize)):
		for i in range(outSize.value):
			names.append(pyNativeStr(outName[i]))
		core.BNFreeDemangledName(ctypes.byref(outName), outSize.value)
		return (types.Type(handle), names)
	return (None, mangled_name)


def demangle_gnu3(arch, mangled_name):
	handle = ctypes.POINTER(core.BNType)()
	outName = ctypes.POINTER(ctypes.c_char_p)()
	outSize = ctypes.c_ulonglong()
	names = []
	if core.BNDemangleGNU3(arch.handle, mangled_name, ctypes.byref(handle), ctypes.byref(outName), ctypes.byref(outSize)):
		for i in range(outSize.value):
			names.append(pyNativeStr(outName[i]))
		core.BNFreeDemangledName(ctypes.byref(outName), outSize.value)
		if not handle:
			return (None, names)
		return (types.Type(handle), names)
	return (None, mangled_name)
