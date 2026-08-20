# Copyright (c) 2015-2026 Vector 35 Inc
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
from typing import List, Optional, Union

import binaryninja
from . import _binaryninjacore as core
from . import binaryview


def escape_unicode_string(
    data: Union[str, bytes, bytearray], view: Optional['binaryview.BinaryView'] = None
) -> str:
	"""
	Escapes a string for display, passing through any text that decodes to a codepoint in one of the
	enabled Unicode blocks as unaltered UTF-8.

	Which blocks are enabled is controlled by the ``analysis.unicode.blocks`` setting, resolved against
	``view`` when one is given. Passthrough additionally requires ``analysis.unicode.utf8`` to be enabled.
	Everything else is escaped, including bytes belonging to a truncated or otherwise invalid encoding, so
	``data`` need not be valid UTF-8.

	This is the escaping used when rendering string contents in HLIL, Pseudo C and Pseudo Rust.

	:param data: string or raw bytes to escape
	:param view: view whose settings select the enabled blocks, or None to use the global settings
	:return: the escaped string
	:Example:

		>>> Settings().set_string_list("analysis.unicode.blocks", ["Hiragana"], bv)
		True
		>>> escape_unicode_string("Unicode: \\u3053\\u3093\\u306b\\u3061\\u306f", bv)
		'Unicode: こんにちは'
		>>> escape_unicode_string(b"\\xff\\xfe", bv)
		'\\\\xff\\\\xfe'
	"""
	binaryninja._init_plugins()
	if isinstance(data, str):
		raw = data.encode("utf-8")
	else:
		raw = bytes(data)
	return core.BNUnicodeToEscapedStringForView(view.handle if view is not None else None, raw, len(raw))


def unicode_display_width(text: str) -> int:
	"""
	Width of a string in character cells, following Unicode Standard Annex #11 (East Asian Width).

	Wide and fullwidth codepoints, such as CJK ideographs and kana, occupy two cells; combining marks and
	other zero width codepoints occupy none; everything else occupies one.

	Binary Ninja renders text on a fixed character cell grid, so this, rather than a character count, is
	the measurement that :py:attr:`InstructionTextToken.width` is expressed in.

	:param text: string to measure
	:return: width of the string in character cells
	:Example:

		>>> display_width("hello")
		5
		>>> display_width("\\u3053\\u3093\\u306b\\u3061\\u306f")
		10
	"""
	return core.BNUnicodeGetDisplayWidth(text)

