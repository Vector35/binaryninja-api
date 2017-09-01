# Copyright (c) 2015-2017 Vector 35 LLC
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


class LinearDisassemblyPosition(object):
	"""
	``class LinearDisassemblyPosition`` is a helper object containing the position of the current Linear Disassembly.

	.. note:: This object should not be instantiated directly. Rather call \
	:py:meth:`get_linear_disassembly_position_at` which instantiates this object.
	"""
	def __init__(self, func, block, addr):
		self.function = func
		self.block = block
		self.address = addr


class LinearDisassemblyLine(object):
	def __init__(self, line_type, func, block, line_offset, contents):
		self.type = line_type
		self.function = func
		self.block = block
		self.line_offset = line_offset
		self.contents = contents

	def __str__(self):
		return str(self.contents)

	def __repr__(self):
		return repr(self.contents)
