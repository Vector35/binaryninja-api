#!/usr/bin/env python
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


# Thanks to @theqlabs from arm.ninja for the nice writeup and idea for this plugin:
# http://arm.ninja/2016/03/08/intro-to-binary-ninja-api/

import sys
from itertools import chain

from binaryninja.binaryview import BinaryViewType
from binaryninja.enums import LowLevelILOperation


def print_syscalls(fileName):
	""" Print Syscall numbers for a provided file """
	bv = BinaryViewType.get_view_of_file(fileName)
	calling_convention = bv.platform.system_call_convention
	if calling_convention is None:
		print('Error: No syscall convention available for {:s}'.format(bv.platform))
		return

	register = calling_convention.int_arg_regs[0]

	for func in bv.functions:
		syscalls = (il for il in chain.from_iterable(func.low_level_il)
					if il.operation == LowLevelILOperation.LLIL_SYSCALL)
		for il in syscalls:
			value = func.get_reg_value_at(il.address, register).value
			print("System call address: {:#x} - {:d}".format(il.address, value))


if __name__ == "__main__":
	if len(sys.argv) != 2:
		print('Usage: {} <file>'.format(sys.argv[0]))
	else:
		print_syscalls(sys.argv[1])
