#!/usr/bin/env python
# Copyright (c) 2015-2016 Vector 35 LLC
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

from binaryninja import BinaryView, core


def print_syscalls(bv):
    """ Print Syscall numbers for a provided binaryview """

    calling_convention = bv.platform.system_call_convention
    if not calling_convention:
        print('Error: No syscall convention available for {:s}'.format(bv.platform))
        return

    register = calling_convention.int_arg_regs[0]

    for func in bv.functions:
        syscalls = (il for il in chain.from_iterable(func.low_level_il)
                    if il.operation == core.BNLowLevelILOperation.LLIL_SYSCALL)
        for il in syscalls:
            value = func.get_reg_value_at(bv.arch, il.address, register).value
            print("System call address: {:#x} - {:d}".format(il.address, value))


def main():
    if len(sys.argv) != 2:
        print('Usage: {} <file>'.format(sys.argv[0]))
        return -1

    target = sys.argv[1]

    bv = BinaryView.open(target)
    view_type = next(bvt for bvt in bv.available_view_types if bvt.name != 'Raw')
    if not view_type:
        print('Error: Unable to get any other view type besides Raw')
        return -1

    bv = bv.file.get_view_of_type(view_type.name)
    bv.update_analysis_and_wait()

    print_syscalls(bv)


if __name__ == "__main__":
    sys.exit(main())
