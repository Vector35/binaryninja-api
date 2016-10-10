#!/usr/bin/env python
"""
    Thanks to @theqlabs from arm.ninja for the nice writeup and idea for this plugin:
    http://arm.ninja/2016/03/08/intro-to-binary-ninja-api/
"""
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
                    if il.operation == core.LLIL_SYSCALL)
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
