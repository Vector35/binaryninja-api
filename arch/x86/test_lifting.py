#!/usr/bin/env python

tests_interrupts = [
    (b'\xcd\x00', 'LLIL_TRAP(0)'), # int 0
    (b'\xcd\x01', 'LLIL_TRAP(1)'), # int 1
    (b'\xcd\x02', 'LLIL_TRAP(2)'), # int 2
    (b'\xcd\x03', 'LLIL_TRAP(3)'), # int 3
    (b'\xcd\x04', 'LLIL_TRAP(4)'), # int 4
    (b'\xcd\x05', 'LLIL_TRAP(5)'), # int 5
    (b'\xcd\x06', 'LLIL_TRAP(6)'), # int 6
    (b'\xcd\x07', 'LLIL_TRAP(7)'), # int 7
    (b'\xcd\x08', 'LLIL_TRAP(8)'), # int 8
    (b'\xcd\x09', 'LLIL_TRAP(9)'), # int 9
    (b'\xcd\x0A', 'LLIL_TRAP(10)'), # int 10
    (b'\xcd\x0B', 'LLIL_TRAP(11)'), # int 11
    (b'\xcd\x0C', 'LLIL_TRAP(12)'), # int 12
    (b'\xcd\x0D', 'LLIL_TRAP(13)'), # int 13
    (b'\xcd\x0E', 'LLIL_TRAP(14)'), # int 14
    (b'\xcd\x0F', 'LLIL_TRAP(15)'), # int 15
    (b'\xcd\x29', 'LLIL_TRAP(13)'), # int 0x29 is lifted as TRAP_GPF
    (b'\xcd\x80', 'LLIL_SYSCALL()'), # int 0x80 is syscall on Linux
]

tests_basics = [
    # nop
    (b'\x90', 'LLIL_NOP()')
]

tests_movd = [
    # vmovd eax, xmm0
    (b'\xC5\xF9\x7E\xC0', 'LLIL_SET_REG.d(eax,LLIL_REG.d(xmm0))'),
]

test_cases = \
    tests_interrupts + \
    tests_basics + \
    tests_movd

import re
import sys
import binaryninja
from binaryninja import binaryview
from binaryninja import lowlevelil
from binaryninja.enums import LowLevelILOperation

def il2str(il):
    sz_lookup = {1:'.b', 2:'.w', 4:'.d', 8:'.q', 16:'.o'}
    if isinstance(il, lowlevelil.LowLevelILInstruction):
        size_code = sz_lookup.get(il.size, '?') if il.size else ''
        flags_code = '' if not hasattr(il, 'flags') or not il.flags else '{%s}'%il.flags

        # print size-specified IL constants in hex
        if il.operation in [LowLevelILOperation.LLIL_CONST, LowLevelILOperation.LLIL_CONST_PTR] and il.size:
            tmp = il.operands[0]
            if tmp < 0: tmp = (1<<(il.size*8))+tmp
            tmp = '0x%X' % tmp if il.size else '%d' % il.size
            return 'LLIL_CONST%s(%s)' % (size_code, tmp)
        else:
            return '%s%s%s(%s)' % (il.operation.name, size_code, flags_code, ','.join([il2str(o) for o in il.operands]))
    elif isinstance(il, list):
        return '[' + ','.join([il2str(x) for x in il]) + ']'
    else:
        return str(il)

# TODO: make this less hacky
def instr_to_il(data):
    platform = binaryninja.Platform['linux-x86']
    # make a pretend function that returns
    bv = binaryview.BinaryView.new(data)
    bv.add_function(0, plat=platform)
    assert len(bv.functions) == 1

    result = []
    for block in bv.functions[0].lifted_il:
        for il in block:
            result.append(il2str(il))
    result = '; '.join(result)

    try:
        result = result[0:result.rindex('; LLIL_UNDEF{none}()')]
    except:
        pass

    try:
        result = result[0:result.rindex('; LLIL_UNDEF()')]
    except:
        pass

    return result

def il_str_to_tree(ilstr):
    result = ''
    depth = 0
    for c in ilstr:
        if c == '(':
            result += '\n'
            depth += 1
            result += '    '*depth
        elif c == ')':
            depth -= 1
        elif c == ',':
            result += '\n'
            result += '    '*depth
            pass
        else:
            result += c
    return result

def test_all():
    for (test_i, (data, expected)) in enumerate(test_cases):
        actual = instr_to_il(data)
        if actual != expected:
            print('MISMATCH AT TEST %d!' % test_i)
            print('\t   input: %s' % data.hex())
            print('\texpected: %s' % expected)
            print('\t  actual: %s' % actual)
            print('\t    tree:')
            print(il_str_to_tree(actual))

            return False

    return True

if __name__ == '__main__':
    if test_all():
        print('success!')
        sys.exit(0)
    else:
        sys.exit(-1)

if __name__ == 'test_lifting':
    if test_all():
        print('success!')
