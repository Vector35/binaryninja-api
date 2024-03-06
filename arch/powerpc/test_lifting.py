#!/usr/bin/env python

tests_mfcr = [
    # mfcr 0
    (b'\x7c\x00\x00\x26', 'LLIL_SET_REG.d{none}(r0,LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(lt,31),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(gt,30),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(eq,29),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(so,28),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr1_lt,27),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr1_gt,26),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr1_eq,25),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr1_so,24),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr2_lt,23),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr2_gt,22),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr2_eq,21),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr2_so,20),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr3_lt,19),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr3_gt,18),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr3_eq,17),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr3_so,16),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr4_lt,15),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr4_gt,14),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr4_eq,13),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr4_so,12),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr5_lt,11),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr5_gt,10),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr5_eq,9),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr5_so,8),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr6_lt,7),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr6_gt,6),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr6_eq,5),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr6_so,4),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr7_lt,3),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr7_gt,2),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr7_eq,1),LLIL_FLAG_BIT.d{none}(cr7_so,0)))))))))))))))))))))))))))))))))'),
    # mfcr 15
    (b'\x7d\xe0\x00\x26', 'LLIL_SET_REG.d{none}(r15,LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(lt,31),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(gt,30),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(eq,29),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(so,28),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr1_lt,27),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr1_gt,26),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr1_eq,25),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr1_so,24),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr2_lt,23),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr2_gt,22),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr2_eq,21),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr2_so,20),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr3_lt,19),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr3_gt,18),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr3_eq,17),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr3_so,16),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr4_lt,15),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr4_gt,14),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr4_eq,13),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr4_so,12),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr5_lt,11),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr5_gt,10),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr5_eq,9),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr5_so,8),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr6_lt,7),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr6_gt,6),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr6_eq,5),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr6_so,4),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr7_lt,3),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr7_gt,2),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr7_eq,1),LLIL_FLAG_BIT.d{none}(cr7_so,0)))))))))))))))))))))))))))))))))'),
    # mfcr 31
    (b'\x7f\xe0\x00\x26', 'LLIL_SET_REG.d{none}(r31,LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(lt,31),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(gt,30),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(eq,29),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(so,28),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr1_lt,27),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr1_gt,26),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr1_eq,25),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr1_so,24),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr2_lt,23),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr2_gt,22),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr2_eq,21),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr2_so,20),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr3_lt,19),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr3_gt,18),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr3_eq,17),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr3_so,16),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr4_lt,15),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr4_gt,14),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr4_eq,13),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr4_so,12),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr5_lt,11),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr5_gt,10),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr5_eq,9),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr5_so,8),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr6_lt,7),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr6_gt,6),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr6_eq,5),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr6_so,4),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr7_lt,3),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr7_gt,2),LLIL_OR.d{none}(LLIL_FLAG_BIT.d{none}(cr7_eq,1),LLIL_FLAG_BIT.d{none}(cr7_so,0)))))))))))))))))))))))))))))))))')
]

tests_basics = [
    # li 3, 100
    (b'\x38\x60\x00\x64', 'LLIL_SET_REG.d{none}(r3,LLIL_CONST.d(0x64))')
]

test_cases = \
    tests_mfcr + \
    tests_basics

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
    platform = binaryninja.Platform['linux-ppc32']
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
