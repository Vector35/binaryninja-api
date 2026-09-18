#!/usr/bin/env python

test_cases = \
[
    # lswi: full words with one-byte and three-byte tails.
    ('ppc', b'\x7c\xd0\x2c\xaa', 'LLIL_SET_REG.d(r6,LLIL_LOAD.d(LLIL_REG.d(r16))); LLIL_SET_REG.d(r7,LLIL_LSL.d(LLIL_ZX.d(LLIL_LOAD.b(LLIL_ADD.d(LLIL_REG.d(r16),LLIL_CONST.d(0x4)))),LLIL_CONST.b(0x18)))'),
    ('ppc', b'\x7c\xd0\x3c\xaa', 'LLIL_SET_REG.d(r6,LLIL_LOAD.d(LLIL_REG.d(r16))); LLIL_SET_REG.d(r7,LLIL_OR.d(LLIL_LSL.d(LLIL_ZX.d(LLIL_LOAD.w(LLIL_ADD.d(LLIL_REG.d(r16),LLIL_CONST.d(0x4)))),LLIL_CONST.b(0x10)),LLIL_LSL.d(LLIL_ZX.d(LLIL_LOAD.b(LLIL_ADD.d(LLIL_REG.d(r16),LLIL_CONST.d(0x6)))),LLIL_CONST.b(0x8))))'),
    ('ppc_le', b'\xaa\x2c\xd0\x7c', 'LLIL_SET_REG.d(r6,LLIL_BSWAP.d(LLIL_LOAD.d(LLIL_REG.d(r16)))); LLIL_SET_REG.d(r7,LLIL_LSL.d(LLIL_ZX.d(LLIL_LOAD.b(LLIL_ADD.d(LLIL_REG.d(r16),LLIL_CONST.d(0x4)))),LLIL_CONST.b(0x18)))'),
    ('ppc_le', b'\xaa\x3c\xd0\x7c', 'LLIL_SET_REG.d(r6,LLIL_BSWAP.d(LLIL_LOAD.d(LLIL_REG.d(r16)))); LLIL_SET_REG.d(r7,LLIL_OR.d(LLIL_LSL.d(LLIL_ZX.d(LLIL_BSWAP.w(LLIL_LOAD.w(LLIL_ADD.d(LLIL_REG.d(r16),LLIL_CONST.d(0x4))))),LLIL_CONST.b(0x10)),LLIL_LSL.d(LLIL_ZX.d(LLIL_LOAD.b(LLIL_ADD.d(LLIL_REG.d(r16),LLIL_CONST.d(0x6)))),LLIL_CONST.b(0x8))))'),
    ('ppc64', b'\x7c\xd0\x2c\xaa', 'LLIL_SET_REG.q(r6,LLIL_ZX.q(LLIL_LOAD.d(LLIL_REG.q(r16)))); LLIL_SET_REG.q(r7,LLIL_ZX.q(LLIL_LSL.d(LLIL_ZX.d(LLIL_LOAD.b(LLIL_ADD.q(LLIL_REG.q(r16),LLIL_CONST.q(0x4)))),LLIL_CONST.b(0x18))))'),
    ('ppc64', b'\x7c\xd0\x3c\xaa', 'LLIL_SET_REG.q(r6,LLIL_ZX.q(LLIL_LOAD.d(LLIL_REG.q(r16)))); LLIL_SET_REG.q(r7,LLIL_ZX.q(LLIL_OR.d(LLIL_LSL.d(LLIL_ZX.d(LLIL_LOAD.w(LLIL_ADD.q(LLIL_REG.q(r16),LLIL_CONST.q(0x4)))),LLIL_CONST.b(0x10)),LLIL_LSL.d(LLIL_ZX.d(LLIL_LOAD.b(LLIL_ADD.q(LLIL_REG.q(r16),LLIL_CONST.q(0x6)))),LLIL_CONST.b(0x8)))))'),
    ('ppc64_le', b'\xaa\x2c\xd0\x7c', 'LLIL_SET_REG.q(r6,LLIL_ZX.q(LLIL_BSWAP.d(LLIL_LOAD.d(LLIL_REG.q(r16))))); LLIL_SET_REG.q(r7,LLIL_ZX.q(LLIL_LSL.d(LLIL_ZX.d(LLIL_LOAD.b(LLIL_ADD.q(LLIL_REG.q(r16),LLIL_CONST.q(0x4)))),LLIL_CONST.b(0x18))))'),
    ('ppc64_le', b'\xaa\x3c\xd0\x7c', 'LLIL_SET_REG.q(r6,LLIL_ZX.q(LLIL_BSWAP.d(LLIL_LOAD.d(LLIL_REG.q(r16))))); LLIL_SET_REG.q(r7,LLIL_ZX.q(LLIL_OR.d(LLIL_LSL.d(LLIL_ZX.d(LLIL_BSWAP.w(LLIL_LOAD.w(LLIL_ADD.q(LLIL_REG.q(r16),LLIL_CONST.q(0x4))))),LLIL_CONST.b(0x10)),LLIL_LSL.d(LLIL_ZX.d(LLIL_LOAD.b(LLIL_ADD.q(LLIL_REG.q(r16),LLIL_CONST.q(0x6)))),LLIL_CONST.b(0x8)))))'),

    # stswi: full words with one-byte and three-byte tails.
    ('ppc', b'\x7c\xd0\x2d\xaa', 'LLIL_STORE.d(LLIL_REG.d(r16),LLIL_REG.d(r6)); LLIL_STORE.b(LLIL_ADD.d(LLIL_REG.d(r16),LLIL_CONST.d(0x4)),LLIL_LOW_PART.b(LLIL_LSR.d(LLIL_REG.d(r7),LLIL_CONST.b(0x18))))'),
    ('ppc', b'\x7c\xd0\x3d\xaa', 'LLIL_STORE.d(LLIL_REG.d(r16),LLIL_REG.d(r6)); LLIL_STORE.w(LLIL_ADD.d(LLIL_REG.d(r16),LLIL_CONST.d(0x4)),LLIL_LOW_PART.w(LLIL_LSR.d(LLIL_REG.d(r7),LLIL_CONST.b(0x10)))); LLIL_STORE.b(LLIL_ADD.d(LLIL_REG.d(r16),LLIL_CONST.d(0x6)),LLIL_LOW_PART.b(LLIL_LSR.d(LLIL_REG.d(r7),LLIL_CONST.b(0x8))))'),
    ('ppc_le', b'\xaa\x2d\xd0\x7c', 'LLIL_STORE.d(LLIL_REG.d(r16),LLIL_BSWAP.d(LLIL_REG.d(r6))); LLIL_STORE.b(LLIL_ADD.d(LLIL_REG.d(r16),LLIL_CONST.d(0x4)),LLIL_LOW_PART.b(LLIL_LSR.d(LLIL_REG.d(r7),LLIL_CONST.b(0x18))))'),
    ('ppc_le', b'\xaa\x3d\xd0\x7c', 'LLIL_STORE.d(LLIL_REG.d(r16),LLIL_BSWAP.d(LLIL_REG.d(r6))); LLIL_STORE.w(LLIL_ADD.d(LLIL_REG.d(r16),LLIL_CONST.d(0x4)),LLIL_BSWAP.w(LLIL_LOW_PART.w(LLIL_LSR.d(LLIL_REG.d(r7),LLIL_CONST.b(0x10))))); LLIL_STORE.b(LLIL_ADD.d(LLIL_REG.d(r16),LLIL_CONST.d(0x6)),LLIL_LOW_PART.b(LLIL_LSR.d(LLIL_REG.d(r7),LLIL_CONST.b(0x8))))'),
    ('ppc64', b'\x7c\xd0\x2d\xaa', 'LLIL_STORE.d(LLIL_REG.q(r16),LLIL_REG.d(r6)); LLIL_STORE.b(LLIL_ADD.q(LLIL_REG.q(r16),LLIL_CONST.q(0x4)),LLIL_LOW_PART.b(LLIL_LSR.d(LLIL_REG.d(r7),LLIL_CONST.b(0x18))))'),
    ('ppc64', b'\x7c\xd0\x3d\xaa', 'LLIL_STORE.d(LLIL_REG.q(r16),LLIL_REG.d(r6)); LLIL_STORE.w(LLIL_ADD.q(LLIL_REG.q(r16),LLIL_CONST.q(0x4)),LLIL_LOW_PART.w(LLIL_LSR.d(LLIL_REG.d(r7),LLIL_CONST.b(0x10)))); LLIL_STORE.b(LLIL_ADD.q(LLIL_REG.q(r16),LLIL_CONST.q(0x6)),LLIL_LOW_PART.b(LLIL_LSR.d(LLIL_REG.d(r7),LLIL_CONST.b(0x8))))'),
    ('ppc64_le', b'\xaa\x2d\xd0\x7c', 'LLIL_STORE.d(LLIL_REG.q(r16),LLIL_BSWAP.d(LLIL_REG.d(r6))); LLIL_STORE.b(LLIL_ADD.q(LLIL_REG.q(r16),LLIL_CONST.q(0x4)),LLIL_LOW_PART.b(LLIL_LSR.d(LLIL_REG.d(r7),LLIL_CONST.b(0x18))))'),
    ('ppc64_le', b'\xaa\x3d\xd0\x7c', 'LLIL_STORE.d(LLIL_REG.q(r16),LLIL_BSWAP.d(LLIL_REG.d(r6))); LLIL_STORE.w(LLIL_ADD.q(LLIL_REG.q(r16),LLIL_CONST.q(0x4)),LLIL_BSWAP.w(LLIL_LOW_PART.w(LLIL_LSR.d(LLIL_REG.d(r7),LLIL_CONST.b(0x10))))); LLIL_STORE.b(LLIL_ADD.q(LLIL_REG.q(r16),LLIL_CONST.q(0x6)),LLIL_LOW_PART.b(LLIL_LSR.d(LLIL_REG.d(r7),LLIL_CONST.b(0x8))))'),

    # Matching lswi/stswi pairs copying 8 and 16 bytes.
    ('ppc', b'\x7d\x69\x44\xaa\x7d\x63\x45\xaa', 'LLIL_INTRINSIC([r11,r12],copy_string_words,[LLIL_REG.d(r3),LLIL_REG.d(r9),LLIL_CONST.d(0x8)])'),
    ('ppc', b'\x7c\xa9\x84\xaa\x7c\xa3\x85\xaa', 'LLIL_INTRINSIC([r5,r6,r7,r8],copy_string_words,[LLIL_REG.d(r3),LLIL_REG.d(r9),LLIL_CONST.d(0x10)])'),
    ('ppc_le', b'\xaa\x44\x69\x7d\xaa\x45\x63\x7d', 'LLIL_INTRINSIC([r11,r12],copy_string_words,[LLIL_REG.d(r3),LLIL_REG.d(r9),LLIL_CONST.d(0x8)])'),
    ('ppc_le', b'\xaa\x84\xa9\x7c\xaa\x85\xa3\x7c', 'LLIL_INTRINSIC([r5,r6,r7,r8],copy_string_words,[LLIL_REG.d(r3),LLIL_REG.d(r9),LLIL_CONST.d(0x10)])'),
    ('ppc64', b'\x7d\x69\x44\xaa\x7d\x63\x45\xaa', 'LLIL_INTRINSIC([r11,r12],copy_string_words,[LLIL_REG.q(r3),LLIL_REG.q(r9),LLIL_CONST.d(0x8)])'),
    ('ppc64', b'\x7c\xa9\x84\xaa\x7c\xa3\x85\xaa', 'LLIL_INTRINSIC([r5,r6,r7,r8],copy_string_words,[LLIL_REG.q(r3),LLIL_REG.q(r9),LLIL_CONST.d(0x10)])'),
    ('ppc64_le', b'\xaa\x44\x69\x7d\xaa\x45\x63\x7d', 'LLIL_INTRINSIC([r11,r12],copy_string_words,[LLIL_REG.q(r3),LLIL_REG.q(r9),LLIL_CONST.d(0x8)])'),
    ('ppc64_le', b'\xaa\x84\xa9\x7c\xaa\x85\xa3\x7c', 'LLIL_INTRINSIC([r5,r6,r7,r8],copy_string_words,[LLIL_REG.q(r3),LLIL_REG.q(r9),LLIL_CONST.d(0x10)])'),

    # blrl: a GOT helper followed by data, and an ordinary indirect call.
    ('ppc', b'\x4e\x80\x00\x21\x10\x09\x60\x20\x00\x00\x00\x00\x00\x00\x00\x00', 'LLIL_SET_REG.d(temp0,LLIL_REG.d(lr)); LLIL_SET_REG.d(lr,LLIL_CONST.d(0x4)); LLIL_RET(LLIL_REG.d(temp0))'),
    ('ppc', b'\x7f\xe8\x02\xa6\x7c\x68\x03\xa6\x4e\x80\x00\x21\x38\x60\x00\x07\x7f\xe8\x03\xa6\x4e\x80\x00\x20', 'LLIL_SET_REG.d(r31,LLIL_REG.d(lr)); LLIL_SET_REG.d(lr,LLIL_REG.d(r3)); LLIL_SET_REG.d(temp0,LLIL_REG.d(lr)); LLIL_SET_REG.d(lr,LLIL_CONST.d(0xC)); LLIL_CALL(LLIL_REG.d(temp0)); LLIL_SET_REG.d(r3,LLIL_CONST.d(0x7)); LLIL_SET_REG.d(lr,LLIL_REG.d(r31)); LLIL_RET(LLIL_REG.d(lr))'),
    ('ppc_le', b'\x21\x00\x80\x4e\x20\x60\x09\x10\x00\x00\x00\x00\x00\x00\x00\x00', 'LLIL_SET_REG.d(temp0,LLIL_REG.d(lr)); LLIL_SET_REG.d(lr,LLIL_CONST.d(0x4)); LLIL_RET(LLIL_REG.d(temp0))'),
    ('ppc_le', b'\xa6\x02\xe8\x7f\xa6\x03\x68\x7c\x21\x00\x80\x4e\x07\x00\x60\x38\xa6\x03\xe8\x7f\x20\x00\x80\x4e', 'LLIL_SET_REG.d(r31,LLIL_REG.d(lr)); LLIL_SET_REG.d(lr,LLIL_REG.d(r3)); LLIL_SET_REG.d(temp0,LLIL_REG.d(lr)); LLIL_SET_REG.d(lr,LLIL_CONST.d(0xC)); LLIL_CALL(LLIL_REG.d(temp0)); LLIL_SET_REG.d(r3,LLIL_CONST.d(0x7)); LLIL_SET_REG.d(lr,LLIL_REG.d(r31)); LLIL_RET(LLIL_REG.d(lr))'),
    ('ppc64', b'\x4e\x80\x00\x21\x10\x09\x60\x20\x00\x00\x00\x00\x00\x00\x00\x00', 'LLIL_SET_REG.q(temp0,LLIL_REG.q(lr)); LLIL_SET_REG.q(lr,LLIL_CONST.q(0x4)); LLIL_RET(LLIL_REG.q(temp0))'),
    ('ppc64', b'\x7f\xe8\x02\xa6\x7c\x68\x03\xa6\x4e\x80\x00\x21\x38\x60\x00\x07\x7f\xe8\x03\xa6\x4e\x80\x00\x20', 'LLIL_SET_REG.q(r31,LLIL_REG.q(lr)); LLIL_SET_REG.q(lr,LLIL_REG.q(r3)); LLIL_SET_REG.q(temp0,LLIL_REG.q(lr)); LLIL_SET_REG.q(lr,LLIL_CONST.q(0xC)); LLIL_CALL(LLIL_REG.q(temp0)); LLIL_SET_REG.q(r3,LLIL_CONST.q(0x7)); LLIL_SET_REG.q(lr,LLIL_REG.q(r31)); LLIL_RET(LLIL_REG.q(lr))'),
    ('ppc64_le', b'\x21\x00\x80\x4e\x20\x60\x09\x10\x00\x00\x00\x00\x00\x00\x00\x00', 'LLIL_SET_REG.q(temp0,LLIL_REG.q(lr)); LLIL_SET_REG.q(lr,LLIL_CONST.q(0x4)); LLIL_RET(LLIL_REG.q(temp0))'),
    ('ppc64_le', b'\xa6\x02\xe8\x7f\xa6\x03\x68\x7c\x21\x00\x80\x4e\x07\x00\x60\x38\xa6\x03\xe8\x7f\x20\x00\x80\x4e', 'LLIL_SET_REG.q(r31,LLIL_REG.q(lr)); LLIL_SET_REG.q(lr,LLIL_REG.q(r3)); LLIL_SET_REG.q(temp0,LLIL_REG.q(lr)); LLIL_SET_REG.q(lr,LLIL_CONST.q(0xC)); LLIL_CALL(LLIL_REG.q(temp0)); LLIL_SET_REG.q(r3,LLIL_CONST.q(0x7)); LLIL_SET_REG.q(lr,LLIL_REG.q(r31)); LLIL_RET(LLIL_REG.q(lr))'),
]

import sys
import binaryninja
from binaryninja import binaryview
from binaryninja import lowlevelil
from binaryninja.enums import LowLevelILOperation


def il2str(il):
    sz_lookup = {1: '.b', 2: '.w', 4: '.d', 8: '.q', 16: '.o'}
    if isinstance(il, lowlevelil.LowLevelILInstruction):
        size_code = sz_lookup.get(il.size, '?') if il.size else ''
        # PowerPC names the absence of flag writes "none".
        flags = getattr(il, 'flags', None)
        flags_code = '' if not flags or flags == 'none' else '{%s}' % flags

        # print size-specified IL constants in hex
        if il.operation in [
                LowLevelILOperation.LLIL_CONST,
                LowLevelILOperation.LLIL_CONST_PTR
        ] and il.size:
            tmp = il.operands[0]
            if tmp < 0:
                tmp = (1 << (il.size * 8)) + tmp
            tmp = '0x%X' % tmp if il.size else '%d' % il.size
            return 'LLIL_CONST%s(%s)' % (size_code, tmp)
        else:
            return '%s%s%s(%s)' % (il.operation.name, size_code, flags_code,
                                   ','.join([il2str(o) for o in il.operands]))
    elif isinstance(il, list):
        return '[' + ','.join([il2str(x) for x in il]) + ']'
    elif type(il) == lowlevelil.LowLevelILFlagCondition:
        return f'LowLevelILFlagCondition.{il.name}'
    else:
        return str(il)


def instr_to_il(data, arch_name):
    # blr return fence, in the architecture's byte order
    RETURN = b'\x20\x00\x80\x4e' if arch_name.endswith(
        '_le') else b'\x4e\x80\x00\x20'
    platform = binaryninja.Architecture[arch_name].standalone_platform
    with binaryview.BinaryView.new(data + RETURN) as bv:
        bv.add_function(0, plat=platform)
        bv.update_analysis_and_wait()
        assert len(bv.functions) == 1

        # Exclude only the appended fence, preserving returns in the input itself.
        return '; '.join(
            il2str(il)
            for block in bv.functions[0].lifted_il
            for il in block
            if il.address < len(data))


def il_str_to_tree(ilstr):
    result = ''
    depth = 0
    for c in ilstr:
        if c == '(':
            result += '\n'
            depth += 1
            result += '    ' * depth
        elif c == ')':
            depth -= 1
        elif c == ',':
            result += '\n'
            result += '    ' * depth
        elif c == ';':
            result += '\n'
            depth = 0
        elif c == ' ':
            pass
        else:
            result += c
    return result


def fail_test(message):
    raise AssertionError(message)


def check_il(test_i, arch_name, data, expected, actual):
    if '?' in expected:
        fail_test(
            'INVALID EXPECTED LLIL AT TEST %s (%s)!\n\t   input: %s\n\texpected: %s'
            % (test_i, arch_name, data.hex(), expected))

    if '?' in actual:
        fail_test(
            'INVALID ACTUAL LLIL AT TEST %s (%s)!\n\t   input: %s\n\t  actual: %s\n\t    tree:\n%s'
            % (test_i, arch_name, data.hex(), actual, il_str_to_tree(actual)))

    if actual != expected:
        fail_test(
            'MISMATCH AT TEST %s (%s)!\n\t   input: %s\n\texpected: %s\n\t  actual: %s\n\t    tree:\n%s'
            % (test_i, arch_name, data.hex(), expected, actual,
               il_str_to_tree(actual)))


def run_all_tests():
    for (test_i, (arch_name, data,
                  expected)) in enumerate(test_cases):
        actual = instr_to_il(data, arch_name)
        check_il(test_i, arch_name, data, expected, actual)


def test_all():
    run_all_tests()


if __name__ == '__main__':
    run_all_tests()
    print('success!')
    sys.exit(0)

if __name__ == 'test_lift':
    test_all()
    print('success!')
