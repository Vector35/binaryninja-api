#!/usr/bin/env python

test_cases = [
    # lwc1 $f0, 0x328($at)
    ('mipsel32', b'\x28\x03\x20\xc4', 'LLIL_SET_REG.d($f0,LLIL_LOAD.d(LLIL_ADD.d(LLIL_REG.d($at),LLIL_CONST.d(0x328))))'),
    # lwc1 $f20, 0x10($t4)
    ('mips32', b'\xc5\x94\x00\x10', 'LLIL_SET_REG.d($f20,LLIL_LOAD.d(LLIL_ADD.d(LLIL_REG.d($t4),LLIL_CONST.d(0x10))))'),
    # swc1 $f20, 0x10($t4)
    ('mips32', b'\xe5\x94\x00\x10', 'LLIL_STORE.d(LLIL_ADD.d(LLIL_REG.d($t4),LLIL_CONST.d(0x10)),LLIL_REG.d($f20))'),
    # lwc1 $f20, 0x10($t4)
    ('mipsel32', b'\x10\x00\x94\xc5', 'LLIL_SET_REG.d($f20,LLIL_LOAD.d(LLIL_ADD.d(LLIL_REG.d($t4),LLIL_CONST.d(0x10))))'),
    # swc1 $f20, 0x10($t4)
    ('mipsel32', b'\x10\x00\x94\xe5', 'LLIL_STORE.d(LLIL_ADD.d(LLIL_REG.d($t4),LLIL_CONST.d(0x10)),LLIL_REG.d($f20))'),
    # ldc1 $f20, 0x10($t4)
    ('mips32', b'\xd5\x94\x00\x10', 'LLIL_SET_REG_SPLIT.d($f21,$f20,LLIL_LOAD.q(LLIL_ADD.d(LLIL_REG.d($t4),LLIL_CONST.d(0x10))))'),
    # sdc1 $f20, 0x10($t4)
    ('mips32', b'\xf5\x94\x00\x10', 'LLIL_STORE.q(LLIL_ADD.d(LLIL_REG.d($t4),LLIL_CONST.d(0x10)),LLIL_REG_SPLIT.d($f21,$f20))'),
    # ldc1 $f20, 0x10($t4)
    ('mipsel32', b'\x10\x00\x94\xd5', 'LLIL_SET_REG_SPLIT.d($f21,$f20,LLIL_LOAD.q(LLIL_ADD.d(LLIL_REG.d($t4),LLIL_CONST.d(0x10))))'),
    # sdc1 $f20, 0x10($t4)
    ('mipsel32', b'\x10\x00\x94\xf5', 'LLIL_STORE.q(LLIL_ADD.d(LLIL_REG.d($t4),LLIL_CONST.d(0x10)),LLIL_REG_SPLIT.d($f21,$f20))'),
    # ldc1 $f20, 0x10($t4)
    ('mips64', b'\xd5\x94\x00\x10', 'LLIL_SET_REG.q($f20,LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q($t4),LLIL_CONST.q(0x10))))'),
    # sdc1 $f20, 0x10($t4)
    ('mips64', b'\xf5\x94\x00\x10', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q($t4),LLIL_CONST.q(0x10)),LLIL_REG.q($f20))'),
    # ldc1 $f20, 0x10($t4)
    ('mipsel64', b'\x10\x00\x94\xd5', 'LLIL_SET_REG.q($f20,LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q($t4),LLIL_CONST.q(0x10))))'),
    # sdc1 $f20, 0x10($t4)
    ('mipsel64', b'\x10\x00\x94\xf5', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q($t4),LLIL_CONST.q(0x10)),LLIL_REG.q($f20))'),
    # ldc1 $f20, 0x10($t4)
    ('r5900l', b'\x10\x00\x94\xd5', 'LLIL_SET_REG.q($f20,LLIL_LOAD.q(LLIL_ADD.d(LLIL_REG.d($t4),LLIL_CONST.d(0x10))))'),
    # sdc1 $f20, 0x10($t4)
    ('r5900l', b'\x10\x00\x94\xf5', 'LLIL_STORE.q(LLIL_ADD.d(LLIL_REG.d($t4),LLIL_CONST.d(0x10)),LLIL_REG.q($f20))'),
    # ldc1 $f21, 0x10($t4) -- odd FPR pair roots are architecturally unpredictable in MIPS32 FR=0 mode
    ('mips32', b'\xd5\x95\x00\x10', 'LLIL_UNKNOWN()'),
    # sdc1 $f21, 0x10($t4) -- odd FPR pair roots are architecturally unpredictable in MIPS32 FR=0 mode
    ('mips32', b'\xf5\x95\x00\x10', 'LLIL_UNKNOWN()'),
    # ldc1 $f31, 0x10($t4) -- odd FPR pair roots are architecturally unpredictable in MIPS32 FR=0 mode
    ('mips32', b'\xd5\x9f\x00\x10', 'LLIL_UNKNOWN()'),
    # sdc1 $f31, 0x10($t4) -- odd FPR pair roots are architecturally unpredictable in MIPS32 FR=0 mode
    ('mips32', b'\xf5\x9f\x00\x10', 'LLIL_UNKNOWN()'),
    # mtc1 $t0, $f20 -- MIPS32 Release 6.06 MTC1 (p. 292): StoreFPR writes GPR[rt][31:0]
    ('mips32', b'\x44\x88\xa0\x00', 'LLIL_SET_REG.d($f20,LLIL_REG.d($t0))'),
    # mtc1 $t0, $f20 -- little-endian encoding of the same MIPS32 operation
    ('mipsel32', b'\x00\xa0\x88\x44', 'LLIL_SET_REG.d($f20,LLIL_REG.d($t0))'),
    # mtc1 $zero, $f31 -- the architectural zero register transfers a zero word
    ('mipsel32', b'\x00\xf8\x80\x44', 'LLIL_SET_REG.d($f31,LLIL_CONST.d(0x0))'),
    # mtc1 $t0, $f20 -- this MIPS III architecture models its FPRs as 32-bit registers
    ('mips3', b'\x44\x88\xa0\x00', 'LLIL_SET_REG.d($f20,LLIL_REG.d($t0))'),
    # mtc1 $t0, $f20 -- little-endian MIPS III uses the same modeled 32-bit FPR write
    ('mipsel3', b'\x00\xa0\x88\x44', 'LLIL_SET_REG.d($f20,LLIL_REG.d($t0))'),
    # mtc1 $t0, $f20 -- R5900 EE Core Instruction Set Manual MTC1 (p. 371)
    ('r5900l', b'\x00\xa0\x88\x44', 'LLIL_SET_REG.d($f20,LLIL_REG.d($t0))'),
    # mtc1 $t0, $f20 -- MIPS64 Release 6.06 MTC1 (p. 385): high word is UNPREDICTABLE
    ('mips64', b'\x44\x88\xa0\x00', 'LLIL_INTRINSIC([temp0],_mtc1UnpredictableHighWord,[]); LLIL_SET_REG.q($f20,LLIL_OR.q(LLIL_LSL.q(LLIL_ZX.q(LLIL_REG.d(temp0)),LLIL_CONST.b(0x20)),LLIL_ZX.q(LLIL_REG.d($t0))))'),
    # mtc1 $t0, $f20 -- little-endian MIPS64 has identical register-transfer semantics
    ('mipsel64', b'\x00\xa0\x88\x44', 'LLIL_INTRINSIC([temp0],_mtc1UnpredictableHighWord,[]); LLIL_SET_REG.q($f20,LLIL_OR.q(LLIL_LSL.q(LLIL_ZX.q(LLIL_REG.d(temp0)),LLIL_CONST.b(0x20)),LLIL_ZX.q(LLIL_REG.d($t0))))'),
    # mtc1 $t0, $f20 -- Cavium uses the same modeled 64-bit MIPS FPR semantics
    ('cavium-mips64', b'\x44\x88\xa0\x00', 'LLIL_INTRINSIC([temp0],_mtc1UnpredictableHighWord,[]); LLIL_SET_REG.q($f20,LLIL_OR.q(LLIL_LSL.q(LLIL_ZX.q(LLIL_REG.d(temp0)),LLIL_CONST.b(0x20)),LLIL_ZX.q(LLIL_REG.d($t0))))'),
    # mfc1 $t0, $f20 -- MIPS32 Release 6.06 MFC1 (p. 267): copy FPR[fs][31:0]
    ('mips32', b'\x44\x08\xa0\x00', 'LLIL_SET_REG.d($t0,LLIL_REG.d($f20))'),
    # mfc1 $t0, $f20 -- little-endian encoding of the same MIPS32 operation
    ('mipsel32', b'\x00\xa0\x08\x44', 'LLIL_SET_REG.d($t0,LLIL_REG.d($f20))'),
    # mfc1 $t0, $f20 -- MIPS64 Release 6.06 MFC1 (p. 357): sign-extend the FPR word
    ('mips64', b'\x44\x08\xa0\x00', 'LLIL_SET_REG.q($t0,LLIL_SX.q(LLIL_REG.d($f20)))'),
    # mfc1 $t0, $f20 -- R5900 EE Core Instruction Set Manual MFC1 (p. 364)
    ('r5900l', b'\x00\xa0\x08\x44', 'LLIL_SET_REG.q($t0,LLIL_SX.q(LLIL_REG.d($f20)))'),
    # dmfc1 $t0, $f20 -- MIPS64 Release 6.06 DMFC1 (p. 217): copy all 64 FPR bits
    ('mips64', b'\x44\x28\xa0\x00', 'LLIL_SET_REG.q($t0,LLIL_REG.q($f20))'),
    # dmfc1 $t0, $f20 -- little-endian encoding of the same MIPS64 operation
    ('mipsel64', b'\x00\xa0\x28\x44', 'LLIL_SET_REG.q($t0,LLIL_REG.q($f20))'),
    # mfhc1 $t0, $f20 -- MIPS32 Release 6.06 MFHC1 (p. 271): read the odd FPR in FR=0
    ('mips32', b'\x44\x68\xa0\x00', 'LLIL_SET_REG.d($t0,LLIL_REG.d($f21))'),
    # mfhc1 $t0, $f21 -- odd FR=0 pair roots are architecturally unpredictable
    ('mips32', b'\x44\x68\xa8\x00', 'LLIL_UNKNOWN()'),
    # mfhc1 $t0, $f20 -- MIPS64 Release 6.06 MFHC1 (p. 361): sign-extend bits 63:32
    ('mips64', b'\x44\x68\xa0\x00', 'LLIL_SET_REG.q($t0,LLIL_SX.q(LLIL_LOW_PART.d(LLIL_LSR.q(LLIL_REG.q($f20),LLIL_CONST.b(0x20)))))'),
    # dmtc1 $t0, $f20 -- MIPS64 Release 6.06 DMTC1 (p. 220): copy all 64 GPR bits
    ('mipsel64', b'\x00\xa0\xa8\x44', 'LLIL_SET_REG.q($f20,LLIL_REG.q($t0))'),
    # mthc1 $t0, $f20 -- MIPS32 Release 6.06 MTHC1 (p. 295): write the odd FPR in FR=0
    ('mips32', b'\x44\xe8\xa0\x00', 'LLIL_SET_REG.d($f21,LLIL_REG.d($t0))'),
    # mthc1 $t0, $f21 -- odd FR=0 pair roots are architecturally unpredictable
    ('mips32', b'\x44\xe8\xa8\x00', 'LLIL_UNKNOWN()'),
    # mthc1 $t0, $f20 -- MIPS64 Release 6.06 MTHC1 (p. 389): preserve low, replace high
    ('mipsel64', b'\x00\xa0\xe8\x44', 'LLIL_SET_REG.q($f20,LLIL_OR.q(LLIL_AND.q(LLIL_REG.q($f20),LLIL_CONST.q(0xFFFFFFFF)),LLIL_LSL.q(LLIL_ZX.q(LLIL_REG.d($t0)),LLIL_CONST.b(0x20))))'),
    # c.ole.s $f12, $f0 -- MIPS32 Release 6.06 pp. 110-113: ordered less-or-equal
    ('mipsel32', b'\x36\x60\x00\x46', 'LLIL_SET_FLAG($fcc0,LLIL_FCMP_LE.d(LLIL_REG.d($f12),LLIL_REG.d($f0)))'),
    # c.ule.s $f21, $f20 -- unordered or less-or-equal
    ('mipsel32', b'\x37\xa8\x14\x46', 'LLIL_SET_FLAG($fcc0,LLIL_OR(LLIL_FCMP_UO.d(LLIL_REG.d($f21),LLIL_REG.d($f20)),LLIL_FCMP_LE.d(LLIL_REG.d($f21),LLIL_REG.d($f20))))'),
    # c.olt.s $f12, $f0 -- ordered less-than
    ('mips32', b'\x46\x00\x60\x34', 'LLIL_SET_FLAG($fcc0,LLIL_FCMP_LT.d(LLIL_REG.d($f12),LLIL_REG.d($f0)))'),
    # c.ult.s $f12, $f0 -- unordered or less-than
    ('mipsel32', b'\x35\x60\x00\x46', 'LLIL_SET_FLAG($fcc0,LLIL_OR(LLIL_FCMP_UO.d(LLIL_REG.d($f12),LLIL_REG.d($f0)),LLIL_FCMP_LT.d(LLIL_REG.d($f12),LLIL_REG.d($f0))))'),
    # c.ueq.s $f12, $f0 -- unordered or equal
    ('mipsel32', b'\x33\x60\x00\x46', 'LLIL_SET_FLAG($fcc0,LLIL_OR(LLIL_FCMP_UO.d(LLIL_REG.d($f12),LLIL_REG.d($f0)),LLIL_FCMP_E.d(LLIL_REG.d($f12),LLIL_REG.d($f0))))'),
    # c.ngle.s $f12, $f0 -- signaling unordered predicate
    ('mipsel32', b'\x39\x60\x00\x46', 'LLIL_SET_FLAG($fcc0,LLIL_FCMP_UO.d(LLIL_REG.d($f12),LLIL_REG.d($f0)))'),
    # c.ngl.s $f12, $f0 -- signaling unordered-or-equal predicate
    ('mipsel32', b'\x3b\x60\x00\x46', 'LLIL_SET_FLAG($fcc0,LLIL_OR(LLIL_FCMP_UO.d(LLIL_REG.d($f12),LLIL_REG.d($f0)),LLIL_FCMP_E.d(LLIL_REG.d($f12),LLIL_REG.d($f0))))'),
    # c.ole.d $f12, $f0 -- FR=0 doubles use even/odd FPR pairs
    ('mipsel32', b'\x36\x60\x20\x46', 'LLIL_SET_FLAG($fcc0,LLIL_FCMP_LE.q(LLIL_REG_SPLIT.d($f13,$f12),LLIL_REG_SPLIT.d($f1,$f0)))'),
    # c.ole.d $f13, $f0 -- odd FR=0 double roots are architecturally unpredictable
    ('mipsel32', b'\x36\x68\x20\x46', 'LLIL_UNKNOWN()'),
    # c.nge.d $f12, $f0 -- unordered or less-than
    ('mipsel32', b'\x3d\x60\x20\x46', 'LLIL_SET_FLAG($fcc0,LLIL_OR(LLIL_FCMP_UO.q(LLIL_REG_SPLIT.d($f13,$f12),LLIL_REG_SPLIT.d($f1,$f0)),LLIL_FCMP_LT.q(LLIL_REG_SPLIT.d($f13,$f12),LLIL_REG_SPLIT.d($f1,$f0))))'),
    # c.ngt.d $f12, $f0 -- unordered or less-than-or-equal
    ('mipsel32', b'\x3f\x60\x20\x46', 'LLIL_SET_FLAG($fcc0,LLIL_OR(LLIL_FCMP_UO.q(LLIL_REG_SPLIT.d($f13,$f12),LLIL_REG_SPLIT.d($f1,$f0)),LLIL_FCMP_LE.q(LLIL_REG_SPLIT.d($f13,$f12),LLIL_REG_SPLIT.d($f1,$f0))))'),
    # c.ole.s $fcc3, $f12, $f0 -- only the selected condition code is written
    ('mipsel32', b'\x36\x63\x00\x46', 'LLIL_SET_FLAG($fcc3,LLIL_FCMP_LE.d(LLIL_REG.d($f12),LLIL_REG.d($f0)))'),
    # c.ole.d $fcc3, $f12, $f0 -- explicit condition codes also apply to doubles
    ('mipsel32', b'\x36\x63\x20\x46', 'LLIL_SET_FLAG($fcc3,LLIL_FCMP_LE.q(LLIL_REG_SPLIT.d($f13,$f12),LLIL_REG_SPLIT.d($f1,$f0)))'),
    # c.ole.ps $f12, $f0 -- paired lanes write FCC0 and FCC1 in FR=1
    ('mipsel64', b'\x36\x60\xc0\x46', 'LLIL_SET_FLAG($fcc0,LLIL_FCMP_LE.d(LLIL_LOW_PART.d(LLIL_REG.q($f12)),LLIL_LOW_PART.d(LLIL_REG.q($f0)))); LLIL_SET_FLAG($fcc1,LLIL_FCMP_LE.d(LLIL_LOW_PART.d(LLIL_LSR.q(LLIL_REG.q($f12),LLIL_CONST.b(0x20))),LLIL_LOW_PART.d(LLIL_LSR.q(LLIL_REG.q($f0),LLIL_CONST.b(0x20)))))'),
    # c.ule.ps $fcc2, $f12, $f0 -- unordered-inclusive predicates are applied independently per lane
    ('mipsel64', b'\x37\x62\xc0\x46', 'LLIL_SET_FLAG($fcc2,LLIL_OR(LLIL_FCMP_UO.d(LLIL_LOW_PART.d(LLIL_REG.q($f12)),LLIL_LOW_PART.d(LLIL_REG.q($f0))),LLIL_FCMP_LE.d(LLIL_LOW_PART.d(LLIL_REG.q($f12)),LLIL_LOW_PART.d(LLIL_REG.q($f0))))); LLIL_SET_FLAG($fcc3,LLIL_OR(LLIL_FCMP_UO.d(LLIL_LOW_PART.d(LLIL_LSR.q(LLIL_REG.q($f12),LLIL_CONST.b(0x20))),LLIL_LOW_PART.d(LLIL_LSR.q(LLIL_REG.q($f0),LLIL_CONST.b(0x20)))),LLIL_FCMP_LE.d(LLIL_LOW_PART.d(LLIL_LSR.q(LLIL_REG.q($f12),LLIL_CONST.b(0x20))),LLIL_LOW_PART.d(LLIL_LSR.q(LLIL_REG.q($f0),LLIL_CONST.b(0x20))))))'),
    # c.ole.ps $fcc1, $f12, $f0 -- paired-single requires an even condition code
    ('mipsel64', b'\x36\x61\xc0\x46', 'LLIL_UNKNOWN()'),
]

import sys
import binaryninja
from binaryninja import binaryview
from binaryninja import lowlevelil
from binaryninja.enums import Endianness, LowLevelILOperation


def il2str(il):
    sz_lookup = {1: '.b', 2: '.w', 4: '.d', 8: '.q', 16: '.o'}
    if isinstance(il, lowlevelil.LowLevelILInstruction):
        size_code = sz_lookup.get(il.size, '?') if il.size else ''
        flags_code = '' if not hasattr(il, 'flags') or not il.flags or il.flags == 'update0' else '{%s}' % il.flags

        if il.operation == LowLevelILOperation.LLIL_UNIMPL and il.raw_operands[0]:
            return 'LLIL_UNKNOWN()'
        if il.operation in [LowLevelILOperation.LLIL_CONST, LowLevelILOperation.LLIL_CONST_PTR] and il.size:
            value = il.operands[0]
            if value < 0:
                value = (1 << (il.size * 8)) + value
            value = '0x%X' % value
            return 'LLIL_CONST%s(%s)' % (size_code, value)
        return '%s%s%s(%s)' % (il.operation.name, size_code, flags_code, ','.join([il2str(op) for op in il.operands]))
    if isinstance(il, list):
        return '[' + ','.join([il2str(op) for op in il]) + ']'
    if type(il) == lowlevelil.LowLevelILFlagCondition:
        return 'LowLevelILFlagCondition.%s' % il.name
    return str(il)


def instr_to_il(data, arch_name):
    arch = binaryninja.Architecture[arch_name]
    if arch.endianness == Endianness.LittleEndian:
        return_instruction = b'\x08\x00\xe0\x03\x00\x00\x00\x00'
    else:
        return_instruction = b'\x03\xe0\x00\x08\x00\x00\x00\x00'

    bv = binaryview.BinaryView.new(data + return_instruction)
    bv.add_function(0, plat=arch.standalone_platform)
    assert len(bv.functions) == 1

    result = []
    for block in bv.functions[0].lifted_il:
        for il in block:
            result.append(il2str(il))
    # Strip the return, its delay-slot nop, and the placeholder nop used while lifting the delay slot.
    return '; '.join(result[:-3])


def il_str_to_tree(ilstr):
    result = ''
    depth = 0
    for char in ilstr:
        if char == '(':
            result += '\n'
            depth += 1
            result += '    ' * depth
        elif char == ')':
            depth -= 1
        elif char == ',':
            result += '\n' + '    ' * depth
        elif char == ';':
            result += '\n'
            depth = 0
        elif char != ' ':
            result += char
    return result


def fail_test(message):
    raise AssertionError(message)


def run_all_tests():
    for test_i, (arch_name, data, expected) in enumerate(test_cases):
        if '?' in expected:
            fail_test(
                'INVALID EXPECTED LLIL AT TEST %d!\n\t   arch: %s\n\t   input: %s\n\texpected: %s'
                % (test_i, arch_name, data.hex(), expected))

        actual = instr_to_il(data, arch_name)
        if '?' in actual:
            fail_test(
                'INVALID ACTUAL LLIL AT TEST %d!\n\t   arch: %s\n\t   input: %s\n\t  actual: %s\n\t    tree:\n%s'
                % (test_i, arch_name, data.hex(), actual, il_str_to_tree(actual)))

        if actual != expected:
            fail_test(
                'MISMATCH AT TEST %d!\n\t   arch: %s\n\t   input: %s\n\texpected: %s\n\t  actual: %s\n\t    tree:\n%s'
                % (test_i, arch_name, data.hex(), expected, actual, il_str_to_tree(actual)))


def test_all():
    run_all_tests()


if __name__ == '__main__':
    run_all_tests()
    print('success!')
    sys.exit(0)

if __name__ == 'test_lifting':
    test_all()
    print('success!')
