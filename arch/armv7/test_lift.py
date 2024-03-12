#!/usr/bin/env python

test_cases = \
[
    # Post-Indexed addressing (normal)
    # with register offset
    # ldr r0, [r1], r2
    ('A', b'\x02\x00\x91\xe6', 'LLIL_SET_REG.d(r0,LLIL_LOAD.d(LLIL_REG.d(r1))); LLIL_SET_REG.d(r1,LLIL_ADD.d(LLIL_REG.d(r1),LLIL_REG.d(r2)))'),
    # with immediate offset
    # ldr r0, [r1], #4
    ('A', b'\x04\x00\x91\xe4', 'LLIL_SET_REG.d(r0,LLIL_LOAD.d(LLIL_REG.d(r1))); LLIL_SET_REG.d(r1,LLIL_ADD.d(LLIL_REG.d(r1),LLIL_CONST.d(0x4)))'),
    # with register and shift
    # ldr r0, [r1], r2, lsl #2
    ('A', b'\x02\x01\x91\xe6', 'LLIL_SET_REG.d(r0,LLIL_LOAD.d(LLIL_REG.d(r1))); LLIL_SET_REG.d(r1,LLIL_ADD.d(LLIL_REG.d(r1),LLIL_LSL.d(LLIL_REG.d(r2),LLIL_CONST.b(0x2))))'),

    # Post-Indexed addressing (to pc)
    # ldr pc, [r1], r2
    ('A', b'\x02\xf0\x91\xe6', 'LLIL_SET_REG.d(temp0,LLIL_LOAD.d(LLIL_REG.d(r1))); LLIL_SET_REG.d(r1,LLIL_ADD.d(LLIL_REG.d(r1),LLIL_REG.d(r2))); LLIL_JUMP(LLIL_REG.d(temp0))'),
    # ldr pc, [r1], #4
    ('A', b'\x04\xf0\x91\xe4', 'LLIL_SET_REG.d(temp0,LLIL_LOAD.d(LLIL_REG.d(r1))); LLIL_SET_REG.d(r1,LLIL_ADD.d(LLIL_REG.d(r1),LLIL_CONST.d(0x4))); LLIL_JUMP(LLIL_REG.d(temp0))'),
    # ldr pc, [r1], r2, lsl #2
    ('A', b'\x02\xf1\x91\xe6', 'LLIL_SET_REG.d(temp0,LLIL_LOAD.d(LLIL_REG.d(r1))); LLIL_SET_REG.d(r1,LLIL_ADD.d(LLIL_REG.d(r1),LLIL_LSL.d(LLIL_REG.d(r2),LLIL_CONST.b(0x2)))); LLIL_JUMP(LLIL_REG.d(temp0))'),
    # from " Armv7: POP(PC) lifted as LDR without writeback #3982"
    ('A', b'\x04\xf0\x9d\xe4', 'LLIL_SET_REG.d(temp0,LLIL_LOAD.d(LLIL_REG.d(sp))); LLIL_SET_REG.d(sp,LLIL_ADD.d(LLIL_REG.d(sp),LLIL_CONST.d(0x4))); LLIL_JUMP(LLIL_REG.d(temp0))'),

    # umaal r0, r1, r2, r3
    ('A', b'\x92\x03\x41\xe0', 'LLIL_SET_REG_SPLIT.d(r1,r0,LLIL_ADD.q(LLIL_MULU_DP.d(LLIL_REG.d(r3),LLIL_REG.d(r2)),LLIL_ADD.q(LLIL_REG.d(r1),LLIL_REG.d(r0))))'),
    # umlal r0, r1, r2, r3
    ('A', b'\x92\x03\xa1\xe0', 'LLIL_SET_REG_SPLIT.d(r1,r0,LLIL_ADD.q(LLIL_MULU_DP.d(LLIL_REG.d(r3),LLIL_REG.d(r2)),LLIL_REG_SPLIT.d(r1,r0)))'),
    # umlals r0, r1, r2, r3
    ('A', b'\x92\x03\xb1\xe0', 'LLIL_SET_REG_SPLIT.d{nz}(r1,r0,LLIL_ADD.q(LLIL_MULU_DP.d(LLIL_REG.d(r3),LLIL_REG.d(r2)),LLIL_REG_SPLIT.d(r1,r0)))'),
    # umulls r0, r1, r2, r3
    ('A', b'\x92\x03\x81\xe0', 'LLIL_SET_REG_SPLIT.d(r1,r0,LLIL_MULU_DP.d(LLIL_REG.d(r2),LLIL_REG.d(r3)))'),
    # smull r0, r1, r2, r3
    ('A', b'\x92\x03\xc1\xe0', 'LLIL_SET_REG_SPLIT.d(r1,r0,LLIL_MULS_DP.d(LLIL_REG.d(r2),LLIL_REG.d(r3)))'),
    # teq r0, #0
    ('A', b'\x00\x00\x30\xe3', 'LLIL_XOR.d{cnz}(LLIL_REG.d(r0),LLIL_CONST.d(0x0))'),
    # teq r1, #1
    ('A', b'\x01\x00\x31\xe3', 'LLIL_XOR.d{cnz}(LLIL_REG.d(r1),LLIL_CONST.d(0x1))'),
    # teq r2, #2
    ('A', b'\x02\x00\x32\xe3', 'LLIL_XOR.d{cnz}(LLIL_REG.d(r2),LLIL_CONST.d(0x2))'),
    # teq r3, #3
    ('A', b'\x03\x00\x33\xe3', 'LLIL_XOR.d{cnz}(LLIL_REG.d(r3),LLIL_CONST.d(0x3))'),

    # sxth    r0, r1, ror  #0
    ('A', b'\x71\x00\xbf\xe6', 'LLIL_SET_REG.d(r0,LLIL_SX.d(LLIL_LOW_PART.w(LLIL_REG.d(r1))))'),
    # sxth    r0, r1, ror  #0x8
    ('A', b'\x71\x04\xbf\xe6', 'LLIL_SET_REG.d(r0,LLIL_SX.d(LLIL_LOW_PART.w(LLIL_ROR.d(LLIL_REG.d(r1),LLIL_CONST.b(0x8)))))'),
    # sxth    r0, r1, ror  #0x10
    ('A', b'\x71\x08\xbf\xe6', 'LLIL_SET_REG.d(r0,LLIL_SX.d(LLIL_LOW_PART.w(LLIL_ROR.d(LLIL_REG.d(r1),LLIL_CONST.b(0x10)))))'),
    # sxth    r0, r1, ror  #0x18
    ('A', b'\x71\x0c\xbf\xe6', 'LLIL_SET_REG.d(r0,LLIL_SX.d(LLIL_LOW_PART.w(LLIL_ROR.d(LLIL_REG.d(r1),LLIL_CONST.b(0x18)))))'),

    # ror r0, r1
    ('A', b'\x70\x01\xa0\xe1', 'LLIL_SET_REG.d(r0,LLIL_ROR.d(LLIL_REG.d(r0),LLIL_AND.b(LLIL_REG.d(r1),LLIL_CONST.b(0xFF))))'),
    # ror r0, 7
    ('A', b'\xe0\x03\xa0\xe1', 'LLIL_SET_REG.d(r0,LLIL_ROR.d(LLIL_REG.d(r0),LLIL_AND.b(LLIL_CONST.d(0x7),LLIL_CONST.b(0xFF))))'),
    # rors r0, r1
    ('A', b'\x70\x01\xb0\xe1', 'LLIL_SET_REG.d(r0,LLIL_ROR.d{*}(LLIL_REG.d(r0),LLIL_AND.b(LLIL_REG.d(r1),LLIL_CONST.b(0xFF))))'),
    # rors r0, 7
    ('A', b'\xe0\x03\xb0\xe1', 'LLIL_SET_REG.d(r0,LLIL_ROR.d{*}(LLIL_REG.d(r0),LLIL_AND.b(LLIL_CONST.d(0x7),LLIL_CONST.b(0xFF))))'),
    # vadd.f32 s0, s1, s2
    ('A', b'\x81\x0a\x30\xee', 'LLIL_SET_REG.d(s0,LLIL_FADD.d(LLIL_REG.d(s1),LLIL_REG.d(s2)))'),
    # vsub.f32 s0, s1, s2
    ('A', b'\xc1\x0a\x30\xee', 'LLIL_SET_REG.d(s0,LLIL_FSUB.d(LLIL_REG.d(s1),LLIL_REG.d(s2)))'),
    # vmul.f32 s0, s1, s2
    ('A', b'\x81\x0a\x20\xee', 'LLIL_SET_REG.d(s0,LLIL_FMUL.d(LLIL_REG.d(s1),LLIL_REG.d(s2)))'),
    # vdiv.f32 s0, s1, s2
    ('A', b'\x81\x0a\x80\xee', 'LLIL_SET_REG.d(s0,LLIL_FDIV.d(LLIL_REG.d(s1),LLIL_REG.d(s2)))'),
    # svc #0; svc #1; svc #2; svc #3
    ('A', b'\x00\x00\x00\xef', 'LLIL_SET_REG.d(syscall_info,LLIL_CONST.d(0x0)); LLIL_SYSCALL()'),
    ('A', b'\x01\x00\x00\xef', 'LLIL_SET_REG.d(syscall_info,LLIL_CONST.d(0x1)); LLIL_SYSCALL()'),
    ('A', b'\x02\x00\x00\xef', 'LLIL_SET_REG.d(syscall_info,LLIL_CONST.d(0x2)); LLIL_SYSCALL()'),
    ('A', b'\x03\x00\x00\xef', 'LLIL_SET_REG.d(syscall_info,LLIL_CONST.d(0x3)); LLIL_SYSCALL()'),
    # svcle #0xDEAD
    ('A', b'\xAD\xDE\x00\xdf', 'LLIL_IF(LLIL_FLAG_COND(LowLevelILFlagCondition.LLFC_SLE,None),1,4); LLIL_SET_REG.d(syscall_info,LLIL_CONST.d(0xDEAD)); LLIL_SYSCALL(); LLIL_GOTO(4)'),
    # svcgt #0xdead
    ('A', b'\xad\xde\x00\xcf', 'LLIL_IF(LLIL_FLAG_COND(LowLevelILFlagCondition.LLFC_SGT,None),1,4); LLIL_SET_REG.d(syscall_info,LLIL_CONST.d(0xDEAD)); LLIL_SYSCALL(); LLIL_GOTO(4)'),
    # mov r0, r1
    ('A', b'\x01\x00\xa0\xe1', 'LLIL_SET_REG.d(r0,LLIL_REG.d(r1))'),
    # nop
    ('A', b'\x00\xf0\x20\xe3', 'LLIL_NOP()'),
    # vmov.i32 d16, #0
    ('A', b'\x10\x00\xc0\xf2', 'LLIL_SET_REG.q(d16,LLIL_CONST.q(0x0))'),
    # vmov.i32 q8, #0
    ('A', b'\x50\x00\xc0\xf2', 'LLIL_SET_REG.o(q8,LLIL_OR.o(LLIL_CONST.q(0x0),LLIL_LSL.o(LLIL_CONST.q(0x0),LLIL_CONST.q(0x40))))'),
    # vmov.i32 d16, #1
    ('A', b'\x11\x00\xc0\xf2', 'LLIL_SET_REG.q(d16,LLIL_CONST.q(0x100000001))'),
    # vmov.i32 q8, #1
    ('A', b'\x51\x00\xc0\xf2', 'LLIL_SET_REG.o(q8,LLIL_OR.o(LLIL_CONST.q(0x100000001),LLIL_LSL.o(LLIL_CONST.q(0x100000001),LLIL_CONST.q(0x40))))'),
    # vmov.i16 d16, #0
    ('A', b'\x10\x08\xc0\xf2', 'LLIL_SET_REG.q(d16,LLIL_CONST.q(0x0))'),
    # vmov.i16 d16, #1
    ('A', b'\x11\x08\xc0\xf2', 'LLIL_SET_REG.q(d16,LLIL_CONST.q(0x1000100010001))'),
    # vmov.i8 d16, #1
    ('A', b'\x11\x0e\xc0\xf2', 'LLIL_SET_REG.q(d16,LLIL_CONST.q(0x101010101010101))'),
    # vmov.i8 q8, #1
    ('A', b'\x51\x0e\xc0\xf2', 'LLIL_SET_REG.o(q8,LLIL_OR.o(LLIL_CONST.q(0x101010101010101),LLIL_LSL.o(LLIL_CONST.q(0x101010101010101),LLIL_CONST.q(0x40))))'),
    # vstr s0, [r3, #0x8]
    ('A', b'\x02\x0a\x83\xed', 'LLIL_STORE.d(LLIL_ADD.d(LLIL_REG.d(r3),LLIL_CONST.d(0x8)),LLIL_REG.d(s0))'),
    # vstr d16, [r3, #0x8]
    ('A', b'\x02\x0b\xc3\xed', 'LLIL_STORE.q(LLIL_ADD.d(LLIL_REG.d(r3),LLIL_CONST.d(0x8)),LLIL_REG.q(d16))'),
    # mov r2, r0
    ('T', b'\x02\x46', 'LLIL_SET_REG.d(r2,LLIL_REG.d(r0))'),
    # cmp r1, r2
    ('T', b'\x91\x42', 'LLIL_SUB.d{*}(LLIL_REG.d(r1),LLIL_REG.d(r2))'),
    # cmp r1, r2, lsl #7
    ('T', b'\xb1\xeb\xc2\x1f', 'LLIL_SUB.d{*}(LLIL_REG.d(r1),LLIL_LSL.d(LLIL_REG.d(r2),LLIL_CONST.d(0x7)))'),
    # uadd8   r5, r2, r12
    ('T', b'\x82\xfa\x4c\xf5', 'LLIL_SET_REG.d(temp0,LLIL_ADD.b(LLIL_LOW_PART.b(LLIL_REG.d(r2)),LLIL_LOW_PART.b(LLIL_REG.d(r12)))); LLIL_SET_REG.d(temp1,LLIL_ADD.b(LLIL_LOW_PART.b(LLIL_LSR.d(LLIL_REG.d(r2),LLIL_CONST.b(0x8))),LLIL_LOW_PART.b(LLIL_LSR.d(LLIL_REG.d(r12),LLIL_CONST.b(0x8))))); LLIL_SET_REG.d(temp2,LLIL_ADD.b(LLIL_LOW_PART.b(LLIL_LSR.d(LLIL_REG.d(r2),LLIL_CONST.b(0x10))),LLIL_LOW_PART.b(LLIL_LSR.d(LLIL_REG.d(r12),LLIL_CONST.b(0x10))))); LLIL_SET_REG.d(temp3,LLIL_ADD.b(LLIL_LOW_PART.b(LLIL_LSR.d(LLIL_REG.d(r2),LLIL_CONST.b(0x18))),LLIL_LOW_PART.b(LLIL_LSR.d(LLIL_REG.d(r12),LLIL_CONST.b(0x18))))); LLIL_SET_REG.d(r5,LLIL_OR.d(LLIL_OR.d(LLIL_LSL.d(LLIL_REG.b(temp3),LLIL_CONST.b(0x18)),LLIL_LSL.d(LLIL_REG.b(temp2),LLIL_CONST.b(0x10))),LLIL_OR.d(LLIL_LSL.d(LLIL_REG.b(temp1),LLIL_CONST.b(0x8)),LLIL_REG.b(temp0))))'),
    # ldrex r0, [r1, #4]
    ('T', b'\x51\xe8\x01\x0f', 'LLIL_SET_REG.d(r0,LLIL_LOAD.d(LLIL_ADD.d(LLIL_REG.d(r1),LLIL_CONST.d(0x4))))'),
    # ldrexb r0, [r1]
    ('T', b'\xd1\xe8\x4f\x0f', 'LLIL_SET_REG.d(r0,LLIL_ZX.d(LLIL_LOAD.b(LLIL_REG.d(r1))))'),
    # ldrexh r0, [r1]
    ('T', b'\xd1\xe8\x5f\x0f', 'LLIL_SET_REG.d(r0,LLIL_ZX.d(LLIL_LOAD.w(LLIL_REG.d(r1))))'),
    # umlal r0, r1, r2, r3
    ('T', b'\xe2\xfb\x03\x01', 'LLIL_SET_REG_SPLIT.d(r1,r0,LLIL_ADD.q(LLIL_MULU_DP.d(LLIL_REG.d(r3),LLIL_REG.d(r2)),LLIL_REG_SPLIT.d(r1,r0)))'),
    # sbfx r0, r1, 0, 1 (starting at b0, width 1, so extract b0)
    ('T', b'\x41\xf3\x00\x00', 'LLIL_SET_REG.d(r0,LLIL_ASR.d(LLIL_LSL.d(LLIL_REG.d(r1),LLIL_CONST.b(0x1F)),LLIL_CONST.b(0x1F)))'),
    # sbfx r0, r1, 1, 2 (starting at b1, width 2, so extract b2b1)
    ('T', b'\x41\xf3\x41\x00', 'LLIL_SET_REG.d(r0,LLIL_ASR.d(LLIL_LSL.d(LLIL_REG.d(r1),LLIL_CONST.b(0x1D)),LLIL_CONST.b(0x1E)))'),
    # sbfx r0, r1, 20, 30 (starting at b20, width 30... gets clamped, so b31b30...b20
    # just r0 = r1 >> 20, no left shift required
    ('T', b'\x41\xf3\x1d\x50', 'LLIL_SET_REG.d(r0,LLIL_ASR.d(LLIL_REG.d(r1),LLIL_CONST.b(0x14)))')
]

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
    elif type(il) == lowlevelil.LowLevelILFlagCondition:
        return f'LowLevelILFlagCondition.{il.name}'
    else:
        return str(il)

# TODO: make this less hacky
def instr_to_il(data, platform):
    # mov pc, lr
    RETURN = {  'linux-armv7': b'\x0e\xf0\xa0\xe1',
                'linux-thumb2': b'\xf7\x46'
            }[platform]
    RETURN_LIFTED = 'LLIL_JUMP(LLIL_REG.d(lr))'

    platform = binaryninja.Platform[platform]
    # make a pretend function that returns
    bv = binaryview.BinaryView.new(data + RETURN)
    bv.add_function(0, plat=platform)
    assert len(bv.functions) == 1

    result = []
    #for block in bv.functions[0].low_level_il:
    for block in bv.functions[0].lifted_il:
        for il in block:
            result.append(il2str(il))
    result = '; '.join(result)
    # strip return fence
    if result.endswith(RETURN_LIFTED):
        result = result[0:result.index(RETURN_LIFTED)]
    # strip trailing separator
    if result.endswith('; '):
        result = result[0:-2]

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
        elif c == ';':
            result += '\n'
            depth = 0
        elif c == ' ':
            pass
        else:
            result += c
    return result

def test_all():
    for (test_i, (arch_name, data, expected)) in enumerate(test_cases):
        platform = {'A':'linux-armv7', 'T':'linux-thumb2'}[arch_name]
        actual = instr_to_il(data, platform)

        #print(f'{test_i:04d} {data.hex()} {actual}')

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

if __name__ == 'test_lift':
    if test_all():
        print('success!')
