#!/usr/bin/env python

def scalar_intrinsic_expected(dst, intrinsic, *sources):
    inputs = ','.join(f'LLIL_REG.d({src})' for src in sources)
    return f'LLIL_INTRINSIC([{dst}],__{intrinsic},[{inputs}])'

def scalar_ge_intrinsic_expected(dst, intrinsic, *sources):
    inputs = ','.join(f'LLIL_REG.d({src})' for src in sources)
    return f'LLIL_INTRINSIC([{dst},apsr_g],__{intrinsic},[{inputs}])'

def scalar_q_intrinsic_expected(dst, intrinsic, *sources):
    inputs = ','.join(f'LLIL_REG.d({src})' for src in sources)
    return f'LLIL_INTRINSIC([{dst},q],__{intrinsic},[{inputs}])'

def vector_intrinsic_expected(dst, intrinsic, size, modifier, src1, src2):
    return f'LLIL_INTRINSIC([{dst}],__{intrinsic},[LLIL_CONST.b(0x{size:X}),LLIL_CONST.b(0x{modifier:X}),LLIL_REG.q({src1}),LLIL_REG.q({src2})])'

def saturating_scalar_expected(dst, src1, src2, intrinsic):
    return scalar_q_intrinsic_expected(dst, intrinsic, src1, src2)

def vmlal_expected(size, unsigned):
    return (
        f'LLIL_INTRINSIC([q8],__vmlal,[LLIL_CONST.b(0x{size:X}),LLIL_CONST.b(0x{unsigned:X}),'
        'LLIL_REG.o(q8),LLIL_REG.q(d0),LLIL_REG.q(d1),LLIL_CONST.b(0xFF)])'
    )

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
    ('A', b'\x92\x03\x41\xe0', 'LLIL_SET_REG_SPLIT.d(r1,r0,LLIL_ADD.q(LLIL_MULU_DP.d(LLIL_REG.d(r3),LLIL_REG.d(r2)),LLIL_ADD.q(LLIL_ZX.q(LLIL_REG.d(r1)),LLIL_ZX.q(LLIL_REG.d(r0)))))'),
    ('T', b'\xe2\xfb\x63\x01', 'LLIL_SET_REG_SPLIT.d(r1,r0,LLIL_ADD.q(LLIL_MULU_DP.d(LLIL_REG.d(r3),LLIL_REG.d(r2)),LLIL_ADD.q(LLIL_ZX.q(LLIL_REG.d(r1)),LLIL_ZX.q(LLIL_REG.d(r0)))))'),
    # umlal r0, r1, r2, r3
    ('A', b'\x92\x03\xa1\xe0', 'LLIL_SET_REG_SPLIT.d(r1,r0,LLIL_ADD.q(LLIL_MULU_DP.d(LLIL_REG.d(r3),LLIL_REG.d(r2)),LLIL_REG_SPLIT.d(r1,r0)))'),
    # umlals r0, r1, r2, r3
    ('A', b'\x92\x03\xb1\xe0', 'LLIL_SET_REG_SPLIT.d{nz}(r1,r0,LLIL_ADD.q(LLIL_MULU_DP.d(LLIL_REG.d(r3),LLIL_REG.d(r2)),LLIL_REG_SPLIT.d(r1,r0)))'),
    # umulls r0, r1, r2, r3
    ('A', b'\x92\x03\x81\xe0', 'LLIL_SET_REG_SPLIT.d(r1,r0,LLIL_MULU_DP.d(LLIL_REG.d(r2),LLIL_REG.d(r3)))'),
    # smull r0, r1, r2, r3
    ('A', b'\x92\x03\xc1\xe0', 'LLIL_SET_REG_SPLIT.d(r1,r0,LLIL_MULS_DP.d(LLIL_REG.d(r2),LLIL_REG.d(r3)))'),
    # stlex r1, r2, [r3]
    ('A', b'\x92\x1e\x83\xe1', 'LLIL_INTRINSIC([temp0],ExclusiveMonitorsPass,[LLIL_ADD.d(LLIL_REG.d(r3),LLIL_CONST.d(0x0)),LLIL_CONST.b(0x4)]); LLIL_IF(LLIL_CMP_E.d(LLIL_REG.d(temp0),LLIL_CONST.d(0x1)),2,5); LLIL_STORE.d(LLIL_ADD.d(LLIL_REG.d(r3),LLIL_CONST.d(0x0)),LLIL_REG.d(r2)); LLIL_SET_REG.d(r1,LLIL_CONST.d(0x0)); LLIL_GOTO(7); LLIL_SET_REG.d(r1,LLIL_CONST.d(0x1)); LLIL_GOTO(7)'),
    # stc2l p8, c0, [r5, #0x48]!
    ('T', b'\xe5\xfd\x12\x08', 'LLIL_INTRINSIC([],Coproc_Store,[LLIL_ADD.d(LLIL_REG.d(r5),LLIL_CONST.d(0x48)),LLIL_CONST.b(0x8),LLIL_CONST.b(0x0),LLIL_CONST.b(0x1)]); LLIL_SET_REG.d(r5,LLIL_ADD.d(LLIL_REG.d(r5),LLIL_CONST.d(0x48)))'),
    # stc2 p8, c0, [sp, #-0x48]!
    ('T', b'\x2d\xfd\x12\x08', 'LLIL_INTRINSIC([],Coproc_Store,[LLIL_SUB.d(LLIL_REG.d(sp),LLIL_CONST.d(0x48)),LLIL_CONST.b(0x8),LLIL_CONST.b(0x0),LLIL_CONST.b(0x0)]); LLIL_SET_REG.d(sp,LLIL_SUB.d(LLIL_REG.d(sp),LLIL_CONST.d(0x48)))'),
    # ldc p8, c0, [r12], {0x1b}
    ('T', b'\x9c\xec\x1b\x08', 'LLIL_INTRINSIC([],Coproc_Load,[LLIL_REG.d(r12),LLIL_CONST.b(0x8),LLIL_CONST.b(0x0),LLIL_CONST.b(0x0)])'),
    # ldc2l p8, c0, [sp], #0x48
    ('T', b'\xdd\xfc\x12\x08', 'LLIL_INTRINSIC([],Coproc_Load,[LLIL_REG.d(sp),LLIL_CONST.b(0x8),LLIL_CONST.b(0x0),LLIL_CONST.b(0x1)]); LLIL_SET_REG.d(sp,LLIL_ADD.d(LLIL_REG.d(sp),LLIL_CONST.d(0x48)))'),
    # ldc2 p8, c0, [sp], {0x12}
    ('T', b'\x9d\xfc\x12\x08', 'LLIL_INTRINSIC([],Coproc_Load,[LLIL_REG.d(sp),LLIL_CONST.b(0x8),LLIL_CONST.b(0x0),LLIL_CONST.b(0x0)])'),
    # cdp2 p8, #8, c0, c5, c5, #0
    ('T', b'\x85\xfe\x05\x08', 'LLIL_INTRINSIC([],Coproc_DataProcessing,[LLIL_CONST.b(0x8),LLIL_CONST.b(0x8),LLIL_CONST.b(0x0),LLIL_CONST.b(0x5),LLIL_CONST.b(0x5),LLIL_CONST.b(0x0)])'),
    # mrc p15, #0, pc, c1, c0, #0
    ('A', b'\x10\xff\x11\xee', 'LLIL_INTRINSIC([n,z,c,v],Coproc_GetOneWord,[LLIL_CONST.b(0xF),LLIL_CONST.b(0x0),LLIL_CONST.b(0x1),LLIL_CONST.b(0x0),LLIL_CONST.b(0x0)])'),
    # mrc2 p15, #0, pc, c1, c0, #0
    ('A', b'\x10\xff\x11\xfe', 'LLIL_INTRINSIC([n,z,c,v],Coproc_GetOneWord,[LLIL_CONST.b(0xF),LLIL_CONST.b(0x0),LLIL_CONST.b(0x1),LLIL_CONST.b(0x0),LLIL_CONST.b(0x0)])'),
    # mrc p15, #0, pc, c1, c0, #0 (Thumb2)
    ('T', b'\x11\xee\x10\xff', 'LLIL_INTRINSIC([n,z,c,v],Coproc_GetOneWord,[LLIL_CONST.b(0xF),LLIL_CONST.b(0x0),LLIL_CONST.b(0x1),LLIL_CONST.b(0x0),LLIL_CONST.b(0x0)])'),
    # mrc2 p15, #0, pc, c1, c0, #0 (Thumb2)
    ('T', b'\x11\xfe\x10\xff', 'LLIL_INTRINSIC([n,z,c,v],Coproc_GetOneWord,[LLIL_CONST.b(0xF),LLIL_CONST.b(0x0),LLIL_CONST.b(0x1),LLIL_CONST.b(0x0),LLIL_CONST.b(0x0)])'),
    # ands r0, r5
    ('T', b'\x28\x40', 'LLIL_SET_REG.d(r0,LLIL_AND.d{*}(LLIL_REG.d(r0),LLIL_REG.d(r5)))'),
    # bics r3, r3
    ('T', b'\x9b\x43', 'LLIL_SET_REG.d(r3,LLIL_AND.d{*}(LLIL_REG.d(r3),LLIL_NOT.d(LLIL_REG.d(r3))))'),
    # mvns r3, r6
    ('T', b'\xf3\x43', 'LLIL_SET_REG.d(r3,LLIL_NOT.d{*}(LLIL_REG.d(r6)))'),
    # eors r2, r0
    ('T', b'\x42\x40', 'LLIL_SET_REG.d(r2,LLIL_XOR.d{*}(LLIL_REG.d(r2),LLIL_REG.d(r0)))'),
    # eors r10, r9, r1, lsl #18
    ('T', b'\x99\xea\x81\x4a', 'LLIL_SET_REG.d(r10,LLIL_XOR.d{*}(LLIL_REG.d(r9),LLIL_LSL.d(LLIL_REG.d(r1),LLIL_CONST.d(0x12))))'),
    # ands r2, sp, r8, lsl #6
    ('T', b'\x1d\xea\x88\x12', 'LLIL_SET_REG.d(r2,LLIL_AND.d{*}(LLIL_REG.d(sp),LLIL_LSL.d(LLIL_REG.d(r8),LLIL_CONST.d(0x6))))'),
    # teq r0, #0
    ('A', b'\x00\x00\x30\xe3', 'LLIL_XOR.d{cnz}(LLIL_REG.d(r0),LLIL_CONST.d(0x0))'),
    # teq r1, #1
    ('A', b'\x01\x00\x31\xe3', 'LLIL_XOR.d{cnz}(LLIL_REG.d(r1),LLIL_CONST.d(0x1))'),
    # teq r2, #2
    ('A', b'\x02\x00\x32\xe3', 'LLIL_XOR.d{cnz}(LLIL_REG.d(r2),LLIL_CONST.d(0x2))'),
    # teq r3, #3
    ('A', b'\x03\x00\x33\xe3', 'LLIL_XOR.d{cnz}(LLIL_REG.d(r3),LLIL_CONST.d(0x3))'),
    # crc32b r0, r1, r2
    ('A', b'\x42\x00\x01\xe1', 'LLIL_INTRINSIC([r0],__crc32b,[LLIL_REG.d(r1),LLIL_LOW_PART.b(LLIL_REG.d(r2))])'),
    # crc32h r0, r1, r2
    ('A', b'\x42\x00\x21\xe1', 'LLIL_INTRINSIC([r0],__crc32h,[LLIL_REG.d(r1),LLIL_LOW_PART.w(LLIL_REG.d(r2))])'),
    # crc32w r0, r1, r2
    ('A', b'\x42\x00\x41\xe1', 'LLIL_INTRINSIC([r0],__crc32w,[LLIL_REG.d(r1),LLIL_REG.d(r2)])'),
    # crc32cb r0, r1, r2
    ('A', b'\x42\x02\x01\xe1', 'LLIL_INTRINSIC([r0],__crc32cb,[LLIL_REG.d(r1),LLIL_LOW_PART.b(LLIL_REG.d(r2))])'),
    # crc32ch r0, r1, r2
    ('A', b'\x42\x02\x21\xe1', 'LLIL_INTRINSIC([r0],__crc32ch,[LLIL_REG.d(r1),LLIL_LOW_PART.w(LLIL_REG.d(r2))])'),
    # crc32cw r0, r1, r2
    ('A', b'\x42\x02\x41\xe1', 'LLIL_INTRINSIC([r0],__crc32cw,[LLIL_REG.d(r1),LLIL_REG.d(r2)])'),
    # crc32b r0, r1, r2 (Thumb2)
    ('T', b'\xc1\xfa\x82\xf0', 'LLIL_INTRINSIC([r0],__crc32b,[LLIL_REG.d(r1),LLIL_LOW_PART.b(LLIL_REG.d(r2))])'),
    # crc32h r0, r1, r2 (Thumb2)
    ('T', b'\xc1\xfa\x92\xf0', 'LLIL_INTRINSIC([r0],__crc32h,[LLIL_REG.d(r1),LLIL_LOW_PART.w(LLIL_REG.d(r2))])'),
    # crc32w r0, r1, r2 (Thumb2)
    ('T', b'\xc1\xfa\xa2\xf0', 'LLIL_INTRINSIC([r0],__crc32w,[LLIL_REG.d(r1),LLIL_REG.d(r2)])'),
    # crc32cb r0, r1, r2 (Thumb2)
    ('T', b'\xd1\xfa\x82\xf0', 'LLIL_INTRINSIC([r0],__crc32cb,[LLIL_REG.d(r1),LLIL_LOW_PART.b(LLIL_REG.d(r2))])'),
    # crc32ch r0, r1, r2 (Thumb2)
    ('T', b'\xd1\xfa\x92\xf0', 'LLIL_INTRINSIC([r0],__crc32ch,[LLIL_REG.d(r1),LLIL_LOW_PART.w(LLIL_REG.d(r2))])'),
    # crc32cw r0, r1, r2 (Thumb2)
    ('T', b'\xd1\xfa\xa2\xf0', 'LLIL_INTRINSIC([r0],__crc32cw,[LLIL_REG.d(r1),LLIL_REG.d(r2)])'),
    # mrs lr, spsr
    ('A', b'\x00\xe0\x4f\xe1', 'LLIL_INTRINSIC([lr],__mrs,[LLIL_CONST.d(0x95)])'),
    # mrs r0, apsr
    ('A', b'\x00\x00\x0f\xe1', 'LLIL_INTRINSIC([r0],__mrs,[LLIL_CONST.d(0x81)])'),
    # mrs r9, apsr
    ('A', b'\x00\x90\x0f\xe1', 'LLIL_INTRINSIC([r9],__mrs,[LLIL_CONST.d(0x81)])'),
    # uqasx r0, r1, r2
    ('A', b'\x32\x0f\x61\xe6', scalar_q_intrinsic_expected('r0', 'uqasx', 'r1', 'r2')),
    # uqsax r0, r1, r2
    ('A', b'\x52\x0f\x61\xe6', scalar_q_intrinsic_expected('r0', 'uqsax', 'r1', 'r2')),
    # msr cpsr_c, r9
    ('A', b'\x09\xf0\x21\xe1', 'LLIL_INTRINSIC([],__msr,[LLIL_CONST.d(0x86),LLIL_REG.d(r9)])'),
    # msr cpsr_fc, r0
    ('A', b'\x00\xf0\x29\xe1', 'LLIL_INTRINSIC([],__msr,[LLIL_CONST.d(0x8E),LLIL_REG.d(r0)])'),
    # msr spsr_fc, sp
    ('A', b'\x0d\xf0\x69\xe1', 'LLIL_INTRINSIC([],__msr,[LLIL_CONST.d(0x9E),LLIL_REG.d(sp)])'),
    # msrmi cpsr_fsx, #0x3100
    ('A', b'\x31\x0c\x2e\x43', 'LLIL_IF(LLIL_FLAG_COND(LowLevelILFlagCondition.LLFC_NEG,None),1,3); LLIL_INTRINSIC([],__msr,[LLIL_CONST.d(0x93),LLIL_CONST.d(0x3100)]); LLIL_GOTO(3)'),
    # vmsr fpexc, r1
    ('A', b'\x10\x1a\xe8\xee', 'LLIL_INTRINSIC([],__vmsr,[LLIL_CONST.d(0xAB),LLIL_REG.d(r1)])'),
    # vmsr fpscr, r0 (Thumb2)
    ('T', b'\xe1\xee\x10\x0a', 'LLIL_INTRINSIC([],__vmsr,[LLIL_CONST.d(0xA7),LLIL_REG.d(r0)])'),
    # vmrs r1, fpexc
    ('A', b'\x10\x1a\xf8\xee', 'LLIL_INTRINSIC([r1],__vmrs,[LLIL_CONST.d(0xAB)])'),
    # vmrs apsr_nzcv, fpscr
    ('A', b'\x10\xfa\xf1\xee', 'LLIL_NOP()'),
    # vmrs apsr_nzcv, fpscr (Thumb2)
    ('T', b'\xf1\xee\x10\xfa', 'LLIL_NOP()'),

    # sxth    r0, r1, ror  #0
    ('A', b'\x71\x00\xbf\xe6', 'LLIL_SET_REG.d(r0,LLIL_SX.d(LLIL_LOW_PART.w(LLIL_REG.d(r1))))'),
    # sxth    r0, r1, ror  #0x8
    ('A', b'\x71\x04\xbf\xe6', 'LLIL_SET_REG.d(r0,LLIL_SX.d(LLIL_LOW_PART.w(LLIL_ROR.d(LLIL_REG.d(r1),LLIL_CONST.b(0x8)))))'),
    # sxth    r0, r1, ror  #0x10
    ('A', b'\x71\x08\xbf\xe6', 'LLIL_SET_REG.d(r0,LLIL_SX.d(LLIL_LOW_PART.w(LLIL_ROR.d(LLIL_REG.d(r1),LLIL_CONST.b(0x10)))))'),
    # sxth    r0, r1, ror  #0x18
    ('A', b'\x71\x0c\xbf\xe6', 'LLIL_SET_REG.d(r0,LLIL_SX.d(LLIL_LOW_PART.w(LLIL_ROR.d(LLIL_REG.d(r1),LLIL_CONST.b(0x18)))))'),
    # sxtab16 r0, r1, r2
    ('T', b'\x21\xfa\x82\xf0', scalar_intrinsic_expected('r0', 'sxtab16', 'r1', 'r2')),
    # sxtb16 r0, r1
    ('T', b'\x2f\xfa\x81\xf0', scalar_intrinsic_expected('r0', 'sxtb16', 'r1')),
    # uxtab16 r0, r1, r2
    ('T', b'\x31\xfa\x82\xf0', scalar_intrinsic_expected('r0', 'uxtab16', 'r1', 'r2')),
    # uxtb16 r0, r1
    ('T', b'\x3f\xfa\x81\xf0', scalar_intrinsic_expected('r0', 'uxtb16', 'r1')),

    # ror r0, r1
    ('A', b'\x70\x01\xa0\xe1', 'LLIL_SET_REG.d(r0,LLIL_ROR.d(LLIL_REG.d(r0),LLIL_AND.d(LLIL_REG.d(r1),LLIL_CONST.d(0xFF))))'),
    # ror r0, 7
    ('A', b'\xe0\x03\xa0\xe1', 'LLIL_SET_REG.d(r0,LLIL_ROR.d(LLIL_REG.d(r0),LLIL_AND.d(LLIL_CONST.d(0x7),LLIL_CONST.d(0xFF))))'),
    # rors r0, r1
    ('A', b'\x70\x01\xb0\xe1', 'LLIL_SET_REG.d(r0,LLIL_ROR.d{cnz}(LLIL_REG.d(r0),LLIL_AND.d(LLIL_REG.d(r1),LLIL_CONST.d(0xFF))))'),
    # rors r0, 7
    ('A', b'\xe0\x03\xb0\xe1', 'LLIL_SET_REG.d(r0,LLIL_ROR.d{cnz}(LLIL_REG.d(r0),LLIL_AND.d(LLIL_CONST.d(0x7),LLIL_CONST.d(0xFF))))'),
    # rors r3, r5
    ('T', b'\xeb\x41', 'LLIL_SET_REG.d(r3,LLIL_ROR.d{cnz}(LLIL_REG.d(r3),LLIL_AND.d(LLIL_REG.d(r5),LLIL_CONST.d(0xFF))))'),
    # orrs r0, r0, r12, lsl #1
    ('T', b'\x50\xea\x4c\x00', 'LLIL_SET_REG.d(r0,LLIL_OR.d{*}(LLIL_REG.d(r0),LLIL_LSL.d(LLIL_REG.d(r12),LLIL_CONST.d(0x1))))'),
    # asrs r5, r5, #0x1e
    ('T', b'\xad\x17', 'LLIL_SET_REG.d(r5,LLIL_ASR.d{cnz}(LLIL_REG.d(r5),LLIL_CONST.d(0x1E)))'),
    # adcs r2, r7
    ('T', b'\x7a\x41', 'LLIL_SET_REG.d(r2,LLIL_ADC.d{*}(LLIL_REG.d(r2),LLIL_REG.d(r7),LLIL_FLAG(c)))'),
    # strht r3, [r3, #0x7f]
    ('T', b'\x23\xf8\x7f\x3e', 'LLIL_STORE.w(LLIL_ADD.d(LLIL_REG.d(r3),LLIL_CONST.d(0x7F)),LLIL_LOW_PART.w(LLIL_REG.d(r3)))'),
    # srsia sp!, #0x1c
    ('T', b'\xa3\xe9\x1c\x3f', 'LLIL_INTRINSIC([],__srs,[LLIL_CONST.b(0x1C),LLIL_CONST.b(0x1),LLIL_CONST.b(0x0),LLIL_CONST.b(0x1)])'),
    # srsdb sp!, #0x17
    ('T', b'\x2d\xe8\x17\x08', 'LLIL_INTRINSIC([],__srs,[LLIL_CONST.b(0x17),LLIL_CONST.b(0x0),LLIL_CONST.b(0x0),LLIL_CONST.b(0x1)])'),
    # rfeia r5!
    ('T', b'\xb5\xe9\x5b\xc2', 'LLIL_INTRINSIC([],__rfe,[LLIL_REG.d(r5),LLIL_CONST.b(0x1),LLIL_CONST.b(0x0),LLIL_CONST.b(0x1)])'),
    # rfedb r9
    ('T', b'\x19\xe8\x92\xd1', 'LLIL_INTRINSIC([],__rfe,[LLIL_REG.d(r9),LLIL_CONST.b(0x0),LLIL_CONST.b(0x0),LLIL_CONST.b(0x0)])'),
    # usat16 r8, #8, r9
    ('T', b'\xa9\xf7\x08\x08', 'LLIL_INTRINSIC([r8,q],__usat16,[LLIL_CONST.d(0x8),LLIL_REG.d(r9)])'),
    # usat r1, #8, r1
    ('T', b'\x81\xf3\x08\x01', 'LLIL_INTRINSIC([r1,q],__usat,[LLIL_CONST.d(0x8),LLIL_REG.d(r1)])'),
    # tst r0, r6
    ('T', b'\x30\x42', 'LLIL_AND.d{cnz}(LLIL_REG.d(r0),LLIL_REG.d(r6))'),
    # teq r0, r1
    ('T', b'\x90\xea\x01\x0f', 'LLIL_XOR.d{cnz}(LLIL_REG.d(r0),LLIL_REG.d(r1))'),
    # stmdavs r5!, {r1, r2, r3, r5, r6, r9, r11, r12, sp}
    ('A', b'\x6e\x3a\x25\x68', 'LLIL_IF(LLIL_FLAG_COND(LowLevelILFlagCondition.LLFC_O,None),1,22); LLIL_SET_REG.d(temp0,LLIL_SUB.d(LLIL_REG.d(r5),LLIL_CONST.d(0x20))); LLIL_STORE.d(LLIL_REG.d(temp0),LLIL_REG.d(r1)); LLIL_SET_REG.d(temp0,LLIL_ADD.d(LLIL_REG.d(temp0),LLIL_CONST.b(0x4))); LLIL_STORE.d(LLIL_REG.d(temp0),LLIL_REG.d(r2)); LLIL_SET_REG.d(temp0,LLIL_ADD.d(LLIL_REG.d(temp0),LLIL_CONST.b(0x4))); LLIL_STORE.d(LLIL_REG.d(temp0),LLIL_REG.d(r3)); LLIL_SET_REG.d(temp0,LLIL_ADD.d(LLIL_REG.d(temp0),LLIL_CONST.b(0x4))); LLIL_STORE.d(LLIL_REG.d(temp0),LLIL_REG.d(r5)); LLIL_SET_REG.d(temp0,LLIL_ADD.d(LLIL_REG.d(temp0),LLIL_CONST.b(0x4))); LLIL_STORE.d(LLIL_REG.d(temp0),LLIL_REG.d(r6)); LLIL_SET_REG.d(temp0,LLIL_ADD.d(LLIL_REG.d(temp0),LLIL_CONST.b(0x4))); LLIL_STORE.d(LLIL_REG.d(temp0),LLIL_REG.d(r9)); LLIL_SET_REG.d(temp0,LLIL_ADD.d(LLIL_REG.d(temp0),LLIL_CONST.b(0x4))); LLIL_STORE.d(LLIL_REG.d(temp0),LLIL_REG.d(r11)); LLIL_SET_REG.d(temp0,LLIL_ADD.d(LLIL_REG.d(temp0),LLIL_CONST.b(0x4))); LLIL_STORE.d(LLIL_REG.d(temp0),LLIL_REG.d(r12)); LLIL_SET_REG.d(temp0,LLIL_ADD.d(LLIL_REG.d(temp0),LLIL_CONST.b(0x4))); LLIL_STORE.d(LLIL_REG.d(temp0),LLIL_REG.d(sp)); LLIL_SET_REG.d(temp0,LLIL_ADD.d(LLIL_REG.d(temp0),LLIL_CONST.b(0x4))); LLIL_SET_REG.d(r5,LLIL_SUB.d(LLIL_REG.d(r5),LLIL_CONST.d(0x24))); LLIL_GOTO(22)'),
    # vadd.f32 s0, s1, s2
    ('A', b'\x81\x0a\x30\xee', 'LLIL_SET_REG.d(s0,LLIL_FADD.d(LLIL_REG.d(s1),LLIL_REG.d(s2)))'),
    # vsub.f32 s0, s1, s2
    ('A', b'\xc1\x0a\x30\xee', 'LLIL_SET_REG.d(s0,LLIL_FSUB.d(LLIL_REG.d(s1),LLIL_REG.d(s2)))'),
    # vmul.f32 s0, s1, s2
    ('A', b'\x81\x0a\x20\xee', 'LLIL_SET_REG.d(s0,LLIL_FMUL.d(LLIL_REG.d(s1),LLIL_REG.d(s2)))'),
    # vdiv.f32 s0, s1, s2
    ('A', b'\x81\x0a\x80\xee', 'LLIL_SET_REG.d(s0,LLIL_FDIV.d(LLIL_REG.d(s1),LLIL_REG.d(s2)))'),
    # hvc #0
    ('A', b'\x70\x00\x40\xe1', 'LLIL_INTRINSIC([],__hvc,[LLIL_CONST.w(0x0)])'),
    # smc #0
    ('A', b'\x70\x00\x60\xe1', 'LLIL_INTRINSIC([],__smc,[LLIL_CONST.b(0x0)])'),
    # smc #0
    ('T', b'\xf0\xf7\xfa\x8d', 'LLIL_INTRINSIC([],__smc,[LLIL_CONST.b(0x0)])'),
    # hint #0x5
    ('A', b'\x05\xf0\x20\xe3', 'LLIL_INTRINSIC([],__hint,[LLIL_CONST.b(0x5)])'),
    # hint #0xf
    ('T', b'\xf0\xbf', 'LLIL_INTRINSIC([],__hint,[LLIL_CONST.b(0xF)])'),
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
    # clrex
    ('A', b'\x1f\xf0\x7f\xf5', 'LLIL_INTRINSIC([],__clrex,[])'),
    ('T', b'\xbf\xf3\x2f\x8f', 'LLIL_INTRINSIC([],__clrex,[])'),
    # strex r1, r2, [r3]
    ('T', b'\x43\xe8\x00\x21', 'LLIL_INTRINSIC([temp0],ExclusiveMonitorsPass,[LLIL_ADD.d(LLIL_REG.d(r3),LLIL_CONST.d(0x0)),LLIL_CONST.b(0x4)]); LLIL_IF(LLIL_CMP_E.d(LLIL_REG.d(temp0),LLIL_CONST.d(0x1)),2,5); LLIL_STORE.d(LLIL_ADD.d(LLIL_REG.d(r3),LLIL_CONST.d(0x0)),LLIL_REG.d(r2)); LLIL_SET_REG.d(r1,LLIL_CONST.d(0x0)); LLIL_GOTO(7); LLIL_SET_REG.d(r1,LLIL_CONST.d(0x1)); LLIL_GOTO(7)'),
    # strexd r0, r2, r3, [r4]
    ('T', b'\xc4\xe8\x70\x23', 'LLIL_INTRINSIC([temp0],ExclusiveMonitorsPass,[LLIL_REG.d(r4),LLIL_CONST.b(0x8)]); LLIL_IF(LLIL_CMP_E.d(LLIL_REG.d(temp0),LLIL_CONST.d(0x1)),2,5); LLIL_STORE.q(LLIL_REG.d(r4),LLIL_REG_SPLIT.d(r3,r2)); LLIL_SET_REG.d(r0,LLIL_CONST.d(0x0)); LLIL_GOTO(7); LLIL_SET_REG.d(r0,LLIL_CONST.d(0x1)); LLIL_GOTO(7)'),
    # pld [r0]
    ('A', b'\x00\xf0\xd0\xf5', 'LLIL_INTRINSIC([],__pld,[LLIL_REG.d(r0)])'),
    ('T', b'\x90\xf8\x00\xf0', 'LLIL_INTRINSIC([],__pld,[LLIL_ADD.d(LLIL_REG.d(r0),LLIL_CONST.d(0x0))])'),
    # bxj r0
    ('T', b'\xc0\xf3\x00\x8f', 'LLIL_JUMP(LLIL_REG.d(r0))'),
    # pkhbt r0, r1, r2, lsl #8
    ('A', b'\x12\x04\x81\xe6', 'LLIL_SET_REG.d(r0,LLIL_OR.d(LLIL_AND.d(LLIL_REG.d(r1),LLIL_CONST.d(0xFFFF)),LLIL_AND.d(LLIL_LSL.d(LLIL_REG.d(r2),LLIL_CONST.b(0x8)),LLIL_CONST.d(0xFFFF0000))))'),
    # pkhtb r0, r1, r2, asr #8
    ('A', b'\x52\x04\x81\xe6', 'LLIL_SET_REG.d(r0,LLIL_OR.d(LLIL_AND.d(LLIL_REG.d(r1),LLIL_CONST.d(0xFFFF0000)),LLIL_AND.d(LLIL_ASR.d(LLIL_REG.d(r2),LLIL_CONST.b(0x8)),LLIL_CONST.d(0xFFFF))))'),
    # pkhbt r0, r1, r2, lsl #8
    ('T', b'\xc1\xea\x02\x20', 'LLIL_SET_REG.d(r0,LLIL_OR.d(LLIL_AND.d(LLIL_LSL.d(LLIL_REG.d(r2),LLIL_CONST.d(0x8)),LLIL_CONST.d(0xFFFF0000)),LLIL_AND.d(LLIL_REG.d(r1),LLIL_CONST.d(0xFFFF))))'),
    # pkhtb r0, r1, r2, asr #8
    ('T', b'\xc1\xea\x22\x20', 'LLIL_SET_REG.d(r0,LLIL_OR.d(LLIL_AND.d(LLIL_REG.d(r1),LLIL_CONST.d(0xFFFF0000)),LLIL_AND.d(LLIL_ASR.d(LLIL_REG.d(r2),LLIL_CONST.d(0x8)),LLIL_CONST.d(0xFFFF))))'),
    # qadd r0, r1, r2
    ('A', b'\x51\x00\x02\xe1', saturating_scalar_expected('r0', 'r1', 'r2', 'qadd')),
    # qadd r0, r1, r2
    ('T', b'\x82\xfa\x81\xf0', saturating_scalar_expected('r0', 'r1', 'r2', 'qadd')),
    # qsub r0, r1, r2
    ('A', b'\x51\x00\x22\xe1', saturating_scalar_expected('r0', 'r1', 'r2', 'qsub')),
    # qsub r0, r1, r2
    ('T', b'\x82\xfa\xa1\xf0', saturating_scalar_expected('r0', 'r1', 'r2', 'qsub')),
    # qadd16 r0, r1, r2
    ('A', b'\x12\x0f\x21\xe6', saturating_scalar_expected('r0', 'r1', 'r2', 'qadd16')),
    # qadd16 r0, r1, r2
    ('T', b'\x91\xfa\x12\xf0', saturating_scalar_expected('r0', 'r1', 'r2', 'qadd16')),
    # qadd8 r0, r1, r2
    ('A', b'\x92\x0f\x21\xe6', saturating_scalar_expected('r0', 'r1', 'r2', 'qadd8')),
    # qadd8 r0, r1, r2
    ('T', b'\x81\xfa\x12\xf0', saturating_scalar_expected('r0', 'r1', 'r2', 'qadd8')),
    # qdadd r0, r1, r2
    ('A', b'\x51\x00\x42\xe1', saturating_scalar_expected('r0', 'r1', 'r2', 'qdadd')),
    # qdadd r0, r1, r2
    ('T', b'\x82\xfa\x91\xf0', saturating_scalar_expected('r0', 'r1', 'r2', 'qdadd')),
    # qdsub r0, r1, r2
    ('A', b'\x51\x00\x62\xe1', saturating_scalar_expected('r0', 'r1', 'r2', 'qdsub')),
    # qdsub r0, r1, r2
    ('T', b'\x82\xfa\xb1\xf0', saturating_scalar_expected('r0', 'r1', 'r2', 'qdsub')),
    # qsub16 r0, r1, r2
    ('A', b'\x72\x0f\x21\xe6', saturating_scalar_expected('r0', 'r1', 'r2', 'qsub16')),
    # qsub16 r0, r1, r2
    ('T', b'\xd1\xfa\x12\xf0', saturating_scalar_expected('r0', 'r1', 'r2', 'qsub16')),
    # qsub8 r0, r1, r2
    ('A', b'\xf2\x0f\x21\xe6', saturating_scalar_expected('r0', 'r1', 'r2', 'qsub8')),
    # qsub8 r0, r1, r2
    ('T', b'\xc1\xfa\x12\xf0', saturating_scalar_expected('r0', 'r1', 'r2', 'qsub8')),
    # ssat r0, #8, r1
    ('T', b'\x01\xf3\x07\x00', 'LLIL_INTRINSIC([r0,q],__ssat,[LLIL_CONST.d(0x8),LLIL_REG.d(r1)])'),
    # ssat16 r0, #8, r1
    ('T', b'\x21\xf3\x07\x00', 'LLIL_INTRINSIC([r0,q],__ssat16,[LLIL_CONST.d(0x8),LLIL_REG.d(r1)])'),
    # sadd16 r0, r1, r2
    ('T', b'\x91\xfa\x02\xf0', scalar_ge_intrinsic_expected('r0', 'sadd16', 'r1', 'r2')),
    # sadd8 r0, r1, r2
    ('T', b'\x81\xfa\x02\xf0', scalar_ge_intrinsic_expected('r0', 'sadd8', 'r1', 'r2')),
    # shadd16 r0, r1, r2
    ('T', b'\x91\xfa\x22\xf0', scalar_intrinsic_expected('r0', 'shadd16', 'r1', 'r2')),
    # shadd8 r0, r1, r2
    ('T', b'\x81\xfa\x22\xf0', scalar_intrinsic_expected('r0', 'shadd8', 'r1', 'r2')),
    # shasx r0, r1, r2
    ('T', b'\xa1\xfa\x22\xf0', scalar_intrinsic_expected('r0', 'shasx', 'r1', 'r2')),
    # uhadd16 r0, r1, r2
    ('T', b'\x91\xfa\x62\xf0', scalar_intrinsic_expected('r0', 'uhadd16', 'r1', 'r2')),
    # uhadd8 r0, r1, r2
    ('T', b'\x81\xfa\x62\xf0', scalar_intrinsic_expected('r0', 'uhadd8', 'r1', 'r2')),
    # uqadd16 r0, r1, r2
    ('A', b'\x12\x0f\x61\xe6', saturating_scalar_expected('r0', 'r1', 'r2', 'uqadd16')),
    # uqadd16 r0, r1, r2
    ('T', b'\x91\xfa\x52\xf0', saturating_scalar_expected('r0', 'r1', 'r2', 'uqadd16')),
    # uqadd8 r0, r1, r2
    ('A', b'\x92\x0f\x61\xe6', saturating_scalar_expected('r0', 'r1', 'r2', 'uqadd8')),
    # uqadd8 r0, r1, r2
    ('T', b'\x81\xfa\x52\xf0', saturating_scalar_expected('r0', 'r1', 'r2', 'uqadd8')),
    # sasx r0, r1, r2
    ('T', b'\xa1\xfa\x02\xf0', scalar_ge_intrinsic_expected('r0', 'sasx', 'r1', 'r2')),
    # ssax r0, r1, r2
    ('T', b'\xe1\xfa\x02\xf0', scalar_ge_intrinsic_expected('r0', 'ssax', 'r1', 'r2')),
    # qsax r0, r1, r2
    ('T', b'\xe1\xfa\x12\xf0', scalar_q_intrinsic_expected('r0', 'qsax', 'r1', 'r2')),
    # uasx r0, r1, r2
    ('T', b'\xa1\xfa\x42\xf0', scalar_ge_intrinsic_expected('r0', 'uasx', 'r1', 'r2')),
    # usax r0, r1, r2
    ('T', b'\xe1\xfa\x42\xf0', scalar_ge_intrinsic_expected('r0', 'usax', 'r1', 'r2')),
    # uqasx r0, r1, r2
    ('T', b'\xa1\xfa\x52\xf0', scalar_q_intrinsic_expected('r0', 'uqasx', 'r1', 'r2')),
    # uqsax r0, r1, r2
    ('T', b'\xe1\xfa\x52\xf0', scalar_q_intrinsic_expected('r0', 'uqsax', 'r1', 'r2')),
    # uhasx r0, r1, r2
    ('T', b'\xa1\xfa\x62\xf0', scalar_intrinsic_expected('r0', 'uhasx', 'r1', 'r2')),
    # ssub16 r0, r1, r2
    ('T', b'\xd1\xfa\x02\xf0', scalar_ge_intrinsic_expected('r0', 'ssub16', 'r1', 'r2')),
    # ssub8 r0, r1, r2
    ('T', b'\xc1\xfa\x02\xf0', scalar_ge_intrinsic_expected('r0', 'ssub8', 'r1', 'r2')),
    # shsub16 r0, r1, r2
    ('T', b'\xd1\xfa\x22\xf0', scalar_intrinsic_expected('r0', 'shsub16', 'r1', 'r2')),
    # shsub8 r0, r1, r2
    ('T', b'\xc1\xfa\x22\xf0', scalar_intrinsic_expected('r0', 'shsub8', 'r1', 'r2')),
    # uhsub16 r0, r1, r2
    ('T', b'\xd1\xfa\x62\xf0', scalar_intrinsic_expected('r0', 'uhsub16', 'r1', 'r2')),
    # uhsub8 r0, r1, r2
    ('T', b'\xc1\xfa\x62\xf0', scalar_intrinsic_expected('r0', 'uhsub8', 'r1', 'r2')),
    # usub16 r0, r1, r2
    ('T', b'\xd1\xfa\x42\xf0', scalar_ge_intrinsic_expected('r0', 'usub16', 'r1', 'r2')),
    # usub8 r0, r1, r2
    ('T', b'\xc1\xfa\x42\xf0', scalar_ge_intrinsic_expected('r0', 'usub8', 'r1', 'r2')),
    # uqsub16 r0, r1, r2
    ('A', b'\x72\x0f\x61\xe6', saturating_scalar_expected('r0', 'r1', 'r2', 'uqsub16')),
    # uqsub16 r0, r1, r2
    ('T', b'\xd1\xfa\x52\xf0', saturating_scalar_expected('r0', 'r1', 'r2', 'uqsub16')),
    # uqsub8 r0, r1, r2
    ('A', b'\xf2\x0f\x61\xe6', saturating_scalar_expected('r0', 'r1', 'r2', 'uqsub8')),
    # uqsub8 r0, r1, r2
    ('T', b'\xc1\xfa\x52\xf0', saturating_scalar_expected('r0', 'r1', 'r2', 'uqsub8')),
    # dsb sy
    ('A', b'\x4f\xf0\x7f\xf5', 'LLIL_INTRINSIC([],__dsb_SY,[])'),
    # dmb sy
    ('A', b'\x5f\xf0\x7f\xf5', 'LLIL_INTRINSIC([],__dmb_SY,[])'),
    # isb sy
    ('A', b'\x6f\xf0\x7f\xf5', 'LLIL_INTRINSIC([],__isb,[])'),
    # yield
    ('A', b'\x01\xf0\x20\xe3', 'LLIL_INTRINSIC([],__yield,[])'),
    # wfe
    ('A', b'\x02\xf0\x20\xe3', 'LLIL_INTRINSIC([],__wfe,[])'),
    # wfi
    ('A', b'\x03\xf0\x20\xe3', 'LLIL_INTRINSIC([],__wfi,[])'),
    # sev
    ('A', b'\x04\xf0\x20\xe3', 'LLIL_INTRINSIC([],__sev,[])'),
    # dbg #0
    ('A', b'\xf0\xf0\x20\xe3', 'LLIL_INTRINSIC([],__dbg,[LLIL_CONST.b(0x0)])'),
    # cps #0x13
    ('A', b'\x13\x00\x02\xf1', 'LLIL_INTRINSIC([],__cps,[LLIL_CONST.b(0x13)])'),
    # cpsid i
    ('A', b'\x80\x00\x0c\xf1', 'LLIL_INTRINSIC([],__cpsid,[LLIL_CONST.b(0x2),LLIL_CONST.b(0x0)])'),
    # cpsie i
    ('A', b'\x80\x00\x08\xf1', 'LLIL_INTRINSIC([],__cpsie,[LLIL_CONST.b(0x2),LLIL_CONST.b(0x0)])'),
    # cpsid i (Thumb)
    ('T', b'\x72\xb6', 'LLIL_INTRINSIC([],__cpsid,[LLIL_CONST.b(0x2),LLIL_CONST.b(0x0)])'),
    # cpsie i (Thumb)
    ('T', b'\x62\xb6', 'LLIL_INTRINSIC([],__cpsie,[LLIL_CONST.b(0x2),LLIL_CONST.b(0x0)])'),
    # setend le (Thumb)
    ('T', b'\x46\xb6', 'LLIL_INTRINSIC([],__setend,[LLIL_CONST.b(0x0)])'),
    # setend be (Thumb)
    ('T', b'\x49\xb6', 'LLIL_INTRINSIC([],__setend,[LLIL_CONST.b(0x1)])'),
    # vmov.f32 d0, #2.000000
    ('A', b'\x60\x0a\xb0\xee', 'LLIL_SET_REG.q(d0,LLIL_CONST.q(0x40000000))'),
    # vmov d0, r0, r1
    ('A', b'\x10\x0b\x41\xec', 'LLIL_SET_REG.q(d0,LLIL_REG_SPLIT.d(r1,r0))'),
    # vst1.8 {d16, d17}, [r3:0x40]
    ('A', b'\x1f\x0a\x43\xf4', 'LLIL_STORE.q(LLIL_REG.d(r3),LLIL_REG.q(d16)); LLIL_STORE.q(LLIL_ADD.d(LLIL_REG.d(r3),LLIL_CONST.d(0x8)),LLIL_REG.q(d17))'),
    # vld1.64 {d16}, [r12]!
    ('A', b'\xcd\x07\x6c\xf4', 'LLIL_SET_REG.q(d16,LLIL_LOAD.q(LLIL_REG.d(r12))); LLIL_SET_REG.d(r12,LLIL_ADD.d(LLIL_REG.d(r12),LLIL_CONST.d(0x8)))'),
    # vpush {d8, d9}
    ('A', b'\x04\x8b\x2d\xed', 'LLIL_PUSH.q(LLIL_REG.q(d9)); LLIL_PUSH.q(LLIL_REG.q(d8))'),
    # vpop {d8, d9}
    ('A', b'\x04\x8b\xbd\xec', 'LLIL_SET_REG.q(d8,LLIL_POP.q()); LLIL_SET_REG.q(d9,LLIL_POP.q())'),
    # vcmpe.f32 s0, #0.000000
    ('A', b'\xc0\x0a\xb5\xee', 'LLIL_FSUB.d{fcmp}(LLIL_REG.d(s0),LLIL_FLOAT_CONST.d(0.0))'),
    # vcmpe.f32 s24, s18
    ('A', b'\xc9\xca\xb4\xee', 'LLIL_FSUB.d{fcmp}(LLIL_REG.d(s24),LLIL_REG.d(s18))'),
    # vcmpe.f64 d8, d16
    ('A', b'\xe0\x8b\xb4\xee', 'LLIL_FSUB.q{fcmp}(LLIL_REG.q(d8),LLIL_REG.q(d16))'),
    # vcmpe.f64 d16, #0.000000; vmrs apsr_nzcv, fpscr; ble
    ('T', b'\xf5\xee\xc0\x0b\xf1\xee\x10\xfa\x18\xdd', 'LLIL_FSUB.q{fcmp}(LLIL_REG.q(d16),LLIL_FLOAT_CONST.q(0.0)); LLIL_NOP(); LLIL_IF(LLIL_FLAG_COND(LowLevelILFlagCondition.LLFC_SLE,None),3,5); LLIL_JUMP(LLIL_CONST.d(0x3C))'),
    # vdup.32 d16, r1
    ('A', b'\x90\x1b\x80\xee', 'LLIL_INTRINSIC([d16],__vdup,[LLIL_CONST.b(0x20),LLIL_REG.d(r1),LLIL_CONST.b(0x0)])'),
    # vdup.32 d8, r7
    ('A', b'\x10\x7b\x88\xee', 'LLIL_INTRINSIC([d8],__vdup,[LLIL_CONST.b(0x20),LLIL_REG.d(r7),LLIL_CONST.b(0x0)])'),
    # vdup.8 d16, d1[7]
    ('T', b'\xff\xff\x01\x0c', 'LLIL_INTRINSIC([d16],__vdup,[LLIL_CONST.b(0x8),LLIL_REG.q(d1),LLIL_CONST.b(0x7)])'),
    # vorr d8, d17, d16
    ('A', b'\xb0\x81\x21\xf2', 'LLIL_SET_REG.q(d8,LLIL_OR.q(LLIL_REG.q(d17),LLIL_REG.q(d16)))'),
    # vand d0, d16, d6
    ('T', b'\x00\xef\x96\x01', 'LLIL_SET_REG.q(d0,LLIL_AND.q(LLIL_REG.q(d16),LLIL_REG.q(d6)))'),
    # vshr.u64 d16, d16, #0x20
    ('A', b'\xb0\x00\xe0\xf3', 'LLIL_SET_REG.q(d16,LLIL_LSR.q(LLIL_REG.q(d16),LLIL_CONST.b(0x20)))'),
    # vshr.s64 d8, d8, #0x20
    ('A', b'\x98\x80\xa0\xf2', 'LLIL_SET_REG.q(d8,LLIL_ASR.q(LLIL_REG.q(d8),LLIL_CONST.b(0x20)))'),
    # vshr.u32 d16, d24, #0xf
    ('T', b'\xf1\xff\x38\x00', 'LLIL_INTRINSIC([d16],__vshr,[LLIL_CONST.b(0x20),LLIL_CONST.b(0x1),LLIL_REG.q(d24),LLIL_CONST.q(0xF)])'),
    # vrshr.u32 d16, d18, #0x10
    ('T', b'\xf0\xff\x32\x02', 'LLIL_INTRINSIC([d16],__vrshr,[LLIL_CONST.b(0x20),LLIL_CONST.b(0x1),LLIL_REG.q(d18),LLIL_CONST.q(0x10)])'),
    # vrshl.u8 d0, d15, d16
    ('T', b'\x00\xff\x8f\x05', 'LLIL_INTRINSIC([d0],__vrshl,[LLIL_CONST.b(0x8),LLIL_CONST.b(0x1),LLIL_REG.q(d15),LLIL_REG.q(d16)])'),
    # vqrshl.u8 d0, d4, d16
    ('T', b'\x00\xff\x94\x05', 'LLIL_INTRINSIC([d0],__vqrshl,[LLIL_CONST.b(0x8),LLIL_CONST.b(0x1),LLIL_CONST.b(0x1),LLIL_REG.q(d4),LLIL_REG.q(d16)])'),
    # vqrshl.s8 d0, d2, d16
    ('T', b'\x00\xef\x92\x05', 'LLIL_INTRINSIC([d0],__vqrshl,[LLIL_CONST.b(0x8),LLIL_CONST.b(0x0),LLIL_CONST.b(0x0),LLIL_REG.q(d2),LLIL_REG.q(d16)])'),
    # vsra.u32 d16, d19, #0xf
    ('T', b'\xf1\xff\x33\x01', 'LLIL_INTRINSIC([d16],__vsra,[LLIL_CONST.b(0x20),LLIL_CONST.b(0x1),LLIL_REG.q(d16),LLIL_REG.q(d19),LLIL_CONST.q(0xF)])'),
    # vrsra.u32 d26, d19, #0x10
    ('T', b'\xf0\xff\x33\xa3', 'LLIL_INTRINSIC([d26],__vrsra,[LLIL_CONST.b(0x20),LLIL_CONST.b(0x1),LLIL_REG.q(d26),LLIL_REG.q(d19),LLIL_CONST.q(0x10)])'),
    # vsri.32 d16, d16, #0x10
    ('T', b'\xf0\xff\x30\x04', 'LLIL_INTRINSIC([d16],__vsri,[LLIL_CONST.b(0x20),LLIL_REG.q(d16),LLIL_REG.q(d16),LLIL_CONST.q(0x10)])'),
    # vsli.32 d16, d23, #0x10
    ('T', b'\xf0\xff\x37\x05', 'LLIL_INTRINSIC([d16],__vsli,[LLIL_CONST.b(0x20),LLIL_REG.q(d16),LLIL_REG.q(d23),LLIL_CONST.q(0x10)])'),
    # vshl.i64 d17, d18, #0x7
    ('A', b'\xb2\x15\xc7\xf2', 'LLIL_SET_REG.q(d17,LLIL_LSL.q(LLIL_REG.q(d18),LLIL_CONST.b(0x7)))'),
    # vshl.i64 d29, d25, #0x20
    ('T', b'\xe0\xef\xb9\xd5', 'LLIL_SET_REG.q(d29,LLIL_LSL.q(LLIL_REG.q(d25),LLIL_CONST.b(0x20)))'),
    # vshll.u32 q8, d25, #0x10
    ('T', b'\xf0\xff\x39\x0a', 'LLIL_INTRINSIC([q8],__vshll,[LLIL_CONST.b(0x20),LLIL_CONST.b(0x1),LLIL_REG.q(d25),LLIL_CONST.q(0x10)])'),
    # vqshl.u32 d16, d21, #0x10
    ('T', b'\xf0\xff\x35\x07', 'LLIL_INTRINSIC([d16],__vqshl,[LLIL_CONST.b(0x20),LLIL_CONST.b(0x1),LLIL_CONST.b(0x1),LLIL_REG.q(d21),LLIL_CONST.q(0x10)])'),
    # vqshl.u8 d13, d8, d10
    ('T', b'\x0a\xff\x18\xd4', 'LLIL_INTRINSIC([d13],__vqshl,[LLIL_CONST.b(0x8),LLIL_CONST.b(0x1),LLIL_CONST.b(0x1),LLIL_REG.q(d8),LLIL_REG.q(d10)])'),
    # vqshlu.s32 d16, d28, #0x11
    ('T', b'\xf1\xff\x3c\x06', 'LLIL_INTRINSIC([d16],__vqshl,[LLIL_CONST.b(0x20),LLIL_CONST.b(0x0),LLIL_CONST.b(0x1),LLIL_REG.q(d28),LLIL_CONST.q(0x11)])'),
    # vqshrun.s64 d17, q9, #0xf
    ('T', b'\xf1\xff\x32\x18', 'LLIL_INTRINSIC([d17],__vqshrun,[LLIL_CONST.b(0x40),LLIL_CONST.b(0x0),LLIL_CONST.b(0x1),LLIL_REG.o(q9),LLIL_CONST.o(0xF)])'),
    # vqshrn.u64 d31, q9, #0xe
    ('T', b'\xf2\xff\x32\xf9', 'LLIL_INTRINSIC([d31],__vqshrn,[LLIL_CONST.b(0x40),LLIL_CONST.b(0x1),LLIL_CONST.b(0x1),LLIL_REG.o(q9),LLIL_CONST.o(0xE)])'),
    # vqrshrn.u64 d31, q9, #0xa
    ('T', b'\xf6\xff\x72\xf9', 'LLIL_INTRINSIC([d31],__vqrshrn,[LLIL_CONST.b(0x40),LLIL_CONST.b(0x1),LLIL_CONST.b(0x1),LLIL_REG.o(q9),LLIL_CONST.o(0xA)])'),
    # vqrshrun.s64 d27, q9, #0xa
    ('T', b'\xf6\xff\x72\xb8', 'LLIL_INTRINSIC([d27],__vqrshrun,[LLIL_CONST.b(0x40),LLIL_CONST.b(0x0),LLIL_CONST.b(0x1),LLIL_REG.o(q9),LLIL_CONST.o(0xA)])'),
    # vqmovun.s32 d16, q9
    ('T', b'\xf6\xff\x62\x02', 'LLIL_INTRINSIC([d16],__vqmovun,[LLIL_CONST.b(0x20),LLIL_CONST.b(0x0),LLIL_CONST.b(0x1),LLIL_REG.o(q9)])'),
    # vshll.u32 q10, d19, #0x10
    ('T', b'\xf0\xff\x33\x4a', 'LLIL_INTRINSIC([q10],__vshll,[LLIL_CONST.b(0x20),LLIL_CONST.b(0x1),LLIL_REG.q(d19),LLIL_CONST.q(0x10)])'),
    # vqadd.u16 d0, d11, d8
    ('T', b'\x1b\xff\x18\x00', 'LLIL_INTRINSIC([d0],__vqadd,[LLIL_CONST.b(0x10),LLIL_CONST.b(0x1),LLIL_REG.q(d11),LLIL_REG.q(d8)])'),
    # vqadd.u8 d16, d6, d10
    ('T', b'\x46\xff\x1a\x00', 'LLIL_INTRINSIC([d16],__vqadd,[LLIL_CONST.b(0x8),LLIL_CONST.b(0x1),LLIL_REG.q(d6),LLIL_REG.q(d10)])'),
    # vmax.u8 d8, d13, d24
    ('T', b'\x0d\xff\x28\x86', 'LLIL_INTRINSIC([d8],__vmax,[LLIL_CONST.b(0x8),LLIL_CONST.b(0x1),LLIL_REG.q(d13),LLIL_REG.q(d24)])'),
    # vrev64.8 d16, d8
    ('T', b'\xf0\xff\x08\x00', 'LLIL_INTRINSIC([d16],__vrev64,[LLIL_CONST.b(0x8),LLIL_REG.q(d8)])'),
    # vext.8 d16, d8, d16, #4
    ('A', b'\x20\x04\xf8\xf2', 'LLIL_INTRINSIC([d16],__vext,[LLIL_CONST.b(0x8),LLIL_REG.q(d8),LLIL_REG.q(d16),LLIL_CONST.b(0x4)])'),
    # vext.8 q8, q4, q8, #4
    ('A', b'\x60\x04\xf8\xf2', 'LLIL_INTRINSIC([q8],__vext,[LLIL_CONST.b(0x8),LLIL_REG.o(q4),LLIL_REG.o(q8),LLIL_CONST.b(0x4)])'),
    # vext.8 d16, d8, d16, #4
    ('T', b'\xf8\xef\x20\x04', 'LLIL_INTRINSIC([d16],__vext,[LLIL_CONST.b(0x8),LLIL_REG.q(d8),LLIL_REG.q(d16),LLIL_CONST.b(0x4)])'),
    # vpmin.f32 d4, d1, d19
    ('T', b'\x21\xff\x23\x4f', 'LLIL_INTRINSIC([d4],__vpmin,[LLIL_CONST.b(0x20),LLIL_CONST.b(0x0),LLIL_REG.q(d1),LLIL_REG.q(d19)])'),
    # vshl.u64 d16, d16, d17
    ('A', b'\xa0\x04\x71\xf3', 'LLIL_IF(LLIL_CMP_SLT.q(LLIL_REG.q(d17),LLIL_CONST.q(0x0)),1,3); LLIL_SET_REG.q(d16,LLIL_LSR.q(LLIL_REG.q(d16),LLIL_NEG.q(LLIL_REG.q(d17)))); LLIL_GOTO(5); LLIL_SET_REG.q(d16,LLIL_LSL.q(LLIL_REG.q(d16),LLIL_REG.q(d17))); LLIL_GOTO(5)'),
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
    # vldmia r0, {s0, s1, s2, s3}
    ('A', b'\x04\x0a\x90\xec', 'LLIL_SET_REG.d(s0,LLIL_LOAD.d(LLIL_REG.d(r0))); LLIL_SET_REG.d(s1,LLIL_LOAD.d(LLIL_ADD.d(LLIL_REG.d(r0),LLIL_CONST.d(0x4)))); LLIL_SET_REG.d(s2,LLIL_LOAD.d(LLIL_ADD.d(LLIL_REG.d(r0),LLIL_CONST.d(0x8)))); LLIL_SET_REG.d(s3,LLIL_LOAD.d(LLIL_ADD.d(LLIL_REG.d(r0),LLIL_CONST.d(0xC))))'),
    # vstmia r0, {s0, s1, s2, s3}
    ('A', b'\x04\x0a\x80\xec', 'LLIL_STORE.d(LLIL_REG.d(r0),LLIL_REG.d(s0)); LLIL_STORE.d(LLIL_ADD.d(LLIL_REG.d(r0),LLIL_CONST.d(0x4)),LLIL_REG.d(s1)); LLIL_STORE.d(LLIL_ADD.d(LLIL_REG.d(r0),LLIL_CONST.d(0x8)),LLIL_REG.d(s2)); LLIL_STORE.d(LLIL_ADD.d(LLIL_REG.d(r0),LLIL_CONST.d(0xC)),LLIL_REG.d(s3))'),
    # orr r0, r1, r3, lsl r4
    ('A', b'\x13\x04\x81\xe1', 'LLIL_SET_REG.d(r0,LLIL_OR.d(LLIL_REG.d(r1),LLIL_LSL.d(LLIL_REG.d(r3),LLIL_AND.d(LLIL_REG.d(r4),LLIL_CONST.d(0xFF)))))'),

    # mov r2, r0
    ('T', b'\x02\x46', 'LLIL_SET_REG.d(r2,LLIL_REG.d(r0))'),
    # cmp r1, r2
    ('T', b'\x91\x42', 'LLIL_SUB.d{*}(LLIL_REG.d(r1),LLIL_REG.d(r2))'),
    # cmp r1, r2, lsl #7
    ('T', b'\xb1\xeb\xc2\x1f', 'LLIL_SUB.d{*}(LLIL_REG.d(r1),LLIL_LSL.d(LLIL_REG.d(r2),LLIL_CONST.d(0x7)))'),
    # uadd8 r5, r2, r12
    ('A', b'\x9c\x5f\x52\xe6', scalar_ge_intrinsic_expected('r5', 'uadd8', 'r2', 'r12')),
    # uadd16 r5, r2, r12
    ('A', b'\x1c\x5f\x52\xe6', scalar_ge_intrinsic_expected('r5', 'uadd16', 'r2', 'r12')),
    # uadd8 r5, r2, r12
    ('T', b'\x82\xfa\x4c\xf5', scalar_ge_intrinsic_expected('r5', 'uadd8', 'r2', 'r12')),
    # uadd16 r5, r2, r12
    ('T', b'\x92\xfa\x4c\xf5', scalar_ge_intrinsic_expected('r5', 'uadd16', 'r2', 'r12')),
    # ldrex r0, [r1, #4]
    ('T', b'\x51\xe8\x01\x0f', 'LLIL_INTRINSIC([],SetExclusiveMonitors,[LLIL_ADD.d(LLIL_REG.d(r1),LLIL_CONST.d(0x4)),LLIL_CONST.b(0x4)]); LLIL_SET_REG.d(r0,LLIL_LOAD.d(LLIL_ADD.d(LLIL_REG.d(r1),LLIL_CONST.d(0x4))))'),
    # ldrexb r0, [r1]
    ('T', b'\xd1\xe8\x4f\x0f', 'LLIL_INTRINSIC([],SetExclusiveMonitors,[LLIL_REG.d(r1),LLIL_CONST.b(0x1)]); LLIL_SET_REG.d(r0,LLIL_ZX.d(LLIL_LOAD.b(LLIL_REG.d(r1))))'),
    # ldrexh r0, [r1]
    ('T', b'\xd1\xe8\x5f\x0f', 'LLIL_INTRINSIC([],SetExclusiveMonitors,[LLIL_REG.d(r1),LLIL_CONST.b(0x2)]); LLIL_SET_REG.d(r0,LLIL_ZX.d(LLIL_LOAD.w(LLIL_REG.d(r1))))'),
    # ldrexd r2, r3, [r4]
    ('T', b'\xd4\xe8\x7f\x23', 'LLIL_INTRINSIC([],SetExclusiveMonitors,[LLIL_REG.d(r4),LLIL_CONST.b(0x8)]); LLIL_SET_REG.d(r2,LLIL_LOAD.d(LLIL_REG.d(r4))); LLIL_SET_REG.d(r3,LLIL_LOAD.d(LLIL_ADD.d(LLIL_REG.d(r4),LLIL_CONST.d(0x4))))'),
    # ldm.w r0!, {r1, pc}; followed by an ARM return fence for the arch-transition target
    ('T', b'\xb0\xe8\x02\x80\x0e\xf0\xa0\xe1', 'LLIL_SET_REG.d(temp0,LLIL_REG.d(r0)); LLIL_SET_REG.d(r1,LLIL_LOAD.d(LLIL_ADD.d(LLIL_REG.d(temp0),LLIL_CONST.d(0x0)))); LLIL_SET_REG.d(pc,LLIL_LOAD.d(LLIL_ADD.d(LLIL_REG.d(temp0),LLIL_CONST.d(0x4)))); LLIL_SET_REG.d(r0,LLIL_ADD.d(LLIL_REG.d(r0),LLIL_CONST.d(0x8))); LLIL_JUMP_TO(LLIL_CONST.d(0x4),{4: 6})'),
    # ldaexb r3, [r4]
    ('T', b'\xd4\xe8\xcf\x3f', 'LLIL_INTRINSIC([],SetExclusiveMonitors,[LLIL_REG.d(r4),LLIL_CONST.b(0x1)]); LLIL_SET_REG.d(r3,LLIL_ZX.d(LLIL_LOAD.b(LLIL_REG.d(r4))))'),
    # ldaexh r2, [r5]
    ('T', b'\xd5\xe8\xdf\x2f', 'LLIL_INTRINSIC([],SetExclusiveMonitors,[LLIL_REG.d(r5),LLIL_CONST.b(0x2)]); LLIL_SET_REG.d(r2,LLIL_ZX.d(LLIL_LOAD.w(LLIL_REG.d(r5))))'),
    # vmov.32 d16[0], r3
    ('T', b'\x00\xee\x90\x3b', 'LLIL_SET_REG.q(d16,LLIL_OR.q(LLIL_AND.q(LLIL_REG.q(d16),LLIL_CONST.q(0xFFFFFFFF00000000)),LLIL_ZX.q(LLIL_REG.d(r3))))'),
    # vst1.8 {d16, d17}, [r11]
    ('T', b'\x4b\xf9\x0f\x0a', 'LLIL_STORE.q(LLIL_REG.d(r11),LLIL_REG.q(d16)); LLIL_STORE.q(LLIL_ADD.d(LLIL_REG.d(r11),LLIL_CONST.d(0x8)),LLIL_REG.q(d17))'),
    # vst1.64 {d16, d17}, [r1]
    ('T', b'\x41\xf9\xcf\x0a', 'LLIL_STORE.q(LLIL_REG.d(r1),LLIL_REG.q(d16)); LLIL_STORE.q(LLIL_ADD.d(LLIL_REG.d(r1),LLIL_CONST.d(0x8)),LLIL_REG.q(d17))'),
    # vst1.32 {d16, d17}, [r0]
    ('T', b'\x40\xf9\x8f\x0a', 'LLIL_STORE.q(LLIL_REG.d(r0),LLIL_REG.q(d16)); LLIL_STORE.q(LLIL_ADD.d(LLIL_REG.d(r0),LLIL_CONST.d(0x8)),LLIL_REG.q(d17))'),
    # vst1.16 {d10}, [r1]
    ('T', b'\x01\xf9\x4f\xa7', 'LLIL_STORE.q(LLIL_REG.d(r1),LLIL_REG.q(d10))'),
    # vst1.8 {d0}, [r0], r1
    ('T', b'\x00\xf9\x01\x07', 'LLIL_STORE.q(LLIL_REG.d(r0),LLIL_REG.q(d0)); LLIL_SET_REG.d(r0,LLIL_ADD.d(LLIL_REG.d(r0),LLIL_REG.d(r1)))'),
    # vst4.16 {d20, d21, d22, d23}, [r8:0x40], r1
    ('T', b'\x48\xf9\x51\x40', 'LLIL_INTRINSIC([],__vst4,[LLIL_REG.d(r8),LLIL_CONST.b(0x10),LLIL_CONST.b(0x40),LLIL_CONST.b(0xFF),LLIL_REG.q(d20),LLIL_REG.q(d21),LLIL_REG.q(d22),LLIL_REG.q(d23)]); LLIL_SET_REG.d(r8,LLIL_ADD.d(LLIL_REG.d(r8),LLIL_REG.d(r1)))'),
    # vst2.8 {d8, d9, d10, d11}, [r0:0x40], r10
    ('T', b'\x00\xf9\x1a\x83', 'LLIL_INTRINSIC([],__vst2,[LLIL_REG.d(r0),LLIL_CONST.b(0x8),LLIL_CONST.b(0x40),LLIL_CONST.b(0xFF),LLIL_REG.q(d8),LLIL_REG.q(d9),LLIL_REG.q(d10),LLIL_REG.q(d11)]); LLIL_SET_REG.d(r0,LLIL_ADD.d(LLIL_REG.d(r0),LLIL_REG.d(r10)))'),
    # vst4.16 {d22[3], d24[3], d26[3], d28[3]}, [r0:0x40], r7
    ('T', b'\xc0\xf9\xf7\x67', 'LLIL_INTRINSIC([],__vst4,[LLIL_REG.d(r0),LLIL_CONST.b(0x10),LLIL_CONST.b(0x40),LLIL_CONST.b(0x3),LLIL_REG.q(d22),LLIL_REG.q(d24),LLIL_REG.q(d26),LLIL_REG.q(d28)]); LLIL_SET_REG.d(r0,LLIL_ADD.d(LLIL_REG.d(r0),LLIL_REG.d(r7)))'),
    # vld4.16 {d30, d0, d2, d4}, [r9:0x80], r10
    ('T', b'\x69\xf9\x6a\xe1', 'LLIL_INTRINSIC([d30,d0,d2,d4],__vld4,[LLIL_REG.d(r9),LLIL_CONST.b(0x10),LLIL_CONST.b(0x80),LLIL_CONST.b(0xFF)]); LLIL_SET_REG.d(r9,LLIL_ADD.d(LLIL_REG.d(r9),LLIL_REG.d(r10)))'),
    # vld2.16 {d17, d18}, [r11:0x80], r10
    ('T', b'\x6b\xf9\x6a\x18', 'LLIL_INTRINSIC([d17,d18],__vld2,[LLIL_REG.d(r11),LLIL_CONST.b(0x10),LLIL_CONST.b(0x80),LLIL_CONST.b(0xFF)]); LLIL_SET_REG.d(r11,LLIL_ADD.d(LLIL_REG.d(r11),LLIL_REG.d(r10)))'),
    # vld1.8 {d18, d19}, [r7]
    ('T', b'\x67\xf9\x0f\x2a', 'LLIL_SET_REG.q(d18,LLIL_LOAD.q(LLIL_REG.d(r7))); LLIL_SET_REG.q(d19,LLIL_LOAD.q(LLIL_ADD.d(LLIL_REG.d(r7),LLIL_CONST.d(0x8)))); LLIL_SET_REG.d(r7,LLIL_ADD.d(LLIL_REG.d(r7),LLIL_CONST.d(0x10)))'),
    # vld1.64 {d16, d17}, [r6]
    ('T', b'\x66\xf9\xcf\x0a', 'LLIL_SET_REG.q(d16,LLIL_LOAD.q(LLIL_REG.d(r6))); LLIL_SET_REG.q(d17,LLIL_LOAD.q(LLIL_ADD.d(LLIL_REG.d(r6),LLIL_CONST.d(0x8)))); LLIL_SET_REG.d(r6,LLIL_ADD.d(LLIL_REG.d(r6),LLIL_CONST.d(0x10)))'),
    # vld1.16 {d18}, [r7]
    ('T', b'\x67\xf9\x4f\x27', 'LLIL_SET_REG.q(d18,LLIL_LOAD.q(LLIL_REG.d(r7))); LLIL_SET_REG.d(r7,LLIL_ADD.d(LLIL_REG.d(r7),LLIL_CONST.d(0x8)))'),
    # vcmpe.f64 d8, d16
    ('T', b'\xb4\xee\xe0\x8b', 'LLIL_FSUB.q{fcmp}(LLIL_REG.q(d8),LLIL_REG.q(d16))'),
    # vcmpe.f32 s24, s22
    ('T', b'\xb4\xee\xcb\xca', 'LLIL_FSUB.d{fcmp}(LLIL_REG.d(s24),LLIL_REG.d(s22))'),
    # vmls.f32 s24, s0, s16
    ('T', b'\x00\xee\x48\xca', 'LLIL_SET_REG.d(s24,LLIL_FSUB.d(LLIL_REG.d(s24),LLIL_FMUL.d(LLIL_REG.d(s0),LLIL_REG.d(s16))))'),
    # vmla.f64 d0, d1, d2
    ('A', b'\x02\x0b\x01\xee', 'LLIL_SET_REG.q(d0,LLIL_FADD.q(LLIL_REG.q(d0),LLIL_FMUL.q(LLIL_REG.q(d1),LLIL_REG.q(d2))))'),
    # vfma.f32 s0, s1, s2
    ('A', b'\x81\x0a\xa0\xee', 'LLIL_SET_REG.d(s0,LLIL_FADD.d(LLIL_REG.d(s0),LLIL_FMUL.d(LLIL_REG.d(s1),LLIL_REG.d(s2))))'),
    # vfms.f32 s0, s1, s2
    ('A', b'\xc1\x0a\xa0\xee', 'LLIL_SET_REG.d(s0,LLIL_FSUB.d(LLIL_REG.d(s0),LLIL_FMUL.d(LLIL_REG.d(s1),LLIL_REG.d(s2))))'),
    # vmla.i32 d16, d28, d15[1]
    ('T', b'\xec\xef\xef\x00', 'LLIL_INTRINSIC([d16],__vmla,[LLIL_CONST.b(0x20),LLIL_REG.q(d16),LLIL_REG.q(d28),LLIL_REG.q(d15),LLIL_CONST.b(0x1)])'),
    # vmlsl.u32 q8, d9, d1[0]
    ('T', b'\xe9\xff\x41\x06', 'LLIL_INTRINSIC([q8],__vmlsl,[LLIL_CONST.b(0x20),LLIL_CONST.b(0x1),LLIL_REG.o(q8),LLIL_REG.q(d9),LLIL_REG.q(d1),LLIL_CONST.b(0x0)])'),
    # vmul.p8 q12, q9, q10
    ('T', b'\x42\xff\xf4\x89', 'LLIL_INTRINSIC([q12],__vmul,[LLIL_CONST.b(0x8),LLIL_CONST.b(0x0),LLIL_REG.o(q9),LLIL_REG.o(q10)])'),
    # vqdmull.s32 q8, d0, d1
    ('A', b'\x01\x0d\xe0\xf2', 'LLIL_INTRINSIC([q8],__vqdmull,[LLIL_CONST.b(0x20),LLIL_CONST.b(0x0),LLIL_REG.q(d0),LLIL_REG.q(d1)])'),
    # vqdmull.s32 q8, d0, d1
    ('T', b'\xe0\xef\x01\x0d', 'LLIL_INTRINSIC([q8],__vqdmull,[LLIL_CONST.b(0x20),LLIL_CONST.b(0x0),LLIL_REG.q(d0),LLIL_REG.q(d1)])'),
    # vmlal.s8 q8, d0, d1
    ('A', b'\x01\x08\xc0\xf2', vmlal_expected(8, 0)),
    # vmlal.u8 q8, d0, d1
    ('A', b'\x01\x08\xc0\xf3', vmlal_expected(8, 1)),
    # vmlal.s16 q8, d0, d1
    ('A', b'\x01\x08\xd0\xf2', vmlal_expected(16, 0)),
    # vmlal.u16 q8, d0, d1
    ('A', b'\x01\x08\xd0\xf3', vmlal_expected(16, 1)),
    # vmlal.s32 q8, d0, d1
    ('A', b'\x01\x08\xe0\xf2', vmlal_expected(32, 0)),
    # vmlal.u32 q8, d0, d1
    ('A', b'\x01\x08\xe0\xf3', vmlal_expected(32, 1)),
    # vmlal.s8 q8, d0, d1
    ('T', b'\xc0\xef\x01\x08', vmlal_expected(8, 0)),
    # vmlal.u8 q8, d0, d1
    ('T', b'\xc0\xff\x01\x08', vmlal_expected(8, 1)),
    # vmlal.s16 q8, d0, d1
    ('T', b'\xd0\xef\x01\x08', vmlal_expected(16, 0)),
    # vmlal.u16 q8, d0, d1
    ('T', b'\xd0\xff\x01\x08', vmlal_expected(16, 1)),
    # vmlal.s32 q8, d0, d1
    ('T', b'\xe0\xef\x01\x08', vmlal_expected(32, 0)),
    # vmlal.u32 q8, d0, d1
    ('T', b'\xe0\xff\x01\x08', vmlal_expected(32, 1)),
    # vabal.u16 q8, d10, d24
    ('T', b'\xda\xff\x28\x05', 'LLIL_INTRINSIC([q8],__vabal,[LLIL_CONST.b(0x10),LLIL_CONST.b(0x1),LLIL_REG.o(q8),LLIL_REG.q(d10),LLIL_REG.q(d24)])'),
    # vaba.u8 q11, q9, q11
    ('T', b'\x42\xff\xf6\x67', 'LLIL_INTRINSIC([q11],__vaba,[LLIL_CONST.b(0x8),LLIL_CONST.b(0x1),LLIL_REG.o(q11),LLIL_REG.o(q9),LLIL_REG.o(q11)])'),
    # vabdl.u16 q8, d15, d24
    ('T', b'\xdf\xff\x28\x07', 'LLIL_INTRINSIC([q8],__vabdl,[LLIL_CONST.b(0x10),LLIL_CONST.b(0x1),LLIL_REG.q(d15),LLIL_REG.q(d24)])'),
    # vaddw.u16 q8, q6, d19
    ('T', b'\xdc\xff\x23\x01', 'LLIL_INTRINSIC([q8],__vaddw,[LLIL_CONST.b(0x10),LLIL_CONST.b(0x1),LLIL_REG.o(q6),LLIL_REG.q(d19)])'),
    # vaddl.u16 q8, d14, d24
    ('T', b'\xde\xff\x28\x00', 'LLIL_INTRINSIC([q8],__vaddl,[LLIL_CONST.b(0x10),LLIL_CONST.b(0x1),LLIL_REG.q(d14),LLIL_REG.q(d24)])'),
    # vraddhn.i64 d16, q0, q9
    ('T', b'\xe0\xff\x22\x04', 'LLIL_INTRINSIC([d16],__vraddhn,[LLIL_CONST.b(0x40),LLIL_REG.o(q0),LLIL_REG.o(q9)])'),
    # vadd.i32 d0, d1, d8
    ('T', b'\x21\xef\x08\x08', 'LLIL_INTRINSIC([d0],__vadd,[LLIL_CONST.b(0x20),LLIL_CONST.b(0x1),LLIL_REG.q(d1),LLIL_REG.q(d8)])'),
    # vsub.i32 d0, d1, d8
    ('T', b'\x21\xff\x08\x08', 'LLIL_INTRINSIC([d0],__vsub,[LLIL_CONST.b(0x20),LLIL_CONST.b(0x1),LLIL_REG.q(d1),LLIL_REG.q(d8)])'),
    # vsub.i16 d0, d1, d8
    ('T', b'\x11\xff\x08\x08', 'LLIL_INTRINSIC([d0],__vsub,[LLIL_CONST.b(0x10),LLIL_CONST.b(0x1),LLIL_REG.q(d1),LLIL_REG.q(d8)])'),
    # vsub.i8 d0, d13, d8
    ('T', b'\x0d\xff\x08\x08', 'LLIL_INTRINSIC([d0],__vsub,[LLIL_CONST.b(0x8),LLIL_CONST.b(0x1),LLIL_REG.q(d13),LLIL_REG.q(d8)])'),
    # vhadd.u8 d0, d0, d0
    ('T', b'\x00\xff\x00\x00', vector_intrinsic_expected('d0', 'vhadd', 8, 1, 'd0', 'd0')),
    # vceq.s16 d16, d0, d13
    ('T', b'\x50\xff\x1d\x08', vector_intrinsic_expected('d16', 'vceq', 16, 0, 'd0', 'd13')),
    # vcgt.s32 d0, d19, #0
    ('T', b'\xb9\xff\x23\x00', 'LLIL_INTRINSIC([d0],__vcgt,[LLIL_CONST.b(0x20),LLIL_CONST.b(0x0),LLIL_REG.q(d19),LLIL_CONST.q(0x0)])'),
    # vcgt.u32 d10, d1, d18
    ('T', b'\x21\xff\x22\xa3', 'LLIL_INTRINSIC([d10],__vcgt,[LLIL_CONST.b(0x20),LLIL_CONST.b(0x1),LLIL_REG.q(d1),LLIL_REG.q(d18)])'),
    # vtbl.8 d0, {d5}, d4
    ('T', b'\xb5\xff\x04\x08', 'LLIL_INTRINSIC([d0],__vtbl,[LLIL_CONST.b(0x1),LLIL_REG.q(d5),LLIL_CONST.q(0x0),LLIL_CONST.q(0x0),LLIL_CONST.q(0x0),LLIL_REG.q(d4)])'),
    # vshl.u16 d0, d0, d1
    ('T', b'\x11\xff\x00\x04', 'LLIL_INTRINSIC([d0],__vshl,[LLIL_CONST.b(0x10),LLIL_CONST.b(0x1),LLIL_REG.q(d0),LLIL_REG.q(d1)])'),
    # vnmul.f32 s15, s15, s0
    ('T', b'\x67\xee\xc0\x7a', 'LLIL_SET_REG.d(s15,LLIL_FNEG.d(LLIL_FMUL.d(LLIL_REG.d(s15),LLIL_REG.d(s0))))'),
    # vnmls.f32 s0, s1, s2
    ('A', b'\x81\x0a\x10\xee', 'LLIL_SET_REG.d(s0,LLIL_FNEG.d(LLIL_FSUB.d(LLIL_REG.d(s0),LLIL_FMUL.d(LLIL_REG.d(s1),LLIL_REG.d(s2)))))'),
    # vnmla.f32 s0, s1, s2
    ('A', b'\xc1\x0a\x10\xee', 'LLIL_SET_REG.d(s0,LLIL_FNEG.d(LLIL_FADD.d(LLIL_REG.d(s0),LLIL_FMUL.d(LLIL_REG.d(s1),LLIL_REG.d(s2)))))'),
    # vnmls.f32 s0, s1, s2
    ('T', b'\x10\xee\x81\x0a', 'LLIL_SET_REG.d(s0,LLIL_FNEG.d(LLIL_FSUB.d(LLIL_REG.d(s0),LLIL_FMUL.d(LLIL_REG.d(s1),LLIL_REG.d(s2)))))'),
    # vnmla.f32 s0, s1, s2
    ('T', b'\x10\xee\xc1\x0a', 'LLIL_SET_REG.d(s0,LLIL_FNEG.d(LLIL_FADD.d(LLIL_REG.d(s0),LLIL_FMUL.d(LLIL_REG.d(s1),LLIL_REG.d(s2)))))'),
    # vsqrt.f32 s15, s0
    ('T', b'\xf1\xee\xc0\x7a', 'LLIL_SET_REG.d(s15,LLIL_FSQRT.d(LLIL_REG.d(s0)))'),
    # vselgt.f32 s14, s15, s14
    ('T', b'\x37\xfe\x87\x7a', 'LLIL_IF(LLIL_FLAG_COND(LowLevelILFlagCondition.LLFC_SGT,None),1,3); LLIL_SET_REG.d(s14,LLIL_REG.d(s15)); LLIL_GOTO(5); LLIL_SET_REG.d(s14,LLIL_REG.d(s14)); LLIL_GOTO(5)'),
    # vseleq.f32 s15, s13, s14
    ('T', b'\x46\xfe\x87\x7a', 'LLIL_IF(LLIL_FLAG_COND(LowLevelILFlagCondition.LLFC_E,None),1,3); LLIL_SET_REG.d(s15,LLIL_REG.d(s13)); LLIL_GOTO(5); LLIL_SET_REG.d(s15,LLIL_REG.d(s14)); LLIL_GOTO(5)'),
    # vselge.f64 d6, d6, d7
    ('T', b'\x26\xfe\x07\x6b', 'LLIL_IF(LLIL_FLAG_COND(LowLevelILFlagCondition.LLFC_SGE,None),1,3); LLIL_SET_REG.q(d6,LLIL_REG.q(d6)); LLIL_GOTO(5); LLIL_SET_REG.q(d6,LLIL_REG.q(d7)); LLIL_GOTO(5)'),
    # vfnma.f64 d2, d14, d11
    ('T', b'\x9e\xee\x4b\x2b', 'LLIL_SET_REG.q(d2,LLIL_FNEG.q(LLIL_FADD.q(LLIL_REG.q(d2),LLIL_FMUL.q(LLIL_REG.q(d14),LLIL_REG.q(d11)))))'),
    # vfnms.f32 s8, s14, s11
    ('T', b'\x97\xee\x25\x4a', 'LLIL_SET_REG.d(s8,LLIL_FNEG.d(LLIL_FSUB.d(LLIL_REG.d(s8),LLIL_FMUL.d(LLIL_REG.d(s14),LLIL_REG.d(s11)))))'),
    # vrinta.f32 s0, s0
    ('T', b'\xb8\xfe\x40\x0a', 'LLIL_INTRINSIC([s0],__vrinta,[LLIL_REG.d(s0)])'),
    # vrintm.f32 s17, s14
    ('T', b'\xfb\xfe\x47\x8a', 'LLIL_SET_REG.d(s17,LLIL_FLOOR.d(LLIL_REG.d(s14)))'),
    # vcvt.f32.s32 s14, s14, #1
    ('T', b'\xba\xee\xef\x7a', 'LLIL_SET_REG.d(s14,LLIL_FDIV.d(LLIL_INT_TO_FLOAT.d(LLIL_SX.d(LLIL_REG.d(s14))),LLIL_FLOAT_CONST.d(2.0)))'),
    # vcvt.f64.u32 d7, d7, #1
    ('T', b'\xbb\xee\xef\x7b', 'LLIL_SET_REG.q(d7,LLIL_FDIV.q(LLIL_INT_TO_FLOAT.q(LLIL_ZX.q(LLIL_LOW_PART.d(LLIL_REG.q(d7)))),LLIL_FLOAT_CONST.q(2.0)))'),
    # vcvt.s32.f64 d2, d2, #0x20
    ('A', b'\xc0\x2b\xbe\xee', 'LLIL_SET_REG.q(d2,LLIL_SX.q(LLIL_FLOAT_TO_INT.d(LLIL_ROUND_TO_INT.q(LLIL_FMUL.q(LLIL_REG.q(d2),LLIL_FLOAT_CONST.q(4294967296.0))))))'),
    # vcvt.u32.f64 d20, d20, #0x20
    ('A', b'\xc0\x4b\xff\xee', 'LLIL_SET_REG.q(d20,LLIL_ZX.q(LLIL_FLOAT_TO_INT.d(LLIL_ROUND_TO_INT.q(LLIL_FMUL.q(LLIL_REG.q(d20),LLIL_FLOAT_CONST.q(4294967296.0))))))'),
    # vmaxnm.f64 d11, d11, d7
    ('T', b'\x8b\xfe\x07\xbb', 'LLIL_INTRINSIC([d11],__vmaxnm,[LLIL_REG.q(d11),LLIL_REG.q(d7)])'),
    # vminnm.f64 d8, d8, d9
    ('T', b'\x88\xfe\x49\x8b', 'LLIL_INTRINSIC([d8],__vminnm,[LLIL_REG.q(d8),LLIL_REG.q(d9)])'),
    # umlal r0, r1, r2, r3
    ('T', b'\xe2\xfb\x03\x01', 'LLIL_SET_REG_SPLIT.d(r1,r0,LLIL_ADD.q(LLIL_MULU_DP.d(LLIL_REG.d(r3),LLIL_REG.d(r2)),LLIL_REG_SPLIT.d(r1,r0)))'),
    # smlad r0, r1, r2, r3
    ('T', b'\x21\xfb\x02\x30', scalar_q_intrinsic_expected('r0', 'smlad', 'r1', 'r2', 'r3')),
    # smuad r0, r1, r2
    ('T', b'\x21\xfb\x02\xf0', scalar_q_intrinsic_expected('r0', 'smuad', 'r1', 'r2')),
    # smuadx r0, r1, r2
    ('T', b'\x21\xfb\x12\xf0', scalar_q_intrinsic_expected('r0', 'smuadx', 'r1', 'r2')),
    # smusd r0, r1, r2
    ('T', b'\x41\xfb\x02\xf0', scalar_q_intrinsic_expected('r0', 'smusd', 'r1', 'r2')),
    # smusdx r0, r1, r2
    ('T', b'\x41\xfb\x12\xf0', scalar_q_intrinsic_expected('r0', 'smusdx', 'r1', 'r2')),
    # smlsd r0, r1, r2, r3
    ('T', b'\x41\xfb\x02\x30', scalar_q_intrinsic_expected('r0', 'smlsd', 'r1', 'r2', 'r3')),
    # smlsdx r0, r1, r2, r3
    ('T', b'\x41\xfb\x12\x30', scalar_q_intrinsic_expected('r0', 'smlsdx', 'r1', 'r2', 'r3')),
    # smlsld r0, r1, r2, r3
    ('T', b'\xd2\xfb\xc3\x01', 'LLIL_INTRINSIC([r1,r0],__smlsld,[LLIL_REG.d(r2),LLIL_REG.d(r3),LLIL_REG_SPLIT.d(r1,r0)])'),
    # smlsldx r0, r1, r2, r3
    ('T', b'\xd2\xfb\xd3\x01', 'LLIL_INTRINSIC([r1,r0],__smlsldx,[LLIL_REG.d(r2),LLIL_REG.d(r3),LLIL_REG_SPLIT.d(r1,r0)])'),
    # smlalbb r0, r1, r2, r3
    ('A', b'\x82\x03\x41\xe1', 'LLIL_SET_REG_SPLIT.d(r1,r0,LLIL_ADD.q(LLIL_SX.q(LLIL_MUL.d(LLIL_SX.d(LLIL_LOW_PART.w(LLIL_REG.d(r2))),LLIL_SX.d(LLIL_LOW_PART.w(LLIL_REG.d(r3))))),LLIL_REG_SPLIT.d(r1,r0)))'),
    # smlalbt r0, r1, r2, r3
    ('A', b'\xc2\x03\x41\xe1', 'LLIL_SET_REG_SPLIT.d(r1,r0,LLIL_ADD.q(LLIL_SX.q(LLIL_MUL.d(LLIL_SX.d(LLIL_LOW_PART.w(LLIL_REG.d(r2))),LLIL_SX.d(LLIL_LOW_PART.w(LLIL_ASR.d(LLIL_REG.d(r3),LLIL_CONST.b(0x10)))))),LLIL_REG_SPLIT.d(r1,r0)))'),
    # smlaltb r0, r1, r2, r3
    ('A', b'\xa2\x03\x41\xe1', 'LLIL_SET_REG_SPLIT.d(r1,r0,LLIL_ADD.q(LLIL_SX.q(LLIL_MUL.d(LLIL_SX.d(LLIL_LOW_PART.w(LLIL_ASR.d(LLIL_REG.d(r2),LLIL_CONST.b(0x10)))),LLIL_SX.d(LLIL_LOW_PART.w(LLIL_REG.d(r3))))),LLIL_REG_SPLIT.d(r1,r0)))'),
    # smlaltt r0, r1, r2, r3
    ('A', b'\xe2\x03\x41\xe1', 'LLIL_SET_REG_SPLIT.d(r1,r0,LLIL_ADD.q(LLIL_SX.q(LLIL_MUL.d(LLIL_SX.d(LLIL_LOW_PART.w(LLIL_ASR.d(LLIL_REG.d(r2),LLIL_CONST.b(0x10)))),LLIL_SX.d(LLIL_LOW_PART.w(LLIL_ASR.d(LLIL_REG.d(r3),LLIL_CONST.b(0x10)))))),LLIL_REG_SPLIT.d(r1,r0)))'),
    # smlalbb r0, r1, r2, r3
    ('T', b'\xc2\xfb\x83\x01', 'LLIL_SET_REG_SPLIT.d(r1,r0,LLIL_ADD.q(LLIL_SX.q(LLIL_MUL.d(LLIL_SX.d(LLIL_LOW_PART.w(LLIL_REG.d(r2))),LLIL_SX.d(LLIL_LOW_PART.w(LLIL_REG.d(r3))))),LLIL_REG_SPLIT.d(r1,r0)))'),
    # smlalbt r0, r1, r2, r3
    ('T', b'\xc2\xfb\x93\x01', 'LLIL_SET_REG_SPLIT.d(r1,r0,LLIL_ADD.q(LLIL_SX.q(LLIL_MUL.d(LLIL_SX.d(LLIL_LOW_PART.w(LLIL_REG.d(r2))),LLIL_ASR.d(LLIL_REG.d(r3),LLIL_CONST.b(0x10)))),LLIL_REG_SPLIT.d(r1,r0)))'),
    # smlaltb r0, r1, r2, r3
    ('T', b'\xc2\xfb\xa3\x01', 'LLIL_SET_REG_SPLIT.d(r1,r0,LLIL_ADD.q(LLIL_SX.q(LLIL_MUL.d(LLIL_ASR.d(LLIL_REG.d(r2),LLIL_CONST.b(0x10)),LLIL_SX.d(LLIL_LOW_PART.w(LLIL_REG.d(r3))))),LLIL_REG_SPLIT.d(r1,r0)))'),
    # smlaltt r0, r1, r2, r3
    ('T', b'\xc2\xfb\xb3\x01', 'LLIL_SET_REG_SPLIT.d(r1,r0,LLIL_ADD.q(LLIL_SX.q(LLIL_MUL.d(LLIL_ASR.d(LLIL_REG.d(r2),LLIL_CONST.b(0x10)),LLIL_ASR.d(LLIL_REG.d(r3),LLIL_CONST.b(0x10)))),LLIL_REG_SPLIT.d(r1,r0)))'),
    # smlawb r0, r1, r2, r3
    ('T', b'\x31\xfb\x02\x30', scalar_q_intrinsic_expected('r0', 'smlawb', 'r1', 'r2', 'r3')),
    # smlawt r0, r1, r2, r3
    ('T', b'\x31\xfb\x12\x30', scalar_q_intrinsic_expected('r0', 'smlawt', 'r1', 'r2', 'r3')),
    # smulwb r0, r1, r2
    ('A', b'\xa1\x02\x20\xe1', 'LLIL_SET_REG.d(r0,LLIL_LOW_PART.d(LLIL_ASR.q(LLIL_MUL.q(LLIL_SX.q(LLIL_REG.d(r1)),LLIL_SX.q(LLIL_SX.d(LLIL_LOW_PART.w(LLIL_REG.d(r2))))),LLIL_CONST.b(0x10))))'),
    # smulwt r0, r1, r2
    ('A', b'\xe1\x02\x20\xe1', 'LLIL_SET_REG.d(r0,LLIL_LOW_PART.d(LLIL_ASR.q(LLIL_MUL.q(LLIL_SX.q(LLIL_REG.d(r1)),LLIL_SX.q(LLIL_SX.d(LLIL_LOW_PART.w(LLIL_ASR.d(LLIL_REG.d(r2),LLIL_CONST.b(0x10)))))),LLIL_CONST.b(0x10))))'),
    # smulwb r0, r1, r2
    ('T', b'\x31\xfb\x02\xf0', 'LLIL_SET_REG.d(r0,LLIL_LOW_PART.d(LLIL_ASR.q(LLIL_MUL.q(LLIL_SX.q(LLIL_REG.d(r1)),LLIL_SX.q(LLIL_SX.d(LLIL_LOW_PART.w(LLIL_REG.d(r2))))),LLIL_CONST.b(0x10))))'),
    # smulwt r0, r1, r2
    ('T', b'\x31\xfb\x12\xf0', 'LLIL_SET_REG.d(r0,LLIL_LOW_PART.d(LLIL_ASR.q(LLIL_MUL.q(LLIL_SX.q(LLIL_REG.d(r1)),LLIL_SX.q(LLIL_ASR.d(LLIL_REG.d(r2),LLIL_CONST.b(0x10)))),LLIL_CONST.b(0x10))))'),
    # smlal r4, r5, r2, r3
    ('T', b'\xc2\xfb\x03\x45', 'LLIL_SET_REG_SPLIT.d(r5,r4,LLIL_ADD.q(LLIL_MULS_DP.d(LLIL_REG.d(r2),LLIL_REG.d(r3)),LLIL_REG_SPLIT.d(r5,r4)))'),
    # smlald r11, r5, pc, r0
    ('T', b'\xcf\xfb\xc0\xb5', 'LLIL_INTRINSIC([r5,r11],__smlald,[LLIL_CONST.d(0x4),LLIL_REG.d(r0),LLIL_REG_SPLIT.d(r5,r11)])'),
    # usad8 r0, r1, r2
    ('T', b'\x71\xfb\x02\xf0', scalar_intrinsic_expected('r0', 'usad8', 'r1', 'r2')),
    # usada8 r0, r1, r2, r3
    ('T', b'\x71\xfb\x02\x30', scalar_intrinsic_expected('r0', 'usada8', 'r1', 'r2', 'r3')),
    # smmul r0, r0, r1
    ('T', b'\x50\xfb\x01\xf0', 'LLIL_SET_REG.d(r0,LLIL_LOW_PART.d(LLIL_ASR.q(LLIL_MULS_DP.d(LLIL_REG.d(r0),LLIL_REG.d(r1)),LLIL_CONST.b(0x20))))'),
    # smmulr r3, r2, r1
    ('T', b'\x52\xfb\x11\xf3', 'LLIL_SET_REG.d(r3,LLIL_LOW_PART.d(LLIL_ASR.q(LLIL_ADD.q(LLIL_MULS_DP.d(LLIL_REG.d(r2),LLIL_REG.d(r1)),LLIL_CONST.q(0x80000000)),LLIL_CONST.b(0x20))))'),
    # smmlar r8, sp, r6, r0
    ('T', b'\x5d\xfb\x16\x08', 'LLIL_SET_REG.d(r8,LLIL_ADD.d(LLIL_LOW_PART.d(LLIL_ASR.q(LLIL_ADD.q(LLIL_MULS_DP.d(LLIL_REG.d(sp),LLIL_REG.d(r6)),LLIL_CONST.q(0x80000000)),LLIL_CONST.b(0x20))),LLIL_REG.d(r0)))'),
    # smmlsr r8, r5, r6, r0
    ('T', b'\x65\xfb\x16\x08', 'LLIL_SET_REG.d(r8,LLIL_LOW_PART.d(LLIL_ASR.q(LLIL_ADD.q(LLIL_SUB.q(LLIL_LSL.q(LLIL_REG.d(r0),LLIL_CONST.b(0x20)),LLIL_MULS_DP.d(LLIL_REG.d(r5),LLIL_REG.d(r6))),LLIL_CONST.q(0x80000000)),LLIL_CONST.b(0x20))))'),
    # smlabb r6, r0, r1, r11
    ('T', b'\x10\xfb\x01\xb6', scalar_q_intrinsic_expected('r6', 'smlabb', 'r0', 'r1', 'r11')),
    # sel r5, r3, r7
    ('A', b'\xb7\x5f\x83\xe6', 'LLIL_INTRINSIC([r5],__sel,[LLIL_REG.d(r3),LLIL_REG.d(r7),LLIL_REG.d(apsr_g)])'),
    # sel r5, r3, r7
    ('T', b'\xa3\xfa\x87\xf5', 'LLIL_INTRINSIC([r5],__sel,[LLIL_REG.d(r3),LLIL_REG.d(r7),LLIL_REG.d(apsr_g)])'),
    # sbfx r0, r1, 0, 1 (starting at b0, width 1, so extract b0)
    ('T', b'\x41\xf3\x00\x00', 'LLIL_SET_REG.d(r0,LLIL_ASR.d(LLIL_LSL.d(LLIL_REG.d(r1),LLIL_CONST.b(0x1F)),LLIL_CONST.b(0x1F)))'),
    # sbfx r0, r1, 1, 2 (starting at b1, width 2, so extract b2b1)
    ('T', b'\x41\xf3\x41\x00', 'LLIL_SET_REG.d(r0,LLIL_ASR.d(LLIL_LSL.d(LLIL_REG.d(r1),LLIL_CONST.b(0x1D)),LLIL_CONST.b(0x1E)))'),
    # sbfx r0, r1, 20, 30 (starting at b20, width 30... gets clamped, so b31b30...b20
    # just r0 = r1 >> 20, no left shift required
    ('T', b'\x41\xf3\x1d\x50', 'LLIL_SET_REG.d(r0,LLIL_ASR.d(LLIL_REG.d(r1),LLIL_CONST.b(0x14)))'),
    # rev r1, r1
    ('T', b'\x09\xba',         'LLIL_SET_REG.d(r1,LLIL_BSWAP.d(LLIL_REG.d(r1)))'),
    # revsh r3, r3
    ('T', b'\xdb\xba', 'LLIL_SET_REG.d(r3,LLIL_SX.d(LLIL_BSWAP.w(LLIL_LOW_PART.w(LLIL_REG.d(r3)))))'),
    # revsh.w r8, r8
    ('T', b'\x98\xfa\xb8\xf8', 'LLIL_SET_REG.d(r8,LLIL_SX.d(LLIL_BSWAP.w(LLIL_LOW_PART.w(LLIL_REG.d(r8)))))'),
]

info_test_cases = [
    # ldm.w r0!, {r1, pc}
    ('T', b'\xb0\xe8\x02\x80', 4, [('UnresolvedBranch', 0)], True),
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

def fail_test(message):
    raise AssertionError(message)

def run_all_tests():
    for (test_i, (arch_name, data, expected)) in enumerate(test_cases):
        platform = {'A':'linux-armv7', 'T':'linux-thumb2'}[arch_name]

        if '?' in expected:
            fail_test(
                'INVALID EXPECTED LLIL AT TEST %d!\n\t   input: %s\n\texpected: %s'
                % (test_i, data.hex(), expected))

        actual = instr_to_il(data, platform)

        #print(f'{test_i:04d} {data.hex()} {actual}')

        if '?' in actual:
            fail_test(
                'INVALID ACTUAL LLIL AT TEST %d!\n\t   input: %s\n\t  actual: %s\n\t    tree:\n%s'
                % (test_i, data.hex(), actual, il_str_to_tree(actual)))

        if actual != expected:
            fail_test(
                'MISMATCH AT TEST %d!\n\t   input: %s\n\texpected: %s\n\t  actual: %s\n\t    tree:\n%s'
                % (test_i, data.hex(), expected, actual, il_str_to_tree(actual)))

    for (test_i, (arch_name, data, expected_length, expected_branches, expected_arch_transition)) in enumerate(info_test_cases):
        platform = {'A':'linux-armv7', 'T':'linux-thumb2'}[arch_name]
        info = binaryninja.Platform[platform].arch.get_instruction_info(data, 0)
        actual_branches = [(branch.type.name, branch.target) for branch in info.branches]

        if info.length != expected_length or actual_branches != expected_branches or info.arch_transition_by_target_addr != expected_arch_transition:
            fail_test(
                'MISMATCH AT INFO TEST %d!\n\t   input: %s\n\texpected: length=%d branches=%s arch_transition=%s\n\t  actual: length=%d branches=%s arch_transition=%s'
                % (test_i, data.hex(), expected_length, expected_branches, expected_arch_transition,
                    info.length, actual_branches, info.arch_transition_by_target_addr))

def test_all():
    run_all_tests()

if __name__ == '__main__':
    run_all_tests()
    print('success!')
    sys.exit(0)

if __name__ == 'test_lift':
    test_all()
    print('success!')
