#!/usr/bin/env python

test_cases = [
    # align $t0, $t1, $t2, 0 -- bp=0 is a register-to-register move from rt
    ('mips32', b'\x7d\x2a\x42\x20', 'LLIL_SET_REG.d($t0,LLIL_REG.d($t2))'),
    # align $t0, $t1, $t2, 1 -- concatenate rt:rs and select at byte position 1
    ('mipsel32', b'\x60\x42\x2a\x7d', 'LLIL_SET_REG.d($t0,LLIL_OR.d(LLIL_LSL.d(LLIL_REG.d($t2),LLIL_CONST.b(0x8)),LLIL_LSR.d(LLIL_REG.d($t1),LLIL_CONST.b(0x18))))'),
    # align $t0, $t1, $t2, 2 -- select the middle two bytes from each source
    ('mips32', b'\x7d\x2a\x42\xa0', 'LLIL_SET_REG.d($t0,LLIL_OR.d(LLIL_LSL.d(LLIL_REG.d($t2),LLIL_CONST.b(0x10)),LLIL_LSR.d(LLIL_REG.d($t1),LLIL_CONST.b(0x10))))'),
    # align $t0, $t1, $t2, 3 -- concatenate rt:rs and select at byte position 3
    ('mipsel32', b'\xe0\x42\x2a\x7d', 'LLIL_SET_REG.d($t0,LLIL_OR.d(LLIL_LSL.d(LLIL_REG.d($t2),LLIL_CONST.b(0x18)),LLIL_LSR.d(LLIL_REG.d($t1),LLIL_CONST.b(0x8))))'),
    # bitswap $t0, $t1 -- reverse the bits within each byte without moving the bytes
    ('mips32', b'\x7c\x09\x40\x20', 'LLIL_SET_REG.d($t0,LLIL_BSWAP.d(LLIL_RBIT.d(LLIL_REG.d($t1))))'),
    # bitswap $t1, $t1 -- little-endian encoding and an in-place operation
    ('mipsel32', b'\x20\x48\x09\x7c', 'LLIL_SET_REG.d($t1,LLIL_BSWAP.d(LLIL_RBIT.d(LLIL_REG.d($t1))))'),
    # dbitswap $t0, $t1 -- MIPS64 Release 6.06 pp. 112-113: reverse bits within all eight bytes
    ('mips64', b'\x7c\x09\x40\x24', 'LLIL_SET_REG.q($t0,LLIL_BSWAP.q(LLIL_RBIT.q(LLIL_REG.q($t1))))'),
    # dbitswap $t1, $t1 -- little-endian encoding and source/destination aliasing
    ('mipsel64', b'\x24\x48\x09\x7c', 'LLIL_SET_REG.q($t1,LLIL_BSWAP.q(LLIL_RBIT.q(LLIL_REG.q($t1))))'),
    # dbitswap $t0, $zero -- the zero source is not a register read
    ('mips64', b'\x7c\x00\x40\x24', 'LLIL_SET_REG.q($t0,LLIL_BSWAP.q(LLIL_RBIT.q(LLIL_CONST.q(0x0))))'),
    # dbitswap $zero, $t1 -- writes to the architectural zero register are discarded
    ('mipsel64', b'\x24\x00\x09\x7c', 'LLIL_NOP()'),
    # dbitswap $ra, $ra -- the final GPR and an in-place full-width operation
    ('mips64', b'\x7c\x1f\xf8\x24', 'LLIL_SET_REG.q($ra,LLIL_BSWAP.q(LLIL_RBIT.q(LLIL_REG.q($ra))))'),
    # dalign $t0, $t1, $t2, 0 -- MIPS64 Release 6.06 pp. 59-60: bp=0 copies rt without shifting by 64
    ('mips64', b'\x7d\x2a\x42\x24', 'LLIL_SET_REG.q($t0,LLIL_REG.q($t2))'),
    # dalign $t0, $t1, $t2, 1 -- concatenate rt:rs, not rs:rt
    ('mipsel64', b'\x64\x42\x2a\x7d', 'LLIL_SET_REG.q($t0,LLIL_OR.q(LLIL_LSL.q(LLIL_REG.q($t2),LLIL_CONST.b(0x8)),LLIL_LSR.q(LLIL_REG.q($t1),LLIL_CONST.b(0x38))))'),
    # dalign $t0, $t1, $t2, 2
    ('mips64', b'\x7d\x2a\x42\xa4', 'LLIL_SET_REG.q($t0,LLIL_OR.q(LLIL_LSL.q(LLIL_REG.q($t2),LLIL_CONST.b(0x10)),LLIL_LSR.q(LLIL_REG.q($t1),LLIL_CONST.b(0x30))))'),
    # dalign $t0, $t1, $t2, 3
    ('mipsel64', b'\xe4\x42\x2a\x7d', 'LLIL_SET_REG.q($t0,LLIL_OR.q(LLIL_LSL.q(LLIL_REG.q($t2),LLIL_CONST.b(0x18)),LLIL_LSR.q(LLIL_REG.q($t1),LLIL_CONST.b(0x28))))'),
    # dalign $t0, $t1, $t2, 4 -- bp bit 2 must not be discarded
    ('mips64', b'\x7d\x2a\x43\x24', 'LLIL_SET_REG.q($t0,LLIL_OR.q(LLIL_LSL.q(LLIL_REG.q($t2),LLIL_CONST.b(0x20)),LLIL_LSR.q(LLIL_REG.q($t1),LLIL_CONST.b(0x20))))'),
    # dalign $t0, $t1, $t2, 5
    ('mipsel64', b'\x64\x43\x2a\x7d', 'LLIL_SET_REG.q($t0,LLIL_OR.q(LLIL_LSL.q(LLIL_REG.q($t2),LLIL_CONST.b(0x28)),LLIL_LSR.q(LLIL_REG.q($t1),LLIL_CONST.b(0x18))))'),
    # dalign $t0, $t1, $t2, 6
    ('mips64', b'\x7d\x2a\x43\xa4', 'LLIL_SET_REG.q($t0,LLIL_OR.q(LLIL_LSL.q(LLIL_REG.q($t2),LLIL_CONST.b(0x30)),LLIL_LSR.q(LLIL_REG.q($t1),LLIL_CONST.b(0x10))))'),
    # dalign $t0, $t1, $t2, 7 -- maximum byte position
    ('mipsel64', b'\xe4\x43\x2a\x7d', 'LLIL_SET_REG.q($t0,LLIL_OR.q(LLIL_LSL.q(LLIL_REG.q($t2),LLIL_CONST.b(0x38)),LLIL_LSR.q(LLIL_REG.q($t1),LLIL_CONST.b(0x8))))'),
    # dalign $t1, $t1, $t2, 7 -- destination aliases rs
    ('mipsel64', b'\xe4\x4b\x2a\x7d', 'LLIL_SET_REG.q($t1,LLIL_OR.q(LLIL_LSL.q(LLIL_REG.q($t2),LLIL_CONST.b(0x38)),LLIL_LSR.q(LLIL_REG.q($t1),LLIL_CONST.b(0x8))))'),
    # dalign $t2, $t1, $t2, 1 -- destination aliases rt
    ('mips64', b'\x7d\x2a\x52\x64', 'LLIL_SET_REG.q($t2,LLIL_OR.q(LLIL_LSL.q(LLIL_REG.q($t2),LLIL_CONST.b(0x8)),LLIL_LSR.q(LLIL_REG.q($t1),LLIL_CONST.b(0x38))))'),
    # dalign $t0, $zero, $t2, 7 -- zero rs supplies the low half of the concatenation
    ('mips64', b'\x7c\x0a\x43\xe4', 'LLIL_SET_REG.q($t0,LLIL_OR.q(LLIL_LSL.q(LLIL_REG.q($t2),LLIL_CONST.b(0x38)),LLIL_LSR.q(LLIL_CONST.q(0x0),LLIL_CONST.b(0x8))))'),
    # dalign $t0, $t1, $zero, 1 -- zero rt supplies the high half
    ('mipsel64', b'\x64\x42\x20\x7d', 'LLIL_SET_REG.q($t0,LLIL_OR.q(LLIL_LSL.q(LLIL_CONST.q(0x0),LLIL_CONST.b(0x8)),LLIL_LSR.q(LLIL_REG.q($t1),LLIL_CONST.b(0x38))))'),
    # dalign $t0, $t1, $zero, 0 -- bp=0 still selects rt when rt is zero
    ('mips64', b'\x7d\x20\x42\x24', 'LLIL_SET_REG.q($t0,LLIL_CONST.q(0x0))'),
    # dalign $t0, $zero, $zero, 4 -- both sources may be zero
    ('mipsel64', b'\x24\x43\x00\x7c', 'LLIL_SET_REG.q($t0,LLIL_OR.q(LLIL_LSL.q(LLIL_CONST.q(0x0),LLIL_CONST.b(0x20)),LLIL_LSR.q(LLIL_CONST.q(0x0),LLIL_CONST.b(0x20))))'),
    # dalign $zero, $t1, $t2, 7 -- the result is discarded
    ('mips64', b'\x7d\x2a\x03\xe4', 'LLIL_NOP()'),
    # align $t0, $t1, $t2, 0 -- the word variant still sign-extends on MIPS64
    ('mips64', b'\x7d\x2a\x42\x20', 'LLIL_SET_REG.q($t0,LLIL_SX.q(LLIL_REG.d($t2)))'),
    # align $t0, $t1, $t2, 3 -- retain 32-bit shifts and result sign extension
    ('mipsel64', b'\xe0\x42\x2a\x7d', 'LLIL_SET_REG.q($t0,LLIL_SX.q(LLIL_OR.d(LLIL_LSL.d(LLIL_REG.d($t2),LLIL_CONST.b(0x18)),LLIL_LSR.d(LLIL_REG.d($t1),LLIL_CONST.b(0x8)))))'),
    # bitswap $t0, $t1 -- unlike DBITSWAP, this operates on and sign-extends a word
    ('mips64', b'\x7c\x09\x40\x20', 'LLIL_SET_REG.q($t0,LLIL_SX.q(LLIL_BSWAP.d(LLIL_RBIT.d(LLIL_REG.d($t1)))))'),
    # bnez $t0, 0xc; dbitswap $t0, $t1 -- preserve the pre-delay-slot full-width branch input
    ('mips64', b'\x15\x00\x00\x02\x7c\x09\x40\x24', 'LLIL_SET_REG.q(temp1,LLIL_REG.q($t0)); LLIL_SET_REG.q($t0,LLIL_BSWAP.q(LLIL_RBIT.q(LLIL_REG.q($t1)))); LLIL_IF(LLIL_CMP_NE.q(LLIL_REG.q(temp1),LLIL_CONST.q(0x0)),6,3)'),
    # bnez $t1, 0xc; dalign $t1, $t1, $t2, 7 -- an aliased source still uses the original value
    ('mipsel64', b'\x02\x00\x20\x15\xe4\x4b\x2a\x7d', 'LLIL_SET_REG.q(temp1,LLIL_REG.q($t1)); LLIL_SET_REG.q($t1,LLIL_OR.q(LLIL_LSL.q(LLIL_REG.q($t2),LLIL_CONST.b(0x38)),LLIL_LSR.q(LLIL_REG.q($t1),LLIL_CONST.b(0x8)))); LLIL_IF(LLIL_CMP_NE.q(LLIL_REG.q(temp1),LLIL_CONST.q(0x0)),6,3)'),
    # bc1eqz $f3, 0xc; mtc1 $zero, $f3 -- test pre-delay-slot bit 0 for equality
    ('mips32', b'\x45\x23\x00\x02\x44\x80\x18\x00', 'LLIL_SET_REG.d(temp1,LLIL_REG.d($f3)); LLIL_SET_REG.d($f3,LLIL_CONST.d(0x0)); LLIL_IF(LLIL_NOT(LLIL_TEST_BIT.d(LLIL_REG.d(temp1),LLIL_CONST.b(0x0))),6,3)'),
    # bc1nez $f4, 0xc; mtc1 $zero, $f4 -- test pre-delay-slot bit 0 for inequality
    ('mipsel32', b'\x02\x00\xa4\x45\x00\x20\x80\x44', 'LLIL_SET_REG.d(temp1,LLIL_REG.d($f4)); LLIL_SET_REG.d($f4,LLIL_CONST.d(0x0)); LLIL_IF(LLIL_TEST_BIT.d(LLIL_REG.d(temp1),LLIL_CONST.b(0x0)),6,3)'),
    # bc2eqz $3, 0xc; nop -- branch when COP2 condition selector 3 is zero
    ('mips32', b'\x49\x23\x00\x02\x00\x00\x00\x00', 'LLIL_NOP(); LLIL_NOP(); LLIL_IF(LLIL_CMP_E.d(LLIL_REG.d($3),LLIL_CONST.d(0x0)),6,3)'),
    # bc2nez $4, 0xc; nop -- branch when COP2 condition selector 4 is nonzero
    ('mipsel32', b'\x02\x00\xa4\x49\x00\x00\x00\x00', 'LLIL_NOP(); LLIL_NOP(); LLIL_IF(LLIL_CMP_NE.d(LLIL_REG.d($4),LLIL_CONST.d(0x0)),6,3)'),
    # beqz $t0, 0xc; cfc1 $t0, $fcr31 -- an intrinsic output clobbers the branch input
    ('mips32', b'\x11\x00\x00\x02\x44\x48\xf8\x00', 'LLIL_SET_REG.d(temp1,LLIL_REG.d($t0)); LLIL_INTRINSIC([temp0],moveControlWordFromCoprocessor1,[LLIL_REG.d($fcr31)]); LLIL_SET_REG.d($t0,LLIL_REG.d(temp0)); LLIL_IF(LLIL_CMP_E.d(LLIL_REG.d(temp1),LLIL_CONST.d(0x0)),7,4)'),
    # beqz $t0, 0xc; cfc1 $t0, $fcr31 -- little-endian encoding
    ('mipsel32', b'\x02\x00\x00\x11\x00\xf8\x48\x44', 'LLIL_SET_REG.d(temp1,LLIL_REG.d($t0)); LLIL_INTRINSIC([temp0],moveControlWordFromCoprocessor1,[LLIL_REG.d($fcr31)]); LLIL_SET_REG.d($t0,LLIL_REG.d(temp0)); LLIL_IF(LLIL_CMP_E.d(LLIL_REG.d(temp1),LLIL_CONST.d(0x0)),7,4)'),
    # beqz $t0, 0xc; cfc1 $t0, $fcr31 -- save all 64 old bits despite the word-sized intrinsic result
    ('mips64', b'\x11\x00\x00\x02\x44\x48\xf8\x00', 'LLIL_SET_REG.q(temp1,LLIL_REG.q($t0)); LLIL_INTRINSIC([temp0],moveControlWordFromCoprocessor1,[LLIL_REG.d($fcr31)]); LLIL_SET_REG.q($t0,LLIL_SX.q(LLIL_REG.d(temp0))); LLIL_IF(LLIL_CMP_E.q(LLIL_REG.q(temp1),LLIL_CONST.q(0x0)),7,4)'),
    # bnez $t0, 0xc; cfc2 $t0, 0x1234 -- nonzero predicate and a full-width snapshot
    ('mipsel64', b'\x02\x00\x00\x15\x34\x12\x48\x48', 'LLIL_SET_REG.q(temp1,LLIL_REG.q($t0)); LLIL_INTRINSIC([temp0],moveControlWordFromCoprocessor2,[LLIL_CONST.w(0x1234)]); LLIL_SET_REG.q($t0,LLIL_SX.q(LLIL_REG.d(temp0))); LLIL_IF(LLIL_CMP_NE.q(LLIL_REG.q(temp1),LLIL_CONST.q(0x0)),7,4)'),
    # beqz $t0, 0xc; mfhc0 $t0, $12, 3 -- high-word read also defines a GPR through an intrinsic
    ('mips64', b'\x11\x00\x00\x02\x40\x48\x60\x03', 'LLIL_SET_REG.q(temp1,LLIL_REG.q($t0)); LLIL_INTRINSIC([temp0],moveHighWordFromCoprocessor0,[LLIL_CONST.d(0xC),LLIL_CONST.d(0x3)]); LLIL_SET_REG.q($t0,LLIL_SX.q(LLIL_REG.d(temp0))); LLIL_IF(LLIL_CMP_E.q(LLIL_REG.q(temp1),LLIL_CONST.q(0x0)),7,4)'),
    # beqz $t0, 0xc; mfhc2 $t0, 0x1234 -- preserve the original value before reading COP2
    ('mipsel32', b'\x02\x00\x00\x11\x34\x12\x68\x48', 'LLIL_SET_REG.d(temp1,LLIL_REG.d($t0)); LLIL_INTRINSIC([temp0],moveHighWordFromCoprocessor2,[LLIL_CONST.w(0x1234)]); LLIL_SET_REG.d($t0,LLIL_REG.d(temp0)); LLIL_IF(LLIL_CMP_E.d(LLIL_REG.d(temp1),LLIL_CONST.d(0x0)),7,4)'),
    # beqz $t0, 0xc; rdpgpr $t0, $s1 -- the branch tests the current set, before the shadow-set read
    ('mips32', b'\x11\x00\x00\x02\x41\x51\x40\x00', 'LLIL_SET_REG.d(temp1,LLIL_REG.d($t0)); LLIL_INTRINSIC([$t0],readGPRFromPreviousShadowSet,[LLIL_CONST.d(0x11)]); LLIL_IF(LLIL_CMP_E.d(LLIL_REG.d(temp1),LLIL_CONST.d(0x0)),6,3)'),
    # beqz $t0, 0xc; rdpgpr $t0, $s1 -- little-endian 64-bit shadow-set transfer
    ('mipsel64', b'\x02\x00\x00\x11\x00\x40\x51\x41', 'LLIL_SET_REG.q(temp1,LLIL_REG.q($t0)); LLIL_INTRINSIC([$t0],readGPRFromPreviousShadowSet,[LLIL_CONST.d(0x11)]); LLIL_IF(LLIL_CMP_E.q(LLIL_REG.q(temp1),LLIL_CONST.q(0x0)),6,3)'),
    # beq $t0, $t1, 0xc; cfc1 $t1, $fcr31 -- only the clobbered second branch operand is replaced
    ('mips32', b'\x11\x09\x00\x02\x44\x49\xf8\x00', 'LLIL_SET_REG.d(temp1,LLIL_REG.d($t1)); LLIL_INTRINSIC([temp0],moveControlWordFromCoprocessor1,[LLIL_REG.d($fcr31)]); LLIL_SET_REG.d($t1,LLIL_REG.d(temp0)); LLIL_IF(LLIL_CMP_E.d(LLIL_REG.d($t0),LLIL_REG.d(temp1)),7,4)'),
    # beqz $t0, 0xc; cfc1 $t1, $fcr31 -- an unrelated intrinsic output needs no snapshot
    ('mips32', b'\x11\x00\x00\x02\x44\x49\xf8\x00', 'LLIL_NOP(); LLIL_INTRINSIC([temp0],moveControlWordFromCoprocessor1,[LLIL_REG.d($fcr31)]); LLIL_SET_REG.d($t1,LLIL_REG.d(temp0)); LLIL_IF(LLIL_CMP_E.d(LLIL_REG.d($t0),LLIL_CONST.d(0x0)),7,4)'),
    # beqz $t0, 0xc; ctc1 $t0, $fcr31 -- reading a branch input is not a clobber
    ('mips32', b'\x11\x00\x00\x02\x44\xc8\xf8\x00', 'LLIL_NOP(); LLIL_INTRINSIC([],moveControlWordToCoprocessor1,[LLIL_REG.d($fcr31),LLIL_REG.d($t0)]); LLIL_IF(LLIL_CMP_E.d(LLIL_REG.d($t0),LLIL_CONST.d(0x0)),6,3)'),
    # beqzl $t0, 0xc; cfc1 $t0, $fcr31 -- likely branches evaluate the predicate before the delay slot
    ('mips32', b'\x51\x00\x00\x02\x44\x48\xf8\x00', 'LLIL_IF(LLIL_CMP_E.d(LLIL_REG.d($t0),LLIL_CONST.d(0x0)),1,4); LLIL_INTRINSIC([temp0],moveControlWordFromCoprocessor1,[LLIL_REG.d($fcr31)]); LLIL_SET_REG.d($t0,LLIL_REG.d(temp0)); LLIL_GOTO(5)'),
    # jalr $t0; cfc1 $t0, $fcr31 -- an indirect call also uses its pre-delay-slot target
    ('mips32', b'\x01\x00\xf8\x09\x44\x48\xf8\x00', 'LLIL_SET_REG.d(temp1,LLIL_REG.d($t0)); LLIL_INTRINSIC([temp0],moveControlWordFromCoprocessor1,[LLIL_REG.d($fcr31)]); LLIL_SET_REG.d($t0,LLIL_REG.d(temp0)); LLIL_CALL(LLIL_REG.d(temp1))'),
    # bc1nez $f2, 0xc; sub.ps $f2, $f4, $f6 -- preserve a directly written paired-single destination
    ('mips64', b'\x45\xa2\x00\x02\x46\xc6\x20\x81', 'LLIL_SET_REG.q(temp1,LLIL_REG.q($f2)); LLIL_INTRINSIC([$f2],_sub_ps,[LLIL_REG.q($f4),LLIL_REG.q($f6)]); LLIL_IF(LLIL_TEST_BIT.d(LLIL_REG.d(temp1),LLIL_CONST.b(0x0)),6,3)'),
    # bc1eqz $f2, 0xc; neg.ps $f2, $f4 -- false-polarity FP predicate and little-endian encoding
    ('mipsel64', b'\x02\x00\x22\x45\x87\x20\xc0\x46', 'LLIL_SET_REG.q(temp1,LLIL_REG.q($f2)); LLIL_INTRINSIC([$f2],_neg_ps,[LLIL_REG.q($f4)]); LLIL_IF(LLIL_NOT(LLIL_TEST_BIT.d(LLIL_REG.d(temp1),LLIL_CONST.b(0x0))),6,3)'),
    # bc1nez $f2, 0xc; mov.ps $f2, $f2 -- snapshot rewriting must not replace the delay-slot source
    ('mips64', b'\x45\xa2\x00\x02\x46\xc0\x10\x86', 'LLIL_SET_REG.q(temp1,LLIL_REG.q($f2)); LLIL_INTRINSIC([$f2],_mov_ps,[LLIL_REG.q($f2)]); LLIL_IF(LLIL_TEST_BIT.d(LLIL_REG.d(temp1),LLIL_CONST.b(0x0)),6,3)'),
    # bc1nez $f2, 0xc; msub.ps $f2, $f4, $f6, $f8 -- direct three-input intrinsic
    ('mipsel64', b'\x02\x00\xa2\x45\xae\x30\x88\x4c', 'LLIL_SET_REG.q(temp1,LLIL_REG.q($f2)); LLIL_INTRINSIC([$f2],_msub_ps,[LLIL_REG.q($f4),LLIL_REG.q($f6),LLIL_REG.q($f8)]); LLIL_IF(LLIL_TEST_BIT.d(LLIL_REG.d(temp1),LLIL_CONST.b(0x0)),6,3)'),
    # bc1nez $f2, 0xc; nmadd.ps $f2, $f4, $f6, $f8
    ('mips64', b'\x45\xa2\x00\x02\x4c\x88\x30\xb6', 'LLIL_SET_REG.q(temp1,LLIL_REG.q($f2)); LLIL_INTRINSIC([$f2],_nmadd_ps,[LLIL_REG.q($f4),LLIL_REG.q($f6),LLIL_REG.q($f8)]); LLIL_IF(LLIL_TEST_BIT.d(LLIL_REG.d(temp1),LLIL_CONST.b(0x0)),6,3)'),
    # bc1nez $f2, 0xc; nmsub.ps $f2, $f4, $f6, $f8
    ('mipsel64', b'\x02\x00\xa2\x45\xbe\x30\x88\x4c', 'LLIL_SET_REG.q(temp1,LLIL_REG.q($f2)); LLIL_INTRINSIC([$f2],_nmsub_ps,[LLIL_REG.q($f4),LLIL_REG.q($f6),LLIL_REG.q($f8)]); LLIL_IF(LLIL_TEST_BIT.d(LLIL_REG.d(temp1),LLIL_CONST.b(0x0)),6,3)'),
    # cfc1 $t0, $fcr31 -- read an FPU control word through the CFC1 intrinsic
    ('mips32', b'\x44\x48\xf8\x00', 'LLIL_INTRINSIC([temp0],moveControlWordFromCoprocessor1,[LLIL_REG.d($fcr31)]); LLIL_SET_REG.d($t0,LLIL_REG.d(temp0))'),
    # cfc1 $t1, $fcr0 -- little-endian encoding and a different control register
    ('mipsel32', b'\x00\x00\x49\x44', 'LLIL_INTRINSIC([temp0],moveControlWordFromCoprocessor1,[LLIL_REG.d($fcr0)]); LLIL_SET_REG.d($t1,LLIL_REG.d(temp0))'),
    # cfc1 $t0, $fcr31 -- explicitly sign-extend the word result to the full MIPS64 GPR
    ('mips64', b'\x44\x48\xf8\x00', 'LLIL_INTRINSIC([temp0],moveControlWordFromCoprocessor1,[LLIL_REG.d($fcr31)]); LLIL_SET_REG.q($t0,LLIL_SX.q(LLIL_REG.d(temp0)))'),
    # cfc1 $t1, $fcr0 -- little-endian MIPS64
    ('mipsel64', b'\x00\x00\x49\x44', 'LLIL_INTRINSIC([temp0],moveControlWordFromCoprocessor1,[LLIL_REG.d($fcr0)]); LLIL_SET_REG.q($t1,LLIL_SX.q(LLIL_REG.d(temp0)))'),
    # cfc1 $zero, $fcr31 -- retain the opaque read but discard its result
    ('mips32', b'\x44\x40\xf8\x00', 'LLIL_INTRINSIC([temp0],moveControlWordFromCoprocessor1,[LLIL_REG.d($fcr31)]); LLIL_NOP()'),
    ('mipsel64', b'\x00\xf8\x40\x44', 'LLIL_INTRINSIC([temp0],moveControlWordFromCoprocessor1,[LLIL_REG.d($fcr31)]); LLIL_NOP()'),
    # cfc2 $t0, 0x1234 -- preserve the full implementation-defined selector
    ('mips32', b'\x48\x48\x12\x34', 'LLIL_INTRINSIC([temp0],moveControlWordFromCoprocessor2,[LLIL_CONST.w(0x1234)]); LLIL_SET_REG.d($t0,LLIL_REG.d(temp0))'),
    # cfc2 $t1, 0xabcd -- little-endian encoding of another opaque selector
    ('mipsel32', b'\xcd\xab\x49\x48', 'LLIL_INTRINSIC([temp0],moveControlWordFromCoprocessor2,[LLIL_CONST.w(0xABCD)]); LLIL_SET_REG.d($t1,LLIL_REG.d(temp0))'),
    # cfc2 $t0, 0x1234 -- preserve the selector while sign-extending the word result
    ('mips64', b'\x48\x48\x12\x34', 'LLIL_INTRINSIC([temp0],moveControlWordFromCoprocessor2,[LLIL_CONST.w(0x1234)]); LLIL_SET_REG.q($t0,LLIL_SX.q(LLIL_REG.d(temp0)))'),
    # cfc2 $t1, 0xabcd -- little-endian MIPS64
    ('mipsel64', b'\xcd\xab\x49\x48', 'LLIL_INTRINSIC([temp0],moveControlWordFromCoprocessor2,[LLIL_CONST.w(0xABCD)]); LLIL_SET_REG.q($t1,LLIL_SX.q(LLIL_REG.d(temp0)))'),
    # cfc2 $zero, 0xabcd -- no architectural zero-register definition
    ('mipsel32', b'\xcd\xab\x40\x48', 'LLIL_INTRINSIC([temp0],moveControlWordFromCoprocessor2,[LLIL_CONST.w(0xABCD)]); LLIL_NOP()'),
    ('mips64', b'\x48\x40\xab\xcd', 'LLIL_INTRINSIC([temp0],moveControlWordFromCoprocessor2,[LLIL_CONST.w(0xABCD)]); LLIL_NOP()'),
    # ctc1 $t0, $fcr31 -- write the low GPR word through the CTC1 intrinsic
    ('mips32', b'\x44\xc8\xf8\x00', 'LLIL_INTRINSIC([],moveControlWordToCoprocessor1,[LLIL_REG.d($fcr31),LLIL_REG.d($t0)])'),
    # ctc1 $t1, $fcr0 -- little-endian encoding and a different control register
    ('mipsel32', b'\x00\x00\xc9\x44', 'LLIL_INTRINSIC([],moveControlWordToCoprocessor1,[LLIL_REG.d($fcr0),LLIL_REG.d($t1)])'),
    # ctc1 $t0, $fcr31 -- R5900 writes the modeled control register from the low GPR word
    ('r5900l', b'\x00\xf8\xc8\x44', 'LLIL_SET_REG.d($fcr31,LLIL_REG.d($t0))'),
    # cfc1 $v0, $fcr31 -- R5900 reads that state and sign-extends into the low 64 GPR bits
    ('r5900l', b'\x00\xf8\x42\x44', 'LLIL_SET_REG.q($v0,LLIL_SX.q(LLIL_REG.d($fcr31)))'),
    # cfc1 $v0, $fcr0 -- the implementation/revision register is also a modeled control-register read
    ('r5900l', b'\x00\x00\x42\x44', 'LLIL_SET_REG.q($v0,LLIL_SX.q(LLIL_REG.d($fcr0)))'),
    # ctc1 $zero, $fcr31 -- clear the modeled control register without reading $zero
    ('r5900l', b'\x00\xf8\xc0\x44', 'LLIL_SET_REG.d($fcr31,LLIL_CONST.d(0x0))'),
    # cfc1 $zero, $fcr31 -- discard a transfer to the architectural zero register
    ('r5900l', b'\x00\xf8\x40\x44', 'LLIL_NOP()'),
    # ctc1 $t0, $fcr31; cfc1 $v0, $fcr31 -- reproduce the R5900 write/read regression
    ('r5900l', b'\x00\xf8\xc8\x44\x00\xf8\x42\x44', 'LLIL_SET_REG.d($fcr31,LLIL_REG.d($t0)); LLIL_SET_REG.q($v0,LLIL_SX.q(LLIL_REG.d($fcr31)))'),
    # ctc1 $t0, $fcr31; cfc1 $t0, $fcr31 -- source and destination GPR may alias
    ('r5900l', b'\x00\xf8\xc8\x44\x00\xf8\x48\x44', 'LLIL_SET_REG.d($fcr31,LLIL_REG.d($t0)); LLIL_SET_REG.q($t0,LLIL_SX.q(LLIL_REG.d($fcr31)))'),
    # beqz $t0, 0xc; cfc1 $t0, $fcr31 -- the restored direct read preserves the old branch input
    ('r5900l', b'\x02\x00\x00\x11\x00\xf8\x48\x44', 'LLIL_SET_REG.q(temp1,LLIL_REG.q($t0)); LLIL_SET_REG.q($t0,LLIL_SX.q(LLIL_REG.d($fcr31))); LLIL_IF(LLIL_CMP_E.q(LLIL_REG.q(temp1),LLIL_CONST.q(0x0)),6,3)'),
    # beqz $t0, 0xc; ctc1 $t0, $fcr31 -- writing an FCR must not clobber the source GPR
    ('r5900l', b'\x02\x00\x00\x11\x00\xf8\xc8\x44', 'LLIL_NOP(); LLIL_SET_REG.d($fcr31,LLIL_REG.d($t0)); LLIL_IF(LLIL_CMP_E.q(LLIL_REG.q($t0),LLIL_CONST.q(0x0)),6,3)'),
    # ctc2 $t0, 0x1234 -- preserve the full implementation-defined selector
    ('mips32', b'\x48\xc8\x12\x34', 'LLIL_INTRINSIC([],moveControlWordToCoprocessor2,[LLIL_CONST.w(0x1234),LLIL_REG.d($t0)])'),
    # ctc2 $t1, 0xabcd -- little-endian encoding and low-word source transfer
    ('mipsel32', b'\xcd\xab\xc9\x48', 'LLIL_INTRINSIC([],moveControlWordToCoprocessor2,[LLIL_CONST.w(0xABCD),LLIL_REG.d($t1)])'),
    # cop2 0x1234567 -- pass all 25 implementation-defined cofun bits to the intrinsic
    ('mips32', b'\x4b\x23\x45\x67', 'LLIL_INTRINSIC([],coprocessor2Operation,[LLIL_CONST.d(0x1234567)])'),
    # cop2 0x1abcdef -- little-endian encoding with the high cofun bit set
    ('mipsel32', b'\xef\xcd\xab\x4b', 'LLIL_INTRINSIC([],coprocessor2Operation,[LLIL_CONST.d(0x1ABCDEF)])'),
    # jalx 0; nop -- delayed call into the alternate ISA mode, targeting within the view
    ('mips32', b'\x74\x00\x00\x00\x00\x00\x00\x00', 'LLIL_NOP(); LLIL_NOP(); LLIL_CALL(LLIL_CONST.d(0x0))'),
    # jalx 0; nop -- little-endian encoding
    ('mipsel32', b'\x00\x00\x00\x74\x00\x00\x00\x00', 'LLIL_NOP(); LLIL_NOP(); LLIL_CALL(LLIL_CONST.d(0x0))'),
    # mfhc0 $t0, $12, 3 -- read the high word of a selected COP0 register
    ('mips32', b'\x40\x48\x60\x03', 'LLIL_INTRINSIC([temp0],moveHighWordFromCoprocessor0,[LLIL_CONST.d(0xC),LLIL_CONST.d(0x3)]); LLIL_SET_REG.d($t0,LLIL_REG.d(temp0))'),
    # mfhc0 $t1, $5, 1 -- little-endian encoding with a different selector
    ('mipsel32', b'\x01\x28\x49\x40', 'LLIL_INTRINSIC([temp0],moveHighWordFromCoprocessor0,[LLIL_CONST.d(0x5),LLIL_CONST.d(0x1)]); LLIL_SET_REG.d($t1,LLIL_REG.d(temp0))'),
    # mfhc0 $t0, $12, 3 -- sign-extend the transferred high word to a full MIPS64 GPR
    ('mips64', b'\x40\x48\x60\x03', 'LLIL_INTRINSIC([temp0],moveHighWordFromCoprocessor0,[LLIL_CONST.d(0xC),LLIL_CONST.d(0x3)]); LLIL_SET_REG.q($t0,LLIL_SX.q(LLIL_REG.d(temp0)))'),
    # mfhc0 $t1, $5, 1 -- little-endian MIPS64
    ('mipsel64', b'\x01\x28\x49\x40', 'LLIL_INTRINSIC([temp0],moveHighWordFromCoprocessor0,[LLIL_CONST.d(0x5),LLIL_CONST.d(0x1)]); LLIL_SET_REG.q($t1,LLIL_SX.q(LLIL_REG.d(temp0)))'),
    # mfhc0 $zero, $12, 3 -- retain both selectors and discard the result
    ('mips32', b'\x40\x40\x60\x03', 'LLIL_INTRINSIC([temp0],moveHighWordFromCoprocessor0,[LLIL_CONST.d(0xC),LLIL_CONST.d(0x3)]); LLIL_NOP()'),
    ('mipsel64', b'\x03\x60\x40\x40', 'LLIL_INTRINSIC([temp0],moveHighWordFromCoprocessor0,[LLIL_CONST.d(0xC),LLIL_CONST.d(0x3)]); LLIL_NOP()'),
    # mfhc2 $t0, 0x1234 -- preserve the implementation-defined COP2 selector
    ('mips32', b'\x48\x68\x12\x34', 'LLIL_INTRINSIC([temp0],moveHighWordFromCoprocessor2,[LLIL_CONST.w(0x1234)]); LLIL_SET_REG.d($t0,LLIL_REG.d(temp0))'),
    # mfhc2 $t1, 0xabcd -- little-endian encoding of another opaque selector
    ('mipsel32', b'\xcd\xab\x69\x48', 'LLIL_INTRINSIC([temp0],moveHighWordFromCoprocessor2,[LLIL_CONST.w(0xABCD)]); LLIL_SET_REG.d($t1,LLIL_REG.d(temp0))'),
    # mfhc2 $t0, 0x1234 -- sign-extend the transferred word rather than zero-extending it
    ('mips64', b'\x48\x68\x12\x34', 'LLIL_INTRINSIC([temp0],moveHighWordFromCoprocessor2,[LLIL_CONST.w(0x1234)]); LLIL_SET_REG.q($t0,LLIL_SX.q(LLIL_REG.d(temp0)))'),
    # mfhc2 $t1, 0xabcd -- little-endian MIPS64
    ('mipsel64', b'\xcd\xab\x69\x48', 'LLIL_INTRINSIC([temp0],moveHighWordFromCoprocessor2,[LLIL_CONST.w(0xABCD)]); LLIL_SET_REG.q($t1,LLIL_SX.q(LLIL_REG.d(temp0)))'),
    # mfhc2 $zero, 0xabcd -- preserve the read without writing $zero
    ('mipsel32', b'\xcd\xab\x60\x48', 'LLIL_INTRINSIC([temp0],moveHighWordFromCoprocessor2,[LLIL_CONST.w(0xABCD)]); LLIL_NOP()'),
    ('mips64', b'\x48\x60\xab\xcd', 'LLIL_INTRINSIC([temp0],moveHighWordFromCoprocessor2,[LLIL_CONST.w(0xABCD)]); LLIL_NOP()'),
    # mthc0 $t0, $12, 3 -- write a GPR word to the selected COP0 high half
    ('mips32', b'\x40\xc8\x60\x03', 'LLIL_INTRINSIC([],moveHighWordToCoprocessor0,[LLIL_CONST.d(0xC),LLIL_CONST.d(0x3),LLIL_REG.d($t0)])'),
    # mthc0 $t1, $5, 1 -- little-endian encoding with a different selector
    ('mipsel32', b'\x01\x28\xc9\x40', 'LLIL_INTRINSIC([],moveHighWordToCoprocessor0,[LLIL_CONST.d(0x5),LLIL_CONST.d(0x1),LLIL_REG.d($t1)])'),
    # mthc2 $t0, 0x1234 -- preserve the implementation-defined COP2 selector
    ('mips32', b'\x48\xe8\x12\x34', 'LLIL_INTRINSIC([],moveHighWordToCoprocessor2,[LLIL_CONST.w(0x1234),LLIL_REG.d($t0)])'),
    # mthc2 $t1, 0xabcd -- little-endian encoding of another opaque selector
    ('mipsel32', b'\xcd\xab\xe9\x48', 'LLIL_INTRINSIC([],moveHighWordToCoprocessor2,[LLIL_CONST.w(0xABCD),LLIL_REG.d($t1)])'),
    # mfhc1 $t0, $f20 -- little-endian FR=0 reads the paired odd FPR
    ('mipsel32', b'\x00\xa0\x68\x44', 'LLIL_SET_REG.d($t0,LLIL_REG.d($f21))'),
    # mfhc1 $t0, $f20 -- little-endian FR=1 reads and sign-extends bits 63:32
    ('mipsel64', b'\x00\xa0\x68\x44', 'LLIL_SET_REG.q($t0,LLIL_SX.q(LLIL_LOW_PART.d(LLIL_LSR.q(LLIL_REG.q($f20),LLIL_CONST.b(0x20)))))'),
    # prefx 6, $t1($t0) -- combine the base and index registers for the prefetch address
    ('mips32', b'\x4d\x09\x30\x0f', 'LLIL_INTRINSIC([],_prefetch,[LLIL_CONST.b(0x6),LLIL_ADD.d(LLIL_REG.d($t0),LLIL_REG.d($t1))])'),
    # prefx 25, $s1($s0) -- little-endian MIPS64 uses a 64-bit effective address
    ('mipsel64', b'\x0f\xc8\x11\x4e', 'LLIL_INTRINSIC([],_prefetch,[LLIL_CONST.b(0x19),LLIL_ADD.q(LLIL_REG.q($s0),LLIL_REG.q($s1))])'),
    # rdpgpr $t0, $s1 -- read shadow GPR 17 into the current 32-bit destination
    ('mips32', b'\x41\x51\x40\x00', 'LLIL_INTRINSIC([$t0],readGPRFromPreviousShadowSet,[LLIL_CONST.d(0x11)])'),
    # rdpgpr $a1, $ra -- little-endian MIPS64 returns the full GPR width
    ('mipsel64', b'\x00\x28\x5f\x41', 'LLIL_INTRINSIC([$a1],readGPRFromPreviousShadowSet,[LLIL_CONST.d(0x1F)])'),
    # wrpgpr $t0, $s1 -- write the current 32-bit GPR value to shadow GPR 8
    ('mips32', b'\x41\xd1\x40\x00', 'LLIL_INTRINSIC([],writeGPRToPreviousShadowSet,[LLIL_CONST.d(0x8),LLIL_REG.d($s1)])'),
    # wrpgpr $a1, $ra -- little-endian MIPS64 writes the full current GPR value
    ('mipsel64', b'\x00\x28\xdf\x41', 'LLIL_INTRINSIC([],writeGPRToPreviousShadowSet,[LLIL_CONST.d(0x5),LLIL_REG.q($ra)])'),
    # rdpgpr $t0, $zero -- every shadow set has a hardwired zero register
    ('mips32', b'\x41\x40\x40\x00', 'LLIL_SET_REG.d($t0,LLIL_CONST.d(0x0))'),
    ('mipsel32', b'\x00\x40\x40\x41', 'LLIL_SET_REG.d($t0,LLIL_CONST.d(0x0))'),
    # The complete MIPS64 GPR is cleared, including its high word.
    ('mips64', b'\x41\x40\x40\x00', 'LLIL_SET_REG.q($t0,LLIL_CONST.q(0x0))'),
    ('mipsel64', b'\x00\x40\x40\x41', 'LLIL_SET_REG.q($t0,LLIL_CONST.q(0x0))'),
    # rdpgpr $zero, $t0 -- discard the read without defining the current $zero register
    ('mips32', b'\x41\x48\x00\x00', 'LLIL_NOP()'),
    # rdpgpr $zero, $ra -- the final shadow register is also ignored for a zero destination
    ('mipsel64', b'\x00\x00\x5f\x41', 'LLIL_NOP()'),
    # rdpgpr $zero, $zero -- neither a register definition nor an opaque read is needed
    ('mips32', b'\x41\x40\x00\x00', 'LLIL_NOP()'),
    # wrpgpr $zero, $t0 -- writes to zero in the previous shadow set are discarded
    ('mips32', b'\x41\xc8\x00\x00', 'LLIL_NOP()'),
    ('mipsel32', b'\x00\x00\xc8\x41', 'LLIL_NOP()'),
    ('mips64', b'\x41\xc8\x00\x00', 'LLIL_NOP()'),
    ('mipsel64', b'\x00\x00\xc8\x41', 'LLIL_NOP()'),
    # wrpgpr $zero, $zero -- also discarded when both operands are zero
    ('mipsel64', b'\x00\x00\xc0\x41', 'LLIL_NOP()'),
    # wrpgpr $t0, $zero -- a zero source still writes a nonzero shadow-register destination
    ('mips32', b'\x41\xc0\x40\x00', 'LLIL_INTRINSIC([],writeGPRToPreviousShadowSet,[LLIL_CONST.d(0x8),LLIL_CONST.d(0x0)])'),
    # wrpgpr $ra, $zero -- preserve the full-width zero write and highest register selector
    ('mipsel64', b'\x00\xf8\xc0\x41', 'LLIL_INTRINSIC([],writeGPRToPreviousShadowSet,[LLIL_CONST.d(0x1F),LLIL_CONST.q(0x0)])'),
    # bnez $t0, 0xc; rdpgpr $t0, $zero -- clearing the GPR must not change the branch predicate
    ('mips32', b'\x15\x00\x00\x02\x41\x40\x40\x00', 'LLIL_SET_REG.d(temp1,LLIL_REG.d($t0)); LLIL_SET_REG.d($t0,LLIL_CONST.d(0x0)); LLIL_IF(LLIL_CMP_NE.d(LLIL_REG.d(temp1),LLIL_CONST.d(0x0)),6,3)'),
    ('mipsel64', b'\x02\x00\x00\x15\x00\x40\x40\x41', 'LLIL_SET_REG.q(temp1,LLIL_REG.q($t0)); LLIL_SET_REG.q($t0,LLIL_CONST.q(0x0)); LLIL_IF(LLIL_CMP_NE.q(LLIL_REG.q(temp1),LLIL_CONST.q(0x0)),6,3)'),
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
    # madd.s $f0, $f0, $f12, $f12 -- reported little-endian encoding
    ('mipsel32', b'\x20\x60\x0c\x4c', 'LLIL_SET_REG.d($f0,LLIL_FADD.d(LLIL_FMUL.d(LLIL_REG.d($f12),LLIL_REG.d($f12)),LLIL_REG.d($f0)))'),
    # madd.s $f2, $f4, $f6, $f8 -- MIPS32 Release 6.06 pp. 256-257: round(fs*ft), then add fr
    ('mips32', b'\x4c\x88\x30\xa0', 'LLIL_SET_REG.d($f2,LLIL_FADD.d(LLIL_FMUL.d(LLIL_REG.d($f6),LLIL_REG.d($f8)),LLIL_REG.d($f4)))'),
    # madd.d $f2, $f4, $f6, $f8 -- FR=0 doubles use even/odd FPR pairs
    ('mipsel32', b'\xa1\x30\x88\x4c', 'LLIL_SET_REG_SPLIT.d($f3,$f2,LLIL_FADD.q(LLIL_FMUL.q(LLIL_REG_SPLIT.d($f7,$f6),LLIL_REG_SPLIT.d($f9,$f8)),LLIL_REG_SPLIT.d($f5,$f4)))'),
    # madd.d $f3, $f4, $f6, $f8 -- odd FR=0 operands are architecturally unpredictable
    ('mipsel32', b'\xe1\x30\x88\x4c', 'LLIL_UNKNOWN()'),
    # madd.d $f3, $f4, $f6, $f8 -- odd FPRs are valid in the modeled FR=1 register file
    ('mipsel64', b'\xe1\x30\x88\x4c', 'LLIL_SET_REG.q($f3,LLIL_FADD.q(LLIL_FMUL.q(LLIL_REG.q($f6),LLIL_REG.q($f8)),LLIL_REG.q($f4)))'),
    # madd.ps $f2, $f4, $f6, $f8 -- paired-single operates independently on both FR=1 lanes
    ('mipsel64', b'\xa6\x30\x88\x4c', 'LLIL_INTRINSIC([$f2],_madd_ps,[LLIL_REG.q($f4),LLIL_REG.q($f6),LLIL_REG.q($f8)])'),
    # madd.ps $f2, $f4, $f6, $f8 -- paired-single is unpredictable with modeled 32-bit FPRs
    ('mipsel32', b'\xa6\x30\x88\x4c', 'LLIL_UNKNOWN()'),
    # add.ps $f2, $f4, $f6 -- MIPS32 Release 6.06 p. 34: two independent single-precision sums
    ('mips64', b'\x46\xc6\x20\x80', 'LLIL_INTRINSIC([temp0],_add_ps,[LLIL_REG.q($f4),LLIL_REG.q($f6)]); LLIL_SET_REG.q($f2,LLIL_REG.q(temp0))'),
    # add.ps $f2, $f4, $f6 -- little-endian encoding has the same packed operands
    ('mipsel64', b'\x80\x20\xc6\x46', 'LLIL_INTRINSIC([temp0],_add_ps,[LLIL_REG.q($f4),LLIL_REG.q($f6)]); LLIL_SET_REG.q($f2,LLIL_REG.q(temp0))'),
    # add.ps $f31, $f3, $f31 -- odd FPRs are valid in FR=1, including an aliased ft
    ('mipsel64', b'\xc0\x1f\xdf\x46', 'LLIL_INTRINSIC([temp0],_add_ps,[LLIL_REG.q($f3),LLIL_REG.q($f31)]); LLIL_SET_REG.q($f31,LLIL_REG.q(temp0))'),
    # add.ps $f4, $f4, $f6 -- read both source lanes before overwriting fs
    ('mips64', b'\x46\xc6\x21\x00', 'LLIL_INTRINSIC([temp0],_add_ps,[LLIL_REG.q($f4),LLIL_REG.q($f6)]); LLIL_SET_REG.q($f4,LLIL_REG.q(temp0))'),
    # add.ps $f2, $f4, $f6 -- even register numbers do not make PS valid in FR=0
    ('mips32', b'\x46\xc6\x20\x80', 'LLIL_UNKNOWN()'),
    # add.ps $f2, $f4, $f6 -- little-endian FR=0 is also unpredictable
    ('mipsel32', b'\x80\x20\xc6\x46', 'LLIL_UNKNOWN()'),
    # bc1nez $f2, 0xc; add.ps $f2, $f4, $f6 -- retain the pre-delay-slot branch value
    ('mips64', b'\x45\xa2\x00\x02\x46\xc6\x20\x80', 'LLIL_SET_REG.q(temp1,LLIL_REG.q($f2)); LLIL_INTRINSIC([temp0],_add_ps,[LLIL_REG.q($f4),LLIL_REG.q($f6)]); LLIL_SET_REG.q($f2,LLIL_REG.q(temp0)); LLIL_IF(LLIL_TEST_BIT.d(LLIL_REG.d(temp1),LLIL_CONST.b(0x0)),7,4)'),
    # mul.ps $f2, $f4, $f6 -- MIPS32 Release 6.06 p. 302: two independent single-precision products
    ('mips64', b'\x46\xc6\x20\x82', 'LLIL_INTRINSIC([temp0],_mul_ps,[LLIL_REG.q($f4),LLIL_REG.q($f6)]); LLIL_SET_REG.q($f2,LLIL_REG.q(temp0))'),
    # mul.ps $f2, $f4, $f6 -- little-endian encoding
    ('mipsel64', b'\x82\x20\xc6\x46', 'LLIL_INTRINSIC([temp0],_mul_ps,[LLIL_REG.q($f4),LLIL_REG.q($f6)]); LLIL_SET_REG.q($f2,LLIL_REG.q(temp0))'),
    # mul.ps $f31, $f3, $f31 -- odd FPRs and destination/ft aliasing are valid in FR=1
    ('mipsel64', b'\xc2\x1f\xdf\x46', 'LLIL_INTRINSIC([temp0],_mul_ps,[LLIL_REG.q($f3),LLIL_REG.q($f31)]); LLIL_SET_REG.q($f31,LLIL_REG.q(temp0))'),
    # mul.ps $f4, $f4, $f6 -- destination/fs aliasing preserves both original source lanes
    ('mips64', b'\x46\xc6\x21\x02', 'LLIL_INTRINSIC([temp0],_mul_ps,[LLIL_REG.q($f4),LLIL_REG.q($f6)]); LLIL_SET_REG.q($f4,LLIL_REG.q(temp0))'),
    # mul.ps $f2, $f4, $f6 -- paired-single is unpredictable in FR=0
    ('mips32', b'\x46\xc6\x20\x82', 'LLIL_UNKNOWN()'),
    # mul.ps $f2, $f4, $f6 -- little-endian FR=0 is also unpredictable
    ('mipsel32', b'\x82\x20\xc6\x46', 'LLIL_UNKNOWN()'),
    # bc1nez $f2, 0xc; mul.ps $f2, $f4, $f6 -- the result temporary must not replace the branch snapshot
    ('mipsel64', b'\x02\x00\xa2\x45\x82\x20\xc6\x46', 'LLIL_SET_REG.q(temp1,LLIL_REG.q($f2)); LLIL_INTRINSIC([temp0],_mul_ps,[LLIL_REG.q($f4),LLIL_REG.q($f6)]); LLIL_SET_REG.q($f2,LLIL_REG.q(temp0)); LLIL_IF(LLIL_TEST_BIT.d(LLIL_REG.d(temp1),LLIL_CONST.b(0x0)),7,4)'),
    # sub.s $f2, $f4, $f6 -- scalar subtraction is already representable directly
    ('mips32', b'\x46\x06\x20\x81', 'LLIL_SET_REG.d($f2,LLIL_FSUB.d(LLIL_REG.d($f4),LLIL_REG.d($f6)))'),
    # sub.d $f2, $f4, $f6 -- FR=0 doubles use even/odd FPR pairs
    ('mipsel32', b'\x81\x20\x26\x46', 'LLIL_SET_REG_SPLIT.d($f3,$f2,LLIL_FSUB.q(LLIL_REG_SPLIT.d($f5,$f4),LLIL_REG_SPLIT.d($f7,$f6)))'),
    # sub.d $f3, $f4, $f6 -- odd FR=0 operands are architecturally unpredictable
    ('mips32', b'\x46\x26\x20\xc1', 'LLIL_UNKNOWN()'),
    # sub.d $f2, $f4, $f6 -- FR=1 uses directly modeled 64-bit FPRs
    ('mipsel64', b'\x81\x20\x26\x46', 'LLIL_SET_REG.q($f2,LLIL_FSUB.q(LLIL_REG.q($f4),LLIL_REG.q($f6)))'),
    # sub.ps $f2, $f4, $f6 -- paired lanes are modeled by an intrinsic
    ('mipsel64', b'\x81\x20\xc6\x46', 'LLIL_INTRINSIC([$f2],_sub_ps,[LLIL_REG.q($f4),LLIL_REG.q($f6)])'),
    # sub.ps $f2, $f4, $f6 -- paired-single is unpredictable with modeled 32-bit FPRs
    ('mips32', b'\x46\xc6\x20\x81', 'LLIL_UNKNOWN()'),
    # msub.s $f2, $f4, $f6, $f8 -- round(fs*ft), then subtract fr
    ('mips32', b'\x4c\x88\x30\xa8', 'LLIL_SET_REG.d($f2,LLIL_FSUB.d(LLIL_FMUL.d(LLIL_REG.d($f6),LLIL_REG.d($f8)),LLIL_REG.d($f4)))'),
    # msub.d $f2, $f4, $f6, $f8 -- FR=0 doubles use even/odd FPR pairs
    ('mipsel32', b'\xa9\x30\x88\x4c', 'LLIL_SET_REG_SPLIT.d($f3,$f2,LLIL_FSUB.q(LLIL_FMUL.q(LLIL_REG_SPLIT.d($f7,$f6),LLIL_REG_SPLIT.d($f9,$f8)),LLIL_REG_SPLIT.d($f5,$f4)))'),
    # msub.d $f3, $f4, $f6, $f8 -- odd FR=0 operands are architecturally unpredictable
    ('mipsel32', b'\xe9\x30\x88\x4c', 'LLIL_UNKNOWN()'),
    # msub.d $f3, $f4, $f6, $f8 -- odd FPRs are valid in the modeled FR=1 register file
    ('mipsel64', b'\xe9\x30\x88\x4c', 'LLIL_SET_REG.q($f3,LLIL_FSUB.q(LLIL_FMUL.q(LLIL_REG.q($f6),LLIL_REG.q($f8)),LLIL_REG.q($f4)))'),
    # msub.ps $f2, $f4, $f6, $f8 -- packed lanes are modeled by an intrinsic
    ('mipsel64', b'\xae\x30\x88\x4c', 'LLIL_INTRINSIC([$f2],_msub_ps,[LLIL_REG.q($f4),LLIL_REG.q($f6),LLIL_REG.q($f8)])'),
    # msub.ps $f2, $f4, $f6, $f8 -- paired-single is unpredictable with modeled 32-bit FPRs
    ('mipsel32', b'\xae\x30\x88\x4c', 'LLIL_UNKNOWN()'),
    # neg.s $f2, $f4 -- negate a single-precision FPR value
    ('mips32', b'\x46\x00\x20\x87', 'LLIL_SET_REG.d($f2,LLIL_FNEG.d(LLIL_REG.d($f4)))'),
    # neg.d $f2, $f4 -- FR=0 doubles use even/odd FPR pairs
    ('mipsel32', b'\x87\x20\x20\x46', 'LLIL_SET_REG_SPLIT.d($f3,$f2,LLIL_FNEG.q(LLIL_REG_SPLIT.d($f5,$f4)))'),
    # neg.d $f3, $f4 -- odd FR=0 destinations are architecturally unpredictable
    ('mips32', b'\x46\x20\x20\xc7', 'LLIL_UNKNOWN()'),
    # neg.d $f3, $f5 -- odd FPRs are valid in the modeled FR=1 register file
    ('mipsel64', b'\xc7\x28\x20\x46', 'LLIL_SET_REG.q($f3,LLIL_FNEG.q(LLIL_REG.q($f5)))'),
    # neg.ps $f2, $f4 -- packed lanes are modeled by an intrinsic
    ('mipsel64', b'\x87\x20\xc0\x46', 'LLIL_INTRINSIC([$f2],_neg_ps,[LLIL_REG.q($f4)])'),
    # neg.ps $f2, $f4 -- paired-single is unpredictable with modeled 32-bit FPRs
    ('mips32', b'\x46\xc0\x20\x87', 'LLIL_UNKNOWN()'),
    # abs.ps $f2, $f4 -- MIPS32 Release 6.06 p. 32: independent absolute values, not a double-precision ABS
    ('mips64', b'\x46\xc0\x20\x85', 'LLIL_INTRINSIC([temp0],_abs_ps,[LLIL_REG.q($f4)]); LLIL_SET_REG.q($f2,LLIL_REG.q(temp0))'),
    # abs.ps $f2, $f4 -- little-endian encoding
    ('mipsel64', b'\x85\x20\xc0\x46', 'LLIL_INTRINSIC([temp0],_abs_ps,[LLIL_REG.q($f4)]); LLIL_SET_REG.q($f2,LLIL_REG.q(temp0))'),
    # abs.ps $f31, $f3 -- odd FPRs, including the final register, are valid in FR=1
    ('mips64', b'\x46\xc0\x1f\xc5', 'LLIL_INTRINSIC([temp0],_abs_ps,[LLIL_REG.q($f3)]); LLIL_SET_REG.q($f31,LLIL_REG.q(temp0))'),
    # abs.ps $f31, $f31 -- in-place operation reads both original lanes
    ('mipsel64', b'\xc5\xff\xc0\x46', 'LLIL_INTRINSIC([temp0],_abs_ps,[LLIL_REG.q($f31)]); LLIL_SET_REG.q($f31,LLIL_REG.q(temp0))'),
    # abs.ps $f2, $f4 -- paired-single is unpredictable in FR=0
    ('mips32', b'\x46\xc0\x20\x85', 'LLIL_UNKNOWN()'),
    # abs.ps $f2, $f4 -- little-endian FR=0 is also unpredictable
    ('mipsel32', b'\x85\x20\xc0\x46', 'LLIL_UNKNOWN()'),
    # bc1nez $f2, 0xc; abs.ps $f2, $f4 -- retain the original branch value across the intrinsic
    ('mipsel64', b'\x02\x00\xa2\x45\x85\x20\xc0\x46', 'LLIL_SET_REG.q(temp1,LLIL_REG.q($f2)); LLIL_INTRINSIC([temp0],_abs_ps,[LLIL_REG.q($f4)]); LLIL_SET_REG.q($f2,LLIL_REG.q(temp0)); LLIL_IF(LLIL_TEST_BIT.d(LLIL_REG.d(temp1),LLIL_CONST.b(0x0)),7,4)'),
    # nmadd.s $f2, $f4, $f6, $f8 -- negate the rounded multiply-plus-add result
    ('mips32', b'\x4c\x88\x30\xb0', 'LLIL_SET_REG.d($f2,LLIL_FNEG.d(LLIL_FADD.d(LLIL_FMUL.d(LLIL_REG.d($f6),LLIL_REG.d($f8)),LLIL_REG.d($f4))))'),
    # nmadd.d $f2, $f4, $f6, $f8 -- FR=0 doubles use even/odd FPR pairs
    ('mipsel32', b'\xb1\x30\x88\x4c', 'LLIL_SET_REG_SPLIT.d($f3,$f2,LLIL_FNEG.q(LLIL_FADD.q(LLIL_FMUL.q(LLIL_REG_SPLIT.d($f7,$f6),LLIL_REG_SPLIT.d($f9,$f8)),LLIL_REG_SPLIT.d($f5,$f4))))'),
    # nmadd.d $f3, $f4, $f6, $f8 -- odd FR=0 destinations are architecturally unpredictable
    ('mipsel32', b'\xf1\x30\x88\x4c', 'LLIL_UNKNOWN()'),
    # nmadd.d $f3, $f4, $f6, $f8 -- odd FPRs are valid in the modeled FR=1 register file
    ('mipsel64', b'\xf1\x30\x88\x4c', 'LLIL_SET_REG.q($f3,LLIL_FNEG.q(LLIL_FADD.q(LLIL_FMUL.q(LLIL_REG.q($f6),LLIL_REG.q($f8)),LLIL_REG.q($f4))))'),
    # nmadd.ps $f2, $f4, $f6, $f8 -- packed lanes are modeled by an intrinsic
    ('mipsel64', b'\xb6\x30\x88\x4c', 'LLIL_INTRINSIC([$f2],_nmadd_ps,[LLIL_REG.q($f4),LLIL_REG.q($f6),LLIL_REG.q($f8)])'),
    # nmadd.ps $f2, $f4, $f6, $f8 -- paired-single is unpredictable with modeled 32-bit FPRs
    ('mipsel32', b'\xb6\x30\x88\x4c', 'LLIL_UNKNOWN()'),
    # nmsub.s $f2, $f4, $f6, $f8 -- negate the rounded multiply-minus-subtract result
    ('mips32', b'\x4c\x88\x30\xb8', 'LLIL_SET_REG.d($f2,LLIL_FNEG.d(LLIL_FSUB.d(LLIL_FMUL.d(LLIL_REG.d($f6),LLIL_REG.d($f8)),LLIL_REG.d($f4))))'),
    # nmsub.d $f2, $f4, $f6, $f8 -- FR=0 doubles use even/odd FPR pairs
    ('mipsel32', b'\xb9\x30\x88\x4c', 'LLIL_SET_REG_SPLIT.d($f3,$f2,LLIL_FNEG.q(LLIL_FSUB.q(LLIL_FMUL.q(LLIL_REG_SPLIT.d($f7,$f6),LLIL_REG_SPLIT.d($f9,$f8)),LLIL_REG_SPLIT.d($f5,$f4))))'),
    # nmsub.d $f3, $f4, $f6, $f8 -- odd FR=0 destinations are architecturally unpredictable
    ('mipsel32', b'\xf9\x30\x88\x4c', 'LLIL_UNKNOWN()'),
    # nmsub.d $f3, $f4, $f6, $f8 -- odd FPRs are valid in the modeled FR=1 register file
    ('mipsel64', b'\xf9\x30\x88\x4c', 'LLIL_SET_REG.q($f3,LLIL_FNEG.q(LLIL_FSUB.q(LLIL_FMUL.q(LLIL_REG.q($f6),LLIL_REG.q($f8)),LLIL_REG.q($f4))))'),
    # nmsub.ps $f2, $f4, $f6, $f8 -- packed lanes are modeled by an intrinsic
    ('mipsel64', b'\xbe\x30\x88\x4c', 'LLIL_INTRINSIC([$f2],_nmsub_ps,[LLIL_REG.q($f4),LLIL_REG.q($f6),LLIL_REG.q($f8)])'),
    # nmsub.ps $f2, $f4, $f6, $f8 -- paired-single is unpredictable with modeled 32-bit FPRs
    ('mipsel32', b'\xbe\x30\x88\x4c', 'LLIL_UNKNOWN()'),
    # mov.s $f2, $f4 -- single-precision transfer between modeled 32-bit FPRs
    ('mips32', b'\x46\x00\x20\x86', 'LLIL_SET_REG.d($f2,LLIL_REG.d($f4))'),
    # mov.s $f2, $f4 -- only the low word is transferred with modeled 64-bit FPRs
    ('mipsel64', b'\x86\x20\x00\x46', 'LLIL_SET_REG.d($f2,LLIL_REG.d($f4))'),
    # mov.d $f2, $f4 -- FR=0 doubles use even/odd FPR pairs
    ('mipsel32', b'\x86\x20\x20\x46', 'LLIL_SET_REG_SPLIT.d($f3,$f2,LLIL_REG_SPLIT.d($f5,$f4))'),
    # mov.d $f3, $f4 -- odd FR=0 pair roots are architecturally unpredictable
    ('mips32', b'\x46\x20\x20\xc6', 'LLIL_UNKNOWN()'),
    # mov.d $f3, $f5 -- odd FPRs are valid in the modeled FR=1 register file
    ('mips64', b'\x46\x20\x28\xc6', 'LLIL_SET_REG.q($f3,LLIL_REG.q($f5))'),
    # mov.ps $f2, $f4 -- paired-single transfer through the packed intrinsic
    ('mipsel64', b'\x86\x20\xc0\x46', 'LLIL_INTRINSIC([$f2],_mov_ps,[LLIL_REG.q($f4)])'),
    # mov.ps $f2, $f4 -- paired-single is unpredictable with modeled 32-bit FPRs
    ('mips32', b'\x46\xc0\x20\x86', 'LLIL_UNKNOWN()'),
    # movt.s $f0, $f1, $fcc0 -- MIPS32 Release 6.06 pp. 282-283
    ('mipsel32', b'\x11\x08\x01\x46', 'LLIL_IF(LLIL_FLAG($fcc0),1,3); LLIL_SET_REG.d($f0,LLIL_REG.d($f1)); LLIL_GOTO(3)'),
    # movf.s $f0, $f12, $fcc0 -- MIPS32 Release 6.06 pp. 277-278
    ('mipsel32', b'\x11\x60\x00\x46', 'LLIL_IF(LLIL_NOT(LLIL_FLAG($fcc0)),1,3); LLIL_SET_REG.d($f0,LLIL_REG.d($f12)); LLIL_GOTO(3)'),
    # movt.s $f0, $f1, $fcc0 -- big-endian encoding
    ('mips32', b'\x46\x01\x08\x11', 'LLIL_IF(LLIL_FLAG($fcc0),1,3); LLIL_SET_REG.d($f0,LLIL_REG.d($f1)); LLIL_GOTO(3)'),
    # movt.s $f0, $f1, $fcc3 -- the encoded condition-code selector is honored
    ('mipsel32', b'\x11\x08\x0d\x46', 'LLIL_IF(LLIL_FLAG($fcc3),1,3); LLIL_SET_REG.d($f0,LLIL_REG.d($f1)); LLIL_GOTO(3)'),
    # movf.d $f2, $f4, $fcc0 -- FR=0 doubles move an even/odd FPR pair
    ('mipsel32', b'\x91\x20\x20\x46', 'LLIL_IF(LLIL_NOT(LLIL_FLAG($fcc0)),1,3); LLIL_SET_REG_SPLIT.d($f3,$f2,LLIL_REG_SPLIT.d($f5,$f4)); LLIL_GOTO(3)'),
    # movt.d $f1, $f3, $fcc0 -- odd FR=0 double roots are architecturally unpredictable
    ('mipsel32', b'\x51\x18\x21\x46', 'LLIL_UNKNOWN()'),
    # movt.d $f1, $f3, $fcc0 -- odd FPRs are valid in the modeled FR=1 register file
    ('mipsel64', b'\x51\x18\x21\x46', 'LLIL_IF(LLIL_FLAG($fcc0),1,3); LLIL_SET_REG.q($f1,LLIL_REG.q($f3)); LLIL_GOTO(3)'),
    # movf $at, $zero, $fcc0 -- MIPS32 Release 6.06 p. 276
    ('mipsel32', b'\x01\x08\x00\x00', 'LLIL_IF(LLIL_NOT(LLIL_FLAG($fcc0)),1,3); LLIL_SET_REG.d($at,LLIL_CONST.d(0x0)); LLIL_GOTO(3)'),
    # movf $at, $zero, $fcc0 -- big-endian encoding
    ('mips32', b'\x00\x00\x08\x01', 'LLIL_IF(LLIL_NOT(LLIL_FLAG($fcc0)),1,3); LLIL_SET_REG.d($at,LLIL_CONST.d(0x0)); LLIL_GOTO(3)'),
    # movt $at, $t0, $fcc3 -- MIPS32 Release 6.06 p. 281 and explicit FCC selection
    ('mipsel32', b'\x01\x08\x0d\x01', 'LLIL_IF(LLIL_FLAG($fcc3),1,3); LLIL_SET_REG.d($at,LLIL_REG.d($t0)); LLIL_GOTO(3)'),
    # movt $at, $t0, $fcc0 -- MIPS64 Release 6.06 p. 373 uses full-width GPRs
    ('mipsel64', b'\x01\x08\x01\x01', 'LLIL_IF(LLIL_FLAG($fcc0),1,3); LLIL_SET_REG.q($at,LLIL_REG.q($t0)); LLIL_GOTO(3)'),
    # movn.s $f2, $f4, $t0 -- MIPS32 Release 6.06 p. 280: copy only for a nonzero GPR
    ('mips32', b'\x46\x08\x20\x93', 'LLIL_IF(LLIL_CMP_NE.d(LLIL_REG.d($t0),LLIL_CONST.d(0x0)),1,3); LLIL_SET_REG.d($f2,LLIL_REG.d($f4)); LLIL_GOTO(3)'),
    # movn.s $f2, $f4, $t0 -- little-endian encoding
    ('mipsel32', b'\x93\x20\x08\x46', 'LLIL_IF(LLIL_CMP_NE.d(LLIL_REG.d($t0),LLIL_CONST.d(0x0)),1,3); LLIL_SET_REG.d($f2,LLIL_REG.d($f4)); LLIL_GOTO(3)'),
    # movn.s $f31, $f31, $ra -- full 64-bit GPR test, but only a 32-bit FPR transfer
    ('mipsel64', b'\xd3\xff\x1f\x46', 'LLIL_IF(LLIL_CMP_NE.q(LLIL_REG.q($ra),LLIL_CONST.q(0x0)),1,3); LLIL_SET_REG.d($f31,LLIL_REG.d($f31)); LLIL_GOTO(3)'),
    # movn.s $f3, $f5, $zero -- the architectural zero register never selects the source
    ('mips32', b'\x46\x00\x28\xd3', 'LLIL_IF(LLIL_CMP_NE.d(LLIL_CONST.d(0x0),LLIL_CONST.d(0x0)),1,3); LLIL_SET_REG.d($f3,LLIL_REG.d($f5)); LLIL_GOTO(3)'),
    # movz.s $f2, $f4, $t0 -- MIPS32 Release 6.06 p. 285: copy only for a zero GPR
    ('mipsel32', b'\x92\x20\x08\x46', 'LLIL_IF(LLIL_CMP_E.d(LLIL_REG.d($t0),LLIL_CONST.d(0x0)),1,3); LLIL_SET_REG.d($f2,LLIL_REG.d($f4)); LLIL_GOTO(3)'),
    # movz.s $f2, $f4, $t0 -- big-endian encoding
    ('mips32', b'\x46\x08\x20\x92', 'LLIL_IF(LLIL_CMP_E.d(LLIL_REG.d($t0),LLIL_CONST.d(0x0)),1,3); LLIL_SET_REG.d($f2,LLIL_REG.d($f4)); LLIL_GOTO(3)'),
    # movz.s $f31, $f31, $ra -- odd and aliased FPRs are valid for single precision
    ('mips64', b'\x46\x1f\xff\xd2', 'LLIL_IF(LLIL_CMP_E.q(LLIL_REG.q($ra),LLIL_CONST.q(0x0)),1,3); LLIL_SET_REG.d($f31,LLIL_REG.d($f31)); LLIL_GOTO(3)'),
    # movz.s $f3, $f5, $zero -- the architectural zero register always selects the source
    ('mipsel32', b'\xd2\x28\x00\x46', 'LLIL_IF(LLIL_CMP_E.d(LLIL_CONST.d(0x0),LLIL_CONST.d(0x0)),1,3); LLIL_SET_REG.d($f3,LLIL_REG.d($f5)); LLIL_GOTO(3)'),
    # movn.d $f2, $f4, $t0 -- FR=0 copies the complete even/odd FPR pair
    ('mipsel32', b'\x93\x20\x28\x46', 'LLIL_IF(LLIL_CMP_NE.d(LLIL_REG.d($t0),LLIL_CONST.d(0x0)),1,3); LLIL_SET_REG_SPLIT.d($f3,$f2,LLIL_REG_SPLIT.d($f5,$f4)); LLIL_GOTO(3)'),
    # movn.d $f2, $f4, $t0 -- big-endian FR=0 uses the same register-pair ordering
    ('mips32', b'\x46\x28\x20\x93', 'LLIL_IF(LLIL_CMP_NE.d(LLIL_REG.d($t0),LLIL_CONST.d(0x0)),1,3); LLIL_SET_REG_SPLIT.d($f3,$f2,LLIL_REG_SPLIT.d($f5,$f4)); LLIL_GOTO(3)'),
    # movn.d $f3, $f5, $t1 -- odd FPRs and full-width GPR conditions in FR=1
    ('mipsel64', b'\xd3\x28\x29\x46', 'LLIL_IF(LLIL_CMP_NE.q(LLIL_REG.q($t1),LLIL_CONST.q(0x0)),1,3); LLIL_SET_REG.q($f3,LLIL_REG.q($f5)); LLIL_GOTO(3)'),
    # movn.d $f3, $f4, $t0 -- odd FR=0 destination pair roots are unpredictable
    ('mips32', b'\x46\x28\x20\xd3', 'LLIL_UNKNOWN()'),
    # movn.d $f2, $f5, $t0 -- odd FR=0 source pair roots are unpredictable
    ('mipsel32', b'\x93\x28\x28\x46', 'LLIL_UNKNOWN()'),
    # movn.d $f3, $f5, $zero -- a false predicate does not waive format restrictions
    ('mipsel32', b'\xd3\x28\x20\x46', 'LLIL_UNKNOWN()'),
    # movn.d $f4, $f4, $t0 -- an aliased even/odd pair is copied atomically
    ('mipsel32', b'\x13\x21\x28\x46', 'LLIL_IF(LLIL_CMP_NE.d(LLIL_REG.d($t0),LLIL_CONST.d(0x0)),1,3); LLIL_SET_REG_SPLIT.d($f5,$f4,LLIL_REG_SPLIT.d($f5,$f4)); LLIL_GOTO(3)'),
    # movz.d $f2, $f4, $t0 -- the false path preserves both destination words
    ('mips32', b'\x46\x28\x20\x92', 'LLIL_IF(LLIL_CMP_E.d(LLIL_REG.d($t0),LLIL_CONST.d(0x0)),1,3); LLIL_SET_REG_SPLIT.d($f3,$f2,LLIL_REG_SPLIT.d($f5,$f4)); LLIL_GOTO(3)'),
    # movz.d $f2, $f4, $t0 -- little-endian FR=0 encoding
    ('mipsel32', b'\x92\x20\x28\x46', 'LLIL_IF(LLIL_CMP_E.d(LLIL_REG.d($t0),LLIL_CONST.d(0x0)),1,3); LLIL_SET_REG_SPLIT.d($f3,$f2,LLIL_REG_SPLIT.d($f5,$f4)); LLIL_GOTO(3)'),
    # movz.d $f3, $f5, $t1 -- FR=1 copies a complete 64-bit FPR
    ('mips64', b'\x46\x29\x28\xd2', 'LLIL_IF(LLIL_CMP_E.q(LLIL_REG.q($t1),LLIL_CONST.q(0x0)),1,3); LLIL_SET_REG.q($f3,LLIL_REG.q($f5)); LLIL_GOTO(3)'),
    # movz.d $f3, $f4, $t0 -- odd FR=0 destination pair roots are unpredictable
    ('mipsel32', b'\xd2\x20\x28\x46', 'LLIL_UNKNOWN()'),
    # movz.d $f2, $f5, $t0 -- odd FR=0 source pair roots are unpredictable
    ('mips32', b'\x46\x28\x28\x92', 'LLIL_UNKNOWN()'),
    # movz.d $f3, $f5, $zero -- a true predicate does not waive format restrictions
    ('mips32', b'\x46\x20\x28\xd2', 'LLIL_UNKNOWN()'),
    # movz.d $f4, $f4, $t0 -- source and destination may name the same valid pair
    ('mips32', b'\x46\x28\x21\x12', 'LLIL_IF(LLIL_CMP_E.d(LLIL_REG.d($t0),LLIL_CONST.d(0x0)),1,3); LLIL_SET_REG_SPLIT.d($f5,$f4,LLIL_REG_SPLIT.d($f5,$f4)); LLIL_GOTO(3)'),
    # movn.ps $f2, $f4, $t0 -- one full-width GPR condition controls both FR=1 lanes
    ('mips64', b'\x46\xc8\x20\x93', 'LLIL_IF(LLIL_CMP_NE.q(LLIL_REG.q($t0),LLIL_CONST.q(0x0)),1,3); LLIL_SET_REG.q($f2,LLIL_REG.q($f4)); LLIL_GOTO(3)'),
    # movn.ps $f3, $f5, $t1 -- little-endian encoding with odd FPRs
    ('mipsel64', b'\xd3\x28\xc9\x46', 'LLIL_IF(LLIL_CMP_NE.q(LLIL_REG.q($t1),LLIL_CONST.q(0x0)),1,3); LLIL_SET_REG.q($f3,LLIL_REG.q($f5)); LLIL_GOTO(3)'),
    # movn.ps $f3, $f5, $zero -- both lanes are preserved for a zero predicate
    ('mipsel64', b'\xd3\x28\xc0\x46', 'LLIL_IF(LLIL_CMP_NE.q(LLIL_CONST.q(0x0),LLIL_CONST.q(0x0)),1,3); LLIL_SET_REG.q($f3,LLIL_REG.q($f5)); LLIL_GOTO(3)'),
    # movn.ps $f2, $f4, $t0 -- PS is unpredictable in the modeled FR=0 register file
    ('mips32', b'\x46\xc8\x20\x93', 'LLIL_UNKNOWN()'),
    # movz.ps $f3, $f5, $t1 -- odd FPRs are valid in FR=1
    ('mipsel64', b'\xd2\x28\xc9\x46', 'LLIL_IF(LLIL_CMP_E.q(LLIL_REG.q($t1),LLIL_CONST.q(0x0)),1,3); LLIL_SET_REG.q($f3,LLIL_REG.q($f5)); LLIL_GOTO(3)'),
    # movz.ps $f2, $f4, $t0 -- big-endian encoding
    ('mips64', b'\x46\xc8\x20\x92', 'LLIL_IF(LLIL_CMP_E.q(LLIL_REG.q($t0),LLIL_CONST.q(0x0)),1,3); LLIL_SET_REG.q($f2,LLIL_REG.q($f4)); LLIL_GOTO(3)'),
    # movz.ps $f3, $f5, $zero -- both lanes are selected for a zero predicate
    ('mips64', b'\x46\xc0\x28\xd2', 'LLIL_IF(LLIL_CMP_E.q(LLIL_CONST.q(0x0),LLIL_CONST.q(0x0)),1,3); LLIL_SET_REG.q($f3,LLIL_REG.q($f5)); LLIL_GOTO(3)'),
    # movz.ps $f2, $f4, $t0 -- even FPRs do not make PS valid in FR=0
    ('mipsel32', b'\x92\x20\xc8\x46', 'LLIL_UNKNOWN()'),
    # movt.ps $f2, $f4, $fcc0 -- MIPS32 Release 6.06 pp. 282-283: FCC0/FCC1 select low/high independently
    ('mips64', b'\x46\xc1\x20\x91', 'LLIL_INTRINSIC([temp0],_movt_ps,[LLIL_REG.q($f2),LLIL_REG.q($f4),LLIL_FLAG($fcc0),LLIL_FLAG($fcc1)]); LLIL_SET_REG.q($f2,LLIL_REG.q(temp0))'),
    # movt.ps $f2, $f4, $fcc2 -- little-endian encoding and a non-default FCC pair
    ('mipsel64', b'\x91\x20\xc9\x46', 'LLIL_INTRINSIC([temp0],_movt_ps,[LLIL_REG.q($f2),LLIL_REG.q($f4),LLIL_FLAG($fcc2),LLIL_FLAG($fcc3)]); LLIL_SET_REG.q($f2,LLIL_REG.q(temp0))'),
    # movt.ps $f3, $f5, $fcc4 -- odd FPRs with a valid even FCC selector
    ('mips64', b'\x46\xd1\x28\xd1', 'LLIL_INTRINSIC([temp0],_movt_ps,[LLIL_REG.q($f3),LLIL_REG.q($f5),LLIL_FLAG($fcc4),LLIL_FLAG($fcc5)]); LLIL_SET_REG.q($f3,LLIL_REG.q(temp0))'),
    # movt.ps $f31, $f31, $fcc6 -- aliasing and the highest valid FCC pair
    ('mipsel64', b'\xd1\xff\xd9\x46', 'LLIL_INTRINSIC([temp0],_movt_ps,[LLIL_REG.q($f31),LLIL_REG.q($f31),LLIL_FLAG($fcc6),LLIL_FLAG($fcc7)]); LLIL_SET_REG.q($f31,LLIL_REG.q(temp0))'),
    # movt.ps $f2, $f4, $fcc1 -- odd FCC selectors are unpredictable
    ('mips64', b'\x46\xc5\x20\x91', 'LLIL_UNKNOWN()'),
    # movt.ps $f2, $f4, $fcc7 -- FCC7 must not wrap to FCC0 or reference FCC8
    ('mipsel64', b'\x91\x20\xdd\x46', 'LLIL_UNKNOWN()'),
    # movt.ps $f2, $f4, $fcc0 -- paired-single conditional moves require FR=1
    ('mips32', b'\x46\xc1\x20\x91', 'LLIL_UNKNOWN()'),
    # movf.ps $f2, $f4, $fcc2 -- MIPS32 Release 6.06 pp. 277-278: unselected lanes retain their old values
    ('mipsel64', b'\x91\x20\xc8\x46', 'LLIL_INTRINSIC([temp0],_movf_ps,[LLIL_REG.q($f2),LLIL_REG.q($f4),LLIL_FLAG($fcc2),LLIL_FLAG($fcc3)]); LLIL_SET_REG.q($f2,LLIL_REG.q(temp0))'),
    # movf.ps $f2, $f4, $fcc0 -- big-endian encoding and both false-polarity lane predicates
    ('mips64', b'\x46\xc0\x20\x91', 'LLIL_INTRINSIC([temp0],_movf_ps,[LLIL_REG.q($f2),LLIL_REG.q($f4),LLIL_FLAG($fcc0),LLIL_FLAG($fcc1)]); LLIL_SET_REG.q($f2,LLIL_REG.q(temp0))'),
    # movf.ps $f3, $f5, $fcc4 -- odd FPRs with a valid even FCC selector
    ('mips64', b'\x46\xd0\x28\xd1', 'LLIL_INTRINSIC([temp0],_movf_ps,[LLIL_REG.q($f3),LLIL_REG.q($f5),LLIL_FLAG($fcc4),LLIL_FLAG($fcc5)]); LLIL_SET_REG.q($f3,LLIL_REG.q(temp0))'),
    # movf.ps $f31, $f31, $fcc6 -- an in-place move preserves both lanes for every FCC combination
    ('mipsel64', b'\xd1\xff\xd8\x46', 'LLIL_INTRINSIC([temp0],_movf_ps,[LLIL_REG.q($f31),LLIL_REG.q($f31),LLIL_FLAG($fcc6),LLIL_FLAG($fcc7)]); LLIL_SET_REG.q($f31,LLIL_REG.q(temp0))'),
    # movf.ps $f2, $f4, $fcc1 -- odd FCC selectors are unpredictable
    ('mipsel64', b'\x91\x20\xc4\x46', 'LLIL_UNKNOWN()'),
    # movf.ps $f2, $f4, $fcc7 -- the highest odd FCC selector is also unpredictable
    ('mips64', b'\x46\xdc\x20\x91', 'LLIL_UNKNOWN()'),
    # movf.ps $f2, $f4, $fcc0 -- paired-single is unpredictable in FR=0
    ('mipsel32', b'\x91\x20\xc0\x46', 'LLIL_UNKNOWN()'),
    # bc1nez $f2, 0xc; movn.s $f2, $f4, $t0 -- preserve the branch value before conditional delay-slot control flow
    ('mipsel32', b'\x02\x00\xa2\x45\x93\x20\x08\x46', 'LLIL_SET_REG.d(temp1,LLIL_REG.d($f2)); LLIL_IF(LLIL_CMP_NE.d(LLIL_REG.d($t0),LLIL_CONST.d(0x0)),2,4); LLIL_SET_REG.d($f2,LLIL_REG.d($f4)); LLIL_GOTO(4); LLIL_IF(LLIL_TEST_BIT.d(LLIL_REG.d(temp1),LLIL_CONST.b(0x0)),8,5)'),
    # bc1nez $f2, 0xc; movz.s $f2, $f4, $t0 -- big-endian zero-predicate delay slot
    ('mips32', b'\x45\xa2\x00\x02\x46\x08\x20\x92', 'LLIL_SET_REG.d(temp1,LLIL_REG.d($f2)); LLIL_IF(LLIL_CMP_E.d(LLIL_REG.d($t0),LLIL_CONST.d(0x0)),2,4); LLIL_SET_REG.d($f2,LLIL_REG.d($f4)); LLIL_GOTO(4); LLIL_IF(LLIL_TEST_BIT.d(LLIL_REG.d(temp1),LLIL_CONST.b(0x0)),8,5)'),
    # bc1nez $f2, 0xc; movn.d $f2, $f4, $t0 -- the branch reads the old low half of the FR=0 pair
    ('mipsel32', b'\x02\x00\xa2\x45\x93\x20\x28\x46', 'LLIL_SET_REG.q(temp1,LLIL_REG_SPLIT.d($f3,$f2)); LLIL_IF(LLIL_CMP_NE.d(LLIL_REG.d($t0),LLIL_CONST.d(0x0)),2,4); LLIL_SET_REG_SPLIT.d($f3,$f2,LLIL_REG_SPLIT.d($f5,$f4)); LLIL_GOTO(4); LLIL_IF(LLIL_TEST_BIT.d(LLIL_LOW_PART.d(LLIL_REG.q(temp1)),LLIL_CONST.b(0x0)),8,5)'),
    # bc1nez $f3, 0xc; movz.d $f2, $f4, $t0 -- preserve the old high half, without swapping the pair
    ('mips32', b'\x45\xa3\x00\x02\x46\x28\x20\x92', 'LLIL_SET_REG.q(temp1,LLIL_REG_SPLIT.d($f3,$f2)); LLIL_IF(LLIL_CMP_E.d(LLIL_REG.d($t0),LLIL_CONST.d(0x0)),2,4); LLIL_SET_REG_SPLIT.d($f3,$f2,LLIL_REG_SPLIT.d($f5,$f4)); LLIL_GOTO(4); LLIL_IF(LLIL_TEST_BIT.d(LLIL_LOW_PART.d(LLIL_LSR.q(LLIL_REG.q(temp1),LLIL_CONST.b(0x20))),LLIL_CONST.b(0x0)),8,5)'),
    # bc1nez $f2, 0xc; movn.ps $f2, $f4, $t0 -- snapshot the packed destination before its conditional write
    ('mips64', b'\x45\xa2\x00\x02\x46\xc8\x20\x93', 'LLIL_SET_REG.q(temp1,LLIL_REG.q($f2)); LLIL_IF(LLIL_CMP_NE.q(LLIL_REG.q($t0),LLIL_CONST.q(0x0)),2,4); LLIL_SET_REG.q($f2,LLIL_REG.q($f4)); LLIL_GOTO(4); LLIL_IF(LLIL_TEST_BIT.d(LLIL_REG.d(temp1),LLIL_CONST.b(0x0)),8,5)'),
    # bc1nez $f2, 0xc; movz.ps $f2, $f4, $t0 -- the branch predicate is independent of the move predicate
    ('mipsel64', b'\x02\x00\xa2\x45\x92\x20\xc8\x46', 'LLIL_SET_REG.q(temp1,LLIL_REG.q($f2)); LLIL_IF(LLIL_CMP_E.q(LLIL_REG.q($t0),LLIL_CONST.q(0x0)),2,4); LLIL_SET_REG.q($f2,LLIL_REG.q($f4)); LLIL_GOTO(4); LLIL_IF(LLIL_TEST_BIT.d(LLIL_REG.d(temp1),LLIL_CONST.b(0x0)),8,5)'),
    # bc1nez $f2, 0xc; movt.ps $f2, $f4, $fcc0 -- snapshot before either lane can change the branch value
    ('mipsel64', b'\x02\x00\xa2\x45\x91\x20\xc1\x46', 'LLIL_SET_REG.q(temp1,LLIL_REG.q($f2)); LLIL_INTRINSIC([temp0],_movt_ps,[LLIL_REG.q($f2),LLIL_REG.q($f4),LLIL_FLAG($fcc0),LLIL_FLAG($fcc1)]); LLIL_SET_REG.q($f2,LLIL_REG.q(temp0)); LLIL_IF(LLIL_TEST_BIT.d(LLIL_REG.d(temp1),LLIL_CONST.b(0x0)),7,4)'),
    # bc1nez $f2, 0xc; movf.ps $f2, $f4, $fcc0 -- false-polarity lane selection also preserves the branch value
    ('mips64', b'\x45\xa2\x00\x02\x46\xc0\x20\x91', 'LLIL_SET_REG.q(temp1,LLIL_REG.q($f2)); LLIL_INTRINSIC([temp0],_movf_ps,[LLIL_REG.q($f2),LLIL_REG.q($f4),LLIL_FLAG($fcc0),LLIL_FLAG($fcc1)]); LLIL_SET_REG.q($f2,LLIL_REG.q(temp0)); LLIL_IF(LLIL_TEST_BIT.d(LLIL_REG.d(temp1),LLIL_CONST.b(0x0)),7,4)'),
    # trunc.w.s $f2, $f4 -- truncate a single to a signed 32-bit fixed-point value
    ('mips32', b'\x46\x00\x20\x8d', 'LLIL_SET_REG.d($f2,LLIL_FLOAT_TO_INT.d(LLIL_FTRUNC.d(LLIL_REG.d($f4))))'),
    # trunc.w.s $f2, $f4 -- little-endian encoding
    ('mipsel32', b'\x8d\x20\x00\x46', 'LLIL_SET_REG.d($f2,LLIL_FLOAT_TO_INT.d(LLIL_FTRUNC.d(LLIL_REG.d($f4))))'),
    # trunc.w.d $f2, $f4 -- FR=0 reads an even/odd double source pair
    ('mipsel32', b'\x8d\x20\x20\x46', 'LLIL_SET_REG.d($f2,LLIL_FLOAT_TO_INT.d(LLIL_FTRUNC.q(LLIL_REG_SPLIT.d($f5,$f4))))'),
    # trunc.w.d $f2, $f4 -- FR=1 reads a directly modeled 64-bit FPR
    ('mipsel64', b'\x8d\x20\x20\x46', 'LLIL_SET_REG.d($f2,LLIL_FLOAT_TO_INT.d(LLIL_FTRUNC.q(LLIL_REG.q($f4))))'),
    # trunc.w.d $f3, $f5 -- odd FR=0 double roots are architecturally unpredictable
    ('mipsel32', b'\xcd\x28\x20\x46', 'LLIL_UNKNOWN()'),
    # trunc.w.d $f3, $f5 -- odd FPRs are valid in the modeled FR=1 register file
    ('mipsel64', b'\xcd\x28\x20\x46', 'LLIL_SET_REG.d($f3,LLIL_FLOAT_TO_INT.d(LLIL_FTRUNC.q(LLIL_REG.q($f5))))'),
    # trunc.l.s $f2, $f4 -- truncate a single to a signed 64-bit fixed-point value
    ('mips64', b'\x46\x00\x20\x89', 'LLIL_SET_REG.q($f2,LLIL_FLOAT_TO_INT.q(LLIL_FTRUNC.d(LLIL_REG.d($f4))))'),
    # trunc.l.s $f2, $f4 -- little-endian encoding
    ('mipsel64', b'\x89\x20\x00\x46', 'LLIL_SET_REG.q($f2,LLIL_FLOAT_TO_INT.q(LLIL_FTRUNC.d(LLIL_REG.d($f4))))'),
    # trunc.l.d $f2, $f4 -- truncate a double to a signed 64-bit fixed-point value
    ('mipsel64', b'\x89\x20\x20\x46', 'LLIL_SET_REG.q($f2,LLIL_FLOAT_TO_INT.q(LLIL_FTRUNC.q(LLIL_REG.q($f4))))'),
    # trunc.l.d $f3, $f5 -- odd FPRs are valid in the modeled FR=1 register file
    ('mipsel64', b'\xc9\x28\x20\x46', 'LLIL_SET_REG.q($f3,LLIL_FLOAT_TO_INT.q(LLIL_FTRUNC.q(LLIL_REG.q($f5))))'),
    # trunc.l.s $f2, $f4 -- a long result is unpredictable in the FR=0 FPR model
    ('mips32', b'\x46\x00\x20\x89', 'LLIL_UNKNOWN()'),
    # trunc.l.d $f2, $f4 -- FR=0 cannot hold the 64-bit result in one FPR
    ('mipsel32', b'\x89\x20\x20\x46', 'LLIL_UNKNOWN()'),
    # round.w.s $f2, $f4 -- MIPS32 Release 6.06 p. 342: nearest/even, independent of FCSR.RM
    ('mips32', b'\x46\x00\x20\x8c', 'LLIL_INTRINSIC([temp0],_round_w_s,[LLIL_REG.d($f4)]); LLIL_SET_REG.d($f2,LLIL_REG.d(temp0))'),
    # round.w.s $f2, $f4 -- little-endian encoding
    ('mipsel32', b'\x8c\x20\x00\x46', 'LLIL_INTRINSIC([temp0],_round_w_s,[LLIL_REG.d($f4)]); LLIL_SET_REG.d($f2,LLIL_REG.d(temp0))'),
    # round.w.s $f31, $f31 -- in-place conversion reads and writes only a word in FR=1
    ('mipsel64', b'\xcc\xff\x00\x46', 'LLIL_INTRINSIC([temp0],_round_w_s,[LLIL_REG.d($f31)]); LLIL_SET_REG.d($f31,LLIL_REG.d(temp0))'),
    # round.w.d $f2, $f4 -- FR=0 reads an even/odd double source pair
    ('mips32', b'\x46\x20\x20\x8c', 'LLIL_INTRINSIC([temp0],_round_w_d,[LLIL_REG_SPLIT.d($f5,$f4)]); LLIL_SET_REG.d($f2,LLIL_REG.d(temp0))'),
    # round.w.d $f2, $f4 -- little-endian FR=0 has the same register-pair ordering
    ('mipsel32', b'\x8c\x20\x20\x46', 'LLIL_INTRINSIC([temp0],_round_w_d,[LLIL_REG_SPLIT.d($f5,$f4)]); LLIL_SET_REG.d($f2,LLIL_REG.d(temp0))'),
    # round.w.d $f2, $f4 -- FR=1 reads a double but writes a 32-bit integer
    ('mipsel64', b'\x8c\x20\x20\x46', 'LLIL_INTRINSIC([temp0],_round_w_d,[LLIL_REG.q($f4)]); LLIL_SET_REG.d($f2,LLIL_REG.d(temp0))'),
    # round.w.d $f3, $f4 -- an odd word destination is valid in FR=0
    ('mipsel32', b'\xcc\x20\x20\x46', 'LLIL_INTRINSIC([temp0],_round_w_d,[LLIL_REG_SPLIT.d($f5,$f4)]); LLIL_SET_REG.d($f3,LLIL_REG.d(temp0))'),
    # round.w.d $f3, $f5 -- an odd FR=0 double source is unpredictable
    ('mipsel32', b'\xcc\x28\x20\x46', 'LLIL_UNKNOWN()'),
    # round.w.d $f3, $f5 -- odd double sources are valid in FR=1
    ('mipsel64', b'\xcc\x28\x20\x46', 'LLIL_INTRINSIC([temp0],_round_w_d,[LLIL_REG.q($f5)]); LLIL_SET_REG.d($f3,LLIL_REG.d(temp0))'),
    # round.w.d $f5, $f4 -- read the pair before overwriting its high word
    ('mipsel32', b'\x4c\x21\x20\x46', 'LLIL_INTRINSIC([temp0],_round_w_d,[LLIL_REG_SPLIT.d($f5,$f4)]); LLIL_SET_REG.d($f5,LLIL_REG.d(temp0))'),
    # bc1nez $f5, 0xc; round.w.d $f5, $f4 -- keep the pre-delay-slot branch value separate from the result temp
    ('mipsel32', b'\x02\x00\xa5\x45\x4c\x21\x20\x46', 'LLIL_SET_REG.d(temp1,LLIL_REG.d($f5)); LLIL_INTRINSIC([temp0],_round_w_d,[LLIL_REG_SPLIT.d($f5,$f4)]); LLIL_SET_REG.d($f5,LLIL_REG.d(temp0)); LLIL_IF(LLIL_TEST_BIT.d(LLIL_REG.d(temp1),LLIL_CONST.b(0x0)),7,4)'),
    # round.l.s $f2, $f4 -- MIPS32 Release 6.06 p. 341: nearest/even to a signed long
    ('mips64', b'\x46\x00\x20\x88', 'LLIL_INTRINSIC([temp0],_round_l_s,[LLIL_REG.d($f4)]); LLIL_SET_REG.q($f2,LLIL_REG.q(temp0))'),
    # round.l.s $f2, $f4 -- little-endian encoding
    ('mipsel64', b'\x88\x20\x00\x46', 'LLIL_INTRINSIC([temp0],_round_l_s,[LLIL_REG.d($f4)]); LLIL_SET_REG.q($f2,LLIL_REG.q(temp0))'),
    # round.l.d $f2, $f4 -- double source and 64-bit integer result
    ('mips64', b'\x46\x20\x20\x88', 'LLIL_INTRINSIC([temp0],_round_l_d,[LLIL_REG.q($f4)]); LLIL_SET_REG.q($f2,LLIL_REG.q(temp0))'),
    # round.l.d $f3, $f5 -- odd source and destination are valid in FR=1
    ('mipsel64', b'\xc8\x28\x20\x46', 'LLIL_INTRINSIC([temp0],_round_l_d,[LLIL_REG.q($f5)]); LLIL_SET_REG.q($f3,LLIL_REG.q(temp0))'),
    # round.l.s $f2, $f4 -- long results are unpredictable in FR=0
    ('mips32', b'\x46\x00\x20\x88', 'LLIL_UNKNOWN()'),
    # round.l.d $f2, $f4 -- even register numbers do not make long results valid in FR=0
    ('mipsel32', b'\x88\x20\x20\x46', 'LLIL_UNKNOWN()'),
    # ceil.w.s $f2, $f4 -- MIPS32 Release 6.06 p. 128: toward positive infinity, independent of FCSR.RM
    ('mips32', b'\x46\x00\x20\x8e', 'LLIL_SET_REG.d($f2,LLIL_FLOAT_TO_INT.d(LLIL_CEIL.d(LLIL_REG.d($f4))))'),
    # ceil.w.s $f2, $f4 -- little-endian encoding
    ('mipsel32', b'\x8e\x20\x00\x46', 'LLIL_SET_REG.d($f2,LLIL_FLOAT_TO_INT.d(LLIL_CEIL.d(LLIL_REG.d($f4))))'),
    # ceil.w.s $f31, $f31 -- in-place conversion reads and writes only a word in FR=1
    ('mipsel64', b'\xce\xff\x00\x46', 'LLIL_SET_REG.d($f31,LLIL_FLOAT_TO_INT.d(LLIL_CEIL.d(LLIL_REG.d($f31))))'),
    # ceil.w.d $f2, $f4 -- FR=0 reads an even/odd double source pair
    ('mips32', b'\x46\x20\x20\x8e', 'LLIL_SET_REG.d($f2,LLIL_FLOAT_TO_INT.d(LLIL_CEIL.q(LLIL_REG_SPLIT.d($f5,$f4))))'),
    # ceil.w.d $f2, $f4 -- little-endian FR=0 has the same register-pair ordering
    ('mipsel32', b'\x8e\x20\x20\x46', 'LLIL_SET_REG.d($f2,LLIL_FLOAT_TO_INT.d(LLIL_CEIL.q(LLIL_REG_SPLIT.d($f5,$f4))))'),
    # ceil.w.d $f2, $f4 -- FR=1 reads a double but writes a 32-bit integer
    ('mipsel64', b'\x8e\x20\x20\x46', 'LLIL_SET_REG.d($f2,LLIL_FLOAT_TO_INT.d(LLIL_CEIL.q(LLIL_REG.q($f4))))'),
    # ceil.w.d $f3, $f4 -- an odd word destination is valid in FR=0
    ('mipsel32', b'\xce\x20\x20\x46', 'LLIL_SET_REG.d($f3,LLIL_FLOAT_TO_INT.d(LLIL_CEIL.q(LLIL_REG_SPLIT.d($f5,$f4))))'),
    # ceil.w.d $f3, $f5 -- an odd FR=0 double source is unpredictable
    ('mipsel32', b'\xce\x28\x20\x46', 'LLIL_UNKNOWN()'),
    # ceil.w.d $f3, $f5 -- odd double sources are valid in FR=1
    ('mipsel64', b'\xce\x28\x20\x46', 'LLIL_SET_REG.d($f3,LLIL_FLOAT_TO_INT.d(LLIL_CEIL.q(LLIL_REG.q($f5))))'),
    # ceil.w.d $f5, $f4 -- read the pair before overwriting its high word
    ('mipsel32', b'\x4e\x21\x20\x46', 'LLIL_SET_REG.d($f5,LLIL_FLOAT_TO_INT.d(LLIL_CEIL.q(LLIL_REG_SPLIT.d($f5,$f4))))'),
    # ceil.l.s $f2, $f4 -- MIPS32 Release 6.06 p. 127: toward positive infinity to a signed long
    ('mips64', b'\x46\x00\x20\x8a', 'LLIL_SET_REG.q($f2,LLIL_FLOAT_TO_INT.q(LLIL_CEIL.d(LLIL_REG.d($f4))))'),
    # ceil.l.s $f2, $f4 -- little-endian encoding
    ('mipsel64', b'\x8a\x20\x00\x46', 'LLIL_SET_REG.q($f2,LLIL_FLOAT_TO_INT.q(LLIL_CEIL.d(LLIL_REG.d($f4))))'),
    # ceil.l.d $f2, $f4 -- double source and 64-bit integer result
    ('mips64', b'\x46\x20\x20\x8a', 'LLIL_SET_REG.q($f2,LLIL_FLOAT_TO_INT.q(LLIL_CEIL.q(LLIL_REG.q($f4))))'),
    # ceil.l.d $f3, $f5 -- odd source and destination are valid in FR=1
    ('mipsel64', b'\xca\x28\x20\x46', 'LLIL_SET_REG.q($f3,LLIL_FLOAT_TO_INT.q(LLIL_CEIL.q(LLIL_REG.q($f5))))'),
    # ceil.l.s $f2, $f4 -- long results are unpredictable in FR=0
    ('mips32', b'\x46\x00\x20\x8a', 'LLIL_UNKNOWN()'),
    # ceil.l.d $f2, $f4 -- even register numbers do not make long results valid in FR=0
    ('mipsel32', b'\x8a\x20\x20\x46', 'LLIL_UNKNOWN()'),
    # floor.w.s $f2, $f4 -- MIPS32 Release 6.06 p. 186: toward negative infinity, independent of FCSR.RM
    ('mips32', b'\x46\x00\x20\x8f', 'LLIL_SET_REG.d($f2,LLIL_FLOAT_TO_INT.d(LLIL_FLOOR.d(LLIL_REG.d($f4))))'),
    # floor.w.s $f2, $f4 -- little-endian encoding
    ('mipsel32', b'\x8f\x20\x00\x46', 'LLIL_SET_REG.d($f2,LLIL_FLOAT_TO_INT.d(LLIL_FLOOR.d(LLIL_REG.d($f4))))'),
    # floor.w.s $f31, $f31 -- in-place conversion reads and writes only a word in FR=1
    ('mipsel64', b'\xcf\xff\x00\x46', 'LLIL_SET_REG.d($f31,LLIL_FLOAT_TO_INT.d(LLIL_FLOOR.d(LLIL_REG.d($f31))))'),
    # floor.w.d $f2, $f4 -- FR=0 reads an even/odd double source pair
    ('mips32', b'\x46\x20\x20\x8f', 'LLIL_SET_REG.d($f2,LLIL_FLOAT_TO_INT.d(LLIL_FLOOR.q(LLIL_REG_SPLIT.d($f5,$f4))))'),
    # floor.w.d $f2, $f4 -- little-endian FR=0 has the same register-pair ordering
    ('mipsel32', b'\x8f\x20\x20\x46', 'LLIL_SET_REG.d($f2,LLIL_FLOAT_TO_INT.d(LLIL_FLOOR.q(LLIL_REG_SPLIT.d($f5,$f4))))'),
    # floor.w.d $f2, $f4 -- FR=1 reads a double but writes a 32-bit integer
    ('mipsel64', b'\x8f\x20\x20\x46', 'LLIL_SET_REG.d($f2,LLIL_FLOAT_TO_INT.d(LLIL_FLOOR.q(LLIL_REG.q($f4))))'),
    # floor.w.d $f3, $f4 -- an odd word destination is valid in FR=0
    ('mipsel32', b'\xcf\x20\x20\x46', 'LLIL_SET_REG.d($f3,LLIL_FLOAT_TO_INT.d(LLIL_FLOOR.q(LLIL_REG_SPLIT.d($f5,$f4))))'),
    # floor.w.d $f3, $f5 -- an odd FR=0 double source is unpredictable
    ('mipsel32', b'\xcf\x28\x20\x46', 'LLIL_UNKNOWN()'),
    # floor.w.d $f3, $f5 -- odd double sources are valid in FR=1
    ('mipsel64', b'\xcf\x28\x20\x46', 'LLIL_SET_REG.d($f3,LLIL_FLOAT_TO_INT.d(LLIL_FLOOR.q(LLIL_REG.q($f5))))'),
    # floor.w.d $f5, $f4 -- read the pair before overwriting its high word
    ('mipsel32', b'\x4f\x21\x20\x46', 'LLIL_SET_REG.d($f5,LLIL_FLOAT_TO_INT.d(LLIL_FLOOR.q(LLIL_REG_SPLIT.d($f5,$f4))))'),
    # floor.l.s $f2, $f4 -- MIPS32 Release 6.06 p. 185: toward negative infinity to a signed long
    ('mips64', b'\x46\x00\x20\x8b', 'LLIL_SET_REG.q($f2,LLIL_FLOAT_TO_INT.q(LLIL_FLOOR.d(LLIL_REG.d($f4))))'),
    # floor.l.s $f2, $f4 -- little-endian encoding
    ('mipsel64', b'\x8b\x20\x00\x46', 'LLIL_SET_REG.q($f2,LLIL_FLOAT_TO_INT.q(LLIL_FLOOR.d(LLIL_REG.d($f4))))'),
    # floor.l.d $f2, $f4 -- double source and 64-bit integer result
    ('mips64', b'\x46\x20\x20\x8b', 'LLIL_SET_REG.q($f2,LLIL_FLOAT_TO_INT.q(LLIL_FLOOR.q(LLIL_REG.q($f4))))'),
    # floor.l.d $f3, $f5 -- odd source and destination are valid in FR=1
    ('mipsel64', b'\xcb\x28\x20\x46', 'LLIL_SET_REG.q($f3,LLIL_FLOAT_TO_INT.q(LLIL_FLOOR.q(LLIL_REG.q($f5))))'),
    # floor.l.s $f2, $f4 -- long results are unpredictable in FR=0
    ('mips32', b'\x46\x00\x20\x8b', 'LLIL_UNKNOWN()'),
    # floor.l.d $f2, $f4 -- even register numbers do not make long results valid in FR=0
    ('mipsel32', b'\x8b\x20\x20\x46', 'LLIL_UNKNOWN()'),
]

import sys
import binaryninja
from binaryninja import binaryview
from binaryninja import lowlevelil
from binaryninja.enums import Endianness, LowLevelILOperation


# These terminate the function themselves, so lift the instruction pair directly
# instead of appending and stripping a synthetic return as instr_to_il does.
terminating_test_cases = [
    # jr $t0; cfc1 $t0, $fcr31 -- preserve an indirect jump target
    ('mips32', b'\x01\x00\x00\x08\x44\x48\xf8\x00', 'LLIL_SET_REG.d(temp1,LLIL_REG.d($t0)); LLIL_INTRINSIC([temp0],moveControlWordFromCoprocessor1,[LLIL_REG.d($fcr31)]); LLIL_SET_REG.d($t0,LLIL_REG.d(temp0)); LLIL_JUMP(LLIL_REG.d(temp1))'),
    # jr $ra; cfc1 $ra, $fcr31 -- preserve a return target
    ('mips32', b'\x03\xe0\x00\x08\x44\x5f\xf8\x00', 'LLIL_SET_REG.d(temp1,LLIL_REG.d($ra)); LLIL_INTRINSIC([temp0],moveControlWordFromCoprocessor1,[LLIL_REG.d($fcr31)]); LLIL_SET_REG.d($ra,LLIL_REG.d(temp0)); LLIL_RET(LLIL_REG.d(temp1))'),
    # jr $t0; cfc1 $t0, $fcr31 -- little-endian full-width jump target
    ('mipsel64', b'\x08\x00\x00\x01\x00\xf8\x48\x44', 'LLIL_SET_REG.q(temp1,LLIL_REG.q($t0)); LLIL_INTRINSIC([temp0],moveControlWordFromCoprocessor1,[LLIL_REG.d($fcr31)]); LLIL_SET_REG.q($t0,LLIL_SX.q(LLIL_REG.d(temp0))); LLIL_JUMP(LLIL_REG.q(temp1))'),
    # jr $ra; cfc1 $ra, $fcr31 -- little-endian full-width return target
    ('mipsel64', b'\x08\x00\xe0\x03\x00\xf8\x5f\x44', 'LLIL_SET_REG.q(temp1,LLIL_REG.q($ra)); LLIL_INTRINSIC([temp0],moveControlWordFromCoprocessor1,[LLIL_REG.d($fcr31)]); LLIL_SET_REG.q($ra,LLIL_SX.q(LLIL_REG.d(temp0))); LLIL_RET(LLIL_REG.q(temp1))'),
    # jr $t0; pcpyh $t0, $t1 -- the snapshot must survive a slot that uses both temp0 and temp1
    ('r5900l', b'\x08\x00\x00\x01\xe9\x46\x09\x70',
     'LLIL_SET_REG.o(temp2,LLIL_REG.o($t0)); '
     'LLIL_SET_REG.q(temp0,LLIL_REG.w($t1)); '
     'LLIL_SET_REG.q(temp1,LLIL_LSR.w(LLIL_REG.o($t1),LLIL_CONST.b(0x40))); '
     'LLIL_SET_REG.q(temp0,LLIL_OR.q(LLIL_REG.q(temp0),LLIL_LSL.q(LLIL_REG.q(temp0),LLIL_CONST.b(0x10)))); '
     'LLIL_SET_REG.q(temp1,LLIL_OR.q(LLIL_REG.q(temp1),LLIL_LSL.q(LLIL_REG.q(temp1),LLIL_CONST.b(0x10)))); '
     'LLIL_SET_REG.q(temp0,LLIL_OR.q(LLIL_REG.q(temp0),LLIL_LSL.q(LLIL_REG.q(temp0),LLIL_CONST.b(0x10)))); '
     'LLIL_SET_REG.q(temp1,LLIL_OR.q(LLIL_REG.q(temp1),LLIL_LSL.q(LLIL_REG.q(temp1),LLIL_CONST.b(0x10)))); '
     'LLIL_SET_REG.q(temp0,LLIL_OR.q(LLIL_REG.q(temp0),LLIL_LSL.q(LLIL_REG.q(temp0),LLIL_CONST.b(0x10)))); '
     'LLIL_SET_REG.q(temp1,LLIL_OR.q(LLIL_REG.q(temp1),LLIL_LSL.q(LLIL_REG.q(temp1),LLIL_CONST.b(0x10)))); '
     'LLIL_SET_REG.q(temp0,LLIL_OR.q(LLIL_REG.q(temp0),LLIL_LSL.q(LLIL_REG.q(temp0),LLIL_CONST.b(0x10)))); '
     'LLIL_SET_REG.q(temp1,LLIL_OR.q(LLIL_REG.q(temp1),LLIL_LSL.q(LLIL_REG.q(temp1),LLIL_CONST.b(0x10)))); '
     'LLIL_SET_REG.o($t0,LLIL_OR.o(LLIL_REG.q(temp0),LLIL_LSL.o(LLIL_REG.q(temp1),LLIL_CONST.b(0x40)))); '
     'LLIL_JUMP(LLIL_REG.d(temp2))'),
]


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


def instruction_pair_to_il(data, arch_name):
    arch = binaryninja.Architecture[arch_name]
    il = lowlevelil.LowLevelILFunction(arch)
    arch.get_instruction_low_level_il(data, 0, il)
    il.finalize()
    return '; '.join(il2str(il[i]) for i in range(len(il)))


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


def run_tests(cases, lift):
    for test_i, (arch_name, data, expected) in enumerate(cases):
        if '?' in expected:
            fail_test(
                'INVALID EXPECTED LLIL AT TEST %d!\n\t   arch: %s\n\t   input: %s\n\texpected: %s'
                % (test_i, arch_name, data.hex(), expected))

        actual = lift(data, arch_name)
        if '?' in actual:
            fail_test(
                'INVALID ACTUAL LLIL AT TEST %d!\n\t   arch: %s\n\t   input: %s\n\t  actual: %s\n\t    tree:\n%s'
                % (test_i, arch_name, data.hex(), actual, il_str_to_tree(actual)))

        if actual != expected:
            fail_test(
                'MISMATCH AT TEST %d!\n\t   arch: %s\n\t   input: %s\n\texpected: %s\n\t  actual: %s\n\t    tree:\n%s'
                % (test_i, arch_name, data.hex(), expected, actual, il_str_to_tree(actual)))


def run_all_tests():
    run_tests(test_cases, instr_to_il)
    run_tests(terminating_test_cases, instruction_pair_to_il)


def test_all():
    run_all_tests()


if __name__ == '__main__':
    run_all_tests()
    print('success!')
    sys.exit(0)

if __name__ == 'test_lifting':
    test_all()
    print('success!')
