#!/usr/bin/env python3

import os
import re
import sys
import pathlib

import binaryninja
from binaryninja import binaryview
from binaryninja import lowlevelil
from binaryninja.enums import LowLevelILOperation, ILInstructionAttribute

path_here = pathlib.Path(__file__).parent.absolute()
path_il_h = os.path.join(path_here, 'il.h')

ATTR_PTR_AUTH = ILInstructionAttribute(16) # enum BNILInstructionAttribute.SrcInstructionUsesPointerAuth from api/binaryninjacore.h

tests_udf = [
    # udf #0
    (b'\x00\x00\x00\x00', 'LLIL_TRAP(0)'),
    # udf #1
    (b'\x01\x00\x00\x00', 'LLIL_TRAP(1)'),
]

# These instructions potentially use PAC, but we always lift them as if PAC is disabled.
tests_pac = [
    # BRANCHES
    # blr x12 (example of encoding: BLR_64_branch_reg)
    (b'\x80\x01\x3F\xD6', 'LLIL_CALL(LLIL_REG.q(x12))'),
    # blraaz x7 (example of encoding: BLRAAZ_64_branch_reg)
    (b'\xFF\x08\x3F\xD6', 'LLIL_CALL(LLIL_REG.q(x7))', ATTR_PTR_AUTH),
    # blraa xzr, sp (example of encoding: BLRAA_64P_branch_reg)
    (b'\xFF\x0B\x3F\xD7', 'LLIL_CALL(LLIL_CONST.q(0x0))', ATTR_PTR_AUTH),
    # blrabz x13 (example of encoding: BLRABZ_64_branch_reg)
    (b'\xBF\x0D\x3F\xD6', 'LLIL_CALL(LLIL_REG.q(x13))', ATTR_PTR_AUTH),
    # blrab x4, sp (example of encoding: BLRAB_64P_branch_reg)
    (b'\x9F\x0C\x3F\xD7', 'LLIL_CALL(LLIL_REG.q(x4))', ATTR_PTR_AUTH),
    # br x21 (example of encoding: BR_64_branch_reg)
    (b'\xA0\x02\x1F\xD6', 'LLIL_JUMP(LLIL_REG.q(x21))'),
    # braaz x7 (example of encoding: BRAAZ_64_branch_reg)
    (b'\xFF\x08\x1F\xD6', 'LLIL_JUMP(LLIL_REG.q(x7))', ATTR_PTR_AUTH),
    # braa x25, x5 (example of encoding: BRAA_64P_branch_reg)
    (b'\x25\x0B\x1F\xD7', 'LLIL_JUMP(LLIL_REG.q(x25))', ATTR_PTR_AUTH),
    # brabz x6 (example of encoding: BRABZ_64_branch_reg)
    (b'\xDF\x0C\x1F\xD6', 'LLIL_JUMP(LLIL_REG.q(x6))', ATTR_PTR_AUTH),
    # brab x23, x17 (example of encoding: BRAB_64P_branch_reg)
    (b'\xF1\x0E\x1F\xD7', 'LLIL_JUMP(LLIL_REG.q(x23))', ATTR_PTR_AUTH),

    # EXCEPTION RETURN
    # eret (example of encoding: ERET_64E_branch_reg)
    (b'\xE0\x03\x9F\xD6', 'LLIL_INTRINSIC([],_eret,[]); LLIL_TRAP(0)'),
    # eretaa (example of encoding: ERETAA_64E_branch_reg)
    (b'\xFF\x0B\x9F\xD6', 'LLIL_INTRINSIC([],_eret,[]); LLIL_TRAP(0)'),
    # eretab (example of encoding: ERETAB_64E_branch_reg)
    (b'\xFF\x0F\x9F\xD6', 'LLIL_INTRINSIC([],_eret,[]); LLIL_TRAP(0)'),

    # LOAD REGISTER WITH AUTHENTICATION (key A or B)
    # ldraa x7, [x30, #-0x6b0] (example of encoding: LDRAA_64_ldst_pac)
    (b'\xC7\xA7\x72\xF8', 'LLIL_SET_REG.q(x7,LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x30),LLIL_CONST.q(0xFFFFFFFFFFFFF950))))', ATTR_PTR_AUTH),
    # ldraa x7, [sp, #-0xf20]! (example of encoding: LDRAA_64W_ldst_pac)
    (b'\xE7\xCF\x61\xF8', 'LLIL_SET_REG.q(sp,LLIL_ADD.q(LLIL_REG.q(sp),LLIL_CONST.q(0xFFFFFFFFFFFFF0E0))); LLIL_SET_REG.q(x7,LLIL_LOAD.q(LLIL_REG.q(sp)))', ATTR_PTR_AUTH),
    # ldrab x27, [x17, #0x8d0] (example of encoding: LDRAB_64_ldst_pac)
    (b'\x3B\xA6\xB1\xF8', 'LLIL_SET_REG.q(x27,LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x17),LLIL_CONST.q(0x8D0))))', ATTR_PTR_AUTH),
    # ldrab x20, [x1, #0xac8]! (example of encoding: LDRAB_64W_ldst_pac)
    (b'\x34\x9C\xB5\xF8', 'LLIL_SET_REG.q(x1,LLIL_ADD.q(LLIL_REG.q(x1),LLIL_CONST.q(0xAC8))); LLIL_SET_REG.q(x20,LLIL_LOAD.q(LLIL_REG.q(x1)))', ATTR_PTR_AUTH),

    # RETURN
    # ret x27 (example of encoding: RET_64R_branch_reg)
    (b'\x60\x03\x5F\xD6', 'LLIL_RET(LLIL_REG.q(x27))'),

    # RETURN FROM SUBROUTINE, WITH POINTER AUTHENTICATION
    # retaa (example of encoding: RETAA_64E_branch_reg)
    (b'\xFF\x0B\x5F\xD6', 'LLIL_RET(LLIL_REG.q(x30))', ATTR_PTR_AUTH),
    # retab (example of encoding: RETAB_64E_branch_reg)
    (b'\xFF\x0F\x5F\xD6', 'LLIL_RET(LLIL_REG.q(x30))', ATTR_PTR_AUTH),

    # mixed instructions from old tests
    # BLRAA_64P_branch_reg 1101011100111111000010xxxxxxxxxx
    (b'\x14\x0B\x3F\xD7', 'LLIL_CALL(LLIL_REG.q(x24))', ATTR_PTR_AUTH), # blraa x24, x20
    (b'\xFD\x0A\x3F\xD7', 'LLIL_CALL(LLIL_REG.q(x23))', ATTR_PTR_AUTH), # blraa x23, x29
    # BLRAAZ_64_branch_reg 1101011000111111000010xxxxx11111
    (b'\xDF\x09\x3F\xD6', 'LLIL_CALL(LLIL_REG.q(x14))', ATTR_PTR_AUTH), # blraaz x14
    (b'\xDF\x08\x3F\xD6', 'LLIL_CALL(LLIL_REG.q(x6))', ATTR_PTR_AUTH), # blraaz x6
    # BLRAB_64P_branch_reg 1101011100111111000011xxxxxxxxxx
    (b'\xBA\x0C\x3F\xD7', 'LLIL_CALL(LLIL_REG.q(x5))', ATTR_PTR_AUTH), # blrab x5, x26
    (b'\xC2\x0E\x3F\xD7', 'LLIL_CALL(LLIL_REG.q(x22))', ATTR_PTR_AUTH), # blrab x22, x2
    # BLRABZ_64_branch_reg 1101011000111111000011xxxxx11111
    (b'\x3F\x0E\x3F\xD6', 'LLIL_CALL(LLIL_REG.q(x17))', ATTR_PTR_AUTH), # blrabz x17
    (b'\x3F\x0F\x3F\xD6', 'LLIL_CALL(LLIL_REG.q(x25))', ATTR_PTR_AUTH), # blrabz x25
    # BRAAZ_64_branch_reg 1101011000011111000010xxxxx11111
    (b'\x5F\x08\x1F\xD6', 'LLIL_JUMP(LLIL_REG.q(x2))', ATTR_PTR_AUTH), # braaz x2
    (b'\x5F\x0A\x1F\xD6', 'LLIL_JUMP(LLIL_REG.q(x18))', ATTR_PTR_AUTH), # braaz x18
    # BRAA_64P_branch_reg 1101011100011111000010xxxxxxxxxx
    (b'\x81\x08\x1F\xD7', 'LLIL_JUMP(LLIL_REG.q(x4))', ATTR_PTR_AUTH), # braa x4, x1
    (b'\x4C\x09\x1F\xD7', 'LLIL_JUMP(LLIL_REG.q(x10))', ATTR_PTR_AUTH), # braa x10, x12
    # BRABZ_64_branch_reg 1101011000011111000011xxxxx11111
    (b'\x3F\x0C\x1F\xD6', 'LLIL_JUMP(LLIL_REG.q(x1))', ATTR_PTR_AUTH), # brabz x1
    (b'\xBF\x0E\x1F\xD6', 'LLIL_JUMP(LLIL_REG.q(x21))', ATTR_PTR_AUTH), # brabz x21
    # BRAB_64P_branch_reg 1101011100011111000011xxxxxxxxxx
    (b'\x39\x0F\x1F\xD7', 'LLIL_JUMP(LLIL_REG.q(x25))', ATTR_PTR_AUTH), # brab x25, x25
    (b'\xA3\x0E\x1F\xD7', 'LLIL_JUMP(LLIL_REG.q(x21))', ATTR_PTR_AUTH), # brab x21, x3
    # LDRAA_64W_ldst_pac 111110000x1xxxxxxxxxxxxxxxxxxxxx
    (b'\xAE\x1D\x25\xF8', 'LLIL_SET_REG.q(x13,LLIL_ADD.q(LLIL_REG.q(x13),LLIL_CONST.q(0x288)));' + \
                        ' LLIL_SET_REG.q(x14,LLIL_LOAD.q(LLIL_REG.q(x13)))', ATTR_PTR_AUTH), # ldraa x14, [x13, #648]!
    (b'\x63\x6E\x62\xF8', 'LLIL_SET_REG.q(x19,LLIL_ADD.q(LLIL_REG.q(x19),LLIL_CONST.q(0xFFFFFFFFFFFFF130)));' + \
                        ' LLIL_SET_REG.q(x3,LLIL_LOAD.q(LLIL_REG.q(x19)))', ATTR_PTR_AUTH), # ldraa x3, [x19, #-3792]!
    # LDRAA_64_ldst_pac 111110000x1xxxxxxxxxxxxxxxxxxxxx
    (b'\x90\x15\x62\xF8', 'LLIL_SET_REG.q(x16,LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x12),LLIL_CONST.q(0xFFFFFFFFFFFFF108))))', ATTR_PTR_AUTH), # ldraa x16, [x12, #-3832]
    (b'\x52\x26\x73\xF8', 'LLIL_SET_REG.q(x18,LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x18),LLIL_CONST.q(0xFFFFFFFFFFFFF990))))', ATTR_PTR_AUTH), # ldraa x18, [x18, #-1648]
    # LDRAB_64W_ldst_pac 111110001x1xxxxxxxxx11xxxxxxxxxx
    (b'\x68\xDE\xB8\xF8', 'LLIL_SET_REG.q(x19,LLIL_ADD.q(LLIL_REG.q(x19),LLIL_CONST.q(0xC68)));' + \
                        ' LLIL_SET_REG.q(x8,LLIL_LOAD.q(LLIL_REG.q(x19)))', ATTR_PTR_AUTH), # ldrab x8, [x19, #3176]!
    (b'\x8D\x0D\xFF\xF8', 'LLIL_SET_REG.q(x12,LLIL_ADD.q(LLIL_REG.q(x12),LLIL_CONST.q(0xFFFFFFFFFFFFFF80)));' + \
                        ' LLIL_SET_REG.q(x13,LLIL_LOAD.q(LLIL_REG.q(x12)))', ATTR_PTR_AUTH), # ldrab x13, [x12, #-o]!
    # LDRAB_64_ldst_pac 111110001x1xxxxxxxxxxxxxxxxxxxxx
    (b'\x94\xF5\xA1\xF8', 'LLIL_SET_REG.q(x20,LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x12),LLIL_CONST.q(0xF8))))', ATTR_PTR_AUTH), # ldrab x20, [x12, #248]
    (b'\x2B\x35\xAA\xF8', 'LLIL_SET_REG.q(x11,LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x9),LLIL_CONST.q(0x518))))', ATTR_PTR_AUTH), # ldrab x11, [x9, #1304]
    (b'\x28\x1b\x02\x90', 'LLIL_SET_REG.q(x8,LLIL_CONST.q(0x4364000))'), # ldrsw   x8, 0x100008000
    # RETAA_64E_branch_reg 11010110010111110000101111111111
    (b'\xFF\x0B\x5F\xD6', 'LLIL_RET(LLIL_REG.q(x30))', ATTR_PTR_AUTH), # retaa
    # RETAB_64E_branch_reg 11010110010111110000111111111111
    (b'\xFF\x0F\x5F\xD6', 'LLIL_RET(LLIL_REG.q(x30))', ATTR_PTR_AUTH), # retab
]

# pac tests depend on whether the architecture is configured to lift them as
# intrinsics or as their non-authenticated counterparts
# see if the line "#define LIFT_PAC_AS_INTRINSIC 1" exists in il.h
if '#define LIFT_PAC_AS_INTRINSIC 1\n' in open(path_il_h).readlines():
    print('testing that select PAC instructions lift to intrinsics')
    tests_pac.extend([
    # AUTHENTICATE (VALIDATE CODE)
    # regex: autda[d|i]z?[a|b] where:
    # d means "data", i means "instruction"
    # z means modifier zero
    # a means "use key A", b means "use key B"
    # autda x22, x18 (example of encoding: AUTDA_64P_dp_1src)
    (b'\x56\x1A\xC1\xDA', 'LLIL_INTRINSIC([x22],__autda,[LLIL_REG.q(x22),LLIL_REG.q(x18)])'),
    # authenticate data address with modifier zero
    # autdza x1 (example of encoding: AUTDZA_64Z_dp_1src)
    (b'\xE1\x3B\xC1\xDA', 'LLIL_INTRINSIC([x1],__autda,[LLIL_REG.q(x1),LLIL_CONST.q(0x0)])'),
    # autdb x19, x3 (example of encoding: AUTDB_64P_dp_1src)
    (b'\x73\x1C\xC1\xDA', 'LLIL_INTRINSIC([x19],__autdb,[LLIL_REG.q(x19),LLIL_REG.q(x3)])'),
    # autdzb x1 (example of encoding: AUTDZB_64Z_dp_1src)
    (b'\xE1\x3F\xC1\xDA', 'LLIL_INTRINSIC([x1],__autdb,[LLIL_REG.q(x1),LLIL_CONST.q(0x0)])'),
    # autia x26, x9 (example of encoding: AUTIA_64P_dp_1src)
    (b'\x3A\x11\xC1\xDA', 'LLIL_INTRINSIC([x26],__autia,[LLIL_REG.q(x26),LLIL_REG.q(x9)])'),
    # autiza x30 (example of encoding: AUTIZA_64Z_dp_1src)
    (b'\xFE\x33\xC1\xDA', 'LLIL_INTRINSIC([x30],__autia,[LLIL_REG.q(x30),LLIL_CONST.q(0x0)])'),
    # autib x18, x21 (example of encoding: AUTIB_64P_dp_1src)
    (b'\xB2\x16\xC1\xDA', 'LLIL_INTRINSIC([x18],__autib,[LLIL_REG.q(x18),LLIL_REG.q(x21)])'),
    # autizb x17 (example of encoding: AUTIZB_64Z_dp_1src)
    (b'\xF1\x37\xC1\xDA', 'LLIL_INTRINSIC([x17],__autib,[LLIL_REG.q(x17),LLIL_CONST.q(0x0)])'),

    # SIGN (COMPUTE CODE)
    # regex: pac[d|i][z][a|b] where:
    # regex: autda[d|i]z?g?[a|b] where:
    # d means "data", i means "instruction"
    # z means modifier zero
    # g means "use generic key" (even if "a" follows)
    # a means "use key A", b means "use key B"
    # pacda x9, x21 (example of encoding: PACDA_64P_dp_1src)
    (b'\xA9\x0A\xC1\xDA', 'LLIL_INTRINSIC([x9],__pacda,[LLIL_REG.q(x9),LLIL_REG.q(x21)])'),
    # pacdza x5 (example of encoding: PACDZA_64Z_dp_1src)
    (b'\xE5\x2B\xC1\xDA', 'LLIL_INTRINSIC([x5],__pacda,[LLIL_REG.q(x5),LLIL_CONST.q(0x0)])'),
    # pacdb x14, x3 (example of encoding: PACDB_64P_dp_1src)
    (b'\x6E\x0C\xC1\xDA', 'LLIL_INTRINSIC([x14],__pacdb,[LLIL_REG.q(x14),LLIL_REG.q(x3)])'),
    # pacdzb x1 (example of encoding: PACDZB_64Z_dp_1src)
    (b'\xE1\x2F\xC1\xDA', 'LLIL_INTRINSIC([x1],__pacdb,[LLIL_REG.q(x1),LLIL_CONST.q(0x0)])'),
    # pacga x1, xzr, x12 (example of encoding: PACGA_64P_dp_2src)
    (b'\xE1\x33\xCC\x9A', 'LLIL_INTRINSIC([x1],__pacga,[LLIL_CONST.q(0x0),LLIL_REG.q(x12)])'),
    # pacia x6, x14 (example of encoding: PACIA_64P_dp_1src)
    (b'\xC6\x01\xC1\xDA', 'LLIL_INTRINSIC([x6],__pacia,[LLIL_REG.q(x6),LLIL_REG.q(x14)])'),
    # paciza x21 (example of encoding: PACIZA_64Z_dp_1src)
    (b'\xF5\x23\xC1\xDA', 'LLIL_INTRINSIC([x21],__pacia,[LLIL_REG.q(x21),LLIL_CONST.q(0x0)])'),
    # pacib x29, x4 (example of encoding: PACIB_64P_dp_1src)
    (b'\x9D\x04\xC1\xDA', 'LLIL_INTRINSIC([x29],__pacib,[LLIL_REG.q(x29),LLIL_REG.q(x4)])'),
    # pacizb x14 (example of encoding: PACIZB_64Z_dp_1src)
    (b'\xEE\x27\xC1\xDA', 'LLIL_INTRINSIC([x14],__pacib,[LLIL_REG.q(x14),LLIL_CONST.q(0x0)])'),

    # STRIP (REMOVE CODE WITHOUT AUTHENTICATION)
    # xpacd xzr (example of encoding: XPACD_64Z_dp_1src)
    (b'\xFF\x47\xC1\xDA', 'LLIL_INTRINSIC([xzr],__xpacd,[LLIL_CONST.q(0x0)])'),
    # xpaci x25 (example of encoding: XPACI_64Z_dp_1src)
    (b'\xF9\x43\xC1\xDA', 'LLIL_INTRINSIC([x25],__xpaci,[LLIL_REG.q(x25)])'),

    # mixed instructions from old tests
    # PACDA_64P_dp_1src 1101101011000001000010xxxxxxxxxx
    (b'\xAC\x0B\xC1\xDA', 'LLIL_INTRINSIC([x12],__pacda,[LLIL_REG.q(x12),LLIL_REG.q(x29)])'), # pacda x12, x29
    (b'\xD2\x09\xC1\xDA', 'LLIL_INTRINSIC([x18],__pacda,[LLIL_REG.q(x18),LLIL_REG.q(x14)])'), # pacda x18, x14
    # PACDB_64P_dp_1src 1101101011000001000011xxxxxxxxxx
    (b'\xF9\x0E\xC1\xDA', 'LLIL_INTRINSIC([x25],__pacdb,[LLIL_REG.q(x25),LLIL_REG.q(x23)])'), # pacdb x25, x23
    (b'\xBA\x0C\xC1\xDA', 'LLIL_INTRINSIC([x26],__pacdb,[LLIL_REG.q(x26),LLIL_REG.q(x5)])'), # pacdb x26, x5
    # PACDZA_64Z_dp_1src 110110101100000100101xxxxxxxxxxx
    (b'\xE7\x2B\xC1\xDA', 'LLIL_INTRINSIC([x7],__pacda,[LLIL_REG.q(x7),LLIL_CONST.q(0x0)])'), # pacdza x7
    (b'\xF7\x2B\xC1\xDA', 'LLIL_INTRINSIC([x23],__pacda,[LLIL_REG.q(x23),LLIL_CONST.q(0x0)])'), # pacdza x23
    # PACDZB_64Z_dp_1src 1101101011000001001xxxxxxxxxxxxx
    (b'\xE6\x2F\xC1\xDA', 'LLIL_INTRINSIC([x6],__pacdb,[LLIL_REG.q(x6),LLIL_CONST.q(0x0)])'), # pacdzb x6
    (b'\xE0\x2F\xC1\xDA', 'LLIL_INTRINSIC([x0],__pacdb,[LLIL_REG.q(x0),LLIL_CONST.q(0x0)])'), # pacdzb x0
    # PACGA_64P_dp_2src 10011010110xxxxx001100xxxxxxxxxx
    (b'\x22\x30\xCD\x9A', 'LLIL_INTRINSIC([x2],__pacga,[LLIL_REG.q(x1),LLIL_REG.q(x13)])'), # pacga x2, x1, x13
    (b'\x99\x32\xD3\x9A', 'LLIL_INTRINSIC([x25],__pacga,[LLIL_REG.q(x20),LLIL_REG.q(x19)])'), # pacga x25, x20, x19
    # PACIA1716_HI_hints 1101010100000011001000010xxxxxxx
    (b'\x1F\x21\x03\xD5', 'LLIL_INTRINSIC([x17],__pacia,[LLIL_REG.q(x17),LLIL_REG.q(x16)])'), # pacia1716
    # PACIAZ_HI_hints 11010101000000110010001100xxxxxx
    (b'\x1F\x23\x03\xD5', 'LLIL_INTRINSIC([x30],__pacia,[LLIL_REG.q(x30),LLIL_CONST.q(0x0)])'), # paciaz
    # PACIA_64P_dp_1src 1101101011000001000000xxxxxxxxxx
    (b'\x4A\x02\xC1\xDA', 'LLIL_INTRINSIC([x10],__pacia,[LLIL_REG.q(x10),LLIL_REG.q(x18)])'), # pacia x10, x18
    (b'\xAA\x00\xC1\xDA', 'LLIL_INTRINSIC([x10],__pacia,[LLIL_REG.q(x10),LLIL_REG.q(x5)])'), # pacia x10, x5
    # PACIB1716_HI_hints 110101010000001100100001xxxxxxxx
    (b'\x5F\x21\x03\xD5', 'LLIL_INTRINSIC([x17],__pacib,[LLIL_REG.q(x17),LLIL_REG.q(x16)])'), # pacib1716
    # PACIASP_HI_hints 1101010100000011001000110xxxxxxx
    # writes x30 (after PAC computation), reads sp for modifier
    (b'\x3F\x23\x03\xD5', 'LLIL_INTRINSIC([x30],__pacia,[LLIL_REG.q(x30),LLIL_REG.q(sp)])'), # paciasp
    # PACIBSP_HI_hints 110101010000001100100011xxxxxxxx
    (b'\x7F\x23\x03\xD5', 'LLIL_INTRINSIC([x30],__pacib,[LLIL_REG.q(x30),LLIL_REG.q(sp)])'), # pacibsp
    # PACIBZ_HI_hints 11010101000000110010001101xxxxxx
    (b'\x5F\x23\x03\xD5', 'LLIL_INTRINSIC([x30],__pacib,[LLIL_REG.q(x30),LLIL_CONST.q(0x0)])'), # pacibz
    # PACIB_64P_dp_1src 1101101011000001000001xxxxxxxxxx
    (b'\x84\x06\xC1\xDA', 'LLIL_INTRINSIC([x4],__pacib,[LLIL_REG.q(x4),LLIL_REG.q(x20)])'), # pacib x4, x20
    (b'\x61\x06\xC1\xDA', 'LLIL_INTRINSIC([x1],__pacib,[LLIL_REG.q(x1),LLIL_REG.q(x19)])'), # pacib x1, x19
    # PACIZA_64Z_dp_1src 110110101100000100100xxxxxxxxxxx
    (b'\xE3\x23\xC1\xDA', 'LLIL_INTRINSIC([x3],__pacia,[LLIL_REG.q(x3),LLIL_CONST.q(0x0)])'), # paciza x3
    (b'\xFE\x23\xC1\xDA', 'LLIL_INTRINSIC([x30],__pacia,[LLIL_REG.q(x30),LLIL_CONST.q(0x0)])'), # paciza x30
    # PACIZB_64Z_dp_1src 11011010110000010010xxxxxxxxxxxx
    (b'\xE3\x27\xC1\xDA', 'LLIL_INTRINSIC([x3],__pacib,[LLIL_REG.q(x3),LLIL_CONST.q(0x0)])'), # pacizb x3
    (b'\xE7\x27\xC1\xDA', 'LLIL_INTRINSIC([x7],__pacib,[LLIL_REG.q(x7),LLIL_CONST.q(0x0)])'), # pacizb x7
    # XPACD_64Z_dp_1src 110110101100000101000111111xxxxx
    (b'\xF8\x47\xC1\xDA', 'LLIL_INTRINSIC([x24],__xpacd,[LLIL_REG.q(x24)])'), # xpacd x24
    (b'\xED\x47\xC1\xDA', 'LLIL_INTRINSIC([x13],__xpacd,[LLIL_REG.q(x13)])'), # xpacd x13
    # XPACI_64Z_dp_1src 110110101100000101000xxxxxxxxxxx
    (b'\xE2\x43\xC1\xDA', 'LLIL_INTRINSIC([x2],__xpaci,[LLIL_REG.q(x2)])'), # xpaci x2
    (b'\xE7\x43\xC1\xDA', 'LLIL_INTRINSIC([x7],__xpaci,[LLIL_REG.q(x7)])'), # xpaci x7
    # XPACLRI_HI_hints 11010101000000110010000xxxxxxxxx
    (b'\xFF\x20\x03\xD5', 'LLIL_INTRINSIC([x30],__xpaci,[LLIL_REG.q(x30)])'), # xpaclri
    ])
# DO NOT LIFT PAC AS INTRINSIC
else:
    print('testing that select PAC instructions lift to NOP')
    tests_pac.extend([
    # In all these cases, we leave the target untouched.
    # Authenticate instructions normally modify the target, removing the code if authentication succeeds.
    (b'\x56\x1A\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH),
    (b'\xE1\x3B\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH),
    (b'\x73\x1C\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH),
    (b'\xE1\x3F\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH),
    (b'\x3A\x11\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH),
    (b'\xFE\x33\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH),
    (b'\xB2\x16\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH),
    (b'\xF1\x37\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH),
    # Sign instructions normally modify the target, adding a code.
    (b'\xA9\x0A\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH),
    (b'\xE5\x2B\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH),
    (b'\x6E\x0C\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH),
    (b'\xE1\x2F\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH),
    (b'\xE1\x33\xCC\x9A', 'LLIL_NOP()', ATTR_PTR_AUTH),
    (b'\xC6\x01\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH),
    (b'\xF5\x23\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH),
    (b'\x9D\x04\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH),
    (b'\xEE\x27\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH),
    # Strip instructions normally modify the target, removing the code without authentication.
    (b'\xFF\x47\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH),
    (b'\xF9\x43\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH),
    # mixed instructions from old tests
    (b'\xAC\x0B\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH), # pacda x12, x29
    (b'\xD2\x09\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH), # pacda x18, x14
    (b'\xF9\x0E\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH), # pacdb x25, x23
    (b'\xBA\x0C\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH), # pacdb x26, x5
    (b'\xE7\x2B\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH), # pacdza x7
    (b'\xF7\x2B\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH), # pacdza x23
    (b'\xE6\x2F\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH), # pacdzb x6
    (b'\xE0\x2F\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH), # pacdzb x0
    (b'\x22\x30\xCD\x9A', 'LLIL_NOP()', ATTR_PTR_AUTH), # pacga x2, x1, x13
    (b'\x99\x32\xD3\x9A', 'LLIL_NOP()', ATTR_PTR_AUTH), # pacga x25, x20, x19
    (b'\x1F\x21\x03\xD5', 'LLIL_NOP()', ATTR_PTR_AUTH), # pacia1716
    (b'\x1F\x23\x03\xD5', 'LLIL_NOP()', ATTR_PTR_AUTH), # paciaz
    (b'\x4A\x02\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH), # pacia x10, x18
    (b'\xAA\x00\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH), # pacia x10, x5
    (b'\x5F\x21\x03\xD5', 'LLIL_NOP()', ATTR_PTR_AUTH), # pacib1716
    (b'\x3F\x23\x03\xD5', 'LLIL_NOP()', ATTR_PTR_AUTH), # paciasp
    (b'\x7F\x23\x03\xD5', 'LLIL_NOP()', ATTR_PTR_AUTH), # pacibsp
    (b'\x5F\x23\x03\xD5', 'LLIL_NOP()', ATTR_PTR_AUTH), # pacibz
    (b'\x84\x06\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH), # pacib x4, x20
    (b'\x61\x06\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH), # pacib x1, x19
    (b'\xE3\x23\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH), # paciza x3
    (b'\xFE\x23\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH), # paciza x30
    (b'\xE3\x27\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH), # pacizb x3
    (b'\xE7\x27\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH), # pacizb x7
    (b'\xF8\x47\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH), # xpacd x24
    (b'\xED\x47\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH), # xpacd x13
    (b'\xE2\x43\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH), # xpaci x2
    (b'\xE7\x43\xC1\xDA', 'LLIL_NOP()', ATTR_PTR_AUTH), # xpaci x7
    (b'\xFF\x20\x03\xD5', 'LLIL_NOP()', ATTR_PTR_AUTH), # xpaclri
    ])

tests_load_acquire_store_release = [
    # LDAPURB <Wt>, [<Xn|SP>{, #<simm>}]
    (b'\xBE\xE3\x53\x19', 'LLIL_SET_REG.d(w30,LLIL_ZX.d(LLIL_LOAD.b(LLIL_ADD.q(LLIL_REG.q(x29),LLIL_CONST.q(0xFFFFFFFFFFFFFF3E)))))'), # ldapurb w30, [x29, #-0xc2]
    (b'\x7C\xB3\x5E\x19', 'LLIL_SET_REG.d(w28,LLIL_ZX.d(LLIL_LOAD.b(LLIL_ADD.q(LLIL_REG.q(x27),LLIL_CONST.q(0xFFFFFFFFFFFFFFEB)))))'), # ldapurb w28, [x27, #-0x15]
    (b'\x2D\x62\x59\x19', 'LLIL_SET_REG.d(w13,LLIL_ZX.d(LLIL_LOAD.b(LLIL_ADD.q(LLIL_REG.q(x17),LLIL_CONST.q(0xFFFFFFFFFFFFFF96)))))'), # ldapurb w13, [x17, #-0x6a]
    (b'\xE1\x01\x45\x19', 'LLIL_SET_REG.d(w1,LLIL_ZX.d(LLIL_LOAD.b(LLIL_ADD.q(LLIL_REG.q(x15),LLIL_CONST.q(0x50)))))'), # ldapurb w1, [x15, #0x50]
    # LDAPURSB <Wt>, [<Xn|SP>{, #<simm>}]
    (b'\x7F\xC1\xD5\x19', 'LLIL_SX.d(LLIL_LOAD.b(LLIL_ADD.q(LLIL_REG.q(x11),LLIL_CONST.q(0xFFFFFFFFFFFFFF5C))))'), # ldapursb wzr, [x11, #-0xa4]
    (b'\x5E\x03\xD7\x19', 'LLIL_SET_REG.d(w30,LLIL_SX.d(LLIL_LOAD.b(LLIL_ADD.q(LLIL_REG.q(x26),LLIL_CONST.q(0xFFFFFFFFFFFFFF70)))))'), # ldapursb w30, [x26, #-0x90]
    (b'\xE0\x82\xD2\x19', 'LLIL_SET_REG.d(w0,LLIL_SX.d(LLIL_LOAD.b(LLIL_ADD.q(LLIL_REG.q(x23),LLIL_CONST.q(0xFFFFFFFFFFFFFF28)))))'), # ldapursb w0, [x23, #-0xd8]
    (b'\xAF\x70\xD3\x19', 'LLIL_SET_REG.d(w15,LLIL_SX.d(LLIL_LOAD.b(LLIL_ADD.q(LLIL_REG.q(x5),LLIL_CONST.q(0xFFFFFFFFFFFFFF37)))))'), # ldapursb w15, [x5, #-0xc9]
    # LDAPURSB <Xt>, [<Xn|SP>{, #<simm>}]
    (b'\x00\x72\x9D\x19', 'LLIL_SET_REG.q(x0,LLIL_SX.q(LLIL_LOAD.b(LLIL_ADD.q(LLIL_REG.q(x16),LLIL_CONST.q(0xFFFFFFFFFFFFFFD7)))))'), # ldapursb x0, [x16, #-0x29]
    (b'\xB0\x40\x8A\x19', 'LLIL_SET_REG.q(x16,LLIL_SX.q(LLIL_LOAD.b(LLIL_ADD.q(LLIL_REG.q(x5),LLIL_CONST.q(0xA4)))))'), # ldapursb x16, [x5, #0xa4]
    (b'\x9E\xC2\x84\x19', 'LLIL_SET_REG.q(x30,LLIL_SX.q(LLIL_LOAD.b(LLIL_ADD.q(LLIL_REG.q(x20),LLIL_CONST.q(0x4C)))))'), # ldapursb x30, [x20, #0x4c]
    (b'\x2B\x63\x81\x19', 'LLIL_SET_REG.q(x11,LLIL_SX.q(LLIL_LOAD.b(LLIL_ADD.q(LLIL_REG.q(x25),LLIL_CONST.q(0x16)))))'), # ldapursb x11, [x25, #0x16]
    # LDAPURH <Wt>, [<Xn|SP>{, #<simm>}]
    (b'\x21\x72\x40\x59', 'LLIL_SET_REG.d(w1,LLIL_ZX.d(LLIL_LOAD.w(LLIL_ADD.q(LLIL_REG.q(x17),LLIL_CONST.q(0x7)))))'), # ldapurh w1, [x17, #0x7]
    (b'\xAB\xD2\x48\x59', 'LLIL_SET_REG.d(w11,LLIL_ZX.d(LLIL_LOAD.w(LLIL_ADD.q(LLIL_REG.q(x21),LLIL_CONST.q(0x8D)))))'), # ldapurh w11, [x21, #0x8d]
    (b'\x0E\xB0\x54\x59', 'LLIL_SET_REG.d(w14,LLIL_ZX.d(LLIL_LOAD.w(LLIL_ADD.q(LLIL_REG.q(x0),LLIL_CONST.q(0xFFFFFFFFFFFFFF4B)))))'), # ldapurh w14, [x0, #-0xb5]
    (b'\x76\x50\x4A\x59', 'LLIL_SET_REG.d(w22,LLIL_ZX.d(LLIL_LOAD.w(LLIL_ADD.q(LLIL_REG.q(x3),LLIL_CONST.q(0xA5)))))'), # ldapurh w22, [x3, #0xa5]
    # LDAPURSH <Wt>, [<Xn|SP>{, #<simm>}]
    (b'\xA1\x81\xC2\x59', 'LLIL_SET_REG.d(w1,LLIL_SX.d(LLIL_LOAD.w(LLIL_ADD.q(LLIL_REG.q(x13),LLIL_CONST.q(0x28)))))'), # ldapursh w1, [x13, #0x28]
    (b'\x7D\x60\xC3\x59', 'LLIL_SET_REG.d(w29,LLIL_SX.d(LLIL_LOAD.w(LLIL_ADD.q(LLIL_REG.q(x3),LLIL_CONST.q(0x36)))))'), # ldapursh w29, [x3, #0x36]
    (b'\x5C\xD1\xDF\x59', 'LLIL_SET_REG.d(w28,LLIL_SX.d(LLIL_LOAD.w(LLIL_ADD.q(LLIL_REG.q(x10),LLIL_CONST.q(0xFFFFFFFFFFFFFFFD)))))'), # ldapursh w28, [x10, #-0x3]
    (b'\x6B\x42\xC0\x59', 'LLIL_SET_REG.d(w11,LLIL_SX.d(LLIL_LOAD.w(LLIL_ADD.q(LLIL_REG.q(x19),LLIL_CONST.q(0x4)))))'), # ldapursh w11, [x19, #0x4]
    # LDAPURSH <Xt>, [<Xn|SP>{, #<simm>}]
    (b'\x17\xB1\x8C\x59', 'LLIL_SET_REG.q(x23,LLIL_SX.q(LLIL_LOAD.w(LLIL_ADD.q(LLIL_REG.q(x8),LLIL_CONST.q(0xCB)))))'), # ldapursh x23, [x8, #0xcb]
    (b'\xC0\xE3\x89\x59', 'LLIL_SET_REG.q(x0,LLIL_SX.q(LLIL_LOAD.w(LLIL_ADD.q(LLIL_REG.q(x30),LLIL_CONST.q(0x9E)))))'), # ldapursh x0, [x30, #0x9e]
    (b'\x19\x01\x91\x59', 'LLIL_SET_REG.q(x25,LLIL_SX.q(LLIL_LOAD.w(LLIL_ADD.q(LLIL_REG.q(x8),LLIL_CONST.q(0xFFFFFFFFFFFFFF10)))))'), # ldapursh x25, [x8, #-0xf0]
    (b'\x4F\xE1\x8D\x59', 'LLIL_SET_REG.q(x15,LLIL_SX.q(LLIL_LOAD.w(LLIL_ADD.q(LLIL_REG.q(x10),LLIL_CONST.q(0xDE)))))'), # ldapursh x15, [x10, #0xde]
    # LDAPURSW <Xt>, [<Xn|SP>{, #<simm>}]
    (b'\x1D\xA1\x80\x99', 'LLIL_SET_REG.q(x29,LLIL_SX.q(LLIL_LOAD.d(LLIL_ADD.q(LLIL_REG.q(x8),LLIL_CONST.q(0xA)))))'), # ldapursw x29, [x8, #0xa]
    (b'\xD8\xD2\x83\x99', 'LLIL_SET_REG.q(x24,LLIL_SX.q(LLIL_LOAD.d(LLIL_ADD.q(LLIL_REG.q(x22),LLIL_CONST.q(0x3D)))))'), # ldapursw x24, [x22, #0x3d]
    (b'\xBA\xD2\x9E\x99', 'LLIL_SET_REG.q(x26,LLIL_SX.q(LLIL_LOAD.d(LLIL_ADD.q(LLIL_REG.q(x21),LLIL_CONST.q(0xFFFFFFFFFFFFFFED)))))'), # ldapursw x26, [x21, #-0x13]
    (b'\x45\x43\x89\x99', 'LLIL_SET_REG.q(x5,LLIL_SX.q(LLIL_LOAD.d(LLIL_ADD.q(LLIL_REG.q(x26),LLIL_CONST.q(0x94)))))'), # ldapursw x5, [x26, #0x94]
    # LDAPR <Wt>, [<Xn|SP>{,#0}]
    (b'\x11\xC0\xBF\xB8', 'LLIL_SET_REG.d(w17,LLIL_LOAD.d(LLIL_REG.q(x0)))'), # ldapr w17, [x0]
    (b'\x24\xC3\xBF\xB8', 'LLIL_SET_REG.d(w4,LLIL_LOAD.d(LLIL_REG.q(x25)))'), # ldapr w4, [x25]
    (b'\x49\xC3\xBF\xB8', 'LLIL_SET_REG.d(w9,LLIL_LOAD.d(LLIL_REG.q(x26)))'), # ldapr w9, [x26]
    (b'\x3F\xC0\xBF\xB8', 'LLIL_LOAD.d(LLIL_REG.q(x1))'), # ldapr wzr, [x1]
    # LDAPR <Xt>, [<Xn|SP>{,#0}]
    (b'\x08\xC3\xBF\xF8', 'LLIL_SET_REG.q(x8,LLIL_LOAD.q(LLIL_REG.q(x24)))'), # ldapr x8, [x24]
    (b'\x25\xC3\xBF\xF8', 'LLIL_SET_REG.q(x5,LLIL_LOAD.q(LLIL_REG.q(x25)))'), # ldapr x5, [x25]
    (b'\x6D\xC2\xBF\xF8', 'LLIL_SET_REG.q(x13,LLIL_LOAD.q(LLIL_REG.q(x19)))'), # ldapr x13, [x19]
    (b'\xD6\xC0\xBF\xF8', 'LLIL_SET_REG.q(x22,LLIL_LOAD.q(LLIL_REG.q(x6)))'), # ldapr x22, [x6]
    # LDAPRB <Wt>, [<Xn|SP>{,#0}]
    (b'\x80\xC3\xBF\x38', 'LLIL_SET_REG.d(w0,LLIL_ZX.d(LLIL_LOAD.b(LLIL_REG.q(x28))))'), # ldaprb w0, [x28]
    (b'\x5C\xC2\xBF\x38', 'LLIL_SET_REG.d(w28,LLIL_ZX.d(LLIL_LOAD.b(LLIL_REG.q(x18))))'), # ldaprb w28, [x18]
    (b'\x05\xC3\xBF\x38', 'LLIL_SET_REG.d(w5,LLIL_ZX.d(LLIL_LOAD.b(LLIL_REG.q(x24))))'), # ldaprb w5, [x24]
    (b'\x61\xC2\xBF\x38', 'LLIL_SET_REG.d(w1,LLIL_ZX.d(LLIL_LOAD.b(LLIL_REG.q(x19))))'), # ldaprb w1, [x19]
    # LDAPRH <Wt>, [<Xn|SP>{,#0}]
    (b'\x6B\xC0\xBF\x78', 'LLIL_SET_REG.d(w11,LLIL_ZX.d(LLIL_LOAD.w(LLIL_REG.q(x3))))'), # ldaprh w11, [x3]
    (b'\x02\xC3\xBF\x78', 'LLIL_SET_REG.d(w2,LLIL_ZX.d(LLIL_LOAD.w(LLIL_REG.q(x24))))'), # ldaprh w2, [x24]
    (b'\xE0\xC2\xBF\x78', 'LLIL_SET_REG.d(w0,LLIL_ZX.d(LLIL_LOAD.w(LLIL_REG.q(x23))))'), # ldaprh w0, [x23]
    (b'\x2B\xC3\xBF\x78', 'LLIL_SET_REG.d(w11,LLIL_ZX.d(LLIL_LOAD.w(LLIL_REG.q(x25))))'), # ldaprh w11, [x25]
    # STLUR <Wt>, [<Xn|SP>{, #<simm>}]
    (b'\x62\xD0\x14\x99', 'LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x3),LLIL_CONST.q(0xFFFFFFFFFFFFFF4D)),LLIL_REG.d(w2))'), # stlur w2, [x3, #-0xb3]
    (b'\x2D\x71\x05\x99', 'LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x9),LLIL_CONST.q(0x57)),LLIL_REG.d(w13))'), # stlur w13, [x9, #0x57]
    (b'\xC4\x03\x01\x99', 'LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x30),LLIL_CONST.q(0x10)),LLIL_REG.d(w4))'), # stlur w4, [x30, #0x10]
    (b'\x46\x91\x1B\x99', 'LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x10),LLIL_CONST.q(0xFFFFFFFFFFFFFFB9)),LLIL_REG.d(w6))'), # stlur w6, [x10, #-0x47]
    # STLUR <Xt>, [<Xn|SP>{, #<simm>}]
    (b'\x5C\x52\x0A\xD9', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x18),LLIL_CONST.q(0xA5)),LLIL_REG.q(x28))'), # stlur x28, [x18, #0xa5]
    (b'\x0D\x63\x09\xD9', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x24),LLIL_CONST.q(0x96)),LLIL_REG.q(x13))'), # stlur x13, [x24, #0x96]
    (b'\xF6\x92\x14\xD9', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x23),LLIL_CONST.q(0xFFFFFFFFFFFFFF49)),LLIL_REG.q(x22))'), # stlur x22, [x23, #-0xb7]
    (b'\xD5\x20\x01\xD9', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x6),LLIL_CONST.q(0x12)),LLIL_REG.q(x21))'), # stlur x21, [x6, #0x12]
    # STLURB <Wt>, [<Xn|SP>{, #<simm>}]
    (b'\x29\xF2\x0C\x19', 'LLIL_STORE.b(LLIL_ADD.q(LLIL_REG.q(x17),LLIL_CONST.q(0xCF)),LLIL_LOW_PART.b(LLIL_REG.d(w9)))'), # stlurb w9, [x17, #0xcf]
    (b'\x76\xA2\x10\x19', 'LLIL_STORE.b(LLIL_ADD.q(LLIL_REG.q(x19),LLIL_CONST.q(0xFFFFFFFFFFFFFF0A)),LLIL_LOW_PART.b(LLIL_REG.d(w22)))'), # stlurb w22, [x19, #-0xf6]
    (b'\x0B\xA0\x10\x19', 'LLIL_STORE.b(LLIL_ADD.q(LLIL_REG.q(x0),LLIL_CONST.q(0xFFFFFFFFFFFFFF0A)),LLIL_LOW_PART.b(LLIL_REG.d(w11)))'), # stlurb w11, [x0, #-0xf6]
    (b'\xF0\xE3\x0D\x19', 'LLIL_STORE.b(LLIL_ADD.q(LLIL_REG.q(sp),LLIL_CONST.q(0xDE)),LLIL_LOW_PART.b(LLIL_REG.d(w16)))'), # stlurb w16, [sp, #0xde]
    # STLURH <Wt>, [<Xn|SP>{, #<simm>}]
    (b'\xE2\x51\x0E\x59', 'LLIL_STORE.w(LLIL_ADD.q(LLIL_REG.q(x15),LLIL_CONST.q(0xE5)),LLIL_LOW_PART.w(LLIL_REG.d(w2)))'), # stlurh w2, [x15, #0xe5]
    (b'\x4E\x33\x12\x59', 'LLIL_STORE.w(LLIL_ADD.q(LLIL_REG.q(x26),LLIL_CONST.q(0xFFFFFFFFFFFFFF23)),LLIL_LOW_PART.w(LLIL_REG.d(w14)))'), # stlurh w14, [x26, #-0xdd]
    (b'\xBA\x83\x1B\x59', 'LLIL_STORE.w(LLIL_ADD.q(LLIL_REG.q(x29),LLIL_CONST.q(0xFFFFFFFFFFFFFFB8)),LLIL_LOW_PART.w(LLIL_REG.d(w26)))'), # stlurh w26, [x29, #-0x48]
    (b'\x61\xB3\x01\x59', 'LLIL_STORE.w(LLIL_ADD.q(LLIL_REG.q(x27),LLIL_CONST.q(0x1B)),LLIL_LOW_PART.w(LLIL_REG.d(w1)))'), # stlurh w1, [x27, #0x1b]
    # LDAPUR <Wt>, [<Xn|SP>{, #<simm>}]
    (b'\xD9\x51\x59\x99', 'LLIL_SET_REG.d(w25,LLIL_LOAD.d(LLIL_ADD.q(LLIL_REG.q(x14),LLIL_CONST.q(0xFFFFFFFFFFFFFF95))))'), # ldapur w25, [x14, #-0x6b]
    (b'\x38\xC1\x58\x99', 'LLIL_SET_REG.d(w24,LLIL_LOAD.d(LLIL_ADD.q(LLIL_REG.q(x9),LLIL_CONST.q(0xFFFFFFFFFFFFFF8C))))'), # ldapur w24, [x9, #-0x74]
    (b'\xB3\x42\x54\x99', 'LLIL_SET_REG.d(w19,LLIL_LOAD.d(LLIL_ADD.q(LLIL_REG.q(x21),LLIL_CONST.q(0xFFFFFFFFFFFFFF44))))'), # ldapur w19, [x21, #-0xbc]
    (b'\x2A\x01\x56\x99', 'LLIL_SET_REG.d(w10,LLIL_LOAD.d(LLIL_ADD.q(LLIL_REG.q(x9),LLIL_CONST.q(0xFFFFFFFFFFFFFF60))))'), # ldapur w10, [x9, #-0xa0]
    # LDAPUR <Xt>, [<Xn|SP>{, #<simm>}]
    (b'\x51\x52\x5B\xD9', 'LLIL_SET_REG.q(x17,LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x18),LLIL_CONST.q(0xFFFFFFFFFFFFFFB5))))'), # ldapur x17, [x18, #-0x4b]
    (b'\x71\x30\x56\xD9', 'LLIL_SET_REG.q(x17,LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x3),LLIL_CONST.q(0xFFFFFFFFFFFFFF63))))'), # ldapur x17, [x3, #-0x9d]
    (b'\x6C\x00\x4C\xD9', 'LLIL_SET_REG.q(x12,LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x3),LLIL_CONST.q(0xC0))))'), # ldapur x12, [x3, #0xc0]
    (b'\xD4\x82\x43\xD9', 'LLIL_SET_REG.q(x20,LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x22),LLIL_CONST.q(0x38))))') # ldapur x20, [x22, #0x38]
]

tests_movk = [
    (b'\xe9\xae\xb7\xf2', 'LLIL_SET_REG.q(x9,LLIL_AND.q(LLIL_REG.q(x9),LLIL_NOT.q(LLIL_CONST.q(0xFFFF0000)))); LLIL_SET_REG.q(x9,LLIL_OR.q(LLIL_REG.q(x9),LLIL_CONST.q(0xBD770000)))'), # movk    x9, #0xbd77, lsl #0x10
]

tests_mvni = [
    (b'\xe2\x05\x01\x6f', 'LLIL_SET_REG.o(v2,LLIL_NOT.o(LLIL_CONST.o(0x2F)))'), # mvni    v2.4s, #0x2f
]

# https://github.com/Vector35/binaryninja-api/issues/2791
tests_2791 = [
    (b'\x00\x20\x21\x1e', 'LLIL_FSUB.d{f*}(LLIL_REG.d(s0),LLIL_REG.d(s1))'), # fcmp s0, s1
]

tests_ucvtf = [
    # msr, mrs with unnamed (implementation specific) sysregs
    (b'\x2B\x19\x1B\xD5', 'LLIL_INTRINSIC([sysreg_unknown],_WriteStatusReg,[LLIL_REG.q(x11)])'), # msr s3_3_c1_c9_1, x11
    (b'\xEE\x47\x1E\xD5', 'LLIL_INTRINSIC([sysreg_unknown],_WriteStatusReg,[LLIL_REG.q(x14)])'), # msr s3_6_c4_c7_7, x14
    (b'\x39\xB5\x15\xD5', 'LLIL_INTRINSIC([sysreg_unknown],_WriteStatusReg,[LLIL_REG.q(x25)])'), # msr s2_5_c11_c5_1, x25
    (b'\x87\xBF\x11\xD5', 'LLIL_INTRINSIC([sysreg_unknown],_WriteStatusReg,[LLIL_REG.q(x7)])'), # msr s2_1_c11_c15_4, x7
    (b'\x3E\x53\x39\xD5', 'LLIL_INTRINSIC([x30],_ReadStatusReg,[LLIL_REG.q(sysreg_unknown)])'), # mrs x30, s3_1_c5_c3_1
    (b'\x5D\x93\x3C\xD5', 'LLIL_INTRINSIC([x29],_ReadStatusReg,[LLIL_REG.q(sysreg_unknown)])'), # mrs x29, s3_4_c9_c3_2
    (b'\x30\x0E\x34\xD5', 'LLIL_INTRINSIC([x16],_ReadStatusReg,[LLIL_REG.q(sysreg_unknown)])'), # mrs x16, s2_4_c0_c14_1
    (b'\x3A\x8E\x33\xD5', 'LLIL_INTRINSIC([x26],_ReadStatusReg,[LLIL_REG.q(sysreg_unknown)])'), # mrs x26, s2_3_c8_c14_1
    # msr, mrs with named sysregs
    (b'\x36\xE2\x1C\xD5', 'LLIL_INTRINSIC([cnthp_ctl_el2],_WriteStatusReg,[LLIL_REG.q(x22)])'), # msr cnthp_ctl_el2, x22
    (b'\xF4\xEA\x1B\xD5', 'LLIL_INTRINSIC([pmevcntr23_el0],_WriteStatusReg,[LLIL_REG.q(x20)])'), # msr pmevcntr23_el0, x20
    (b'\x05\xE1\x18\xD5', 'LLIL_INTRINSIC([cntkctl_el1],_WriteStatusReg,[LLIL_REG.q(x5)])'), # msr cntkctl_el1, x5
    (b'\x00\xE2\x1D\xD5', 'LLIL_INTRINSIC([cntp_tval_el02],_WriteStatusReg,[LLIL_REG.q(x0)])'), # msr cntp_tval_el02, x
    (b'\xF9\x20\x31\xD5', 'LLIL_INTRINSIC([x25],_ReadStatusReg,[LLIL_REG(trcdvcmr4)])'), # mrs x25, trcdvcmr4
    (b'\x4D\xC9\x3C\xD5', 'LLIL_INTRINSIC([x13],_ReadStatusReg,[LLIL_REG(ich_ap1r2_el2)])'), # mrs x13, ich_ap1r2_el2
    (b'\xC4\xC8\x38\xD5', 'LLIL_INTRINSIC([x4],_ReadStatusReg,[LLIL_REG(icc_ap0r2_el1)])'), # mrs x4, icc_ap0r2_el1
    (b'\x80\x10\x30\xD5', 'LLIL_INTRINSIC([x0],_ReadStatusReg,[LLIL_REG(oslar_el1)])'), # mrs x0, oslar_el1
    # when same input/output register, encoding is UCVTF_asisdmisc_R
    # ucvtf s16, s7                                          UCVTF_asisdmisc_R
    (b'\xF0\xD8\x21\x7E', 'LLIL_INTRINSIC([s16],vcvts_f32_u32,[LLIL_REG.d(s7)])'),
    # ucvtf d26, d30                                         UCVTF_asisdmisc_R
    (b'\xDA\xDB\x61\x7E', 'LLIL_INTRINSIC([d26],vcvt_f64_u64,[LLIL_REG.q(d30)])'),
    # ucvtf s6, s19                                          UCVTF_asisdmisc_R
    (b'\x66\xDA\x21\x7E', 'LLIL_INTRINSIC([s6],vcvts_f32_u32,[LLIL_REG.d(s19)])'),
    # ucvtf s13, s0                                          UCVTF_asisdmisc_R
    (b'\x0D\xD8\x21\x7E', 'LLIL_INTRINSIC([s13],vcvts_f32_u32,[LLIL_REG.d(s0)])'),
    # ucvtf d28, d26                                         UCVTF_asisdmisc_R
    (b'\x5C\xDB\x61\x7E', 'LLIL_INTRINSIC([d28],vcvt_f64_u64,[LLIL_REG.q(d26)])'),
    # ucvtf d25, d11                                         UCVTF_asisdmisc_R
    (b'\x79\xD9\x61\x7E', 'LLIL_INTRINSIC([d25],vcvt_f64_u64,[LLIL_REG.q(d11)])'),
    # ucvtf d24, d21                                         UCVTF_asisdmisc_R
    (b'\xB8\xDA\x61\x7E', 'LLIL_INTRINSIC([d24],vcvt_f64_u64,[LLIL_REG.q(d21)])'),
    # ucvtf s7, s18                                          UCVTF_asisdmisc_R
    (b'\x47\xDA\x21\x7E', 'LLIL_INTRINSIC([s7],vcvts_f32_u32,[LLIL_REG.d(s18)])'),
    # when 16-bit reg, needs FP16 extension and encoding name breaks convention
    # ucvtf h30, h0                                          UCVTF_asisdmiscfp16_R
    (b'\x1E\xD8\x79\x7E', 'LLIL_INTRINSIC([h30],vcvth_f16_u16,[LLIL_REG.w(h0)])'),
    # ucvtf h22, h6                                          UCVTF_asisdmiscfp16_R
    (b'\xD6\xD8\x79\x7E', 'LLIL_INTRINSIC([h22],vcvth_f16_u16,[LLIL_REG.w(h6)])'),
    # ucvtf h7, h2                                           UCVTF_asisdmiscfp16_R
    (b'\x47\xD8\x79\x7E', 'LLIL_INTRINSIC([h7],vcvth_f16_u16,[LLIL_REG.w(h2)])'),
    # ucvtf h24, h18                                         UCVTF_asisdmiscfp16_R
    (b'\x58\xDA\x79\x7E', 'LLIL_INTRINSIC([h24],vcvth_f16_u16,[LLIL_REG.w(h18)])'),
    # ucvtf h8, h21                                          UCVTF_asisdmiscfp16_R
    # 64-bit GPR to 64-bit FP
    # ucvtf d30, x19                                         UCVTF_D64_float2int
    (b'\x7E\x02\x63\x9E', 'LLIL_INTRINSIC([d30],vcvt_f64_u64,[LLIL_REG.q(x19)])'),
    # ucvtf d10, x28                                         UCVTF_D64_float2int
    (b'\x8A\x03\x63\x9E', 'LLIL_INTRINSIC([d10],vcvt_f64_u64,[LLIL_REG.q(x28)])'),
    # ucvtf d16, x21                                         UCVTF_D64_float2int
    (b'\xB0\x02\x63\x9E', 'LLIL_INTRINSIC([d16],vcvt_f64_u64,[LLIL_REG.q(x21)])'),
    # ucvtf d18, x24                                         UCVTF_D64_float2int
    (b'\x12\x03\x63\x9E', 'LLIL_INTRINSIC([d18],vcvt_f64_u64,[LLIL_REG.q(x24)])'),
    # 64-bit GPR to 32-bit FP
    # ucvtf s29, x5                                          UCVTF_S64_float2int
    (b'\xBD\x00\x23\x9E', 'LLIL_INTRINSIC([s29],vcvth_f16_u16,[LLIL_REG.q(x5)])'),
    # ucvtf s23, x8                                          UCVTF_S64_float2int
    (b'\x17\x01\x23\x9E', 'LLIL_INTRINSIC([s23],vcvth_f16_u16,[LLIL_REG.q(x8)])'),
    # ucvtf s22, x14                                         UCVTF_S64_float2int
    (b'\xD6\x01\x23\x9E', 'LLIL_INTRINSIC([s22],vcvth_f16_u16,[LLIL_REG.q(x14)])'),
    # ucvtf s10, x11                                         UCVTF_S64_float2int
    (b'\x6A\x01\x23\x9E', 'LLIL_INTRINSIC([s10],vcvth_f16_u16,[LLIL_REG.q(x11)])'),
    # 64-bit GPR to 16-bit FP
    # ucvtf h3, x2                                           UCVTF_H64_float2int
    (b'\x43\x00\xE3\x9E', 'LLIL_INTRINSIC([h3],vcvth_f16_u64,[LLIL_REG.q(x2)])'),
    # ucvtf h18, x21                                         UCVTF_H64_float2int
    (b'\xB2\x02\xE3\x9E', 'LLIL_INTRINSIC([h18],vcvth_f16_u64,[LLIL_REG.q(x21)])'),
    # ucvtf h18, x7                                          UCVTF_H64_float2int
    (b'\xF2\x00\xE3\x9E', 'LLIL_INTRINSIC([h18],vcvth_f16_u64,[LLIL_REG.q(x7)])'),
    # ucvtf h27, x29                                         UCVTF_H64_float2int
    (b'\xBB\x03\xE3\x9E', 'LLIL_INTRINSIC([h27],vcvth_f16_u64,[LLIL_REG.q(x29)])'),
    # 32-bit GPR to 64-bit FP
    # ucvtf d0, w7                                           UCVTF_D32_float2int
    (b'\xE0\x00\x63\x1E', 'LLIL_INTRINSIC([d0],vcvt_f64_u32,[LLIL_REG.d(w7)])'),
    # ucvtf d19, w25                                         UCVTF_D32_float2int
    (b'\x33\x03\x63\x1E', 'LLIL_INTRINSIC([d19],vcvt_f64_u32,[LLIL_REG.d(w25)])'),
    # ucvtf d19, w5                                          UCVTF_D32_float2int
    (b'\xB3\x00\x63\x1E', 'LLIL_INTRINSIC([d19],vcvt_f64_u32,[LLIL_REG.d(w5)])'),
    # ucvtf d26, w16                                         UCVTF_D32_float2int
    (b'\x1A\x02\x63\x1E', 'LLIL_INTRINSIC([d26],vcvt_f64_u32,[LLIL_REG.d(w16)])'),
    # ucvtf d0, w7
    (b'\xE0\x00\x63\x1e', 'LLIL_INTRINSIC([d0],vcvt_f64_u32,[LLIL_REG.d(w7)])'),
    # 32-bit GPR to 64-bit FP + #<fbits>
    # ucvtf d18, w3, #0x1f
    (b'\x72\x84\x43\x1E', 'LLIL_INTRINSIC([d18],vcvtd_n_f64_u32,[LLIL_REG.d(w3),LLIL_CONST(31)])'),
    # ucvtf d25, w5, #0x1c
    (b'\xB9\x90\x43\x1E', 'LLIL_INTRINSIC([d25],vcvtd_n_f64_u32,[LLIL_REG.d(w5),LLIL_CONST(28)])'),
    # ucvtf d22, w9, #0x2
    (b'\x36\xf9\x43\x1e', 'LLIL_INTRINSIC([d22],vcvtd_n_f64_u32,[LLIL_REG.d(w9),LLIL_CONST(2)])'),
    # ucvtf d12, w28, #0x3
    (b'\x8c\xf7\x43\x1e', 'LLIL_INTRINSIC([d12],vcvtd_n_f64_u32,[LLIL_REG.d(w28),LLIL_CONST(3)])'),
    # 32-bit GPR to 32-bit FP
    # ucvtf s29, w24                                         UCVTF_S32_float2int
    (b'\x1D\x03\x23\x1E', 'LLIL_INTRINSIC([s29],vcvts_f32_u32,[LLIL_REG.d(w24)])'),
    # ucvtf s6, w7                                           UCVTF_S32_float2int
    (b'\xE6\x00\x23\x1E', 'LLIL_INTRINSIC([s6],vcvts_f32_u32,[LLIL_REG.d(w7)])'),
    # ucvtf s31, w23                                         UCVTF_S32_float2int
    (b'\xFF\x02\x23\x1E', 'LLIL_INTRINSIC([s31],vcvts_f32_u32,[LLIL_REG.d(w23)])'),
    # ucvtf s21, w0                                          UCVTF_S32_float2int
    (b'\x15\x00\x23\x1E', 'LLIL_INTRINSIC([s21],vcvts_f32_u32,[LLIL_REG.d(w0)])'),
    # 32-bit GPR to 16-bit FP
    # ucvtf h5, w12                                          UCVTF_H32_float2int
    (b'\x85\x01\xE3\x1E', 'LLIL_INTRINSIC([h5],vcvth_f16_u32,[LLIL_REG.d(w12)])'),
    # ucvtf h30, w15                                         UCVTF_H32_float2int
    (b'\xFE\x01\xE3\x1E', 'LLIL_INTRINSIC([h30],vcvth_f16_u32,[LLIL_REG.d(w15)])'),
    # ucvtf h7, w13                                          UCVTF_H32_float2int
    (b'\xA7\x01\xE3\x1E', 'LLIL_INTRINSIC([h7],vcvth_f16_u32,[LLIL_REG.d(w13)])'),
    # ucvtf h26, w8                                          UCVTF_H32_float2int
    (b'\x1A\x01\xE3\x1E', 'LLIL_INTRINSIC([h26],vcvth_f16_u32,[LLIL_REG.d(w8)])'),
]

tests_ucvtf2 = [
    # UCVTF_D32_float2fix 00011110010000111xxxxxxxxxxxxxxx
    # ucvtf d18, w3, #0x1f
    (b'\x72\x84\x43\x1E', 'LLIL_INTRINSIC([d18],vcvtd_n_f64_u32,[LLIL_REG.d(w3),LLIL_CONST(31)])'),
    # UCVTF_D32_float2int 0001111001100011000000xxxxxxxxxx
    # ucvtf d0, w7
    (b'\xE0\x00\x63\x1E', 'LLIL_INTRINSIC([d0],vcvt_f64_u32,[LLIL_REG.d(w7)])'),
    # UCVTF_D64_float2fix 1001111001000011xxxxxxxxxxxxxxxx
    # ucvtf d19, x26, #0x23
    (b'\x53\x77\x43\x9E', 'LLIL_INTRINSIC([d19],vcvtd_n_f64_u64,[LLIL_REG.q(x26),LLIL_CONST(35)])'),
    # UCVTF_D64_float2int 1001111001100011000000xxxxxxxxxx
    # ucvtf d30, x19
    (b'\x7E\x02\x63\x9E', 'LLIL_INTRINSIC([d30],vcvt_f64_u64,[LLIL_REG.q(x19)])'),
    # UCVTF_H32_float2fix 00011110110000111xxxxxxxxxxxxxxx
    # ucvtf h3, w29, #0x13
    (b'\xA3\xB7\xC3\x1E', 'LLIL_INTRINSIC([h3],vcvth_n_f16_u32,[LLIL_REG.d(w29),LLIL_CONST(19)])'),
    # UCVTF_H32_float2int 0001111011100011000000xxxxxxxxxx
    # ucvtf h5, w12
    (b'\x85\x01\xE3\x1E', 'LLIL_INTRINSIC([h5],vcvth_f16_u32,[LLIL_REG.d(w12)])'),
    # UCVTF_H64_float2fix 1001111011000011xxxxxxxxxxxxxxxx
    # ucvtf h5, x13, #0x16
    (b'\xA5\xA9\xC3\x9E', 'LLIL_INTRINSIC([h5],vcvth_n_f16_u64,[LLIL_REG.q(x13),LLIL_CONST(22)])'),
    # UCVTF_H64_float2int 1001111011100011000000xxxxxxxxxx
    # ucvtf h3, x2
    (b'\x43\x00\xE3\x9E', 'LLIL_INTRINSIC([h3],vcvth_f16_u64,[LLIL_REG.q(x2)])'),
    # UCVTF_S32_float2fix 00011110000000111xxxxxxxxxxxxxxx
    # ucvtf s1, w22, #0x1
    (b'\xC1\xFE\x03\x1E', 'LLIL_INTRINSIC([s1],vcvts_n_f32_u32,[LLIL_REG.d(w22),LLIL_CONST(1)])'),
    # UCVTF_S32_float2int 0001111000100011000000xxxxxxxxxx
    # ucvtf s29, w24
    (b'\x1D\x03\x23\x1E', 'LLIL_INTRINSIC([s29],vcvts_f32_u32,[LLIL_REG.d(w24)])'),
    # UCVTF_S64_float2fix 1001111000000011xxxxxxxxxxxxxxxx
    # ucvtf s2, x27, #0xf
    (b'\x62\xC7\x03\x9E', 'LLIL_INTRINSIC([s2],vcvts_n_f32_u64,[LLIL_REG.q(x27),LLIL_CONST(15)])'),
    # UCVTF_S64_float2int 1001111000100011000000xxxxxxxxxx
    # ucvtf s29, x5
    (b'\xBD\x00\x23\x9E', 'LLIL_INTRINSIC([s29],vcvth_f16_u16,[LLIL_REG.q(x5)])'),
    # UCVTF_asisdshf_C 011111110xxxxxxx111001xxxxxxxxxx
    # ucvtf d20, d1, #0x2a
    (b'\x34\xE4\x56\x7F', 'LLIL_INTRINSIC([d20],vcvt_n_f64_u64,[LLIL_REG.q(d1),LLIL_CONST(42)])'),
    # UCVTF_asimdshf_C 0x1011110xxxxxxx1110xxxxxxxxxxxx
    # ucvtf v15.2s, v14.2s, #0x19
    (b'\xCF\xE5\x27\x2F', 'LLIL_INTRINSIC([v15],vcvt_n_f32_u32,[LLIL_REG.o(v14),LLIL_CONST(25)])'),
    # UCVTF_asimdmisc_R 0x1011100x100001110110xxxxxxxxxx
    # ucvtf v11.2d, v11.2d
    (b'\x6B\xD9\x61\x6E', 'LLIL_INTRINSIC([v11],vcvt_f32_u32,[LLIL_REG.o(v11)])'),
    # UCVTF_asimdmiscfp16_R 0x1011100111100111011xxxxxxxxxxx
    # ucvtf v31.4h, v29.4h
    (b'\xBF\xDB\x79\x2E', 'LLIL_INTRINSIC([v31],vcvt_n_f16_u16,[LLIL_REG.o(v29)])'),
    # UCVTF_asisdmisc_R 011111100x100001110110xxxxxxxxxx
    # ucvtf s16, s7
    (b'\xF0\xD8\x21\x7E', 'LLIL_INTRINSIC([s16],vcvts_f32_u32,[LLIL_REG.d(s7)])'),
    # UCVTF_asisdmiscfp16_R 0111111001111001110110xxxxxxxxxx
    # ucvtf h30, h0
    (b'\x1E\xD8\x79\x7E', 'LLIL_INTRINSIC([h30],vcvth_f16_u16,[LLIL_REG.w(h0)])')
]

tests_scvtf = [
    # scvtf d1, x15                                          SCVTF_D64_float2int
    (b'\xe1\x01b\x9e', 'LLIL_INTRINSIC([d1],vcvtd_f64_s64,[LLIL_REG.q(x15)])')
]

tests_ret = [
    # ret
    (b'\xC0\x03\x5F\xD6', 'LLIL_RET(LLIL_REG.q(x30))'),
    # ret x10
    (b'\x40\x01\x5F\xD6', 'LLIL_RET(LLIL_REG.q(x10))'),
]

tests_svc_hvc_smc = [
    # svc #0xb79                                            SVC_EX_EXCEPTION
    (b'\x21\x6F\x01\xD4', 'LLIL_SET_REG.d(syscall_info,LLIL_CONST.d(0x40000B79));' + \
                         ' LLIL_SYSCALL()'),
    # svc #0x18a3                                            SVC_EX_EXCEPTION
    (b'\x61\x14\x03\xD4', 'LLIL_SET_REG.d(syscall_info,LLIL_CONST.d(0x400018A3));' + \
                         ' LLIL_SYSCALL()'),
    # svc #0x6ea8                                            SVC_EX_EXCEPTION
    (b'\x01\xD5\x0D\xD4', 'LLIL_SET_REG.d(syscall_info,LLIL_CONST.d(0x40006EA8));' + \
                         ' LLIL_SYSCALL()'),
    # svc #0x73ac                                            SVC_EX_EXCEPTION
    (b'\x81\x75\x0E\xD4', 'LLIL_SET_REG.d(syscall_info,LLIL_CONST.d(0x400073AC));' + \
                         ' LLIL_SYSCALL()'),
    # hvc #0x6fa3                                            HVC_EX_EXCEPTION
    (b'\x62\xF4\x0D\xD4', 'LLIL_SET_REG.d(syscall_info,LLIL_CONST.d(0x80006FA3));' + \
                         ' LLIL_SYSCALL()'),
    # hvc #0xa4c4                                            HVC_EX_EXCEPTION
    (b'\x82\x98\x14\xD4', 'LLIL_SET_REG.d(syscall_info,LLIL_CONST.d(0x8000A4C4));' + \
                         ' LLIL_SYSCALL()'),
    # hvc #0xd5b2                                            HVC_EX_EXCEPTION
    (b'\x42\xB6\x1A\xD4', 'LLIL_SET_REG.d(syscall_info,LLIL_CONST.d(0x8000D5B2));' + \
                         ' LLIL_SYSCALL()'),
    # hvc #0x85e5                                            HVC_EX_EXCEPTION
    (b'\xA2\xBC\x10\xD4', 'LLIL_SET_REG.d(syscall_info,LLIL_CONST.d(0x800085E5));' + \
                         ' LLIL_SYSCALL()'),
    # smc #0xcfd4                                            SMC_EX_EXCEPTION
    (b'\x83\xFA\x19\xD4', 'LLIL_SET_REG.d(syscall_info,LLIL_CONST.d(0xC000CFD4));' + \
                         ' LLIL_SYSCALL()'),
    # smc #0xc2ff                                            SMC_EX_EXCEPTION
    (b'\xE3\x5F\x18\xD4', 'LLIL_SET_REG.d(syscall_info,LLIL_CONST.d(0xC000C2FF));' + \
                         ' LLIL_SYSCALL()'),
    # smc #0x7dd1                                            SMC_EX_EXCEPTION
    (b'\x23\xBA\x0F\xD4', 'LLIL_SET_REG.d(syscall_info,LLIL_CONST.d(0xC0007DD1));' + \
                         ' LLIL_SYSCALL()'),
    # smc #0x7bb1                                            SMC_EX_EXCEPTION
    (b'\x23\x76\x0F\xD4', 'LLIL_SET_REG.d(syscall_info,LLIL_CONST.d(0xC0007BB1));' + \
                         ' LLIL_SYSCALL()'),
]

tests_clrex = [
    # clrex #0xe                                            CLREX_BN_BARRIERS
    (b'\x5F\x3E\x03\xD5', 'LLIL_INTRINSIC([],__clrex,[])'),
    # clrex #0x1                                            CLREX_BN_BARRIERS
    (b'\x5F\x31\x03\xD5', 'LLIL_INTRINSIC([],__clrex,[])'),
    # clrex #0xb                                            CLREX_BN_BARRIERS
    (b'\x5F\x3B\x03\xD5', 'LLIL_INTRINSIC([],__clrex,[])'),
    # clrex #0x2                                            CLREX_BN_BARRIERS
    (b'\x5F\x32\x03\xD5', 'LLIL_INTRINSIC([],__clrex,[])'),
]

tests_xtn_xtn2 = [
    # xtn v17.4h, v24.4s                                      XTN_ASIMDMISC_N
    (b'\x11\x2B\x61\x0E', 'LLIL_INTRINSIC([v17],vmovn_u32,[LLIL_REG.o(v24)])'),
    # xtn v13.4h, v30.4s                                      XTN_ASIMDMISC_N
    (b'\xCD\x2B\x61\x0E', 'LLIL_INTRINSIC([v13],vmovn_u32,[LLIL_REG.o(v30)])'),
    # xtn v30.4h, v20.4s                                      XTN_ASIMDMISC_N
    (b'\x9E\x2A\x61\x0E', 'LLIL_INTRINSIC([v30],vmovn_u32,[LLIL_REG.o(v20)])'),
    # xtn v13.2s, v10.2d                                      XTN_ASIMDMISC_N
    (b'\x4D\x29\xA1\x0E', 'LLIL_INTRINSIC([v13],vmovn_u64,[LLIL_REG.o(v10)])'),
    # xtn2 v27.8h, v19.4s                                     XTN_ASIMDMISC_N
    (b'\x7B\x2A\x61\x4E', 'LLIL_INTRINSIC([v27],vmovn_high_u32,[LLIL_REG.o(v19)])'),
    # xtn2 v26.4s, v7.2d                                      XTN_ASIMDMISC_N
    (b'\xFA\x28\xA1\x4E', 'LLIL_INTRINSIC([v26],vmovn_high_u64,[LLIL_REG.o(v7)])'),
    # xtn2 v3.4s, v22.2d                                      XTN_ASIMDMISC_N
    (b'\xC3\x2A\xA1\x4E', 'LLIL_INTRINSIC([v3],vmovn_high_u64,[LLIL_REG.o(v22)])'),
    # xtn2 v13.8h, v23.4s                                     XTN_ASIMDMISC_N
    (b'\xED\x2A\x61\x4E', 'LLIL_INTRINSIC([v13],vmovn_high_u32,[LLIL_REG.o(v23)])'),
]

tests_dc = [
    # dc cvadp, x26                                          DC_SYS_CR_SYSTEMINSTRS
    (b'\x3A\x7D\x0B\xD5', 'LLIL_INTRINSIC([],__dc,[LLIL_REG.q(x26)])'),
    # dc zva, x24                                            DC_SYS_CR_SYSTEMINSTRS
    (b'\x38\x74\x0B\xD5', 'LLIL_INTRINSIC([],__dc,[LLIL_REG.q(x24)])'),
    # dc zva, xzr                                            DC_SYS_CR_SYSTEMINSTRS
    (b'\x3F\x74\x0B\xD5', 'LLIL_INTRINSIC([],__dc,[LLIL_CONST.q(0x0)])'),
    # dc cisw, x18                                           DC_SYS_CR_SYSTEMINSTRS
    (b'\x52\x7E\x08\xD5', 'LLIL_INTRINSIC([],__dc,[LLIL_REG.q(x18)])'),
]

tests_uxtl_uxtl2 = [
    # uxtl v2.2d, v8.2s                                       UXTL_USHLL_ASIMDSHF_L
    (b'\x02\xA5\x20\x2F', 'LLIL_SET_REG.q(v2.d[0],LLIL_REG.d(v8.s[0]));' + \
                         ' LLIL_SET_REG.q(v2.d[1],LLIL_REG.d(v8.s[1]))'),
    # uxtl v6.8h, v1.8b                                       UXTL_USHLL_ASIMDSHF_L
    (b'\x26\xA4\x08\x2F', 'LLIL_SET_REG.w(v6.h[0],LLIL_REG.b(v1.b[0]));' + \
                         ' LLIL_SET_REG.w(v6.h[1],LLIL_REG.b(v1.b[1]));' + \
                         ' LLIL_SET_REG.w(v6.h[2],LLIL_REG.b(v1.b[2]));' + \
                         ' LLIL_SET_REG.w(v6.h[3],LLIL_REG.b(v1.b[3]));' + \
                         ' LLIL_SET_REG.w(v6.h[4],LLIL_REG.b(v1.b[4]));' + \
                         ' LLIL_SET_REG.w(v6.h[5],LLIL_REG.b(v1.b[5]));' + \
                         ' LLIL_SET_REG.w(v6.h[6],LLIL_REG.b(v1.b[6]));' + \
                         ' LLIL_SET_REG.w(v6.h[7],LLIL_REG.b(v1.b[7]))'),
    # uxtl v11.8h, v29.8b                                     UXTL_USHLL_ASIMDSHF_L
    (b'\xAB\xA7\x08\x2F', 'LLIL_SET_REG.w(v11.h[0],LLIL_REG.b(v29.b[0]));' + \
                         ' LLIL_SET_REG.w(v11.h[1],LLIL_REG.b(v29.b[1]));' + \
                         ' LLIL_SET_REG.w(v11.h[2],LLIL_REG.b(v29.b[2]));' + \
                         ' LLIL_SET_REG.w(v11.h[3],LLIL_REG.b(v29.b[3]));' + \
                         ' LLIL_SET_REG.w(v11.h[4],LLIL_REG.b(v29.b[4]));' + \
                         ' LLIL_SET_REG.w(v11.h[5],LLIL_REG.b(v29.b[5]));' + \
                         ' LLIL_SET_REG.w(v11.h[6],LLIL_REG.b(v29.b[6]));' + \
                         ' LLIL_SET_REG.w(v11.h[7],LLIL_REG.b(v29.b[7]))'),
    # uxtl v9.2d, v8.2s                                       UXTL_USHLL_ASIMDSHF_L
    (b'\x09\xA5\x20\x2F', 'LLIL_SET_REG.q(v9.d[0],LLIL_REG.d(v8.s[0]));' + \
                         ' LLIL_SET_REG.q(v9.d[1],LLIL_REG.d(v8.s[1]))'),
    # uxtl2 v19.2d, v20.4s                                    UXTL_USHLL_ASIMDSHF_L
    (b'\x93\xA6\x20\x6F', 'LLIL_SET_REG.q(v19.d[0],LLIL_REG.d(v20.s[2]));' + \
                         ' LLIL_SET_REG.q(v19.d[1],LLIL_REG.d(v20.s[3]))'),
    # uxtl2 v11.2d, v18.4s                                    UXTL_USHLL_ASIMDSHF_L
    (b'\x4B\xA6\x20\x6F', 'LLIL_SET_REG.q(v11.d[0],LLIL_REG.d(v18.s[2]));' + \
                         ' LLIL_SET_REG.q(v11.d[1],LLIL_REG.d(v18.s[3]))'),
    # uxtl2 v11.8h, v10.16b                                    UXTL_USHLL_ASIMDSHF_L
    (b'\x4B\xA5\x08\x6F', 'LLIL_SET_REG.w(v11.h[0],LLIL_REG.b(v10.b[8]));' + \
                         ' LLIL_SET_REG.w(v11.h[1],LLIL_REG.b(v10.b[9]));' + \
                         ' LLIL_SET_REG.w(v11.h[2],LLIL_REG.b(v10.b[10]));' + \
                         ' LLIL_SET_REG.w(v11.h[3],LLIL_REG.b(v10.b[11]));' + \
                         ' LLIL_SET_REG.w(v11.h[4],LLIL_REG.b(v10.b[12]));' + \
                         ' LLIL_SET_REG.w(v11.h[5],LLIL_REG.b(v10.b[13]));' + \
                         ' LLIL_SET_REG.w(v11.h[6],LLIL_REG.b(v10.b[14]));' + \
                         ' LLIL_SET_REG.w(v11.h[7],LLIL_REG.b(v10.b[15]))'),
    # uxtl2 v0.4s, v13.8h                                     UXTL_USHLL_ASIMDSHF_L
    (b'\xA0\xA5\x10\x6F', 'LLIL_SET_REG.d(v0.s[0],LLIL_REG.w(v13.h[4]));' + \
                         ' LLIL_SET_REG.d(v0.s[1],LLIL_REG.w(v13.h[5]));' + \
                         ' LLIL_SET_REG.d(v0.s[2],LLIL_REG.w(v13.h[6]));' + \
                         ' LLIL_SET_REG.d(v0.s[3],LLIL_REG.w(v13.h[7]))'),
]

tests_ldadd = [
    # ldaddab w13, w7, [x30]                                   LDADDAB_32_MEMOP
    (b'\xC7\x03\xAD\x38', 'LLIL_SET_REG.d(w7,LLIL_LOAD.b(LLIL_REG.q(x30)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x30),LLIL_ADD.b(LLIL_LOW_PART.b(LLIL_REG.d(w13)),LLIL_LOW_PART.b(LLIL_REG.d(w7))))'),
    # ldaddab w0, w22, [x28]                                   LDADDAB_32_MEMOP
    (b'\x96\x03\xA0\x38', 'LLIL_SET_REG.d(w22,LLIL_LOAD.b(LLIL_REG.q(x28)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x28),LLIL_ADD.b(LLIL_LOW_PART.b(LLIL_REG.d(w0)),LLIL_LOW_PART.b(LLIL_REG.d(w22))))'),
    # ldaddah w9, w16, [x11]                                   LDADDAH_32_MEMOP
    (b'\x70\x01\xA9\x78', 'LLIL_SET_REG.d(w16,LLIL_LOAD.w(LLIL_REG.q(x11)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x11),LLIL_ADD.w(LLIL_LOW_PART.w(LLIL_REG.d(w9)),LLIL_LOW_PART.w(LLIL_REG.d(w16))))'),
    # ldaddah w14, w16, [x28]                                  LDADDAH_32_MEMOP
    (b'\x90\x03\xAE\x78', 'LLIL_SET_REG.d(w16,LLIL_LOAD.w(LLIL_REG.q(x28)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x28),LLIL_ADD.w(LLIL_LOW_PART.w(LLIL_REG.d(w14)),LLIL_LOW_PART.w(LLIL_REG.d(w16))))'),
    # ldaddalb w14, w2, [x14]                                  LDADDALB_32_MEMOP
    (b'\xC2\x01\xEE\x38', 'LLIL_SET_REG.d(w2,LLIL_LOAD.b(LLIL_REG.q(x14)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x14),LLIL_ADD.b(LLIL_LOW_PART.b(LLIL_REG.d(w14)),LLIL_LOW_PART.b(LLIL_REG.d(w2))))'),
    # ldaddalb w0, w24, [x16]                                  LDADDALB_32_MEMOP
    (b'\x18\x02\xE0\x38', 'LLIL_SET_REG.d(w24,LLIL_LOAD.b(LLIL_REG.q(x16)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x16),LLIL_ADD.b(LLIL_LOW_PART.b(LLIL_REG.d(w0)),LLIL_LOW_PART.b(LLIL_REG.d(w24))))'),
    # ldaddalh w21, w30, [sp]                                  LDADDALH_32_MEMOP
    (b'\xFE\x03\xF5\x78', 'LLIL_SET_REG.d(w30,LLIL_LOAD.w(LLIL_REG.q(sp)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(sp),LLIL_ADD.w(LLIL_LOW_PART.w(LLIL_REG.d(w21)),LLIL_LOW_PART.w(LLIL_REG.d(w30))))'),
    # ldaddalh w24, wzr, [x19]                                 LDADDALH_32_MEMOP
    (b'\x7F\x02\xF8\x78', 'LLIL_LOAD.w(LLIL_REG.q(x19));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x19),LLIL_ADD.w(LLIL_LOW_PART.w(LLIL_REG.d(w24)),LLIL_LOW_PART.w(LLIL_CONST.d(0x0))))'),
    # ldaddal w17, w13, [x7]                                   LDADDAL_32_MEMOP
    (b'\xED\x00\xF1\xB8', 'LLIL_SET_REG.d(w13,LLIL_LOAD.d(LLIL_REG.q(x7)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x7),LLIL_ADD.d(LLIL_REG.d(w17),LLIL_REG.d(w13)))'),
    # ldaddal w7, w27, [x3]                                    LDADDAL_32_MEMOP
    (b'\x7B\x00\xE7\xB8', 'LLIL_SET_REG.d(w27,LLIL_LOAD.d(LLIL_REG.q(x3)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x3),LLIL_ADD.d(LLIL_REG.d(w7),LLIL_REG.d(w27)))'),
    # ldaddal x0, x5, [x1]                                    LDADDAL_64_MEMOP
    (b'\x25\x00\xE0\xF8', 'LLIL_SET_REG.q(x5,LLIL_LOAD.q(LLIL_REG.q(x1)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x1),LLIL_ADD.q(LLIL_REG.q(x0),LLIL_REG.q(x5)))'),
    # ldaddal x6, x13, [x13]                                   LDADDAL_64_MEMOP
    (b'\xAD\x01\xE6\xF8', 'LLIL_SET_REG.q(x13,LLIL_LOAD.q(LLIL_REG.q(x13)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x13),LLIL_ADD.q(LLIL_REG.q(x6),LLIL_REG.q(x13)))'),
    # ldadda w9, w4, [x4]                                     LDADDA_32_MEMOP
    (b'\x84\x00\xA9\xB8', 'LLIL_SET_REG.d(w4,LLIL_LOAD.d(LLIL_REG.q(x4)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x4),LLIL_ADD.d(LLIL_REG.d(w9),LLIL_REG.d(w4)))'),
    # ldadda w17, w29, [x27]                                   LDADDA_32_MEMOP
    (b'\x7D\x03\xB1\xB8', 'LLIL_SET_REG.d(w29,LLIL_LOAD.d(LLIL_REG.q(x27)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x27),LLIL_ADD.d(LLIL_REG.d(w17),LLIL_REG.d(w29)))'),
    # ldadda x5, x9, [x22]                                    LDADDA_64_MEMOP
    (b'\xC9\x02\xA5\xF8', 'LLIL_SET_REG.q(x9,LLIL_LOAD.q(LLIL_REG.q(x22)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x22),LLIL_ADD.q(LLIL_REG.q(x5),LLIL_REG.q(x9)))'),
    # ldadda x6, x2, [x4]                                     LDADDA_64_MEMOP
    (b'\x82\x00\xA6\xF8', 'LLIL_SET_REG.q(x2,LLIL_LOAD.q(LLIL_REG.q(x4)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x4),LLIL_ADD.q(LLIL_REG.q(x6),LLIL_REG.q(x2)))'),
    # ldaddb w16, w24, [x10]                                   LDADDB_32_MEMOP
    (b'\x58\x01\x30\x38', 'LLIL_SET_REG.d(w24,LLIL_LOAD.b(LLIL_REG.q(x10)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x10),LLIL_ADD.b(LLIL_LOW_PART.b(LLIL_REG.d(w16)),LLIL_LOW_PART.b(LLIL_REG.d(w24))))'),
    # ldaddb w4, w0, [x27]                                    LDADDB_32_MEMOP
    (b'\x60\x03\x24\x38', 'LLIL_SET_REG.d(w0,LLIL_LOAD.b(LLIL_REG.q(x27)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x27),LLIL_ADD.b(LLIL_LOW_PART.b(LLIL_REG.d(w4)),LLIL_LOW_PART.b(LLIL_REG.d(w0))))'),
    # ldaddh w30, w28, [x27]                                   LDADDH_32_MEMOP
    (b'\x7C\x03\x3E\x78', 'LLIL_SET_REG.d(w28,LLIL_LOAD.w(LLIL_REG.q(x27)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x27),LLIL_ADD.w(LLIL_LOW_PART.w(LLIL_REG.d(w30)),LLIL_LOW_PART.w(LLIL_REG.d(w28))))'),
    # ldaddh w20, w5, [x24]                                    LDADDH_32_MEMOP
    (b'\x05\x03\x34\x78', 'LLIL_SET_REG.d(w5,LLIL_LOAD.w(LLIL_REG.q(x24)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x24),LLIL_ADD.w(LLIL_LOW_PART.w(LLIL_REG.d(w20)),LLIL_LOW_PART.w(LLIL_REG.d(w5))))'),
    # ldaddlb w9, w24, [x5]                                    LDADDLB_32_MEMOP
    (b'\xB8\x00\x69\x38', 'LLIL_SET_REG.d(w24,LLIL_LOAD.b(LLIL_REG.q(x5)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x5),LLIL_ADD.b(LLIL_LOW_PART.b(LLIL_REG.d(w9)),LLIL_LOW_PART.b(LLIL_REG.d(w24))))'),
    # ldaddlb w3, w9, [x11]                                    LDADDLB_32_MEMOP
    (b'\x69\x01\x63\x38', 'LLIL_SET_REG.d(w9,LLIL_LOAD.b(LLIL_REG.q(x11)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x11),LLIL_ADD.b(LLIL_LOW_PART.b(LLIL_REG.d(w3)),LLIL_LOW_PART.b(LLIL_REG.d(w9))))'),
    # ldaddlh w17, w18, [x1]                                   LDADDLH_32_MEMOP
    (b'\x32\x00\x71\x78', 'LLIL_SET_REG.d(w18,LLIL_LOAD.w(LLIL_REG.q(x1)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x1),LLIL_ADD.w(LLIL_LOW_PART.w(LLIL_REG.d(w17)),LLIL_LOW_PART.w(LLIL_REG.d(w18))))'),
    # ldaddlh w16, w8, [x1]                                    LDADDLH_32_MEMOP
    (b'\x28\x00\x70\x78', 'LLIL_SET_REG.d(w8,LLIL_LOAD.w(LLIL_REG.q(x1)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x1),LLIL_ADD.w(LLIL_LOW_PART.w(LLIL_REG.d(w16)),LLIL_LOW_PART.w(LLIL_REG.d(w8))))'),
    # ldaddl w8, w6, [x4]                                     LDADDL_32_MEMOP
    (b'\x86\x00\x68\xB8', 'LLIL_SET_REG.d(w6,LLIL_LOAD.d(LLIL_REG.q(x4)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x4),LLIL_ADD.d(LLIL_REG.d(w8),LLIL_REG.d(w6)))'),
    # ldaddl w15, w23, [x28]                                   LDADDL_32_MEMOP
    (b'\x97\x03\x6F\xB8', 'LLIL_SET_REG.d(w23,LLIL_LOAD.d(LLIL_REG.q(x28)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x28),LLIL_ADD.d(LLIL_REG.d(w15),LLIL_REG.d(w23)))'),
    # ldaddl x19, x17, [x26]                                   LDADDL_64_MEMOP
    (b'\x51\x03\x73\xF8', 'LLIL_SET_REG.q(x17,LLIL_LOAD.q(LLIL_REG.q(x26)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x26),LLIL_ADD.q(LLIL_REG.q(x19),LLIL_REG.q(x17)))'),
    # ldaddl x4, x17, [x20]                                    LDADDL_64_MEMOP
    (b'\x91\x02\x64\xF8', 'LLIL_SET_REG.q(x17,LLIL_LOAD.q(LLIL_REG.q(x20)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x20),LLIL_ADD.q(LLIL_REG.q(x4),LLIL_REG.q(x17)))'),
    # ldadd w24, w11, [x29]                                    LDADD_32_MEMOP
    (b'\xAB\x03\x38\xB8', 'LLIL_SET_REG.d(w11,LLIL_LOAD.d(LLIL_REG.q(x29)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x29),LLIL_ADD.d(LLIL_REG.d(w24),LLIL_REG.d(w11)))'),
    # ldadd w17, w22, [x12]                                    LDADD_32_MEMOP
    (b'\x96\x01\x31\xB8', 'LLIL_SET_REG.d(w22,LLIL_LOAD.d(LLIL_REG.q(x12)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x12),LLIL_ADD.d(LLIL_REG.d(w17),LLIL_REG.d(w22)))'),
    # ldadd x4, x24, [x5]                                     LDADD_64_MEMOP
    (b'\xB8\x00\x24\xF8', 'LLIL_SET_REG.q(x24,LLIL_LOAD.q(LLIL_REG.q(x5)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x5),LLIL_ADD.q(LLIL_REG.q(x4),LLIL_REG.q(x24)))'),
    # ldadd x25, x4, [x7]                                     LDADD_64_MEMOP
    (b'\xE4\x00\x39\xF8', 'LLIL_SET_REG.q(x4,LLIL_LOAD.q(LLIL_REG.q(x7)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x7),LLIL_ADD.q(LLIL_REG.q(x25),LLIL_REG.q(x4)))'),
]

tests_swp = [
    # swpab w19, wzr, [x25]                                    SWPAB_32_MEMOP
    (b'\x3F\x83\xB3\x38', 'LLIL_LOAD.b(LLIL_REG.q(x25));' + \
                         ' LLIL_STORE.b(LLIL_REG.q(x25),LLIL_LOW_PART.b(LLIL_REG.d(w19)))'),
    # swpab w24, w2, [x14]                                    SWPAB_32_MEMOP
    (b'\xC2\x81\xB8\x38', 'LLIL_SET_REG.d(w2,LLIL_LOAD.b(LLIL_REG.q(x14)));' + \
                         ' LLIL_STORE.b(LLIL_REG.q(x14),LLIL_LOW_PART.b(LLIL_REG.d(w24)))'),
    # swpah w18, w25, [x15]                                    SWPAH_32_MEMOP
    (b'\xF9\x81\xB2\x78', 'LLIL_SET_REG.d(w25,LLIL_LOAD.w(LLIL_REG.q(x15)));' + \
                         ' LLIL_STORE.w(LLIL_REG.q(x15),LLIL_LOW_PART.w(LLIL_REG.d(w18)))'),
    # swpah w13, w25, [x10]                                    SWPAH_32_MEMOP
    (b'\x59\x81\xAD\x78', 'LLIL_SET_REG.d(w25,LLIL_LOAD.w(LLIL_REG.q(x10)));' + \
                         ' LLIL_STORE.w(LLIL_REG.q(x10),LLIL_LOW_PART.w(LLIL_REG.d(w13)))'),
    # swpalb w21, w3, [x19]                                    SWPALB_32_MEMOP
    (b'\x63\x82\xF5\x38', 'LLIL_SET_REG.d(w3,LLIL_LOAD.b(LLIL_REG.q(x19)));' + \
                         ' LLIL_STORE.b(LLIL_REG.q(x19),LLIL_LOW_PART.b(LLIL_REG.d(w21)))'),
    # swpalb w21, w28, [x30]                                   SWPALB_32_MEMOP
    (b'\xDC\x83\xF5\x38', 'LLIL_SET_REG.d(w28,LLIL_LOAD.b(LLIL_REG.q(x30)));' + \
                         ' LLIL_STORE.b(LLIL_REG.q(x30),LLIL_LOW_PART.b(LLIL_REG.d(w21)))'),
    # swpalh w11, w3, [x6]                                    SWPALH_32_MEMOP
    (b'\xC3\x80\xEB\x78', 'LLIL_SET_REG.d(w3,LLIL_LOAD.w(LLIL_REG.q(x6)));' + \
                         ' LLIL_STORE.w(LLIL_REG.q(x6),LLIL_LOW_PART.w(LLIL_REG.d(w11)))'),
    # swpalh w0, w12, [x26]                                    SWPALH_32_MEMOP
    (b'\x4C\x83\xE0\x78', 'LLIL_SET_REG.d(w12,LLIL_LOAD.w(LLIL_REG.q(x26)));' + \
                         ' LLIL_STORE.w(LLIL_REG.q(x26),LLIL_LOW_PART.w(LLIL_REG.d(w0)))'),
    # swpal wzr, w24, [x16]                                    SWPAL_32_MEMOP
    (b'\x18\x82\xFF\xB8', 'LLIL_SET_REG.d(w24,LLIL_LOAD.d(LLIL_REG.q(x16)));' + \
                         ' LLIL_STORE.d(LLIL_REG.q(x16),LLIL_CONST.d(0x0))'),
    # swpal w14, w15, [x0]                                    SWPAL_32_MEMOP
    (b'\x0F\x80\xEE\xB8', 'LLIL_SET_REG.d(w15,LLIL_LOAD.d(LLIL_REG.q(x0)));' + \
                         ' LLIL_STORE.d(LLIL_REG.q(x0),LLIL_REG.d(w14))'),
    # swpal x26, x16, [x23]                                    SWPAL_64_MEMOP
    (b'\xF0\x82\xFA\xF8', 'LLIL_SET_REG.q(x16,LLIL_LOAD.q(LLIL_REG.q(x23)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x23),LLIL_REG.q(x26))'),
    # swpal x8, x9, [x8]                                      SWPAL_64_MEMOP
    (b'\x09\x81\xE8\xF8', 'LLIL_SET_REG.q(x9,LLIL_LOAD.q(LLIL_REG.q(x8)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x8),LLIL_REG.q(x8))'),
    # swpa w10, w6, [x27]                                     SWPA_32_MEMOP
    (b'\x66\x83\xAA\xB8', 'LLIL_SET_REG.d(w6,LLIL_LOAD.d(LLIL_REG.q(x27)));' + \
                         ' LLIL_STORE.d(LLIL_REG.q(x27),LLIL_REG.d(w10))'),
    # swpa w0, w24, [x30]                                     SWPA_32_MEMOP
    (b'\xD8\x83\xA0\xB8', 'LLIL_SET_REG.d(w24,LLIL_LOAD.d(LLIL_REG.q(x30)));' + \
                         ' LLIL_STORE.d(LLIL_REG.q(x30),LLIL_REG.d(w0))'),
    # swpa x15, x1, [x28]                                     SWPA_64_MEMOP
    (b'\x81\x83\xAF\xF8', 'LLIL_SET_REG.q(x1,LLIL_LOAD.q(LLIL_REG.q(x28)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x28),LLIL_REG.q(x15))'),
    # swpa x13, x16, [x29]                                    SWPA_64_MEMOP
    (b'\xB0\x83\xAD\xF8', 'LLIL_SET_REG.q(x16,LLIL_LOAD.q(LLIL_REG.q(x29)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x29),LLIL_REG.q(x13))'),
    # swpb w22, w5, [x21]                                     SWPB_32_MEMOP
    (b'\xA5\x82\x36\x38', 'LLIL_SET_REG.d(w5,LLIL_LOAD.b(LLIL_REG.q(x21)));' + \
                         ' LLIL_STORE.b(LLIL_REG.q(x21),LLIL_LOW_PART.b(LLIL_REG.d(w22)))'),
    # swpb w7, w30, [x13]                                     SWPB_32_MEMOP
    (b'\xBE\x81\x27\x38', 'LLIL_SET_REG.d(w30,LLIL_LOAD.b(LLIL_REG.q(x13)));' + \
                         ' LLIL_STORE.b(LLIL_REG.q(x13),LLIL_LOW_PART.b(LLIL_REG.d(w7)))'),
    # swph w0, w26, [x5]                                      SWPH_32_MEMOP
    (b'\xBA\x80\x20\x78', 'LLIL_SET_REG.d(w26,LLIL_LOAD.w(LLIL_REG.q(x5)));' + \
                         ' LLIL_STORE.w(LLIL_REG.q(x5),LLIL_LOW_PART.w(LLIL_REG.d(w0)))'),
    # swph w10, w13, [x3]                                     SWPH_32_MEMOP
    (b'\x6D\x80\x2A\x78', 'LLIL_SET_REG.d(w13,LLIL_LOAD.w(LLIL_REG.q(x3)));' + \
                         ' LLIL_STORE.w(LLIL_REG.q(x3),LLIL_LOW_PART.w(LLIL_REG.d(w10)))'),
    # swplb w7, w27, [x3]                                     SWPLB_32_MEMOP
    (b'\x7B\x80\x67\x38', 'LLIL_SET_REG.d(w27,LLIL_LOAD.b(LLIL_REG.q(x3)));' + \
                         ' LLIL_STORE.b(LLIL_REG.q(x3),LLIL_LOW_PART.b(LLIL_REG.d(w7)))'),
    # swplb w25, w27, [x21]                                    SWPLB_32_MEMOP
    (b'\xBB\x82\x79\x38', 'LLIL_SET_REG.d(w27,LLIL_LOAD.b(LLIL_REG.q(x21)));' + \
                         ' LLIL_STORE.b(LLIL_REG.q(x21),LLIL_LOW_PART.b(LLIL_REG.d(w25)))'),
    # swplh w13, w19, [x3]                                    SWPLH_32_MEMOP
    (b'\x73\x80\x6D\x78', 'LLIL_SET_REG.d(w19,LLIL_LOAD.w(LLIL_REG.q(x3)));' + \
                         ' LLIL_STORE.w(LLIL_REG.q(x3),LLIL_LOW_PART.w(LLIL_REG.d(w13)))'),
    # swplh w12, w25, [x12]                                    SWPLH_32_MEMOP
    (b'\x99\x81\x6C\x78', 'LLIL_SET_REG.d(w25,LLIL_LOAD.w(LLIL_REG.q(x12)));' + \
                         ' LLIL_STORE.w(LLIL_REG.q(x12),LLIL_LOW_PART.w(LLIL_REG.d(w12)))'),
    # swpl w15, w8, [x23]                                     SWPL_32_MEMOP
    (b'\xE8\x82\x6F\xB8', 'LLIL_SET_REG.d(w8,LLIL_LOAD.d(LLIL_REG.q(x23)));' + \
                         ' LLIL_STORE.d(LLIL_REG.q(x23),LLIL_REG.d(w15))'),
    # swpl w16, w2, [x21]                                     SWPL_32_MEMOP
    (b'\xA2\x82\x70\xB8', 'LLIL_SET_REG.d(w2,LLIL_LOAD.d(LLIL_REG.q(x21)));' + \
                         ' LLIL_STORE.d(LLIL_REG.q(x21),LLIL_REG.d(w16))'),
    # swpl x13, x14, [sp]                                     SWPL_64_MEMOP
    (b'\xEE\x83\x6D\xF8', 'LLIL_SET_REG.q(x14,LLIL_LOAD.q(LLIL_REG.q(sp)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(sp),LLIL_REG.q(x13))'),
    # swpl x4, x19, [x2]                                      SWPL_64_MEMOP
    (b'\x53\x80\x64\xF8', 'LLIL_SET_REG.q(x19,LLIL_LOAD.q(LLIL_REG.q(x2)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x2),LLIL_REG.q(x4))'),
    # swp w1, w0, [x10]                                       SWP_32_MEMOP
    (b'\x40\x81\x21\xB8', 'LLIL_SET_REG.d(w0,LLIL_LOAD.d(LLIL_REG.q(x10)));' + \
                         ' LLIL_STORE.d(LLIL_REG.q(x10),LLIL_REG.d(w1))'),
    # swp w3, w5, [x11]                                       SWP_32_MEMOP
    (b'\x65\x81\x23\xB8', 'LLIL_SET_REG.d(w5,LLIL_LOAD.d(LLIL_REG.q(x11)));' + \
                         ' LLIL_STORE.d(LLIL_REG.q(x11),LLIL_REG.d(w3))'),
    # swp x1, x16, [sp]                                       SWP_64_MEMOP
    (b'\xF0\x83\x21\xF8', 'LLIL_SET_REG.q(x16,LLIL_LOAD.q(LLIL_REG.q(sp)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(sp),LLIL_REG.q(x1))'),
    # swp x8, x6, [x5]                                        SWP_64_MEMOP
    (b'\xA6\x80\x28\xF8', 'LLIL_SET_REG.q(x6,LLIL_LOAD.q(LLIL_REG.q(x5)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x5),LLIL_REG.q(x8))'),
]

tests_dup = [
    # dup v7.16b, w30                                        DUP_ASIMDINS_DR_R
    (b'\xC7\x0F\x15\x4E', 'LLIL_SET_REG.b(v7.b[0],LLIL_LOW_PART.b(LLIL_REG.d(w30)));' + \
                         ' LLIL_SET_REG.b(v7.b[1],LLIL_LOW_PART.b(LLIL_REG.d(w30)));' + \
                         ' LLIL_SET_REG.b(v7.b[2],LLIL_LOW_PART.b(LLIL_REG.d(w30)));' + \
                         ' LLIL_SET_REG.b(v7.b[3],LLIL_LOW_PART.b(LLIL_REG.d(w30)));' + \
                         ' LLIL_SET_REG.b(v7.b[4],LLIL_LOW_PART.b(LLIL_REG.d(w30)));' + \
                         ' LLIL_SET_REG.b(v7.b[5],LLIL_LOW_PART.b(LLIL_REG.d(w30)));' + \
                         ' LLIL_SET_REG.b(v7.b[6],LLIL_LOW_PART.b(LLIL_REG.d(w30)));' + \
                         ' LLIL_SET_REG.b(v7.b[7],LLIL_LOW_PART.b(LLIL_REG.d(w30)));' + \
                         ' LLIL_SET_REG.b(v7.b[8],LLIL_LOW_PART.b(LLIL_REG.d(w30)));' + \
                         ' LLIL_SET_REG.b(v7.b[9],LLIL_LOW_PART.b(LLIL_REG.d(w30)));' + \
                         ' LLIL_SET_REG.b(v7.b[10],LLIL_LOW_PART.b(LLIL_REG.d(w30)));' + \
                         ' LLIL_SET_REG.b(v7.b[11],LLIL_LOW_PART.b(LLIL_REG.d(w30)));' + \
                         ' LLIL_SET_REG.b(v7.b[12],LLIL_LOW_PART.b(LLIL_REG.d(w30)));' + \
                         ' LLIL_SET_REG.b(v7.b[13],LLIL_LOW_PART.b(LLIL_REG.d(w30)));' + \
                         ' LLIL_SET_REG.b(v7.b[14],LLIL_LOW_PART.b(LLIL_REG.d(w30)));' + \
                         ' LLIL_SET_REG.b(v7.b[15],LLIL_LOW_PART.b(LLIL_REG.d(w30)))'),
    # dup v4.8b, w12                                         DUP_ASIMDINS_DR_R
    (b'\x84\x0D\x07\x0E', 'LLIL_SET_REG.b(v4.b[0],LLIL_LOW_PART.b(LLIL_REG.d(w12)));' + \
                         ' LLIL_SET_REG.b(v4.b[1],LLIL_LOW_PART.b(LLIL_REG.d(w12)));' + \
                         ' LLIL_SET_REG.b(v4.b[2],LLIL_LOW_PART.b(LLIL_REG.d(w12)));' + \
                         ' LLIL_SET_REG.b(v4.b[3],LLIL_LOW_PART.b(LLIL_REG.d(w12)));' + \
                         ' LLIL_SET_REG.b(v4.b[4],LLIL_LOW_PART.b(LLIL_REG.d(w12)));' + \
                         ' LLIL_SET_REG.b(v4.b[5],LLIL_LOW_PART.b(LLIL_REG.d(w12)));' + \
                         ' LLIL_SET_REG.b(v4.b[6],LLIL_LOW_PART.b(LLIL_REG.d(w12)));' + \
                         ' LLIL_SET_REG.b(v4.b[7],LLIL_LOW_PART.b(LLIL_REG.d(w12)))'),
    # dup v24.4h, w11                                        DUP_ASIMDINS_DR_R
    (b'\x78\x0D\x02\x0E', 'LLIL_SET_REG.w(v24.h[0],LLIL_LOW_PART.w(LLIL_REG.d(w11)));' + \
                         ' LLIL_SET_REG.w(v24.h[1],LLIL_LOW_PART.w(LLIL_REG.d(w11)));' + \
                         ' LLIL_SET_REG.w(v24.h[2],LLIL_LOW_PART.w(LLIL_REG.d(w11)));' + \
                         ' LLIL_SET_REG.w(v24.h[3],LLIL_LOW_PART.w(LLIL_REG.d(w11)))'),
    # dup v27.8h, w3                                         DUP_ASIMDINS_DR_R
    (b'\x7B\x0C\x0A\x4E', 'LLIL_SET_REG.w(v27.h[0],LLIL_LOW_PART.w(LLIL_REG.d(w3)));' + \
                         ' LLIL_SET_REG.w(v27.h[1],LLIL_LOW_PART.w(LLIL_REG.d(w3)));' + \
                         ' LLIL_SET_REG.w(v27.h[2],LLIL_LOW_PART.w(LLIL_REG.d(w3)));' + \
                         ' LLIL_SET_REG.w(v27.h[3],LLIL_LOW_PART.w(LLIL_REG.d(w3)));' + \
                         ' LLIL_SET_REG.w(v27.h[4],LLIL_LOW_PART.w(LLIL_REG.d(w3)));' + \
                         ' LLIL_SET_REG.w(v27.h[5],LLIL_LOW_PART.w(LLIL_REG.d(w3)));' + \
                         ' LLIL_SET_REG.w(v27.h[6],LLIL_LOW_PART.w(LLIL_REG.d(w3)));' + \
                         ' LLIL_SET_REG.w(v27.h[7],LLIL_LOW_PART.w(LLIL_REG.d(w3)))'),
    # dup v1.16b, v0.b[1]
    (b'\x01\x04\x03\x4E', 'LLIL_INTRINSIC([v1],vdupq_laneq_s8,[LLIL_REG.o(v0),LLIL_CONST.b(0x1)])'),
    # dup V3.8B, V23.B[2]
    (b'\xE3\x06\x05\x0E', 'LLIL_INTRINSIC([v3],vdup_laneq_s8,[LLIL_REG.o(v23),LLIL_CONST.b(0x2)])'),
    # dup v5.4s, v3.s[3]
    (b'\x65\x04\x1C\x4E', 'LLIL_INTRINSIC([v5],vdupq_laneq_s32,[LLIL_REG.o(v3),LLIL_CONST.b(0x3)])'),
    # dup V30.2S, V18.S[0]
    (b'\x5E\x06\x04\x0E', 'LLIL_INTRINSIC([v30],vdup_laneq_s32,[LLIL_REG.o(v18),LLIL_CONST.b(0x0)])'),
    # dup v16.2d, v16.d[0]
    (b'\x10\x06\x08\x4E', 'LLIL_INTRINSIC([v16],vdupq_laneq_s64,[LLIL_REG.o(v16),LLIL_CONST.b(0x0)])'),
    # dup V24.4H, V6.H[3]
    (b'\xD8\x04\x0E\x0E', 'LLIL_INTRINSIC([v24],vdup_laneq_s16,[LLIL_REG.o(v6),LLIL_CONST.b(0x3)])'),
    # dup v24.8h, v6.h[3]
    (b'\xd8\x04\x0e\x4e', 'LLIL_INTRINSIC([v24],vdupq_laneq_s16,[LLIL_REG.o(v6),LLIL_CONST.b(0x3)])'),
    # dup s6, v8.s[0]
    (b'\x06\x05\x04\x5E', 'LLIL_INTRINSIC([s6],vdups_laneq_s32,[LLIL_REG.o(v8),LLIL_CONST.b(0x0)])'),
    # dup b1, v4.b[9]
    (b'\x81\x04\x13\x5E', 'LLIL_INTRINSIC([b1],vdupb_laneq_s8,[LLIL_REG.o(v4),LLIL_CONST.b(0x9)])'),
    # dup h24, v13.h[0]
    (b'\xB8\x05\x02\x5E', 'LLIL_INTRINSIC([h24],vduph_laneq_s16,[LLIL_REG.o(v13),LLIL_CONST.b(0x0)])'),
    # dup d4, v13.d[0]
    (b'\xA4\x05\x08\x5E', 'LLIL_INTRINSIC([d4],vdupd_laneq_s64,[LLIL_REG.o(v13),LLIL_CONST.b(0x0)])')
]

tests_stlr = [
    # stlrb w18, [x15]                                        STLRB_SL32_LDSTEXCL
    (b'\xF2\xB9\x8C\x08', 'LLIL_STORE.b(LLIL_REG.q(x15),LLIL_LOW_PART.b(LLIL_REG.d(w18)))'),
    # stlrb w18, [x24]                                        STLRB_SL32_LDSTEXCL
    (b'\x12\xD3\x8F\x08', 'LLIL_STORE.b(LLIL_REG.q(x24),LLIL_LOW_PART.b(LLIL_REG.d(w18)))'),
    # stlrh w10, [x12]                                        STLRH_SL32_LDSTEXCL
    (b'\x8A\x99\x89\x48', 'LLIL_STORE.w(LLIL_REG.q(x12),LLIL_LOW_PART.w(LLIL_REG.d(w10)))'),
    # stlrh w25, [x18]                                        STLRH_SL32_LDSTEXCL
    (b'\x59\x86\x8B\x48', 'LLIL_STORE.w(LLIL_REG.q(x18),LLIL_LOW_PART.w(LLIL_REG.d(w25)))'),
    # stlr wzr, [x14]                                        STLR_SL32_LDSTEXCL
    (b'\xDF\xAD\x8D\x88', 'LLIL_STORE.d(LLIL_REG.q(x14),LLIL_CONST.d(0x0))'),
    # stlr w24, [x3]                                         STLR_SL32_LDSTEXCL
    (b'\x78\xF8\x9B\x88', 'LLIL_STORE.d(LLIL_REG.q(x3),LLIL_REG.d(w24))'),
    # stlr x18, [x25]                                        STLR_SL64_LDSTEXCL
    (b'\x32\xD3\x8D\xC8', 'LLIL_STORE.q(LLIL_REG.q(x25),LLIL_REG.q(x18))'),
    # stlr x0, [x17]                                         STLR_SL64_LDSTEXCL
    (b'\x20\xCE\x82\xC8', 'LLIL_STORE.q(LLIL_REG.q(x17),LLIL_REG.q(x0))'),
]

tests_ldnp = [
    # ldnp w28, w5, [x14, #-0xd8]                               LDNP_32_LDSTNAPAIR_OFFS
    (b'\xDC\x15\x65\x28', 'LLIL_SET_REG.d(w28,LLIL_LOAD.d(LLIL_ADD.q(LLIL_REG.q(x14),LLIL_CONST.q(0xFFFFFFFFFFFFFF28))));' + \
                         ' LLIL_SET_REG.d(w5,LLIL_LOAD.d(LLIL_ADD.q(LLIL_REG.q(x14),LLIL_CONST.q(0xFFFFFFFFFFFFFF2C))))'),
    # ldnp w0, w17, [x7, #-0xa8]                                LDNP_32_LDSTNAPAIR_OFFS
    (b'\xE0\x44\x6B\x28', 'LLIL_SET_REG.d(w0,LLIL_LOAD.d(LLIL_ADD.q(LLIL_REG.q(x7),LLIL_CONST.q(0xFFFFFFFFFFFFFF58))));' + \
                         ' LLIL_SET_REG.d(w17,LLIL_LOAD.d(LLIL_ADD.q(LLIL_REG.q(x7),LLIL_CONST.q(0xFFFFFFFFFFFFFF5C))))'),
    # ldnp x26, x8, [x7, #-0x1b0]                               LDNP_64_LDSTNAPAIR_OFFS
    (b'\xFA\x20\x65\xA8', 'LLIL_SET_REG.q(x26,LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x7),LLIL_CONST.q(0xFFFFFFFFFFFFFE50))));' + \
                         ' LLIL_SET_REG.q(x8,LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x7),LLIL_CONST.q(0xFFFFFFFFFFFFFE58))))'),
    # ldnp xzr, x1, [x11, #0x170]                               LDNP_64_LDSTNAPAIR_OFFS
    (b'\x7F\x05\x57\xA8', 'LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x11),LLIL_CONST.q(0x170)));' + \
                         ' LLIL_SET_REG.q(x1,LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x11),LLIL_CONST.q(0x178))))'),
    # ldnp d22, d3, [x15, #-0x88]                               LDNP_D_LDSTNAPAIR_OFFS
    (b'\xF6\x8D\x77\x6C', 'LLIL_SET_REG.q(d22,LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x15),LLIL_CONST.q(0xFFFFFFFFFFFFFF78))));' + \
                         ' LLIL_SET_REG.q(d3,LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x15),LLIL_CONST.q(0xFFFFFFFFFFFFFF80))))'),
    # ldnp d14, d12, [x15, #-0xc0]                              LDNP_D_LDSTNAPAIR_OFFS
    (b'\xEE\x31\x74\x6C', 'LLIL_SET_REG.q(d14,LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x15),LLIL_CONST.q(0xFFFFFFFFFFFFFF40))));' + \
                         ' LLIL_SET_REG.q(d12,LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x15),LLIL_CONST.q(0xFFFFFFFFFFFFFF48))))'),
    # ldnp q12, q1, [x6, #0x240]                                LDNP_Q_LDSTNAPAIR_OFFS
    (b'\xCC\x04\x52\xAC', 'LLIL_SET_REG.o(q12,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(x6),LLIL_CONST.q(0x240))));' + \
                         ' LLIL_SET_REG.o(q1,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(x6),LLIL_CONST.q(0x250))))'),
    # ldnp q24, q14, [x0, #-0x1f0]                              LDNP_Q_LDSTNAPAIR_OFFS
    (b'\x18\xB8\x70\xAC', 'LLIL_SET_REG.o(q24,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(x0),LLIL_CONST.q(0xFFFFFFFFFFFFFE10))));' + \
                         ' LLIL_SET_REG.o(q14,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(x0),LLIL_CONST.q(0xFFFFFFFFFFFFFE20))))'),
    # ldnp s15, s28, [x29, #-0xdc]                              LDNP_S_LDSTNAPAIR_OFFS
    (b'\xAF\xF3\x64\x2C', 'LLIL_SET_REG.d(s15,LLIL_LOAD.d(LLIL_ADD.q(LLIL_REG.q(x29),LLIL_CONST.q(0xFFFFFFFFFFFFFF24))));' + \
                         ' LLIL_SET_REG.d(s28,LLIL_LOAD.d(LLIL_ADD.q(LLIL_REG.q(x29),LLIL_CONST.q(0xFFFFFFFFFFFFFF28))))'),
    # ldnp s2, s12, [x3, #-0x6c]                                LDNP_S_LDSTNAPAIR_OFFS
    (b'\x62\xB0\x72\x2C', 'LLIL_SET_REG.d(s2,LLIL_LOAD.d(LLIL_ADD.q(LLIL_REG.q(x3),LLIL_CONST.q(0xFFFFFFFFFFFFFF94))));' + \
                         ' LLIL_SET_REG.d(s12,LLIL_LOAD.d(LLIL_ADD.q(LLIL_REG.q(x3),LLIL_CONST.q(0xFFFFFFFFFFFFFF98))))'),
]

tests_stnp = [
    # stnp w7, w9, [x16, #-0xc8]                                STNP_32_LDSTNAPAIR_OFFS
    (b'\x07\x26\x27\x28', 'LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x16),LLIL_CONST.q(0xFFFFFFFFFFFFFF38)),LLIL_REG.d(w7));' + \
                         ' LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x16),LLIL_CONST.q(0xFFFFFFFFFFFFFF3C)),LLIL_REG.d(w9))'),
    # stnp w6, wzr, [x28, #-0x3c]                               STNP_32_LDSTNAPAIR_OFFS
    (b'\x86\xFF\x38\x28', 'LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x28),LLIL_CONST.q(0xFFFFFFFFFFFFFFC4)),LLIL_REG.d(w6));' + \
                         ' LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x28),LLIL_CONST.q(0xFFFFFFFFFFFFFFC8)),LLIL_CONST.d(0x0))'),
    # stnp x27, x13, [x19, #0x40]                               STNP_64_LDSTNAPAIR_OFFS
    (b'\x7B\x36\x04\xA8', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x19),LLIL_CONST.q(0x40)),LLIL_REG.q(x27));' + \
                         ' LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x19),LLIL_CONST.q(0x48)),LLIL_REG.q(x13))'),
    # stnp x7, x20, [x13, #0x28]                                STNP_64_LDSTNAPAIR_OFFS
    (b'\xA7\xD1\x02\xA8', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x13),LLIL_CONST.q(0x28)),LLIL_REG.q(x7));' + \
                         ' LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x13),LLIL_CONST.q(0x30)),LLIL_REG.q(x20))'),
    # stnp d19, d4, [x22, #-0x138]                              STNP_D_LDSTNAPAIR_OFFS
    (b'\xD3\x92\x2C\x6C', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x22),LLIL_CONST.q(0xFFFFFFFFFFFFFEC8)),LLIL_REG.q(d19));' + \
                         ' LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x22),LLIL_CONST.q(0xFFFFFFFFFFFFFED0)),LLIL_REG.q(d4))'),
    # stnp d8, d6, [x16, #-0xc0]                                STNP_D_LDSTNAPAIR_OFFS
    (b'\x08\x1A\x34\x6C', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x16),LLIL_CONST.q(0xFFFFFFFFFFFFFF40)),LLIL_REG.q(d8));' + \
                         ' LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x16),LLIL_CONST.q(0xFFFFFFFFFFFFFF48)),LLIL_REG.q(d6))'),
    # stnp q10, q9, [x17, #0x30]                                STNP_Q_LDSTNAPAIR_OFFS
    (b'\x2A\xA6\x01\xAC', 'LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x17),LLIL_CONST.q(0x30)),LLIL_REG.o(q10));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x17),LLIL_CONST.q(0x40)),LLIL_REG.o(q9))'),
    # stnp q3, q14, [x5, #0x250]                                STNP_Q_LDSTNAPAIR_OFFS
    (b'\xA3\xB8\x12\xAC', 'LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x5),LLIL_CONST.q(0x250)),LLIL_REG.o(q3));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x5),LLIL_CONST.q(0x260)),LLIL_REG.o(q14))'),
    # stnp s1, s4, [x17, #-0x88]                                STNP_S_LDSTNAPAIR_OFFS
    (b'\x21\x12\x2F\x2C', 'LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x17),LLIL_CONST.q(0xFFFFFFFFFFFFFF78)),LLIL_REG.d(s1));' + \
                         ' LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x17),LLIL_CONST.q(0xFFFFFFFFFFFFFF7C)),LLIL_REG.d(s4))'),
    # stnp s8, s6, [x17, #0x2c]                                STNP_S_LDSTNAPAIR_OFFS
    (b'\x28\x9A\x05\x2C', 'LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x17),LLIL_CONST.q(0x2C)),LLIL_REG.d(s8));' + \
                         ' LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x17),LLIL_CONST.q(0x30)),LLIL_REG.d(s6))'),
]

tests_mov = [
    # 011c044e   mov    v1.s[0], w0
    (b'\x01\x1C\x04\x4E', 'LLIL_SET_REG.d(v1.s[0],LLIL_REG.d(w0))'),
    # mov w10, #0
    (b'\x0A\x00\x80\x52', 'LLIL_SET_REG.d(w10,LLIL_CONST.d(0x0))'),
    # mov v8.16b, v1.16b
    (b'\x28\x1C\xA1\x4E', 'LLIL_SET_REG.o(v8,LLIL_REG.o(v1))'),
    # mov v0.2s, v1.2s
    (b'\x20\x1C\xA1\x0E', 'LLIL_SET_REG.q(v0.d[0],LLIL_REG.q(v1.d[0]))'),
]

tests_movi = [
    # movi v4.2d, #0xffffff0000ffff                             MOVI_ASIMDIMM_D2_D
    (b'\x64\xE6\x03\x6F', 'LLIL_SET_REG.q(v4.d[0],LLIL_CONST.q(0xFFFFFF0000FFFF));' + \
                         ' LLIL_SET_REG.q(v4.d[1],LLIL_CONST.q(0xFFFFFF0000FFFF))'),
    # movi v16.2d, #0xffffff00ffffff                            MOVI_ASIMDIMM_D2_D
    (b'\xF0\xE6\x03\x6F', 'LLIL_SET_REG.q(v16.d[0],LLIL_CONST.q(0xFFFFFF00FFFFFF));' + \
                         ' LLIL_SET_REG.q(v16.d[1],LLIL_CONST.q(0xFFFFFF00FFFFFF))'),
    # movi d11, #0xff00ffff0000ff00                             MOVI_ASIMDIMM_D_DS
    (b'\x4B\xE6\x05\x2F', 'LLIL_SET_REG.q(d11,LLIL_CONST.q(0xFF00FFFF0000FF00))'),
    # movi d25, #0xffffffffffff0000                             MOVI_ASIMDIMM_D_DS
    (b'\x99\xE7\x07\x2F', 'LLIL_SET_REG.q(d25,LLIL_CONST.q(0xFFFFFFFFFFFF0000))'),
    # movi v6.8h, #0xc9, lsl #0x8                               MOVI_ASIMDIMM_L_HL
    (b'\x26\xA5\x06\x4F', 'LLIL_SET_REG.w(v6.h[0],LLIL_CONST.w(0xC900));' + \
                         ' LLIL_SET_REG.w(v6.h[1],LLIL_CONST.w(0xC900));' + \
                         ' LLIL_SET_REG.w(v6.h[2],LLIL_CONST.w(0xC900));' + \
                         ' LLIL_SET_REG.w(v6.h[3],LLIL_CONST.w(0xC900));' + \
                         ' LLIL_SET_REG.w(v6.h[4],LLIL_CONST.w(0xC900));' + \
                         ' LLIL_SET_REG.w(v6.h[5],LLIL_CONST.w(0xC900));' + \
                         ' LLIL_SET_REG.w(v6.h[6],LLIL_CONST.w(0xC900));' + \
                         ' LLIL_SET_REG.w(v6.h[7],LLIL_CONST.w(0xC900))'),
    # movi v21.4h, #0x49                                      MOVI_ASIMDIMM_L_HL
    (b'\x35\x85\x02\x0F', 'LLIL_SET_REG.w(v21.h[0],LLIL_CONST.w(0x49));' + \
                         ' LLIL_SET_REG.w(v21.h[1],LLIL_CONST.w(0x49));' + \
                         ' LLIL_SET_REG.w(v21.h[2],LLIL_CONST.w(0x49));' + \
                         ' LLIL_SET_REG.w(v21.h[3],LLIL_CONST.w(0x49))'),
    # movi v30.4s, #0x44, lsl #0x8                              MOVI_ASIMDIMM_L_SL
    (b'\x9E\x24\x02\x4F', 'LLIL_SET_REG.d(v30.s[0],LLIL_CONST.d(0x4400));' + \
                         ' LLIL_SET_REG.d(v30.s[1],LLIL_CONST.d(0x4400));' + \
                         ' LLIL_SET_REG.d(v30.s[2],LLIL_CONST.d(0x4400));' + \
                         ' LLIL_SET_REG.d(v30.s[3],LLIL_CONST.d(0x4400))'),
    # movi v1.2s, #0x26                                       MOVI_ASIMDIMM_L_SL
    (b'\xC1\x04\x01\x0F', 'LLIL_SET_REG.d(v1.s[0],LLIL_CONST.d(0x26));' + \
                         ' LLIL_SET_REG.d(v1.s[1],LLIL_CONST.d(0x26))'),
    # movi v17.2s, #0x96, msl #0x10                             MOVI_ASIMDIMM_M_SM
    (b'\xD1\xD6\x04\x0F', 'LLIL_SET_REG.d(v17.s[0],LLIL_CONST.d(0x96FFFF));' + \
                         ' LLIL_SET_REG.d(v17.s[1],LLIL_CONST.d(0x96FFFF))'),
    # movi v25.2s, #0x42, msl #0x8                              MOVI_ASIMDIMM_M_SM
    (b'\x59\xC4\x02\x0F', 'LLIL_SET_REG.d(v25.s[0],LLIL_CONST.d(0x42FF));' + \
                         ' LLIL_SET_REG.d(v25.s[1],LLIL_CONST.d(0x42FF))'),
    # movi v10.16b, #0x89                                     MOVI_ASIMDIMM_N_B
    (b'\x2A\xE5\x04\x4F', 'LLIL_SET_REG.b(v10.b[0],LLIL_CONST.b(0x89));' + \
                         ' LLIL_SET_REG.b(v10.b[1],LLIL_CONST.b(0x89));' + \
                         ' LLIL_SET_REG.b(v10.b[2],LLIL_CONST.b(0x89));' + \
                         ' LLIL_SET_REG.b(v10.b[3],LLIL_CONST.b(0x89));' + \
                         ' LLIL_SET_REG.b(v10.b[4],LLIL_CONST.b(0x89));' + \
                         ' LLIL_SET_REG.b(v10.b[5],LLIL_CONST.b(0x89));' + \
                         ' LLIL_SET_REG.b(v10.b[6],LLIL_CONST.b(0x89));' + \
                         ' LLIL_SET_REG.b(v10.b[7],LLIL_CONST.b(0x89));' + \
                         ' LLIL_SET_REG.b(v10.b[8],LLIL_CONST.b(0x89));' + \
                         ' LLIL_SET_REG.b(v10.b[9],LLIL_CONST.b(0x89));' + \
                         ' LLIL_SET_REG.b(v10.b[10],LLIL_CONST.b(0x89));' + \
                         ' LLIL_SET_REG.b(v10.b[11],LLIL_CONST.b(0x89));' + \
                         ' LLIL_SET_REG.b(v10.b[12],LLIL_CONST.b(0x89));' + \
                         ' LLIL_SET_REG.b(v10.b[13],LLIL_CONST.b(0x89));' + \
                         ' LLIL_SET_REG.b(v10.b[14],LLIL_CONST.b(0x89));' + \
                         ' LLIL_SET_REG.b(v10.b[15],LLIL_CONST.b(0x89))'),
    # movi v19.16b, #0x80                                     MOVI_ASIMDIMM_N_B
    (b'\x13\xE4\x04\x4F', 'LLIL_SET_REG.b(v19.b[0],LLIL_CONST.b(0x80));' + \
                         ' LLIL_SET_REG.b(v19.b[1],LLIL_CONST.b(0x80));' + \
                         ' LLIL_SET_REG.b(v19.b[2],LLIL_CONST.b(0x80));' + \
                         ' LLIL_SET_REG.b(v19.b[3],LLIL_CONST.b(0x80));' + \
                         ' LLIL_SET_REG.b(v19.b[4],LLIL_CONST.b(0x80));' + \
                         ' LLIL_SET_REG.b(v19.b[5],LLIL_CONST.b(0x80));' + \
                         ' LLIL_SET_REG.b(v19.b[6],LLIL_CONST.b(0x80));' + \
                         ' LLIL_SET_REG.b(v19.b[7],LLIL_CONST.b(0x80));' + \
                         ' LLIL_SET_REG.b(v19.b[8],LLIL_CONST.b(0x80));' + \
                         ' LLIL_SET_REG.b(v19.b[9],LLIL_CONST.b(0x80));' + \
                         ' LLIL_SET_REG.b(v19.b[10],LLIL_CONST.b(0x80));' + \
                         ' LLIL_SET_REG.b(v19.b[11],LLIL_CONST.b(0x80));' + \
                         ' LLIL_SET_REG.b(v19.b[12],LLIL_CONST.b(0x80));' + \
                         ' LLIL_SET_REG.b(v19.b[13],LLIL_CONST.b(0x80));' + \
                         ' LLIL_SET_REG.b(v19.b[14],LLIL_CONST.b(0x80));' + \
                         ' LLIL_SET_REG.b(v19.b[15],LLIL_CONST.b(0x80))'),
]

tests_fsub = [
    # fsub d9, d7, d11                                        FSUB_D_FLOATDP2
    (b'\xE9\x38\x6B\x1E', 'LLIL_SET_REG.q(d9,LLIL_FSUB.q(LLIL_REG.q(d7),LLIL_REG.q(d11)))'),
    # fsub d1, d14, d7                                        FSUB_D_FLOATDP2
    (b'\xC1\x39\x67\x1E', 'LLIL_SET_REG.q(d1,LLIL_FSUB.q(LLIL_REG.q(d14),LLIL_REG.q(d7)))'),
    # fsub h3, h21, h9                                        FSUB_H_FLOATDP2
    (b'\xA3\x3A\xE9\x1E', 'LLIL_SET_REG.w(h3,LLIL_FSUB.w(LLIL_REG.w(h21),LLIL_REG.w(h9)))'),
    # fsub h10, h22, h2                                       FSUB_H_FLOATDP2
    (b'\xCA\x3A\xE2\x1E', 'LLIL_SET_REG.w(h10,LLIL_FSUB.w(LLIL_REG.w(h22),LLIL_REG.w(h2)))'),
    # fsub s18, s10, s28                                      FSUB_S_FLOATDP2
    (b'\x52\x39\x3C\x1E', 'LLIL_SET_REG.d(s18,LLIL_FSUB.d(LLIL_REG.d(s10),LLIL_REG.d(s28)))'),
    # fsub s11, s12, s23                                      FSUB_S_FLOATDP2
    (b'\x8B\x39\x37\x1E', 'LLIL_SET_REG.d(s11,LLIL_FSUB.d(LLIL_REG.d(s12),LLIL_REG.d(s23)))'),
    # fsub v24.2s, v27.2s, v20.2s                               FSUB_ASIMDSAME_ONLY
    (b'\x78\xD7\xB4\x0E', 'LLIL_FSUB.d(LLIL_REG.d(v24.s[0]),LLIL_REG.d(v27.s[0]));' + \
                         ' LLIL_FSUB.d(LLIL_REG.d(v24.s[1]),LLIL_REG.d(v27.s[1]))'),
    # fsub v5.4s, v16.4s, v15.4s                                FSUB_ASIMDSAME_ONLY
    (b'\x05\xD6\xAF\x4E', 'LLIL_FSUB.d(LLIL_REG.d(v5.s[0]),LLIL_REG.d(v16.s[0]));' + \
                         ' LLIL_FSUB.d(LLIL_REG.d(v5.s[1]),LLIL_REG.d(v16.s[1]));' + \
                         ' LLIL_FSUB.d(LLIL_REG.d(v5.s[2]),LLIL_REG.d(v16.s[2]));' + \
                         ' LLIL_FSUB.d(LLIL_REG.d(v5.s[3]),LLIL_REG.d(v16.s[3]))'),
    # fsub v10.8h, v29.8h, v3.8h                                FSUB_ASIMDSAMEFP16_ONLY
    (b'\xAA\x17\xC3\x4E', 'LLIL_FSUB.w(LLIL_REG.w(v10.h[0]),LLIL_REG.w(v29.h[0]));' + \
                         ' LLIL_FSUB.w(LLIL_REG.w(v10.h[1]),LLIL_REG.w(v29.h[1]));' + \
                         ' LLIL_FSUB.w(LLIL_REG.w(v10.h[2]),LLIL_REG.w(v29.h[2]));' + \
                         ' LLIL_FSUB.w(LLIL_REG.w(v10.h[3]),LLIL_REG.w(v29.h[3]));' + \
                         ' LLIL_FSUB.w(LLIL_REG.w(v10.h[4]),LLIL_REG.w(v29.h[4]));' + \
                         ' LLIL_FSUB.w(LLIL_REG.w(v10.h[5]),LLIL_REG.w(v29.h[5]));' + \
                         ' LLIL_FSUB.w(LLIL_REG.w(v10.h[6]),LLIL_REG.w(v29.h[6]));' + \
                         ' LLIL_FSUB.w(LLIL_REG.w(v10.h[7]),LLIL_REG.w(v29.h[7]))'),
    # fsub v24.4h, v27.4h, v17.4h                               FSUB_ASIMDSAMEFP16_ONLY
    (b'\x78\x17\xD1\x0E', 'LLIL_FSUB.w(LLIL_REG.w(v24.h[0]),LLIL_REG.w(v27.h[0]));' + \
                         ' LLIL_FSUB.w(LLIL_REG.w(v24.h[1]),LLIL_REG.w(v27.h[1]));' + \
                         ' LLIL_FSUB.w(LLIL_REG.w(v24.h[2]),LLIL_REG.w(v27.h[2]));' + \
                         ' LLIL_FSUB.w(LLIL_REG.w(v24.h[3]),LLIL_REG.w(v27.h[3]))'),
]

tests_fmul = [
    # fmul v7.2d, v20.2d, v1.2d                                FMUL_asimdsame_only
    (b'\x87\xDE\x61\x6E', 'LLIL_SET_REG.q(v7.d[0],LLIL_FMUL.q(LLIL_REG.q(v20.d[0]),LLIL_REG.q(v1.d[0])));' + \
                         ' LLIL_SET_REG.q(v7.d[1],LLIL_FMUL.q(LLIL_REG.q(v20.d[1]),LLIL_REG.q(v1.d[1])))'),
    # fmul v28.2s, v21.2s, v1.2s                                FMUL_asimdsame_only
    (b'\xBC\xDE\x21\x2E', 'LLIL_SET_REG.d(v28.s[0],LLIL_FMUL.d(LLIL_REG.d(v21.s[0]),LLIL_REG.d(v1.s[0])));' + \
                         ' LLIL_SET_REG.d(v28.s[1],LLIL_FMUL.d(LLIL_REG.d(v21.s[1]),LLIL_REG.d(v1.s[1])))'),
    # fmul v6.2s, v21.2s, v1.2s                                FMUL_asimdsame_only
    (b'\xA6\xDE\x21\x2E', 'LLIL_SET_REG.d(v6.s[0],LLIL_FMUL.d(LLIL_REG.d(v21.s[0]),LLIL_REG.d(v1.s[0])));' + \
                         ' LLIL_SET_REG.d(v6.s[1],LLIL_FMUL.d(LLIL_REG.d(v21.s[1]),LLIL_REG.d(v1.s[1])))'),
    # fmul v22.4s, v15.4s, v26.4s                               FMUL_asimdsame_only
    (b'\xF6\xDD\x3A\x6E', 'LLIL_SET_REG.d(v22.s[0],LLIL_FMUL.d(LLIL_REG.d(v15.s[0]),LLIL_REG.d(v26.s[0])));' + \
                         ' LLIL_SET_REG.d(v22.s[1],LLIL_FMUL.d(LLIL_REG.d(v15.s[1]),LLIL_REG.d(v26.s[1])));' + \
                         ' LLIL_SET_REG.d(v22.s[2],LLIL_FMUL.d(LLIL_REG.d(v15.s[2]),LLIL_REG.d(v26.s[2])));' + \
                         ' LLIL_SET_REG.d(v22.s[3],LLIL_FMUL.d(LLIL_REG.d(v15.s[3]),LLIL_REG.d(v26.s[3])))'),
    # fmul v13.2s, v10.2s, v21.2s                               FMUL_asimdsame_only
    (b'\x4D\xDD\x35\x2E', 'LLIL_SET_REG.d(v13.s[0],LLIL_FMUL.d(LLIL_REG.d(v10.s[0]),LLIL_REG.d(v21.s[0])));' + \
                         ' LLIL_SET_REG.d(v13.s[1],LLIL_FMUL.d(LLIL_REG.d(v10.s[1]),LLIL_REG.d(v21.s[1])))'),
    # fmul v22.4s, v6.4s, v31.4s                                FMUL_asimdsame_only
    (b'\xD6\xDC\x3F\x6E', 'LLIL_SET_REG.d(v22.s[0],LLIL_FMUL.d(LLIL_REG.d(v6.s[0]),LLIL_REG.d(v31.s[0])));' + \
                         ' LLIL_SET_REG.d(v22.s[1],LLIL_FMUL.d(LLIL_REG.d(v6.s[1]),LLIL_REG.d(v31.s[1])));' + \
                         ' LLIL_SET_REG.d(v22.s[2],LLIL_FMUL.d(LLIL_REG.d(v6.s[2]),LLIL_REG.d(v31.s[2])));' + \
                         ' LLIL_SET_REG.d(v22.s[3],LLIL_FMUL.d(LLIL_REG.d(v6.s[3]),LLIL_REG.d(v31.s[3])))'),
    # fmul v18.2d, v3.2d, v26.2d                                FMUL_asimdsame_only
    (b'\x72\xDC\x7A\x6E', 'LLIL_SET_REG.q(v18.d[0],LLIL_FMUL.q(LLIL_REG.q(v3.d[0]),LLIL_REG.q(v26.d[0])));' + \
                         ' LLIL_SET_REG.q(v18.d[1],LLIL_FMUL.q(LLIL_REG.q(v3.d[1]),LLIL_REG.q(v26.d[1])))'),
    # fmul v14.2d, v19.2d, v23.2d                               FMUL_asimdsame_only
    (b'\x6E\xDE\x77\x6E', 'LLIL_SET_REG.q(v14.d[0],LLIL_FMUL.q(LLIL_REG.q(v19.d[0]),LLIL_REG.q(v23.d[0])));' + \
                         ' LLIL_SET_REG.q(v14.d[1],LLIL_FMUL.q(LLIL_REG.q(v19.d[1]),LLIL_REG.q(v23.d[1])))'),
    # fmul v14.4h, v25.4h, v26.4h                               FMUL_asimdsamefp16_only
    (b'\x2E\x1F\x5A\x2E', 'LLIL_SET_REG.w(v14.h[0],LLIL_FMUL.w(LLIL_REG.w(v25.h[0]),LLIL_REG.w(v26.h[0])));' + \
                         ' LLIL_SET_REG.w(v14.h[1],LLIL_FMUL.w(LLIL_REG.w(v25.h[1]),LLIL_REG.w(v26.h[1])));' + \
                         ' LLIL_SET_REG.w(v14.h[2],LLIL_FMUL.w(LLIL_REG.w(v25.h[2]),LLIL_REG.w(v26.h[2])));' + \
                         ' LLIL_SET_REG.w(v14.h[3],LLIL_FMUL.w(LLIL_REG.w(v25.h[3]),LLIL_REG.w(v26.h[3])))'),
    # fmul v24.4h, v21.4h, v29.4h                               FMUL_asimdsamefp16_only
    (b'\xB8\x1E\x5D\x2E', 'LLIL_SET_REG.w(v24.h[0],LLIL_FMUL.w(LLIL_REG.w(v21.h[0]),LLIL_REG.w(v29.h[0])));' + \
                         ' LLIL_SET_REG.w(v24.h[1],LLIL_FMUL.w(LLIL_REG.w(v21.h[1]),LLIL_REG.w(v29.h[1])));' + \
                         ' LLIL_SET_REG.w(v24.h[2],LLIL_FMUL.w(LLIL_REG.w(v21.h[2]),LLIL_REG.w(v29.h[2])));' + \
                         ' LLIL_SET_REG.w(v24.h[3],LLIL_FMUL.w(LLIL_REG.w(v21.h[3]),LLIL_REG.w(v29.h[3])))'),
    # fmul v22.8h, v17.8h, v26.8h                               FMUL_asimdsamefp16_only
    (b'\x36\x1E\x5A\x6E', 'LLIL_SET_REG.w(v22.h[0],LLIL_FMUL.w(LLIL_REG.w(v17.h[0]),LLIL_REG.w(v26.h[0])));' + \
                         ' LLIL_SET_REG.w(v22.h[1],LLIL_FMUL.w(LLIL_REG.w(v17.h[1]),LLIL_REG.w(v26.h[1])));' + \
                         ' LLIL_SET_REG.w(v22.h[2],LLIL_FMUL.w(LLIL_REG.w(v17.h[2]),LLIL_REG.w(v26.h[2])));' + \
                         ' LLIL_SET_REG.w(v22.h[3],LLIL_FMUL.w(LLIL_REG.w(v17.h[3]),LLIL_REG.w(v26.h[3])));' + \
                         ' LLIL_SET_REG.w(v22.h[4],LLIL_FMUL.w(LLIL_REG.w(v17.h[4]),LLIL_REG.w(v26.h[4])));' + \
                         ' LLIL_SET_REG.w(v22.h[5],LLIL_FMUL.w(LLIL_REG.w(v17.h[5]),LLIL_REG.w(v26.h[5])));' + \
                         ' LLIL_SET_REG.w(v22.h[6],LLIL_FMUL.w(LLIL_REG.w(v17.h[6]),LLIL_REG.w(v26.h[6])));' + \
                         ' LLIL_SET_REG.w(v22.h[7],LLIL_FMUL.w(LLIL_REG.w(v17.h[7]),LLIL_REG.w(v26.h[7])))'),
    # fmul v9.8h, v2.8h, v17.8h                                FMUL_asimdsamefp16_only
    (b'\x49\x1C\x51\x6E', 'LLIL_SET_REG.w(v9.h[0],LLIL_FMUL.w(LLIL_REG.w(v2.h[0]),LLIL_REG.w(v17.h[0])));' + \
                         ' LLIL_SET_REG.w(v9.h[1],LLIL_FMUL.w(LLIL_REG.w(v2.h[1]),LLIL_REG.w(v17.h[1])));' + \
                         ' LLIL_SET_REG.w(v9.h[2],LLIL_FMUL.w(LLIL_REG.w(v2.h[2]),LLIL_REG.w(v17.h[2])));' + \
                         ' LLIL_SET_REG.w(v9.h[3],LLIL_FMUL.w(LLIL_REG.w(v2.h[3]),LLIL_REG.w(v17.h[3])));' + \
                         ' LLIL_SET_REG.w(v9.h[4],LLIL_FMUL.w(LLIL_REG.w(v2.h[4]),LLIL_REG.w(v17.h[4])));' + \
                         ' LLIL_SET_REG.w(v9.h[5],LLIL_FMUL.w(LLIL_REG.w(v2.h[5]),LLIL_REG.w(v17.h[5])));' + \
                         ' LLIL_SET_REG.w(v9.h[6],LLIL_FMUL.w(LLIL_REG.w(v2.h[6]),LLIL_REG.w(v17.h[6])));' + \
                         ' LLIL_SET_REG.w(v9.h[7],LLIL_FMUL.w(LLIL_REG.w(v2.h[7]),LLIL_REG.w(v17.h[7])))'),
    # fmul v9.8h, v31.8h, v4.8h                                FMUL_asimdsamefp16_only
    (b'\xE9\x1F\x44\x6E', 'LLIL_SET_REG.w(v9.h[0],LLIL_FMUL.w(LLIL_REG.w(v31.h[0]),LLIL_REG.w(v4.h[0])));' + \
                         ' LLIL_SET_REG.w(v9.h[1],LLIL_FMUL.w(LLIL_REG.w(v31.h[1]),LLIL_REG.w(v4.h[1])));' + \
                         ' LLIL_SET_REG.w(v9.h[2],LLIL_FMUL.w(LLIL_REG.w(v31.h[2]),LLIL_REG.w(v4.h[2])));' + \
                         ' LLIL_SET_REG.w(v9.h[3],LLIL_FMUL.w(LLIL_REG.w(v31.h[3]),LLIL_REG.w(v4.h[3])));' + \
                         ' LLIL_SET_REG.w(v9.h[4],LLIL_FMUL.w(LLIL_REG.w(v31.h[4]),LLIL_REG.w(v4.h[4])));' + \
                         ' LLIL_SET_REG.w(v9.h[5],LLIL_FMUL.w(LLIL_REG.w(v31.h[5]),LLIL_REG.w(v4.h[5])));' + \
                         ' LLIL_SET_REG.w(v9.h[6],LLIL_FMUL.w(LLIL_REG.w(v31.h[6]),LLIL_REG.w(v4.h[6])));' + \
                         ' LLIL_SET_REG.w(v9.h[7],LLIL_FMUL.w(LLIL_REG.w(v31.h[7]),LLIL_REG.w(v4.h[7])))'),
    # fmul v21.4h, v19.4h, v2.4h                                FMUL_asimdsamefp16_only
    (b'\x75\x1E\x42\x2E', 'LLIL_SET_REG.w(v21.h[0],LLIL_FMUL.w(LLIL_REG.w(v19.h[0]),LLIL_REG.w(v2.h[0])));' + \
                         ' LLIL_SET_REG.w(v21.h[1],LLIL_FMUL.w(LLIL_REG.w(v19.h[1]),LLIL_REG.w(v2.h[1])));' + \
                         ' LLIL_SET_REG.w(v21.h[2],LLIL_FMUL.w(LLIL_REG.w(v19.h[2]),LLIL_REG.w(v2.h[2])));' + \
                         ' LLIL_SET_REG.w(v21.h[3],LLIL_FMUL.w(LLIL_REG.w(v19.h[3]),LLIL_REG.w(v2.h[3])))'),
    # fmul v24.8h, v4.8h, v20.8h                                FMUL_asimdsamefp16_only
    (b'\x98\x1C\x54\x6E', 'LLIL_SET_REG.w(v24.h[0],LLIL_FMUL.w(LLIL_REG.w(v4.h[0]),LLIL_REG.w(v20.h[0])));' + \
                         ' LLIL_SET_REG.w(v24.h[1],LLIL_FMUL.w(LLIL_REG.w(v4.h[1]),LLIL_REG.w(v20.h[1])));' + \
                         ' LLIL_SET_REG.w(v24.h[2],LLIL_FMUL.w(LLIL_REG.w(v4.h[2]),LLIL_REG.w(v20.h[2])));' + \
                         ' LLIL_SET_REG.w(v24.h[3],LLIL_FMUL.w(LLIL_REG.w(v4.h[3]),LLIL_REG.w(v20.h[3])));' + \
                         ' LLIL_SET_REG.w(v24.h[4],LLIL_FMUL.w(LLIL_REG.w(v4.h[4]),LLIL_REG.w(v20.h[4])));' + \
                         ' LLIL_SET_REG.w(v24.h[5],LLIL_FMUL.w(LLIL_REG.w(v4.h[5]),LLIL_REG.w(v20.h[5])));' + \
                         ' LLIL_SET_REG.w(v24.h[6],LLIL_FMUL.w(LLIL_REG.w(v4.h[6]),LLIL_REG.w(v20.h[6])));' + \
                         ' LLIL_SET_REG.w(v24.h[7],LLIL_FMUL.w(LLIL_REG.w(v4.h[7]),LLIL_REG.w(v20.h[7])))'),
    # fmul v29.4h, v12.4h, v5.4h                                FMUL_asimdsamefp16_only
    (b'\x9D\x1D\x45\x2E', 'LLIL_SET_REG.w(v29.h[0],LLIL_FMUL.w(LLIL_REG.w(v12.h[0]),LLIL_REG.w(v5.h[0])));' + \
                         ' LLIL_SET_REG.w(v29.h[1],LLIL_FMUL.w(LLIL_REG.w(v12.h[1]),LLIL_REG.w(v5.h[1])));' + \
                         ' LLIL_SET_REG.w(v29.h[2],LLIL_FMUL.w(LLIL_REG.w(v12.h[2]),LLIL_REG.w(v5.h[2])));' + \
                         ' LLIL_SET_REG.w(v29.h[3],LLIL_FMUL.w(LLIL_REG.w(v12.h[3]),LLIL_REG.w(v5.h[3])))'),
    # fmul v2.4h, v23.4h, v15.h[0]                              FMUL_asimdelem_RH_H
    (b'\xE2\x92\x0F\x0F', 'LLIL_SET_REG.w(v2.h[0],LLIL_FMUL.w(LLIL_REG.w(v23.h[0]),LLIL_REG.w(v15.h[0])));' + \
                         ' LLIL_SET_REG.w(v2.h[1],LLIL_FMUL.w(LLIL_REG.w(v23.h[1]),LLIL_REG.w(v15.h[0])));' + \
                         ' LLIL_SET_REG.w(v2.h[2],LLIL_FMUL.w(LLIL_REG.w(v23.h[2]),LLIL_REG.w(v15.h[0])));' + \
                         ' LLIL_SET_REG.w(v2.h[3],LLIL_FMUL.w(LLIL_REG.w(v23.h[3]),LLIL_REG.w(v15.h[0])))'),
    # fmul v19.4h, v7.4h, v11.h[3]                              FMUL_asimdelem_RH_H
    (b'\xF3\x90\x3B\x0F', 'LLIL_SET_REG.w(v19.h[0],LLIL_FMUL.w(LLIL_REG.w(v7.h[0]),LLIL_REG.w(v11.h[3])));' + \
                         ' LLIL_SET_REG.w(v19.h[1],LLIL_FMUL.w(LLIL_REG.w(v7.h[1]),LLIL_REG.w(v11.h[3])));' + \
                         ' LLIL_SET_REG.w(v19.h[2],LLIL_FMUL.w(LLIL_REG.w(v7.h[2]),LLIL_REG.w(v11.h[3])));' + \
                         ' LLIL_SET_REG.w(v19.h[3],LLIL_FMUL.w(LLIL_REG.w(v7.h[3]),LLIL_REG.w(v11.h[3])))'),
    # fmul v31.4h, v8.4h, v9.h[1]                               FMUL_asimdelem_RH_H
    (b'\x1F\x91\x19\x0F', 'LLIL_SET_REG.w(v31.h[0],LLIL_FMUL.w(LLIL_REG.w(v8.h[0]),LLIL_REG.w(v9.h[1])));' + \
                         ' LLIL_SET_REG.w(v31.h[1],LLIL_FMUL.w(LLIL_REG.w(v8.h[1]),LLIL_REG.w(v9.h[1])));' + \
                         ' LLIL_SET_REG.w(v31.h[2],LLIL_FMUL.w(LLIL_REG.w(v8.h[2]),LLIL_REG.w(v9.h[1])));' + \
                         ' LLIL_SET_REG.w(v31.h[3],LLIL_FMUL.w(LLIL_REG.w(v8.h[3]),LLIL_REG.w(v9.h[1])))'),
    # fmul v11.8h, v27.8h, v9.h[4]                              FMUL_asimdelem_RH_H
    (b'\x6B\x9B\x09\x4F', 'LLIL_SET_REG.w(v11.h[0],LLIL_FMUL.w(LLIL_REG.w(v27.h[0]),LLIL_REG.w(v9.h[4])));' + \
                         ' LLIL_SET_REG.w(v11.h[1],LLIL_FMUL.w(LLIL_REG.w(v27.h[1]),LLIL_REG.w(v9.h[4])));' + \
                         ' LLIL_SET_REG.w(v11.h[2],LLIL_FMUL.w(LLIL_REG.w(v27.h[2]),LLIL_REG.w(v9.h[4])));' + \
                         ' LLIL_SET_REG.w(v11.h[3],LLIL_FMUL.w(LLIL_REG.w(v27.h[3]),LLIL_REG.w(v9.h[4])));' + \
                         ' LLIL_SET_REG.w(v11.h[4],LLIL_FMUL.w(LLIL_REG.w(v27.h[4]),LLIL_REG.w(v9.h[4])));' + \
                         ' LLIL_SET_REG.w(v11.h[5],LLIL_FMUL.w(LLIL_REG.w(v27.h[5]),LLIL_REG.w(v9.h[4])));' + \
                         ' LLIL_SET_REG.w(v11.h[6],LLIL_FMUL.w(LLIL_REG.w(v27.h[6]),LLIL_REG.w(v9.h[4])));' + \
                         ' LLIL_SET_REG.w(v11.h[7],LLIL_FMUL.w(LLIL_REG.w(v27.h[7]),LLIL_REG.w(v9.h[4])))'),
    # fmul v5.4h, v5.4h, v5.h[7]                                FMUL_asimdelem_RH_H
    (b'\xA5\x98\x35\x0F', 'LLIL_SET_REG.w(v5.h[0],LLIL_FMUL.w(LLIL_REG.w(v5.h[0]),LLIL_REG.w(v5.h[7])));' + \
                         ' LLIL_SET_REG.w(v5.h[1],LLIL_FMUL.w(LLIL_REG.w(v5.h[1]),LLIL_REG.w(v5.h[7])));' + \
                         ' LLIL_SET_REG.w(v5.h[2],LLIL_FMUL.w(LLIL_REG.w(v5.h[2]),LLIL_REG.w(v5.h[7])));' + \
                         ' LLIL_SET_REG.w(v5.h[3],LLIL_FMUL.w(LLIL_REG.w(v5.h[3]),LLIL_REG.w(v5.h[7])))'),
    # fmul v7.8h, v22.8h, v12.h[3]                              FMUL_asimdelem_RH_H
    (b'\xC7\x92\x3C\x4F', 'LLIL_SET_REG.w(v7.h[0],LLIL_FMUL.w(LLIL_REG.w(v22.h[0]),LLIL_REG.w(v12.h[3])));' + \
                         ' LLIL_SET_REG.w(v7.h[1],LLIL_FMUL.w(LLIL_REG.w(v22.h[1]),LLIL_REG.w(v12.h[3])));' + \
                         ' LLIL_SET_REG.w(v7.h[2],LLIL_FMUL.w(LLIL_REG.w(v22.h[2]),LLIL_REG.w(v12.h[3])));' + \
                         ' LLIL_SET_REG.w(v7.h[3],LLIL_FMUL.w(LLIL_REG.w(v22.h[3]),LLIL_REG.w(v12.h[3])));' + \
                         ' LLIL_SET_REG.w(v7.h[4],LLIL_FMUL.w(LLIL_REG.w(v22.h[4]),LLIL_REG.w(v12.h[3])));' + \
                         ' LLIL_SET_REG.w(v7.h[5],LLIL_FMUL.w(LLIL_REG.w(v22.h[5]),LLIL_REG.w(v12.h[3])));' + \
                         ' LLIL_SET_REG.w(v7.h[6],LLIL_FMUL.w(LLIL_REG.w(v22.h[6]),LLIL_REG.w(v12.h[3])));' + \
                         ' LLIL_SET_REG.w(v7.h[7],LLIL_FMUL.w(LLIL_REG.w(v22.h[7]),LLIL_REG.w(v12.h[3])))'),
    # fmul v17.4h, v22.4h, v5.h[0]                              FMUL_asimdelem_RH_H
    (b'\xD1\x92\x05\x0F', 'LLIL_SET_REG.w(v17.h[0],LLIL_FMUL.w(LLIL_REG.w(v22.h[0]),LLIL_REG.w(v5.h[0])));' + \
                         ' LLIL_SET_REG.w(v17.h[1],LLIL_FMUL.w(LLIL_REG.w(v22.h[1]),LLIL_REG.w(v5.h[0])));' + \
                         ' LLIL_SET_REG.w(v17.h[2],LLIL_FMUL.w(LLIL_REG.w(v22.h[2]),LLIL_REG.w(v5.h[0])));' + \
                         ' LLIL_SET_REG.w(v17.h[3],LLIL_FMUL.w(LLIL_REG.w(v22.h[3]),LLIL_REG.w(v5.h[0])))'),
    # fmul v24.8h, v14.8h, v0.h[5]                              FMUL_asimdelem_RH_H
    (b'\xD8\x99\x10\x4F', 'LLIL_SET_REG.w(v24.h[0],LLIL_FMUL.w(LLIL_REG.w(v14.h[0]),LLIL_REG.w(v0.h[5])));' + \
                         ' LLIL_SET_REG.w(v24.h[1],LLIL_FMUL.w(LLIL_REG.w(v14.h[1]),LLIL_REG.w(v0.h[5])));' + \
                         ' LLIL_SET_REG.w(v24.h[2],LLIL_FMUL.w(LLIL_REG.w(v14.h[2]),LLIL_REG.w(v0.h[5])));' + \
                         ' LLIL_SET_REG.w(v24.h[3],LLIL_FMUL.w(LLIL_REG.w(v14.h[3]),LLIL_REG.w(v0.h[5])));' + \
                         ' LLIL_SET_REG.w(v24.h[4],LLIL_FMUL.w(LLIL_REG.w(v14.h[4]),LLIL_REG.w(v0.h[5])));' + \
                         ' LLIL_SET_REG.w(v24.h[5],LLIL_FMUL.w(LLIL_REG.w(v14.h[5]),LLIL_REG.w(v0.h[5])));' + \
                         ' LLIL_SET_REG.w(v24.h[6],LLIL_FMUL.w(LLIL_REG.w(v14.h[6]),LLIL_REG.w(v0.h[5])));' + \
                         ' LLIL_SET_REG.w(v24.h[7],LLIL_FMUL.w(LLIL_REG.w(v14.h[7]),LLIL_REG.w(v0.h[5])))'),
    # fmul v1.2s, v1.2s, v0.s[0]                                FMUL_asimdelem_R_SD
    (b'\x21\x90\x80\x0F', 'LLIL_SET_REG.d(v1.s[0],LLIL_FMUL.d(LLIL_REG.d(v1.s[0]),LLIL_REG.d(v0.s[0])));' + \
                         ' LLIL_SET_REG.d(v1.s[1],LLIL_FMUL.d(LLIL_REG.d(v1.s[1]),LLIL_REG.d(v0.s[0])))'),
    # fmul v5.2d, v11.2d, v3.d[1]                               FMUL_asimdelem_R_SD
    (b'\x65\x99\xC3\x4F', 'LLIL_SET_REG.q(v5.d[0],LLIL_FMUL.q(LLIL_REG.q(v11.d[0]),LLIL_REG.q(v3.d[1])));' + \
                         ' LLIL_SET_REG.q(v5.d[1],LLIL_FMUL.q(LLIL_REG.q(v11.d[1]),LLIL_REG.q(v3.d[1])))'),
    # fmul v23.4s, v4.4s, v3.s[3]                               FMUL_asimdelem_R_SD
    (b'\x97\x98\xA3\x4F', 'LLIL_SET_REG.d(v23.s[0],LLIL_FMUL.d(LLIL_REG.d(v4.s[0]),LLIL_REG.d(v3.s[3])));' + \
                         ' LLIL_SET_REG.d(v23.s[1],LLIL_FMUL.d(LLIL_REG.d(v4.s[1]),LLIL_REG.d(v3.s[3])));' + \
                         ' LLIL_SET_REG.d(v23.s[2],LLIL_FMUL.d(LLIL_REG.d(v4.s[2]),LLIL_REG.d(v3.s[3])));' + \
                         ' LLIL_SET_REG.d(v23.s[3],LLIL_FMUL.d(LLIL_REG.d(v4.s[3]),LLIL_REG.d(v3.s[3])))'),
    # fmul v16.2s, v15.2s, v21.s[1]                             FMUL_asimdelem_R_SD
    (b'\xF0\x91\xB5\x0F', 'LLIL_SET_REG.d(v16.s[0],LLIL_FMUL.d(LLIL_REG.d(v15.s[0]),LLIL_REG.d(v21.s[1])));' + \
                         ' LLIL_SET_REG.d(v16.s[1],LLIL_FMUL.d(LLIL_REG.d(v15.s[1]),LLIL_REG.d(v21.s[1])))'),
    # fmul v24.2s, v18.2s, v5.s[1]                              FMUL_asimdelem_R_SD
    (b'\x58\x92\xA5\x0F', 'LLIL_SET_REG.d(v24.s[0],LLIL_FMUL.d(LLIL_REG.d(v18.s[0]),LLIL_REG.d(v5.s[1])));' + \
                         ' LLIL_SET_REG.d(v24.s[1],LLIL_FMUL.d(LLIL_REG.d(v18.s[1]),LLIL_REG.d(v5.s[1])))'),
    # fmul v24.2d, v11.2d, v8.d[0]                              FMUL_asimdelem_R_SD
    (b'\x78\x91\xC8\x4F', 'LLIL_SET_REG.q(v24.d[0],LLIL_FMUL.q(LLIL_REG.q(v11.d[0]),LLIL_REG.q(v8.d[0])));' + \
                         ' LLIL_SET_REG.q(v24.d[1],LLIL_FMUL.q(LLIL_REG.q(v11.d[1]),LLIL_REG.q(v8.d[0])))'),
    # fmul v7.2s, v0.2s, v12.s[0]                               FMUL_asimdelem_R_SD
    (b'\x07\x90\x8C\x0F', 'LLIL_SET_REG.d(v7.s[0],LLIL_FMUL.d(LLIL_REG.d(v0.s[0]),LLIL_REG.d(v12.s[0])));' + \
                         ' LLIL_SET_REG.d(v7.s[1],LLIL_FMUL.d(LLIL_REG.d(v0.s[1]),LLIL_REG.d(v12.s[0])))'),
    # fmul v9.4s, v9.4s, v25.s[2]                               FMUL_asimdelem_R_SD
    (b'\x29\x99\x99\x4F', 'LLIL_SET_REG.d(v9.s[0],LLIL_FMUL.d(LLIL_REG.d(v9.s[0]),LLIL_REG.d(v25.s[2])));' + \
                         ' LLIL_SET_REG.d(v9.s[1],LLIL_FMUL.d(LLIL_REG.d(v9.s[1]),LLIL_REG.d(v25.s[2])));' + \
                         ' LLIL_SET_REG.d(v9.s[2],LLIL_FMUL.d(LLIL_REG.d(v9.s[2]),LLIL_REG.d(v25.s[2])));' + \
                         ' LLIL_SET_REG.d(v9.s[3],LLIL_FMUL.d(LLIL_REG.d(v9.s[3]),LLIL_REG.d(v25.s[2])))'),
    # fmul v7.2d, v20.2d, v1.2d                                FMUL_asimdsame_only
    (b'\x87\xDE\x61\x6E', 'LLIL_SET_REG.q(v7.d[0],LLIL_FMUL.q(LLIL_REG.q(v20.d[0]),LLIL_REG.q(v1.d[0])));' + \
                         ' LLIL_SET_REG.q(v7.d[1],LLIL_FMUL.q(LLIL_REG.q(v20.d[1]),LLIL_REG.q(v1.d[1])))'),
    # fmul v28.2s, v21.2s, v1.2s                                FMUL_asimdsame_only
    (b'\xBC\xDE\x21\x2E', 'LLIL_SET_REG.d(v28.s[0],LLIL_FMUL.d(LLIL_REG.d(v21.s[0]),LLIL_REG.d(v1.s[0])));' + \
                         ' LLIL_SET_REG.d(v28.s[1],LLIL_FMUL.d(LLIL_REG.d(v21.s[1]),LLIL_REG.d(v1.s[1])))'),
    # fmul h19, h5, v4.h[3]                                    FMUL_asisdelem_RH_H
    (b'\xB3\x90\x34\x5F', 'LLIL_SET_REG.w(h19,LLIL_FMUL.w(LLIL_REG.w(h5),LLIL_REG.w(v4.h[3])))'),
    # fmul h0, h5, v2.h[7]                                    FMUL_asisdelem_RH_H
    (b'\xA0\x98\x32\x5F', 'LLIL_SET_REG.w(h0,LLIL_FMUL.w(LLIL_REG.w(h5),LLIL_REG.w(v2.h[7])))'),
    # fmul h18, h14, v11.h[5]                                  FMUL_asisdelem_RH_H
    (b'\xD2\x99\x1B\x5F', 'LLIL_SET_REG.w(h18,LLIL_FMUL.w(LLIL_REG.w(h14),LLIL_REG.w(v11.h[5])))'),
    # fmul h10, h7, v2.h[6]                                    FMUL_asisdelem_RH_H
    (b'\xEA\x98\x22\x5F', 'LLIL_SET_REG.w(h10,LLIL_FMUL.w(LLIL_REG.w(h7),LLIL_REG.w(v2.h[6])))'),
    # fmul h24, h25, v1.h[7]                                   FMUL_asisdelem_RH_H
    (b'\x38\x9B\x31\x5F', 'LLIL_SET_REG.w(h24,LLIL_FMUL.w(LLIL_REG.w(h25),LLIL_REG.w(v1.h[7])))'),
    # fmul h2, h14, v2.h[6]                                    FMUL_asisdelem_RH_H
    (b'\xC2\x99\x22\x5F', 'LLIL_SET_REG.w(h2,LLIL_FMUL.w(LLIL_REG.w(h14),LLIL_REG.w(v2.h[6])))'),
    # fmul h17, h28, v6.h[4]                                   FMUL_asisdelem_RH_H
    (b'\x91\x9B\x06\x5F', 'LLIL_SET_REG.w(h17,LLIL_FMUL.w(LLIL_REG.w(h28),LLIL_REG.w(v6.h[4])))'),
    # fmul h15, h3, v9.h[7]                                    FMUL_asisdelem_RH_H
    (b'\x6F\x98\x39\x5F', 'LLIL_SET_REG.w(h15,LLIL_FMUL.w(LLIL_REG.w(h3),LLIL_REG.w(v9.h[7])))'),
    # fmul s21, s9, v5.s[3]                                    FMUL_asisdelem_R_SD
    (b'\x35\x99\xA5\x5F', 'LLIL_SET_REG.d(s21,LLIL_FMUL.d(LLIL_REG.d(s9),LLIL_REG.d(v5.s[3])))'),
    # fmul s29, s0, v16.s[1]                                   FMUL_asisdelem_R_SD
    (b'\x1D\x90\xB0\x5F', 'LLIL_SET_REG.d(s29,LLIL_FMUL.d(LLIL_REG.d(s0),LLIL_REG.d(v16.s[1])))'),
    # fmul s25, s8, v30.s[1]                                   FMUL_asisdelem_R_SD
    (b'\x19\x91\xBE\x5F', 'LLIL_SET_REG.d(s25,LLIL_FMUL.d(LLIL_REG.d(s8),LLIL_REG.d(v30.s[1])))'),
    # fmul d2, d27, v4.d[0]                                    FMUL_asisdelem_R_SD
    (b'\x62\x93\xC4\x5F', 'LLIL_SET_REG.q(d2,LLIL_FMUL.q(LLIL_REG.q(d27),LLIL_REG.q(v4.d[0])))'),
    # fmul d26, d3, v27.d[1]                                   FMUL_asisdelem_R_SD
    (b'\x7A\x98\xDB\x5F', 'LLIL_SET_REG.q(d26,LLIL_FMUL.q(LLIL_REG.q(d3),LLIL_REG.q(v27.d[1])))'),
    # fmul s26, s30, v13.s[3]                                  FMUL_asisdelem_R_SD
    (b'\xDA\x9B\xAD\x5F', 'LLIL_SET_REG.d(s26,LLIL_FMUL.d(LLIL_REG.d(s30),LLIL_REG.d(v13.s[3])))'),
    # fmul s4, s24, v8.s[3]                                    FMUL_asisdelem_R_SD
    (b'\x04\x9B\xA8\x5F', 'LLIL_SET_REG.d(s4,LLIL_FMUL.d(LLIL_REG.d(s24),LLIL_REG.d(v8.s[3])))'),
    # fmul s28, s11, v9.s[0]                                   FMUL_asisdelem_R_SD
    (b'\x7C\x91\x89\x5F', 'LLIL_SET_REG.d(s28,LLIL_FMUL.d(LLIL_REG.d(s11),LLIL_REG.d(v9.s[0])))'),
]

tests_fadd = [
    # fadd d30, d9, d18                                       FADD_D_FLOATDP2
    (b'\x3E\x29\x72\x1E', 'LLIL_SET_REG.q(d30,LLIL_FADD.q(LLIL_REG.q(d9),LLIL_REG.q(d18)))'),
    # fadd d23, d15, d25                                      FADD_D_FLOATDP2
    (b'\xF7\x29\x79\x1E', 'LLIL_SET_REG.q(d23,LLIL_FADD.q(LLIL_REG.q(d15),LLIL_REG.q(d25)))'),
    # fadd h24, h23, h13                                      FADD_H_FLOATDP2
    (b'\xF8\x2A\xED\x1E', 'LLIL_SET_REG.w(h24,LLIL_FADD.w(LLIL_REG.w(h23),LLIL_REG.w(h13)))'),
    # fadd h17, h1, h30                                       FADD_H_FLOATDP2
    (b'\x31\x28\xFE\x1E', 'LLIL_SET_REG.w(h17,LLIL_FADD.w(LLIL_REG.w(h1),LLIL_REG.w(h30)))'),
    # fadd s18, s19, s31                                      FADD_S_FLOATDP2
    (b'\x72\x2A\x3F\x1E', 'LLIL_SET_REG.d(s18,LLIL_FADD.d(LLIL_REG.d(s19),LLIL_REG.d(s31)))'),
    # fadd s30, s2, s14                                       FADD_S_FLOATDP2
    (b'\x5E\x28\x2E\x1E', 'LLIL_SET_REG.d(s30,LLIL_FADD.d(LLIL_REG.d(s2),LLIL_REG.d(s14)))'),
    # fadd v25.2s, v15.2s, v27.2s                               FADD_ASIMDSAME_ONLY
    (b'\xF9\xD5\x3B\x0E', 'LLIL_SET_REG.d(v25.s[0],LLIL_FADD.d(LLIL_REG.d(v15.s[0]),LLIL_REG.d(v27.s[0])));' + \
                         ' LLIL_SET_REG.d(v25.s[1],LLIL_FADD.d(LLIL_REG.d(v15.s[1]),LLIL_REG.d(v27.s[1])))'),
    # fadd v26.2s, v15.2s, v21.2s                               FADD_ASIMDSAME_ONLY
    (b'\xFA\xD5\x35\x0E', 'LLIL_SET_REG.d(v26.s[0],LLIL_FADD.d(LLIL_REG.d(v15.s[0]),LLIL_REG.d(v21.s[0])));' + \
                         ' LLIL_SET_REG.d(v26.s[1],LLIL_FADD.d(LLIL_REG.d(v15.s[1]),LLIL_REG.d(v21.s[1])))'),
    # fadd v21.8h, v20.8h, v16.8h                               FADD_ASIMDSAMEFP16_ONLY
    (b'\x95\x16\x50\x4E', 'LLIL_SET_REG.w(v21.h[0],LLIL_FADD.w(LLIL_REG.w(v20.h[0]),LLIL_REG.w(v16.h[0])));' + \
                         ' LLIL_SET_REG.w(v21.h[1],LLIL_FADD.w(LLIL_REG.w(v20.h[1]),LLIL_REG.w(v16.h[1])));' + \
                         ' LLIL_SET_REG.w(v21.h[2],LLIL_FADD.w(LLIL_REG.w(v20.h[2]),LLIL_REG.w(v16.h[2])));' + \
                         ' LLIL_SET_REG.w(v21.h[3],LLIL_FADD.w(LLIL_REG.w(v20.h[3]),LLIL_REG.w(v16.h[3])));' + \
                         ' LLIL_SET_REG.w(v21.h[4],LLIL_FADD.w(LLIL_REG.w(v20.h[4]),LLIL_REG.w(v16.h[4])));' + \
                         ' LLIL_SET_REG.w(v21.h[5],LLIL_FADD.w(LLIL_REG.w(v20.h[5]),LLIL_REG.w(v16.h[5])));' + \
                         ' LLIL_SET_REG.w(v21.h[6],LLIL_FADD.w(LLIL_REG.w(v20.h[6]),LLIL_REG.w(v16.h[6])));' + \
                         ' LLIL_SET_REG.w(v21.h[7],LLIL_FADD.w(LLIL_REG.w(v20.h[7]),LLIL_REG.w(v16.h[7])))'),
    # fadd v22.8h, v10.8h, v7.8h                                FADD_ASIMDSAMEFP16_ONLY
    (b'\x56\x15\x47\x4E', 'LLIL_SET_REG.w(v22.h[0],LLIL_FADD.w(LLIL_REG.w(v10.h[0]),LLIL_REG.w(v7.h[0])));' + \
                         ' LLIL_SET_REG.w(v22.h[1],LLIL_FADD.w(LLIL_REG.w(v10.h[1]),LLIL_REG.w(v7.h[1])));' + \
                         ' LLIL_SET_REG.w(v22.h[2],LLIL_FADD.w(LLIL_REG.w(v10.h[2]),LLIL_REG.w(v7.h[2])));' + \
                         ' LLIL_SET_REG.w(v22.h[3],LLIL_FADD.w(LLIL_REG.w(v10.h[3]),LLIL_REG.w(v7.h[3])));' + \
                         ' LLIL_SET_REG.w(v22.h[4],LLIL_FADD.w(LLIL_REG.w(v10.h[4]),LLIL_REG.w(v7.h[4])));' + \
                         ' LLIL_SET_REG.w(v22.h[5],LLIL_FADD.w(LLIL_REG.w(v10.h[5]),LLIL_REG.w(v7.h[5])));' + \
                         ' LLIL_SET_REG.w(v22.h[6],LLIL_FADD.w(LLIL_REG.w(v10.h[6]),LLIL_REG.w(v7.h[6])));' + \
                         ' LLIL_SET_REG.w(v22.h[7],LLIL_FADD.w(LLIL_REG.w(v10.h[7]),LLIL_REG.w(v7.h[7])))'),
]

tests_fcvt = [
    # fcvt d9, h29
    (b'\xA9\xC3\xE2\x1E', 'LLIL_SET_REG.q(d9,LLIL_FLOAT_CONV.q(LLIL_REG.w(h29)))'),
    # fcvt d11, h29
    (b'\xAB\xC3\xE2\x1E', 'LLIL_SET_REG.q(d11,LLIL_FLOAT_CONV.q(LLIL_REG.w(h29)))'),
    # fcvt d27, s12
    (b'\x9B\xC1\x22\x1E', 'LLIL_SET_REG.q(d27,LLIL_FLOAT_CONV.q(LLIL_REG.d(s12)))'),
    # fcvt d18, s7
    (b'\xF2\xC0\x22\x1E', 'LLIL_SET_REG.q(d18,LLIL_FLOAT_CONV.q(LLIL_REG.d(s7)))'),
    # fcvt h11, d15
    (b'\xEB\xC1\x63\x1E', 'LLIL_SET_REG.w(h11,LLIL_FLOAT_CONV.w(LLIL_REG.q(d15)))'),
    # fcvt h4, d8
    (b'\x04\xC1\x63\x1E', 'LLIL_SET_REG.w(h4,LLIL_FLOAT_CONV.w(LLIL_REG.q(d8)))'),
    # fcvt h14, s1
    (b'\x2E\xC0\x23\x1E', 'LLIL_SET_REG.w(h14,LLIL_FLOAT_CONV.w(LLIL_REG.d(s1)))'),
    # fcvt h7, s26
    (b'\x47\xC3\x23\x1E', 'LLIL_SET_REG.w(h7,LLIL_FLOAT_CONV.w(LLIL_REG.d(s26)))'),
    # fcvt s28, d16
    (b'\x1C\x42\x62\x1E', 'LLIL_SET_REG.d(s28,LLIL_FLOAT_CONV.d(LLIL_REG.q(d16)))'),
    # fcvt s28, d13
    (b'\xBC\x41\x62\x1E', 'LLIL_SET_REG.d(s28,LLIL_FLOAT_CONV.d(LLIL_REG.q(d13)))'),
    # fcvt s15, h17
    (b'\x2F\x42\xE2\x1E', 'LLIL_SET_REG.d(s15,LLIL_FLOAT_CONV.d(LLIL_REG.w(h17)))'),
    # fcvt s5, h14
    (b'\xC5\x41\xE2\x1E', 'LLIL_SET_REG.d(s5,LLIL_FLOAT_CONV.d(LLIL_REG.w(h14)))'),
    # fcvtzs x8, d0
    (b'\x08\x00\x78\x9E', 'LLIL_INTRINSIC([x8],vcvtd_s64_f64,[LLIL_REG.q(d0)])'),
    # fcvtzs x15, d0
    (b'\x0F\x00\x78\x9E', 'LLIL_INTRINSIC([x15],vcvtd_s64_f64,[LLIL_REG.q(d0)])'),
    # fcvtzs x9, d1
    (b'\x29\x00\x78\x9E', 'LLIL_INTRINSIC([x9],vcvtd_s64_f64,[LLIL_REG.q(d1)])'),
    # fcvtzu x10, d0
    (b'\x0A\x00\x79\x9E', 'LLIL_INTRINSIC([x10],vcvtd_u64_f64,[LLIL_REG.q(d0)])'),
    # fcvtzu X3, D0, #3
    (b'\x03\xF4\x59\x9E', 'LLIL_INTRINSIC([x3],vcvtd_n_u64_f64,[LLIL_REG.q(d0),LLIL_CONST(3)])'),
    # fcvtzu v23.4s, v22.4s
    (b'\xd7\xba\xa1\x6e', 'LLIL_INTRINSIC([v23],vcvtq_u32_f32,[LLIL_REG.o(v22)])'),
    # fcvtzu v24.2s, v20.2s
    (b'\x98\xba\xa1\x2e', 'LLIL_INTRINSIC([v24],vcvt_u32_f32,[LLIL_REG.o(v20)])'),
    # fcvtzu v9.2d, v18.2d
    (b'\x49\xba\xe1\x6e', 'LLIL_INTRINSIC([v9],vcvtq_u64_f64,[LLIL_REG.o(v18)])'),
    # fcvtzu v16.4h, v1.4h
    (b'\x30\xB8\xF9\x2E', 'LLIL_INTRINSIC([v16],vcvt_u16_f16,[LLIL_REG.o(v1)])'),
    # fcvtzu v28.8h, v5.8h
    (b'\xBC\xB8\xF9\x6E', 'LLIL_INTRINSIC([v28],vcvtq_u16_f16,[LLIL_REG.o(v5)])'),
    # fcvtzu v3.2d, v25.2d, #0x2f
    (b'\x23\xff\x51\x6f', 'LLIL_INTRINSIC([v3],vcvtq_n_u64_f64,[LLIL_REG.o(v25),LLIL_CONST(47)])'),
    # fcvtzu v16.4s, v14.4s, #0x15
    (b'\xd0\xfd\x2b\x6f', 'LLIL_INTRINSIC([v16],vcvtq_n_u32_f32,[LLIL_REG.o(v14),LLIL_CONST(21)])'),
    # fcvtzu v11.2s, v4.2s, #0xb
    (b'\x8b\xfc\x35\x2f', 'LLIL_INTRINSIC([v11],vcvt_n_u32_f32,[LLIL_REG.o(v4),LLIL_CONST(11)])'),
    # fcvtzu v11.4h, v20.4h, #2
    (b'\x8B\xFE\x1E\x2F', 'LLIL_INTRINSIC([v11],vcvt_n_u16_f16,[LLIL_REG.o(v20),LLIL_CONST(2)])'),
    # fcvtzu v11.8h, v4.8h, #0xb
    (b'\x8B\xFC\x15\x6F', 'LLIL_INTRINSIC([v11],vcvtq_n_u16_f16,[LLIL_REG.o(v4),LLIL_CONST(11)])'),
    # fcvtzu w4, s18
    (b'\x44\x02\x39\x1E', 'LLIL_INTRINSIC([w4],vcvts_u32_f32,[LLIL_REG.d(s18)])')
]

tests_fccmp_fccmpe = [
    # fccmpe d0, d20, #0x7, lo
    (b'\x17\x34\x74\x1E', 'LLIL_IF(LLIL_FLAG_GROUP(cc),1,3);' + \
                         ' LLIL_FSUB.q{f*}(LLIL_REG.q(d0),LLIL_REG.q(d20));' + \
                         ' LLIL_GOTO(8);' + \
                         ' LLIL_SET_FLAG(n,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(z,LLIL_CONST(1));' + \
                         ' LLIL_SET_FLAG(c,LLIL_CONST(1));' + \
                         ' LLIL_SET_FLAG(v,LLIL_CONST(1));' + \
                         ' LLIL_GOTO(8)'),
    # fccmpe d29, d0, #0x8, le
    (b'\xB8\xD7\x60\x1E', 'LLIL_IF(LLIL_FLAG_GROUP(le),1,3);' + \
                         ' LLIL_FSUB.q{f*}(LLIL_REG.q(d29),LLIL_REG.q(d0));' + \
                         ' LLIL_GOTO(8);' + \
                         ' LLIL_SET_FLAG(n,LLIL_CONST(1));' + \
                         ' LLIL_SET_FLAG(z,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(c,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(v,LLIL_CONST(0));' + \
                         ' LLIL_GOTO(8)'),
    # fccmpe h5, h1, #0x1, ne
    (b'\xB1\x14\xE1\x1E', 'LLIL_IF(LLIL_FLAG_GROUP(ne),1,3);' + \
                         ' LLIL_FSUB.w{f*}(LLIL_REG.w(h5),LLIL_REG.w(h1));' + \
                         ' LLIL_GOTO(8);' + \
                         ' LLIL_SET_FLAG(n,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(z,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(c,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(v,LLIL_CONST(1));' + \
                         ' LLIL_GOTO(8)'),
    # fccmpe h0, h22, #0x5, eq
    (b'\x15\x04\xF6\x1E', 'LLIL_IF(LLIL_FLAG_GROUP(eq),1,3);' + \
                         ' LLIL_FSUB.w{f*}(LLIL_REG.w(h0),LLIL_REG.w(h22));' + \
                         ' LLIL_GOTO(8);' + \
                         ' LLIL_SET_FLAG(n,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(z,LLIL_CONST(1));' + \
                         ' LLIL_SET_FLAG(c,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(v,LLIL_CONST(1));' + \
                         ' LLIL_GOTO(8)'),
    # fccmpe s10, s19, #0x4, ge
    (b'\x54\xA5\x33\x1E', 'LLIL_IF(LLIL_FLAG_GROUP(ge),1,3);' + \
                         ' LLIL_FSUB.d{f*}(LLIL_REG.d(s10),LLIL_REG.d(s19));' + \
                         ' LLIL_GOTO(8);' + \
                         ' LLIL_SET_FLAG(n,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(z,LLIL_CONST(1));' + \
                         ' LLIL_SET_FLAG(c,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(v,LLIL_CONST(0));' + \
                         ' LLIL_GOTO(8)'),
    # fccmpe s24, s11, #0x4, pl
    (b'\x14\x57\x2B\x1E', 'LLIL_IF(LLIL_FLAG_GROUP(pl),1,3);' + \
                         ' LLIL_FSUB.d{f*}(LLIL_REG.d(s24),LLIL_REG.d(s11));' + \
                         ' LLIL_GOTO(8);' + \
                         ' LLIL_SET_FLAG(n,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(z,LLIL_CONST(1));' + \
                         ' LLIL_SET_FLAG(c,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(v,LLIL_CONST(0));' + \
                         ' LLIL_GOTO(8)'),
    # fccmp d2, d28, #0xf, lo
    (b'\x4F\x34\x7C\x1E', 'LLIL_IF(LLIL_FLAG_GROUP(cc),1,3);' + \
                         ' LLIL_FSUB.q{f*}(LLIL_REG.q(d2),LLIL_REG.q(d28));' + \
                         ' LLIL_GOTO(8);' + \
                         ' LLIL_SET_FLAG(n,LLIL_CONST(1));' + \
                         ' LLIL_SET_FLAG(z,LLIL_CONST(1));' + \
                         ' LLIL_SET_FLAG(c,LLIL_CONST(1));' + \
                         ' LLIL_SET_FLAG(v,LLIL_CONST(1));' + \
                         ' LLIL_GOTO(8)'),
    # fccmp d8, d25, #0xc, vs
    (b'\x0C\x65\x79\x1E', 'LLIL_IF(LLIL_FLAG_GROUP(vs),1,3);' + \
                         ' LLIL_FSUB.q{f*}(LLIL_REG.q(d8),LLIL_REG.q(d25));' + \
                         ' LLIL_GOTO(8);' + \
                         ' LLIL_SET_FLAG(n,LLIL_CONST(1));' + \
                         ' LLIL_SET_FLAG(z,LLIL_CONST(1));' + \
                         ' LLIL_SET_FLAG(c,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(v,LLIL_CONST(0));' + \
                         ' LLIL_GOTO(8)'),
    # fccmp h0, h11, #0xb, al
    (b'\x0B\xE4\xEB\x1E', 'LLIL_IF(LLIL_CONST(1),1,3);' + \
                         ' LLIL_FSUB.w{f*}(LLIL_REG.w(h0),LLIL_REG.w(h11));' + \
                         ' LLIL_GOTO(8);' + \
                         ' LLIL_SET_FLAG(n,LLIL_CONST(1));' + \
                         ' LLIL_SET_FLAG(z,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(c,LLIL_CONST(1));' + \
                         ' LLIL_SET_FLAG(v,LLIL_CONST(1));' + \
                         ' LLIL_GOTO(8)'),
    # fccmp h18, h21, #0xf, al
    (b'\x4F\xE6\xF5\x1E', 'LLIL_IF(LLIL_CONST(1),1,3);' + \
                         ' LLIL_FSUB.w{f*}(LLIL_REG.w(h18),LLIL_REG.w(h21));' + \
                         ' LLIL_GOTO(8);' + \
                         ' LLIL_SET_FLAG(n,LLIL_CONST(1));' + \
                         ' LLIL_SET_FLAG(z,LLIL_CONST(1));' + \
                         ' LLIL_SET_FLAG(c,LLIL_CONST(1));' + \
                         ' LLIL_SET_FLAG(v,LLIL_CONST(1));' + \
                         ' LLIL_GOTO(8)'),
    # fccmp s23, s31, #0x6, hs
    (b'\xE6\x26\x3F\x1E', 'LLIL_IF(LLIL_FLAG_GROUP(cs),1,3);' + \
                         ' LLIL_FSUB.d{f*}(LLIL_REG.d(s23),LLIL_REG.d(s31));' + \
                         ' LLIL_GOTO(8);' + \
                         ' LLIL_SET_FLAG(n,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(z,LLIL_CONST(1));' + \
                         ' LLIL_SET_FLAG(c,LLIL_CONST(1));' + \
                         ' LLIL_SET_FLAG(v,LLIL_CONST(0));' + \
                         ' LLIL_GOTO(8)'),
    # fccmp s7, s16, #0x0, eq
    (b'\xE0\x04\x30\x1E', 'LLIL_IF(LLIL_FLAG_GROUP(eq),1,3);' + \
                         ' LLIL_FSUB.d{f*}(LLIL_REG.d(s7),LLIL_REG.d(s16));' + \
                         ' LLIL_GOTO(8);' + \
                         ' LLIL_SET_FLAG(n,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(z,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(c,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(v,LLIL_CONST(0));' + \
                         ' LLIL_GOTO(8)'),
]

tests_fcsel = [
    # fcsel d10, d3, d20, vs
    (b'\x6A\x6C\x74\x1E', 'LLIL_IF(LLIL_FLAG_GROUP(vs),1,3);' + \
                         ' LLIL_SET_REG.q(d10,LLIL_REG.q(d3));' + \
                         ' LLIL_GOTO(5);' + \
                         ' LLIL_SET_REG.q(d10,LLIL_REG.q(d20));' + \
                         ' LLIL_GOTO(5)'),
    # fcsel d30, d8, d21, al
    (b'\x1E\xED\x75\x1E', 'LLIL_IF(LLIL_CONST(1),1,3);' + \
                         ' LLIL_SET_REG.q(d30,LLIL_REG.q(d8));' + \
                         ' LLIL_GOTO(5);' + \
                         ' LLIL_SET_REG.q(d30,LLIL_REG.q(d21));' + \
                         ' LLIL_GOTO(5)'),
    # fcsel h30, h9, h13, lo
    (b'\x3E\x3D\xED\x1E', 'LLIL_IF(LLIL_FLAG_GROUP(cc),1,3);' + \
                         ' LLIL_SET_REG.w(h30,LLIL_REG.w(h9));' + \
                         ' LLIL_GOTO(5);' + \
                         ' LLIL_SET_REG.w(h30,LLIL_REG.w(h13));' + \
                         ' LLIL_GOTO(5)'),
    # fcsel h29, h20, h31, vs
    (b'\x9D\x6E\xFF\x1E', 'LLIL_IF(LLIL_FLAG_GROUP(vs),1,3);' + \
                         ' LLIL_SET_REG.w(h29,LLIL_REG.w(h20));' + \
                         ' LLIL_GOTO(5);' + \
                         ' LLIL_SET_REG.w(h29,LLIL_REG.w(h31));' + \
                         ' LLIL_GOTO(5)'),
    # fcsel s26, s16, s18, lt
    (b'\x1A\xBE\x32\x1E', 'LLIL_IF(LLIL_FLAG_GROUP(lt),1,3);' + \
                         ' LLIL_SET_REG.d(s26,LLIL_REG.d(s16));' + \
                         ' LLIL_GOTO(5);' + \
                         ' LLIL_SET_REG.d(s26,LLIL_REG.d(s18));' + \
                         ' LLIL_GOTO(5)'),
    # fcsel s15, s9, s28, vc
    (b'\x2F\x7D\x3C\x1E', 'LLIL_IF(LLIL_FLAG_GROUP(vc),1,3);' + \
                         ' LLIL_SET_REG.d(s15,LLIL_REG.d(s9));' + \
                         ' LLIL_GOTO(5);' + \
                         ' LLIL_SET_REG.d(s15,LLIL_REG.d(s28));' + \
                         ' LLIL_GOTO(5)'),
]

tests_fcmp_fcmpe = [
    # fcmpe d23, #0.0
    (b'\xF8\x22\x7F\x1E', 'LLIL_FSUB.q{f*}(LLIL_REG.q(d23),LLIL_FLOAT_CONST.q(0.0))'),
    # fcmpe d2, #0.0
    (b'\x58\x20\x73\x1E', 'LLIL_FSUB.q{f*}(LLIL_REG.q(d2),LLIL_FLOAT_CONST.q(0.0))'),
    # fcmpe d4, d23
    (b'\x90\x20\x77\x1E', 'LLIL_FSUB.q{f*}(LLIL_REG.q(d4),LLIL_REG.q(d23))'),
    # fcmpe d15, d16
    (b'\xF0\x21\x70\x1E', 'LLIL_FSUB.q{f*}(LLIL_REG.q(d15),LLIL_REG.q(d16))'),
    # fcmpe h8, #0.0
    (b'\x18\x21\xEC\x1E', 'LLIL_FSUB.w{f*}(LLIL_REG.w(h8),LLIL_FLOAT_CONST.w(0))'),
    # fcmpe h23, #0.0
    (b'\xF8\x22\xEE\x1E', 'LLIL_FSUB.w{f*}(LLIL_REG.w(h23),LLIL_FLOAT_CONST.w(0))'),
    # fcmpe h14, h17
    (b'\xD0\x21\xF1\x1E', 'LLIL_FSUB.w{f*}(LLIL_REG.w(h14),LLIL_REG.w(h17))'),
    # fcmpe h23, h25
    (b'\xF0\x22\xF9\x1E', 'LLIL_FSUB.w{f*}(LLIL_REG.w(h23),LLIL_REG.w(h25))'),
    # fcmpe s4, #0.0
    (b'\x98\x20\x2D\x1E', 'LLIL_FSUB.d{f*}(LLIL_REG.d(s4),LLIL_FLOAT_CONST.d(0.0))'),
    # fcmpe s16, #0.0
    (b'\x18\x22\x27\x1E', 'LLIL_FSUB.d{f*}(LLIL_REG.d(s16),LLIL_FLOAT_CONST.d(0.0))'),
    # fcmpe s21, s23
    (b'\xB0\x22\x37\x1E', 'LLIL_FSUB.d{f*}(LLIL_REG.d(s21),LLIL_REG.d(s23))'),
    # fcmpe s26, s6
    (b'\x50\x23\x26\x1E', 'LLIL_FSUB.d{f*}(LLIL_REG.d(s26),LLIL_REG.d(s6))'),
    # fcmp d10, #0.0
    (b'\x48\x21\x68\x1E', 'LLIL_FSUB.q{f*}(LLIL_REG.q(d10),LLIL_FLOAT_CONST.q(0.0))'),
    # fcmp d5, #0.0
    (b'\xA8\x20\x71\x1E', 'LLIL_FSUB.q{f*}(LLIL_REG.q(d5),LLIL_FLOAT_CONST.q(0.0))'),
    # fcmp d2, d17
    (b'\x40\x20\x71\x1E', 'LLIL_FSUB.q{f*}(LLIL_REG.q(d2),LLIL_REG.q(d17))'),
    # fcmp d27, d3
    (b'\x60\x23\x63\x1E', 'LLIL_FSUB.q{f*}(LLIL_REG.q(d27),LLIL_REG.q(d3))'),
    # fcmp h19, #0.0
    (b'\x68\x22\xF8\x1E', 'LLIL_FSUB.w{f*}(LLIL_REG.w(h19),LLIL_FLOAT_CONST.w(0))'),
    # fcmp h26, #0.0
    (b'\x48\x23\xEF\x1E', 'LLIL_FSUB.w{f*}(LLIL_REG.w(h26),LLIL_FLOAT_CONST.w(0))'),
    # fcmp h8, h17
    (b'\x00\x21\xF1\x1E', 'LLIL_FSUB.w{f*}(LLIL_REG.w(h8),LLIL_REG.w(h17))'),
    # fcmp h18, h26
    (b'\x40\x22\xFA\x1E', 'LLIL_FSUB.w{f*}(LLIL_REG.w(h18),LLIL_REG.w(h26))'),
    # fcmp s20, #0.0
    (b'\x88\x22\x27\x1E', 'LLIL_FSUB.d{f*}(LLIL_REG.d(s20),LLIL_FLOAT_CONST.d(0.0))'),
    # fcmp s29, #0.0
    (b'\xA8\x23\x39\x1E', 'LLIL_FSUB.d{f*}(LLIL_REG.d(s29),LLIL_FLOAT_CONST.d(0.0))'),
    # fcmp s2, s19
    (b'\x40\x20\x33\x1E', 'LLIL_FSUB.d{f*}(LLIL_REG.d(s2),LLIL_REG.d(s19))'),
    # fcmp s4, s7
    (b'\x80\x20\x27\x1E', 'LLIL_FSUB.d{f*}(LLIL_REG.d(s4),LLIL_REG.d(s7))'),
]

tests_fmov = [
    # fmov w2, h17
    (b'\x22\x02\xE6\x1E', 'LLIL_SET_REG.d(w2,LLIL_FLOAT_TO_INT.d(LLIL_REG.w(h17)))'),
    # fmov w24, h20
    (b'\x98\x02\xE6\x1E', 'LLIL_SET_REG.d(w24,LLIL_FLOAT_TO_INT.d(LLIL_REG.w(h20)))'),
    # fmov w10, s23
    (b'\xEA\x02\x26\x1E', 'LLIL_SET_REG.d(w10,LLIL_FLOAT_TO_INT.d(LLIL_REG.d(s23)))'),
    # fmov w12, s23
    (b'\xEC\x02\x26\x1E', 'LLIL_SET_REG.d(w12,LLIL_FLOAT_TO_INT.d(LLIL_REG.d(s23)))'),
    # fmov x25, d31
    (b'\xF9\x03\x66\x9E', 'LLIL_SET_REG.q(x25,LLIL_FLOAT_TO_INT.q(LLIL_REG.q(d31)))'),
    # fmov x21, d24
    (b'\x15\x03\x66\x9E', 'LLIL_SET_REG.q(x21,LLIL_FLOAT_TO_INT.q(LLIL_REG.q(d24)))'),
    # fmov x26, h11
    (b'\x7A\x01\xE6\x9E', 'LLIL_SET_REG.q(x26,LLIL_FLOAT_TO_INT.q(LLIL_REG.w(h11)))'),
    # fmov x21, h3
    (b'\x75\x00\xE6\x9E', 'LLIL_SET_REG.q(x21,LLIL_FLOAT_TO_INT.q(LLIL_REG.w(h3)))'),
    # fmov x4, v28.d[1]
    (b'\x84\x03\xAE\x9E', 'LLIL_SET_REG.q(x4,LLIL_FLOAT_TO_INT.q(LLIL_REG.q(v28.d[1])))'),
    # fmov x7, v8.d[1]
    (b'\x07\x01\xAE\x9E', 'LLIL_SET_REG.q(x7,LLIL_FLOAT_TO_INT.q(LLIL_REG.q(v8.d[1])))'),
    # fmov d19, x0
    (b'\x13\x00\x67\x9E', 'LLIL_SET_REG.q(d19,LLIL_FLOAT_TO_INT.q(LLIL_REG.q(x0)))'),
    # fmov d8, x21
    (b'\xA8\x02\x67\x9E', 'LLIL_SET_REG.q(d8,LLIL_FLOAT_TO_INT.q(LLIL_REG.q(x21)))'),
    # fmov d24, d27
    (b'\x78\x43\x60\x1E', 'LLIL_SET_REG.q(d24,LLIL_REG.q(d27))'),
    # fmov d19, d19
    (b'\x73\x42\x60\x1E', 'LLIL_SET_REG.q(d19,LLIL_REG.q(d19))'),
    # TODO fmov d17, #-1.9375
    (b'\x11\xF0\x7F\x1E', 'LLIL_SET_REG.q(d17,LLIL_FLOAT_CONST.q(-1.9375))'),
    # TODO fmov d19, #-3.125
    (b'\x13\x30\x71\x1E', 'LLIL_SET_REG.q(d19,LLIL_FLOAT_CONST.q(-3.125))'),
    # fmov h28, w19
    (b'\x7C\x02\xE7\x1E', 'LLIL_SET_REG.w(h28,LLIL_FLOAT_TO_INT.w(LLIL_REG.d(w19)))'),
    # fmov h2, w5
    (b'\xA2\x00\xE7\x1E', 'LLIL_SET_REG.w(h2,LLIL_FLOAT_TO_INT.w(LLIL_REG.d(w5)))'),
    # fmov h10, x14
    (b'\xCA\x01\xE7\x9E', 'LLIL_SET_REG.w(h10,LLIL_FLOAT_TO_INT.w(LLIL_REG.q(x14)))'),
    # fmov h9, x29
    (b'\xA9\x03\xE7\x9E', 'LLIL_SET_REG.w(h9,LLIL_FLOAT_TO_INT.w(LLIL_REG.q(x29)))'),
    # fmov h6, h23
    (b'\xE6\x42\xE0\x1E', 'LLIL_SET_REG.w(h6,LLIL_REG.w(h23))'),
    # fmov h6, h28
    (b'\x86\x43\xE0\x1E', 'LLIL_SET_REG.w(h6,LLIL_REG.w(h28))'),
    # fmov h23, #-5.25
    (b'\x17\xB0\xF2\x1E', 'LLIL_SET_REG.w(h23,LLIL_FLOAT_CONST.w(3232235520))'),
    # fmov h25, #11.0
    (b'\x19\xD0\xE4\x1E', 'LLIL_SET_REG.w(h25,LLIL_FLOAT_CONST.w(1093664768))'),
    # fmov s17, w2
    (b'\x51\x00\x27\x1E', 'LLIL_SET_REG.d(s17,LLIL_FLOAT_TO_INT.d(LLIL_REG.d(w2)))'),
    # fmov s1, wzr
    (b'\xE1\x03\x27\x1E', 'LLIL_SET_REG.d(s1,LLIL_FLOAT_TO_INT.d(LLIL_CONST.d(0x0)))'),
    # fmov s4, s11
    (b'\x64\x41\x20\x1E', 'LLIL_SET_REG.d(s4,LLIL_REG.d(s11))'),
    # fmov s23, s2
    (b'\x57\x40\x20\x1E', 'LLIL_SET_REG.d(s23,LLIL_REG.d(s2))'),
    # fmov s17, #-1.5
    (b'\x11\x10\x3F\x1E', 'LLIL_SET_REG.d(s17,LLIL_FLOAT_CONST.d(-1.5))'),
    # fmov s14, #21.0
    (b'\x0E\xB0\x26\x1E', 'LLIL_SET_REG.d(s14,LLIL_FLOAT_CONST.d(21.0))'),
    # fmov v14.d[1], x26
    (b'\x4E\x03\xAF\x9E', 'LLIL_SET_REG.q(v14.d[1],LLIL_FLOAT_TO_INT.o(LLIL_REG.q(x26)))'),
    # fmov v28.d[1], x14
    (b'\xDC\x01\xAF\x9E', 'LLIL_SET_REG.q(v28.d[1],LLIL_FLOAT_TO_INT.o(LLIL_REG.q(x14)))'),
    # TODO fmov v13.2d, #-3.0 (.d in arm namespace is 64-bit, .q in binja namespce is 64-bit)
    (b'\x0D\xF5\x04\x6F', 'LLIL_SET_REG.q(v13.d[0],LLIL_FLOAT_CONST.q(-3.0));' + \
                         ' LLIL_SET_REG.q(v13.d[1],LLIL_FLOAT_CONST.q(-3.0))'),
    # TODO fmov v24.2d, #-22.0
    (b'\xD8\xF6\x05\x6F', 'LLIL_SET_REG.q(v24.d[0],LLIL_FLOAT_CONST.q(-22.0));' + \
                         ' LLIL_SET_REG.q(v24.d[1],LLIL_FLOAT_CONST.q(-22.0))'),
    # TODO fmov v29.4h, #13.5
    (b'\x7D\xFD\x01\x0F', 'LLIL_SET_REG.w(v29.h[0],LLIL_FLOAT_CONST.w(1096286208));' + \
                         ' LLIL_SET_REG.w(v29.h[1],LLIL_FLOAT_CONST.w(1096286208));' + \
                         ' LLIL_SET_REG.w(v29.h[2],LLIL_FLOAT_CONST.w(1096286208));' + \
                         ' LLIL_SET_REG.w(v29.h[3],LLIL_FLOAT_CONST.w(1096286208))'),
    # TODO fmov v16.8h, #-0.1953125
    (b'\x30\xFD\x06\x4F', 'LLIL_SET_REG.w(v16.h[0],LLIL_FLOAT_CONST.w(3192389632));' + \
                         ' LLIL_SET_REG.w(v16.h[1],LLIL_FLOAT_CONST.w(3192389632));' + \
                         ' LLIL_SET_REG.w(v16.h[2],LLIL_FLOAT_CONST.w(3192389632));' + \
                         ' LLIL_SET_REG.w(v16.h[3],LLIL_FLOAT_CONST.w(3192389632));' + \
                         ' LLIL_SET_REG.w(v16.h[4],LLIL_FLOAT_CONST.w(3192389632));' + \
                         ' LLIL_SET_REG.w(v16.h[5],LLIL_FLOAT_CONST.w(3192389632));' + \
                         ' LLIL_SET_REG.w(v16.h[6],LLIL_FLOAT_CONST.w(3192389632));' + \
                         ' LLIL_SET_REG.w(v16.h[7],LLIL_FLOAT_CONST.w(3192389632))'),
    # TODO fmov v23.2s, #-6.25
    (b'\x37\xF7\x04\x0F', 'LLIL_SET_REG.d(v23.s[0],LLIL_FLOAT_CONST.d(-6.25));' + \
                         ' LLIL_SET_REG.d(v23.s[1],LLIL_FLOAT_CONST.d(-6.25))'),
    # TODO fmov v13.2s, #-2.0
    (b'\x0D\xF4\x04\x0F', 'LLIL_SET_REG.d(v13.s[0],LLIL_FLOAT_CONST.d(-2.0));' + \
                         ' LLIL_SET_REG.d(v13.s[1],LLIL_FLOAT_CONST.d(-2.0))'),
]

tests_sha = [
    # sha1c q13, s7, v27.4s
    (b'\xED\x00\x1B\x5E', 'LLIL_INTRINSIC([q13],vsha1cq_u32,[LLIL_REG.o(q13),LLIL_REG.d(s7),LLIL_REG.o(v27)])'),
    # sha1c q20, s15, v13.4s
    (b'\xF4\x01\x0D\x5E', 'LLIL_INTRINSIC([q20],vsha1cq_u32,[LLIL_REG.o(q20),LLIL_REG.d(s15),LLIL_REG.o(v13)])'),
    # sha1h s27, s21
    (b'\xBB\x0A\x28\x5E', 'LLIL_INTRINSIC([s27],vsha1h_u32,[LLIL_REG.d(s21)])'),
    # sha1h s7, s9
    (b'\x27\x09\x28\x5E', 'LLIL_INTRINSIC([s7],vsha1h_u32,[LLIL_REG.d(s9)])'),
    # sha1m q3, s31, v10.4s
    (b'\xE3\x23\x0A\x5E', 'LLIL_INTRINSIC([q3],vsha1mq_u32,[LLIL_REG.o(q3),LLIL_REG.d(s31),LLIL_REG.o(v10)])'),
    # sha1m q26, s2, v6.4s
    (b'\x5A\x20\x06\x5E', 'LLIL_INTRINSIC([q26],vsha1mq_u32,[LLIL_REG.o(q26),LLIL_REG.d(s2),LLIL_REG.o(v6)])'),
    # sha1p q15, s15, v19.4s
    (b'\xEF\x11\x13\x5E', 'LLIL_INTRINSIC([q15],vsha1pq_u32,[LLIL_REG.o(q15),LLIL_REG.d(s15),LLIL_REG.o(v19)])'),
    # sha1p q16, s31, v18.4s
    (b'\xF0\x13\x12\x5E', 'LLIL_INTRINSIC([q16],vsha1pq_u32,[LLIL_REG.o(q16),LLIL_REG.d(s31),LLIL_REG.o(v18)])'),
    # sha1su0 v31.4s, v30.4s, v5.4s
    (b'\xDF\x33\x05\x5E', 'LLIL_INTRINSIC([v31],vsha1su0q_u32,[LLIL_REG.o(v31),LLIL_REG.o(v30),LLIL_REG.o(v5)])'),
    # sha1su0 v16.4s, v16.4s, v31.4s
    (b'\x10\x32\x1F\x5E', 'LLIL_INTRINSIC([v16],vsha1su0q_u32,[LLIL_REG.o(v16),LLIL_REG.o(v16),LLIL_REG.o(v31)])'),
    # sha1su1 v13.4s, v19.4s
    (b'\x6D\x1A\x28\x5E', 'LLIL_INTRINSIC([v13],vsha1su1q_u32,[LLIL_REG.o(v13),LLIL_REG.o(v19)])'),
    # sha1su1 v29.4s, v0.4s
    (b'\x1D\x18\x28\x5E', 'LLIL_INTRINSIC([v29],vsha1su1q_u32,[LLIL_REG.o(v29),LLIL_REG.o(v0)])'),
    # sha256h2 q21, q29, v18.4s
    (b'\xB5\x53\x12\x5E', 'LLIL_INTRINSIC([q21],vsha256h2q_u32,[LLIL_REG.o(q21),LLIL_REG.o(q29),LLIL_REG.o(v18)])'),
    # sha256h2 q2, q9, v4.4s
    (b'\x22\x51\x04\x5E', 'LLIL_INTRINSIC([q2],vsha256h2q_u32,[LLIL_REG.o(q2),LLIL_REG.o(q9),LLIL_REG.o(v4)])'),
    # sha256h q7, q0, v30.4s
    (b'\x07\x40\x1E\x5E', 'LLIL_INTRINSIC([q7],vsha256hq_u32,[LLIL_REG.o(q7),LLIL_REG.o(q0),LLIL_REG.o(v30)])'),
    # sha256h q16, q11, v4.4s
    (b'\x70\x41\x04\x5E', 'LLIL_INTRINSIC([q16],vsha256hq_u32,[LLIL_REG.o(q16),LLIL_REG.o(q11),LLIL_REG.o(v4)])'),
    # sha256su0 v9.4s, v11.4s
    (b'\x69\x29\x28\x5E', 'LLIL_INTRINSIC([v9],vsha256su0q_u32,[LLIL_REG.o(v9),LLIL_REG.o(v11)])'),
    # sha256su0 v24.4s, v26.4s
    (b'\x58\x2B\x28\x5E', 'LLIL_INTRINSIC([v24],vsha256su0q_u32,[LLIL_REG.o(v24),LLIL_REG.o(v26)])'),
    # sha256su1 v13.4s, v17.4s, v12.4s
    (b'\x2D\x62\x0C\x5E', 'LLIL_INTRINSIC([v13],vsha256su1q_u32,[LLIL_REG.o(v13),LLIL_REG.o(v17),LLIL_REG.o(v12)])'),
    # sha256su1 v1.4s, v28.4s, v8.4s
    (b'\x81\x63\x08\x5E', 'LLIL_INTRINSIC([v1],vsha256su1q_u32,[LLIL_REG.o(v1),LLIL_REG.o(v28),LLIL_REG.o(v8)])'),
    # sha512h2 q30, q0, v15.2d
    (b'\x1E\x84\x6F\xCE', 'LLIL_INTRINSIC([q30],vsha512h2q_u64,[LLIL_REG.o(q30),LLIL_REG.o(q0),LLIL_REG.o(v15)])'),
    # sha512h2 q13, q3, v0.2d
    (b'\x6D\x84\x60\xCE', 'LLIL_INTRINSIC([q13],vsha512h2q_u64,[LLIL_REG.o(q13),LLIL_REG.o(q3),LLIL_REG.o(v0)])'),
    # sha512h q30, q14, v10.2d
    (b'\xDE\x81\x6A\xCE', 'LLIL_INTRINSIC([q30],vsha512hq_u64,[LLIL_REG.o(q30),LLIL_REG.o(q14),LLIL_REG.o(v10)])'),
    # sha512h q13, q14, v28.2d
    (b'\xCD\x81\x7C\xCE', 'LLIL_INTRINSIC([q13],vsha512hq_u64,[LLIL_REG.o(q13),LLIL_REG.o(q14),LLIL_REG.o(v28)])'),
    # sha512su0 v10.2d, v6.2d
    (b'\xCA\x80\xC0\xCE', 'LLIL_INTRINSIC([v10],vsha512su0q_u64,[LLIL_REG.o(v10),LLIL_REG.o(v6)])'),
    # sha512su0 v13.2d, v9.2d
    (b'\x2D\x81\xC0\xCE', 'LLIL_INTRINSIC([v13],vsha512su0q_u64,[LLIL_REG.o(v13),LLIL_REG.o(v9)])'),
    # sha512su1 v13.2d, v6.2d, v5.2d
    (b'\xCD\x88\x65\xCE', 'LLIL_INTRINSIC([v13],vsha512su1q_u64,[LLIL_REG.o(v13),LLIL_REG.o(v6),LLIL_REG.o(v5)])'),
    # sha512su1 v18.2d, v19.2d, v12.2d
    (b'\x72\x8A\x6C\xCE', 'LLIL_INTRINSIC([v18],vsha512su1q_u64,[LLIL_REG.o(v18),LLIL_REG.o(v19),LLIL_REG.o(v12)])'),
]

tests_rev = [
    (b'\x49\x29\xC8\x9A', 'LLIL_SET_REG.q(x9,LLIL_ASR.q(LLIL_REG.q(x10),LLIL_REG.q(x8)))'), # asr    x9, x10, x8
    # rev16 w25, w2
    (b'\x59\x04\xC0\x5A', 'LLIL_INTRINSIC([w25],_byteswap,[LLIL_REG.d(w2)])'),
    # rev16 w25, w6
    (b'\xD9\x04\xC0\x5A', 'LLIL_INTRINSIC([w25],_byteswap,[LLIL_REG.d(w6)])'),
    # rev16 x23, x3
    (b'\x77\x04\xC0\xDA', 'LLIL_INTRINSIC([x23],_byteswap,[LLIL_REG.q(x3)])'),
    # rev16 x14, x17
    (b'\x2E\x06\xC0\xDA', 'LLIL_INTRINSIC([x14],_byteswap,[LLIL_REG.q(x17)])'),
    # rev16 v8.16b, v26.16b
    (b'\x48\x1B\x20\x4E', 'LLIL_INTRINSIC([v8],_byteswap,[LLIL_REG.o(v26)])'),
    # rev16 v4.8b, v27.8b
    (b'\x64\x1B\x20\x0E', 'LLIL_INTRINSIC([v4],_byteswap,[LLIL_REG.o(v27)])'),
    # rev32 x29, x8
    (b'\x1D\x09\xC0\xDA', 'LLIL_INTRINSIC([x29],_byteswap,[LLIL_REG.q(x8)])'),
    # rev32 x18, x26
    (b'\x52\x0B\xC0\xDA', 'LLIL_INTRINSIC([x18],_byteswap,[LLIL_REG.q(x26)])'),
    # rev32 v18.4h, v15.4h
    (b'\xF2\x09\x60\x2E', 'LLIL_INTRINSIC([v18],_byteswap,[LLIL_REG.o(v15)])'),
    # rev32 v20.8h, v26.8h
    (b'\x54\x0B\x60\x6E', 'LLIL_INTRINSIC([v20],_byteswap,[LLIL_REG.o(v26)])'),
    # rev64 v9.2s, v26.2s
    (b'\x49\x0B\xA0\x0E', 'LLIL_INTRINSIC([v9],_byteswap,[LLIL_REG.o(v26)])'),
    # rev64 v17.16b, v18.16b
    (b'\x51\x0A\x20\x4E', 'LLIL_INTRINSIC([v17],_byteswap,[LLIL_REG.o(v18)])'),
    # rev w14, w21
    (b'\xAE\x0A\xC0\x5A', 'LLIL_INTRINSIC([w14],_byteswap,[LLIL_REG.d(w21)])'),
    # rev w23, w3
    (b'\x77\x08\xC0\x5A', 'LLIL_INTRINSIC([w23],_byteswap,[LLIL_REG.d(w3)])'),
    # rev x11, x6
    (b'\xCB\x0C\xC0\xDA', 'LLIL_INTRINSIC([x11],_byteswap,[LLIL_REG.q(x6)])'),
    # rev x18, x0
    (b'\x12\x0C\xC0\xDA', 'LLIL_INTRINSIC([x18],_byteswap,[LLIL_REG.q(x0)])'),
    # rev p1.s, p8.s
    (b'\x01\x41\xB4\x05', 'LLIL_UNIMPL()'),
    # rev p15.d, p11.d
    (b'\x6F\x41\xF4\x05', 'LLIL_UNIMPL()'),
    # rev z27.d, z28.d
    (b'\x9B\x3B\xF8\x05', 'LLIL_UNIMPL()'),
    # rev z15.h, z12.h
    (b'\x8F\x39\x78\x05', 'LLIL_UNIMPL()'),
    # revb z17.d, p7/m, z17.d
    (b'\x31\x9E\xE4\x05', 'LLIL_UNIMPL()'),
    # revb z28.d, p7/m, z27.d
    (b'\x7C\x9F\xE4\x05', 'LLIL_UNIMPL()'),
    # revh z7.s, p3/m, z6.s
    (b'\xC7\x8C\xA5\x05', 'LLIL_UNIMPL()'),
    # revh z13.s, p3/m, z12.s
    (b'\x8D\x8D\xA5\x05', 'LLIL_UNIMPL()'),
    # revw z3.d, p1/m, z25.d
    (b'\x23\x87\xE6\x05', 'LLIL_UNIMPL()'),
    # revw z29.d, p7/m, z12.d
    (b'\x9D\x9D\xE6\x05', 'LLIL_UNIMPL()'),
]

tests_ld1 = [
    # ld1 {v14.1d}, [sp]
    (b'\xEE\x7F\x40\x0C', 'LLIL_SET_REG.q(v14.d[0],LLIL_LOAD.q(LLIL_REG.q(sp)))'),
    # ld1 {v12.16b}, [x29]
    (b'\xAC\x73\x40\x4C', 'LLIL_SET_REG.o(v12,LLIL_LOAD.o(LLIL_REG.q(x29)))'),
    # ld1 {v15.1d, v16.1d}, [x11]
    (b'\x6F\xAD\x40\x0C', 'LLIL_SET_REG.q(v15.d[0],LLIL_LOAD.q(LLIL_REG.q(x11)));' + \
                         ' LLIL_SET_REG.q(v16.d[0],LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x11),LLIL_CONST.q(0x8))))'),
    # ld1 {v22.1d, v23.1d}, [x0]
    (b'\x16\xAC\x40\x0C', 'LLIL_SET_REG.q(v22.d[0],LLIL_LOAD.q(LLIL_REG.q(x0)));' + \
                         ' LLIL_SET_REG.q(v23.d[0],LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x0),LLIL_CONST.q(0x8))))'),
    # ld1 {v29.8b, v30.8b, v31.8b}, [x22]
    (b'\xDD\x62\x40\x0C', 'LLIL_SET_REG.q(v29.d[0],LLIL_LOAD.q(LLIL_REG.q(x22)));' + \
                         ' LLIL_SET_REG.q(v30.d[0],LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x22),LLIL_CONST.q(0x8))));' + \
                         ' LLIL_SET_REG.q(v31.d[0],LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x22),LLIL_CONST.q(0x10))))'),
    # ld1 {v29.16b, v30.16b, v31.16b}, [x16]
    (b'\x1D\x62\x40\x4C', 'LLIL_SET_REG.o(v29,LLIL_LOAD.o(LLIL_REG.q(x16)));' + \
                         ' LLIL_SET_REG.o(v30,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(x16),LLIL_CONST.q(0x10))));' + \
                         ' LLIL_SET_REG.o(v31,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(x16),LLIL_CONST.q(0x20))))'),
    # ld1 {v25.4s, v26.4s, v27.4s, v28.4s}, [x10]
    (b'\x59\x29\x40\x4C', 'LLIL_SET_REG.o(v25,LLIL_LOAD.o(LLIL_REG.q(x10)));' + \
                         ' LLIL_SET_REG.o(v26,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(x10),LLIL_CONST.q(0x10))));' + \
                         ' LLIL_SET_REG.o(v27,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(x10),LLIL_CONST.q(0x20))));' + \
                         ' LLIL_SET_REG.o(v28,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(x10),LLIL_CONST.q(0x30))))'),
    # ld1 {v22.2d, v23.2d, v24.2d, v25.2d}, [x22]
    (b'\xD6\x2E\x40\x4C', 'LLIL_SET_REG.o(v22,LLIL_LOAD.o(LLIL_REG.q(x22)));' + \
                         ' LLIL_SET_REG.o(v23,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(x22),LLIL_CONST.q(0x10))));' + \
                         ' LLIL_SET_REG.o(v24,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(x22),LLIL_CONST.q(0x20))));' + \
                         ' LLIL_SET_REG.o(v25,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(x22),LLIL_CONST.q(0x30))))'),
    # ld1 {v31.4h}, [x6], #0x8
    (b'\xDF\x74\xDF\x0C', 'LLIL_SET_REG.q(v31.d[0],LLIL_LOAD.q(LLIL_REG.q(x6)))'),
    # ld1 {v2.2d}, [x22], #0x10
    (b'\xC2\x7E\xDF\x4C', 'LLIL_SET_REG.o(v2,LLIL_LOAD.o(LLIL_REG.q(x22)))'),
    # ld1 {v10.8b, v11.8b}, [x26], #0x10
    (b'\x4A\xA3\xDF\x0C', 'LLIL_SET_REG.q(v10.d[0],LLIL_LOAD.q(LLIL_REG.q(x26)));' + \
                         ' LLIL_SET_REG.q(v11.d[0],LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x26),LLIL_CONST.q(0x8))));' + \
                         ' LLIL_SET_REG.q(x26,LLIL_ADD.q(LLIL_REG.q(x26),LLIL_CONST.q(0x10)))'),
    # ld1 {v1.4s, v2.4s}, [x17], #0x20
    (b'\x21\xAA\xDF\x4C', 'LLIL_SET_REG.o(v1,LLIL_LOAD.o(LLIL_REG.q(x17)));' + \
                         ' LLIL_SET_REG.o(v2,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(x17),LLIL_CONST.q(0x10))));' + \
                         ' LLIL_SET_REG.q(x17,LLIL_ADD.q(LLIL_REG.q(x17),LLIL_CONST.q(0x20)))'),
    # ld1 {v15.1d, v16.1d, v17.1d}, [x7], #0x18
    (b'\xEF\x6C\xDF\x0C', 'LLIL_SET_REG.q(v15.d[0],LLIL_LOAD.q(LLIL_REG.q(x7)));' + \
                         ' LLIL_SET_REG.q(v16.d[0],LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x7),LLIL_CONST.q(0x8))));' + \
                         ' LLIL_SET_REG.q(v17.d[0],LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x7),LLIL_CONST.q(0x10))));' + \
                         ' LLIL_SET_REG.q(x7,LLIL_ADD.q(LLIL_REG.q(x7),LLIL_CONST.q(0x18)))'),
    # ld1 {v7.4s, v8.4s, v9.4s}, [x17], #0x30
    (b'\x27\x6A\xDF\x4C', 'LLIL_SET_REG.o(v7,LLIL_LOAD.o(LLIL_REG.q(x17)));' + \
                         ' LLIL_SET_REG.o(v8,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(x17),LLIL_CONST.q(0x10))));' + \
                         ' LLIL_SET_REG.o(v9,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(x17),LLIL_CONST.q(0x20))));' + \
                         ' LLIL_SET_REG.q(x17,LLIL_ADD.q(LLIL_REG.q(x17),LLIL_CONST.q(0x30)))'),
    # ld1 {v27.2d, v28.2d, v29.2d, v30.2d}, [x1], #0x40
    (b'\x3B\x2C\xDF\x4C', 'LLIL_SET_REG.o(v27,LLIL_LOAD.o(LLIL_REG.q(x1)));' + \
                         ' LLIL_SET_REG.o(v28,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(x1),LLIL_CONST.q(0x10))));' + \
                         ' LLIL_SET_REG.o(v29,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(x1),LLIL_CONST.q(0x20))));' + \
                         ' LLIL_SET_REG.o(v30,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(x1),LLIL_CONST.q(0x30))));' + \
                         ' LLIL_SET_REG.q(x1,LLIL_ADD.q(LLIL_REG.q(x1),LLIL_CONST.q(0x40)))'),
    # ld1 {v17.2s, v18.2s, v19.2s, v20.2s}, [x6], #0x20
    (b'\xD1\x28\xDF\x0C', 'LLIL_SET_REG.q(v17.d[0],LLIL_LOAD.q(LLIL_REG.q(x6)));' + \
                         ' LLIL_SET_REG.q(v18.d[0],LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x6),LLIL_CONST.q(0x8))));' + \
                         ' LLIL_SET_REG.q(v19.d[0],LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x6),LLIL_CONST.q(0x10))));' + \
                         ' LLIL_SET_REG.q(v20.d[0],LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x6),LLIL_CONST.q(0x18))));' + \
                         ' LLIL_SET_REG.q(x6,LLIL_ADD.q(LLIL_REG.q(x6),LLIL_CONST.q(0x20)))'),
    # ld1 {v22.2d}, [x8], x6
    (b'\x16\x7D\xC6\x4C', 'LLIL_SET_REG.o(v22,LLIL_LOAD.o(LLIL_REG.q(x8)));' + \
                         ' LLIL_SET_REG.q(x8,LLIL_ADD.q(LLIL_REG.q(x8),LLIL_REG.q(x6)))'),
    # ld1 {v12.2d}, [x2], x29
    (b'\x4C\x7C\xDD\x4C', 'LLIL_SET_REG.o(v12,LLIL_LOAD.o(LLIL_REG.q(x2)));' + \
                         ' LLIL_SET_REG.q(x2,LLIL_ADD.q(LLIL_REG.q(x2),LLIL_REG.q(x29)))'),
    # ld1 {v5.16b, v6.16b}, [x20], x19
    (b'\x85\xA2\xD3\x4C', 'LLIL_SET_REG.o(v5,LLIL_LOAD.o(LLIL_REG.q(x20)));' + \
                         ' LLIL_SET_REG.o(v6,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(x20),LLIL_CONST.q(0x10))));' + \
                         ' LLIL_SET_REG.q(x20,LLIL_ADD.q(LLIL_REG.q(x20),LLIL_REG.q(x19)))'),
    # ld1 {v11.4s, v12.4s}, [sp], x30
    (b'\xEB\xAB\xDE\x4C', 'LLIL_SET_REG.o(v11,LLIL_LOAD.o(LLIL_REG.q(sp)));' + \
                         ' LLIL_SET_REG.o(v12,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(sp),LLIL_CONST.q(0x10))));' + \
                         ' LLIL_SET_REG.q(sp,LLIL_ADD.q(LLIL_REG.q(sp),LLIL_REG.q(x30)))'),
    # ld1 {v30.16b, v31.16b, v0.16b}, [x22], x9
    (b'\xDE\x62\xC9\x4C', 'LLIL_SET_REG.o(v30,LLIL_LOAD.o(LLIL_REG.q(x22)));' + \
                         ' LLIL_SET_REG.o(v31,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(x22),LLIL_CONST.q(0x10))));' + \
                         ' LLIL_SET_REG.o(v0,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(x22),LLIL_CONST.q(0x20))));' + \
                         ' LLIL_SET_REG.q(x22,LLIL_ADD.q(LLIL_REG.q(x22),LLIL_REG.q(x9)))'),
    # ld1 {v30.2d, v31.2d, v0.2d}, [x29], x19
    (b'\xBE\x6F\xD3\x4C', 'LLIL_SET_REG.o(v30,LLIL_LOAD.o(LLIL_REG.q(x29)));' + \
                         ' LLIL_SET_REG.o(v31,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(x29),LLIL_CONST.q(0x10))));' + \
                         ' LLIL_SET_REG.o(v0,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(x29),LLIL_CONST.q(0x20))));' + \
                         ' LLIL_SET_REG.q(x29,LLIL_ADD.q(LLIL_REG.q(x29),LLIL_REG.q(x19)))'),
    # ld1 {v16.4s, v17.4s, v18.4s, v19.4s}, [x17], x4
    (b'\x30\x2A\xC4\x4C', 'LLIL_SET_REG.o(v16,LLIL_LOAD.o(LLIL_REG.q(x17)));' + \
                         ' LLIL_SET_REG.o(v17,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(x17),LLIL_CONST.q(0x10))));' + \
                         ' LLIL_SET_REG.o(v18,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(x17),LLIL_CONST.q(0x20))));' + \
                         ' LLIL_SET_REG.o(v19,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(x17),LLIL_CONST.q(0x30))));' + \
                         ' LLIL_SET_REG.q(x17,LLIL_ADD.q(LLIL_REG.q(x17),LLIL_REG.q(x4)))'),
    # ld1 {v16.4s, v17.4s, v18.4s, v19.4s}, [x1], x4
    (b'\x30\x28\xC4\x4C', 'LLIL_SET_REG.o(v16,LLIL_LOAD.o(LLIL_REG.q(x1)));' + \
                         ' LLIL_SET_REG.o(v17,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(x1),LLIL_CONST.q(0x10))));' + \
                         ' LLIL_SET_REG.o(v18,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(x1),LLIL_CONST.q(0x20))));' + \
                         ' LLIL_SET_REG.o(v19,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(x1),LLIL_CONST.q(0x30))));' + \
                         ' LLIL_SET_REG.q(x1,LLIL_ADD.q(LLIL_REG.q(x1),LLIL_REG.q(x4)))'),
    # ld1 {v28.b}[0], [x23]
    (b'\xFC\x02\x40\x0D', 'LLIL_SET_REG.b(v28.b[0],LLIL_LOAD.b(LLIL_REG.q(x23)))'),
    # ld1 {v19.b}[10], [x29]
    (b'\xB3\x0B\x40\x4D', 'LLIL_SET_REG.b(v19.b[10],LLIL_LOAD.b(LLIL_REG.q(x29)))'),
    # ld1 {v2.d}[0], [sp]
    (b'\xE2\x87\x40\x0D', 'LLIL_SET_REG.q(v2.d[0],LLIL_LOAD.q(LLIL_REG.q(sp)))'),
    # ld1 {v20.d}[0], [sp]
    (b'\xF4\x87\x40\x0D', 'LLIL_SET_REG.q(v20.d[0],LLIL_LOAD.q(LLIL_REG.q(sp)))'),
    # ld1 {v4.h}[5], [x15]
    (b'\xE4\x49\x40\x4D', 'LLIL_SET_REG.w(v4.h[5],LLIL_LOAD.w(LLIL_REG.q(x15)))'),
    # ld1 {v23.h}[5], [x4]
    (b'\x97\x48\x40\x4D', 'LLIL_SET_REG.w(v23.h[5],LLIL_LOAD.w(LLIL_REG.q(x4)))'),
    # ld1 {v28.s}[0], [sp]
    (b'\xFC\x83\x40\x0D', 'LLIL_SET_REG.d(v28.s[0],LLIL_LOAD.d(LLIL_REG.q(sp)))'),
    # ld1 {v14.s}[2], [x22]
    (b'\xCE\x82\x40\x4D', 'LLIL_SET_REG.d(v14.s[2],LLIL_LOAD.d(LLIL_REG.q(x22)))'),
    # ld1 {v17.b}[10], [x19], #0x1
    (b'\x71\x0A\xDF\x4D', 'LLIL_SET_REG.b(v17.b[10],LLIL_LOAD.b(LLIL_REG.q(x19)));' + \
                         ' LLIL_SET_REG.q(x19,LLIL_ADD.q(LLIL_REG.q(x19),LLIL_CONST.q(0x1)))'),
    # ld1 {v16.b}[2], [x19], #0x1
    (b'\x70\x0A\xDF\x0D', 'LLIL_SET_REG.b(v16.b[2],LLIL_LOAD.b(LLIL_REG.q(x19)));' + \
                         ' LLIL_SET_REG.q(x19,LLIL_ADD.q(LLIL_REG.q(x19),LLIL_CONST.q(0x1)))'),
    # ld1 {v5.b}[7], [x26], x29
    (b'\x45\x1F\xDD\x0D', 'LLIL_SET_REG.b(v5.b[7],LLIL_LOAD.b(LLIL_REG.q(x26)));' + \
                         ' LLIL_SET_REG.q(x26,LLIL_ADD.q(LLIL_REG.q(x26),LLIL_REG.q(x29)))'),
    # ld1 {v5.b}[3], [x8], x10
    (b'\x05\x0D\xCA\x0D', 'LLIL_SET_REG.b(v5.b[3],LLIL_LOAD.b(LLIL_REG.q(x8)));' + \
                         ' LLIL_SET_REG.q(x8,LLIL_ADD.q(LLIL_REG.q(x8),LLIL_REG.q(x10)))'),
    # ld1 {v16.d}[1], [x4], #0x8
    (b'\x90\x84\xDF\x4D', 'LLIL_SET_REG.q(v16.d[1],LLIL_LOAD.q(LLIL_REG.q(x4)));' + \
                         ' LLIL_SET_REG.q(x4,LLIL_ADD.q(LLIL_REG.q(x4),LLIL_CONST.q(0x8)))'),
    # ld1 {v8.d}[1], [x15], #0x8
    (b'\xE8\x85\xDF\x4D', 'LLIL_SET_REG.q(v8.d[1],LLIL_LOAD.q(LLIL_REG.q(x15)));' + \
                         ' LLIL_SET_REG.q(x15,LLIL_ADD.q(LLIL_REG.q(x15),LLIL_CONST.q(0x8)))'),
    # ld1 {v18.d}[1], [x24], x13
    (b'\x12\x87\xCD\x4D', 'LLIL_SET_REG.q(v18.d[1],LLIL_LOAD.q(LLIL_REG.q(x24)));' + \
                         ' LLIL_SET_REG.q(x24,LLIL_ADD.q(LLIL_REG.q(x24),LLIL_REG.q(x13)))'),
    # ld1 {v25.d}[0], [x14], x29
    (b'\xD9\x85\xDD\x0D', 'LLIL_SET_REG.q(v25.d[0],LLIL_LOAD.q(LLIL_REG.q(x14)));' + \
                         ' LLIL_SET_REG.q(x14,LLIL_ADD.q(LLIL_REG.q(x14),LLIL_REG.q(x29)))'),
    # ld1 {v6.h}[0], [x21], #0x2
    (b'\xA6\x42\xDF\x0D', 'LLIL_SET_REG.w(v6.h[0],LLIL_LOAD.w(LLIL_REG.q(x21)));' + \
                         ' LLIL_SET_REG.q(x21,LLIL_ADD.q(LLIL_REG.q(x21),LLIL_CONST.q(0x2)))'),
    # ld1 {v21.h}[1], [x16], #0x2
    (b'\x15\x4A\xDF\x0D', 'LLIL_SET_REG.w(v21.h[1],LLIL_LOAD.w(LLIL_REG.q(x16)));' + \
                         ' LLIL_SET_REG.q(x16,LLIL_ADD.q(LLIL_REG.q(x16),LLIL_CONST.q(0x2)))'),
    # ld1 {v2.h}[6], [x2], x28
    (b'\x42\x50\xDC\x4D', 'LLIL_SET_REG.w(v2.h[6],LLIL_LOAD.w(LLIL_REG.q(x2)));' + \
                         ' LLIL_SET_REG.q(x2,LLIL_ADD.q(LLIL_REG.q(x2),LLIL_REG.q(x28)))'),
    # ld1 {v3.h}[6], [x15], x17
    (b'\xE3\x51\xD1\x4D', 'LLIL_SET_REG.w(v3.h[6],LLIL_LOAD.w(LLIL_REG.q(x15)));' + \
                         ' LLIL_SET_REG.q(x15,LLIL_ADD.q(LLIL_REG.q(x15),LLIL_REG.q(x17)))'),
    # ld1 {v0.s}[0], [x14], #0x4
    (b'\xC0\x81\xDF\x0D', 'LLIL_SET_REG.d(v0.s[0],LLIL_LOAD.d(LLIL_REG.q(x14)));' + \
                         ' LLIL_SET_REG.q(x14,LLIL_ADD.q(LLIL_REG.q(x14),LLIL_CONST.q(0x4)))'),
    # ld1 {v20.s}[1], [x18], #0x4
    (b'\x54\x92\xDF\x0D', 'LLIL_SET_REG.d(v20.s[1],LLIL_LOAD.d(LLIL_REG.q(x18)));' + \
                         ' LLIL_SET_REG.q(x18,LLIL_ADD.q(LLIL_REG.q(x18),LLIL_CONST.q(0x4)))'),
    # ld1 {v22.s}[1], [x6], x6
    (b'\xD6\x90\xC6\x0D', 'LLIL_SET_REG.d(v22.s[1],LLIL_LOAD.d(LLIL_REG.q(x6)));' + \
                         ' LLIL_SET_REG.q(x6,LLIL_ADD.q(LLIL_REG.q(x6),LLIL_REG.q(x6)))'),
    # ld1 {v22.s}[1], [x23], x23
    (b'\xF6\x92\xD7\x0D', 'LLIL_SET_REG.d(v22.s[1],LLIL_LOAD.d(LLIL_REG.q(x23)));' + \
                         ' LLIL_SET_REG.q(x23,LLIL_ADD.q(LLIL_REG.q(x23),LLIL_REG.q(x23)))'),
]

tests_ld2 = [
    # LD2           {V2.8H-V3.8H}, [X13]
    (b'\xA2\x85\x40\x4C', 'LLIL_INTRINSIC([v2],vld2q_s16,[LLIL_REG.q(x13)])'),
    # LD2           {V6.4H-V7.4H}, [X27]
    (b'\x66\x87\x40\x0C', 'LLIL_INTRINSIC([v6],vld2_s16,[LLIL_REG.q(x27)])'),
    # LD2           {V7.2S-V8.2S}, [X9]
    (b'\x27\x89\x40\x0C', 'LLIL_INTRINSIC([v7],vld2_s32,[LLIL_REG.q(x9)])'),
    # LD2           {V2.4S-V3.4S}, [X24]
    (b'\x02\x8B\x40\x4C', 'LLIL_INTRINSIC([v2],vld2q_s32,[LLIL_REG.q(x24)])'),
    # LD2           {V27.8B-V28.8B}, [X7]
    (b'\xFB\x80\x40\x0C', 'LLIL_INTRINSIC([v27],vld2_s8,[LLIL_REG.q(x7)])'),
    # LD2           {V8.16B-V9.16B}, [X18]
    (b'\x48\x82\x40\x4C', 'LLIL_INTRINSIC([v8],vld2q_s8,[LLIL_REG.q(x18)])'),
    # LD2           {V26.2D-V27.2D}, [X0]
    (b'\x1A\x8C\x40\x4C', 'LLIL_INTRINSIC([v26],vld2q_s64,[LLIL_REG.q(x0)])')
]

tests_st1 = [
    # st1 {v3.2s}, [x27]
    (b'\x63\x7B\x00\x0C', 'LLIL_STORE.q(LLIL_REG.q(x27),LLIL_REG.q(v3.d[0]))'),
    # st1 {v22.8b}, [x28]
    (b'\x96\x73\x00\x0C', 'LLIL_STORE.q(LLIL_REG.q(x28),LLIL_REG.q(v22.d[0]))'),
    # st1 {v6.4s, v7.4s}, [x14]
    (b'\xC6\xA9\x00\x4C', 'LLIL_STORE.o(LLIL_REG.q(x14),LLIL_REG.o(v6));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x14),LLIL_CONST.q(0x10)),LLIL_REG.o(v7))'),
    # st1 {v29.4h, v30.4h}, [x11]
    (b'\x7D\xA5\x00\x0C', 'LLIL_STORE.q(LLIL_REG.q(x11),LLIL_REG.q(v29.d[0]));' + \
                         ' LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x11),LLIL_CONST.q(0x8)),LLIL_REG.q(v30.d[0]))'),
    # st1 {v27.2d, v28.2d, v29.2d}, [x17]
    (b'\x3B\x6E\x00\x4C', 'LLIL_STORE.o(LLIL_REG.q(x17),LLIL_REG.o(v27));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x17),LLIL_CONST.q(0x10)),LLIL_REG.o(v28));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x17),LLIL_CONST.q(0x20)),LLIL_REG.o(v29))'),
    # st1 {v10.4s, v11.4s, v12.4s}, [x1]
    (b'\x2A\x68\x00\x4C', 'LLIL_STORE.o(LLIL_REG.q(x1),LLIL_REG.o(v10));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x1),LLIL_CONST.q(0x10)),LLIL_REG.o(v11));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x1),LLIL_CONST.q(0x20)),LLIL_REG.o(v12))'),
    # st1 {v1.2d, v2.2d, v3.2d, v4.2d}, [x30]
    (b'\xC1\x2F\x00\x4C', 'LLIL_STORE.o(LLIL_REG.q(x30),LLIL_REG.o(v1));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x30),LLIL_CONST.q(0x10)),LLIL_REG.o(v2));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x30),LLIL_CONST.q(0x20)),LLIL_REG.o(v3));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x30),LLIL_CONST.q(0x30)),LLIL_REG.o(v4))'),
    # st1 {v26.4s, v27.4s, v28.4s, v29.4s}, [x13]
    (b'\xBA\x29\x00\x4C', 'LLIL_STORE.o(LLIL_REG.q(x13),LLIL_REG.o(v26));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x13),LLIL_CONST.q(0x10)),LLIL_REG.o(v27));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x13),LLIL_CONST.q(0x20)),LLIL_REG.o(v28));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x13),LLIL_CONST.q(0x30)),LLIL_REG.o(v29))'),
    # st1 {v5.2d}, [x10], #0x10
    (b'\x45\x7D\x9F\x4C', 'LLIL_STORE.o(LLIL_REG.q(x10),LLIL_REG.o(v5))'),
    # st1 {v20.2d}, [x5], #0x10
    (b'\xB4\x7C\x9F\x4C', 'LLIL_STORE.o(LLIL_REG.q(x5),LLIL_REG.o(v20))'),
    # st1 {v26.2s, v27.2s}, [x0], #0x10
    (b'\x1A\xA8\x9F\x0C', 'LLIL_STORE.q(LLIL_REG.q(x0),LLIL_REG.q(v26.d[0]));' + \
                         ' LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x0),LLIL_CONST.q(0x8)),LLIL_REG.q(v27.d[0]));' + \
                         ' LLIL_SET_REG.q(x0,LLIL_ADD.q(LLIL_REG.q(x0),LLIL_CONST.q(0x10)))'),
    # st1 {v10.4s, v11.4s}, [x12], #0x20
    (b'\x8A\xA9\x9F\x4C', 'LLIL_STORE.o(LLIL_REG.q(x12),LLIL_REG.o(v10));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x12),LLIL_CONST.q(0x10)),LLIL_REG.o(v11));' + \
                         ' LLIL_SET_REG.q(x12,LLIL_ADD.q(LLIL_REG.q(x12),LLIL_CONST.q(0x20)))'),
    # st1 {v26.4s, v27.4s, v28.4s}, [x4], #0x30
    (b'\x9A\x68\x9F\x4C', 'LLIL_STORE.o(LLIL_REG.q(x4),LLIL_REG.o(v26));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x4),LLIL_CONST.q(0x10)),LLIL_REG.o(v27));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x4),LLIL_CONST.q(0x20)),LLIL_REG.o(v28));' + \
                         ' LLIL_SET_REG.q(x4,LLIL_ADD.q(LLIL_REG.q(x4),LLIL_CONST.q(0x30)))'),
    # st1 {v1.4s, v2.4s, v3.4s}, [x24], #0x30
    (b'\x01\x6B\x9F\x4C', 'LLIL_STORE.o(LLIL_REG.q(x24),LLIL_REG.o(v1));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x24),LLIL_CONST.q(0x10)),LLIL_REG.o(v2));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x24),LLIL_CONST.q(0x20)),LLIL_REG.o(v3));' + \
                         ' LLIL_SET_REG.q(x24,LLIL_ADD.q(LLIL_REG.q(x24),LLIL_CONST.q(0x30)))'),
    # st1 {v4.2d, v5.2d, v6.2d, v7.2d}, [x1], #0x40
    (b'\x24\x2C\x9F\x4C', 'LLIL_STORE.o(LLIL_REG.q(x1),LLIL_REG.o(v4));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x1),LLIL_CONST.q(0x10)),LLIL_REG.o(v5));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x1),LLIL_CONST.q(0x20)),LLIL_REG.o(v6));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x1),LLIL_CONST.q(0x30)),LLIL_REG.o(v7));' + \
                         ' LLIL_SET_REG.q(x1,LLIL_ADD.q(LLIL_REG.q(x1),LLIL_CONST.q(0x40)))'),
    # st1 {v7.2s, v8.2s, v9.2s, v10.2s}, [x10], #0x20
    (b'\x47\x29\x9F\x0C', 'LLIL_STORE.q(LLIL_REG.q(x10),LLIL_REG.q(v7.d[0]));' + \
                         ' LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x10),LLIL_CONST.q(0x8)),LLIL_REG.q(v8.d[0]));' + \
                         ' LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x10),LLIL_CONST.q(0x10)),LLIL_REG.q(v9.d[0]));' + \
                         ' LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x10),LLIL_CONST.q(0x18)),LLIL_REG.q(v10.d[0]));' + \
                         ' LLIL_SET_REG.q(x10,LLIL_ADD.q(LLIL_REG.q(x10),LLIL_CONST.q(0x20)))'),
    # st1 {v16.1d}, [x0], x13
    (b'\x10\x7C\x8D\x0C', 'LLIL_STORE.q(LLIL_REG.q(x0),LLIL_REG.q(v16.d[0]));' + \
                         ' LLIL_SET_REG.q(x0,LLIL_ADD.q(LLIL_REG.q(x0),LLIL_REG.q(x13)))'),
    # st1 {v12.4s}, [x23], x23
    (b'\xEC\x7A\x97\x4C', 'LLIL_STORE.o(LLIL_REG.q(x23),LLIL_REG.o(v12));' + \
                         ' LLIL_SET_REG.q(x23,LLIL_ADD.q(LLIL_REG.q(x23),LLIL_REG.q(x23)))'),
    # st1 {v17.4s, v18.4s}, [x15], x8
    (b'\xF1\xA9\x88\x4C', 'LLIL_STORE.o(LLIL_REG.q(x15),LLIL_REG.o(v17));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x15),LLIL_CONST.q(0x10)),LLIL_REG.o(v18));' + \
                         ' LLIL_SET_REG.q(x15,LLIL_ADD.q(LLIL_REG.q(x15),LLIL_REG.q(x8)))'),
    # st1 {v30.16b, v31.16b}, [x21], x10
    (b'\xBE\xA2\x8A\x4C', 'LLIL_STORE.o(LLIL_REG.q(x21),LLIL_REG.o(v30));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x21),LLIL_CONST.q(0x10)),LLIL_REG.o(v31));' + \
                         ' LLIL_SET_REG.q(x21,LLIL_ADD.q(LLIL_REG.q(x21),LLIL_REG.q(x10)))'),
    # st1 {v4.4h, v5.4h, v6.4h}, [x25], x4
    (b'\x24\x67\x84\x0C', 'LLIL_STORE.q(LLIL_REG.q(x25),LLIL_REG.q(v4.d[0]));' + \
                         ' LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x25),LLIL_CONST.q(0x8)),LLIL_REG.q(v5.d[0]));' + \
                         ' LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x25),LLIL_CONST.q(0x10)),LLIL_REG.q(v6.d[0]));' + \
                         ' LLIL_SET_REG.q(x25,LLIL_ADD.q(LLIL_REG.q(x25),LLIL_REG.q(x4)))'),
    # st1 {v1.1d, v2.1d, v3.1d}, [x27], x2
    (b'\x61\x6F\x82\x0C', 'LLIL_STORE.q(LLIL_REG.q(x27),LLIL_REG.q(v1.d[0]));' + \
                         ' LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x27),LLIL_CONST.q(0x8)),LLIL_REG.q(v2.d[0]));' + \
                         ' LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x27),LLIL_CONST.q(0x10)),LLIL_REG.q(v3.d[0]));' + \
                         ' LLIL_SET_REG.q(x27,LLIL_ADD.q(LLIL_REG.q(x27),LLIL_REG.q(x2)))'),
    # st1 {v11.2s, v12.2s, v13.2s, v14.2s}, [x7], x19
    (b'\xEB\x28\x93\x0C', 'LLIL_STORE.q(LLIL_REG.q(x7),LLIL_REG.q(v11.d[0]));' + \
                         ' LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x7),LLIL_CONST.q(0x8)),LLIL_REG.q(v12.d[0]));' + \
                         ' LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x7),LLIL_CONST.q(0x10)),LLIL_REG.q(v13.d[0]));' + \
                         ' LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x7),LLIL_CONST.q(0x18)),LLIL_REG.q(v14.d[0]));' + \
                         ' LLIL_SET_REG.q(x7,LLIL_ADD.q(LLIL_REG.q(x7),LLIL_REG.q(x19)))'),
    # st1 {v27.4s, v28.4s, v29.4s, v30.4s}, [x25], x12
    (b'\x3B\x2B\x8C\x4C', 'LLIL_STORE.o(LLIL_REG.q(x25),LLIL_REG.o(v27));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x25),LLIL_CONST.q(0x10)),LLIL_REG.o(v28));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x25),LLIL_CONST.q(0x20)),LLIL_REG.o(v29));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x25),LLIL_CONST.q(0x30)),LLIL_REG.o(v30));' + \
                         ' LLIL_SET_REG.q(x25,LLIL_ADD.q(LLIL_REG.q(x25),LLIL_REG.q(x12)))'),
    # st1 {v20.b}[6], [x22]
    (b'\xD4\x1A\x00\x0D', 'LLIL_STORE.b(LLIL_REG.q(x22),LLIL_REG.b(v20.b[6]))'),
    # st1 {v12.b}[9], [x21]
    (b'\xAC\x06\x00\x4D', 'LLIL_STORE.b(LLIL_REG.q(x21),LLIL_REG.b(v12.b[9]))'),
    # st1 {v5.d}[0], [sp]
    (b'\xE5\x87\x00\x0D', 'LLIL_STORE.q(LLIL_REG.q(sp),LLIL_REG.q(v5.d[0]))'),
    # st1 {v27.d}[0], [x17]
    (b'\x3B\x86\x00\x0D', 'LLIL_STORE.q(LLIL_REG.q(x17),LLIL_REG.q(v27.d[0]))'),
    # st1 {v20.h}[4], [x30]
    (b'\xD4\x43\x00\x4D', 'LLIL_STORE.w(LLIL_REG.q(x30),LLIL_REG.w(v20.h[4]))'),
    # st1 {v1.h}[5], [x22]
    (b'\xC1\x4A\x00\x4D', 'LLIL_STORE.w(LLIL_REG.q(x22),LLIL_REG.w(v1.h[5]))'),
    # st1 {v30.s}[0], [x9]
    (b'\x3E\x81\x00\x0D', 'LLIL_STORE.d(LLIL_REG.q(x9),LLIL_REG.d(v30.s[0]))'),
    # st1 {v1.s}[0], [x0]
    (b'\x01\x80\x00\x0D', 'LLIL_STORE.d(LLIL_REG.q(x0),LLIL_REG.d(v1.s[0]))'),
    # st1 {v21.b}[9], [x10], #0x1
    (b'\x55\x05\x9F\x4D', 'LLIL_STORE.b(LLIL_REG.q(x10),LLIL_REG.b(v21.b[9]));' + \
                         ' LLIL_SET_REG.q(x10,LLIL_ADD.q(LLIL_REG.q(x10),LLIL_CONST.q(0x1)))'),
    # st1 {v28.b}[15], [x5], #0x1
    (b'\xBC\x1C\x9F\x4D', 'LLIL_STORE.b(LLIL_REG.q(x5),LLIL_REG.b(v28.b[15]));' + \
                         ' LLIL_SET_REG.q(x5,LLIL_ADD.q(LLIL_REG.q(x5),LLIL_CONST.q(0x1)))'),
    # st1 {v8.b}[1], [x28], x5
    (b'\x88\x07\x85\x0D', 'LLIL_STORE.b(LLIL_REG.q(x28),LLIL_REG.b(v8.b[1]));' + \
                         ' LLIL_SET_REG.q(x28,LLIL_ADD.q(LLIL_REG.q(x28),LLIL_REG.q(x5)))'),
    # st1 {v2.b}[3], [x15], x2
    (b'\xE2\x0D\x82\x0D', 'LLIL_STORE.b(LLIL_REG.q(x15),LLIL_REG.b(v2.b[3]));' + \
                         ' LLIL_SET_REG.q(x15,LLIL_ADD.q(LLIL_REG.q(x15),LLIL_REG.q(x2)))'),
    # st1 {v16.d}[1], [x15], #0x8
    (b'\xF0\x85\x9F\x4D', 'LLIL_STORE.q(LLIL_REG.q(x15),LLIL_REG.q(v16.d[1]));' + \
                         ' LLIL_SET_REG.q(x15,LLIL_ADD.q(LLIL_REG.q(x15),LLIL_CONST.q(0x8)))'),
    # st1 {v0.d}[0], [x13], #0x8
    (b'\xA0\x85\x9F\x0D', 'LLIL_STORE.q(LLIL_REG.q(x13),LLIL_REG.q(v0.d[0]));' + \
                         ' LLIL_SET_REG.q(x13,LLIL_ADD.q(LLIL_REG.q(x13),LLIL_CONST.q(0x8)))'),
    # st1 {v11.d}[1], [x5], x28
    (b'\xAB\x84\x9C\x4D', 'LLIL_STORE.q(LLIL_REG.q(x5),LLIL_REG.q(v11.d[1]));' + \
                         ' LLIL_SET_REG.q(x5,LLIL_ADD.q(LLIL_REG.q(x5),LLIL_REG.q(x28)))'),
    # st1 {v12.d}[1], [x5], x12
    (b'\xAC\x84\x8C\x4D', 'LLIL_STORE.q(LLIL_REG.q(x5),LLIL_REG.q(v12.d[1]));' + \
                         ' LLIL_SET_REG.q(x5,LLIL_ADD.q(LLIL_REG.q(x5),LLIL_REG.q(x12)))'),
    # st1 {v17.h}[3], [x8], #0x2
    (b'\x11\x59\x9F\x0D', 'LLIL_STORE.w(LLIL_REG.q(x8),LLIL_REG.w(v17.h[3]));' + \
                         ' LLIL_SET_REG.q(x8,LLIL_ADD.q(LLIL_REG.q(x8),LLIL_CONST.q(0x2)))'),
    # st1 {v13.h}[4], [x9], #0x2
    (b'\x2D\x41\x9F\x4D', 'LLIL_STORE.w(LLIL_REG.q(x9),LLIL_REG.w(v13.h[4]));' + \
                         ' LLIL_SET_REG.q(x9,LLIL_ADD.q(LLIL_REG.q(x9),LLIL_CONST.q(0x2)))'),
    # st1 {v16.h}[6], [x25], x15
    (b'\x30\x53\x8F\x4D', 'LLIL_STORE.w(LLIL_REG.q(x25),LLIL_REG.w(v16.h[6]));' + \
                         ' LLIL_SET_REG.q(x25,LLIL_ADD.q(LLIL_REG.q(x25),LLIL_REG.q(x15)))'),
    # st1 {v13.h}[3], [x2], x0
    (b'\x4D\x58\x80\x0D', 'LLIL_STORE.w(LLIL_REG.q(x2),LLIL_REG.w(v13.h[3]));' + \
                         ' LLIL_SET_REG.q(x2,LLIL_ADD.q(LLIL_REG.q(x2),LLIL_REG.q(x0)))'),
    # st1 {v9.s}[0], [x28], #0x4
    (b'\x89\x83\x9F\x0D', 'LLIL_STORE.d(LLIL_REG.q(x28),LLIL_REG.d(v9.s[0]));' + \
                         ' LLIL_SET_REG.q(x28,LLIL_ADD.q(LLIL_REG.q(x28),LLIL_CONST.q(0x4)))'),
    # st1 {v31.s}[3], [x6], #0x4
    (b'\xDF\x90\x9F\x4D', 'LLIL_STORE.d(LLIL_REG.q(x6),LLIL_REG.d(v31.s[3]));' + \
                         ' LLIL_SET_REG.q(x6,LLIL_ADD.q(LLIL_REG.q(x6),LLIL_CONST.q(0x4)))'),
    # st1 {v19.s}[1], [x6], x22
    (b'\xD3\x90\x96\x0D', 'LLIL_STORE.d(LLIL_REG.q(x6),LLIL_REG.d(v19.s[1]));' + \
                         ' LLIL_SET_REG.q(x6,LLIL_ADD.q(LLIL_REG.q(x6),LLIL_REG.q(x22)))'),
    # st1 {v1.s}[0], [x29], x21
    (b'\xA1\x83\x95\x0D', 'LLIL_STORE.d(LLIL_REG.q(x29),LLIL_REG.d(v1.s[0]));' + \
                         ' LLIL_SET_REG.q(x29,LLIL_ADD.q(LLIL_REG.q(x29),LLIL_REG.q(x21)))'),
]

test_cases = \
    tests_udf + \
    tests_pac + \
    tests_load_acquire_store_release + \
    tests_movk + \
    tests_mvni + \
    tests_2791 + \
    tests_ucvtf + \
    tests_ucvtf2 + \
    tests_scvtf + \
    tests_ret + \
    tests_svc_hvc_smc + \
    tests_clrex + \
    tests_xtn_xtn2 + \
    tests_dc + \
    tests_uxtl_uxtl2 + \
    tests_ldadd + \
    tests_swp + \
    tests_dup + \
    tests_stlr + \
    tests_ldnp + \
    tests_stnp + \
    tests_mov + \
    tests_movi + \
    tests_fsub + \
    tests_fadd + \
    tests_fmul + \
    tests_fcvt + \
    tests_fccmp_fccmpe + \
    tests_fcmp_fcmpe + \
    tests_fcsel + \
    tests_fmov + \
    tests_sha + \
    tests_rev + \
    tests_ld1 + \
    tests_ld2 + \
    tests_st1 + \
    [
    # some vectors loads/stores that do not fill the entire register
    # TODO: ld1/st1 with different addressing modes
    # ld1 {v0.8b, v1.8b}, [x0]
    (b'\x00\xA0\x40\x0C', 'LLIL_SET_REG.q(v0.d[0],LLIL_LOAD.q(LLIL_REG.q(x0)));' + \
                         ' LLIL_SET_REG.q(v1.d[0],LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x0),LLIL_CONST.q(0x8))))'),
    # ld1 {v4.4h, v5.4h}, [x0]
    (b'\x04\xA4\x40\x0C', 'LLIL_SET_REG.q(v4.d[0],LLIL_LOAD.q(LLIL_REG.q(x0)));' + \
                         ' LLIL_SET_REG.q(v5.d[0],LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x0),LLIL_CONST.q(0x8))))'),
    # ld1 {v8.2s, v9.2s}, [x0]
    (b'\x08\xA8\x40\x0C', 'LLIL_SET_REG.q(v8.d[0],LLIL_LOAD.q(LLIL_REG.q(x0)));' + \
                         ' LLIL_SET_REG.q(v9.d[0],LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x0),LLIL_CONST.q(0x8))))'),
    # ld1 {v12.1d, v13.1d}, [x0]
    (b'\x0C\xAC\x40\x0C', 'LLIL_SET_REG.q(v12.d[0],LLIL_LOAD.q(LLIL_REG.q(x0)));' + \
                         ' LLIL_SET_REG.q(v13.d[0],LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x0),LLIL_CONST.q(0x8))))'),
    # shl v19.2d, v21.2d, #0x2
    (b'\xB3\x56\x42\x4F', 'LLIL_SET_REG.q(v19.d[0],LLIL_LSL.q(LLIL_REG.q(v21.d[0]),LLIL_CONST.b(0x2)));' + \
                         ' LLIL_SET_REG.q(v19.d[1],LLIL_LSL.q(LLIL_REG.q(v21.d[1]),LLIL_CONST.b(0x2)))'),
    # shl v7.4h, v8.4h, #0x7
    (b'\x07\x55\x17\x0F', 'LLIL_SET_REG.w(v7.h[0],LLIL_LSL.w(LLIL_REG.w(v8.h[0]),LLIL_CONST.b(0x7)));' + \
                         ' LLIL_SET_REG.w(v7.h[1],LLIL_LSL.w(LLIL_REG.w(v8.h[1]),LLIL_CONST.b(0x7)));' + \
                         ' LLIL_SET_REG.w(v7.h[2],LLIL_LSL.w(LLIL_REG.w(v8.h[2]),LLIL_CONST.b(0x7)));' + \
                         ' LLIL_SET_REG.w(v7.h[3],LLIL_LSL.w(LLIL_REG.w(v8.h[3]),LLIL_CONST.b(0x7)))'),
    # shl v17.2s, v9.2s, #0x5
    (b'\x31\x55\x25\x0F', 'LLIL_SET_REG.d(v17.s[0],LLIL_LSL.d(LLIL_REG.d(v9.s[0]),LLIL_CONST.b(0x5)));' + \
                         ' LLIL_SET_REG.d(v17.s[1],LLIL_LSL.d(LLIL_REG.d(v9.s[1]),LLIL_CONST.b(0x5)))'),
    # shl d18, d6, #0x3e
    (b'\xD2\x54\x7E\x5F', 'LLIL_SET_REG.q(d18,LLIL_LSL.q(LLIL_REG.q(d6),LLIL_CONST.b(0x3E)))'),
    # shl d27, d3, #0x30
    (b'\x7B\x54\x70\x5F', 'LLIL_SET_REG.q(d27,LLIL_LSL.q(LLIL_REG.q(d3),LLIL_CONST.b(0x30)))'),
    # ushr v25.4h, v11.4h, #0x4
    (b'\x79\x05\x1C\x2F', 'LLIL_SET_REG.w(v25.h[0],LLIL_LSR.w(LLIL_REG.w(v11.h[0]),LLIL_CONST.b(0x4)));' + \
                         ' LLIL_SET_REG.w(v25.h[1],LLIL_LSR.w(LLIL_REG.w(v11.h[1]),LLIL_CONST.b(0x4)));' + \
                         ' LLIL_SET_REG.w(v25.h[2],LLIL_LSR.w(LLIL_REG.w(v11.h[2]),LLIL_CONST.b(0x4)));' + \
                         ' LLIL_SET_REG.w(v25.h[3],LLIL_LSR.w(LLIL_REG.w(v11.h[3]),LLIL_CONST.b(0x4)))'),
    # ushr v23.2s, v29.2s, #0x8
    (b'\xB7\x07\x38\x2F', 'LLIL_SET_REG.d(v23.s[0],LLIL_LSR.d(LLIL_REG.d(v29.s[0]),LLIL_CONST.b(0x8)));' + \
                         ' LLIL_SET_REG.d(v23.s[1],LLIL_LSR.d(LLIL_REG.d(v29.s[1]),LLIL_CONST.b(0x8)))'),
    # ushr v21.8b, v15.8b, #0x7
    (b'\xF5\x05\x09\x2F', 'LLIL_SET_REG.b(v21.b[0],LLIL_LSR.b(LLIL_REG.b(v15.b[0]),LLIL_CONST.b(0x7)));' + \
                         ' LLIL_SET_REG.b(v21.b[1],LLIL_LSR.b(LLIL_REG.b(v15.b[1]),LLIL_CONST.b(0x7)));' + \
                         ' LLIL_SET_REG.b(v21.b[2],LLIL_LSR.b(LLIL_REG.b(v15.b[2]),LLIL_CONST.b(0x7)));' + \
                         ' LLIL_SET_REG.b(v21.b[3],LLIL_LSR.b(LLIL_REG.b(v15.b[3]),LLIL_CONST.b(0x7)));' + \
                         ' LLIL_SET_REG.b(v21.b[4],LLIL_LSR.b(LLIL_REG.b(v15.b[4]),LLIL_CONST.b(0x7)));' + \
                         ' LLIL_SET_REG.b(v21.b[5],LLIL_LSR.b(LLIL_REG.b(v15.b[5]),LLIL_CONST.b(0x7)));' + \
                         ' LLIL_SET_REG.b(v21.b[6],LLIL_LSR.b(LLIL_REG.b(v15.b[6]),LLIL_CONST.b(0x7)));' + \
                         ' LLIL_SET_REG.b(v21.b[7],LLIL_LSR.b(LLIL_REG.b(v15.b[7]),LLIL_CONST.b(0x7)))'),
    # ushr d2, d25, #0x26
    (b'\x22\x07\x5A\x7F', 'LLIL_SET_REG.q(d2,LLIL_LSR.q(LLIL_REG.q(d25),LLIL_CONST.b(0x26)))'),
    # ushr d31, d13, #0x8
    (b'\xBF\x05\x78\x7F', 'LLIL_SET_REG.q(d31,LLIL_LSR.q(LLIL_REG.q(d13),LLIL_CONST.b(0x8)))'),
    #
    (b'\x3B\x7F\xB6\x88', 'LLIL_SET_REG.d(temp0,LLIL_LOAD.d(LLIL_REG.q(x25))); LLIL_IF(LLIL_CMP_E.d(LLIL_REG.d(w22),LLIL_REG.d(temp0)),2,4);' + \
                         ' LLIL_STORE.d(LLIL_REG.q(x25),LLIL_REG.d(w27)); LLIL_GOTO(4); LLIL_SET_REG.d(w22,LLIL_REG.d(temp0))'), # casa w22, w27, [x25]
    (b'\x0C\x7D\xF1\x88', 'LLIL_SET_REG.d(temp0,LLIL_LOAD.d(LLIL_REG.q(x8))); LLIL_IF(LLIL_CMP_E.d(LLIL_REG.d(w17),LLIL_REG.d(temp0)),2,4);' + \
                         ' LLIL_STORE.d(LLIL_REG.q(x8),LLIL_REG.d(w12)); LLIL_GOTO(4); LLIL_SET_REG.d(w17,LLIL_REG.d(temp0))'), # casa w17, w12, [x8]
    (b'\xC6\xFF\xBB\x88', 'LLIL_SET_REG.d(temp0,LLIL_LOAD.d(LLIL_REG.q(x30))); LLIL_IF(LLIL_CMP_E.d(LLIL_REG.d(w27),LLIL_REG.d(temp0)),2,4);' + \
                         ' LLIL_STORE.d(LLIL_REG.q(x30),LLIL_REG.d(w6)); LLIL_GOTO(4); LLIL_SET_REG.d(w27,LLIL_REG.d(temp0))'), # casl w27, w6, [x30]
    (b'\x7E\xFC\xED\x88', 'LLIL_SET_REG.d(temp0,LLIL_LOAD.d(LLIL_REG.q(x3))); LLIL_IF(LLIL_CMP_E.d(LLIL_REG.d(w13),LLIL_REG.d(temp0)),2,4);' + \
                         ' LLIL_STORE.d(LLIL_REG.q(x3),LLIL_REG.d(w30)); LLIL_GOTO(4); LLIL_SET_REG.d(w13,LLIL_REG.d(temp0))'), # casal w13, w30, [x3]
    (b'\x43\x7C\xE5\x48', 'LLIL_SET_REG.w(temp0,LLIL_LOAD.w(LLIL_REG.q(x2))); LLIL_IF(LLIL_CMP_E.d(LLIL_LOW_PART.w(LLIL_REG.d(w5)),LLIL_NOP()),2,4);' + \
                         ' LLIL_STORE.w(LLIL_REG.q(x2),LLIL_LOW_PART.w(LLIL_REG.d(w3))); LLIL_GOTO(4); LLIL_SET_REG.d(w5,LLIL_REG.w(temp0))'), # casah w5, w3, [x2]
    (b'\xDE\xFC\xF2\x48', 'LLIL_SET_REG.w(temp0,LLIL_LOAD.w(LLIL_REG.q(x6))); LLIL_IF(LLIL_CMP_E.d(LLIL_LOW_PART.w(LLIL_REG.d(w18)),LLIL_NOP()),2,4);' + \
                         ' LLIL_STORE.w(LLIL_REG.q(x6),LLIL_LOW_PART.w(LLIL_REG.d(w30))); LLIL_GOTO(4); LLIL_SET_REG.d(w18,LLIL_REG.w(temp0))'), # casalh w18, w30, [x6]
    (b'\x80\x7F\xB5\x48', 'LLIL_SET_REG.w(temp0,LLIL_LOAD.w(LLIL_REG.q(x28))); LLIL_IF(LLIL_CMP_E.d(LLIL_LOW_PART.w(LLIL_REG.d(w21)),LLIL_NOP()),2,4);' + \
                         ' LLIL_STORE.w(LLIL_REG.q(x28),LLIL_LOW_PART.w(LLIL_REG.d(w0))); LLIL_GOTO(4); LLIL_SET_REG.d(w21,LLIL_REG.w(temp0))'), # cash w21, w0, [x28]
    (b'\xEB\xFD\xA5\x48', 'LLIL_SET_REG.w(temp0,LLIL_LOAD.w(LLIL_REG.q(x15))); LLIL_IF(LLIL_CMP_E.d(LLIL_LOW_PART.w(LLIL_REG.d(w5)),LLIL_NOP()),2,4);' + \
                         ' LLIL_STORE.w(LLIL_REG.q(x15),LLIL_LOW_PART.w(LLIL_REG.d(w11))); LLIL_GOTO(4); LLIL_SET_REG.d(w5,LLIL_REG.w(temp0))'), # caslh w5, w11, [x15]
    (b'\x2E\x7C\xF7\x08', 'LLIL_SET_REG.b(temp0,LLIL_LOAD.b(LLIL_REG.q(x1))); LLIL_IF(LLIL_CMP_E.d(LLIL_LOW_PART.b(LLIL_REG.d(w23)),LLIL_NOP()),2,4);' + \
                         ' LLIL_STORE.b(LLIL_REG.q(x1),LLIL_LOW_PART.b(LLIL_REG.d(w14))); LLIL_GOTO(4); LLIL_SET_REG.d(w23,LLIL_REG.b(temp0))'), # casab w23, w14, [x1]
    (b'\x27\xFF\xE6\x08', 'LLIL_SET_REG.b(temp0,LLIL_LOAD.b(LLIL_REG.q(x25))); LLIL_IF(LLIL_CMP_E.d(LLIL_LOW_PART.b(LLIL_REG.d(w6)),LLIL_NOP()),2,4);' + \
                         ' LLIL_STORE.b(LLIL_REG.q(x25),LLIL_LOW_PART.b(LLIL_REG.d(w7))); LLIL_GOTO(4); LLIL_SET_REG.d(w6,LLIL_REG.b(temp0))'), # casalb w6, w7, [x25]
    (b'\x1E\x7E\xB8\x08', 'LLIL_SET_REG.b(temp0,LLIL_LOAD.b(LLIL_REG.q(x16))); LLIL_IF(LLIL_CMP_E.d(LLIL_LOW_PART.b(LLIL_REG.d(w24)),LLIL_NOP()),2,4);' + \
                         ' LLIL_STORE.b(LLIL_REG.q(x16),LLIL_LOW_PART.b(LLIL_REG.d(w30))); LLIL_GOTO(4); LLIL_SET_REG.d(w24,LLIL_REG.b(temp0))'), # casb w24, w30, [x16]
    (b'\xA6\xFD\xAE\x08', 'LLIL_SET_REG.b(temp0,LLIL_LOAD.b(LLIL_REG.q(x13))); LLIL_IF(LLIL_CMP_E.d(LLIL_LOW_PART.b(LLIL_REG.d(w14)),LLIL_NOP()),2,4);' + \
                         ' LLIL_STORE.b(LLIL_REG.q(x13),LLIL_LOW_PART.b(LLIL_REG.d(w6))); LLIL_GOTO(4); LLIL_SET_REG.d(w14,LLIL_REG.b(temp0))'), # caslb w14, w6, [x13]
    # store pair
    (b'\xFD\x7B\x01\xA9', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(sp),LLIL_CONST.q(0x10)),LLIL_REG.q(x29));' + \
                         ' LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(sp),LLIL_CONST.q(0x18)),LLIL_REG.q(x30))'),
    # stp w11, w0, [x9, #0x38]
    (b'\x2B\x01\x07\x29', 'LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x9),LLIL_CONST.q(0x38)),LLIL_REG.d(w11));' + \
                         ' LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x9),LLIL_CONST.q(0x3C)),LLIL_REG.d(w0))'),
    # stp w13, w14, [x19, #-0x98]
    (b'\x6D\x3A\x2D\x29', 'LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x19),LLIL_CONST.q(0xFFFFFFFFFFFFFF68)),LLIL_REG.d(w13));' + \
                         ' LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x19),LLIL_CONST.q(0xFFFFFFFFFFFFFF6C)),LLIL_REG.d(w14))'),
    # stp x24, x3, [x11, #0xf0]
    (b'\x78\x0D\x0F\xA9', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x11),LLIL_CONST.q(0xF0)),LLIL_REG.q(x24));' + \
                         ' LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x11),LLIL_CONST.q(0xF8)),LLIL_REG.q(x3))'),
    # stp x26, x12, [x22], #0x1b0
    (b'\xDA\x32\x9B\xA8', 'LLIL_STORE.q(LLIL_REG.q(x22),LLIL_REG.q(x26));' + \
                         ' LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x22),LLIL_CONST.q(0x8)),LLIL_REG.q(x12));' + \
                         ' LLIL_SET_REG.q(x22,LLIL_ADD.q(LLIL_REG.q(x22),LLIL_CONST.q(0x1B0)))'),
    # stp d16, d18, [x15, #0x0]!
    (b'\xF0\x49\x80\x6D', 'LLIL_STORE.q(LLIL_REG.q(x15),LLIL_REG.q(d16));' + \
                         ' LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x15),LLIL_CONST.q(0x8)),LLIL_REG.q(d18))'),
    # stp q5, q12, [x16, #0x270]
    (b'\x05\xB2\x13\xAD', 'LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x16),LLIL_CONST.q(0x270)),LLIL_REG.o(q5));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x16),LLIL_CONST.q(0x280)),LLIL_REG.o(q12))'),
    # stp q27, q9, [x25], #0x260
    (b'\x3B\x27\x93\xAC', 'LLIL_STORE.o(LLIL_REG.q(x25),LLIL_REG.o(q27));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x25),LLIL_CONST.q(0x10)),LLIL_REG.o(q9));' + \
                         ' LLIL_SET_REG.q(x25,LLIL_ADD.q(LLIL_REG.q(x25),LLIL_CONST.q(0x260)))'),
    # stp q19, q11, [x19, #0x310]!
    (b'\x73\xAE\x98\xAD', 'LLIL_SET_REG.q(x19,LLIL_ADD.q(LLIL_REG.q(x19),LLIL_CONST.q(0x310)));' + \
                         ' LLIL_STORE.o(LLIL_REG.q(x19),LLIL_REG.o(q19));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x19),LLIL_CONST.q(0x10)),LLIL_REG.o(q11))'),
    # stp q9, q11, [x2, #0x50]!
    (b'\x49\xAC\x82\xAD', 'LLIL_SET_REG.q(x2,LLIL_ADD.q(LLIL_REG.q(x2),LLIL_CONST.q(0x50)));' + \
                         ' LLIL_STORE.o(LLIL_REG.q(x2),LLIL_REG.o(q9));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x2),LLIL_CONST.q(0x10)),LLIL_REG.o(q11))'),
    # stp s9, s30, [x7, #0xe4]
    (b'\xE9\xF8\x1C\x2D', 'LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x7),LLIL_CONST.q(0xE4)),LLIL_REG.d(s9));' + \
                         ' LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x7),LLIL_CONST.q(0xE8)),LLIL_REG.d(s30))'),
    # stp s19, s3, [x3, #0x68]!
    (b'\x73\x0C\x8D\x2D', 'LLIL_SET_REG.q(x3,LLIL_ADD.q(LLIL_REG.q(x3),LLIL_CONST.q(0x68)));' + \
                         ' LLIL_STORE.d(LLIL_REG.q(x3),LLIL_REG.d(s19));' + \
                         ' LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x3),LLIL_CONST.q(0x4)),LLIL_REG.d(s3))'),
    # ldp w23, w23, [x2, #0xa4]
    (b'\x57\xDC\x54\x29', 'LLIL_SET_REG.d(w23,LLIL_LOAD.d(LLIL_ADD.q(LLIL_REG.q(x2),LLIL_CONST.q(0xA4))));' + \
                         ' LLIL_SET_REG.d(w23,LLIL_LOAD.d(LLIL_ADD.q(LLIL_REG.q(x2),LLIL_CONST.q(0xA8))))'),
    # ldp w14, w30, [x30], #0x78
    (b'\xCE\x7B\xCF\x28', 'LLIL_SET_REG.d(w14,LLIL_LOAD.d(LLIL_REG.q(x30)));' + \
                         ' LLIL_SET_REG.d(w30,LLIL_LOAD.d(LLIL_ADD.q(LLIL_REG.q(x30),LLIL_CONST.q(0x4))));' + \
                         ' LLIL_SET_REG.q(x30,LLIL_ADD.q(LLIL_REG.q(x30),LLIL_CONST.q(0x78)))'),
    # ldp w23, w18, [x4, #0x30]!
    (b'\x97\x48\xC6\x29', 'LLIL_SET_REG.q(x4,LLIL_ADD.q(LLIL_REG.q(x4),LLIL_CONST.q(0x30)));' + \
                         ' LLIL_SET_REG.d(w23,LLIL_LOAD.d(LLIL_REG.q(x4)));' + \
                         ' LLIL_SET_REG.d(w18,LLIL_LOAD.d(LLIL_ADD.q(LLIL_REG.q(x4),LLIL_CONST.q(0x4))))'),
    # ldp x12, x10, [x14, #0x38]
    (b'\xCC\xA9\x43\xA9', 'LLIL_SET_REG.q(x12,LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x14),LLIL_CONST.q(0x38))));' + \
                         ' LLIL_SET_REG.q(x10,LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x14),LLIL_CONST.q(0x40))))'),
    # ldp x22, x28, [x21], #0x90
    (b'\xB6\x72\xC9\xA8', 'LLIL_SET_REG.q(x22,LLIL_LOAD.q(LLIL_REG.q(x21)));' + \
                         ' LLIL_SET_REG.q(x28,LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x21),LLIL_CONST.q(0x8))));' + \
                         ' LLIL_SET_REG.q(x21,LLIL_ADD.q(LLIL_REG.q(x21),LLIL_CONST.q(0x90)))'),
    # # cset w8, ne
    (b'\xE8\x07\x9F\x1A', 'LLIL_SET_REG.d(w8,LLIL_BOOL_TO_INT.d(LLIL_FLAG_GROUP(ne)))'),
    # some vector loads/stores
    (b'\x00\x70\x00\x4C', 'LLIL_STORE.o(LLIL_REG.q(x0),LLIL_REG.o(v0))'), # st1 {v0.16b}, [x0]
    (b'\x00\xA0\x00\x4C', 'LLIL_STORE.o(LLIL_REG.q(x0),LLIL_REG.o(v0));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x0),LLIL_CONST.q(0x10)),LLIL_REG.o(v1))'), # st1 {v0.16b, v1.16b}, [x0]
    (b'\x00\x60\x00\x4C', 'LLIL_STORE.o(LLIL_REG.q(x0),LLIL_REG.o(v0));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x0),LLIL_CONST.q(0x10)),LLIL_REG.o(v1));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x0),LLIL_CONST.q(0x20)),LLIL_REG.o(v2))'), # st1 {v0.16b, v1.16b, v2.16b}, [x0]
    (b'\x00\x20\x00\x4C', 'LLIL_STORE.o(LLIL_REG.q(x0),LLIL_REG.o(v0));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x0),LLIL_CONST.q(0x10)),LLIL_REG.o(v1));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x0),LLIL_CONST.q(0x20)),LLIL_REG.o(v2));' + \
                         ' LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x0),LLIL_CONST.q(0x30)),LLIL_REG.o(v3))'), # st1 {v0.16b, v1.16b, v2.16b, v3.16b}, [x0]
    (b'\x00\x70\x40\x4C', 'LLIL_SET_REG.o(v0,LLIL_LOAD.o(LLIL_REG.q(x0)))'), # ld1 {v0.16b}, [x0]
    (b'\x00\xA0\x40\x4C', 'LLIL_SET_REG.o(v0,LLIL_LOAD.o(LLIL_REG.q(x0)));' + \
                         ' LLIL_SET_REG.o(v1,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(x0),LLIL_CONST.q(0x10))))'), # ld1 {v0.16b, v1.16b}, [x0]
    (b'\x00\x60\x40\x4C', 'LLIL_SET_REG.o(v0,LLIL_LOAD.o(LLIL_REG.q(x0)));' + \
                         ' LLIL_SET_REG.o(v1,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(x0),LLIL_CONST.q(0x10))));' + \
                         ' LLIL_SET_REG.o(v2,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(x0),LLIL_CONST.q(0x20))))'), # ld1 {v0.16b, v1.16b, v2.16b}, [x0]
    (b'\x00\x20\x40\x4C', 'LLIL_SET_REG.o(v0,LLIL_LOAD.o(LLIL_REG.q(x0)));' + \
                         ' LLIL_SET_REG.o(v1,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(x0),LLIL_CONST.q(0x10))));' + \
                         ' LLIL_SET_REG.o(v2,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(x0),LLIL_CONST.q(0x20))));' + \
                         ' LLIL_SET_REG.o(v3,LLIL_LOAD.o(LLIL_ADD.q(LLIL_REG.q(x0),LLIL_CONST.q(0x30))))'), # ld1 {v0.16b, v1.16b, v2.16b, v3.16b}, [x0]
    #
    (b'\x63\x86\xA3\x9B', 'LLIL_SET_REG.q(x3,LLIL_SUB.q(LLIL_REG.q(x1),LLIL_MULU_DP.q(LLIL_REG.d(w19),LLIL_REG.d(w3))))'), # umsubl  x3, w19, w3, x1
    (b'\x63\xFE\xA3\x9B', 'LLIL_SET_REG.q(x3,LLIL_SUB.q(LLIL_CONST.q(0x0),LLIL_MULU_DP.q(LLIL_REG.d(w19),LLIL_REG.d(w3))))'), # umnegl  x3, w19, w3
    (b'\x63\x86\x23\x9B', 'LLIL_SET_REG.q(x3,LLIL_SUB.q(LLIL_REG.q(x1),LLIL_MULS_DP.q(LLIL_REG.d(w19),LLIL_REG.d(w3))))'), # smsubl  x3, w19, w3, x1
    (b'\x63\xFE\x23\x9B', 'LLIL_SET_REG.q(x3,LLIL_SUB.q(LLIL_CONST.q(0x0),LLIL_MULS_DP.q(LLIL_REG.d(w19),LLIL_REG.d(w3))))'), # smnegl  x3, w19, w3
    (b'\x63\x06\x23\x9B', 'LLIL_SET_REG.q(x3,LLIL_ADD.q(LLIL_REG.q(x1),LLIL_MULS_DP.q(LLIL_REG.d(w19),LLIL_REG.d(w3))))'), # smaddl  x3, w19, w3, x1
    (b'\x63\x06\xA3\x9B', 'LLIL_SET_REG.q(x3,LLIL_ADD.q(LLIL_REG.q(x1),LLIL_MULU_DP.q(LLIL_REG.d(w19),LLIL_REG.d(w3))))'), # umaddl  x3, w19, w3, x1
    (b'\x00\xFC\x14\x9B', 'LLIL_SET_REG.q(x0,LLIL_SUB.q(LLIL_CONST.q(0x0),LLIL_MUL.q(LLIL_REG.q(x0),LLIL_REG.q(x20))))'), # mneg    x0, x0, x20
    (b'\x20\x00\x02\x9A', 'LLIL_SET_REG.q(x0,LLIL_ADC.q(LLIL_REG.q(x1),LLIL_REG.q(x2),LLIL_FLAG(c)))'), # adc x0, x1, x2
    (b'\x20\x00\x02\xBA', 'LLIL_SET_REG.q(x0,LLIL_ADC.q{*}(LLIL_REG.q(x1),LLIL_REG.q(x2),LLIL_FLAG(c)))'), # adcs x0, x1, x2
    (b'\x08\x75\x93\x13', 'LLIL_SET_REG.d(w8,LLIL_LSR.q(LLIL_OR.q(LLIL_LSL.q(LLIL_REG.d(w8),LLIL_CONST.b(0x20)),LLIL_REG.d(w19)),LLIL_CONST.b(0x1D)))'), # extr    w8, w8, w19, #0x1d
    (b'\x20\x28\xC2\x93', 'LLIL_SET_REG.q(x0,LLIL_LSR.o(LLIL_OR.o(LLIL_LSL.o(LLIL_REG.q(x1),LLIL_CONST.b(0x40)),LLIL_REG.q(x2)),LLIL_CONST.b(0xA)))'), # extr x0, x1, x2, #10
    (b'\xC6\x0C\xC0\xDA', 'LLIL_INTRINSIC([x6],_byteswap,[LLIL_REG.q(x6)])'), # rev x6, x6
    (b'\xCB\x10\xC0\xDA', 'LLIL_INTRINSIC([x11],_CountLeadingZeros,[LLIL_REG.q(x6)])'), # clz    x11, x6
    (b'\x63\x00\xC0\xDA', 'LLIL_INTRINSIC([x3],__rbit,[LLIL_REG.q(x3)])'), # rbit    x3, x3
    # Unknown system register
    (b'\x21\x00\x1B\xD5', 'LLIL_INTRINSIC([sysreg_unknown],_WriteStatusReg,[LLIL_REG.q(x1)])'), # msr s3_3_c0_c0_1, x1
    (b'\x23\x00\x3B\xD5', 'LLIL_INTRINSIC([x3],_ReadStatusReg,[LLIL_REG.q(sysreg_unknown)])'), # mrs x3, s3_3_c0_c0_1
    (b'\xE0\x03\x9F\xD6', 'LLIL_INTRINSIC([],_eret,[]);' + \
                         ' LLIL_TRAP(0)'), # eret
    (b'\x00\x08\x21\x1E', 'LLIL_SET_REG.d(s0,LLIL_FMUL.d(LLIL_REG.d(s0),LLIL_REG.d(s1)))'), # fmul s0, s0, s1
    (b'\x00\x18\x21\x1E', 'LLIL_SET_REG.d(s0,LLIL_FDIV.d(LLIL_REG.d(s0),LLIL_REG.d(s1)))'), # fdiv s0, s0, s1
    (b'\xE0\x0F\x40\xBD', 'LLIL_SET_REG.d(s0,LLIL_LOAD.d(LLIL_ADD.q(LLIL_REG.q(sp),LLIL_CONST.q(0xC))))'), # ldr s0, [sp, #0xc]
    (b'\xE1\x0B\x40\xBD', 'LLIL_SET_REG.d(s1,LLIL_LOAD.d(LLIL_ADD.q(LLIL_REG.q(sp),LLIL_CONST.q(0x8))))'), # ldr s1, [sp, #0x8]
    (b'\x29\x7D\x40\xD3', 'LLIL_SET_REG.q(x9,LLIL_LOW_PART.d(LLIL_REG.q(x9)))'), # ubfx x9, x9, #0, #0x20
    (b'\x00\xC0\x1E\xD5', 'LLIL_INTRINSIC([vbar_el3],_WriteStatusReg,[LLIL_REG.q(x0)])'), # msr vbar_el3, x0
    (b'\x69\x01\x08\x4A', 'LLIL_SET_REG.d(w9,LLIL_XOR.d(LLIL_REG.d(w11),LLIL_REG.d(w8)))'), # eor w9, w11, w8
    (b'\x2C\x09\xD5\x4A', 'LLIL_SET_REG.d(w12,LLIL_XOR.d(LLIL_REG.d(w9),LLIL_ROR.d(LLIL_REG.d(w21),LLIL_CONST.b(0x2))))'), # eor w12, w9, w21, ror #0x2
    # adrp
    (b'\x80\x00\x00\xB0', 'LLIL_SET_REG.q(x0,LLIL_CONST.q(0x11000))'), # adrp x0, 0x11000
    # compare with asr
    (b'\x5F\x0D\x88\xEB', 'LLIL_SUB.q{*}(LLIL_REG.q(x10),LLIL_ASR.q(LLIL_REG.q(x8),LLIL_CONST.b(0x3)))'), # cmp x10, x8, asr #0x3
    (b'\x1F\x0C\x81\xEB', 'LLIL_SUB.q{*}(LLIL_REG.q(x0),LLIL_ASR.q(LLIL_REG.q(x1),LLIL_CONST.b(0x3)))'), # cmp x0, x1, asr #0x3
    (b'\x1F\x04\x81\x6B', 'LLIL_SUB.d{*}(LLIL_REG.d(w0),LLIL_ASR.d(LLIL_REG.d(w1),LLIL_CONST.b(0x1)))'), # cmp w0, w1, asr #0x1
    (b'\x3F\x14\x82\x6B', 'LLIL_SUB.d{*}(LLIL_REG.d(w1),LLIL_ASR.d(LLIL_REG.d(w2),LLIL_CONST.b(0x5)))'), # cmp w1, w2, asr #0x5
    # bfi/bfc/bfxil aliases of bfm
    # BFC_BFM_32M_bitfield 0011001100xxxxxxxxxxxxxxxxxxxxxx
    (b'\xF5\x27\x1F\x33', 'LLIL_SET_REG.d(w21,LLIL_AND.d(LLIL_CONST.d(0xFFFFF801),LLIL_REG.d(w21)))'), # bfc w21, #1, #10
    (b'\xFF\x37\x16\x33', 'LLIL_AND.d(LLIL_CONST.d(0xFF0003FF),LLIL_CONST.d(0x0))'), # bfc wzr, #10, #14 (optimized: any BFC on WZR yields 0)
    (b'\xF0\x2B\x17\x33', 'LLIL_SET_REG.d(w16,LLIL_AND.d(LLIL_CONST.d(0xFFF001FF),LLIL_REG.d(w16)))'), # bfc w16, #9, #11
    (b'\xEE\x5F\x1E\x33', 'LLIL_SET_REG.d(w14,LLIL_AND.d(LLIL_CONST.d(0xFC000003),LLIL_REG.d(w14)))'), # bfc w14, #2, #24
    # BFC_BFM_64M_bitfield 1011001101xxxxxxxxxxxxxxxxxxxxxx
    (b'\xF8\x5B\x74\xB3', 'LLIL_SET_REG.q(x24,LLIL_AND.q(LLIL_CONST.q(0xFFFFFFF800000FFF),LLIL_REG.q(x24)))'), # bfc x24, #12, #23
    (b'\xF4\x67\x77\xB3', 'LLIL_SET_REG.q(x20,LLIL_AND.q(LLIL_CONST.q(0xFFFFFFF8000001FF),LLIL_REG.q(x20)))'), # bfc x20, #9, #26
    (b'\xFF\x5F\x6B\xB3', 'LLIL_AND.q(LLIL_CONST.q(0xFFFFE000001FFFFF),LLIL_CONST.q(0x0))'), # bfc xzr, #21, #24
    (b'\xE0\x17\x5D\xB3', 'LLIL_SET_REG.q(x0,LLIL_AND.q(LLIL_CONST.q(0xFFFFFE07FFFFFFFF),LLIL_REG.q(x0)))'), # bfc x0, #35, #6
    # BFI_BFM_32M_bitfield 00110011000xxxxx0xxxxxxxxxxxxxxx
    (b'\xC3\x1D\x1C\x33', 'LLIL_SET_REG.d(w3,LLIL_OR.d(LLIL_AND.d(LLIL_CONST.d(0xFFFFF00F),LLIL_REG.d(w3)),LLIL_LSL.d(LLIL_AND.d(LLIL_CONST.d(0xFF),LLIL_REG.d(w14)),LLIL_CONST.b(0x4))))'), # bfi w3, w14, #4, #8
    (b'\x71\x23\x0C\x33', 'LLIL_SET_REG.d(w17,LLIL_OR.d(LLIL_AND.d(LLIL_CONST.d(0xE00FFFFF),LLIL_REG.d(w17)),LLIL_LSL.d(LLIL_AND.d(LLIL_CONST.d(0x1FF),LLIL_REG.d(w27)),LLIL_CONST.b(0x14))))'), # bfi w17, w27, #20, #9
    (b'\x2F\x3A\x14\x33', 'LLIL_SET_REG.d(w15,LLIL_OR.d(LLIL_AND.d(LLIL_CONST.d(0xF8000FFF),LLIL_REG.d(w15)),LLIL_LSL.d(LLIL_AND.d(LLIL_CONST.d(0x7FFF),LLIL_REG.d(w17)),LLIL_CONST.b(0xC))))'), # bfi w15, w17, #12, #15
    (b'\x42\x0C\x0A\x33', 'LLIL_SET_REG.d(w2,LLIL_OR.d(LLIL_AND.d(LLIL_CONST.d(0xFC3FFFFF),LLIL_REG.d(w2)),LLIL_LSL.d(LLIL_AND.d(LLIL_CONST.d(0xF),LLIL_REG.d(w2)),LLIL_CONST.b(0x16))))'), # bfi w2, w2, #22, #4
    # BFI_BFM_64M_bitfield 1011001101xxxxxxxxxxxxxxxxxxxxxx
    (b'\xE9\x05\x71\xB3', 'LLIL_SET_REG.q(x9,LLIL_OR.q(LLIL_AND.q(LLIL_CONST.q(0xFFFFFFFFFFFE7FFF),LLIL_REG.q(x9)),LLIL_LSL.q(LLIL_AND.q(LLIL_CONST.q(0x3),LLIL_REG.q(x15)),LLIL_CONST.b(0xF))))'), # bfi x9, x15, #15, #2
    (b'\x80\x3C\x74\xB3', 'LLIL_SET_REG.q(x0,LLIL_OR.q(LLIL_AND.q(LLIL_CONST.q(0xFFFFFFFFF0000FFF),LLIL_REG.q(x0)),LLIL_LSL.q(LLIL_AND.q(LLIL_CONST.q(0xFFFF),LLIL_REG.q(x4)),LLIL_CONST.b(0xC))))'), # bfi x0, x4, #12, #16
    (b'\x76\x6B\x7B\xB3', 'LLIL_SET_REG.q(x22,LLIL_OR.q(LLIL_AND.q(LLIL_CONST.q(0xFFFFFFFF0000001F),LLIL_REG.q(x22)),LLIL_LSL.q(LLIL_AND.q(LLIL_CONST.q(0x7FFFFFF),LLIL_REG.q(x27)),LLIL_CONST.b(0x5))))'), # bfi x22, x27, #5, #27
    (b'\xD1\x03\x7F\xB3', 'LLIL_SET_REG.q(x17,LLIL_OR.q(LLIL_AND.q(LLIL_CONST.q(0xFFFFFFFFFFFFFFFD),LLIL_REG.q(x17)),LLIL_LSL.q(LLIL_AND.q(LLIL_CONST.q(0x1),LLIL_REG.q(x30)),LLIL_CONST.b(0x1))))'), # bfi x17, x30, #1, #1
    # BFXIL_BFM_32M_bitfield 00110011000xxxxxxxxxxxxxxxxxxxxx
    (b'\x99\x2B\x06\x33', 'LLIL_SET_REG.d(w25,LLIL_OR.d(LLIL_AND.d(LLIL_REG.d(w25),LLIL_CONST.d(0xFFFFFFE0)),LLIL_LSR.d(LLIL_AND.d(LLIL_REG.d(w28),LLIL_CONST.d(0x7C0)),LLIL_CONST.b(0x6))))'), # bfxil w25, w28, #6, #5
    (b'\x83\x4A\x01\x33', 'LLIL_SET_REG.d(w3,LLIL_OR.d(LLIL_AND.d(LLIL_REG.d(w3),LLIL_CONST.d(0xFFFC0000)),LLIL_LSR.d(LLIL_AND.d(LLIL_REG.d(w20),LLIL_CONST.d(0x7FFFE)),LLIL_CONST.b(0x1))))'), # bfxil w3, w20, #1, #18
    (b'\x1C\x29\x09\x33', 'LLIL_SET_REG.d(w28,LLIL_OR.d(LLIL_AND.d(LLIL_REG.d(w28),LLIL_CONST.d(0xFFFFFFFC)),LLIL_LSR.d(LLIL_AND.d(LLIL_REG.d(w8),LLIL_CONST.d(0x600)),LLIL_CONST.b(0x9))))'), # bfxil w28, w8, #9, #2
    (b'\xF9\x7A\x16\x33', 'LLIL_SET_REG.d(w25,LLIL_OR.d(LLIL_AND.d(LLIL_REG.d(w25),LLIL_CONST.d(0xFFFFFE00)),LLIL_LSR.d(LLIL_AND.d(LLIL_REG.d(w23),LLIL_CONST.d(0x7FC00000)),LLIL_CONST.b(0x16))))'), # bfxil w25, w23, #22, #9
    # BFXIL_BFM_64M_bitfield 1011001101xxxxxxxxxxxxxxxxxxxxxx
    (b'\xF1\xC1\x65\xB3', 'LLIL_SET_REG.q(x17,LLIL_OR.q(LLIL_AND.q(LLIL_REG.q(x17),LLIL_CONST.q(0xFFFFFFFFFFFFF000)),LLIL_LSR.q(LLIL_AND.q(LLIL_REG.q(x15),LLIL_CONST.q(0x1FFE000000000)),LLIL_CONST.b(0x25))))'), # bfxil x17, x15, #37, #12
    (b'\x25\xF0\x51\xB3', 'LLIL_SET_REG.q(x5,LLIL_OR.q(LLIL_AND.q(LLIL_REG.q(x5),LLIL_CONST.q(0xFFFFF00000000000)),LLIL_LSR.q(LLIL_AND.q(LLIL_REG.q(x1),LLIL_CONST.q(0x1FFFFFFFFFFE0000)),LLIL_CONST.b(0x11))))'), # bfxil x5, x1, #17, #44
    (b'\x6E\xBE\x48\xB3', 'LLIL_SET_REG.q(x14,LLIL_OR.q(LLIL_AND.q(LLIL_REG.q(x14),LLIL_CONST.q(0xFFFFFF0000000000)),LLIL_LSR.q(LLIL_AND.q(LLIL_REG.q(x19),LLIL_CONST.q(0xFFFFFFFFFF00)),LLIL_CONST.b(0x8))))'), # bfxil x14, x19, #8, #40
    (b'\x0D\xF0\x48\xB3', 'LLIL_SET_REG.q(x13,LLIL_OR.q(LLIL_AND.q(LLIL_REG.q(x13),LLIL_CONST.q(0xFFE0000000000000)),LLIL_LSR.q(LLIL_AND.q(LLIL_REG.q(x0),LLIL_CONST.q(0x1FFFFFFFFFFFFF00)),LLIL_CONST.b(0x8))))'), # bfxil x13, x0, #8, #53
    (b'\x62\xFC\x40\xB3', 'LLIL_SET_REG.q(x2,LLIL_OR.q(LLIL_AND.q(LLIL_REG.q(x2),LLIL_CONST.q(0x0)),LLIL_LSR.q(LLIL_AND.q(LLIL_REG.q(x3),LLIL_CONST.q(0xFFFFFFFFFFFFFFFF)),LLIL_CONST.b(0x0))))'), # bfxil x2, x3, #0, #0x40
    (b'\xE0\xFF\x40\xB3', 'LLIL_SET_REG.q(x0,LLIL_OR.q(LLIL_AND.q(LLIL_REG.q(x0),LLIL_CONST.q(0x0)),LLIL_LSR.q(LLIL_AND.q(LLIL_CONST.q(0x0),LLIL_CONST.q(0xFFFFFFFFFFFFFFFF)),LLIL_CONST.b(0x0))))'), # bfxil x0, xzr, #0, #64
    # str instructions
    # STR_32_ldst_immpost 10111000000xxxxxxxxx01xxxxxxxxxx
    (b'\xC4\xA5\x15\xB8', 'LLIL_STORE.d(LLIL_REG.q(x14),LLIL_REG.d(w4));' + \
                         ' LLIL_SET_REG.q(x14,LLIL_ADD.q(LLIL_REG.q(x14),LLIL_CONST.q(0xFFFFFFFFFFFFFF5A)))'), # str w4, [x14], #-166
    (b'\x30\xD7\x10\xB8', 'LLIL_STORE.d(LLIL_REG.q(x25),LLIL_REG.d(w16));' + \
                         ' LLIL_SET_REG.q(x25,LLIL_ADD.q(LLIL_REG.q(x25),LLIL_CONST.q(0xFFFFFFFFFFFFFF0D)))'), # str w16, [x25], #-243
    (b'\xC7\x24\x0A\xB8', 'LLIL_STORE.d(LLIL_REG.q(x6),LLIL_REG.d(w7));' + \
                         ' LLIL_SET_REG.q(x6,LLIL_ADD.q(LLIL_REG.q(x6),LLIL_CONST.q(0xA2)))'), # str w7, [x6], #162
    (b'\xA8\xF4\x01\xB8', 'LLIL_STORE.d(LLIL_REG.q(x5),LLIL_REG.d(w8));' + \
                         ' LLIL_SET_REG.q(x5,LLIL_ADD.q(LLIL_REG.q(x5),LLIL_CONST.q(0x1F)))'), # str w8, [x5], #31
    # STR_32_ldst_immpre 10111000000xxxxxxxxx11xxxxxxxxxx
    (b'\x54\xCD\x07\xB8', 'LLIL_SET_REG.q(x10,LLIL_ADD.q(LLIL_REG.q(x10),LLIL_CONST.q(0x7C)));' + \
                         ' LLIL_STORE.d(LLIL_REG.q(x10),LLIL_REG.d(w20))'), # str w20, [x10, #124]!
    (b'\x6A\x0E\x0A\xB8', 'LLIL_SET_REG.q(x19,LLIL_ADD.q(LLIL_REG.q(x19),LLIL_CONST.q(0xA0)));' + \
                         ' LLIL_STORE.d(LLIL_REG.q(x19),LLIL_REG.d(w10))'), # str w10, [x19, #160]!
    (b'\xC5\x3C\x18\xB8', 'LLIL_SET_REG.q(x6,LLIL_ADD.q(LLIL_REG.q(x6),LLIL_CONST.q(0xFFFFFFFFFFFFFF83)));' + \
                         ' LLIL_STORE.d(LLIL_REG.q(x6),LLIL_REG.d(w5))'), # str w5, [x6, #-125]!
    (b'\x40\x5D\x1F\xB8', 'LLIL_SET_REG.q(x10,LLIL_ADD.q(LLIL_REG.q(x10),LLIL_CONST.q(0xFFFFFFFFFFFFFFF5)));' + \
                         ' LLIL_STORE.d(LLIL_REG.q(x10),LLIL_REG.d(w0))'), # str w0, [x10, #-11]!
    # STR_32_ldst_pos 1011100100xxxxxxxxxxxxxxxxxxxxxx
    (b'\x3C\xD5\x3B\xB9', 'LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x9),LLIL_CONST.q(0x3BD4)),LLIL_REG.d(w28))'), # str w28, [x9, #15316]
    (b'\xF4\xAA\x08\xB9', 'LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x23),LLIL_CONST.q(0x8A8)),LLIL_REG.d(w20))'), # str w20, [x23, #2216]
    (b'\x04\x91\x10\xB9', 'LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x8),LLIL_CONST.q(0x1090)),LLIL_REG.d(w4))'), # str w4, [x8, #4240]
    (b'\x73\xE3\x06\xB9', 'LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x27),LLIL_CONST.q(0x6E0)),LLIL_REG.d(w19))'), # str w19, [x27, #1760]
    # STR_32_ldst_regoff 10111000001xxxxxx1xx10xxxxxxxxxx
    (b'\x49\x79\x25\xB8', 'LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x10),LLIL_LSL.q(LLIL_REG.q(x5),LLIL_CONST.b(0x2))),LLIL_REG.d(w9))'), # str w9, [x10, x5, lsl #2]
    (b'\x5C\x7B\x27\xB8', 'LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x26),LLIL_LSL.q(LLIL_REG.q(x7),LLIL_CONST.b(0x2))),LLIL_REG.d(w28))'), # str w28, [x26, x7, lsl #2]
    (b'\xFA\xF8\x27\xB8', 'LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x7),LLIL_LSL.q(LLIL_REG.q(x7),LLIL_CONST.b(0x2))),LLIL_REG.d(w26))'), # str w26, [x7, x7, sxtx #2]
    (b'\xB0\xEB\x38\xB8', 'LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x29),LLIL_REG.q(x24)),LLIL_REG.d(w16))'), # str w16, [x29, x24, sxtx]
    # STR_64_ldst_immpost 11111000000xxxxxxxxx01xxxxxxxxxx
    (b'\x34\x45\x06\xF8', 'LLIL_STORE.q(LLIL_REG.q(x9),LLIL_REG.q(x20));' + \
                         ' LLIL_SET_REG.q(x9,LLIL_ADD.q(LLIL_REG.q(x9),LLIL_CONST.q(0x64)))'), # str x20, [x9], #100
    (b'\x2E\xE6\x0B\xF8', 'LLIL_STORE.q(LLIL_REG.q(x17),LLIL_REG.q(x14));' + \
                         ' LLIL_SET_REG.q(x17,LLIL_ADD.q(LLIL_REG.q(x17),LLIL_CONST.q(0xBE)))'), # str x14, [x17], #190
    (b'\x1F\xB4\x0B\xF8', 'LLIL_STORE.q(LLIL_REG.q(x0),LLIL_CONST.q(0x0));' + \
                         ' LLIL_SET_REG.q(x0,LLIL_ADD.q(LLIL_REG.q(x0),LLIL_CONST.q(0xBB)))'), # str xzr, [x0], #187
    (b'\x90\xD5\x1E\xF8', 'LLIL_STORE.q(LLIL_REG.q(x12),LLIL_REG.q(x16));' + \
                         ' LLIL_SET_REG.q(x12,LLIL_ADD.q(LLIL_REG.q(x12),LLIL_CONST.q(0xFFFFFFFFFFFFFFED)))'), # str x16, [x12], #-19
    # STR_64_ldst_immpre 11111000000xxxxxxxxx11xxxxxxxxxx
    (b'\x94\xEE\x19\xF8', 'LLIL_SET_REG.q(x20,LLIL_ADD.q(LLIL_REG.q(x20),LLIL_CONST.q(0xFFFFFFFFFFFFFF9E)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x20),LLIL_REG.q(x20))'), # str x20, [x20, #-98]!
    (b'\x34\xBC\x0F\xF8', 'LLIL_SET_REG.q(x1,LLIL_ADD.q(LLIL_REG.q(x1),LLIL_CONST.q(0xFB)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x1),LLIL_REG.q(x20))'), # str x20, [x1, #251]!
    (b'\x71\xFC\x04\xF8', 'LLIL_SET_REG.q(x3,LLIL_ADD.q(LLIL_REG.q(x3),LLIL_CONST.q(0x4F)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x3),LLIL_REG.q(x17))'), # str x17, [x3, #79]!
    (b'\xC3\xBC\x1E\xF8', 'LLIL_SET_REG.q(x6,LLIL_ADD.q(LLIL_REG.q(x6),LLIL_CONST.q(0xFFFFFFFFFFFFFFEB)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x6),LLIL_REG.q(x3))'), # str x3, [x6, #-21]!
    # STR_64_ldst_pos 1111100100xxxxxxxxxxxxxxxxxxxxxx
    (b'\xED\x1A\x3C\xF9', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x23),LLIL_CONST.q(0x7830)),LLIL_REG.q(x13))'), # str x13, [x23, #30768]
    (b'\xA3\xA0\x21\xF9', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x5),LLIL_CONST.q(0x4340)),LLIL_REG.q(x3))'), # str x3, [x5, #17216]
    (b'\x19\x88\x2F\xF9', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x0),LLIL_CONST.q(0x5F10)),LLIL_REG.q(x25))'), # str x25, [x0, #24336]
    (b'\xBD\x8C\x14\xF9', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x5),LLIL_CONST.q(0x2918)),LLIL_REG.q(x29))'), # str x29, [x5, #10520]
    # STR_64_ldst_regoff 11111000001xxxxxx1xx10xxxxxxxxxx
    (b'\xD3\xE9\x21\xF8', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x14),LLIL_REG.q(x1)),LLIL_REG.q(x19))'), # str x19, [x14, x1, sxtx]
    (b'\xA2\x58\x25\xF8', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x5),LLIL_LSL.q(LLIL_ZX.q(LLIL_REG.d(w5)),LLIL_CONST.b(0x3))),LLIL_REG.q(x2))'), # str x2, [x5, w5, uxtw #3]
    (b'\xF4\xFA\x3A\xF8', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x23),LLIL_LSL.q(LLIL_REG.q(x26),LLIL_CONST.b(0x3))),LLIL_REG.q(x20))'), # str x20, [x23, x26, sxtx #3]
    (b'\xEE\xF9\x34\xF8', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x15),LLIL_LSL.q(LLIL_REG.q(x20),LLIL_CONST.b(0x3))),LLIL_REG.q(x14))'), # str x14, [x15, x20, sxtx #3]
    # IFORM: STR_reg_fpsimd
    # STR_B_ldst_regoff 00111100001xxxxxx1xx10xxxxxxxxxx
    (b'\xFD\xD8\x27\x3C', 'LLIL_STORE.b(LLIL_ADD.q(LLIL_REG.q(x7),LLIL_SX.q(LLIL_REG.d(w7))),LLIL_REG.b(b29))'), # str b29, [x7, w7, sxtw #0]
    (b'\x20\xDA\x30\x3C', 'LLIL_STORE.b(LLIL_ADD.q(LLIL_REG.q(x17),LLIL_SX.q(LLIL_REG.d(w16))),LLIL_REG.b(b0))'), # str b0, [x17, w16, sxtw #0]
    # STR_BL_ldst_regoff 00111100001xxxxx011x10xxxxxxxxxx
    (b'\xCC\x7B\x27\x3C', 'LLIL_STORE.b(LLIL_ADD.q(LLIL_REG.q(x30),LLIL_REG.q(x7)),LLIL_REG.b(b12))'), # str b12, [x30, x7, lsl #0]
    (b'\x1F\x79\x3A\x3C', 'LLIL_STORE.b(LLIL_ADD.q(LLIL_REG.q(x8),LLIL_REG.q(x26)),LLIL_REG.b(b31))'), # str b31, [x8, x26, lsl #0]
    # STR_H_ldst_regoff 01111100001xxxxxx1xx10xxxxxxxxxx
    (b'\xCE\xD9\x36\x7C', 'LLIL_STORE.w(LLIL_ADD.q(LLIL_REG.q(x14),LLIL_LSL.q(LLIL_SX.q(LLIL_REG.d(w22)),LLIL_CONST.b(0x1))),LLIL_REG.w(h14))'), # str h14, [x14, w22, sxtw #1]
    (b'\x39\xCB\x2D\x7C', 'LLIL_STORE.w(LLIL_ADD.q(LLIL_REG.q(x25),LLIL_SX.q(LLIL_REG.d(w13))),LLIL_REG.w(h25))'), # str h25, [x25, w13, sxtw]
    # STR_S_ldst_regoff 10111100001xxxxxx1xx10xxxxxxxxxx
    (b'\xB5\x79\x3F\xBC', 'LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x13),LLIL_LSL.q(LLIL_CONST.q(0x0),LLIL_CONST.b(0x2))),LLIL_REG.d(s21))'), # str s21, [x13, xzr, lsl #2]
    (b'\x8B\x7B\x2C\xBC', 'LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x28),LLIL_LSL.q(LLIL_REG.q(x12),LLIL_CONST.b(0x2))),LLIL_REG.d(s11))'), # str s11, [x28, x12, lsl #2]
    # STR_D_ldst_regoff 11111100001xxxxxx1xx10xxxxxxxxxx
    (b'\x2C\x59\x22\xFC', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x9),LLIL_LSL.q(LLIL_ZX.q(LLIL_REG.d(w2)),LLIL_CONST.b(0x3))),LLIL_REG.q(d12))'), # str d12, [x9, w2, uxtw #3]
    (b'\x25\xD9\x22\xFC', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x9),LLIL_LSL.q(LLIL_SX.q(LLIL_REG.d(w2)),LLIL_CONST.b(0x3))),LLIL_REG.q(d5))'), # str d5, [x9, w2, sxtw #3]
    # STR_Q_ldst_regoff 00111100101xxxxxx1xx10xxxxxxxxxx
    (b'\x0B\xCB\xA1\x3C', 'LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x24),LLIL_SX.q(LLIL_REG.d(w1))),LLIL_REG.o(q11))'), # str q11, [x24, w1, sxtw]
    (b'\x8E\xCB\xBD\x3C', 'LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x28),LLIL_SX.q(LLIL_REG.d(w29))),LLIL_REG.o(q14))'), # str q14, [x28, w29, sxtw]
    # IFORM: STR_imm_fpsimd (class post_indexed)
    # STR_B_ldst_immpost 00111100000xxxxxxxxx01xxxxxxxxxx
    (b'\xB6\x57\x07\x3C', 'LLIL_STORE.b(LLIL_REG.q(x29),LLIL_REG.b(b22));' + \
                         ' LLIL_SET_REG.q(x29,LLIL_ADD.q(LLIL_REG.q(x29),LLIL_CONST.q(0x75)))'), # str b22, [x29], #117
    (b'\x0F\xE7\x0C\x3C', 'LLIL_STORE.b(LLIL_REG.q(x24),LLIL_REG.b(b15));' + \
                         ' LLIL_SET_REG.q(x24,LLIL_ADD.q(LLIL_REG.q(x24),LLIL_CONST.q(0xCE)))'), # str b15, [x24], #206
    # STR_H_ldst_immpost 01111100000xxxxxxxxx01xxxxxxxxxx
    (b'\x56\xC6\x01\x7C', 'LLIL_STORE.w(LLIL_REG.q(x18),LLIL_REG.w(h22));' + \
                         ' LLIL_SET_REG.q(x18,LLIL_ADD.q(LLIL_REG.q(x18),LLIL_CONST.q(0x1C)))'), # str h22, [x18], #28
    (b'\x93\xD7\x07\x7C', 'LLIL_STORE.w(LLIL_REG.q(x28),LLIL_REG.w(h19));' + \
                         ' LLIL_SET_REG.q(x28,LLIL_ADD.q(LLIL_REG.q(x28),LLIL_CONST.q(0x7D)))'), # str h19, [x28], #125
    # STR_S_ldst_immpost 10111100000xxxxxxxxx01xxxxxxxxxx
    (b'\x9E\x06\x13\xBC', 'LLIL_STORE.d(LLIL_REG.q(x20),LLIL_REG.d(s30));' + \
                         ' LLIL_SET_REG.q(x20,LLIL_ADD.q(LLIL_REG.q(x20),LLIL_CONST.q(0xFFFFFFFFFFFFFF30)))'), # str s30, [x20], #-208
    (b'\xA9\x07\x07\xBC', 'LLIL_STORE.d(LLIL_REG.q(x29),LLIL_REG.d(s9));' + \
                         ' LLIL_SET_REG.q(x29,LLIL_ADD.q(LLIL_REG.q(x29),LLIL_CONST.q(0x70)))'), # str s9, [x29], #112
    # STR_D_ldst_immpost 11111100000xxxxxxxxx01xxxxxxxxxx
    (b'\xAD\xE4\x1F\xFC', 'LLIL_STORE.q(LLIL_REG.q(x5),LLIL_REG.q(d13));' + \
                         ' LLIL_SET_REG.q(x5,LLIL_ADD.q(LLIL_REG.q(x5),LLIL_CONST.q(0xFFFFFFFFFFFFFFFE)))'), # str d13, [x5], #-2
    (b'\xE3\x64\x15\xFC', 'LLIL_STORE.q(LLIL_REG.q(x7),LLIL_REG.q(d3));' + \
                         ' LLIL_SET_REG.q(x7,LLIL_ADD.q(LLIL_REG.q(x7),LLIL_CONST.q(0xFFFFFFFFFFFFFF56)))'), # str d3, [x7], #-170
    # STR_Q_ldst_immpost 00111100100xxxxxxxxx01xxxxxxxxxx
    (b'\xAD\xA5\x9A\x3C', 'LLIL_STORE.o(LLIL_REG.q(x13),LLIL_REG.o(q13));' + \
                         ' LLIL_SET_REG.q(x13,LLIL_ADD.q(LLIL_REG.q(x13),LLIL_CONST.q(0xFFFFFFFFFFFFFFAA)))'), # str q13, [x13], #-86
    (b'\x6C\x15\x8B\x3C', 'LLIL_STORE.o(LLIL_REG.q(x11),LLIL_REG.o(q12));' + \
                         ' LLIL_SET_REG.q(x11,LLIL_ADD.q(LLIL_REG.q(x11),LLIL_CONST.q(0xB1)))'), # str q12, [x11], #177
    # IFORM: STR_imm_fpsimd (class pre_indexed)
    # STR_B_ldst_immpre 00111100000xxxxxxxxx11xxxxxxxxxx
    (b'\x26\xBF\x00\x3C', 'LLIL_SET_REG.q(x25,LLIL_ADD.q(LLIL_REG.q(x25),LLIL_CONST.q(0xB)));' + \
                         ' LLIL_STORE.b(LLIL_REG.q(x25),LLIL_REG.b(b6))'), # str b6, [x25, #11]!
    (b'\x8A\xED\x0E\x3C', 'LLIL_SET_REG.q(x12,LLIL_ADD.q(LLIL_REG.q(x12),LLIL_CONST.q(0xEE)));' + \
                         ' LLIL_STORE.b(LLIL_REG.q(x12),LLIL_REG.b(b10))'), # str b10, [x12, #238]!
    # STR_H_ldst_immpre 01111100000xxxxxxxxx11xxxxxxxxxx
    (b'\xFA\xBC\x03\x7C', 'LLIL_SET_REG.q(x7,LLIL_ADD.q(LLIL_REG.q(x7),LLIL_CONST.q(0x3B)));' + \
                         ' LLIL_STORE.w(LLIL_REG.q(x7),LLIL_REG.w(h26))'), # str h26, [x7, #59]!
    (b'\xBE\x3E\x1E\x7C', 'LLIL_SET_REG.q(x21,LLIL_ADD.q(LLIL_REG.q(x21),LLIL_CONST.q(0xFFFFFFFFFFFFFFE3)));' + \
                         ' LLIL_STORE.w(LLIL_REG.q(x21),LLIL_REG.w(h30))'), # str h30, [x21, #-29]!
    # STR_S_ldst_immpre 10111100000xxxxxxxxx11xxxxxxxxxx
    (b'\xD6\x4E\x13\xBC', 'LLIL_SET_REG.q(x22,LLIL_ADD.q(LLIL_REG.q(x22),LLIL_CONST.q(0xFFFFFFFFFFFFFF34)));' + \
                         ' LLIL_STORE.d(LLIL_REG.q(x22),LLIL_REG.d(s22))'), # str s22, [x22, #-204]!
    (b'\xDC\xFF\x09\xBC', 'LLIL_SET_REG.q(x30,LLIL_ADD.q(LLIL_REG.q(x30),LLIL_CONST.q(0x9F)));' + \
                         ' LLIL_STORE.d(LLIL_REG.q(x30),LLIL_REG.d(s28))'), # str s28, [x30, #159]!
    # STR_D_ldst_immpre 11111100000xxxxxxxxx11xxxxxxxxxx
    (b'\x04\xEF\x1B\xFC', 'LLIL_SET_REG.q(x24,LLIL_ADD.q(LLIL_REG.q(x24),LLIL_CONST.q(0xFFFFFFFFFFFFFFBE)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x24),LLIL_REG.q(d4))'), # str d4, [x24, #-66]!
    (b'\x71\x6F\x1A\xFC', 'LLIL_SET_REG.q(x27,LLIL_ADD.q(LLIL_REG.q(x27),LLIL_CONST.q(0xFFFFFFFFFFFFFFA6)));' + \
                         ' LLIL_STORE.q(LLIL_REG.q(x27),LLIL_REG.q(d17))'), # str d17, [x27, #-90]!
    # STR_Q_ldst_immpre 00111100100xxxxxxxxx11xxxxxxxxxx
    (b'\x8B\x8D\x93\x3C', 'LLIL_SET_REG.q(x12,LLIL_ADD.q(LLIL_REG.q(x12),LLIL_CONST.q(0xFFFFFFFFFFFFFF38)));' + \
                         ' LLIL_STORE.o(LLIL_REG.q(x12),LLIL_REG.o(q11))'), # str q11, [x12, #-200]!
    (b'\x89\xBC\x80\x3C', 'LLIL_SET_REG.q(x4,LLIL_ADD.q(LLIL_REG.q(x4),LLIL_CONST.q(0xB)));' + \
                         ' LLIL_STORE.o(LLIL_REG.q(x4),LLIL_REG.o(q9))'), # str q9, [x4, #11]!
    # IFORM: STR_imm_fpsimd (class unsigned_scaled_offset)
    # STR_B_ldst_pos 0011110100xxxxxxxxxxxxxxxxxxxxxx
    (b'\x0B\xB2\x30\x3D', 'LLIL_STORE.b(LLIL_ADD.q(LLIL_REG.q(x16),LLIL_CONST.q(0xC2C)),LLIL_REG.b(b11))'), # str b11, [x16, #3116]
    (b'\x5B\xEE\x27\x3D', 'LLIL_STORE.b(LLIL_ADD.q(LLIL_REG.q(x18),LLIL_CONST.q(0x9FB)),LLIL_REG.b(b27))'), # str b27, [x18, #2555]
    # STR_H_ldst_pos 0111110100xxxxxxxxxxxxxxxxxxxxxx
    (b'\x28\x61\x39\x7D', 'LLIL_STORE.w(LLIL_ADD.q(LLIL_REG.q(x9),LLIL_CONST.q(0x1CB0)),LLIL_REG.w(h8))'), # str h8, [x9, #7344]
    (b'\x85\x98\x0C\x7D', 'LLIL_STORE.w(LLIL_ADD.q(LLIL_REG.q(x4),LLIL_CONST.q(0x64C)),LLIL_REG.w(h5))'), # str h5, [x4, #1612]
    # STR_S_ldst_pos 1011110100xxxxxxxxxxxxxxxxxxxxxx
    (b'\x92\xAE\x15\xBD', 'LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x20),LLIL_CONST.q(0x15AC)),LLIL_REG.d(s18))'), # str s18, [x20, #5548]
    (b'\xBF\xD7\x08\xBD', 'LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x29),LLIL_CONST.q(0x8D4)),LLIL_REG.d(s31))'), # str s31, [x29, #2260]
    # STR_D_ldst_pos 1111110100xxxxxxxxxxxxxxxxxxxxxx
    (b'\xF0\xC8\x34\xFD', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x7),LLIL_CONST.q(0x6990)),LLIL_REG.q(d16))'), # str d16, [x7, #27024]
    (b'\xBF\x6F\x17\xFD', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x29),LLIL_CONST.q(0x2ED8)),LLIL_REG.q(d31))'), # str d31, [x29, #11992]
    # STR_Q_ldst_pos 0011110110xxxxxxxxxxxxxxxxxxxxxx
    (b'\x70\x26\x93\x3D', 'LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x19),LLIL_CONST.q(0x4C90)),LLIL_REG.o(q16))'), # str q16, [x19, #19600]
    (b'\xE8\xB0\x88\x3D', 'LLIL_STORE.o(LLIL_ADD.q(LLIL_REG.q(x7),LLIL_CONST.q(0x22C0)),LLIL_REG.o(q8))'), # str q8, [x7, #8896]
    # IFORM: str_p_bi
    # str_p_bi_ 1110010110xxxxxx000xxxxxxxx0xxxx
    #(b'\xA6\x12\xB0\xE5', 'LLIL_UNDEF()'), # str p6, [x21, #-124, mul vl]
    #(b'\x0F\x12\x84\xE5', 'LLIL_UNDEF()'), # str p15, [x16, #36, mul vl]
    # IFORM: str_z_bi
    # str_z_bi_ 1110010110xxxxxx01xxxxxxxxxxxxxx
    #(b'\x11\x55\x89\xE5', 'LLIL_UNDEF()'), # str z17, [x8, #77, mul vl]
    #(b'\x4E\x43\x9B\xE5', 'LLIL_UNDEF()'), # str z14, [x26, #216, mul vl]
    # signed bitfield insert zeros, lsb is position in DESTINATION register (position 0 in source)
    # strategy: LSL extracted field to the most significant end, then ASR it back
    (b'\x20\x00\x40\x93', 'LLIL_SET_REG.q(x0,LLIL_ASR.q(LLIL_LSL.q(LLIL_AND.q(LLIL_REG.q(x1),LLIL_CONST.q(0x1)),LLIL_CONST.b(0x3F)),LLIL_CONST.b(0x3F)))'), # sbfiz x0, x1, #0, #1
    (b'\x20\x00\x7F\x93', 'LLIL_SET_REG.q(x0,LLIL_ASR.q(LLIL_LSL.q(LLIL_AND.q(LLIL_REG.q(x1),LLIL_CONST.q(0x1)),LLIL_CONST.b(0x3F)),LLIL_CONST.b(0x3E)))'), # sbfiz x0, x1, #1, #1
    (b'\x20\xFC\x40\x93', 'LLIL_SET_REG.q(x0,LLIL_ASR.q(LLIL_REG.q(x1),LLIL_CONST.q(0x0)))'), # sbfiz x0, x1, #0, #64
    # signed bitfield extract, lsb is position in SOURCE register (position 0 in destination)
    (b'\x20\x00\x40\x93', 'LLIL_SET_REG.q(x0,LLIL_ASR.q(LLIL_LSL.q(LLIL_AND.q(LLIL_REG.q(x1),LLIL_CONST.q(0x1)),LLIL_CONST.b(0x3F)),LLIL_CONST.b(0x3F)))'), # sbfx x0, x1, #0, #1
    (b'\x20\x04\x41\x93', 'LLIL_SET_REG.q(x0,LLIL_ASR.q(LLIL_LSL.q(LLIL_AND.q(LLIL_REG.q(x1),LLIL_CONST.q(0x2)),LLIL_CONST.b(0x3E)),LLIL_CONST.b(0x3F)))'), # sbfx x0, x1, #1, #1
    (b'\x20\xFC\x40\x93', 'LLIL_SET_REG.q(x0,LLIL_ASR.q(LLIL_REG.q(x1),LLIL_CONST.q(0x0)))'), # sbfx x0, x1, #0, #64
    # unsigned bitfield insert zeros, lsb is position in DESTINATION register (position 0 in source)
    # should be same as sbfiz, but logical (LSR) instead of arithmetic (ASR)
    (b'\x20\x00\x40\xD3', 'LLIL_SET_REG.q(x0,LLIL_ZX.q(LLIL_AND.q(LLIL_LSR.q(LLIL_REG.q(x1),LLIL_CONST.b(0x0)),LLIL_CONST.q(0x1))))'), # ubfiz x0, x1, #0, #1
    (b'\x20\x00\x7F\xD3', 'LLIL_SET_REG.q(x0,LLIL_ZX.q(LLIL_LSL.q(LLIL_AND.q(LLIL_REG.q(x1),LLIL_CONST.q(0x1)),LLIL_CONST.b(0x1))))'), # ubfiz x0, x1, #1, #1
    (b'\x20\x04\x40\xD3', 'LLIL_SET_REG.q(x0,LLIL_ZX.q(LLIL_AND.q(LLIL_LSR.q(LLIL_REG.q(x1),LLIL_CONST.b(0x0)),LLIL_CONST.q(0x3))))'), # ubfiz x0, x1, #0, #2
    (b'\x20\x08\x40\xD3', 'LLIL_SET_REG.q(x0,LLIL_ZX.q(LLIL_AND.q(LLIL_LSR.q(LLIL_REG.q(x1),LLIL_CONST.b(0x0)),LLIL_CONST.q(0x7))))'), # ubfiz x0, x1, #0, #3
    (b'\x20\xF8\x40\xD3', 'LLIL_SET_REG.q(x0,LLIL_ZX.q(LLIL_AND.q(LLIL_LSR.q(LLIL_REG.q(x1),LLIL_CONST.b(0x0)),LLIL_CONST.q(0x7FFFFFFFFFFFFFFF))))'), # ubfiz x0, x1, #0, #63
    # ADDS_32S_addsub_ext
    # note: since the shift amount is 0, no LLIL_LSL need be generated
    (b'\x55\x01\x2B\x2B', 'LLIL_SET_REG.d(w21,LLIL_ADD.d{*}(LLIL_REG.d(w10),LLIL_ZX.d(LLIL_LOW_PART.b(LLIL_REG.d(w11)))))'), # adds w21, w10, w11, uxtb
    (b'\xC5\xF2\x24\x2B', 'LLIL_SET_REG.d(w5,LLIL_ADD.d{*}(LLIL_REG.d(w22),LLIL_LSL.d(LLIL_SX.d(LLIL_REG.d(w4)),LLIL_CONST.b(0x4))))'), # adds w5, w22, w4, sxtx #4
    (b'\x11\x29\x35\x2B', 'LLIL_SET_REG.d(w17,LLIL_ADD.d{*}(LLIL_REG.d(w8),LLIL_LSL.d(LLIL_ZX.d(LLIL_LOW_PART.w(LLIL_REG.d(w21))),LLIL_CONST.b(0x2))))'), # adds w17, w8, w21, uxth #2
    (b'\x7E\x31\x3B\x2B', 'LLIL_SET_REG.d(w30,LLIL_ADD.d{*}(LLIL_REG.d(w11),LLIL_LSL.d(LLIL_ZX.d(LLIL_LOW_PART.w(LLIL_REG.d(w27))),LLIL_CONST.b(0x4))))'), # adds w30, w11, w27, uxth #4
    # ADDS_64S_addsub_ext
    (b'\x13\x06\x22\xAB', 'LLIL_SET_REG.q(x19,LLIL_ADD.q{*}(LLIL_REG.q(x16),LLIL_LSL.q(LLIL_ZX.q(LLIL_LOW_PART.b(LLIL_REG.d(w2))),LLIL_CONST.b(0x1))))'), # adds x19, x16, w2, uxtb #1
    (b'\xEF\x06\x21\xAB', 'LLIL_SET_REG.q(x15,LLIL_ADD.q{*}(LLIL_REG.q(x23),LLIL_LSL.q(LLIL_ZX.q(LLIL_LOW_PART.b(LLIL_REG.d(w1))),LLIL_CONST.b(0x1))))'), # adds x15, x23, w1, uxtb #1
    (b'\xFA\xA5\x32\xAB', 'LLIL_SET_REG.q(x26,LLIL_ADD.q{*}(LLIL_REG.q(x15),LLIL_LSL.q(LLIL_SX.q(LLIL_LOW_PART.w(LLIL_REG.d(w18))),LLIL_CONST.b(0x1))))'), # adds x26, x15, w18, sxth #1
    (b'\x00\x04\x20\xAB', 'LLIL_SET_REG.q(x0,LLIL_ADD.q{*}(LLIL_REG.q(x0),LLIL_LSL.q(LLIL_ZX.q(LLIL_LOW_PART.b(LLIL_REG.d(w0))),LLIL_CONST.b(0x1))))'), # adds x0, x0, w0, uxtb #0x1
    # note: if size(reg) == size(extend) then no extend (like LLIL_ZX) is needed
    (b'\x25\x6D\x2A\xAB', 'LLIL_SET_REG.q(x5,LLIL_ADD.q{*}(LLIL_REG.q(x9),LLIL_LSL.q(LLIL_REG.q(x10),LLIL_CONST.b(0x3))))'), # adds x5, x9, x10, uxtx #3
    # ADD_32_addsub_ext
    (b'\xB0\x2F\x28\x0B', 'LLIL_SET_REG.d(w16,LLIL_ADD.d(LLIL_REG.d(w29),LLIL_LSL.d(LLIL_ZX.d(LLIL_LOW_PART.w(LLIL_REG.d(w8))),LLIL_CONST.b(0x3))))'), # add w16, w29, w8, uxth #3
    (b'\x4D\x73\x2B\x0B', 'LLIL_SET_REG.d(w13,LLIL_ADD.d(LLIL_REG.d(w26),LLIL_LSL.d(LLIL_ZX.d(LLIL_REG.d(w11)),LLIL_CONST.b(0x4))))'), # add w13, w26, w11, uxtx #4
    (b'\x07\xEE\x2E\x0B', 'LLIL_SET_REG.d(w7,LLIL_ADD.d(LLIL_REG.d(w16),LLIL_LSL.d(LLIL_SX.d(LLIL_REG.d(w14)),LLIL_CONST.b(0x3))))'), # add w7, w16, w14, sxtx #3
    (b'\x28\x63\x31\x0B', 'LLIL_SET_REG.d(w8,LLIL_ADD.d(LLIL_REG.d(w25),LLIL_ZX.d(LLIL_REG.d(w17))))'), # add w8, w25, w17, uxtx
    # ADD_64_addsub_ext
    (b'\xD2\xE8\x2B\x8B', 'LLIL_SET_REG.q(x18,LLIL_ADD.q(LLIL_REG.q(x6),LLIL_LSL.q(LLIL_REG.q(x11),LLIL_CONST.b(0x2))))'), # add x18, x6, x11, sxtx #2
    (b'\x5D\xC4\x2B\x8B', 'LLIL_SET_REG.q(x29,LLIL_ADD.q(LLIL_REG.q(x2),LLIL_LSL.q(LLIL_SX.q(LLIL_REG.d(w11)),LLIL_CONST.b(0x1))))'), # add x29, x2, w11, sxtw #1
    (b'\x82\x49\x31\x8B', 'LLIL_SET_REG.q(x2,LLIL_ADD.q(LLIL_REG.q(x12),LLIL_LSL.q(LLIL_ZX.q(LLIL_REG.d(w17)),LLIL_CONST.b(0x2))))'), # add x2, x12, w17, uxtw #2
    (b'\xFF\xA5\x2C\x8B', 'LLIL_SET_REG.q(sp,LLIL_ADD.q(LLIL_REG.q(x15),LLIL_LSL.q(LLIL_SX.q(LLIL_LOW_PART.w(LLIL_REG.d(w12))),LLIL_CONST.b(0x1))))'), # add sp, x15, w12, sxth #1
    # CMN_ADDS_32S_addsub_ext
    # Compare Negative (extended register) adds a register value and a sign or zero-extended register value, followed by an optional left shift amount.
    (b'\x7F\x8F\x2E\x2B', 'LLIL_ADD.d{*}(LLIL_REG.d(w27),LLIL_LSL.d(LLIL_SX.d(LLIL_LOW_PART.b(LLIL_REG.d(w14))),LLIL_CONST.b(0x3)))'), # cmn w27, w14, sxtb #3
    (b'\x3F\x8E\x3E\x2B', 'LLIL_ADD.d{*}(LLIL_REG.d(w17),LLIL_LSL.d(LLIL_SX.d(LLIL_LOW_PART.b(LLIL_REG.d(w30))),LLIL_CONST.b(0x3)))'), # cmn w17, w30, sxtb #3
    (b'\x3F\x83\x3D\x2B', 'LLIL_ADD.d{*}(LLIL_REG.d(w25),LLIL_SX.d(LLIL_LOW_PART.b(LLIL_REG.d(w29))))'), # cmn w25, w29, sxtb
    (b'\x7F\x0F\x25\x2B', 'LLIL_ADD.d{*}(LLIL_REG.d(w27),LLIL_LSL.d(LLIL_ZX.d(LLIL_LOW_PART.b(LLIL_REG.d(w5))),LLIL_CONST.b(0x3)))'), # cmn w27, w5, uxtb #3
    # CMN_ADDS_64S_addsub_ext
    (b'\xBF\x0D\x2D\xAB', 'LLIL_ADD.q{*}(LLIL_REG.q(x13),LLIL_LSL.q(LLIL_ZX.q(LLIL_LOW_PART.b(LLIL_REG.d(w13))),LLIL_CONST.b(0x3)))'), # cmn x13, w13, uxtb #3
    (b'\x3F\x65\x22\xAB', 'LLIL_ADD.q{*}(LLIL_REG.q(x9),LLIL_LSL.q(LLIL_REG.q(x2),LLIL_CONST.b(0x1)))'), # cmn x9, x2, uxtx #1
    # does the add to 0 get optimized out?
    (b'\xDF\xA8\x3F\xAB', 'LLIL_ADD.q{*}(LLIL_REG.q(x6),LLIL_CONST.q(0x0))'), # cmn x6, wzr, sxth #2
    (b'\x3F\x8B\x3E\xAB', 'LLIL_ADD.q{*}(LLIL_REG.q(x25),LLIL_LSL.q(LLIL_SX.q(LLIL_LOW_PART.b(LLIL_REG.d(w30))),LLIL_CONST.b(0x2)))'), # cmn x25, w30, sxtb #2
    # CMP_SUBS_32S_addsub_ext
    (b'\x1F\x2B\x2D\x6B', 'LLIL_SUB.d{*}(LLIL_REG.d(w24),LLIL_LSL.d(LLIL_ZX.d(LLIL_LOW_PART.w(LLIL_REG.d(w13))),LLIL_CONST.b(0x2)))'), # cmp w24, w13, uxth #2
    (b'\xBF\x51\x23\x6B', 'LLIL_SUB.d{*}(LLIL_REG.d(w13),LLIL_LSL.d(LLIL_REG.d(w3),LLIL_CONST.b(0x4)))'), # cmp w13, w3, uxtw #4
    (b'\x1F\xD0\x31\x6B', 'LLIL_SUB.d{*}(LLIL_REG.d(w0),LLIL_LSL.d(LLIL_REG.d(w17),LLIL_CONST.b(0x4)))'), # cmp w0, w17, sxtw #4
    (b'\xBF\x53\x3E\x6B', 'LLIL_SUB.d{*}(LLIL_REG.d(w29),LLIL_LSL.d(LLIL_REG.d(w30),LLIL_CONST.b(0x4)))'), # cmp w29, w30, uxtw #4
    # CMP_SUBS_64S_addsub_ext
    (b'\x3F\x49\x22\xEB', 'LLIL_SUB.q{*}(LLIL_REG.q(x9),LLIL_LSL.q(LLIL_ZX.q(LLIL_REG.d(w2)),LLIL_CONST.b(0x2)))'), # cmp x9, w2, uxtw #2
    (b'\xDF\x93\x31\xEB', 'LLIL_SUB.q{*}(LLIL_REG.q(x30),LLIL_LSL.q(LLIL_SX.q(LLIL_LOW_PART.b(LLIL_REG.d(w17))),LLIL_CONST.b(0x4)))'), # cmp x30, w17, sxtb #4
    (b'\x7F\x87\x27\xEB', 'LLIL_SUB.q{*}(LLIL_REG.q(x27),LLIL_LSL.q(LLIL_SX.q(LLIL_LOW_PART.b(LLIL_REG.d(w7))),LLIL_CONST.b(0x1)))'), # cmp x27, w7, sxtb #1
    (b'\x9F\xEC\x34\xEB', 'LLIL_SUB.q{*}(LLIL_REG.q(x4),LLIL_LSL.q(LLIL_REG.q(x20),LLIL_CONST.b(0x3)))'), # cmp x4, x20, sxtx #3
    # SUBS_32S_addsub_ext
    (b'\xCD\xC9\x38\x6B', 'LLIL_SET_REG.d(w13,LLIL_SUB.d{*}(LLIL_REG.d(w14),LLIL_LSL.d(LLIL_REG.d(w24),LLIL_CONST.b(0x2))))'), # subs w13, w14, w24, sxtw #2
    (b'\x72\xF0\x2B\x6B', 'LLIL_SET_REG.d(w18,LLIL_SUB.d{*}(LLIL_REG.d(w3),LLIL_LSL.d(LLIL_SX.d(LLIL_REG.d(w11)),LLIL_CONST.b(0x4))))'), # subs w18, w3, w11, sxtx #4
    (b'\x77\xC1\x23\x6B', 'LLIL_SET_REG.d(w23,LLIL_SUB.d{*}(LLIL_REG.d(w11),LLIL_REG.d(w3)))'), # subs w23, w11, w3, sxtw
    (b'\xD4\x47\x3F\x6B', 'LLIL_SET_REG.d(w20,LLIL_SUB.d{*}(LLIL_REG.d(w30),LLIL_CONST.d(0x0)))'), # subs w20, w30, wzr, uxtw #1
    # SUBS_64S_addsub_ext
    (b'\x26\x44\x3C\xEB', 'LLIL_SET_REG.q(x6,LLIL_SUB.q{*}(LLIL_REG.q(x1),LLIL_LSL.q(LLIL_ZX.q(LLIL_REG.d(w28)),LLIL_CONST.b(0x1))))'), # subs x6, x1, w28, uxtw #1
    (b'\x8A\xE2\x2E\xEB', 'LLIL_SET_REG.q(x10,LLIL_SUB.q{*}(LLIL_REG.q(x20),LLIL_REG.q(x14)))'), # subs x10, x20, x14, sxtx
    (b'\xC2\x4B\x3A\xEB', 'LLIL_SET_REG.q(x2,LLIL_SUB.q{*}(LLIL_REG.q(x30),LLIL_LSL.q(LLIL_ZX.q(LLIL_REG.d(w26)),LLIL_CONST.b(0x2))))'), # subs x2, x30, w26, uxtw #2
    (b'\x04\x4A\x20\xEB', 'LLIL_SET_REG.q(x4,LLIL_SUB.q{*}(LLIL_REG.q(x16),LLIL_LSL.q(LLIL_ZX.q(LLIL_REG.d(w0)),LLIL_CONST.b(0x2))))'), # subs x4, x16, w0, uxtw #2
    # SUB_32_addsub_ext
    (b'\x9E\x82\x2C\x4B', 'LLIL_SET_REG.d(w30,LLIL_SUB.d(LLIL_REG.d(w20),LLIL_SX.d(LLIL_LOW_PART.b(LLIL_REG.d(w12)))))'), # sub w30, w20, w12, sxtb
    (b'\xB9\x42\x32\x4B', 'LLIL_SET_REG.d(w25,LLIL_SUB.d(LLIL_REG.d(w21),LLIL_REG.d(w18)))'), # sub w25, w21, w18, uxtw
    (b'\xD9\x66\x3C\x4B', 'LLIL_SET_REG.d(w25,LLIL_SUB.d(LLIL_REG.d(w22),LLIL_LSL.d(LLIL_ZX.d(LLIL_REG.d(w28)),LLIL_CONST.b(0x1))))'), # sub w25, w22, w28, uxtx #1
    (b'\xCD\x4F\x22\x4B', 'LLIL_SET_REG.d(w13,LLIL_SUB.d(LLIL_REG.d(w30),LLIL_LSL.d(LLIL_REG.d(w2),LLIL_CONST.b(0x3))))'), # sub w13, w30, w2, uxtw #3
    # SUB_64_addsub_ext
    (b'\xF7\x8D\x3F\xCB', 'LLIL_SET_REG.q(x23,LLIL_SUB.q(LLIL_REG.q(x15),LLIL_CONST.q(0x0)))'), # sub x23, x15, wzr, sxtb #3
    (b'\xFF\x64\x27\xCB', 'LLIL_SET_REG.q(sp,LLIL_SUB.q(LLIL_REG.q(x7),LLIL_LSL.q(LLIL_REG.q(x7),LLIL_CONST.b(0x1))))'), # sub sp, x7, x7, lsl #1
    (b'\xA5\x23\x23\xCB', 'LLIL_SET_REG.q(x5,LLIL_SUB.q(LLIL_REG.q(x29),LLIL_ZX.q(LLIL_LOW_PART.w(LLIL_REG.d(w3)))))'), # sub x5, x29, w3, uxth
    (b'\xA4\x69\x37\xCB', 'LLIL_SET_REG.q(x4,LLIL_SUB.q(LLIL_REG.q(x13),LLIL_LSL.q(LLIL_REG.q(x23),LLIL_CONST.b(0x2))))'), # sub x4, x13, x23, uxtx #2
    (b'\x21\xF0\x9F\xF8', 'LLIL_INTRINSIC([],__prefetch,[LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x1),LLIL_CONST.q(0xFFFFFFFFFFFFFFFF)))])'), # prfum pldl1strm, [x1, #-0x1]
    (b'\x21\x00\x80\xF9', 'LLIL_INTRINSIC([],__prefetch,[LLIL_LOAD.q(LLIL_REG.q(x1))])'), # prfm pldl1strm, [x1]
    (b'\x24\x98\x41\xBA', 'LLIL_IF(LLIL_FLAG_GROUP(ls),1,3);' + \
                         ' LLIL_ADD.q{*}(LLIL_REG.q(x1),LLIL_CONST.q(0x1));' + \
                         ' LLIL_GOTO(8);' + \
                         ' LLIL_SET_FLAG(n,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(z,LLIL_CONST(1));' + \
                         ' LLIL_SET_FLAG(c,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(v,LLIL_CONST(0));' + \
                         ' LLIL_GOTO(8)'), # ccmn x1, #0x1, #0x4, ls
    (b'\x41\x7C\xC3\x9B', 'LLIL_SET_REG.q(x1,LLIL_LOW_PART.q(LLIL_LSR.o(LLIL_MULU_DP.q(LLIL_REG.q(x2),LLIL_REG.q(x3)),LLIL_CONST.b(0x40))))'), # umulh x1, x2, x3
    (b'\x41\x7C\x43\x9B', 'LLIL_SET_REG.q(x1,LLIL_LOW_PART.q(LLIL_LSR.o(LLIL_MULS_DP.q(LLIL_REG.q(x2),LLIL_REG.q(x3)),LLIL_CONST.b(0x40))))'), # smulh x1, x2, x3
    (b'\x41\x7C\x23\x9B', 'LLIL_SET_REG.q(x1,LLIL_MULS_DP.q(LLIL_REG.d(w2),LLIL_REG.d(w3)))'), # smull x1, w2, w3
    (b'\x41\x7C\xA3\x9B', 'LLIL_SET_REG.q(x1,LLIL_MULU_DP.q(LLIL_REG.d(w2),LLIL_REG.d(w3)))'), # umull x1, w2, w3
    (b'\x41\x00\x03\x8B', 'LLIL_SET_REG.q(x1,LLIL_ADD.q(LLIL_REG.q(x2),LLIL_REG.q(x3)))'), # add x1,x2,x3
    (b'\x41\x00\x03\xAB', 'LLIL_SET_REG.q(x1,LLIL_ADD.q{*}(LLIL_REG.q(x2),LLIL_REG.q(x3)))'), # adds x1,x2,x3 with IL_FLAGWRITE_ALL
    (b'\x41\x00\x03\x8A', 'LLIL_SET_REG.q(x1,LLIL_AND.q(LLIL_REG.q(x2),LLIL_REG.q(x3)))'), # and x1,x2,x3
    (b'\x41\x00\x03\xEA', 'LLIL_SET_REG.q(x1,LLIL_AND.q{*}(LLIL_REG.q(x2),LLIL_REG.q(x3)))'), # ands x1,x2,x3 with IL_FLAGWRITE_ALL
    (b'\x41\x00\x03\xDA', 'LLIL_SET_REG.q(x1,LLIL_SBB.q(LLIL_REG.q(x2),LLIL_REG.q(x3),LLIL_NOT(LLIL_FLAG(c))))'), # sbc x1,x2,x3
    (b'\x41\x00\x03\xFA', 'LLIL_SET_REG.q(x1,LLIL_SBB.q{*}(LLIL_REG.q(x2),LLIL_REG.q(x3),LLIL_NOT(LLIL_FLAG(c))))'), # sbcs x1,x2,x3 with IL_FLAGWRITE_ALL
    (b'\xe9\x03\x1f\xfa', 'LLIL_SET_REG.q(x9,LLIL_SBB.q{*}(LLIL_CONST.q(0x0),LLIL_CONST.q(0x0),LLIL_NOT(LLIL_FLAG(c))))'), # ngcs    x9, xzr
    (b'\x01\x00\x00\xD4', 'LLIL_SET_REG.d(syscall_info,LLIL_CONST.d(0x40000000));' + \
                         ' LLIL_SYSCALL()'), # svc #0; ret; ZwAccessCheck() on win-arm64
    (b'\x21\x00\x00\xD4', 'LLIL_SET_REG.d(syscall_info,LLIL_CONST.d(0x40000001));' + \
                         ' LLIL_SYSCALL()'), # svc #1; ret; ZwWorkerFactoryWorkerReady() on win-arm64
    (b'\x41\x00\x00\xD4', 'LLIL_SET_REG.d(syscall_info,LLIL_CONST.d(0x40000002));' + \
                         ' LLIL_SYSCALL()'), # svc #2; ret; ZwAcceptConnectPort() on win-arm64
    (b'\x61\x00\x00\xD4', 'LLIL_SET_REG.d(syscall_info,LLIL_CONST.d(0x40000003));' + \
                         ' LLIL_SYSCALL()'), # svc #3; ret; ZwMapUserPhysicalPagesScatter() on win-arm64
    (b'\xBF\x3F\x03\xD5', 'LLIL_INTRINSIC([],__dmb,[])'), # dmb sy (data memory barrier, system)
    (b'\xBF\x3E\x03\xD5', 'LLIL_INTRINSIC([],__dmb,[])'), # dmb st (data memory barrier, stores)
    (b'\xBF\x3A\x03\xD5', 'LLIL_INTRINSIC([],__dmb,[])'), # dmb ishst (data memory barrier, inner shareable domain)
    (b'\x9F\x3F\x03\xD5', 'LLIL_INTRINSIC([],__dsb,[])'), # dsb sy (data synchronization barrier, system)
    (b'\x9F\x3E\x03\xD5', 'LLIL_INTRINSIC([],__dsb,[])'), # dsb st (data synchronization barrier, stores)
    (b'\x9F\x3A\x03\xD5', 'LLIL_INTRINSIC([],__dsb,[])'), # dsb ishst (data synchronization barrier, inner shareable domain)
    (b'\xDF\x3F\x03\xD5', 'LLIL_INTRINSIC([],__isb,[])'), # isb (instruction synchronization barrier, implied system)
    (b'\x3F\x20\x03\xD5', 'LLIL_INTRINSIC([],__yield,[])'), # "yield" or "hint 0x1"
    (b'\x5F\x20\x03\xD5', 'LLIL_INTRINSIC([],__wfe,[])'), # "wfe" or "hint 0x2"
    (b'\x7F\x20\x03\xD5', 'LLIL_INTRINSIC([],__wfi,[])'), # "wfi" or "hint 0x3"
    (b'\x9F\x20\x03\xD5', 'LLIL_INTRINSIC([],__sev,[])'), # "hint 0x4" or "sev"
    (b'\xBF\x20\x03\xD5', 'LLIL_INTRINSIC([],__sevl,[])'), # "hint 0x5" or "sevl"
    #(b'\xdf\x20\x03\xd5', 'LLIL_INTRINSIC([],SystemHintOp_DGH,[])'), # hint 0x6 - now ARM64_DGH
    #(b'\x1f\x22\x03\xd5', 'LLIL_INTRINSIC([],SystemHintOp_ESB,[])'), # hint 0x10 - now ARM64_ESB
    #(b'\x3f\x22\x03\xd5', 'LLIL_INTRINSIC([],SystemHintOp_PSB,[])'), # hint 0x11 - now ARM64_PSB
    #(b'\x5f\x22\x03\xd5', 'LLIL_INTRINSIC([],SystemHintOp_TSB,[])'), # hint 0x12 - now ARM64_TSB
    #(b'\x9f\x22\x03\xd5', 'LLIL_INTRINSIC([],SystemHintOp_CSDB,[])'), # hint 0x14 - now ARM64_CSDB
    #(b'\x5f\x24\x03\xd5', 'LLIL_INTRINSIC([],SystemHintOp_BTI,[])'), # hint 0x22 - now ARM64_BTI
    (b'\x00\xC0\x1E\xD5', 'LLIL_INTRINSIC([vbar_el3],_WriteStatusReg,[LLIL_REG.q(x0)])'), # msr vbar_el3, x0
    (b'\x00\x10\x1E\xD5', 'LLIL_INTRINSIC([sctlr_el3],_WriteStatusReg,[LLIL_REG.q(x0)])'), # msr sctlr_el3, x0
#    (b'\xff\x44\x03\xd5', 'LLIL_INTRINSIC([daifclr],_WriteStatusReg,[LLIL_CONST.d(0x4)])'), # msr daifclr, #0x4
    (b'\x00\x10\x3E\xD5', 'LLIL_INTRINSIC([x0],_ReadStatusReg,[LLIL_REG(sctlr_el3)])'), # mrs x0, sctlr_el3
    (b'\xC1\x48\x52\x7A', 'LLIL_IF(LLIL_FLAG_GROUP(mi),1,3);' + \
                         ' LLIL_SUB.d{*}(LLIL_REG.d(w6),LLIL_CONST.d(0x12));' + \
                         ' LLIL_GOTO(8);' + \
                         ' LLIL_SET_FLAG(n,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(z,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(c,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(v,LLIL_CONST(1));' + \
                         ' LLIL_GOTO(8)'), # ccmp w6, #18, #1, mi
    (b'\x62\x08\x40\x7A', 'LLIL_IF(LLIL_FLAG_GROUP(eq),1,3);' + \
                         ' LLIL_SUB.d{*}(LLIL_REG.d(w3),LLIL_CONST.d(0x0));' + \
                         ' LLIL_GOTO(8);' + \
                         ' LLIL_SET_FLAG(n,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(z,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(c,LLIL_CONST(1));' + \
                         ' LLIL_SET_FLAG(v,LLIL_CONST(0));' + \
                         ' LLIL_GOTO(8)'), # ccmp w3, #0, #2, eq
    (b'\x43\xBA\x59\x7A', 'LLIL_IF(LLIL_FLAG_GROUP(lt),1,3);' + \
                         ' LLIL_SUB.d{*}(LLIL_REG.d(w18),LLIL_CONST.d(0x19));' + \
                         ' LLIL_GOTO(8);' + \
                         ' LLIL_SET_FLAG(n,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(z,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(c,LLIL_CONST(1));' + \
                         ' LLIL_SET_FLAG(v,LLIL_CONST(1));' + \
                         ' LLIL_GOTO(8)'), # ccmp w18, #25, #3, lt
    (b'\xC4\x29\x5B\x7A', 'LLIL_IF(LLIL_FLAG_GROUP(cs),1,3);' + \
                         ' LLIL_SUB.d{*}(LLIL_REG.d(w14),LLIL_CONST.d(0x1B));' + \
                         ' LLIL_GOTO(8);' + \
                         ' LLIL_SET_FLAG(n,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(z,LLIL_CONST(1));' + \
                         ' LLIL_SET_FLAG(c,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(v,LLIL_CONST(0));' + \
                         ' LLIL_GOTO(8)'), # ccmp w14, #27, #4, hs
    (b'\x24\x08\x5B\x7A', 'LLIL_IF(LLIL_FLAG_GROUP(eq),1,3);' + \
                         ' LLIL_SUB.d{*}(LLIL_REG.d(w1),LLIL_CONST.d(0x1B));' + \
                         ' LLIL_GOTO(8);' + \
                         ' LLIL_SET_FLAG(n,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(z,LLIL_CONST(1));' + \
                         ' LLIL_SET_FLAG(c,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(v,LLIL_CONST(0));' + \
                         ' LLIL_GOTO(8)'), # ccmp w1, #27, #4, eq
    (b'\x22\x6A\x41\x7A', 'LLIL_IF(LLIL_FLAG_GROUP(vs),1,3);' + \
                         ' LLIL_SUB.d{*}(LLIL_REG.d(w17),LLIL_CONST.d(0x1));' + \
                         ' LLIL_GOTO(8);' + \
                         ' LLIL_SET_FLAG(n,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(z,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(c,LLIL_CONST(1));' + \
                         ' LLIL_SET_FLAG(v,LLIL_CONST(0));' + \
                         ' LLIL_GOTO(8)'), # ccmp w17, #1, #2, vs
    (b'\xA8\xA8\x41\x7A', 'LLIL_IF(LLIL_FLAG_GROUP(ge),1,3);' + \
                         ' LLIL_SUB.d{*}(LLIL_REG.d(w5),LLIL_CONST.d(0x1));' + \
                         ' LLIL_GOTO(8);' + \
                         ' LLIL_SET_FLAG(n,LLIL_CONST(1));' + \
                         ' LLIL_SET_FLAG(z,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(c,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(v,LLIL_CONST(0));' + \
                         ' LLIL_GOTO(8)'), # ccmp w5, #1, #8, ge
    (b'\x08\x49\x5E\x7A', 'LLIL_IF(LLIL_FLAG_GROUP(mi),1,3);' + \
                         ' LLIL_SUB.d{*}(LLIL_REG.d(w8),LLIL_CONST.d(0x1E));' + \
                         ' LLIL_GOTO(8);' + \
                         ' LLIL_SET_FLAG(n,LLIL_CONST(1));' + \
                         ' LLIL_SET_FLAG(z,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(c,LLIL_CONST(0));' + \
                         ' LLIL_SET_FLAG(v,LLIL_CONST(0));' + \
                         ' LLIL_GOTO(8)'), # ccmp w8, #30, #8, mi
    (b'\x1F\x20\x03\xD5', 'LLIL_NOP()'), # nop, gets optimized from function
]

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
def lift(data):
    EPILOG = b'\xa0\xd5\x9b\xd2' + b'\xc0\x03\x5f\xd6' # mov x0, 0xDEAD; return

    platform = binaryninja.Platform['linux-aarch64']
    # make a pretend function that returns
    bv = binaryview.BinaryView.new(data + EPILOG)
    bv.add_function(0, plat=platform)
    assert len(bv.functions) == 1

    tokens = []
    attributes = set()
    #for block in bv.functions[0].low_level_il:
    for block in bv.functions[0].lifted_il:
        for il in block:
            attributes = attributes.union(il.attributes)
            tokens.append(il2str(il))
    il_str = '; '.join(tokens)

    try:
        i = il_str.rindex('; LLIL_SET_REG.q(x0,LLIL_CONST.q(0xDEAD))')
        il_str = il_str[0:i]
    except:
        # ValueError: substring not found
        pass

    return il_str, attributes

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

def test_all_lifts():
    for test_i, test_info in enumerate(test_cases):
        if (test_i+1) % 25 == 0:
            print(f'on test {test_i+1}/{len(test_cases)}')

        data, expected_lift = test_info[0], test_info[1]
        il_attrs = test_info[2] if len(test_info) == 3 else None

        actual_lift, actual_attrs = lift(data)
        if actual_lift != expected_lift:
            print('LIFT MISMATCH AT TEST %d!' % test_i)
            print('\t   input: %s' % data.hex())
            print('\texpected: %s' % expected_lift)
            print('\t  actual: %s' % actual_lift)
            print('\t    tree:')
            print(il_str_to_tree(actual_lift))
            return False

        # if IL attributes given, verify those too
        if len(test_info) == 3:
            expected_attr = test_info[2]
            if not expected_attr in actual_attrs:
                print('ATTR MISMATCH AT TEST %d!' % test_i)
                print('\t   input: %s' % data.hex())
                print('\texpected: 0x%X' % expected_attr)
                print('\t  actual: ' + str(actual_attrs))
                return False

    return True

if __name__ == '__main__':
    if test_all_lifts():
        print('success!')
        sys.exit(0)
    else:
        sys.exit(-1)

if __name__ == 'arm64test':
    if test_all_lifts():
        print('success!')
