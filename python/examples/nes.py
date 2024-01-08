# Copyright (c) 2015-2024 Vector 35 Inc
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

import struct
import traceback
import os
from typing import Callable, List, Type, Optional, Dict, Tuple, NewType

from binaryninja.architecture import Architecture, InstructionInfo, RegisterInfo, RegisterName, FlagName, FlagWriteTypeName, FlagType
from binaryninja.lowlevelil import LowLevelILLabel, LLIL_TEMP, ExpressionIndex, LowLevelILFunction, ILRegisterType, LowLevelILConst, LowLevelILInstruction
from binaryninja.function import InstructionTextToken
from binaryninja.binaryview import BinaryView
from binaryninja.types import Symbol
from binaryninja.log import log_error
from binaryninja.enums import (
  BranchType, InstructionTextTokenType, LowLevelILOperation, LowLevelILFlagCondition, FlagRole, SegmentFlag, SymbolType
)

Mnemonic = NewType('Mnemonic', str)
Operand = NewType('Operand', int)

NONE        = Operand(0)
ABS         = Operand(1)
ABS_DEST    = Operand(2)
ABS_X       = Operand(3)
ABS_X_DEST  = Operand(4)
ABS_Y       = Operand(5)
ABS_Y_DEST  = Operand(6)
ACCUM       = Operand(7)
ADDR        = Operand(8)
IMMED       = Operand(9)
IND         = Operand(10)
IND_X       = Operand(11)
IND_X_DEST  = Operand(12)
IND_Y       = Operand(13)
IND_Y_DEST  = Operand(14)
REL         = Operand(15)
ZERO        = Operand(16)
ZERO_DEST   = Operand(17)
ZERO_X      = Operand(18)
ZERO_X_DEST = Operand(19)
ZERO_Y      = Operand(20)
ZERO_Y_DEST = Operand(21)


x_reg = RegisterName("x")
y_reg = RegisterName("y")
a_reg = RegisterName("a")
s_reg = RegisterName("s")
c_flag = FlagName("c")
d_flag = FlagName("d")
i_flag = FlagName("i")
v_flag = FlagName("v")
s_flag = FlagName("s")
b_flag = FlagName("b")
z_flag = FlagName("z")


class M6502(Architecture):
	name = "6502"
	address_size = 2
	default_int_size = 1
	instr_alignment = 1
	max_instr_length = 3
	regs:Dict[RegisterName, RegisterInfo] = {
	  a_reg: RegisterInfo(a_reg, 1), x_reg: RegisterInfo(x_reg, 1),
	  y_reg: RegisterInfo(y_reg, 1), s_reg: RegisterInfo(s_reg, 1)
	}
	stack_pointer = "s"
	flags = [c_flag, z_flag, i_flag, d_flag, b_flag, v_flag, s_flag]
	flag_write_types = [FlagWriteTypeName("*"), FlagWriteTypeName("czs"), FlagWriteTypeName("zvs"),FlagWriteTypeName( "zs")]
	flag_roles = {
	  c_flag: FlagRole.SpecialFlagRole,  # Not a normal carry flag, subtract result is inverted
	  z_flag: FlagRole.ZeroFlagRole, v_flag: FlagRole.OverflowFlagRole, s_flag: FlagRole.NegativeSignFlagRole
	}
	flags_required_for_flag_condition = {
	  LowLevelILFlagCondition.LLFC_UGE: [c_flag], LowLevelILFlagCondition.LLFC_ULT: [c_flag],
	  LowLevelILFlagCondition.LLFC_E: [z_flag], LowLevelILFlagCondition.LLFC_NE: [z_flag],
	  LowLevelILFlagCondition.LLFC_NEG: [s_flag], LowLevelILFlagCondition.LLFC_POS: [s_flag]
	}
	flags_written_by_flag_write_type = {
	  "*": ["c", "z", "v", "s"], "czs": ["c", "z", "s"], "zvs": ["z", "v", "s"], "zs": ["z", "s"]
	}

	InstructionIL:Dict[Mnemonic, Callable[[LowLevelILFunction, Optional[ExpressionIndex]], Optional[ExpressionIndex]]] = {
		Mnemonic("adc"):lambda il, operand: il.set_reg(1, a_reg, il.add_carry(1, il.reg(1, a_reg), operand, il.flag(c_flag), flags=FlagName("*"))),
		Mnemonic("asl"):lambda il, operand: il.store(1, operand, il.shift_left(1, il.load(1, operand), il.const(1, 1), flags=FlagName("czs"))),
		Mnemonic("asl@"):lambda il, operand: il.set_reg(1, a_reg, il.shift_left(1, operand, il.const(1, 1), flags=FlagName("czs"))),
		Mnemonic("and"):lambda il, operand: il.set_reg(1, a_reg, il.and_expr(1, il.reg(1, a_reg), operand, flags=FlagName("zs"))),
		Mnemonic("bcc"):lambda il, operand: M6502.cond_branch(il, il.flag_condition(LowLevelILFlagCondition.LLFC_UGE), operand),
		Mnemonic("bcs"):lambda il, operand: M6502.cond_branch(il, il.flag_condition(LowLevelILFlagCondition.LLFC_ULT), operand),
		Mnemonic("beq"):lambda il, operand: M6502.cond_branch(il, il.flag_condition(LowLevelILFlagCondition.LLFC_E), operand),
		Mnemonic("bit"):lambda il, operand: il.and_expr(1, il.reg(1, a_reg), operand, flags=FlagName("czs")),
		Mnemonic("bmi"):lambda il, operand: M6502.cond_branch(il, il.flag_condition(LowLevelILFlagCondition.LLFC_NEG), operand),
		Mnemonic("bne"):lambda il, operand: M6502.cond_branch(il, il.flag_condition(LowLevelILFlagCondition.LLFC_NE), operand),
		Mnemonic("bpl"):lambda il, operand: M6502.cond_branch(il, il.flag_condition(LowLevelILFlagCondition.LLFC_POS), operand),
		Mnemonic("brk"):lambda il, operand: il.system_call(),
		Mnemonic("bvc"):lambda il, operand: M6502.cond_branch(il, il.not_expr(0, il.flag(v_flag)), operand),
		Mnemonic("bvs"):lambda il, operand: M6502.cond_branch(il, il.flag(v_flag), operand),
		Mnemonic("clc"):lambda il, operand: il.set_flag(c_flag, il.const(0, 0)),
		Mnemonic("cld"):lambda il, operand: il.set_flag(d_flag, il.const(0, 0)),
		Mnemonic("cli"):lambda il, operand: il.set_flag(i_flag, il.const(0, 0)),
		Mnemonic("clv"):lambda il, operand: il.set_flag(v_flag, il.const(0, 0)),
		Mnemonic("cmp"):lambda il, operand: il.sub(1, il.reg(1, a_reg), operand, flags=FlagName("czs")),
		Mnemonic("cpx"):lambda il, operand: il.sub(1, il.reg(1, x_reg), operand, flags=FlagName("czs")),
		Mnemonic("cpy"):lambda il, operand: il.sub(1, il.reg(1, y_reg), operand, flags=FlagName("czs")),
		Mnemonic("dec"):lambda il, operand: il.store(1, operand, il.sub(1, il.load(1, operand), il.const(1, 1), flags=FlagName("zs"))),
		Mnemonic("dex"):lambda il, operand: il.set_reg(1, x_reg, il.sub(1, il.reg(1, x_reg), il.const(1, 1), flags=FlagName("zs"))),
		Mnemonic("dey"):lambda il, operand: il.set_reg(1, y_reg, il.sub(1, il.reg(1, y_reg), il.const(1, 1), flags=FlagName("zs"))),
		Mnemonic("eor"):lambda il, operand: il.set_reg(1, a_reg, il.xor_expr(1, il.reg(1, a_reg), operand, flags=FlagName("zs"))),
		Mnemonic("inc"):lambda il, operand: il.store(1, operand, il.add(1, il.load(1, operand), il.const(1, 1), flags=FlagName("zs"))),
		Mnemonic("inx"):lambda il, operand: il.set_reg(1, x_reg, il.add(1, il.reg(1, x_reg), il.const(1, 1), flags=FlagName("zs"))),
		Mnemonic("iny"):lambda il, operand: il.set_reg(1, y_reg, il.add(1, il.reg(1, y_reg), il.const(1, 1), flags=FlagName("zs"))),
		Mnemonic("jmp"):lambda il, operand: M6502.jump(il, operand),
		Mnemonic("jsr"):lambda il, operand: il.call(operand),
		Mnemonic("lda"):lambda il, operand: il.set_reg(1, a_reg, operand, flags=FlagName("zs")),
		Mnemonic("ldx"):lambda il, operand: il.set_reg(1, x_reg, operand, flags=FlagName("zs")),
		Mnemonic("ldy"):lambda il, operand: il.set_reg(1, y_reg, operand, flags=FlagName("zs")),
		Mnemonic("lsr"):lambda il, operand: il.store(1, operand, il.logical_shift_right(1, il.load(1, operand), il.const(1, 1), flags=FlagName("czs"))),
		Mnemonic("lsr@"):lambda il, operand: il.set_reg(1, a_reg, il.logical_shift_right(1, il.reg(1, a_reg), il.const(1, 1), flags=FlagName("czs"))),
		Mnemonic("nop"):lambda il, operand: il.nop(),
		Mnemonic("ora"):lambda il, operand: il.set_reg(1, a_reg, il.or_expr(1, il.reg(1, a_reg), operand, flags=FlagName("zs"))),
		Mnemonic("pha"):lambda il, operand: il.push(1, il.reg(1, a_reg)),
		Mnemonic("php"):lambda il, operand: il.push(1, M6502.get_p_value(il)),
		Mnemonic("pla"):lambda il, operand: il.set_reg(1, a_reg, il.pop(1), flags=FlagName("zs")),
		Mnemonic("plp"):lambda il, operand: M6502.set_p_value(il, il.pop(1)),
		Mnemonic("rol"):lambda il, operand: il.store(1, operand, il.rotate_left_carry(1, il.load(1, operand), il.const(1, 1), il.flag(c_flag), flags=FlagName("czs"))),
		Mnemonic("rol@"):lambda il, operand: il.set_reg(1, a_reg, il.rotate_left_carry(1, il.reg(1, a_reg), il.const(1, 1), il.flag(c_flag), flags=FlagName("czs"))),
		Mnemonic("ror"):lambda il, operand: il.store(1, operand, il.rotate_right_carry(1, il.load(1, operand), il.const(1, 1), il.flag(c_flag), flags=FlagName("czs"))),
		Mnemonic("ror@"):lambda il, operand: il.set_reg(1, a_reg, il.rotate_right_carry(1, il.reg(1, a_reg), il.const(1, 1), il.flag(c_flag), flags=FlagName("czs"))),
		Mnemonic("rti"):lambda il, operand: M6502.rti(il),
		Mnemonic("rts"):lambda il, operand: il.ret(il.add(2, il.pop(2), il.const(2, 1))),
		Mnemonic("sbc"):lambda il, operand: il.set_reg(1, a_reg, il.sub_borrow(1, il.reg(1, a_reg), operand, il.flag(c_flag), flags=FlagName("*"))),
		Mnemonic("sec"):lambda il, operand: il.set_flag(c_flag, il.const(0, 1)),
		Mnemonic("sed"):lambda il, operand: il.set_flag(d_flag, il.const(0, 1)),
		Mnemonic("sei"):lambda il, operand: il.set_flag(i_flag, il.const(0, 1)),
		Mnemonic("sta"):lambda il, operand: il.store(1, operand, il.reg(1, a_reg)),
		Mnemonic("stx"):lambda il, operand: il.store(1, operand, il.reg(1, x_reg)),
		Mnemonic("sty"):lambda il, operand: il.store(1, operand, il.reg(1, y_reg)),
		Mnemonic("tax"):lambda il, operand: il.set_reg(1, x_reg, il.reg(1, a_reg), flags=FlagName("zs")),
		Mnemonic("tay"):lambda il, operand: il.set_reg(1, y_reg, il.reg(1, a_reg), flags=FlagName("zs")),
		Mnemonic("tsx"):lambda il, operand: il.set_reg(1, x_reg, il.reg(1, s_reg), flags=FlagName("zs")),
		Mnemonic("txa"):lambda il, operand: il.set_reg(1, a_reg, il.reg(1, x_reg), flags=FlagName("zs")),
		Mnemonic("txs"):lambda il, operand: il.set_reg(1, s_reg, il.reg(1, x_reg)),
		Mnemonic("tya"):lambda il, operand: il.set_reg(1, a_reg, il.reg(1, y_reg), flags=FlagName("zs"))
	}

	OperandIL:List[Callable[[LowLevelILFunction, int], Optional[ExpressionIndex]]] = [
		lambda il, value: None,  # NONE
		lambda il, value: il.load(1, il.const_pointer(2, value)),  # ABS
		lambda il, value: il.const(2, value),  # ABS_DEST
		lambda il, value: il.load(1, il.add(2, il.const(2, value), il.zero_extend(2, il.reg(1, x_reg)))),  # ABS_X
		lambda il, value: il.add(2, il.const(2, value), il.zero_extend(2, il.reg(1, x_reg))),  # ABS_X_DEST
		lambda il, value: il.load(1, il.add(2, il.const(2, value), il.zero_extend(2, il.reg(1, y_reg)))),  # ABS_Y
		lambda il, value: il.add(2, il.const(2, value), il.zero_extend(2, il.reg(1, y_reg))),  # ABS_Y_DEST
		lambda il, value: il.reg(1, a_reg),  # ACCUM
		lambda il, value: il.const_pointer(2, value),  # ADDR
		lambda il, value: il.const(1, value),  # IMMED
		lambda il, value: M6502.indirect_load(il, value),  # IND
		lambda il, value: il.load(1, M6502.load_zero_page_16(il, il.add(1, il.const(1, value), il.reg(1, x_reg)))),  # IND_X
		lambda il, value: M6502.load_zero_page_16(il, il.add(1, il.const(1, value), il.reg(1, x_reg))),  # IND_X_DEST
		lambda il, value: il.load(1, il.add(2, M6502.load_zero_page_16(il, il.const(1, value)), il.reg(1, y_reg))),  # IND_Y
		lambda il, value: il.add(2, M6502.load_zero_page_16(il, il.const(1, value)), il.reg(1, y_reg)),  # IND_Y_DEST
		lambda il, value: il.const_pointer(2, value),  # REL
		lambda il, value: il.load(1, il.const_pointer(2, value)),  # ZERO
		lambda il, value: il.const_pointer(2, value),  # ZERO_DEST
		lambda il, value: il.load(1, il.zero_extend(2, il.add(1, il.const(1, value), il.reg(1, x_reg)))),  # ZERO_X
		lambda il, value: il.zero_extend(2, il.add(1, il.const(1, value), il.reg(1, x_reg))),  # ZERO_X_DEST
		lambda il, value: il.load(1, il.zero_extend(2, il.add(1, il.const(1, value), il.reg(1, y_reg)))),  # ZERO_Y
		lambda il, value: il.zero_extend(2, il.add(1, il.const(1, value), il.reg(1, y_reg)))  # ZERO_Y_DEST
	]

	InstructionNames:List[Optional[Mnemonic]] = [
		Mnemonic("brk"), Mnemonic("ora"), None,             None, None,            Mnemonic("ora"), Mnemonic("asl"), None,  # 0x00
		Mnemonic("php"), Mnemonic("ora"), Mnemonic("asl@"), None, None,            Mnemonic("ora"), Mnemonic("asl"), None,  # 0x08
		Mnemonic("bpl"), Mnemonic("ora"), None,             None, None,            Mnemonic("ora"), Mnemonic("asl"), None,  # 0x10
		Mnemonic("clc"), Mnemonic("ora"), None,             None, None,            Mnemonic("ora"), Mnemonic("asl"), None,  # 0x18
		Mnemonic("jsr"), Mnemonic("and"), None,             None, Mnemonic("bit"), Mnemonic("and"), Mnemonic("rol"), None,  # 0x20
		Mnemonic("plp"), Mnemonic("and"), Mnemonic("rol@"), None, Mnemonic("bit"), Mnemonic("and"), Mnemonic("rol"), None,  # 0x28
		Mnemonic("bmi"), Mnemonic("and"), None,             None, None,            Mnemonic("and"), Mnemonic("rol"), None,  # 0x30
		Mnemonic("sec"), Mnemonic("and"), None,             None, None,            Mnemonic("and"), Mnemonic("rol"), None,  # 0x38
		Mnemonic("rti"), Mnemonic("eor"), None,             None, None,            Mnemonic("eor"), Mnemonic("lsr"), None,  # 0x40
		Mnemonic("pha"), Mnemonic("eor"), Mnemonic("lsr@"), None, Mnemonic("jmp"), Mnemonic("eor"), Mnemonic("lsr"), None,  # 0x48
		Mnemonic("bvc"), Mnemonic("eor"), None,             None, None,            Mnemonic("eor"), Mnemonic("lsr"), None,  # 0x50
		Mnemonic("cli"), Mnemonic("eor"), None,             None, None,            Mnemonic("eor"), Mnemonic("lsr"), None,  # 0x58
		Mnemonic("rts"), Mnemonic("adc"), None,             None, None,            Mnemonic("adc"), Mnemonic("ror"), None,  # 0x60
		Mnemonic("pla"), Mnemonic("adc"), Mnemonic("ror@"), None, Mnemonic("jmp"), Mnemonic("adc"), Mnemonic("ror"), None,  # 0x68
		Mnemonic("bvs"), Mnemonic("adc"), None,             None, None,            Mnemonic("adc"), Mnemonic("ror"), None,  # 0x70
		Mnemonic("sei"), Mnemonic("adc"), None,             None, None,            Mnemonic("adc"), Mnemonic("ror"), None,  # 0x78
		None,            Mnemonic("sta"), None,             None, Mnemonic("sty"), Mnemonic("sta"), Mnemonic("stx"), None,  # 0x80
		Mnemonic("dey"), None,            Mnemonic("txa"),  None, Mnemonic("sty"), Mnemonic("sta"), Mnemonic("stx"), None,  # 0x88
		Mnemonic("bcc"), Mnemonic("sta"), None,             None, Mnemonic("sty"), Mnemonic("sta"), Mnemonic("stx"), None,  # 0x90
		Mnemonic("tya"), Mnemonic("sta"), Mnemonic("txs"),  None, None,            Mnemonic("sta"), None,            None,  # 0x98
		Mnemonic("ldy"), Mnemonic("lda"), Mnemonic("ldx"),  None, Mnemonic("ldy"), Mnemonic("lda"), Mnemonic("ldx"), None,  # 0xa0
		Mnemonic("tay"), Mnemonic("lda"), Mnemonic("tax"),  None, Mnemonic("ldy"), Mnemonic("lda"), Mnemonic("ldx"), None,  # 0xa8
		Mnemonic("bcs"), Mnemonic("lda"), None,             None, Mnemonic("ldy"), Mnemonic("lda"), Mnemonic("ldx"), None,  # 0xb0
		Mnemonic("clv"), Mnemonic("lda"), Mnemonic("tsx"),  None, Mnemonic("ldy"), Mnemonic("lda"), Mnemonic("ldx"), None,  # 0xb8
		Mnemonic("cpy"), Mnemonic("cmp"), None,             None, Mnemonic("cpy"), Mnemonic("cmp"), Mnemonic("dec"), None,  # 0xc0
		Mnemonic("iny"), Mnemonic("cmp"), Mnemonic("dex"),  None, Mnemonic("cpy"), Mnemonic("cmp"), Mnemonic("dec"), None,  # 0xc8
		Mnemonic("bne"), Mnemonic("cmp"), None,             None, None,            Mnemonic("cmp"), Mnemonic("dec"), None,  # 0xd0
		Mnemonic("cld"), Mnemonic("cmp"), None,             None, None,            Mnemonic("cmp"), Mnemonic("dec"), None,  # 0xd8
		Mnemonic("cpx"), Mnemonic("sbc"), None,             None, Mnemonic("cpx"), Mnemonic("sbc"), Mnemonic("inc"), None,  # 0xe0
		Mnemonic("inx"), Mnemonic("sbc"), Mnemonic("nop"),  None, Mnemonic("cpx"), Mnemonic("sbc"), Mnemonic("inc"), None,  # 0xe8
		Mnemonic("beq"), Mnemonic("sbc"), None,             None, None,            Mnemonic("sbc"), Mnemonic("inc"), None,  # 0xf0
		Mnemonic("sed"), Mnemonic("sbc"), None,             None, None,            Mnemonic("sbc"), Mnemonic("inc"), None   # 0xf8
	]

	OperandTokens: List[Callable[[int], List[InstructionTextToken]]] = [
		lambda value: [],  # NONE
		lambda value: [InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, "$%.4x" % value, value)],  # ABS
		lambda value: [InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, "$%.4x" % value, value)
						],  # ABS_DEST
		lambda value: [
			InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, "$%.4x" % value, value),
			InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
			InstructionTextToken(InstructionTextTokenType.RegisterToken, "x")
		],  # ABS_X
		lambda value: [
			InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, "$%.4x" % value, value),
			InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
			InstructionTextToken(InstructionTextTokenType.RegisterToken, "x")
		],  # ABS_X_DEST
		lambda value: [
			InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, "$%.4x" % value, value),
			InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
			InstructionTextToken(InstructionTextTokenType.RegisterToken, "y")
		],  # ABS_Y
		lambda value: [
			InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, "$%.4x" % value, value),
			InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
			InstructionTextToken(InstructionTextTokenType.RegisterToken, "y")
		],  # ABS_Y_DEST
		lambda value: [InstructionTextToken(InstructionTextTokenType.RegisterToken, "a")],  # ACCUM
		lambda value: [InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, "$%.4x" % value, value)],  # ADDR
		lambda value: [
			InstructionTextToken(InstructionTextTokenType.TextToken, "#"),
			InstructionTextToken(InstructionTextTokenType.IntegerToken, "$%.2x" % value, value)
		],  # IMMED
		lambda value: [
			InstructionTextToken(InstructionTextTokenType.TextToken, "["),
			InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, "$%.4x" % value, value),
			InstructionTextToken(InstructionTextTokenType.TextToken, "]")
		],  # IND
		lambda value: [
			InstructionTextToken(InstructionTextTokenType.TextToken, "["),
			InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, "$%.2x" % value, value),
			InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
			InstructionTextToken(InstructionTextTokenType.RegisterToken, "x"),
			InstructionTextToken(InstructionTextTokenType.TextToken, "]")
		],  # IND_X
		lambda value: [
			InstructionTextToken(InstructionTextTokenType.TextToken, "["),
			InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, "$%.2x" % value, value),
			InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
			InstructionTextToken(InstructionTextTokenType.RegisterToken, "x"),
			InstructionTextToken(InstructionTextTokenType.TextToken, "]")
		],  # IND_X_DEST
		lambda value: [
			InstructionTextToken(InstructionTextTokenType.TextToken, "["),
			InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, "$%.2x" % value, value),
			InstructionTextToken(InstructionTextTokenType.TextToken, "], "),
			InstructionTextToken(InstructionTextTokenType.RegisterToken, "y")
		],  # IND_Y
		lambda value: [
			InstructionTextToken(InstructionTextTokenType.TextToken, "["),
			InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, "$%.2x" % value, value),
			InstructionTextToken(InstructionTextTokenType.TextToken, "], "),
			InstructionTextToken(InstructionTextTokenType.RegisterToken, "y")
		],  # IND_Y_DEST
		lambda value: [InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, "$%.4x" % value, value)],  # REL
		lambda value: [InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, "$%.2x" % value, value)],  # ZERO
		lambda value: [InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, "$%.2x" % value, value)
		],  # ZERO_DEST
		lambda value: [
			InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, "$%.2x" % value, value),
			InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
			InstructionTextToken(InstructionTextTokenType.RegisterToken, "x")
		],  # ZERO_X
		lambda value: [
			InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, "$%.2x" % value, value),
			InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
			InstructionTextToken(InstructionTextTokenType.RegisterToken, "x")
		],  # ZERO_X_DEST
		lambda value: [
			InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, "$%.2x" % value, value),
			InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
			InstructionTextToken(InstructionTextTokenType.RegisterToken, "y")
		],  # ZERO_Y
		lambda value: [
			InstructionTextToken(InstructionTextTokenType.PossibleAddressToken, "$%.2x" % value, value),
			InstructionTextToken(InstructionTextTokenType.TextToken, ", "),
			InstructionTextToken(InstructionTextTokenType.RegisterToken, "y")
		]  # ZERO_Y_DEST
	]

	InstructionOperandTypes:List[Optional[Operand]] = [
		NONE, IND_X, NONE, NONE, NONE, ZERO, ZERO_DEST, NONE,  # 0x00
		NONE, IMMED, ACCUM, NONE, NONE, ABS, ABS_DEST, NONE,  # 0x08
		REL, IND_Y, NONE, NONE, NONE, ZERO_X, ZERO_X_DEST, NONE,  # 0x10
		NONE, ABS_Y, NONE, NONE, NONE, ABS_X, ABS_X_DEST, NONE,  # 0x18
		ADDR, IND_X, NONE, NONE, ZERO, ZERO, ZERO_DEST, NONE,  # 0x20
		NONE, IMMED, ACCUM, NONE, ABS, ABS, ABS_DEST, NONE,  # 0x28
		REL, IND_Y, NONE, NONE, NONE, ZERO_X, ZERO_X_DEST, NONE,  # 0x30
		NONE, ABS_Y, NONE, NONE, NONE, ABS_X, ABS_X_DEST, NONE,  # 0x38
		NONE, IND_X, NONE, NONE, NONE, ZERO, ZERO_DEST, NONE,  # 0x40
		NONE, IMMED, ACCUM, NONE, ADDR, ABS, ABS_DEST, NONE,  # 0x48
		REL, IND_Y, NONE, NONE, NONE, ZERO_X, ZERO_X_DEST, NONE,  # 0x50
		NONE, ABS_Y, NONE, NONE, NONE, ABS_X, ABS_X_DEST, NONE,  # 0x58
		NONE, IND_X, NONE, NONE, NONE, ZERO, ZERO_DEST, NONE,  # 0x60
		NONE, IMMED, ACCUM, NONE, IND, ABS, ABS_DEST, NONE,  # 0x68
		REL, IND_Y, NONE, NONE, NONE, ZERO_X, ZERO_X_DEST, NONE,  # 0x70
		NONE, ABS_Y, NONE, NONE, NONE, ABS_X, ABS_X_DEST, NONE,  # 0x78
		NONE, IND_X_DEST, NONE, NONE, ZERO_DEST, ZERO_DEST, ZERO_DEST, NONE,  # 0x80
		NONE, NONE, NONE, NONE, ABS_DEST, ABS_DEST, ABS_DEST, NONE,  # 0x88
		REL, IND_Y_DEST, NONE, NONE, ZERO_X_DEST, ZERO_X_DEST, ZERO_Y_DEST, NONE,  # 0x90
		NONE, ABS_Y_DEST, NONE, NONE, NONE, ABS_X_DEST, NONE, NONE,  # 0x98
		IMMED, IND_X, IMMED, NONE, ZERO, ZERO, ZERO, NONE,  # 0xa0
		NONE, IMMED, NONE, NONE, ABS, ABS, ABS, NONE,  # 0xa8
		REL, IND_Y, NONE, NONE, ZERO_X, ZERO_X, ZERO_Y, NONE,  # 0xb0
		NONE, ABS_Y, NONE, NONE, ABS_X, ABS_X, ABS_Y, NONE,  # 0xb8
		IMMED, IND_X, NONE, NONE, ZERO, ZERO, ZERO_DEST, NONE,  # 0xc0
		NONE, IMMED, NONE, NONE, ABS, ABS, ABS_DEST, NONE,  # 0xc8
		REL, IND_Y, NONE, NONE, NONE, ZERO_X, ZERO_X_DEST, NONE,  # 0xd0
		NONE, ABS_Y, NONE, NONE, NONE, ABS_X, ABS_X_DEST, NONE,  # 0xd8
		IMMED, IND_X, NONE, NONE, ZERO, ZERO, ZERO_DEST, NONE,  # 0xe0
		NONE, IMMED, NONE, NONE, ABS, ABS, ABS_DEST, NONE,  # 0xe8
		REL, IND_Y, NONE, NONE, NONE, ZERO_X, ZERO_X_DEST, NONE,  # 0xf0
		NONE, ABS_Y, NONE, NONE, NONE, ABS_X, ABS_X_DEST, NONE  # 0xf8
	]

	OperandLengths:List[int] = [
		0,  # NONE
		2,  # ABS
		2,  # ABS_DEST
		2,  # ABS_X
		2,  # ABS_X_DEST
		2,  # ABS_Y
		2,  # ABS_Y_DEST
		0,  # ACCUM
		2,  # ADDR
		1,  # IMMED
		2,  # IND
		1,  # IND_X
		1,  # IND_X_DEST
		1,  # IND_Y
		1,  # IND_Y_DEST
		1,  # REL
		1,  # ZERO
		1,  # ZERO_DEST
		1,  # ZERO_X
		1,  # ZERO_X_DEST
		1,  # ZERO_Y
		1  # ZERO_Y_DEST
	]


	@staticmethod
	def load_zero_page_16(il:LowLevelILFunction, value:ExpressionIndex) -> ExpressionIndex:
		instr = LowLevelILInstruction.create(il, value)
		if isinstance(instr, LowLevelILConst):
			if instr.constant == 0xff:
				lo = il.zero_extend(2, il.load(1, il.const_pointer(2, 0xff)))
				hi = il.shift_left(2, il.zero_extend(2, il.load(1, il.const_pointer(2, 0))), il.const(2, 8))
				return il.or_expr(2, lo, hi)
			return il.load(2, il.const_pointer(2, instr.constant))
		il.append(il.set_reg(1, LLIL_TEMP(0), value))
		expr = il.reg(1, LLIL_TEMP(0))
		lo_addr = expr
		hi_addr = il.add(1, expr, il.const(1, 1))
		lo = il.zero_extend(2, il.load(1, lo_addr))
		hi = il.shift_left(2, il.zero_extend(2, il.load(1, hi_addr)), il.const(2, 8))
		return il.or_expr(2, lo, hi)

	@staticmethod
	def indirect_load(il:LowLevelILFunction, value:int) -> ExpressionIndex:
		if (value & 0xff) == 0xff:
			lo_addr = il.const_pointer(2, value)
			hi_addr = il.const_pointer(2, (value & 0xff00) | ((value + 1) & 0xff))
			lo = il.zero_extend(2, il.load(1, lo_addr))
			hi = il.shift_left(2, il.zero_extend(2, il.load(1, hi_addr)), il.const(2, 8))
			return il.or_expr(2, lo, hi)
		return il.load(2, il.const_pointer(2, value))

	@staticmethod
	def cond_branch(il:LowLevelILFunction, cond:ExpressionIndex, dest:ExpressionIndex) -> None:
		t = None
		instr = LowLevelILInstruction.create(il, dest)
		if isinstance(instr, LowLevelILConst):
			t = il.get_label_for_address(Architecture['6502'], instr.constant)  # type: ignore
		if t is None:
			t = LowLevelILLabel()
			indirect = True
		else:
			indirect = False
		f = LowLevelILLabel()
		il.append(il.if_expr(cond, t, f))
		if indirect:
			il.mark_label(t)
			il.append(il.jump(dest))
		il.mark_label(f)
		return None

	@staticmethod
	def jump(il:LowLevelILFunction, dest:ExpressionIndex) -> None:
		label = None
		instr = LowLevelILInstruction.create(il, dest)
		if isinstance(instr, LowLevelILConst):
			label = il.get_label_for_address(Architecture['6502'], instr.constant)  # type: ignore
		if label is None:
			il.append(il.jump(dest))
		else:
			il.append(il.goto(label))
		return None

	@staticmethod
	def get_p_value(il:LowLevelILFunction) -> ExpressionIndex:
		c = il.flag_bit(1, c_flag, 0)
		z = il.flag_bit(1, z_flag, 1)
		i = il.flag_bit(1, i_flag, 2)
		d = il.flag_bit(1, d_flag, 3)
		b = il.flag_bit(1, b_flag, 4)
		v = il.flag_bit(1, v_flag, 6)
		s = il.flag_bit(1, s_flag, 7)
		return il.or_expr(1, il.or_expr(1, il.or_expr(1, il.or_expr(1, il.or_expr(1, il.or_expr(1, c, z), i), d), b), v), s)

	@staticmethod
	def set_p_value(il:LowLevelILFunction, value:ExpressionIndex) -> None:
		il.append(il.set_reg(1, LLIL_TEMP(0), value))
		il.append(il.set_flag(c_flag, il.test_bit(1, il.reg(1, LLIL_TEMP(0)), il.const(1, 0x01))))
		il.append(il.set_flag(z_flag, il.test_bit(1, il.reg(1, LLIL_TEMP(0)), il.const(1, 0x02))))
		il.append(il.set_flag(i_flag, il.test_bit(1, il.reg(1, LLIL_TEMP(0)), il.const(1, 0x04))))
		il.append(il.set_flag(d_flag, il.test_bit(1, il.reg(1, LLIL_TEMP(0)), il.const(1, 0x08))))
		il.append(il.set_flag(b_flag, il.test_bit(1, il.reg(1, LLIL_TEMP(0)), il.const(1, 0x10))))
		il.append(il.set_flag(v_flag, il.test_bit(1, il.reg(1, LLIL_TEMP(0)), il.const(1, 0x40))))
		il.append(il.set_flag(s_flag, il.test_bit(1, il.reg(1, LLIL_TEMP(0)), il.const(1, 0x80))))
		return None

	@staticmethod
	def rti(il:LowLevelILFunction) -> ExpressionIndex:
		M6502.set_p_value(il, il.pop(1))
		return il.ret(il.pop(2))

	@staticmethod
	def decode_instruction(data:bytes, addr:int) -> Optional[Tuple[Mnemonic, Operand, int, int]]:
		if len(data) < 1:
			return None
		opcode = ord(data[0:1])
		instr = M6502.InstructionNames[opcode]
		if instr is None:
			return None
		operand = M6502.InstructionOperandTypes[opcode]
		assert operand is not None
		length = 1 + M6502.OperandLengths[operand]
		if len(data) < length:
			return None

		if M6502.OperandLengths[operand] == 0:
			value = 0
		elif operand == REL:
			value = (addr + 2 + struct.unpack("b", data[1:2])[0]) & 0xffff
		elif M6502.OperandLengths[operand] == 1:
			value = ord(data[1:2])
		else:
			value = struct.unpack("<H", data[1:3])[0]

		return instr, operand, length, value

	def get_instruction_info(self, data:bytes, addr:int) -> Optional[InstructionInfo]:
		result = M6502.decode_instruction(data, addr)
		if result is None:
			return None
		instr, operand, length, _ = result
		assert length is not None
		result = InstructionInfo()
		result.length = length
		if instr == "jmp":
			if operand == ADDR:
				result.add_branch(BranchType.UnconditionalBranch, struct.unpack("<H", data[1:3])[0])
			else:
				result.add_branch(BranchType.UnresolvedBranch)
		elif instr == "jsr":
			result.add_branch(BranchType.CallDestination, struct.unpack("<H", data[1:3])[0])
		elif instr in ["rti", "rts"]:
			result.add_branch(BranchType.FunctionReturn)
		if instr in ["bcc", "bcs", "beq", "bmi", "bne", "bpl", "bvc", "bvs"]:
			dest = (addr + 2 + struct.unpack("b", data[1:2])[0]) & 0xffff
			result.add_branch(BranchType.TrueBranch, dest)
			result.add_branch(BranchType.FalseBranch, addr + 2)
		return result

	def get_instruction_text(self, data: bytes, addr: int) -> Optional[Tuple[List[InstructionTextToken], int]]:
		result = M6502.decode_instruction(data, addr)
		if result is None:
			return None
		instr, operand, length, value = result
		tokens:List[InstructionTextToken] = []
		tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, "%-7s " % instr.replace("@", "")))
		tokens += M6502.OperandTokens[operand](value)
		return tokens, length

	def get_instruction_low_level_il(self, data: bytes, addr: int, il: LowLevelILFunction) -> Optional[int]:
		result = M6502.decode_instruction(data, addr)
		if result is None:
			return None
		instr, operand, length, value = result
		if instr is None or operand is None or length is None:
			return None
		op = M6502.OperandIL[operand](il, value)
		i = M6502.InstructionIL[instr](il, op)
		if i is not None:
			il.append(i)
		return length

	def get_flag_write_low_level_il(self, op: LowLevelILOperation, size: int, write_type: Optional[FlagWriteTypeName], flag: FlagType, operands: List[ILRegisterType], il: LowLevelILFunction) -> ExpressionIndex:
		if flag == 'c':
			if (op == LowLevelILOperation.LLIL_SUB) or (op == LowLevelILOperation.LLIL_SBB):
				# Subtraction carry flag is inverted from the commom implementation
				return il.not_expr(0, self.get_default_flag_write_low_level_il(op, size, FlagRole.CarryFlagRole, operands, il))
			# Other operations use a normal carry flag
			return self.get_default_flag_write_low_level_il(op, size, FlagRole.CarryFlagRole, operands, il)
		return Architecture.get_flag_write_low_level_il(self, op, size, write_type, flag, operands, il)

	def is_never_branch_patch_available(self, data:bytes, addr:int) -> bool:
		if (data[0:1] == b"\x10") or (data[0:1] == b"\x30") or (data[0:1] == b"\x50") or (data[0:1] == b"\x70") or (
		  data[0:1] == b"\x90"
		) or (data[0:1] == b"\xb0") or (data[0:1] == b"\xd0") or (data[0:1] == b"\xf0"):
			return True
		return False

	def is_invert_branch_patch_available(self, data:bytes, addr:int) -> bool:
		if (data[0:1] == b"\x10") or (data[0:1] == b"\x30") or (data[0:1] == b"\x50") or (data[0:1] == b"\x70") or (
		  data[0:1] == b"\x90"
		) or (data[0:1] == b"\xb0") or (data[0:1] == b"\xd0") or (data[0:1] == b"\xf0"):
			return True
		return False

	def is_always_branch_patch_available(self, data:bytes, addr:int) -> bool:
		return False

	def is_skip_and_return_zero_patch_available(self, data:bytes, addr:int) -> bool:
		return (data[0:1] == b"\x20") and (len(data) == 3)

	def is_skip_and_return_value_patch_available(self, data:bytes, addr:int) -> bool:
		return (data[0:1] == b"\x20") and (len(data) == 3)

	def convert_to_nop(self, data:bytes, addr:int) -> bytes:
		return b"\xea" * len(data)

	def never_branch(self, data:bytes, addr:int) -> Optional[bytes]:
		if (data[0:1] == b"\x10") or (data[0:1] == b"\x30") or (data[0:1] == b"\x50") or (data[0:1] == b"\x70") or (
		  data[0:1] == b"\x90"
		) or (data[0:1] == b"\xb0") or (data[0:1] == b"\xd0") or (data[0:1] == b"\xf0"):
			return b"\xea" * len(data)
		return None

	def invert_branch(self, data:bytes, addr:int) -> Optional[bytes]:
		if (data[0:1] == b"\x10") or (data[0:1] == b"\x30") or (data[0:1] == b"\x50") or (data[0:1] == b"\x70") or (
		  data[0:1] == b"\x90"
		) or (data[0:1] == b"\xb0") or (data[0:1] == b"\xd0") or (data[0:1] == b"\xf0"):
			result = bytearray(data)
			result[0] ^= 0x20
			return bytes(result)
		return None

	def skip_and_return_value(self, data:bytes, addr:int, value:int) -> Optional[bytes]:
		if (data[0:1] != b"\x20") or (len(data) != 3):
			return None
		return b"\xa9" + (value & 0xff).to_bytes(1, "little") + b"\xea"


class NESView(BinaryView):
	name = "NES"
	long_name = "NES ROM"
	bank = None

	def __init__(self, data:BinaryView):
		BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
		self.platform = Architecture['6502'].standalone_platform  # type: ignore

	@classmethod
	def is_valid_for_data(cls, data:BinaryView) -> bool:
		hdr = data.read(0, 16)
		if len(hdr) < 16:
			return False
		if hdr[0:4] != b"NES\x1a":
			return False
		rom_banks = struct.unpack("B", hdr[4:5])[0]
		assert cls.bank is not None
		if rom_banks < (cls.bank + 1):
			return False
		return True

	def init(self) -> bool:
		try:
			assert self.parent_view is not None
			hdr = self.parent_view.read(0, 16)
			self.rom_banks = struct.unpack("B", hdr[4:5])[0]
			self.vrom_banks = struct.unpack("B", hdr[5:6])[0]
			self.rom_flags = struct.unpack("B", hdr[6:7])[0]
			self.mapper_index = struct.unpack("B", hdr[7:8])[0] | (self.rom_flags >> 4)
			self.ram_banks = struct.unpack("B", hdr[8:9])[0]
			self.rom_offset = 16
			if self.rom_flags & 4:
				self.rom_offset += 512
			self.rom_length = self.rom_banks * 0x4000

			# Add mapping for RAM and hardware registers, not backed by file contents
			self.add_auto_segment(
			  0, 0x8000, 0, 0, SegmentFlag.SegmentReadable | SegmentFlag.SegmentWritable | SegmentFlag.SegmentExecutable
			)

			# Add ROM mappings
			assert self.__class__.bank is not None
			self.add_auto_segment(
			  0x8000, 0x4000, self.rom_offset + (self.__class__.bank * 0x4000), 0x4000,
			  SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable
			)
			self.add_auto_segment(
			  0xc000, 0x4000, self.rom_offset + self.rom_length - 0x4000, 0x4000,
			  SegmentFlag.SegmentReadable | SegmentFlag.SegmentExecutable
			)

			nmi = struct.unpack("<H", self.read(0xfffa, 2))[0]
			start = struct.unpack("<H", self.read(0xfffc, 2))[0]
			irq = struct.unpack("<H", self.read(0xfffe, 2))[0]
			self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, nmi, "_nmi"))
			self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, start, "_start"))
			self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, irq, "_irq"))
			self.add_function(nmi)
			self.add_function(irq)
			self.add_entry_point(start)

			# Hardware registers
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x2000, "PPUCTRL"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x2001, "PPUMASK"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x2002, "PPUSTATUS"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x2003, "OAMADDR"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x2004, "OAMDATA"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x2005, "PPUSCROLL"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x2006, "PPUADDR"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x2007, "PPUDATA"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x4000, "SQ1_VOL"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x4001, "SQ1_SWEEP"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x4002, "SQ1_LO"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x4003, "SQ1_HI"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x4004, "SQ2_VOL"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x4005, "SQ2_SWEEP"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x4006, "SQ2_LO"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x4007, "SQ2_HI"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x4008, "TRI_LINEAR"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x400a, "TRI_LO"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x400b, "TRI_HI"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x400c, "NOISE_VOL"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x400e, "NOISE_LO"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x400f, "NOISE_HI"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x4010, "DMC_FREQ"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x4011, "DMC_RAW"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x4012, "DMC_START"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x4013, "DMC_LEN"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x4014, "OAMDMA"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x4015, "SND_CHN"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x4016, "JOY1"))
			self.define_auto_symbol(Symbol(SymbolType.DataSymbol, 0x4017, "JOY2"))

			sym_files = [
			  self.file.filename + f".{self.__class__.bank:x}.nl",
			  self.file.filename + ".ram.nl",
			  self.file.filename + f".{self.rom_banks - 1:x}.nl"
			]
			for file_name in sym_files:
				if os.path.exists(file_name):
					with open(file_name, "r") as cur_file:
						lines = cur_file.readlines()
					for line in lines:
						line = line.strip()
						sym = line.split('#')
						if len(sym) < 3:
							break
						addr = int(sym[0][1:], 16)
						name = sym[1]
						self.define_auto_symbol(Symbol(SymbolType.FunctionSymbol, addr, name))
						if addr >= 0x8000:
							self.add_function(addr)

			return True
		except:
			log_error(traceback.format_exc())
			return False

	def perform_is_executable(self) -> bool:
		return True

	def perform_get_address_size(self) -> int:
		return self.address_size

	def perform_get_entry_point(self) -> int:
		return struct.unpack("<H", self.read(0xfffc, 2))[0]


banks:List[Type['NESViewBank']] = []
for i in range(32):
	class NESViewBank(NESView):
		bank = i
		name = "NES Bank %X" % i
		long_name = "NES ROM (bank %X)" % i

		def __init__(self, data:BinaryView):
			NESView.__init__(self, data)

	banks.append(NESViewBank)
	NESViewBank.register()

M6502.register()
