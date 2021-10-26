# Copyright (c) 2015-2021 Vector 35 Inc
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

import ctypes
import struct
from typing import Generator, List, Optional, Mapping, Union, Tuple, NewType, ClassVar
from dataclasses import dataclass

# Binary Ninja components
from .enums import LowLevelILOperation, LowLevelILFlagCondition, DataFlowQueryOption, FunctionGraphType
from . import _binaryninjacore as core
from . import basicblock #required for LowLevelILBasicBlock
from . import function
from . import mediumlevelil
from . import highlevelil
from . import flowgraph
from . import variable
from . import binaryview
from . import architecture
from . import types
from .commonil import (ILInstruction, Constant, BinaryOperation, UnaryOperation, Comparison, SSA,
	Phi, FloatingPoint, ControlFlow, Terminal, Call, StackOperation, Return,
	Signed, Arithmetic, Carry, DoublePrecision, Memory, Load, Store, RegisterStack, SetReg)

ExpressionIndex = NewType('ExpressionIndex', int)
InstructionIndex = NewType('InstructionIndex', int)
Index = Union[ExpressionIndex, InstructionIndex]
TokenList = List['function.InstructionTextToken']
InstructionOrExpression = Union['LowLevelILInstruction', Index]
ILRegisterType = Union[str, 'ILRegister', int]
LLILInstructionsType = Generator['LowLevelILInstruction', None, None]
OperandsType = Tuple[ExpressionIndex, ExpressionIndex, ExpressionIndex, ExpressionIndex]
LowLevelILOperandType = Union[
	'LowLevelILOperationAndSize',
	'ILRegister',
	'ILFlag',
	'ILIntrinsic',
	'ILRegisterStack',
	int,
	Mapping[int, int],
	float,
	'LowLevelILInstruction',
	Mapping['architecture.RegisterStackName', int],
	'SSAFlag',
	'SSARegister',
	'SSARegisterStack',
	'ILSemanticFlagClass',
	'ILSemanticFlagGroup',
	'LowLevelILFlagCondition',
	List[int],
	List['LowLevelILInstruction'],
	List[Union['ILFlag', 'ILRegister']],
	List['SSARegister'],
	List['SSARegisterStack'],
	List['SSAFlag'],
	List['SSARegisterOrFlag'],
]

class LowLevelILLabel:
	def __init__(self, handle:core.BNLowLevelILLabel=None):
		if handle is None:
			self.handle = (core.BNLowLevelILLabel * 1)()
			core.BNLowLevelILInitLabel(self.handle)
		else:
			self.handle = handle

@dataclass(frozen=True)
class ILRegister:
	arch:'architecture.Architecture'
	index:'architecture.RegisterIndex'

	def __repr__(self):
		return f"<reg {self.name}>"

	def __str__(self):
		return self.name

	def __int__(self):
		return self.index

	def __eq__(self, other):
		if isinstance(other, str) and other in self.arch.regs:
			index = self.arch.regs[architecture.RegisterName(other)].index
			assert index is not None
			other = ILRegister(self.arch, index)
		elif not isinstance(other, self.__class__):
			return NotImplemented
		return (self.arch, self.index) == (other.arch, other.index)

	@property
	def info(self) -> 'architecture.RegisterInfo':
		return self.arch.regs[self.name]

	@property
	def temp(self) -> bool:
		return (self.index & 0x80000000) != 0

	@property
	def name(self) -> 'architecture.RegisterName':
		if self.temp:
			return architecture.RegisterName(f"temp{self.index & 0x7fffffff}")
		else:
			return architecture.RegisterName(self.arch.get_reg_name(self.index))


@dataclass(frozen=True)
class ILRegisterStack:
	arch:'architecture.Architecture'
	index:'architecture.RegisterStackIndex'

	def __repr__(self):
		return f"<reg-stack {self.name}>"

	def __str__(self):
		return self.name

	def __int__(self):
		return self.index

	@property
	def info(self) -> 'architecture.RegisterStackInfo':
		return self.arch.reg_stacks[self.name]

	@property
	def name(self) -> 'architecture.RegisterStackName':
		return self.arch.get_reg_stack_name(self.index)


@dataclass(frozen=True)
class ILFlag:
	arch:'architecture.Architecture'
	index:'architecture.FlagIndex'

	def __repr__(self):
		return f"<flag {self.name}>"

	def __str__(self):
		return self.name

	def __int__(self):
		return self.index

	@property
	def temp(self) -> bool:
		return (self.index & 0x80000000) != 0

	@property
	def name(self) -> 'architecture.FlagName':
		if self.temp:
			return architecture.FlagName(f"cond:{(self.index & 0x7fffffff)}")
		else:
			return architecture.FlagName(self.arch.get_flag_name(self.index))


@dataclass(frozen=True)
class ILSemanticFlagClass:
	arch:'architecture.Architecture'
	index:'architecture.SemanticClassIndex'

	def __repr__(self):
		return self.name

	def __str__(self):
		return self.name

	def __int__(self):
		return self.index

	@property
	def name(self) -> 'architecture.SemanticClassName':
		return self.arch.get_semantic_flag_class_name(self.index)


@dataclass(frozen=True)
class ILSemanticFlagGroup:
	arch:'architecture.Architecture'
	index:'architecture.SemanticGroupIndex'

	def __repr__(self):
		return self.name

	def __str__(self):
		return self.name

	def __int__(self):
		return self.index

	@property
	def name(self) -> 'architecture.SemanticGroupName':
		return self.arch.get_semantic_flag_group_name(self.index)


@dataclass(frozen=True)
class ILIntrinsic:
	arch:'architecture.Architecture'
	index:'architecture.IntrinsicIndex'

	def __repr__(self):
		return self.name

	def __str__(self):
		return self.name

	@property
	def name(self) -> 'architecture.IntrinsicName':
		return self.arch.get_intrinsic_name(self.index)

	@property
	def inputs(self) -> List['architecture.IntrinsicInput']:
		"""``inputs`` is only available if the IL intrinsic is an Architecture intrinsic """
		return self.arch.intrinsics[self.name].inputs

	@property
	def outputs(self) -> List['types.Type']:
		"""``outputs`` is only available if the IL intrinsic is an Architecture intrinsic """
		return self.arch.intrinsics[self.name].outputs


@dataclass(frozen=True)
class SSARegister:
	reg:ILRegister
	version:int

	def __repr__(self):
		return f"<ssa {self.reg} version {self.version}>"


@dataclass(frozen=True)
class SSARegisterStack:
	reg_stack:ILRegisterStack
	version:int

	def __repr__(self):
		return f"<ssa {self.reg_stack} version {self.version}>"


@dataclass(frozen=True)
class SSAFlag:
	flag:ILFlag
	version:int

	def __repr__(self):
		return f"<ssa {self.flag} version {self.version}>"


@dataclass(frozen=True)
class SSARegisterOrFlag:
	reg_or_flag:Union[ILRegister, ILFlag]
	version:int

	def __repr__(self):
		return f"<ssa {self.reg_or_flag} version {self.version}>"


@dataclass(frozen=True)
class LowLevelILOperationAndSize:
	operation:'LowLevelILOperation'
	size:int

	def __repr__(self):
		if self.size == 0:
			return f"<{self.operation.name}>"
		return f"<{self.operation.name} {self.size}>"


@dataclass(frozen=True)
class CoreLowLevelILInstruction:
	operation:LowLevelILOperation
	size:int
	flags:int
	source_operand:ExpressionIndex
	operands:OperandsType
	address:int

	@classmethod
	def from_BNLowLevelILInstruction(cls, instr:core.BNLowLevelILInstruction) -> 'CoreLowLevelILInstruction':
		operands:OperandsType = (ExpressionIndex(instr.operands[0]),
			ExpressionIndex(instr.operands[1]),
			ExpressionIndex(instr.operands[2]),
			ExpressionIndex(instr.operands[3]))
		return cls(LowLevelILOperation(instr.operation), instr.size, instr.flags, instr.sourceOperand, operands, instr.address)


@dataclass(frozen=True)
class LowLevelILInstruction(ILInstruction):
	"""
	``class LowLevelILInstruction`` Low Level Intermediate Language Instructions are infinite length tree-based
	instructions. Tree-based instructions use infix notation with the left hand operand being the destination operand.
	Infix notation is thus more natural to read than other notations (e.g. x86 ``mov eax, 0`` vs. LLIL ``eax = 0``).
	"""

	function:'LowLevelILFunction'
	expr_index:ExpressionIndex
	instr:CoreLowLevelILInstruction
	instr_index:Optional[InstructionIndex]
	ILOperations:ClassVar[Mapping[LowLevelILOperation, List[Tuple[str,str]]]] = {
		LowLevelILOperation.LLIL_NOP: [],
		LowLevelILOperation.LLIL_SET_REG: [("dest", "reg"), ("src", "expr")],
		LowLevelILOperation.LLIL_SET_REG_SPLIT: [("hi", "reg"), ("lo", "reg"), ("src", "expr")],
		LowLevelILOperation.LLIL_SET_REG_STACK_REL: [("stack", "reg_stack"), ("dest", "expr"), ("src", "expr")],
		LowLevelILOperation.LLIL_REG_STACK_PUSH: [("stack", "reg_stack"), ("src", "expr")],
		LowLevelILOperation.LLIL_SET_FLAG: [("dest", "flag"), ("src", "expr")],
		LowLevelILOperation.LLIL_LOAD: [("src", "expr")],
		LowLevelILOperation.LLIL_STORE: [("dest", "expr"), ("src", "expr")],
		LowLevelILOperation.LLIL_PUSH: [("src", "expr")],
		LowLevelILOperation.LLIL_POP: [],
		LowLevelILOperation.LLIL_REG: [("src", "reg")],
		LowLevelILOperation.LLIL_REG_SPLIT: [("hi", "reg"), ("lo", "reg")],
		LowLevelILOperation.LLIL_REG_STACK_REL: [("stack", "reg_stack"), ("src", "expr")],
		LowLevelILOperation.LLIL_REG_STACK_POP: [("stack", "reg_stack")],
		LowLevelILOperation.LLIL_REG_STACK_FREE_REG: [("dest", "reg")],
		LowLevelILOperation.LLIL_REG_STACK_FREE_REL: [("stack", "reg_stack"), ("dest", "expr")],
		LowLevelILOperation.LLIL_CONST: [("constant", "int")],
		LowLevelILOperation.LLIL_CONST_PTR: [("constant", "int")],
		LowLevelILOperation.LLIL_EXTERN_PTR: [("constant", "int"), ("offset", "int")],
		LowLevelILOperation.LLIL_FLOAT_CONST: [("constant", "float")],
		LowLevelILOperation.LLIL_FLAG: [("src", "flag")],
		LowLevelILOperation.LLIL_FLAG_BIT: [("src", "flag"), ("bit", "int")],
		LowLevelILOperation.LLIL_ADD: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_ADC: [("left", "expr"), ("right", "expr"), ("carry", "expr")],
		LowLevelILOperation.LLIL_SUB: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_SBB: [("left", "expr"), ("right", "expr"), ("carry", "expr")],
		LowLevelILOperation.LLIL_AND: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_OR: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_XOR: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_LSL: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_LSR: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_ASR: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_ROL: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_RLC: [("left", "expr"), ("right", "expr"), ("carry", "expr")],
		LowLevelILOperation.LLIL_ROR: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_RRC: [("left", "expr"), ("right", "expr"), ("carry", "expr")],
		LowLevelILOperation.LLIL_MUL: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_MULU_DP: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_MULS_DP: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_DIVU: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_DIVU_DP: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_DIVS: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_DIVS_DP: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_MODU: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_MODU_DP: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_MODS: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_MODS_DP: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_NEG: [("src", "expr")],
		LowLevelILOperation.LLIL_NOT: [("src", "expr")],
		LowLevelILOperation.LLIL_SX: [("src", "expr")],
		LowLevelILOperation.LLIL_ZX: [("src", "expr")],
		LowLevelILOperation.LLIL_LOW_PART: [("src", "expr")],
		LowLevelILOperation.LLIL_JUMP: [("dest", "expr")],
		LowLevelILOperation.LLIL_JUMP_TO: [("dest", "expr"), ("targets", "target_map")],
		LowLevelILOperation.LLIL_CALL: [("dest", "expr")],
		LowLevelILOperation.LLIL_CALL_STACK_ADJUST: [("dest", "expr"), ("stack_adjustment", "int"), ("reg_stack_adjustments", "reg_stack_adjust")],
		LowLevelILOperation.LLIL_TAILCALL: [("dest", "expr")],
		LowLevelILOperation.LLIL_RET: [("dest", "expr")],
		LowLevelILOperation.LLIL_NORET: [],
		LowLevelILOperation.LLIL_IF: [("condition", "expr"), ("true", "int"), ("false", "int")],
		LowLevelILOperation.LLIL_GOTO: [("dest", "int")],
		LowLevelILOperation.LLIL_FLAG_COND: [("condition", "cond"), ("semantic_class", "sem_class")],
		LowLevelILOperation.LLIL_FLAG_GROUP: [("semantic_group", "sem_group")],
		LowLevelILOperation.LLIL_CMP_E: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_CMP_NE: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_CMP_SLT: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_CMP_ULT: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_CMP_SLE: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_CMP_ULE: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_CMP_SGE: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_CMP_UGE: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_CMP_SGT: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_CMP_UGT: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_TEST_BIT: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_BOOL_TO_INT: [("src", "expr")],
		LowLevelILOperation.LLIL_ADD_OVERFLOW: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_SYSCALL: [],
		LowLevelILOperation.LLIL_INTRINSIC: [("output", "reg_or_flag_list"), ("intrinsic", "intrinsic"), ("param", "expr")],
		LowLevelILOperation.LLIL_INTRINSIC_SSA: [("output", "reg_or_flag_ssa_list"), ("intrinsic", "intrinsic"), ("param", "expr")],
		LowLevelILOperation.LLIL_BP: [],
		LowLevelILOperation.LLIL_TRAP: [("vector", "int")],
		LowLevelILOperation.LLIL_UNDEF: [],
		LowLevelILOperation.LLIL_UNIMPL: [],
		LowLevelILOperation.LLIL_UNIMPL_MEM: [("src", "expr")],
		LowLevelILOperation.LLIL_FADD: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_FSUB: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_FMUL: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_FDIV: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_FSQRT: [("src", "expr")],
		LowLevelILOperation.LLIL_FNEG: [("src", "expr")],
		LowLevelILOperation.LLIL_FABS: [("src", "expr")],
		LowLevelILOperation.LLIL_FLOAT_TO_INT: [("src", "expr")],
		LowLevelILOperation.LLIL_INT_TO_FLOAT: [("src", "expr")],
		LowLevelILOperation.LLIL_FLOAT_CONV: [("src", "expr")],
		LowLevelILOperation.LLIL_ROUND_TO_INT: [("src", "expr")],
		LowLevelILOperation.LLIL_FLOOR: [("src", "expr")],
		LowLevelILOperation.LLIL_CEIL: [("src", "expr")],
		LowLevelILOperation.LLIL_FTRUNC: [("src", "expr")],
		LowLevelILOperation.LLIL_FCMP_E: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_FCMP_NE: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_FCMP_LT: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_FCMP_LE: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_FCMP_GE: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_FCMP_GT: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_FCMP_O: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_FCMP_UO: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_SET_REG_SSA: [("dest", "reg_ssa"), ("src", "expr")],
		LowLevelILOperation.LLIL_SET_REG_SSA_PARTIAL: [("full_reg", "reg_ssa"), ("dest", "reg"), ("src", "expr")],
		LowLevelILOperation.LLIL_SET_REG_SPLIT_SSA: [("hi", "expr"), ("lo", "expr"), ("src", "expr")],
		LowLevelILOperation.LLIL_SET_REG_STACK_REL_SSA: [("stack", "expr"), ("dest", "expr"), ("top", "expr"), ("src", "expr")],
		LowLevelILOperation.LLIL_SET_REG_STACK_ABS_SSA: [("stack", "expr"), ("dest", "reg"), ("src", "expr")],
		LowLevelILOperation.LLIL_REG_SPLIT_DEST_SSA: [("dest", "reg_ssa")],
		LowLevelILOperation.LLIL_REG_STACK_DEST_SSA: [("src", "reg_stack_ssa_dest_and_src")],
		LowLevelILOperation.LLIL_REG_SSA: [("src", "reg_ssa")],
		LowLevelILOperation.LLIL_REG_SSA_PARTIAL: [("full_reg", "reg_ssa"), ("src", "reg")],
		LowLevelILOperation.LLIL_REG_SPLIT_SSA: [("hi", "reg_ssa"), ("lo", "reg_ssa")],
		LowLevelILOperation.LLIL_REG_STACK_REL_SSA: [("stack", "reg_stack_ssa"), ("src", "expr"), ("top", "expr")],
		LowLevelILOperation.LLIL_REG_STACK_ABS_SSA: [("stack", "reg_stack_ssa"), ("src", "reg")],
		LowLevelILOperation.LLIL_REG_STACK_FREE_REL_SSA: [("stack", "expr"), ("dest", "expr"), ("top", "expr")],
		LowLevelILOperation.LLIL_REG_STACK_FREE_ABS_SSA: [("stack", "expr"), ("dest", "reg")],
		LowLevelILOperation.LLIL_SET_FLAG_SSA: [("dest", "flag_ssa"), ("src", "expr")],
		LowLevelILOperation.LLIL_FLAG_SSA: [("src", "flag_ssa")],
		LowLevelILOperation.LLIL_FLAG_BIT_SSA: [("src", "flag_ssa"), ("bit", "int")],
		LowLevelILOperation.LLIL_CALL_SSA: [("output", "expr"), ("dest", "expr"), ("stack", "expr"), ("param", "expr")],
		LowLevelILOperation.LLIL_SYSCALL_SSA: [("output", "expr"), ("stack", "expr"), ("param", "expr")],
		LowLevelILOperation.LLIL_TAILCALL_SSA: [("output", "expr"), ("dest", "expr"), ("stack", "expr"), ("param", "expr")],
		LowLevelILOperation.LLIL_CALL_OUTPUT_SSA: [("dest_memory", "int"), ("dest", "reg_ssa_list")],
		LowLevelILOperation.LLIL_CALL_STACK_SSA: [("src", "reg_ssa"), ("src_memory", "int")],
		LowLevelILOperation.LLIL_CALL_PARAM: [("src", "expr_list")],
		LowLevelILOperation.LLIL_LOAD_SSA: [("src", "expr"), ("src_memory", "int")],
		LowLevelILOperation.LLIL_STORE_SSA: [("dest", "expr"), ("dest_memory", "int"), ("src_memory", "int"), ("src", "expr")],
		LowLevelILOperation.LLIL_REG_PHI: [("dest", "reg_ssa"), ("src", "reg_ssa_list")],
		LowLevelILOperation.LLIL_REG_STACK_PHI: [("dest", "reg_stack_ssa"), ("src", "reg_stack_ssa_list")],
		LowLevelILOperation.LLIL_FLAG_PHI: [("dest", "flag_ssa"), ("src", "flag_ssa_list")],
		LowLevelILOperation.LLIL_MEM_PHI: [("dest_memory", "int"), ("src_memory", "int_list")]
	}

	@classmethod
	def create(cls, func:'LowLevelILFunction', expr_index:ExpressionIndex, instr_index:Optional[InstructionIndex]=None) -> 'LowLevelILInstruction':
		assert func.arch is not None, "Attempted to create IL instruction with function missing an Architecture"
		inst = core.BNGetLowLevelILByIndex(func.handle, expr_index)
		assert inst is not None, "core.BNGetLowLevelILByIndex returned None"
		core_inst = CoreLowLevelILInstruction.from_BNLowLevelILInstruction(inst)
		return ILInstruction[core_inst.operation](func, expr_index, core_inst, instr_index)  # type: ignore

	def __str__(self):
		tokens = self.tokens
		if tokens is None:
			return "invalid"
		result = ""
		for token in tokens:
			result += token.text
		return result

	def __repr__(self):
		return f"<llil: {self}>"

	def __eq__(self, other:'LowLevelILInstruction') -> bool:
		if not isinstance(other, LowLevelILInstruction):
			return NotImplemented
		return self.function == other.function and self.expr_index == other.expr_index

	def __ne__(self, other:'LowLevelILInstruction') -> bool:
		if not isinstance(other, LowLevelILInstruction):
			return NotImplemented
		return not (self == other)

	def __lt__(self, other:'LowLevelILInstruction') -> bool:
		if not isinstance(other, LowLevelILInstruction):
			return NotImplemented
		return self.function == other.function and self.expr_index < other.expr_index

	def __le__(self, other:'LowLevelILInstruction') -> bool:
		if not isinstance(other, LowLevelILInstruction):
			return NotImplemented
		return self.function == other.function and self.expr_index <= other.expr_index

	def __gt__(self, other:'LowLevelILInstruction') -> bool:
		if not isinstance(other, LowLevelILInstruction):
			return NotImplemented
		return self.function == other.function and self.expr_index > other.expr_index

	def __ge__(self, other:'LowLevelILInstruction') -> bool:
		if not isinstance(other, LowLevelILInstruction):
			return NotImplemented
		return self.function == other.function and self.expr_index >= other.expr_index

	def __hash__(self):
		return hash((self.function, self.expr_index))

	@property
	def size(self) -> int:
		return self.instr.size

	@property
	def address(self) -> int:
		return self.instr.address

	@property
	def operation(self) -> LowLevelILOperation:
		return self.instr.operation

	@property
	def source_operand(self) -> Optional[ExpressionIndex]:
		return self.instr.source_operand

	@property
	def tokens(self) -> TokenList:
		"""LLIL tokens (read-only)"""
		count = ctypes.c_ulonglong()
		assert self.function.arch is not None, f"self.function.arch is None"
		tokens = ctypes.POINTER(core.BNInstructionTextToken)()
		result = core.BNGetLowLevelILExprText(self.function.handle, self.function.arch.handle,
			self.expr_index, tokens, count)
		assert result, "core.BNGetLowLevelILExprText returned False"
		try:
			return function.InstructionTextToken._from_core_struct(tokens, count.value)
		finally:
			core.BNFreeInstructionText(tokens, count.value)

	@property
	def il_basic_block(self) -> 'LowLevelILBasicBlock':
		"""IL basic block object containing this expression (read-only) (only available on finalized functions)"""
		assert self.function.source_function is not None
		view = self.function.source_function.view
		core_block = core.BNGetLowLevelILBasicBlockForInstruction(self.function.handle, self.instr_index)
		assert core_block is not None, "BNGetLowLevelILBasicBlockForInstruction returned None"
		return LowLevelILBasicBlock(core_block, self.function, view)

	@property
	def ssa_form(self) -> 'LowLevelILInstruction':
		"""SSA form of expression (read-only)"""
		ssa_func = self.function.ssa_form
		assert ssa_func is not None
		return LowLevelILInstruction.create(ssa_func,
			core.BNGetLowLevelILSSAExprIndex(self.function.handle, self.expr_index),
			core.BNGetLowLevelILSSAInstructionIndex(self.function.handle, self.instr_index) if self.instr_index is not None else None)

	@property
	def non_ssa_form(self) -> 'LowLevelILInstruction':
		"""Non-SSA form of expression (read-only)"""
		non_ssa_function = self.function.non_ssa_form
		assert non_ssa_function is not None
		return LowLevelILInstruction.create(non_ssa_function,
			core.BNGetLowLevelILNonSSAExprIndex(self.function.handle, self.expr_index),
			core.BNGetLowLevelILNonSSAInstructionIndex(self.function.handle, self.instr_index) if self.instr_index is not None else None)

	@property
	def medium_level_il(self) -> Optional['mediumlevelil.MediumLevelILInstruction']:
		"""Gets the medium level IL expression corresponding to this expression (may be None for eliminated instructions)"""
		expr = self.function.get_medium_level_il_expr_index(self.expr_index)
		if expr is None:
			return None
		mlil_func = self.function.medium_level_il
		assert mlil_func is not None, "self.function.medium_level_il is None"
		return mediumlevelil.MediumLevelILInstruction.create(mlil_func, expr)

	@property
	def mlil(self) -> Optional['mediumlevelil.MediumLevelILInstruction']:
		return self.medium_level_il

	@property
	def mlils(self) -> List['mediumlevelil.MediumLevelILInstruction']:
		result = []
		for expr in self.function.get_medium_level_il_expr_indexes(self.expr_index):
			result.append(mediumlevelil.MediumLevelILInstruction.create(self.function.medium_level_il, expr))
		return result

	@property
	def mapped_medium_level_il(self) -> Optional['mediumlevelil.MediumLevelILInstruction']:
		"""Gets the mapped medium level IL expression corresponding to this expression"""
		expr = self.function.get_mapped_medium_level_il_expr_index(self.expr_index)
		if expr is None:
			return None
		return mediumlevelil.MediumLevelILInstruction.create(self.function.mapped_medium_level_il, expr)

	@property
	def mmlil(self) -> Optional['mediumlevelil.MediumLevelILInstruction']:
		return self.mapped_medium_level_il

	@property
	def high_level_il(self) -> Optional['highlevelil.HighLevelILInstruction']:
		"""Gets the high level IL expression corresponding to this expression (may be None for eliminated instructions)"""
		if self.mlil is None:
			return None
		return self.mlil.hlil

	@property
	def hlil(self) -> Optional['highlevelil.HighLevelILInstruction']:
		return self.high_level_il

	@property
	def hlils(self) -> List['highlevelil.HighLevelILInstruction']:
		result = set()
		for mlil_expr in self.mlils:
			for hlil_expr in mlil_expr.hlils:
				try:
					result.add(hlil_expr)
				except:
					assert False, f"mlil_expr.hlils returned list of lists: {hlil_expr} {type(hlil_expr)}"
		return list(result)

	@property
	def value(self) -> 'variable.RegisterValue':
		"""Value of expression if constant or a known value (read-only)"""
		value = core.BNGetLowLevelILExprValue(self.function.handle, self.expr_index)
		return variable.RegisterValue.from_BNRegisterValue(value, self.function.arch)

	@property
	def possible_values(self) -> 'variable.PossibleValueSet':
		"""Possible values of expression using path-sensitive static data flow analysis (read-only)"""
		value = core.BNGetLowLevelILPossibleExprValues(self.function.handle, self.expr_index, None, 0)
		result = variable.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return []

	@property
	def prefix_operands(self) -> List[LowLevelILOperandType]:
		"""All operands in the expression tree in prefix order"""
		result:List[LowLevelILOperandType] = [LowLevelILOperationAndSize(self.instr.operation, self.instr.size)]
		for operand in self.operands:
			if isinstance(operand, LowLevelILInstruction):
				assert id(self) != id(operand), f"circular reference {operand}({repr(operand)}) is {self}({repr(self)})"
				result.extend(operand.prefix_operands)
			else:
				result.append(operand)
		return result

	@property
	def postfix_operands(self) -> List[LowLevelILOperandType]:
		"""All operands in the expression tree in postfix order"""
		result:List[LowLevelILOperandType] = []
		for operand in self.operands:
			if isinstance(operand, LowLevelILInstruction):
				assert id(self) != id(operand), f"circular reference {operand}({repr(operand)}) is {self}({repr(self)})"
				result.extend(operand.postfix_operands)
			else:
				result.append(operand)
		result.append(LowLevelILOperationAndSize(self.instr.operation, self.instr.size))
		return result

	def get_possible_values(self, options:List[DataFlowQueryOption]=[]) -> variable.PossibleValueSet:
		option_array = (ctypes.c_int * len(options))()
		idx = 0
		for option in options:
			option_array[idx] = option
			idx += 1
		value = core.BNGetLowLevelILPossibleExprValues(self.function.handle, self.expr_index, option_array, len(options))
		result = variable.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_reg_value(self, reg:'architecture.RegisterType') -> variable.RegisterValue:
		if self.function.arch is None:
			raise Exception("Can not call get_reg_value on function with Architecture set to None")
		reg = self.function.arch.get_reg_index(reg)
		value = core.BNGetLowLevelILRegisterValueAtInstruction(self.function.handle, reg, self.instr_index)
		return variable.RegisterValue.from_BNRegisterValue(value, self.function.arch)

	def get_reg_value_after(self, reg:'architecture.RegisterType') -> variable.RegisterValue:
		if self.function.arch is None:
			raise Exception("Can not call get_reg_value_after on function with Architecture set to None")
		reg = self.function.arch.get_reg_index(reg)
		value = core.BNGetLowLevelILRegisterValueAfterInstruction(self.function.handle, reg, self.instr_index)
		return variable.RegisterValue.from_BNRegisterValue(value, self.function.arch)

	def get_possible_reg_values(self, reg:'architecture.RegisterType', options:List[DataFlowQueryOption]=[]) -> 'variable.PossibleValueSet':
		if self.function.arch is None:
			raise Exception("Can not call get_possible_reg_values on function with Architecture set to None")
		reg = self.function.arch.get_reg_index(reg)
		option_array = (ctypes.c_int * len(options))()
		idx = 0
		for option in options:
			option_array[idx] = option
			idx += 1
		value = core.BNGetLowLevelILPossibleRegisterValuesAtInstruction(self.function.handle, reg, self.instr_index,
			option_array, len(options))
		result = variable.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_possible_reg_values_after(self, reg:'architecture.RegisterType', options:List[DataFlowQueryOption]=[]) -> 'variable.PossibleValueSet':
		if self.function.arch is None:
			raise Exception("Can not call get_possible_reg_values_after on function with Architecture set to None")
		reg = self.function.arch.get_reg_index(reg)
		option_array = (ctypes.c_int * len(options))()
		idx = 0
		for option in options:
			option_array[idx] = option
			idx += 1
		value = core.BNGetLowLevelILPossibleRegisterValuesAfterInstruction(self.function.handle, reg, self.instr_index,
			option_array, len(options))
		result = variable.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_flag_value(self, flag:'architecture.FlagType') -> 'variable.RegisterValue':
		if self.function.arch is None:
			raise Exception("Can not call get_flag_value on function with Architecture set to None")
		flag = self.function.arch.get_flag_index(flag)
		value = core.BNGetLowLevelILFlagValueAtInstruction(self.function.handle, flag, self.instr_index)
		result = variable.RegisterValue.from_BNRegisterValue(value, self.function.arch)
		return result

	def get_flag_value_after(self, flag:'architecture.FlagType') -> 'variable.RegisterValue':
		if self.function.arch is None:
			raise Exception("Can not call get_flag_value_after on function with Architecture set to None")
		flag = self.function.arch.get_flag_index(flag)
		value = core.BNGetLowLevelILFlagValueAfterInstruction(self.function.handle, flag, self.instr_index)
		result = variable.RegisterValue.from_BNRegisterValue(value, self.function.arch)
		return result

	def get_possible_flag_values(self, flag:'architecture.FlagType', options:List[DataFlowQueryOption]=[]) -> 'variable.PossibleValueSet':
		if self.function.arch is None:
			raise Exception("Can not call get_possible_flag_values on function with Architecture set to None")
		flag = self.function.arch.get_flag_index(flag)
		option_array = (ctypes.c_int * len(options))()
		idx = 0
		for option in options:
			option_array[idx] = option
			idx += 1
		value = core.BNGetLowLevelILPossibleFlagValuesAtInstruction(self.function.handle, flag, self.instr_index,
			option_array, len(options))
		result = variable.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_possible_flag_values_after(self, flag:'architecture.FlagType', options:List[DataFlowQueryOption]=[]) -> 'variable.PossibleValueSet':
		if self.function.arch is None:
			raise Exception("Can not call get_possible_flag_values_after on function with Architecture set to None")
		flag = self.function.arch.get_flag_index(flag)
		option_array = (ctypes.c_int * len(options))()
		idx = 0
		for option in options:
			option_array[idx] = option
			idx += 1
		value = core.BNGetLowLevelILPossibleFlagValuesAfterInstruction(self.function.handle, flag, self.instr_index,
			option_array, len(options))
		result = variable.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_stack_contents(self, offset:int, size:int) -> 'variable.RegisterValue':
		value = core.BNGetLowLevelILStackContentsAtInstruction(self.function.handle, offset, size, self.instr_index)
		result = variable.RegisterValue.from_BNRegisterValue(value, self.function.arch)
		return result

	def get_stack_contents_after(self, offset:int, size:int) -> 'variable.RegisterValue':
		value = core.BNGetLowLevelILStackContentsAfterInstruction(self.function.handle, offset, size, self.instr_index)
		result = variable.RegisterValue.from_BNRegisterValue(value, self.function.arch)
		return result

	def get_possible_stack_contents(self, offset:int, size:int, options:List[DataFlowQueryOption]=[]) -> variable.PossibleValueSet:
		option_array = (ctypes.c_int * len(options))()
		idx = 0
		for option in options:
			option_array[idx] = option
			idx += 1
		value = core.BNGetLowLevelILPossibleStackContentsAtInstruction(self.function.handle, offset, size, self.instr_index,
			option_array, len(options))
		result = variable.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_possible_stack_contents_after(self, offset:int, size:int, options:List[DataFlowQueryOption]=[]) -> variable.PossibleValueSet:
		option_array = (ctypes.c_int * len(options))()
		idx = 0
		for option in options:
			option_array[idx] = option
			idx += 1
		value = core.BNGetLowLevelILPossibleStackContentsAfterInstruction(self.function.handle, offset, size, self.instr_index,
			option_array, len(options))
		result = variable.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	@property
	def flags(self) -> Optional['architecture.FlagWriteTypeName']:
		return self.function.arch.get_flag_write_type_name(architecture.FlagWriteTypeIndex(self.instr.flags))

	def get_reg(self, operand_index:int) -> ILRegister:
		return ILRegister(self.function.arch, architecture.RegisterIndex(self.instr.operands[operand_index]))

	def get_flag(self, operand_index:int) -> ILFlag:
		return ILFlag(self.function.arch, architecture.FlagIndex(self.instr.operands[operand_index]))

	def get_intrinsic(self, operand_index:int) -> ILIntrinsic:
		return ILIntrinsic(self.function.arch, architecture.IntrinsicIndex(self.instr.operands[operand_index]))

	def get_reg_stack(self, operand_index:int) -> ILRegisterStack:
		return ILRegisterStack(self.function.arch, architecture.RegisterStackIndex(self.instr.operands[operand_index]))

	def get_int(self, operand_index:int) -> int:
		return (self.instr.operands[operand_index] & ((1 << 63) - 1)) - (self.instr.operands[operand_index] & (1 << 63))

	def get_target_map(self, operand_index:int) -> Mapping[int, int]:
		count = ctypes.c_ulonglong()
		operand_list = core.BNLowLevelILGetOperandList(self.function.handle, self.expr_index, operand_index, count)
		assert operand_list is not None, "core.BNLowLevelILGetOperandList returned None"
		try:
			value:Mapping[int, int] = {}
			for j in range(count.value // 2):
				key = operand_list[j * 2]
				target = operand_list[(j * 2) + 1]
				value[key] = target
			return value
		finally:
			core.BNLowLevelILFreeOperandList(operand_list)

	def get_float(self, operand_index:int) -> Union[int, float]:
		if self.instr.size == 4:
			return struct.unpack("f", struct.pack("I", self.instr.operands[operand_index] & 0xffffffff))[0]
		elif self.instr.size == 8:
			return struct.unpack("d", struct.pack("Q", self.instr.operands[operand_index]))[0]
		else:
			return self.instr.operands[operand_index]

	def get_expr(self, operand_index:int) -> 'LowLevelILInstruction':
		return LowLevelILInstruction.create(self.function, self.instr.operands[operand_index], self.instr_index)

	def get_reg_stack_adjust(self, operand_index:int) -> Mapping['architecture.RegisterStackName', int]:
		count = ctypes.c_ulonglong()
		operand_list = core.BNLowLevelILGetOperandList(self.function.handle, self.expr_index, operand_index, count)
		assert operand_list is not None, "core.BNLowLevelILGetOperandList returned None"
		result:Mapping['architecture.RegisterStackName', int] = {}
		try:
			for j in range(count.value // 2):
				reg_stack = operand_list[j * 2]
				adjust = operand_list[(j * 2) + 1]
				if adjust & 0x80000000:
					adjust |= ~0x80000000
				result[self.function.arch.get_reg_stack_name(reg_stack)] = adjust
			return result
		finally:
			core.BNLowLevelILFreeOperandList(operand_list)

	def get_flag_ssa(self, operand_index1:int, operand_index2:int) -> SSAFlag:
		return SSAFlag(ILFlag(self.function.arch, architecture.FlagIndex(self.instr.operands[operand_index1])),
			self.instr.operands[operand_index2])

	def get_reg_ssa(self, operand_index1:int, operand_index2:int) -> SSARegister:
		return SSARegister(ILRegister(self.function.arch,
			architecture.RegisterIndex(self.instr.operands[operand_index1])),
			self.instr.operands[operand_index2])

	def get_reg_stack_ssa(self, operand_index1:int, operand_index2:int) -> SSARegisterStack:
		reg_stack = ILRegisterStack(self.function.arch,
			architecture.RegisterStackIndex(self.instr.operands[operand_index1]))
		return SSARegisterStack(reg_stack, self.instr.operands[operand_index2])

	def get_sem_class(self, operand_index:int) -> Optional[ILSemanticFlagClass]:
		if self.instr.operands[operand_index] == 0:
			return None
		return ILSemanticFlagClass(self.function.arch,
			architecture.SemanticClassIndex(self.instr.operands[operand_index]))

	def get_sem_group(self, operand_index:int) -> ILSemanticFlagGroup:
		return ILSemanticFlagGroup(self.function.arch,
			architecture.SemanticGroupIndex(self.instr.operands[operand_index]))

	def get_cond(self, operand_index:int) -> LowLevelILFlagCondition:
		return LowLevelILFlagCondition(self.instr.operands[operand_index])

	def get_int_list(self, operand_index:int) -> List[int]:
		count = ctypes.c_ulonglong()
		operand_list = core.BNLowLevelILGetOperandList(self.function.handle, self.expr_index, operand_index, count)
		assert operand_list is not None, "core.BNLowLevelILGetOperandList returned None"
		result:List[int] = []
		try:
			for j in range(count.value):
				result.append(operand_list[j])
			return result
		finally:
			core.BNLowLevelILFreeOperandList(operand_list)

	def get_expr_list(self, operand_index:int) -> List['LowLevelILInstruction']:
		count = ctypes.c_ulonglong()
		operand_list = core.BNLowLevelILGetOperandList(self.function.handle, self.expr_index, operand_index, count)
		assert operand_list is not None, "core.BNLowLevelILGetOperandList returned None"
		result = []
		try:
			for j in range(count.value):
				result.append(LowLevelILInstruction.create(self.function, operand_list[j], None))
			return result
		finally:
			core.BNLowLevelILFreeOperandList(operand_list)

	def get_reg_or_flag_list(self, operand_index:int) -> List[Union[ILFlag, ILRegister]]:
		count = ctypes.c_ulonglong()
		operand_list = core.BNLowLevelILGetOperandList(self.function.handle, self.expr_index, operand_index, count)
		assert operand_list is not None, "core.BNLowLevelILGetOperandList returned None"

		result:List[Union[ILFlag, ILRegister]] = []
		try:
			for j in range(count.value):
				if (operand_list[j] & (1 << 32)) != 0:
					result.append(ILFlag(self.function.arch, operand_list[j] & 0xffffffff))
				else:
					result.append(ILRegister(self.function.arch, operand_list[j] & 0xffffffff))
			return result
		finally:
			core.BNLowLevelILFreeOperandList(operand_list)

	def get_reg_ssa_list(self, operand_index:int) -> List[SSARegister]:
		count = ctypes.c_ulonglong()
		operand_list = core.BNLowLevelILGetOperandList(self.function.handle, self.expr_index, operand_index, count)
		assert operand_list is not None, "core.BNLowLevelILGetOperandList returned None"
		result = []
		try:
			for j in range(count.value // 2):
				reg = operand_list[j * 2]
				reg_version = operand_list[(j * 2) + 1]
				result.append(SSARegister(ILRegister(self.function.arch, reg), reg_version))
			return result
		finally:
			core.BNLowLevelILFreeOperandList(operand_list)

	def get_reg_stack_ssa_list(self, operand_index:int) -> List[SSARegisterStack]:
		count = ctypes.c_ulonglong()
		operand_list = core.BNLowLevelILGetOperandList(self.function.handle, self.expr_index, operand_index, count)
		assert operand_list is not None, "core.BNLowLevelILGetOperandList returned None"
		result:List[SSARegisterStack] = []
		try:
			for j in range(count.value // 2):
				reg_stack = operand_list[j * 2]
				reg_version = operand_list[(j * 2) + 1]
				result.append(SSARegisterStack(ILRegisterStack(self.function.arch, reg_stack), reg_version))
			return result
		finally:
			core.BNLowLevelILFreeOperandList(operand_list)

	def get_flag_ssa_list(self, operand_index:int) -> List[SSAFlag]:
		count = ctypes.c_ulonglong()
		operand_list = core.BNLowLevelILGetOperandList(self.function.handle, self.expr_index, operand_index, count)
		assert operand_list is not None, "core.BNLowLevelILGetOperandList returned None"
		try:
			result:List[SSAFlag] = []
			for j in range(count.value // 2):
				flag = operand_list[j * 2]
				flag_version = operand_list[(j * 2) + 1]
				result.append(SSAFlag(ILFlag(self.function.arch, flag), flag_version))
			return result
		finally:
			core.BNLowLevelILFreeOperandList(operand_list)

	def get_reg_or_flag_ssa_list(self, operand_index:int) -> List[SSARegisterOrFlag]:
		count = ctypes.c_ulonglong()
		operand_list = core.BNLowLevelILGetOperandList(self.function.handle, self.expr_index, operand_index, count)
		assert operand_list is not None, "core.BNLowLevelILGetOperandList returned None"
		result:List[SSARegisterOrFlag] = []
		try:
			for j in range(count.value // 2):
				if (operand_list[j * 2] & (1 << 32)) != 0:
					reg_or_flag = ILFlag(self.function.arch, operand_list[j * 2] & 0xffffffff)
				else:
					reg_or_flag = ILRegister(self.function.arch, operand_list[j * 2] & 0xffffffff)
				reg_version = operand_list[(j * 2) + 1]
				result.append(SSARegisterOrFlag(reg_or_flag, reg_version))
			return result
		finally:
			core.BNLowLevelILFreeOperandList(operand_list)


@dataclass(frozen=True, repr=False)
class LowLevelILBinaryBase(LowLevelILInstruction, BinaryOperation):

	@property
	def left(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def right(self) -> LowLevelILInstruction:
		return self.get_expr(1)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.left, self.right]


@dataclass(frozen=True, repr=False)
class LowLevelILComparisonBase(LowLevelILBinaryBase):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILCarryBase(LowLevelILInstruction, Carry):

	@property
	def left(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def right(self) -> LowLevelILInstruction:
		return self.get_expr(1)

	@property
	def carry(self) -> LowLevelILInstruction:
		return self.get_expr(2)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.left, self.right, self.carry]


@dataclass(frozen=True, repr=False)
class LowLevelILUnaryBase(LowLevelILInstruction, UnaryOperation):

	@property
	def src(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILConstantBase(LowLevelILInstruction, Constant):

	def __int__(self):
		return self.constant

	def __bool__(self):
		return self.constant != 0

	def __eq__(self, other):
		return self.constant == other.constant

	def __ne__(self, other):
		return self.constant != other.constant

	def __lt__(self, other):
		return self.constant < other.constant

	def __gt__(self, other):
		return self.constant > other.constant

	def __le__(self, other):
		return self.constant <= other.constant

	def __ge__(self, other):
		return self.constant >= other.constant

	@property
	def constant(self) -> int:
		return self.get_int(0)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.constant]


@dataclass(frozen=True, repr=False)
class LowLevelILNop(LowLevelILInstruction):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILPop(LowLevelILInstruction, StackOperation):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILNoret(LowLevelILInstruction, Terminal):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILSyscall(LowLevelILInstruction, Call):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILBp(LowLevelILInstruction, Terminal):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILUndef(LowLevelILInstruction, Terminal):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILUnimpl(LowLevelILInstruction):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILNeg(LowLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILNot(LowLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILSx(LowLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILZx(LowLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILLow_part(LowLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILJump(LowLevelILInstruction, Terminal):

	@property
	def dest(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.dest]


@dataclass(frozen=True, repr=False)
class LowLevelILCall(LowLevelILInstruction, Call):

	@property
	def dest(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.dest]


@dataclass(frozen=True, repr=False)
class LowLevelILTailcall(LowLevelILInstruction, Call):

	@property
	def dest(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.dest]


@dataclass(frozen=True, repr=False)
class LowLevelILRet(LowLevelILInstruction, Return):

	@property
	def dest(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.dest]


@dataclass(frozen=True, repr=False)
class LowLevelILUnimpl_mem(LowLevelILInstruction, Memory):

	@property
	def src(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILFsqrt(LowLevelILInstruction, FloatingPoint, Arithmetic):

	@property
	def src(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILFneg(LowLevelILInstruction, FloatingPoint, Arithmetic):

	@property
	def src(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILFabs(LowLevelILInstruction, FloatingPoint, Arithmetic):

	@property
	def src(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILFloat_to_int(LowLevelILInstruction, FloatingPoint, Arithmetic):

	@property
	def src(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILInt_to_float(LowLevelILInstruction, FloatingPoint, Arithmetic):

	@property
	def src(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILFloat_conv(LowLevelILInstruction, FloatingPoint, Arithmetic):

	@property
	def src(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILRound_to_int(LowLevelILInstruction, FloatingPoint, Arithmetic):

	@property
	def src(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILFloor(LowLevelILInstruction, FloatingPoint, Arithmetic):

	@property
	def src(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILCeil(LowLevelILInstruction, FloatingPoint, Arithmetic):

	@property
	def src(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILFtrunc(LowLevelILInstruction, FloatingPoint, Arithmetic):

	@property
	def src(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILLoad(LowLevelILInstruction, Load):

	@property
	def src(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILPush(LowLevelILInstruction, StackOperation):

	@property
	def src(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILReg(LowLevelILInstruction):

	@property
	def src(self) -> ILRegister:
		return self.get_reg(0)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILReg_stack_pop(LowLevelILInstruction, RegisterStack):

	@property
	def stack(self) -> ILRegisterStack:
		return self.get_reg_stack(0)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.stack]


@dataclass(frozen=True, repr=False)
class LowLevelILReg_stack_free_reg(LowLevelILInstruction, RegisterStack):

	@property
	def dest(self) -> ILRegister:
		return self.get_reg(0)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.dest]


@dataclass(frozen=True, repr=False)
class LowLevelILConst(LowLevelILConstantBase):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILConst_ptr(LowLevelILConstantBase):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILFloat_const(LowLevelILConstantBase, FloatingPoint):

	@property
	def constant(self) -> Union[int, float]:
		return self.get_float(0)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.constant]


@dataclass(frozen=True, repr=False)
class LowLevelILFlag(LowLevelILInstruction):

	@property
	def src(self) -> ILFlag:
		return self.get_flag(0)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILGoto(LowLevelILInstruction, Terminal):

	@property
	def dest(self) -> int:
		return self.get_int(0)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.dest]


@dataclass(frozen=True, repr=False)
class LowLevelILFlag_group(LowLevelILInstruction):

	@property
	def semantic_group(self) -> ILSemanticFlagGroup:
		return self.get_sem_group(0)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.semantic_group]


@dataclass(frozen=True, repr=False)
class LowLevelILBool_to_int(LowLevelILInstruction):

	@property
	def src(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILTrap(LowLevelILInstruction, Terminal):

	@property
	def vector(self) -> int:
		return self.get_int(0)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.vector]


@dataclass(frozen=True, repr=False)
class LowLevelILReg_split_dest_ssa(LowLevelILInstruction, SSA):

	@property
	def dest(self) -> SSARegister:
		return self.get_reg_ssa(0, 1)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.dest]


@dataclass(frozen=True, repr=False)
class LowLevelILReg_stack_dest_ssa(LowLevelILInstruction, RegisterStack, SSA):

	@property
	def dest(self) -> SSARegisterStack:
		return self.get_reg_stack_ssa(0, 1)

	@property
	def src(self) -> SSARegisterStack:
		return self.get_reg_stack_ssa(0, 2)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.dest, self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILReg_ssa(LowLevelILInstruction, SSA):

	@property
	def src(self) -> SSARegister:
		return self.get_reg_ssa(0, 1)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILFlag_ssa(LowLevelILInstruction, SSA):

	@property
	def src(self) -> SSAFlag:
		return self.get_flag_ssa(0, 1)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILCall_param(LowLevelILInstruction, SSA):

	@property
	def src(self) -> List['LowLevelILInstruction']:
		return self.get_expr_list(0)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILMem_phi(LowLevelILInstruction, Memory, SSA):

	@property
	def dest_memory(self) -> int:
		return self.get_int(0)

	@property
	def src_memory(self) -> List[int]:
		return self.get_int_list(1)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.dest_memory, self.src_memory]


@dataclass(frozen=True, repr=False)
class LowLevelILSet_reg(LowLevelILInstruction, SetReg):

	@property
	def dest(self) -> ILRegister:
		return self.get_reg(0)

	@property
	def src(self) -> LowLevelILInstruction:
		return self.get_expr(1)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.dest, self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILReg_stack_push(LowLevelILInstruction, RegisterStack):

	@property
	def stack(self) -> ILRegisterStack:
		return self.get_reg_stack(0)

	@property
	def src(self) -> LowLevelILInstruction:
		return self.get_expr(1)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.stack, self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILSet_flag(LowLevelILInstruction):

	@property
	def dest(self) -> ILFlag:
		return self.get_flag(0)

	@property
	def src(self) -> LowLevelILInstruction:
		return self.get_expr(1)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.dest, self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILStore(LowLevelILInstruction, Store):

	@property
	def dest(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def src(self) -> LowLevelILInstruction:
		return self.get_expr(1)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.dest, self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILReg_split(LowLevelILInstruction):

	@property
	def hi(self) -> ILRegister:
		return self.get_reg(0)

	@property
	def lo(self) -> ILRegister:
		return self.get_reg(1)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.hi, self.lo]


@dataclass(frozen=True, repr=False)
class LowLevelILReg_stack_rel(LowLevelILInstruction, RegisterStack):

	@property
	def stack(self) -> ILRegisterStack:
		return self.get_reg_stack(0)

	@property
	def src(self) -> LowLevelILInstruction:
		return self.get_expr(1)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.stack, self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILReg_stack_free_rel(LowLevelILInstruction, RegisterStack):

	@property
	def stack(self) -> ILRegisterStack:
		return self.get_reg_stack(0)

	@property
	def dest(self) -> LowLevelILInstruction:
		return self.get_expr(1)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.stack, self.dest]


@dataclass(frozen=True, repr=False)
class LowLevelILExtern_ptr(LowLevelILConstantBase):

	@property
	def constant(self) -> int:
		return self.get_int(0)

	@property
	def offset(self) -> int:
		return self.get_int(1)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.constant, self.offset]


@dataclass(frozen=True, repr=False)
class LowLevelILFlag_bit(LowLevelILInstruction):

	@property
	def src(self) -> ILFlag:
		return self.get_flag(0)

	@property
	def bit(self) -> int:
		return self.get_int(1)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.src, self.bit]


@dataclass(frozen=True, repr=False)
class LowLevelILAdd(LowLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILSub(LowLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILAnd(LowLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILOr(LowLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILXor(LowLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILLsl(LowLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILLsr(LowLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILAsr(LowLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILRol(LowLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILRor(LowLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILMul(LowLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILMulu_dp(LowLevelILBinaryBase, DoublePrecision):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILMuls_dp(LowLevelILBinaryBase, DoublePrecision):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILDivu(LowLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILDivu_dp(LowLevelILBinaryBase, DoublePrecision):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILDivs(LowLevelILBinaryBase, Arithmetic, Signed):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILDivs_dp(LowLevelILBinaryBase, DoublePrecision, Signed):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILModu(LowLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILModu_dp(LowLevelILBinaryBase, DoublePrecision):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILMods(LowLevelILBinaryBase, Arithmetic, Signed):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILMods_dp(LowLevelILBinaryBase, DoublePrecision, Signed):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILCmp_e(LowLevelILComparisonBase):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILCmp_ne(LowLevelILComparisonBase):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILCmp_slt(LowLevelILComparisonBase, Signed):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILCmp_ult(LowLevelILComparisonBase):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILCmp_sle(LowLevelILComparisonBase,Signed):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILCmp_ule(LowLevelILComparisonBase):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILCmp_sge(LowLevelILComparisonBase, Signed):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILCmp_uge(LowLevelILComparisonBase):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILCmp_sgt(LowLevelILComparisonBase, Signed):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILCmp_ugt(LowLevelILComparisonBase):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILTest_bit(LowLevelILBinaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILFadd(LowLevelILBinaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILFsub(LowLevelILBinaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILFmul(LowLevelILBinaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILFdiv(LowLevelILBinaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILFcmp_e(LowLevelILInstruction, Comparison, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILFcmp_ne(LowLevelILInstruction, Comparison, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILFcmp_lt(LowLevelILInstruction, Comparison, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILFcmp_le(LowLevelILInstruction, Comparison, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILFcmp_ge(LowLevelILInstruction, Comparison, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILFcmp_gt(LowLevelILInstruction, Comparison, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILFcmp_o(LowLevelILInstruction, Comparison, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILFcmp_uo(LowLevelILInstruction, Comparison, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILJump_to(LowLevelILInstruction):

	@property
	def dest(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def targets(self) -> Mapping[int, int]:
		return self.get_target_map(1)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.dest, self.targets]


@dataclass(frozen=True, repr=False)
class LowLevelILFlag_cond(LowLevelILInstruction):

	@property
	def condition(self) -> LowLevelILFlagCondition:
		return self.get_cond(0)

	@property
	def semantic_class(self) -> Optional[ILSemanticFlagClass]:
		return self.get_sem_class(1)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.condition, self.semantic_class]


@dataclass(frozen=True, repr=False)
class LowLevelILAdd_overflow(LowLevelILBinaryBase, Arithmetic):

	@property
	def left(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def right(self) -> LowLevelILInstruction:
		return self.get_expr(1)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.left, self.right]


@dataclass(frozen=True, repr=False)
class LowLevelILSet_reg_ssa(LowLevelILInstruction, SetReg, SSA):

	@property
	def dest(self) -> SSARegister:
		return self.get_reg_ssa(0, 1)

	@property
	def src(self) -> LowLevelILInstruction:
		return self.get_expr(2)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.dest, self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILReg_ssa_partial(LowLevelILInstruction, SetReg, SSA):

	@property
	def full_reg(self) -> SSARegister:
		return self.get_reg_ssa(0, 1)

	@property
	def src(self) -> ILRegister:
		return self.get_reg(2)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.full_reg, self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILReg_split_ssa(LowLevelILInstruction, SetReg, SSA):

	@property
	def hi(self) -> SSARegister:
		return self.get_reg_ssa(0, 1)

	@property
	def lo(self) -> SSARegister:
		return self.get_reg_ssa(2, 3)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.hi, self.lo]


@dataclass(frozen=True, repr=False)
class LowLevelILReg_stack_abs_ssa(LowLevelILInstruction, RegisterStack, SSA):

	@property
	def stack(self) -> SSARegisterStack:
		return self.get_reg_stack_ssa(0, 1)

	@property
	def src(self) -> ILRegister:
		return self.get_reg(2)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.stack, self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILReg_stack_free_abs_ssa(LowLevelILInstruction, RegisterStack):

	@property
	def stack(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def dest(self) -> ILRegister:
		return self.get_reg(1)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.stack, self.dest]


@dataclass(frozen=True, repr=False)
class LowLevelILSet_flag_ssa(LowLevelILInstruction, SSA):

	@property
	def dest(self) -> SSAFlag:
		return self.get_flag_ssa(0, 1)

	@property
	def src(self) -> LowLevelILInstruction:
		return self.get_expr(2)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.dest, self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILFlag_bit_ssa(LowLevelILInstruction, SSA):

	@property
	def src(self) -> SSAFlag:
		return self.get_flag_ssa(0, 1)

	@property
	def bit(self) -> int:
		return self.get_int(2)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.src, self.bit]


@dataclass(frozen=True, repr=False)
class LowLevelILCall_output_ssa(LowLevelILInstruction, SSA):

	@property
	def dest_memory(self) -> int:
		return self.get_int(0)

	@property
	def dest(self) -> List[SSARegister]:
		return self.get_reg_ssa_list(1)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.dest_memory, self.dest]


@dataclass(frozen=True, repr=False)
class LowLevelILCall_stack_ssa(LowLevelILInstruction, SSA):

	@property
	def src(self) -> SSARegister:
		return self.get_reg_ssa(0, 1)

	@property
	def src_memory(self) -> int:
		return self.get_int(2)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.src, self.src_memory]


@dataclass(frozen=True, repr=False)
class LowLevelILLoad_ssa(LowLevelILInstruction, Load, SSA):

	@property
	def src(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def src_memory(self) -> int:
		return self.get_int(1)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.src, self.src_memory]


@dataclass(frozen=True, repr=False)
class LowLevelILReg_phi(LowLevelILInstruction, SSA):

	@property
	def dest(self) -> SSARegister:
		return self.get_reg_ssa(0, 1)

	@property
	def src(self) -> List[SSARegister]:
		return self.get_reg_ssa_list(2)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.dest, self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILReg_stack_phi(LowLevelILInstruction, RegisterStack, SSA):

	@property
	def dest(self) -> SSARegisterStack:
		return self.get_reg_stack_ssa(0, 1)

	@property
	def src(self) -> List[SSARegisterStack]:
		return self.get_reg_stack_ssa_list(2)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.dest, self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILFlag_phi(LowLevelILInstruction, SSA):

	@property
	def dest(self) -> SSAFlag:
		return self.get_flag_ssa(0, 1)

	@property
	def src(self) -> List[SSAFlag]:
		return self.get_flag_ssa_list(2)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.dest, self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILSet_reg_split(LowLevelILInstruction, SetReg):

	@property
	def hi(self) -> ILRegister:
		return self.get_reg(0)

	@property
	def lo(self) -> ILRegister:
		return self.get_reg(1)

	@property
	def src(self) -> LowLevelILInstruction:
		return self.get_expr(2)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.hi, self.lo, self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILSet_reg_stack_rel(LowLevelILInstruction, RegisterStack):

	@property
	def stack(self) -> ILRegisterStack:
		return self.get_reg_stack(0)

	@property
	def dest(self) -> LowLevelILInstruction:
		return self.get_expr(1)

	@property
	def src(self) -> LowLevelILInstruction:
		return self.get_expr(2)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.stack, self.dest, self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILSbb(LowLevelILCarryBase):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILAdc(LowLevelILCarryBase):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILRlc(LowLevelILCarryBase):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILRrc(LowLevelILCarryBase):
	pass


@dataclass(frozen=True, repr=False)
class LowLevelILCall_stack_adjust(LowLevelILInstruction, Call):

	@property
	def dest(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def stack_adjustment(self) -> int:
		return self.get_int(1)

	@property
	def reg_stack_adjustments(self) -> Mapping['architecture.RegisterStackName', int]:
		return self.get_reg_stack_adjust(2)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.dest, self.stack_adjustment, self.reg_stack_adjustments]


@dataclass(frozen=True, repr=False)
class LowLevelILIf(LowLevelILInstruction, ControlFlow):

	@property
	def condition(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def true(self) -> int:
		return self.get_int(1)

	@property
	def false(self) -> int:
		return self.get_int(2)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.condition, self.true, self.false]


@dataclass(frozen=True, repr=False)
class LowLevelILIntrinsic(LowLevelILInstruction):

	@property
	def output(self) -> List[Union[ILFlag, ILRegister]]:
		return self.get_reg_or_flag_list(0)

	@property
	def intrinsic(self) -> ILIntrinsic:
		return self.get_intrinsic(2)

	@property
	def param(self) -> LowLevelILInstruction:
		return self.get_expr(3)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.output, self.intrinsic, self.param]


@dataclass(frozen=True, repr=False)
class LowLevelILIntrinsic_ssa(LowLevelILInstruction, SSA):

	@property
	def output(self) -> List[SSARegisterOrFlag]:
		return self.get_reg_or_flag_ssa_list(0)

	@property
	def intrinsic(self) -> ILIntrinsic:
		return self.get_intrinsic(2)

	@property
	def param(self) -> LowLevelILInstruction:
		return self.get_expr(3)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.output, self.intrinsic, self.param]


@dataclass(frozen=True, repr=False)
class LowLevelILSet_reg_ssa_partial(LowLevelILInstruction, SetReg, SSA):

	@property
	def full_reg(self) -> SSARegister:
		return self.get_reg_ssa(0, 1)

	@property
	def dest(self) -> ILRegister:
		return self.get_reg(2)

	@property
	def src(self) -> LowLevelILInstruction:
		return self.get_expr(3)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.full_reg, self.dest, self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILSet_reg_split_ssa(LowLevelILInstruction, SetReg, SSA):

	@property
	def hi(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def lo(self) -> LowLevelILInstruction:
		return self.get_expr(1)

	@property
	def src(self) -> LowLevelILInstruction:
		return self.get_expr(2)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.hi, self.lo, self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILSet_reg_stack_abs_ssa(LowLevelILInstruction, RegisterStack, SSA):
	@property
	def stack(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def dest(self) -> ILRegister:
		return self.get_reg(1)

	@property
	def src(self) -> LowLevelILInstruction:
		return self.get_expr(2)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.stack, self.dest, self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILReg_stack_rel_ssa(LowLevelILInstruction, RegisterStack, SSA):

	@property
	def stack(self) -> SSARegisterStack:
		return self.get_reg_stack_ssa(0, 1)

	@property
	def src(self) -> LowLevelILInstruction:
		return self.get_expr(2)

	@property
	def top(self) -> LowLevelILInstruction:
		return self.get_expr(3)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.stack, self.src, self.top]


@dataclass(frozen=True, repr=False)
class LowLevelILReg_stack_free_rel_ssa(LowLevelILInstruction, RegisterStack, SSA):

	@property
	def stack(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def dest(self) -> LowLevelILInstruction:
		return self.get_expr(1)

	@property
	def top(self) -> LowLevelILInstruction:
		return self.get_expr(2)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.stack, self.dest, self.top]


@dataclass(frozen=True, repr=False)
class LowLevelILSyscall_ssa(LowLevelILInstruction, Call, SSA):

	@property
	def output(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def stack(self) -> LowLevelILInstruction:
		return self.get_expr(1)

	@property
	def param(self) -> LowLevelILInstruction:
		return self.get_expr(2)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.output, self.stack, self.param]


@dataclass(frozen=True, repr=False)
class LowLevelILSet_reg_stack_rel_ssa(LowLevelILInstruction, RegisterStack, SSA):

	@property
	def stack(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def dest(self) -> LowLevelILInstruction:
		return self.get_expr(1)

	@property
	def top(self) -> LowLevelILInstruction:
		return self.get_expr(2)

	@property
	def src(self) -> LowLevelILInstruction:
		return self.get_expr(3)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.stack, self.dest, self.top, self.src]


@dataclass(frozen=True, repr=False)
class LowLevelILCall_ssa(LowLevelILInstruction, Call, SSA):

	@property
	def output(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def dest(self) -> LowLevelILInstruction:
		return self.get_expr(1)

	@property
	def stack(self) -> LowLevelILInstruction:
		return self.get_expr(2)

	@property
	def param(self) -> LowLevelILInstruction:
		return self.get_expr(3)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.output, self.dest, self.stack, self.param]


@dataclass(frozen=True, repr=False)
class LowLevelILTailcall_ssa(LowLevelILInstruction, Call, SSA, Terminal):

	@property
	def output(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def dest(self) -> LowLevelILInstruction:
		return self.get_expr(1)

	@property
	def stack(self) -> LowLevelILInstruction:
		return self.get_expr(2)

	@property
	def param(self) -> LowLevelILInstruction:
		return self.get_expr(3)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.output, self.dest, self.stack, self.param]


@dataclass(frozen=True, repr=False)
class LowLevelILStore_ssa(LowLevelILInstruction, Store, SSA):

	@property
	def dest(self) -> LowLevelILInstruction:
		return self.get_expr(0)

	@property
	def dest_memory(self) -> int:
		return self.get_int(1)

	@property
	def src_memory(self) -> int:
		return self.get_int(2)

	@property
	def src(self) -> LowLevelILInstruction:
		return self.get_expr(3)

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		return [self.dest, self.dest_memory, self.src_memory, self.src]


ILInstruction:Mapping[LowLevelILOperation, LowLevelILInstruction] = {  # type: ignore
	LowLevelILOperation.LLIL_NOP: LowLevelILNop,                                        #  [],
	LowLevelILOperation.LLIL_SET_REG: LowLevelILSet_reg,                                #  [("dest", "reg"), ("src", "expr")],
	LowLevelILOperation.LLIL_SET_REG_SPLIT: LowLevelILSet_reg_split,                    #  [("hi", "reg"), ("lo", "reg"), ("src", "expr")],
	LowLevelILOperation.LLIL_SET_REG_STACK_REL: LowLevelILSet_reg_stack_rel,            #  [("stack", "reg_stack"), ("dest", "expr"), ("src", "expr")],
	LowLevelILOperation.LLIL_REG_STACK_PUSH: LowLevelILReg_stack_push,                  #  [("stack", "reg_stack"), ("src", "expr")],
	LowLevelILOperation.LLIL_SET_FLAG: LowLevelILSet_flag,                              #  [("dest", "flag"), ("src", "expr")],
	LowLevelILOperation.LLIL_LOAD: LowLevelILLoad,                                      #  [("src", "expr")],
	LowLevelILOperation.LLIL_STORE: LowLevelILStore,                                    #  [("dest", "expr"), ("src", "expr")],
	LowLevelILOperation.LLIL_PUSH: LowLevelILPush,                                      #  [("src", "expr")],
	LowLevelILOperation.LLIL_POP: LowLevelILPop,                                        #  [],
	LowLevelILOperation.LLIL_REG: LowLevelILReg,                                        #  [("src", "reg")],
	LowLevelILOperation.LLIL_REG_SPLIT: LowLevelILReg_split,                            #  [("hi", "reg"), ("lo", "reg")],
	LowLevelILOperation.LLIL_REG_STACK_REL: LowLevelILReg_stack_rel,                    #  [("stack", "reg_stack"), ("src", "expr")],
	LowLevelILOperation.LLIL_REG_STACK_POP: LowLevelILReg_stack_pop,                    #  [("stack", "reg_stack")],
	LowLevelILOperation.LLIL_REG_STACK_FREE_REG: LowLevelILReg_stack_free_reg,          #  [("dest", "reg")],
	LowLevelILOperation.LLIL_REG_STACK_FREE_REL: LowLevelILReg_stack_free_rel,          #  [("stack", "reg_stack"), ("dest", "expr")],
	LowLevelILOperation.LLIL_CONST: LowLevelILConst,                                    #  [("constant", "int")],
	LowLevelILOperation.LLIL_CONST_PTR: LowLevelILConst_ptr,                            #  [("constant", "int")],
	LowLevelILOperation.LLIL_EXTERN_PTR: LowLevelILExtern_ptr,                          #  [("constant", "int"), ("offset", "int")],
	LowLevelILOperation.LLIL_FLOAT_CONST: LowLevelILFloat_const,                        #  [("constant", "float")],
	LowLevelILOperation.LLIL_FLAG: LowLevelILFlag,                                      #  [("src", "flag")],
	LowLevelILOperation.LLIL_FLAG_BIT: LowLevelILFlag_bit,                              #  [("src", "flag"), ("bit", "int")],
	LowLevelILOperation.LLIL_ADD: LowLevelILAdd,                                        #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_ADC: LowLevelILAdc,                                        #  [("left", "expr"), ("right", "expr"), ("carry", "expr")],
	LowLevelILOperation.LLIL_SUB: LowLevelILSub,                                        #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_SBB: LowLevelILSbb,                                        #  [("left", "expr"), ("right", "expr"), ("carry", "expr")],
	LowLevelILOperation.LLIL_AND: LowLevelILAnd,                                        #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_OR: LowLevelILOr,                                          #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_XOR: LowLevelILXor,                                        #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_LSL: LowLevelILLsl,                                        #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_LSR: LowLevelILLsr,                                        #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_ASR: LowLevelILAsr,                                        #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_ROL: LowLevelILRol,                                        #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_RLC: LowLevelILRlc,                                        #  [("left", "expr"), ("right", "expr"), ("carry", "expr")],
	LowLevelILOperation.LLIL_ROR: LowLevelILRor,                                        #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_RRC: LowLevelILRrc,                                        #  [("left", "expr"), ("right", "expr"), ("carry", "expr")],
	LowLevelILOperation.LLIL_MUL: LowLevelILMul,                                        #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_MULU_DP: LowLevelILMulu_dp,                                #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_MULS_DP: LowLevelILMuls_dp,                                #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_DIVU: LowLevelILDivu,                                      #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_DIVU_DP: LowLevelILDivu_dp,                                #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_DIVS: LowLevelILDivs,                                      #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_DIVS_DP: LowLevelILDivs_dp,                                #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_MODU: LowLevelILModu,                                      #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_MODU_DP: LowLevelILModu_dp,                                #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_MODS: LowLevelILMods,                                      #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_MODS_DP: LowLevelILMods_dp,                                #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_NEG: LowLevelILNeg,                                        #  [("src", "expr")],
	LowLevelILOperation.LLIL_NOT: LowLevelILNot,                                        #  [("src", "expr")],
	LowLevelILOperation.LLIL_SX: LowLevelILSx,                                          #  [("src", "expr")],
	LowLevelILOperation.LLIL_ZX: LowLevelILZx,                                          #  [("src", "expr")],
	LowLevelILOperation.LLIL_LOW_PART: LowLevelILLow_part,                              #  [("src", "expr")],
	LowLevelILOperation.LLIL_JUMP: LowLevelILJump,                                      #  [("dest", "expr")],
	LowLevelILOperation.LLIL_JUMP_TO: LowLevelILJump_to,                                #  [("dest", "expr"), ("targets", "target_map")],
	LowLevelILOperation.LLIL_CALL: LowLevelILCall,                                      #  [("dest", "expr")],
	LowLevelILOperation.LLIL_CALL_STACK_ADJUST: LowLevelILCall_stack_adjust,            #  [("dest", "expr"), ("stack_adjustment", "int"), ("reg_stack_adjustments", "reg_stack_adjust")],
	LowLevelILOperation.LLIL_TAILCALL: LowLevelILTailcall,                              #  [("dest", "expr")],
	LowLevelILOperation.LLIL_RET: LowLevelILRet,                                        #  [("dest", "expr")],
	LowLevelILOperation.LLIL_NORET: LowLevelILNoret,                                    #  [],
	LowLevelILOperation.LLIL_IF: LowLevelILIf,                                          #  [("condition", "expr"), ("true", "int"), ("false", "int")],
	LowLevelILOperation.LLIL_GOTO: LowLevelILGoto,                                      #  [("dest", "int")],
	LowLevelILOperation.LLIL_FLAG_COND: LowLevelILFlag_cond,                            #  [("condition", "cond"), ("semantic_class", "sem_class")],
	LowLevelILOperation.LLIL_FLAG_GROUP: LowLevelILFlag_group,                          #  [("semantic_group", "sem_group")],
	LowLevelILOperation.LLIL_CMP_E: LowLevelILCmp_e,                                    #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_CMP_NE: LowLevelILCmp_ne,                                  #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_CMP_SLT: LowLevelILCmp_slt,                                #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_CMP_ULT: LowLevelILCmp_ult,                                #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_CMP_SLE: LowLevelILCmp_sle,                                #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_CMP_ULE: LowLevelILCmp_ule,                                #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_CMP_SGE: LowLevelILCmp_sge,                                #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_CMP_UGE: LowLevelILCmp_uge,                                #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_CMP_SGT: LowLevelILCmp_sgt,                                #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_CMP_UGT: LowLevelILCmp_ugt,                                #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_TEST_BIT: LowLevelILTest_bit,                              #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_BOOL_TO_INT: LowLevelILBool_to_int,                        #  [("src", "expr")],
	LowLevelILOperation.LLIL_ADD_OVERFLOW: LowLevelILAdd_overflow,                      #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_SYSCALL: LowLevelILSyscall,                                #  [],
	LowLevelILOperation.LLIL_INTRINSIC: LowLevelILIntrinsic,                            #  [("output", "reg_or_flag_list"), ("intrinsic", "intrinsic"), ("param", "expr")],
	LowLevelILOperation.LLIL_INTRINSIC_SSA: LowLevelILIntrinsic_ssa,                    #  [("output", "reg_or_flag_ssa_list"), ("intrinsic", "intrinsic"), ("param", "expr")],
	LowLevelILOperation.LLIL_BP: LowLevelILBp,                                          #  [],
	LowLevelILOperation.LLIL_TRAP: LowLevelILTrap,                                      #  [("vector", "int")],
	LowLevelILOperation.LLIL_UNDEF: LowLevelILUndef,                                    #  [],
	LowLevelILOperation.LLIL_UNIMPL: LowLevelILUnimpl,                                  #  [],
	LowLevelILOperation.LLIL_UNIMPL_MEM: LowLevelILUnimpl_mem,                          #  [("src", "expr")],
	LowLevelILOperation.LLIL_FADD: LowLevelILFadd,                                      #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_FSUB: LowLevelILFsub,                                      #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_FMUL: LowLevelILFmul,                                      #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_FDIV: LowLevelILFdiv,                                      #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_FSQRT: LowLevelILFsqrt,                                    #  [("src", "expr")],
	LowLevelILOperation.LLIL_FNEG: LowLevelILFneg,                                      #  [("src", "expr")],
	LowLevelILOperation.LLIL_FABS: LowLevelILFabs,                                      #  [("src", "expr")],
	LowLevelILOperation.LLIL_FLOAT_TO_INT: LowLevelILFloat_to_int,                      #  [("src", "expr")],
	LowLevelILOperation.LLIL_INT_TO_FLOAT: LowLevelILInt_to_float,                      #  [("src", "expr")],
	LowLevelILOperation.LLIL_FLOAT_CONV: LowLevelILFloat_conv,                          #  [("src", "expr")],
	LowLevelILOperation.LLIL_ROUND_TO_INT: LowLevelILRound_to_int,                      #  [("src", "expr")],
	LowLevelILOperation.LLIL_FLOOR: LowLevelILFloor,                                    #  [("src", "expr")],
	LowLevelILOperation.LLIL_CEIL: LowLevelILCeil,                                      #  [("src", "expr")],
	LowLevelILOperation.LLIL_FTRUNC: LowLevelILFtrunc,                                  #  [("src", "expr")],
	LowLevelILOperation.LLIL_FCMP_E: LowLevelILFcmp_e,                                  #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_FCMP_NE: LowLevelILFcmp_ne,                                #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_FCMP_LT: LowLevelILFcmp_lt,                                #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_FCMP_LE: LowLevelILFcmp_le,                                #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_FCMP_GE: LowLevelILFcmp_ge,                                #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_FCMP_GT: LowLevelILFcmp_gt,                                #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_FCMP_O: LowLevelILFcmp_o,                                  #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_FCMP_UO: LowLevelILFcmp_uo,                                #  [("left", "expr"), ("right", "expr")],
	LowLevelILOperation.LLIL_SET_REG_SSA: LowLevelILSet_reg_ssa,                        #  [("dest", "reg_ssa"), ("src", "expr")],
	LowLevelILOperation.LLIL_SET_REG_SSA_PARTIAL: LowLevelILSet_reg_ssa_partial,        #  [("full_reg", "reg_ssa"), ("dest", "reg"), ("src", "expr")],
	LowLevelILOperation.LLIL_SET_REG_SPLIT_SSA: LowLevelILSet_reg_split_ssa,            #  [("hi", "expr"), ("lo", "expr"), ("src", "expr")],
	LowLevelILOperation.LLIL_SET_REG_STACK_REL_SSA: LowLevelILSet_reg_stack_rel_ssa,    #  [("stack", "expr"), ("dest", "expr"), ("top", "expr"), ("src", "expr")],
	LowLevelILOperation.LLIL_SET_REG_STACK_ABS_SSA: LowLevelILSet_reg_stack_abs_ssa,    #  [("stack", "expr"), ("dest", "reg"), ("src", "expr")],
	LowLevelILOperation.LLIL_REG_SPLIT_DEST_SSA: LowLevelILReg_split_dest_ssa,          #  [("dest", "reg_ssa")],
	LowLevelILOperation.LLIL_REG_STACK_DEST_SSA: LowLevelILReg_stack_dest_ssa,          #  [("src", "reg_stack_ssa_dest_and_src")],
	LowLevelILOperation.LLIL_REG_SSA: LowLevelILReg_ssa,                                #  [("src", "reg_ssa")],
	LowLevelILOperation.LLIL_REG_SSA_PARTIAL: LowLevelILReg_ssa_partial,                #  [("full_reg", "reg_ssa"), ("src", "reg")],
	LowLevelILOperation.LLIL_REG_SPLIT_SSA: LowLevelILReg_split_ssa,                    #  [("hi", "reg_ssa"), ("lo", "reg_ssa")],
	LowLevelILOperation.LLIL_REG_STACK_REL_SSA: LowLevelILReg_stack_rel_ssa,            #  [("stack", "reg_stack_ssa"), ("src", "expr"), ("top", "expr")],
	LowLevelILOperation.LLIL_REG_STACK_ABS_SSA: LowLevelILReg_stack_abs_ssa,            #  [("stack", "reg_stack_ssa"), ("src", "reg")],
	LowLevelILOperation.LLIL_REG_STACK_FREE_REL_SSA: LowLevelILReg_stack_free_rel_ssa,  #  [("stack", "expr"), ("dest", "expr"), ("top", "expr")],
	LowLevelILOperation.LLIL_REG_STACK_FREE_ABS_SSA: LowLevelILReg_stack_free_abs_ssa,  #  [("stack", "expr"), ("dest", "reg")],
	LowLevelILOperation.LLIL_SET_FLAG_SSA: LowLevelILSet_flag_ssa,                      #  [("dest", "flag_ssa"), ("src", "expr")],
	LowLevelILOperation.LLIL_FLAG_SSA: LowLevelILFlag_ssa,                              #  [("src", "flag_ssa")],
	LowLevelILOperation.LLIL_FLAG_BIT_SSA: LowLevelILFlag_bit_ssa,                      #  [("src", "flag_ssa"), ("bit", "int")],
	LowLevelILOperation.LLIL_CALL_SSA: LowLevelILCall_ssa,                              #  [("output", "expr"), ("dest", "expr"), ("stack", "expr"), ("param", "expr")],
	LowLevelILOperation.LLIL_SYSCALL_SSA: LowLevelILSyscall_ssa,                        #  [("output", "expr"), ("stack", "expr"), ("param", "expr")],
	LowLevelILOperation.LLIL_TAILCALL_SSA: LowLevelILTailcall_ssa,                      #  [("output", "expr"), ("dest", "expr"), ("stack", "expr"), ("param", "expr")],
	LowLevelILOperation.LLIL_CALL_OUTPUT_SSA: LowLevelILCall_output_ssa,                #  [("dest_memory", "int"), ("dest", "reg_ssa_list")],
	LowLevelILOperation.LLIL_CALL_STACK_SSA: LowLevelILCall_stack_ssa,                  #  [("src", "reg_ssa"), ("src_memory", "int")],
	LowLevelILOperation.LLIL_CALL_PARAM: LowLevelILCall_param,                          #  [("src", "expr_list")],
	LowLevelILOperation.LLIL_LOAD_SSA: LowLevelILLoad_ssa,                              #  [("src", "expr"), ("src_memory", "int")],
	LowLevelILOperation.LLIL_STORE_SSA: LowLevelILStore_ssa,                            #  [("dest", "expr"), ("dest_memory", "int"), ("src_memory", "int"), ("src", "expr")],
	LowLevelILOperation.LLIL_REG_PHI: LowLevelILReg_phi,                                #  [("dest", "reg_ssa"), ("src", "reg_ssa_list")],
	LowLevelILOperation.LLIL_REG_STACK_PHI: LowLevelILReg_stack_phi,                    #  [("dest", "reg_stack_ssa"), ("src", "reg_stack_ssa_list")],
	LowLevelILOperation.LLIL_FLAG_PHI: LowLevelILFlag_phi,                              #  [("dest", "flag_ssa"), ("src", "flag_ssa_list")],
	LowLevelILOperation.LLIL_MEM_PHI: LowLevelILMem_phi,                                #  [("dest_memory", "int"), ("src_memory", "int_list")]
}


class LowLevelILFunction:
	"""
	``class LowLevelILFunction`` contains the list of ExpressionIndex objects that make up a function. ExpressionIndex
	objects can be added to the LowLevelILFunction by calling :func:`append` and passing the result of the various class
	methods which return ExpressionIndex objects.


	LowLevelILFlagCondition values used as parameters in the :func:`flag_condition` method.

		======================= ========== ===============================
		LowLevelILFlagCondition Operator   Description
		======================= ========== ===============================
		LLFC_E                  ==         Equal
		LLFC_NE                 !=         Not equal
		LLFC_SLT                s<         Signed less than
		LLFC_ULT                u<         Unsigned less than
		LLFC_SLE                s<=        Signed less than or equal
		LLFC_ULE                u<=        Unsigned less than or equal
		LLFC_SGE                s>=        Signed greater than or equal
		LLFC_UGE                u>=        Unsigned greater than or equal
		LLFC_SGT                s>         Signed greater than
		LLFC_UGT                u>         Unsigned greater than
		LLFC_NEG                -          Negative
		LLFC_POS                +          Positive
		LLFC_O                  overflow   Overflow
		LLFC_NO                 !overflow  No overflow
		======================= ========== ===============================
	"""
	def __init__(self, arch:Optional['architecture.Architecture']=None, handle:Optional[core.BNLowLevelILFunction]=None,
		source_func:'function.Function'=None):
		self._arch = arch
		self._source_function = source_func
		if handle is not None:
			LLILHandle = ctypes.POINTER(core.BNLowLevelILFunction)
			_handle = ctypes.cast(handle, LLILHandle)
			if self._source_function is None:
				source_handle = core.BNGetLowLevelILOwnerFunction(_handle)
				if source_handle:
					self._source_function = function.Function(handle = source_handle)
				else:
					self._source_function = None
			if self._arch is None:
				if self._source_function is None:
					raise Exception("Can not instantiate LowLevelILFunction without an architecture")
				self._arch = self._source_function.arch
		else:
			if self._arch is None:
				if self._source_function is None:
					raise Exception("Can not instantiate LowLevelILFunction without an architecture")
				self._arch = self._source_function.arch
				assert self._arch is not None
			if self._source_function is None:
				func_handle = None
			else:
				func_handle = self._source_function.handle
			_handle = core.BNCreateLowLevelILFunction(self._arch.handle, func_handle)
		assert _handle is not None
		self.handle = _handle
		assert self._arch is not None

	def __del__(self):
		if core is not None:
			core.BNFreeLowLevelILFunction(self.handle)

	def __repr__(self):
		if self.source_function is not None and self.source_function.arch is not None:
			return f"<llil func: {self.source_function.arch.name}@{self.source_function.start:#x}>"
		elif self.source_function is not None:
			return f"<llil func: {self.source_function.start:#x}>"
		else:
			return "<llil func: anonymous>"

	def __len__(self):
		return int(core.BNGetLowLevelILInstructionCount(self.handle))

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(other.handle.contents)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash(ctypes.addressof(self.handle.contents))

	def __getitem__(self, i):
		if isinstance(i, slice) or isinstance(i, tuple):
			raise IndexError("expected integer instruction index")
		if i < -len(self) or i >= len(self):
			raise IndexError("index out of range")
		if i < 0:
			i = len(self) + i
		return LowLevelILInstruction.create(self, core.BNGetLowLevelILIndexForInstruction(self.handle, i), i)

	def __setitem__(self, i, j):
		raise IndexError("instruction modification not implemented")

	def __iter__(self) -> Generator['LowLevelILBasicBlock', None, None]:
		count = ctypes.c_ulonglong()
		blocks = core.BNGetLowLevelILBasicBlockList(self.handle, count)
		assert blocks is not None, "core.BNGetLowLevelILBasicBlockList returned None"
		view = None
		if self._source_function is not None:
			view = self._source_function.view
		try:
			for i in range(0, count.value):
				core_block = core.BNNewBasicBlockReference(blocks[i])
				assert core_block is not None, "core.BNNewBasicBlockReference returned None"
				yield LowLevelILBasicBlock(core_block, self, view)
		finally:
			core.BNFreeBasicBlockList(blocks, count.value)

	@property
	def current_address(self) -> int:
		"""Current IL Address (read/write)"""
		return core.BNLowLevelILGetCurrentAddress(self.handle)

	@current_address.setter
	def current_address(self, value:int) -> None:
		core.BNLowLevelILSetCurrentAddress(self.handle, self.arch.handle, value)

	def set_current_address(self, value:int, arch:Optional['architecture.Architecture']=None) -> None:
		if arch is None:
			arch = self.arch
		core.BNLowLevelILSetCurrentAddress(self.handle, arch.handle, value)

	def set_current_source_block(self, block) -> None:
		core.BNLowLevelILSetCurrentSourceBlock(self.handle, block.handle)

	@property
	def temp_reg_count(self) -> int:
		"""Number of temporary registers (read-only)"""
		return core.BNGetLowLevelILTemporaryRegisterCount(self.handle)

	@property
	def temp_flag_count(self) -> int:
		"""Number of temporary flags (read-only)"""
		return core.BNGetLowLevelILTemporaryFlagCount(self.handle)

	@property
	def basic_blocks(self) -> Generator['LowLevelILBasicBlock', None, None]:
		"""list of LowLevelILBasicBlock objects (read-only)"""
		count = ctypes.c_ulonglong()
		blocks = core.BNGetLowLevelILBasicBlockList(self.handle, count)
		assert blocks is not None, "core.BNGetLowLevelILBasicBlockList returned None"
		view = None
		if self._source_function is not None:
			view = self._source_function.view
		try:
			for i in range(0, count.value):
				core_block = core.BNNewBasicBlockReference(blocks[i])
				assert core_block is not None, "core.BNNewBasicBlockReference returned None"
				yield LowLevelILBasicBlock(core_block, self, view)
		finally:
			core.BNFreeBasicBlockList(blocks, count.value)

	@property
	def instructions(self) -> Generator['LowLevelILInstruction', None, None]:
		"""A generator of llil instructions of the current llil function"""
		for block in self.basic_blocks:
			for i in block:
				yield i

	@property
	def ssa_form(self) -> 'LowLevelILFunction':
		"""Low level IL in SSA form (read-only)"""
		result = core.BNGetLowLevelILSSAForm(self.handle)
		assert result is not None, "Failed to retrieve ssa-form"
		return LowLevelILFunction(self._arch, result, self._source_function)

	@property
	def non_ssa_form(self) -> 'LowLevelILFunction':
		"""Low level IL in non-SSA (default) form (read-only)"""
		result = core.BNGetLowLevelILNonSSAForm(self.handle)
		assert result is not None, "Failed to retrieve non-ssa-form"
		return LowLevelILFunction(self._arch, result, self._source_function)

	@property
	def medium_level_il(self) -> 'mediumlevelil.MediumLevelILFunction':
		"""Medium level IL for this low level IL."""
		result = core.BNGetMediumLevelILForLowLevelIL(self.handle)
		assert result is not None, "MLIL not present"
		return mediumlevelil.MediumLevelILFunction(self._arch, result, self._source_function)

	@property
	def mlil(self) -> 'mediumlevelil.MediumLevelILFunction':
		return self.medium_level_il

	@property
	def mapped_medium_level_il(self) -> 'mediumlevelil.MediumLevelILFunction':
		"""Medium level IL with mappings between low level IL and medium level IL. Unused stores are not removed.
		Typically, this should only be used to answer queries on assembly or low level IL where the query is
		easier to perform on medium level IL."""
		result = core.BNGetMappedMediumLevelIL(self.handle)
		assert result is not None, "MLIL not present"
		return mediumlevelil.MediumLevelILFunction(self._arch, result, self._source_function)

	@property
	def mmlil(self) -> 'mediumlevelil.MediumLevelILFunction':
		return self.mapped_medium_level_il

	@property
	def arch(self) -> 'architecture.Architecture':
		assert self._arch is not None
		return self._arch

	@arch.setter
	def arch(self, value='architecture.Architecture') -> None:
		self._arch = value

	@property
	def source_function(self) -> Optional['function.Function']:
		return self._source_function

	@source_function.setter
	def source_function(self, value:'function.Function') -> None:
		self._source_function = value

	@property
	def il_form(self) -> FunctionGraphType:
		if len(list(self.basic_blocks)) < 1:
			return FunctionGraphType.InvalidILViewType
		return FunctionGraphType(core.BNGetBasicBlockFunctionGraphType(list(self.basic_blocks)[0].handle))

	@property
	def registers(self) -> List[ILRegister]:
		""" List of registers used in this IL """
		count = ctypes.c_ulonglong()
		registers = core.BNGetLowLevelRegisters(self.handle, count)
		assert registers is not None, "core.BNGetLowLevelRegisters returned None"
		result = []
		try:
			for var_i in range(count.value):
				result.append(ILRegister(self.arch, registers[var_i]))
			return result
		finally:
			core.BNFreeLLILVariablesList(registers)

	@property
	def register_stacks(self) -> List[ILRegisterStack]:
		""" List of register stacks used in this IL """
		count = ctypes.c_ulonglong()
		registerStacks = core.BNGetLowLevelRegisterStacks(self.handle, count)
		assert registerStacks is not None, "core.BNGetLowLevelRegisterStacks returned None"
		result = []
		try:
			for var_i in range(count.value):
				result.append(ILRegisterStack(self.arch, registerStacks[var_i]))
			return result
		finally:
			core.BNFreeLLILVariablesList(registerStacks)

	@property
	def flags(self) -> List[ILFlag]:
		""" List of flags used in this IL """
		count = ctypes.c_ulonglong()
		flags = core.BNGetLowLevelFlags(self.handle, count)
		assert flags is not None, "core.BNGetLowLevelFlags returned None"
		result = []
		try:
			for var_i in range(count.value):
				result.append(ILFlag(self.arch, flags[var_i]))
			return result
		finally:
			core.BNFreeLLILVariablesList(flags)

	@property
	def ssa_registers(self) -> List[SSARegister]:
		""" List of SSA registers used in this IL """
		if self.il_form != FunctionGraphType.LowLevelILSSAFormFunctionGraph:
			return []

		register_count = ctypes.c_ulonglong()
		registers = core.BNGetLowLevelRegisters(self.handle, register_count)
		assert registers is not None, "core.BNGetLowLevelRegisters returned None"
		result = []
		try:
			for var_i in range(register_count.value):
				version_count = ctypes.c_ulonglong()
				versions = core.BNGetLowLevelRegisterSSAVersions(self.handle, registers[var_i], version_count)
				assert versions is not None, "core.BNGetLowLevelRegisterSSAVersions returned None"
				try:
					for version_i in range(version_count.value):
						result.append(SSARegister(ILRegister(self.arch, registers[var_i]), versions[version_i]))
				finally:
					core.BNFreeLLILVariableVersionList(versions)

			return result
		finally:
			core.BNFreeLLILVariablesList(registers)

	@property
	def ssa_register_stacks(self) -> List[SSARegisterStack]:
		""" List of SSA register stacks used in this IL """
		if self.il_form != FunctionGraphType.LowLevelILSSAFormFunctionGraph:
			return []

		register_stack_count = ctypes.c_ulonglong()
		register_stacks = core.BNGetLowLevelRegisterStacks(self.handle, register_stack_count)
		assert register_stacks is not None, "core.BNGetLowLevelRegisterStacks returned None"
		result = []
		try:
			for var_i in range(register_stack_count.value):
				version_count = ctypes.c_ulonglong()
				versions = core.BNGetLowLevelRegisterStackSSAVersions(self.handle, register_stacks[var_i], version_count)
				assert versions is not None, "core.BNGetLowLevelRegisterStackSSAVersions returned None"
				try:
					for version_i in range(version_count.value):
						result.append(SSARegisterStack(ILRegisterStack(self.arch, register_stacks[var_i]), versions[version_i]))
				finally:
					core.BNFreeLLILVariableVersionList(versions)
		finally:
			core.BNFreeLLILVariablesList(register_stacks)
		return result

	@property
	def ssa_flags(self) -> List[SSAFlag]:
		""" List of SSA flags used in this IL """
		if self.il_form != FunctionGraphType.LowLevelILSSAFormFunctionGraph:
			return []

		flag_count = ctypes.c_ulonglong()
		flags = core.BNGetLowLevelFlags(self.handle, flag_count)
		assert flags is not None, "core.BNGetLowLevelFlags returned None"
		result = []
		try:
			for var_i in range(flag_count.value):
				version_count = ctypes.c_ulonglong()
				versions = core.BNGetLowLevelFlagSSAVersions(self.handle, flags[var_i], version_count)
				assert versions is not None, "core.BNGetLowLevelFlagSSAVersions returned None"
				try:
					for version_i in range(version_count.value):
						result.append(SSAFlag(ILFlag(self.arch, flags[var_i]), versions[version_i]))
				finally:
					core.BNFreeLLILVariableVersionList(versions)
		finally:
			core.BNFreeLLILVariablesList(flags)
		return result

	@property
	def memory_versions(self) -> List[int]:
		""" List of memory versions used in this IL """
		count = ctypes.c_ulonglong()
		memory_versions = core.BNGetLowLevelMemoryVersions(self.handle, count)
		assert memory_versions is not None, "core.BNGetLowLevelMemoryVersions returned None"
		result = []
		try:
			for version_i in range(count.value):
				result.append(memory_versions[version_i])
			return result
		finally:
			core.BNFreeLLILVariableVersionList(memory_versions)

	@property
	def vars(self) -> List[Union[ILRegister, ILRegisterStack, ILFlag]]:
		"""This is the union `LowLevelILFunction.registers`, `LowLevelILFunction.register_stacks`, and `LowLevelILFunction.flags`"""
		if self._source_function is None:
			return []

		if self.il_form in [FunctionGraphType.LiftedILFunctionGraph, FunctionGraphType.LowLevelILFunctionGraph, FunctionGraphType.LowLevelILSSAFormFunctionGraph]:
			return self.registers + self.register_stacks + self.flags  # type: ignore
		return []

	@property
	def ssa_vars(self) -> List[Union['mediumlevelil.SSAVariable', SSARegisterStack, SSAFlag]]:
		"""This is the union `LowLevelILFunction.ssa_registers`, `LowLevelILFunction.ssa_register_stacks`, and `LowLevelILFunction.ssa_flags`"""
		if self.il_form == FunctionGraphType.LowLevelILSSAFormFunctionGraph:
			return self.ssa_registers + self.ssa_register_stacks + self.ssa_flags  # type: ignore
		return []

	def get_instruction_start(self, addr:int, arch:Optional['architecture.Architecture']=None) -> Optional[int]:
		if arch is None:
			arch = self.arch
		result = core.BNLowLevelILGetInstructionStart(self.handle, arch.handle, addr)
		if result >= core.BNGetLowLevelILInstructionCount(self.handle):
			return None
		return result

	def clear_indirect_branches(self) -> None:
		core.BNLowLevelILClearIndirectBranches(self.handle)

	def set_indirect_branches(self, branches:List[Tuple['architecture.Architecture', int]]) -> None:
		branch_list = (core.BNArchitectureAndAddress * len(branches))()
		for i in range(len(branches)):
			branch_list[i].arch = branches[i][0].handle
			branch_list[i].address = branches[i][1]
		core.BNLowLevelILSetIndirectBranches(self.handle, branch_list, len(branches))

	def expr(self, operation, a:int=0, b:int=0, c:int=0, d:int=0, size:int=0,
		flags:Union['architecture.FlagWriteTypeName', 'architecture.FlagType', 'architecture.FlagIndex']=None):
		_flags = architecture.FlagIndex(0)
		if isinstance(operation, str):
			operation = LowLevelILOperation[operation]
		elif isinstance(operation, LowLevelILOperation):
			operation = operation.value
		if isinstance(flags, str):
			_flags = self.arch.get_flag_write_type_by_name(architecture.FlagWriteTypeName(flags))
		elif isinstance(flags, ILFlag):
			_flags = flags.index
		elif isinstance(flags, int):
			_flags = architecture.FlagIndex(flags)
		elif flags is None:
			_flags = architecture.FlagIndex(0)
		else:
			assert False, "flags type unsupported"
		return ExpressionIndex(core.BNLowLevelILAddExpr(self.handle, operation, size, _flags, a, b, c, d))

	def replace_expr(self, original:InstructionOrExpression, new:InstructionOrExpression) -> None:
		"""
		``replace_expr`` allows modification of ExpressionIndexessions but ONLY during lifting.

		.. warning:: This function should ONLY be called as a part of a lifter. It will otherwise not do anything useful as there's no way to trigger re-analysis of IL levels at this time.

		:param ExpressionIndex original: the ExpressionIndex to replace (may also be an expression index)
		:param ExpressionIndex new: the ExpressionIndex to add to the current LowLevelILFunction (may also be an expression index)
		:rtype: None
		"""
		if isinstance(original, LowLevelILInstruction):
			original = original.expr_index
		elif isinstance(original, int):
			original = ExpressionIndex(original)

		if isinstance(new, LowLevelILInstruction):
			new = new.expr_index
		elif isinstance(new, int):
			new = ExpressionIndex(new)

		core.BNReplaceLowLevelILExpr(self.handle, original, new)

	def append(self, expr:ExpressionIndex) -> int:
		"""
		``append`` adds the ExpressionIndex ``expr`` to the current LowLevelILFunction.

		:param ExpressionIndex expr: the ExpressionIndex to add to the current LowLevelILFunction
		:return: number of ExpressionIndex in the current function
		:rtype: int
		"""
		return core.BNLowLevelILAddInstruction(self.handle, expr)

	def nop(self) -> ExpressionIndex:
		"""
		``nop`` no operation, this instruction does nothing

		:return: The no operation expression
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_NOP)

	def set_reg(self, size:int, reg:'architecture.RegisterType', value:ExpressionIndex,
		flags:Optional['architecture.FlagType']=None) -> ExpressionIndex:
		"""
		``set_reg`` sets the register ``reg`` of size ``size`` to the expression ``value``

		:param int size: size of the register parameter in bytes
		:param str reg: the register name
		:param ExpressionIndex value: an expression to set the register to
		:param str flags: which flags are set by this operation
		:return: The expression ``reg = value``
		:rtype: ExpressionIndex
		"""
		_reg = ExpressionIndex(self.arch.get_reg_index(reg))
		if flags is None:
			flags = architecture.FlagIndex(0)
		return self.expr(LowLevelILOperation.LLIL_SET_REG, _reg, value, size = size, flags = flags)

	def set_reg_split(self, size:int, hi:'architecture.RegisterType', lo:'architecture.RegisterType',
		value:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``set_reg_split`` uses ``hi`` and ``lo`` as a single extended register setting ``hi:lo`` to the expression
		``value``.

		:param int size: size of the register parameter in bytes
		:param str hi: the high register name
		:param str lo: the low register name
		:param ExpressionIndex value: an expression to set the split registers to
		:param str flags: which flags are set by this operation
		:return: The expression ``hi:lo = value``
		:rtype: ExpressionIndex
		"""
		_hi = ExpressionIndex(self.arch.get_reg_index(hi))
		_lo = ExpressionIndex(self.arch.get_reg_index(lo))
		if flags is None:
			flags = architecture.FlagIndex(0)
		return self.expr(LowLevelILOperation.LLIL_SET_REG_SPLIT, _hi, _lo, value, size = size, flags = flags)

	def set_reg_stack_top_relative(self, size:int, reg_stack:'architecture.RegisterStackType', entry:ExpressionIndex,
		value:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``set_reg_stack_top_relative`` sets the top-relative entry ``entry`` of size ``size`` in register
		stack ``reg_stack`` to the expression ``value``

		:param int size: size of the register parameter in bytes
		:param str reg_stack: the register stack name
		:param ExpressionIndex entry: an expression for which stack entry to set
		:param ExpressionIndex value: an expression to set the entry to
		:param str flags: which flags are set by this operation
		:return: The expression ``reg_stack[entry] = value``
		:rtype: ExpressionIndex
		"""
		_reg_stack = ExpressionIndex(self.arch.get_reg_stack_index(reg_stack))
		if flags is None:
			flags = architecture.FlagIndex(0)
		return self.expr(LowLevelILOperation.LLIL_SET_REG_STACK_REL, _reg_stack, entry, value,
			size = size, flags = flags)

	def reg_stack_push(self, size:int, reg_stack:'architecture.RegisterStackType', value:ExpressionIndex,
		flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``reg_stack_push`` pushes the expression ``value`` of size ``size`` onto the top of the register
		stack ``reg_stack``

		:param int size: size of the register parameter in bytes
		:param str reg_stack: the register stack name
		:param ExpressionIndex value: an expression to push
		:param str flags: which flags are set by this operation
		:return: The expression ``reg_stack.push(value)``
		:rtype: ExpressionIndex
		"""
		_reg_stack = ExpressionIndex(self.arch.get_reg_stack_index(reg_stack))
		if flags is None:
			flags = architecture.FlagIndex(0)
		return self.expr(LowLevelILOperation.LLIL_REG_STACK_PUSH, _reg_stack, value, size = size, flags = flags)

	def set_flag(self, flag:'architecture.FlagName', value:ExpressionIndex) -> ExpressionIndex:
		"""
		``set_flag`` sets the flag ``flag`` to the ExpressionIndex ``value``

		:param str flag: the low register name
		:param ExpressionIndex value: an expression to set the flag to
		:return: The expression FLAG.flag = value
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_SET_FLAG, ExpressionIndex(self.arch.get_flag_by_name(flag)),
			value)

	def load(self, size:int, addr:ExpressionIndex) -> ExpressionIndex:
		"""
		``load`` Reads ``size`` bytes from the expression ``addr``

		:param int size: number of bytes to read
		:param ExpressionIndex addr: the expression to read memory from
		:return: The expression ``[addr].size``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_LOAD, addr, size=size)

	def store(self, size:int, addr:ExpressionIndex, value:ExpressionIndex, flags=None) -> ExpressionIndex:
		"""
		``store`` Writes ``size`` bytes to expression ``addr`` read from expression ``value``

		:param int size: number of bytes to write
		:param ExpressionIndex addr: the expression to write to
		:param ExpressionIndex value: the expression to be written
		:param str flags: which flags are set by this operation
		:return: The expression ``[addr].size = value``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_STORE, addr, value, size=size, flags=flags)

	def push(self, size:int, value:ExpressionIndex) -> ExpressionIndex:
		"""
		``push`` writes ``size`` bytes from expression ``value`` to the stack, adjusting the stack by ``size``.

		:param int size: number of bytes to write and adjust the stack by
		:param ExpressionIndex value: the expression to write
		:return: The expression push(value)
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_PUSH, value, size=size)

	def pop(self, size:int) -> ExpressionIndex:
		"""
		``pop`` reads ``size`` bytes from the stack, adjusting the stack by ``size``.

		:param int size: number of bytes to read from the stack
		:return: The expression ``pop``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_POP, size=size)

	def reg(self, size:int, reg:'architecture.RegisterType') -> ExpressionIndex:
		"""
		``reg`` returns a register of size ``size`` with name ``reg``

		:param int size: the size of the register in bytes
		:param str reg: the name of the register
		:return: A register expression for the given string
		:rtype: ExpressionIndex
		"""
		_reg = ExpressionIndex(self.arch.get_reg_index(reg))
		return self.expr(LowLevelILOperation.LLIL_REG, _reg, size=size)

	def reg_split(self, size:int, hi:'architecture.RegisterType', lo:'architecture.RegisterType') -> ExpressionIndex:
		"""
		``reg_split`` combines registers of size ``size`` with names ``hi`` and ``lo``

		:param int size: the size of the register in bytes
		:param str hi: register holding high part of value
		:param str lo: register holding low part of value
		:return: The expression ``hi:lo``
		:rtype: ExpressionIndex
		"""
		_hi = ExpressionIndex(self.arch.get_reg_index(hi))
		_lo = ExpressionIndex(self.arch.get_reg_index(lo))
		return self.expr(LowLevelILOperation.LLIL_REG_SPLIT, _hi, _lo, size=size)

	def reg_stack_top_relative(self, size:int, reg_stack:'architecture.RegisterStackType', entry:ExpressionIndex) -> ExpressionIndex:
		"""
		``reg_stack_top_relative`` returns a register stack entry of size ``size`` at top-relative
		location ``entry`` in register stack with name ``reg_stack``

		:param int size: the size of the register in bytes
		:param str reg_stack: the name of the register stack
		:param ExpressionIndex entry: an expression for which stack entry to fetch
		:return: The expression ``reg_stack[entry]``
		:rtype: ExpressionIndex
		"""
		_reg_stack = self.arch.get_reg_stack_index(reg_stack)
		return self.expr(LowLevelILOperation.LLIL_REG_STACK_REL, _reg_stack, entry, size=size)

	def reg_stack_pop(self, size:int, reg_stack:'architecture.RegisterStackType') -> ExpressionIndex:
		"""
		``reg_stack_pop`` returns the top entry of size ``size`` in register stack with name ``reg_stack``, and
		removes the entry from the stack

		:param int size: the size of the register in bytes
		:param str reg_stack: the name of the register stack
		:return: The expression ``reg_stack.pop``
		:rtype: ExpressionIndex
		"""
		_reg_stack = ExpressionIndex(self.arch.get_reg_stack_index(reg_stack))
		return self.expr(LowLevelILOperation.LLIL_REG_STACK_POP, _reg_stack, size=size)

	def const(self, size:int, value:int) -> ExpressionIndex:
		"""
		``const`` returns an expression for the constant integer ``value`` with size ``size``

		:param int size: the size of the constant in bytes
		:param int value: integer value of the constant
		:return: A constant expression of given value and size
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_CONST, ExpressionIndex(value), size=size)

	def const_pointer(self, size:int, value:int) -> ExpressionIndex:
		"""
		``const_pointer`` returns an expression for the constant pointer ``value`` with size ``size``

		:param int size: the size of the pointer in bytes
		:param int value: address referenced by pointer
		:return: A constant expression of given value and size
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_CONST_PTR, value, size=size)

	def reloc_pointer(self, size:int, value:int) -> ExpressionIndex:
		"""
		``reloc_pointer`` returns an expression for the constant relocated pointer ``value`` with size ``size``

		:param int size: the size of the pointer in bytes
		:param int value: address referenced by pointer
		:return: A constant expression of given value and size
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_EXTERN_PTR, value, size=size)

	def float_const_raw(self, size:int, value:int) -> ExpressionIndex:
		"""
		``float_const_raw`` returns an expression for the constant raw binary floating point
		value ``value`` with size ``size``

		:param int size: the size of the constant in bytes
		:param int value: integer value for the raw binary representation of the constant
		:return: A constant expression of given value and size
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FLOAT_CONST, value, size=size)

	def float_const_single(self, value:float) -> ExpressionIndex:
		"""
		``float_const_single`` returns an expression for the single precision floating point value ``value``

		:param float value: float value for the constant
		:return: A constant expression of given value and size
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FLOAT_CONST, struct.unpack("I", struct.pack("f", value))[0], size=4)

	def float_const_double(self, value:float) -> ExpressionIndex:
		"""
		``float_const_double`` returns an expression for the double precision floating point value ``value``

		:param float value: float value for the constant
		:return: A constant expression of given value and size
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FLOAT_CONST, struct.unpack("Q", struct.pack("d", value))[0], size=8)

	def flag(self, reg:'architecture.FlagName') -> ExpressionIndex:
		"""
		``flag`` returns a flag expression for the given flag name.

		:param architecture.FlagName reg: name of the flag expression to retrieve
		:return: A flag expression of given flag name
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FLAG, self.arch.get_flag_by_name(reg))

	def flag_bit(self, size:int, reg:'architecture.FlagName', bit:int) -> ExpressionIndex:
		"""
		``flag_bit`` sets the flag named ``reg`` and size ``size`` to the constant integer value ``bit``

		:param int size: the size of the flag
		:param str reg: flag value
		:param int bit: integer value to set the bit to
		:return: A constant expression of given value and size ``FLAG.reg = bit``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FLAG_BIT, self.arch.get_flag_by_name(reg), bit, size=size)

	def add(self, size:int, a:ExpressionIndex, b:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``add`` adds expression ``a`` to expression ``b`` potentially setting flags ``flags`` and returning
		an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param str flags: flags to set
		:return: The expression ``add.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_ADD, a, b, size=size, flags=flags)

	def add_carry(self, size:int, a:ExpressionIndex, b:ExpressionIndex, carry:ExpressionIndex,
		flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``add_carry`` adds with carry expression ``a`` to expression ``b`` potentially setting flags ``flags`` and
		returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ExpressionIndex carry: Carry flag expression
		:param str flags: flags to set
		:return: The expression ``adc.<size>{<flags>}(a, b, carry)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_ADC, a, b, carry, size=size, flags=flags)

	def sub(self, size:int, a:ExpressionIndex, b:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``sub`` subtracts expression ``b`` from expression ``a`` potentially setting flags ``flags`` and returning
		an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param str flags: flags to set
		:return: The expression ``sub.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_SUB, a, b, size=size, flags=flags)

	def sub_borrow(self, size:int, a:ExpressionIndex, b:ExpressionIndex, carry:ExpressionIndex,
		flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``sub_borrow`` subtracts with borrow expression ``b`` from expression ``a`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ExpressionIndex carry: Carry flag expression
		:param str flags: flags to set
		:return: The expression ``sbb.<size>{<flags>}(a, b, carry)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_SBB, a, b, carry, size=size, flags=flags)

	def and_expr(self, size:int, a:ExpressionIndex, b:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``and_expr`` bitwise and's expression ``a`` and expression ``b`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``and.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_AND, a, b, size=size, flags=flags)

	def or_expr(self, size:int, a:ExpressionIndex, b:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``or_expr`` bitwise or's expression ``a`` and expression ``b`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``or.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_OR, a, b, size=size, flags=flags)

	def xor_expr(self, size:int, a:ExpressionIndex, b:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``xor_expr`` xor's expression ``a`` with expression ``b`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``xor.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_XOR, a, b, size=size, flags=flags)

	def shift_left(self, size:int, a:ExpressionIndex, b:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``shift_left`` shifts left expression ``a`` by expression ``b`` from expression ``a`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``lsl.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_LSL, a, b, size=size, flags=flags)

	def logical_shift_right(self, size:int, a:ExpressionIndex, b:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``logical_shift_right`` shifts logically right expression ``a`` by expression ``b`` potentially setting flags
		``flags`` and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``lsr.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_LSR, a, b, size=size, flags=flags)

	def arith_shift_right(self, size:int, a:ExpressionIndex, b:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``arith_shift_right`` shifts arithmetic right expression ``a`` by expression ``b``  potentially setting flags
		``flags`` and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``asr.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_ASR, a, b, size=size, flags=flags)

	def rotate_left(self, size:int, a:ExpressionIndex, b:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``rotate_left`` bitwise rotates left expression ``a`` by expression ``b`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``rol.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_ROL, a, b, size=size, flags=flags)

	def rotate_left_carry(self, size:int, a:ExpressionIndex, b:ExpressionIndex, carry:ExpressionIndex,
		flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``rotate_left_carry`` bitwise rotates left with carry expression ``a`` by expression ``b`` potentially setting
		flags ``flags`` and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ExpressionIndex carry: Carry flag expression
		:param str flags: optional, flags to set
		:return: The expression ``rlc.<size>{<flags>}(a, b, carry)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_RLC, a, b, carry, size=size, flags=flags)

	def rotate_right(self, size:int, a:ExpressionIndex, b:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``rotate_right`` bitwise rotates right expression ``a`` by expression ``b`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``ror.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_ROR, a, b, size=size, flags=flags)

	def rotate_right_carry(self, size:int, a:ExpressionIndex, b:ExpressionIndex, carry:ExpressionIndex,
		flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``rotate_right_carry`` bitwise rotates right with carry expression ``a`` by expression ``b`` potentially setting
		flags ``flags`` and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ExpressionIndex carry: Carry flag expression
		:param str flags: optional, flags to set
		:return: The expression ``rrc.<size>{<flags>}(a, b, carry)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_RRC, a, b, carry, size=size, flags=flags)

	def mult(self, size:int, a:ExpressionIndex, b:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``mult`` multiplies expression ``a`` by expression ``b`` potentially setting flags ``flags`` and returning an
		expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``sbc.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_MUL, a, b, size=size, flags=flags)

	def mult_double_prec_signed(self, size:int, a:ExpressionIndex, b:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``mult_double_prec_signed`` multiplies signed with double precision expression ``a`` by expression ``b``
		potentially setting flags ``flags`` and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``muls.dp.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_MULS_DP, a, b, size=size, flags=flags)

	def mult_double_prec_unsigned(self, size:int, a:ExpressionIndex, b:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``mult_double_prec_unsigned`` multiplies unsigned with double precision expression ``a`` by expression ``b``
		potentially setting flags ``flags`` and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``mulu.dp.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_MULU_DP, a, b, size=size, flags=flags)

	def div_signed(self, size:int, a:ExpressionIndex, b:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``div_signed`` signed divide expression ``a`` by expression ``b`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``divs.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_DIVS, a, b, size=size, flags=flags)

	def div_double_prec_signed(self, size:int, a:ExpressionIndex, b:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``div_double_prec_signed`` signed double precision divide using expression ``a`` as a
		single double precision register by expression ``b`` potentially  setting flags ``flags`` and returning an
		expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``divs.dp.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_DIVS_DP, a, b, size=size, flags=flags)

	def div_unsigned(self, size:int, a:ExpressionIndex, b:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``div_unsigned`` unsigned divide expression ``a`` by expression ``b`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``divu.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_DIVU, a, b, size=size, flags=flags)

	def div_double_prec_unsigned(self, size:int, a:ExpressionIndex, b:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``div_double_prec_unsigned`` unsigned double precision divide using expression ``a`` as
		a single double precision register by expression ``b`` potentially  setting flags ``flags`` and returning an
		expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``divu.dp.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_DIVU_DP, a, b, size=size, flags=flags)

	def mod_signed(self, size:int, a:ExpressionIndex, b:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``mod_signed`` signed modulus expression ``a`` by expression ``b`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``mods.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_MODS, a, b, size=size, flags=flags)

	def mod_double_prec_signed(self, size:int, a:ExpressionIndex, b:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``mod_double_prec_signed`` signed double precision modulus using expression ``a`` as a single
		double precision register by expression ``b`` potentially  setting flags ``flags`` and returning an expression
		of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``mods.dp.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_MODS_DP, a, b, size=size, flags=flags)

	def mod_unsigned(self, size:int, a:ExpressionIndex, b:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``mod_unsigned`` unsigned modulus expression ``a`` by expression ``b`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``modu.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_MODU, a, b, size=size, flags=flags)

	def mod_double_prec_unsigned(self, size:int, a:ExpressionIndex, b:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``mod_double_prec_unsigned`` unsigned double precision modulus using expression ``a`` as
		a single double precision register by expression ``b`` potentially  setting flags ``flags`` and returning an
		expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``modu.dp.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_MODU_DP, a, b, size=size, flags=flags)

	def neg_expr(self, size:int, value:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``neg_expr`` two's complement sign negation of expression ``value`` of size ``size`` potentially setting flags

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to negate
		:param str flags: optional, flags to set
		:return: The expression ``neg.<size>{<flags>}(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_NEG, value, size=size, flags=flags)

	def not_expr(self, size:int, value:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``not_expr`` bitwise inverse of expression ``value`` of size ``size`` potentially setting flags

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to bitwise invert
		:param str flags: optional, flags to set
		:return: The expression ``not.<size>{<flags>}(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_NOT, value, size=size, flags=flags)

	def sign_extend(self, size:int, value:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``sign_extend`` two's complement sign-extends the expression in ``value`` to ``size`` bytes

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to sign extend
		:param str flags: optional, flags to set
		:return: The expression ``sx.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_SX, value, size=size, flags=flags)

	def zero_extend(self, size:int, value:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``zero_extend`` zero-extends the expression in ``value`` to ``size`` bytes

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to zero extend
		:return: The expression ``zx.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_ZX, value, size=size, flags=flags)

	def low_part(self, size:int, value:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``low_part`` truncates ``value`` to ``size`` bytes

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to zero extend
		:return: The expression ``(value).<size>``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_LOW_PART, value, size=size, flags=flags)

	def jump(self, dest:ExpressionIndex) -> ExpressionIndex:
		"""
		``jump`` returns an expression which jumps (branches) to the expression ``dest``

		:param ExpressionIndex dest: the expression to jump to
		:return: The expression ``jump(dest)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_JUMP, dest)

	def call(self, dest:ExpressionIndex) -> ExpressionIndex:
		"""
		``call`` returns an expression which first pushes the address of the next instruction onto the stack then jumps
		(branches) to the expression ``dest``

		:param ExpressionIndex dest: the expression to call
		:return: The expression ``call(dest)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_CALL, dest)

	def call_stack_adjust(self, dest:ExpressionIndex, stack_adjust:int) -> ExpressionIndex:
		"""
		``call_stack_adjust`` returns an expression which first pushes the address of the next instruction onto the stack
		then jumps (branches) to the expression ``dest``. After the function exits, ``stack_adjust`` is added to the
		stack pointer register.

		:param ExpressionIndex dest: the expression to call
		:return: The expression ``call(dest), stack += stack_adjust``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_CALL_STACK_ADJUST, dest, stack_adjust)

	def tailcall(self, dest:ExpressionIndex) -> ExpressionIndex:
		"""
		``tailcall`` returns an expression which jumps (branches) to the expression ``dest``

		:param ExpressionIndex dest: the expression to jump to
		:return: The expression ``tailcall(dest)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_TAILCALL, dest)

	def ret(self, dest:ExpressionIndex) -> ExpressionIndex:
		"""
		``ret`` returns an expression which jumps (branches) to the expression ``dest``. ``ret`` is a special alias for
		jump that makes the disassembler stop disassembling.

		:param ExpressionIndex dest: the expression to jump to
		:return: The expression ``jump(dest)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_RET, dest)

	def no_ret(self) -> ExpressionIndex:
		"""
		``no_ret`` returns an expression halts disassembly

		:return: The expression ``noreturn``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_NORET)

	def flag_condition(self, cond:Union[str, LowLevelILFlagCondition, int],
		sem_class:Optional['architecture.SemanticClassType']=None) -> ExpressionIndex:
		"""
		``flag_condition`` returns a flag_condition expression for the given LowLevelILFlagCondition

		:param LowLevelILFlagCondition cond: Flag condition expression to retrieve
		:param str sem_class: Optional semantic flag class
		:return: A flag_condition expression
		:rtype: ExpressionIndex
		"""
		if isinstance(cond, str):
			cond = LowLevelILFlagCondition[cond]
		elif isinstance(cond, LowLevelILFlagCondition):
			cond = cond.value
		class_index = self.arch.get_semantic_flag_class_index(sem_class)
		return self.expr(LowLevelILOperation.LLIL_FLAG_COND, cond, architecture.SemanticClassIndex(class_index))

	def flag_group(self, sem_group) -> ExpressionIndex:
		"""
		``flag_group`` returns a flag_group expression for the given semantic flag group

		:param str sem_group: Semantic flag group to access
		:return: A flag_group expression
		:rtype: ExpressionIndex
		"""
		group = self.arch.get_semantic_flag_group_index(sem_group)
		return self.expr(LowLevelILOperation.LLIL_FLAG_GROUP, group)

	def compare_equal(self, size:int, a:ExpressionIndex, b:ExpressionIndex) -> ExpressionIndex:
		"""
		``compare_equal`` returns comparison expression of size ``size`` checking if expression ``a`` is equal to
		expression ``b``

		:param int size: size in bytes
		:param ExpressionIndex a: LHS of comparison
		:param ExpressionIndex b: RHS of comparison
		:return: a comparison expression.
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_CMP_E, a, b, size = size)

	def compare_not_equal(self, size:int, a:ExpressionIndex, b:ExpressionIndex) -> ExpressionIndex:
		"""
		``compare_not_equal`` returns comparison expression of size ``size`` checking if expression ``a`` is not equal to
		expression ``b``

		:param int size: size in bytes
		:param ExpressionIndex a: LHS of comparison
		:param ExpressionIndex b: RHS of comparison
		:return: a comparison expression.
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_CMP_NE, a, b, size = size)

	def compare_signed_less_than(self, size:int, a:ExpressionIndex, b:ExpressionIndex) -> ExpressionIndex:
		"""
		``compare_signed_less_than`` returns comparison expression of size ``size`` checking if expression ``a`` is
		signed less than expression ``b``

		:param int size: size in bytes
		:param ExpressionIndex a: LHS of comparison
		:param ExpressionIndex b: RHS of comparison
		:return: a comparison expression.
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_CMP_SLT, a, b, size = size)

	def compare_unsigned_less_than(self, size:int, a:ExpressionIndex, b:ExpressionIndex) -> ExpressionIndex:
		"""
		``compare_unsigned_less_than`` returns comparison expression of size ``size`` checking if expression ``a`` is
		unsigned less than expression ``b``

		:param int size: size in bytes
		:param ExpressionIndex a: LHS of comparison
		:param ExpressionIndex b: RHS of comparison
		:return: a comparison expression.
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_CMP_ULT, a, b, size = size)

	def compare_signed_less_equal(self, size:int, a:ExpressionIndex, b:ExpressionIndex) -> ExpressionIndex:
		"""
		``compare_signed_less_equal`` returns comparison expression of size ``size`` checking if expression ``a`` is
		signed less than or equal to expression ``b``

		:param int size: size in bytes
		:param ExpressionIndex a: LHS of comparison
		:param ExpressionIndex b: RHS of comparison
		:return: a comparison expression.
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_CMP_SLE, a, b, size = size)

	def compare_unsigned_less_equal(self, size:int, a:ExpressionIndex, b:ExpressionIndex) -> ExpressionIndex:
		"""
		``compare_unsigned_less_equal`` returns comparison expression of size ``size`` checking if expression ``a`` is
		unsigned less than or equal to expression ``b``

		:param int size: size in bytes
		:param ExpressionIndex a: LHS of comparison
		:param ExpressionIndex b: RHS of comparison
		:return: a comparison expression.
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_CMP_ULE, a, b, size = size)

	def compare_signed_greater_equal(self, size:int, a:ExpressionIndex, b:ExpressionIndex) -> ExpressionIndex:
		"""
		``compare_signed_greater_equal`` returns comparison expression of size ``size`` checking if expression ``a`` is
		signed greater than or equal to expression ``b``

		:param int size: size in bytes
		:param ExpressionIndex a: LHS of comparison
		:param ExpressionIndex b: RHS of comparison
		:return: a comparison expression.
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_CMP_SGE, a, b, size = size)

	def compare_unsigned_greater_equal(self, size:int, a:ExpressionIndex, b:ExpressionIndex) -> ExpressionIndex:
		"""
		``compare_unsigned_greater_equal`` returns comparison expression of size ``size`` checking if expression ``a``
		is unsigned greater than or equal to expression ``b``

		:param int size: size in bytes
		:param ExpressionIndex a: LHS of comparison
		:param ExpressionIndex b: RHS of comparison
		:return: a comparison expression.
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_CMP_UGE, a, b, size = size)

	def compare_signed_greater_than(self, size:int, a:ExpressionIndex, b:ExpressionIndex) -> ExpressionIndex:
		"""
		``compare_signed_greater_than`` returns comparison expression of size ``size`` checking if expression ``a`` is
		signed greater than or equal to expression ``b``

		:param int size: size in bytes
		:param ExpressionIndex a: LHS of comparison
		:param ExpressionIndex b: RHS of comparison
		:return: a comparison expression.
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_CMP_SGT, a, b, size = size)

	def compare_unsigned_greater_than(self, size:int, a:ExpressionIndex, b:ExpressionIndex) -> ExpressionIndex:
		"""
		``compare_unsigned_greater_than`` returns comparison expression of size ``size`` checking if expression ``a`` is
		unsigned greater than or equal to expression ``b``

		:param int size: size in bytes
		:param ExpressionIndex a: LHS of comparison
		:param ExpressionIndex b: RHS of comparison
		:return: a comparison expression.
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_CMP_UGT, a, b, size = size)

	def test_bit(self, size:int, a:ExpressionIndex, b:ExpressionIndex) -> ExpressionIndex:
		return self.expr(LowLevelILOperation.LLIL_TEST_BIT, a, b, size = size)

	def system_call(self) -> ExpressionIndex:
		"""
		``system_call`` return a system call expression.

		:return: a system call expression.
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_SYSCALL)

	def intrinsic(self, outputs:List[Union[ILFlag, ExpressionIndex]], intrinsic:'architecture.IntrinsicType',
		params:List[ExpressionIndex], flags:'architecture.FlagType'=None):
		"""
		``intrinsic`` return an intrinsic expression.

		:return: an intrinsic expression.
		:rtype: ExpressionIndex
		"""
		output_list = []
		for output in outputs:
			if isinstance(output, ILFlag):
				output_list.append((1 << 32) | int(output))
			else:
				output_list.append(output)
		param_list = []
		for param in params:
			param_list.append(param)
		call_param = self.expr(LowLevelILOperation.LLIL_CALL_PARAM, len(params), self.add_operand_list(param_list))
		return self.expr(LowLevelILOperation.LLIL_INTRINSIC, len(outputs), self.add_operand_list(output_list),
			self.arch.get_intrinsic_index(intrinsic), call_param, flags = flags)

	def breakpoint(self) -> ExpressionIndex:
		"""
		``breakpoint`` returns a processor breakpoint expression.

		:return: a breakpoint expression.
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_BP)

	def trap(self, value:int) -> ExpressionIndex:
		"""
		``trap`` returns a processor trap (interrupt) expression of the given integer ``value``.

		:param int value: trap (interrupt) number
		:return: a trap expression.
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_TRAP, value)

	def undefined(self) -> ExpressionIndex:
		"""
		``undefined`` returns the undefined expression. This should be used for instructions which perform functions but
		aren't important for dataflow or partial emulation purposes.

		:return: the unimplemented expression.
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_UNDEF)

	def unimplemented(self) -> ExpressionIndex:
		"""
		``unimplemented`` returns the unimplemented expression. This should be used for all instructions which aren't
		implemented.

		:return: the unimplemented expression.
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_UNIMPL)

	def unimplemented_memory_ref(self, size:int, addr:ExpressionIndex) -> ExpressionIndex:
		"""
		``unimplemented_memory_ref`` a memory reference to expression ``addr`` of size ``size`` with unimplemented operation.

		:param int size: size in bytes of the memory reference
		:param ExpressionIndex addr: expression to reference memory
		:return: the unimplemented memory reference expression.
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_UNIMPL_MEM, addr, size = size)

	def float_add(self, size:int, a:ExpressionIndex, b:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``float_add`` adds floating point expression ``a`` to expression ``b`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param str flags: flags to set
		:return: The expression ``fadd.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FADD, a, b, size=size, flags=flags)

	def float_sub(self, size:int, a:ExpressionIndex, b:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``float_sub`` subtracts floating point expression ``b`` from expression ``a`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param str flags: flags to set
		:return: The expression ``fsub.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FSUB, a, b, size=size, flags=flags)

	def float_mult(self, size:int, a:ExpressionIndex, b:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``float_mult`` multiplies floating point expression ``a`` by expression ``b`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param str flags: flags to set
		:return: The expression ``fmul.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FMUL, a, b, size=size, flags=flags)

	def float_div(self, size:int, a:ExpressionIndex, b:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``float_div`` divides floating point expression ``a`` by expression ``b`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param str flags: flags to set
		:return: The expression ``fdiv.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FDIV, a, b, size=size, flags=flags)

	def float_sqrt(self, size:int, value:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``float_sqrt`` returns square root of floating point expression ``value`` of size ``size`` potentially setting flags

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to negate
		:param str flags: optional, flags to set
		:return: The expression ``sqrt.<size>{<flags>}(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FSQRT, value, size=size, flags=flags)

	def float_neg(self, size:int, value:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``float_neg`` returns sign negation of floating point expression ``value`` of size ``size`` potentially setting flags

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to negate
		:param str flags: optional, flags to set
		:return: The expression ``fneg.<size>{<flags>}(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FNEG, value, size=size, flags=flags)

	def float_abs(self, size:int, value:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``float_abs`` returns absolute value of floating point expression ``value`` of size ``size`` potentially setting flags

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to negate
		:param str flags: optional, flags to set
		:return: The expression ``fabs.<size>{<flags>}(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FABS, value, size=size, flags=flags)

	def float_to_int(self, size:int, value:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``float_to_int`` returns integer value of floating point expression ``value`` of size ``size`` potentially setting flags

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to negate
		:param str flags: optional, flags to set
		:return: The expression ``int.<size>{<flags>}(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FLOAT_TO_INT, value, size=size, flags=flags)

	def int_to_float(self, size:int, value:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``int_to_float`` returns floating point value of integer expression ``value`` of size ``size`` potentially setting flags

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to negate
		:param str flags: optional, flags to set
		:return: The expression ``float.<size>{<flags>}(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_INT_TO_FLOAT, value, size=size, flags=flags)

	def float_convert(self, size:int, value:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``int_to_float`` converts floating point value of expression ``value`` to size ``size`` potentially setting flags

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to negate
		:param str flags: optional, flags to set
		:return: The expression ``fconvert.<size>{<flags>}(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FLOAT_CONV, value, size=size, flags=flags)

	def round_to_int(self, size:int, value:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``round_to_int`` rounds a floating point value to the nearest integer

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to negate
		:param str flags: optional, flags to set
		:return: The expression ``roundint.<size>{<flags>}(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_ROUND_TO_INT, value, size=size, flags=flags)

	def floor(self, size:int, value:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``floor`` rounds a floating point value to an integer towards negative infinity

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to negate
		:param str flags: optional, flags to set
		:return: The expression ``roundint.<size>{<flags>}(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FLOOR, value, size=size, flags=flags)

	def ceil(self, size:int, value:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``ceil`` rounds a floating point value to an integer towards positive infinity

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to negate
		:param str flags: optional, flags to set
		:return: The expression ``roundint.<size>{<flags>}(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_CEIL, value, size=size, flags=flags)

	def float_trunc(self, size:int, value:ExpressionIndex, flags:'architecture.FlagType'=None) -> ExpressionIndex:
		"""
		``float_trunc`` rounds a floating point value to an integer towards zero

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to negate
		:param str flags: optional, flags to set
		:return: The expression ``roundint.<size>{<flags>}(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FTRUNC, value, size=size, flags=flags)

	def float_compare_equal(self, size:int, a:ExpressionIndex, b:ExpressionIndex) -> ExpressionIndex:
		"""
		``float_compare_equal`` returns floating point comparison expression of size ``size`` checking if
		expression ``a`` is equal to expression ``b``

		:param int size: the size of the operands in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param str flags: flags to set
		:return: The expression ``a f== b``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FCMP_E, a, b)

	def float_compare_not_equal(self, size:int, a:ExpressionIndex, b:ExpressionIndex) -> ExpressionIndex:
		"""
		``float_compare_not_equal`` returns floating point comparison expression of size ``size`` checking if
		expression ``a`` is not equal to expression ``b``

		:param int size: the size of the operands in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param str flags: flags to set
		:return: The expression ``a f!= b``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FCMP_NE, a, b)

	def float_compare_less_than(self, size:int, a:ExpressionIndex, b:ExpressionIndex) -> ExpressionIndex:
		"""
		``float_compare_less_than`` returns floating point comparison expression of size ``size`` checking if
		expression ``a`` is less than to expression ``b``

		:param int size: the size of the operands in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param str flags: flags to set
		:return: The expression ``a f< b``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FCMP_LT, a, b)

	def float_compare_less_equal(self, size:int, a:ExpressionIndex, b:ExpressionIndex) -> ExpressionIndex:
		"""
		``float_compare_less_equal`` returns floating point comparison expression of size ``size`` checking if
		expression ``a`` is less than or equal to expression ``b``

		:param int size: the size of the operands in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param str flags: flags to set
		:return: The expression ``a f<= b``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FCMP_LE, a, b)

	def float_compare_greater_equal(self, size:int, a:ExpressionIndex, b:ExpressionIndex) -> ExpressionIndex:
		"""
		``float_compare_greater_equal`` returns floating point comparison expression of size ``size`` checking if
		expression ``a`` is greater than or equal to expression ``b``

		:param int size: the size of the operands in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param str flags: flags to set
		:return: The expression ``a f>= b``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FCMP_GE, a, b)

	def float_compare_greater_than(self, size:int, a:ExpressionIndex, b:ExpressionIndex) -> ExpressionIndex:
		"""
		``float_compare_greater_than`` returns floating point comparison expression of size ``size`` checking if
		expression ``a`` is greater than or equal to expression ``b``

		:param int size: the size of the operands in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param str flags: flags to set
		:return: The expression ``a f> b``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FCMP_GT, a, b)

	def float_compare_unordered(self, size:int, a:ExpressionIndex, b:ExpressionIndex) -> ExpressionIndex:
		"""
		``float_compare_unordered`` returns floating point comparison expression of size ``size`` checking if
		expression ``a`` is unordered relative to expression ``b``

		:param int size: the size of the operands in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param str flags: flags to set
		:return: The expression ``is_unordered(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FCMP_UO, a, b)

	def goto(self, label:LowLevelILLabel) -> ExpressionIndex:
		"""
		``goto`` returns a goto expression which jumps to the provided LowLevelILLabel.

		:param LowLevelILLabel label: Label to jump to
		:return: the ExpressionIndex that jumps to the provided label
		:rtype: ExpressionIndex
		"""
		return ExpressionIndex(core.BNLowLevelILGoto(self.handle, label.handle))

	def if_expr(self, operand:ExpressionIndex, t:LowLevelILLabel, f:LowLevelILLabel) -> ExpressionIndex:
		"""
		``if_expr`` returns the ``if`` expression which depending on condition ``operand`` jumps to the LowLevelILLabel
		``t`` when the condition expression ``operand`` is non-zero and ``f`` when it's zero.

		:param ExpressionIndex operand: comparison expression to evaluate.
		:param LowLevelILLabel t: Label for the true branch
		:param LowLevelILLabel f: Label for the false branch
		:return: the ExpressionIndex for the if expression
		:rtype: ExpressionIndex
		"""
		return ExpressionIndex(core.BNLowLevelILIf(self.handle, operand, t.handle, f.handle))

	def mark_label(self, label:LowLevelILLabel) -> None:
		"""
		``mark_label`` assigns a LowLevelILLabel to the current IL address.

		:param LowLevelILLabel label:
		:rtype: None
		"""
		core.BNLowLevelILMarkLabel(self.handle, label.handle)

	def add_label_map(self, labels:Mapping[int, LowLevelILLabel]) -> ExpressionIndex:
		"""
		``add_label_map`` returns a label list expression for the given list of LowLevelILLabel objects.

		:param labels: the list of LowLevelILLabel to get a label list expression from
		:type labels: dict(int, LowLevelILLabel)
		:return: the label list expression
		:rtype: ExpressionIndex
		"""
		label_list = (ctypes.POINTER(core.BNLowLevelILLabel) * len(labels))()
		value_list = (ctypes.POINTER(ctypes.c_ulonglong) * len(labels))()
		for i, (key, value) in enumerate(labels.items()):
			value_list[i] = key
			label_list[i] = value.handle

		return ExpressionIndex(core.BNLowLevelILAddLabelMap(self.handle, value_list, label_list, len(labels)))

	def add_operand_list(self, operands:List[Union[ExpressionIndex, ExpressionIndex]]) -> ExpressionIndex:
		"""
		``add_operand_list`` returns an operand list expression for the given list of integer operands.

		:param operands: list of operand numbers
		:type operands: List(Union[ExpressionIndex, ExpressionIndex])
		:return: an operand list expression
		:rtype: ExpressionIndex
		"""
		operand_list = (ctypes.c_ulonglong * len(operands))()
		for i in range(len(operands)):
			op = operands[i]
			if isinstance(op, int):
				operand_list[i] = ExpressionIndex(op)
			else:
				raise Exception("Invalid operand type")
		return ExpressionIndex(core.BNLowLevelILAddOperandList(self.handle, operand_list, len(operands)))

	def operand(self, n:int, expr:ExpressionIndex) -> ExpressionIndex:
		"""
		``operand`` sets the operand number of the expression ``expr`` and passes back ``expr`` without modification.

		:param int n:
		:param ExpressionIndex expr:
		:return: returns the expression ``expr`` unmodified
		:rtype: ExpressionIndex
		"""
		core.BNLowLevelILSetExprSourceOperand(self.handle, expr, n)
		return expr

	def finalize(self) -> None:
		"""
		``finalize`` ends the function and computes the list of basic blocks.

		:rtype: None
		"""
		core.BNFinalizeLowLevelILFunction(self.handle)

	def generate_ssa_form(self) -> None:
		"""
		``generate_ssa_form`` generate SSA form given the current LLIL

		:rtype: None
		"""
		core.BNGenerateLowLevelILSSAForm(self.handle)

	def add_label_for_address(self, arch:'architecture.Architecture', addr:int) -> None:
		"""
		``add_label_for_address`` adds a low-level IL label for the given architecture ``arch`` at the given virtual
		address ``addr``

		:param Architecture arch: Architecture to add labels for
		:param int addr: the IL address to add a label at
		"""
		if arch is not None:
			arch = arch.handle
		core.BNAddLowLevelILLabelForAddress(self.handle, arch, addr)

	def get_label_for_address(self, arch:'architecture.Architecture', addr:int) -> Optional[LowLevelILLabel]:
		"""
		``get_label_for_address`` returns the LowLevelILLabel for the given Architecture ``arch`` and IL address ``addr``.

		:param Architecture arch:
		:param int addr: IL Address label to retrieve
		:return: the LowLevelILLabel for the given IL address
		:rtype: LowLevelILLabel
		"""
		if arch is not None:
			arch = arch.handle
		label = core.BNGetLowLevelILLabelForAddress(self.handle, arch, addr)
		if label is None:
			return None
		return LowLevelILLabel(label)

	def get_ssa_instruction_index(self, instr:InstructionIndex) -> InstructionIndex:
		return core.BNGetLowLevelILSSAInstructionIndex(self.handle, instr)

	def get_non_ssa_instruction_index(self, instr:InstructionIndex) -> InstructionIndex:
		return core.BNGetLowLevelILNonSSAInstructionIndex(self.handle, instr)

	def get_ssa_reg_definition(self, reg_ssa:SSARegister) -> Optional[LowLevelILInstruction]:
		reg = self.arch.get_reg_index(reg_ssa.reg)
		result = core.BNGetLowLevelILSSARegisterDefinition(self.handle, reg, reg_ssa.version)
		if result >= core.BNGetLowLevelILInstructionCount(self.handle):
			return None
		return self[result]

	def get_ssa_flag_definition(self, flag_ssa:SSAFlag) -> Optional[LowLevelILInstruction]:
		flag = self.arch.get_flag_index(flag_ssa.flag)
		result = core.BNGetLowLevelILSSAFlagDefinition(self.handle, flag, flag_ssa.version)
		if result >= core.BNGetLowLevelILInstructionCount(self.handle):
			return None
		return self[result]

	def get_ssa_memory_definition(self, index:int) -> Optional[LowLevelILInstruction]:
		result = core.BNGetLowLevelILSSAMemoryDefinition(self.handle, index)
		if result >= core.BNGetLowLevelILInstructionCount(self.handle):
			return None
		return self[result]

	def get_ssa_reg_uses(self, reg_ssa:SSARegister) -> List[LowLevelILInstruction]:
		reg = self.arch.get_reg_index(reg_ssa.reg)
		count = ctypes.c_ulonglong()
		instrs = core.BNGetLowLevelILSSARegisterUses(self.handle, reg, reg_ssa.version, count)
		assert instrs is not None, "core.BNGetLowLevelILSSARegisterUses returned None"
		result = []
		for i in range(0, count.value):
			result.append(self[instrs[i]])
		core.BNFreeILInstructionList(instrs)
		return result

	def get_ssa_flag_uses(self, flag_ssa:SSAFlag) -> List[LowLevelILInstruction]:
		flag = self.arch.get_flag_index(flag_ssa.flag)
		count = ctypes.c_ulonglong()
		instrs = core.BNGetLowLevelILSSAFlagUses(self.handle, flag, flag_ssa.version, count)
		assert instrs is not None, "core.BNGetLowLevelILSSAFlagUses returned None"
		result = []
		for i in range(0, count.value):
			result.append(self[instrs[i]])
		core.BNFreeILInstructionList(instrs)
		return result

	def get_ssa_memory_uses(self, index:int) -> List[LowLevelILInstruction]:
		count = ctypes.c_ulonglong()
		instrs = core.BNGetLowLevelILSSAMemoryUses(self.handle, index, count)
		assert instrs is not None, "core.BNGetLowLevelILSSAMemoryUses returned None"
		result = []
		for i in range(0, count.value):
			result.append(self[instrs[i]])
		core.BNFreeILInstructionList(instrs)
		return result

	def get_ssa_reg_value(self, reg_ssa:SSARegister) -> 'variable.RegisterValue':
		reg = self.arch.get_reg_index(reg_ssa.reg)
		value = core.BNGetLowLevelILSSARegisterValue(self.handle, reg, reg_ssa.version)
		result = variable.RegisterValue.from_BNRegisterValue(value, self._arch)
		return result

	def get_ssa_flag_value(self, flag_ssa:SSAFlag) -> 'variable.RegisterValue':
		flag = self.arch.get_flag_index(flag_ssa.flag)
		value = core.BNGetLowLevelILSSAFlagValue(self.handle, flag, flag_ssa.version)
		result = variable.RegisterValue.from_BNRegisterValue(value, self._arch)
		return result

	def get_medium_level_il_instruction_index(self, instr:InstructionIndex) -> Optional['mediumlevelil.InstructionIndex']:
		med_il = self.medium_level_il
		if med_il is None:
			return None
		result = core.BNGetMediumLevelILInstructionIndex(self.handle, instr)
		if result >= core.BNGetMediumLevelILInstructionCount(med_il.handle):
			return None
		return result

	def get_medium_level_il_expr_index(self, expr:ExpressionIndex) -> Optional['mediumlevelil.ExpressionIndex']:
		med_il = self.medium_level_il
		if med_il is None:
			return None
		result = core.BNGetMediumLevelILExprIndex(self.handle, expr)
		if result >= core.BNGetMediumLevelILExprCount(med_il.handle):
			return None
		return result

	def get_medium_level_il_expr_indexes(self, expr:ExpressionIndex) -> List['mediumlevelil.ExpressionIndex']:
		count = ctypes.c_ulonglong()
		exprs = core.BNGetMediumLevelILExprIndexes(self.handle, expr, count)
		assert exprs is not None, "core.BNGetMediumLevelILExprIndexes returned None"
		result = []
		for i in range(0, count.value):
			result.append(exprs[i])
		core.BNFreeILInstructionList(exprs)
		return result

	def get_mapped_medium_level_il_instruction_index(self, instr:InstructionIndex) -> Optional[InstructionIndex]:
		med_il = self.mapped_medium_level_il
		if med_il is None:
			return None
		result = core.BNGetMappedMediumLevelILInstructionIndex(self.handle, instr)
		if result >= core.BNGetMediumLevelILInstructionCount(med_il.handle):
			return None
		return result

	def get_mapped_medium_level_il_expr_index(self, expr:ExpressionIndex) -> Optional['mediumlevelil.ExpressionIndex']:
		med_il = self.mapped_medium_level_il
		if med_il is None:
			return None
		result = core.BNGetMappedMediumLevelILExprIndex(self.handle, expr)
		if result >= core.BNGetMediumLevelILExprCount(med_il.handle):
			return None
		return result

	def get_high_level_il_instruction_index(self, instr:InstructionIndex) -> Optional['highlevelil.InstructionIndex']:
		med_il = self.medium_level_il
		if med_il is None:
			return None
		mlil_instr = self.get_medium_level_il_instruction_index(instr)
		if mlil_instr is None:
			return None
		return med_il.get_high_level_il_instruction_index(mlil_instr)

	def get_high_level_il_expr_index(self, expr:ExpressionIndex) -> Optional['highlevelil.ExpressionIndex']:
		med_il = self.medium_level_il
		if med_il is None:
			return None
		mlil_expr = self.get_medium_level_il_expr_index(expr)
		if mlil_expr is None:
			return None
		return med_il.get_high_level_il_expr_index(mlil_expr)

	def create_graph(self, settings:Optional['function.DisassemblySettings']=None) -> flowgraph.CoreFlowGraph:
		if settings is not None:
			settings_obj = settings.handle
		else:
			settings_obj = None
		return flowgraph.CoreFlowGraph(core.BNCreateLowLevelILFunctionGraph(self.handle, settings_obj))


class LowLevelILBasicBlock(basicblock.BasicBlock):
	def __init__(self, handle:core.BNBasicBlockHandle, owner:LowLevelILFunction, view:Optional['binaryview.BinaryView']):
		super(LowLevelILBasicBlock, self).__init__(handle, view)
		self._il_function = owner

	def __repr__(self):
		arch = self.arch
		if arch:
			return f"<llil block: {arch.name}@{self.start}-{self.end}>"
		else:
			return f"<llil block: {self.start}-{self.end}>"

	def __hash__(self):
		return hash((self.start, self.end, self._il_function))

	def __contains__(self, instruction):
		if type(instruction) != LowLevelILInstruction or instruction.il_basic_block != self:
			return False
		return True

	def __iter__(self) -> Generator['LowLevelILInstruction', None, None]:
		for idx in range(self.start, self.end):
			yield self._il_function[idx]

	def __getitem__(self, idx):
		size = self.end - self.start
		if isinstance(idx, slice):
			return [self[index] for index in range(*idx.indices(size))]
		if idx > size or idx < -size:
			raise IndexError("list index is out of range")
		if idx >= 0:
			return self._il_function[idx + self.start]
		else:
			return self._il_function[self.end + idx]

	def _create_instance(self, handle, view):
		"""Internal method by super to instantiate child instances"""
		return LowLevelILBasicBlock(handle, self._il_function, view)

	@property
	def instruction_count(self) -> int:
		return self.end - self.start

	@property
	def il_function(self) -> LowLevelILFunction:
		return self._il_function


def LLIL_TEMP(n:int) -> int:
	return n | 0x80000000


def LLIL_REG_IS_TEMP(n:int) -> bool:
	return (n & 0x80000000) != 0


def LLIL_GET_TEMP_REG_INDEX(n:int) -> int:
	return n & 0x7fffffff
