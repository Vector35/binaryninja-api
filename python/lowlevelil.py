# Copyright (c) 2015-2026 Vector 35 Inc
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
from typing import Generator, List, Optional, Dict, Union, Tuple, NewType, ClassVar, Set, \
	Callable, Any, Iterator, overload, Mapping
from dataclasses import dataclass

# Binary Ninja components
from .enums import LowLevelILOperation, LowLevelILFlagCondition, DataFlowQueryOption, FunctionGraphType, ILInstructionAttribute
from . import _binaryninjacore as core
from . import basicblock  #required for LowLevelILBasicBlock
from . import function
from . import mediumlevelil
from . import highlevelil
from . import flowgraph
from . import variable
from . import binaryview
from . import architecture
from . import types
from . import deprecation
from .interaction import show_graph_report
from .commonil import (
    BaseILInstruction, Constant, BinaryOperation, Tailcall, UnaryOperation, Comparison, SSA, Phi, FloatingPoint,
    ControlFlow, Terminal, Syscall, Localcall, StackOperation, Return, Signed, Arithmetic, Carry, DoublePrecision,
    Memory, Load, Store, RegisterStack, SetReg, Intrinsic, ILSourceLocation
)

ExpressionIndex = NewType('ExpressionIndex', int)
InstructionIndex = NewType('InstructionIndex', int)
Index = Union[ExpressionIndex, InstructionIndex]
TokenList = List['function.InstructionTextToken']
InstructionOrExpression = Union['LowLevelILInstruction', Index]
ILRegisterType = Union[str, 'ILRegister', int]
ILOperandType = Union[ILRegisterType, 'architecture.ILFlag', int]
LLILInstructionsType = Generator['LowLevelILInstruction', None, None]
OperandsType = Tuple[ExpressionIndex, ExpressionIndex, ExpressionIndex, ExpressionIndex]
LowLevelILOperandType = Union['LowLevelILOperationAndSize', 'ILRegister', 'ILFlag', 'ILIntrinsic', 'ILRegisterStack',
                              int, Dict[int, int], float, 'LowLevelILInstruction',
                              Dict['architecture.RegisterStackName', int], 'SSAFlag', 'SSARegister', 'SSARegisterStack',
                              'ILSemanticFlagClass', 'ILSemanticFlagGroup', 'LowLevelILFlagCondition', List[int],
                              List['LowLevelILInstruction'], List[Union['ILFlag', 'ILRegister']], List['SSARegister'],
                              List['SSARegisterStack'], List['SSAFlag'], List['SSARegisterOrFlag'], None]
ILInstructionAttributeSet = Union[Set[ILInstructionAttribute], List[ILInstructionAttribute]]
LowLevelILVisitorCallback = Callable[[str, LowLevelILOperandType, str, Optional['LowLevelILInstruction']], bool]


class LowLevelILLabel:
	def __init__(self, handle: Optional[core.BNLowLevelILLabel] = None):
		if handle is None:
			self.handle = (core.BNLowLevelILLabel * 1)()
			core.BNLowLevelILInitLabel(self.handle)
		else:
			self.handle = handle

	@property
	def ref(self) -> bool:
		return self.handle[0].ref

	@ref.setter
	def ref(self, value):
		self.handle[0].ref = value

	@property
	def resolved(self) -> bool:
		return self.handle[0].resolved

	@property
	def operand(self) -> InstructionIndex:
		return InstructionIndex(self.handle[0].operand)

	@operand.setter
	def operand(self, value: InstructionIndex):
		self.handle[0].operand = int(value)


@dataclass(frozen=True)
class ILRegister:
	arch: 'architecture.Architecture'
	index: 'architecture.RegisterIndex'

	def __repr__(self):
		return f"<ILRegister: {self.name}>"

	def __str__(self):
		return self.name

	def __int__(self):
		return self.index

	def __eq__(self, other: Union[str, 'ILRegister']):
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
	arch: 'architecture.Architecture'
	index: 'architecture.RegisterStackIndex'

	def __repr__(self):
		return f"<ILRegisterStack: {self.name}>"

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
	arch: 'architecture.Architecture'
	index: 'architecture.FlagIndex'

	def __repr__(self):
		return f"<ILFlag: {self.name}>"

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
	arch: 'architecture.Architecture'
	index: 'architecture.SemanticClassIndex'

	def __repr__(self):
		return f"<ILSemanticFlagClass: {self.name}>"

	def __str__(self):
		return self.name

	def __int__(self):
		return self.index

	@property
	def name(self) -> 'architecture.SemanticClassName':
		return self.arch.get_semantic_flag_class_name(self.index)


@dataclass(frozen=True)
class ILSemanticFlagGroup:
	arch: 'architecture.Architecture'
	index: 'architecture.SemanticGroupIndex'

	def __repr__(self):
		return f"<ILSemanticFlagGroup: {self.name}>"

	def __str__(self):
		return self.name

	def __int__(self):
		return self.index

	@property
	def name(self) -> 'architecture.SemanticGroupName':
		return self.arch.get_semantic_flag_group_name(self.index)


@dataclass(frozen=True)
class ILIntrinsic:
	arch: 'architecture.Architecture'
	index: 'architecture.IntrinsicIndex'

	def __repr__(self):
		return f"<ILIntrinsic: {self.name} - {self.arch}>"

	def __str__(self):
		return self.name

	@property
	def name(self) -> 'architecture.IntrinsicName':
		return self.arch.get_intrinsic_name(self.index)

	@property
	def inputs(self) -> List['architecture.IntrinsicInput']:
		"""``inputs`` is only available if the IL intrinsic is an Architecture intrinsic """
		# Distinct intrinsic IDs can share a display name but have different signatures.
		return self.arch._intrinsics_by_index[self.index][1].inputs

	@property
	def outputs(self) -> List['types.Type']:
		"""``outputs`` is only available if the IL intrinsic is an Architecture intrinsic """
		return self.arch._intrinsics_by_index[self.index][1].outputs


@dataclass(frozen=True)
class SSARegister:
	reg: ILRegister
	version: int

	def __repr__(self):
		return f"<SSARegister: {self.reg} version {self.version}>"


@dataclass(frozen=True)
class SSARegisterStack:
	reg_stack: ILRegisterStack
	version: int

	def __repr__(self):
		return f"<SSARegisterStack: {self.reg_stack} version {self.version}>"


@dataclass(frozen=True)
class SSAFlag:
	flag: ILFlag
	version: int

	def __repr__(self):
		return f"<SSAFlag {self.flag} version {self.version}>"


@dataclass(frozen=True)
class SSARegisterOrFlag:
	reg_or_flag: Union[ILRegister, ILFlag]
	version: int

	def __repr__(self):
		return f"<SSARegisterOrFlag: {self.reg_or_flag} version {self.version}>"


@dataclass(frozen=True)
class LowLevelILOperationAndSize:
	operation: 'LowLevelILOperation'
	size: int

	def __repr__(self):
		if self.size == 0:
			return f"<LowLevelILOperationAndSize: {self.operation.name}>"
		return f"<LowLevelILOperationAndSize: {self.operation.name} {self.size}>"


@dataclass(frozen=True)
class CoreLowLevelILInstruction:
	operation: LowLevelILOperation
	attributes: int
	size: int
	flags: int
	source_operand: ExpressionIndex
	operands: OperandsType
	address: int

	@classmethod
	def from_BNLowLevelILInstruction(cls, instr: core.BNLowLevelILInstruction) -> 'CoreLowLevelILInstruction':
		operands: OperandsType = (
		    ExpressionIndex(instr.operands[0]), ExpressionIndex(instr.operands[1]), ExpressionIndex(instr.operands[2]),
		    ExpressionIndex(instr.operands[3])
		)
		return cls(
		    LowLevelILOperation(instr.operation), instr.attributes, instr.size, instr.flags, instr.sourceOperand, operands, instr.address
		)


@dataclass(frozen=True)
class LowLevelILInstruction(BaseILInstruction):
	"""
	``class LowLevelILInstruction`` Low Level Intermediate Language Instructions are infinite length tree-based
	instructions. Tree-based instructions use infix notation with the left hand operand being the destination operand.
	Infix notation is thus more natural to read than other notations (e.g. x86 ``mov eax, 0`` vs. LLIL ``eax = 0``).
	"""

	function: 'LowLevelILFunction'
	expr_index: ExpressionIndex
	instr: CoreLowLevelILInstruction
	instr_index: Optional[InstructionIndex]
	# ILOperations is deprecated and will be removed in a future version once BNIL Graph no longer uses it
	# Use the visit methods visit, visit_all, and visit_operands
	# BEGIN GENERATED llil-operations: from api/il, do not edit
	ILOperations: ClassVar[Dict[LowLevelILOperation, List[Tuple[str, str]]]] = {
		LowLevelILOperation.LLIL_NOP: [],
		LowLevelILOperation.LLIL_SET_REG: [("dest", "reg"), ("src", "expr")],
		LowLevelILOperation.LLIL_SET_REG_SPLIT: [("hi", "reg"), ("lo", "reg"), ("src", "expr")],
		LowLevelILOperation.LLIL_SET_FLAG: [("dest", "flag"), ("src", "expr")],
		LowLevelILOperation.LLIL_SET_REG_STACK_REL: [("stack", "reg_stack"), ("dest", "expr"), ("src", "expr")],
		LowLevelILOperation.LLIL_REG_STACK_PUSH: [("stack", "reg_stack"), ("src", "expr")],
		LowLevelILOperation.LLIL_ASSERT: [("src", "reg"), ("constraint", "constraint")],
		LowLevelILOperation.LLIL_FORCE_VER: [("dest", "reg")],
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
		LowLevelILOperation.LLIL_CALL_STACK_ADJUST: [
			("dest", "expr"),
			("stack_adjustment", "int"),
			("reg_stack_adjustments", "reg_stack_adjust"),
		],
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
		LowLevelILOperation.LLIL_BP: [],
		LowLevelILOperation.LLIL_TRAP: [("vector", "int")],
		LowLevelILOperation.LLIL_INTRINSIC: [
			("output", "reg_or_flag_list"),
			("intrinsic", "intrinsic"),
			("params", "expr_list"),
		],
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
		LowLevelILOperation.LLIL_SET_REG_STACK_REL_SSA: [
			("stack", "expr"),
			("dest", "expr"),
			("top", "expr"),
			("src", "expr"),
		],
		LowLevelILOperation.LLIL_SET_REG_STACK_ABS_SSA: [("stack", "expr"), ("dest", "reg"), ("src", "expr")],
		LowLevelILOperation.LLIL_REG_SPLIT_DEST_SSA: [("dest", "reg_ssa")],
		LowLevelILOperation.LLIL_REG_STACK_DEST_SSA: [("dest", "reg_stack_ssa"), ("src", "reg_stack_ssa")],
		LowLevelILOperation.LLIL_REG_SSA: [("src", "reg_ssa")],
		LowLevelILOperation.LLIL_REG_SSA_PARTIAL: [("full_reg", "reg_ssa"), ("src", "reg")],
		LowLevelILOperation.LLIL_REG_SPLIT_SSA: [("hi", "reg_ssa"), ("lo", "reg_ssa")],
		LowLevelILOperation.LLIL_REG_STACK_REL_SSA: [("stack", "reg_stack_ssa"), ("src", "expr"), ("top", "expr")],
		LowLevelILOperation.LLIL_REG_STACK_ABS_SSA: [("stack", "reg_stack_ssa"), ("src", "reg")],
		LowLevelILOperation.LLIL_REG_STACK_FREE_REL_SSA: [("stack", "expr"), ("dest", "expr"), ("top", "expr")],
		LowLevelILOperation.LLIL_REG_STACK_FREE_ABS_SSA: [("stack", "expr"), ("dest", "reg")],
		LowLevelILOperation.LLIL_SET_FLAG_SSA: [("dest", "flag_ssa"), ("src", "expr")],
		LowLevelILOperation.LLIL_ASSERT_SSA: [("src", "reg_ssa"), ("constraint", "constraint")],
		LowLevelILOperation.LLIL_FORCE_VER_SSA: [("dest", "reg_ssa"), ("src", "reg_ssa")],
		LowLevelILOperation.LLIL_FLAG_SSA: [("src", "flag_ssa")],
		LowLevelILOperation.LLIL_FLAG_BIT_SSA: [("src", "flag_ssa"), ("bit", "int")],
		LowLevelILOperation.LLIL_CALL_SSA: [
			("output", "reg_ssa_list"),
			("dest", "expr"),
			("stack", "expr"),
			("params", "expr_list"),
		],
		LowLevelILOperation.LLIL_SYSCALL_SSA: [
			("output", "reg_ssa_list"),
			("stack_reg", "reg_ssa"),
			("stack_memory", "int"),
			("params", "expr_list"),
		],
		LowLevelILOperation.LLIL_TAILCALL_SSA: [
			("output", "reg_ssa_list"),
			("dest", "expr"),
			("stack", "expr"),
			("params", "expr_list"),
		],
		LowLevelILOperation.LLIL_CALL_PARAM: [("src", "expr_list")],
		LowLevelILOperation.LLIL_CALL_STACK_SSA: [("src", "reg_ssa"), ("src_memory", "int")],
		LowLevelILOperation.LLIL_CALL_OUTPUT_SSA: [("dest_memory", "int"), ("dest", "reg_ssa_list")],
		LowLevelILOperation.LLIL_SEPARATE_PARAM_LIST_SSA: [("src", "expr_list")],
		LowLevelILOperation.LLIL_SHARED_PARAM_SLOT_SSA: [("src", "expr_list")],
		LowLevelILOperation.LLIL_MEMORY_INTRINSIC_OUTPUT_SSA: [
			("dest_memory", "int"),
			("output", "reg_or_flag_ssa_list"),
		],
		LowLevelILOperation.LLIL_LOAD_SSA: [("src", "expr"), ("src_memory", "int")],
		LowLevelILOperation.LLIL_STORE_SSA: [
			("dest", "expr"),
			("dest_memory", "int"),
			("src_memory", "int"),
			("src", "expr"),
		],
		LowLevelILOperation.LLIL_INTRINSIC_SSA: [
			("output", "reg_or_flag_ssa_list"),
			("intrinsic", "intrinsic"),
			("params", "expr_list"),
		],
		LowLevelILOperation.LLIL_MEMORY_INTRINSIC_SSA: [
			("output", "reg_or_flag_ssa_list"),
			("intrinsic", "intrinsic"),
			("params", "expr_list"),
			("dest_memory", "int"),
			("src_memory", "int"),
		],
		LowLevelILOperation.LLIL_REG_PHI: [("dest", "reg_ssa"), ("src", "reg_ssa_list")],
		LowLevelILOperation.LLIL_REG_STACK_PHI: [("dest", "reg_stack_ssa"), ("src", "reg_stack_ssa_list")],
		LowLevelILOperation.LLIL_FLAG_PHI: [("dest", "flag_ssa"), ("src", "flag_ssa_list")],
		LowLevelILOperation.LLIL_MEM_PHI: [("dest_memory", "int"), ("src_memory", "int_list")],
		LowLevelILOperation.LLIL_BSWAP: [("src", "expr")],
		LowLevelILOperation.LLIL_POPCNT: [("src", "expr")],
		LowLevelILOperation.LLIL_CLZ: [("src", "expr")],
		LowLevelILOperation.LLIL_CTZ: [("src", "expr")],
		LowLevelILOperation.LLIL_RBIT: [("src", "expr")],
		LowLevelILOperation.LLIL_CLS: [("src", "expr")],
		LowLevelILOperation.LLIL_MINS: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_MAXS: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_MINU: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_MAXU: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_ABS: [("src", "expr")],
	}
	# END GENERATED llil-operations

	@staticmethod
	def show_llil_hierarchy():
		"""
		Opens a new tab showing the LLIL hierarchy which includes classes which can
		easily be used with isinstance to match multiple types of IL instructions.
		"""
		graph = flowgraph.FlowGraph()
		nodes = {}
		for instruction in ILInstruction.values():
			instruction.add_subgraph(graph, nodes)
		show_graph_report("LLIL Class Hierarchy Graph", graph)

	@classmethod
	def create(
	    cls, func: 'LowLevelILFunction', expr_index: ExpressionIndex, instr_index: Optional[InstructionIndex] = None
	) -> 'LowLevelILInstruction':
		assert func.arch is not None, "Attempted to create IL instruction with function missing an Architecture"
		inst = core.BNGetLowLevelILByIndex(func.handle, expr_index)
		assert inst is not None, "core.BNGetLowLevelILByIndex returned None"
		core_inst = CoreLowLevelILInstruction.from_BNLowLevelILInstruction(inst)
		if instr_index is None:
			instr_index = func.get_instruction_index_for_expr(expr_index)
		return ILInstruction[core_inst.operation](func, expr_index, core_inst, instr_index)  # type: ignore

	def copy_to(
		self, dest: 'LowLevelILFunction',
		sub_expr_handler: Optional[Callable[['LowLevelILInstruction'], ExpressionIndex]] = None
	) -> ExpressionIndex:
		"""
		``copy_to`` deep copies an expression into a new IL function.
		If provided, the function ``sub_expr_handler`` will be called on every copied sub-expression

		.. warning:: This function should ONLY be called as a part of a lifter or workflow. It will otherwise not do anything useful as analysis will not be running.

		:param LowLevelILFunction dest: Function to copy the expression to
		:param sub_expr_handler: Optional function to call on every copied sub-expression
		:return: Index of the copied expression in the target function
		"""
		return self.function.copy_expr_to(self, dest, sub_expr_handler)

	def __str__(self):
		tokens = self.tokens
		if tokens is None:
			return "invalid"
		result = ""
		for token in tokens:
			result += token.text
		return result

	def __repr__(self):
		return f"<{self.__class__.__name__}: {self}>"

	def __eq__(self, other: 'LowLevelILInstruction') -> bool:
		if not isinstance(other, LowLevelILInstruction):
			return NotImplemented
		return self.function == other.function and self.expr_index == other.expr_index

	def __ne__(self, other: 'LowLevelILInstruction') -> bool:
		if not isinstance(other, LowLevelILInstruction):
			return NotImplemented
		return not (self == other)

	def __lt__(self, other: 'LowLevelILInstruction') -> bool:
		if not isinstance(other, LowLevelILInstruction):
			return NotImplemented
		return self.function == other.function and self.expr_index < other.expr_index

	def __le__(self, other: 'LowLevelILInstruction') -> bool:
		if not isinstance(other, LowLevelILInstruction):
			return NotImplemented
		return self.function == other.function and self.expr_index <= other.expr_index

	def __gt__(self, other: 'LowLevelILInstruction') -> bool:
		if not isinstance(other, LowLevelILInstruction):
			return NotImplemented
		return self.function == other.function and self.expr_index > other.expr_index

	def __ge__(self, other: 'LowLevelILInstruction') -> bool:
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
	def source_location(self) -> ILSourceLocation:
		return ILSourceLocation.from_instruction(self)

	@property
	def tokens(self) -> TokenList:
		"""LLIL tokens (read-only)"""
		# special case for those instructions that don't have tokens
		if isinstance(self, (LowLevelILCallOutputSsa, LowLevelILCallParam, LowLevelILCallStackSsa, LowLevelILMemoryIntrinsicOutputSsa)):
			return []

		count = ctypes.c_ulonglong()
		assert self.function.arch is not None, f"self.function.arch is None"
		tokens = ctypes.POINTER(core.BNInstructionTextToken)()
		result = core.BNGetLowLevelILExprText(
		    self.function.handle, self.function.arch.handle, self.expr_index, None, tokens, count
		)
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
		return LowLevelILInstruction.create(
		    ssa_func, ExpressionIndex(core.BNGetLowLevelILSSAExprIndex(self.function.handle, self.expr_index)),
		    core.BNGetLowLevelILSSAInstructionIndex(self.function.handle, self.instr_index)
		    if self.instr_index is not None else None
		)

	@property
	def non_ssa_form(self) -> 'LowLevelILInstruction':
		"""Non-SSA form of expression (read-only)"""
		non_ssa_function = self.function.non_ssa_form
		assert non_ssa_function is not None
		return LowLevelILInstruction.create(
		    non_ssa_function,
		    ExpressionIndex(core.BNGetLowLevelILNonSSAExprIndex(self.function.handle, self.expr_index)),
		    core.BNGetLowLevelILNonSSAInstructionIndex(self.function.handle, self.instr_index)
		    if self.instr_index is not None else None
		)

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
				except Exception:
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
	def raw_operands(self) -> OperandsType:
		"""Raw operand expression indices as specified by the core structure (read-only)"""
		return self.instr.operands

	@property
	def operands(self) -> List[LowLevelILOperandType]:
		"""
		Operands for the instruction

		Consider using more specific APIs for ``src``, ``dest``, ``params``, etc where appropriate.
		"""
		return list(map(lambda x: x[1], self.detailed_operands))

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		"""
		Returns a list of tuples containing the name of the operand, the operand, and the type of the operand.
		Useful for iterating over all operands of an instruction and sub-instructions.
		"""
		return []

	def traverse(self, cb: Callable[['LowLevelILInstruction', Any], Any], *args: Any, **kwargs: Any) -> Iterator[Any]:
		"""
		``traverse`` is a generator that allows you to traverse the LowLevelILInstruction in a depth-first manner. It will yield the
		result of the callback function for each node in the tree. Arguments can be passed to the callback function using
		``args`` and ``kwargs``. See the `Developer Docs <https://docs.binary.ninja/dev/concepts.html#walking-ils>`_ for more examples.

		:param Callable[[LowLevelILInstruction, Any], Any] cb: The callback function to call for each node in the LowLevelILInstruction
		:param Any args: Custom user-defined arguments
		:param Any kwargs: Custom user-defined keyword arguments
		:return: An iterator of the results of the callback function
		:rtype: Iterator[Any]

		:Example:
			>>> def get_constant_less_than_value(inst: LowLevelILInstruction, value: int) -> int:
			>>>     if isinstance(inst, Constant) and inst.constant < value:
			>>>         return inst.constant
			>>>
			>>> list(inst.traverse(get_constant_less_than_value, 10))
		"""
		if (result := cb(self, *args, **kwargs)) is not None:
			yield result
		for _, op, _ in self.detailed_operands:
			if isinstance(op, LowLevelILInstruction):
				yield from op.traverse(cb, *args, **kwargs)
			elif isinstance(op, list) and all(isinstance(i, LowLevelILInstruction) for i in op):
				for i in op:
					yield from i.traverse(cb, *args, **kwargs) # type: ignore


	@deprecation.deprecated(deprecated_in="4.0.4907", details="Use :py:func:`LowLevelILInstruction.traverse` instead.")
	def visit_all(self, cb: LowLevelILVisitorCallback,
	       name: str = "root", parent: Optional['LowLevelILInstruction'] = None) -> bool:
		"""
		Visits all operands of this instruction and all operands of any sub-instructions.
		Using pre-order traversal.

		:param LowLevelILVisitorCallback cb: Callback function that takes the name of the operand, the operand, operand type, and parent instruction
		:return: True if all instructions were visited, False if the callback returned False
		"""
		if cb(name, self, "LowLevelILInstruction", parent) == False:
			return False
		for name, op, opType in self.detailed_operands:
			if isinstance(op, LowLevelILInstruction):
				if not op.visit_all(cb, name, self):
					return False
			elif isinstance(op, list) and all(isinstance(i, LowLevelILInstruction) for i in op):
				for i in op:
					if not i.visit_all(cb, name, self): # type: ignore
						return False
			elif cb(name, op, opType, self) == False:
				return False
		return True

	@deprecation.deprecated(deprecated_in="4.0.4907", details="Use :py:func:`LowLevelILInstruction.traverse` instead.")
	def visit_operands(self, cb: LowLevelILVisitorCallback,
	       name: str = "root", parent: Optional['LowLevelILInstruction'] = None) -> bool:
		"""
		Visits all leaf operands of this instruction and any sub-instructions.

		:param LowLevelILVisitorCallback cb: Callback function that takes the name of the operand, the operand, operand type, and parent instruction
		:return: True if all instructions were visited, False if the callback returned False
		"""
		for name, op, opType in self.detailed_operands:
			if isinstance(op, LowLevelILInstruction):
				if not op.visit_operands(cb, name, self):
					return False
			elif isinstance(op, list) and all(isinstance(i, LowLevelILInstruction) for i in op):
				for i in op:
					if not i.visit_operands(cb, name, self): # type: ignore
						return False
			elif cb(name, op, opType, self) == False:
				return False
		return True

	@deprecation.deprecated(deprecated_in="4.0.4907", details="Use :py:func:`LowLevelILInstruction.traverse` instead.")
	def visit(self, cb: LowLevelILVisitorCallback,
	       name: str = "root", parent: Optional['LowLevelILInstruction'] = None) -> bool:
		"""
		Visits all LowLevelILInstructions in the operands of this instruction and any sub-instructions.

		:param LowLevelILVisitorCallback cb: Callback function that takes the name of the operand, the operand, operand type, and parent instruction
		:return: True if all instructions were visited, False if the callback returned False
		"""
		if cb(name, self, "LowLevelILInstruction", parent) == False:
			return False
		for name, op, opType in self.detailed_operands:
			if isinstance(op, LowLevelILInstruction):
				if not op.visit(cb, name, self):
					return False
			elif isinstance(op, list) and all(isinstance(i, LowLevelILInstruction) for i in op):
				for i in op:
					if not i.visit(cb, name, self): # type: ignore
						return False
		return True

	@property
	def prefix_operands(self) -> List[LowLevelILOperandType]:
		"""All operands in the expression tree in prefix order"""
		result: List[LowLevelILOperandType] = [LowLevelILOperationAndSize(self.instr.operation, self.instr.size)]
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
		result: List[LowLevelILOperandType] = []
		for operand in self.operands:
			if isinstance(operand, LowLevelILInstruction):
				assert id(self) != id(operand), f"circular reference {operand}({repr(operand)}) is {self}({repr(self)})"
				result.extend(operand.postfix_operands)
			else:
				result.append(operand)
		result.append(LowLevelILOperationAndSize(self.instr.operation, self.instr.size))
		return result

	@property
	def attributes(self) -> Set[ILInstructionAttribute]:
		"""The set of optional attributes placed on the instruction"""
		result: Set[ILInstructionAttribute] = set()
		for flag in ILInstructionAttribute:
			if self.instr.attributes & flag.value != 0:
				result.add(flag)
		return result

	@staticmethod
	def _make_options_array(options: Optional[List[DataFlowQueryOption]]):
		if options is None:
			options = []
		idx = 0
		option_array = (core.DataFlowQueryOptionEnum * len(options))()
		for option in options:
			option_array[idx] = option
			idx += 1
		return option_array, len(options)

	def get_possible_values(self, options: Optional[List[DataFlowQueryOption]] = None) -> variable.PossibleValueSet:
		option_array, option_size = LowLevelILInstruction._make_options_array(options)
		value = core.BNGetLowLevelILPossibleExprValues(self.function.handle, self.expr_index, option_array, option_size)
		result = variable.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_reg_value(self, reg: 'architecture.RegisterType') -> variable.RegisterValue:
		if self.function.arch is None:
			raise Exception("Can not call get_reg_value on function with Architecture set to None")
		reg = self.function.arch.get_reg_index(reg)
		value = core.BNGetLowLevelILRegisterValueAtInstruction(self.function.handle, reg, self.instr_index)
		return variable.RegisterValue.from_BNRegisterValue(value, self.function.arch)

	def get_reg_value_after(self, reg: 'architecture.RegisterType') -> variable.RegisterValue:
		if self.function.arch is None:
			raise Exception("Can not call get_reg_value_after on function with Architecture set to None")
		reg = self.function.arch.get_reg_index(reg)
		value = core.BNGetLowLevelILRegisterValueAfterInstruction(self.function.handle, reg, self.instr_index)
		return variable.RegisterValue.from_BNRegisterValue(value, self.function.arch)

	def get_possible_reg_values(
	    self, reg: 'architecture.RegisterType', options: Optional[List[DataFlowQueryOption]] = None
	) -> 'variable.PossibleValueSet':
		if self.function.arch is None:
			raise Exception("Can not call get_possible_reg_values on function with Architecture set to None")
		reg = self.function.arch.get_reg_index(reg)
		option_array, option_size = LowLevelILInstruction._make_options_array(options)
		value = core.BNGetLowLevelILPossibleRegisterValuesAtInstruction(
		    self.function.handle, reg, self.instr_index, option_array, option_size
		)
		result = variable.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_possible_reg_values_after(
	    self, reg: 'architecture.RegisterType', options: Optional[List[DataFlowQueryOption]] = None
	) -> 'variable.PossibleValueSet':
		if self.function.arch is None:
			raise Exception("Can not call get_possible_reg_values_after on function with Architecture set to None")
		reg = self.function.arch.get_reg_index(reg)
		option_array, option_size = LowLevelILInstruction._make_options_array(options)
		value = core.BNGetLowLevelILPossibleRegisterValuesAfterInstruction(
		    self.function.handle, reg, self.instr_index, option_array, option_size
		)
		result = variable.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_flag_value(self, flag: 'architecture.FlagType') -> 'variable.RegisterValue':
		if self.function.arch is None:
			raise Exception("Can not call get_flag_value on function with Architecture set to None")
		flag = self.function.arch.get_flag_index(flag)
		value = core.BNGetLowLevelILFlagValueAtInstruction(self.function.handle, flag, self.instr_index)
		result = variable.RegisterValue.from_BNRegisterValue(value, self.function.arch)
		return result

	def get_flag_value_after(self, flag: 'architecture.FlagType') -> 'variable.RegisterValue':
		if self.function.arch is None:
			raise Exception("Can not call get_flag_value_after on function with Architecture set to None")
		flag = self.function.arch.get_flag_index(flag)
		value = core.BNGetLowLevelILFlagValueAfterInstruction(self.function.handle, flag, self.instr_index)
		result = variable.RegisterValue.from_BNRegisterValue(value, self.function.arch)
		return result

	def get_possible_flag_values(
	    self, flag: 'architecture.FlagType', options: Optional[List[DataFlowQueryOption]] = None
	) -> 'variable.PossibleValueSet':
		if self.function.arch is None:
			raise Exception("Can not call get_possible_flag_values on function with Architecture set to None")
		flag = self.function.arch.get_flag_index(flag)
		option_array, option_size = LowLevelILInstruction._make_options_array(options)
		value = core.BNGetLowLevelILPossibleFlagValuesAtInstruction(
		    self.function.handle, flag, self.instr_index, option_array, option_size
		)
		result = variable.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_possible_flag_values_after(
	    self, flag: 'architecture.FlagType', options: Optional[List[DataFlowQueryOption]] = None
	) -> 'variable.PossibleValueSet':
		if self.function.arch is None:
			raise Exception("Can not call get_possible_flag_values_after on function with Architecture set to None")
		flag = self.function.arch.get_flag_index(flag)
		option_array, option_size = LowLevelILInstruction._make_options_array(options)
		value = core.BNGetLowLevelILPossibleFlagValuesAfterInstruction(
		    self.function.handle, flag, self.instr_index, option_array, option_size
		)
		result = variable.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_stack_contents(self, offset: int, size: int) -> 'variable.RegisterValue':
		value = core.BNGetLowLevelILStackContentsAtInstruction(self.function.handle, offset, size, self.instr_index)
		result = variable.RegisterValue.from_BNRegisterValue(value, self.function.arch)
		return result

	def get_stack_contents_after(self, offset: int, size: int) -> 'variable.RegisterValue':
		value = core.BNGetLowLevelILStackContentsAfterInstruction(self.function.handle, offset, size, self.instr_index)
		result = variable.RegisterValue.from_BNRegisterValue(value, self.function.arch)
		return result

	def get_possible_stack_contents(
	    self, offset: int, size: int, options: Optional[List[DataFlowQueryOption]] = None
	) -> variable.PossibleValueSet:
		option_array, option_size = LowLevelILInstruction._make_options_array(options)
		value = core.BNGetLowLevelILPossibleStackContentsAtInstruction(
		    self.function.handle, offset, size, self.instr_index, option_array, option_size
		)
		result = variable.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_possible_stack_contents_after(
	    self, offset: int, size: int, options: Optional[List[DataFlowQueryOption]] = None
	) -> variable.PossibleValueSet:
		option_array, option_size = LowLevelILInstruction._make_options_array(options)
		value = core.BNGetLowLevelILPossibleStackContentsAfterInstruction(
		    self.function.handle, offset, size, self.instr_index, option_array, option_size
		)
		result = variable.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	@property
	def flags(self) -> Optional['architecture.FlagWriteTypeName']:
		return self.function.arch.get_flag_write_type_name(architecture.FlagWriteTypeIndex(self.instr.flags))

	@property
	def raw_flags(self) -> int:
		return self.instr.flags

	def _get_reg(self, operand_index: int) -> ILRegister:
		return ILRegister(self.function.arch, architecture.RegisterIndex(self.instr.operands[operand_index]))

	def _get_flag(self, operand_index: int) -> ILFlag:
		return ILFlag(self.function.arch, architecture.FlagIndex(self.instr.operands[operand_index]))

	def _get_intrinsic(self, operand_index: int) -> ILIntrinsic:
		return ILIntrinsic(self.function.arch, architecture.IntrinsicIndex(self.instr.operands[operand_index]))

	def _get_reg_stack(self, operand_index: int) -> ILRegisterStack:
		return ILRegisterStack(self.function.arch, architecture.RegisterStackIndex(self.instr.operands[operand_index]))

	def _get_int(self, operand_index: int) -> int:
		return (self.instr.operands[operand_index] & ((1 << 63) - 1)) - (self.instr.operands[operand_index] & (1 << 63))

	def _get_target_map(self, operand_index: int) -> Dict[int, int]:
		count = ctypes.c_ulonglong()
		operand_list = core.BNLowLevelILGetOperandList(self.function.handle, self.expr_index, operand_index, count)
		assert operand_list is not None, "core.BNLowLevelILGetOperandList returned None"
		try:
			value: Dict[int, int] = {}
			for j in range(count.value // 2):
				key = operand_list[j * 2]
				target = operand_list[(j*2) + 1]
				value[key] = target
			return value
		finally:
			core.BNLowLevelILFreeOperandList(operand_list)

	def _get_float(self, operand_index: int) -> Union[int, float]:
		if self.instr.size == 4:
			return struct.unpack("f", struct.pack("I", self.instr.operands[operand_index] & 0xffffffff))[0]
		elif self.instr.size == 8:
			return struct.unpack("d", struct.pack("Q", self.instr.operands[operand_index]))[0]
		else:
			return self.instr.operands[operand_index]

	def _get_expr(self, operand_index: int) -> 'LowLevelILInstruction':
		return LowLevelILInstruction.create(self.function, self.instr.operands[operand_index], self.instr_index)

	def _get_reg_stack_adjust(self, operand_index: int) -> Dict['architecture.RegisterStackName', int]:
		count = ctypes.c_ulonglong()
		operand_list = core.BNLowLevelILGetOperandList(self.function.handle, self.expr_index, operand_index, count)
		assert operand_list is not None, "core.BNLowLevelILGetOperandList returned None"
		result: Dict['architecture.RegisterStackName', int] = {}
		try:
			for j in range(count.value // 2):
				reg_stack = operand_list[j * 2]
				adjust = operand_list[(j*2) + 1]
				adjust &= 0xffffffff
				if adjust & 0x80000000:
					adjust -= 1 << 32
				result[self.function.arch.get_reg_stack_name(reg_stack)] = adjust
			return result
		finally:
			core.BNLowLevelILFreeOperandList(operand_list)

	def _get_flag_ssa(self, operand_index1: int, operand_index2: int) -> SSAFlag:
		return SSAFlag(
		    ILFlag(self.function.arch, architecture.FlagIndex(self.instr.operands[operand_index1])),
		    self.instr.operands[operand_index2]
		)

	def _get_reg_ssa(self, operand_index1: int, operand_index2: int) -> SSARegister:
		return SSARegister(
		    ILRegister(self.function.arch, architecture.RegisterIndex(self.instr.operands[operand_index1])),
		    self.instr.operands[operand_index2]
		)

	def _get_reg_stack_ssa(self, operand_index1: int, operand_index2: int) -> SSARegisterStack:
		reg_stack = ILRegisterStack(
		    self.function.arch, architecture.RegisterStackIndex(self.instr.operands[operand_index1])
		)
		return SSARegisterStack(reg_stack, self.instr.operands[operand_index2])

	def _get_sem_class(self, operand_index: int) -> Optional[ILSemanticFlagClass]:
		if self.instr.operands[operand_index] == 0:
			return None
		return ILSemanticFlagClass(
		    self.function.arch, architecture.SemanticClassIndex(self.instr.operands[operand_index])
		)

	def _get_sem_group(self, operand_index: int) -> ILSemanticFlagGroup:
		return ILSemanticFlagGroup(
		    self.function.arch, architecture.SemanticGroupIndex(self.instr.operands[operand_index])
		)

	def _get_cond(self, operand_index: int) -> LowLevelILFlagCondition:
		return LowLevelILFlagCondition(self.instr.operands[operand_index])

	def _get_int_list(self, operand_index: int) -> List[int]:
		count = ctypes.c_ulonglong()
		operand_list = core.BNLowLevelILGetOperandList(self.function.handle, self.expr_index, operand_index, count)
		assert operand_list is not None, "core.BNLowLevelILGetOperandList returned None"
		result: List[int] = []
		try:
			for j in range(count.value):
				result.append(operand_list[j])
			return result
		finally:
			core.BNLowLevelILFreeOperandList(operand_list)

	def _get_expr_list(self, operand_index: int) -> List['LowLevelILInstruction']:
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

	def _get_reg_or_flag_list(self, operand_index: int) -> List[Union[ILFlag, ILRegister]]:
		count = ctypes.c_ulonglong()
		operand_list = core.BNLowLevelILGetOperandList(self.function.handle, self.expr_index, operand_index, count)
		assert operand_list is not None, "core.BNLowLevelILGetOperandList returned None"

		result: List[Union[ILFlag, ILRegister]] = []
		try:
			for j in range(count.value):
				if (operand_list[j] & (1 << 32)) != 0:
					result.append(ILFlag(self.function.arch, operand_list[j] & 0xffffffff))
				else:
					result.append(ILRegister(self.function.arch, operand_list[j] & 0xffffffff))
			return result
		finally:
			core.BNLowLevelILFreeOperandList(operand_list)

	def _get_reg_ssa_list(self, operand_index: int) -> List[SSARegister]:
		count = ctypes.c_ulonglong()
		operand_list = core.BNLowLevelILGetOperandList(self.function.handle, self.expr_index, operand_index, count)
		assert operand_list is not None, "core.BNLowLevelILGetOperandList returned None"
		result = []
		try:
			for j in range(count.value // 2):
				reg = operand_list[j * 2]
				reg_version = operand_list[(j*2) + 1]
				result.append(SSARegister(ILRegister(self.function.arch, reg), reg_version))
			return result
		finally:
			core.BNLowLevelILFreeOperandList(operand_list)

	def _get_reg_stack_ssa_list(self, operand_index: int) -> List[SSARegisterStack]:
		count = ctypes.c_ulonglong()
		operand_list = core.BNLowLevelILGetOperandList(self.function.handle, self.expr_index, operand_index, count)
		assert operand_list is not None, "core.BNLowLevelILGetOperandList returned None"
		result: List[SSARegisterStack] = []
		try:
			for j in range(count.value // 2):
				reg_stack = operand_list[j * 2]
				reg_version = operand_list[(j*2) + 1]
				result.append(SSARegisterStack(ILRegisterStack(self.function.arch, reg_stack), reg_version))
			return result
		finally:
			core.BNLowLevelILFreeOperandList(operand_list)

	def _get_flag_ssa_list(self, operand_index: int) -> List[SSAFlag]:
		count = ctypes.c_ulonglong()
		operand_list = core.BNLowLevelILGetOperandList(self.function.handle, self.expr_index, operand_index, count)
		assert operand_list is not None, "core.BNLowLevelILGetOperandList returned None"
		try:
			result: List[SSAFlag] = []
			for j in range(count.value // 2):
				flag = operand_list[j * 2]
				flag_version = operand_list[(j*2) + 1]
				result.append(SSAFlag(ILFlag(self.function.arch, flag), flag_version))
			return result
		finally:
			core.BNLowLevelILFreeOperandList(operand_list)

	def _get_reg_or_flag_ssa_list(self, operand_index: int) -> List[SSARegisterOrFlag]:
		count = ctypes.c_ulonglong()
		operand_list = core.BNLowLevelILGetOperandList(self.function.handle, self.expr_index, operand_index, count)
		assert operand_list is not None, "core.BNLowLevelILGetOperandList returned None"
		result: List[SSARegisterOrFlag] = []
		try:
			for j in range(count.value // 2):
				if (operand_list[j * 2] & (1 << 32)) != 0:
					reg_or_flag = ILFlag(self.function.arch, operand_list[j * 2] & 0xffffffff)
				else:
					reg_or_flag = ILRegister(self.function.arch, operand_list[j * 2] & 0xffffffff)
				reg_version = operand_list[(j*2) + 1]
				result.append(SSARegisterOrFlag(reg_or_flag, reg_version))
			return result
		finally:
			core.BNLowLevelILFreeOperandList(operand_list)

	def _get_constraint(self, operand_index: int) -> variable.PossibleValueSet:
		value = core.BNGetCachedLowLevelILPossibleValueSet(self.function.handle, self.instr.operands[operand_index])
		result = variable.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILBinaryBase(LowLevelILInstruction, BinaryOperation):
	@property
	def left(self) -> LowLevelILInstruction:
		return self._get_expr(0)

	@property
	def right(self) -> LowLevelILInstruction:
		return self._get_expr(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("left", self.left, "LowLevelILInstruction"),
			("right", self.right, "LowLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILComparisonBase(LowLevelILBinaryBase, Comparison):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILCarryBase(LowLevelILInstruction, Carry):
	@property
	def left(self) -> LowLevelILInstruction:
		return self._get_expr(0)

	@property
	def right(self) -> LowLevelILInstruction:
		return self._get_expr(1)

	@property
	def carry(self) -> LowLevelILInstruction:
		return self._get_expr(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("left", self.left, "LowLevelILInstruction"),
			("right", self.right, "LowLevelILInstruction"),
			("carry", self.carry, "LowLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILUnaryBase(LowLevelILInstruction, UnaryOperation):
	@property
	def src(self) -> LowLevelILInstruction:
		return self._get_expr(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("src", self.src, "LowLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILConstantBase(LowLevelILInstruction, Constant):
	def __int__(self):
		return self.constant

	def __bool__(self):
		return self.constant != 0

	def __eq__(self, other: 'LowLevelILConstantBase'):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self.constant == other.constant

	def __ne__(self, other: 'LowLevelILConstantBase'):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self.constant != other.constant

	def __lt__(self, other: 'LowLevelILConstantBase'):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self.constant < other.constant

	def __gt__(self, other: 'LowLevelILConstantBase'):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self.constant > other.constant

	def __le__(self, other: 'LowLevelILConstantBase'):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self.constant <= other.constant

	def __ge__(self, other: 'LowLevelILConstantBase'):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self.constant >= other.constant

	def __hash__(self):
		return LowLevelILInstruction.__hash__(self)

	@property
	def constant(self) -> int:
		return self._get_int(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("constant", self.constant, "int"),
		]


class _ParamListFormatting:
	def __repr__(self):
		return f"<{type(self).__name__}: {self.src}>"

	def __str__(self):
		return str(self.src)


class _CallOutputSsaFormatting:
	def __repr__(self):
		return f"<LowLevelILCallOutputSsa: {self.dest_memory} {self.dest}>"


class _CallStackSsaFormatting:
	def __repr__(self):
		return f"<LowLevelILCallStackSsa: {self.src} @ mem#{self.src_memory}>"


class _MemoryIntrinsicOutputSsaFormatting:
	def __repr__(self):
		return f"<LowLevelILMemoryIntrinsicOutputSsa: {self.dest_memory} {self.output}>"


# BEGIN GENERATED llil-classes: from api/il, do not edit
@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILNop(LowLevelILInstruction):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILSetReg(LowLevelILInstruction, SetReg):
	@property
	def dest(self) -> ILRegister:
		return self._get_reg(0)

	@property
	def src(self) -> LowLevelILInstruction:
		return self._get_expr(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("dest", self.dest, "ILRegister"),
			("src", self.src, "LowLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILSetRegSplit(LowLevelILInstruction, SetReg):
	@property
	def hi(self) -> ILRegister:
		return self._get_reg(0)

	@property
	def lo(self) -> ILRegister:
		return self._get_reg(1)

	@property
	def src(self) -> LowLevelILInstruction:
		return self._get_expr(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("hi", self.hi, "ILRegister"),
			("lo", self.lo, "ILRegister"),
			("src", self.src, "LowLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILSetFlag(LowLevelILInstruction):
	@property
	def dest(self) -> ILFlag:
		return self._get_flag(0)

	@property
	def src(self) -> LowLevelILInstruction:
		return self._get_expr(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("dest", self.dest, "ILFlag"),
			("src", self.src, "LowLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILSetRegStackRel(LowLevelILInstruction, RegisterStack):
	@property
	def stack(self) -> ILRegisterStack:
		return self._get_reg_stack(0)

	@property
	def dest(self) -> LowLevelILInstruction:
		return self._get_expr(1)

	@property
	def src(self) -> LowLevelILInstruction:
		return self._get_expr(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("stack", self.stack, "ILRegisterStack"),
			("dest", self.dest, "LowLevelILInstruction"),
			("src", self.src, "LowLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILRegStackPush(LowLevelILInstruction, RegisterStack):
	@property
	def stack(self) -> ILRegisterStack:
		return self._get_reg_stack(0)

	@property
	def src(self) -> LowLevelILInstruction:
		return self._get_expr(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("stack", self.stack, "ILRegisterStack"),
			("src", self.src, "LowLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILAssert(LowLevelILInstruction):
	@property
	def src(self) -> ILRegister:
		return self._get_reg(0)

	@property
	def constraint(self) -> variable.PossibleValueSet:
		return self._get_constraint(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("src", self.src, "ILRegister"),
			("constraint", self.constraint, "PossibleValueSet"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILForceVer(LowLevelILInstruction):
	@property
	def dest(self) -> ILRegister:
		return self._get_reg(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("dest", self.dest, "ILRegister"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILLoad(LowLevelILUnaryBase, Load):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILStore(LowLevelILInstruction, Store):
	@property
	def dest(self) -> LowLevelILInstruction:
		return self._get_expr(0)

	@property
	def src(self) -> LowLevelILInstruction:
		return self._get_expr(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("dest", self.dest, "LowLevelILInstruction"),
			("src", self.src, "LowLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILPush(LowLevelILUnaryBase, StackOperation):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILPop(LowLevelILInstruction, StackOperation):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILReg(LowLevelILInstruction):
	@property
	def src(self) -> ILRegister:
		return self._get_reg(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("src", self.src, "ILRegister"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILRegSplit(LowLevelILInstruction):
	@property
	def hi(self) -> ILRegister:
		return self._get_reg(0)

	@property
	def lo(self) -> ILRegister:
		return self._get_reg(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("hi", self.hi, "ILRegister"),
			("lo", self.lo, "ILRegister"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILRegStackRel(LowLevelILInstruction, RegisterStack):
	@property
	def stack(self) -> ILRegisterStack:
		return self._get_reg_stack(0)

	@property
	def src(self) -> LowLevelILInstruction:
		return self._get_expr(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("stack", self.stack, "ILRegisterStack"),
			("src", self.src, "LowLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILRegStackPop(LowLevelILInstruction, RegisterStack):
	@property
	def stack(self) -> ILRegisterStack:
		return self._get_reg_stack(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("stack", self.stack, "ILRegisterStack"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILRegStackFreeReg(LowLevelILInstruction, RegisterStack):
	@property
	def dest(self) -> ILRegister:
		return self._get_reg(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("dest", self.dest, "ILRegister"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILRegStackFreeRel(LowLevelILInstruction, RegisterStack):
	@property
	def stack(self) -> ILRegisterStack:
		return self._get_reg_stack(0)

	@property
	def dest(self) -> LowLevelILInstruction:
		return self._get_expr(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("stack", self.stack, "ILRegisterStack"),
			("dest", self.dest, "LowLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILConst(LowLevelILConstantBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILConstPtr(LowLevelILConstantBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILExternPtr(LowLevelILConstantBase):
	@property
	def offset(self) -> int:
		return self._get_int(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("constant", self.constant, "int"),
			("offset", self.offset, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILFloatConst(LowLevelILConstantBase, FloatingPoint):
	@property
	def constant(self) -> Union[int, float]:
		return self._get_float(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("constant", self.constant, "Union[int, float]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILFlag(LowLevelILInstruction):
	@property
	def src(self) -> ILFlag:
		return self._get_flag(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("src", self.src, "ILFlag"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILFlagBit(LowLevelILInstruction):
	@property
	def src(self) -> ILFlag:
		return self._get_flag(0)

	@property
	def bit(self) -> int:
		return self._get_int(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("src", self.src, "ILFlag"),
			("bit", self.bit, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILAdd(LowLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILAdc(LowLevelILCarryBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILSub(LowLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILSbb(LowLevelILCarryBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILAnd(LowLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILOr(LowLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILXor(LowLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILLsl(LowLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILLsr(LowLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILAsr(LowLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILRol(LowLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILRlc(LowLevelILCarryBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILRor(LowLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILRrc(LowLevelILCarryBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILMul(LowLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILMuluDp(LowLevelILBinaryBase, DoublePrecision):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILMulsDp(LowLevelILBinaryBase, DoublePrecision, Signed):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILDivu(LowLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILDivuDp(LowLevelILBinaryBase, DoublePrecision):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILDivs(LowLevelILBinaryBase, Arithmetic, Signed):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILDivsDp(LowLevelILBinaryBase, DoublePrecision, Signed):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILModu(LowLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILModuDp(LowLevelILBinaryBase, DoublePrecision):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILMods(LowLevelILBinaryBase, Arithmetic, Signed):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILModsDp(LowLevelILBinaryBase, DoublePrecision, Signed):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILNeg(LowLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILNot(LowLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILSx(LowLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILZx(LowLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILLowPart(LowLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILJump(LowLevelILInstruction, Terminal):
	@property
	def dest(self) -> LowLevelILInstruction:
		return self._get_expr(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("dest", self.dest, "LowLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILJumpTo(LowLevelILInstruction, Terminal):
	@property
	def dest(self) -> LowLevelILInstruction:
		return self._get_expr(0)

	@property
	def targets(self) -> Dict[int, int]:
		return self._get_target_map(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("dest", self.dest, "LowLevelILInstruction"),
			("targets", self.targets, "Dict[int, int]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILCall(LowLevelILInstruction, Localcall):
	@property
	def dest(self) -> LowLevelILInstruction:
		return self._get_expr(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("dest", self.dest, "LowLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILCallStackAdjust(LowLevelILInstruction, Localcall):
	@property
	def dest(self) -> LowLevelILInstruction:
		return self._get_expr(0)

	@property
	def stack_adjustment(self) -> int:
		return self._get_int(1)

	@property
	def reg_stack_adjustments(self) -> Dict['architecture.RegisterStackName', int]:
		return self._get_reg_stack_adjust(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("dest", self.dest, "LowLevelILInstruction"),
			("stack_adjustment", self.stack_adjustment, "int"),
			("reg_stack_adjustments", self.reg_stack_adjustments, "Dict[RegisterStackName, int]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILTailcall(LowLevelILInstruction, Tailcall):
	@property
	def dest(self) -> LowLevelILInstruction:
		return self._get_expr(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("dest", self.dest, "LowLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILRet(LowLevelILInstruction, Return):
	@property
	def dest(self) -> LowLevelILInstruction:
		return self._get_expr(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("dest", self.dest, "LowLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILNoret(LowLevelILInstruction, Terminal):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILIf(LowLevelILInstruction, ControlFlow):
	@property
	def condition(self) -> LowLevelILInstruction:
		return self._get_expr(0)

	@property
	def true(self) -> InstructionIndex:
		return InstructionIndex(self._get_int(1))

	@property
	def false(self) -> InstructionIndex:
		return InstructionIndex(self._get_int(2))

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("condition", self.condition, "LowLevelILInstruction"),
			("true", self.true, "InstructionIndex"),
			("false", self.false, "InstructionIndex"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILGoto(LowLevelILInstruction, Terminal):
	@property
	def dest(self) -> InstructionIndex:
		return InstructionIndex(self._get_int(0))

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("dest", self.dest, "InstructionIndex"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILFlagCond(LowLevelILInstruction):
	@property
	def condition(self) -> LowLevelILFlagCondition:
		return self._get_cond(0)

	@property
	def semantic_class(self) -> Optional[ILSemanticFlagClass]:
		return self._get_sem_class(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("condition", self.condition, "LowLevelILFlagCondition"),
			("semantic_class", self.semantic_class, "Optional[ILSemanticFlagClass]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILFlagGroup(LowLevelILInstruction):
	@property
	def semantic_group(self) -> ILSemanticFlagGroup:
		return self._get_sem_group(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("semantic_group", self.semantic_group, "ILSemanticFlagGroup"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILCmpE(LowLevelILComparisonBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILCmpNe(LowLevelILComparisonBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILCmpSlt(LowLevelILComparisonBase, Signed):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILCmpUlt(LowLevelILComparisonBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILCmpSle(LowLevelILComparisonBase, Signed):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILCmpUle(LowLevelILComparisonBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILCmpSge(LowLevelILComparisonBase, Signed):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILCmpUge(LowLevelILComparisonBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILCmpSgt(LowLevelILComparisonBase, Signed):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILCmpUgt(LowLevelILComparisonBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILTestBit(LowLevelILComparisonBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILBoolToInt(LowLevelILUnaryBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILAddOverflow(LowLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILSyscall(LowLevelILInstruction, Syscall):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILBp(LowLevelILInstruction, Terminal):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILTrap(LowLevelILInstruction, Terminal):
	@property
	def vector(self) -> int:
		return self._get_int(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("vector", self.vector, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILIntrinsic(LowLevelILInstruction, Intrinsic):
	@property
	def output(self) -> List[Union[ILFlag, ILRegister]]:
		return self._get_reg_or_flag_list(0)

	@property
	def intrinsic(self) -> ILIntrinsic:
		return self._get_intrinsic(2)

	@property
	def param(self) -> 'LowLevelILCallParam':
		result = self._get_expr(3)
		assert isinstance(result, LowLevelILCallParam)
		return result

	@property
	def params(self) -> List[LowLevelILInstruction]:
		return self.param.src

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("output", self.output, "List[Union[ILFlag, ILRegister]]"),
			("intrinsic", self.intrinsic, "ILIntrinsic"),
			("params", self.params, "List[LowLevelILInstruction]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILUndef(LowLevelILInstruction, Terminal):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILUnimpl(LowLevelILInstruction):
	@property
	def unknown(self) -> bool:
		return self._get_int(0) != 0


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILUnimplMem(LowLevelILUnaryBase, Memory):
	@property
	def unknown(self) -> bool:
		return self._get_int(1) != 0


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILFadd(LowLevelILBinaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILFsub(LowLevelILBinaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILFmul(LowLevelILBinaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILFdiv(LowLevelILBinaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILFsqrt(LowLevelILUnaryBase, FloatingPoint, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILFneg(LowLevelILUnaryBase, FloatingPoint, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILFabs(LowLevelILUnaryBase, FloatingPoint, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILFloatToInt(LowLevelILUnaryBase, FloatingPoint, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILIntToFloat(LowLevelILUnaryBase, FloatingPoint, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILFloatConv(LowLevelILUnaryBase, FloatingPoint, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILRoundToInt(LowLevelILUnaryBase, FloatingPoint, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILFloor(LowLevelILUnaryBase, FloatingPoint, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILCeil(LowLevelILUnaryBase, FloatingPoint, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILFtrunc(LowLevelILUnaryBase, FloatingPoint, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILFcmpE(LowLevelILComparisonBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILFcmpNe(LowLevelILComparisonBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILFcmpLt(LowLevelILComparisonBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILFcmpLe(LowLevelILComparisonBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILFcmpGe(LowLevelILComparisonBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILFcmpGt(LowLevelILComparisonBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILFcmpO(LowLevelILComparisonBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILFcmpUo(LowLevelILComparisonBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILSetRegSsa(LowLevelILInstruction, SetReg, SSA):
	@property
	def dest(self) -> SSARegister:
		return self._get_reg_ssa(0, 1)

	@property
	def src(self) -> LowLevelILInstruction:
		return self._get_expr(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("dest", self.dest, "SSARegister"),
			("src", self.src, "LowLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILSetRegSsaPartial(LowLevelILInstruction, SetReg, SSA):
	@property
	def full_reg(self) -> SSARegister:
		return self._get_reg_ssa(0, 1)

	@property
	def dest(self) -> ILRegister:
		return self._get_reg(2)

	@property
	def src(self) -> LowLevelILInstruction:
		return self._get_expr(3)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("full_reg", self.full_reg, "SSARegister"),
			("dest", self.dest, "ILRegister"),
			("src", self.src, "LowLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILSetRegSplitSsa(LowLevelILInstruction, SetReg, SSA):
	@property
	def hi(self) -> 'LowLevelILRegSplitDestSsa':
		result = self._get_expr(0)
		assert isinstance(result, LowLevelILRegSplitDestSsa)
		return result

	@property
	def hi_reg(self) -> SSARegister:
		return self.hi.dest

	@property
	def lo(self) -> 'LowLevelILRegSplitDestSsa':
		result = self._get_expr(1)
		assert isinstance(result, LowLevelILRegSplitDestSsa)
		return result

	@property
	def lo_reg(self) -> SSARegister:
		return self.lo.dest

	@property
	def src(self) -> LowLevelILInstruction:
		return self._get_expr(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("hi", self.hi, "LowLevelILInstruction"),
			("lo", self.lo, "LowLevelILInstruction"),
			("src", self.src, "LowLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILSetRegStackRelSsa(LowLevelILInstruction, RegisterStack, SSA):
	@property
	def stack(self) -> 'LowLevelILRegStackDestSsa':
		result = self._get_expr(0)
		assert isinstance(result, LowLevelILRegStackDestSsa)
		return result

	@property
	def dest_stack(self) -> SSARegisterStack:
		return self.stack.dest

	@property
	def src_stack(self) -> SSARegisterStack:
		return self.stack.src

	@property
	def dest(self) -> LowLevelILInstruction:
		return self._get_expr(1)

	@property
	def top(self) -> 'LowLevelILRegSsa':
		result = self._get_expr(2)
		assert isinstance(result, LowLevelILRegSsa)
		return result

	@property
	def top_reg(self) -> SSARegister:
		return self.top.src

	@property
	def src(self) -> LowLevelILInstruction:
		return self._get_expr(3)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("stack", self.stack, "LowLevelILInstruction"),
			("dest", self.dest, "LowLevelILInstruction"),
			("top", self.top, "LowLevelILInstruction"),
			("src", self.src, "LowLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILSetRegStackAbsSsa(LowLevelILInstruction, RegisterStack, SSA):
	@property
	def stack(self) -> 'LowLevelILRegStackDestSsa':
		result = self._get_expr(0)
		assert isinstance(result, LowLevelILRegStackDestSsa)
		return result

	@property
	def dest_stack(self) -> SSARegisterStack:
		return self.stack.dest

	@property
	def src_stack(self) -> SSARegisterStack:
		return self.stack.src

	@property
	def dest(self) -> ILRegister:
		return self._get_reg(1)

	@property
	def src(self) -> LowLevelILInstruction:
		return self._get_expr(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("stack", self.stack, "LowLevelILInstruction"),
			("dest", self.dest, "ILRegister"),
			("src", self.src, "LowLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILRegSplitDestSsa(LowLevelILInstruction, SSA):
	@property
	def dest(self) -> SSARegister:
		return self._get_reg_ssa(0, 1)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("dest", self.dest, "SSARegister"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILRegStackDestSsa(LowLevelILInstruction, RegisterStack, SSA):
	@property
	def dest(self) -> SSARegisterStack:
		return self._get_reg_stack_ssa(0, 1)

	@property
	def src(self) -> SSARegisterStack:
		return self._get_reg_stack_ssa(0, 2)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("dest", self.dest, "SSARegisterStack"),
			("src", self.src, "SSARegisterStack"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILRegSsa(LowLevelILInstruction, SSA):
	@property
	def src(self) -> SSARegister:
		return self._get_reg_ssa(0, 1)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("src", self.src, "SSARegister"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILRegSsaPartial(LowLevelILInstruction, SSA):
	@property
	def full_reg(self) -> SSARegister:
		return self._get_reg_ssa(0, 1)

	@property
	def src(self) -> ILRegister:
		return self._get_reg(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("full_reg", self.full_reg, "SSARegister"),
			("src", self.src, "ILRegister"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILRegSplitSsa(LowLevelILInstruction, SSA):
	@property
	def hi(self) -> SSARegister:
		return self._get_reg_ssa(0, 1)

	@property
	def lo(self) -> SSARegister:
		return self._get_reg_ssa(2, 3)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("hi", self.hi, "SSARegister"),
			("lo", self.lo, "SSARegister"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILRegStackRelSsa(LowLevelILInstruction, RegisterStack, SSA):
	@property
	def stack(self) -> SSARegisterStack:
		return self._get_reg_stack_ssa(0, 1)

	@property
	def src(self) -> LowLevelILInstruction:
		return self._get_expr(2)

	@property
	def top(self) -> 'LowLevelILRegSsa':
		result = self._get_expr(3)
		assert isinstance(result, LowLevelILRegSsa)
		return result

	@property
	def top_reg(self) -> SSARegister:
		return self.top.src

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("stack", self.stack, "SSARegisterStack"),
			("src", self.src, "LowLevelILInstruction"),
			("top", self.top, "LowLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILRegStackAbsSsa(LowLevelILInstruction, RegisterStack, SSA):
	@property
	def stack(self) -> SSARegisterStack:
		return self._get_reg_stack_ssa(0, 1)

	@property
	def src(self) -> ILRegister:
		return self._get_reg(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("stack", self.stack, "SSARegisterStack"),
			("src", self.src, "ILRegister"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILRegStackFreeRelSsa(LowLevelILInstruction, RegisterStack, SSA):
	@property
	def stack(self) -> 'LowLevelILRegStackDestSsa':
		result = self._get_expr(0)
		assert isinstance(result, LowLevelILRegStackDestSsa)
		return result

	@property
	def dest_stack(self) -> SSARegisterStack:
		return self.stack.dest

	@property
	def src_stack(self) -> SSARegisterStack:
		return self.stack.src

	@property
	def dest(self) -> LowLevelILInstruction:
		return self._get_expr(1)

	@property
	def top(self) -> 'LowLevelILRegSsa':
		result = self._get_expr(2)
		assert isinstance(result, LowLevelILRegSsa)
		return result

	@property
	def top_reg(self) -> SSARegister:
		return self.top.src

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("stack", self.stack, "LowLevelILInstruction"),
			("dest", self.dest, "LowLevelILInstruction"),
			("top", self.top, "LowLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILRegStackFreeAbsSsa(LowLevelILInstruction, RegisterStack, SSA):
	@property
	def stack(self) -> 'LowLevelILRegStackDestSsa':
		result = self._get_expr(0)
		assert isinstance(result, LowLevelILRegStackDestSsa)
		return result

	@property
	def dest_stack(self) -> SSARegisterStack:
		return self.stack.dest

	@property
	def src_stack(self) -> SSARegisterStack:
		return self.stack.src

	@property
	def dest(self) -> ILRegister:
		return self._get_reg(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("stack", self.stack, "LowLevelILInstruction"),
			("dest", self.dest, "ILRegister"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILSetFlagSsa(LowLevelILInstruction, SSA):
	@property
	def dest(self) -> SSAFlag:
		return self._get_flag_ssa(0, 1)

	@property
	def src(self) -> LowLevelILInstruction:
		return self._get_expr(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("dest", self.dest, "SSAFlag"),
			("src", self.src, "LowLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILAssertSsa(LowLevelILInstruction, SSA):
	@property
	def src(self) -> SSARegister:
		return self._get_reg_ssa(0, 1)

	@property
	def constraint(self) -> variable.PossibleValueSet:
		return self._get_constraint(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("src", self.src, "SSARegister"),
			("constraint", self.constraint, "PossibleValueSet"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILForceVerSsa(LowLevelILInstruction, SSA):
	@property
	def dest(self) -> SSARegister:
		return self._get_reg_ssa(0, 1)

	@property
	def src(self) -> SSARegister:
		return self._get_reg_ssa(2, 3)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("dest", self.dest, "SSARegister"),
			("src", self.src, "SSARegister"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILFlagSsa(LowLevelILInstruction, SSA):
	@property
	def src(self) -> SSAFlag:
		return self._get_flag_ssa(0, 1)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("src", self.src, "SSAFlag"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILFlagBitSsa(LowLevelILInstruction, SSA):
	@property
	def src(self) -> SSAFlag:
		return self._get_flag_ssa(0, 1)

	@property
	def bit(self) -> int:
		return self._get_int(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("src", self.src, "SSAFlag"),
			("bit", self.bit, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILCallSsa(LowLevelILInstruction, Localcall, SSA):
	@property
	def output_expr(self) -> 'LowLevelILCallOutputSsa':
		result = self._get_expr(0)
		assert isinstance(result, LowLevelILCallOutputSsa)
		return result

	@property
	def output(self) -> List[SSARegister]:
		return self.output_expr.dest

	@property
	def dest_memory(self) -> int:
		return self.output_expr.dest_memory

	@property
	def dest(self) -> LowLevelILInstruction:
		return self._get_expr(1)

	@property
	def stack(self) -> 'LowLevelILCallStackSsa':
		result = self._get_expr(2)
		assert isinstance(result, LowLevelILCallStackSsa)
		return result

	@property
	def stack_reg(self) -> SSARegister:
		return self.stack.src

	@property
	def stack_memory(self) -> int:
		return self.stack.src_memory

	@property
	def param(self) -> 'LowLevelILCallParam':
		result = self._get_expr(3)
		assert isinstance(result, LowLevelILCallParam)
		return result

	@property
	def params(self) -> List[LowLevelILInstruction]:
		return self.param.src

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("output", self.output, "List[SSARegister]"),
			("dest", self.dest, "LowLevelILInstruction"),
			("stack", self.stack, "LowLevelILInstruction"),
			("params", self.params, "List[LowLevelILInstruction]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILSyscallSsa(LowLevelILInstruction, Syscall, SSA):
	@property
	def output_expr(self) -> 'LowLevelILCallOutputSsa':
		result = self._get_expr(0)
		assert isinstance(result, LowLevelILCallOutputSsa)
		return result

	@property
	def output(self) -> List[SSARegister]:
		return self.output_expr.dest

	@property
	def dest_memory(self) -> int:
		return self.output_expr.dest_memory

	@property
	def stack(self) -> 'LowLevelILCallStackSsa':
		result = self._get_expr(1)
		assert isinstance(result, LowLevelILCallStackSsa)
		return result

	@property
	def stack_reg(self) -> SSARegister:
		return self.stack.src

	@property
	def stack_memory(self) -> int:
		return self.stack.src_memory

	@property
	def param(self) -> 'LowLevelILCallParam':
		result = self._get_expr(2)
		assert isinstance(result, LowLevelILCallParam)
		return result

	@property
	def params(self) -> List[LowLevelILInstruction]:
		return self.param.src

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("output", self.output, "List[SSARegister]"),
			("stack_reg", self.stack_reg, "SSARegister"),
			("stack_memory", self.stack_memory, "int"),
			("params", self.params, "List[LowLevelILInstruction]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILTailcallSsa(LowLevelILInstruction, Tailcall, SSA):
	@property
	def output_expr(self) -> 'LowLevelILCallOutputSsa':
		result = self._get_expr(0)
		assert isinstance(result, LowLevelILCallOutputSsa)
		return result

	@property
	def output(self) -> List[SSARegister]:
		return self.output_expr.dest

	@property
	def dest_memory(self) -> int:
		return self.output_expr.dest_memory

	@property
	def dest(self) -> LowLevelILInstruction:
		return self._get_expr(1)

	@property
	def stack(self) -> 'LowLevelILCallStackSsa':
		result = self._get_expr(2)
		assert isinstance(result, LowLevelILCallStackSsa)
		return result

	@property
	def stack_reg(self) -> SSARegister:
		return self.stack.src

	@property
	def stack_memory(self) -> int:
		return self.stack.src_memory

	@property
	def param(self) -> 'LowLevelILCallParam':
		result = self._get_expr(3)
		assert isinstance(result, LowLevelILCallParam)
		return result

	@property
	def params(self) -> List[LowLevelILInstruction]:
		return self.param.src

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("output", self.output, "List[SSARegister]"),
			("dest", self.dest, "LowLevelILInstruction"),
			("stack", self.stack, "LowLevelILInstruction"),
			("params", self.params, "List[LowLevelILInstruction]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILCallParam(_ParamListFormatting, LowLevelILInstruction, SSA):
	@property
	def src(self) -> List[LowLevelILInstruction]:
		return self._get_expr_list(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("src", self.src, "List[LowLevelILInstruction]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILCallStackSsa(_CallStackSsaFormatting, LowLevelILInstruction, SSA):
	@property
	def src(self) -> SSARegister:
		return self._get_reg_ssa(0, 1)

	@property
	def src_memory(self) -> int:
		return self._get_int(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("src", self.src, "SSARegister"),
			("src_memory", self.src_memory, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILCallOutputSsa(_CallOutputSsaFormatting, LowLevelILInstruction, SSA):
	@property
	def dest_memory(self) -> int:
		return self._get_int(0)

	@property
	def dest(self) -> List[SSARegister]:
		return self._get_reg_ssa_list(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("dest_memory", self.dest_memory, "int"),
			("dest", self.dest, "List[SSARegister]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILSeparateParamListSsa(_ParamListFormatting, LowLevelILInstruction, SSA):
	@property
	def src(self) -> List[LowLevelILInstruction]:
		return self._get_expr_list(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("src", self.src, "List[LowLevelILInstruction]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILSharedParamSlotSsa(_ParamListFormatting, LowLevelILInstruction, SSA):
	@property
	def src(self) -> List[LowLevelILInstruction]:
		return self._get_expr_list(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("src", self.src, "List[LowLevelILInstruction]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILMemoryIntrinsicOutputSsa(_MemoryIntrinsicOutputSsaFormatting, LowLevelILInstruction, SSA):
	@property
	def dest_memory(self) -> int:
		return self._get_int(0)

	@property
	def output(self) -> List[SSARegisterOrFlag]:
		return self._get_reg_or_flag_ssa_list(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("dest_memory", self.dest_memory, "int"),
			("output", self.output, "List[SSARegisterOrFlag]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILLoadSsa(LowLevelILInstruction, Load, SSA):
	@property
	def src(self) -> LowLevelILInstruction:
		return self._get_expr(0)

	@property
	def src_memory(self) -> int:
		return self._get_int(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("src", self.src, "LowLevelILInstruction"),
			("src_memory", self.src_memory, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILStoreSsa(LowLevelILInstruction, Store, SSA):
	@property
	def dest(self) -> LowLevelILInstruction:
		return self._get_expr(0)

	@property
	def dest_memory(self) -> int:
		return self._get_int(1)

	@property
	def src_memory(self) -> int:
		return self._get_int(2)

	@property
	def src(self) -> LowLevelILInstruction:
		return self._get_expr(3)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("dest", self.dest, "LowLevelILInstruction"),
			("dest_memory", self.dest_memory, "int"),
			("src_memory", self.src_memory, "int"),
			("src", self.src, "LowLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILIntrinsicSsa(LowLevelILInstruction, SSA):
	@property
	def output(self) -> List[SSARegisterOrFlag]:
		return self._get_reg_or_flag_ssa_list(0)

	@property
	def intrinsic(self) -> ILIntrinsic:
		return self._get_intrinsic(2)

	@property
	def param(self) -> 'LowLevelILCallParam':
		result = self._get_expr(3)
		assert isinstance(result, LowLevelILCallParam)
		return result

	@property
	def params(self) -> List[LowLevelILInstruction]:
		return self.param.src

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("output", self.output, "List[SSARegisterOrFlag]"),
			("intrinsic", self.intrinsic, "ILIntrinsic"),
			("params", self.params, "List[LowLevelILInstruction]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILMemoryIntrinsicSsa(LowLevelILInstruction, SSA):
	@property
	def output_expr(self) -> 'LowLevelILMemoryIntrinsicOutputSsa':
		result = self._get_expr(0)
		assert isinstance(result, LowLevelILMemoryIntrinsicOutputSsa)
		return result

	@property
	def output(self) -> List[SSARegisterOrFlag]:
		return self.output_expr.output

	@property
	def dest_memory(self) -> int:
		return self.output_expr.dest_memory

	@property
	def intrinsic(self) -> ILIntrinsic:
		return self._get_intrinsic(1)

	@property
	def param(self) -> 'LowLevelILCallParam':
		result = self._get_expr(2)
		assert isinstance(result, LowLevelILCallParam)
		return result

	@property
	def params(self) -> List[LowLevelILInstruction]:
		return self.param.src

	@property
	def src_memory(self) -> int:
		return self._get_int(3)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("output", self.output, "List[SSARegisterOrFlag]"),
			("intrinsic", self.intrinsic, "ILIntrinsic"),
			("params", self.params, "List[LowLevelILInstruction]"),
			("dest_memory", self.dest_memory, "int"),
			("src_memory", self.src_memory, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILRegPhi(LowLevelILInstruction, Phi):
	@property
	def dest(self) -> SSARegister:
		return self._get_reg_ssa(0, 1)

	@property
	def src(self) -> List[SSARegister]:
		return self._get_reg_ssa_list(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("dest", self.dest, "SSARegister"),
			("src", self.src, "List[SSARegister]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILRegStackPhi(LowLevelILInstruction, RegisterStack, Phi):
	@property
	def dest(self) -> SSARegisterStack:
		return self._get_reg_stack_ssa(0, 1)

	@property
	def src(self) -> List[SSARegisterStack]:
		return self._get_reg_stack_ssa_list(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("dest", self.dest, "SSARegisterStack"),
			("src", self.src, "List[SSARegisterStack]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILFlagPhi(LowLevelILInstruction, Phi):
	@property
	def dest(self) -> SSAFlag:
		return self._get_flag_ssa(0, 1)

	@property
	def src(self) -> List[SSAFlag]:
		return self._get_flag_ssa_list(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("dest", self.dest, "SSAFlag"),
			("src", self.src, "List[SSAFlag]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILMemPhi(LowLevelILInstruction, Memory, Phi):
	@property
	def dest_memory(self) -> int:
		return self._get_int(0)

	@property
	def src_memory(self) -> List[int]:
		return self._get_int_list(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, LowLevelILOperandType, str]]:
		return [
			("dest_memory", self.dest_memory, "int"),
			("src_memory", self.src_memory, "List[int]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILBswap(LowLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILPopcnt(LowLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILClz(LowLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILCtz(LowLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILRbit(LowLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILCls(LowLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILMins(LowLevelILBinaryBase, Arithmetic, Signed):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILMaxs(LowLevelILBinaryBase, Arithmetic, Signed):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILMinu(LowLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILMaxu(LowLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class LowLevelILAbs(LowLevelILUnaryBase, Arithmetic):
	pass


ILInstruction: Dict[LowLevelILOperation, type[LowLevelILInstruction]] = {
	LowLevelILOperation.LLIL_NOP: LowLevelILNop,
	LowLevelILOperation.LLIL_SET_REG: LowLevelILSetReg,
	LowLevelILOperation.LLIL_SET_REG_SPLIT: LowLevelILSetRegSplit,
	LowLevelILOperation.LLIL_SET_FLAG: LowLevelILSetFlag,
	LowLevelILOperation.LLIL_SET_REG_STACK_REL: LowLevelILSetRegStackRel,
	LowLevelILOperation.LLIL_REG_STACK_PUSH: LowLevelILRegStackPush,
	LowLevelILOperation.LLIL_ASSERT: LowLevelILAssert,
	LowLevelILOperation.LLIL_FORCE_VER: LowLevelILForceVer,
	LowLevelILOperation.LLIL_LOAD: LowLevelILLoad,
	LowLevelILOperation.LLIL_STORE: LowLevelILStore,
	LowLevelILOperation.LLIL_PUSH: LowLevelILPush,
	LowLevelILOperation.LLIL_POP: LowLevelILPop,
	LowLevelILOperation.LLIL_REG: LowLevelILReg,
	LowLevelILOperation.LLIL_REG_SPLIT: LowLevelILRegSplit,
	LowLevelILOperation.LLIL_REG_STACK_REL: LowLevelILRegStackRel,
	LowLevelILOperation.LLIL_REG_STACK_POP: LowLevelILRegStackPop,
	LowLevelILOperation.LLIL_REG_STACK_FREE_REG: LowLevelILRegStackFreeReg,
	LowLevelILOperation.LLIL_REG_STACK_FREE_REL: LowLevelILRegStackFreeRel,
	LowLevelILOperation.LLIL_CONST: LowLevelILConst,
	LowLevelILOperation.LLIL_CONST_PTR: LowLevelILConstPtr,
	LowLevelILOperation.LLIL_EXTERN_PTR: LowLevelILExternPtr,
	LowLevelILOperation.LLIL_FLOAT_CONST: LowLevelILFloatConst,
	LowLevelILOperation.LLIL_FLAG: LowLevelILFlag,
	LowLevelILOperation.LLIL_FLAG_BIT: LowLevelILFlagBit,
	LowLevelILOperation.LLIL_ADD: LowLevelILAdd,
	LowLevelILOperation.LLIL_ADC: LowLevelILAdc,
	LowLevelILOperation.LLIL_SUB: LowLevelILSub,
	LowLevelILOperation.LLIL_SBB: LowLevelILSbb,
	LowLevelILOperation.LLIL_AND: LowLevelILAnd,
	LowLevelILOperation.LLIL_OR: LowLevelILOr,
	LowLevelILOperation.LLIL_XOR: LowLevelILXor,
	LowLevelILOperation.LLIL_LSL: LowLevelILLsl,
	LowLevelILOperation.LLIL_LSR: LowLevelILLsr,
	LowLevelILOperation.LLIL_ASR: LowLevelILAsr,
	LowLevelILOperation.LLIL_ROL: LowLevelILRol,
	LowLevelILOperation.LLIL_RLC: LowLevelILRlc,
	LowLevelILOperation.LLIL_ROR: LowLevelILRor,
	LowLevelILOperation.LLIL_RRC: LowLevelILRrc,
	LowLevelILOperation.LLIL_MUL: LowLevelILMul,
	LowLevelILOperation.LLIL_MULU_DP: LowLevelILMuluDp,
	LowLevelILOperation.LLIL_MULS_DP: LowLevelILMulsDp,
	LowLevelILOperation.LLIL_DIVU: LowLevelILDivu,
	LowLevelILOperation.LLIL_DIVU_DP: LowLevelILDivuDp,
	LowLevelILOperation.LLIL_DIVS: LowLevelILDivs,
	LowLevelILOperation.LLIL_DIVS_DP: LowLevelILDivsDp,
	LowLevelILOperation.LLIL_MODU: LowLevelILModu,
	LowLevelILOperation.LLIL_MODU_DP: LowLevelILModuDp,
	LowLevelILOperation.LLIL_MODS: LowLevelILMods,
	LowLevelILOperation.LLIL_MODS_DP: LowLevelILModsDp,
	LowLevelILOperation.LLIL_NEG: LowLevelILNeg,
	LowLevelILOperation.LLIL_NOT: LowLevelILNot,
	LowLevelILOperation.LLIL_SX: LowLevelILSx,
	LowLevelILOperation.LLIL_ZX: LowLevelILZx,
	LowLevelILOperation.LLIL_LOW_PART: LowLevelILLowPart,
	LowLevelILOperation.LLIL_JUMP: LowLevelILJump,
	LowLevelILOperation.LLIL_JUMP_TO: LowLevelILJumpTo,
	LowLevelILOperation.LLIL_CALL: LowLevelILCall,
	LowLevelILOperation.LLIL_CALL_STACK_ADJUST: LowLevelILCallStackAdjust,
	LowLevelILOperation.LLIL_TAILCALL: LowLevelILTailcall,
	LowLevelILOperation.LLIL_RET: LowLevelILRet,
	LowLevelILOperation.LLIL_NORET: LowLevelILNoret,
	LowLevelILOperation.LLIL_IF: LowLevelILIf,
	LowLevelILOperation.LLIL_GOTO: LowLevelILGoto,
	LowLevelILOperation.LLIL_FLAG_COND: LowLevelILFlagCond,
	LowLevelILOperation.LLIL_FLAG_GROUP: LowLevelILFlagGroup,
	LowLevelILOperation.LLIL_CMP_E: LowLevelILCmpE,
	LowLevelILOperation.LLIL_CMP_NE: LowLevelILCmpNe,
	LowLevelILOperation.LLIL_CMP_SLT: LowLevelILCmpSlt,
	LowLevelILOperation.LLIL_CMP_ULT: LowLevelILCmpUlt,
	LowLevelILOperation.LLIL_CMP_SLE: LowLevelILCmpSle,
	LowLevelILOperation.LLIL_CMP_ULE: LowLevelILCmpUle,
	LowLevelILOperation.LLIL_CMP_SGE: LowLevelILCmpSge,
	LowLevelILOperation.LLIL_CMP_UGE: LowLevelILCmpUge,
	LowLevelILOperation.LLIL_CMP_SGT: LowLevelILCmpSgt,
	LowLevelILOperation.LLIL_CMP_UGT: LowLevelILCmpUgt,
	LowLevelILOperation.LLIL_TEST_BIT: LowLevelILTestBit,
	LowLevelILOperation.LLIL_BOOL_TO_INT: LowLevelILBoolToInt,
	LowLevelILOperation.LLIL_ADD_OVERFLOW: LowLevelILAddOverflow,
	LowLevelILOperation.LLIL_SYSCALL: LowLevelILSyscall,
	LowLevelILOperation.LLIL_BP: LowLevelILBp,
	LowLevelILOperation.LLIL_TRAP: LowLevelILTrap,
	LowLevelILOperation.LLIL_INTRINSIC: LowLevelILIntrinsic,
	LowLevelILOperation.LLIL_UNDEF: LowLevelILUndef,
	LowLevelILOperation.LLIL_UNIMPL: LowLevelILUnimpl,
	LowLevelILOperation.LLIL_UNIMPL_MEM: LowLevelILUnimplMem,
	LowLevelILOperation.LLIL_FADD: LowLevelILFadd,
	LowLevelILOperation.LLIL_FSUB: LowLevelILFsub,
	LowLevelILOperation.LLIL_FMUL: LowLevelILFmul,
	LowLevelILOperation.LLIL_FDIV: LowLevelILFdiv,
	LowLevelILOperation.LLIL_FSQRT: LowLevelILFsqrt,
	LowLevelILOperation.LLIL_FNEG: LowLevelILFneg,
	LowLevelILOperation.LLIL_FABS: LowLevelILFabs,
	LowLevelILOperation.LLIL_FLOAT_TO_INT: LowLevelILFloatToInt,
	LowLevelILOperation.LLIL_INT_TO_FLOAT: LowLevelILIntToFloat,
	LowLevelILOperation.LLIL_FLOAT_CONV: LowLevelILFloatConv,
	LowLevelILOperation.LLIL_ROUND_TO_INT: LowLevelILRoundToInt,
	LowLevelILOperation.LLIL_FLOOR: LowLevelILFloor,
	LowLevelILOperation.LLIL_CEIL: LowLevelILCeil,
	LowLevelILOperation.LLIL_FTRUNC: LowLevelILFtrunc,
	LowLevelILOperation.LLIL_FCMP_E: LowLevelILFcmpE,
	LowLevelILOperation.LLIL_FCMP_NE: LowLevelILFcmpNe,
	LowLevelILOperation.LLIL_FCMP_LT: LowLevelILFcmpLt,
	LowLevelILOperation.LLIL_FCMP_LE: LowLevelILFcmpLe,
	LowLevelILOperation.LLIL_FCMP_GE: LowLevelILFcmpGe,
	LowLevelILOperation.LLIL_FCMP_GT: LowLevelILFcmpGt,
	LowLevelILOperation.LLIL_FCMP_O: LowLevelILFcmpO,
	LowLevelILOperation.LLIL_FCMP_UO: LowLevelILFcmpUo,
	LowLevelILOperation.LLIL_SET_REG_SSA: LowLevelILSetRegSsa,
	LowLevelILOperation.LLIL_SET_REG_SSA_PARTIAL: LowLevelILSetRegSsaPartial,
	LowLevelILOperation.LLIL_SET_REG_SPLIT_SSA: LowLevelILSetRegSplitSsa,
	LowLevelILOperation.LLIL_SET_REG_STACK_REL_SSA: LowLevelILSetRegStackRelSsa,
	LowLevelILOperation.LLIL_SET_REG_STACK_ABS_SSA: LowLevelILSetRegStackAbsSsa,
	LowLevelILOperation.LLIL_REG_SPLIT_DEST_SSA: LowLevelILRegSplitDestSsa,
	LowLevelILOperation.LLIL_REG_STACK_DEST_SSA: LowLevelILRegStackDestSsa,
	LowLevelILOperation.LLIL_REG_SSA: LowLevelILRegSsa,
	LowLevelILOperation.LLIL_REG_SSA_PARTIAL: LowLevelILRegSsaPartial,
	LowLevelILOperation.LLIL_REG_SPLIT_SSA: LowLevelILRegSplitSsa,
	LowLevelILOperation.LLIL_REG_STACK_REL_SSA: LowLevelILRegStackRelSsa,
	LowLevelILOperation.LLIL_REG_STACK_ABS_SSA: LowLevelILRegStackAbsSsa,
	LowLevelILOperation.LLIL_REG_STACK_FREE_REL_SSA: LowLevelILRegStackFreeRelSsa,
	LowLevelILOperation.LLIL_REG_STACK_FREE_ABS_SSA: LowLevelILRegStackFreeAbsSsa,
	LowLevelILOperation.LLIL_SET_FLAG_SSA: LowLevelILSetFlagSsa,
	LowLevelILOperation.LLIL_ASSERT_SSA: LowLevelILAssertSsa,
	LowLevelILOperation.LLIL_FORCE_VER_SSA: LowLevelILForceVerSsa,
	LowLevelILOperation.LLIL_FLAG_SSA: LowLevelILFlagSsa,
	LowLevelILOperation.LLIL_FLAG_BIT_SSA: LowLevelILFlagBitSsa,
	LowLevelILOperation.LLIL_CALL_SSA: LowLevelILCallSsa,
	LowLevelILOperation.LLIL_SYSCALL_SSA: LowLevelILSyscallSsa,
	LowLevelILOperation.LLIL_TAILCALL_SSA: LowLevelILTailcallSsa,
	LowLevelILOperation.LLIL_CALL_PARAM: LowLevelILCallParam,
	LowLevelILOperation.LLIL_CALL_STACK_SSA: LowLevelILCallStackSsa,
	LowLevelILOperation.LLIL_CALL_OUTPUT_SSA: LowLevelILCallOutputSsa,
	LowLevelILOperation.LLIL_SEPARATE_PARAM_LIST_SSA: LowLevelILSeparateParamListSsa,
	LowLevelILOperation.LLIL_SHARED_PARAM_SLOT_SSA: LowLevelILSharedParamSlotSsa,
	LowLevelILOperation.LLIL_MEMORY_INTRINSIC_OUTPUT_SSA: LowLevelILMemoryIntrinsicOutputSsa,
	LowLevelILOperation.LLIL_LOAD_SSA: LowLevelILLoadSsa,
	LowLevelILOperation.LLIL_STORE_SSA: LowLevelILStoreSsa,
	LowLevelILOperation.LLIL_INTRINSIC_SSA: LowLevelILIntrinsicSsa,
	LowLevelILOperation.LLIL_MEMORY_INTRINSIC_SSA: LowLevelILMemoryIntrinsicSsa,
	LowLevelILOperation.LLIL_REG_PHI: LowLevelILRegPhi,
	LowLevelILOperation.LLIL_REG_STACK_PHI: LowLevelILRegStackPhi,
	LowLevelILOperation.LLIL_FLAG_PHI: LowLevelILFlagPhi,
	LowLevelILOperation.LLIL_MEM_PHI: LowLevelILMemPhi,
	LowLevelILOperation.LLIL_BSWAP: LowLevelILBswap,
	LowLevelILOperation.LLIL_POPCNT: LowLevelILPopcnt,
	LowLevelILOperation.LLIL_CLZ: LowLevelILClz,
	LowLevelILOperation.LLIL_CTZ: LowLevelILCtz,
	LowLevelILOperation.LLIL_RBIT: LowLevelILRbit,
	LowLevelILOperation.LLIL_CLS: LowLevelILCls,
	LowLevelILOperation.LLIL_MINS: LowLevelILMins,
	LowLevelILOperation.LLIL_MAXS: LowLevelILMaxs,
	LowLevelILOperation.LLIL_MINU: LowLevelILMinu,
	LowLevelILOperation.LLIL_MAXU: LowLevelILMaxu,
	LowLevelILOperation.LLIL_ABS: LowLevelILAbs,
}


# Lists the slots `copy_expr_to` copies for each op. Ops that hold labels aren't listed because
# `copy_expr_to` copies them itself.
_COPY_LAYOUTS: Dict[LowLevelILOperation, Tuple] = {
	LowLevelILOperation.LLIL_NOP: (),
	LowLevelILOperation.LLIL_SET_REG: (
		"value",
		"expr",
	),
	LowLevelILOperation.LLIL_SET_REG_SPLIT: (
		"value",
		"value",
		"expr",
	),
	LowLevelILOperation.LLIL_SET_FLAG: (
		"value",
		"expr",
	),
	LowLevelILOperation.LLIL_SET_REG_STACK_REL: (
		"value",
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_REG_STACK_PUSH: (
		"value",
		"expr",
	),
	LowLevelILOperation.LLIL_ASSERT: (
		"value",
		"constraint",
	),
	LowLevelILOperation.LLIL_FORCE_VER: ("value",),
	LowLevelILOperation.LLIL_LOAD: ("expr",),
	LowLevelILOperation.LLIL_STORE: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_PUSH: ("expr",),
	LowLevelILOperation.LLIL_POP: (),
	LowLevelILOperation.LLIL_REG: ("value",),
	LowLevelILOperation.LLIL_REG_SPLIT: (
		"value",
		"value",
	),
	LowLevelILOperation.LLIL_REG_STACK_REL: (
		"value",
		"expr",
	),
	LowLevelILOperation.LLIL_REG_STACK_POP: ("value",),
	LowLevelILOperation.LLIL_REG_STACK_FREE_REG: ("value",),
	LowLevelILOperation.LLIL_REG_STACK_FREE_REL: (
		"value",
		"expr",
	),
	LowLevelILOperation.LLIL_CONST: ("value",),
	LowLevelILOperation.LLIL_CONST_PTR: ("value",),
	LowLevelILOperation.LLIL_EXTERN_PTR: (
		"value",
		"value",
	),
	LowLevelILOperation.LLIL_FLOAT_CONST: ("value",),
	LowLevelILOperation.LLIL_FLAG: ("value",),
	LowLevelILOperation.LLIL_FLAG_BIT: (
		"value",
		"value",
	),
	LowLevelILOperation.LLIL_ADD: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_ADC: (
		"expr",
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_SUB: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_SBB: (
		"expr",
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_AND: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_OR: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_XOR: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_LSL: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_LSR: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_ASR: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_ROL: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_RLC: (
		"expr",
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_ROR: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_RRC: (
		"expr",
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_MUL: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_MULU_DP: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_MULS_DP: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_DIVU: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_DIVU_DP: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_DIVS: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_DIVS_DP: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_MODU: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_MODU_DP: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_MODS: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_MODS_DP: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_NEG: ("expr",),
	LowLevelILOperation.LLIL_NOT: ("expr",),
	LowLevelILOperation.LLIL_SX: ("expr",),
	LowLevelILOperation.LLIL_ZX: ("expr",),
	LowLevelILOperation.LLIL_LOW_PART: ("expr",),
	LowLevelILOperation.LLIL_JUMP: ("expr",),
	LowLevelILOperation.LLIL_CALL: ("expr",),
	LowLevelILOperation.LLIL_CALL_STACK_ADJUST: (
		"expr",
		"value",
		"list",
	),
	LowLevelILOperation.LLIL_TAILCALL: ("expr",),
	LowLevelILOperation.LLIL_RET: ("expr",),
	LowLevelILOperation.LLIL_NORET: (),
	LowLevelILOperation.LLIL_FLAG_COND: (
		"value",
		"value",
	),
	LowLevelILOperation.LLIL_FLAG_GROUP: ("value",),
	LowLevelILOperation.LLIL_CMP_E: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_CMP_NE: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_CMP_SLT: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_CMP_ULT: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_CMP_SLE: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_CMP_ULE: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_CMP_SGE: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_CMP_UGE: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_CMP_SGT: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_CMP_UGT: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_TEST_BIT: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_BOOL_TO_INT: ("expr",),
	LowLevelILOperation.LLIL_ADD_OVERFLOW: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_SYSCALL: (),
	LowLevelILOperation.LLIL_BP: (),
	LowLevelILOperation.LLIL_TRAP: ("value",),
	LowLevelILOperation.LLIL_INTRINSIC: (
		"list",
		"value",
		("part", LowLevelILOperation.LLIL_CALL_PARAM, ("expr_list",)),
	),
	LowLevelILOperation.LLIL_UNDEF: (),
	LowLevelILOperation.LLIL_UNIMPL: ("value",),
	LowLevelILOperation.LLIL_UNIMPL_MEM: (
		"expr",
		"value",
	),
	LowLevelILOperation.LLIL_FADD: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_FSUB: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_FMUL: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_FDIV: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_FSQRT: ("expr",),
	LowLevelILOperation.LLIL_FNEG: ("expr",),
	LowLevelILOperation.LLIL_FABS: ("expr",),
	LowLevelILOperation.LLIL_FLOAT_TO_INT: ("expr",),
	LowLevelILOperation.LLIL_INT_TO_FLOAT: ("expr",),
	LowLevelILOperation.LLIL_FLOAT_CONV: ("expr",),
	LowLevelILOperation.LLIL_ROUND_TO_INT: ("expr",),
	LowLevelILOperation.LLIL_FLOOR: ("expr",),
	LowLevelILOperation.LLIL_CEIL: ("expr",),
	LowLevelILOperation.LLIL_FTRUNC: ("expr",),
	LowLevelILOperation.LLIL_FCMP_E: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_FCMP_NE: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_FCMP_LT: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_FCMP_LE: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_FCMP_GE: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_FCMP_GT: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_FCMP_O: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_FCMP_UO: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_SET_REG_SSA: (
		"value",
		"value",
		"expr",
	),
	LowLevelILOperation.LLIL_SET_REG_SSA_PARTIAL: (
		"value",
		"value",
		"value",
		"expr",
	),
	LowLevelILOperation.LLIL_SET_REG_SPLIT_SSA: (
		(
			"part",
			LowLevelILOperation.LLIL_REG_SPLIT_DEST_SSA,
			(
				"value",
				"value",
			),
		),
		(
			"part",
			LowLevelILOperation.LLIL_REG_SPLIT_DEST_SSA,
			(
				"value",
				"value",
			),
		),
		"expr",
	),
	LowLevelILOperation.LLIL_SET_REG_STACK_REL_SSA: (
		(
			"part",
			LowLevelILOperation.LLIL_REG_STACK_DEST_SSA,
			(
				"value",
				"value",
				"value",
			),
		),
		"expr",
		(
			"part",
			LowLevelILOperation.LLIL_REG_SSA,
			(
				"value",
				"value",
			),
		),
		"expr",
	),
	LowLevelILOperation.LLIL_SET_REG_STACK_ABS_SSA: (
		(
			"part",
			LowLevelILOperation.LLIL_REG_STACK_DEST_SSA,
			(
				"value",
				"value",
				"value",
			),
		),
		"value",
		"expr",
	),
	LowLevelILOperation.LLIL_REG_SSA: (
		"value",
		"value",
	),
	LowLevelILOperation.LLIL_REG_SSA_PARTIAL: (
		"value",
		"value",
		"value",
	),
	LowLevelILOperation.LLIL_REG_SPLIT_SSA: (
		"value",
		"value",
		"value",
		"value",
	),
	LowLevelILOperation.LLIL_REG_STACK_REL_SSA: (
		"value",
		"value",
		"expr",
		(
			"part",
			LowLevelILOperation.LLIL_REG_SSA,
			(
				"value",
				"value",
			),
		),
	),
	LowLevelILOperation.LLIL_REG_STACK_ABS_SSA: (
		"value",
		"value",
		"value",
	),
	LowLevelILOperation.LLIL_REG_STACK_FREE_REL_SSA: (
		(
			"part",
			LowLevelILOperation.LLIL_REG_STACK_DEST_SSA,
			(
				"value",
				"value",
				"value",
			),
		),
		"expr",
		(
			"part",
			LowLevelILOperation.LLIL_REG_SSA,
			(
				"value",
				"value",
			),
		),
	),
	LowLevelILOperation.LLIL_REG_STACK_FREE_ABS_SSA: (
		(
			"part",
			LowLevelILOperation.LLIL_REG_STACK_DEST_SSA,
			(
				"value",
				"value",
				"value",
			),
		),
		"value",
	),
	LowLevelILOperation.LLIL_SET_FLAG_SSA: (
		"value",
		"value",
		"expr",
	),
	LowLevelILOperation.LLIL_ASSERT_SSA: (
		"value",
		"value",
		"constraint",
	),
	LowLevelILOperation.LLIL_FORCE_VER_SSA: (
		"value",
		"value",
		"value",
		"value",
	),
	LowLevelILOperation.LLIL_FLAG_SSA: (
		"value",
		"value",
	),
	LowLevelILOperation.LLIL_FLAG_BIT_SSA: (
		"value",
		"value",
		"value",
	),
	LowLevelILOperation.LLIL_CALL_SSA: (
		(
			"part",
			LowLevelILOperation.LLIL_CALL_OUTPUT_SSA,
			(
				"value",
				"list",
			),
		),
		"expr",
		(
			"part",
			LowLevelILOperation.LLIL_CALL_STACK_SSA,
			(
				"value",
				"value",
				"value",
			),
		),
		("part", LowLevelILOperation.LLIL_CALL_PARAM, ("expr_list",)),
	),
	LowLevelILOperation.LLIL_SYSCALL_SSA: (
		(
			"part",
			LowLevelILOperation.LLIL_CALL_OUTPUT_SSA,
			(
				"value",
				"list",
			),
		),
		(
			"part",
			LowLevelILOperation.LLIL_CALL_STACK_SSA,
			(
				"value",
				"value",
				"value",
			),
		),
		("part", LowLevelILOperation.LLIL_CALL_PARAM, ("expr_list",)),
	),
	LowLevelILOperation.LLIL_TAILCALL_SSA: (
		(
			"part",
			LowLevelILOperation.LLIL_CALL_OUTPUT_SSA,
			(
				"value",
				"list",
			),
		),
		"expr",
		(
			"part",
			LowLevelILOperation.LLIL_CALL_STACK_SSA,
			(
				"value",
				"value",
				"value",
			),
		),
		("part", LowLevelILOperation.LLIL_CALL_PARAM, ("expr_list",)),
	),
	LowLevelILOperation.LLIL_SEPARATE_PARAM_LIST_SSA: ("expr_list",),
	LowLevelILOperation.LLIL_SHARED_PARAM_SLOT_SSA: ("expr_list",),
	LowLevelILOperation.LLIL_LOAD_SSA: (
		"expr",
		"value",
	),
	LowLevelILOperation.LLIL_STORE_SSA: (
		"expr",
		"value",
		"value",
		"expr",
	),
	LowLevelILOperation.LLIL_INTRINSIC_SSA: (
		"list",
		"value",
		("part", LowLevelILOperation.LLIL_CALL_PARAM, ("expr_list",)),
	),
	LowLevelILOperation.LLIL_MEMORY_INTRINSIC_SSA: (
		(
			"part",
			LowLevelILOperation.LLIL_MEMORY_INTRINSIC_OUTPUT_SSA,
			(
				"value",
				"list",
			),
		),
		"value",
		("part", LowLevelILOperation.LLIL_CALL_PARAM, ("expr_list",)),
		"value",
	),
	LowLevelILOperation.LLIL_REG_PHI: (
		"value",
		"value",
		"list",
	),
	LowLevelILOperation.LLIL_REG_STACK_PHI: (
		"value",
		"value",
		"list",
	),
	LowLevelILOperation.LLIL_FLAG_PHI: (
		"value",
		"value",
		"list",
	),
	LowLevelILOperation.LLIL_MEM_PHI: (
		"value",
		"list",
	),
	LowLevelILOperation.LLIL_BSWAP: ("expr",),
	LowLevelILOperation.LLIL_POPCNT: ("expr",),
	LowLevelILOperation.LLIL_CLZ: ("expr",),
	LowLevelILOperation.LLIL_CTZ: ("expr",),
	LowLevelILOperation.LLIL_RBIT: ("expr",),
	LowLevelILOperation.LLIL_CLS: ("expr",),
	LowLevelILOperation.LLIL_MINS: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_MAXS: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_MINU: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_MAXU: (
		"expr",
		"expr",
	),
	LowLevelILOperation.LLIL_ABS: ("expr",),
}
# END GENERATED llil-classes


class LowLevelILExpr:
	"""
	``class LowLevelILExpr`` hold the index of IL Expressions.

	.. note:: Deprecated. Use ExpressionIndex instead
	"""
	def __init__(self, index: ExpressionIndex):
		self._index = index

	def __int__(self):
		return self._index

	@property
	def index(self) -> ExpressionIndex:
		return self._index


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
	def __init__(
	    self, arch: Optional['architecture.Architecture'] = None, handle: Optional[core.BNLowLevelILFunction] = None,
	    source_func: Optional['function.Function'] = None
	):
		if arch is not None:
			self._arch = arch
		self._source_function = source_func
		if handle is not None:
			LLILHandle = ctypes.POINTER(core.BNLowLevelILFunction)
			_handle = ctypes.cast(handle, LLILHandle)
			if self._source_function is None:
				source_handle = core.BNGetLowLevelILOwnerFunction(_handle)
				if source_handle:
					self._source_function = function.Function(handle=source_handle)
				else:
					self._source_function = None
			if arch is None:
				if self._source_function is None:
					raise Exception("Can not instantiate LowLevelILFunction without an architecture")
				self._arch = self._source_function.arch
		else:
			if arch is None:
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
		if core is not None and hasattr(self, 'handle'):
			core.BNFreeLowLevelILFunction(self.handle)

	def __repr__(self):
		form = ""
		if self.il_form == FunctionGraphType.LiftedILFunctionGraph:
			form += " lifted il"
		if self.il_form == FunctionGraphType.LowLevelILSSAFormFunctionGraph:
			form += " ssa form"
		if self.source_function is not None and self.source_function.arch is not None:
			return f"<{self.__class__.__name__}{form}: {self.source_function.arch.name}@{self.source_function.start:#x}>"
		elif self.source_function is not None:
			return f"<{self.__class__.__name__}{form}: {self.source_function.start:#x}>"
		else:
			return f"<{self.__class__.__name__}{form}: anonymous>"

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

	def __getitem__(self, i: InstructionIndex) -> LowLevelILInstruction:
		if isinstance(i, slice) or isinstance(i, tuple):
			raise IndexError("expected integer instruction index")
		if i < -len(self) or i >= len(self):
			raise IndexError(f"index {i} out of range (-{len(self)}, {len(self)})")
		if i < 0:
			i = len(self) + i
		return LowLevelILInstruction.create(
		    self, ExpressionIndex(core.BNGetLowLevelILIndexForInstruction(self.handle, i)), i
		)

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
	def current_address(self, value: int) -> None:
		core.BNLowLevelILSetCurrentAddress(self.handle, self.arch.handle, value)

	def set_current_address(self, value: int, arch: Optional['architecture.Architecture'] = None) -> None:
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

	def _basic_block_list(self):
		count = ctypes.c_ulonglong()
		blocks = core.BNGetLowLevelILBasicBlockList(self.handle, count)
		assert blocks is not None, "core.BNGetLowLevelILBasicBlockList returned None"
		return (count, blocks)

	def _instantiate_block(self, handle):
		return LowLevelILBasicBlock(handle, self, self.view)

	@property
	def basic_blocks(self) -> 'function.LowLevelILBasicBlockList':
		return function.LowLevelILBasicBlockList(self)

	def get_basic_block_at(self, index: int) -> Optional['LowLevelILBasicBlock']:
		"""
		``get_basic_block_at`` returns the BasicBlock at the given LLIL instruction ``index``.

		:param int index: Index of the LLIL instruction of the BasicBlock to retrieve.
		:Example:
			>>> current_il_function.get_basic_block_at(current_il_index)
			<llil block: x86@19-26>
		"""
		block = core.BNGetLowLevelILBasicBlockForInstruction(self.handle, index)
		if not block:
			return None

		view = None
		if self._source_function is not None:
			view = self._source_function.view

		return LowLevelILBasicBlock(block, self, view)

	@property
	def instructions(self) -> Generator['LowLevelILInstruction', None, None]:
		"""A generator of llil instructions of the current llil function"""
		for block in self.basic_blocks:
			yield from block

	def traverse(self, cb: Callable[['LowLevelILInstruction', Any], Any], *args: Any, **kwargs: Any) -> Iterator[Any]:
		"""
		``traverse`` iterates through all the instructions in the LowLevelILFunction and calls the callback function for
		each instruction and sub-instruction. See the `Developer Docs <https://docs.binary.ninja/dev/concepts.html#walking-ils>`_ for more examples.

		:param Callable[[LowLevelILInstruction, Any], Any] cb: The callback function to call for each node in the LowLevelILInstruction
		:param Any args: Custom user-defined arguments
		:param Any kwargs: Custom user-defined keyword arguments
		:return: An iterator of the results of the callback function
		:rtype: Iterator[Any]

		:Example:
			>>> def find_constants(instr) -> Optional[int]:
			...     if isinstance(instr, Constant):
			...         return instr.constant
			>>> print(list(current_il_function.traverse(find_constants)))
		"""
		for instr in self.instructions:
			yield from instr.traverse(cb, *args, **kwargs)

	@deprecation.deprecated(deprecated_in="4.0.4907", details="Use :py:func:`LowLevelILFunction.traverse` instead.")
	def visit(self, cb: LowLevelILVisitorCallback) -> bool:
		"""
		Iterates over all the instructions in the function and calls the callback function
		for each instruction and each sub-instruction.

		:param LowLevelILVisitorCallback cb: Callback function that takes the name of the operand, the operand, operand type, and parent instruction
		:return: True if all instructions were visited, False if the callback function returned False.
		"""
		for instr in self.instructions:
			if not instr.visit(cb):
				return False
		return True

	@deprecation.deprecated(deprecated_in="4.0.4907", details="Use :py:func:`LowLevelILFunction.traverse` instead.")
	def visit_all(self, cb: LowLevelILVisitorCallback) -> bool:
		"""
		Iterates over all the instructions in the function and calls the callback function for each instruction and their operands.

		:param LowLevelILVisitorCallback cb: Callback function that takes the name of the operand, the operand, operand type, and parent instruction
		:return: True if all instructions were visited, False if the callback function returned False.
		"""
		for instr in self.instructions:
			if not instr.visit_all(cb):
				return False
		return True

	@deprecation.deprecated(deprecated_in="4.0.4907", details="Use :py:func:`LowLevelILFunction.traverse` instead.")
	def visit_operands(self, cb: LowLevelILVisitorCallback) -> bool:
		"""
		Iterates over all the instructions in the function and calls the callback function for each operand and
		 the operands of each sub-instruction.

		:param LowLevelILVisitorCallback cb: Callback function that takes the name of the operand, the operand, operand type, and parent instruction
		:return: True if all instructions were visited, False if the callback function returned False.
		"""
		for instr in self.instructions:
			if not instr.visit_operands(cb):
				return False
		return True

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
	def arch(self, value: 'architecture.Architecture') -> None:
		self._arch = value

	@property
	def source_function(self) -> Optional['function.Function']:
		return self._source_function

	@source_function.setter
	def source_function(self, value: 'function.Function') -> None:
		self._source_function = value

	@property
	def view(self) -> Optional['binaryview.BinaryView']:
		return self.source_function.view if self.source_function else None

	@property
	def il_form(self) -> FunctionGraphType:
		if len(list(self.basic_blocks)) < 1:
			return FunctionGraphType.InvalidILViewType
		return FunctionGraphType(core.BNGetBasicBlockFunctionGraphType(list(self.basic_blocks)[0].handle))

	@property
	def registers(self) -> List[SSARegister]:
		""" Deprecated, use `regs` instead. List of registers used in this IL """
		return self.regs

	@property
	def regs(self) -> List[SSARegister]:
		""" List of registers used in this IL """
		if self.il_form == FunctionGraphType.LowLevelILSSAFormFunctionGraph:
			# If this is a LLIL SSA function, then its registers is SSA registers
			return self.ssa_regs

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
	def is_thunk(self) -> bool:
		"""Returns True if the function starts with a Tailcall (read-only)"""
		if len(self.basic_blocks) == 1:
			return isinstance(self.basic_blocks[0][-1], Tailcall)
		return False

	@property
	def register_stacks(self) -> List[SSARegisterStack]:
		""" Deprecated, use `reg_stacks` instead. List of register stacks used in this IL """
		return self.reg_stacks

	@property
	def reg_stacks(self) -> List[SSARegisterStack]:
		""" List of register stacks used in this IL """
		if self.il_form == FunctionGraphType.LowLevelILSSAFormFunctionGraph:
			# If this is a LLIL SSA function, then its registers is SSA registers
			return self.ssa_reg_stacks

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
	def flags(self) -> List[SSAFlag]:
		""" List of flags used in this IL """
		if self.il_form == FunctionGraphType.LowLevelILSSAFormFunctionGraph:
			# If this is a LLIL SSA function, then its registers is SSA registers
			return self.ssa_flags

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
	def ssa_regs_without_versions(self) -> List[SSARegister]:
		""" List of SSA registers used in this IL """
		register_count = ctypes.c_ulonglong()
		registers = core.BNGetLowLevelSSARegistersWithoutVersions(self.handle, register_count)
		assert registers is not None, "core.BNGetLowLevelRegisters returned None"
		result = []
		try:
			for var_i in range(register_count.value):
				result.append(SSARegister(ILRegister(self.arch, registers[var_i]), 0))
		finally:
			core.BNFreeLLILVariablesList(registers)

		return result

	@property
	def ssa_reg_stacks_without_versions(self) -> List[SSARegisterStack]:
		""" List of SSA register stacks used in this IL """
		register_stack_count = ctypes.c_ulonglong()
		register_stacks = core.BNGetLowLevelSSARegisterStacksWithoutVersions(self.handle, register_stack_count)
		assert register_stacks is not None, "core.BNGetLowLevelRegisterStacks returned None"
		result = []
		try:
			for var_i in range(register_stack_count.value):
				result.append(SSARegisterStack(ILRegisterStack(self.arch, register_stacks[var_i]), 0))
		finally:
			core.BNFreeLLILVariablesList(register_stacks)

		return result

	@property
	def ssa_flags_without_versions(self) -> List[SSAFlag]:
		""" List of SSA flags used in this IL """
		flag_count = ctypes.c_ulonglong()
		flags = core.BNGetLowLevelSSAFlagsWithoutVersions(self.handle, flag_count)
		assert flags is not None, "core.BNGetLowLevelFlags returned None"
		result = []
		try:
			for var_i in range(flag_count.value):
				result.append(SSAFlag(ILFlag(self.arch, flags[var_i]), 0))
		finally:
			core.BNFreeLLILVariablesList(flags)

		return result

	@property
	def ssa_registers(self) -> List[SSARegister]:
		return self.ssa_regs

	@property
	def ssa_register_stacks(self) -> List[SSARegisterStack]:
		return self.ssa_reg_stacks

	@property
	def ssa_regs(self) -> List[SSARegister]:
		""" List of all SSA registers and versions used in this IL """
		register_count = ctypes.c_ulonglong()
		registers = core.BNGetLowLevelSSARegistersWithoutVersions(self.handle, register_count)
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
	def ssa_reg_stacks(self) -> List[SSARegisterStack]:
		""" List of all SSA register stacks and versions used in this IL """
		register_stack_count = ctypes.c_ulonglong()
		register_stacks = core.BNGetLowLevelSSARegisterStacksWithoutVersions(self.handle, register_stack_count)
		assert register_stacks is not None, "core.BNGetLowLevelRegisterStacks returned None"
		result = []
		try:
			for var_i in range(register_stack_count.value):
				version_count = ctypes.c_ulonglong()
				versions = core.BNGetLowLevelRegisterStackSSAVersions(
				    self.handle, register_stacks[var_i], version_count
				)
				assert versions is not None, "core.BNGetLowLevelRegisterStackSSAVersions returned None"
				try:
					for version_i in range(version_count.value):
						result.append(
						    SSARegisterStack(ILRegisterStack(self.arch, register_stacks[var_i]), versions[version_i])
						)
				finally:
					core.BNFreeLLILVariableVersionList(versions)
		finally:
			core.BNFreeLLILVariablesList(register_stacks)
		return result

	@property
	def ssa_flags(self) -> List[SSAFlag]:
		""" List of all SSA flags and versions used in this IL """
		flag_count = ctypes.c_ulonglong()
		flags = core.BNGetLowLevelSSAFlagsWithoutVersions(self.handle, flag_count)
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
		"""This is the union `LowLevelILFunction.regs`, `LowLevelILFunction.reg_stacks`, and `LowLevelILFunction.flags`"""
		if self._source_function is None:
			return []

		if self.il_form in [
		    FunctionGraphType.LiftedILFunctionGraph, FunctionGraphType.LowLevelILFunctionGraph,
		    FunctionGraphType.LowLevelILSSAFormFunctionGraph
		]:
			return self.regs + self.reg_stacks + self.flags  # type: ignore
		return []

	@property
	def ssa_vars(self) -> List[Union[SSARegister, SSARegisterStack, SSAFlag]]:
		"""This is the union `LowLevelILFunction.ssa_regs`, `LowLevelILFunction.ssa_reg_stacks`, and `LowLevelILFunction.ssa_flags`"""
		return self.ssa_regs + self.ssa_reg_stacks + self.ssa_flags

	@property
	def ssa_vars_without_versions(self) -> List[Union[SSARegister, SSARegisterStack, SSAFlag]]:
		"""This is the union `LowLevelILFunction.ssa_regs_without_versions`,
		`LowLevelILFunction.ssa_reg_stacks_without_versions`, and `LowLevelILFunction.ssa_flags_without_versions`"""
		return self.ssa_regs_without_versions + self.ssa_reg_stacks_without_versions + self.ssa_flags_without_versions

	def get_instruction_start(self, addr: int, arch: Optional['architecture.Architecture'] = None) -> Optional[InstructionIndex]:
		if arch is None:
			arch = self.arch
		result = core.BNLowLevelILGetInstructionStart(self.handle, arch.handle, addr)
		if result >= core.BNGetLowLevelILInstructionCount(self.handle):
			return None
		return InstructionIndex(result)

	def get_instructions_at(self, addr: int, arch: Optional['architecture.Architecture'] = None) -> List[InstructionIndex]:
		"""
		``get_instructions_at`` gets the InstructionIndex(s) corresponding to the given virtual address
		See the `docs for mappings between ils <https://dev-docs.binary.ninja/dev/concepts.html#mapping-between-ils>`_ for more information.

		:param int addr: virtual address of the instruction to be queried
		:param Architecture arch: (optional) Architecture for the given function
		:rtype: list(InstructionIndex)
		:Example:

			>>> func = next(bv.functions)
			>>> func.llil.get_instructions_at(func.start)
			[0]
		"""
		if arch is None:
			arch = self.arch
		count = ctypes.c_ulonglong()
		instrs = core.BNLowLevelILGetInstructionsAt(self.handle, arch.handle, addr, count)
		assert instrs is not None, "core.BNLowLevelILGetInstructionsAt returned None"
		try:
			result = []
			for i in range(0, count.value):
				result.append(instrs[i])
			return result
		finally:
			core.BNFreeILInstructionList(instrs)

	def get_exits_for_instr(self, idx: InstructionIndex) -> List[InstructionIndex]:
		count = ctypes.c_ulonglong()
		exits = core.BNLowLevelILGetExitsForInstruction(self.handle, idx, count)
		assert exits is not None, "core.BNLowLevelILGetExitsForInstruction returned None"
		try:
			result = []
			for i in range(0, count.value):
				result.append(exits[i])
			return result
		finally:
			core.BNFreeILInstructionList(exits)

	def clear_indirect_branches(self) -> None:
		core.BNLowLevelILClearIndirectBranches(self.handle)

	def set_indirect_branches(self, branches: List[Tuple['architecture.Architecture', int]]) -> None:
		branch_list = (core.BNArchitectureAndAddress * len(branches))()
		for i in range(len(branches)):
			branch_list[i].arch = branches[i][0].handle
			branch_list[i].address = branches[i][1]
		core.BNLowLevelILSetIndirectBranches(self.handle, branch_list, len(branches))

	def expr(
	    self, operation, a: ExpressionIndex = 0, b: ExpressionIndex = 0, c: ExpressionIndex = 0, d: ExpressionIndex = 0, size: int = 0,
	    flags: Optional['architecture.FlagWriteType'] = None,
	    source_location: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		_flags = architecture.FlagWriteTypeIndex(0)
		if isinstance(operation, str):
			operation = LowLevelILOperation[operation]
		elif isinstance(operation, LowLevelILOperation):
			operation = operation.value
		if isinstance(flags, str):
			_flags = self.arch.get_flag_write_type_by_name(architecture.FlagWriteTypeName(flags))
		elif isinstance(flags, int):
			_flags = architecture.FlagWriteTypeIndex(flags)
		elif flags is None:
			_flags = architecture.FlagWriteTypeIndex(0)
		else:
			assert False, "flags type unsupported"
		if source_location is not None:
			return ExpressionIndex(core.BNLowLevelILAddExprWithLocation(
				self.handle,
				source_location.address,
				source_location.source_operand,
				operation,
				size,
				_flags,
				a,
				b,
				c,
				d
			))
		else:
			return ExpressionIndex(core.BNLowLevelILAddExpr(self.handle, operation, size, _flags, a, b, c, d))

	def get_expr_count(self) -> int:
		"""
		``get_expr_count`` gives a the total number of expressions in this IL function

		You can use this to enumerate all expressions in conjunction with :py:func:`get_expr`

		.. warning :: Not all IL expressions are valid, even if their index is within the returned value from this,
		              they might not be used by the function and might not contain properly structured data.

		:return: The number of expressions in the function
		"""
		return core.BNGetLowLevelILExprCount(self.handle)

	def get_expr(self, index: ExpressionIndex) -> Optional[LowLevelILInstruction]:
		"""
		``get_expr`` retrieves the IL expression at a given expression index in the function.

		.. warning :: Not all IL expressions are valid, even if their index is within the bounds of the function,
		              they might not be used by the function and might not contain properly structured data.

		:param index: Index of desired expression in function
		:return: A LowLevelILInstruction object for the expression, if it exists. Otherwise, None
		"""
		if index >= self.get_expr_count():
			return None

		return LowLevelILInstruction.create(self, index)

	def copy_expr(self, original: LowLevelILInstruction) -> ExpressionIndex:
		"""
		``copy_expr`` adds an expression to the function which is equivalent to the given expression

		.. warning:: This function should ONLY be called as a part of a lifter or workflow. It will otherwise not do anything useful as analysis will not be running.

		:param LowLevelILInstruction original: the original IL Instruction you want to copy
		:return: The index of the newly copied expression
		"""
		return self.expr(
			original.operation,
			original.raw_operands[0],
			original.raw_operands[1],
			original.raw_operands[2],
			original.raw_operands[3],
			original.size,
			original.raw_flags,
			original.source_location
		)

	def replace_expr(self, original: InstructionOrExpression, new: InstructionOrExpression) -> None:
		"""
		``replace_expr`` allows modification of expressions but ONLY during lifting.

		.. warning:: This function should ONLY be called as a part of a lifter or workflow. It will otherwise not do anything useful as analysis will not be running.

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

	def copy_expr_to(
		self, expr: LowLevelILInstruction, dest: 'LowLevelILFunction',
		sub_expr_handler: Optional[Callable[[LowLevelILInstruction], ExpressionIndex]] = None
	) -> ExpressionIndex:
		"""
		``copy_expr_to`` deep copies an expression from this function into a target function
		If provided, the function ``sub_expr_handler`` will be called on every copied sub-expression

		.. warning:: This function should ONLY be called as a part of a lifter or workflow. It will otherwise not do anything useful as analysis will not be running.

		:param LowLevelILInstruction expr: Expression in this function to copy
		:param LowLevelILFunction dest: Function to copy the expression to
		:param sub_expr_handler: Optional function to call on every copied sub-expression
		:return: Index of the copied expression in the target function
		"""

		if sub_expr_handler is None:
			sub_expr_handler = lambda sub_expr: self.copy_expr_to(sub_expr, dest)
		loc = ILSourceLocation.from_instruction(expr)

		# Rebuild branches so they target `dest`'s labels, because their targets are instruction indices in this
		# function.
		if expr.operation == LowLevelILOperation.LLIL_JUMP_TO:
			expr: LowLevelILJumpTo
			label_list = {}
			for a, b in expr.targets.items():
				label_a = dest.get_label_for_source_instruction(b)
				if label_a is None:
					return dest.jump(sub_expr_handler(expr.dest), loc)
				label_list[a] = label_a
			return dest.jump_to(sub_expr_handler(expr.dest), label_list, loc)
		if expr.operation == LowLevelILOperation.LLIL_GOTO:
			expr: LowLevelILGoto
			label_a = dest.get_label_for_source_instruction(expr.dest)
			if label_a is None:
				return dest.jump(dest.const_pointer(expr.function.arch.address_size, expr.function[expr.dest].address), loc)
			return dest.goto(label_a, loc)
		if expr.operation == LowLevelILOperation.LLIL_IF:
			expr: LowLevelILIf
			label_a = dest.get_label_for_source_instruction(expr.true)
			label_b = dest.get_label_for_source_instruction(expr.false)
			if label_a is None or label_b is None:
				return dest.undefined(loc)
			return dest.if_expr(sub_expr_handler(expr.condition), label_a, label_b, loc)

		layout = _COPY_LAYOUTS.get(expr.operation)
		if layout is None:
			raise NotImplementedError(f"unknown expr operation {expr.operation} in copy_expr_to")
		operands = self._copy_operands(expr, layout, dest, sub_expr_handler, loc)
		return dest.expr(expr.operation, *operands, size=expr.size, flags=expr.instr.flags, source_location=loc)

	def _copy_operands(
		self, expr: LowLevelILInstruction, layout: Tuple, dest: 'LowLevelILFunction',
		sub_expr_handler: Callable[[LowLevelILInstruction], ExpressionIndex], loc: 'ILSourceLocation'
	) -> List[int]:
		operands: List[int] = []
		slot = 0
		for entry in layout:
			if entry == "value":
				operands.append(expr.instr.operands[slot])
				slot += 1
			elif entry == "expr":
				operands.append(sub_expr_handler(expr._get_expr(slot)))
				slot += 1
			elif entry == "expr_list":
				exprs = [sub_expr_handler(sub_expr) for sub_expr in expr._get_expr_list(slot)]
				operands += [len(exprs), dest.add_operand_list(exprs)]
				slot += 2
			elif entry == "list":
				items = expr._get_int_list(slot)
				operands += [len(items), dest.add_index_list(items)]
				slot += 2
			elif entry == "constraint":
				operands.append(dest.cache_possible_value_set(expr._get_constraint(slot)))
				slot += 1
			else:
				_, operation, part_layout = entry
				part = expr._get_expr(slot)
				part_operands = self._copy_operands(part, part_layout, dest, sub_expr_handler, loc)
				operands.append(dest.expr(operation, *part_operands, size=part.size, flags=part.instr.flags, source_location=loc))
				slot += 1
		return operands

	def translate(
		self, expr_handler: Callable[['LowLevelILFunction', 'LowLevelILBasicBlock', 'LowLevelILInstruction'], ExpressionIndex]
	) -> 'LowLevelILFunction':
		"""
		``translate`` clones an IL function and modifies its expressions as specified by
		a given ``expr_handler``, returning the updated IL function.

		:param expr_handler: Function to modify an expression and copy it to the new function.
		                     The function should have the following signature:

		                     expr_handler(new_func: LowLevelILFunction, old_block: LowLevelILBasicBlock, old_instr: LowLevelILInstruction) -> ExpressionIndex

		                     Where:
		                         - **new_func** (*LowLevelILFunction*): New function to receive translated instructions
		                         - **old_block** (*LowLevelILBasicBlock*): Original block containing old_instr
		                         - **old_instr** (*LowLevelILInstruction*): Original instruction
		                         - **returns** (*ExpressionIndex*): Expression index of newly created instruction in ``new_func``
		:return: Cloned IL function with modifications
		"""

		propagated_func = LowLevelILFunction(self.arch, source_func=self.source_function)
		propagated_func.prepare_to_copy_function(self)
		for block in self.basic_blocks:
			propagated_func.prepare_to_copy_block(block)
			for instr_index in range(block.start, block.end):
				instr: LowLevelILInstruction = self[InstructionIndex(instr_index)]
				propagated_func.set_current_address(instr.address, block.arch)
				propagated_func.append(expr_handler(propagated_func, block, instr))

		return propagated_func

	def set_expr_attributes(self, expr: InstructionOrExpression, value: ILInstructionAttributeSet):
		"""
		``set_expr_attributes`` allows modification of instruction attributes but ONLY during lifting.

		.. warning:: This function should ONLY be called as a part of a lifter or workflow. It will otherwise not do anything useful as analysis will not be running.

		:param ExpressionIndex expr: the ExpressionIndex to replace (may also be an expression index)
		:param set(ILInstructionAttribute) value: the set of attributes to place on the instruction
		:rtype: None
		"""
		if isinstance(expr, LowLevelILInstruction):
			expr = expr.expr_index
		elif isinstance(expr, int):
			expr = ExpressionIndex(expr)

		result = 0
		for flag in value:
			result |= flag.value
		core.BNSetLowLevelILExprAttributes(self.handle, expr, result)

	def append(self, expr: ExpressionIndex) -> InstructionIndex:
		"""
		``append`` adds the ExpressionIndex ``expr`` to the current LowLevelILFunction.

		:param ExpressionIndex expr: the ExpressionIndex to add to the current LowLevelILFunction
		:return: Index of added instruction in the current function
		:rtype: int
		"""
		return InstructionIndex(core.BNLowLevelILAddInstruction(self.handle, expr))

	def _flag_condition_value(self, cond: Union[str, LowLevelILFlagCondition, int]) -> int:
		if isinstance(cond, str):
			return LowLevelILFlagCondition[cond].value
		return int(cond)

	def _register_or_flag_identifiers(
		self, outputs: List[Union[ILRegisterType, ILFlag, 'architecture.RegisterInfo']]
	) -> List[int]:
		identifiers = []
		for output in outputs:
			if isinstance(output, str):
				if architecture.RegisterName(output) in self.arch.regs:
					identifiers.append(self.arch.regs[architecture.RegisterName(output)].index)
				elif architecture.FlagName(output) in self.arch.flags:
					identifiers.append(1 << 32 | self.arch.get_flag_by_name(architecture.FlagName(output)))
				else:
					raise Exception('Invalid register or flag name')
			elif isinstance(output, (architecture.RegisterInfo, ILRegister)):
				identifiers.append(output.index)
			elif isinstance(output, ILFlag):
				identifiers.append(1 << 32 | output.index)
			else:
				identifiers.append(output)
		return identifiers

	def _register_stack_adjustment_list(
		self, adjustments: Optional[Dict['architecture.RegisterStackType', int]]
	) -> List[int]:
		items = []
		for reg_stack, adjustment in (adjustments or {}).items():
			items += [self.arch.get_reg_stack_index(reg_stack), adjustment]
		return items

	# BEGIN GENERATED llil-builders: from api/il, do not edit
	def nop(self, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Does nothing.

		:param loc: The IL location this expression was added from
		:return: The expression ``nop``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_NOP, source_location=loc)

	def set_reg(
		self,
		size: int,
		reg: 'architecture.RegisterType',
		value: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Sets register ``reg`` to ``value``.

		:param size: The size of ``value`` in bytes
		:param reg: The register to set
		:param value: The value to set it to
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``reg = value {<flags>}``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			LowLevelILOperation.LLIL_SET_REG,
			self.arch.get_reg_index(reg),
			value,
			size=size,
			flags=flags,
			source_location=loc,
		)

	def set_reg_split(
		self,
		size: int,
		hi: 'architecture.RegisterType',
		lo: 'architecture.RegisterType',
		value: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Sets the register pair ``hi``:``lo`` to ``value``, a value twice the size of each register.

		:param size: The size of each register in bytes
		:param hi: The register that receives the high half
		:param lo: The register that receives the low half
		:param value: The value to set the pair to
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``hi:lo = value {<flags>}``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			LowLevelILOperation.LLIL_SET_REG_SPLIT,
			self.arch.get_reg_index(hi),
			self.arch.get_reg_index(lo),
			value,
			size=size,
			flags=flags,
			source_location=loc,
		)

	def set_flag(
		self, flag: 'architecture.FlagType', value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Sets flag ``flag`` to ``value``.

		:param flag: The flag to set
		:param value: The value to set it to
		:param loc: The IL location this expression was added from
		:return: The expression ``flag = value``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_SET_FLAG, self.arch.get_flag_index(flag), value, source_location=loc)

	def set_reg_stack_top_relative(
		self,
		size: int,
		reg_stack: 'architecture.RegisterStackType',
		entry: ExpressionIndex,
		value: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Sets the register stack entry at position ``entry`` from the top of ``reg_stack`` to ``value``.

		:param size: The size of ``value`` in bytes
		:param reg_stack: The register stack
		:param entry: The position of the entry, relative to the top of the stack
		:param value: The value to set the entry to
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``reg_stack[entry] = value {<flags>}``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			LowLevelILOperation.LLIL_SET_REG_STACK_REL,
			self.arch.get_reg_stack_index(reg_stack),
			entry,
			value,
			size=size,
			flags=flags,
			source_location=loc,
		)

	def reg_stack_push(
		self,
		size: int,
		reg_stack: 'architecture.RegisterStackType',
		value: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Pushes ``value`` onto the top of register stack ``reg_stack``.

		:param size: The size of ``value`` in bytes
		:param reg_stack: The register stack
		:param value: The value to push
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``reg_stack.push{<flags>}(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			LowLevelILOperation.LLIL_REG_STACK_PUSH,
			self.arch.get_reg_stack_index(reg_stack),
			value,
			size=size,
			flags=flags,
			source_location=loc,
		)

	def assert_expr(
		self,
		size: int,
		src: 'architecture.RegisterType',
		constraint: 'variable.PossibleValueSet',
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Asserts that register ``src`` holds one of the values ``constraint`` allows. Core inserts it where a
		user has set possible values for ``src``.

		:param size: The size of the register in bytes
		:param src: The register to constrain
		:param constraint: The values the register may hold
		:param loc: The IL location this expression was added from
		:return: The expression ``ASSERT(src, constraint)``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			LowLevelILOperation.LLIL_ASSERT,
			self.arch.get_reg_index(src),
			self.cache_possible_value_set(constraint),
			size=size,
			source_location=loc,
		)

	def force_ver(
		self, size: int, dest: 'architecture.RegisterType', loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Gives register ``dest`` a new SSA version, as though it were assigned its own value. MLIL can then
		use this as a new variable definition site.

		:param size: The size of the register in bytes
		:param dest: The register to give a new version
		:param loc: The IL location this expression was added from
		:return: The expression ``FORCE_VER(dest)``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			LowLevelILOperation.LLIL_FORCE_VER, self.arch.get_reg_index(dest), size=size, source_location=loc
		)

	def load(
		self,
		size: int,
		addr: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Reads ``size`` bytes from memory at ``addr``.

		:param size: The size of the result in bytes
		:param addr: The address to read from
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``[addr].<size> {<flags>}``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_LOAD, addr, size=size, flags=flags, source_location=loc)

	def store(
		self,
		size: int,
		addr: ExpressionIndex,
		value: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Writes the ``size`` bytes of ``value`` to memory at ``addr``.

		:param size: The size of ``value`` in bytes
		:param addr: The address to write to
		:param value: The value to write
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``[addr].<size> = value {<flags>}``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_STORE, addr, value, size=size, flags=flags, source_location=loc)

	def push(
		self,
		size: int,
		value: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Writes ``value`` to the stack, adjusting the stack pointer by ``size``.

		:param size: The size of ``value`` in bytes
		:param value: The value to push
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``push.<size>{<flags>}(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_PUSH, value, size=size, flags=flags, source_location=loc)

	def pop(
		self, size: int, flags: Optional['architecture.FlagWriteType'] = None, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Reads ``size`` bytes from the stack, adjusting the stack pointer by ``size``.

		:param size: The size of the result in bytes
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``pop.<size>{<flags>}``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_POP, size=size, flags=flags, source_location=loc)

	def reg(
		self, size: int, reg: 'architecture.RegisterType', loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Reads register ``reg``.

		:param size: The size of the result in bytes
		:param reg: The register to read
		:param loc: The IL location this expression was added from
		:return: The expression ``reg``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_REG, self.arch.get_reg_index(reg), size=size, source_location=loc)

	def reg_split(
		self,
		size: int,
		hi: 'architecture.RegisterType',
		lo: 'architecture.RegisterType',
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Reads the register pair ``hi``:``lo`` as one value, twice the size of each register.

		:param size: The size of each register in bytes
		:param hi: The register holding the high half
		:param lo: The register holding the low half
		:param loc: The IL location this expression was added from
		:return: The expression ``hi:lo``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			LowLevelILOperation.LLIL_REG_SPLIT,
			self.arch.get_reg_index(hi),
			self.arch.get_reg_index(lo),
			size=size,
			source_location=loc,
		)

	def reg_stack_top_relative(
		self,
		size: int,
		reg_stack: 'architecture.RegisterStackType',
		entry: ExpressionIndex,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Reads the register stack entry at position ``entry`` from the top of ``reg_stack``.

		:param size: The size of the result in bytes
		:param reg_stack: The register stack
		:param entry: The position of the entry, relative to the top of the stack
		:param loc: The IL location this expression was added from
		:return: The expression ``reg_stack[entry]``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			LowLevelILOperation.LLIL_REG_STACK_REL,
			self.arch.get_reg_stack_index(reg_stack),
			entry,
			size=size,
			source_location=loc,
		)

	def reg_stack_pop(
		self,
		size: int,
		reg_stack: 'architecture.RegisterStackType',
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Reads the top entry of register stack ``reg_stack`` and removes it from the stack.

		:param size: The size of the result in bytes
		:param reg_stack: The register stack
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``reg_stack.pop{<flags>}``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			LowLevelILOperation.LLIL_REG_STACK_POP,
			self.arch.get_reg_stack_index(reg_stack),
			size=size,
			flags=flags,
			source_location=loc,
		)

	def reg_stack_free_reg(
		self, reg: 'architecture.RegisterType', loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Frees register ``reg`` in its register stack, without changing which register is at the top of the
		stack.

		:param reg: The register to free
		:param loc: The IL location this expression was added from
		:return: The expression ``__free_slot(reg)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_REG_STACK_FREE_REG, self.arch.get_reg_index(reg), source_location=loc)

	def reg_stack_free_top_relative(
		self,
		reg_stack: 'architecture.RegisterStackType',
		entry: ExpressionIndex,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Frees the register stack entry at position ``entry`` from the top of ``reg_stack``.

		:param reg_stack: The register stack
		:param entry: The position of the entry, relative to the top of the stack
		:param loc: The IL location this expression was added from
		:return: The expression ``__free_slot(reg_stack[entry])``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			LowLevelILOperation.LLIL_REG_STACK_FREE_REL,
			self.arch.get_reg_stack_index(reg_stack),
			entry,
			source_location=loc,
		)

	def const(self, size: int, value: int, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		An integer constant.

		:param size: The size of the result in bytes
		:param value: The value
		:param loc: The IL location this expression was added from
		:return: The expression ``value``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_CONST, value, size=size, source_location=loc)

	def const_pointer(self, size: int, value: int, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		A constant pointer to address ``value``.

		:param size: The size of the result in bytes
		:param value: The value
		:param loc: The IL location this expression was added from
		:return: The expression ``value``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_CONST_PTR, value, size=size, source_location=loc)

	def extern_pointer(
		self, size: int, value: int, offset: int, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		A constant pointer ``offset`` bytes from the relocated external address ``value``.

		:param size: The size of the result in bytes
		:param value: The external address
		:param offset: The offset from the external address, in bytes
		:param loc: The IL location this expression was added from
		:return: The expression ``(value + offset)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_EXTERN_PTR, value, offset, size=size, source_location=loc)

	def float_const_raw(self, size: int, value: int, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		A floating point constant. ``value`` holds the bits of its representation as an integer. The single
		and double precision builders take a floating point value and convert it themselves.

		:param size: The size of the result in bytes
		:param value: The bits of the constant's representation, read as an integer
		:param loc: The IL location this expression was added from
		:return: The expression ``value``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FLOAT_CONST, value, size=size, source_location=loc)

	def flag(self, flag: 'architecture.FlagType', loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Reads flag ``flag``.

		:param flag: The flag to read
		:param loc: The IL location this expression was added from
		:return: The expression ``flag``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FLAG, self.arch.get_flag_index(flag), source_location=loc)

	def flag_bit(
		self, size: int, flag: 'architecture.FlagType', bit: int, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		An integer holding the value of flag ``flag`` at bit ``bit``, with every other bit clear.

		:param size: The size of the result in bytes
		:param flag: The flag to read
		:param bit: The index of the bit that holds the flag's value
		:param loc: The IL location this expression was added from
		:return: The expression ``flagbit.<size>(flag, bit)``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			LowLevelILOperation.LLIL_FLAG_BIT, self.arch.get_flag_index(flag), bit, size=size, source_location=loc
		)

	def add(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Adds ``a`` and ``b``. Without flags, renders as ``a + b``.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``add.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_ADD, a, b, size=size, flags=flags, source_location=loc)

	def add_carry(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		carry: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Adds ``a``, ``b`` and the carry ``carry``.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param carry: The carry in
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``adc.<size>{<flags>}(a, b, carry)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_ADC, a, b, carry, size=size, flags=flags, source_location=loc)

	def sub(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Subtracts ``b`` from ``a``. Without flags, renders as ``a - b``.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``sub.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_SUB, a, b, size=size, flags=flags, source_location=loc)

	def sub_borrow(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		carry: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Subtracts ``b`` and the borrow ``carry`` from ``a``.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param carry: The carry in
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``sbb.<size>{<flags>}(a, b, carry)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_SBB, a, b, carry, size=size, flags=flags, source_location=loc)

	def and_expr(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		The bitwise and of ``a`` and ``b``. Without flags, renders as ``a & b``, or as ``a && b`` when
		``size`` is 0.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``and.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_AND, a, b, size=size, flags=flags, source_location=loc)

	def or_expr(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		The bitwise or of ``a`` and ``b``. Without flags, renders as ``a | b``, or as ``a || b`` when
		``size`` is 0.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``or.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_OR, a, b, size=size, flags=flags, source_location=loc)

	def xor_expr(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		The bitwise exclusive or of ``a`` and ``b``. Without flags, renders as ``a ^ b``.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``xor.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_XOR, a, b, size=size, flags=flags, source_location=loc)

	def shift_left(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Shifts ``a`` left by ``b`` bits. Without flags, renders as ``a << b``.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``lsl.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_LSL, a, b, size=size, flags=flags, source_location=loc)

	def logical_shift_right(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Shifts ``a`` logically right by ``b`` bits. Without flags, renders as ``a u>> b``.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``lsr.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_LSR, a, b, size=size, flags=flags, source_location=loc)

	def arith_shift_right(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Shifts ``a`` arithmetically right by ``b`` bits. Without flags, renders as ``a s>> b``.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``asr.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_ASR, a, b, size=size, flags=flags, source_location=loc)

	def rotate_left(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Rotates ``a`` left by ``b`` bits.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``rol.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_ROL, a, b, size=size, flags=flags, source_location=loc)

	def rotate_left_carry(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		carry: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Rotates ``a`` left by ``b`` bits through the carry ``carry``.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param carry: The carry in
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``rlc.<size>{<flags>}(a, b, carry)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_RLC, a, b, carry, size=size, flags=flags, source_location=loc)

	def rotate_right(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Rotates ``a`` right by ``b`` bits.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``ror.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_ROR, a, b, size=size, flags=flags, source_location=loc)

	def rotate_right_carry(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		carry: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Rotates ``a`` right by ``b`` bits through the carry ``carry``.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param carry: The carry in
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``rrc.<size>{<flags>}(a, b, carry)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_RRC, a, b, carry, size=size, flags=flags, source_location=loc)

	def mult(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Multiplies ``a`` by ``b``. The operands and the result are all ``size`` bytes, so the upper half of
		the product is discarded. Without flags, renders as ``a * b``.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``mul.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_MUL, a, b, size=size, flags=flags, source_location=loc)

	def mult_double_prec_unsigned(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Multiplies ``a`` by ``b`` as unsigned integers. The operands are ``size`` bytes and the result is
		``2 * size`` bytes. The expression's size, which it renders with, is still ``size``.

		:param size: The size of ``a`` and ``b`` in bytes
		:param a: The left operand
		:param b: The right operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``mulu.dp.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_MULU_DP, a, b, size=size, flags=flags, source_location=loc)

	def mult_double_prec_signed(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Multiplies ``a`` by ``b`` as signed integers. The operands are ``size`` bytes and the result is
		``2 * size`` bytes. The expression's size, which it renders with, is still ``size``.

		:param size: The size of ``a`` and ``b`` in bytes
		:param a: The left operand
		:param b: The right operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``muls.dp.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_MULS_DP, a, b, size=size, flags=flags, source_location=loc)

	def div_unsigned(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Divides ``a`` by ``b`` as unsigned integers.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``divu.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_DIVU, a, b, size=size, flags=flags, source_location=loc)

	def div_double_prec_unsigned(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Divides ``a`` by ``b`` as unsigned integers. ``a`` is ``2 * size`` bytes, and ``b`` and the result
		are ``size`` bytes.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``divu.dp.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_DIVU_DP, a, b, size=size, flags=flags, source_location=loc)

	def div_signed(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Divides ``a`` by ``b`` as signed integers.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``divs.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_DIVS, a, b, size=size, flags=flags, source_location=loc)

	def div_double_prec_signed(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Divides ``a`` by ``b`` as signed integers. ``a`` is ``2 * size`` bytes, and ``b`` and the result are
		``size`` bytes.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``divs.dp.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_DIVS_DP, a, b, size=size, flags=flags, source_location=loc)

	def mod_unsigned(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		The remainder of dividing ``a`` by ``b`` as unsigned integers.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``modu.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_MODU, a, b, size=size, flags=flags, source_location=loc)

	def mod_double_prec_unsigned(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		The remainder of dividing ``a`` by ``b`` as unsigned integers. ``a`` is ``2 * size`` bytes, and
		``b`` and the result are ``size`` bytes.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``modu.dp.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_MODU_DP, a, b, size=size, flags=flags, source_location=loc)

	def mod_signed(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		The remainder of dividing ``a`` by ``b`` as signed integers.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``mods.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_MODS, a, b, size=size, flags=flags, source_location=loc)

	def mod_double_prec_signed(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		The remainder of dividing ``a`` by ``b`` as signed integers. ``a`` is ``2 * size`` bytes, and ``b``
		and the result are ``size`` bytes.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``mods.dp.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_MODS_DP, a, b, size=size, flags=flags, source_location=loc)

	def neg_expr(
		self,
		size: int,
		value: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Negates ``value`` as a two's complement integer.

		:param size: The size of the result in bytes
		:param value: The operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``neg.<size>{<flags>}(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_NEG, value, size=size, flags=flags, source_location=loc)

	def not_expr(
		self,
		size: int,
		value: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Inverts the bits of ``value``.

		:param size: The size of the result in bytes
		:param value: The operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``not.<size>{<flags>}(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_NOT, value, size=size, flags=flags, source_location=loc)

	def sign_extend(
		self,
		size: int,
		value: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Sign-extends ``value`` to ``size`` bytes.

		:param size: The size of the result in bytes
		:param value: The operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``sx.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_SX, value, size=size, flags=flags, source_location=loc)

	def zero_extend(
		self,
		size: int,
		value: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Zero-extends ``value`` to ``size`` bytes.

		:param size: The size of the result in bytes
		:param value: The operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``zx.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_ZX, value, size=size, flags=flags, source_location=loc)

	def low_part(
		self,
		size: int,
		value: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Truncates ``value`` to its low ``size`` bytes.

		:param size: The size of the result in bytes
		:param value: The operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``(value).<size>``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_LOW_PART, value, size=size, flags=flags, source_location=loc)

	def jump(self, dest: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Jumps to ``dest``.

		:param dest: The address to jump to
		:param loc: The IL location this expression was added from
		:return: The expression ``jump(dest)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_JUMP, dest, source_location=loc)

	def jump_to(
		self, dest: ExpressionIndex, targets: Dict[int, 'LowLevelILLabel'], loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Jumps to the target in ``targets`` chosen by the value of ``dest``.

		:param dest: The value that chooses the target
		:param targets: The labels to jump to, keyed by the value of the destination that chooses each
		:param loc: The IL location this expression was added from
		:return: The expression ``jump(dest => targets)``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			LowLevelILOperation.LLIL_JUMP_TO, dest, len(targets) * 2, self.add_label_map(targets), source_location=loc
		)

	def call(self, dest: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Calls ``dest``. On architectures without a link register, this pushes the address of the next
		instruction onto the stack, then jumps to ``dest``.

		:param dest: The address to call
		:param loc: The IL location this expression was added from
		:return: The expression ``call(dest)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_CALL, dest, source_location=loc)

	def call_stack_adjust(
		self,
		dest: ExpressionIndex,
		stack_adjust: int,
		reg_stack_adjustments: Optional[Dict['architecture.RegisterStackType', int]] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Calls ``dest``, then once the callee returns, adds ``stack_adjust`` to the stack pointer and adjusts
		the top of each register stack by its amount in ``reg_stack_adjustments``.

		:param dest: The address to call
		:param stack_adjust: The amount to add to the stack pointer once the callee returns
		:param reg_stack_adjustments: The amount to move the top of each register stack by once the callee
			returns
		:param loc: The IL location this expression was added from
		:return: The expression ``call(dest), stack += stack_adjust``
		:rtype: ExpressionIndex
		"""
		_reg_stack_adjustments = self._register_stack_adjustment_list(reg_stack_adjustments)
		return self.expr(
			LowLevelILOperation.LLIL_CALL_STACK_ADJUST,
			dest,
			stack_adjust,
			len(_reg_stack_adjustments),
			self.add_index_list(_reg_stack_adjustments),
			source_location=loc,
		)

	def tailcall(self, dest: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Jumps to ``dest`` as a tail call.

		:param dest: The address to jump to
		:param loc: The IL location this expression was added from
		:return: The expression ``<return> tailcall(dest)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_TAILCALL, dest, source_location=loc)

	def ret(self, dest: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Returns from the function by jumping to ``dest``.

		:param dest: The address to return to
		:param loc: The IL location this expression was added from
		:return: The expression ``<return> jump(dest)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_RET, dest, source_location=loc)

	def no_ret(self, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Marks a point that execution doesn't pass, such as after a call that doesn't return.

		:param loc: The IL location this expression was added from
		:return: The expression ``noreturn``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_NORET, source_location=loc)

	def flag_condition(
		self,
		cond: Union[str, LowLevelILFlagCondition, int],
		sem_class: Optional['architecture.SemanticClassType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Tests the flag condition ``cond``, using semantic flag class ``sem_class`` where given.

		:param cond: The condition to test
		:param sem_class: The semantic flag class
		:param loc: The IL location this expression was added from
		:return: The expression ``cond``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			LowLevelILOperation.LLIL_FLAG_COND,
			self._flag_condition_value(cond),
			self.arch.get_semantic_flag_class_index(sem_class),
			source_location=loc,
		)

	def flag_group(
		self, sem_group: 'architecture.SemanticGroupName', loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Tests semantic flag group ``sem_group``.

		:param sem_group: The semantic flag group
		:param loc: The IL location this expression was added from
		:return: The expression ``sem_group``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			LowLevelILOperation.LLIL_FLAG_GROUP, self.arch.get_semantic_flag_group_index(sem_group), source_location=loc
		)

	def compare_equal(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Tests whether ``a`` equals ``b``.

		:param size: The size of ``a`` and ``b`` in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a == b``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_CMP_E, a, b, size=size, source_location=loc)

	def compare_not_equal(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Tests whether ``a`` doesn't equal ``b``.

		:param size: The size of ``a`` and ``b`` in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a != b``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_CMP_NE, a, b, size=size, source_location=loc)

	def compare_signed_less_than(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Tests whether ``a`` is less than ``b`` as signed integers.

		:param size: The size of ``a`` and ``b`` in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a s< b``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_CMP_SLT, a, b, size=size, source_location=loc)

	def compare_unsigned_less_than(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Tests whether ``a`` is less than ``b`` as unsigned integers.

		:param size: The size of ``a`` and ``b`` in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a u< b``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_CMP_ULT, a, b, size=size, source_location=loc)

	def compare_signed_less_equal(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Tests whether ``a`` is less than or equal to ``b`` as signed integers.

		:param size: The size of ``a`` and ``b`` in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a s<= b``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_CMP_SLE, a, b, size=size, source_location=loc)

	def compare_unsigned_less_equal(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Tests whether ``a`` is less than or equal to ``b`` as unsigned integers.

		:param size: The size of ``a`` and ``b`` in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a u<= b``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_CMP_ULE, a, b, size=size, source_location=loc)

	def compare_signed_greater_equal(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Tests whether ``a`` is greater than or equal to ``b`` as signed integers.

		:param size: The size of ``a`` and ``b`` in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a s>= b``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_CMP_SGE, a, b, size=size, source_location=loc)

	def compare_unsigned_greater_equal(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Tests whether ``a`` is greater than or equal to ``b`` as unsigned integers.

		:param size: The size of ``a`` and ``b`` in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a u>= b``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_CMP_UGE, a, b, size=size, source_location=loc)

	def compare_signed_greater_than(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Tests whether ``a`` is greater than ``b`` as signed integers.

		:param size: The size of ``a`` and ``b`` in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a s> b``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_CMP_SGT, a, b, size=size, source_location=loc)

	def compare_unsigned_greater_than(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Tests whether ``a`` is greater than ``b`` as unsigned integers.

		:param size: The size of ``a`` and ``b`` in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a u> b``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_CMP_UGT, a, b, size=size, source_location=loc)

	def test_bit(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Tests whether bit ``b`` of ``a`` is set.

		:param size: The size of ``a`` in bytes
		:param a: The left operand
		:param b: The index of the bit to test
		:param loc: The IL location this expression was added from
		:return: The expression ``test_bit(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_TEST_BIT, a, b, size=size, source_location=loc)

	def bool_to_int(self, size: int, a: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Converts ``a`` to the integer 1 if it's true, or 0 if it's false.

		:param size: The size of the result in bytes
		:param a: The operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a ? 1 : 0``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_BOOL_TO_INT, a, size=size, source_location=loc)

	def system_call(self, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Makes a system call.

		:param loc: The IL location this expression was added from
		:return: The expression ``syscall``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_SYSCALL, source_location=loc)

	def breakpoint(self, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		A processor breakpoint.

		:param loc: The IL location this expression was added from
		:return: The expression ``breakpoint``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_BP, source_location=loc)

	def trap(self, value: int, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		A processor trap, or interrupt, with number ``value``.

		:param value: The trap number
		:param loc: The IL location this expression was added from
		:return: The expression ``trap(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_TRAP, value, source_location=loc)

	def intrinsic(
		self,
		outputs: List[Union[ILRegisterType, ILFlag, 'architecture.RegisterInfo']],
		intrinsic: 'architecture.IntrinsicType',
		params: List[ExpressionIndex],
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Calls intrinsic ``intrinsic`` with ``params``. An intrinsic is an architecture operation lifted as a
		call to a built-in function that doesn't exist in the binary. Its results go to ``outputs``.

		:param outputs: The registers and flags the intrinsic writes
		:param intrinsic: The architecture intrinsic to call
		:param params: The parameters
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``outputs = intrinsic{<flags>}(params)``
		:rtype: ExpressionIndex
		"""
		_outputs = self._register_or_flag_identifiers(outputs)
		return self.expr(
			LowLevelILOperation.LLIL_INTRINSIC,
			len(_outputs),
			self.add_index_list(_outputs),
			self.arch.get_intrinsic_index(intrinsic),
			self.expr(
				LowLevelILOperation.LLIL_CALL_PARAM,
				len(params),
				self.add_operand_list(params),
				size=0,
				source_location=loc,
			),
			flags=flags,
			source_location=loc,
		)

	def undefined(self, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		An undefined value or operation. As a statement, it ends the basic block and leaves its outgoing
		edges undetermined.

		:param loc: The IL location this expression was added from
		:return: The expression ``undefined``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_UNDEF, source_location=loc)

	def unimplemented(self, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		An unimplemented instruction or value.

		:param loc: The IL location this expression was added from
		:return: The expression ``unimplemented``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_UNIMPL, 0, source_location=loc)

	def unknown(self, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		A value that can't be known at analysis time, such as a flag that depends on runtime state. It
		doesn't produce the warning an unimplemented expression does.

		:param loc: The IL location this expression was added from
		:return: The expression ``unknown``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_UNIMPL, 1, source_location=loc)

	def unimplemented_memory_ref(
		self, size: int, addr: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		A reference to ``size`` bytes of memory at ``addr``, for an unimplemented operation.

		:param size: The size of the result in bytes
		:param addr: The address referenced
		:param loc: The IL location this expression was added from
		:return: The expression ``unimplemented([addr].<size>)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_UNIMPL_MEM, addr, 0, size=size, source_location=loc)

	def unknown_memory_ref(
		self, size: int, addr: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		A reference to ``size`` bytes of memory at ``addr``, whose value can't be known at analysis time. It
		doesn't produce the warning an unimplemented expression does.

		:param size: The size of the result in bytes
		:param addr: The address referenced
		:param loc: The IL location this expression was added from
		:return: The expression ``unknown([addr].<size>)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_UNIMPL_MEM, addr, 1, size=size, source_location=loc)

	def float_add(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Adds ``a`` and ``b`` as floating point values. Without flags, renders as ``a f+ b``.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``fadd.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FADD, a, b, size=size, flags=flags, source_location=loc)

	def float_sub(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Subtracts ``b`` from ``a`` as floating point values. Without flags, renders as ``a f- b``.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``fsub.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FSUB, a, b, size=size, flags=flags, source_location=loc)

	def float_mult(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Multiplies ``a`` by ``b`` as floating point values. Without flags, renders as ``a f* b``.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``fmul.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FMUL, a, b, size=size, flags=flags, source_location=loc)

	def float_div(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Divides ``a`` by ``b`` as floating point values. Without flags, renders as ``a f/ b``.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``fdiv.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FDIV, a, b, size=size, flags=flags, source_location=loc)

	def float_sqrt(
		self,
		size: int,
		value: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		The square root of the floating point value ``value``.

		:param size: The size of the result in bytes
		:param value: The operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``sqrt{<flags>}(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FSQRT, value, size=size, flags=flags, source_location=loc)

	def float_neg(
		self,
		size: int,
		value: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Negates the floating point value ``value``.

		:param size: The size of the result in bytes
		:param value: The operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``fneg{<flags>}(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FNEG, value, size=size, flags=flags, source_location=loc)

	def float_abs(
		self,
		size: int,
		value: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		The absolute value of the floating point value ``value``.

		:param size: The size of the result in bytes
		:param value: The operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``fabs{<flags>}(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FABS, value, size=size, flags=flags, source_location=loc)

	def float_to_int(
		self,
		size: int,
		value: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Converts the floating point value ``value`` to an integer.

		:param size: The size of the result in bytes
		:param value: The operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``int.<size>{<flags>}(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FLOAT_TO_INT, value, size=size, flags=flags, source_location=loc)

	def int_to_float(
		self,
		size: int,
		value: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Converts the integer ``value`` to a floating point value.

		:param size: The size of the result in bytes
		:param value: The operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``float.<size>{<flags>}(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_INT_TO_FLOAT, value, size=size, flags=flags, source_location=loc)

	def float_convert(
		self,
		size: int,
		value: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Converts the floating point value ``value`` to a floating point value of ``size`` bytes.

		:param size: The size of the result in bytes
		:param value: The operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``fconvert.<size>{<flags>}(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FLOAT_CONV, value, size=size, flags=flags, source_location=loc)

	def round_to_int(
		self,
		size: int,
		value: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Rounds the floating point value ``value`` to the nearest integral value.

		:param size: The size of the result in bytes
		:param value: The operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``roundint.<size>{<flags>}(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_ROUND_TO_INT, value, size=size, flags=flags, source_location=loc)

	def floor(
		self,
		size: int,
		value: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Rounds the floating point value ``value`` to an integral value, towards negative infinity.

		:param size: The size of the result in bytes
		:param value: The operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``floor.<size>{<flags>}(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FLOOR, value, size=size, flags=flags, source_location=loc)

	def ceil(
		self,
		size: int,
		value: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Rounds the floating point value ``value`` to an integral value, towards positive infinity.

		:param size: The size of the result in bytes
		:param value: The operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``ceil.<size>{<flags>}(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_CEIL, value, size=size, flags=flags, source_location=loc)

	def float_trunc(
		self,
		size: int,
		value: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Rounds the floating point value ``value`` to an integral value, towards zero.

		:param size: The size of the result in bytes
		:param value: The operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``ftrunc.<size>{<flags>}(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FTRUNC, value, size=size, flags=flags, source_location=loc)

	def float_compare_equal(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Tests whether ``a`` equals ``b`` as floating point values.

		:param size: The size of ``a`` and ``b`` in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a f== b``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FCMP_E, a, b, size=size, source_location=loc)

	def float_compare_not_equal(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Tests whether ``a`` doesn't equal ``b`` as floating point values.

		:param size: The size of ``a`` and ``b`` in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a f!= b``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FCMP_NE, a, b, size=size, source_location=loc)

	def float_compare_less_than(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Tests whether ``a`` is less than ``b`` as floating point values.

		:param size: The size of ``a`` and ``b`` in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a f< b``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FCMP_LT, a, b, size=size, source_location=loc)

	def float_compare_less_equal(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Tests whether ``a`` is less than or equal to ``b`` as floating point values.

		:param size: The size of ``a`` and ``b`` in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a f<= b``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FCMP_LE, a, b, size=size, source_location=loc)

	def float_compare_greater_equal(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Tests whether ``a`` is greater than or equal to ``b`` as floating point values.

		:param size: The size of ``a`` and ``b`` in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a f>= b``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FCMP_GE, a, b, size=size, source_location=loc)

	def float_compare_greater_than(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Tests whether ``a`` is greater than ``b`` as floating point values.

		:param size: The size of ``a`` and ``b`` in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a f> b``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FCMP_GT, a, b, size=size, source_location=loc)

	def float_compare_ordered(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Tests whether ``a`` and ``b`` are ordered, which they are when neither is NaN.

		:param size: The size of ``a`` and ``b`` in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``is_ordered.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FCMP_O, a, b, size=size, source_location=loc)

	def float_compare_unordered(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Tests whether ``a`` and ``b`` are unordered, which they are when either is NaN.

		:param size: The size of ``a`` and ``b`` in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``is_unordered.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FCMP_UO, a, b, size=size, source_location=loc)

	def byte_swap(
		self,
		size: int,
		value: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Reverses the byte order of ``value``.

		:param size: The size of the result in bytes
		:param value: The operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``bswap.<size>{<flags>}(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_BSWAP, value, size=size, flags=flags, source_location=loc)

	def population_count(
		self,
		size: int,
		value: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Counts the set bits in ``value``.

		:param size: The size of the result in bytes
		:param value: The operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``popcnt.<size>{<flags>}(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_POPCNT, value, size=size, flags=flags, source_location=loc)

	def count_leading_zeros(
		self,
		size: int,
		value: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Counts the leading zero bits in ``value``. The result is ``8 * size`` when ``value`` is zero.

		:param size: The size of the result in bytes
		:param value: The operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``clz.<size>{<flags>}(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_CLZ, value, size=size, flags=flags, source_location=loc)

	def count_trailing_zeros(
		self,
		size: int,
		value: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Counts the trailing zero bits in ``value``. The result is ``8 * size`` when ``value`` is zero.

		:param size: The size of the result in bytes
		:param value: The operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``ctz.<size>{<flags>}(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_CTZ, value, size=size, flags=flags, source_location=loc)

	def reverse_bits(
		self,
		size: int,
		value: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Reverses the bit order of ``value``.

		:param size: The size of the result in bytes
		:param value: The operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``rbit.<size>{<flags>}(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_RBIT, value, size=size, flags=flags, source_location=loc)

	def count_leading_signs(
		self,
		size: int,
		value: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Counts the bits below the sign bit of ``value`` that match it.

		:param size: The size of the result in bytes
		:param value: The operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``cls.<size>{<flags>}(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_CLS, value, size=size, flags=flags, source_location=loc)

	def min_signed(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		The smaller of ``a`` and ``b`` as signed integers.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``mins.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_MINS, a, b, size=size, flags=flags, source_location=loc)

	def max_signed(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		The larger of ``a`` and ``b`` as signed integers.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``maxs.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_MAXS, a, b, size=size, flags=flags, source_location=loc)

	def min_unsigned(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		The smaller of ``a`` and ``b`` as unsigned integers.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``minu.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_MINU, a, b, size=size, flags=flags, source_location=loc)

	def max_unsigned(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		The larger of ``a`` and ``b`` as unsigned integers.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``maxu.<size>{<flags>}(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_MAXU, a, b, size=size, flags=flags, source_location=loc)

	def absolute_value(
		self,
		size: int,
		value: ExpressionIndex,
		flags: Optional['architecture.FlagWriteType'] = None,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		The absolute value of ``value`` as a signed integer.

		:param size: The size of the result in bytes
		:param value: The operand
		:param flags: The flag write type that selects the flags the operation sets
		:param loc: The IL location this expression was added from
		:return: The expression ``abs.<size>{<flags>}(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_ABS, value, size=size, flags=flags, source_location=loc)

	# END GENERATED llil-builders

	def float_const_single(self, value: float, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``float_const_single`` returns an expression for the single precision floating point value ``value``

		:param float value: float value for the constant
		:param ILSourceLocation loc: location of returned expression
		:return: A constant expression of given value and size
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FLOAT_CONST, struct.unpack("I", struct.pack("f", value))[0], size=4, source_location=loc)

	def float_const_double(self, value: float, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``float_const_double`` returns an expression for the double precision floating point value ``value``

		:param float value: float value for the constant
		:param ILSourceLocation loc: location of returned expression
		:return: A constant expression of given value and size
		:rtype: ExpressionIndex
		"""
		return self.expr(LowLevelILOperation.LLIL_FLOAT_CONST, struct.unpack("Q", struct.pack("d", value))[0], size=8, source_location=loc)

	def goto(self, label: LowLevelILLabel, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``goto`` returns a goto expression which jumps to the provided LowLevelILLabel.

		:param LowLevelILLabel label: Label to jump to
		:param ILSourceLocation loc: location of returned expression
		:return: the ExpressionIndex that jumps to the provided label
		:rtype: ExpressionIndex
		"""
		if loc is not None:
			return ExpressionIndex(core.BNLowLevelILGotoWithLocation(self.handle, label.handle, loc.address, loc.source_operand))
		else:
			return ExpressionIndex(core.BNLowLevelILGoto(self.handle, label.handle))

	def if_expr(
	    self, operand: ExpressionIndex, t: LowLevelILLabel, f: LowLevelILLabel,
	    loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``if_expr`` returns the ``if`` expression which depending on condition ``operand`` jumps to the LowLevelILLabel
		``t`` when the condition expression ``operand`` is non-zero and ``f`` when it's zero.

		:param ExpressionIndex operand: comparison expression to evaluate.
		:param LowLevelILLabel t: Label for the true branch
		:param LowLevelILLabel f: Label for the false branch
		:param ILSourceLocation loc: location of returned expression
		:return: the ExpressionIndex for the if expression
		:rtype: ExpressionIndex
		"""
		if loc is not None:
			return ExpressionIndex(core.BNLowLevelILIfWithLocation(self.handle, operand, t.handle, f.handle, loc.address, loc.source_operand))
		else:
			return ExpressionIndex(core.BNLowLevelILIf(self.handle, operand, t.handle, f.handle))

	def mark_label(self, label: LowLevelILLabel) -> None:
		"""
		``mark_label`` assigns a LowLevelILLabel to the current IL address.

		:param LowLevelILLabel label:
		:rtype: None
		"""
		core.BNLowLevelILMarkLabel(self.handle, label.handle)

	def add_label_map(self, labels: Dict[int, LowLevelILLabel], loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``add_label_map`` returns a label list expression for the given list of LowLevelILLabel objects.

		:param labels: the list of LowLevelILLabel to get a label list expression from
		:type labels: dict(int, LowLevelILLabel)
		:param ILSourceLocation loc: location of returned expression
		:return: the label list expression
		:rtype: ExpressionIndex
		"""
		label_list = (ctypes.POINTER(core.BNLowLevelILLabel) * len(labels))()
		value_list = (ctypes.c_ulonglong * len(labels))()
		for i, (key, value) in enumerate(labels.items()):
			value_list[i] = key
			label_list[i] = value.handle

		return ExpressionIndex(core.BNLowLevelILAddLabelMap(self.handle, value_list, label_list, len(labels)))

	def add_operand_list(self, operands: List[Union[ExpressionIndex, ExpressionIndex]]) -> ExpressionIndex:
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

	def add_index_list(self, indices: List[int]) -> ExpressionIndex:
		"""
		``add_index_list`` returns an index list expression for the given list of integers.

		:param indices: list of numbers
		:type indices: List(int)
		:return: an operand list expression
		:rtype: ExpressionIndex
		"""
		index_list = (ctypes.c_ulonglong * len(indices))()
		for i in range(len(indices)):
			index = indices[i]
			if isinstance(index, int):
				index_list[i] = ExpressionIndex(index)
			else:
				raise Exception("Invalid index type")
		return ExpressionIndex(core.BNLowLevelILAddOperandList(self.handle, index_list, len(indices)))

	def cache_possible_value_set(self, pvs: 'variable.PossibleValueSet') -> int:
		"""
		Cache a PossibleValueSet in the IL function, returning its index for use in an expression operand
		:param pvs: PossibleValueSet to cache
		:return: Index of the PossibleValueSet in the cache
		"""
		return core.BNCacheLowLevelILPossibleValueSet(self.handle, pvs._to_core_struct())

	def operand(self, n: int, expr: ExpressionIndex) -> ExpressionIndex:
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

	def prepare_to_copy_function(self, src: 'LowLevelILFunction'):
		"""
		``prepare_to_copy_function`` sets up state in this LLIL function in preparation
		of copying instructions from ``src``.
		It enables use of :py:func:`get_label_for_source_instruction` during function transformation.

		:param LowLevelILFunction src: function about to be copied from
		"""
		core.BNPrepareToCopyLowLevelILFunction(self.handle, src.handle)

	def prepare_to_copy_block(self, src: 'LowLevelILBasicBlock'):
		"""
		``prepare_to_copy_block`` sets up state when copying a function in preparation
		of copying the instructions from the block ``src``
		It enables use of :py:func:`get_label_for_source_instruction` during function transformation.

		:param LowLevelILBasicBlock src: block about to be copied from
		"""
		core.BNPrepareToCopyLowLevelILBasicBlock(self.handle, src.handle)

	def get_label_for_source_instruction(self, i: InstructionIndex) -> Optional['LowLevelILLabel']:
		"""
		Get the LowLevelILLabel for a given source instruction. The source instruction must be
		at the start of a basic block in the source function passed to :py:func:`prepare_to_copy_function`.
		The label will be marked resolved when its source block is passed to :py:func:`prepare_to_copy_block`.

		.. warning:: The instruction index parameter for this pertains to the *source function*
		             passed to `prepare_to_copy_function`, not the current function.

		.. note:: The returned label is to an internal object with the same lifetime as the containing LowLevelILFunction.

		:param i: The source instruction index
		:return: The LowLevelILLabel for the source instruction
		"""
		label = core.BNGetLabelForLowLevelILSourceInstruction(self.handle, i)
		if not label:
			return None
		return LowLevelILLabel(handle=label)

	def add_label_for_address(self, arch: 'architecture.Architecture', addr: int) -> None:
		"""
		``add_label_for_address`` adds a low-level IL label for the given architecture ``arch`` at the given virtual
		address ``addr``.
		This is generally called automatically by the core when Lifted IL is being generated,
		and will be automatically called with the start address of every basic block found during disassembly.

		:param Architecture arch: Architecture to add labels for
		:param int addr: the IL address to add a label at
		"""
		if arch is not None:
			arch = arch.handle
		core.BNAddLowLevelILLabelForAddress(self.handle, arch, addr)

	def get_label_for_address(self, arch: 'architecture.Architecture', addr: int) -> Optional[LowLevelILLabel]:
		"""
		``get_label_for_address`` returns the LowLevelILLabel for the given Architecture ``arch`` and IL address ``addr``
		that has been previously added to the function with :py:func:`add_label_for_address`.
		When lifting to Lifted IL, labels will be automatically added with :py:func:`add_label_for_address`
		for the start address of every basic block found during disassembly.

		.. note:: The returned label is to an internal object with the same lifetime as the containing LowLevelILFunction.

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

	def get_ssa_instruction_index(self, instr: InstructionIndex) -> InstructionIndex:
		return core.BNGetLowLevelILSSAInstructionIndex(self.handle, instr)

	def get_non_ssa_instruction_index(self, instr: InstructionIndex) -> InstructionIndex:
		return core.BNGetLowLevelILNonSSAInstructionIndex(self.handle, instr)

	def get_ssa_reg_definition(self, reg_ssa: SSARegister) -> Optional[LowLevelILInstruction]:
		reg = self.arch.get_reg_index(reg_ssa.reg)
		result = core.BNGetLowLevelILSSARegisterDefinition(self.handle, reg, reg_ssa.version)
		if result >= core.BNGetLowLevelILInstructionCount(self.handle):
			return None
		return self[result]

	def get_ssa_flag_definition(self, flag_ssa: SSAFlag) -> Optional[LowLevelILInstruction]:
		flag = self.arch.get_flag_index(flag_ssa.flag)
		result = core.BNGetLowLevelILSSAFlagDefinition(self.handle, flag, flag_ssa.version)
		if result >= core.BNGetLowLevelILInstructionCount(self.handle):
			return None
		return self[result]

	def get_ssa_memory_definition(self, index: int) -> Optional[LowLevelILInstruction]:
		result = core.BNGetLowLevelILSSAMemoryDefinition(self.handle, index)
		if result >= core.BNGetLowLevelILInstructionCount(self.handle):
			return None
		return self[result]

	def get_ssa_reg_uses(self, reg_ssa: SSARegister) -> List[LowLevelILInstruction]:
		reg = self.arch.get_reg_index(reg_ssa.reg)
		count = ctypes.c_ulonglong()
		instrs = core.BNGetLowLevelILSSARegisterUses(self.handle, reg, reg_ssa.version, count)
		assert instrs is not None, "core.BNGetLowLevelILSSARegisterUses returned None"
		result = []
		for i in range(0, count.value):
			result.append(self[instrs[i]])
		core.BNFreeILInstructionList(instrs)
		return result

	def get_ssa_flag_uses(self, flag_ssa: SSAFlag) -> List[LowLevelILInstruction]:
		flag = self.arch.get_flag_index(flag_ssa.flag)
		count = ctypes.c_ulonglong()
		instrs = core.BNGetLowLevelILSSAFlagUses(self.handle, flag, flag_ssa.version, count)
		assert instrs is not None, "core.BNGetLowLevelILSSAFlagUses returned None"
		result = []
		for i in range(0, count.value):
			result.append(self[instrs[i]])
		core.BNFreeILInstructionList(instrs)
		return result

	def get_ssa_memory_uses(self, index: int) -> List[LowLevelILInstruction]:
		count = ctypes.c_ulonglong()
		instrs = core.BNGetLowLevelILSSAMemoryUses(self.handle, index, count)
		assert instrs is not None, "core.BNGetLowLevelILSSAMemoryUses returned None"
		result = []
		for i in range(0, count.value):
			result.append(self[instrs[i]])
		core.BNFreeILInstructionList(instrs)
		return result

	def get_ssa_reg_value(self, reg_ssa: SSARegister) -> 'variable.RegisterValue':
		reg = self.arch.get_reg_index(reg_ssa.reg)
		value = core.BNGetLowLevelILSSARegisterValue(self.handle, reg, reg_ssa.version)
		result = variable.RegisterValue.from_BNRegisterValue(value, self._arch)
		return result

	def get_ssa_flag_value(self, flag_ssa: SSAFlag) -> 'variable.RegisterValue':
		flag = self.arch.get_flag_index(flag_ssa.flag)
		value = core.BNGetLowLevelILSSAFlagValue(self.handle, flag, flag_ssa.version)
		result = variable.RegisterValue.from_BNRegisterValue(value, self._arch)
		return result

	def get_instruction_index_for_expr(self, expr: ExpressionIndex) -> Optional[InstructionIndex]:
		result = core.BNGetLowLevelILInstructionForExpr(self.handle, expr)
		if result >= core.BNGetLowLevelILInstructionCount(self.handle):
			return None
		return InstructionIndex(result)

	def get_expr_index_for_instruction(self, instr: InstructionIndex) -> ExpressionIndex:
		result = core.BNGetLowLevelILIndexForInstruction(self.handle, instr)
		return ExpressionIndex(result)

	def get_medium_level_il_instruction_index(self,
	                                          instr: InstructionIndex) -> Optional['mediumlevelil.InstructionIndex']:
		med_il = self.medium_level_il
		if med_il is None:
			return None
		result = core.BNGetMediumLevelILInstructionIndex(self.handle, instr)
		if result >= core.BNGetMediumLevelILInstructionCount(med_il.handle):
			return None
		return result

	def get_medium_level_il_expr_index(self, expr: ExpressionIndex) -> Optional['mediumlevelil.ExpressionIndex']:
		med_il = self.medium_level_il
		if med_il is None:
			return None
		result = core.BNGetMediumLevelILExprIndex(self.handle, expr)
		if result >= core.BNGetMediumLevelILExprCount(med_il.handle):
			return None
		return result

	def get_medium_level_il_expr_indexes(self, expr: ExpressionIndex) -> List['mediumlevelil.ExpressionIndex']:
		count = ctypes.c_ulonglong()
		exprs = core.BNGetMediumLevelILExprIndexes(self.handle, expr, count)
		assert exprs is not None, "core.BNGetMediumLevelILExprIndexes returned None"
		result = []
		for i in range(0, count.value):
			result.append(exprs[i])
		core.BNFreeILInstructionList(exprs)
		return result

	def get_mapped_medium_level_il_instruction_index(self, instr: InstructionIndex) -> Optional[InstructionIndex]:
		med_il = self.mapped_medium_level_il
		if med_il is None:
			return None
		result = core.BNGetMappedMediumLevelILInstructionIndex(self.handle, instr)
		if result >= core.BNGetMediumLevelILInstructionCount(med_il.handle):
			return None
		return result

	def get_mapped_medium_level_il_expr_index(self, expr: ExpressionIndex) -> Optional['mediumlevelil.ExpressionIndex']:
		med_il = self.mapped_medium_level_il
		if med_il is None:
			return None
		result = core.BNGetMappedMediumLevelILExprIndex(self.handle, expr)
		if result >= core.BNGetMediumLevelILExprCount(med_il.handle):
			return None
		return result

	def get_high_level_il_instruction_index(self, instr: InstructionIndex) -> Optional['highlevelil.InstructionIndex']:
		med_il = self.medium_level_il
		if med_il is None:
			return None
		mlil_instr = self.get_medium_level_il_instruction_index(instr)
		if mlil_instr is None:
			return None
		return med_il.get_high_level_il_instruction_index(mlil_instr)

	def get_high_level_il_expr_index(self, expr: ExpressionIndex) -> Optional['highlevelil.ExpressionIndex']:
		med_il = self.medium_level_il
		if med_il is None:
			return None
		mlil_expr = self.get_medium_level_il_expr_index(expr)
		if mlil_expr is None:
			return None
		return med_il.get_high_level_il_expr_index(mlil_expr)

	def create_graph(self, settings: Optional['function.DisassemblySettings'] = None) -> flowgraph.CoreFlowGraph:
		if settings is not None:
			settings_obj = settings.handle
		else:
			settings_obj = None
		return flowgraph.CoreFlowGraph(core.BNCreateLowLevelILFunctionGraph(self.handle, settings_obj))

	def create_graph_immediate(self, settings: Optional['function.DisassemblySettings'] = None) -> flowgraph.CoreFlowGraph:
		if settings is not None:
			settings_obj = settings.handle
		else:
			settings_obj = None
		return flowgraph.CoreFlowGraph(core.BNCreateLowLevelILImmediateFunctionGraph(self.handle, settings_obj))


class LowLevelILBasicBlock(basicblock.BasicBlock):
	"""
	The ``LogLevelILBasicBlock`` object is returned during analysis and should not be directly instantiated.
	"""
	def __init__(
	    self, handle: core.BNBasicBlockHandle, owner: LowLevelILFunction, view: Optional['binaryview.BinaryView']
	):
		super().__init__(handle, view)
		self._il_function = owner

	def __hash__(self):
		return hash((self.start, self.end, self._il_function))

	def __contains__(self, instruction):
		if not isinstance(instruction, LowLevelILInstruction) or instruction.il_basic_block != self:
			return False
		return True

	def __iter__(self) -> Generator['LowLevelILInstruction', None, None]:
		for idx in range(self.start, self.end):
			yield self._il_function[idx]

	@overload
	def __getitem__(self, idx: int) -> 'LowLevelILInstruction': ...

	@overload
	def __getitem__(self, idx: slice) -> List['LowLevelILInstruction']: ...

	def __getitem__(self, idx: Union[int, slice]) -> Union['LowLevelILInstruction', List['LowLevelILInstruction']]:
		size = self.end - self.start
		if isinstance(idx, slice):
			return [self[index] for index in range(*idx.indices(size))]
		if idx > size or idx < -size:
			raise IndexError("list index is out of range")
		if idx >= 0:
			return self._il_function[idx + self.start]
		else:
			return self._il_function[self.end + idx]

	def __repr__(self):
		arch = self.arch
		if arch:
			return f"<{self.__class__.__name__}: {arch.name}@{self.start}-{self.end}>"
		else:
			return f"<{self.__class__.__name__}: {self.start}-{self.end}>"

	def _create_instance(self, handle):
		"""Internal method by super to instantiate child instances"""
		return LowLevelILBasicBlock(handle, self._il_function, self.view)

	@property
	def instruction_count(self) -> int:
		return self.end - self.start

	@property
	def il_function(self) -> LowLevelILFunction:
		return self._il_function


def LLIL_TEMP(n: Union[ILRegister, int]) -> 'architecture.RegisterIndex':
	return architecture.RegisterIndex(int(n) | 0x80000000)


def LLIL_REG_IS_TEMP(n: Union[ILRegister, int]) -> bool:
	return (int(n) & 0x80000000) != 0


def LLIL_GET_TEMP_REG_INDEX(n: Union[ILRegister, int]) -> int:
	return int(n) & 0x7fffffff
