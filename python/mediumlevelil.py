# Copyright (c) 2018-2021 Vector 35 Inc
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
from typing import Optional, List, Union, Mapping, Generator, NewType, Tuple, ClassVar
from dataclasses import dataclass

# Binary Ninja components
from . import _binaryninjacore as core
from .enums import MediumLevelILOperation, ILBranchDependence, DataFlowQueryOption, FunctionGraphType
from . import basicblock
from . import function
from . import types
from . import lowlevelil
from . import highlevelil
from . import flowgraph
from . import variable
from . import architecture
from . import binaryview
from .commonil import (Constant, BinaryOperation, UnaryOperation, Comparison, SSA,
	Phi, FloatingPoint, ControlFlow, Terminal, Call, Syscall, Tailcall, Return,
	Signed, Arithmetic, Carry, DoublePrecision, Memory, Load, Store, RegisterStack, SetVar)

OptionalTokens = Optional[List['function.InstructionTextToken']]
ExpressionIndex = NewType('ExpressionIndex', int)
InstructionIndex = NewType('InstructionIndex', int)
MLILInstructionsType = Generator['MediumLevelILInstruction', None, None]
MLILBasicBlocksType = Generator['MediumLevelILBasicBlock', None, None]
OperandsType = Tuple[ExpressionIndex, ExpressionIndex, ExpressionIndex, ExpressionIndex, ExpressionIndex]
MediumLevelILOperandType = Union[
		int,
		float,
		'MediumLevelILOperationAndSize',
		'MediumLevelILInstruction',
		'lowlevelil.ILIntrinsic',
		'variable.Variable',
		'SSAVariable',
		List[int],
		List['SSAVariable'],
		List['MediumLevelILInstruction'],
		Mapping[int, int]
	]

@dataclass(frozen=True, repr=False, order=True)
class SSAVariable:
	var:'variable.Variable'
	version:int

	def __repr__(self):
		return f"<ssa {self.var} version {self.version}>"


class MediumLevelILLabel:
	def __init__(self, handle:Optional[core.BNMediumLevelILLabel]=None):
		if handle is None:
			self.handle = (core.BNMediumLevelILLabel * 1)()
			core.BNMediumLevelILInitLabel(self.handle)
		else:
			self.handle = handle


@dataclass(frozen=True, repr=False)
class MediumLevelILOperationAndSize:
	operation:MediumLevelILOperation
	size:int

	def __repr__(self):
		if self.size == 0:
			return f"<{self.operation.name}>"
		return f"<{self.operation.name} {self.size}>"


@dataclass(frozen=True)
class CoreMediumLevelILInstruction:
	operation:MediumLevelILOperation
	source_operand:int
	size:int
	operands:OperandsType
	address:int


	@classmethod
	def from_BNMediumLevelILInstruction(cls, instr:core.BNMediumLevelILInstruction) -> 'CoreMediumLevelILInstruction':
		operands:OperandsType = tuple([ExpressionIndex(instr.operands[i]) for i in range(5)])  # type: ignore
		return cls(MediumLevelILOperation(instr.operation), instr.sourceOperand, instr.size, operands, instr.address)


@dataclass(frozen=True)
class MediumLevelILInstruction:
	"""
	``class MediumLevelILInstruction`` Medium Level Intermediate Language Instructions are infinite length tree-based
	instructions. Tree-based instructions use infix notation with the left hand operand being the destination operand.
	Infix notation is thus more natural to read than other notations (e.g. x86 ``mov eax, 0`` vs. MLIL ``eax = 0``).
	"""

	function:'MediumLevelILFunction'
	expr_index:ExpressionIndex
	instr:CoreMediumLevelILInstruction
	instr_index:InstructionIndex
	ILOperations:ClassVar[Mapping[MediumLevelILOperation, List[Tuple[str,str]]]] = {
		MediumLevelILOperation.MLIL_NOP: [],
		MediumLevelILOperation.MLIL_SET_VAR: [("dest", "var"), ("src", "expr")],
		MediumLevelILOperation.MLIL_SET_VAR_FIELD: [("dest", "var"), ("offset", "int"), ("src", "expr")],
		MediumLevelILOperation.MLIL_SET_VAR_SPLIT: [("high", "var"), ("low", "var"), ("src", "expr")],
		MediumLevelILOperation.MLIL_LOAD: [("src", "expr")],
		MediumLevelILOperation.MLIL_LOAD_STRUCT: [("src", "expr"), ("offset", "int")],
		MediumLevelILOperation.MLIL_STORE: [("dest", "expr"), ("src", "expr")],
		MediumLevelILOperation.MLIL_STORE_STRUCT: [("dest", "expr"), ("offset", "int"), ("src", "expr")],
		MediumLevelILOperation.MLIL_VAR: [("src", "var")],
		MediumLevelILOperation.MLIL_VAR_FIELD: [("src", "var"), ("offset", "int")],
		MediumLevelILOperation.MLIL_VAR_SPLIT: [("high", "var"), ("low", "var")],
		MediumLevelILOperation.MLIL_ADDRESS_OF: [("src", "var")],
		MediumLevelILOperation.MLIL_ADDRESS_OF_FIELD: [("src", "var"), ("offset", "int")],
		MediumLevelILOperation.MLIL_CONST: [("constant", "int")],
		MediumLevelILOperation.MLIL_CONST_PTR: [("constant", "int")],
		MediumLevelILOperation.MLIL_EXTERN_PTR: [("constant", "int"), ("offset", "int")],
		MediumLevelILOperation.MLIL_FLOAT_CONST: [("constant", "float")],
		MediumLevelILOperation.MLIL_IMPORT: [("constant", "int")],
		MediumLevelILOperation.MLIL_ADD: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_ADC: [("left", "expr"), ("right", "expr"), ("carry", "expr")],
		MediumLevelILOperation.MLIL_SUB: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_SBB: [("left", "expr"), ("right", "expr"), ("carry", "expr")],
		MediumLevelILOperation.MLIL_AND: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_OR: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_XOR: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_LSL: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_LSR: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_ASR: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_ROL: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_RLC: [("left", "expr"), ("right", "expr"), ("carry", "expr")],
		MediumLevelILOperation.MLIL_ROR: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_RRC: [("left", "expr"), ("right", "expr"), ("carry", "expr")],
		MediumLevelILOperation.MLIL_MUL: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_MULU_DP: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_MULS_DP: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_DIVU: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_DIVU_DP: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_DIVS: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_DIVS_DP: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_MODU: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_MODU_DP: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_MODS: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_MODS_DP: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_NEG: [("src", "expr")],
		MediumLevelILOperation.MLIL_NOT: [("src", "expr")],
		MediumLevelILOperation.MLIL_SX: [("src", "expr")],
		MediumLevelILOperation.MLIL_ZX: [("src", "expr")],
		MediumLevelILOperation.MLIL_LOW_PART: [("src", "expr")],
		MediumLevelILOperation.MLIL_JUMP: [("dest", "expr")],
		MediumLevelILOperation.MLIL_JUMP_TO: [("dest", "expr"), ("targets", "target_map")],
		MediumLevelILOperation.MLIL_RET_HINT: [("dest", "expr")],
		MediumLevelILOperation.MLIL_CALL: [("output", "var_list"), ("dest", "expr"), ("params", "expr_list")],
		MediumLevelILOperation.MLIL_CALL_UNTYPED: [("output", "expr"), ("dest", "expr"), ("params", "expr"), ("stack", "expr")],
		MediumLevelILOperation.MLIL_CALL_OUTPUT: [("dest", "var_list")],
		MediumLevelILOperation.MLIL_CALL_PARAM: [("src", "var_list")],
		MediumLevelILOperation.MLIL_RET: [("src", "expr_list")],
		MediumLevelILOperation.MLIL_NORET: [],
		MediumLevelILOperation.MLIL_IF: [("condition", "expr"), ("true", "int"), ("false", "int")],
		MediumLevelILOperation.MLIL_GOTO: [("dest", "int")],
		MediumLevelILOperation.MLIL_CMP_E: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_CMP_NE: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_CMP_SLT: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_CMP_ULT: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_CMP_SLE: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_CMP_ULE: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_CMP_SGE: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_CMP_UGE: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_CMP_SGT: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_CMP_UGT: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_TEST_BIT: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_BOOL_TO_INT: [("src", "expr")],
		MediumLevelILOperation.MLIL_ADD_OVERFLOW: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_SYSCALL: [("output", "var_list"), ("params", "expr_list")],
		MediumLevelILOperation.MLIL_SYSCALL_UNTYPED: [("output", "expr"), ("params", "expr"), ("stack", "expr")],
		MediumLevelILOperation.MLIL_TAILCALL: [("output", "var_list"), ("dest", "expr"), ("params", "expr_list")],
		MediumLevelILOperation.MLIL_TAILCALL_UNTYPED: [("output", "expr"), ("dest", "expr"), ("params", "expr"), ("stack", "expr")],
		MediumLevelILOperation.MLIL_BP: [],
		MediumLevelILOperation.MLIL_TRAP: [("vector", "int")],
		MediumLevelILOperation.MLIL_INTRINSIC: [("output", "var_list"), ("intrinsic", "intrinsic"), ("params", "expr_list")],
		MediumLevelILOperation.MLIL_INTRINSIC_SSA: [("output", "var_ssa_list"), ("intrinsic", "intrinsic"), ("params", "expr_list")],
		MediumLevelILOperation.MLIL_FREE_VAR_SLOT: [("dest", "var")],
		MediumLevelILOperation.MLIL_FREE_VAR_SLOT_SSA: [("prev", "var_ssa_dest_and_src")],
		MediumLevelILOperation.MLIL_UNDEF: [],
		MediumLevelILOperation.MLIL_UNIMPL: [],
		MediumLevelILOperation.MLIL_UNIMPL_MEM: [("src", "expr")],
		MediumLevelILOperation.MLIL_FADD: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_FSUB: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_FMUL: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_FDIV: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_FSQRT: [("src", "expr")],
		MediumLevelILOperation.MLIL_FNEG: [("src", "expr")],
		MediumLevelILOperation.MLIL_FABS: [("src", "expr")],
		MediumLevelILOperation.MLIL_FLOAT_TO_INT: [("src", "expr")],
		MediumLevelILOperation.MLIL_INT_TO_FLOAT: [("src", "expr")],
		MediumLevelILOperation.MLIL_FLOAT_CONV: [("src", "expr")],
		MediumLevelILOperation.MLIL_ROUND_TO_INT: [("src", "expr")],
		MediumLevelILOperation.MLIL_FLOOR: [("src", "expr")],
		MediumLevelILOperation.MLIL_CEIL: [("src", "expr")],
		MediumLevelILOperation.MLIL_FTRUNC: [("src", "expr")],
		MediumLevelILOperation.MLIL_FCMP_E: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_FCMP_NE: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_FCMP_LT: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_FCMP_LE: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_FCMP_GE: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_FCMP_GT: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_FCMP_O: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_FCMP_UO: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_SET_VAR_SSA: [("dest", "var_ssa"), ("src", "expr")],
		MediumLevelILOperation.MLIL_SET_VAR_SSA_FIELD: [("prev", "var_ssa_dest_and_src"), ("offset", "int"), ("src", "expr")],
		MediumLevelILOperation.MLIL_SET_VAR_SPLIT_SSA: [("high", "var_ssa"), ("low", "var_ssa"), ("src", "expr")],
		MediumLevelILOperation.MLIL_SET_VAR_ALIASED: [("prev", "var_ssa_dest_and_src"), ("src", "expr")],
		MediumLevelILOperation.MLIL_SET_VAR_ALIASED_FIELD: [("prev", "var_ssa_dest_and_src"), ("offset", "int"), ("src", "expr")],
		MediumLevelILOperation.MLIL_VAR_SSA: [("src", "var_ssa")],
		MediumLevelILOperation.MLIL_VAR_SSA_FIELD: [("src", "var_ssa"), ("offset", "int")],
		MediumLevelILOperation.MLIL_VAR_ALIASED: [("src", "var_ssa")],
		MediumLevelILOperation.MLIL_VAR_ALIASED_FIELD: [("src", "var_ssa"), ("offset", "int")],
		MediumLevelILOperation.MLIL_VAR_SPLIT_SSA: [("high", "var_ssa"), ("low", "var_ssa")],
		MediumLevelILOperation.MLIL_CALL_SSA: [("output", "expr"), ("dest", "expr"), ("params", "expr_list"), ("src_memory", "int")],
		MediumLevelILOperation.MLIL_CALL_UNTYPED_SSA: [("output", "expr"), ("dest", "expr"), ("params", "expr"), ("stack", "expr")],
		MediumLevelILOperation.MLIL_SYSCALL_SSA: [("output", "expr"), ("params", "expr_list"), ("src_memory", "int")],
		MediumLevelILOperation.MLIL_SYSCALL_UNTYPED_SSA: [("output", "expr"), ("params", "expr"), ("stack", "expr")],
		MediumLevelILOperation.MLIL_TAILCALL_SSA: [("output", "expr"), ("dest", "expr"), ("params", "expr_list"), ("src_memory", "int")],
		MediumLevelILOperation.MLIL_TAILCALL_UNTYPED_SSA: [("output", "expr"), ("dest", "expr"), ("params", "expr"), ("stack", "expr")],
		MediumLevelILOperation.MLIL_CALL_OUTPUT_SSA: [("dest_memory", "int"), ("dest", "var_ssa_list")],
		MediumLevelILOperation.MLIL_CALL_PARAM_SSA: [("src_memory", "int"), ("src", "var_ssa_list")],
		MediumLevelILOperation.MLIL_LOAD_SSA: [("src", "expr"), ("src_memory", "int")],
		MediumLevelILOperation.MLIL_LOAD_STRUCT_SSA: [("src", "expr"), ("offset", "int"), ("src_memory", "int")],
		MediumLevelILOperation.MLIL_STORE_SSA: [("dest", "expr"), ("dest_memory", "int"), ("src_memory", "int"), ("src", "expr")],
		MediumLevelILOperation.MLIL_STORE_STRUCT_SSA: [("dest", "expr"), ("offset", "int"), ("dest_memory", "int"), ("src_memory", "int"), ("src", "expr")],
		MediumLevelILOperation.MLIL_VAR_PHI: [("dest", "var_ssa"), ("src", "var_ssa_list")],
		MediumLevelILOperation.MLIL_MEM_PHI: [("dest_memory", "int"), ("src_memory", "int_list")]
	}

	@classmethod
	def create(cls, func:'MediumLevelILFunction', expr_index:ExpressionIndex, instr_index:Optional[InstructionIndex]=None) -> 'MediumLevelILInstruction':
		assert func.arch is not None, "Attempted to create IL instruction with function missing an Architecture"
		inst = core.BNGetMediumLevelILByIndex(func.handle, expr_index)
		assert inst is not None, "core.BNGetMediumLevelILByIndex returned None"
		if instr_index is None:
			instr_index = core.BNGetMediumLevelILInstructionForExpr(func.handle, expr_index)
			assert instr_index is not None, "core.BNGetMediumLevelILInstructionForExpr returned None"
		instr = CoreMediumLevelILInstruction.from_BNMediumLevelILInstruction(inst)
		return ILInstruction[instr.operation](func, expr_index, instr, instr_index)  # type: ignore

	def __str__(self):
		tokens = self.tokens
		if tokens is None:
			return "invalid"
		result = ""
		for token in tokens:
			result += token.text
		return result

	def __repr__(self):
		return "<il: %s>" % str(self)

	def __eq__(self, other:'MediumLevelILInstruction'):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self.function == other.function and self.expr_index == other.expr_index

	def __lt__(self, other:'MediumLevelILInstruction'):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self.function == other.function and self.expr_index < other.expr_index

	def __le__(self, other:'MediumLevelILInstruction'):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self.function == other.function and self.expr_index <= other.expr_index

	def __gt__(self, other:'MediumLevelILInstruction'):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self.function == other.function and self.expr_index > other.expr_index

	def __ge__(self, other:'MediumLevelILInstruction'):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self.function == other.function and self.expr_index >= other.expr_index

	def __hash__(self):
		return hash((self.function, self.expr_index))

	@property
	def tokens(self) -> OptionalTokens:
		"""MLIL tokens (read-only)"""
		count = ctypes.c_ulonglong()
		tokens = ctypes.POINTER(core.BNInstructionTextToken)()
		if self.function.arch is None:
			raise Exception("Attempting to get tokens for MLIL Function with no Architecture set")
		if ((self.instr_index is not None) and (self.function.source_function is not None) and
			(self.expr_index == core.BNGetMediumLevelILIndexForInstruction(self.function.handle, self.instr_index))):
			if not core.BNGetMediumLevelILInstructionText(self.function.handle, self.function.source_function.handle,
				self.function.arch.handle, self.instr_index, tokens, count, None):
				return None
		else:
			if not core.BNGetMediumLevelILExprText(self.function.handle, self.function.arch.handle,
				self.expr_index, tokens, count, None):
				return None
		result = function.InstructionTextToken._from_core_struct(tokens, count.value)
		core.BNFreeInstructionText(tokens, count.value)
		return result

	@property
	def il_basic_block(self) -> 'MediumLevelILBasicBlock':
		"""IL basic block object containing this expression (read-only) (only available on finalized functions)"""
		core_block = core.BNGetMediumLevelILBasicBlockForInstruction(self.function.handle, self.instr_index)
		assert core_block is not None
		assert self.function.source_function is not None
		return MediumLevelILBasicBlock(core_block, self.function, self.function.source_function.view)

	@property
	def ssa_form(self) -> 'MediumLevelILInstruction':
		"""SSA form of expression (read-only)"""
		ssa_func = self.function.ssa_form
		assert ssa_func is not None
		return MediumLevelILInstruction.create(ssa_func,
			core.BNGetMediumLevelILSSAExprIndex(self.function.handle, self.expr_index))

	@property
	def non_ssa_form(self) -> 'MediumLevelILInstruction':
		"""Non-SSA form of expression (read-only)"""
		non_ssa_func = self.function.non_ssa_form
		assert non_ssa_func is not None
		return MediumLevelILInstruction.create(non_ssa_func,
			core.BNGetMediumLevelILNonSSAExprIndex(self.function.handle, self.expr_index))

	@property
	def value(self) -> variable.RegisterValue:
		"""Value of expression if constant or a known value (read-only)"""
		value = core.BNGetMediumLevelILExprValue(self.function.handle, self.expr_index)
		result = variable.RegisterValue.from_BNRegisterValue(value, self.function.arch)
		return result

	@property
	def possible_values(self) -> variable.PossibleValueSet:
		"""Possible values of expression using path-sensitive static data flow analysis (read-only)"""
		value = core.BNGetMediumLevelILPossibleExprValues(self.function.handle, self.expr_index, None, 0)
		result = variable.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	@property
	def branch_dependence(self) -> Mapping[int, ILBranchDependence]:
		"""Set of branching instructions that must take the true or false path to reach this instruction"""
		count = ctypes.c_ulonglong()
		deps = core.BNGetAllMediumLevelILBranchDependence(self.function.handle, self.instr_index, count)
		assert deps is not None, "core.BNGetAllMediumLevelILBranchDependence returned None"
		result = {}
		for i in range(0, count.value):
			result[deps[i].branch] = ILBranchDependence(deps[i].dependence)
		core.BNFreeILBranchDependenceList(deps)
		return result

	@property
	def low_level_il(self) -> Optional['lowlevelil.LowLevelILInstruction']:
		"""Low level IL form of this expression"""
		expr = self.function.get_low_level_il_expr_index(self.expr_index)
		if expr is None or self.function.low_level_il is None:
			return None
		return lowlevelil.LowLevelILInstruction.create(self.function.low_level_il.ssa_form, expr, None)

	@property
	def llil(self) -> Optional['lowlevelil.LowLevelILInstruction']:
		"""Alias for low_level_il"""
		return self.low_level_il

	@property
	def llils(self) -> List['lowlevelil.LowLevelILInstruction']:
		exprs = self.function.get_low_level_il_expr_indexes(self.expr_index)
		if self.function.low_level_il is None:
			return []
		result = []
		for expr in exprs:
			result.append(lowlevelil.LowLevelILInstruction.create(self.function.low_level_il.ssa_form, expr, None))
		return result

	@property
	def high_level_il(self) -> Optional[highlevelil.HighLevelILInstruction]:
		"""High level IL form of this expression"""
		expr = self.function.get_high_level_il_expr_index(self.expr_index)
		if expr is None or self.function.high_level_il is None:
			return None
		return highlevelil.HighLevelILInstruction.create(self.function.high_level_il, expr)

	@property
	def hlil(self) -> Optional[highlevelil.HighLevelILInstruction]:
		"""Alias for high_level_il"""
		return self.high_level_il

	@property
	def hlils(self) -> List[highlevelil.HighLevelILInstruction]:
		exprs = self.function.get_high_level_il_expr_indexes(self.expr_index)
		result = []
		if self.function.high_level_il is None:
			return result
		for expr in exprs:
			result.append(highlevelil.HighLevelILInstruction.create(self.function.high_level_il, expr))
		return result

	@property
	def ssa_memory_version(self) -> int:
		"""Version of active memory contents in SSA form for this instruction"""
		return core.BNGetMediumLevelILSSAMemoryVersionAtILInstruction(self.function.handle, self.instr_index)

	@property
	def prefix_operands(self) -> List[MediumLevelILOperandType]:
		"""All operands in the expression tree in prefix order"""
		result:List[MediumLevelILOperandType] = [MediumLevelILOperationAndSize(self.operation, self.size)]
		for operand in self.operands:
			if isinstance(operand, MediumLevelILInstruction):
				result.extend(operand.prefix_operands)
			else:
				result.append(operand)
		return result

	@property
	def postfix_operands(self) -> List[MediumLevelILOperandType]:
		"""All operands in the expression tree in postfix order"""
		result:List[MediumLevelILOperandType] = []
		for operand in self.operands:
			if isinstance(operand, MediumLevelILInstruction):
				result.extend(operand.postfix_operands)
			else:
				result.append(operand)
		result.append(MediumLevelILOperationAndSize(self.operation, self.size))
		return result

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		"""Operands for the instruction"""
		return []

	@property
	def vars_written(self) -> List[Union[variable.Variable, SSAVariable]]:
		"""List of variables written by instruction"""
		return []

	@property
	def vars_read(self) -> List[Union[variable.Variable, SSAVariable]]:
		"""List of variables read by instruction"""
		result = []
		for operand in self.operands:
			if (isinstance(operand, variable.Variable)) or (isinstance(operand, SSAVariable)):
				result.append(operand)
			elif isinstance(operand, MediumLevelILInstruction):
				result += operand.vars_read
		return result

	@property
	def expr_type(self) -> Optional['types.Type']:
		"""Type of expression"""
		result = core.BNGetMediumLevelILExprType(self.function.handle, self.expr_index)
		if result.type:
			platform = None
			if self.function.source_function:
				platform = self.function.source_function.platform
			return types.Type.create(core.BNNewTypeReference(result.type), platform = platform, confidence = result.confidence)
		return None

	def get_possible_values(self, options:List[DataFlowQueryOption]=[]) -> variable.PossibleValueSet:
		option_array = (ctypes.c_int * len(options))()
		idx = 0
		for option in options:
			option_array[idx] = option
			idx += 1
		value = core.BNGetMediumLevelILPossibleExprValues(self.function.handle, self.expr_index, option_array, len(options))
		result = variable.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_ssa_var_possible_values(self, ssa_var:SSAVariable, options:List[DataFlowQueryOption]=[]):
		var_data = ssa_var.var.to_BNVariable()
		option_array = (ctypes.c_int * len(options))()
		idx = 0
		for option in options:
			option_array[idx] = option
			idx += 1
		value = core.BNGetMediumLevelILPossibleSSAVarValues(self.function.handle, var_data, ssa_var.version,
			self.instr_index, option_array, len(options))
		result = variable.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_ssa_var_version(self, var:variable.Variable) -> int:
		var_data = var.to_BNVariable()
		return core.BNGetMediumLevelILSSAVarVersionAtILInstruction(self.function.handle, var_data, self.instr_index)

	def get_var_for_reg(self, reg:'architecture.RegisterType') -> variable.Variable:
		reg = self.function.arch.get_reg_index(reg)
		result = core.BNGetMediumLevelILVariableForRegisterAtInstruction(self.function.handle, reg, self.instr_index)
		return variable.Variable.from_BNVariable(self.function.source_function, result)

	def get_var_for_flag(self, flag:'architecture.FlagType') -> variable.Variable:
		flag = self.function.arch.get_flag_index(flag)
		result = core.BNGetMediumLevelILVariableForFlagAtInstruction(self.function.handle, flag, self.instr_index)
		return variable.Variable.from_BNVariable(self.function.source_function, result)

	def get_var_for_stack_location(self, offset:int) -> variable.Variable:
		result = core.BNGetMediumLevelILVariableForStackLocationAtInstruction(self.function.handle, offset, self.instr_index)
		return variable.Variable.from_BNVariable(self.function.source_function, result)

	def get_reg_value(self, reg:'architecture.RegisterType') -> 'variable.RegisterValue':
		reg = self.function.arch.get_reg_index(reg)
		value = core.BNGetMediumLevelILRegisterValueAtInstruction(self.function.handle, reg, self.instr_index)
		result = variable.RegisterValue.from_BNRegisterValue(value, self.function.arch)
		return result

	def get_reg_value_after(self, reg:'architecture.RegisterType') -> 'variable.RegisterValue':
		reg = self.function.arch.get_reg_index(reg)
		value = core.BNGetMediumLevelILRegisterValueAfterInstruction(self.function.handle, reg, self.instr_index)
		result = variable.RegisterValue.from_BNRegisterValue(value, self.function.arch)
		return result

	def get_possible_reg_values(self, reg:'architecture.RegisterType',
		options:List[DataFlowQueryOption]=[]) -> 'variable.PossibleValueSet':
		reg = self.function.arch.get_reg_index(reg)
		option_array = (ctypes.c_int * len(options))()
		idx = 0
		for option in options:
			option_array[idx] = option
			idx += 1
		value = core.BNGetMediumLevelILPossibleRegisterValuesAtInstruction(self.function.handle, reg, self.instr_index,
			option_array, len(options))
		result = variable.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_possible_reg_values_after(self, reg:'architecture.RegisterType',
		options:List[DataFlowQueryOption]=[]) -> 'variable.PossibleValueSet':
		reg = self.function.arch.get_reg_index(reg)
		option_array = (ctypes.c_int * len(options))()
		idx = 0
		for option in options:
			option_array[idx] = option
			idx += 1
		value = core.BNGetMediumLevelILPossibleRegisterValuesAfterInstruction(self.function.handle, reg, self.instr_index,
			option_array, len(options))
		result = variable.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_flag_value(self, flag:'architecture.FlagType') -> 'variable.RegisterValue':
		flag = self.function.arch.get_flag_index(flag)
		value = core.BNGetMediumLevelILFlagValueAtInstruction(self.function.handle, flag, self.instr_index)
		result = variable.RegisterValue.from_BNRegisterValue(value, self.function.arch)
		return result

	def get_flag_value_after(self, flag:'architecture.FlagType') -> 'variable.RegisterValue':
		flag = self.function.arch.get_flag_index(flag)
		value = core.BNGetMediumLevelILFlagValueAfterInstruction(self.function.handle, flag, self.instr_index)
		result = variable.RegisterValue.from_BNRegisterValue(value, self.function.arch)
		return result

	def get_possible_flag_values(self, flag:'architecture.FlagType',
		options:List[DataFlowQueryOption]=[]) -> 'variable.PossibleValueSet':
		flag = self.function.arch.get_flag_index(flag)
		option_array = (ctypes.c_int * len(options))()
		idx = 0
		for option in options:
			option_array[idx] = option
			idx += 1
		value = core.BNGetMediumLevelILPossibleFlagValuesAtInstruction(self.function.handle, flag, self.instr_index,
			option_array, len(options))
		result = variable.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_possible_flag_values_after(self, flag:'architecture.FlagType',
		options:List[DataFlowQueryOption]=[]) -> 'variable.PossibleValueSet':
		flag = self.function.arch.get_flag_index(flag)
		option_array = (ctypes.c_int * len(options))()
		idx = 0
		for option in options:
			option_array[idx] = option
			idx += 1
		value = core.BNGetMediumLevelILPossibleFlagValuesAfterInstruction(self.function.handle, flag, self.instr_index,
			option_array, len(options))
		result = variable.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_stack_contents(self, offset:int, size:int) -> 'variable.RegisterValue':
		value = core.BNGetMediumLevelILStackContentsAtInstruction(self.function.handle, offset, size, self.instr_index)
		result = variable.RegisterValue.from_BNRegisterValue(value, self.function.arch)
		return result

	def get_stack_contents_after(self, offset:int, size:int) -> 'variable.RegisterValue':
		value = core.BNGetMediumLevelILStackContentsAfterInstruction(self.function.handle, offset, size, self.instr_index)
		result = variable.RegisterValue.from_BNRegisterValue(value, self.function.arch)
		return result

	def get_possible_stack_contents(self, offset:int, size:int,
		options:List[DataFlowQueryOption]=[]) -> 'variable.PossibleValueSet':
		option_array = (ctypes.c_int * len(options))()
		idx = 0
		for option in options:
			option_array[idx] = option
			idx += 1
		value = core.BNGetMediumLevelILPossibleStackContentsAtInstruction(self.function.handle, offset, size, self.instr_index,
			option_array, len(options))
		result = variable.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_possible_stack_contents_after(self, offset:int, size:int,
		options:List[DataFlowQueryOption]=[]) -> 'variable.PossibleValueSet':
		option_array = (ctypes.c_int * len(options))()
		idx = 0
		for option in options:
			option_array[idx] = option
			idx += 1
		value = core.BNGetMediumLevelILPossibleStackContentsAfterInstruction(self.function.handle, offset, size, self.instr_index,
			option_array, len(options))
		result = variable.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_branch_dependence(self, branch_instr:int) -> ILBranchDependence:
		return ILBranchDependence(core.BNGetMediumLevelILBranchDependence(self.function.handle, self.instr_index, branch_instr))

	@property
	def operation(self) -> MediumLevelILOperation:
		return self.instr.operation

	@property
	def size(self) -> int:
		return self.instr.size

	@property
	def address(self) -> int:
		return self.instr.address

	@property
	def source_operand(self) -> ExpressionIndex:
		return ExpressionIndex(self.instr.source_operand)

	@property
	def core_operands(self) -> OperandsType:
		return self.instr.operands

	def get_int(self, operand_index:int) -> int:
		value = self.instr.operands[operand_index]
		return (value & ((1 << 63) - 1)) - (value & (1 << 63))

	def get_float(self, operand_index:int) -> float:
		value = self.instr.operands[operand_index]
		if self.instr.size == 4:
			return struct.unpack("f", struct.pack("I", value & 0xffffffff))[0]
		elif self.instr.size == 8:
			return struct.unpack("d", struct.pack("Q", value))[0]
		else:
			return float(value)

	def get_expr(self, operand_index:int) -> 'MediumLevelILInstruction':
		return MediumLevelILInstruction.create(self.function,
			ExpressionIndex(self.instr.operands[operand_index]))

	def get_intrinsic(self, operand_index:int) -> 'lowlevelil.ILIntrinsic':
		assert self.function.arch is not None, "Attempting to create ILIntrinsic from function with no Architecture"
		return lowlevelil.ILIntrinsic(self.function.arch,
			architecture.IntrinsicIndex(self.instr.operands[operand_index]))

	def get_var(self, operand_index:int) -> variable.Variable:
		value = self.instr.operands[operand_index]
		return variable.Variable.from_identifier(self.function.source_function, self.instr.operands[operand_index])

	def get_var_ssa(self, operand_index1:int, operand_index2:int) -> SSAVariable:
		var = variable.Variable.from_identifier(self.function.source_function, self.instr.operands[operand_index1])
		version = self.instr.operands[operand_index2]
		return SSAVariable(var, version)

	def get_var_ssa_dest_and_src(self, operand_index1:int, operand_index2:int) -> SSAVariable:
		var = variable.Variable.from_identifier(self.function.source_function, self.instr.operands[operand_index1])
		dest_version = self.instr.operands[operand_index2]
		return SSAVariable(var, dest_version)

	def get_int_list(self, operand_index:int) -> List[int]:
		count = ctypes.c_ulonglong()
		operand_list = core.BNMediumLevelILGetOperandList(self.function.handle, self.expr_index, operand_index, count)
		assert operand_list is not None, "core.BNMediumLevelILGetOperandList returned None"
		value:List[int] = []
		try:
			for j in range(count.value):
				value.append(operand_list[j])
			return value
		finally:
			core.BNMediumLevelILFreeOperandList(operand_list)

	def get_var_list(self, operand_index1:int, operand_index2:int) -> List[variable.Variable]:
		count = ctypes.c_ulonglong()
		operand_list = core.BNMediumLevelILGetOperandList(self.function.handle, self.expr_index, operand_index1, count)
		assert operand_list is not None, "core.BNMediumLevelILGetOperandList returned None"
		value:List[variable.Variable] = []
		try:
			for j in range(count.value):
				value.append(variable.Variable.from_identifier(self.function.source_function, operand_list[j]))
			return value
		finally:
			core.BNMediumLevelILFreeOperandList(operand_list)

	def get_var_ssa_list(self, operand_index1:int, _:int) -> List[SSAVariable]:
		count = ctypes.c_ulonglong()
		operand_list = core.BNMediumLevelILGetOperandList(self.function.handle, self.expr_index, operand_index1, count)
		assert operand_list is not None, "core.BNMediumLevelILGetOperandList returned None"
		value = []
		try:
			for j in range(count.value // 2):
				var_id = operand_list[j * 2]
				var_version = operand_list[(j * 2) + 1]
				value.append(SSAVariable(variable.Variable.from_identifier(self.function.source_function,
					var_id), var_version))
			return value
		finally:
			core.BNMediumLevelILFreeOperandList(operand_list)

	def get_expr_list(self, operand_index1:int, _:int) -> List['MediumLevelILInstruction']:
		count = ctypes.c_ulonglong()
		operand_list = core.BNMediumLevelILGetOperandList(self.function.handle, self.expr_index, operand_index1, count)
		assert operand_list is not None, "core.BNMediumLevelILGetOperandList returned None"
		value:List['MediumLevelILInstruction'] = []
		try:
			for j in range(count.value):
				value.append(MediumLevelILInstruction.create(self.function, operand_list[j], None))
			return value
		finally:
			core.BNMediumLevelILFreeOperandList(operand_list)

	def get_target_map(self, operand_index1:int, _:int) -> Mapping[int, int]:
		count = ctypes.c_ulonglong()
		operand_list = core.BNMediumLevelILGetOperandList(self.function.handle, self.expr_index, operand_index1, count)
		assert operand_list is not None, "core.BNMediumLevelILGetOperandList returned None"
		value:Mapping[int, int] = {}
		try:
			for j in range(count.value // 2):
				key = operand_list[j * 2]
				target = operand_list[(j * 2) + 1]
				value[key] = target
			return value
		finally:
			core.BNMediumLevelILFreeOperandList(operand_list)


@dataclass(frozen=True, repr=False)
class MediumLevelILConstBase(MediumLevelILInstruction, Constant):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILCallBase(MediumLevelILInstruction, Call):
	@property
	def output(self) -> List[Union[SSAVariable, variable.Variable]]:
		return NotImplemented

	@property
	def vars_written(self) -> List[Union[SSAVariable, variable.Variable]]:
		return self.output

	@property
	def params(self) -> List[Union[SSAVariable, variable.Variable]]:
		return NotImplemented

	@property
	def vars_read(self) -> List[Union[SSAVariable, variable.Variable]]:
		result = []
		for param in self.params:
			if isinstance(param, MediumLevelILInstruction):
				result.extend(param.vars_read)
			elif isinstance(param, (variable.Variable, SSAVariable)):
				result.append(param)
			else:
				assert False, "Call.params returned object other than Variable, SSAVariable or MediumLevelILInstruction"
		return result


@dataclass(frozen=True, repr=False)
class MediumLevelILUnaryBase(MediumLevelILInstruction, UnaryOperation):

	@property
	def src(self) -> MediumLevelILInstruction:
		return self.get_expr(0)

	@property
	def operands(self) -> List[MediumLevelILInstruction]:
		return [self.src]


@dataclass(frozen=True, repr=False)
class MediumLevelILBinaryBase(MediumLevelILInstruction, BinaryOperation):

	@property
	def left(self) -> MediumLevelILInstruction:
		return self.get_expr(0)

	@property
	def right(self) -> MediumLevelILInstruction:
		return self.get_expr(1)

	@property
	def operands(self) -> List[MediumLevelILInstruction]:
		return [self.left, self.right]


@dataclass(frozen=True, repr=False)
class MediumLevelILComparisonBase(MediumLevelILBinaryBase):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILCarryBase(MediumLevelILInstruction, Carry):

	@property
	def left(self) -> MediumLevelILInstruction:
		return self.get_expr(0)

	@property
	def right(self) -> MediumLevelILInstruction:
		return self.get_expr(1)

	@property
	def carry(self) -> MediumLevelILInstruction:
		return self.get_expr(2)

	@property
	def operands(self) -> List[MediumLevelILInstruction]:
		return [self.left, self.right, self.carry]


@dataclass(frozen=True, repr=False)
class MediumLevelILNop(MediumLevelILInstruction):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILNoret(MediumLevelILInstruction, Terminal):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILBp(MediumLevelILInstruction, Terminal):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILUndef(MediumLevelILInstruction):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILUnimpl(MediumLevelILInstruction):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILLoad(MediumLevelILInstruction, Load):

	@property
	def src(self) -> MediumLevelILInstruction:
		return self.get_expr(0)

	@property
	def operands(self) -> List[MediumLevelILInstruction]:
		return [self.src]


@dataclass(frozen=True, repr=False)
class MediumLevelILVar(MediumLevelILInstruction):

	@property
	def src(self) -> variable.Variable:
		return self.get_var(0)

	@property
	def operands(self) -> List[variable.Variable]:
		return [self.src]


@dataclass(frozen=True, repr=False)
class MediumLevelILAddress_of(MediumLevelILInstruction):

	@property
	def src(self) -> variable.Variable:
		return self.get_var(0)

	@property
	def operands(self) -> List[variable.Variable]:
		return [self.src]


@dataclass(frozen=True, repr=False)
class MediumLevelILConst(MediumLevelILConstBase):

	@property
	def constant(self) -> int:
		return self.get_int(0)

	@property
	def operands(self) -> List[int]:
		return [self.constant]


@dataclass(frozen=True, repr=False)
class MediumLevelILConst_ptr(MediumLevelILConstBase):

	@property
	def constant(self) -> int:
		return self.get_int(0)

	@property
	def operands(self) -> List[int]:
		return [self.constant]


@dataclass(frozen=True, repr=False)
class MediumLevelILFloat_const(MediumLevelILConstBase, FloatingPoint):

	@property
	def constant(self) -> float:
		return self.get_float(0)

	@property
	def operands(self) -> List[float]:
		return [self.constant]


@dataclass(frozen=True, repr=False)
class MediumLevelILImport(MediumLevelILConstBase):

	@property
	def constant(self) -> int:
		return self.get_int(0)

	@property
	def operands(self) -> List[int]:
		return [self.constant]


@dataclass(frozen=True, repr=False)
class MediumLevelILNeg(MediumLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILNot(MediumLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILSx(MediumLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILZx(MediumLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILLow_part(MediumLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILJump(MediumLevelILInstruction, Terminal):

	@property
	def dest(self) -> MediumLevelILInstruction:
		return self.get_expr(0)

	@property
	def operands(self) -> List[MediumLevelILInstruction]:
		return [self.dest]


@dataclass(frozen=True, repr=False)
class MediumLevelILRet_hint(MediumLevelILInstruction, ControlFlow):

	@property
	def dest(self) -> MediumLevelILInstruction:
		return self.get_expr(0)

	@property
	def operands(self) -> List[MediumLevelILInstruction]:
		return [self.dest]


@dataclass(frozen=True, repr=False)
class MediumLevelILCall_output(MediumLevelILInstruction):

	@property
	def dest(self) -> List[variable.Variable]:
		return self.get_var_list(0, 1)

	@property
	def vars_written(self) -> List[variable.Variable]:
		return self.dest

	@property
	def operands(self) -> List[variable.Variable]:
		return self.dest


@dataclass(frozen=True, repr=False)
class MediumLevelILCall_param(MediumLevelILInstruction):

	@property
	def src(self) -> List[variable.Variable]:
		return self.get_var_list(0, 1)

	@property
	def operands(self) -> List[variable.Variable]:
		return self.src


@dataclass(frozen=True, repr=False)
class MediumLevelILRet(MediumLevelILInstruction, Return):

	@property
	def src(self) -> List[MediumLevelILInstruction]:
		return self.get_expr_list(0, 1)

	@property
	def operands(self) -> List[MediumLevelILInstruction]:
		return [self.src]  # TODO: Expand output and params before regeneration


@dataclass(frozen=True, repr=False)
class MediumLevelILGoto(MediumLevelILInstruction, Terminal):

	@property
	def dest(self) -> int:
		return self.get_int(0)

	@property
	def operands(self) -> List[int]:
		return [self.dest]


@dataclass(frozen=True, repr=False)
class MediumLevelILBool_to_int(MediumLevelILInstruction):

	@property
	def src(self) -> MediumLevelILInstruction:
		return self.get_expr(0)

	@property
	def operands(self) -> List[MediumLevelILInstruction]:
		return [self.src]


@dataclass(frozen=True, repr=False)
class MediumLevelILFree_var_slot(MediumLevelILInstruction, RegisterStack):

	@property
	def dest(self) -> variable.Variable:
		return self.get_var(0)

	@property
	def operands(self) -> List[variable.Variable]:
		return [self.dest]


@dataclass(frozen=True, repr=False)
class MediumLevelILTrap(MediumLevelILInstruction, Terminal):

	@property
	def vector(self) -> int:
		return self.get_int(0)

	@property
	def operands(self) -> List[int]:
		return [self.vector]


@dataclass(frozen=True, repr=False)
class MediumLevelILFree_var_slot_ssa(MediumLevelILInstruction, SSA, RegisterStack):

	@property
	def dest(self) -> SSAVariable:
		return self.get_var_ssa_dest_and_src(0, 1)

	@property
	def prev(self) -> SSAVariable:
		return self.get_var_ssa_dest_and_src(0, 2)

	@property
	def operands(self) -> List[SSAVariable]:
		return [self.dest, self.prev]


@dataclass(frozen=True, repr=False)
class MediumLevelILUnimpl_mem(MediumLevelILInstruction, Memory):

	@property
	def src(self) -> MediumLevelILInstruction:
		return self.get_expr(0)

	@property
	def operands(self) -> List[MediumLevelILInstruction]:
		return [self.src]


@dataclass(frozen=True, repr=False)
class MediumLevelILFsqrt(MediumLevelILUnaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILFneg(MediumLevelILUnaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILFabs(MediumLevelILUnaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILFloat_to_int(MediumLevelILUnaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILInt_to_float(MediumLevelILUnaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILFloat_conv(MediumLevelILUnaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILRound_to_int(MediumLevelILUnaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILFloor(MediumLevelILUnaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILCeil(MediumLevelILUnaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILFtrunc(MediumLevelILUnaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILVar_ssa(MediumLevelILInstruction, SSA):

	@property
	def src(self) -> SSAVariable:
		return self.get_var_ssa(0, 1)

	@property
	def operands(self) -> List[SSAVariable]:
		return [self.src]


@dataclass(frozen=True, repr=False)
class MediumLevelILVar_aliased(MediumLevelILInstruction, SSA):

	@property
	def src(self) -> SSAVariable:
		return self.get_var_ssa(0, 1)

	@property
	def operands(self) -> List[SSAVariable]:
		return [self.src]


@dataclass(frozen=True, repr=False)
class MediumLevelILSet_var(MediumLevelILInstruction, SetVar):

	@property
	def dest(self) -> variable.Variable:
		return self.get_var(0)

	@property
	def src(self) -> MediumLevelILInstruction:
		return self.get_expr(1)

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [self.dest, self.src]

	@property
	def vars_written(self) -> List[variable.Variable]:
		return [self.dest]

	@property
	def vars_read(self) -> List[Union[variable.Variable, SSAVariable]]:
		return self.src.vars_read


@dataclass(frozen=True, repr=False)
class MediumLevelILLoad_struct(MediumLevelILInstruction, Load):

	@property
	def src(self) -> MediumLevelILInstruction:
		return self.get_expr(0)

	@property
	def offset(self) -> int:
		return self.get_int(1)

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [self.src, self.offset]


@dataclass(frozen=True, repr=False)
class MediumLevelILStore(MediumLevelILInstruction, Store):

	@property
	def dest(self) -> MediumLevelILInstruction:
		return self.get_expr(0)

	@property
	def src(self) -> MediumLevelILInstruction:
		return self.get_expr(1)

	@property
	def operands(self) -> List[MediumLevelILInstruction]:
		return [self.dest, self.src]


@dataclass(frozen=True, repr=False)
class MediumLevelILVar_field(MediumLevelILInstruction):

	@property
	def src(self) -> variable.Variable:
		return self.get_var(0)

	@property
	def offset(self) -> int:
		return self.get_int(1)

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [self.src, self.offset]


@dataclass(frozen=True, repr=False)
class MediumLevelILVar_split(MediumLevelILInstruction):

	@property
	def high(self) -> variable.Variable:
		return self.get_var(0)

	@property
	def low(self) -> variable.Variable:
		return self.get_var(1)

	@property
	def operands(self) -> List[variable.Variable]:
		return [self.high, self.low]


@dataclass(frozen=True, repr=False)
class MediumLevelILAddress_of_field(MediumLevelILInstruction):

	@property
	def src(self) -> variable.Variable:
		return self.get_var(0)

	@property
	def offset(self) -> int:
		return self.get_int(1)

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [self.src, self.offset]


@dataclass(frozen=True, repr=False)
class MediumLevelILExtern_ptr(MediumLevelILConstBase):

	@property
	def constant(self) -> int:
		return self.get_int(0)

	@property
	def offset(self) -> int:
		return self.get_int(1)

	@property
	def operands(self) -> List[int]:
		return [self.constant, self.offset]


@dataclass(frozen=True, repr=False)
class MediumLevelILAdd(MediumLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILSub(MediumLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILAnd(MediumLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILOr(MediumLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILXor(MediumLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILLsl(MediumLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILLsr(MediumLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILAsr(MediumLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILRol(MediumLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILRor(MediumLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILMul(MediumLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILMulu_dp(MediumLevelILBinaryBase, DoublePrecision):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILMuls_dp(MediumLevelILBinaryBase, DoublePrecision, Signed):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILDivu(MediumLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILDivu_dp(MediumLevelILBinaryBase, DoublePrecision):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILDivs(MediumLevelILBinaryBase, Arithmetic, Signed):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILDivs_dp(MediumLevelILBinaryBase, DoublePrecision, Signed):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILModu(MediumLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILModu_dp(MediumLevelILBinaryBase, DoublePrecision):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILMods(MediumLevelILBinaryBase, Arithmetic, Signed):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILMods_dp(MediumLevelILBinaryBase, DoublePrecision, Signed):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILCmp_e(MediumLevelILComparisonBase):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILCmp_ne(MediumLevelILComparisonBase):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILCmp_slt(MediumLevelILComparisonBase, Signed):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILCmp_ult(MediumLevelILComparisonBase):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILCmp_sle(MediumLevelILComparisonBase, Signed):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILCmp_ule(MediumLevelILComparisonBase):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILCmp_sge(MediumLevelILComparisonBase, Signed):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILCmp_uge(MediumLevelILComparisonBase):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILCmp_sgt(MediumLevelILComparisonBase, Signed):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILCmp_ugt(MediumLevelILComparisonBase):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILTest_bit(MediumLevelILComparisonBase):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILAdd_overflow(MediumLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILSyscall(MediumLevelILInstruction, Syscall):

	@property
	def output(self) -> List[variable.Variable]:
		return self.get_var_list(0, 1)

	@property
	def params(self) -> List[MediumLevelILInstruction]:
		return self.get_expr_list(2, 3)

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [self.output, self.params]  # TODO: Expand output and params before regeneration


@dataclass(frozen=True, repr=False)
class MediumLevelILVar_ssa_field(MediumLevelILInstruction, SSA):

	@property
	def src(self) -> SSAVariable:
		return self.get_var_ssa(0, 1)

	@property
	def offset(self) -> int:
		return self.get_int(2)

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [self.src, self.offset]


@dataclass(frozen=True, repr=False)
class MediumLevelILVar_aliased_field(MediumLevelILInstruction, SSA):

	@property
	def src(self) -> SSAVariable:
		return self.get_var_ssa(0, 1)

	@property
	def offset(self) -> int:
		return self.get_int(2)

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [self.src, self.offset]


@dataclass(frozen=True, repr=False)
class MediumLevelILVar_split_ssa(MediumLevelILInstruction, SSA):

	@property
	def high(self) -> SSAVariable:
		return self.get_var_ssa(0, 1)

	@property
	def low(self) -> SSAVariable:
		return self.get_var_ssa(2, 3)

	@property
	def operands(self) -> List[SSAVariable]:
		return [self.high, self.low]


@dataclass(frozen=True, repr=False)
class MediumLevelILCall_output_ssa(MediumLevelILInstruction, SSA):

	@property
	def dest_memory(self) -> int:
		return self.get_int(0)

	@property
	def dest(self) -> List[SSAVariable]:
		return self.get_var_ssa_list(1, 2)

	@property
	def vars_written(self) -> List[SSAVariable]:
		return self.dest

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [self.dest_memory, *self.dest]


@dataclass(frozen=True, repr=False)
class MediumLevelILCall_param_ssa(MediumLevelILInstruction, SSA):

	@property
	def src_memory(self) -> int:
		return self.get_int(0)

	@property
	def src(self) -> List[SSAVariable]:
		return self.get_var_ssa_list(1, 2)

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [self.src_memory, *self.src]


@dataclass(frozen=True, repr=False)
class MediumLevelILLoad_ssa(MediumLevelILInstruction, Load, SSA):

	@property
	def src(self) -> MediumLevelILInstruction:
		return self.get_expr(0)

	@property
	def src_memory(self) -> int:
		return self.get_int(1)

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [self.src, self.src_memory]


@dataclass(frozen=True, repr=False)
class MediumLevelILVar_phi(MediumLevelILInstruction, SetVar, Phi, SSA):

	@property
	def dest(self) -> SSAVariable:
		return self.get_var_ssa(0, 1)

	@property
	def src(self) -> List[SSAVariable]:
		return self.get_var_ssa_list(2, 3)

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [self.dest, *self.src]

	@property
	def vars_read(self) -> List[SSAVariable]:
		return self.src


@dataclass(frozen=True, repr=False)
class MediumLevelILMem_phi(MediumLevelILInstruction, Memory, Phi):

	@property
	def dest_memory(self) -> int:
		return self.get_int(0)

	@property
	def src_memory(self) -> List[int]:
		return self.get_int_list(1)

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [self.dest_memory, *self.src_memory]


@dataclass(frozen=True, repr=False)
class MediumLevelILSet_var_ssa(MediumLevelILInstruction, SetVar, SSA):

	@property
	def dest(self) -> SSAVariable:
		return self.get_var_ssa(0, 1)

	@property
	def src(self) -> MediumLevelILInstruction:
		return self.get_expr(2)

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [self.dest, self.src]

	@property
	def vars_read(self) -> List[Union[variable.Variable, SSAVariable]]:
		return self.src.vars_read

	@property
	def vars_written(self) -> List[SSAVariable]:
		return [self.dest]


@dataclass(frozen=True, repr=False)
class MediumLevelILFcmp_e(MediumLevelILComparisonBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILFcmp_ne(MediumLevelILComparisonBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILFcmp_lt(MediumLevelILComparisonBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILFcmp_le(MediumLevelILComparisonBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILFcmp_ge(MediumLevelILComparisonBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILFcmp_gt(MediumLevelILComparisonBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILFcmp_o(MediumLevelILComparisonBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILFcmp_uo(MediumLevelILComparisonBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILFadd(MediumLevelILBinaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILFsub(MediumLevelILBinaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILFmul(MediumLevelILBinaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILFdiv(MediumLevelILBinaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILJump_to(MediumLevelILInstruction, Terminal):

	@property
	def dest(self) -> MediumLevelILInstruction:
		return self.get_expr(0)

	@property
	def targets(self) -> Mapping[int, int]:
		return self.get_target_map(1, 2)

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [self.dest, self.targets]


@dataclass(frozen=True, repr=False)
class MediumLevelILSet_var_aliased(MediumLevelILInstruction, SetVar, SSA):

	@property
	def dest(self) -> SSAVariable:
		return self.get_var_ssa_dest_and_src(0, 1)

	@property
	def prev(self) -> SSAVariable:
		return self.get_var_ssa_dest_and_src(0, 2)

	@property
	def src(self) -> MediumLevelILInstruction:
		return self.get_expr(3)

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [self.dest, self.prev, self.src]

	@property
	def vars_read(self) -> List[Union[variable.Variable, SSAVariable]]:
		return self.src.vars_read

	@property
	def vars_written(self) -> List[SSAVariable]:
		return [self.dest]



@dataclass(frozen=True, repr=False)
class MediumLevelILSyscall_untyped(MediumLevelILCallBase, Syscall):

	@property
	def output(self) -> List[variable.Variable]:
		inst = self.get_expr(0)
		assert isinstance(inst, MediumLevelILCall_output), "MediumLevelILCall_untyped return bad type for 'output'"
		return inst.dest

	@property
	def params(self) -> List[variable.Variable]:
		inst = self.get_expr(1)
		assert isinstance(inst, MediumLevelILCall_param), "MediumLevelILCall_untyped return bad type for 'params'"
		return inst.src

	@property
	def stack(self) -> MediumLevelILInstruction:
		return self.get_expr(2)

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [*self.output, *self.params, self.stack]


@dataclass(frozen=True, repr=False)
class MediumLevelILIntrinsic(MediumLevelILInstruction):

	@property
	def output(self) -> List[variable.Variable]:
		return self.get_var_list(0, 1)

	@property
	def intrinsic(self) -> 'lowlevelil.ILIntrinsic':
		return self.get_intrinsic(2)

	@property
	def params(self) -> List[MediumLevelILInstruction]:
		return self.get_expr_list(3, 4)

	@property
	def vars_read(self) -> List[variable.Variable]:
		result:List[variable.Variable] = []
		for i in self.params:
			result.extend(i.vars_read)  # type: ignore
		return result

	@property
	def vars_written(self) -> List[variable.Variable]:
		return self.output

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [self.output, self.intrinsic, self.params]  # TODO: Expand output and params before regeneration


@dataclass(frozen=True, repr=False)
class MediumLevelILIntrinsic_ssa(MediumLevelILInstruction, SSA):

	@property
	def output(self) -> List[SSAVariable]:
		return self.get_var_ssa_list(0, 1)

	@property
	def intrinsic(self) -> 'lowlevelil.ILIntrinsic':
		return self.get_intrinsic(2)

	@property
	def params(self) -> List[MediumLevelILInstruction]:
		return self.get_expr_list(3, 4)

	@property
	def vars_read(self) -> List[SSAVariable]:
		result:List[SSAVariable] = []
		for i in self.params:
			result.extend(i.vars_read)  # type: ignore
		return result

	@property
	def vars_written(self) -> List[SSAVariable]:
		return self.output

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [self.output, self.intrinsic, self.params]  # TODO: Expand output and params before regeneration


@dataclass(frozen=True, repr=False)
class MediumLevelILSet_var_ssa_field(MediumLevelILInstruction, SetVar, SSA):

	@property
	def dest(self) -> SSAVariable:
		return self.get_var_ssa_dest_and_src(0, 1)

	@property
	def prev(self) -> SSAVariable:
		return self.get_var_ssa_dest_and_src(0, 2)

	@property
	def offset(self) -> int:
		return self.get_int(3)

	@property
	def src(self) -> MediumLevelILInstruction:
		return self.get_expr(4)

	@property
	def vars_read(self) -> List[SSAVariable]:
		return [self.prev, *self.src.vars_read]  # type: ignore we're guaranteed not to return non-SSAVariables here

	@property
	def vars_written(self) -> List[SSAVariable]:
		return [self.dest]

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [self.dest, self.prev, self.offset, self.src]


@dataclass(frozen=True, repr=False)
class MediumLevelILSet_var_split_ssa(MediumLevelILInstruction, SetVar, SSA):

	@property
	def high(self) -> SSAVariable:
		return self.get_var_ssa(0, 1)

	@property
	def low(self) -> SSAVariable:
		return self.get_var_ssa(2, 3)

	@property
	def src(self) -> MediumLevelILInstruction:
		return self.get_expr(4)

	@property
	def vars_read(self) -> List[Union[variable.Variable, SSAVariable]]:
		return self.src.vars_read

	@property
	def vars_written(self) -> List[SSAVariable]:
		return [self.high, self.low]

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [self.high, self.low, self.src]


@dataclass(frozen=True, repr=False)
class MediumLevelILSet_var_aliased_field(MediumLevelILInstruction, SetVar, SSA):

	@property
	def dest(self) -> SSAVariable:
		return self.get_var_ssa_dest_and_src(0, 1)

	@property
	def prev(self) -> SSAVariable:
		return self.get_var_ssa_dest_and_src(0, 2)

	@property
	def offset(self) -> int:
		return self.get_int(3)

	@property
	def src(self) -> MediumLevelILInstruction:
		return self.get_expr(4)

	@property
	def vars_read(self) -> List[SSAVariable]:
		return [self.prev, *self.src.vars_read]  # type: ignore we're guaranteed not to return non-SSAVariables here

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [self.dest, self.prev, self.offset, self.src]


@dataclass(frozen=True, repr=False)
class MediumLevelILSyscall_ssa(MediumLevelILCallBase, Syscall, SSA):

	@property
	def output(self) -> List[SSAVariable]:
		inst = self.get_expr(0)
		assert isinstance(inst, MediumLevelILCall_output_ssa), "MediumLevelILSyscall_ssa return bad type for output"
		return inst.dest

	@property
	def output_dest_memory(self) -> int:
		inst = self.get_expr(0)
		assert isinstance(inst, MediumLevelILCall_output_ssa), "MediumLevelILSyscall_ssa return bad type for output"
		return inst.dest_memory

	@property
	def params(self) -> List[MediumLevelILInstruction]:
		return self.get_expr_list(1, 2)

	@property
	def src_memory(self) -> int:
		return self.get_int(3)

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [*self.output, *self.params, self.src_memory]


@dataclass(frozen=True, repr=False)
class MediumLevelILSyscall_untyped_ssa(MediumLevelILCallBase, Syscall, SSA):

	@property
	def output(self) -> List[SSAVariable]:
		inst = self.get_expr(0)
		assert isinstance(inst, MediumLevelILCall_output_ssa), "MediumLevelILSyscall_untyped_ssa return bad type for 'output'"
		return inst.dest

	@property
	def output_dest_memory(self) -> int:
		inst = self.get_expr(0)
		assert isinstance(inst, MediumLevelILCall_output_ssa), "MediumLevelILSyscall_untyped_ssa return bad type for 'output_dest_memory'"
		return inst.dest_memory

	@property
	def params(self) -> List[SSAVariable]:
		inst = self.get_expr(1)
		assert isinstance(inst, MediumLevelILCall_param_ssa), "MediumLevelILSyscall_untyped_ssa return bad type for 'params'"
		return inst.src

	@property
	def params_src_memory(self) -> int:
		inst = self.get_expr(1)
		assert isinstance(inst, MediumLevelILCall_param_ssa), "MediumLevelILSyscall_untyped_ssa return bad type for 'params_src_memory'"
		return inst.src_memory

	@property
	def stack(self) -> MediumLevelILInstruction:
		return self.get_expr(2)

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [*self.output, *self.params, self.stack]


@dataclass(frozen=True, repr=False)
class MediumLevelILLoad_struct_ssa(MediumLevelILInstruction, Load, SSA):

	@property
	def src(self) -> MediumLevelILInstruction:
		return self.get_expr(0)

	@property
	def offset(self) -> int:
		return self.get_int(1)

	@property
	def src_memory(self) -> int:
		return self.get_int(2)

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [self.src, self.offset, self.src_memory]


@dataclass(frozen=True, repr=False)
class MediumLevelILSet_var_field(MediumLevelILInstruction, SetVar):

	@property
	def dest(self) -> variable.Variable:
		return self.get_var(0)

	@property
	def offset(self) -> int:
		return self.get_int(1)

	@property
	def src(self) -> MediumLevelILInstruction:
		return self.get_expr(2)

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [self.dest, self.offset, self.src]


@dataclass(frozen=True, repr=False)
class MediumLevelILSet_var_split(MediumLevelILInstruction, SetVar):

	@property
	def high(self) -> variable.Variable:
		return self.get_var(0)

	@property
	def low(self) -> variable.Variable:
		return self.get_var(1)

	@property
	def src(self) -> MediumLevelILInstruction:
		return self.get_expr(2)

	@property
	def vars_written(self) -> List[variable.Variable]:
		return [self.high, self.low]

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [self.high, self.low, self.src]


@dataclass(frozen=True, repr=False)
class MediumLevelILStore_struct(MediumLevelILInstruction, Store):

	@property
	def dest(self) -> MediumLevelILInstruction:
		return self.get_expr(0)

	@property
	def offset(self) -> int:
		return self.get_int(1)

	@property
	def src(self) -> MediumLevelILInstruction:
		return self.get_expr(2)

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [self.dest, self.offset, self.src]


@dataclass(frozen=True, repr=False)
class MediumLevelILAdc(MediumLevelILCarryBase):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILSbb(MediumLevelILCarryBase):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILRlc(MediumLevelILCarryBase):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILRrc(MediumLevelILCarryBase):
	pass


@dataclass(frozen=True, repr=False)
class MediumLevelILCall(MediumLevelILCallBase):

	@property
	def output(self) -> List[variable.Variable]:
		return self.get_var_list(0, 1)

	@property
	def dest(self) -> MediumLevelILInstruction:
		return self.get_expr(2)

	@property
	def params(self) -> List[MediumLevelILInstruction]:
		return self.get_expr_list(3, 4)

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [self.output, self.dest, self.params]  # TODO: Expand output and params before regeneration


@dataclass(frozen=True, repr=False)
class MediumLevelILIf(MediumLevelILInstruction, Terminal):

	@property
	def condition(self) -> MediumLevelILInstruction:
		return self.get_expr(0)

	@property
	def true(self) -> int:
		return self.get_int(1)

	@property
	def false(self) -> int:
		return self.get_int(2)

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [self.condition, self.true, self.false]


@dataclass(frozen=True, repr=False)
class MediumLevelILTailcall_untyped(MediumLevelILCallBase, Tailcall):

	@property
	def output(self) -> List[variable.Variable]:
		inst = self.get_expr(0)
		assert isinstance(inst, MediumLevelILCall_output), "MediumLevelILTailcall_untyped return bad type for 'output'"
		return inst.dest

	@property
	def dest(self) -> MediumLevelILInstruction:
		return self.get_expr(1)

	@property
	def params(self) -> List[variable.Variable]:
		inst = self.get_expr(2)
		assert isinstance(inst, MediumLevelILCall_param), "MediumLevelILTailcall_untyped return bad type for 'params'"
		return inst.src

	@property
	def stack(self) -> MediumLevelILInstruction:
		return self.get_expr(3)

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [*self.output, self.dest, *self.params, self.stack]


@dataclass(frozen=True, repr=False)
class MediumLevelILCall_ssa(MediumLevelILCallBase, SSA):

	@property
	def output(self) -> List[SSAVariable]:
		inst = self.get_expr(0)
		assert isinstance(inst, MediumLevelILCall_output_ssa), "MediumLevelILCall_ssa return bad type for output"
		return inst.dest

	@property
	def output_dest_memory(self) -> int:
		inst = self.get_expr(0)
		assert isinstance(inst, MediumLevelILCall_output_ssa), "MediumLevelILCall_ssa return bad type for output"
		return inst.dest_memory

	@property
	def dest(self) -> MediumLevelILInstruction:
		return self.get_expr(1)

	@property
	def params(self) -> List[MediumLevelILInstruction]:
		return self.get_expr_list(2, 3)

	@property
	def src_memory(self) -> int:
		return self.get_int(4)

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [*self.output, self.dest, *self.params, self.src_memory]


@dataclass(frozen=True, repr=False)
class MediumLevelILCall_untyped_ssa(MediumLevelILCallBase, SSA):

	@property
	def output(self) -> List[SSAVariable]:
		inst = self.get_expr(0)
		assert isinstance(inst, MediumLevelILCall_output_ssa), "MediumLevelILCall_untyped_ssa return bad type for output"
		return inst.dest

	@property
	def output_dest_memory(self) -> int:
		inst = self.get_expr(0)
		assert isinstance(inst, MediumLevelILCall_output_ssa), "MediumLevelILCall_untyped_ssa return bad type for output"
		return inst.dest_memory

	@property
	def dest(self) -> MediumLevelILInstruction:
		return self.get_expr(1)

	@property
	def params(self) -> List[SSAVariable]:
		inst = self.get_expr(2)
		assert isinstance(inst, MediumLevelILCall_param_ssa), "MediumLevelILCall_untyped_ssa return bad type for 'params'"
		return inst.src

	@property
	def params_src_memory(self):
		inst = self.get_expr(2)
		assert isinstance(inst, MediumLevelILCall_param_ssa), "MediumLevelILCall_untyped_ssa return bad type for 'params_src_memory'"
		return inst.src_memory

	@property
	def stack(self) -> MediumLevelILInstruction:
		return self.get_expr(3)

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [*self.output, self.dest, *self.params, self.stack]


@dataclass(frozen=True, repr=False)
class MediumLevelILTailcall(MediumLevelILCallBase, Tailcall):

	@property
	def output(self) -> List[variable.Variable]:
		return self.get_var_list(0, 1)

	@property
	def dest(self) -> MediumLevelILInstruction:
		return self.get_expr(2)

	@property
	def params(self) -> List[MediumLevelILInstruction]:
		return self.get_expr_list(3, 4)

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [self.output, self.dest, self.params]  # TODO: Expand output and params before regeneration


@dataclass(frozen=True, repr=False)
class MediumLevelILTailcall_ssa(MediumLevelILCallBase, Tailcall, SSA):

	@property
	def output(self) -> List[SSAVariable]:
		inst = self.get_expr(0)
		assert isinstance(inst, MediumLevelILCall_output_ssa), "MediumLevelILTailcall_ssa return bad type for output"
		return inst.dest

	@property
	def output_dest_memory(self) -> int:
		inst = self.get_expr(0)
		assert isinstance(inst, MediumLevelILCall_output_ssa), "MediumLevelILTailcall_ssa return bad type for output"
		return inst.dest_memory

	@property
	def dest(self) -> MediumLevelILInstruction:
		return self.get_expr(1)

	@property
	def params(self) -> List[MediumLevelILInstruction]:
		return self.get_expr_list(2, 3)

	@property
	def src_memory(self) -> int:
		return self.get_int(4)

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [*self.output, self.dest, *self.params, self.src_memory]


@dataclass(frozen=True, repr=False)
class MediumLevelILTailcall_untyped_ssa(MediumLevelILCallBase, Tailcall, SSA):

	@property
	def output(self) -> List[SSAVariable]:
		inst = self.get_expr(0)
		assert isinstance(inst, MediumLevelILCall_output_ssa), "MediumLevelILTailcall_untyped_ssa return bad type for 'output'"
		return inst.dest

	@property
	def output_dest_memory(self) -> int:
		inst = self.get_expr(0)
		assert isinstance(inst, MediumLevelILCall_output_ssa), "MediumLevelILTailcall_untyped_ssa return bad type for 'output'"
		return inst.dest_memory

	@property
	def dest(self) -> MediumLevelILInstruction:
		return self.get_expr(1)

	@property
	def params(self) -> MediumLevelILInstruction:
		return self.get_expr(2)

	@property
	def stack(self) -> MediumLevelILInstruction:
		return self.get_expr(3)

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [*self.output, self.dest, self.params, self.stack]


@dataclass(frozen=True, repr=False)
class MediumLevelILStore_ssa(MediumLevelILInstruction, Store, SSA):

	@property
	def dest(self) -> MediumLevelILInstruction:
		return self.get_expr(0)

	@property
	def dest_memory(self) -> int:
		return self.get_int(1)

	@property
	def src_memory(self) -> int:
		return self.get_int(2)

	@property
	def src(self) -> MediumLevelILInstruction:
		return self.get_expr(3)

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [self.dest, self.dest_memory, self.src_memory, self.src]


@dataclass(frozen=True, repr=False)
class MediumLevelILCall_untyped(MediumLevelILCallBase):

	@property
	def output(self) -> List[variable.Variable]:
		inst = self.get_expr(0)
		assert isinstance(inst, MediumLevelILCall_output), "MediumLevelILCall_untyped return bad type for 'output'"
		return inst.dest

	@property
	def dest(self) -> MediumLevelILInstruction:
		return self.get_expr(1)

	@property
	def params(self) -> List[variable.Variable]:
		inst = self.get_expr(2)
		assert isinstance(inst, MediumLevelILCall_param), "MediumLevelILCall_untyped return bad type for 'params'"
		return inst.src

	@property
	def stack(self) -> MediumLevelILInstruction:
		return self.get_expr(3)

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [*self.output, self.dest, *self.params, self.stack]


@dataclass(frozen=True, repr=False)
class MediumLevelILStore_struct_ssa(MediumLevelILInstruction, Store, SSA):

	@property
	def dest(self) -> MediumLevelILInstruction:
		return self.get_expr(0)

	@property
	def offset(self) -> int:
		return self.get_int(1)

	@property
	def dest_memory(self) -> int:
		return self.get_int(2)

	@property
	def src_memory(self) -> int:
		return self.get_int(3)

	@property
	def src(self) -> MediumLevelILInstruction:
		return self.get_expr(4)

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		return [self.dest, self.offset, self.dest_memory, self.src_memory, self.src]


ILInstruction = {
	MediumLevelILOperation.MLIL_NOP:MediumLevelILNop,                                      # [],
	MediumLevelILOperation.MLIL_NORET:MediumLevelILNoret,                                  # [],
	MediumLevelILOperation.MLIL_BP:MediumLevelILBp,                                        # [],
	MediumLevelILOperation.MLIL_UNDEF:MediumLevelILUndef,                                  # [],
	MediumLevelILOperation.MLIL_UNIMPL:MediumLevelILUnimpl,                                # [],
	MediumLevelILOperation.MLIL_LOAD:MediumLevelILLoad,                                    # [("src", "expr")],
	MediumLevelILOperation.MLIL_VAR:MediumLevelILVar,                                      # [("src", "var")],
	MediumLevelILOperation.MLIL_ADDRESS_OF:MediumLevelILAddress_of,                        # [("src", "var")],
	MediumLevelILOperation.MLIL_CONST:MediumLevelILConst,                                  # [("constant", "int")],
	MediumLevelILOperation.MLIL_CONST_PTR:MediumLevelILConst_ptr,                          # [("constant", "int")],
	MediumLevelILOperation.MLIL_FLOAT_CONST:MediumLevelILFloat_const,                      # [("constant", "float")],
	MediumLevelILOperation.MLIL_IMPORT:MediumLevelILImport,                                # [("constant", "int")],
	MediumLevelILOperation.MLIL_SET_VAR:MediumLevelILSet_var,                              # [("dest", "var"), ("src", "expr")],
	MediumLevelILOperation.MLIL_LOAD_STRUCT:MediumLevelILLoad_struct,                      # [("src", "expr"), ("offset", "int")],
	MediumLevelILOperation.MLIL_STORE:MediumLevelILStore,                                  # [("dest", "expr"), ("src", "expr")],
	MediumLevelILOperation.MLIL_VAR_FIELD:MediumLevelILVar_field,                          # [("src", "var"), ("offset", "int")],
	MediumLevelILOperation.MLIL_VAR_SPLIT:MediumLevelILVar_split,                          # [("high", "var"), ("low", "var")],
	MediumLevelILOperation.MLIL_ADDRESS_OF_FIELD:MediumLevelILAddress_of_field,            # [("src", "var"), ("offset", "int")],
	MediumLevelILOperation.MLIL_EXTERN_PTR:MediumLevelILExtern_ptr,                        # [("constant", "int"), ("offset", "int")],
	MediumLevelILOperation.MLIL_ADD:MediumLevelILAdd,                                      # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_SUB:MediumLevelILSub,                                      # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_AND:MediumLevelILAnd,                                      # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_OR:MediumLevelILOr,                                        # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_XOR:MediumLevelILXor,                                      # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_LSL:MediumLevelILLsl,                                      # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_LSR:MediumLevelILLsr,                                      # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_ASR:MediumLevelILAsr,                                      # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_ROL:MediumLevelILRol,                                      # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_ROR:MediumLevelILRor,                                      # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_MUL:MediumLevelILMul,                                      # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_MULU_DP:MediumLevelILMulu_dp,                              # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_MULS_DP:MediumLevelILMuls_dp,                              # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_DIVU:MediumLevelILDivu,                                    # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_DIVU_DP:MediumLevelILDivu_dp,                              # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_DIVS:MediumLevelILDivs,                                    # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_DIVS_DP:MediumLevelILDivs_dp,                              # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_MODU:MediumLevelILModu,                                    # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_MODU_DP:MediumLevelILModu_dp,                              # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_MODS:MediumLevelILMods,                                    # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_MODS_DP:MediumLevelILMods_dp,                              # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_NEG:MediumLevelILNeg,                                      # [("src", "expr")],
	MediumLevelILOperation.MLIL_NOT:MediumLevelILNot,                                      # [("src", "expr")],
	MediumLevelILOperation.MLIL_SX:MediumLevelILSx,                                        # [("src", "expr")],
	MediumLevelILOperation.MLIL_ZX:MediumLevelILZx,                                        # [("src", "expr")],
	MediumLevelILOperation.MLIL_LOW_PART:MediumLevelILLow_part,                            # [("src", "expr")],
	MediumLevelILOperation.MLIL_JUMP:MediumLevelILJump,                                    # [("dest", "expr")],
	MediumLevelILOperation.MLIL_RET_HINT:MediumLevelILRet_hint,                            # [("dest", "expr")],
	MediumLevelILOperation.MLIL_CALL_OUTPUT:MediumLevelILCall_output,                      # [("dest", "var_list")],
	MediumLevelILOperation.MLIL_CALL_PARAM:MediumLevelILCall_param,                        # [("src", "var_list")],
	MediumLevelILOperation.MLIL_RET:MediumLevelILRet,                                      # [("src", "expr_list")],
	MediumLevelILOperation.MLIL_GOTO:MediumLevelILGoto,                                    # [("dest", "int")],
	MediumLevelILOperation.MLIL_BOOL_TO_INT:MediumLevelILBool_to_int,                      # [("src", "expr")],
	MediumLevelILOperation.MLIL_FREE_VAR_SLOT:MediumLevelILFree_var_slot,                  # [("dest", "var")],
	MediumLevelILOperation.MLIL_TRAP:MediumLevelILTrap,                                    # [("vector", "int")],
	MediumLevelILOperation.MLIL_FREE_VAR_SLOT_SSA:MediumLevelILFree_var_slot_ssa,          # [("prev", "var_ssa_dest_and_src")],
	MediumLevelILOperation.MLIL_UNIMPL_MEM:MediumLevelILUnimpl_mem,                        # [("src", "expr")],
	MediumLevelILOperation.MLIL_FSQRT:MediumLevelILFsqrt,                                  # [("src", "expr")],
	MediumLevelILOperation.MLIL_FNEG:MediumLevelILFneg,                                    # [("src", "expr")],
	MediumLevelILOperation.MLIL_FABS:MediumLevelILFabs,                                    # [("src", "expr")],
	MediumLevelILOperation.MLIL_FLOAT_TO_INT:MediumLevelILFloat_to_int,                    # [("src", "expr")],
	MediumLevelILOperation.MLIL_INT_TO_FLOAT:MediumLevelILInt_to_float,                    # [("src", "expr")],
	MediumLevelILOperation.MLIL_FLOAT_CONV:MediumLevelILFloat_conv,                        # [("src", "expr")],
	MediumLevelILOperation.MLIL_ROUND_TO_INT:MediumLevelILRound_to_int,                    # [("src", "expr")],
	MediumLevelILOperation.MLIL_FLOOR:MediumLevelILFloor,                                  # [("src", "expr")],
	MediumLevelILOperation.MLIL_CEIL:MediumLevelILCeil,                                    # [("src", "expr")],
	MediumLevelILOperation.MLIL_FTRUNC:MediumLevelILFtrunc,                                # [("src", "expr")],
	MediumLevelILOperation.MLIL_VAR_SSA:MediumLevelILVar_ssa,                              # [("src", "var_ssa")],
	MediumLevelILOperation.MLIL_VAR_ALIASED:MediumLevelILVar_aliased,                      # [("src", "var_ssa")],
	MediumLevelILOperation.MLIL_CMP_E:MediumLevelILCmp_e,                                  # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_CMP_NE:MediumLevelILCmp_ne,                                # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_CMP_SLT:MediumLevelILCmp_slt,                              # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_CMP_ULT:MediumLevelILCmp_ult,                              # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_CMP_SLE:MediumLevelILCmp_sle,                              # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_CMP_ULE:MediumLevelILCmp_ule,                              # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_CMP_SGE:MediumLevelILCmp_sge,                              # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_CMP_UGE:MediumLevelILCmp_uge,                              # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_CMP_SGT:MediumLevelILCmp_sgt,                              # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_CMP_UGT:MediumLevelILCmp_ugt,                              # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_TEST_BIT:MediumLevelILTest_bit,                            # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_ADD_OVERFLOW:MediumLevelILAdd_overflow,                    # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_SYSCALL:MediumLevelILSyscall,                              # [("output", "var_list"), ("params", "expr_list")],
	MediumLevelILOperation.MLIL_VAR_SSA_FIELD:MediumLevelILVar_ssa_field,                  # [("src", "var_ssa"), ("offset", "int")],
	MediumLevelILOperation.MLIL_VAR_ALIASED_FIELD:MediumLevelILVar_aliased_field,          # [("src", "var_ssa"), ("offset", "int")],
	MediumLevelILOperation.MLIL_VAR_SPLIT_SSA:MediumLevelILVar_split_ssa,                  # [("high", "var_ssa"), ("low", "var_ssa")],
	MediumLevelILOperation.MLIL_CALL_OUTPUT_SSA:MediumLevelILCall_output_ssa,              # [("dest_memory", "int"), ("dest", "var_ssa_list")],
	MediumLevelILOperation.MLIL_CALL_PARAM_SSA:MediumLevelILCall_param_ssa,                # [("src_memory", "int"), ("src", "var_ssa_list")],
	MediumLevelILOperation.MLIL_LOAD_SSA:MediumLevelILLoad_ssa,                            # [("src", "expr"), ("src_memory", "int")],
	MediumLevelILOperation.MLIL_VAR_PHI:MediumLevelILVar_phi,                              # [("dest", "var_ssa"), ("src", "var_ssa_list")],
	MediumLevelILOperation.MLIL_MEM_PHI:MediumLevelILMem_phi,                              # [("dest_memory", "int"), ("src_memory", "int_list")],
	MediumLevelILOperation.MLIL_SET_VAR_SSA:MediumLevelILSet_var_ssa,                      # [("dest", "var_ssa"), ("src", "expr")],
	MediumLevelILOperation.MLIL_FCMP_E:MediumLevelILFcmp_e,                                # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_FCMP_NE:MediumLevelILFcmp_ne,                              # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_FCMP_LT:MediumLevelILFcmp_lt,                              # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_FCMP_LE:MediumLevelILFcmp_le,                              # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_FCMP_GE:MediumLevelILFcmp_ge,                              # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_FCMP_GT:MediumLevelILFcmp_gt,                              # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_FCMP_O:MediumLevelILFcmp_o,                                # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_FCMP_UO:MediumLevelILFcmp_uo,                              # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_FADD:MediumLevelILFadd,                                    # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_FSUB:MediumLevelILFsub,                                    # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_FMUL:MediumLevelILFmul,                                    # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_FDIV:MediumLevelILFdiv,                                    # [("left", "expr"), ("right", "expr")],
	MediumLevelILOperation.MLIL_JUMP_TO:MediumLevelILJump_to,                              # [("dest", "expr"), ("targets", "target_map")],
	MediumLevelILOperation.MLIL_SET_VAR_ALIASED:MediumLevelILSet_var_aliased,              # [("prev", "var_ssa_dest_and_src"), ("src", "expr")],
	MediumLevelILOperation.MLIL_SYSCALL_UNTYPED:MediumLevelILSyscall_untyped,              # [("output", "expr"), ("params", "expr"), ("stack", "expr")],
	MediumLevelILOperation.MLIL_TAILCALL:MediumLevelILTailcall,                            # [("output", "var_list"), ("dest", "expr"), ("params", "expr_list")],
	MediumLevelILOperation.MLIL_INTRINSIC:MediumLevelILIntrinsic,                          # [("output", "var_list"), ("intrinsic", "intrinsic"), ("params", "expr_list")],
	MediumLevelILOperation.MLIL_INTRINSIC_SSA:MediumLevelILIntrinsic_ssa,                  # [("output", "var_ssa_list"), ("intrinsic", "intrinsic"), ("params", "expr_list")],
	MediumLevelILOperation.MLIL_SET_VAR_SSA_FIELD:MediumLevelILSet_var_ssa_field,          # [("prev", "var_ssa_dest_and_src"), ("offset", "int"), ("src", "expr")],
	MediumLevelILOperation.MLIL_SET_VAR_SPLIT_SSA:MediumLevelILSet_var_split_ssa,          # [("high", "var_ssa"), ("low", "var_ssa"), ("src", "expr")],
	MediumLevelILOperation.MLIL_SET_VAR_ALIASED_FIELD:MediumLevelILSet_var_aliased_field,  # [("prev", "var_ssa_dest_and_src"), ("offset", "int"), ("src", "expr")],
	MediumLevelILOperation.MLIL_SYSCALL_SSA:MediumLevelILSyscall_ssa,                      # [("output", "expr"), ("params", "expr_list"), ("src_memory", "int")],
	MediumLevelILOperation.MLIL_SYSCALL_UNTYPED_SSA:MediumLevelILSyscall_untyped_ssa,      # [("output", "expr"), ("params", "expr"), ("stack", "expr")],
	MediumLevelILOperation.MLIL_LOAD_STRUCT_SSA:MediumLevelILLoad_struct_ssa,              # [("src", "expr"), ("offset", "int"), ("src_memory", "int")],
	MediumLevelILOperation.MLIL_SET_VAR_FIELD:MediumLevelILSet_var_field,                  # [("dest", "var"), ("offset", "int"), ("src", "expr")],
	MediumLevelILOperation.MLIL_SET_VAR_SPLIT:MediumLevelILSet_var_split,                  # [("high", "var"), ("low", "var"), ("src", "expr")],
	MediumLevelILOperation.MLIL_STORE_STRUCT:MediumLevelILStore_struct,                    # [("dest", "expr"), ("offset", "int"), ("src", "expr")],
	MediumLevelILOperation.MLIL_ADC:MediumLevelILAdc,                                      # [("left", "expr"), ("right", "expr"), ("carry", "expr")],
	MediumLevelILOperation.MLIL_SBB:MediumLevelILSbb,                                      # [("left", "expr"), ("right", "expr"), ("carry", "expr")],
	MediumLevelILOperation.MLIL_RLC:MediumLevelILRlc,                                      # [("left", "expr"), ("right", "expr"), ("carry", "expr")],
	MediumLevelILOperation.MLIL_RRC:MediumLevelILRrc,                                      # [("left", "expr"), ("right", "expr"), ("carry", "expr")],
	MediumLevelILOperation.MLIL_TAILCALL_UNTYPED:MediumLevelILTailcall_untyped,            # [("output", "expr"), ("dest", "expr"), ("params", "expr"), ("stack", "expr")],
	MediumLevelILOperation.MLIL_CALL_SSA:MediumLevelILCall_ssa,                            # [("output", "expr"), ("dest", "expr"), ("params", "expr_list"), ("src_memory", "int")],
	MediumLevelILOperation.MLIL_CALL_UNTYPED_SSA:MediumLevelILCall_untyped_ssa,            # [("output", "expr"), ("dest", "expr"), ("params", "expr"), ("stack", "expr")],
	MediumLevelILOperation.MLIL_TAILCALL_SSA:MediumLevelILTailcall_ssa,                    # [("output", "expr"), ("dest", "expr"), ("params", "expr_list"), ("src_memory", "int")],
	MediumLevelILOperation.MLIL_TAILCALL_UNTYPED_SSA:MediumLevelILTailcall_untyped_ssa,    # [("output", "expr"), ("dest", "expr"), ("params", "expr"), ("stack", "expr")],
	MediumLevelILOperation.MLIL_CALL:MediumLevelILCall,                                    # [("output", "var_list"), ("dest", "expr"), ("params", "expr_list")],
	MediumLevelILOperation.MLIL_IF:MediumLevelILIf,                                        # [("condition", "expr"), ("true", "int"), ("false", "int")],
	MediumLevelILOperation.MLIL_STORE_SSA:MediumLevelILStore_ssa,                          # [("dest", "expr"), ("dest_memory", "int"), ("src_memory", "int"), ("src", "expr")],
	MediumLevelILOperation.MLIL_CALL_UNTYPED:MediumLevelILCall_untyped,                    # [("output", "expr"), ("dest", "expr"), ("params", "expr"), ("stack", "expr")],
	MediumLevelILOperation.MLIL_STORE_STRUCT_SSA:MediumLevelILStore_struct_ssa,            # [("dest", "expr"), ("offset", "int"), ("dest_memory", "int"), ("src_memory", "int"), ("src", "expr")],
}

class MediumLevelILExpr:
	"""
	``class MediumLevelILExpr`` hold the index of IL Expressions.

	.. note:: This class shouldn't be instantiated directly. Rather the helper members of MediumLevelILFunction should be \
	used instead.
	"""
	def __init__(self, index):
		self._index = index

	@property
	def index(self):
		return self._index

	@index.setter
	def index(self, value):
		self._index = value


class MediumLevelILFunction:
	"""
	``class MediumLevelILFunction`` contains the list of MediumLevelILExpr objects that make up a function. MediumLevelILExpr
	objects can be added to the MediumLevelILFunction by calling :func:`append` and passing the result of the various class
	methods which return MediumLevelILExpr objects.
	"""
	def __init__(self, arch:Optional['architecture.Architecture']=None,
		handle:Optional[core.BNMediumLevelILFunction]=None, source_func:Optional['function.Function']=None):
		_arch = arch
		_source_function = source_func
		if handle is not None:
			MLILHandle = ctypes.POINTER(core.BNMediumLevelILFunction)
			_handle = ctypes.cast(handle, MLILHandle)
			if _source_function is None:
				_source_function = function.Function(handle = core.BNGetMediumLevelILOwnerFunction(_handle))
			if _arch is None:
				_arch = _source_function.arch
		else:
			if _source_function is None:
				raise ValueError("IL functions must be created with an associated function")
			if _arch is None:
				_arch = _source_function.arch
			func_handle = _source_function.handle
			_handle = core.BNCreateMediumLevelILFunction(self.arch.handle, func_handle)
		assert _source_function is not None
		assert _arch is not None
		assert _handle is not None
		self.handle = _handle
		self._arch = _arch
		self._source_function = _source_function

	def __del__(self):
		if self.handle is not None:
			core.BNFreeMediumLevelILFunction(self.handle)

	def __repr__(self):
		arch = self.source_function.arch
		if arch:
			return "<mlil func: %s@%#x>" % (arch.name, self.source_function.start)
		else:
			return "<mlil func: %#x>" % self.source_function.start

	def __len__(self):
		return int(core.BNGetMediumLevelILInstructionCount(self.handle))

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(other.handle.contents)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash(('MLIL', self._source_function))

	def __getitem__(self, i) -> 'MediumLevelILInstruction':
		if isinstance(i, slice) or isinstance(i, tuple):
			raise IndexError("expected integer instruction index")
		if isinstance(i, MediumLevelILExpr):
			return MediumLevelILInstruction.create(self, i.index)
		# for backwards compatibility
		if isinstance(i, MediumLevelILInstruction):
			return i
		if i < -len(self) or i >= len(self):
			raise IndexError("index out of range")
		if i < 0:
			i = len(self) + i
		return MediumLevelILInstruction.create(self, core.BNGetMediumLevelILIndexForInstruction(self.handle, i), i)

	def __setitem__(self, i, j):
		raise IndexError("instruction modification not implemented")

	def __iter__(self):
		count = ctypes.c_ulonglong()
		blocks = core.BNGetMediumLevelILBasicBlockList(self.handle, count)
		assert blocks is not None, "core.BNGetMediumLevelILBasicBlockList returned None"
		view = None
		if self._source_function is not None:
			view = self._source_function.view
		try:
			for i in range(0, count.value):
				core_block = core.BNNewBasicBlockReference(blocks[i])
				assert core_block is not None, "Got None from core.BNNewBasicBlockReference"
				yield MediumLevelILBasicBlock(core_block, self, view)
		finally:
			core.BNFreeBasicBlockList(blocks, count.value)

	@property
	def current_address(self) -> int:
		"""Current IL Address (read/write)"""
		return core.BNMediumLevelILGetCurrentAddress(self.handle)

	@current_address.setter
	def current_address(self, value:int) -> None:
		core.BNMediumLevelILSetCurrentAddress(self.handle, self._arch.handle, value)

	def set_current_address(self, value:int, arch:Optional['architecture.Architecture']=None) -> None:
		_arch = arch
		if _arch is None:
			_arch = self._arch
		core.BNMediumLevelILSetCurrentAddress(self.handle, _arch.handle, value)

	@property
	def basic_blocks(self) -> Generator['MediumLevelILBasicBlock', None, None]:
		"""list of MediumLevelILBasicBlock objects (read-only)"""
		count = ctypes.c_ulonglong()
		blocks = core.BNGetMediumLevelILBasicBlockList(self.handle, count)
		assert blocks is not None, "core.BNGetMediumLevelILBasicBlockList returned None"
		view = None
		if self._source_function is not None:
			view = self._source_function.view
		try:
			for i in range(0, count.value):
				core_block = core.BNNewBasicBlockReference(blocks[i])
				assert core_block is not None
				yield MediumLevelILBasicBlock(core_block, self, view)
		finally:
			core.BNFreeBasicBlockList(blocks, count.value)

	@property
	def instructions(self) -> Generator[MediumLevelILInstruction, None, None]:
		"""A generator of mlil instructions of the current function"""
		for block in self.basic_blocks:
			for i in block:
				yield i

	@property
	def ssa_form(self) -> Optional['MediumLevelILFunction']:
		"""Medium level IL in SSA form (read-only)"""
		result = core.BNGetMediumLevelILSSAForm(self.handle)
		if not result:
			return None
		return MediumLevelILFunction(self._arch, result, self._source_function)

	@property
	def non_ssa_form(self) -> Optional['MediumLevelILFunction']:
		"""Medium level IL in non-SSA (default) form (read-only)"""
		result = core.BNGetMediumLevelILNonSSAForm(self.handle)
		if not result:
			return None
		return MediumLevelILFunction(self._arch, result, self._source_function)

	@property
	def low_level_il(self) -> Optional['lowlevelil.LowLevelILFunction']:
		"""Low level IL for this function"""
		result = core.BNGetLowLevelILForMediumLevelIL(self.handle)
		if not result:
			return None
		return lowlevelil.LowLevelILFunction(self._arch, result, self._source_function)

	@property
	def llil(self) -> Optional['lowlevelil.LowLevelILFunction']:
		"""Alias for low_level_il"""
		return self.low_level_il

	@property
	def high_level_il(self) -> Optional[highlevelil.HighLevelILFunction]:
		"""High level IL for this medium level IL."""
		result = core.BNGetHighLevelILForMediumLevelIL(self.handle)
		if not result:
			return None
		return highlevelil.HighLevelILFunction(self._arch, result, self._source_function)

	@property
	def hlil(self) -> Optional[highlevelil.HighLevelILFunction]:
		return self.high_level_il

	def get_instruction_start(self, addr:int, arch:Optional['architecture.Architecture']=None) -> Optional[int]:
		_arch = arch
		if _arch is None:
			if self._arch is None:
				raise Exception("Attempting to get_instruction_start from a MLIL Function without an Architecture")
			_arch = self._arch
		result = core.BNMediumLevelILGetInstructionStart(self.handle, _arch.handle, addr)
		if result >= core.BNGetMediumLevelILInstructionCount(self.handle):
			return None
		return result

	def expr(self, operation:MediumLevelILOperation, a:int=0, b:int=0, c:int=0, d:int=0, e:int=0,
		size:int=0) -> MediumLevelILExpr:
		_operation = operation
		if isinstance(operation, str):
			_operation = MediumLevelILOperation[operation]
		elif isinstance(operation, MediumLevelILOperation):
			_operation = operation.value
		return MediumLevelILExpr(core.BNMediumLevelILAddExpr(self.handle, _operation, size, a, b, c, d, e))

	def append(self, expr:MediumLevelILExpr) -> int:
		"""
		``append`` adds the MediumLevelILExpr ``expr`` to the current MediumLevelILFunction.

		:param MediumLevelILExpr expr: the MediumLevelILExpr to add to the current MediumLevelILFunction
		:return: number of MediumLevelILExpr in the current function
		:rtype: int
		"""
		return core.BNMediumLevelILAddInstruction(self.handle, expr.index)

	def goto(self, label:MediumLevelILLabel) -> MediumLevelILExpr:
		"""
		``goto`` returns a goto expression which jumps to the provided MediumLevelILLabel.

		:param MediumLevelILLabel label: Label to jump to
		:return: the MediumLevelILExpr that jumps to the provided label
		:rtype: MediumLevelILExpr
		"""
		return MediumLevelILExpr(core.BNMediumLevelILGoto(self.handle, label.handle))

	def if_expr(self, operand:MediumLevelILExpr, t:MediumLevelILLabel, f:MediumLevelILLabel) -> MediumLevelILExpr:
		"""
		``if_expr`` returns the ``if`` expression which depending on condition ``operand`` jumps to the MediumLevelILLabel
		``t`` when the condition expression ``operand`` is non-zero and ``f`` when it's zero.

		:param MediumLevelILExpr operand: comparison expression to evaluate.
		:param MediumLevelILLabel t: Label for the true branch
		:param MediumLevelILLabel f: Label for the false branch
		:return: the MediumLevelILExpr for the if expression
		:rtype: MediumLevelILExpr
		"""
		return MediumLevelILExpr(core.BNMediumLevelILIf(self.handle, operand.index, t.handle, f.handle))

	def mark_label(self, label:MediumLevelILLabel) -> None:
		"""
		``mark_label`` assigns a MediumLevelILLabel to the current IL address.

		:param MediumLevelILLabel label:
		:rtype: None
		"""
		core.BNMediumLevelILMarkLabel(self.handle, label.handle)

	def add_label_map(self, labels:Mapping[int, MediumLevelILLabel]) -> MediumLevelILExpr:
		"""
		``add_label_map`` returns a label list expression for the given list of MediumLevelILLabel objects.

		:param labels: the list of MediumLevelILLabel to get a label list expression from
		:type labels: dict(int, MediumLevelILLabel)
		:return: the label list expression
		:rtype: MediumLevelILExpr
		"""
		label_list = (ctypes.POINTER(core.BNMediumLevelILLabel) * len(labels))()  # type: ignore
		value_list = (ctypes.POINTER(ctypes.c_ulonglong) * len(labels))()  # type: ignore
		for i, (key, value) in enumerate(labels.items()):
			value_list[i] = key
			label_list[i] = value.handle

		return MediumLevelILExpr(core.BNMediumLevelILAddLabelMap(self.handle, value_list, label_list, len(labels)))

	def add_operand_list(self, operands:List[ExpressionIndex]) -> MediumLevelILExpr:
		"""
		``add_operand_list`` returns an operand list expression for the given list of integer operands.

		:param operands: list of operand numbers
		:type operands: list(int)
		:return: an operand list expression
		:rtype: MediumLevelILExpr
		"""
		operand_list = (ctypes.c_ulonglong * len(operands))()
		for i in range(len(operands)):
			operand_list[i] = operands[i]
		return MediumLevelILExpr(core.BNMediumLevelILAddOperandList(self.handle, operand_list, len(operands)))

	def finalize(self) -> None:
		"""
		``finalize`` ends the function and computes the list of basic blocks.

		:rtype: None
		"""
		core.BNFinalizeMediumLevelILFunction(self.handle)

	def get_ssa_instruction_index(self, instr:InstructionIndex) -> InstructionIndex:
		return core.BNGetMediumLevelILSSAInstructionIndex(self.handle, instr)

	def get_non_ssa_instruction_index(self, instr:InstructionIndex) -> InstructionIndex:
		return core.BNGetMediumLevelILNonSSAInstructionIndex(self.handle, instr)

	def get_ssa_var_definition(self, ssa_var:SSAVariable) -> Optional[MediumLevelILInstruction]:
		var_data = ssa_var.var.to_BNVariable()
		result = core.BNGetMediumLevelILSSAVarDefinition(self.handle, var_data, ssa_var.version)
		if result >= core.BNGetMediumLevelILInstructionCount(self.handle):
			return None
		return self[result]

	def get_ssa_memory_definition(self, version:int) -> Optional[MediumLevelILInstruction]:
		result = core.BNGetMediumLevelILSSAMemoryDefinition(self.handle, version)
		if result >= core.BNGetMediumLevelILInstructionCount(self.handle):
			return None
		return self[result]

	def get_ssa_var_uses(self, ssa_var:SSAVariable) -> List[MediumLevelILInstruction]:
		count = ctypes.c_ulonglong()
		var_data = ssa_var.var.to_BNVariable()
		instrs = core.BNGetMediumLevelILSSAVarUses(self.handle, var_data, ssa_var.version, count)
		assert instrs is not None, "core.BNGetMediumLevelILSSAVarUses returned None"
		result = []
		for i in range(0, count.value):
			result.append(self[instrs[i]])
		core.BNFreeILInstructionList(instrs)
		return result

	def get_ssa_memory_uses(self, version:int) -> List[MediumLevelILInstruction]:
		count = ctypes.c_ulonglong()
		instrs = core.BNGetMediumLevelILSSAMemoryUses(self.handle, version, count)
		assert instrs is not None, "core.BNGetMediumLevelILSSAMemoryUses returned None"
		result = []
		for i in range(0, count.value):
			result.append(self[instrs[i]])
		core.BNFreeILInstructionList(instrs)
		return result

	def is_ssa_var_live(self, ssa_var:SSAVariable) -> bool:
		"""
		``is_ssa_var_live`` determines if ``ssa_var`` is live at any point in the function

		:param SSAVariable ssa_var: the SSA variable to query
		:return: whether the variable is live at any point in the function
		:rtype: bool
		"""
		var_data = ssa_var.var.to_BNVariable()
		return core.BNIsMediumLevelILSSAVarLive(self.handle, var_data, ssa_var.version)

	def get_var_definitions(self, var:'variable.Variable') -> List[MediumLevelILInstruction]:
		count = ctypes.c_ulonglong()
		var_data = var.to_BNVariable()
		instrs = core.BNGetMediumLevelILVariableDefinitions(self.handle, var_data, count)
		assert instrs is not None, "core.BNGetMediumLevelILVariableDefinitions returned None"
		result = []
		for i in range(0, count.value):
			result.append(self[instrs[i]])
		core.BNFreeILInstructionList(instrs)
		return result

	def get_var_uses(self, var:'variable.Variable') -> List[MediumLevelILInstruction]:
		count = ctypes.c_ulonglong()
		var_data = var.to_BNVariable()
		instrs = core.BNGetMediumLevelILVariableDefinitions(self.handle, var_data, count)
		assert instrs is not None, "core.BNGetMediumLevelILVariableDefinitions returned None"
		result = []
		for i in range(0, count.value):
			result.append(self[instrs[i]])
		core.BNFreeILInstructionList(instrs)
		return result

		count = ctypes.c_ulonglong()
		var_data = var.to_BNVariable()
		instrs = core.BNGetMediumLevelILVariableUses(self.handle, var_data, count)
		result = []
		for i in range(0, count.value):
			result.append(self[instrs[i]])
		core.BNFreeILInstructionList(instrs)
		return result

	def get_ssa_var_value(self, ssa_var:SSAVariable) -> 'variable.RegisterValue':
		var_data = ssa_var.var.to_BNVariable()
		value = core.BNGetMediumLevelILSSAVarValue(self.handle, var_data, ssa_var.version)
		result = variable.RegisterValue.from_BNRegisterValue(value, self._arch)
		return result

	def get_low_level_il_instruction_index(self, instr:InstructionIndex) -> Optional['lowlevelil.InstructionIndex']:
		low_il = self.low_level_il
		if low_il is None:
			return None
		low_il = low_il.ssa_form
		if low_il is None:
			return None
		result = core.BNGetLowLevelILInstructionIndex(self.handle, instr)
		if result >= core.BNGetLowLevelILInstructionCount(low_il.handle):
			return None
		return result

	def get_low_level_il_expr_index(self, expr:ExpressionIndex) -> Optional['lowlevelil.ExpressionIndex']:
		low_il = self.low_level_il
		if low_il is None:
			return None
		low_il = low_il.ssa_form
		if low_il is None:
			return None
		result = core.BNGetLowLevelILExprIndex(self.handle, expr)
		if result >= core.BNGetLowLevelILExprCount(low_il.handle):
			return None
		return result

	def get_low_level_il_expr_indexes(self, expr:ExpressionIndex) -> List['lowlevelil.ExpressionIndex']:
		count = ctypes.c_ulonglong()
		exprs = core.BNGetLowLevelILExprIndexes(self.handle, expr, count)
		assert exprs is not None, "core.BNGetLowLevelILExprIndexes returned None"
		result = []
		for i in range(0, count.value):
			result.append(exprs[i])
		core.BNFreeILInstructionList(exprs)
		return result

	def get_high_level_il_instruction_index(self, instr:InstructionIndex) -> Optional['highlevelil.InstructionIndex']:
		high_il = self.high_level_il
		if high_il is None:
			return None
		result = core.BNGetHighLevelILInstructionIndex(self.handle, instr)
		if result >= core.BNGetHighLevelILInstructionCount(high_il.handle):
			return None
		return result

	def get_high_level_il_expr_index(self, expr:ExpressionIndex) -> Optional['highlevelil.ExpressionIndex']:
		high_il = self.high_level_il
		if high_il is None:
			return None
		result = core.BNGetHighLevelILExprIndex(self.handle, expr)
		if result >= core.BNGetHighLevelILExprCount(high_il.handle):
			return None
		return result

	def get_high_level_il_expr_indexes(self, expr:ExpressionIndex) -> List['highlevelil.ExpressionIndex']:
		count = ctypes.c_ulonglong()
		exprs = core.BNGetHighLevelILExprIndexes(self.handle, expr, count)
		assert exprs is not None, "core.BNGetHighLevelILExprIndexes returned None"
		result = []
		for i in range(0, count.value):
			result.append(exprs[i])
		core.BNFreeILInstructionList(exprs)
		return result

	def create_graph(self, settings:'function.DisassemblySettings'=None) -> flowgraph.CoreFlowGraph:
		if settings is not None:
			settings_obj = settings.handle
		else:
			settings_obj = None
		return flowgraph.CoreFlowGraph(core.BNCreateMediumLevelILFunctionGraph(self.handle, settings_obj))

	@property
	def arch(self) -> 'architecture.Architecture':
		return self._arch

	@property
	def source_function(self) -> 'function.Function':
		return self._source_function

	@source_function.setter
	def source_function(self, value):
		self._source_function = value

	@property
	def il_form(self) -> FunctionGraphType:
		if len(list(self.basic_blocks)) < 1:
			return FunctionGraphType.InvalidILViewType
		return FunctionGraphType(core.BNGetBasicBlockFunctionGraphType(list(self.basic_blocks)[0].handle))

	@property
	def vars(self) -> List['variable.Variable']:
		"""This gets just the MLIL variables - you may be interested in the union of `MediumLevelIlFunction.source_function.param_vars` for all the variables used in the function"""
		if self.source_function is None:
			return []

		if self.il_form in [FunctionGraphType.MediumLevelILFunctionGraph, FunctionGraphType.MediumLevelILSSAFormFunctionGraph, FunctionGraphType.MappedMediumLevelILFunctionGraph, FunctionGraphType.MappedMediumLevelILSSAFormFunctionGraph]:
			count = ctypes.c_ulonglong()
			core_variables = core.BNGetMediumLevelILVariables(self.handle, count)
			assert core_variables is not None, "core.BNGetMediumLevelILVariables returned None"
			result = []
			try:
				for var_i in range(count.value):
					result.append(variable.Variable(self.source_function, core_variables[var_i].type, core_variables[var_i].index, core_variables[var_i].storage))
				return result
			finally:
				core.BNFreeVariableList(core_variables)
		return []

	@property
	def ssa_vars(self) -> List[SSAVariable]:
		"""This gets just the MLIL SSA variables - you may be interested in the union of `MediumLevelIlFunction.source_function.param_vars` for all the variables used in the function"""
		if self.source_function is None:
			return []

		if self.il_form in [FunctionGraphType.MediumLevelILSSAFormFunctionGraph, FunctionGraphType.MappedMediumLevelILSSAFormFunctionGraph]:
			variable_count = ctypes.c_ulonglong()
			core_variables = core.BNGetMediumLevelILVariables(self.handle, variable_count)
			assert core_variables is not None, "core.BNGetMediumLevelILVariables returned None"
			try:
				result = []
				for var_i in range(variable_count.value):
					version_count = ctypes.c_ulonglong()
					versions = core.BNGetMediumLevelILVariableSSAVersions(self.handle, core_variables[var_i], version_count)
					assert versions is not None, "core.BNGetMediumLevelILVariableSSAVersions returned None"
					try:
						for version_i in range(version_count.value):
							result.append(SSAVariable(variable.Variable(self.source_function,
								core_variables[var_i].type, core_variables[var_i].index,
								core_variables[var_i].storage), versions[version_i]))
					finally:
						core.BNFreeILInstructionList(versions)

				return result
			finally:
				core.BNFreeVariableList(core_variables)

		return []


class MediumLevelILBasicBlock(basicblock.BasicBlock):
	def __init__(self, handle:core.BNBasicBlockHandle, owner:MediumLevelILFunction, view:Optional['binaryview.BinaryView']=None):
		super(MediumLevelILBasicBlock, self).__init__(handle, view)
		self._il_function = owner

	def __repr__(self):
		arch = self.arch
		if arch:
			return "<mlil block: %s@%d-%d>" % (arch.name, self.start, self.end)
		else:
			return "<mlil block: %d-%d>" % (self.start, self.end)

	def __iter__(self):
		for idx in range(self.start, self.end):
			yield self._il_function[idx]

	def __getitem__(self, idx) -> Union[List['MediumLevelILInstruction'], 'MediumLevelILInstruction']:
		size = self.end - self.start
		if isinstance(idx, slice):
			return [self[index] for index in range(*idx.indices(size))]  # type: ignore
		if idx > size or idx < -size:
			raise IndexError("list index is out of range")
		if idx >= 0:
			return self._il_function[idx + self.start]
		else:
			return self._il_function[self.end + idx]

	def __hash__(self):
		return hash((self.start, self.end, self._il_function))

	def __contains__(self, instruction):
		if type(instruction) != MediumLevelILInstruction or instruction.il_basic_block != self:
			return False
		if instruction.instr_index >= self.start and instruction.instr_index <= self.end:
			return True
		else:
			return False

	def _create_instance(self, handle:core.BNBasicBlockHandle, view:'binaryview.BinaryView') -> 'MediumLevelILBasicBlock':
		"""Internal method by super to instantiate child instances"""
		return MediumLevelILBasicBlock(handle, self.il_function, view)

	@property
	def instruction_count(self) -> int:
		return self.end - self.start

	@property
	def il_function(self) -> 'MediumLevelILFunction':
		return self._il_function
