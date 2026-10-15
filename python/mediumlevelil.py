# Copyright (c) 2018-2026 Vector 35 Inc
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
from typing import (Optional, List, Union, Mapping, MutableMapping,
	Generator, NewType, Tuple, ClassVar, Dict, Set, Callable, Any, Iterator, overload)
from dataclasses import dataclass
from . import deprecation

# Binary Ninja components
from . import _binaryninjacore as core
from .enums import MediumLevelILOperation, ILBranchDependence, DataFlowQueryOption, FunctionGraphType, DeadStoreElimination, ILInstructionAttribute, StringType, ForceVersionReason
from . import basicblock
from . import function
from . import types
from . import lowlevelil
from . import highlevelil
from . import flowgraph
from . import variable
from . import architecture
from . import binaryview
from . import types as _types
from .interaction import show_graph_report
from .commonil import (
    BaseILInstruction, Constant, BinaryOperation, UnaryOperation, Comparison, SSA, Phi, FloatingPoint, ControlFlow,
    Terminal, Call, Localcall, Syscall, Tailcall, Return, Signed, Arithmetic, Carry, DoublePrecision, Memory, Load,
    Store, RegisterStack, SetVar, Intrinsic, VariableInstruction, SSAVariableInstruction, AliasedVariableInstruction,
    ILSourceLocation, invalid_il_index
)

TokenList = List['function.InstructionTextToken']
ExpressionIndex = NewType('ExpressionIndex', int)
InstructionIndex = NewType('InstructionIndex', int)
Index = Union[ExpressionIndex, InstructionIndex]
InstructionOrExpression = Union['MediumLevelILInstruction', Index]
MLILInstructionsType = Generator['MediumLevelILInstruction', None, None]
MLILBasicBlocksType = Generator['MediumLevelILBasicBlock', None, None]
OperandsType = Tuple[ExpressionIndex, ExpressionIndex, ExpressionIndex, ExpressionIndex, ExpressionIndex]
MediumLevelILOperandType = Union[int, float, 'MediumLevelILOperationAndSize', 'MediumLevelILInstruction',
                                 'lowlevelil.ILIntrinsic', 'variable.Variable', 'SSAVariable', List[int],
                                 List['variable.Variable'], List['SSAVariable'], List['MediumLevelILInstruction'],
                                 Dict[int, int], 'variable.ConstantData']
MediumLevelILVisitorCallback = Callable[[str, MediumLevelILOperandType, str, Optional['MediumLevelILInstruction']], bool]
StringOrType = Union[str, '_types.Type', '_types.TypeBuilder']
ILInstructionAttributeSet = Union[Set[ILInstructionAttribute], List[ILInstructionAttribute]]
LLILSSAToMLILInstructionMapping = MutableMapping['lowlevelil.InstructionIndex', InstructionIndex]
CallOutputList = Union[List[ExpressionIndex], List['variable.CoreVariable']]


@dataclass(frozen=True)
class LLILSSAToMLILExpressionMap:
	lower_index: 'lowlevelil.ExpressionIndex'
	higher_index: ExpressionIndex
	map_lower_to_higher: bool
	map_higher_to_lower: bool
	lower_to_higher_direct: bool
	higher_to_lower_direct: bool

	def _to_core_struct(self):
		result = core.BNExprMapInfo()
		result.lowerIndex = self.lower_index
		result.higherIndex = self.higher_index
		result.mapLowerToHigher = self.map_lower_to_higher
		result.mapHigherToLower = self.map_higher_to_lower
		result.lowerToHigherDirect = self.lower_to_higher_direct
		result.higherToLowerDirect = self.higher_to_lower_direct
		return result


LLILSSAToMLILExpressionMapping = List['LLILSSAToMLILExpressionMap']


@dataclass(frozen=True, repr=False, order=True)
class SSAVariable:
	var: 'variable.Variable'
	version: int

	def __repr__(self):
		return f"<SSAVariable: {self.var} version {self.version}>"

	@property
	def name(self) -> str:
		return self.var.name

	@property
	def type(self) -> 'types.Type':
		return self.var.type

	@property
	def function(self) -> 'function.Function':
		"""returns the source Function object which this variable belongs to"""
		return self.var.function

	@property
	def il_function(self) -> 'function.ILFunctionType':
		"""returns the il Function object which this variable belongs to"""
		return self.var._il_function

	@property
	def dead_store_elimination(self) -> DeadStoreElimination:
		"""returns the dead store elimination setting for this variable (read-only)"""
		return self.var.dead_store_elimination

	@property
	def def_site(self) -> Optional[Union['MediumLevelILInstruction', 'highlevelil.HighLevelILInstruction']]:
		"""
		Gets the IL instructions where this SSAVariable is defined.
		"""
		return self.il_function.get_ssa_var_definition(self)

	@property
	def use_sites(self) -> List[Union['MediumLevelILInstruction', 'highlevelil.HighLevelILInstruction']]:
		"""
		Gets the list of IL instructions where this SSAVariable is used inside of this function.
		"""
		return self.il_function.get_ssa_var_uses(self)


class MediumLevelILLabel:
	def __init__(self, handle: Optional[core.BNMediumLevelILLabel] = None):
		if handle is None:
			self.handle = (core.BNMediumLevelILLabel * 1)()
			core.BNMediumLevelILInitLabel(self.handle)
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


@dataclass(frozen=True, repr=False)
class MediumLevelILOperationAndSize:
	operation: MediumLevelILOperation
	size: int

	def __repr__(self):
		if self.size == 0:
			return f"<MediumLevelILOperationAndSize: {self.operation.name}>"
		return f"<MediumLevelILOperationAndSize: {self.operation.name} {self.size}>"


@dataclass(frozen=True)
class CoreMediumLevelILInstruction:
	operation: MediumLevelILOperation
	attributes: int
	source_operand: int
	size: int
	operands: OperandsType
	address: int

	@classmethod
	def from_BNMediumLevelILInstruction(cls, instr: core.BNMediumLevelILInstruction) -> 'CoreMediumLevelILInstruction':
		operands: OperandsType = tuple([ExpressionIndex(instr.operands[i]) for i in range(5)])  # type: ignore
		return cls(MediumLevelILOperation(instr.operation), instr.attributes, instr.sourceOperand, instr.size, operands, instr.address)


@dataclass(frozen=True)
class MediumLevelILInstruction(BaseILInstruction):
	"""
	``class MediumLevelILInstruction`` Medium Level Intermediate Language Instructions are infinite length tree-based
	instructions. Tree-based instructions use infix notation with the left hand operand being the destination operand.
	Infix notation is thus more natural to read than other notations (e.g. x86 ``mov eax, 0`` vs. MLIL ``eax = 0``).
	"""

	function: 'MediumLevelILFunction'
	expr_index: ExpressionIndex
	instr: CoreMediumLevelILInstruction
	instr_index: InstructionIndex

	# ILOperations is deprecated and will be removed in a future version once BNIL Graph no longer uses it
	# Use the visit methods visit, visit_all, and visit_operands
	# BEGIN GENERATED mlil-operations: from api/il, do not edit
	ILOperations: ClassVar[Dict[MediumLevelILOperation, List[Tuple[str, str]]]] = {
		MediumLevelILOperation.MLIL_NOP: [],
		MediumLevelILOperation.MLIL_SET_VAR: [("dest", "var"), ("src", "expr")],
		MediumLevelILOperation.MLIL_SET_VAR_FIELD: [("dest", "var"), ("offset", "int"), ("src", "expr")],
		MediumLevelILOperation.MLIL_SET_VAR_SPLIT: [("high", "var"), ("low", "var"), ("src", "expr")],
		MediumLevelILOperation.MLIL_ASSERT: [("src", "var"), ("constraint", "constraint")],
		MediumLevelILOperation.MLIL_FORCE_VER: [("dest", "var"), ("src", "var"), ("reason", "int")],
		MediumLevelILOperation.MLIL_LOAD: [("src", "expr")],
		MediumLevelILOperation.MLIL_LOAD_STRUCT: [("src", "expr"), ("offset", "int")],
		MediumLevelILOperation.MLIL_STORE: [("dest", "expr"), ("src", "expr")],
		MediumLevelILOperation.MLIL_STORE_STRUCT: [("dest", "expr"), ("offset", "int"), ("src", "expr")],
		MediumLevelILOperation.MLIL_VAR: [("var", "var")],
		MediumLevelILOperation.MLIL_VAR_FIELD: [("src", "var"), ("offset", "int")],
		MediumLevelILOperation.MLIL_VAR_SPLIT: [("high", "var"), ("low", "var")],
		MediumLevelILOperation.MLIL_ADDRESS_OF: [("src", "var")],
		MediumLevelILOperation.MLIL_ADDRESS_OF_FIELD: [("src", "var"), ("offset", "int")],
		MediumLevelILOperation.MLIL_PASS_BY_REF: [("src", "expr")],
		MediumLevelILOperation.MLIL_RETURN_BY_REF: [("src", "expr")],
		MediumLevelILOperation.MLIL_CONST: [("constant", "int")],
		MediumLevelILOperation.MLIL_CONST_DATA: [("constant", "ConstantData")],
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
		MediumLevelILOperation.MLIL_CALL_UNTYPED: [
			("output", "var_list"),
			("dest", "expr"),
			("params", "expr_list"),
			("stack", "expr"),
		],
		MediumLevelILOperation.MLIL_CALL_PARAM: [("src", "expr_list")],
		MediumLevelILOperation.MLIL_SEPARATE_PARAM_LIST: [("params", "expr_list")],
		MediumLevelILOperation.MLIL_SHARED_PARAM_SLOT: [("params", "expr_list")],
		MediumLevelILOperation.MLIL_VAR_OUTPUT: [("dest", "var")],
		MediumLevelILOperation.MLIL_VAR_OUTPUT_FIELD: [("dest", "var"), ("offset", "int")],
		MediumLevelILOperation.MLIL_STORE_OUTPUT: [("dest", "expr")],
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
		MediumLevelILOperation.MLIL_SYSCALL_UNTYPED: [
			("output", "var_list"),
			("params", "expr_list"),
			("stack", "expr"),
		],
		MediumLevelILOperation.MLIL_TAILCALL: [("output", "var_list"), ("dest", "expr"), ("params", "expr_list")],
		MediumLevelILOperation.MLIL_TAILCALL_UNTYPED: [
			("output", "var_list"),
			("dest", "expr"),
			("params", "expr_list"),
			("stack", "expr"),
		],
		MediumLevelILOperation.MLIL_INTRINSIC: [
			("output", "var_list"),
			("intrinsic", "intrinsic"),
			("params", "expr_list"),
		],
		MediumLevelILOperation.MLIL_FREE_VAR_SLOT: [("dest", "var")],
		MediumLevelILOperation.MLIL_BP: [],
		MediumLevelILOperation.MLIL_TRAP: [("vector", "int")],
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
		MediumLevelILOperation.MLIL_SET_VAR_SSA_FIELD: [
			("dest", "var_ssa_dest_and_src"),
			("prev", "var_ssa_dest_and_src"),
			("offset", "int"),
			("src", "expr"),
		],
		MediumLevelILOperation.MLIL_SET_VAR_SPLIT_SSA: [("high", "var_ssa"), ("low", "var_ssa"), ("src", "expr")],
		MediumLevelILOperation.MLIL_SET_VAR_ALIASED: [
			("dest", "var_ssa_dest_and_src"),
			("prev", "var_ssa_dest_and_src"),
			("src", "expr"),
		],
		MediumLevelILOperation.MLIL_SET_VAR_ALIASED_FIELD: [
			("dest", "var_ssa_dest_and_src"),
			("prev", "var_ssa_dest_and_src"),
			("offset", "int"),
			("src", "expr"),
		],
		MediumLevelILOperation.MLIL_VAR_SSA: [("var", "var_ssa")],
		MediumLevelILOperation.MLIL_VAR_SSA_FIELD: [("src", "var_ssa"), ("offset", "int")],
		MediumLevelILOperation.MLIL_VAR_ALIASED: [("src", "var_ssa")],
		MediumLevelILOperation.MLIL_VAR_ALIASED_FIELD: [("src", "var_ssa"), ("offset", "int")],
		MediumLevelILOperation.MLIL_VAR_SPLIT_SSA: [("high", "var_ssa"), ("low", "var_ssa")],
		MediumLevelILOperation.MLIL_ASSERT_SSA: [("src", "var_ssa"), ("constraint", "constraint")],
		MediumLevelILOperation.MLIL_FORCE_VER_SSA: [("dest", "var_ssa"), ("src", "var_ssa"), ("reason", "int")],
		MediumLevelILOperation.MLIL_CALL_SSA: [
			("output", "var_ssa_list"),
			("output_dest_memory", "int"),
			("dest", "expr"),
			("params", "expr_list"),
			("src_memory", "int"),
		],
		MediumLevelILOperation.MLIL_CALL_UNTYPED_SSA: [
			("output", "var_ssa_list"),
			("output_dest_memory", "int"),
			("dest", "expr"),
			("params", "expr_list"),
			("params_src_memory", "int"),
			("stack", "expr"),
		],
		MediumLevelILOperation.MLIL_SYSCALL_SSA: [
			("output", "var_ssa_list"),
			("output_dest_memory", "int"),
			("params", "expr_list"),
			("src_memory", "int"),
		],
		MediumLevelILOperation.MLIL_SYSCALL_UNTYPED_SSA: [
			("output", "var_ssa_list"),
			("output_dest_memory", "int"),
			("params", "expr_list"),
			("params_src_memory", "int"),
			("stack", "expr"),
		],
		MediumLevelILOperation.MLIL_TAILCALL_SSA: [
			("output", "var_ssa_list"),
			("output_dest_memory", "int"),
			("dest", "expr"),
			("params", "expr_list"),
			("src_memory", "int"),
		],
		MediumLevelILOperation.MLIL_TAILCALL_UNTYPED_SSA: [
			("output", "var_ssa_list"),
			("output_dest_memory", "int"),
			("dest", "expr"),
			("params", "expr_list"),
			("params_src_memory", "int"),
			("stack", "expr"),
		],
		MediumLevelILOperation.MLIL_CALL_PARAM_SSA: [("src_memory", "int"), ("src", "expr_list")],
		MediumLevelILOperation.MLIL_CALL_OUTPUT_SSA: [("dest_memory", "int"), ("dest", "var_ssa_list")],
		MediumLevelILOperation.MLIL_VAR_OUTPUT_SSA: [("var", "var_ssa")],
		MediumLevelILOperation.MLIL_VAR_OUTPUT_SSA_FIELD: [
			("dest", "var_ssa_dest_and_src"),
			("prev", "var_ssa_dest_and_src"),
			("offset", "int"),
		],
		MediumLevelILOperation.MLIL_VAR_OUTPUT_ALIASED: [
			("dest", "var_ssa_dest_and_src"),
			("prev", "var_ssa_dest_and_src"),
		],
		MediumLevelILOperation.MLIL_VAR_OUTPUT_ALIASED_FIELD: [
			("dest", "var_ssa_dest_and_src"),
			("prev", "var_ssa_dest_and_src"),
			("offset", "int"),
		],
		MediumLevelILOperation.MLIL_MEMORY_INTRINSIC_OUTPUT_SSA: [("dest_memory", "int"), ("output", "var_ssa_list")],
		MediumLevelILOperation.MLIL_LOAD_SSA: [("src", "expr"), ("src_memory", "int")],
		MediumLevelILOperation.MLIL_LOAD_STRUCT_SSA: [("src", "expr"), ("offset", "int"), ("src_memory", "int")],
		MediumLevelILOperation.MLIL_STORE_SSA: [
			("dest", "expr"),
			("dest_memory", "int"),
			("src_memory", "int"),
			("src", "expr"),
		],
		MediumLevelILOperation.MLIL_STORE_STRUCT_SSA: [
			("dest", "expr"),
			("offset", "int"),
			("dest_memory", "int"),
			("src_memory", "int"),
			("src", "expr"),
		],
		MediumLevelILOperation.MLIL_INTRINSIC_SSA: [
			("output", "var_ssa_list"),
			("intrinsic", "intrinsic"),
			("params", "expr_list"),
		],
		MediumLevelILOperation.MLIL_MEMORY_INTRINSIC_SSA: [
			("output", "var_ssa_list"),
			("dest_memory", "int"),
			("intrinsic", "intrinsic"),
			("params", "expr_list"),
			("src_memory", "int"),
		],
		MediumLevelILOperation.MLIL_FREE_VAR_SLOT_SSA: [
			("dest", "var_ssa_dest_and_src"),
			("prev", "var_ssa_dest_and_src"),
		],
		MediumLevelILOperation.MLIL_VAR_PHI: [("dest", "var_ssa"), ("src", "var_ssa_list")],
		MediumLevelILOperation.MLIL_MEM_PHI: [("dest_memory", "int"), ("src_memory", "int_list")],
		MediumLevelILOperation.MLIL_BLOCK_TO_EXPAND: [("exprs", "expr_list")],
		MediumLevelILOperation.MLIL_BSWAP: [("src", "expr")],
		MediumLevelILOperation.MLIL_POPCNT: [("src", "expr")],
		MediumLevelILOperation.MLIL_CLZ: [("src", "expr")],
		MediumLevelILOperation.MLIL_CTZ: [("src", "expr")],
		MediumLevelILOperation.MLIL_RBIT: [("src", "expr")],
		MediumLevelILOperation.MLIL_CLS: [("src", "expr")],
		MediumLevelILOperation.MLIL_MINS: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_MAXS: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_MINU: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_MAXU: [("left", "expr"), ("right", "expr")],
		MediumLevelILOperation.MLIL_ABS: [("src", "expr")],
	}
	# END GENERATED mlil-operations

	@staticmethod
	def show_mlil_hierarchy():
		"""
		Opens a new tab showing the MLIL hierarchy which includes classes which can
		easily be used with isinstance to match multiple types of IL instructions.
		"""
		graph = flowgraph.FlowGraph()
		nodes = {}
		for instruction in ILInstruction.values():
			instruction.add_subgraph(graph, nodes)
		show_graph_report("MLIL Class Hierarchy Graph", graph)

	@classmethod
	def create(
	    cls, func: 'MediumLevelILFunction', expr_index: ExpressionIndex, instr_index: Optional[InstructionIndex] = None
	) -> 'MediumLevelILInstruction':
		assert func.arch is not None, "Attempted to create IL instruction with function missing an Architecture"
		inst = core.BNGetMediumLevelILByIndex(func.handle, expr_index)
		assert inst is not None, "core.BNGetMediumLevelILByIndex returned None"
		if instr_index is None:
			instr_index = core.BNGetMediumLevelILInstructionForExpr(func.handle, expr_index)
			assert instr_index is not None, "core.BNGetMediumLevelILInstructionForExpr returned None"
		instr = CoreMediumLevelILInstruction.from_BNMediumLevelILInstruction(inst)
		return ILInstruction[instr.operation](func, expr_index, instr, instr_index)  # type: ignore

	def copy_to(
		self, dest: 'MediumLevelILFunction',
		sub_expr_handler: Optional[Callable[['MediumLevelILInstruction'], ExpressionIndex]] = None
	) -> ExpressionIndex:
		"""
		``copy_to`` deep copies an expression into a new IL function.
		If provided, the function ``sub_expr_handler`` will be called on every copied sub-expression

		.. warning:: This function should ONLY be called as a part of a lifter or workflow. It will otherwise not do anything useful as analysis will not be running.

		:param MediumLevelILFunction dest: Function to copy the expression to
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

	def __eq__(self, other: 'MediumLevelILInstruction') -> bool:
		if not isinstance(other, MediumLevelILInstruction):
			return NotImplemented
		return self.function == other.function and self.expr_index == other.expr_index

	def __lt__(self, other: 'MediumLevelILInstruction') -> bool:
		if not isinstance(other, MediumLevelILInstruction):
			return NotImplemented
		return self.function == other.function and self.expr_index < other.expr_index

	def __le__(self, other: 'MediumLevelILInstruction') -> bool:
		if not isinstance(other, MediumLevelILInstruction):
			return NotImplemented
		return self.function == other.function and self.expr_index <= other.expr_index

	def __gt__(self, other: 'MediumLevelILInstruction') -> bool:
		if not isinstance(other, MediumLevelILInstruction):
			return NotImplemented
		return self.function == other.function and self.expr_index > other.expr_index

	def __ge__(self, other: 'MediumLevelILInstruction') -> bool:
		if not isinstance(other, MediumLevelILInstruction):
			return NotImplemented
		return self.function == other.function and self.expr_index >= other.expr_index

	def __hash__(self):
		return hash((self.function, self.expr_index))

	@property
	def operands(self) -> List[MediumLevelILOperandType]:
		"""
		Operands for the instruction

		Consider using more specific APIs for ``src``, ``dest``, ``params``, etc where appropriate.
		"""
		return list(map(lambda x: x[1], self.detailed_operands))

	@property
	def raw_operands(self) -> OperandsType:
		"""Raw operand expression indices as specified by the core structure (read-only)"""
		return self.instr.operands

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		"""
		Returns a list of tuples containing the name of the operand, the operand, and the type of the operand.
		Useful for iterating over all operands of an instruction and sub-instructions.
		"""
		return []

	def traverse(self, cb: Callable[['MediumLevelILInstruction', Any], Any], *args: Any, **kwargs: Any) -> Iterator[Any]:
		"""
		``traverse`` is a generator that allows you to traverse the MediumLevelILInstruction in a depth-first manner. It will yield the
		result of the callback function for each node in the tree. Arguments can be passed to the callback function using
		``args`` and ``kwargs``. See the `Developer Docs <https://docs.binary.ninja/dev/concepts.html#walking-ils>`_ for more examples.

		:param Callable[[MediumLevelILInstruction, Any], Any] cb: The callback function to call for each node in the MediumLevelILInstruction
		:param Any args: Custom user-defined arguments
		:param Any kwargs: Custom user-defined keyword arguments
		:return: An iterator of the results of the callback function
		:rtype: Iterator[Any]

		:Example:
			>>> def get_constant_less_than_value(inst: MediumLevelILInstruction, value: int) -> int:
			>>>     if isinstance(inst, Constant) and inst.constant < value:
			>>>         return inst.constant
			>>>
			>>> list(inst.traverse(get_constant_less_than_value, 10))
		"""
		if (result := cb(self, *args, **kwargs)) is not None:
			yield result
		for _, op, _ in self.detailed_operands:
			if isinstance(op, MediumLevelILInstruction):
				yield from op.traverse(cb, *args, **kwargs)
			elif isinstance(op, list) and all(isinstance(i, MediumLevelILInstruction) for i in op):
				for i in op:
					yield from i.traverse(cb, *args, **kwargs) # type: ignore

	@deprecation.deprecated(deprecated_in="4.0.4907", details="Use :py:func:`MediumLevelILInstruction.traverse` instead.")
	def visit_all(self, cb: MediumLevelILVisitorCallback,
	       name: str = "root", parent: Optional['MediumLevelILInstruction'] = None) -> bool:
		"""
		Visits all operands of this instruction and all operands of any sub-instructions.
		Using pre-order traversal.

		:param MediumLevelILVisitorCallback cb: Callback function that takes the name of the operand, the operand, operand type, and parent instruction
		:return: True if all instructions were visited, False if the callback returned False
		"""
		if cb(name, self, "MediumLevelILInstruction", parent) == False:
			return False
		for name, op, opType in self.detailed_operands:
			if isinstance(op, MediumLevelILInstruction):
				if not op.visit_all(cb, name, self):
					return False
			elif isinstance(op, list) and all(isinstance(i, MediumLevelILInstruction) for i in op):
				for i in op:
					if not i.visit_all(cb, name, self): # type: ignore
						return False
			elif cb(name, op, opType, self) == False:
				return False
		return True

	@deprecation.deprecated(deprecated_in="4.0.4907", details="Use :py:func:`MediumLevelILInstruction.traverse` instead.")
	def visit_operands(self, cb: MediumLevelILVisitorCallback,
	       name: str = "root", parent: Optional['MediumLevelILInstruction'] = None) -> bool:
		"""
		Visits all leaf operands of this instruction and any sub-instructions.

		:param MediumLevelILVisitorCallback cb: Callback function that takes the name of the operand, the operand, operand type, and parent instruction
		:return: True if all instructions were visited, False if the callback returned False
		"""
		for name, op, opType in self.detailed_operands:
			if isinstance(op, MediumLevelILInstruction):
				if not op.visit_operands(cb, name, self):
					return False
			elif isinstance(op, list) and all(isinstance(i, MediumLevelILInstruction) for i in op):
				for i in op:
					if not i.visit_operands(cb, name, self): # type: ignore
						return False
			elif cb(name, op, opType, self) == False:
				return False
		return True

	@deprecation.deprecated(deprecated_in="4.0.4907", details="Use :py:func:`MediumLevelILInstruction.traverse` instead.")
	def visit(self, cb: MediumLevelILVisitorCallback,
	       name: str = "root", parent: Optional['MediumLevelILInstruction'] = None) -> bool:
		"""
		Visits all MediumLevelILInstructions in the operands of this instruction and any sub-instructions.
		In the callback you provide, you likely only need to interact with the second argument (see the example below).

		:param MediumLevelILVisitorCallback cb: Callback function that takes the name of the operand, the operand, operand type, and parent instruction
		:return: True if all instructions were visited, False if the callback returned False

		:Example:
			>>> def visitor(_a, inst, _c, _d) -> bool:
			>>>     if isinstance(inst, Constant):
			>>>         print(f"Found constant: {inst.constant}")
			>>>         return False # Stop recursion (once we find a constant, don't recurse in to any sub-instructions (which there won't actually be any...))
			>>>     # Otherwise, keep recursing the subexpressions of this instruction; if no return value is provided, it'll keep descending
			>>>
			>>> # Finds all constants used in the program
			>>> for inst in current_mlil.instructions:
			>>>     inst.visit(visitor)
		"""
		if cb(name, self, "MediumLevelILInstruction", parent) == False:
			return False
		for name, op, _ in self.detailed_operands:
			if isinstance(op, MediumLevelILInstruction):
				if not op.visit(cb, name, self):
					return False
			elif isinstance(op, list) and all(isinstance(i, MediumLevelILInstruction) for i in op):
				for i in op:
					if not i.visit(cb, name, self): # type: ignore
						return False
		return True

	@property
	def tokens(self) -> TokenList:
		"""MLIL tokens (read-only)"""

		# Special case for the helper instructions which don't have tokens
		if isinstance(self, (MediumLevelILCallParam, MediumLevelILCallParamSsa)):
			return []

		count = ctypes.c_ulonglong()
		tokens = ctypes.POINTER(core.BNInstructionTextToken)()
		assert self.function.arch is not None, f"type(self.function): {type(self.function)} "
		result = core.BNGetMediumLevelILExprText(
		    self.function.handle, self.function.arch.handle, self.expr_index, tokens, count, None
		)
		assert result, "core.BNGetMediumLevelILExprText returned False"
		try:
			return function.InstructionTextToken._from_core_struct(tokens, count.value)
		finally:
			core.BNFreeInstructionText(tokens, count.value)

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
		return MediumLevelILInstruction.create(
		    ssa_func, ExpressionIndex(core.BNGetMediumLevelILSSAExprIndex(self.function.handle, self.expr_index))
		)

	@property
	def non_ssa_form(self) -> 'MediumLevelILInstruction':
		"""Non-SSA form of expression (read-only)"""
		non_ssa_func = self.function.non_ssa_form
		assert non_ssa_func is not None
		return MediumLevelILInstruction.create(
		    non_ssa_func,
		    ExpressionIndex(core.BNGetMediumLevelILNonSSAExprIndex(self.function.handle, self.expr_index))
		)

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
		return highlevelil.HighLevelILInstruction.create(self.function.high_level_il, expr, False)

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
			result.append(highlevelil.HighLevelILInstruction.create(self.function.high_level_il, expr, False))
		return result

	@property
	def ssa_memory_version(self) -> int:
		"""Version of active memory contents in SSA form for this instruction"""
		return core.BNGetMediumLevelILSSAMemoryVersionAtILInstruction(self.function.handle, self.instr_index)

	@property
	def ssa_memory_version_after(self) -> int:
		"""Version of active memory contents in SSA form after this instruction"""
		return core.BNGetMediumLevelILSSAMemoryVersionAfterILInstruction(self.function.handle, self.instr_index)

	@property
	def prefix_operands(self) -> List[MediumLevelILOperandType]:
		"""All operands in the expression tree in prefix order"""
		result: List[MediumLevelILOperandType] = [MediumLevelILOperationAndSize(self.operation, self.size)]
		for operand in self.operands:
			if isinstance(operand, MediumLevelILInstruction):
				result.extend(operand.prefix_operands)
			else:
				result.append(operand)
		return result

	@property
	def postfix_operands(self) -> List[MediumLevelILOperandType]:
		"""All operands in the expression tree in postfix order"""
		result: List[MediumLevelILOperandType] = []
		for operand in self.operands:
			if isinstance(operand, MediumLevelILInstruction):
				result.extend(operand.postfix_operands)
			else:
				result.append(operand)
		result.append(MediumLevelILOperationAndSize(self.operation, self.size))
		return result

	@property
	def instruction_operands(self) -> List['MediumLevelILInstruction']:
		return [i for i in self.operands if isinstance(i, MediumLevelILInstruction)]

	@property
	def vars_written(self) -> List[Union[variable.Variable, SSAVariable]]:
		"""List of variables written by instruction"""
		return []

	@property
	def vars_read(self) -> List[Union[variable.Variable, SSAVariable]]:
		"""List of variables read by instruction"""
		result = []
		for operand in self.operands:
			if isinstance(operand, (variable.Variable, SSAVariable)):
				result.append(operand)
			elif isinstance(operand, MediumLevelILInstruction):
				result += operand.vars_read
		return result

	@property
	def vars_address_taken(self) -> List[Union[variable.Variable, SSAVariable]]:
		"""Non-unique list of variables whose address is taken by instruction"""
		result = []
		for operand in self.instruction_operands:
			result.extend(operand.vars_address_taken)
		return result

	@property
	def expr_type(self) -> Optional['types.Type']:
		"""Type of expression"""
		result = core.BNGetMediumLevelILExprType(self.function.handle, self.expr_index)
		if result.type:
			platform = None
			if self.function.source_function:
				platform = self.function.source_function.platform
			return types.Type.create(
			    result.type, platform=platform, confidence=result.confidence
			)
		return None

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
		option_array, size = MediumLevelILInstruction._make_options_array(options)
		value = core.BNGetMediumLevelILPossibleExprValues(self.function.handle, self.expr_index, option_array, size)
		result = variable.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_ssa_var_possible_values(self, ssa_var: SSAVariable, options: List[DataFlowQueryOption] = []):
		var_data = ssa_var.var.to_BNVariable()
		option_array, size = MediumLevelILInstruction._make_options_array(options)
		value = core.BNGetMediumLevelILPossibleSSAVarValues(
		    self.function.handle, var_data, ssa_var.version, self.instr_index, option_array, size
		)
		result = variable.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_ssa_var_version(self, var: variable.CoreVariable) -> int:
		var_data = var.to_BNVariable()
		return core.BNGetMediumLevelILSSAVarVersionAtILInstruction(self.function.handle, var_data, self.instr_index)

	def get_ssa_var_version_after(self, var: variable.CoreVariable) -> int:
		var_data = var.to_BNVariable()
		return core.BNGetMediumLevelILSSAVarVersionAfterILInstruction(self.function.handle, var_data, self.instr_index)

	def get_var_for_reg(self, reg: 'architecture.RegisterType') -> variable.Variable:
		reg = self.function.arch.get_reg_index(reg)
		result = core.BNGetMediumLevelILVariableForRegisterAtInstruction(self.function.handle, reg, self.instr_index)
		return variable.Variable.from_BNVariable(self.function, result)

	def get_var_for_reg_after(self, reg: 'architecture.RegisterType') -> variable.Variable:
		reg = self.function.arch.get_reg_index(reg)
		result = core.BNGetMediumLevelILVariableForRegisterAfterInstruction(self.function.handle, reg, self.instr_index)
		return variable.Variable.from_BNVariable(self.function, result)

	def get_var_for_flag(self, flag: 'architecture.FlagType') -> variable.Variable:
		flag = self.function.arch.get_flag_index(flag)
		result = core.BNGetMediumLevelILVariableForFlagAtInstruction(self.function.handle, flag, self.instr_index)
		return variable.Variable.from_BNVariable(self.function, result)

	def get_var_for_flag_after(self, flag: 'architecture.FlagType') -> variable.Variable:
		flag = self.function.arch.get_flag_index(flag)
		result = core.BNGetMediumLevelILVariableForFlagAfterInstruction(self.function.handle, flag, self.instr_index)
		return variable.Variable.from_BNVariable(self.function, result)

	def get_var_for_stack_location(self, offset: int) -> variable.Variable:
		result = core.BNGetMediumLevelILVariableForStackLocationAtInstruction(
		    self.function.handle, offset, self.instr_index
		)
		return variable.Variable.from_BNVariable(self.function, result)

	def get_var_for_stack_location_after(self, offset: int) -> variable.Variable:
		result = core.BNGetMediumLevelILVariableForStackLocationAfterInstruction(
		    self.function.handle, offset, self.instr_index
		)
		return variable.Variable.from_BNVariable(self.function, result)

	def get_reg_value(self, reg: 'architecture.RegisterType') -> 'variable.RegisterValue':
		reg = self.function.arch.get_reg_index(reg)
		value = core.BNGetMediumLevelILRegisterValueAtInstruction(self.function.handle, reg, self.instr_index)
		result = variable.RegisterValue.from_BNRegisterValue(value, self.function.arch)
		return result

	def get_reg_value_after(self, reg: 'architecture.RegisterType') -> 'variable.RegisterValue':
		reg = self.function.arch.get_reg_index(reg)
		value = core.BNGetMediumLevelILRegisterValueAfterInstruction(self.function.handle, reg, self.instr_index)
		result = variable.RegisterValue.from_BNRegisterValue(value, self.function.arch)
		return result

	def get_possible_reg_values(
	    self, reg: 'architecture.RegisterType', options: Optional[List[DataFlowQueryOption]] = None
	) -> 'variable.PossibleValueSet':
		option_array, size = MediumLevelILInstruction._make_options_array(options)
		reg = self.function.arch.get_reg_index(reg)
		value = core.BNGetMediumLevelILPossibleRegisterValuesAtInstruction(
		    self.function.handle, reg, self.instr_index, option_array, size
		)
		result = variable.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_possible_reg_values_after(
	    self, reg: 'architecture.RegisterType', options: Optional[List[DataFlowQueryOption]] = None
	) -> 'variable.PossibleValueSet':
		reg = self.function.arch.get_reg_index(reg)
		option_array, size = MediumLevelILInstruction._make_options_array(options)
		value = core.BNGetMediumLevelILPossibleRegisterValuesAfterInstruction(
		    self.function.handle, reg, self.instr_index, option_array, size
		)
		result = variable.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_flag_value(self, flag: 'architecture.FlagType') -> 'variable.RegisterValue':
		flag = self.function.arch.get_flag_index(flag)
		value = core.BNGetMediumLevelILFlagValueAtInstruction(self.function.handle, flag, self.instr_index)
		result = variable.RegisterValue.from_BNRegisterValue(value, self.function.arch)
		return result

	def get_flag_value_after(self, flag: 'architecture.FlagType') -> 'variable.RegisterValue':
		flag = self.function.arch.get_flag_index(flag)
		value = core.BNGetMediumLevelILFlagValueAfterInstruction(self.function.handle, flag, self.instr_index)
		result = variable.RegisterValue.from_BNRegisterValue(value, self.function.arch)
		return result

	def get_possible_flag_values(
	    self, flag: 'architecture.FlagType', options: Optional[List[DataFlowQueryOption]] = None
	) -> 'variable.PossibleValueSet':
		flag = self.function.arch.get_flag_index(flag)
		option_array, size = MediumLevelILInstruction._make_options_array(options)
		value = core.BNGetMediumLevelILPossibleFlagValuesAtInstruction(
		    self.function.handle, flag, self.instr_index, option_array, size
		)
		result = variable.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_possible_flag_values_after(
	    self, flag: 'architecture.FlagType', options: Optional[List[DataFlowQueryOption]] = None
	) -> 'variable.PossibleValueSet':
		flag = self.function.arch.get_flag_index(flag)
		option_array, size = MediumLevelILInstruction._make_options_array(options)
		value = core.BNGetMediumLevelILPossibleFlagValuesAfterInstruction(
		    self.function.handle, flag, self.instr_index, option_array, size
		)
		result = variable.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_stack_contents(self, offset: int, size: int) -> 'variable.RegisterValue':
		value = core.BNGetMediumLevelILStackContentsAtInstruction(self.function.handle, offset, size, self.instr_index)
		result = variable.RegisterValue.from_BNRegisterValue(value, self.function.arch)
		return result

	def get_stack_contents_after(self, offset: int, size: int) -> 'variable.RegisterValue':
		value = core.BNGetMediumLevelILStackContentsAfterInstruction(
		    self.function.handle, offset, size, self.instr_index
		)
		result = variable.RegisterValue.from_BNRegisterValue(value, self.function.arch)
		return result

	def get_possible_stack_contents(
	    self, offset: int, size: int, options: Optional[List[DataFlowQueryOption]] = None
	) -> 'variable.PossibleValueSet':
		option_array, option_size = MediumLevelILInstruction._make_options_array(options)
		value = core.BNGetMediumLevelILPossibleStackContentsAtInstruction(
		    self.function.handle, offset, size, self.instr_index, option_array, option_size
		)
		result = variable.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_possible_stack_contents_after(
	    self, offset: int, size: int, options: Optional[List[DataFlowQueryOption]] = None
	) -> 'variable.PossibleValueSet':
		option_array, option_size = MediumLevelILInstruction._make_options_array(options)
		value = core.BNGetMediumLevelILPossibleStackContentsAfterInstruction(
		    self.function.handle, offset, size, self.instr_index, option_array, option_size
		)
		result = variable.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_branch_dependence(self, branch_instr: int) -> ILBranchDependence:
		return ILBranchDependence(
		    core.BNGetMediumLevelILBranchDependence(self.function.handle, self.instr_index, branch_instr)
		)

	def get_split_var_for_definition(self, var: variable.CoreVariable) -> variable.Variable:
		"""
		Gets the unique variable for a definition instruction. This unique variable can be passed
		to ``Function.split_var`` to split a variable at a definition. The given ``var`` is the
		assigned variable to query.

		:param Variable var: variable to query
		:rtype: Variable
		"""
		return variable.Variable(
		    self.function.source_function, var.source_type,
		    core.BNGetDefaultIndexForMediumLevelILVariableDefinition(
		        self.function.handle, var.to_BNVariable(), self.instr_index
		    ), var.storage
		)

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
	def source_location(self) -> ILSourceLocation:
		return ILSourceLocation.from_instruction(self)

	@property
	def core_operands(self) -> OperandsType:
		return self.instr.operands

	def _get_int(self, operand_index: int) -> int:
		value = self.instr.operands[operand_index]
		return (value & ((1 << 63) - 1)) - (value & (1 << 63))

	def _get_float(self, operand_index: int) -> float:
		value = self.instr.operands[operand_index]
		if self.instr.size == 4:
			return struct.unpack("f", struct.pack("I", value & 0xffffffff))[0]
		elif self.instr.size == 8:
			return struct.unpack("d", struct.pack("Q", value))[0]
		else:
			return float(value)

	def _get_constant_data(self, operand_index1: int, operand_index2: int) -> variable.ConstantData:
		state = variable.RegisterValueType(self.instr.operands[operand_index1])
		value = self.instr.operands[operand_index2]
		return variable.ConstantData(value, 0, state, core.max_confidence, self.instr.size, self.function.source_function)

	def _get_expr(self, operand_index: int) -> 'MediumLevelILInstruction':
		return MediumLevelILInstruction.create(self.function, ExpressionIndex(self.instr.operands[operand_index]))

	def _get_intrinsic(self, operand_index: int) -> 'lowlevelil.ILIntrinsic':
		assert self.function.arch is not None, "Attempting to create ILIntrinsic from function with no Architecture"
		return lowlevelil.ILIntrinsic(
		    self.function.arch, architecture.IntrinsicIndex(self.instr.operands[operand_index])
		)

	def _get_var(self, operand_index: int) -> variable.Variable:
		value = self.instr.operands[operand_index]
		return variable.Variable.from_identifier(self.function, value)

	def _get_var_ssa(self, operand_index1: int, operand_index2: int) -> SSAVariable:
		var = variable.Variable.from_identifier(self.function, self.instr.operands[operand_index1])
		version = self.instr.operands[operand_index2]
		return SSAVariable(var, version)

	def _get_int_list(self, operand_index: int) -> List[int]:
		count = ctypes.c_ulonglong()
		operand_list = core.BNMediumLevelILGetOperandList(self.function.handle, self.expr_index, operand_index, count)
		assert operand_list is not None, "core.BNMediumLevelILGetOperandList returned None"
		value: List[int] = []
		try:
			for j in range(count.value):
				value.append(operand_list[j])
			return value
		finally:
			core.BNMediumLevelILFreeOperandList(operand_list)

	def _get_var_list(self, operand_index1: int, operand_index2: int) -> List[variable.Variable]:
		# We keep this extra parameter around because when this function is called
		# the subclasses that call this don't use the next operand
		# without this parameter it looks like this operand is being skipped unintentionally
		# rather this operand is being skipped intentionally.
		_ = operand_index2
		count = ctypes.c_ulonglong()
		operand_list = core.BNMediumLevelILGetOperandList(self.function.handle, self.expr_index, operand_index1, count)
		assert operand_list is not None, "core.BNMediumLevelILGetOperandList returned None"
		value: List[variable.Variable] = []
		try:
			for j in range(count.value):
				value.append(variable.Variable.from_identifier(self.function, operand_list[j]))
			return value
		finally:
			core.BNMediumLevelILFreeOperandList(operand_list)

	def _get_var_ssa_list(self, operand_index1: int, _: int) -> List[SSAVariable]:
		count = ctypes.c_ulonglong()
		operand_list = core.BNMediumLevelILGetOperandList(self.function.handle, self.expr_index, operand_index1, count)
		assert operand_list is not None, "core.BNMediumLevelILGetOperandList returned None"
		value = []
		try:
			for j in range(count.value // 2):
				var_id = operand_list[j * 2]
				var_version = operand_list[(j*2) + 1]
				value.append(SSAVariable(variable.Variable.from_identifier(self.function, var_id), var_version))
			return value
		finally:
			core.BNMediumLevelILFreeOperandList(operand_list)

	def _get_expr_list(self, operand_index1: int, _: int) -> List['MediumLevelILInstruction']:
		count = ctypes.c_ulonglong()
		operand_list = core.BNMediumLevelILGetOperandList(self.function.handle, self.expr_index, operand_index1, count)
		assert operand_list is not None, "core.BNMediumLevelILGetOperandList returned None"
		value: List['MediumLevelILInstruction'] = []
		try:
			for j in range(count.value):
				value.append(MediumLevelILInstruction.create(self.function, operand_list[j], None))
			return value
		finally:
			core.BNMediumLevelILFreeOperandList(operand_list)

	def _get_target_map(self, operand_index1: int, _: int) -> Dict[int, int]:
		count = ctypes.c_ulonglong()
		operand_list = core.BNMediumLevelILGetOperandList(self.function.handle, self.expr_index, operand_index1, count)
		assert operand_list is not None, "core.BNMediumLevelILGetOperandList returned None"
		value: Dict[int, int] = {}
		try:
			for j in range(count.value // 2):
				key = operand_list[j * 2]
				target = operand_list[(j*2) + 1]
				value[key] = target
			return value
		finally:
			core.BNMediumLevelILFreeOperandList(operand_list)

	def _get_constraint(self, operand_index: int) -> variable.PossibleValueSet:
		value = core.BNGetCachedMediumLevelILPossibleValueSet(self.function.handle, self.instr.operands[operand_index])
		result = variable.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def _var_written_for_function_call_output(self) -> Optional[variable.Variable]:
		if isinstance(self, MediumLevelILReturnByRef):
			return self.src._var_written_for_function_call_output()
		if isinstance(self, MediumLevelILVarOutput):
			return self.dest
		if isinstance(self, MediumLevelILVarOutputField):
			return self.dest
		return None

	def _ssa_var_written_for_function_call_output(self) -> Optional[SSAVariable]:
		if isinstance(self, MediumLevelILReturnByRef):
			return self.src._ssa_var_written_for_function_call_output()
		if isinstance(self, MediumLevelILVarOutputSsa):
			return self.dest
		if isinstance(self, MediumLevelILVarOutputSsaField):
			return self.dest
		if isinstance(self, MediumLevelILVarOutputAliased):
			return self.dest
		if isinstance(self, MediumLevelILVarOutputAliasedField):
			return self.dest
		return None


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILConstBase(MediumLevelILInstruction, Constant):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILCallBase(MediumLevelILInstruction, Call):
	@property
	def output(self) -> List[Union[SSAVariable, variable.Variable]]:
		return NotImplemented

	@property
	def vars_written(self) -> List[Union[SSAVariable, variable.Variable]]:
		return self.output

	@property
	def params(self) -> List[Union[SSAVariable, variable.Variable, MediumLevelILInstruction]]:
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


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILUnaryBase(MediumLevelILInstruction, UnaryOperation):
	@property
	def src(self) -> MediumLevelILInstruction:
		return self._get_expr(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [("src", self.src, "MediumLevelILInstruction")]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILBinaryBase(MediumLevelILInstruction, BinaryOperation):
	@property
	def left(self) -> MediumLevelILInstruction:
		return self._get_expr(0)

	@property
	def right(self) -> MediumLevelILInstruction:
		return self._get_expr(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("left", self.left, "MediumLevelILInstruction"),
			("right", self.right, "MediumLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILComparisonBase(MediumLevelILBinaryBase, Comparison):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILCarryBase(MediumLevelILInstruction, Carry):
	@property
	def left(self) -> MediumLevelILInstruction:
		return self._get_expr(0)

	@property
	def right(self) -> MediumLevelILInstruction:
		return self._get_expr(1)

	@property
	def carry(self) -> MediumLevelILInstruction:
		return self._get_expr(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("left", self.left, "MediumLevelILInstruction"),
			("right", self.right, "MediumLevelILInstruction"),
			("carry", self.carry, "MediumLevelILInstruction"),
		]


class _CallOutput:
	@property
	def output(self) -> List[variable.Variable]:
		result = []
		for expr in self.output_exprs:
			var = expr._var_written_for_function_call_output()
			if var is not None:
				result.append(var)
		return result


class _CallSsaOutput:
	@property
	def output(self) -> List[SSAVariable]:
		return self.output_expr.dest


class _CallOutputSsaVars:
	@property
	def dest(self) -> List[SSAVariable]:
		result = []
		for expr in self.dest_exprs:
			var = expr._ssa_var_written_for_function_call_output()
			if var is not None:
				result.append(var)
		return result

	@property
	def vars_written(self) -> List[SSAVariable]:
		return self.dest


class _SetVarVars:
	@property
	def vars_read(self) -> List[Union[variable.Variable, SSAVariable]]:
		return self.src.vars_read

	@property
	def vars_written(self) -> List[variable.Variable]:
		return [self.dest]


class _SetVarSsaVars:
	@property
	def vars_read(self) -> List[Union[variable.Variable, SSAVariable]]:
		return self.src.vars_read

	@property
	def vars_written(self) -> List[SSAVariable]:
		return [self.dest]


class _SetVarFieldVars:
	@property
	def vars_read(self) -> List[SSAVariable]:
		return [self.prev, *self.src.vars_read]

	@property
	def vars_written(self) -> List[SSAVariable]:
		return [self.dest]


class _SetVarSplitVars:
	@property
	def vars_read(self) -> List[variable.Variable]:
		return self.src.vars_read

	@property
	def vars_written(self) -> List[variable.Variable]:
		return [self.high, self.low]


class _SetVarSplitSsaVars:
	@property
	def vars_read(self) -> List[Union[variable.Variable, SSAVariable]]:
		return self.src.vars_read

	@property
	def vars_written(self) -> List[SSAVariable]:
		return [self.high, self.low]


class _ForceVerVars:
	@property
	def vars_read(self) -> List[variable.Variable]:
		return [self.src]

	@property
	def vars_written(self) -> List[variable.Variable]:
		return [self.dest]


class _ForceVerSsaVars:
	@property
	def vars_read(self) -> List[SSAVariable]:
		return [self.src]

	@property
	def vars_written(self) -> List[SSAVariable]:
		return [self.dest]


class _VarOutputVars:
	@property
	def vars_read(self) -> List[variable.Variable]:
		return []

	@property
	def vars_written(self) -> List[variable.Variable]:
		return [self.dest]


class _VarOutputSsaVars:
	@property
	def vars_read(self) -> List[SSAVariable]:
		return []

	@property
	def vars_written(self) -> List[SSAVariable]:
		return [self.dest]


class _VarOutputFieldVars:
	@property
	def vars_read(self) -> List[SSAVariable]:
		return [self.prev]

	@property
	def vars_written(self) -> List[SSAVariable]:
		return [self.dest]


class _VarPhiVars:
	@property
	def vars_read(self) -> List[SSAVariable]:
		return self.src

	@property
	def vars_written(self) -> List[SSAVariable]:
		return [self.dest]


class _IntrinsicVars:
	@property
	def vars_read(self) -> List[variable.Variable]:
		result: List[variable.Variable] = []
		for param in self.params:
			result.extend(param.vars_read)
		return result

	@property
	def vars_written(self) -> List[variable.Variable]:
		return self.output


class _IntrinsicSsaVars:
	@property
	def vars_read(self) -> List[SSAVariable]:
		result: List[SSAVariable] = []
		for param in self.params:
			result.extend(param.vars_read)
		return result

	@property
	def vars_written(self) -> List[SSAVariable]:
		return self.output


class _AddressOfVars:
	@property
	def vars_address_taken(self) -> List[variable.Variable]:
		return [self.src]


class _ConstPtrString:
	@property
	def string(self) -> Optional[Tuple[str, StringType]]:
		return self.function.view.check_for_string_annotation_type(self.constant, True, True, 0)


class _ParamListFormatting:
	def __repr__(self):
		return f"<{type(self).__name__}: {self.src}>"


class _NestedParamListFormatting:
	def __repr__(self):
		return f"<{type(self).__name__}: {self.params}>"


class _MemoryIntrinsicOutputSsaFormatting:
	def __repr__(self):
		return f"<MediumLevelILMemoryIntrinsicOutputSsa: {self.dest_memory} {self.output}>"


# BEGIN GENERATED mlil-classes: from api/il, do not edit
@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILNop(MediumLevelILInstruction):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILSetVar(_SetVarVars, MediumLevelILInstruction, SetVar):
	@property
	def dest(self) -> variable.Variable:
		return self._get_var(0)

	@property
	def src(self) -> MediumLevelILInstruction:
		return self._get_expr(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("dest", self.dest, "Variable"),
			("src", self.src, "MediumLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILSetVarField(MediumLevelILInstruction, SetVar):
	@property
	def dest(self) -> variable.Variable:
		return self._get_var(0)

	@property
	def offset(self) -> int:
		return self._get_int(1)

	@property
	def src(self) -> MediumLevelILInstruction:
		return self._get_expr(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("dest", self.dest, "Variable"),
			("offset", self.offset, "int"),
			("src", self.src, "MediumLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILSetVarSplit(_SetVarSplitVars, MediumLevelILInstruction, SetVar):
	@property
	def high(self) -> variable.Variable:
		return self._get_var(0)

	@property
	def low(self) -> variable.Variable:
		return self._get_var(1)

	@property
	def src(self) -> MediumLevelILInstruction:
		return self._get_expr(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("high", self.high, "Variable"),
			("low", self.low, "Variable"),
			("src", self.src, "MediumLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILAssert(MediumLevelILInstruction):
	@property
	def src(self) -> variable.Variable:
		return self._get_var(0)

	@property
	def constraint(self) -> variable.PossibleValueSet:
		return self._get_constraint(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("src", self.src, "Variable"),
			("constraint", self.constraint, "PossibleValueSet"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILForceVer(_ForceVerVars, MediumLevelILInstruction):
	@property
	def dest(self) -> variable.Variable:
		return self._get_var(0)

	@property
	def src(self) -> variable.Variable:
		return self._get_var(1)

	@property
	def reason(self) -> ForceVersionReason:
		return ForceVersionReason(self._get_int(2))

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("dest", self.dest, "Variable"),
			("src", self.src, "Variable"),
			("reason", self.reason, "ForceVersionReason"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILLoad(MediumLevelILUnaryBase, Load):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILLoadStruct(MediumLevelILInstruction, Load):
	@property
	def src(self) -> MediumLevelILInstruction:
		return self._get_expr(0)

	@property
	def offset(self) -> int:
		return self._get_int(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("src", self.src, "MediumLevelILInstruction"),
			("offset", self.offset, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILStore(MediumLevelILInstruction, Store):
	@property
	def dest(self) -> MediumLevelILInstruction:
		return self._get_expr(0)

	@property
	def src(self) -> MediumLevelILInstruction:
		return self._get_expr(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("dest", self.dest, "MediumLevelILInstruction"),
			("src", self.src, "MediumLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILStoreStruct(MediumLevelILInstruction, Store):
	@property
	def dest(self) -> MediumLevelILInstruction:
		return self._get_expr(0)

	@property
	def offset(self) -> int:
		return self._get_int(1)

	@property
	def src(self) -> MediumLevelILInstruction:
		return self._get_expr(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("dest", self.dest, "MediumLevelILInstruction"),
			("offset", self.offset, "int"),
			("src", self.src, "MediumLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILVar(MediumLevelILInstruction, VariableInstruction):
	@property
	def src(self) -> variable.Variable:
		return self._get_var(0)

	@property
	def var(self) -> variable.Variable:
		return self.src

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("var", self.var, "Variable"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILVarField(MediumLevelILInstruction):
	@property
	def src(self) -> variable.Variable:
		return self._get_var(0)

	@property
	def offset(self) -> int:
		return self._get_int(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("src", self.src, "Variable"),
			("offset", self.offset, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILVarSplit(MediumLevelILInstruction):
	@property
	def high(self) -> variable.Variable:
		return self._get_var(0)

	@property
	def low(self) -> variable.Variable:
		return self._get_var(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("high", self.high, "Variable"),
			("low", self.low, "Variable"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILAddressOf(_AddressOfVars, MediumLevelILInstruction):
	@property
	def src(self) -> variable.Variable:
		return self._get_var(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("src", self.src, "Variable"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILAddressOfField(_AddressOfVars, MediumLevelILInstruction):
	@property
	def src(self) -> variable.Variable:
		return self._get_var(0)

	@property
	def offset(self) -> int:
		return self._get_int(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("src", self.src, "Variable"),
			("offset", self.offset, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILPassByRef(MediumLevelILUnaryBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILReturnByRef(MediumLevelILUnaryBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILConst(MediumLevelILConstBase):
	@property
	def constant(self) -> int:
		return self._get_int(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("constant", self.constant, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILConstData(MediumLevelILConstBase):
	@property
	def constant_data(self) -> variable.ConstantData:
		return self._get_constant_data(0, 1)

	@property
	def constant(self) -> variable.ConstantData:
		return self.constant_data

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("constant", self.constant, "ConstantData"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILConstPtr(_ConstPtrString, MediumLevelILConstBase):
	@property
	def constant(self) -> int:
		return self._get_int(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("constant", self.constant, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILExternPtr(MediumLevelILConstBase):
	@property
	def constant(self) -> int:
		return self._get_int(0)

	@property
	def offset(self) -> int:
		return self._get_int(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("constant", self.constant, "int"),
			("offset", self.offset, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILFloatConst(MediumLevelILConstBase, FloatingPoint):
	@property
	def constant(self) -> float:
		return self._get_float(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("constant", self.constant, "float"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILImport(MediumLevelILConstBase):
	@property
	def constant(self) -> int:
		return self._get_int(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("constant", self.constant, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILAdd(MediumLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILAdc(MediumLevelILCarryBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILSub(MediumLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILSbb(MediumLevelILCarryBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILAnd(MediumLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILOr(MediumLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILXor(MediumLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILLsl(MediumLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILLsr(MediumLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILAsr(MediumLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILRol(MediumLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILRlc(MediumLevelILCarryBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILRor(MediumLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILRrc(MediumLevelILCarryBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILMul(MediumLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILMuluDp(MediumLevelILBinaryBase, DoublePrecision):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILMulsDp(MediumLevelILBinaryBase, DoublePrecision, Signed):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILDivu(MediumLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILDivuDp(MediumLevelILBinaryBase, DoublePrecision):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILDivs(MediumLevelILBinaryBase, Arithmetic, Signed):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILDivsDp(MediumLevelILBinaryBase, DoublePrecision, Signed):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILModu(MediumLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILModuDp(MediumLevelILBinaryBase, DoublePrecision):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILMods(MediumLevelILBinaryBase, Arithmetic, Signed):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILModsDp(MediumLevelILBinaryBase, DoublePrecision, Signed):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILNeg(MediumLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILNot(MediumLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILSx(MediumLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILZx(MediumLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILLowPart(MediumLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILJump(MediumLevelILInstruction, Terminal):
	@property
	def dest(self) -> MediumLevelILInstruction:
		return self._get_expr(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("dest", self.dest, "MediumLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILJumpTo(MediumLevelILInstruction, Terminal):
	@property
	def dest(self) -> MediumLevelILInstruction:
		return self._get_expr(0)

	@property
	def targets(self) -> Dict[int, int]:
		return self._get_target_map(1, 2)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("dest", self.dest, "MediumLevelILInstruction"),
			("targets", self.targets, "Dict[int, int]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILRetHint(MediumLevelILInstruction, ControlFlow):
	@property
	def dest(self) -> MediumLevelILInstruction:
		return self._get_expr(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("dest", self.dest, "MediumLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILCall(_CallOutput, MediumLevelILCallBase, Localcall):
	@property
	def output_exprs(self) -> List[MediumLevelILInstruction]:
		return self._get_expr_list(0, 1)

	@property
	def dest(self) -> MediumLevelILInstruction:
		return self._get_expr(2)

	@property
	def params(self) -> List[MediumLevelILInstruction]:
		return self._get_expr_list(3, 4)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("output", self.output, "List[Variable]"),
			("dest", self.dest, "MediumLevelILInstruction"),
			("params", self.params, "List[MediumLevelILInstruction]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILCallUntyped(_CallOutput, MediumLevelILCallBase, Localcall):
	@property
	def output_exprs(self) -> List[MediumLevelILInstruction]:
		return self._get_expr_list(0, 1)

	@property
	def dest(self) -> MediumLevelILInstruction:
		return self._get_expr(2)

	@property
	def param(self) -> 'MediumLevelILCallParam':
		result = self._get_expr(3)
		assert isinstance(result, MediumLevelILCallParam)
		return result

	@property
	def params(self) -> List[MediumLevelILInstruction]:
		return self.param.src

	@property
	def stack(self) -> MediumLevelILInstruction:
		return self._get_expr(4)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("output", self.output, "List[Variable]"),
			("dest", self.dest, "MediumLevelILInstruction"),
			("params", self.params, "List[MediumLevelILInstruction]"),
			("stack", self.stack, "MediumLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILCallParam(_ParamListFormatting, MediumLevelILInstruction):
	@property
	def src(self) -> List[MediumLevelILInstruction]:
		return self._get_expr_list(0, 1)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("src", self.src, "List[MediumLevelILInstruction]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILSeparateParamList(_NestedParamListFormatting, MediumLevelILInstruction):
	@property
	def params(self) -> List[MediumLevelILInstruction]:
		return self._get_expr_list(0, 1)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("params", self.params, "List[MediumLevelILInstruction]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILSharedParamSlot(_NestedParamListFormatting, MediumLevelILInstruction):
	@property
	def params(self) -> List[MediumLevelILInstruction]:
		return self._get_expr_list(0, 1)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("params", self.params, "List[MediumLevelILInstruction]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILVarOutput(_VarOutputVars, MediumLevelILInstruction, RegisterStack):
	@property
	def dest(self) -> variable.Variable:
		return self._get_var(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("dest", self.dest, "Variable"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILVarOutputField(MediumLevelILInstruction, SetVar):
	@property
	def dest(self) -> variable.Variable:
		return self._get_var(0)

	@property
	def offset(self) -> int:
		return self._get_int(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("dest", self.dest, "Variable"),
			("offset", self.offset, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILStoreOutput(MediumLevelILInstruction, Store):
	@property
	def dest(self) -> MediumLevelILInstruction:
		return self._get_expr(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("dest", self.dest, "MediumLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILRet(MediumLevelILInstruction, Return):
	@property
	def src(self) -> List[MediumLevelILInstruction]:
		return self._get_expr_list(0, 1)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("src", self.src, "List[MediumLevelILInstruction]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILNoret(MediumLevelILInstruction, Terminal):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILIf(MediumLevelILInstruction, Terminal):
	@property
	def condition(self) -> MediumLevelILInstruction:
		return self._get_expr(0)

	@property
	def true(self) -> InstructionIndex:
		return InstructionIndex(self._get_int(1))

	@property
	def false(self) -> InstructionIndex:
		return InstructionIndex(self._get_int(2))

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("condition", self.condition, "MediumLevelILInstruction"),
			("true", self.true, "InstructionIndex"),
			("false", self.false, "InstructionIndex"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILGoto(MediumLevelILInstruction, Terminal):
	@property
	def dest(self) -> InstructionIndex:
		return InstructionIndex(self._get_int(0))

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("dest", self.dest, "InstructionIndex"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILCmpE(MediumLevelILComparisonBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILCmpNe(MediumLevelILComparisonBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILCmpSlt(MediumLevelILComparisonBase, Signed):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILCmpUlt(MediumLevelILComparisonBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILCmpSle(MediumLevelILComparisonBase, Signed):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILCmpUle(MediumLevelILComparisonBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILCmpSge(MediumLevelILComparisonBase, Signed):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILCmpUge(MediumLevelILComparisonBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILCmpSgt(MediumLevelILComparisonBase, Signed):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILCmpUgt(MediumLevelILComparisonBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILTestBit(MediumLevelILComparisonBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILBoolToInt(MediumLevelILUnaryBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILAddOverflow(MediumLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILSyscall(_CallOutput, MediumLevelILCallBase, Syscall):
	@property
	def output_exprs(self) -> List[MediumLevelILInstruction]:
		return self._get_expr_list(0, 1)

	@property
	def params(self) -> List[MediumLevelILInstruction]:
		return self._get_expr_list(2, 3)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("output", self.output, "List[Variable]"),
			("params", self.params, "List[MediumLevelILInstruction]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILSyscallUntyped(_CallOutput, MediumLevelILCallBase, Syscall):
	@property
	def output_exprs(self) -> List[MediumLevelILInstruction]:
		return self._get_expr_list(0, 1)

	@property
	def param(self) -> 'MediumLevelILCallParam':
		result = self._get_expr(2)
		assert isinstance(result, MediumLevelILCallParam)
		return result

	@property
	def params(self) -> List[MediumLevelILInstruction]:
		return self.param.src

	@property
	def stack(self) -> MediumLevelILInstruction:
		return self._get_expr(3)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("output", self.output, "List[Variable]"),
			("params", self.params, "List[MediumLevelILInstruction]"),
			("stack", self.stack, "MediumLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILTailcall(_CallOutput, MediumLevelILCallBase, Tailcall):
	@property
	def output_exprs(self) -> List[MediumLevelILInstruction]:
		return self._get_expr_list(0, 1)

	@property
	def dest(self) -> MediumLevelILInstruction:
		return self._get_expr(2)

	@property
	def params(self) -> List[MediumLevelILInstruction]:
		return self._get_expr_list(3, 4)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("output", self.output, "List[Variable]"),
			("dest", self.dest, "MediumLevelILInstruction"),
			("params", self.params, "List[MediumLevelILInstruction]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILTailcallUntyped(_CallOutput, MediumLevelILCallBase, Tailcall):
	@property
	def output_exprs(self) -> List[MediumLevelILInstruction]:
		return self._get_expr_list(0, 1)

	@property
	def dest(self) -> MediumLevelILInstruction:
		return self._get_expr(2)

	@property
	def param(self) -> 'MediumLevelILCallParam':
		result = self._get_expr(3)
		assert isinstance(result, MediumLevelILCallParam)
		return result

	@property
	def params(self) -> List[MediumLevelILInstruction]:
		return self.param.src

	@property
	def stack(self) -> MediumLevelILInstruction:
		return self._get_expr(4)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("output", self.output, "List[Variable]"),
			("dest", self.dest, "MediumLevelILInstruction"),
			("params", self.params, "List[MediumLevelILInstruction]"),
			("stack", self.stack, "MediumLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILIntrinsic(_IntrinsicVars, MediumLevelILInstruction, Intrinsic):
	@property
	def output(self) -> List[variable.Variable]:
		return self._get_var_list(0, 1)

	@property
	def intrinsic(self) -> 'lowlevelil.ILIntrinsic':
		return self._get_intrinsic(2)

	@property
	def params(self) -> List[MediumLevelILInstruction]:
		return self._get_expr_list(3, 4)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("output", self.output, "List[Variable]"),
			("intrinsic", self.intrinsic, "ILIntrinsic"),
			("params", self.params, "List[MediumLevelILInstruction]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILFreeVarSlot(MediumLevelILInstruction, RegisterStack):
	@property
	def dest(self) -> variable.Variable:
		return self._get_var(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("dest", self.dest, "Variable"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILBp(MediumLevelILInstruction, Terminal):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILTrap(MediumLevelILInstruction, Terminal):
	@property
	def vector(self) -> int:
		return self._get_int(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("vector", self.vector, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILUndef(MediumLevelILInstruction):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILUnimpl(MediumLevelILInstruction):
	@property
	def unknown(self) -> bool:
		return self._get_int(0) != 0


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILUnimplMem(MediumLevelILUnaryBase, Memory):
	@property
	def unknown(self) -> bool:
		return self._get_int(1) != 0


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILFadd(MediumLevelILBinaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILFsub(MediumLevelILBinaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILFmul(MediumLevelILBinaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILFdiv(MediumLevelILBinaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILFsqrt(MediumLevelILUnaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILFneg(MediumLevelILUnaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILFabs(MediumLevelILUnaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILFloatToInt(MediumLevelILUnaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILIntToFloat(MediumLevelILUnaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILFloatConv(MediumLevelILUnaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILRoundToInt(MediumLevelILUnaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILFloor(MediumLevelILUnaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILCeil(MediumLevelILUnaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILFtrunc(MediumLevelILUnaryBase, Arithmetic, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILFcmpE(MediumLevelILComparisonBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILFcmpNe(MediumLevelILComparisonBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILFcmpLt(MediumLevelILComparisonBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILFcmpLe(MediumLevelILComparisonBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILFcmpGe(MediumLevelILComparisonBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILFcmpGt(MediumLevelILComparisonBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILFcmpO(MediumLevelILComparisonBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILFcmpUo(MediumLevelILComparisonBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILSetVarSsa(_SetVarSsaVars, MediumLevelILInstruction, SetVar, SSA):
	@property
	def dest(self) -> SSAVariable:
		return self._get_var_ssa(0, 1)

	@property
	def src(self) -> MediumLevelILInstruction:
		return self._get_expr(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("dest", self.dest, "SSAVariable"),
			("src", self.src, "MediumLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILSetVarSsaField(_SetVarFieldVars, MediumLevelILInstruction, SetVar, SSA):
	@property
	def dest(self) -> SSAVariable:
		return self._get_var_ssa(0, 1)

	@property
	def prev(self) -> SSAVariable:
		return self._get_var_ssa(0, 2)

	@property
	def offset(self) -> int:
		return self._get_int(3)

	@property
	def src(self) -> MediumLevelILInstruction:
		return self._get_expr(4)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("dest", self.dest, "SSAVariable"),
			("prev", self.prev, "SSAVariable"),
			("offset", self.offset, "int"),
			("src", self.src, "MediumLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILSetVarSplitSsa(_SetVarSplitSsaVars, MediumLevelILInstruction, SetVar, SSA):
	@property
	def high(self) -> SSAVariable:
		return self._get_var_ssa(0, 1)

	@property
	def low(self) -> SSAVariable:
		return self._get_var_ssa(2, 3)

	@property
	def src(self) -> MediumLevelILInstruction:
		return self._get_expr(4)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("high", self.high, "SSAVariable"),
			("low", self.low, "SSAVariable"),
			("src", self.src, "MediumLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILSetVarAliased(_SetVarSsaVars, MediumLevelILInstruction, SetVar, SSA):
	@property
	def dest(self) -> SSAVariable:
		return self._get_var_ssa(0, 1)

	@property
	def prev(self) -> SSAVariable:
		return self._get_var_ssa(0, 2)

	@property
	def src(self) -> MediumLevelILInstruction:
		return self._get_expr(3)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("dest", self.dest, "SSAVariable"),
			("prev", self.prev, "SSAVariable"),
			("src", self.src, "MediumLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILSetVarAliasedField(_SetVarFieldVars, MediumLevelILInstruction, SetVar, SSA):
	@property
	def dest(self) -> SSAVariable:
		return self._get_var_ssa(0, 1)

	@property
	def prev(self) -> SSAVariable:
		return self._get_var_ssa(0, 2)

	@property
	def offset(self) -> int:
		return self._get_int(3)

	@property
	def src(self) -> MediumLevelILInstruction:
		return self._get_expr(4)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("dest", self.dest, "SSAVariable"),
			("prev", self.prev, "SSAVariable"),
			("offset", self.offset, "int"),
			("src", self.src, "MediumLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILVarSsa(MediumLevelILInstruction, SSAVariableInstruction):
	@property
	def src(self) -> SSAVariable:
		return self._get_var_ssa(0, 1)

	@property
	def var(self) -> SSAVariable:
		return self.src

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("var", self.var, "SSAVariable"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILVarSsaField(MediumLevelILInstruction, SSA):
	@property
	def src(self) -> SSAVariable:
		return self._get_var_ssa(0, 1)

	@property
	def offset(self) -> int:
		return self._get_int(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("src", self.src, "SSAVariable"),
			("offset", self.offset, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILVarAliased(MediumLevelILInstruction, SSA, AliasedVariableInstruction):
	@property
	def src(self) -> SSAVariable:
		return self._get_var_ssa(0, 1)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("src", self.src, "SSAVariable"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILVarAliasedField(MediumLevelILInstruction, SSA):
	@property
	def src(self) -> SSAVariable:
		return self._get_var_ssa(0, 1)

	@property
	def offset(self) -> int:
		return self._get_int(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("src", self.src, "SSAVariable"),
			("offset", self.offset, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILVarSplitSsa(MediumLevelILInstruction, SSA):
	@property
	def high(self) -> SSAVariable:
		return self._get_var_ssa(0, 1)

	@property
	def low(self) -> SSAVariable:
		return self._get_var_ssa(2, 3)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("high", self.high, "SSAVariable"),
			("low", self.low, "SSAVariable"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILAssertSsa(MediumLevelILInstruction, SSA):
	@property
	def src(self) -> SSAVariable:
		return self._get_var_ssa(0, 1)

	@property
	def constraint(self) -> variable.PossibleValueSet:
		return self._get_constraint(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("src", self.src, "SSAVariable"),
			("constraint", self.constraint, "PossibleValueSet"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILForceVerSsa(_ForceVerSsaVars, MediumLevelILInstruction, SSA):
	@property
	def dest(self) -> SSAVariable:
		return self._get_var_ssa(0, 1)

	@property
	def src(self) -> SSAVariable:
		return self._get_var_ssa(2, 3)

	@property
	def reason(self) -> ForceVersionReason:
		return ForceVersionReason(self._get_int(4))

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("dest", self.dest, "SSAVariable"),
			("src", self.src, "SSAVariable"),
			("reason", self.reason, "ForceVersionReason"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILCallSsa(_CallSsaOutput, MediumLevelILCallBase, Localcall, SSA):
	@property
	def output_expr(self) -> 'MediumLevelILCallOutputSsa':
		result = self._get_expr(0)
		assert isinstance(result, MediumLevelILCallOutputSsa)
		return result

	@property
	def output_exprs(self) -> List[MediumLevelILInstruction]:
		return self.output_expr.dest_exprs

	@property
	def output_dest_memory(self) -> int:
		return self.output_expr.dest_memory

	@property
	def dest(self) -> MediumLevelILInstruction:
		return self._get_expr(1)

	@property
	def params(self) -> List[MediumLevelILInstruction]:
		return self._get_expr_list(2, 3)

	@property
	def src_memory(self) -> int:
		return self._get_int(4)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("output", self.output, "List[SSAVariable]"),
			("output_dest_memory", self.output_dest_memory, "int"),
			("dest", self.dest, "MediumLevelILInstruction"),
			("params", self.params, "List[MediumLevelILInstruction]"),
			("src_memory", self.src_memory, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILCallUntypedSsa(_CallSsaOutput, MediumLevelILCallBase, Localcall, SSA):
	@property
	def output_expr(self) -> 'MediumLevelILCallOutputSsa':
		result = self._get_expr(0)
		assert isinstance(result, MediumLevelILCallOutputSsa)
		return result

	@property
	def output_exprs(self) -> List[MediumLevelILInstruction]:
		return self.output_expr.dest_exprs

	@property
	def output_dest_memory(self) -> int:
		return self.output_expr.dest_memory

	@property
	def dest(self) -> MediumLevelILInstruction:
		return self._get_expr(1)

	@property
	def param(self) -> 'MediumLevelILCallParamSsa':
		result = self._get_expr(2)
		assert isinstance(result, MediumLevelILCallParamSsa)
		return result

	@property
	def params(self) -> List[MediumLevelILInstruction]:
		return self.param.src

	@property
	def params_src_memory(self) -> int:
		return self.param.src_memory

	@property
	def stack(self) -> MediumLevelILInstruction:
		return self._get_expr(3)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("output", self.output, "List[SSAVariable]"),
			("output_dest_memory", self.output_dest_memory, "int"),
			("dest", self.dest, "MediumLevelILInstruction"),
			("params", self.params, "List[MediumLevelILInstruction]"),
			("params_src_memory", self.params_src_memory, "int"),
			("stack", self.stack, "MediumLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILSyscallSsa(_CallSsaOutput, MediumLevelILCallBase, Syscall, SSA):
	@property
	def output_expr(self) -> 'MediumLevelILCallOutputSsa':
		result = self._get_expr(0)
		assert isinstance(result, MediumLevelILCallOutputSsa)
		return result

	@property
	def output_exprs(self) -> List[MediumLevelILInstruction]:
		return self.output_expr.dest_exprs

	@property
	def output_dest_memory(self) -> int:
		return self.output_expr.dest_memory

	@property
	def params(self) -> List[MediumLevelILInstruction]:
		return self._get_expr_list(1, 2)

	@property
	def src_memory(self) -> int:
		return self._get_int(3)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("output", self.output, "List[SSAVariable]"),
			("output_dest_memory", self.output_dest_memory, "int"),
			("params", self.params, "List[MediumLevelILInstruction]"),
			("src_memory", self.src_memory, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILSyscallUntypedSsa(_CallSsaOutput, MediumLevelILCallBase, Syscall, SSA):
	@property
	def output_expr(self) -> 'MediumLevelILCallOutputSsa':
		result = self._get_expr(0)
		assert isinstance(result, MediumLevelILCallOutputSsa)
		return result

	@property
	def output_exprs(self) -> List[MediumLevelILInstruction]:
		return self.output_expr.dest_exprs

	@property
	def output_dest_memory(self) -> int:
		return self.output_expr.dest_memory

	@property
	def param(self) -> 'MediumLevelILCallParamSsa':
		result = self._get_expr(1)
		assert isinstance(result, MediumLevelILCallParamSsa)
		return result

	@property
	def params(self) -> List[MediumLevelILInstruction]:
		return self.param.src

	@property
	def params_src_memory(self) -> int:
		return self.param.src_memory

	@property
	def stack(self) -> MediumLevelILInstruction:
		return self._get_expr(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("output", self.output, "List[SSAVariable]"),
			("output_dest_memory", self.output_dest_memory, "int"),
			("params", self.params, "List[MediumLevelILInstruction]"),
			("params_src_memory", self.params_src_memory, "int"),
			("stack", self.stack, "MediumLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILTailcallSsa(_CallSsaOutput, MediumLevelILCallBase, Tailcall, SSA):
	@property
	def output_expr(self) -> 'MediumLevelILCallOutputSsa':
		result = self._get_expr(0)
		assert isinstance(result, MediumLevelILCallOutputSsa)
		return result

	@property
	def output_exprs(self) -> List[MediumLevelILInstruction]:
		return self.output_expr.dest_exprs

	@property
	def output_dest_memory(self) -> int:
		return self.output_expr.dest_memory

	@property
	def dest(self) -> MediumLevelILInstruction:
		return self._get_expr(1)

	@property
	def params(self) -> List[MediumLevelILInstruction]:
		return self._get_expr_list(2, 3)

	@property
	def src_memory(self) -> int:
		return self._get_int(4)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("output", self.output, "List[SSAVariable]"),
			("output_dest_memory", self.output_dest_memory, "int"),
			("dest", self.dest, "MediumLevelILInstruction"),
			("params", self.params, "List[MediumLevelILInstruction]"),
			("src_memory", self.src_memory, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILTailcallUntypedSsa(_CallSsaOutput, MediumLevelILCallBase, Tailcall, SSA):
	@property
	def output_expr(self) -> 'MediumLevelILCallOutputSsa':
		result = self._get_expr(0)
		assert isinstance(result, MediumLevelILCallOutputSsa)
		return result

	@property
	def output_exprs(self) -> List[MediumLevelILInstruction]:
		return self.output_expr.dest_exprs

	@property
	def output_dest_memory(self) -> int:
		return self.output_expr.dest_memory

	@property
	def dest(self) -> MediumLevelILInstruction:
		return self._get_expr(1)

	@property
	def param(self) -> 'MediumLevelILCallParamSsa':
		result = self._get_expr(2)
		assert isinstance(result, MediumLevelILCallParamSsa)
		return result

	@property
	def params(self) -> List[MediumLevelILInstruction]:
		return self.param.src

	@property
	def params_src_memory(self) -> int:
		return self.param.src_memory

	@property
	def stack(self) -> MediumLevelILInstruction:
		return self._get_expr(3)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("output", self.output, "List[SSAVariable]"),
			("output_dest_memory", self.output_dest_memory, "int"),
			("dest", self.dest, "MediumLevelILInstruction"),
			("params", self.params, "List[MediumLevelILInstruction]"),
			("params_src_memory", self.params_src_memory, "int"),
			("stack", self.stack, "MediumLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILCallParamSsa(_ParamListFormatting, MediumLevelILInstruction, SSA):
	@property
	def src_memory(self) -> int:
		return self._get_int(0)

	@property
	def src(self) -> List[MediumLevelILInstruction]:
		return self._get_expr_list(1, 2)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("src_memory", self.src_memory, "int"),
			("src", self.src, "List[MediumLevelILInstruction]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILCallOutputSsa(_CallOutputSsaVars, MediumLevelILInstruction, SSA):
	@property
	def dest_memory(self) -> int:
		return self._get_int(0)

	@property
	def dest_exprs(self) -> List[MediumLevelILInstruction]:
		return self._get_expr_list(1, 2)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("dest_memory", self.dest_memory, "int"),
			("dest", self.dest, "List[SSAVariable]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILVarOutputSsa(_VarOutputSsaVars, MediumLevelILInstruction, SSAVariableInstruction):
	@property
	def dest(self) -> SSAVariable:
		return self._get_var_ssa(0, 1)

	@property
	def var(self) -> SSAVariable:
		return self.dest

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("var", self.var, "SSAVariable"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILVarOutputSsaField(_VarOutputFieldVars, MediumLevelILInstruction, SetVar, SSA):
	@property
	def dest(self) -> SSAVariable:
		return self._get_var_ssa(0, 1)

	@property
	def prev(self) -> SSAVariable:
		return self._get_var_ssa(0, 2)

	@property
	def offset(self) -> int:
		return self._get_int(3)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("dest", self.dest, "SSAVariable"),
			("prev", self.prev, "SSAVariable"),
			("offset", self.offset, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILVarOutputAliased(_VarOutputSsaVars, MediumLevelILInstruction, SetVar, SSA):
	@property
	def dest(self) -> SSAVariable:
		return self._get_var_ssa(0, 1)

	@property
	def prev(self) -> SSAVariable:
		return self._get_var_ssa(0, 2)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("dest", self.dest, "SSAVariable"),
			("prev", self.prev, "SSAVariable"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILVarOutputAliasedField(_VarOutputFieldVars, MediumLevelILInstruction, SetVar, SSA):
	@property
	def dest(self) -> SSAVariable:
		return self._get_var_ssa(0, 1)

	@property
	def prev(self) -> SSAVariable:
		return self._get_var_ssa(0, 2)

	@property
	def offset(self) -> int:
		return self._get_int(3)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("dest", self.dest, "SSAVariable"),
			("prev", self.prev, "SSAVariable"),
			("offset", self.offset, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILMemoryIntrinsicOutputSsa(_MemoryIntrinsicOutputSsaFormatting, MediumLevelILInstruction, SSA):
	@property
	def dest_memory(self) -> int:
		return self._get_int(0)

	@property
	def output(self) -> List[SSAVariable]:
		return self._get_var_ssa_list(1, 2)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("dest_memory", self.dest_memory, "int"),
			("output", self.output, "List[SSAVariable]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILLoadSsa(MediumLevelILInstruction, Load, SSA):
	@property
	def src(self) -> MediumLevelILInstruction:
		return self._get_expr(0)

	@property
	def src_memory(self) -> int:
		return self._get_int(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("src", self.src, "MediumLevelILInstruction"),
			("src_memory", self.src_memory, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILLoadStructSsa(MediumLevelILInstruction, Load, SSA):
	@property
	def src(self) -> MediumLevelILInstruction:
		return self._get_expr(0)

	@property
	def offset(self) -> int:
		return self._get_int(1)

	@property
	def src_memory(self) -> int:
		return self._get_int(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("src", self.src, "MediumLevelILInstruction"),
			("offset", self.offset, "int"),
			("src_memory", self.src_memory, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILStoreSsa(MediumLevelILInstruction, Store, SSA):
	@property
	def dest(self) -> MediumLevelILInstruction:
		return self._get_expr(0)

	@property
	def dest_memory(self) -> int:
		return self._get_int(1)

	@property
	def src_memory(self) -> int:
		return self._get_int(2)

	@property
	def src(self) -> MediumLevelILInstruction:
		return self._get_expr(3)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("dest", self.dest, "MediumLevelILInstruction"),
			("dest_memory", self.dest_memory, "int"),
			("src_memory", self.src_memory, "int"),
			("src", self.src, "MediumLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILStoreStructSsa(MediumLevelILInstruction, Store, SSA):
	@property
	def dest(self) -> MediumLevelILInstruction:
		return self._get_expr(0)

	@property
	def offset(self) -> int:
		return self._get_int(1)

	@property
	def dest_memory(self) -> int:
		return self._get_int(2)

	@property
	def src_memory(self) -> int:
		return self._get_int(3)

	@property
	def src(self) -> MediumLevelILInstruction:
		return self._get_expr(4)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("dest", self.dest, "MediumLevelILInstruction"),
			("offset", self.offset, "int"),
			("dest_memory", self.dest_memory, "int"),
			("src_memory", self.src_memory, "int"),
			("src", self.src, "MediumLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILIntrinsicSsa(_IntrinsicSsaVars, MediumLevelILInstruction, SSA):
	@property
	def output(self) -> List[SSAVariable]:
		return self._get_var_ssa_list(0, 1)

	@property
	def intrinsic(self) -> 'lowlevelil.ILIntrinsic':
		return self._get_intrinsic(2)

	@property
	def params(self) -> List[MediumLevelILInstruction]:
		return self._get_expr_list(3, 4)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("output", self.output, "List[SSAVariable]"),
			("intrinsic", self.intrinsic, "ILIntrinsic"),
			("params", self.params, "List[MediumLevelILInstruction]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILMemoryIntrinsicSsa(_IntrinsicSsaVars, MediumLevelILInstruction, SSA):
	@property
	def output_expr(self) -> 'MediumLevelILMemoryIntrinsicOutputSsa':
		result = self._get_expr(0)
		assert isinstance(result, MediumLevelILMemoryIntrinsicOutputSsa)
		return result

	@property
	def output(self) -> List[SSAVariable]:
		return self.output_expr.output

	@property
	def dest_memory(self) -> int:
		return self.output_expr.dest_memory

	@property
	def intrinsic(self) -> 'lowlevelil.ILIntrinsic':
		return self._get_intrinsic(1)

	@property
	def params(self) -> List[MediumLevelILInstruction]:
		return self._get_expr_list(2, 3)

	@property
	def src_memory(self) -> int:
		return self._get_int(4)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("output", self.output, "List[SSAVariable]"),
			("dest_memory", self.dest_memory, "int"),
			("intrinsic", self.intrinsic, "ILIntrinsic"),
			("params", self.params, "List[MediumLevelILInstruction]"),
			("src_memory", self.src_memory, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILFreeVarSlotSsa(MediumLevelILInstruction, SSA, RegisterStack):
	@property
	def dest(self) -> SSAVariable:
		return self._get_var_ssa(0, 1)

	@property
	def prev(self) -> SSAVariable:
		return self._get_var_ssa(0, 2)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("dest", self.dest, "SSAVariable"),
			("prev", self.prev, "SSAVariable"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILVarPhi(_VarPhiVars, MediumLevelILInstruction, SetVar, Phi, SSA):
	@property
	def dest(self) -> SSAVariable:
		return self._get_var_ssa(0, 1)

	@property
	def src(self) -> List[SSAVariable]:
		return self._get_var_ssa_list(2, 3)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("dest", self.dest, "SSAVariable"),
			("src", self.src, "List[SSAVariable]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILMemPhi(MediumLevelILInstruction, Memory, Phi):
	@property
	def dest_memory(self) -> int:
		return self._get_int(0)

	@property
	def src_memory(self) -> List[int]:
		return self._get_int_list(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("dest_memory", self.dest_memory, "int"),
			("src_memory", self.src_memory, "List[int]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILBlockToExpand(MediumLevelILInstruction):
	@property
	def exprs(self) -> List[MediumLevelILInstruction]:
		return self._get_expr_list(0, 1)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("exprs", self.exprs, "List[MediumLevelILInstruction]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILBswap(MediumLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILPopcnt(MediumLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILClz(MediumLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILCtz(MediumLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILRbit(MediumLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILCls(MediumLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILMins(MediumLevelILBinaryBase, Arithmetic, Signed):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILMaxs(MediumLevelILBinaryBase, Arithmetic, Signed):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILMinu(MediumLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILMaxu(MediumLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILAbs(MediumLevelILUnaryBase, Arithmetic):
	pass


ILInstruction: Dict[MediumLevelILOperation, type[MediumLevelILInstruction]] = {
	MediumLevelILOperation.MLIL_NOP: MediumLevelILNop,
	MediumLevelILOperation.MLIL_SET_VAR: MediumLevelILSetVar,
	MediumLevelILOperation.MLIL_SET_VAR_FIELD: MediumLevelILSetVarField,
	MediumLevelILOperation.MLIL_SET_VAR_SPLIT: MediumLevelILSetVarSplit,
	MediumLevelILOperation.MLIL_ASSERT: MediumLevelILAssert,
	MediumLevelILOperation.MLIL_FORCE_VER: MediumLevelILForceVer,
	MediumLevelILOperation.MLIL_LOAD: MediumLevelILLoad,
	MediumLevelILOperation.MLIL_LOAD_STRUCT: MediumLevelILLoadStruct,
	MediumLevelILOperation.MLIL_STORE: MediumLevelILStore,
	MediumLevelILOperation.MLIL_STORE_STRUCT: MediumLevelILStoreStruct,
	MediumLevelILOperation.MLIL_VAR: MediumLevelILVar,
	MediumLevelILOperation.MLIL_VAR_FIELD: MediumLevelILVarField,
	MediumLevelILOperation.MLIL_VAR_SPLIT: MediumLevelILVarSplit,
	MediumLevelILOperation.MLIL_ADDRESS_OF: MediumLevelILAddressOf,
	MediumLevelILOperation.MLIL_ADDRESS_OF_FIELD: MediumLevelILAddressOfField,
	MediumLevelILOperation.MLIL_PASS_BY_REF: MediumLevelILPassByRef,
	MediumLevelILOperation.MLIL_RETURN_BY_REF: MediumLevelILReturnByRef,
	MediumLevelILOperation.MLIL_CONST: MediumLevelILConst,
	MediumLevelILOperation.MLIL_CONST_DATA: MediumLevelILConstData,
	MediumLevelILOperation.MLIL_CONST_PTR: MediumLevelILConstPtr,
	MediumLevelILOperation.MLIL_EXTERN_PTR: MediumLevelILExternPtr,
	MediumLevelILOperation.MLIL_FLOAT_CONST: MediumLevelILFloatConst,
	MediumLevelILOperation.MLIL_IMPORT: MediumLevelILImport,
	MediumLevelILOperation.MLIL_ADD: MediumLevelILAdd,
	MediumLevelILOperation.MLIL_ADC: MediumLevelILAdc,
	MediumLevelILOperation.MLIL_SUB: MediumLevelILSub,
	MediumLevelILOperation.MLIL_SBB: MediumLevelILSbb,
	MediumLevelILOperation.MLIL_AND: MediumLevelILAnd,
	MediumLevelILOperation.MLIL_OR: MediumLevelILOr,
	MediumLevelILOperation.MLIL_XOR: MediumLevelILXor,
	MediumLevelILOperation.MLIL_LSL: MediumLevelILLsl,
	MediumLevelILOperation.MLIL_LSR: MediumLevelILLsr,
	MediumLevelILOperation.MLIL_ASR: MediumLevelILAsr,
	MediumLevelILOperation.MLIL_ROL: MediumLevelILRol,
	MediumLevelILOperation.MLIL_RLC: MediumLevelILRlc,
	MediumLevelILOperation.MLIL_ROR: MediumLevelILRor,
	MediumLevelILOperation.MLIL_RRC: MediumLevelILRrc,
	MediumLevelILOperation.MLIL_MUL: MediumLevelILMul,
	MediumLevelILOperation.MLIL_MULU_DP: MediumLevelILMuluDp,
	MediumLevelILOperation.MLIL_MULS_DP: MediumLevelILMulsDp,
	MediumLevelILOperation.MLIL_DIVU: MediumLevelILDivu,
	MediumLevelILOperation.MLIL_DIVU_DP: MediumLevelILDivuDp,
	MediumLevelILOperation.MLIL_DIVS: MediumLevelILDivs,
	MediumLevelILOperation.MLIL_DIVS_DP: MediumLevelILDivsDp,
	MediumLevelILOperation.MLIL_MODU: MediumLevelILModu,
	MediumLevelILOperation.MLIL_MODU_DP: MediumLevelILModuDp,
	MediumLevelILOperation.MLIL_MODS: MediumLevelILMods,
	MediumLevelILOperation.MLIL_MODS_DP: MediumLevelILModsDp,
	MediumLevelILOperation.MLIL_NEG: MediumLevelILNeg,
	MediumLevelILOperation.MLIL_NOT: MediumLevelILNot,
	MediumLevelILOperation.MLIL_SX: MediumLevelILSx,
	MediumLevelILOperation.MLIL_ZX: MediumLevelILZx,
	MediumLevelILOperation.MLIL_LOW_PART: MediumLevelILLowPart,
	MediumLevelILOperation.MLIL_JUMP: MediumLevelILJump,
	MediumLevelILOperation.MLIL_JUMP_TO: MediumLevelILJumpTo,
	MediumLevelILOperation.MLIL_RET_HINT: MediumLevelILRetHint,
	MediumLevelILOperation.MLIL_CALL: MediumLevelILCall,
	MediumLevelILOperation.MLIL_CALL_UNTYPED: MediumLevelILCallUntyped,
	MediumLevelILOperation.MLIL_CALL_PARAM: MediumLevelILCallParam,
	MediumLevelILOperation.MLIL_SEPARATE_PARAM_LIST: MediumLevelILSeparateParamList,
	MediumLevelILOperation.MLIL_SHARED_PARAM_SLOT: MediumLevelILSharedParamSlot,
	MediumLevelILOperation.MLIL_VAR_OUTPUT: MediumLevelILVarOutput,
	MediumLevelILOperation.MLIL_VAR_OUTPUT_FIELD: MediumLevelILVarOutputField,
	MediumLevelILOperation.MLIL_STORE_OUTPUT: MediumLevelILStoreOutput,
	MediumLevelILOperation.MLIL_RET: MediumLevelILRet,
	MediumLevelILOperation.MLIL_NORET: MediumLevelILNoret,
	MediumLevelILOperation.MLIL_IF: MediumLevelILIf,
	MediumLevelILOperation.MLIL_GOTO: MediumLevelILGoto,
	MediumLevelILOperation.MLIL_CMP_E: MediumLevelILCmpE,
	MediumLevelILOperation.MLIL_CMP_NE: MediumLevelILCmpNe,
	MediumLevelILOperation.MLIL_CMP_SLT: MediumLevelILCmpSlt,
	MediumLevelILOperation.MLIL_CMP_ULT: MediumLevelILCmpUlt,
	MediumLevelILOperation.MLIL_CMP_SLE: MediumLevelILCmpSle,
	MediumLevelILOperation.MLIL_CMP_ULE: MediumLevelILCmpUle,
	MediumLevelILOperation.MLIL_CMP_SGE: MediumLevelILCmpSge,
	MediumLevelILOperation.MLIL_CMP_UGE: MediumLevelILCmpUge,
	MediumLevelILOperation.MLIL_CMP_SGT: MediumLevelILCmpSgt,
	MediumLevelILOperation.MLIL_CMP_UGT: MediumLevelILCmpUgt,
	MediumLevelILOperation.MLIL_TEST_BIT: MediumLevelILTestBit,
	MediumLevelILOperation.MLIL_BOOL_TO_INT: MediumLevelILBoolToInt,
	MediumLevelILOperation.MLIL_ADD_OVERFLOW: MediumLevelILAddOverflow,
	MediumLevelILOperation.MLIL_SYSCALL: MediumLevelILSyscall,
	MediumLevelILOperation.MLIL_SYSCALL_UNTYPED: MediumLevelILSyscallUntyped,
	MediumLevelILOperation.MLIL_TAILCALL: MediumLevelILTailcall,
	MediumLevelILOperation.MLIL_TAILCALL_UNTYPED: MediumLevelILTailcallUntyped,
	MediumLevelILOperation.MLIL_INTRINSIC: MediumLevelILIntrinsic,
	MediumLevelILOperation.MLIL_FREE_VAR_SLOT: MediumLevelILFreeVarSlot,
	MediumLevelILOperation.MLIL_BP: MediumLevelILBp,
	MediumLevelILOperation.MLIL_TRAP: MediumLevelILTrap,
	MediumLevelILOperation.MLIL_UNDEF: MediumLevelILUndef,
	MediumLevelILOperation.MLIL_UNIMPL: MediumLevelILUnimpl,
	MediumLevelILOperation.MLIL_UNIMPL_MEM: MediumLevelILUnimplMem,
	MediumLevelILOperation.MLIL_FADD: MediumLevelILFadd,
	MediumLevelILOperation.MLIL_FSUB: MediumLevelILFsub,
	MediumLevelILOperation.MLIL_FMUL: MediumLevelILFmul,
	MediumLevelILOperation.MLIL_FDIV: MediumLevelILFdiv,
	MediumLevelILOperation.MLIL_FSQRT: MediumLevelILFsqrt,
	MediumLevelILOperation.MLIL_FNEG: MediumLevelILFneg,
	MediumLevelILOperation.MLIL_FABS: MediumLevelILFabs,
	MediumLevelILOperation.MLIL_FLOAT_TO_INT: MediumLevelILFloatToInt,
	MediumLevelILOperation.MLIL_INT_TO_FLOAT: MediumLevelILIntToFloat,
	MediumLevelILOperation.MLIL_FLOAT_CONV: MediumLevelILFloatConv,
	MediumLevelILOperation.MLIL_ROUND_TO_INT: MediumLevelILRoundToInt,
	MediumLevelILOperation.MLIL_FLOOR: MediumLevelILFloor,
	MediumLevelILOperation.MLIL_CEIL: MediumLevelILCeil,
	MediumLevelILOperation.MLIL_FTRUNC: MediumLevelILFtrunc,
	MediumLevelILOperation.MLIL_FCMP_E: MediumLevelILFcmpE,
	MediumLevelILOperation.MLIL_FCMP_NE: MediumLevelILFcmpNe,
	MediumLevelILOperation.MLIL_FCMP_LT: MediumLevelILFcmpLt,
	MediumLevelILOperation.MLIL_FCMP_LE: MediumLevelILFcmpLe,
	MediumLevelILOperation.MLIL_FCMP_GE: MediumLevelILFcmpGe,
	MediumLevelILOperation.MLIL_FCMP_GT: MediumLevelILFcmpGt,
	MediumLevelILOperation.MLIL_FCMP_O: MediumLevelILFcmpO,
	MediumLevelILOperation.MLIL_FCMP_UO: MediumLevelILFcmpUo,
	MediumLevelILOperation.MLIL_SET_VAR_SSA: MediumLevelILSetVarSsa,
	MediumLevelILOperation.MLIL_SET_VAR_SSA_FIELD: MediumLevelILSetVarSsaField,
	MediumLevelILOperation.MLIL_SET_VAR_SPLIT_SSA: MediumLevelILSetVarSplitSsa,
	MediumLevelILOperation.MLIL_SET_VAR_ALIASED: MediumLevelILSetVarAliased,
	MediumLevelILOperation.MLIL_SET_VAR_ALIASED_FIELD: MediumLevelILSetVarAliasedField,
	MediumLevelILOperation.MLIL_VAR_SSA: MediumLevelILVarSsa,
	MediumLevelILOperation.MLIL_VAR_SSA_FIELD: MediumLevelILVarSsaField,
	MediumLevelILOperation.MLIL_VAR_ALIASED: MediumLevelILVarAliased,
	MediumLevelILOperation.MLIL_VAR_ALIASED_FIELD: MediumLevelILVarAliasedField,
	MediumLevelILOperation.MLIL_VAR_SPLIT_SSA: MediumLevelILVarSplitSsa,
	MediumLevelILOperation.MLIL_ASSERT_SSA: MediumLevelILAssertSsa,
	MediumLevelILOperation.MLIL_FORCE_VER_SSA: MediumLevelILForceVerSsa,
	MediumLevelILOperation.MLIL_CALL_SSA: MediumLevelILCallSsa,
	MediumLevelILOperation.MLIL_CALL_UNTYPED_SSA: MediumLevelILCallUntypedSsa,
	MediumLevelILOperation.MLIL_SYSCALL_SSA: MediumLevelILSyscallSsa,
	MediumLevelILOperation.MLIL_SYSCALL_UNTYPED_SSA: MediumLevelILSyscallUntypedSsa,
	MediumLevelILOperation.MLIL_TAILCALL_SSA: MediumLevelILTailcallSsa,
	MediumLevelILOperation.MLIL_TAILCALL_UNTYPED_SSA: MediumLevelILTailcallUntypedSsa,
	MediumLevelILOperation.MLIL_CALL_PARAM_SSA: MediumLevelILCallParamSsa,
	MediumLevelILOperation.MLIL_CALL_OUTPUT_SSA: MediumLevelILCallOutputSsa,
	MediumLevelILOperation.MLIL_VAR_OUTPUT_SSA: MediumLevelILVarOutputSsa,
	MediumLevelILOperation.MLIL_VAR_OUTPUT_SSA_FIELD: MediumLevelILVarOutputSsaField,
	MediumLevelILOperation.MLIL_VAR_OUTPUT_ALIASED: MediumLevelILVarOutputAliased,
	MediumLevelILOperation.MLIL_VAR_OUTPUT_ALIASED_FIELD: MediumLevelILVarOutputAliasedField,
	MediumLevelILOperation.MLIL_MEMORY_INTRINSIC_OUTPUT_SSA: MediumLevelILMemoryIntrinsicOutputSsa,
	MediumLevelILOperation.MLIL_LOAD_SSA: MediumLevelILLoadSsa,
	MediumLevelILOperation.MLIL_LOAD_STRUCT_SSA: MediumLevelILLoadStructSsa,
	MediumLevelILOperation.MLIL_STORE_SSA: MediumLevelILStoreSsa,
	MediumLevelILOperation.MLIL_STORE_STRUCT_SSA: MediumLevelILStoreStructSsa,
	MediumLevelILOperation.MLIL_INTRINSIC_SSA: MediumLevelILIntrinsicSsa,
	MediumLevelILOperation.MLIL_MEMORY_INTRINSIC_SSA: MediumLevelILMemoryIntrinsicSsa,
	MediumLevelILOperation.MLIL_FREE_VAR_SLOT_SSA: MediumLevelILFreeVarSlotSsa,
	MediumLevelILOperation.MLIL_VAR_PHI: MediumLevelILVarPhi,
	MediumLevelILOperation.MLIL_MEM_PHI: MediumLevelILMemPhi,
	MediumLevelILOperation.MLIL_BLOCK_TO_EXPAND: MediumLevelILBlockToExpand,
	MediumLevelILOperation.MLIL_BSWAP: MediumLevelILBswap,
	MediumLevelILOperation.MLIL_POPCNT: MediumLevelILPopcnt,
	MediumLevelILOperation.MLIL_CLZ: MediumLevelILClz,
	MediumLevelILOperation.MLIL_CTZ: MediumLevelILCtz,
	MediumLevelILOperation.MLIL_RBIT: MediumLevelILRbit,
	MediumLevelILOperation.MLIL_CLS: MediumLevelILCls,
	MediumLevelILOperation.MLIL_MINS: MediumLevelILMins,
	MediumLevelILOperation.MLIL_MAXS: MediumLevelILMaxs,
	MediumLevelILOperation.MLIL_MINU: MediumLevelILMinu,
	MediumLevelILOperation.MLIL_MAXU: MediumLevelILMaxu,
	MediumLevelILOperation.MLIL_ABS: MediumLevelILAbs,
}


# Lists the slots `copy_expr_to` copies for each op. Ops that hold labels aren't listed because
# `copy_expr_to` copies them itself.
_COPY_LAYOUTS: Dict[MediumLevelILOperation, Tuple] = {
	MediumLevelILOperation.MLIL_NOP: (),
	MediumLevelILOperation.MLIL_SET_VAR: (
		"value",
		"expr",
	),
	MediumLevelILOperation.MLIL_SET_VAR_FIELD: (
		"value",
		"value",
		"expr",
	),
	MediumLevelILOperation.MLIL_SET_VAR_SPLIT: (
		"value",
		"value",
		"expr",
	),
	MediumLevelILOperation.MLIL_ASSERT: (
		"value",
		"constraint",
	),
	MediumLevelILOperation.MLIL_FORCE_VER: (
		"value",
		"value",
		"value",
	),
	MediumLevelILOperation.MLIL_LOAD: ("expr",),
	MediumLevelILOperation.MLIL_LOAD_STRUCT: (
		"expr",
		"value",
	),
	MediumLevelILOperation.MLIL_STORE: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_STORE_STRUCT: (
		"expr",
		"value",
		"expr",
	),
	MediumLevelILOperation.MLIL_VAR: ("value",),
	MediumLevelILOperation.MLIL_VAR_FIELD: (
		"value",
		"value",
	),
	MediumLevelILOperation.MLIL_VAR_SPLIT: (
		"value",
		"value",
	),
	MediumLevelILOperation.MLIL_ADDRESS_OF: ("value",),
	MediumLevelILOperation.MLIL_ADDRESS_OF_FIELD: (
		"value",
		"value",
	),
	MediumLevelILOperation.MLIL_PASS_BY_REF: ("expr",),
	MediumLevelILOperation.MLIL_RETURN_BY_REF: ("expr",),
	MediumLevelILOperation.MLIL_CONST: ("value",),
	MediumLevelILOperation.MLIL_CONST_DATA: (
		"value",
		"value",
	),
	MediumLevelILOperation.MLIL_CONST_PTR: ("value",),
	MediumLevelILOperation.MLIL_EXTERN_PTR: (
		"value",
		"value",
	),
	MediumLevelILOperation.MLIL_FLOAT_CONST: ("value",),
	MediumLevelILOperation.MLIL_IMPORT: ("value",),
	MediumLevelILOperation.MLIL_ADD: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_ADC: (
		"expr",
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_SUB: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_SBB: (
		"expr",
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_AND: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_OR: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_XOR: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_LSL: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_LSR: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_ASR: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_ROL: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_RLC: (
		"expr",
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_ROR: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_RRC: (
		"expr",
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_MUL: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_MULU_DP: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_MULS_DP: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_DIVU: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_DIVU_DP: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_DIVS: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_DIVS_DP: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_MODU: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_MODU_DP: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_MODS: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_MODS_DP: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_NEG: ("expr",),
	MediumLevelILOperation.MLIL_NOT: ("expr",),
	MediumLevelILOperation.MLIL_SX: ("expr",),
	MediumLevelILOperation.MLIL_ZX: ("expr",),
	MediumLevelILOperation.MLIL_LOW_PART: ("expr",),
	MediumLevelILOperation.MLIL_JUMP: ("expr",),
	MediumLevelILOperation.MLIL_RET_HINT: ("expr",),
	MediumLevelILOperation.MLIL_CALL: (
		"expr_list",
		"expr",
		"expr_list",
	),
	MediumLevelILOperation.MLIL_CALL_UNTYPED: (
		"expr_list",
		"expr",
		("part", MediumLevelILOperation.MLIL_CALL_PARAM, ("expr_list",)),
		"expr",
	),
	MediumLevelILOperation.MLIL_SEPARATE_PARAM_LIST: ("expr_list",),
	MediumLevelILOperation.MLIL_SHARED_PARAM_SLOT: ("expr_list",),
	MediumLevelILOperation.MLIL_VAR_OUTPUT: ("value",),
	MediumLevelILOperation.MLIL_VAR_OUTPUT_FIELD: (
		"value",
		"value",
	),
	MediumLevelILOperation.MLIL_STORE_OUTPUT: ("expr",),
	MediumLevelILOperation.MLIL_RET: ("expr_list",),
	MediumLevelILOperation.MLIL_NORET: (),
	MediumLevelILOperation.MLIL_CMP_E: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_CMP_NE: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_CMP_SLT: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_CMP_ULT: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_CMP_SLE: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_CMP_ULE: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_CMP_SGE: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_CMP_UGE: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_CMP_SGT: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_CMP_UGT: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_TEST_BIT: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_BOOL_TO_INT: ("expr",),
	MediumLevelILOperation.MLIL_ADD_OVERFLOW: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_SYSCALL: (
		"expr_list",
		"expr_list",
	),
	MediumLevelILOperation.MLIL_SYSCALL_UNTYPED: (
		"expr_list",
		("part", MediumLevelILOperation.MLIL_CALL_PARAM, ("expr_list",)),
		"expr",
	),
	MediumLevelILOperation.MLIL_TAILCALL: (
		"expr_list",
		"expr",
		"expr_list",
	),
	MediumLevelILOperation.MLIL_TAILCALL_UNTYPED: (
		"expr_list",
		"expr",
		("part", MediumLevelILOperation.MLIL_CALL_PARAM, ("expr_list",)),
		"expr",
	),
	MediumLevelILOperation.MLIL_INTRINSIC: (
		"list",
		"value",
		"expr_list",
	),
	MediumLevelILOperation.MLIL_FREE_VAR_SLOT: ("value",),
	MediumLevelILOperation.MLIL_BP: (),
	MediumLevelILOperation.MLIL_TRAP: ("value",),
	MediumLevelILOperation.MLIL_UNDEF: (),
	MediumLevelILOperation.MLIL_UNIMPL: ("value",),
	MediumLevelILOperation.MLIL_UNIMPL_MEM: (
		"expr",
		"value",
	),
	MediumLevelILOperation.MLIL_FADD: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_FSUB: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_FMUL: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_FDIV: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_FSQRT: ("expr",),
	MediumLevelILOperation.MLIL_FNEG: ("expr",),
	MediumLevelILOperation.MLIL_FABS: ("expr",),
	MediumLevelILOperation.MLIL_FLOAT_TO_INT: ("expr",),
	MediumLevelILOperation.MLIL_INT_TO_FLOAT: ("expr",),
	MediumLevelILOperation.MLIL_FLOAT_CONV: ("expr",),
	MediumLevelILOperation.MLIL_ROUND_TO_INT: ("expr",),
	MediumLevelILOperation.MLIL_FLOOR: ("expr",),
	MediumLevelILOperation.MLIL_CEIL: ("expr",),
	MediumLevelILOperation.MLIL_FTRUNC: ("expr",),
	MediumLevelILOperation.MLIL_FCMP_E: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_FCMP_NE: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_FCMP_LT: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_FCMP_LE: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_FCMP_GE: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_FCMP_GT: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_FCMP_O: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_FCMP_UO: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_SET_VAR_SSA: (
		"value",
		"value",
		"expr",
	),
	MediumLevelILOperation.MLIL_SET_VAR_SSA_FIELD: (
		"value",
		"value",
		"value",
		"value",
		"expr",
	),
	MediumLevelILOperation.MLIL_SET_VAR_SPLIT_SSA: (
		"value",
		"value",
		"value",
		"value",
		"expr",
	),
	MediumLevelILOperation.MLIL_SET_VAR_ALIASED: (
		"value",
		"value",
		"value",
		"expr",
	),
	MediumLevelILOperation.MLIL_SET_VAR_ALIASED_FIELD: (
		"value",
		"value",
		"value",
		"value",
		"expr",
	),
	MediumLevelILOperation.MLIL_VAR_SSA: (
		"value",
		"value",
	),
	MediumLevelILOperation.MLIL_VAR_SSA_FIELD: (
		"value",
		"value",
		"value",
	),
	MediumLevelILOperation.MLIL_VAR_ALIASED: (
		"value",
		"value",
	),
	MediumLevelILOperation.MLIL_VAR_ALIASED_FIELD: (
		"value",
		"value",
		"value",
	),
	MediumLevelILOperation.MLIL_VAR_SPLIT_SSA: (
		"value",
		"value",
		"value",
		"value",
	),
	MediumLevelILOperation.MLIL_ASSERT_SSA: (
		"value",
		"value",
		"constraint",
	),
	MediumLevelILOperation.MLIL_FORCE_VER_SSA: (
		"value",
		"value",
		"value",
		"value",
		"value",
	),
	MediumLevelILOperation.MLIL_CALL_SSA: (
		(
			"part",
			MediumLevelILOperation.MLIL_CALL_OUTPUT_SSA,
			(
				"value",
				"expr_list",
			),
		),
		"expr",
		"expr_list",
		"value",
	),
	MediumLevelILOperation.MLIL_CALL_UNTYPED_SSA: (
		(
			"part",
			MediumLevelILOperation.MLIL_CALL_OUTPUT_SSA,
			(
				"value",
				"expr_list",
			),
		),
		"expr",
		(
			"part",
			MediumLevelILOperation.MLIL_CALL_PARAM_SSA,
			(
				"value",
				"expr_list",
			),
		),
		"expr",
	),
	MediumLevelILOperation.MLIL_SYSCALL_SSA: (
		(
			"part",
			MediumLevelILOperation.MLIL_CALL_OUTPUT_SSA,
			(
				"value",
				"expr_list",
			),
		),
		"expr_list",
		"value",
	),
	MediumLevelILOperation.MLIL_SYSCALL_UNTYPED_SSA: (
		(
			"part",
			MediumLevelILOperation.MLIL_CALL_OUTPUT_SSA,
			(
				"value",
				"expr_list",
			),
		),
		(
			"part",
			MediumLevelILOperation.MLIL_CALL_PARAM_SSA,
			(
				"value",
				"expr_list",
			),
		),
		"expr",
	),
	MediumLevelILOperation.MLIL_TAILCALL_SSA: (
		(
			"part",
			MediumLevelILOperation.MLIL_CALL_OUTPUT_SSA,
			(
				"value",
				"expr_list",
			),
		),
		"expr",
		"expr_list",
		"value",
	),
	MediumLevelILOperation.MLIL_TAILCALL_UNTYPED_SSA: (
		(
			"part",
			MediumLevelILOperation.MLIL_CALL_OUTPUT_SSA,
			(
				"value",
				"expr_list",
			),
		),
		"expr",
		(
			"part",
			MediumLevelILOperation.MLIL_CALL_PARAM_SSA,
			(
				"value",
				"expr_list",
			),
		),
		"expr",
	),
	MediumLevelILOperation.MLIL_VAR_OUTPUT_SSA: (
		"value",
		"value",
	),
	MediumLevelILOperation.MLIL_VAR_OUTPUT_SSA_FIELD: (
		"value",
		"value",
		"value",
		"value",
	),
	MediumLevelILOperation.MLIL_VAR_OUTPUT_ALIASED: (
		"value",
		"value",
		"value",
	),
	MediumLevelILOperation.MLIL_VAR_OUTPUT_ALIASED_FIELD: (
		"value",
		"value",
		"value",
		"value",
	),
	MediumLevelILOperation.MLIL_LOAD_SSA: (
		"expr",
		"value",
	),
	MediumLevelILOperation.MLIL_LOAD_STRUCT_SSA: (
		"expr",
		"value",
		"value",
	),
	MediumLevelILOperation.MLIL_STORE_SSA: (
		"expr",
		"value",
		"value",
		"expr",
	),
	MediumLevelILOperation.MLIL_STORE_STRUCT_SSA: (
		"expr",
		"value",
		"value",
		"value",
		"expr",
	),
	MediumLevelILOperation.MLIL_INTRINSIC_SSA: (
		"list",
		"value",
		"expr_list",
	),
	MediumLevelILOperation.MLIL_MEMORY_INTRINSIC_SSA: (
		(
			"part",
			MediumLevelILOperation.MLIL_MEMORY_INTRINSIC_OUTPUT_SSA,
			(
				"value",
				"list",
			),
		),
		"value",
		"expr_list",
		"value",
	),
	MediumLevelILOperation.MLIL_FREE_VAR_SLOT_SSA: (
		"value",
		"value",
		"value",
	),
	MediumLevelILOperation.MLIL_VAR_PHI: (
		"value",
		"value",
		"list",
	),
	MediumLevelILOperation.MLIL_MEM_PHI: (
		"value",
		"list",
	),
	MediumLevelILOperation.MLIL_BLOCK_TO_EXPAND: ("expr_list",),
	MediumLevelILOperation.MLIL_BSWAP: ("expr",),
	MediumLevelILOperation.MLIL_POPCNT: ("expr",),
	MediumLevelILOperation.MLIL_CLZ: ("expr",),
	MediumLevelILOperation.MLIL_CTZ: ("expr",),
	MediumLevelILOperation.MLIL_RBIT: ("expr",),
	MediumLevelILOperation.MLIL_CLS: ("expr",),
	MediumLevelILOperation.MLIL_MINS: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_MAXS: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_MINU: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_MAXU: (
		"expr",
		"expr",
	),
	MediumLevelILOperation.MLIL_ABS: ("expr",),
}
# END GENERATED mlil-classes


class MediumLevelILExpr:
	"""
	``class MediumLevelILExpr`` hold the index of IL Expressions.

	.. note:: Deprecated. Use ExpressionIndex instead
	"""
	def __init__(self, index: int):
		self._index = index

	def __int__(self):
		return self._index

	@property
	def index(self):
		return self._index


class MediumLevelILFunction:
	"""
	``class MediumLevelILFunction`` contains the list of ExpressionIndex objects that make up a function. ExpressionIndex
	objects can be added to the MediumLevelILFunction by calling :func:`append` and passing the result of the various class
	methods which return ExpressionIndex objects.
	"""
	def __init__(
	    self,
	    arch: Optional['architecture.Architecture'] = None,
	    handle: Optional[core.BNMediumLevelILFunction] = None,
	    source_func: Optional['function.Function'] = None,
	    low_level_il: Optional['lowlevelil.LowLevelILFunction'] = None
	):
		_arch = arch
		_source_function = source_func
		if handle is not None:
			MLILHandle = ctypes.POINTER(core.BNMediumLevelILFunction)
			_handle = ctypes.cast(handle, MLILHandle)
			if _source_function is None:
				_source_function = function.Function(handle=core.BNGetMediumLevelILOwnerFunction(_handle))
			if _arch is None:
				_arch = _source_function.arch
		else:
			if low_level_il is None and source_func is None:
				raise ValueError("IL functions must be created with an associated function or LLIL function")

			if low_level_il is None:
				_source_function = source_func
			else:
				_source_function = low_level_il.source_function

			if _arch is None:
				_arch = low_level_il.arch
			func_handle = _source_function.handle
			llil_handle = low_level_il.handle if low_level_il is not None else None
			_handle = core.BNCreateMediumLevelILFunction(_arch.handle, func_handle, llil_handle)
		assert _source_function is not None
		assert _arch is not None
		assert _handle is not None
		self.handle = _handle
		self._arch = _arch
		self._source_function = _source_function

		self._mlil_to_mlil_expr_map: dict['MediumLevelILInstruction', List[Tuple[ExpressionIndex, bool]]] = {}
		self._mlil_to_mlil_instr_map: dict['MediumLevelILInstruction', List[Tuple[InstructionIndex, bool]]] = {}
		self._llil_ssa_to_mlil_expr_map: dict['lowlevelil.LowLevelILInstruction', List[Tuple[ExpressionIndex, bool]]] = {}
		self._llil_ssa_to_mlil_instr_map: dict['lowlevelil.LowLevelILInstruction', List[Tuple[InstructionIndex, bool]]] = {}

	def __del__(self):
		if core is not None:
			core.BNFreeMediumLevelILFunction(self.handle)

	def __repr__(self):
		arch = self.source_function.arch
		form = ""
		if self.il_form in [
			FunctionGraphType.MappedMediumLevelILFunctionGraph,
			FunctionGraphType.MappedMediumLevelILSSAFormFunctionGraph,
		]:
			form += " mapped mlil"
		if self.il_form in [
			FunctionGraphType.MediumLevelILSSAFormFunctionGraph,
			FunctionGraphType.MappedMediumLevelILSSAFormFunctionGraph,
		]:
			form += " ssa form"
		if arch:
			return f"<MediumLevelILFunction{form}: {arch.name}@{self.source_function.start:#x}>"
		else:
			return f"<MediumLevelILFunction{form}: {self.source_function.start:#x}>"

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
		elif isinstance(i, MediumLevelILInstruction):  # for backwards compatibility
			return i
		if i < -len(self) or i >= len(self):
			raise IndexError("index out of range")
		if i < 0:
			i = len(self) + i
		return MediumLevelILInstruction.create(
		    self, ExpressionIndex(core.BNGetMediumLevelILIndexForInstruction(self.handle, i)), i
		)

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
	def current_address(self, value: int) -> None:
		core.BNMediumLevelILSetCurrentAddress(self.handle, self._arch.handle, value)

	def set_current_address(self, value: int, arch: Optional['architecture.Architecture'] = None) -> None:
		_arch = arch
		if _arch is None:
			_arch = self._arch
		core.BNMediumLevelILSetCurrentAddress(self.handle, _arch.handle, value)

	def _basic_block_list(self):
		count = ctypes.c_ulonglong()
		blocks = core.BNGetMediumLevelILBasicBlockList(self.handle, count)
		assert blocks is not None, "core.BNGetMediumLevelILBasicBlockList returned None"
		return count, blocks

	def _instantiate_block(self, handle):
		return MediumLevelILBasicBlock(handle, self, self.view)

	@property
	def basic_blocks(self) -> 'function.MediumLevelILBasicBlockList':
		return function.MediumLevelILBasicBlockList(self)

	def get_basic_block_at(self, index: int) -> Optional['MediumLevelILBasicBlock']:
		"""
		``get_basic_block_at`` returns the BasicBlock at the given MLIL instruction ``index``.

		:param int index: Index of the MLIL instruction of the BasicBlock to retrieve.
		:Example:
			>>> current_il_function.get_basic_block_at(current_il_index)
			<mlil block: x86@40-60>
		"""
		block = core.BNGetMediumLevelILBasicBlockForInstruction(self.handle, index)
		if not block:
			return None

		view = None
		if self._source_function is not None:
			view = self._source_function.view

		return MediumLevelILBasicBlock(block, self, view)

	@property
	def instructions(self) -> Generator[MediumLevelILInstruction, None, None]:
		"""A generator of mlil instructions of the current function"""
		for block in self.basic_blocks:
			yield from block

	def traverse(self, cb: Callable[['MediumLevelILInstruction', Any], Any], *args: Any, **kwargs: Any) -> Iterator[Any]:
		"""
		``traverse`` iterates through all the instructions in the MediumLevelILInstruction and calls the callback function for
		each instruction and sub-instruction. See the `Developer Docs <https://docs.binary.ninja/dev/concepts.html#walking-ils>`_ for more examples.

		:param Callable[[MediumLevelILInstruction, Any], Any] cb: Callback function that takes a HighLevelILInstruction and returns a value
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

	@deprecation.deprecated(deprecated_in="4.0.4907", details="Use :py:func:`MediumLevelILFunction.traverse` instead.")
	def visit(self, cb: MediumLevelILVisitorCallback) -> bool:
		"""
		Iterates over all the instructions in the function and calls the callback function
		for each instruction and each sub-instruction.

		:param MediumLevelILVisitorCallback cb: Callback function that takes the name of the operand, the operand, operand type, and parent instruction
		:return: True if all instructions were visited, False if the callback function returned False.
		"""
		for instr in self.instructions:
			if not instr.visit(cb):
				return False
		return True

	@deprecation.deprecated(deprecated_in="4.0.4907", details="Use :py:func:`MediumLevelILFunction.traverse` instead.")
	def visit_all(self, cb: MediumLevelILVisitorCallback) -> bool:
		"""
		Iterates over all the instructions in the function and calls the callback function for each instruction and their operands.

		:param MediumLevelILVisitorCallback cb: Callback function that takes the name of the operand, the operand, operand type, and parent instruction
		:return: True if all instructions were visited, False if the callback function returned False.
		"""
		for instr in self.instructions:
			if not instr.visit_all(cb):
				return False
		return True

	@deprecation.deprecated(deprecated_in="4.0.4907", details="Use :py:func:`MediumLevelILFunction.traverse` instead.")
	def visit_operands(self, cb: MediumLevelILVisitorCallback) -> bool:
		"""
		Iterates over all the instructions in the function and calls the callback function for each operand and
		 the operands of each sub-instruction.

		:param MediumLevelILVisitorCallback cb: Callback function that takes the name of the operand, the operand, operand type, and parent instruction
		:return: True if all instructions were visited, False if the callback function returned False.
		"""
		for instr in self.instructions:
			if not instr.visit_operands(cb):
				return False
		return True

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

	def get_instruction_start(self, addr: int, arch: Optional['architecture.Architecture'] = None) -> Optional[InstructionIndex]:
		_arch = arch
		if _arch is None:
			if self._arch is None:
				raise Exception("Attempting to get_instruction_start from a MLIL Function without an Architecture")
			_arch = self._arch
		result = core.BNMediumLevelILGetInstructionStart(self.handle, _arch.handle, addr)
		if result >= core.BNGetMediumLevelILInstructionCount(self.handle):
			return None
		return InstructionIndex(result)

	def expr(
	    self, operation: MediumLevelILOperation, a: int = 0, b: int = 0, c: int = 0, d: int = 0, e: int = 0,
	    size: int = 0,
	    source_location: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		_operation = operation
		if isinstance(operation, str):
			_operation = MediumLevelILOperation[operation]
		elif isinstance(operation, MediumLevelILOperation):
			_operation = operation.value
		if source_location is not None:
			index = ExpressionIndex(core.BNMediumLevelILAddExprWithLocation(
				self.handle,
				_operation,
				source_location.address,
				source_location.source_operand,
				size,
				a,
				b,
				c,
				d,
				e
			))
			self._record_mlil_to_mlil_expr_map(index, source_location)
			return index
		else:
			return ExpressionIndex(core.BNMediumLevelILAddExpr(self.handle, _operation, size, a, b, c, d, e))

	def get_expr_count(self) -> int:
		"""
		``get_expr_count`` gives a the total number of expressions in this IL function

		You can use this to enumerate all expressions in conjunction with :py:func:`get_expr`

		.. warning :: Not all IL expressions are valid, even if their index is within the bounds of the function,
		              they might not be used by the function and might not contain properly structured data.

		:return: The number of expressions in the function
		"""
		return core.BNGetMediumLevelILExprCount(self.handle)

	def get_expr(self, index: ExpressionIndex) -> Optional[MediumLevelILInstruction]:
		"""
		``get_expr`` retrieves the IL expression at a given expression index in the function.

		.. warning :: Not all IL expressions are valid, even if their index is within the bounds of the function,
		              they might not be used by the function and might not contain properly structured data.

		:param index: Index of desired expression in function
		:return: A MediumLevelILInstruction object for the expression, if it exists. Otherwise, None
		"""
		if index >= self.get_expr_count():
			return None

		return MediumLevelILInstruction.create(self, index)

	def copy_expr(self, original: MediumLevelILInstruction) -> ExpressionIndex:
		"""
		``copy_expr`` makes a shallow copy of the given IL expression, adding a new expression to the IL function.

		.. warning:: The copy will not copy any child expressions, but will instead reference them as well (by expression index).
		             This means that you cannot use this function to copy an expression tree to another function.
		             If you want to copy an expression tree, you should use :py:func:`MediumLevelILFunction.copy_expr_to`.
		             Metadata such as expression type and attributes are also not copied.

		:param MediumLevelILInstruction original: the original IL Instruction you want to copy
		:return: The index of the newly copied expression
		"""
		return self.expr(
			original.operation,
			original.raw_operands[0],
			original.raw_operands[1],
			original.raw_operands[2],
			original.raw_operands[3],
			original.raw_operands[4],
			original.size,
			original.source_location
		)

	def replace_expr(self, original: InstructionOrExpression, new: InstructionOrExpression) -> None:
		"""
		``replace_expr`` replace an existing IL instruction in-place with another one

		Both expressions must have been created on the same function. The original expression
		will be replaced completely and the new expression will not be modified.

		:param ExpressionIndex original: the ExpressionIndex to replace (may also be an expression index)
		:param ExpressionIndex new: the ExpressionIndex to add to the current LowLevelILFunction (may also be an expression index)
		:rtype: None
		"""
		if isinstance(original, MediumLevelILInstruction):
			assert original.function == self
			original = original.expr_index
		elif isinstance(original, int):
			original = ExpressionIndex(original)

		if isinstance(new, MediumLevelILInstruction):
			assert new.function == self
			new = new.expr_index
		elif isinstance(new, int):
			new = ExpressionIndex(new)

		core.BNReplaceMediumLevelILExpr(self.handle, original, new)

	def copy_expr_to(
		self,
		expr: MediumLevelILInstruction,
		dest: 'MediumLevelILFunction',
		sub_expr_handler: Optional[Callable[[MediumLevelILInstruction], ExpressionIndex]] = None
	) -> ExpressionIndex:
		"""
		``copy_expr_to`` deep copies an expression from this function into a target function
		If provided, the function ``sub_expr_handler`` will be called on every copied sub-expression

		.. warning:: This function should ONLY be called as a part of a lifter or workflow. It will otherwise not do anything useful as analysis will not be running.

		:param MediumLevelILInstruction expr: Expression in this function to copy
		:param MediumLevelILFunction dest: Function to copy the expression to
		:param sub_expr_handler: Optional function to call on every copied sub-expression
		:return: Index of the copied expression in the target function
		"""

		if sub_expr_handler is None:
			sub_expr_handler = lambda sub_expr: self.copy_expr_to(sub_expr, dest)
		new_index = self._copy_expr(expr, dest, sub_expr_handler)
		# Copy expression metadata as well
		dest.set_expr_attributes(new_index, expr.attributes)
		return new_index

	def _copy_expr(
		self, expr: MediumLevelILInstruction, dest: 'MediumLevelILFunction',
		sub_expr_handler: Callable[[MediumLevelILInstruction], ExpressionIndex]
	) -> ExpressionIndex:
		loc = ILSourceLocation.from_instruction(expr)

		# Rebuild branches so they target `dest`'s labels, because their targets are instruction indices in this
		# function.
		if expr.operation == MediumLevelILOperation.MLIL_JUMP_TO:
			expr: MediumLevelILJumpTo
			label_list = {}
			for a, b in expr.targets.items():
				label_a = dest.get_label_for_source_instruction(b)
				if label_a is None:
					return dest.jump(sub_expr_handler(expr.dest), loc)
				label_list[a] = label_a
			return dest.jump_to(sub_expr_handler(expr.dest), label_list, loc)
		if expr.operation == MediumLevelILOperation.MLIL_GOTO:
			expr: MediumLevelILGoto
			label_a = dest.get_label_for_source_instruction(expr.dest)
			if label_a is None:
				return dest.jump(dest.const_pointer(expr.function.arch.address_size, expr.function[expr.dest].address), loc)
			return dest.goto(label_a, loc)
		if expr.operation == MediumLevelILOperation.MLIL_IF:
			expr: MediumLevelILIf
			label_a = dest.get_label_for_source_instruction(expr.true)
			label_b = dest.get_label_for_source_instruction(expr.false)
			if label_a is None or label_b is None:
				return dest.undefined(loc)
			return dest.if_expr(sub_expr_handler(expr.condition), label_a, label_b, loc)

		layout = _COPY_LAYOUTS.get(expr.operation)
		if layout is None:
			raise NotImplementedError(f"unknown expr operation {expr.operation} in copy_expr_to")
		operands = self._copy_operands(expr, layout, dest, sub_expr_handler, loc)
		return dest.expr(expr.operation, *operands, size=expr.size, source_location=loc)

	def _copy_operands(
		self, expr: MediumLevelILInstruction, layout: Tuple, dest: 'MediumLevelILFunction',
		sub_expr_handler: Callable[[MediumLevelILInstruction], ExpressionIndex], loc: 'ILSourceLocation'
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
				exprs = [sub_expr_handler(sub_expr) for sub_expr in expr._get_expr_list(slot, slot + 1)]
				operands += [len(exprs), dest.add_operand_list(exprs)]
				slot += 2
			elif entry == "list":
				items = expr._get_int_list(slot)
				operands += [len(items), dest.add_operand_list(items)]
				slot += 2
			elif entry == "constraint":
				operands.append(dest.cache_possible_value_set(expr._get_constraint(slot)))
				slot += 1
			else:
				_, operation, part_layout = entry
				part = expr._get_expr(slot)
				part_operands = self._copy_operands(part, part_layout, dest, sub_expr_handler, loc)
				operands.append(dest.expr(operation, *part_operands, size=part.size, source_location=loc))
				slot += 1
		return operands

	def translate(
		self, expr_handler: Callable[['MediumLevelILFunction', 'MediumLevelILBasicBlock', 'MediumLevelILInstruction'], ExpressionIndex]
	) -> 'MediumLevelILFunction':
		"""
		``translate`` clones an IL function and modifies its expressions as specified by
		a given ``expr_handler``, returning the updated IL function.

		:param expr_handler: Function to modify an expression and copy it to the new function.
		                     The function should have the following signature:

		                     expr_handler(new_func: MediumLevelILFunction, old_block: MediumLevelILBasicBlock, old_instr: MediumLevelILInstruction) -> ExpressionIndex

		                     Where:
		                         - **new_func** (*MediumLevelILFunction*): New function to receive translated instructions
		                         - **old_block** (*MediumLevelILBasicBlock*): Original block containing old_instr
		                         - **old_instr** (*MediumLevelILInstruction*): Original instruction
		                         - **returns** (*ExpressionIndex*): Expression index of newly created instruction in ``new_func``
		:return: Cloned IL function with modifications
		"""

		propagated_func = MediumLevelILFunction(self.arch, low_level_il=self.low_level_il)
		propagated_func.prepare_to_copy_function(self)
		for block in self.basic_blocks:
			propagated_func.prepare_to_copy_block(block)
			for instr_index in range(block.start, block.end):
				instr: MediumLevelILInstruction = self[InstructionIndex(instr_index)]
				propagated_func.set_current_address(instr.address, block.arch)
				propagated_func.append(expr_handler(propagated_func, block, instr), ILSourceLocation.from_instruction(instr))

		return propagated_func

	def set_expr_attributes(self, expr: InstructionOrExpression, value: ILInstructionAttributeSet):
		"""
		``set_expr_attributes`` allows modification of instruction attributes but ONLY during lifting.

		.. warning:: This function should ONLY be called as a part of a lifter. It will otherwise not do anything useful as there's no way to trigger re-analysis of IL levels at this time.

		:param ExpressionIndex expr: the ExpressionIndex to replace (may also be an expression index)
		:param set(ILInstructionAttribute) value: the set of attributes to place on the instruction
		:rtype: None
		"""
		if isinstance(expr, MediumLevelILInstruction):
			expr = expr.expr_index
		elif isinstance(expr, int):
			expr = ExpressionIndex(expr)

		result = 0
		for flag in value:
			result |= flag.value
		core.BNSetMediumLevelILExprAttributes(self.handle, expr, result)

	def append(self, expr: ExpressionIndex, source_location: Optional['ILSourceLocation'] = None) -> InstructionIndex:
		"""
		``append`` adds the ExpressionIndex ``expr`` to the current MediumLevelILFunction.

		:param ExpressionIndex expr: the ExpressionIndex to add to the current MediumLevelILFunction
		:param ILSourceLocation source_location: Optional source location for the instruction
		:return: Index of added instruction in the current function
		:rtype: int
		"""
		index = InstructionIndex(core.BNMediumLevelILAddInstruction(self.handle, expr))
		self._record_mlil_to_mlil_instr_map(index, source_location)
		return index

	def _record_mlil_to_mlil_instr_map(self, index, source_location: 'ILSourceLocation'):
		# Update internal mappings to remember this
		if source_location is not None:
			if source_location.source_mlil_instruction is not None:
				if source_location.source_mlil_instruction not in self._mlil_to_mlil_instr_map:
					self._mlil_to_mlil_instr_map[source_location.source_mlil_instruction] = []
				self._mlil_to_mlil_instr_map[source_location.source_mlil_instruction].append((index, source_location.il_direct))
			if source_location.source_llil_instruction is not None \
				and source_location.source_llil_instruction.function.il_form == FunctionGraphType.LowLevelILSSAFormFunctionGraph:
				if source_location.source_llil_instruction not in self._llil_ssa_to_mlil_instr_map:
					self._llil_ssa_to_mlil_instr_map[source_location.source_llil_instruction] = []
				self._llil_ssa_to_mlil_instr_map[source_location.source_llil_instruction].append((index, source_location.il_direct))

	def _record_mlil_to_mlil_expr_map(self, index, source_location: 'ILSourceLocation'):
		# Update internal mappings to remember this
		if source_location.source_mlil_instruction is not None:
			if source_location.source_mlil_instruction not in self._mlil_to_mlil_expr_map:
				self._mlil_to_mlil_expr_map[source_location.source_mlil_instruction] = []
			self._mlil_to_mlil_expr_map[source_location.source_mlil_instruction].append((index, source_location.il_direct))
		if source_location.source_llil_instruction is not None \
			and source_location.source_llil_instruction.function.il_form == FunctionGraphType.LowLevelILSSAFormFunctionGraph:
			if source_location.source_llil_instruction not in self._llil_ssa_to_mlil_expr_map:
				self._llil_ssa_to_mlil_expr_map[source_location.source_llil_instruction] = []
			self._llil_ssa_to_mlil_expr_map[source_location.source_llil_instruction].append((index, source_location.il_direct))

	def _get_llil_ssa_to_mlil_instr_map(self, from_builders: bool) -> LLILSSAToMLILInstructionMapping:
		llil_ssa_to_mlil_instr_map = {}

		if from_builders:
			# TODO: Handle LLIL SSA -> MLIL mappings in case someone is brave enough to try
			# lifting LLILSSA->MLIL themselves instead of an MLIL->MLIL translation
			# (which is the only one I've seen people do so far)

			for (old_instr, new_indices) in self._mlil_to_mlil_instr_map.items():
				old_instr: MediumLevelILInstruction
				new_indices: List[InstructionIndex]

				# Look up the LLIL SSA instruction for the old instr in its function
				# And then store that mapping for the new function

				for (new_index, new_direct) in new_indices:
					# Instructions are always mapped 1 to 1. If the map is marked indirect
					# then just ignore it
					if new_direct:
						old_llil_ssa_index = old_instr.function.get_low_level_il_instruction_index(old_instr.instr_index)
						if old_llil_ssa_index is not None:
							llil_ssa_to_mlil_instr_map[old_llil_ssa_index] = new_index
		else:
			for instr in self.instructions:
				llil_ssa_index = self.get_low_level_il_instruction_index(instr.instr_index)
				llil_ssa_to_mlil_instr_map[llil_ssa_index] = instr.instr_index

		return llil_ssa_to_mlil_instr_map

	def _get_llil_ssa_to_mlil_expr_map(self, from_builders: bool) -> LLILSSAToMLILExpressionMapping:
		llil_ssa_to_mlil_expr_map = []

		# Memoize the reverse (LLIL-SSA -> MLIL) expr lookups, per LLIL-SSA function. The same LLIL-SSA expr is
		# reached from many MLIL exprs, and a reverse query derives its result by walking the LLIL-SSA use-def graph
		# rather than reading a stored table, so repeating it for each recurrence is what dominates a whole-function
		# map build.
		reverse_memo: Dict['lowlevelil.LowLevelILFunction', Dict[ExpressionIndex, Tuple[
			Optional[ExpressionIndex], List[ExpressionIndex]]]] = {}

		def reverse_lookup(llil_ssa, llil_ssa_expr):
			entries = reverse_memo.setdefault(llil_ssa, {})
			entry = entries.get(llil_ssa_expr)
			if entry is None:
				entry = (
					llil_ssa.get_medium_level_il_expr_index(llil_ssa_expr),
					llil_ssa.get_medium_level_il_expr_indexes(llil_ssa_expr)
				)
				entries[llil_ssa_expr] = entry
			return entry

		if from_builders:
			# TODO: Handle LLIL SSA -> MLIL mappings in case someone is brave enough to try
			# lifting LLILSSA->MLIL themselves instead of an MLIL->MLIL translation
			# (which is the only one I've seen people do so far)

			for (old_expr, new_indices) in self._mlil_to_mlil_expr_map.items():
				old_expr: MediumLevelILInstruction
				new_indices: List[ExpressionIndex]

				# Look up the LLIL SSA expression for the old expr in its function
				# And then store that mapping for the new function

				old_llil_ssa = old_expr.function.low_level_il.ssa_form
				old_llil_ssa_direct = old_expr.function.get_low_level_il_expr_index(old_expr.expr_index)
				old_llil_ssa_indices = old_expr.function.get_low_level_il_expr_indexes(old_expr.expr_index)
				for old_index in old_llil_ssa_indices:
					old_reverse_direct, old_reverse_all = reverse_lookup(old_llil_ssa, old_index)

					for (new_index, new_direct) in new_indices:
						lower_to_higher_direct = new_direct and old_reverse_direct == old_expr.expr_index
						higher_to_lower_direct = new_direct and old_index == old_llil_ssa_direct
						map_lower_to_higher = old_expr.expr_index in old_reverse_all
						map_higher_to_lower = True

						llil_ssa_to_mlil_expr_map.append(LLILSSAToMLILExpressionMap(
							old_index,
							new_index,
							map_lower_to_higher,
							map_higher_to_lower,
							lower_to_higher_direct,
							higher_to_lower_direct
						))
		else:
			llil_ssa = self.low_level_il.ssa_form
			for instr in self.instructions:
				for expr in instr.traverse(lambda e: e):
					llil_ssa_direct = self.get_low_level_il_expr_index(expr.expr_index)
					llil_ssa_indices = self.get_low_level_il_expr_indexes(expr.expr_index)
					for llil_ssa_index in llil_ssa_indices:
						reverse_direct, reverse_all = reverse_lookup(llil_ssa, llil_ssa_index)

						lower_to_higher_direct = reverse_direct == expr.expr_index
						higher_to_lower_direct = llil_ssa_index == llil_ssa_direct
						map_lower_to_higher = expr.expr_index in reverse_all
						map_higher_to_lower = True

						llil_ssa_to_mlil_expr_map.append(LLILSSAToMLILExpressionMap(
							llil_ssa_index,
							expr.expr_index,
							map_lower_to_higher,
							map_higher_to_lower,
							lower_to_higher_direct,
							higher_to_lower_direct
						))

		return llil_ssa_to_mlil_expr_map

	def _call_output_list(self, outputs: CallOutputList, loc: Optional['ILSourceLocation'] = None) -> List[ExpressionIndex]:
		result = []
		for output in outputs:
			if isinstance(output, variable.CoreVariable):
				result.append(self.var_output(0, output, loc))
			else:
				result.append(output)
		return result

	# BEGIN GENERATED mlil-builders: from api/il, do not edit
	def nop(self, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Does nothing.

		:param loc: The IL location this expression was added from
		:return: The expression ``nop``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_NOP, source_location=loc)

	def set_var(
		self, size: int, dest: 'variable.CoreVariable', src: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Sets variable ``dest`` to ``src``.

		:param size: The size of ``src`` in bytes
		:param dest: The variable to set
		:param src: The value to set it to
		:param loc: The IL location this expression was added from
		:return: The expression ``dest = src``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_SET_VAR, dest.identifier, src, size=size, source_location=loc)

	def set_var_field(
		self,
		size: int,
		dest: 'variable.CoreVariable',
		offset: int,
		src: ExpressionIndex,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Sets the ``size`` bytes at offset ``offset`` within variable ``dest`` to ``src``, leaving the rest
		of the variable as it was.

		:param size: The size of ``src`` in bytes
		:param dest: The variable to set part of
		:param offset: The offset of the part within the variable, in bytes
		:param src: The value to set the part to
		:param loc: The IL location this expression was added from
		:return: The expression ``dest:offset.<size> = src``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			MediumLevelILOperation.MLIL_SET_VAR_FIELD, dest.identifier, offset, src, size=size, source_location=loc
		)

	def set_var_split(
		self,
		size: int,
		hi: 'variable.CoreVariable',
		lo: 'variable.CoreVariable',
		src: ExpressionIndex,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Sets the pair of variables ``hi`` and ``lo``, as one value of ``2 * size`` bytes, to ``src``.

		:param size: The size of each variable in bytes
		:param hi: The variable that receives the high half
		:param lo: The variable that receives the low half
		:param src: The value to set them to
		:param loc: The IL location this expression was added from
		:return: The expression ``hi:lo = src``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			MediumLevelILOperation.MLIL_SET_VAR_SPLIT, hi.identifier, lo.identifier, src, size=size, source_location=loc
		)

	def assert_expr(
		self,
		size: int,
		src: 'variable.CoreVariable',
		constraint: 'variable.PossibleValueSet',
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Asserts that variable ``src`` holds one of the values ``constraint`` allows. Core inserts it where a
		user has set possible values for ``src``.

		:param size: The size of the variable in bytes
		:param src: The variable to constrain
		:param constraint: The values the variable may hold
		:param loc: The IL location this expression was added from
		:return: The expression ``ASSERT(src, constraint)``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			MediumLevelILOperation.MLIL_ASSERT,
			src.identifier,
			self.cache_possible_value_set(constraint),
			size=size,
			source_location=loc,
		)

	def force_ver(
		self,
		size: int,
		dest: 'variable.CoreVariable',
		src: 'variable.CoreVariable',
		reason: ForceVersionReason = ForceVersionReason.UserForceVersionReason,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Gives variable ``dest`` a new SSA version holding the value of ``src``. Analysis can then use this
		as a new variable definition site.

		:param size: The size of the variable in bytes
		:param dest: The variable to give a new version
		:param src: The variable whose value it takes
		:param reason: Why the new version is needed
		:param loc: The IL location this expression was added from
		:return: The expression ``FORCE_VER(dest = src)``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			MediumLevelILOperation.MLIL_FORCE_VER,
			dest.identifier,
			src.identifier,
			int(reason),
			size=size,
			source_location=loc,
		)

	def load(self, size: int, src: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Reads ``size`` bytes from memory at ``src``.

		:param size: The size of the result in bytes
		:param src: The address to read from
		:param loc: The IL location this expression was added from
		:return: The expression ``[src].<size>``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_LOAD, src, size=size, source_location=loc)

	def load_struct(
		self, size: int, src: ExpressionIndex, offset: int, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Reads ``size`` bytes from memory ``offset`` bytes past ``src``, such as a member of the structure it
		points to. Shows the member's name when the type of ``src`` has a member at ``offset``.

		:param size: The size of the result in bytes
		:param src: The base address
		:param offset: The offset from ``src``, in bytes
		:param loc: The IL location this expression was added from
		:return: The expression ``[src + offset].<size>``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_LOAD_STRUCT, src, offset, size=size, source_location=loc)

	def store(
		self, size: int, dest: ExpressionIndex, src: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Writes the ``size`` bytes of ``src`` to memory at ``dest``.

		:param size: The size of ``src`` in bytes
		:param dest: The address to write to
		:param src: The value to write
		:param loc: The IL location this expression was added from
		:return: The expression ``[dest].<size> = src``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_STORE, dest, src, size=size, source_location=loc)

	def store_struct(
		self,
		size: int,
		dest: ExpressionIndex,
		offset: int,
		src: ExpressionIndex,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Writes the ``size`` bytes of ``src`` to memory ``offset`` bytes past ``dest``, such as a member of
		the structure it points to. Shows the member's name when the type of ``dest`` has a member at
		``offset``.

		:param size: The size of ``src`` in bytes
		:param dest: The base address
		:param offset: The offset from ``dest``, in bytes
		:param src: The value to write
		:param loc: The IL location this expression was added from
		:return: The expression ``[dest + offset].<size> = src``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_STORE_STRUCT, dest, offset, src, size=size, source_location=loc)

	def var(self, size: int, src: 'variable.CoreVariable', loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Reads variable ``src``.

		:param size: The size of the result in bytes
		:param src: The variable to read
		:param loc: The IL location this expression was added from
		:return: The expression ``src``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_VAR, src.identifier, size=size, source_location=loc)

	def var_field(
		self, size: int, src: 'variable.CoreVariable', offset: int, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Reads the ``size`` bytes at offset ``offset`` within variable ``src``.

		:param size: The size of the result in bytes
		:param src: The variable to read part of
		:param offset: The offset of the part within the variable, in bytes
		:param loc: The IL location this expression was added from
		:return: The expression ``src:offset.<size>``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_VAR_FIELD, src.identifier, offset, size=size, source_location=loc)

	def var_split(
		self,
		size: int,
		hi: 'variable.CoreVariable',
		lo: 'variable.CoreVariable',
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Reads the pair of variables ``hi`` and ``lo`` as one value of ``2 * size`` bytes.

		:param size: The size of each variable in bytes
		:param hi: The variable that holds the high half
		:param lo: The variable that holds the low half
		:param loc: The IL location this expression was added from
		:return: The expression ``hi:lo``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			MediumLevelILOperation.MLIL_VAR_SPLIT, hi.identifier, lo.identifier, size=size, source_location=loc
		)

	def address_of(self, var: 'variable.CoreVariable', loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		The address of variable ``var``.

		:param var: The variable to take the address of
		:param loc: The IL location this expression was added from
		:return: The expression ``&var``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_ADDRESS_OF, var.identifier, source_location=loc)

	def address_of_field(
		self, var: 'variable.CoreVariable', offset: int, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		The address of the byte at offset ``offset`` within variable ``var``.

		:param var: The variable that holds the byte
		:param offset: The offset into the variable, in bytes
		:param loc: The IL location this expression was added from
		:return: The expression ``&var:offset``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_ADDRESS_OF_FIELD, var.identifier, offset, source_location=loc)

	def pass_by_ref(
		self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Passes ``value`` to a call by reference, as the calling convention requires. ``value`` is a pointer
		to the value. Only appears as a call's parameter.

		:param size: The size of the pointer in bytes
		:param value: The address of the value being passed
		:param loc: The IL location this expression was added from
		:return: The expression ``ref *value``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_PASS_BY_REF, value, size=size, source_location=loc)

	def return_by_ref(
		self, size: int, dest: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Receives a call's result in ``dest`` through a pointer the caller supplies. Only appears among a
		call's outputs.

		:param size: The size of the result in bytes
		:param dest: Where the result goes
		:param loc: The IL location this expression was added from
		:return: The expression ``ref dest``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_RETURN_BY_REF, dest, size=size, source_location=loc)

	def const(self, size: int, value: int, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		An integer constant.

		:param size: The size of the result in bytes
		:param value: The value
		:param loc: The IL location this expression was added from
		:return: The expression ``value``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_CONST, value, size=size, source_location=loc)

	def const_data(
		self, size: int, data: 'variable.ConstantData', loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Constant data that isn't a plain integer, such as a string or a value with known extension.

		:param size: The size of the result in bytes
		:param data: The constant data
		:param loc: The IL location this expression was added from
		:return: The expression ``data``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_CONST_DATA, data.type, data.value, size=size, source_location=loc)

	def const_pointer(self, size: int, value: int, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		A constant pointer to address ``value``.

		:param size: The size of the result in bytes
		:param value: The value
		:param loc: The IL location this expression was added from
		:return: The expression ``value``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_CONST_PTR, value, size=size, source_location=loc)

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
		return self.expr(MediumLevelILOperation.MLIL_EXTERN_PTR, value, offset, size=size, source_location=loc)

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
		return self.expr(MediumLevelILOperation.MLIL_FLOAT_CONST, value, size=size, source_location=loc)

	def imported_address(self, size: int, value: int, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		The constant address ``value`` of an imported symbol. Renders as the symbol's name where one is
		known.

		:param size: The size of the result in bytes
		:param value: The value
		:param loc: The IL location this expression was added from
		:return: The expression ``[value]``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_IMPORT, value, size=size, source_location=loc)

	def add(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Adds ``a`` and ``b``.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a + b``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_ADD, a, b, size=size, source_location=loc)

	def add_carry(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		carry: ExpressionIndex,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Adds ``a``, ``b`` and the carry ``carry``.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param carry: The carry in
		:param loc: The IL location this expression was added from
		:return: The expression ``adc.<size>(a, b, carry)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_ADC, a, b, carry, size=size, source_location=loc)

	def sub(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Subtracts ``b`` from ``a``.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a - b``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_SUB, a, b, size=size, source_location=loc)

	def sub_borrow(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		carry: ExpressionIndex,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Subtracts ``b`` and the borrow ``carry`` from ``a``.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param carry: The carry in
		:param loc: The IL location this expression was added from
		:return: The expression ``sbb.<size>(a, b, carry)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_SBB, a, b, carry, size=size, source_location=loc)

	def and_expr(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		The bitwise and of ``a`` and ``b``. Renders as ``a && b`` when ``size`` is 0.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a & b``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_AND, a, b, size=size, source_location=loc)

	def or_expr(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		The bitwise or of ``a`` and ``b``. Renders as ``a || b`` when ``size`` is 0.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a | b``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_OR, a, b, size=size, source_location=loc)

	def xor_expr(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		The bitwise exclusive or of ``a`` and ``b``.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a ^ b``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_XOR, a, b, size=size, source_location=loc)

	def shift_left(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Shifts ``a`` left by ``b`` bits.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a << b``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_LSL, a, b, size=size, source_location=loc)

	def logical_shift_right(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Shifts ``a`` logically right by ``b`` bits.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a u>> b``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_LSR, a, b, size=size, source_location=loc)

	def arith_shift_right(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Shifts ``a`` arithmetically right by ``b`` bits.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a s>> b``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_ASR, a, b, size=size, source_location=loc)

	def rotate_left(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Rotates ``a`` left by ``b`` bits.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``rol.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_ROL, a, b, size=size, source_location=loc)

	def rotate_left_carry(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		carry: ExpressionIndex,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Rotates ``a`` left by ``b`` bits through the carry ``carry``.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param carry: The carry in
		:param loc: The IL location this expression was added from
		:return: The expression ``rlc.<size>(a, b, carry)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_RLC, a, b, carry, size=size, source_location=loc)

	def rotate_right(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Rotates ``a`` right by ``b`` bits.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``ror.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_ROR, a, b, size=size, source_location=loc)

	def rotate_right_carry(
		self,
		size: int,
		a: ExpressionIndex,
		b: ExpressionIndex,
		carry: ExpressionIndex,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Rotates ``a`` right by ``b`` bits through the carry ``carry``.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param carry: The carry in
		:param loc: The IL location this expression was added from
		:return: The expression ``rrc.<size>(a, b, carry)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_RRC, a, b, carry, size=size, source_location=loc)

	def mult(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Multiplies ``a`` by ``b``. The operands and the result are all ``size`` bytes, so the upper half of
		the product is discarded.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a * b``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_MUL, a, b, size=size, source_location=loc)

	def mult_double_prec_unsigned(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Multiplies ``a`` by ``b`` as unsigned integers. The operands are ``size`` bytes and the result is
		``2 * size`` bytes. The expression's size, which it renders with, is still ``size``.

		:param size: The size of ``a`` and ``b`` in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``mulu.dp.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_MULU_DP, a, b, size=size, source_location=loc)

	def mult_double_prec_signed(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Multiplies ``a`` by ``b`` as signed integers. The operands are ``size`` bytes and the result is
		``2 * size`` bytes. The expression's size, which it renders with, is still ``size``.

		:param size: The size of ``a`` and ``b`` in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``muls.dp.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_MULS_DP, a, b, size=size, source_location=loc)

	def div_unsigned(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Divides ``a`` by ``b`` as unsigned integers.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``divu.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_DIVU, a, b, size=size, source_location=loc)

	def div_double_prec_unsigned(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Divides ``a`` by ``b`` as unsigned integers. ``a`` is ``2 * size`` bytes, and ``b`` and the result
		are ``size`` bytes.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``divu.dp.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_DIVU_DP, a, b, size=size, source_location=loc)

	def div_signed(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Divides ``a`` by ``b`` as signed integers.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``divs.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_DIVS, a, b, size=size, source_location=loc)

	def div_double_prec_signed(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Divides ``a`` by ``b`` as signed integers. ``a`` is ``2 * size`` bytes, and ``b`` and the result are
		``size`` bytes.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``divs.dp.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_DIVS_DP, a, b, size=size, source_location=loc)

	def mod_unsigned(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		The remainder of dividing ``a`` by ``b`` as unsigned integers.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``modu.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_MODU, a, b, size=size, source_location=loc)

	def mod_double_prec_unsigned(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		The remainder of dividing ``a`` by ``b`` as unsigned integers. ``a`` is ``2 * size`` bytes, and
		``b`` and the result are ``size`` bytes.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``modu.dp.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_MODU_DP, a, b, size=size, source_location=loc)

	def mod_signed(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		The remainder of dividing ``a`` by ``b`` as signed integers.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``mods.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_MODS, a, b, size=size, source_location=loc)

	def mod_double_prec_signed(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		The remainder of dividing ``a`` by ``b`` as signed integers. ``a`` is ``2 * size`` bytes, and ``b``
		and the result are ``size`` bytes.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``mods.dp.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_MODS_DP, a, b, size=size, source_location=loc)

	def neg_expr(self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Negates ``value`` as a two's complement integer.

		:param size: The size of the result in bytes
		:param value: The operand
		:param loc: The IL location this expression was added from
		:return: The expression ``neg.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_NEG, value, size=size, source_location=loc)

	def not_expr(self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Inverts the bits of ``value``.

		:param size: The size of the result in bytes
		:param value: The operand
		:param loc: The IL location this expression was added from
		:return: The expression ``not.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_NOT, value, size=size, source_location=loc)

	def sign_extend(
		self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Sign-extends ``value`` to ``size`` bytes.

		:param size: The size of the result in bytes
		:param value: The operand
		:param loc: The IL location this expression was added from
		:return: The expression ``sx.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_SX, value, size=size, source_location=loc)

	def zero_extend(
		self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Zero-extends ``value`` to ``size`` bytes.

		:param size: The size of the result in bytes
		:param value: The operand
		:param loc: The IL location this expression was added from
		:return: The expression ``zx.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_ZX, value, size=size, source_location=loc)

	def low_part(self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Truncates ``value`` to its low ``size`` bytes.

		:param size: The size of the result in bytes
		:param value: The operand
		:param loc: The IL location this expression was added from
		:return: The expression ``(value).<size>``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_LOW_PART, value, size=size, source_location=loc)

	def jump(self, dest: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Jumps to ``dest``.

		:param dest: The address to jump to
		:param loc: The IL location this expression was added from
		:return: The expression ``jump(dest)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_JUMP, dest, source_location=loc)

	def jump_to(
		self, dest: ExpressionIndex, targets: Mapping[int, MediumLevelILLabel], loc: Optional['ILSourceLocation'] = None
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
			MediumLevelILOperation.MLIL_JUMP_TO,
			dest,
			len(targets) * 2,
			self.add_label_map(targets),
			source_location=loc,
		)

	def call(
		self,
		output: CallOutputList,
		dest: ExpressionIndex,
		params: List[ExpressionIndex],
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Calls ``dest`` with ``params``. Its results go to ``output``.

		:param output: Where the call's results go
		:param dest: The address to call
		:param params: The parameters
		:param loc: The IL location this expression was added from
		:return: The expression ``output = dest(params)``
		:rtype: ExpressionIndex
		"""
		_output = self._call_output_list(output)
		return self.expr(
			MediumLevelILOperation.MLIL_CALL,
			len(_output),
			self.add_operand_list(_output),
			dest,
			len(params),
			self.add_operand_list(params),
			source_location=loc,
		)

	def call_untyped(
		self,
		output: CallOutputList,
		dest: ExpressionIndex,
		params: List[ExpressionIndex],
		stack: ExpressionIndex,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Calls ``dest`` with ``params`` where analysis couldn't resolve the call's stack usage. Its results
		go to ``output``. Both lists hold only what analysis could find.

		:param output: Where the call's results go
		:param dest: The address to call
		:param params: The parameters
		:param stack: The top of the stack at the call
		:param loc: The IL location this expression was added from
		:return: The expression ``output = call(dest, params, stack = stack)``
		:rtype: ExpressionIndex
		"""
		_output = self._call_output_list(output)
		return self.expr(
			MediumLevelILOperation.MLIL_CALL_UNTYPED,
			len(_output),
			self.add_operand_list(_output),
			dest,
			self.expr(
				MediumLevelILOperation.MLIL_CALL_PARAM,
				len(params),
				self.add_operand_list(params),
				size=0,
				source_location=loc,
			),
			stack,
			source_location=loc,
		)

	def separate_param_list(
		self, params: List[ExpressionIndex], loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Parameters of an untyped call that the calling convention passes separately from the others, such as
		floating point parameters in their own registers.

		:param params: The parameters
		:param loc: The IL location this expression was added from
		:return: The expression ``(params)``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			MediumLevelILOperation.MLIL_SEPARATE_PARAM_LIST,
			len(params),
			self.add_operand_list(params),
			source_location=loc,
		)

	def shared_param_slot(
		self, params: List[ExpressionIndex], loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Alternative values for one parameter slot of an untyped call, such as an integer and a floating
		point register that the calling convention assigns to the same slot.

		:param params: The alternatives
		:param loc: The IL location this expression was added from
		:return: The expression ``params``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			MediumLevelILOperation.MLIL_SHARED_PARAM_SLOT,
			len(params),
			self.add_operand_list(params),
			source_location=loc,
		)

	def var_output(
		self, size: int, dest: 'variable.CoreVariable', loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		A call output that writes variable ``dest``.

		:param size: The size of the result in bytes
		:param dest: The variable the result goes to
		:param loc: The IL location this expression was added from
		:return: The expression ``dest``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_VAR_OUTPUT, dest.identifier, size=size, source_location=loc)

	def var_output_field(
		self, size: int, dest: 'variable.CoreVariable', offset: int, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		A call output that writes the ``size`` bytes at offset ``offset`` within variable ``dest``, such as
		a result placed in part of a structure.

		:param size: The size of the result in bytes
		:param dest: The variable to write part of
		:param offset: The offset of the part within the variable, in bytes
		:param loc: The IL location this expression was added from
		:return: The expression ``dest:offset.<size>``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			MediumLevelILOperation.MLIL_VAR_OUTPUT_FIELD, dest.identifier, offset, size=size, source_location=loc
		)

	def store_output(
		self, size: int, dest: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		A call output that writes ``size`` bytes to memory at ``dest``, for a result that doesn't go to a
		local variable.

		:param size: The size of the result in bytes
		:param dest: The address the result goes to
		:param loc: The IL location this expression was added from
		:return: The expression ``[dest].<size>``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_STORE_OUTPUT, dest, size=size, source_location=loc)

	def ret(self, sources: List[ExpressionIndex], loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Returns ``sources`` from the function.

		:param sources: The values to return
		:param loc: The IL location this expression was added from
		:return: The expression ``return sources``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			MediumLevelILOperation.MLIL_RET, len(sources), self.add_operand_list(sources), source_location=loc
		)

	def no_ret(self, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Marks a point that execution doesn't pass, such as after a call that doesn't return.

		:param loc: The IL location this expression was added from
		:return: The expression ``noreturn``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_NORET, source_location=loc)

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
		return self.expr(MediumLevelILOperation.MLIL_CMP_E, a, b, size=size, source_location=loc)

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
		return self.expr(MediumLevelILOperation.MLIL_CMP_NE, a, b, size=size, source_location=loc)

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
		return self.expr(MediumLevelILOperation.MLIL_CMP_SLT, a, b, size=size, source_location=loc)

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
		return self.expr(MediumLevelILOperation.MLIL_CMP_ULT, a, b, size=size, source_location=loc)

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
		return self.expr(MediumLevelILOperation.MLIL_CMP_SLE, a, b, size=size, source_location=loc)

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
		return self.expr(MediumLevelILOperation.MLIL_CMP_ULE, a, b, size=size, source_location=loc)

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
		return self.expr(MediumLevelILOperation.MLIL_CMP_SGE, a, b, size=size, source_location=loc)

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
		return self.expr(MediumLevelILOperation.MLIL_CMP_UGE, a, b, size=size, source_location=loc)

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
		return self.expr(MediumLevelILOperation.MLIL_CMP_SGT, a, b, size=size, source_location=loc)

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
		return self.expr(MediumLevelILOperation.MLIL_CMP_UGT, a, b, size=size, source_location=loc)

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
		return self.expr(MediumLevelILOperation.MLIL_TEST_BIT, a, b, size=size, source_location=loc)

	def bool_to_int(self, size: int, a: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Converts ``a`` to the integer 1 if it's true, or 0 if it's false.

		:param size: The size of the result in bytes
		:param a: The operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a ? 1 : 0``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_BOOL_TO_INT, a, size=size, source_location=loc)

	def system_call(
		self, output: CallOutputList, params: List[ExpressionIndex], loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Makes a system call with ``params``. Its results go to ``output``.

		:param output: Where the call's results go
		:param params: The parameters
		:param loc: The IL location this expression was added from
		:return: The expression ``output = syscall(params)``
		:rtype: ExpressionIndex
		"""
		_output = self._call_output_list(output)
		return self.expr(
			MediumLevelILOperation.MLIL_SYSCALL,
			len(_output),
			self.add_operand_list(_output),
			len(params),
			self.add_operand_list(params),
			source_location=loc,
		)

	def system_call_untyped(
		self,
		output: CallOutputList,
		params: List[ExpressionIndex],
		stack: ExpressionIndex,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Makes a system call with ``params`` where analysis couldn't resolve the call's stack usage. Its
		results go to ``output``. Both lists hold only what analysis could find.

		:param output: Where the call's results go
		:param params: The parameters
		:param stack: The top of the stack at the call
		:param loc: The IL location this expression was added from
		:return: The expression ``output = syscall(params, stack = stack)``
		:rtype: ExpressionIndex
		"""
		_output = self._call_output_list(output)
		return self.expr(
			MediumLevelILOperation.MLIL_SYSCALL_UNTYPED,
			len(_output),
			self.add_operand_list(_output),
			self.expr(
				MediumLevelILOperation.MLIL_CALL_PARAM,
				len(params),
				self.add_operand_list(params),
				size=0,
				source_location=loc,
			),
			stack,
			source_location=loc,
		)

	def tailcall(
		self,
		output: CallOutputList,
		dest: ExpressionIndex,
		params: List[ExpressionIndex],
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Jumps to ``dest`` with ``params`` as a tail call. Its results go to ``output``.

		:param output: Where the call's results go
		:param dest: The address to jump to
		:param params: The parameters
		:param loc: The IL location this expression was added from
		:return: The expression ``return dest(params) __tailcall``
		:rtype: ExpressionIndex
		"""
		_output = self._call_output_list(output)
		return self.expr(
			MediumLevelILOperation.MLIL_TAILCALL,
			len(_output),
			self.add_operand_list(_output),
			dest,
			len(params),
			self.add_operand_list(params),
			source_location=loc,
		)

	def tailcall_untyped(
		self,
		output: CallOutputList,
		dest: ExpressionIndex,
		params: List[ExpressionIndex],
		stack: ExpressionIndex,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Jumps to ``dest`` with ``params`` as a tail call where analysis couldn't resolve the call's stack
		usage. Its results go to ``output``. Both lists hold only what analysis could find.

		:param output: Where the call's results go
		:param dest: The address to jump to
		:param params: The parameters
		:param stack: The top of the stack at the call
		:param loc: The IL location this expression was added from
		:return: The expression ``output = tailcall(dest, params, stack = stack)``
		:rtype: ExpressionIndex
		"""
		_output = self._call_output_list(output)
		return self.expr(
			MediumLevelILOperation.MLIL_TAILCALL_UNTYPED,
			len(_output),
			self.add_operand_list(_output),
			dest,
			self.expr(
				MediumLevelILOperation.MLIL_CALL_PARAM,
				len(params),
				self.add_operand_list(params),
				size=0,
				source_location=loc,
			),
			stack,
			source_location=loc,
		)

	def intrinsic(
		self,
		outputs: List['variable.CoreVariable'],
		intrinsic: 'architecture.IntrinsicType',
		params: List[ExpressionIndex],
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Calls intrinsic ``intrinsic`` with ``params``. An intrinsic is an architecture operation lifted as a
		call to a built-in function that doesn't exist in the binary. Its results go to the variables
		``outputs``.

		:param outputs: The variables the intrinsic writes
		:param intrinsic: The architecture intrinsic to call
		:param params: The parameters
		:param loc: The IL location this expression was added from
		:return: The expression ``outputs = intrinsic(params)``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			MediumLevelILOperation.MLIL_INTRINSIC,
			len(outputs),
			self.add_variable_list(outputs),
			self.arch.get_intrinsic_index(intrinsic),
			len(params),
			self.add_operand_list(params),
			source_location=loc,
		)

	def free_var_slot(self, var: 'variable.CoreVariable', loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Frees the slot of variable ``var`` on its register stack.

		:param var: The register stack variable whose slot to free
		:param loc: The IL location this expression was added from
		:return: The expression ``__free_slot(var)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_FREE_VAR_SLOT, var.identifier, source_location=loc)

	def breakpoint(self, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		A processor breakpoint.

		:param loc: The IL location this expression was added from
		:return: The expression ``breakpoint``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_BP, source_location=loc)

	def trap(self, value: int, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		A processor trap, or interrupt, with number ``value``.

		:param value: The trap number
		:param loc: The IL location this expression was added from
		:return: The expression ``trap(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_TRAP, value, source_location=loc)

	def undefined(self, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		An undefined value or operation.

		:param loc: The IL location this expression was added from
		:return: The expression ``undefined``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_UNDEF, source_location=loc)

	def unimplemented(self, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		An unimplemented instruction or value.

		:param loc: The IL location this expression was added from
		:return: The expression ``unimplemented``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_UNIMPL, 0, source_location=loc)

	def unknown(self, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		A value that can't be known at analysis time. It doesn't produce the warning an unimplemented
		expression does.

		:param loc: The IL location this expression was added from
		:return: The expression ``unknown``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_UNIMPL, 1, source_location=loc)

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
		return self.expr(MediumLevelILOperation.MLIL_UNIMPL_MEM, addr, 0, size=size, source_location=loc)

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
		return self.expr(MediumLevelILOperation.MLIL_UNIMPL_MEM, addr, 1, size=size, source_location=loc)

	def float_add(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Adds ``a`` and ``b`` as floating point values.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a f+ b``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_FADD, a, b, size=size, source_location=loc)

	def float_sub(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Subtracts ``b`` from ``a`` as floating point values.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a f- b``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_FSUB, a, b, size=size, source_location=loc)

	def float_mult(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Multiplies ``a`` by ``b`` as floating point values.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a f* b``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_FMUL, a, b, size=size, source_location=loc)

	def float_div(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Divides ``a`` by ``b`` as floating point values.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a f/ b``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_FDIV, a, b, size=size, source_location=loc)

	def float_sqrt(
		self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		The square root of the floating point value ``value``.

		:param size: The size of the result in bytes
		:param value: The operand
		:param loc: The IL location this expression was added from
		:return: The expression ``sqrt(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_FSQRT, value, size=size, source_location=loc)

	def float_neg(self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Negates the floating point value ``value``.

		:param size: The size of the result in bytes
		:param value: The operand
		:param loc: The IL location this expression was added from
		:return: The expression ``fneg(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_FNEG, value, size=size, source_location=loc)

	def float_abs(self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		The absolute value of the floating point value ``value``.

		:param size: The size of the result in bytes
		:param value: The operand
		:param loc: The IL location this expression was added from
		:return: The expression ``fabs(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_FABS, value, size=size, source_location=loc)

	def float_to_int(
		self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Converts the floating point value ``value`` to an integer.

		:param size: The size of the result in bytes
		:param value: The operand
		:param loc: The IL location this expression was added from
		:return: The expression ``int.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_FLOAT_TO_INT, value, size=size, source_location=loc)

	def int_to_float(
		self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Converts the integer ``value`` to a floating point value.

		:param size: The size of the result in bytes
		:param value: The operand
		:param loc: The IL location this expression was added from
		:return: The expression ``float.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_INT_TO_FLOAT, value, size=size, source_location=loc)

	def float_convert(
		self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Converts the floating point value ``value`` to a floating point value of ``size`` bytes.

		:param size: The size of the result in bytes
		:param value: The operand
		:param loc: The IL location this expression was added from
		:return: The expression ``fconvert.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_FLOAT_CONV, value, size=size, source_location=loc)

	def round_to_int(
		self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Rounds the floating point value ``value`` to the nearest integral value.

		:param size: The size of the result in bytes
		:param value: The operand
		:param loc: The IL location this expression was added from
		:return: The expression ``roundint.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_ROUND_TO_INT, value, size=size, source_location=loc)

	def floor(self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Rounds the floating point value ``value`` to an integral value, towards negative infinity.

		:param size: The size of the result in bytes
		:param value: The operand
		:param loc: The IL location this expression was added from
		:return: The expression ``floor.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_FLOOR, value, size=size, source_location=loc)

	def ceil(self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Rounds the floating point value ``value`` to an integral value, towards positive infinity.

		:param size: The size of the result in bytes
		:param value: The operand
		:param loc: The IL location this expression was added from
		:return: The expression ``ceil.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_CEIL, value, size=size, source_location=loc)

	def float_trunc(
		self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Rounds the floating point value ``value`` to an integral value, towards zero.

		:param size: The size of the result in bytes
		:param value: The operand
		:param loc: The IL location this expression was added from
		:return: The expression ``ftrunc.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_FTRUNC, value, size=size, source_location=loc)

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
		return self.expr(MediumLevelILOperation.MLIL_FCMP_E, a, b, size=size, source_location=loc)

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
		return self.expr(MediumLevelILOperation.MLIL_FCMP_NE, a, b, size=size, source_location=loc)

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
		return self.expr(MediumLevelILOperation.MLIL_FCMP_LT, a, b, size=size, source_location=loc)

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
		return self.expr(MediumLevelILOperation.MLIL_FCMP_LE, a, b, size=size, source_location=loc)

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
		return self.expr(MediumLevelILOperation.MLIL_FCMP_GE, a, b, size=size, source_location=loc)

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
		return self.expr(MediumLevelILOperation.MLIL_FCMP_GT, a, b, size=size, source_location=loc)

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
		return self.expr(MediumLevelILOperation.MLIL_FCMP_O, a, b, size=size, source_location=loc)

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
		return self.expr(MediumLevelILOperation.MLIL_FCMP_UO, a, b, size=size, source_location=loc)

	def block_to_expand(
		self, exprs: List[ExpressionIndex], loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Holds the statements ``exprs`` until a later analysis step expands them in place of this
		instruction.

		:param exprs: The statements
		:param loc: The IL location this expression was added from
		:return: The expression ``{ exprs }``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			MediumLevelILOperation.MLIL_BLOCK_TO_EXPAND, len(exprs), self.add_operand_list(exprs), source_location=loc
		)

	def byte_swap(self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Reverses the byte order of ``value``.

		:param size: The size of the result in bytes
		:param value: The operand
		:param loc: The IL location this expression was added from
		:return: The expression ``bswap.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_BSWAP, value, size=size, source_location=loc)

	def population_count(
		self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Counts the set bits in ``value``.

		:param size: The size of the result in bytes
		:param value: The operand
		:param loc: The IL location this expression was added from
		:return: The expression ``popcnt.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_POPCNT, value, size=size, source_location=loc)

	def count_leading_zeros(
		self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Counts the leading zero bits in ``value``. The result is ``8 * size`` when ``value`` is zero.

		:param size: The size of the result in bytes
		:param value: The operand
		:param loc: The IL location this expression was added from
		:return: The expression ``clz.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_CLZ, value, size=size, source_location=loc)

	def count_trailing_zeros(
		self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Counts the trailing zero bits in ``value``. The result is ``8 * size`` when ``value`` is zero.

		:param size: The size of the result in bytes
		:param value: The operand
		:param loc: The IL location this expression was added from
		:return: The expression ``ctz.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_CTZ, value, size=size, source_location=loc)

	def reverse_bits(
		self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Reverses the bit order of ``value``.

		:param size: The size of the result in bytes
		:param value: The operand
		:param loc: The IL location this expression was added from
		:return: The expression ``rbit.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_RBIT, value, size=size, source_location=loc)

	def count_leading_signs(
		self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Counts the bits below the sign bit of ``value`` that match it.

		:param size: The size of the result in bytes
		:param value: The operand
		:param loc: The IL location this expression was added from
		:return: The expression ``cls.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_CLS, value, size=size, source_location=loc)

	def min_signed(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		The smaller of ``a`` and ``b`` as signed integers.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``mins.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_MINS, a, b, size=size, source_location=loc)

	def max_signed(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		The larger of ``a`` and ``b`` as signed integers.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``maxs.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_MAXS, a, b, size=size, source_location=loc)

	def min_unsigned(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		The smaller of ``a`` and ``b`` as unsigned integers.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``minu.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_MINU, a, b, size=size, source_location=loc)

	def max_unsigned(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		The larger of ``a`` and ``b`` as unsigned integers.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``maxu.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_MAXU, a, b, size=size, source_location=loc)

	def absolute_value(
		self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		The absolute value of ``value`` as a signed integer. The most negative value is its own absolute
		value.

		:param size: The size of the result in bytes
		:param value: The operand
		:param loc: The IL location this expression was added from
		:return: The expression ``abs.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_ABS, value, size=size, source_location=loc)

	# END GENERATED mlil-builders

	def float_const_single(self, value: float, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``float_const_single`` returns an expression for the single precision floating point value ``value``

		:param float value: float value for the constant
		:param ILSourceLocation loc: location of returned expression
		:return: A constant expression of given value and size
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_FLOAT_CONST, struct.unpack("I", struct.pack("f", value))[0], size=4, source_location=loc)

	def float_const_double(self, value: float, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``float_const_double`` returns an expression for the double precision floating point value ``value``

		:param float value: float value for the constant
		:param ILSourceLocation loc: location of returned expression
		:return: A constant expression of given value and size
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_FLOAT_CONST, struct.unpack("Q", struct.pack("d", value))[0], size=8, source_location=loc)

	def goto(
		self, label: MediumLevelILLabel, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``goto`` returns a goto expression which jumps to the provided MediumLevelILLabel.

		:param MediumLevelILLabel label: Label to jump to
		:param ILSourceLocation loc: location of returned expression
		:return: the ExpressionIndex that jumps to the provided label
		:rtype: ExpressionIndex
		"""
		if loc is not None:
			index = ExpressionIndex(core.BNMediumLevelILGotoWithLocation(self.handle, label.handle, loc.address, loc.source_operand))
			self._record_mlil_to_mlil_expr_map(index, loc)
			return index
		else:
			return ExpressionIndex(core.BNMediumLevelILGoto(self.handle, label.handle))

	def if_expr(
		self, operand: ExpressionIndex, t: MediumLevelILLabel, f: MediumLevelILLabel,
		loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``if_expr`` returns the ``if`` expression which depending on condition ``operand`` jumps to the MediumLevelILLabel
		``t`` when the condition expression ``operand`` is non-zero and ``f`` when it's zero.

		:param ExpressionIndex operand: comparison expression to evaluate.
		:param MediumLevelILLabel t: Label for the true branch
		:param MediumLevelILLabel f: Label for the false branch
		:param ILSourceLocation loc: location of returned expression
		:return: the ExpressionIndex for the if expression
		:rtype: ExpressionIndex
		"""
		if loc is not None:
			index = ExpressionIndex(core.BNMediumLevelILIfWithLocation(self.handle, operand, t.handle, f.handle, loc.address, loc.source_operand))
			self._record_mlil_to_mlil_expr_map(index, loc)
			return index
		else:
			return ExpressionIndex(core.BNMediumLevelILIf(self.handle, operand, t.handle, f.handle))

	def mark_label(self, label: MediumLevelILLabel) -> None:
		"""
		``mark_label`` assigns a MediumLevelILLabel to the current IL address.

		:param MediumLevelILLabel label:
		:rtype: None
		"""
		core.BNMediumLevelILMarkLabel(self.handle, label.handle)

	def add_label_map(self, labels: Mapping[int, MediumLevelILLabel]) -> ExpressionIndex:
		"""
		``add_label_map`` returns a label list expression for the given list of MediumLevelILLabel objects.

		:param labels: the list of MediumLevelILLabel to get a label list expression from
		:type labels: dict(int, MediumLevelILLabel)
		:return: the label list expression
		:rtype: ExpressionIndex
		"""
		label_list = (ctypes.POINTER(core.BNMediumLevelILLabel) * len(labels))()
		value_list = (ctypes.c_ulonglong * len(labels))()
		for i, (key, value) in enumerate(labels.items()):
			value_list[i] = key
			label_list[i] = value.handle

		return ExpressionIndex(core.BNMediumLevelILAddLabelMap(self.handle, value_list, label_list, len(labels)))

	def add_operand_list(self, operands: List[ExpressionIndex]) -> ExpressionIndex:
		"""
		``add_operand_list`` returns an operand list expression for the given list of integer operands.

		:param operands: list of operand numbers
		:type operands: list(int)
		:return: an operand list expression
		:rtype: ExpressionIndex
		"""
		operand_list = (ctypes.c_ulonglong * len(operands))()
		for i in range(len(operands)):
			operand_list[i] = operands[i]
		return ExpressionIndex(core.BNMediumLevelILAddOperandList(self.handle, operand_list, len(operands)))

	def add_variable_list(self, vars: List['variable.CoreVariable']) -> ExpressionIndex:
		"""
		``add_variable_list`` returns a variable list expression for the given list of variables.

		:param vars: list of variables
		:type vars: list(variable.CoreVariable)
		:return: a variable list expression
		:rtype: ExpressionIndex
		"""
		operand_list = (ctypes.c_uint64 * len(vars))()
		for i in range(len(vars)):
			operand_list[i] = vars[i].identifier
		return ExpressionIndex(core.BNMediumLevelILAddOperandList(self.handle, operand_list, len(vars)))

	def cache_possible_value_set(self, pvs: 'variable.PossibleValueSet') -> int:
		"""
		Cache a PossibleValueSet in the IL function, returning its index for use in an expression operand
		:param pvs: PossibleValueSet to cache
		:return: Index of the PossibleValueSet in the cache
		"""
		return core.BNCacheMediumLevelILPossibleValueSet(self.handle, pvs._to_core_struct())

	def finalize(self) -> None:
		"""
		``finalize`` ends the function and computes the list of basic blocks.

		:rtype: None
		"""
		core.BNFinalizeMediumLevelILFunction(self.handle)

	def generate_ssa_form(self, analyze_conditionals : bool = True, handle_aliases : bool = True, known_not_aliases: Optional[List["variable.CoreVariable"]] = None, known_aliases: Optional[List["variable.CoreVariable"]] = None) -> None:
		"""
		``generate_ssa_form`` generate SSA form given the current MLIL

		:param bool analyze_conditionals: whether or not to analyze conditionals, defaults to ``True``
		:param bool handle_aliases: whether or not to handle aliases, defaults to ``True``
		:param list(Variable) known_not_aliases: optional list of variables known to be not aliased
		:param list(Variable) known_aliases: optional list of variables known to be aliased
		:rtype: None
		"""
		if known_not_aliases is None:
			known_not_aliases = []
		if known_aliases is None:
			known_aliases = []
		known_not_alias_list = (core.BNVariable * len(known_not_aliases))()
		for i in range(len(known_not_aliases)):
			known_not_alias_list[i] = known_not_aliases[i].to_BNVariable()
		known_alias_list = (core.BNVariable * len(known_aliases))()
		for i in range(len(known_aliases)):
			known_alias_list[i] = known_aliases[i].to_BNVariable()
		core.BNGenerateMediumLevelILSSAForm(self.handle, analyze_conditionals, handle_aliases, known_not_alias_list, len(known_not_alias_list), known_alias_list, len(known_alias_list))

	def prepare_to_copy_function(self, src: 'MediumLevelILFunction'):
		"""
		``prepare_to_copy_function`` sets up state in this MLIL function in preparation
		of copying instructions from ``src``
		It enables use of :py:func:`get_label_for_source_instruction` during function transformation.

		:param MediumLevelILFunction src: function about to be copied from
		"""
		core.BNPrepareToCopyMediumLevelILFunction(self.handle, src.handle)

	def prepare_to_copy_block(self, src: 'MediumLevelILBasicBlock'):
		"""
		``prepare_to_copy_block`` sets up state when copying a function in preparation
		of copying the instructions from the block ``src``
		It enables use of :py:func:`get_label_for_source_instruction` during function transformation.

		:param MediumLevelILBasicBlock src: block about to be copied from
		"""
		core.BNPrepareToCopyMediumLevelILBasicBlock(self.handle, src.handle)

	def get_label_for_source_instruction(self, i: InstructionIndex) -> Optional['MediumLevelILLabel']:
		"""
		Get the MediumLevelILLabel for a given source instruction. The source instruction must be
		at the start of a basic block in the source function passed to :py:func:`prepare_to_copy_function`.
		The label will be marked resolved when its source block is passed to :py:func:`prepare_to_copy_block`.

		.. warning:: The instruction index parameter for this pertains to the *source function*
		             passed to `prepare_to_copy_function`, not the current function.

		.. note:: The returned label is to an internal object with the same lifetime as the containing MediumLevelILFunction.

		:param i: The source instruction index
		:return: The MediumLevelILLabel for the source instruction
		"""
		label = core.BNGetLabelForMediumLevelILSourceInstruction(self.handle, i)
		if not label:
			return None
		return MediumLevelILLabel(handle=label)

	def get_ssa_instruction_index(self, instr: InstructionIndex) -> InstructionIndex:
		return InstructionIndex(core.BNGetMediumLevelILSSAInstructionIndex(self.handle, instr))

	def get_non_ssa_instruction_index(self, instr: InstructionIndex) -> InstructionIndex:
		return InstructionIndex(core.BNGetMediumLevelILNonSSAInstructionIndex(self.handle, instr))

	def get_ssa_var_definition(self, ssa_var: Union[SSAVariable, MediumLevelILVarSsa]) -> Optional[MediumLevelILInstruction]:
		"""
		Gets the instruction that contains the given SSA variable's definition.

		Since SSA variables can only be defined once, this will return the single instruction where that occurs.
		For SSA variable version 0s, which don't have definitions, this will return None instead.
		"""
		if isinstance(ssa_var, MediumLevelILVarSsa):
			ssa_var = ssa_var.var
		if not isinstance(ssa_var, SSAVariable):
			raise ValueError("Expected SSAVariable")
		var_data = ssa_var.var.to_BNVariable()
		result = core.BNGetMediumLevelILSSAVarDefinition(self.handle, var_data, ssa_var.version)
		if result >= core.BNGetMediumLevelILInstructionCount(self.handle):
			return None
		return self[result]

	def get_ssa_memory_definition(self, version: int) -> Optional[MediumLevelILInstruction]:
		result = core.BNGetMediumLevelILSSAMemoryDefinition(self.handle, version)
		if result >= core.BNGetMediumLevelILInstructionCount(self.handle):
			return None
		return self[result]

	def get_ssa_var_uses(self, ssa_var: Union[SSAVariable, MediumLevelILVarSsa]) -> List[MediumLevelILInstruction]:
		"""
		Gets all the instructions that use the given SSA variable.
		"""
		if isinstance(ssa_var, MediumLevelILVarSsa):
			ssa_var = ssa_var.var
		if not isinstance(ssa_var, SSAVariable):
			raise ValueError("Expected SSAVariable")
		count = ctypes.c_ulonglong()
		var_data = ssa_var.var.to_BNVariable()
		instrs = core.BNGetMediumLevelILSSAVarUses(self.handle, var_data, ssa_var.version, count)
		assert instrs is not None, "core.BNGetMediumLevelILSSAVarUses returned None"
		result = []
		for i in range(0, count.value):
			result.append(self[instrs[i]])
		core.BNFreeILInstructionList(instrs)
		return result

	def get_ssa_memory_uses(self, version: int) -> List[MediumLevelILInstruction]:
		count = ctypes.c_ulonglong()
		instrs = core.BNGetMediumLevelILSSAMemoryUses(self.handle, version, count)
		assert instrs is not None, "core.BNGetMediumLevelILSSAMemoryUses returned None"
		result = []
		for i in range(0, count.value):
			result.append(self[instrs[i]])
		core.BNFreeILInstructionList(instrs)
		return result

	def is_ssa_var_live(self, ssa_var: SSAVariable) -> bool:
		"""
		``is_ssa_var_live`` determines if ``ssa_var`` is live at any point in the function

		:param SSAVariable ssa_var: the SSA variable to query
		:return: whether the variable is live at any point in the function
		:rtype: bool
		"""
		var_data = ssa_var.var.to_BNVariable()
		return core.BNIsMediumLevelILSSAVarLive(self.handle, var_data, ssa_var.version)

	def is_ssa_var_live_at(self, ssa_var: SSAVariable, instr: InstructionIndex) -> bool:
		"""
		``is_ssa_var_live_at`` determines if ``ssa_var`` is live at a given point in the function; counts phi's as uses
		"""
		return core.BNIsMediumLevelILSSAVarLiveAt(self.handle, ssa_var.var.to_BNVariable(), ssa_var.version, instr)

	def is_var_live_at(self, var: 'variable.CoreVariable', instr: InstructionIndex) -> bool:
		"""
		``is_var_live_at`` determines if ``var`` is live at a given point in the function
		"""
		return core.BNIsMediumLevelILVarLiveAt(self.handle, var.to_BNVariable(), instr)

	def get_var_definitions(self, var: 'variable.CoreVariable') -> List[MediumLevelILInstruction]:
		count = ctypes.c_ulonglong()
		var_data = var.to_BNVariable()
		instrs = core.BNGetMediumLevelILVariableDefinitions(self.handle, var_data, count)
		assert instrs is not None, "core.BNGetMediumLevelILVariableDefinitions returned None"
		result = []
		for i in range(0, count.value):
			result.append(self[instrs[i]])
		core.BNFreeILInstructionList(instrs)
		return result

	def get_var_uses(self, var: 'variable.CoreVariable') -> List[MediumLevelILInstruction]:
		count = ctypes.c_ulonglong()
		var_data = var.to_BNVariable()
		instrs = core.BNGetMediumLevelILVariableUses(self.handle, var_data, count)
		assert instrs is not None, "core.BNGetMediumLevelILVariableUses returned None"
		try:
			result = []
			for i in range(0, count.value):
				result.append(self[instrs[i]])
			return result
		finally:
			core.BNFreeILInstructionList(instrs)

	def get_live_instructions_for_var(self, var: 'variable.CoreVariable', include_last_use: bool = True) -> List[MediumLevelILInstruction]:
		"""
		``get_live_instructions_for_var`` computes the list of instructions for which ``var`` is live.
		If ``include_last_use`` is False, the last use of the variable will not be included in the
		list (this allows for easier computation of overlaps in liveness between two variables).
		If the variable is never used, this function will return an empty list.

		:param SSAVariable var: the variable to query
		:param bool include_last_use: whether to include the last use of the variable in the list of instructions
		:return: list of instructions for which ``var`` is live
		:rtype: list(MediumLevelILInstruction)
		"""
		count = ctypes.c_ulonglong()
		var_data = var.to_BNVariable()
		instrs = core.BNGetMediumLevelILLiveInstructionsForVariable(self.handle, var_data, include_last_use, count)
		assert instrs is not None, "core.BNGetMediumLevelILLiveInstructionsForVariable returned None"
		result = []
		for i in range(0, count.value):
			result.append(self[instrs[i]])
		core.BNFreeILInstructionList(instrs)
		return result

	def get_ssa_var_value(self, ssa_var: SSAVariable) -> 'variable.RegisterValue':
		var_data = ssa_var.var.to_BNVariable()
		value = core.BNGetMediumLevelILSSAVarValue(self.handle, var_data, ssa_var.version)
		result = variable.RegisterValue.from_BNRegisterValue(value, self._arch)
		return result

	def get_instruction_index_for_expr(self, expr: ExpressionIndex) -> Optional[InstructionIndex]:
		result = core.BNGetMediumLevelILInstructionForExpr(self.handle, expr)
		if result >= core.BNGetMediumLevelILInstructionCount(self.handle):
			return None
		return InstructionIndex(result)

	def get_expr_index_for_instruction(self, instr: InstructionIndex) -> ExpressionIndex:
		result = core.BNGetMediumLevelILIndexForInstruction(self.handle, instr)
		return ExpressionIndex(result)

	def get_low_level_il_instruction_index(self, instr: InstructionIndex) -> Optional['lowlevelil.InstructionIndex']:
		low_il = self.low_level_il
		if low_il is None:
			return None
		low_il = low_il.ssa_form
		if low_il is None:
			return None
		result = core.BNGetLowLevelILInstructionIndex(self.handle, instr)
		if result >= core.BNGetLowLevelILInstructionCount(low_il.handle):
			return None
		return lowlevelil.InstructionIndex(result)

	def get_low_level_il_expr_index(self, expr: ExpressionIndex) -> Optional['lowlevelil.ExpressionIndex']:
		low_il = self.low_level_il
		if low_il is None:
			return None
		low_il = low_il.ssa_form
		if low_il is None:
			return None
		result = core.BNGetLowLevelILExprIndex(self.handle, expr)
		if result >= core.BNGetLowLevelILExprCount(low_il.handle):
			return None
		return lowlevelil.ExpressionIndex(result)

	def get_low_level_il_expr_indexes(self, expr: ExpressionIndex) -> List['lowlevelil.ExpressionIndex']:
		count = ctypes.c_ulonglong()
		exprs = core.BNGetLowLevelILExprIndexes(self.handle, expr, count)
		assert exprs is not None, "core.BNGetLowLevelILExprIndexes returned None"
		result: List['lowlevelil.ExpressionIndex'] = []
		for i in range(0, count.value):
			result.append(lowlevelil.ExpressionIndex(exprs[i]))
		core.BNFreeILInstructionList(exprs)
		return result

	def get_high_level_il_instruction_index(self, instr: InstructionIndex) -> Optional['highlevelil.InstructionIndex']:
		high_il = self.high_level_il
		if high_il is None:
			return None
		result = core.BNGetHighLevelILInstructionIndex(self.handle, instr)
		if result >= core.BNGetHighLevelILInstructionCount(high_il.handle):
			return None
		return highlevelil.InstructionIndex(result)

	def get_high_level_il_expr_index(self, expr: ExpressionIndex) -> Optional['highlevelil.ExpressionIndex']:
		high_il = self.high_level_il
		if high_il is None:
			return None
		result = core.BNGetHighLevelILExprIndex(self.handle, expr)
		if result >= core.BNGetHighLevelILExprCount(high_il.handle):
			return None
		return highlevelil.ExpressionIndex(result)

	def get_high_level_il_expr_indexes(self, expr: ExpressionIndex) -> List['highlevelil.ExpressionIndex']:
		count = ctypes.c_ulonglong()
		exprs = core.BNGetHighLevelILExprIndexes(self.handle, expr, count)
		assert exprs is not None, "core.BNGetHighLevelILExprIndexes returned None"
		result: List['highlevelil.ExpressionIndex'] = []
		for i in range(0, count.value):
			result.append(highlevelil.ExpressionIndex(exprs[i]))
		core.BNFreeILInstructionList(exprs)
		return result

	def create_graph(self, settings: Optional['function.DisassemblySettings'] = None) -> flowgraph.CoreFlowGraph:
		if settings is not None:
			settings_obj = settings.handle
		else:
			settings_obj = None
		return flowgraph.CoreFlowGraph(core.BNCreateMediumLevelILFunctionGraph(self.handle, settings_obj))

	def create_graph_immediate(self, settings: Optional['function.DisassemblySettings'] = None) -> flowgraph.CoreFlowGraph:
		if settings is not None:
			settings_obj = settings.handle
		else:
			settings_obj = None
		return flowgraph.CoreFlowGraph(core.BNCreateMediumLevelILImmediateFunctionGraph(self.handle, settings_obj))

	@property
	def arch(self) -> 'architecture.Architecture':
		return self._arch

	@property
	def view(self) -> 'binaryview.BinaryView':
		return self.source_function.view

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
		"""This gets just the MLIL variables - you may be interested in the union of `MediumLevelIlFunction.aliased_vars` and `MediumLevelIlFunction.source_function.parameter_vars` for all the variables used in the function"""
		if self.source_function is None:
			return []

		if self.il_form in [
			FunctionGraphType.MediumLevelILSSAFormFunctionGraph,
			FunctionGraphType.MappedMediumLevelILSSAFormFunctionGraph
		]:
			return self.ssa_vars

		if self.il_form in [
		    FunctionGraphType.MediumLevelILFunctionGraph,
		    FunctionGraphType.MappedMediumLevelILFunctionGraph
		]:
			count = ctypes.c_ulonglong()
			core_variables = core.BNGetMediumLevelILVariables(self.handle, count)
			assert core_variables is not None, "core.BNGetMediumLevelILVariables returned None"
			result = []
			try:
				for var_i in range(count.value):
					result.append(
					    variable.Variable(
					        self, core_variables[var_i].type, core_variables[var_i].index, core_variables[var_i].storage
					    )
					)
				return result
			finally:
				core.BNFreeVariableList(core_variables)
		return []

	@property
	def aliased_vars(self) -> List["variable.Variable"]:
		"""This returns a list of Variables that are taken reference to and used elsewhere. You may also wish to consider `MediumLevelIlFunction.vars` and `MediumLevelIlFunction.source_function.parameter_vars`"""
		if self.source_function is None:
			return []

		if self.il_form in [
		    FunctionGraphType.MediumLevelILFunctionGraph, FunctionGraphType.MediumLevelILSSAFormFunctionGraph
		]:
			count = ctypes.c_ulonglong()
			core_variables = core.BNGetMediumLevelILAliasedVariables(self.handle, count)
			assert core_variables is not None, "core.BNGetMediumLevelILAliasedVariables returned None"
			try:
				result = []
				for var_i in range(count.value):
					result.append(
					    variable.Variable(
					        self, core_variables[var_i].type, core_variables[var_i].index, core_variables[var_i].storage
					    )
					)
				return result
			finally:
				core.BNFreeVariableList(core_variables)
		return []

	@property
	def ssa_vars(self) -> List[SSAVariable]:
		"""This gets just the MLIL SSA variables - you may be interested in the union of `MediumLevelIlFunction.aliased_vars` and `MediumLevelIlFunction.source_function.parameter_vars` for all the variables used in the function"""
		if self.source_function is None:
			return []

		if self.il_form in [
		    FunctionGraphType.MediumLevelILSSAFormFunctionGraph,
		    FunctionGraphType.MappedMediumLevelILSSAFormFunctionGraph
		]:
			variable_count = ctypes.c_ulonglong()
			core_variables = core.BNGetMediumLevelILVariables(self.handle, variable_count)
			assert core_variables is not None, "core.BNGetMediumLevelILVariables returned None"
			try:
				result = []
				for var_i in range(variable_count.value):
					version_count = ctypes.c_ulonglong()
					versions = core.BNGetMediumLevelILVariableSSAVersions(
					    self.handle, core_variables[var_i], version_count
					)
					assert versions is not None, "core.BNGetMediumLevelILVariableSSAVersions returned None"
					try:
						for version_i in range(version_count.value):
							result.append(
							    SSAVariable(
							        variable.Variable(
							            self, core_variables[var_i].type, core_variables[var_i].index,
							            core_variables[var_i].storage
							        ), versions[version_i]
							    )
							)
					finally:
						core.BNFreeILInstructionList(versions)

				return result
			finally:
				core.BNFreeVariableList(core_variables)
		elif self.il_form in [
		    FunctionGraphType.MediumLevelILFunctionGraph, FunctionGraphType.MappedMediumLevelILFunctionGraph
		]:
			return self.ssa_form.ssa_vars

		return []

	def get_expr_type(self, expr_index: int) -> Optional['types.Type']:
		"""
		Get type of expression

		:param int expr_index: index of the expression to retrieve
		:rtype: Optional['types.Type']
		"""
		result = core.BNGetMediumLevelILExprType(self.handle, expr_index)
		if result.type:
			platform = None
			if self.source_function:
				platform = self.source_function.platform
			return types.Type.create(
				result.type, platform=platform, confidence=result.confidence
			)
		return None

	def set_expr_type(self, expr_index: int, expr_type: Optional[StringOrType]) -> None:
		"""
		Set type of expression

		This API is only meant for workflows or for debugging purposes, since the changes they make are not persistent
		and get lost after a database save and reload. To make persistent changes to the analysis, one should use other
		APIs to, for example, change the type of variables. The analysis will then propagate the type of the variable
		and update the type of related expressions.

		:param int expr_index: index of the expression to set
		:param StringOrType: new type of the expression
		"""
		if expr_type is not None:
			if isinstance(expr_type, str):
				(expr_type, _) = self.view.parse_type_string(expr_type)
			ic = expr_type.immutable_copy()
			tc = ic._to_core_struct()
		else:
			tc = core.BNTypeWithConfidence()
			tc.type = None
			tc.confidence = 0
		core.BNSetMediumLevelILExprType(self.handle, expr_index, tc)


class MediumLevelILBasicBlock(basicblock.BasicBlock):
	"""
	The ``MediumLevelILBasicBlock`` object is returned during analysis and should not be directly instantiated.
	"""
	def __init__(
	    self, handle: core.BNBasicBlockHandle, owner: MediumLevelILFunction,
	    view: Optional['binaryview.BinaryView'] = None
	):
		super().__init__(handle, view)
		self._il_function = owner

	def __iter__(self):
		for idx in range(self.start, self.end):
			yield self._il_function[idx]

	@overload
	def __getitem__(self, idx: int) -> 'MediumLevelILInstruction': ...

	@overload
	def __getitem__(self, idx: slice) -> List['MediumLevelILInstruction']: ...

	def __getitem__(self, idx: Union[int, slice]) -> Union[List['MediumLevelILInstruction'], 'MediumLevelILInstruction']:
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
		if not isinstance(instruction, MediumLevelILInstruction) or instruction.il_basic_block != self:
			return False
		if self.start <= instruction.instr_index <= self.end:
			return True
		else:
			return False

	def __repr__(self):
		arch = self.arch
		if arch:
			return f"<{self.__class__.__name__}: {arch.name}@{self.start}-{self.end}>"
		else:
			return f"<{self.__class__.__name__}: {self.start}-{self.end}>"

	def _create_instance(
	    self, handle: core.BNBasicBlockHandle) -> 'MediumLevelILBasicBlock':
		"""Internal method by super to instantiate child instances"""
		return MediumLevelILBasicBlock(handle, self.il_function, self.view)

	@property
	def instruction_count(self) -> int:
		return self.end - self.start

	@property
	def il_function(self) -> 'MediumLevelILFunction':
		return self._il_function
