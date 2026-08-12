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
	ILOperations: ClassVar[Mapping[MediumLevelILOperation, List[Tuple[str, str]]]] = {
	    MediumLevelILOperation.MLIL_NOP: [], MediumLevelILOperation.MLIL_SET_VAR: [("dest", "var"), ("src", "expr")],
	    MediumLevelILOperation.MLIL_SET_VAR_FIELD: [("dest", "var"), ("offset", "int"),
	                                                ("src", "expr")], MediumLevelILOperation.MLIL_SET_VAR_SPLIT: [
	                                                    ("high", "var"), ("low", "var"), ("src", "expr")
	                                                ], MediumLevelILOperation.MLIL_LOAD: [("src", "expr")],
	    MediumLevelILOperation.MLIL_LOAD_STRUCT: [("src", "expr"),
	                                              ("offset", "int")], MediumLevelILOperation.MLIL_STORE: [
	                                                  ("dest", "expr"), ("src", "expr")
	                                              ], MediumLevelILOperation.MLIL_STORE_STRUCT: [("dest", "expr"),
	                                                                                            ("offset", "int"),
	                                                                                            ("src", "expr")],
	    MediumLevelILOperation.MLIL_VAR: [("src", "var")], MediumLevelILOperation.MLIL_VAR_FIELD: [
	        ("src", "var"), ("offset", "int")
	    ], MediumLevelILOperation.MLIL_VAR_SPLIT: [("high", "var"), ("low", "var")],
	    MediumLevelILOperation.MLIL_ADDRESS_OF: [("src", "var")], MediumLevelILOperation.MLIL_PASS_BY_REF: [
	        ("src", "expr")
	    ], MediumLevelILOperation.MLIL_RETURN_BY_REF: [
			("src", "expr")
		], MediumLevelILOperation.MLIL_ADDRESS_OF_FIELD: [
	        ("src", "var"), ("offset", "int")
	    ], MediumLevelILOperation.MLIL_CONST: [("constant", "int")], MediumLevelILOperation.MLIL_CONST_PTR: [
	        ("constant", "int")
	    ], MediumLevelILOperation.MLIL_EXTERN_PTR: [
	        ("constant", "int"), ("offset", "int")
	    ], MediumLevelILOperation.MLIL_FLOAT_CONST: [("constant", "float")], MediumLevelILOperation.MLIL_IMPORT: [
	        ("constant", "int")
	    ], MediumLevelILOperation.MLIL_CONST_DATA: [("constant", "ConstantData")], MediumLevelILOperation.MLIL_CONST_DATA: [
	        ("constant", "ConstantData")
	    ], MediumLevelILOperation.MLIL_ADD: [("left", "expr"), ("right", "expr")], MediumLevelILOperation.MLIL_ADC: [
	        ("left", "expr"), ("right", "expr"), ("carry", "expr")
	    ], MediumLevelILOperation.MLIL_SUB: [("left", "expr"), ("right", "expr")], MediumLevelILOperation.MLIL_SBB: [
	        ("left", "expr"), ("right", "expr"), ("carry", "expr")
	    ], MediumLevelILOperation.MLIL_AND: [("left", "expr"), ("right", "expr")], MediumLevelILOperation.MLIL_OR: [
	        ("left", "expr"), ("right", "expr")
	    ], MediumLevelILOperation.MLIL_XOR: [("left", "expr"), ("right", "expr")], MediumLevelILOperation.MLIL_LSL: [
	        ("left", "expr"), ("right", "expr")
	    ], MediumLevelILOperation.MLIL_LSR: [("left", "expr"), ("right", "expr")], MediumLevelILOperation.MLIL_ASR: [
	        ("left", "expr"), ("right", "expr")
	    ], MediumLevelILOperation.MLIL_ROL: [("left", "expr"), ("right", "expr")], MediumLevelILOperation.MLIL_RLC: [
	        ("left", "expr"), ("right", "expr"), ("carry", "expr")
	    ], MediumLevelILOperation.MLIL_ROR: [("left", "expr"),
	                                         ("right", "expr")], MediumLevelILOperation.MLIL_RRC: [("left", "expr"),
	                                                                                               ("right", "expr"),
	                                                                                               ("carry", "expr")],
	    MediumLevelILOperation.MLIL_MUL: [("left", "expr"), ("right", "expr")], MediumLevelILOperation.MLIL_MULU_DP: [
	        ("left", "expr"), ("right", "expr")
	    ], MediumLevelILOperation.MLIL_MULS_DP: [("left", "expr"),
	                                             ("right", "expr")], MediumLevelILOperation.MLIL_DIVU: [
	                                                 ("left", "expr"), ("right", "expr")
	                                             ], MediumLevelILOperation.MLIL_DIVU_DP: [("left", "expr"),
	                                                                                      ("right", "expr")],
	    MediumLevelILOperation.MLIL_DIVS: [("left", "expr"), ("right", "expr")], MediumLevelILOperation.MLIL_DIVS_DP: [
	        ("left", "expr"), ("right", "expr")
	    ], MediumLevelILOperation.MLIL_MODU: [("left", "expr"),
	                                          ("right", "expr")], MediumLevelILOperation.MLIL_MODU_DP: [
	                                              ("left", "expr"), ("right", "expr")
	                                          ], MediumLevelILOperation.MLIL_MODS: [("left", "expr"),
	                                                                                ("right", "expr")],
	    MediumLevelILOperation.MLIL_MODS_DP: [("left", "expr"), ("right", "expr")], MediumLevelILOperation.MLIL_NEG: [
	        ("src", "expr")
	    ], MediumLevelILOperation.MLIL_NOT: [("src", "expr")], MediumLevelILOperation.MLIL_BSWAP: [
	        ("src", "expr")
	    ], MediumLevelILOperation.MLIL_POPCNT: [("src", "expr")], MediumLevelILOperation.MLIL_CLZ: [
	        ("src", "expr")
	    ], MediumLevelILOperation.MLIL_CTZ: [("src", "expr")], MediumLevelILOperation.MLIL_RBIT: [
	        ("src", "expr")
	    ], MediumLevelILOperation.MLIL_CLS: [("src", "expr")], MediumLevelILOperation.MLIL_MINS: [
	        ("left", "expr"), ("right", "expr")
	    ], MediumLevelILOperation.MLIL_MAXS: [("left", "expr"), ("right", "expr")], MediumLevelILOperation.MLIL_MINU: [
	        ("left", "expr"), ("right", "expr")
	    ], MediumLevelILOperation.MLIL_MAXU: [("left", "expr"), ("right", "expr")], MediumLevelILOperation.MLIL_ABS: [
	        ("src", "expr")
	    ], MediumLevelILOperation.MLIL_SX: [
	        ("src", "expr")
	    ], MediumLevelILOperation.MLIL_ZX: [("src", "expr")], MediumLevelILOperation.MLIL_LOW_PART: [
	        ("src", "expr")
	    ], MediumLevelILOperation.MLIL_JUMP: [("dest", "expr")], MediumLevelILOperation.MLIL_JUMP_TO: [
	        ("dest", "expr"), ("targets", "target_map")
	    ], MediumLevelILOperation.MLIL_RET_HINT: [("dest", "expr")], MediumLevelILOperation.MLIL_CALL: [
	        ("output", "expr_list"), ("dest", "expr"), ("params", "expr_list")
	    ], MediumLevelILOperation.MLIL_CALL_UNTYPED: [
	        ("output", "expr_list"), ("dest", "expr"), ("params", "expr"), ("stack", "expr")
	    ], MediumLevelILOperation.MLIL_CALL_PARAM: [
	        ("src", "expr_list")
	    ], MediumLevelILOperation.MLIL_SEPARATE_PARAM_LIST: [
	        ("params", "expr_list")
	    ], MediumLevelILOperation.MLIL_SHARED_PARAM_SLOT: [
	        ("params", "expr_list")
	    ], MediumLevelILOperation.MLIL_VAR_OUTPUT: [
			("dest", "var")
		], MediumLevelILOperation.MLIL_VAR_OUTPUT_FIELD: [
			("dest", "var"), ("offset", "int")
		], MediumLevelILOperation.MLIL_STORE_OUTPUT: [
			("dest", "expr")
		], MediumLevelILOperation.MLIL_RET: [
	        ("src", "expr_list")
	    ], MediumLevelILOperation.MLIL_BLOCK_TO_EXPAND: [
			("src", "expr_list")
		], MediumLevelILOperation.MLIL_NORET: [], MediumLevelILOperation.MLIL_IF: [
	        ("condition", "expr"), ("true", "int"), ("false", "int")
	    ], MediumLevelILOperation.MLIL_GOTO: [("dest", "int")], MediumLevelILOperation.MLIL_CMP_E: [
	        ("left", "expr"), ("right", "expr")
	    ], MediumLevelILOperation.MLIL_CMP_NE: [("left", "expr"),
	                                            ("right", "expr")], MediumLevelILOperation.MLIL_CMP_SLT: [
	                                                ("left", "expr"), ("right", "expr")
	                                            ], MediumLevelILOperation.MLIL_CMP_ULT: [
	                                                ("left", "expr"), ("right", "expr")
	                                            ], MediumLevelILOperation.MLIL_CMP_SLE: [
	                                                ("left", "expr"), ("right", "expr")
	                                            ], MediumLevelILOperation.MLIL_CMP_ULE: [
	                                                ("left", "expr"), ("right", "expr")
	                                            ], MediumLevelILOperation.MLIL_CMP_SGE: [
	                                                ("left", "expr"), ("right", "expr")
	                                            ], MediumLevelILOperation.MLIL_CMP_UGE: [
	                                                ("left", "expr"), ("right", "expr")
	                                            ], MediumLevelILOperation.MLIL_CMP_SGT: [
	                                                ("left", "expr"), ("right", "expr")
	                                            ], MediumLevelILOperation.MLIL_CMP_UGT: [
	                                                ("left", "expr"), ("right", "expr")
	                                            ], MediumLevelILOperation.MLIL_TEST_BIT: [("left", "expr"),
	                                                                                      ("right", "expr")],
	    MediumLevelILOperation.MLIL_BOOL_TO_INT: [("src", "expr")], MediumLevelILOperation.MLIL_ADD_OVERFLOW: [
	        ("left", "expr"), ("right", "expr")
	    ], MediumLevelILOperation.MLIL_SYSCALL: [
	        ("output", "expr_list"), ("params", "expr_list")
	    ], MediumLevelILOperation.MLIL_SYSCALL_UNTYPED: [
	        ("output", "expr_list"), ("params", "expr"), ("stack", "expr")
	    ], MediumLevelILOperation.MLIL_TAILCALL: [
	        ("output", "expr_list"), ("dest", "expr"), ("params", "expr_list")
	    ], MediumLevelILOperation.MLIL_TAILCALL_UNTYPED: [("output", "expr_list"), ("dest", "expr"), ("params", "expr"),
	                                                      ("stack", "expr")], MediumLevelILOperation.MLIL_BP: [],
	    MediumLevelILOperation.MLIL_TRAP: [("vector", "int")], MediumLevelILOperation.MLIL_INTRINSIC: [
	        ("output", "var_list"), ("intrinsic", "intrinsic"), ("params", "expr_list")
	    ], MediumLevelILOperation.MLIL_INTRINSIC_SSA: [
	        ("output", "var_ssa_list"), ("intrinsic", "intrinsic"), ("params", "expr_list")
	    ], MediumLevelILOperation.MLIL_MEMORY_INTRINSIC_OUTPUT_SSA: [
	        ("dest_memory", "int"), ("output", "var_ssa_list")
	    ], MediumLevelILOperation.MLIL_MEMORY_INTRINSIC_SSA: [
	        ("output", "expr"), ("intrinsic", "intrinsic"), ("params", "expr_list"), ("src_memory", "int")
	    ], MediumLevelILOperation.MLIL_FREE_VAR_SLOT: [
	        ("dest", "var")
	    ], MediumLevelILOperation.MLIL_FREE_VAR_SLOT_SSA: [
	        ("prev", "var_ssa_dest_and_src")
	    ], MediumLevelILOperation.MLIL_UNDEF: [], MediumLevelILOperation.MLIL_UNIMPL: [],
	    MediumLevelILOperation.MLIL_UNIMPL_MEM: [("src", "expr")], MediumLevelILOperation.MLIL_FADD: [
	        ("left", "expr"), ("right", "expr")
	    ], MediumLevelILOperation.MLIL_FSUB: [("left", "expr"), ("right", "expr")], MediumLevelILOperation.MLIL_FMUL: [
	        ("left", "expr"), ("right", "expr")
	    ], MediumLevelILOperation.MLIL_FDIV: [("left", "expr"), ("right", "expr")], MediumLevelILOperation.MLIL_FSQRT: [
	        ("src", "expr")
	    ], MediumLevelILOperation.MLIL_FNEG: [("src", "expr")], MediumLevelILOperation.MLIL_FABS: [
	        ("src", "expr")
	    ], MediumLevelILOperation.MLIL_FLOAT_TO_INT: [("src", "expr")], MediumLevelILOperation.MLIL_INT_TO_FLOAT: [
	        ("src", "expr")
	    ], MediumLevelILOperation.MLIL_FLOAT_CONV: [("src", "expr")], MediumLevelILOperation.MLIL_ROUND_TO_INT: [
	        ("src", "expr")
	    ], MediumLevelILOperation.MLIL_FLOOR: [("src", "expr")], MediumLevelILOperation.MLIL_CEIL: [
	        ("src", "expr")
	    ], MediumLevelILOperation.MLIL_FTRUNC: [("src", "expr")], MediumLevelILOperation.MLIL_FCMP_E: [
	        ("left", "expr"), ("right", "expr")
	    ], MediumLevelILOperation.MLIL_FCMP_NE: [
	        ("left", "expr"), ("right", "expr")
	    ], MediumLevelILOperation.MLIL_FCMP_LT: [
	        ("left", "expr"), ("right", "expr")
	    ], MediumLevelILOperation.MLIL_FCMP_LE: [
	        ("left", "expr"), ("right", "expr")
	    ], MediumLevelILOperation.MLIL_FCMP_GE: [
	        ("left", "expr"), ("right", "expr")
	    ], MediumLevelILOperation.MLIL_FCMP_GT: [
	        ("left", "expr"), ("right", "expr")
	    ], MediumLevelILOperation.MLIL_FCMP_O: [
	        ("left", "expr"), ("right", "expr")
	    ], MediumLevelILOperation.MLIL_FCMP_UO: [
	        ("left", "expr"), ("right", "expr")
	    ], MediumLevelILOperation.MLIL_SET_VAR_SSA: [
	        ("dest", "var_ssa"), ("src", "expr")
	    ], MediumLevelILOperation.MLIL_SET_VAR_SSA_FIELD: [
	        ("dest", "var_ssa_dest_and_src"), ("prev", "var_ssa_dest_and_src"), ("offset", "int"), ("src", "expr")
	    ], MediumLevelILOperation.MLIL_SET_VAR_SPLIT_SSA: [
	        ("high", "var_ssa"), ("low", "var_ssa"), ("src", "expr")
	    ], MediumLevelILOperation.MLIL_SET_VAR_ALIASED: [
	        ("dest", "var_ssa_dest_and_src"), ("prev", "var_ssa_dest_and_src"), ("src", "expr")
	    ], MediumLevelILOperation.MLIL_SET_VAR_ALIASED_FIELD: [
	        ("dest", "var_ssa_dest_and_src"), ("prev", "var_ssa_dest_and_src"), ("offset", "int"), ("src", "expr")
	    ], MediumLevelILOperation.MLIL_VAR_SSA: [("src", "var_ssa")], MediumLevelILOperation.MLIL_VAR_SSA_FIELD: [
	        ("src", "var_ssa"), ("offset", "int")
	    ], MediumLevelILOperation.MLIL_VAR_ALIASED: [
	        ("src", "var_ssa")
	    ], MediumLevelILOperation.MLIL_VAR_ALIASED_FIELD: [
	        ("src", "var_ssa"), ("offset", "int")
	    ], MediumLevelILOperation.MLIL_VAR_SPLIT_SSA: [
	        ("high", "var_ssa"), ("low", "var_ssa")
	    ], MediumLevelILOperation.MLIL_VAR_OUTPUT_SSA: [
			("dest", "var_ssa")
		], MediumLevelILOperation.MLIL_VAR_OUTPUT_SSA_FIELD: [
			("dest", "var_ssa_dest_and_src"), ("prev", "var_ssa_dest_and_src"), ("offset", "int")
		], MediumLevelILOperation.MLIL_VAR_OUTPUT_ALIASED: [
			("dest", "var_ssa_dest_and_src"), ("prev", "var_ssa_dest_and_src")
		], MediumLevelILOperation.MLIL_VAR_OUTPUT_ALIASED_FIELD: [
			("dest", "var_ssa_dest_and_src"), ("prev", "var_ssa_dest_and_src"), ("offset", "int")
		], MediumLevelILOperation.MLIL_CALL_SSA: [
	        ("output", "expr"), ("output_dest_memory", "int"), ("dest", "expr"),
	        ("params", "expr_list"), ("src_memory", "int")
	    ], MediumLevelILOperation.MLIL_CALL_UNTYPED_SSA: [
	        ("output", "expr"), ("dest", "expr"), ("params", "expr"), ("stack", "expr")
	    ], MediumLevelILOperation.MLIL_SYSCALL_SSA: [
	        ("output", "expr"), ("params", "expr_list"),
	        ("src_memory", "int")
	    ], MediumLevelILOperation.MLIL_SYSCALL_UNTYPED_SSA: [
	        ("output", "expr"), ("params", "expr"), ("stack", "expr")
	    ], MediumLevelILOperation.MLIL_TAILCALL_SSA: [
	        ("output", "expr"), ("output_dest_memory", "int"),
	        ("dest", "expr"), ("params", "expr_list"), ("src_memory", "int")
	    ], MediumLevelILOperation.MLIL_TAILCALL_UNTYPED_SSA: [
	        ("output", "expr"), ("dest", "expr"), ("params", "expr"), ("stack", "expr")
	    ], MediumLevelILOperation.MLIL_CALL_OUTPUT_SSA: [
	        ("dest_memory", "int"), ("dest", "var_ssa_list")
	    ], MediumLevelILOperation.MLIL_CALL_PARAM_SSA: [
	        ("src_memory", "int"), ("src", "expr_list")
	    ], MediumLevelILOperation.MLIL_LOAD_SSA: [
	        ("src", "expr"), ("src_memory", "int")
	    ], MediumLevelILOperation.MLIL_LOAD_STRUCT_SSA: [
	        ("src", "expr"), ("offset", "int"), ("src_memory", "int")
	    ], MediumLevelILOperation.MLIL_STORE_SSA: [("dest", "expr"), ("dest_memory", "int"), ("src_memory", "int"),
	                                               ("src", "expr")], MediumLevelILOperation.MLIL_STORE_STRUCT_SSA: [
	                                                   ("dest", "expr"), ("offset", "int"), ("dest_memory", "int"),
	                                                   ("src_memory", "int"), ("src", "expr")
	                                               ], MediumLevelILOperation.MLIL_VAR_PHI: [
	                                                   ("dest", "var_ssa"), ("src", "var_ssa_list")
	                                               ], MediumLevelILOperation.MLIL_MEM_PHI: [("dest_memory", "int"),
	                                                                                        ("src_memory", "int_list")]
	}

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

	def _get_var_ssa_dest_and_src(self, operand_index1: int, operand_index2: int) -> SSAVariable:
		var = variable.Variable.from_identifier(self.function, self.instr.operands[operand_index1])
		dest_version = self.instr.operands[operand_index2]
		return SSAVariable(var, dest_version)

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


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILNop(MediumLevelILInstruction):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILNoret(MediumLevelILInstruction, Terminal):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILBp(MediumLevelILInstruction, Terminal):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILUndef(MediumLevelILInstruction):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILUnimpl(MediumLevelILInstruction):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILLoad(MediumLevelILInstruction, Load):
	@property
	def src(self) -> MediumLevelILInstruction:
		return self._get_expr(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [("src", self.src, "MediumLevelILInstruction")]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILVar(MediumLevelILInstruction, VariableInstruction):
	@property
	def src(self) -> variable.Variable:
		return self._get_var(0)

	@property
	def var(self) -> variable.Variable:
		return self._get_var(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [("var", self.var, "Variable")]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILAddressOf(MediumLevelILInstruction):
	@property
	def src(self) -> variable.Variable:
		return self._get_var(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [("src", self.src, "Variable")]

	@property
	def vars_address_taken(self) -> List[variable.Variable]:
		return [self.src]


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
		return [("constant", self.constant, "int")]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILConstPtr(MediumLevelILConstBase):
	@property
	def constant(self) -> int:
		return self._get_int(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [("constant", self.constant, "int")]

	@property
	def string(self) -> Optional[Tuple[str, StringType]]:
		return self.function.view.check_for_string_annotation_type(self.constant, True, True, 0)


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILFloatConst(MediumLevelILConstBase, FloatingPoint):
	@property
	def constant(self) -> float:
		return self._get_float(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [("constant", self.constant, "float")]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILImport(MediumLevelILConstBase):
	@property
	def constant(self) -> int:
		return self._get_int(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [("constant", self.constant, "int")]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILConstData(MediumLevelILConstBase):
	@property
	def constant(self) -> variable.ConstantData:
		return self._get_constant_data(0, 1)

	@property
	def constant_data(self) -> variable.ConstantData:
		return self._get_constant_data(0, 1)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [("constant", self.constant, "ConstantData")]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILNeg(MediumLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILNot(MediumLevelILUnaryBase, Arithmetic):
	pass


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
		return [("dest", self.dest, "MediumLevelILInstruction")]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILRetHint(MediumLevelILInstruction, ControlFlow):
	@property
	def dest(self) -> MediumLevelILInstruction:
		return self._get_expr(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [("dest", self.dest, "MediumLevelILInstruction")]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILCallOutput(MediumLevelILInstruction):
	@property
	def dest(self) -> List[variable.Variable]:
		return self._get_var_list(0, 1)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [("dest", self.dest, "List[Variable]")]

	@property
	def vars_written(self) -> List[variable.Variable]:
		return self.dest



@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILCallParam(MediumLevelILInstruction):
	def __repr__(self):
		return f"<MediumLevelILCallParam: {self.src}>"

	@property
	def src(self) -> List[MediumLevelILInstruction]:
		return self._get_expr_list(0, 1)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [("src", self.src, "List[MediumLevelILInstruction]")]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILSeparateParamList(MediumLevelILInstruction):
	def __repr__(self):
		return f"<MediumLevelILSeparateParamList: {self.params}>"

	@property
	def params(self) -> List[MediumLevelILInstruction]:
		return self._get_expr_list(0, 1)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [("params", self.params, "List[MediumLevelILInstruction]")]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILSharedParamSlot(MediumLevelILInstruction):
	def __repr__(self):
		return f"<MediumLevelILSharedParamSlot: {self.params}>"

	@property
	def params(self) -> List[MediumLevelILInstruction]:
		return self._get_expr_list(0, 1)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [("params", self.params, "List[MediumLevelILInstruction]")]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILVarOutput(MediumLevelILInstruction, RegisterStack):
	@property
	def dest(self) -> variable.Variable:
		return self._get_var(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [("dest", self.dest, "Variable")]


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
			('dest', self.dest, 'Variable'),
			('offset', self.offset, 'int')
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
		return [("src", self.src, "List[MediumLevelILInstruction]")]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILGoto(MediumLevelILInstruction, Terminal):
	@property
	def dest(self) -> InstructionIndex:
		return InstructionIndex(self._get_int(0))

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [("dest", self.dest, "InstructionIndex")]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILBoolToInt(MediumLevelILInstruction):
	@property
	def src(self) -> MediumLevelILInstruction:
		return self._get_expr(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [("src", self.src, "MediumLevelILInstruction")]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILFreeVarSlot(MediumLevelILInstruction, RegisterStack):
	@property
	def dest(self) -> variable.Variable:
		return self._get_var(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [("dest", self.dest, "Variable")]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILTrap(MediumLevelILInstruction, Terminal):
	@property
	def vector(self) -> int:
		return self._get_int(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [("vector", self.vector, "int")]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILFreeVarSlotSsa(MediumLevelILInstruction, SSA, RegisterStack):
	@property
	def dest(self) -> SSAVariable:
		return self._get_var_ssa_dest_and_src(0, 1)

	@property
	def prev(self) -> SSAVariable:
		return self._get_var_ssa_dest_and_src(0, 2)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			("dest", self.dest, "SSAVariable"),
			("prev", self.prev, "SSAVariable"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILUnimplMem(MediumLevelILInstruction, Memory):
	@property
	def src(self) -> MediumLevelILInstruction:
		return self._get_expr(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [("src", self.src, "MediumLevelILInstruction")]


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
class MediumLevelILVarSsa(MediumLevelILInstruction, SSAVariableInstruction):
	@property
	def src(self) -> SSAVariable:
		return self._get_var_ssa(0, 1)

	@property
	def var(self) -> SSAVariable:
		return self._get_var_ssa(0, 1)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [("var", self.var, "SSAVariable")]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILVarOutputSsa(MediumLevelILInstruction, SSAVariableInstruction):
	@property
	def dest(self) -> SSAVariable:
		return self._get_var_ssa(0, 1)

	@property
	def var(self) -> SSAVariable:
		return self._get_var_ssa(0, 1)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [("var", self.var, "SSAVariable")]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILVarOutputSsaField(MediumLevelILInstruction, SetVar, SSA):
	@property
	def dest(self) -> SSAVariable:
		return self._get_var_ssa_dest_and_src(0, 1)

	@property
	def prev(self) -> SSAVariable:
		return self._get_var_ssa_dest_and_src(0, 2)

	@property
	def offset(self) -> int:
		return self._get_int(3)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			('dest', self.dest, 'SSAVariable'),
			('prev', self.prev, 'SSAVariable'),
			('offset', self.offset, 'int')
		]

	@property
	def vars_read(self) -> List[SSAVariable]:
		return [self.prev]  # type: ignore # we're guaranteed not to return non-SSAVariables here

	@property
	def vars_written(self) -> List[SSAVariable]:
		return [self.dest]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILVarOutputAliased(MediumLevelILInstruction, SetVar, SSA):
	@property
	def dest(self) -> SSAVariable:
		return self._get_var_ssa_dest_and_src(0, 1)

	@property
	def prev(self) -> SSAVariable:
		return self._get_var_ssa_dest_and_src(0, 2)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			('dest', self.dest, 'SSAVariable'),
			('prev', self.prev, 'SSAVariable')
		]

	@property
	def vars_read(self) -> List[Union[variable.Variable, SSAVariable]]:
		return []

	@property
	def vars_written(self) -> List[SSAVariable]:
		return [self.dest]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILVarOutputAliasedField(MediumLevelILInstruction, SetVar, SSA):
	@property
	def dest(self) -> SSAVariable:
		return self._get_var_ssa_dest_and_src(0, 1)

	@property
	def prev(self) -> SSAVariable:
		return self._get_var_ssa_dest_and_src(0, 2)

	@property
	def offset(self) -> int:
		return self._get_int(3)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			('dest', self.dest, 'SSAVariable'),
			('prev', self.prev, 'SSAVariable'),
			('offset', self.offset, 'int')
		]

	@property
	def vars_read(self) -> List[SSAVariable]:
		return [self.prev]  # type: ignore # we're guaranteed not to return non-SSAVariables here

	@property
	def vars_written(self) -> List[SSAVariable]:
		return [self.dest]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILVarAliased(MediumLevelILInstruction, SSA, AliasedVariableInstruction):
	@property
	def src(self) -> SSAVariable:
		return self._get_var_ssa(0, 1)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [("src", self.src, "SSAVariable")]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILSetVar(MediumLevelILInstruction, SetVar):
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

	@property
	def vars_written(self) -> List[variable.Variable]:
		return [self.dest]

	@property
	def vars_read(self) -> List[Union[variable.Variable, SSAVariable]]:
		return self.src.vars_read


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
class MediumLevelILAddressOfField(MediumLevelILInstruction):
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
			("offset", self.offset, "int")
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
class MediumLevelILAdd(MediumLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILSub(MediumLevelILBinaryBase, Arithmetic):
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
class MediumLevelILRor(MediumLevelILBinaryBase, Arithmetic):
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
class MediumLevelILAddOverflow(MediumLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILSyscall(MediumLevelILInstruction, Syscall):
	@property
	def output(self) -> List[variable.Variable]:
		result = []
		for expr in self.output_exprs:
			var = expr._var_written_for_function_call_output()
			if var is not None:
				result.append(var)
		return result

	@property
	def output_exprs(self) -> List[MediumLevelILInstruction]:
		return self._get_expr_list(0, 1)

	@property
	def params(self) -> List[MediumLevelILInstruction]:
		return self._get_expr_list(2, 3)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			('output', self.output, 'List[Variable]'),
			('params', self.params, 'List[MediumLevelILInstruction]'),
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
			('src', self.src, 'SSAVariable'),
			('offset', self.offset, 'int'),
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
			('src', self.src, 'SSAVariable'),
			('offset', self.offset, 'int'),
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
			('high', self.high, 'SSAVariable'),
			('low', self.low, 'SSAVariable'),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILCallOutputSsa(MediumLevelILInstruction, SSA):
	@property
	def dest_memory(self) -> int:
		return self._get_int(0)

	@property
	def dest(self) -> List[SSAVariable]:
		result = []
		for expr in self.dest_exprs:
			var = expr._ssa_var_written_for_function_call_output()
			if var is not None:
				result.append(var)
		return result

	@property
	def dest_exprs(self) -> List[MediumLevelILInstruction]:
		return self._get_expr_list(1, 2)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			('dest_memory', self.dest_memory, 'int'),
			('dest', self.dest, 'List[SSAVariable]'),
		]

	@property
	def vars_written(self) -> List[SSAVariable]:
		return self.dest


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILCallParamSsa(MediumLevelILInstruction, SSA):
	def __repr__(self):
		return f"<MediumLevelILCallParamSsa: {self.src}>"

	@property
	def src_memory(self) -> int:
		return self._get_int(0)

	@property
	def src(self) -> List[MediumLevelILInstruction]:
		return self._get_expr_list(1, 2)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			('src_memory', self.src_memory, 'int'),
			('src', self.src, 'List[MediumLevelILInstruction]'),
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
			('src', self.src, 'MediumLevelILInstruction'),
			('src_memory', self.src_memory, 'int'),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILVarPhi(MediumLevelILInstruction, SetVar, Phi, SSA):
	@property
	def dest(self) -> SSAVariable:
		return self._get_var_ssa(0, 1)

	@property
	def src(self) -> List[SSAVariable]:
		return self._get_var_ssa_list(2, 3)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			('dest', self.dest, 'SSAVariable'),
			('src', self.src, 'List[SSAVariable]'),
		]

	@property
	def vars_read(self) -> List[SSAVariable]:
		return self.src

	@property
	def vars_written(self) -> List[SSAVariable]:
		return [self.dest]


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
			('dest_memory', self.dest_memory, 'int'),
			('src_memory', self.src_memory, 'List[int]'),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILSetVarSsa(MediumLevelILInstruction, SetVar, SSA):
	@property
	def dest(self) -> SSAVariable:
		return self._get_var_ssa(0, 1)

	@property
	def src(self) -> MediumLevelILInstruction:
		return self._get_expr(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			('dest', self.dest, 'SSAVariable'),
			('src', self.src, 'MediumLevelILInstruction'),
		]

	@property
	def vars_read(self) -> List[Union[variable.Variable, SSAVariable]]:
		return self.src.vars_read

	@property
	def vars_written(self) -> List[SSAVariable]:
		return [self.dest]


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
			('dest', self.dest, 'MediumLevelILInstruction'),
			('targets', self.targets, 'Dict[int, int]'),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILSetVarAliased(MediumLevelILInstruction, SetVar, SSA):
	@property
	def dest(self) -> SSAVariable:
		return self._get_var_ssa_dest_and_src(0, 1)

	@property
	def prev(self) -> SSAVariable:
		return self._get_var_ssa_dest_and_src(0, 2)

	@property
	def src(self) -> MediumLevelILInstruction:
		return self._get_expr(3)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			('dest', self.dest, 'SSAVariable'),
			('prev', self.prev, 'SSAVariable'),
			('src', self.src, 'MediumLevelILInstruction'),
		]

	@property
	def vars_read(self) -> List[Union[variable.Variable, SSAVariable]]:
		return self.src.vars_read

	@property
	def vars_written(self) -> List[SSAVariable]:
		return [self.dest]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILSyscallUntyped(MediumLevelILCallBase, Syscall):
	@property
	def output(self) -> List[variable.Variable]:
		result = []
		for expr in self.output_exprs:
			var = expr._var_written_for_function_call_output()
			if var is not None:
				result.append(var)
		return result

	@property
	def output_exprs(self) -> List[MediumLevelILInstruction]:
		return self._get_expr_list(0, 1)

	@property
	def params(self) -> List[MediumLevelILInstruction]:
		inst = self._get_expr(2)
		assert isinstance(inst, MediumLevelILCallParam), "MediumLevelILCallUntyped return bad type for 'params'"
		return inst.src

	@property
	def stack(self) -> MediumLevelILInstruction:
		return self._get_expr(3)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			('output', self.output, 'List[Variable]'),
			('params', self.params, 'List[MediumLevelILInstruction]'),
			('stack', self.stack, 'MediumLevelILInstruction'),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILIntrinsic(MediumLevelILInstruction, Intrinsic):
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
			('output', self.output, 'List[Variable]'),
			('intrinsic', self.intrinsic, "ILIntrinsic"),
			('params', self.params, 'List[MediumLevelILInstruction]'),
		]

	@property
	def vars_read(self) -> List[variable.Variable]:
		result: List[variable.Variable] = []
		for i in self.params:
			result.extend(i.vars_read)  # type: ignore
		return result

	@property
	def vars_written(self) -> List[variable.Variable]:
		return self.output


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILIntrinsicSsa(MediumLevelILInstruction, SSA):
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
			('output', self.output, 'List[SSAVariable]'),
			('intrinsic', self.intrinsic, 'ILIntrinsic'),
			('params', self.params, 'List[MediumLevelILInstruction]'),
		]

	@property
	def vars_read(self) -> List[SSAVariable]:
		result: List[SSAVariable] = []
		for i in self.params:
			result.extend(i.vars_read)  # type: ignore
		return result

	@property
	def vars_written(self) -> List[SSAVariable]:
		return self.output


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILMemoryIntrinsicOutputSsa(MediumLevelILInstruction, SSA):
	def __repr__(self):
		return f"<MediumLevelILMemoryIntrinsicOutputSsa: {self.dest_memory} {self.output}>"

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
class MediumLevelILMemoryIntrinsicSsa(MediumLevelILInstruction, SSA):
	@property
	def output(self) -> List[SSAVariable]:
		inst = self._get_expr(0)
		assert isinstance(inst, MediumLevelILMemoryIntrinsicOutputSsa), "MediumLevelILMemoryIntrinsicSsa expected MediumLevelILMemoryIntrinsicOutputSsa as first operand"
		return inst.output

	@property
	def dest_memory(self) -> int:
		inst = self._get_expr(0)
		assert isinstance(inst, MediumLevelILMemoryIntrinsicOutputSsa), "MediumLevelILMemoryIntrinsicSsa expected MediumLevelILMemoryIntrinsicOutputSsa as first operand"
		return inst.dest_memory

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
class MediumLevelILSetVarSsaField(MediumLevelILInstruction, SetVar, SSA):
	@property
	def dest(self) -> SSAVariable:
		return self._get_var_ssa_dest_and_src(0, 1)

	@property
	def prev(self) -> SSAVariable:
		return self._get_var_ssa_dest_and_src(0, 2)

	@property
	def offset(self) -> int:
		return self._get_int(3)

	@property
	def src(self) -> MediumLevelILInstruction:
		return self._get_expr(4)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			('dest', self.dest, 'SSAVariable'),
			('prev', self.prev, 'SSAVariable'),
			('offset', self.offset, 'int'),
			('src', self.src, 'MediumLevelILInstruction'),
		]

	@property
	def vars_read(self) -> List[SSAVariable]:
		return [self.prev, *self.src.vars_read]  # type: ignore # we're guaranteed not to return non-SSAVariables here

	@property
	def vars_written(self) -> List[SSAVariable]:
		return [self.dest]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILSetVarSplitSsa(MediumLevelILInstruction, SetVar, SSA):
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
			('high', self.high, 'SSAVariable'),
			('low', self.low, 'SSAVariable'),
			('src', self.src, 'MediumLevelILInstruction'),
		]

	@property
	def vars_read(self) -> List[Union[variable.Variable, SSAVariable]]:
		return self.src.vars_read

	@property
	def vars_written(self) -> List[SSAVariable]:
		return [self.high, self.low]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILSetVarAliasedField(MediumLevelILInstruction, SetVar, SSA):
	@property
	def dest(self) -> SSAVariable:
		return self._get_var_ssa_dest_and_src(0, 1)

	@property
	def prev(self) -> SSAVariable:
		return self._get_var_ssa_dest_and_src(0, 2)

	@property
	def offset(self) -> int:
		return self._get_int(3)

	@property
	def src(self) -> MediumLevelILInstruction:
		return self._get_expr(4)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			('dest', self.dest, 'SSAVariable'),
			('prev', self.prev, 'SSAVariable'),
			('offset', self.offset, 'int'),
			('src', self.src, 'MediumLevelILInstruction'),
		]

	@property
	def vars_read(self) -> List[SSAVariable]:
		return [self.prev, *self.src.vars_read]  # type: ignore # we're guaranteed not to return non-SSAVariables here


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILSyscallSsa(MediumLevelILCallBase, Syscall, SSA):
	@property
	def output(self) -> List[SSAVariable]:
		inst = self._get_expr(0)
		assert isinstance(inst, MediumLevelILCallOutputSsa), "MediumLevelILSyscallSsa return bad type for output"
		return inst.dest

	@property
	def output_exprs(self) -> List[MediumLevelILInstruction]:
		inst = self._get_expr(0)
		assert isinstance(inst, MediumLevelILCallOutputSsa), "MediumLevelILCallSsa return bad type for output"
		return inst.dest_exprs

	@property
	def output_dest_memory(self) -> int:
		inst = self._get_expr(0)
		assert isinstance(inst, MediumLevelILCallOutputSsa), "MediumLevelILSyscallSsa return bad type for output"
		return inst.dest_memory

	@property
	def params(self) -> List[MediumLevelILInstruction]:
		return self._get_expr_list(1, 2)

	@property
	def src_memory(self) -> int:
		return self._get_int(3)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			('output', self.output, 'List[SSAVariable]'),
			('output_dest_memory', self.output_dest_memory, 'int'),
			('params', self.params, 'List[MediumLevelILInstruction]'),
			('src_memory', self.src_memory, 'int'),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILSyscallUntypedSsa(MediumLevelILCallBase, Syscall, SSA):
	@property
	def output(self) -> List[SSAVariable]:
		inst = self._get_expr(0)
		assert isinstance(
		    inst, MediumLevelILCallOutputSsa
		), "MediumLevelILSyscallUntypedSsa return bad type for 'output'"
		return inst.dest

	@property
	def output_exprs(self) -> List[MediumLevelILInstruction]:
		inst = self._get_expr(0)
		assert isinstance(inst, MediumLevelILCallOutputSsa), "MediumLevelILCallSsa return bad type for output"
		return inst.dest_exprs

	@property
	def output_dest_memory(self) -> int:
		inst = self._get_expr(0)
		assert isinstance(
		    inst, MediumLevelILCallOutputSsa
		), "MediumLevelILSyscallUntypedSsa return bad type for 'output_dest_memory'"
		return inst.dest_memory

	@property
	def params(self) -> List[MediumLevelILInstruction]:
		inst = self._get_expr(1)
		assert isinstance(
		    inst, MediumLevelILCallParamSsa
		), "MediumLevelILSyscallUntypedSsa return bad type for 'params'"
		return inst.src

	@property
	def params_src_memory(self) -> int:
		inst = self._get_expr(1)
		assert isinstance(
		    inst, MediumLevelILCallParamSsa
		), "MediumLevelILSyscallUntypedSsa return bad type for 'params_src_memory'"
		return inst.src_memory

	@property
	def stack(self) -> MediumLevelILInstruction:
		return self._get_expr(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			('output', self.output, 'List[SSAVariable]'),
			('output_dest_memory', self.output_dest_memory, 'int'),
			('params', self.params, 'List[SSAVariable]'),
			('params_src_memory', self.params_src_memory, 'int'),
			('stack', self.stack, 'MediumLevelILInstruction'),
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
			('src', self.src, 'MediumLevelILInstruction'),
			('offset', self.offset, 'int'),
			('src_memory', self.src_memory, 'int'),
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
			('dest', self.dest, 'Variable'),
			('offset', self.offset, 'int'),
			('src', self.src, 'MediumLevelILInstruction'),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILSetVarSplit(MediumLevelILInstruction, SetVar):
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
			('high', self.high, 'Variable'),
			('low', self.low, 'Variable'),
			('src', self.src, 'MediumLevelILInstruction'),
		]

	@property
	def vars_written(self) -> List[variable.Variable]:
		return [self.high, self.low]



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
			('dest', self.dest, 'MediumLevelILInstruction'),
			('offset', self.offset, 'int'),
			('src', self.src, 'MediumLevelILInstruction'),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILAdc(MediumLevelILCarryBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILSbb(MediumLevelILCarryBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILRlc(MediumLevelILCarryBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILRrc(MediumLevelILCarryBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILCall(MediumLevelILCallBase, Localcall):
	@property
	def output(self) -> List[variable.Variable]:
		result = []
		for expr in self.output_exprs:
			var = expr._var_written_for_function_call_output()
			if var is not None:
				result.append(var)
		return result

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
			('output', self.output, 'List[Variable]'),
			('dest', self.dest, 'MediumLevelILInstruction'),
			('params', self.params, 'List[MediumLevelILInstruction]'),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILIf(MediumLevelILInstruction, Terminal):
	@property
	def condition(self) -> MediumLevelILInstruction:
		return self._get_expr(0)

	@property
	def true(self) -> InstructionIndex:
		return self._get_int(1)

	@property
	def false(self) -> InstructionIndex:
		return self._get_int(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			('condition', self.condition, 'MediumLevelILInstruction'),
			('true', self.true, 'InstructionIndex'),
			('false', self.false, 'InstructionIndex'),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILTailcallUntyped(MediumLevelILCallBase, Tailcall):
	@property
	def output(self) -> List[variable.Variable]:
		result = []
		for expr in self.output_exprs:
			var = expr._var_written_for_function_call_output()
			if var is not None:
				result.append(var)
		return result

	@property
	def output_exprs(self) -> List[MediumLevelILInstruction]:
		return self._get_expr_list(0, 1)

	@property
	def dest(self) -> MediumLevelILInstruction:
		return self._get_expr(2)

	@property
	def params(self) -> List[MediumLevelILInstruction]:
		inst = self._get_expr(3)
		assert isinstance(inst, MediumLevelILCallParam), "MediumLevelILTailcallUntyped return bad type for 'params'"
		return inst.src

	@property
	def stack(self) -> MediumLevelILInstruction:
		return self._get_expr(4)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			('output', self.output, 'List[Variable]'),
			('dest', self.dest, 'MediumLevelILInstruction'),
			('params', self.params, 'List[MediumLevelILInstruction]'),
			('stack', self.stack, 'MediumLevelILInstruction'),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILCallSsa(MediumLevelILCallBase, Localcall, SSA):
	@property
	def output(self) -> List[SSAVariable]:
		inst = self._get_expr(0)
		assert isinstance(inst, MediumLevelILCallOutputSsa), "MediumLevelILCallSsa return bad type for output"
		return inst.dest

	@property
	def output_exprs(self) -> List[MediumLevelILInstruction]:
		inst = self._get_expr(0)
		assert isinstance(inst, MediumLevelILCallOutputSsa), "MediumLevelILCallSsa return bad type for output"
		return inst.dest_exprs

	@property
	def output_dest_memory(self) -> int:
		inst = self._get_expr(0)
		assert isinstance(inst, MediumLevelILCallOutputSsa), "MediumLevelILCallSsa return bad type for output"
		return inst.dest_memory

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
			('output', self.output, 'List[SSAVariable]'),
			('output_dest_memory', self.output_dest_memory, 'int'),
			('dest', self.dest, 'MediumLevelILInstruction'),
			('params', self.params, 'List[MediumLevelILInstruction]'),
			('src_memory', self.src_memory, 'int'),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILCallUntypedSsa(MediumLevelILCallBase, Localcall, SSA):
	@property
	def output(self) -> List[SSAVariable]:
		inst = self._get_expr(0)
		assert isinstance(inst, MediumLevelILCallOutputSsa), "MediumLevelILCallUntypedSsa return bad type for output"
		return inst.dest

	@property
	def output_exprs(self) -> List[MediumLevelILInstruction]:
		inst = self._get_expr(0)
		assert isinstance(inst, MediumLevelILCallOutputSsa), "MediumLevelILCallSsa return bad type for output"
		return inst.dest_exprs

	@property
	def output_dest_memory(self) -> int:
		inst = self._get_expr(0)
		assert isinstance(inst, MediumLevelILCallOutputSsa), "MediumLevelILCallUntypedSsa return bad type for output"
		return inst.dest_memory

	@property
	def dest(self) -> MediumLevelILInstruction:
		return self._get_expr(1)

	@property
	def params(self) -> List[MediumLevelILInstruction]:
		inst = self._get_expr(2)
		assert isinstance(inst, MediumLevelILCallParamSsa), "MediumLevelILCallUntypedSsa return bad type for 'params'"
		return inst.src

	@property
	def params_src_memory(self):
		inst = self._get_expr(2)
		assert isinstance(
		    inst, MediumLevelILCallParamSsa
		), "MediumLevelILCallUntypedSsa return bad type for 'params_src_memory'"
		return inst.src_memory

	@property
	def stack(self) -> MediumLevelILInstruction:
		return self._get_expr(3)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			('output', self.output, 'List[SSAVariable]'),
			('output_dest_memory', self.output_dest_memory, 'int'),
			('dest', self.dest, 'MediumLevelILInstruction'),
			('params', self.params, 'List[SSAVariable]'),
			('params_src_memory', self.params_src_memory, 'int'),
			('stack', self.stack, 'MediumLevelILInstruction'),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILTailcall(MediumLevelILCallBase, Tailcall):
	@property
	def output(self) -> List[variable.Variable]:
		result = []
		for expr in self.output_exprs:
			var = expr._var_written_for_function_call_output()
			if var is not None:
				result.append(var)
		return result

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
			('output', self.output, 'List[Variable]'),
			('dest', self.dest, 'MediumLevelILInstruction'),
			('params', self.params, 'List[MediumLevelILInstruction]'),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILTailcallSsa(MediumLevelILCallBase, Tailcall, SSA):
	@property
	def output(self) -> List[SSAVariable]:
		inst = self._get_expr(0)
		assert isinstance(inst, MediumLevelILCallOutputSsa), "MediumLevelILTailcallSsa return bad type for output"
		return inst.dest

	@property
	def output_exprs(self) -> List[MediumLevelILInstruction]:
		inst = self._get_expr(0)
		assert isinstance(inst, MediumLevelILCallOutputSsa), "MediumLevelILCallSsa return bad type for output"
		return inst.dest_exprs

	@property
	def output_dest_memory(self) -> int:
		inst = self._get_expr(0)
		assert isinstance(inst, MediumLevelILCallOutputSsa), "MediumLevelILTailcallSsa return bad type for output"
		return inst.dest_memory

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
			('output', self.output, 'List[SSAVariable]'),
			('output_dest_memory', self.output_dest_memory, 'int'),
			('dest', self.dest, 'MediumLevelILInstruction'),
			('params', self.params, 'List[MediumLevelILInstruction]'),
			('src_memory', self.src_memory, 'int'),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILTailcallUntypedSsa(MediumLevelILCallBase, Tailcall, SSA):
	@property
	def output(self) -> List[SSAVariable]:
		inst = self._get_expr(0)
		assert isinstance(
		    inst, MediumLevelILCallOutputSsa
		), "MediumLevelILTailcallUntypedSsa return bad type for 'output'"
		return inst.dest

	@property
	def output_exprs(self) -> List[MediumLevelILInstruction]:
		inst = self._get_expr(0)
		assert isinstance(inst, MediumLevelILCallOutputSsa), "MediumLevelILCallSsa return bad type for output"
		return inst.dest_exprs

	@property
	def output_dest_memory(self) -> int:
		inst = self._get_expr(0)
		assert isinstance(
		    inst, MediumLevelILCallOutputSsa
		), "MediumLevelILTailcallUntypedSsa return bad type for 'output'"
		return inst.dest_memory

	@property
	def dest(self) -> MediumLevelILInstruction:
		return self._get_expr(1)

	@property
	def params(self) -> List[MediumLevelILInstruction]:
		inst = self._get_expr(2)
		assert isinstance(
		    inst, MediumLevelILCallParamSsa
		), "MediumLevelILTailcallUntypedSsa return bad type for 'params'"
		return inst.src

	@property
	def stack(self) -> MediumLevelILInstruction:
		return self._get_expr(3)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			('output', self.output, 'List[SSAVariable]'),
			('output_dest_memory', self.output_dest_memory, 'int'),
			('dest', self.dest, 'MediumLevelILInstruction'),
			('params', self.params, 'List[SSAVariable]'),
			('stack', self.stack, 'MediumLevelILInstruction'),
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
			('dest', self.dest, 'MediumLevelILInstruction'),
			('dest_memory', self.dest_memory, 'int'),
			('src_memory', self.src_memory, 'int'),
			('src', self.src, 'MediumLevelILInstruction'),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILCallUntyped(MediumLevelILCallBase, Localcall):
	@property
	def output(self) -> List[variable.Variable]:
		result = []
		for expr in self.output_exprs:
			var = expr._var_written_for_function_call_output()
			if var is not None:
				result.append(var)
		return result

	@property
	def output_exprs(self) -> List[MediumLevelILInstruction]:
		return self._get_expr_list(0, 1)

	@property
	def dest(self) -> MediumLevelILInstruction:
		return self._get_expr(2)

	@property
	def params(self) -> List[MediumLevelILInstruction]:
		inst = self._get_expr(3)
		assert isinstance(inst, MediumLevelILCallParam), "MediumLevelILCallUntyped return bad type for 'params'"
		return inst.src

	@property
	def stack(self) -> MediumLevelILInstruction:
		return self._get_expr(4)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			('output', self.output, 'List[Variable]'),
			('dest', self.dest, 'MediumLevelILInstruction'),
			('params', self.params, 'List[MediumLevelILInstruction]'),
			('stack', self.stack, 'MediumLevelILInstruction'),
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
			('dest', self.dest, 'MediumLevelILInstruction'),
			('offset', self.offset, 'int'),
			('dest_memory', self.dest_memory, 'int'),
			('src_memory', self.src_memory, 'int'),
			('src', self.src, 'MediumLevelILInstruction'),
		]

@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILAssert(MediumLevelILInstruction):
	@property
	def src(self) -> variable.Variable:
		return self._get_var(0)

	@property
	def constraint(self) -> variable.PossibleValueSet:
		return self._get_constraint(1)

@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILAssertSsa(MediumLevelILInstruction, SSA):
	@property
	def src(self) -> SSAVariable:
		return self._get_var_ssa(0, 1)

	@property
	def constraint(self) -> variable.PossibleValueSet:
		return self._get_constraint(2)

@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILForceVer(MediumLevelILInstruction):
	@property
	def dest(self) -> variable.Variable:
		return self._get_var(0)

	@property
	def src(self) -> variable.Variable:
		return self._get_var(1)

	@property
	def reason(self) -> ForceVersionReason:
		return ForceVersionReason(self._get_int(2))

@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILForceVerSsa(MediumLevelILInstruction, SSA):
	@property
	def dest(self) -> SSAVariable:
		return self._get_var_ssa(0, 1)

	@property
	def src(self) -> SSAVariable:
		return self._get_var_ssa(2, 3)

	@property
	def reason(self) -> ForceVersionReason:
		return ForceVersionReason(self._get_int(4))

@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILBlockToExpand(MediumLevelILInstruction):
	@property
	def exprs(self) -> List[MediumLevelILInstruction]:
		return self._get_expr_list(0, 1)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [("exprs", self.exprs, "List[MediumLevelILInstruction]")]


ILInstruction = {
    MediumLevelILOperation.MLIL_NOP: MediumLevelILNop,  # [],
    MediumLevelILOperation.MLIL_NORET: MediumLevelILNoret,  # [],
    MediumLevelILOperation.MLIL_BP: MediumLevelILBp,  # [],
    MediumLevelILOperation.MLIL_UNDEF: MediumLevelILUndef,  # [],
    MediumLevelILOperation.MLIL_UNIMPL: MediumLevelILUnimpl,  # [],
    MediumLevelILOperation.MLIL_LOAD: MediumLevelILLoad,  # [("src", "expr")],
    MediumLevelILOperation.MLIL_VAR: MediumLevelILVar,  # [("src", "var")],
    MediumLevelILOperation.MLIL_ADDRESS_OF: MediumLevelILAddressOf,  # [("src", "var")],
    MediumLevelILOperation.MLIL_PASS_BY_REF: MediumLevelILPassByRef,  # [("src", "expr")],
	MediumLevelILOperation.MLIL_RETURN_BY_REF: MediumLevelILReturnByRef,  # [("src", "expr")],
    MediumLevelILOperation.MLIL_CONST: MediumLevelILConst,  # [("constant", "int")],
    MediumLevelILOperation.MLIL_CONST_PTR: MediumLevelILConstPtr,  # [("constant", "int")],
    MediumLevelILOperation.MLIL_FLOAT_CONST: MediumLevelILFloatConst,  # [("constant", "float")],
    MediumLevelILOperation.MLIL_IMPORT: MediumLevelILImport,  # [("constant", "int")],
    MediumLevelILOperation.MLIL_CONST_DATA: MediumLevelILConstData,  # [("constant", "ConstData")],
    MediumLevelILOperation.MLIL_SET_VAR: MediumLevelILSetVar,  # [("dest", "var"), ("src", "expr")],
    MediumLevelILOperation.MLIL_LOAD_STRUCT: MediumLevelILLoadStruct,  # [("src", "expr"), ("offset", "int")],
    MediumLevelILOperation.MLIL_STORE: MediumLevelILStore,  # [("dest", "expr"), ("src", "expr")],
    MediumLevelILOperation.MLIL_VAR_FIELD: MediumLevelILVarField,  # [("src", "var"), ("offset", "int")],
    MediumLevelILOperation.MLIL_VAR_SPLIT: MediumLevelILVarSplit,  # [("high", "var"), ("low", "var")],
    MediumLevelILOperation.MLIL_ADDRESS_OF_FIELD: MediumLevelILAddressOfField,  # [("src", "var"), ("offset", "int")],
    MediumLevelILOperation.MLIL_EXTERN_PTR: MediumLevelILExternPtr,  # [("constant", "int"), ("offset", "int")],
    MediumLevelILOperation.MLIL_ADD: MediumLevelILAdd,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_SUB: MediumLevelILSub,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_AND: MediumLevelILAnd,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_OR: MediumLevelILOr,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_XOR: MediumLevelILXor,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_LSL: MediumLevelILLsl,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_LSR: MediumLevelILLsr,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_ASR: MediumLevelILAsr,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_ROL: MediumLevelILRol,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_ROR: MediumLevelILRor,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_MUL: MediumLevelILMul,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_MULU_DP: MediumLevelILMuluDp,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_MULS_DP: MediumLevelILMulsDp,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_DIVU: MediumLevelILDivu,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_DIVU_DP: MediumLevelILDivuDp,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_DIVS: MediumLevelILDivs,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_DIVS_DP: MediumLevelILDivsDp,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_MODU: MediumLevelILModu,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_MODU_DP: MediumLevelILModuDp,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_MODS: MediumLevelILMods,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_MODS_DP: MediumLevelILModsDp,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_NEG: MediumLevelILNeg,  # [("src", "expr")],
    MediumLevelILOperation.MLIL_NOT: MediumLevelILNot,  # [("src", "expr")],
    MediumLevelILOperation.MLIL_BSWAP: MediumLevelILBswap,  # [("src", "expr")],
    MediumLevelILOperation.MLIL_POPCNT: MediumLevelILPopcnt,  # [("src", "expr")],
    MediumLevelILOperation.MLIL_CLZ: MediumLevelILClz,  # [("src", "expr")],
    MediumLevelILOperation.MLIL_CTZ: MediumLevelILCtz,  # [("src", "expr")],
    MediumLevelILOperation.MLIL_RBIT: MediumLevelILRbit,  # [("src", "expr")],
    MediumLevelILOperation.MLIL_CLS: MediumLevelILCls,  # [("src", "expr")],
    MediumLevelILOperation.MLIL_MINS: MediumLevelILMins,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_MAXS: MediumLevelILMaxs,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_MINU: MediumLevelILMinu,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_MAXU: MediumLevelILMaxu,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_ABS: MediumLevelILAbs,  # [("src", "expr")],
    MediumLevelILOperation.MLIL_SX: MediumLevelILSx,  # [("src", "expr")],
    MediumLevelILOperation.MLIL_ZX: MediumLevelILZx,  # [("src", "expr")],
    MediumLevelILOperation.MLIL_LOW_PART: MediumLevelILLowPart,  # [("src", "expr")],
    MediumLevelILOperation.MLIL_JUMP: MediumLevelILJump,  # [("dest", "expr")],
    MediumLevelILOperation.MLIL_RET_HINT: MediumLevelILRetHint,  # [("dest", "expr")],
    MediumLevelILOperation.MLIL_CALL_PARAM: MediumLevelILCallParam,  # [("src", "expr_list")],
    MediumLevelILOperation.MLIL_SEPARATE_PARAM_LIST: MediumLevelILSeparateParamList,  # [("src", "expr_list")],
    MediumLevelILOperation.MLIL_SHARED_PARAM_SLOT: MediumLevelILSharedParamSlot,  # [("src", "expr_list")],
	MediumLevelILOperation.MLIL_VAR_OUTPUT: MediumLevelILVarOutput,  # [("dest", "var")],
	MediumLevelILOperation.MLIL_VAR_OUTPUT_FIELD: MediumLevelILVarOutputField,  # [("dest", "var"), ("offset", "int")],
	MediumLevelILOperation.MLIL_STORE_OUTPUT: MediumLevelILStoreOutput,  # [("dest", "expr")],
    MediumLevelILOperation.MLIL_RET: MediumLevelILRet,  # [("src", "expr_list")],
    MediumLevelILOperation.MLIL_GOTO: MediumLevelILGoto,  # [("dest", "int")],
    MediumLevelILOperation.MLIL_BOOL_TO_INT: MediumLevelILBoolToInt,  # [("src", "expr")],
    MediumLevelILOperation.MLIL_FREE_VAR_SLOT: MediumLevelILFreeVarSlot,  # [("dest", "var")],
    MediumLevelILOperation.MLIL_TRAP: MediumLevelILTrap,  # [("vector", "int")],
    MediumLevelILOperation.MLIL_FREE_VAR_SLOT_SSA: MediumLevelILFreeVarSlotSsa,  # [("prev", "var_ssa_dest_and_src")],
    MediumLevelILOperation.MLIL_UNIMPL_MEM: MediumLevelILUnimplMem,  # [("src", "expr")],
    MediumLevelILOperation.MLIL_FSQRT: MediumLevelILFsqrt,  # [("src", "expr")],
    MediumLevelILOperation.MLIL_FNEG: MediumLevelILFneg,  # [("src", "expr")],
    MediumLevelILOperation.MLIL_FABS: MediumLevelILFabs,  # [("src", "expr")],
    MediumLevelILOperation.MLIL_FLOAT_TO_INT: MediumLevelILFloatToInt,  # [("src", "expr")],
    MediumLevelILOperation.MLIL_INT_TO_FLOAT: MediumLevelILIntToFloat,  # [("src", "expr")],
    MediumLevelILOperation.MLIL_FLOAT_CONV: MediumLevelILFloatConv,  # [("src", "expr")],
    MediumLevelILOperation.MLIL_ROUND_TO_INT: MediumLevelILRoundToInt,  # [("src", "expr")],
    MediumLevelILOperation.MLIL_FLOOR: MediumLevelILFloor,  # [("src", "expr")],
    MediumLevelILOperation.MLIL_CEIL: MediumLevelILCeil,  # [("src", "expr")],
    MediumLevelILOperation.MLIL_FTRUNC: MediumLevelILFtrunc,  # [("src", "expr")],
    MediumLevelILOperation.MLIL_VAR_SSA: MediumLevelILVarSsa,  # [("src", "var_ssa")],
    MediumLevelILOperation.MLIL_VAR_ALIASED: MediumLevelILVarAliased,  # [("src", "var_ssa")],
	MediumLevelILOperation.MLIL_VAR_OUTPUT_SSA: MediumLevelILVarOutputSsa,  # [("dest", "var_ssa")],
	MediumLevelILOperation.MLIL_VAR_OUTPUT_SSA_FIELD:
		MediumLevelILVarOutputSsaField,  # [("prev", "var_ssa_dest_and_src"), ("offset", "int")],
	MediumLevelILOperation.MLIL_VAR_OUTPUT_ALIASED:
		MediumLevelILVarOutputAliased,  # [("prev", "var_ssa_dest_and_src")],
	MediumLevelILOperation.MLIL_VAR_OUTPUT_ALIASED_FIELD:
		MediumLevelILVarOutputAliasedField,  # [("prev", "var_ssa_dest_and_src"), ("offset", "int")],
    MediumLevelILOperation.MLIL_CMP_E: MediumLevelILCmpE,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_CMP_NE: MediumLevelILCmpNe,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_CMP_SLT: MediumLevelILCmpSlt,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_CMP_ULT: MediumLevelILCmpUlt,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_CMP_SLE: MediumLevelILCmpSle,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_CMP_ULE: MediumLevelILCmpUle,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_CMP_SGE: MediumLevelILCmpSge,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_CMP_UGE: MediumLevelILCmpUge,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_CMP_SGT: MediumLevelILCmpSgt,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_CMP_UGT: MediumLevelILCmpUgt,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_TEST_BIT: MediumLevelILTestBit,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_ADD_OVERFLOW: MediumLevelILAddOverflow,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_SYSCALL: MediumLevelILSyscall,  # [("output", "expr_list"), ("params", "expr_list")],
    MediumLevelILOperation.MLIL_VAR_SSA_FIELD: MediumLevelILVarSsaField,  # [("src", "var_ssa"), ("offset", "int")],
    MediumLevelILOperation.MLIL_VAR_ALIASED_FIELD:
        MediumLevelILVarAliasedField,  # [("src", "var_ssa"), ("offset", "int")],
    MediumLevelILOperation.MLIL_VAR_SPLIT_SSA: MediumLevelILVarSplitSsa,  # [("high", "var_ssa"), ("low", "var_ssa")],
    MediumLevelILOperation.MLIL_CALL_OUTPUT_SSA:
        MediumLevelILCallOutputSsa,  # [("dest_memory", "int"), ("dest", "var_ssa_list")],
    MediumLevelILOperation.MLIL_CALL_PARAM_SSA:
        MediumLevelILCallParamSsa,  # [("src_memory", "int"), ("src", "expr_list")],
    MediumLevelILOperation.MLIL_LOAD_SSA: MediumLevelILLoadSsa,  # [("src", "expr"), ("src_memory", "int")],
    MediumLevelILOperation.MLIL_VAR_PHI: MediumLevelILVarPhi,  # [("dest", "var_ssa"), ("src", "var_ssa_list")],
    MediumLevelILOperation.MLIL_MEM_PHI: MediumLevelILMemPhi,  # [("dest_memory", "int"), ("src_memory", "int_list")],
    MediumLevelILOperation.MLIL_SET_VAR_SSA: MediumLevelILSetVarSsa,  # [("dest", "var_ssa"), ("src", "expr")],
    MediumLevelILOperation.MLIL_FCMP_E: MediumLevelILFcmpE,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_FCMP_NE: MediumLevelILFcmpNe,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_FCMP_LT: MediumLevelILFcmpLt,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_FCMP_LE: MediumLevelILFcmpLe,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_FCMP_GE: MediumLevelILFcmpGe,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_FCMP_GT: MediumLevelILFcmpGt,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_FCMP_O: MediumLevelILFcmpO,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_FCMP_UO: MediumLevelILFcmpUo,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_FADD: MediumLevelILFadd,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_FSUB: MediumLevelILFsub,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_FMUL: MediumLevelILFmul,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_FDIV: MediumLevelILFdiv,  # [("left", "expr"), ("right", "expr")],
    MediumLevelILOperation.MLIL_JUMP_TO: MediumLevelILJumpTo,  # [("dest", "expr"), ("targets", "target_map")],
    MediumLevelILOperation.MLIL_SET_VAR_ALIASED:
        MediumLevelILSetVarAliased,  # [("prev", "var_ssa_dest_and_src"), ("src", "expr")],
    MediumLevelILOperation.MLIL_SYSCALL_UNTYPED:
        MediumLevelILSyscallUntyped,  # [("output", "expr_list"), ("params", "expr"), ("stack", "expr")],
    MediumLevelILOperation.MLIL_TAILCALL:
        MediumLevelILTailcall,  # [("output", "expr_list"), ("dest", "expr"), ("params", "expr_list")],
    MediumLevelILOperation.MLIL_INTRINSIC:
        MediumLevelILIntrinsic,  # [("output", "var_list"), ("intrinsic", "intrinsic"), ("params", "expr_list")],
    MediumLevelILOperation.MLIL_INTRINSIC_SSA: MediumLevelILIntrinsicSsa,  # [("output", "var_ssa_list"), ("intrinsic", "intrinsic"), ("params", "expr_list")],
    MediumLevelILOperation.MLIL_MEMORY_INTRINSIC_OUTPUT_SSA: MediumLevelILMemoryIntrinsicOutputSsa,    # [("dest_memory", "int"), ("output", "var_ssa_list")],
    MediumLevelILOperation.MLIL_MEMORY_INTRINSIC_SSA: MediumLevelILMemoryIntrinsicSsa,    # [("output", "expr"), ("intrinsic", "intrinsic"), ("params", "expr_list"), ("src_memory", "int")],
    MediumLevelILOperation.MLIL_SET_VAR_SSA_FIELD:
        MediumLevelILSetVarSsaField,  # [("prev", "var_ssa_dest_and_src"), ("offset", "int"), ("src", "expr")],
    MediumLevelILOperation.MLIL_SET_VAR_SPLIT_SSA:
        MediumLevelILSetVarSplitSsa,  # [("high", "var_ssa"), ("low", "var_ssa"), ("src", "expr")],
    MediumLevelILOperation.MLIL_SET_VAR_ALIASED_FIELD:
        MediumLevelILSetVarAliasedField,  # [("prev", "var_ssa_dest_and_src"), ("offset", "int"), ("src", "expr")],
    MediumLevelILOperation.MLIL_SYSCALL_SSA:
        MediumLevelILSyscallSsa,  # [("output", "expr"), ("params", "expr_list"), ("src_memory", "int")],
    MediumLevelILOperation.MLIL_SYSCALL_UNTYPED_SSA:
        MediumLevelILSyscallUntypedSsa,  # [("output", "expr"), ("params", "expr"), ("stack", "expr")],
    MediumLevelILOperation.MLIL_LOAD_STRUCT_SSA:
        MediumLevelILLoadStructSsa,  # [("src", "expr"), ("offset", "int"), ("src_memory", "int")],
    MediumLevelILOperation.MLIL_SET_VAR_FIELD:
        MediumLevelILSetVarField,  # [("dest", "var"), ("offset", "int"), ("src", "expr")],
    MediumLevelILOperation.MLIL_SET_VAR_SPLIT:
        MediumLevelILSetVarSplit,  # [("high", "var"), ("low", "var"), ("src", "expr")],
    MediumLevelILOperation.MLIL_STORE_STRUCT:
        MediumLevelILStoreStruct,  # [("dest", "expr"), ("offset", "int"), ("src", "expr")],
    MediumLevelILOperation.MLIL_ADC: MediumLevelILAdc,  # [("left", "expr"), ("right", "expr"), ("carry", "expr")],
    MediumLevelILOperation.MLIL_SBB: MediumLevelILSbb,  # [("left", "expr"), ("right", "expr"), ("carry", "expr")],
    MediumLevelILOperation.MLIL_RLC: MediumLevelILRlc,  # [("left", "expr"), ("right", "expr"), ("carry", "expr")],
    MediumLevelILOperation.MLIL_RRC: MediumLevelILRrc,  # [("left", "expr"), ("right", "expr"), ("carry", "expr")],
    MediumLevelILOperation.MLIL_TAILCALL_UNTYPED:
        MediumLevelILTailcallUntyped,  # [("output", "expr_list"), ("dest", "expr"), ("params", "expr"), ("stack", "expr")],
    MediumLevelILOperation.MLIL_CALL_SSA:
        MediumLevelILCallSsa,  # [("output", "expr"), ("dest", "expr"), ("params", "expr_list"), ("src_memory", "int")],
    MediumLevelILOperation.MLIL_CALL_UNTYPED_SSA:
        MediumLevelILCallUntypedSsa,  # [("output", "expr"), ("dest", "expr"), ("params", "expr"), ("stack", "expr")],
    MediumLevelILOperation.MLIL_TAILCALL_SSA:
        MediumLevelILTailcallSsa,  # [("output", "expr"), ("dest", "expr"), ("params", "expr_list"), ("src_memory", "int")],
    MediumLevelILOperation.MLIL_TAILCALL_UNTYPED_SSA:
        MediumLevelILTailcallUntypedSsa,  # [("output", "expr"), ("dest", "expr"), ("params", "expr"), ("stack", "expr")],
    MediumLevelILOperation.MLIL_CALL:
        MediumLevelILCall,  # [("output", "expr_list"), ("dest", "expr"), ("params", "expr_list")],
    MediumLevelILOperation.MLIL_IF: MediumLevelILIf,  # [("condition", "expr"), ("true", "int"), ("false", "int")],
    MediumLevelILOperation.MLIL_STORE_SSA:
        MediumLevelILStoreSsa,  # [("dest", "expr"), ("dest_memory", "int"), ("src_memory", "int"), ("src", "expr")],
    MediumLevelILOperation.MLIL_CALL_UNTYPED:
        MediumLevelILCallUntyped,  # [("output", "expr_list"), ("dest", "expr"), ("params", "expr"), ("stack", "expr")],
    MediumLevelILOperation.MLIL_STORE_STRUCT_SSA:
        MediumLevelILStoreStructSsa,  # [("dest", "expr"), ("offset", "int"), ("dest_memory", "int"), ("src_memory", "int"), ("src", "expr")],
    MediumLevelILOperation.MLIL_ASSERT: MediumLevelILAssert,
    MediumLevelILOperation.MLIL_ASSERT_SSA: MediumLevelILAssertSsa,
    MediumLevelILOperation.MLIL_FORCE_VER: MediumLevelILForceVer,
    MediumLevelILOperation.MLIL_FORCE_VER_SSA: MediumLevelILForceVerSsa,
	MediumLevelILOperation.MLIL_BLOCK_TO_EXPAND: MediumLevelILBlockToExpand,  # [("exprs", "expr_list")],
}


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

		def do_copy(
			expr: MediumLevelILInstruction,
			dest: 'MediumLevelILFunction',
			sub_expr_handler: Optional[Callable[[MediumLevelILInstruction], ExpressionIndex]] = None
		) -> ExpressionIndex:
			loc = ILSourceLocation.from_instruction(expr)
			if expr.operation == MediumLevelILOperation.MLIL_NOP:
				expr: MediumLevelILNop
				return dest.nop(loc)
			if expr.operation == MediumLevelILOperation.MLIL_SET_VAR:
				expr: MediumLevelILSetVar
				return dest.set_var(expr.size, expr.dest, sub_expr_handler(expr.src), loc)
			if expr.operation == MediumLevelILOperation.MLIL_SET_VAR_SPLIT:
				expr: MediumLevelILSetVarSplit
				return dest.set_var_split(expr.size, expr.high, expr.low, sub_expr_handler(expr.src), loc)
			if expr.operation == MediumLevelILOperation.MLIL_SET_VAR_FIELD:
				expr: MediumLevelILSetVarField
				return dest.set_var_field(expr.size, expr.dest, expr.offset, sub_expr_handler(expr.src), loc)
			if expr.operation == MediumLevelILOperation.MLIL_VAR:
				expr: MediumLevelILVar
				return dest.var(expr.size, expr.src, loc)
			if expr.operation == MediumLevelILOperation.MLIL_VAR_FIELD:
				expr: MediumLevelILVarField
				return dest.var_field(expr.size, expr.src, expr.offset, loc)
			if expr.operation == MediumLevelILOperation.MLIL_VAR_SPLIT:
				expr: MediumLevelILVarSplit
				return dest.var_split(expr.size, expr.high, expr.low, loc)
			if expr.operation == MediumLevelILOperation.MLIL_VAR_OUTPUT:
				expr: MediumLevelILVarOutput
				return dest.var_output(expr.size, expr.dest, loc)
			if expr.operation == MediumLevelILOperation.MLIL_VAR_OUTPUT_FIELD:
				expr: MediumLevelILVarOutputField
				return dest.var_output_field(expr.size, expr.dest, expr.offset, loc)
			if expr.operation == MediumLevelILOperation.MLIL_FORCE_VER:
				expr: MediumLevelILForceVer
				return dest.force_ver(expr.size, expr.dest, expr.src, expr.reason, loc)
			if expr.operation == MediumLevelILOperation.MLIL_ASSERT:
				expr: MediumLevelILAssert
				return dest.assert_expr(expr.size, expr.src, expr.constraint, loc)
			if expr.operation == MediumLevelILOperation.MLIL_ADDRESS_OF:
				expr: MediumLevelILAddressOf
				return dest.address_of(expr.src, loc)
			if expr.operation == MediumLevelILOperation.MLIL_ADDRESS_OF_FIELD:
				expr: MediumLevelILAddressOfField
				return dest.address_of_field(expr.src, expr.offset, loc)
			if expr.operation == MediumLevelILOperation.MLIL_CALL:
				expr: MediumLevelILCall
				output = [sub_expr_handler(output) for output in expr.output_exprs]
				params = [sub_expr_handler(param) for param in expr.params]
				return dest.call(output, sub_expr_handler(expr.dest), params, loc)
			if expr.operation == MediumLevelILOperation.MLIL_CALL_UNTYPED:
				expr: MediumLevelILCallUntyped
				output = [sub_expr_handler(output) for output in expr.output_exprs]
				params = [sub_expr_handler(param) for param in expr.params]
				return dest.call_untyped(
					output,
					sub_expr_handler(expr.dest),
					params,
					sub_expr_handler(expr.stack),
					loc
				)
			if expr.operation == MediumLevelILOperation.MLIL_SYSCALL:
				expr: MediumLevelILSyscall
				output = [sub_expr_handler(output) for output in expr.output_exprs]
				params = [sub_expr_handler(param) for param in expr.params]
				return dest.system_call(output, params, loc)
			if expr.operation == MediumLevelILOperation.MLIL_SYSCALL_UNTYPED:
				expr: MediumLevelILSyscallUntyped
				output = [sub_expr_handler(output) for output in expr.output_exprs]
				params = [sub_expr_handler(param) for param in expr.params]
				return dest.system_call_untyped(
					output,
					params,
					sub_expr_handler(expr.stack),
					loc
				)
			if expr.operation == MediumLevelILOperation.MLIL_TAILCALL:
				expr: MediumLevelILTailcall
				output = [sub_expr_handler(output) for output in expr.output_exprs]
				params = [sub_expr_handler(param) for param in expr.params]
				return dest.tailcall(output, sub_expr_handler(expr.dest), params, loc)
			if expr.operation == MediumLevelILOperation.MLIL_TAILCALL_UNTYPED:
				expr: MediumLevelILTailcallUntyped
				output = [sub_expr_handler(output) for output in expr.output_exprs]
				params = [sub_expr_handler(param) for param in expr.params]
				return dest.tailcall_untyped(
					output,
					sub_expr_handler(expr.dest),
					params,
					sub_expr_handler(expr.stack),
					loc
				)
			if expr.operation == MediumLevelILOperation.MLIL_SEPARATE_PARAM_LIST:
				expr: MediumLevelILSeparateParamList
				params = [sub_expr_handler(param) for param in expr.params]
				return dest.separate_param_list(params, loc)
			if expr.operation == MediumLevelILOperation.MLIL_SHARED_PARAM_SLOT:
				expr: MediumLevelILSharedParamSlot
				params = [sub_expr_handler(param) for param in expr.params]
				return dest.shared_param_slot(params, loc)
			if expr.operation == MediumLevelILOperation.MLIL_RET:
				expr: MediumLevelILRet
				params = [sub_expr_handler(src) for src in expr.src]
				return dest.ret(params, loc)
			if expr.operation == MediumLevelILOperation.MLIL_NORET:
				expr: MediumLevelILNoret
				return dest.no_ret(loc)
			if expr.operation == MediumLevelILOperation.MLIL_STORE:
				expr: MediumLevelILStore
				return dest.store(expr.size, sub_expr_handler(expr.dest), sub_expr_handler(expr.src), loc)
			if expr.operation == MediumLevelILOperation.MLIL_STORE_STRUCT:
				expr: MediumLevelILStoreStruct
				return dest.store_struct(expr.size, sub_expr_handler(expr.dest), expr.offset, sub_expr_handler(expr.src), loc)
			if expr.operation == MediumLevelILOperation.MLIL_STORE_OUTPUT:
				expr: MediumLevelILStoreOutput
				return dest.store_output(expr.size, sub_expr_handler(expr.dest), loc)
			if expr.operation == MediumLevelILOperation.MLIL_LOAD:
				expr: MediumLevelILLoad
				return dest.load(expr.size, sub_expr_handler(expr.src), loc)
			if expr.operation == MediumLevelILOperation.MLIL_LOAD_STRUCT:
				expr: MediumLevelILLoadStruct
				return dest.load_struct(expr.size, sub_expr_handler(expr.src), expr.offset, loc)
			if expr.operation == MediumLevelILOperation.MLIL_JUMP:
				expr: MediumLevelILJump
				return dest.jump(sub_expr_handler(expr.dest), loc)
			if expr.operation in [
				MediumLevelILOperation.MLIL_NEG,
				MediumLevelILOperation.MLIL_NOT,
				MediumLevelILOperation.MLIL_BSWAP,
				MediumLevelILOperation.MLIL_POPCNT,
				MediumLevelILOperation.MLIL_CLZ,
				MediumLevelILOperation.MLIL_CTZ,
				MediumLevelILOperation.MLIL_RBIT,
				MediumLevelILOperation.MLIL_CLS,
				MediumLevelILOperation.MLIL_ABS,
				MediumLevelILOperation.MLIL_SX,
				MediumLevelILOperation.MLIL_ZX,
				MediumLevelILOperation.MLIL_LOW_PART,
				MediumLevelILOperation.MLIL_BOOL_TO_INT,
				MediumLevelILOperation.MLIL_RET_HINT,
				MediumLevelILOperation.MLIL_UNIMPL_MEM,
				MediumLevelILOperation.MLIL_FSQRT,
				MediumLevelILOperation.MLIL_FNEG,
				MediumLevelILOperation.MLIL_FABS,
				MediumLevelILOperation.MLIL_FLOAT_TO_INT,
				MediumLevelILOperation.MLIL_INT_TO_FLOAT,
				MediumLevelILOperation.MLIL_FLOAT_CONV,
				MediumLevelILOperation.MLIL_ROUND_TO_INT,
				MediumLevelILOperation.MLIL_FLOOR,
				MediumLevelILOperation.MLIL_CEIL,
				MediumLevelILOperation.MLIL_FTRUNC,
				MediumLevelILOperation.MLIL_PASS_BY_REF,
				MediumLevelILOperation.MLIL_RETURN_BY_REF
			]:
				expr: MediumLevelILUnaryBase
				return dest.expr(expr.operation, sub_expr_handler(expr.src), size=expr.size, source_location=loc)
			if expr.operation in [
				MediumLevelILOperation.MLIL_ADD,
				MediumLevelILOperation.MLIL_SUB,
				MediumLevelILOperation.MLIL_AND,
				MediumLevelILOperation.MLIL_OR,
				MediumLevelILOperation.MLIL_XOR,
				MediumLevelILOperation.MLIL_LSL,
				MediumLevelILOperation.MLIL_LSR,
				MediumLevelILOperation.MLIL_ASR,
				MediumLevelILOperation.MLIL_ROL,
				MediumLevelILOperation.MLIL_ROR,
				MediumLevelILOperation.MLIL_MUL,
				MediumLevelILOperation.MLIL_MINS,
				MediumLevelILOperation.MLIL_MAXS,
				MediumLevelILOperation.MLIL_MINU,
				MediumLevelILOperation.MLIL_MAXU,
				MediumLevelILOperation.MLIL_MULU_DP,
				MediumLevelILOperation.MLIL_MULS_DP,
				MediumLevelILOperation.MLIL_DIVU,
				MediumLevelILOperation.MLIL_DIVS,
				MediumLevelILOperation.MLIL_MODU,
				MediumLevelILOperation.MLIL_MODS,
				MediumLevelILOperation.MLIL_DIVU_DP,
				MediumLevelILOperation.MLIL_DIVS_DP,
				MediumLevelILOperation.MLIL_MODU_DP,
				MediumLevelILOperation.MLIL_MODS_DP,
				MediumLevelILOperation.MLIL_CMP_E,
				MediumLevelILOperation.MLIL_CMP_NE,
				MediumLevelILOperation.MLIL_CMP_SLT,
				MediumLevelILOperation.MLIL_CMP_ULT,
				MediumLevelILOperation.MLIL_CMP_SLE,
				MediumLevelILOperation.MLIL_CMP_ULE,
				MediumLevelILOperation.MLIL_CMP_SGE,
				MediumLevelILOperation.MLIL_CMP_UGE,
				MediumLevelILOperation.MLIL_CMP_SGT,
				MediumLevelILOperation.MLIL_CMP_UGT,
				MediumLevelILOperation.MLIL_TEST_BIT,
				MediumLevelILOperation.MLIL_ADD_OVERFLOW,
				MediumLevelILOperation.MLIL_FADD,
				MediumLevelILOperation.MLIL_FSUB,
				MediumLevelILOperation.MLIL_FMUL,
				MediumLevelILOperation.MLIL_FDIV,
				MediumLevelILOperation.MLIL_FCMP_E,
				MediumLevelILOperation.MLIL_FCMP_NE,
				MediumLevelILOperation.MLIL_FCMP_LT,
				MediumLevelILOperation.MLIL_FCMP_LE,
				MediumLevelILOperation.MLIL_FCMP_GE,
				MediumLevelILOperation.MLIL_FCMP_GT,
				MediumLevelILOperation.MLIL_FCMP_O,
				MediumLevelILOperation.MLIL_FCMP_UO
			]:
				expr: MediumLevelILBinaryBase
				return dest.expr(
					expr.operation,
					sub_expr_handler(expr.left),
					sub_expr_handler(expr.right),
					size=expr.size,
					source_location=loc
				)
			if expr.operation in [
				MediumLevelILOperation.MLIL_ADC,
				MediumLevelILOperation.MLIL_SBB,
				MediumLevelILOperation.MLIL_RLC,
				MediumLevelILOperation.MLIL_RRC
			]:
				expr: MediumLevelILCarryBase
				return dest.expr(
					expr.operation,
					sub_expr_handler(expr.left),
					sub_expr_handler(expr.right),
					sub_expr_handler(expr.carry),
					size=expr.size,
					source_location=loc
				)
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
			if expr.operation == MediumLevelILOperation.MLIL_CONST:
				expr: MediumLevelILConst
				return dest.const(expr.size, expr.constant, loc)
			if expr.operation == MediumLevelILOperation.MLIL_CONST_PTR:
				expr: MediumLevelILConstPtr
				return dest.const_pointer(expr.size, expr.constant, loc)
			if expr.operation == MediumLevelILOperation.MLIL_EXTERN_PTR:
				expr: MediumLevelILExternPtr
				return dest.extern_pointer(expr.size, expr.constant, expr.offset, loc)
			if expr.operation == MediumLevelILOperation.MLIL_FLOAT_CONST:
				expr: MediumLevelILFloatConst
				return dest.float_const_raw(expr.size, expr.raw_operands[0], loc)
			if expr.operation == MediumLevelILOperation.MLIL_IMPORT:
				expr: MediumLevelILImport
				return dest.imported_address(expr.size, expr.constant, loc)
			if expr.operation == MediumLevelILOperation.MLIL_CONST_DATA:
				expr: MediumLevelILConstData
				return dest.const_data(expr.size, expr.constant_data, loc)
			if expr.operation == MediumLevelILOperation.MLIL_BP:
				expr: MediumLevelILBp
				return dest.breakpoint(loc)
			if expr.operation == MediumLevelILOperation.MLIL_TRAP:
				expr: MediumLevelILTrap
				return dest.trap(expr.vector, loc)
			if expr.operation == MediumLevelILOperation.MLIL_INTRINSIC:
				expr: MediumLevelILIntrinsic
				params = [sub_expr_handler(param) for param in expr.params]
				return dest.intrinsic(expr.output, expr.intrinsic, params, loc)
			if expr.operation == MediumLevelILOperation.MLIL_FREE_VAR_SLOT:
				expr: MediumLevelILFreeVarSlot
				return dest.free_var_slot(expr.dest, loc)
			if expr.operation == MediumLevelILOperation.MLIL_UNDEF:
				expr: MediumLevelILUndef
				return dest.undefined(loc)
			if expr.operation == MediumLevelILOperation.MLIL_UNIMPL:
				expr: MediumLevelILUnimpl
				return dest.unimplemented(loc)
			if expr.operation == MediumLevelILOperation.MLIL_BLOCK_TO_EXPAND:
				expr: MediumLevelILBlockToExpand
				params = [sub_expr_handler(src) for src in expr.src]
				return dest.block_to_expand(params, loc)
			raise NotImplementedError(f"unknown expr operation {expr.operation} in copy_expr_to")

		new_index = do_copy(expr, dest, sub_expr_handler)
		# Copy expression metadata as well
		dest.set_expr_attributes(new_index, expr.attributes)
		return new_index

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

	def nop(self, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``nop`` no operation, this instruction does nothing

		:param loc: Location of expression
		:return: The no operation expression
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_NOP, source_location=loc)

	def set_var(
		self, size: int, dest: 'variable.CoreVariable', src: ExpressionIndex,
		loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``set_var`` sets the variable ``dest`` of size ``size`` to the expression ``src``

		:param int size: the size of the variable in bytes
		:param Variable dest: the variable being set
		:param ExpressionIndex src: expression with the value to set the variable to
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``dest = src``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_SET_VAR, dest.identifier, src, size=size, source_location=loc)

	def set_var_field(
		self, size: int, dest: 'variable.CoreVariable', offset: int, src: ExpressionIndex,
		loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``set_var_field`` sets the field ``offset`` of variable ``dest`` of size ``size`` to the expression ``src``

		:param int size: the size of the field in bytes
		:param Variable dest: the variable being set
		:param int offset: offset of field in the variable
		:param ExpressionIndex src: expression with the value to set the field to
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``dest:offset = src``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_SET_VAR_FIELD, dest.identifier, offset, src, size=size, source_location=loc)

	def set_var_split(
		self, size: int, hi: 'variable.CoreVariable', lo: 'variable.CoreVariable', src: ExpressionIndex,
		loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``set_var_split`` uses ``hi`` and ``lo`` as a single extended variable of size ``2*size``
		setting ``hi:lo`` to the expression ``src``

		:param int size: the size of each variable in bytes
		:param Variable hi: the high variable being set
		:param Variable lo: the low variable being set
		:param ExpressionIndex src: expression with the value to set the variables to
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``hi:lo = src``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_SET_VAR_SPLIT, hi.identifier, lo.identifier, src, size=size, source_location=loc)

	def load(self, size: int, src: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``load`` Reads ``size`` bytes from the expression ``src``

		:param int size: number of bytes to read
		:param ExpressionIndex src: the expression to read memory from
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``[addr].size``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_LOAD, src, size=size, source_location=loc)

	def load_struct(
		self, size: int, src: ExpressionIndex, offset: int, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``load_struct`` Reads ``size`` bytes at the offset ``offset`` from the expression ``src``

		:param int size: number of bytes to read
		:param ExpressionIndex src: the expression to read memory from
		:param int offset: offset of field in the memory
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``[(src + offset)].size`` (often rendered ``src->offset.size``)
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_LOAD_STRUCT, src, offset, size=size, source_location=loc)

	def store(
		self, size: int, dest: ExpressionIndex, src: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``store`` Writes ``size`` bytes to expression ``dest`` read from expression ``src``

		:param int size: number of bytes to write
		:param ExpressionIndex dest: the expression to write to
		:param ExpressionIndex src: the expression to be written
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``[dest].size = src``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_STORE, dest, src, size=size, source_location=loc)

	def store_struct(
		self, size: int, dest: ExpressionIndex, offset: int, src: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``store_struct`` Writes ``size`` bytes to expression ``dest`` at the offset ``offset`` read from expression ``src``

		:param int size: number of bytes to write
		:param ExpressionIndex dest: the expression to write to
		:param int offset: offset of field in the memory
		:param ExpressionIndex src: the expression to be written
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``[(dest + offset)].size = src`` (often rendered ``dest->offset.size``)
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_STORE_STRUCT, dest, offset, src, size=size, source_location=loc)

	def store_output(
			self, size: int, dest: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``store_output`` Outputs ``size`` bytes to expression ``dest`` as the result of a call

		:param int size: number of bytes to write
		:param ExpressionIndex dest: the expression to write to
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``[dest].size``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_STORE_OUTPUT, dest, size=size, source_location=loc)

	def var(self, size: int, src: 'variable.CoreVariable', loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``var`` returns the variable ``src`` of size ``size``

		:param int size: the size of the variable in bytes
		:param Variable src: the variable being read
		:param ILSourceLocation loc: location of returned expression
		:return: An expression for the given variable
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_VAR, src.identifier, size=size, source_location=loc)

	def var_field(
		self, size: int, src: 'variable.CoreVariable', offset: int, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``var_field`` returns the field at offset ``offset`` from variable ``src`` of size ``size``

		:param int size: the size of the field in bytes
		:param Variable src: the variable being read
		:param int offset: offset of field in the variable
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``var:offset.size``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_VAR_FIELD, src.identifier, offset, size=size, source_location=loc)

	def var_split(
		self, size: int, hi: 'variable.CoreVariable', lo: 'variable.CoreVariable', loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``var_split`` combines variables ``hi`` and ``lo`` of size ``size`` into an expression of size ``2*size``

		:param int size: the size of each variable in bytes
		:param Variable hi: the variable holding high part of value
		:param Variable lo: the variable holding low part of value
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``hi:lo``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_VAR_SPLIT, hi.identifier, lo.identifier, size=size, source_location=loc)

	def var_output(self, size: int, dest: 'variable.CoreVariable', loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``var_output`` returns the output variable ``dest`` of size ``size``

		:param int size: the size of the variable in bytes
		:param Variable dest: the variable being written
		:param ILSourceLocation loc: location of returned expression
		:return: An expression for the given variable
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_VAR_OUTPUT, dest.identifier, size=size, source_location=loc)

	def var_output_field(
			self, size: int, dest: 'variable.CoreVariable', offset: int, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``var_output_field`` returns the output field at offset ``offset`` from variable ``dest`` of size ``size``

		:param int size: the size of the field in bytes
		:param Variable dest: the variable being written
		:param int offset: offset of field in the variable
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``var:offset.size``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_VAR_OUTPUT_FIELD, dest.identifier, offset, size=size, source_location=loc)

	def assert_expr(
		self,
		size: int,
		src: 'variable.CoreVariable',
		constraint: 'variable.PossibleValueSet',
		loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``assert_expr`` assert ``constraint`` is the value of the given variable ``src``.
		Used when setting user variable values.

		:param int size: size of value in the constraint
		:param Variable src: variable to constrain
		:param variable.PossibleValueSet constraint: asserted value of variable
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``ASSERT(src, constraint)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_ASSERT, src.identifier, ExpressionIndex(self.cache_possible_value_set(constraint)), size=size, source_location=loc)

	def force_ver(
		self,
		size: int,
		dest: 'variable.CoreVariable',
		src: 'variable.CoreVariable',
		reason: ForceVersionReason = ForceVersionReason.UserForceVersionReason,
		loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``force_ver`` creates a new version of the variable ``dest`` in ``src``
		Effectively, this is like saying src = dest, which analysis can then use as a new
		variable definition site.

		:param int size: size of the variable
		:param Variable dest: the variable to force a new version of
		:param Variable src: the variable created with the new version
		:param ForceVersionReason reason: reason for forcing the version
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``FORCE_VER(reg)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_FORCE_VER, dest.identifier, src.identifier, int(reason), size=size, source_location=loc)

	def address_of(self, var: 'variable.CoreVariable', loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``address_of`` takes the address of ``var``

		:param Variable var: the variable having its address taken
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``&var``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_ADDRESS_OF, var.identifier, size=0, source_location=loc)

	def pass_by_ref(self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``pass_by_ref`` indicates that ``value`` is being passed by reference to a call with a pointer size of  ``size``

		:param int size: the size of the pointer in bytes
		:param ExpressionIndex value: the expression containing the reference being passed
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``ref *value``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_PASS_BY_REF, value, size=size, source_location=loc)

	def return_by_ref(self, size: int, dest: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``return_by_ref`` indicates that ``dest`` is being returned by passing a reference to a call

		:param int size: the size of the value in bytes
		:param ExpressionIndex dest: the expression containing the target of the return value
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``ref dest``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_RETURN_BY_REF, dest, size=size, source_location=loc)

	def address_of_field(self, var: 'variable.CoreVariable', offset: int, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``address_of_field`` takes the address of ``var`` at the offset ``offset``

		:param Variable var: the variable having its address taken
		:param int offset: the offset of the taken address
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``&var:offset``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_ADDRESS_OF_FIELD, var.identifier, offset, size=0, source_location=loc)

	def const(self, size: int, value: int, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``const`` returns an expression for the constant integer ``value`` of size ``size``

		:param int size: the size of the constant in bytes
		:param int value: integer value of the constant
		:param ILSourceLocation loc: location of returned expression
		:return: A constant expression of given value and size
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_CONST, value, size=size, source_location=loc)

	def const_pointer(self, size: int, value: int, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``const_pointer`` returns an expression for the constant pointer ``value`` of size ``size``

		:param int size: the size of the pointer in bytes
		:param int value: address referenced by the pointer
		:param ILSourceLocation loc: location of returned expression
		:return: A constant expression of given value and size
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_CONST_PTR, value, size=size, source_location=loc)

	def extern_pointer(
		self, size: int, value: int, offset: int, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``extern_pointer`` returns an expression for the external pointer ``value`` at offset ``offset`` of size ``size``

		:param int size: the size of the pointer in bytes
		:param int value: address referenced by the pointer
		:param int offset: offset applied to the address
		:param loc: location of returned expression
		:return: A constant expression of given value and size
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_EXTERN_PTR, value, offset, size=size, source_location=loc)

	def float_const_raw(self, size: int, value: int, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``float_const_raw`` returns an expression for the constant raw binary floating point
		value ``value`` with size ``size``

		:param int size: the size of the constant in bytes
		:param int value: integer value for the raw binary representation of the constant
		:param ILSourceLocation loc: location of returned expression
		:return: A constant expression of given value and size
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_FLOAT_CONST, value, size=size, source_location=loc)

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

	def imported_address(self, size: int, value: int, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``imported_address`` returns an expression for an imported value with address ``value`` and size ``size``

		:param int size: size of the imported value
		:param int value: address of the imported value
		:param ILSourceLocation loc: location of returned expression
		:return: A constant expression of given value and size
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_IMPORT, value, size=size, source_location=loc)

	def const_data(self, size: int, data: 'variable.ConstantData', loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``const_data`` returns an expression for the constant data ``data``

		:param int size: size of the data
		:param ConstantData data: value of the data
		:param ILSourceLocation loc: location of returned expression
		:return: A constant expression of given value and size
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_CONST_DATA, data.type, data.value, size=size, source_location=loc)

	def add(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``add`` adds expression ``a`` to expression ``b`` returning an expression of ``size`` bytes

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``add.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_ADD, a, b, size=size, source_location=loc)

	def add_carry(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, carry: ExpressionIndex,
		loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``add_carry`` adds expression ``a`` to expression ``b`` with carry from ``carry`` returning an expression of ``size`` bytes

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ExpressionIndex carry: Carried value expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``adc.<size>(a, b, carry)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_ADC, a, b, carry, size=size, source_location=loc)

	def sub(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``sub`` subtracts expression ``a`` to expression ``b`` returning an expression of ``size`` bytes

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``sub.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_SUB, a, b, size=size, source_location=loc)

	def sub_borrow(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, carry: ExpressionIndex,
		loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``sub_borrow`` subtracts expression ``a`` to expression ``b`` with borrow from ``carry`` returning an expression of ``size`` bytes

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ExpressionIndex carry: Carried value expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``sbb.<size>(a, b, carry)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_SBB, a, b, carry, size=size, source_location=loc)

	def and_expr(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``and_expr`` bitwise and's expression ``a`` and expression ``b`` returning an expression of ``size`` bytes

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``and.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_AND, a, b, size=size, source_location=loc)

	def or_expr(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``or_expr`` bitwise or's expression ``a`` and expression ``b`` returning an expression of ``size`` bytes

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``or.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_OR, a, b, size=size, source_location=loc)

	def xor_expr(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``xor_expr`` xor's expression ``a`` and expression ``b`` returning an expression of ``size`` bytes

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``xor.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_XOR, a, b, size=size, source_location=loc)

	def shift_left(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``shift_left`` left shifts expression ``a`` by expression ``b`` returning an expression of ``size`` bytes

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``lsl.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_LSL, a, b, size=size, source_location=loc)

	def logical_shift_right(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``logical_shift_right`` logically right shifts expression ``a`` by expression ``b`` returning an expression of ``size`` bytes

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``lsr.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_LSR, a, b, size=size, source_location=loc)

	def arith_shift_right(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``arith_shift_right`` arithmetically right shifts expression ``a`` by expression ``b`` returning an expression of ``size`` bytes

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``asr.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_ASR, a, b, size=size, source_location=loc)

	def rotate_left(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``rotate_left`` bitwise rotates left expression ``a`` by expression ``b`` returning an expression of ``size`` bytes

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``rol.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_ROL, a, b, size=size, source_location=loc)

	def rotate_left_carry(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, carry: ExpressionIndex,
		loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``rotate_left_carry`` bitwise rotates left expression ``a`` by expression ``b`` with carry from ``carry`` returning an expression of ``size`` bytes

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ExpressionIndex carry: Carried value expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``rlc.<size>(a, b, carry)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_RLC, a, b, carry, size=size, source_location=loc)

	def rotate_right(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``rotate_right`` bitwise rotates right expression ``a`` by expression ``b`` returning an expression of ``size`` bytes

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``ror.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_ROR, a, b, size=size, source_location=loc)

	def rotate_right_carry(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, carry: ExpressionIndex,
		loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``rotate_right_carry`` bitwise rotates right expression ``a`` by expression ``b`` with carry from ``carry`` returning an expression of ``size`` bytes

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ExpressionIndex carry: Carried value expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``rrc.<size>(a, b, carry)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_RRC, a, b, carry, size=size, source_location=loc)

	def mult(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``mult`` multiplies expression ``a`` by expression ``b`` and returns an expression.
		Both the operands and return value are ``size`` bytes as the product's upper half is discarded.

		:param int size: the size of the result and input operands, in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``mult.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_MUL, a, b, size=size, source_location=loc)

	def mult_double_prec_signed(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``mult_double_prec_signed`` signed multiplies expression ``a`` by expression ``b`` and returns an expression.
		Both the operands are ``size`` bytes and the returned expression is of size ``2*size`` bytes.

		:param int size: the size of the result and input operands, in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``muls.dp.<2*size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_MULS_DP, a, b, size=size, source_location=loc)

	def mult_double_prec_unsigned(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``mult_double_prec_unsigned`` unsigned multiplies expression ``a`` by expression ``b`` and returnisan expression.
		Both the operands are ``size`` bytes and the returned expression is of size ``2*size`` bytes.

		:param int size: the size of the result and input operands, in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``mulu.dp.<2*size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_MULU_DP, a, b, size=size, source_location=loc)

	def min_signed(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``min_signed`` signed minimum of expressions ``a`` and ``b`` returning an expression of ``size`` bytes

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``mins.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_MINS, a, b, size=size, source_location=loc)

	def max_signed(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``max_signed`` signed maximum of expressions ``a`` and ``b`` returning an expression of ``size`` bytes

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``maxs.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_MAXS, a, b, size=size, source_location=loc)

	def min_unsigned(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``min_unsigned`` unsigned minimum of expressions ``a`` and ``b`` returning an expression of ``size`` bytes

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``minu.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_MINU, a, b, size=size, source_location=loc)

	def max_unsigned(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``max_unsigned`` unsigned maximum of expressions ``a`` and ``b`` returning an expression of ``size`` bytes

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``maxu.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_MAXU, a, b, size=size, source_location=loc)

	def div_signed(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``div_signed`` signed divides expression ``a`` by expression ``b`` and returns an expression.
		Both the operands and return value are ``size`` bytes.

		:param int size: the size of the result and input operands, in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``divs.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_DIVS, a, b, size=size, source_location=loc)

	def div_double_prec_signed(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``div_double_prec_signed`` signed divides double precision expression ``a`` by expression ``b`` and returns an expression.
		The first operand is of size ``2*size`` bytes and the other operand and return value are of size ``size`` bytes.

		:param int size: the size of the result and input operands, in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``divs.dp.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_DIVS_DP, a, b, size=size, source_location=loc)

	def div_unsigned(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``div_unsigned`` unsigned divides expression ``a`` by expression ``b`` and returns an expression.
		Both the operands and return value are ``size`` bytes.

		:param int size: the size of the result and input operands, in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``divu.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_DIVU, a, b, size=size, source_location=loc)

	def div_double_prec_unsigned(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``div_double_prec_unsigned`` unsigned divides double precision expression ``a`` by expression ``b`` and returns an expression.
		The first operand is of size ``2*size`` bytes and the other operand and return value are of size ``size`` bytes.

		:param int size: the size of the result and input operands, in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``divu.dp.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_DIVU_DP, a, b, size=size, source_location=loc)

	def mod_signed(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``mod_signed`` signed modulus expression ``a`` by expression ``b`` and returns an expression.
		Both the operands and return value are ``size`` bytes.

		:param int size: the size of the result and input operands, in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``mods.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_MODS, a, b, size=size, source_location=loc)

	def mod_double_prec_signed(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``mod_double_prec_signed`` signed modulus double precision expression ``a`` by expression ``b`` and returns an expression.
		The first operand is of size ``2*size`` bytes and the other operand and return value are of size ``size`` bytes.

		:param int size: the size of the result and input operands, in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``mods.dp.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_MODS_DP, a, b, size=size, source_location=loc)

	def mod_unsigned(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``mod_unsigned`` unsigned modulus expression ``a`` by expression ``b`` and returns an expression.
		Both the operands and return value are ``size`` bytes.

		:param int size: the size of the result and input operands, in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``modu.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_MODU, a, b, size=size, source_location=loc)

	def mod_double_prec_unsigned(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``mod_double_prec_unsigned`` unsigned modulus double precision expression ``a`` by expression ``b`` and returns an expression.
		The first operand is of size ``2*size`` bytes and the other operand and return value are of size ``size`` bytes.

		:param int size: the size of the result and input operands, in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``modu.dp.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_MODU_DP, a, b, size=size, source_location=loc)

	def neg_expr(self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``neg_expr`` two's complement sign negation of expression ``value`` of size ``size``

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to negate
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``neg.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_NEG, value, size=size, source_location=loc)

	def not_expr(self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``not_expr`` bitwise inversion of expression ``value`` of size ``size``

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to bitwise invert
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``not.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_NOT, value, size=size, source_location=loc)

	def byte_swap(self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``byte_swap`` reverses the byte order of expression ``value`` of size ``size``

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to byte swap
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``bswap.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_BSWAP, value, size=size, source_location=loc)

	def population_count(self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``population_count`` counts the number of set bits in expression ``value`` of size ``size``

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to count set bits in
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``popcnt.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_POPCNT, value, size=size, source_location=loc)

	def count_leading_zeros(self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``count_leading_zeros`` counts the leading zero bits in expression ``value`` of size ``size``. The result is
		``8 * size`` when ``value`` is zero.

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to count leading zero bits in
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``clz.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_CLZ, value, size=size, source_location=loc)

	def count_trailing_zeros(self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``count_trailing_zeros`` counts the trailing zero bits in expression ``value`` of size ``size``. The result is
		``8 * size`` when ``value`` is zero.

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to count trailing zero bits in
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``ctz.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_CTZ, value, size=size, source_location=loc)

	def reverse_bits(self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``reverse_bits`` reverses the bit order of expression ``value`` of size ``size``

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to reverse the bits of
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``rbit.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_RBIT, value, size=size, source_location=loc)

	def count_leading_signs(self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``count_leading_signs`` counts the leading sign bits in expression ``value`` of size ``size`` (the number of bits
		below the sign bit that match it)

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to count leading sign bits in
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``cls.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_CLS, value, size=size, source_location=loc)

	def absolute_value(self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``absolute_value`` signed absolute value of expression ``value`` of size ``size``

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to take the absolute value of
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``abs.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_ABS, value, size=size, source_location=loc)

	def sign_extend(self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``sign_extend`` two's complement sign-extends the expression in ``value`` to ``size`` bytes

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to sign extend
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``sx.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_SX, value, size=size, source_location=loc)

	def zero_extend(self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``zero_extend`` zero-extends the expression in ``value`` to ``size`` bytes

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to zero extend
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``zx.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_ZX, value, size=size, source_location=loc)

	def low_part(self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``low_part`` truncates the expression in ``value`` to ``size`` bytes

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to zero extend
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``(value).<size>``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_LOW_PART, value, size=size, source_location=loc)

	def jump(self, dest: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``jump`` returns an expression which jumps (branches) to the expression ``dest``

		:param ExpressionIndex dest: the expression to jump to
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``jump(dest)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_JUMP, dest, size=0, source_location=loc)

	def jump_to(
		self, dest: ExpressionIndex, targets: Mapping[int, MediumLevelILLabel],
		loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``jump_to`` returns an expression which jumps (branches) various targets in ``targets``
		choosing the target in ``targets`` based on the value calculated by ``dest``

		:param ExpressionIndex dest: the expression choosing which jump target to use
		:param Mapping[int, MediumLevelILLabel] targets: the list of targets for jump locations
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``jump(dest)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_JUMP_TO, dest, len(targets) * 2, self.add_label_map(targets), size=0, source_location=loc)

	def call(
		self, output: CallOutputList, dest: ExpressionIndex, params: List[ExpressionIndex],
		loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``call`` returns an expression which calls the function in the expression ``dest``
		with the parameters defined in ``params`` returning values in the variables in ``output``.

		:param CallOutputList output: output variables or expressions
		:param ExpressionIndex dest: the expression to call
		:param List[ExpressionIndex] params: parameter variables
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``output = call(dest, params...)``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			MediumLevelILOperation.MLIL_CALL,
			len(output),
			self.add_operand_list(self._call_output_list(output)),
			dest,
			len(params),
			self.add_operand_list(params),
			size=0,
			source_location=loc
		)

	def call_untyped(
		self, output: CallOutputList, dest: ExpressionIndex, params: List[ExpressionIndex],
		stack: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``call_untyped`` returns an expression which calls the function in the expression ``dest``
		with the parameters defined in ``params`` returning values in the variables in ``output``
		where stack resolution could not be determined and the top of the stack has to be specified in ``stack``

		:param CallOutputList output: output variables or expressions
		:param ExpressionIndex dest: the expression to call
		:param List[ExpressionIndex] params: parameter variables
		:param ExpressionIndex stack: expression of top of stack
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``output = call(dest, params..., stack = stack)``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			MediumLevelILOperation.MLIL_CALL_UNTYPED,
			len(output),
			self.add_operand_list(self._call_output_list(output)),
			dest,
			self.expr(
				MediumLevelILOperation.MLIL_CALL_PARAM,
				len(params),
				self.add_operand_list(params),
				size=0,
				source_location=loc
			),
			stack,
			size=0,
			source_location=loc
		)

	def system_call(
		self, output: CallOutputList, params: List[ExpressionIndex],
		loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``system_call`` returns an expression which performs a system call
		with the parameters defined in ``params`` returning values in the variables in ``output``.

		:param CallOutputList output: output variables or expressions
		:param List[ExpressionIndex] params: parameter variables
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``output = syscall(dest, params...)``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			MediumLevelILOperation.MLIL_SYSCALL,
			len(output),
			self.add_operand_list(self._call_output_list(output)),
			len(params),
			self.add_operand_list(params),
			size=0,
			source_location=loc
		)

	def system_call_untyped(
		self, output: CallOutputList, params: List[ExpressionIndex],
		stack: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``system_call_untyped`` returns an expression which performs a system call
		with the parameters defined in ``params`` returning values in the variables in ``output``
		where stack resolution could not be determined and the top of the stack has to be specified in ``stack``

		:param CallOutputList output: output variables or expressions
		:param List[ExpressionIndex] params: parameter variables
		:param ExpressionIndex stack: expression of top of stack
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``output = syscall(dest, params..., stack = stack)``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			MediumLevelILOperation.MLIL_SYSCALL_UNTYPED,
			len(output),
			self.add_operand_list(self._call_output_list(output)),
			self.expr(
				MediumLevelILOperation.MLIL_CALL_PARAM,
				len(params),
				self.add_operand_list(params),
				size=0,
				source_location=loc
			),
			stack,
			size=0,
			source_location=loc
		)

	def tailcall(
		self, output: CallOutputList, dest: ExpressionIndex, params: List[ExpressionIndex],
		loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``tailcall`` returns an expression which tailcalls the function in the expression ``dest``
		with the parameters defined in ``params`` returning values in the variables in ``output``.

		:param CallOutputList output: output variables or expressions
		:param ExpressionIndex dest: the expression to call
		:param List[ExpressionIndex] params: parameter variables
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``output = tailcall(dest, params...)``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			MediumLevelILOperation.MLIL_TAILCALL,
			len(output),
			self.add_operand_list(self._call_output_list(output)),
			dest,
			len(params),
			self.add_operand_list(params),
			size=0,
			source_location=loc
		)

	def tailcall_untyped(
		self, output: CallOutputList, dest: ExpressionIndex, params: List[ExpressionIndex],
		stack: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``tailcall_untyped`` returns an expression which tailcalls the function in the expression ``dest``
		with the parameters defined in ``params`` returning values in the variables in ``output``
		where stack resolution could not be determined and the top of the stack has to be specified in ``stack``

		:param CallOutputList output: output variables or expressions
		:param ExpressionIndex dest: the expression to call
		:param List[ExpressionIndex] params: parameter variables
		:param ExpressionIndex stack: expression of top of stack
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``output = tailcall(dest, params..., stack = stack)``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			MediumLevelILOperation.MLIL_TAILCALL_UNTYPED,
			len(output),
			self.add_operand_list(self._call_output_list(output)),
			dest,
			self.expr(
				MediumLevelILOperation.MLIL_CALL_PARAM,
				len(params),
				self.add_operand_list(params),
				size=0,
				source_location=loc
			),
			stack,
			size=0,
			source_location=loc
		)

	def separate_param_list(
		self, params: List[ExpressionIndex], loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``separate_param_list`` returns an expression which holds a list of parameters in ``params``

		:param List[ExpressionIndex] params: parameter expressions
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``separate_param_list(params...)``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			MediumLevelILOperation.MLIL_SEPARATE_PARAM_LIST,
			len(params),
			self.add_operand_list(params),
			size=0,
			source_location=loc
		)

	def shared_param_slot(
		self, params: List[ExpressionIndex], loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``shared_param_slot`` returns an expression which holds a list of parameters in ``params``
		that are stored in a shared parameter slot

		:param List[ExpressionIndex] params: parameter expressions
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``shared_param_slot(params...)``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			MediumLevelILOperation.MLIL_SHARED_PARAM_SLOT,
			len(params),
			self.add_operand_list(params),
			size=0,
			source_location=loc
		)

	def ret(self, sources: List[ExpressionIndex], loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``ret`` returns an expression which jumps (branches) to the calling function,
		returning a result specified by the expressions in ``sources``.

		:param List[ExpressionIndex] sources: list of returned expressions
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``return sources...``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_RET, len(sources), self.add_operand_list(sources), size=0, source_location=loc)

	def no_ret(self, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``no_ret`` returns an expression that halts execution

		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``noreturn``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_NORET, size=0, source_location=loc)

	def compare_equal(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``compare_equal`` returns comparison expression of size ``size`` checking if expression ``a`` is equal to
		expression ``b``

		:param int size: size in bytes
		:param ExpressionIndex a: LHS of comparison
		:param ExpressionIndex b: RHS of comparison
		:param ILSourceLocation loc: location of returned expression
		:return: a comparison expression.
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_CMP_E, a, b, size=size, source_location=loc)

	def compare_not_equal(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``compare_not_equal`` returns comparison expression of size ``size`` checking if expression ``a`` is not equal to
		expression ``b``

		:param int size: size in bytes
		:param ExpressionIndex a: LHS of comparison
		:param ExpressionIndex b: RHS of comparison
		:param ILSourceLocation loc: location of returned expression
		:return: a comparison expression.
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_CMP_NE, a, b, size=size, source_location=loc)

	def compare_signed_less_than(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``compare_signed_less_than`` returns comparison expression of size ``size`` checking if expression ``a`` is
		signed less than expression ``b``

		:param int size: size in bytes
		:param ExpressionIndex a: LHS of comparison
		:param ExpressionIndex b: RHS of comparison
		:param ILSourceLocation loc: location of returned expression
		:return: a comparison expression.
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_CMP_SLT, a, b, size=size, source_location=loc)

	def compare_unsigned_less_than(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``compare_unsigned_less_than`` returns comparison expression of size ``size`` checking if expression ``a`` is
		unsigned less than expression ``b``

		:param int size: size in bytes
		:param ExpressionIndex a: LHS of comparison
		:param ExpressionIndex b: RHS of comparison
		:param ILSourceLocation loc: location of returned expression
		:return: a comparison expression.
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_CMP_ULT, a, b, size=size, source_location=loc)

	def compare_signed_less_equal(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``compare_signed_less_equal`` returns comparison expression of size ``size`` checking if expression ``a`` is
		signed less than or equal to expression ``b``

		:param int size: size in bytes
		:param ExpressionIndex a: LHS of comparison
		:param ExpressionIndex b: RHS of comparison
		:param ILSourceLocation loc: location of returned expression
		:return: a comparison expression.
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_CMP_SLE, a, b, size=size, source_location=loc)

	def compare_unsigned_less_equal(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``compare_unsigned_less_equal`` returns comparison expression of size ``size`` checking if expression ``a`` is
		unsigned less than or equal to expression ``b``

		:param int size: size in bytes
		:param ExpressionIndex a: LHS of comparison
		:param ExpressionIndex b: RHS of comparison
		:param ILSourceLocation loc: location of returned expression
		:return: a comparison expression.
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_CMP_ULE, a, b, size=size, source_location=loc)

	def compare_signed_greater_equal(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``compare_signed_greater_equal`` returns comparison expression of size ``size`` checking if expression ``a`` is
		signed greater than or equal to expression ``b``

		:param int size: size in bytes
		:param ExpressionIndex a: LHS of comparison
		:param ExpressionIndex b: RHS of comparison
		:param ILSourceLocation loc: location of returned expression
		:return: a comparison expression.
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_CMP_SGE, a, b, size=size, source_location=loc)

	def compare_unsigned_greater_equal(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``compare_unsigned_greater_equal`` returns comparison expression of size ``size`` checking if expression ``a``
		is unsigned greater than or equal to expression ``b``

		:param int size: size in bytes
		:param ExpressionIndex a: LHS of comparison
		:param ExpressionIndex b: RHS of comparison
		:param ILSourceLocation loc: location of returned expression
		:return: a comparison expression.
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_CMP_UGE, a, b, size=size, source_location=loc)

	def compare_signed_greater_than(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``compare_signed_greater_than`` returns comparison expression of size ``size`` checking if expression ``a`` is
		signed greater than or equal to expression ``b``

		:param int size: size in bytes
		:param ExpressionIndex a: LHS of comparison
		:param ExpressionIndex b: RHS of comparison
		:param ILSourceLocation loc: location of returned expression
		:return: a comparison expression.
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_CMP_SGT, a, b, size=size, source_location=loc)

	def compare_unsigned_greater_than(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``compare_unsigned_greater_than`` returns comparison expression of size ``size`` checking if expression ``a`` is
		unsigned greater than or equal to expression ``b``

		:param int size: size in bytes
		:param ExpressionIndex a: LHS of comparison
		:param ExpressionIndex b: RHS of comparison
		:param ILSourceLocation loc: location of returned expression
		:return: a comparison expression.
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_CMP_UGT, a, b, size=size, source_location=loc)

	def test_bit(self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``test_bit`` returns an expression of size ``size`` that tells whether expression ``a`` has its bit with an
		index of the expression ``b`` is set

		:param int size: size in bytes
		:param ExpressionIndex a: an expression to be tested
		:param ExpressionIndex b: an expression for the index of the big
		:param ILSourceLocation loc: location of returned expression
		:return: the result expression.
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_TEST_BIT, a, b, size=size, source_location=loc)

	def bool_to_int(self, size: int, a: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``bool_to_int`` returns an expression of size ``size`` converting the boolean expression ``a`` to an integer

		:param int size: size in bytes
		:param ExpressionIndex a: boolean expression to be converted
		:param ILSourceLocation loc: location of returned expression
		:return: the converted integer expression.
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_BOOL_TO_INT, a, size=size, source_location=loc)

	def breakpoint(self, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``breakpoint`` returns a processor breakpoint expression.

		:param ILSourceLocation loc: location of returned expression
		:return: a breakpoint expression.
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_BP, source_location=loc)

	def trap(self, value: int, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``trap`` returns a processor trap (interrupt) expression of the given integer ``value``.

		:param int value: trap (interrupt) number
		:param ILSourceLocation loc: location of returned expression
		:return: a trap expression.
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_TRAP, value, source_location=loc)

	def intrinsic(
		self, outputs: List['variable.Variable'], intrinsic: 'architecture.IntrinsicType',
		params: List[ExpressionIndex], loc: Optional['ILSourceLocation'] = None
	):
		"""
		``intrinsic`` return an intrinsic expression.

		:param List[Variable] outputs: list of output variables
		:param IntrinsicType intrinsic: which intrinsic to call
		:param List[ExpressionIndex] params: parameters to intrinsic
		:param ILSourceLocation loc: location of returned expression
		:return: an intrinsic expression.
		:rtype: ExpressionIndex
		"""
		return self.expr(
			MediumLevelILOperation.MLIL_INTRINSIC,
			len(outputs),
			self.add_variable_list(outputs),
			self.arch.get_intrinsic_index(intrinsic),
			len(params),
			self.add_operand_list(params),
			size=0,
			source_location=loc
		)

	def free_var_slot(
		self,
		var: 'variable.Variable',
		loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``free_var_slot`` return an expression that clears the slot of the variable ``var`` which is in a register stack

		:param Variable var: variable to free
		:param ILSourceLocation loc: location of returned expression
		:return: the expression ``free_var_slot(var)``
		"""
		return self.expr(MediumLevelILOperation.MLIL_FREE_VAR_SLOT, var.identifier, source_location=loc)

	def undefined(self, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``undefined`` returns the undefined expression. This should be used for instructions which perform functions but
		aren't important for dataflow or partial emulation purposes.

		:param ILSourceLocation loc: location of returned expression
		:return: the undefined expression.
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_UNDEF, source_location=loc)

	def unimplemented(self, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``unimplemented`` returns the unimplemented expression. This should be used for all instructions which aren't
		implemented.

		:param ILSourceLocation loc: location of returned expression
		:return: the unimplemented expression.
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_UNIMPL, source_location=loc)

	def unimplemented_memory_ref(self, size: int, addr: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``unimplemented_memory_ref`` a memory reference to expression ``addr`` of size ``size`` with unimplemented operation.

		:param int size: size in bytes of the memory reference
		:param ExpressionIndex addr: expression to reference memory
		:param ILSourceLocation loc: location of returned expression
		:return: the unimplemented memory reference expression.
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_UNIMPL_MEM, addr, size=size, source_location=loc)

	def float_add(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``float_add`` adds floating point expression ``a`` to expression ``b``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``fadd.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_FADD, a, b, size=size, source_location=loc)

	def float_sub(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``float_sub`` subtracts floating point expression ``b`` from expression ``a``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``fsub.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_FSUB, a, b, size=size, source_location=loc)

	def float_mult(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``float_mult`` multiplies floating point expression ``a`` by expression ``b``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``fmul.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_FMUL, a, b, size=size, source_location=loc)

	def float_div(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``float_div`` divides floating point expression ``a`` by expression ``b``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``fdiv.<size>(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_FDIV, a, b, size=size, source_location=loc)

	def float_sqrt(
		self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``float_sqrt`` returns square root of floating point expression ``value`` of size ``size``

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to calculate the square root of
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``sqrt.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_FSQRT, value, size=size, source_location=loc)

	def float_neg(
		self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``float_neg`` returns sign negation of floating point expression ``value`` of size ``size``

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to negate
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``fneg.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_FNEG, value, size=size, source_location=loc)

	def float_abs(
		self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``float_abs`` returns absolute value of floating point expression ``value`` of size ``size``

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to get the absolute value of
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``fabs.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_FABS, value, size=size, source_location=loc)

	def float_to_int(
		self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``float_to_int`` returns integer value of floating point expression ``value`` of size ``size``

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to convert to an int
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``int.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_FLOAT_TO_INT, value, size=size, source_location=loc)

	def int_to_float(
		self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``int_to_float`` returns floating point value of integer expression ``value`` of size ``size``

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to convert to a float
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``float.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_INT_TO_FLOAT, value, size=size, source_location=loc)

	def float_convert(
		self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``int_to_float`` converts floating point value of expression ``value`` to size ``size``

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to negate
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``fconvert.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_FLOAT_CONV, value, size=size, source_location=loc)

	def round_to_int(
		self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``round_to_int`` rounds a floating point value to the nearest integer

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to round to the nearest integer
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``roundint.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_ROUND_TO_INT, value, size=size, source_location=loc)

	def floor(
		self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``floor`` rounds a floating point value to an integer towards negative infinity

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to round down
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``roundint.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_FLOOR, value, size=size, source_location=loc)

	def ceil(
		self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``ceil`` rounds a floating point value to an integer towards positive infinity

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to round up
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``roundint.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_CEIL, value, size=size, source_location=loc)

	def float_trunc(
		self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``float_trunc`` rounds a floating point value to an integer towards zero

		:param int size: the size of the result in bytes
		:param ExpressionIndex value: the expression to truncate
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``roundint.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_FTRUNC, value, size=size, source_location=loc)

	def float_compare_equal(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``float_compare_equal`` returns floating point comparison expression of size ``size`` checking if
		expression ``a`` is equal to expression ``b``

		:param int size: the size of the operands in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``a f== b``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_FCMP_E, a, b, size=size, source_location=loc)

	def float_compare_not_equal(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``float_compare_not_equal`` returns floating point comparison expression of size ``size`` checking if
		expression ``a`` is not equal to expression ``b``

		:param int size: the size of the operands in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``a f!= b``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_FCMP_NE, a, b, size=size, source_location=loc)

	def float_compare_less_than(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``float_compare_less_than`` returns floating point comparison expression of size ``size`` checking if
		expression ``a`` is less than expression ``b``

		:param int size: the size of the operands in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``a f< b``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_FCMP_LT, a, b, size=size, source_location=loc)

	def float_compare_less_equal(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``float_compare_less_equal`` returns floating point comparison expression of size ``size`` checking if
		expression ``a`` is less than or equal to expression ``b``

		:param int size: the size of the operands in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``a f<= b``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_FCMP_LE, a, b, size=size, source_location=loc)

	def float_compare_greater_equal(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``float_compare_greater_equal`` returns floating point comparison expression of size ``size`` checking if
		expression ``a`` is greater than or equal to expression ``b``

		:param int size: the size of the operands in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``a f>= b``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_FCMP_GE, a, b, size=size, source_location=loc)

	def float_compare_greater_than(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``float_compare_greater_than`` returns floating point comparison expression of size ``size`` checking if
		expression ``a`` is greater than expression ``b``

		:param int size: the size of the operands in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``a f> b``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_FCMP_GT, a, b, size=size, source_location=loc)

	def float_compare_ordered(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``float_compare_ordered`` returns floating point comparison expression of size ``size`` checking if
		expression ``a`` is ordered relative to expression ``b``

		:param int size: the size of the operands in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``is_ordered(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_FCMP_O, a, b, size=size, source_location=loc)

	def float_compare_unordered(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		``float_compare_unordered`` returns floating point comparison expression of size ``size`` checking if
		expression ``a`` is unordered relative to expression ``b``

		:param int size: the size of the operands in bytes
		:param ExpressionIndex a: LHS expression
		:param ExpressionIndex b: RHS expression
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``is_unordered(a, b)``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_FCMP_UO, a, b, size=size, source_location=loc)

	def block_to_expand(self, exprs: List[ExpressionIndex], loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``block_to_expand`` returns an expression to expand into multiple expressions. This expression must
		be expanded by a future workflow step and is used temporarily to insert instructions.

		:param List[ExpressionIndex] exprs: list of expressions
		:param ILSourceLocation loc: location of returned expression
		:return: The expression ``{ exprs... }``
		:rtype: ExpressionIndex
		"""
		return self.expr(MediumLevelILOperation.MLIL_BLOCK_TO_EXPAND, len(exprs), self.add_operand_list(exprs), size=0, source_location=loc)

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
