# Copyright (c) 2018-2024 Vector 35 Inc
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
from typing import (Optional, List, Union, Mapping,
	Generator, NewType, Tuple, ClassVar, Dict, Set, Callable, Any, Iterator, overload)
from dataclasses import dataclass
from . import deprecation

# Binary Ninja components
from . import _binaryninjacore as core
from .enums import MediumLevelILOperation, ILBranchDependence, DataFlowQueryOption, FunctionGraphType, DeadStoreElimination, ILInstructionAttribute, StringType
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
    Store, RegisterStack, SetVar, Intrinsic, VariableInstruction, SSAVariableInstruction, AliasedVariableInstruction
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
	    MediumLevelILOperation.MLIL_ADDRESS_OF: [("src", "var")], MediumLevelILOperation.MLIL_ADDRESS_OF_FIELD: [
	        ("src", "var"), ("offset", "int")
	    ], MediumLevelILOperation.MLIL_CONST: [("constant", "int")], MediumLevelILOperation.MLIL_CONST_PTR: [
	        ("constant", "int")
	    ], MediumLevelILOperation.MLIL_EXTERN_PTR: [
	        ("constant", "int"), ("offset", "int")
	    ], MediumLevelILOperation.MLIL_FLOAT_CONST: [("constant", "float")], MediumLevelILOperation.MLIL_IMPORT: [
	        ("constant", "int")
	    ], MediumLevelILOperation.MLIL_CONST_DATA: [("constant_data", "constant_data")], MediumLevelILOperation.MLIL_CONST_DATA: [
	        ("constant_data", "constant_data")
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
	    ], MediumLevelILOperation.MLIL_NOT: [("src", "expr")], MediumLevelILOperation.MLIL_SX: [
	        ("src", "expr")
	    ], MediumLevelILOperation.MLIL_ZX: [("src", "expr")], MediumLevelILOperation.MLIL_LOW_PART: [
	        ("src", "expr")
	    ], MediumLevelILOperation.MLIL_JUMP: [("dest", "expr")], MediumLevelILOperation.MLIL_JUMP_TO: [
	        ("dest", "expr"), ("targets", "target_map")
	    ], MediumLevelILOperation.MLIL_RET_HINT: [("dest", "expr")], MediumLevelILOperation.MLIL_CALL: [
	        ("output", "var_list"), ("dest", "expr"), ("params", "expr_list")
	    ], MediumLevelILOperation.MLIL_CALL_UNTYPED: [
	        ("output", "expr"), ("dest", "expr"), ("params", "expr"), ("stack", "expr")
	    ], MediumLevelILOperation.MLIL_CALL_OUTPUT: [("dest", "var_list")], MediumLevelILOperation.MLIL_CALL_PARAM: [
	        ("src", "expr_list")
	    ], MediumLevelILOperation.MLIL_SEPARATE_PARAM_LIST: [
	        ("params", "expr_list")
	    ], MediumLevelILOperation.MLIL_SHARED_PARAM_SLOT: [
	        ("params", "expr_list")
	    ], MediumLevelILOperation.MLIL_RET: [
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
	        ("output", "var_list"), ("params", "expr_list")
	    ], MediumLevelILOperation.MLIL_SYSCALL_UNTYPED: [
	        ("output", "expr"), ("params", "expr"), ("stack", "expr")
	    ], MediumLevelILOperation.MLIL_TAILCALL: [
	        ("output", "var_list"), ("dest", "expr"), ("params", "expr_list")
	    ], MediumLevelILOperation.MLIL_TAILCALL_UNTYPED: [("output", "expr"), ("dest", "expr"), ("params", "expr"),
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
		option_array = (ctypes.c_int * len(options))()
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

	def get_ssa_var_version(self, var: variable.Variable) -> int:
		var_data = var.to_BNVariable()
		return core.BNGetMediumLevelILSSAVarVersionAtILInstruction(self.function.handle, var_data, self.instr_index)

	def get_ssa_var_version_after(self, var: variable.Variable) -> int:
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

	def get_split_var_for_definition(self, var: variable.Variable) -> variable.Variable:
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
	def constant_data(self) -> variable.ConstantData:
		return self._get_constant_data(0, 1)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [("constant_data", self.constant_data, "ConstantData")]


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
	def src(self) -> List[variable.Variable]:
		return self._get_expr_list(0, 1)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [("src", self.src, "List[MediumLevelILInstruction]")]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILSeparateParamList(MediumLevelILInstruction):
	def __repr__(self):
		return f"<MediumLevelILSeparateParamList: {self.src}>"

	@property
	def src(self) -> List[variable.Variable]:
		return self._get_expr_list(0, 1)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [("src", self.src, "List[MediumLevelILInstruction]")]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILSharedParamSlot(MediumLevelILInstruction):
	def __repr__(self):
		return f"<MediumLevelILSharedParamSlot: {self.src}>"

	@property
	def src(self) -> List[variable.Variable]:
		return self._get_expr_list(0, 1)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [("src", self.src, "List[MediumLevelILInstruction]")]


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
	def dest(self) -> int:
		return self._get_int(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [("dest", self.dest, "int")]


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
		return self._get_var_list(0, 1)

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
		return self._get_var_ssa_list(1, 2)

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
	def src(self) -> List[SSAVariable]:
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
		inst = self._get_expr(0)
		assert isinstance(inst, MediumLevelILCallOutput), "MediumLevelILCallUntyped return bad type for 'output'"
		return inst.dest

	@property
	def params(self) -> List[variable.Variable]:
		inst = self._get_expr(1)
		assert isinstance(inst, MediumLevelILCallParam), "MediumLevelILCallUntyped return bad type for 'params'"
		return inst.src

	@property
	def stack(self) -> MediumLevelILInstruction:
		return self._get_expr(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			('output', self.output, 'List[Variable]'),
			('params', self.params, 'List[Variable]'),
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
	def output_dest_memory(self) -> int:
		inst = self._get_expr(0)
		assert isinstance(
		    inst, MediumLevelILCallOutputSsa
		), "MediumLevelILSyscallUntypedSsa return bad type for 'output_dest_memory'"
		return inst.dest_memory

	@property
	def params(self) -> List[SSAVariable]:
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
		return self._get_var_list(0, 1)

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
	def true(self) -> int:
		return self._get_int(1)

	@property
	def false(self) -> int:
		return self._get_int(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			('condition', self.condition, 'MediumLevelILInstruction'),
			('true', self.true, 'int'),
			('false', self.false, 'int'),
		]


@dataclass(frozen=True, repr=False, eq=False)
class MediumLevelILTailcallUntyped(MediumLevelILCallBase, Tailcall):
	@property
	def output(self) -> List[variable.Variable]:
		inst = self._get_expr(0)
		assert isinstance(inst, MediumLevelILCallOutput), "MediumLevelILTailcallUntyped return bad type for 'output'"
		return inst.dest

	@property
	def dest(self) -> MediumLevelILInstruction:
		return self._get_expr(1)

	@property
	def params(self) -> List[variable.Variable]:
		inst = self._get_expr(2)
		assert isinstance(inst, MediumLevelILCallParam), "MediumLevelILTailcallUntyped return bad type for 'params'"
		return inst.src

	@property
	def stack(self) -> MediumLevelILInstruction:
		return self._get_expr(3)

	@property
	def detailed_operands(self) -> List[Tuple[str, MediumLevelILOperandType, str]]:
		return [
			('output', self.output, 'List[Variable]'),
			('dest', self.dest, 'MediumLevelILInstruction'),
			('params', self.params, 'List[Variable]'),
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
	def output_dest_memory(self) -> int:
		inst = self._get_expr(0)
		assert isinstance(inst, MediumLevelILCallOutputSsa), "MediumLevelILCallUntypedSsa return bad type for output"
		return inst.dest_memory

	@property
	def dest(self) -> MediumLevelILInstruction:
		return self._get_expr(1)

	@property
	def params(self) -> List[SSAVariable]:
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
		return self._get_var_list(0, 1)

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
	def params(self) -> List[SSAVariable]:
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
		inst = self._get_expr(0)
		assert isinstance(inst, MediumLevelILCallOutput), "MediumLevelILCallUntyped return bad type for 'output'"
		return inst.dest

	@property
	def dest(self) -> MediumLevelILInstruction:
		return self._get_expr(1)

	@property
	def params(self) -> List[variable.Variable]:
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
			('dest', self.dest, 'MediumLevelILInstruction'),
			('params', self.params, 'List[Variable]'),
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


ILInstruction = {
    MediumLevelILOperation.MLIL_NOP: MediumLevelILNop,  # [],
    MediumLevelILOperation.MLIL_NORET: MediumLevelILNoret,  # [],
    MediumLevelILOperation.MLIL_BP: MediumLevelILBp,  # [],
    MediumLevelILOperation.MLIL_UNDEF: MediumLevelILUndef,  # [],
    MediumLevelILOperation.MLIL_UNIMPL: MediumLevelILUnimpl,  # [],
    MediumLevelILOperation.MLIL_LOAD: MediumLevelILLoad,  # [("src", "expr")],
    MediumLevelILOperation.MLIL_VAR: MediumLevelILVar,  # [("src", "var")],
    MediumLevelILOperation.MLIL_ADDRESS_OF: MediumLevelILAddressOf,  # [("src", "var")],
    MediumLevelILOperation.MLIL_CONST: MediumLevelILConst,  # [("constant", "int")],
    MediumLevelILOperation.MLIL_CONST_PTR: MediumLevelILConstPtr,  # [("constant", "int")],
    MediumLevelILOperation.MLIL_FLOAT_CONST: MediumLevelILFloatConst,  # [("constant", "float")],
    MediumLevelILOperation.MLIL_IMPORT: MediumLevelILImport,  # [("constant", "int")],
    MediumLevelILOperation.MLIL_CONST_DATA: MediumLevelILConstData,  # [("constant_data", "constant_data")],
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
    MediumLevelILOperation.MLIL_SX: MediumLevelILSx,  # [("src", "expr")],
    MediumLevelILOperation.MLIL_ZX: MediumLevelILZx,  # [("src", "expr")],
    MediumLevelILOperation.MLIL_LOW_PART: MediumLevelILLowPart,  # [("src", "expr")],
    MediumLevelILOperation.MLIL_JUMP: MediumLevelILJump,  # [("dest", "expr")],
    MediumLevelILOperation.MLIL_RET_HINT: MediumLevelILRetHint,  # [("dest", "expr")],
    MediumLevelILOperation.MLIL_CALL_OUTPUT: MediumLevelILCallOutput,  # [("dest", "var_list")],
    MediumLevelILOperation.MLIL_CALL_PARAM: MediumLevelILCallParam,  # [("src", "expr_list")],
    MediumLevelILOperation.MLIL_SEPARATE_PARAM_LIST: MediumLevelILSeparateParamList,  # [("src", "expr_list")],
    MediumLevelILOperation.MLIL_SHARED_PARAM_SLOT: MediumLevelILSharedParamSlot,  # [("src", "expr_list")],
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
    MediumLevelILOperation.MLIL_SYSCALL: MediumLevelILSyscall,  # [("output", "var_list"), ("params", "expr_list")],
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
        MediumLevelILSyscallUntyped,  # [("output", "expr"), ("params", "expr"), ("stack", "expr")],
    MediumLevelILOperation.MLIL_TAILCALL:
        MediumLevelILTailcall,  # [("output", "var_list"), ("dest", "expr"), ("params", "expr_list")],
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
        MediumLevelILTailcallUntyped,  # [("output", "expr"), ("dest", "expr"), ("params", "expr"), ("stack", "expr")],
    MediumLevelILOperation.MLIL_CALL_SSA:
        MediumLevelILCallSsa,  # [("output", "expr"), ("dest", "expr"), ("params", "expr_list"), ("src_memory", "int")],
    MediumLevelILOperation.MLIL_CALL_UNTYPED_SSA:
        MediumLevelILCallUntypedSsa,  # [("output", "expr"), ("dest", "expr"), ("params", "expr"), ("stack", "expr")],
    MediumLevelILOperation.MLIL_TAILCALL_SSA:
        MediumLevelILTailcallSsa,  # [("output", "expr"), ("dest", "expr"), ("params", "expr_list"), ("src_memory", "int")],
    MediumLevelILOperation.MLIL_TAILCALL_UNTYPED_SSA:
        MediumLevelILTailcallUntypedSsa,  # [("output", "expr"), ("dest", "expr"), ("params", "expr"), ("stack", "expr")],
    MediumLevelILOperation.MLIL_CALL:
        MediumLevelILCall,  # [("output", "var_list"), ("dest", "expr"), ("params", "expr_list")],
    MediumLevelILOperation.MLIL_IF: MediumLevelILIf,  # [("condition", "expr"), ("true", "int"), ("false", "int")],
    MediumLevelILOperation.MLIL_STORE_SSA:
        MediumLevelILStoreSsa,  # [("dest", "expr"), ("dest_memory", "int"), ("src_memory", "int"), ("src", "expr")],
    MediumLevelILOperation.MLIL_CALL_UNTYPED:
        MediumLevelILCallUntyped,  # [("output", "expr"), ("dest", "expr"), ("params", "expr"), ("stack", "expr")],
    MediumLevelILOperation.MLIL_STORE_STRUCT_SSA:
        MediumLevelILStoreStructSsa,  # [("dest", "expr"), ("offset", "int"), ("dest_memory", "int"), ("src_memory", "int"), ("src", "expr")],
}


class MediumLevelILExpr:
	"""
	``class MediumLevelILExpr`` hold the index of IL Expressions.

	.. note:: Deprecated. Use ExpressionIndex instead
	"""
	def __init__(self, index):
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
	    self, arch: Optional['architecture.Architecture'] = None, handle: Optional[core.BNMediumLevelILFunction] = None,
	    source_func: Optional['function.Function'] = None
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
			if _source_function is None:
				raise ValueError("IL functions must be created with an associated function")
			if _arch is None:
				_arch = _source_function.arch
			func_handle = _source_function.handle
			_handle = core.BNCreateMediumLevelILFunction(_arch.handle, func_handle)
		assert _source_function is not None
		assert _arch is not None
		assert _handle is not None
		self.handle = _handle
		self._arch = _arch
		self._source_function = _source_function

	def __del__(self):
		if core is not None:
			core.BNFreeMediumLevelILFunction(self.handle)

	def __repr__(self):
		arch = self.source_function.arch
		if arch:
			return f"<MediumLevelILFunction: {arch.name}@{self.source_function.start:#x}>"
		else:
			return f"<MediumLevelILFunction: {self.source_function.start:#x}>"

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

	def get_basic_block_at(self, index: int) -> Optional['basicblock.BasicBlock']:
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

	def get_instruction_start(self, addr: int, arch: Optional['architecture.Architecture'] = None) -> Optional[int]:
		_arch = arch
		if _arch is None:
			if self._arch is None:
				raise Exception("Attempting to get_instruction_start from a MLIL Function without an Architecture")
			_arch = self._arch
		result = core.BNMediumLevelILGetInstructionStart(self.handle, _arch.handle, addr)
		if result >= core.BNGetMediumLevelILInstructionCount(self.handle):
			return None
		return result

	def expr(
	    self, operation: MediumLevelILOperation, a: int = 0, b: int = 0, c: int = 0, d: int = 0, e: int = 0,
	    size: int = 0
	) -> ExpressionIndex:
		_operation = operation
		if isinstance(operation, str):
			_operation = MediumLevelILOperation[operation]
		elif isinstance(operation, MediumLevelILOperation):
			_operation = operation.value
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
		``copy_expr`` adds an expression to the function which is equivalent to the given expression

		:param MediumLevelILInstruction original: the original IL Instruction you want to copy
		:return: The index of the newly copied expression
		"""
		return self.expr(original.operation, original.raw_operands[0], original.raw_operands[1], original.raw_operands[2], original.raw_operands[3], original.raw_operands[4], original.size)

	def replace_expr(self, original: InstructionOrExpression, new: InstructionOrExpression) -> None:
		"""
		``replace_expr`` allows modification of MLIL expressions

		:param ExpressionIndex original: the ExpressionIndex to replace (may also be an expression index)
		:param ExpressionIndex new: the ExpressionIndex to add to the current LowLevelILFunction (may also be an expression index)
		:rtype: None
		"""
		if isinstance(original, MediumLevelILInstruction):
			original = original.expr_index
		elif isinstance(original, int):
			original = ExpressionIndex(original)

		if isinstance(new, MediumLevelILInstruction):
			new = new.expr_index
		elif isinstance(new, int):
			new = ExpressionIndex(new)

		core.BNReplaceMediumLevelILExpr(self.handle, original, new)

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

	def append(self, expr: ExpressionIndex) -> int:
		"""
		``append`` adds the ExpressionIndex ``expr`` to the current MediumLevelILFunction.

		:param ExpressionIndex expr: the ExpressionIndex to add to the current MediumLevelILFunction
		:return: number of ExpressionIndex in the current function
		:rtype: int
		"""
		return core.BNMediumLevelILAddInstruction(self.handle, expr)

	def goto(self, label: MediumLevelILLabel) -> ExpressionIndex:
		"""
		``goto`` returns a goto expression which jumps to the provided MediumLevelILLabel.

		:param MediumLevelILLabel label: Label to jump to
		:return: the ExpressionIndex that jumps to the provided label
		:rtype: ExpressionIndex
		"""
		return ExpressionIndex(core.BNMediumLevelILGoto(self.handle, label.handle))

	def if_expr(self, operand: ExpressionIndex, t: MediumLevelILLabel, f: MediumLevelILLabel) -> ExpressionIndex:
		"""
		``if_expr`` returns the ``if`` expression which depending on condition ``operand`` jumps to the MediumLevelILLabel
		``t`` when the condition expression ``operand`` is non-zero and ``f`` when it's zero.

		:param ExpressionIndex operand: comparison expression to evaluate.
		:param MediumLevelILLabel t: Label for the true branch
		:param MediumLevelILLabel f: Label for the false branch
		:return: the ExpressionIndex for the if expression
		:rtype: ExpressionIndex
		"""
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
		label_list = (ctypes.POINTER(core.BNMediumLevelILLabel) * len(labels))()  # type: ignore
		value_list = (ctypes.POINTER(ctypes.c_ulonglong) * len(labels))()  # type: ignore
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

	def finalize(self) -> None:
		"""
		``finalize`` ends the function and computes the list of basic blocks.

		:rtype: None
		"""
		core.BNFinalizeMediumLevelILFunction(self.handle)

	def generate_ssa_form(self, analyze_conditionals : bool = True, handle_aliases : bool = True, known_not_aliases: Optional[List["variable.Variable"]] = None, known_aliases: Optional[List["variable.Variable"]] = None) -> None:
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

	def is_var_live_at(self, var: 'variable.Variable', instr: InstructionIndex) -> bool:
		"""
		``is_var_live_at`` determines if ``var`` is live at a given point in the function
		"""
		return core.BNIsMediumLevelILVarLiveAt(self.handle, var.to_BNVariable(), instr)

	def get_var_definitions(self, var: 'variable.Variable') -> List[MediumLevelILInstruction]:
		count = ctypes.c_ulonglong()
		var_data = var.to_BNVariable()
		instrs = core.BNGetMediumLevelILVariableDefinitions(self.handle, var_data, count)
		assert instrs is not None, "core.BNGetMediumLevelILVariableDefinitions returned None"
		result = []
		for i in range(0, count.value):
			result.append(self[instrs[i]])
		core.BNFreeILInstructionList(instrs)
		return result

	def get_var_uses(self, var: 'variable.Variable') -> List[MediumLevelILInstruction]:
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

	def get_live_instructions_for_var(self, var: 'variable.Variable', include_last_use: bool = True) -> List[MediumLevelILInstruction]:
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

	def set_expr_type(self, expr_index: int, expr_type: StringOrType) -> None:
		"""
		Set type of expression

		This API is only meant for workflows or for debugging purposes, since the changes they make are not persistent
		and get lost after a database save and reload. To make persistent changes to the analysis, one should use other
		APIs to, for example, change the type of variables. The analysis will then propagate the type of the variable
		and update the type of related expressions.

		:param int expr_index: index of the expression to set
		:param StringOrType: new type of the expression
		"""
		if isinstance(expr_type, str):
			(expr_type, _) = self.view.parse_type_string(expr_type)
		tc = expr_type._to_core_struct()
		core.BNSetMediumLevelILExprType(self.handle, expr_index, tc)


class MediumLevelILBasicBlock(basicblock.BasicBlock):
	"""
	The ``MediumLevelILBasicBlock`` object is returned during analysis and should not be directly instantiated.
	"""
	def __init__(
	    self, handle: core.BNBasicBlockHandle, owner: MediumLevelILFunction,
	    view: Optional['binaryview.BinaryView'] = None
	):
		super(MediumLevelILBasicBlock, self).__init__(handle, view)
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
