# Copyright (c) 2019-2026 Vector 35 Inc
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
from typing import Optional, Generator, List, Dict, Union, NewType, Tuple, ClassVar, Set, Callable, Any, Iterator, overload
from dataclasses import dataclass
from enum import Enum

# Binary Ninja components
from . import _binaryninjacore as core
from .enums import (
	HighLevelILOperation, DataFlowQueryOption, FunctionGraphType, ILInstructionAttribute, StringType,
	DisassemblyOption
)
from . import function
from . import binaryview
from . import architecture
from . import lowlevelil
from . import mediumlevelil
from . import basicblock
from . import types
from . import highlight
from . import flowgraph
from . import variable
from . import databuffer
from . import stringrecognizer
from . import types as _types
from .interaction import show_graph_report
from .commonil import (
    BaseILInstruction, Tailcall, Syscall, Localcall, Comparison, Signed, UnaryOperation, BinaryOperation, SSA, Phi,
    Loop, ControlFlow, Memory, Constant, Arithmetic, DoublePrecision, Terminal, FloatingPoint, Intrinsic, Return,
    VariableInstruction, SSAVariableInstruction, SetVar, ILSourceLocation
)
from . import deprecation

TokenList = List['function.InstructionTextToken']
LinesType = Generator['function.DisassemblyTextLine', None, None]
ExpressionIndex = NewType('ExpressionIndex', int)
InstructionIndex = NewType('InstructionIndex', int)
Index = Union[ExpressionIndex, InstructionIndex]
InstructionOrExpression = Union['HighLevelILInstruction', Index]
HLILInstructionsType = Generator['HighLevelILInstruction', None, None]
HLILBasicBlocksType = Generator['HighLevelILBasicBlock', None, None]
OperandsType = Tuple[ExpressionIndex, ExpressionIndex, ExpressionIndex, ExpressionIndex, ExpressionIndex]
HighLevelILOperandType = Union['HighLevelILInstruction', 'lowlevelil.ILIntrinsic', 'variable.Variable',
                               'mediumlevelil.SSAVariable', List[int], List['variable.Variable'],
                               List['mediumlevelil.SSAVariable'], List['HighLevelILInstruction'], Optional[int], float,
                               'GotoLabel', variable.ConstantData, databuffer.DataBuffer]
VariablesList = List[Union['mediumlevelil.SSAVariable', 'variable.Variable']]
StringOrType = Union[str, '_types.Type', '_types.TypeBuilder']
ILInstructionAttributeSet = Union[Set[ILInstructionAttribute], List[ILInstructionAttribute]]
HighLevelILVisitorCallback = Callable[[str, HighLevelILOperandType, str, Optional['HighLevelILInstruction']], bool]


class VariableReferenceType(Enum):
	Read = 0
	Written = 1
	AddressTaken = 2


@dataclass(frozen=True)
class HighLevelILOperationAndSize:
	operation: HighLevelILOperation
	size: int

	def __repr__(self):
		if self.size == 0:
			return f"<HighLevelILOperationAndSize: {self.operation.name}>"
		return f"<HighLevelILOperationAndSize: {self.operation.name} {self.size}>"


@dataclass
class GotoLabel:
	function: 'HighLevelILFunction'
	id: int

	def __repr__(self):
		return f"<GotoLabel: {self.name}>"

	def __str__(self):
		return self.name

	@property
	def label_id(self) -> int:
		return self.id

	@property
	def name(self) -> str:
		assert self.function.source_function is not None, "Cant get name of function without source_function"
		return core.BNGetGotoLabelName(self.function.source_function.handle, self.id)

	@name.setter
	def name(self, value: str) -> None:
		assert self.function.source_function is not None, "Cant set name of function without source_function"
		core.BNSetUserGotoLabelName(self.function.source_function.handle, self.id, value)

	@property
	def definition(self) -> Optional['HighLevelILInstruction']:
		return self.function.get_label(self.id)

	@property
	def uses(self) -> List['HighLevelILInstruction']:
		return self.function.get_label_uses(self.id)

@dataclass(frozen=True, order=True)
class CoreHighLevelILInstruction:
	operation: HighLevelILOperation
	attributes: int
	source_operand: int
	size: int
	operands: OperandsType
	address: int
	parent: ExpressionIndex

	@classmethod
	def from_BNHighLevelILInstruction(cls, instr: core.BNHighLevelILInstruction) -> 'CoreHighLevelILInstruction':
		operands: OperandsType = tuple([ExpressionIndex(instr.operands[i]) for i in range(5)])  # type: ignore
		return cls(
		    HighLevelILOperation(instr.operation), instr.attributes, instr.sourceOperand, instr.size, operands, instr.address,
		    instr.parent
		)


@dataclass(frozen=True)
class HighLevelILInstruction(BaseILInstruction):
	"""
	``class HighLevelILInstruction`` High Level Intermediate Language Instructions form an abstract syntax tree of
	the code. Control flow structures are present as high level constructs in the HLIL tree.
	"""
	function: 'HighLevelILFunction'
	expr_index: ExpressionIndex
	core_instr: CoreHighLevelILInstruction
	as_ast: bool
	instr_index: InstructionIndex
	# ILOperations is deprecated and will be removed in a future version once BNIL Graph no longer uses it
	# Use the visit methods visit, visit_all, and visit_operands
	# BEGIN GENERATED hlil-operations: from api/il, do not edit
	ILOperations: ClassVar[Dict[HighLevelILOperation, List[Tuple[str, str]]]] = {
		HighLevelILOperation.HLIL_NOP: [],
		HighLevelILOperation.HLIL_BLOCK: [("body", "expr_list")],
		HighLevelILOperation.HLIL_IF: [("condition", "expr"), ("true", "expr"), ("false", "expr")],
		HighLevelILOperation.HLIL_WHILE: [("condition", "expr"), ("body", "expr")],
		HighLevelILOperation.HLIL_DO_WHILE: [("body", "expr"), ("condition", "expr")],
		HighLevelILOperation.HLIL_FOR: [("init", "expr"), ("condition", "expr"), ("update", "expr"), ("body", "expr")],
		HighLevelILOperation.HLIL_SWITCH: [("condition", "expr"), ("default", "expr"), ("cases", "expr_list")],
		HighLevelILOperation.HLIL_CASE: [("values", "expr_list"), ("body", "expr")],
		HighLevelILOperation.HLIL_BREAK: [],
		HighLevelILOperation.HLIL_CONTINUE: [],
		HighLevelILOperation.HLIL_JUMP: [("dest", "expr")],
		HighLevelILOperation.HLIL_RET: [("src", "expr_list")],
		HighLevelILOperation.HLIL_NORET: [],
		HighLevelILOperation.HLIL_GOTO: [("target", "label")],
		HighLevelILOperation.HLIL_LABEL: [("target", "label")],
		HighLevelILOperation.HLIL_VAR_DECLARE: [("var", "var")],
		HighLevelILOperation.HLIL_VAR_INIT: [("dest", "var"), ("src", "expr")],
		HighLevelILOperation.HLIL_ASSIGN: [("dest", "expr"), ("src", "expr")],
		HighLevelILOperation.HLIL_ASSIGN_UNPACK: [("dest", "expr_list"), ("src", "expr")],
		HighLevelILOperation.HLIL_FORCE_VER: [("dest", "var"), ("src", "var")],
		HighLevelILOperation.HLIL_ASSERT: [("src", "var"), ("constraint", "constraint")],
		HighLevelILOperation.HLIL_VAR: [("var", "var")],
		HighLevelILOperation.HLIL_STRUCT_FIELD: [("src", "expr"), ("offset", "int"), ("member_index", "member_index")],
		HighLevelILOperation.HLIL_ARRAY_INDEX: [("src", "expr"), ("index", "expr")],
		HighLevelILOperation.HLIL_SPLIT: [("high", "expr"), ("low", "expr")],
		HighLevelILOperation.HLIL_DEREF: [("src", "expr")],
		HighLevelILOperation.HLIL_DEREF_FIELD: [("src", "expr"), ("offset", "int"), ("member_index", "member_index")],
		HighLevelILOperation.HLIL_ADDRESS_OF: [("src", "expr")],
		HighLevelILOperation.HLIL_PASS_BY_REF: [("src", "expr")],
		HighLevelILOperation.HLIL_RETURN_BY_REF: [("src", "expr")],
		HighLevelILOperation.HLIL_CONST: [("constant", "int")],
		HighLevelILOperation.HLIL_CONST_DATA: [("constant", "ConstantData")],
		HighLevelILOperation.HLIL_CONST_PTR: [("constant", "int")],
		HighLevelILOperation.HLIL_EXTERN_PTR: [("constant", "int"), ("offset", "int")],
		HighLevelILOperation.HLIL_FLOAT_CONST: [("constant", "float")],
		HighLevelILOperation.HLIL_IMPORT: [("constant", "int")],
		HighLevelILOperation.HLIL_ADD: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_ADC: [("left", "expr"), ("right", "expr"), ("carry", "expr")],
		HighLevelILOperation.HLIL_SUB: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_SBB: [("left", "expr"), ("right", "expr"), ("carry", "expr")],
		HighLevelILOperation.HLIL_AND: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_OR: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_XOR: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_LSL: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_LSR: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_ASR: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_ROL: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_RLC: [("left", "expr"), ("right", "expr"), ("carry", "expr")],
		HighLevelILOperation.HLIL_ROR: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_RRC: [("left", "expr"), ("right", "expr"), ("carry", "expr")],
		HighLevelILOperation.HLIL_MUL: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_MULU_DP: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_MULS_DP: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_DIVU: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_DIVU_DP: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_DIVS: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_DIVS_DP: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_MODU: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_MODU_DP: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_MODS: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_MODS_DP: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_NEG: [("src", "expr")],
		HighLevelILOperation.HLIL_NOT: [("src", "expr")],
		HighLevelILOperation.HLIL_SX: [("src", "expr")],
		HighLevelILOperation.HLIL_ZX: [("src", "expr")],
		HighLevelILOperation.HLIL_LOW_PART: [("src", "expr")],
		HighLevelILOperation.HLIL_CALL: [("dest", "expr"), ("params", "expr_list")],
		HighLevelILOperation.HLIL_CMP_E: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_CMP_NE: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_CMP_SLT: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_CMP_ULT: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_CMP_SLE: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_CMP_ULE: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_CMP_SGE: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_CMP_UGE: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_CMP_SGT: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_CMP_UGT: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_TEST_BIT: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_BOOL_TO_INT: [("src", "expr")],
		HighLevelILOperation.HLIL_ADD_OVERFLOW: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_SYSCALL: [("params", "expr_list")],
		HighLevelILOperation.HLIL_TAILCALL: [("dest", "expr"), ("params", "expr_list")],
		HighLevelILOperation.HLIL_INTRINSIC: [("intrinsic", "intrinsic"), ("params", "expr_list")],
		HighLevelILOperation.HLIL_BP: [],
		HighLevelILOperation.HLIL_TRAP: [("vector", "int")],
		HighLevelILOperation.HLIL_UNDEF: [],
		HighLevelILOperation.HLIL_UNIMPL: [],
		HighLevelILOperation.HLIL_UNIMPL_MEM: [("src", "expr")],
		HighLevelILOperation.HLIL_STRUCT_INIT: [("fields", "expr_list")],
		HighLevelILOperation.HLIL_STRUCT_INIT_FIELD: [
			("offset", "int"),
			("member_index", "member_index"),
			("src", "expr"),
		],
		HighLevelILOperation.HLIL_FADD: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_FSUB: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_FMUL: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_FDIV: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_FSQRT: [("src", "expr")],
		HighLevelILOperation.HLIL_FNEG: [("src", "expr")],
		HighLevelILOperation.HLIL_FABS: [("src", "expr")],
		HighLevelILOperation.HLIL_FLOAT_TO_INT: [("src", "expr")],
		HighLevelILOperation.HLIL_INT_TO_FLOAT: [("src", "expr")],
		HighLevelILOperation.HLIL_FLOAT_CONV: [("src", "expr")],
		HighLevelILOperation.HLIL_ROUND_TO_INT: [("src", "expr")],
		HighLevelILOperation.HLIL_FLOOR: [("src", "expr")],
		HighLevelILOperation.HLIL_CEIL: [("src", "expr")],
		HighLevelILOperation.HLIL_FTRUNC: [("src", "expr")],
		HighLevelILOperation.HLIL_FCMP_E: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_FCMP_NE: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_FCMP_LT: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_FCMP_LE: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_FCMP_GE: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_FCMP_GT: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_FCMP_O: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_FCMP_UO: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_UNREACHABLE: [],
		HighLevelILOperation.HLIL_WHILE_SSA: [("condition_phi", "expr"), ("condition", "expr"), ("body", "expr")],
		HighLevelILOperation.HLIL_DO_WHILE_SSA: [("body", "expr"), ("condition_phi", "expr"), ("condition", "expr")],
		HighLevelILOperation.HLIL_FOR_SSA: [
			("init", "expr"),
			("condition_phi", "expr"),
			("condition", "expr"),
			("update", "expr"),
			("body", "expr"),
		],
		HighLevelILOperation.HLIL_VAR_INIT_SSA: [("dest", "var_ssa"), ("src", "expr")],
		HighLevelILOperation.HLIL_ASSIGN_MEM_SSA: [
			("dest", "expr"),
			("dest_memory", "int"),
			("src", "expr"),
			("src_memory", "int"),
		],
		HighLevelILOperation.HLIL_ASSIGN_UNPACK_MEM_SSA: [
			("dest", "expr_list"),
			("dest_memory", "int"),
			("src", "expr"),
			("src_memory", "int"),
		],
		HighLevelILOperation.HLIL_FORCE_VER_SSA: [("dest", "var_ssa"), ("src", "var_ssa")],
		HighLevelILOperation.HLIL_ASSERT_SSA: [("src", "var_ssa"), ("constraint", "constraint")],
		HighLevelILOperation.HLIL_VAR_SSA: [("var", "var_ssa")],
		HighLevelILOperation.HLIL_VAR_SSA_PARTIAL: [("dest", "var_ssa_dest_and_src"), ("prev", "var_ssa_dest_and_src")],
		HighLevelILOperation.HLIL_ARRAY_INDEX_SSA: [("src", "expr"), ("src_memory", "int"), ("index", "expr")],
		HighLevelILOperation.HLIL_DEREF_SSA: [("src", "expr"), ("src_memory", "int")],
		HighLevelILOperation.HLIL_DEREF_FIELD_SSA: [
			("src", "expr"),
			("src_memory", "int"),
			("offset", "int"),
			("member_index", "member_index"),
		],
		HighLevelILOperation.HLIL_CALL_SSA: [
			("dest", "expr"),
			("params", "expr_list"),
			("dest_memory", "int"),
			("src_memory", "int"),
		],
		HighLevelILOperation.HLIL_SYSCALL_SSA: [("params", "expr_list"), ("dest_memory", "int"), ("src_memory", "int")],
		HighLevelILOperation.HLIL_INTRINSIC_SSA: [
			("intrinsic", "intrinsic"),
			("params", "expr_list"),
			("dest_memory", "int"),
			("src_memory", "int"),
		],
		HighLevelILOperation.HLIL_VAR_PHI: [("dest", "var_ssa"), ("src", "var_ssa_list")],
		HighLevelILOperation.HLIL_MEM_PHI: [("dest", "int"), ("src", "int_list")],
		HighLevelILOperation.HLIL_BSWAP: [("src", "expr")],
		HighLevelILOperation.HLIL_POPCNT: [("src", "expr")],
		HighLevelILOperation.HLIL_CLZ: [("src", "expr")],
		HighLevelILOperation.HLIL_CTZ: [("src", "expr")],
		HighLevelILOperation.HLIL_RBIT: [("src", "expr")],
		HighLevelILOperation.HLIL_CLS: [("src", "expr")],
		HighLevelILOperation.HLIL_MINS: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_MAXS: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_MINU: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_MAXU: [("left", "expr"), ("right", "expr")],
		HighLevelILOperation.HLIL_ABS: [("src", "expr")],
	}
	# END GENERATED hlil-operations

	@staticmethod
	def show_hlil_hierarchy():
		"""
		Opens a new tab showing the HLIL hierarchy which includes classes which can
		easily be used with isinstance to match multiple types of IL instructions.
		"""
		graph = flowgraph.FlowGraph()
		nodes = {}
		for instruction in ILInstruction.values():
			instruction.add_subgraph(graph, nodes)
		show_graph_report("HLIL Class Hierarchy Graph", graph)

	@classmethod
	def create(
	    cls, func: 'HighLevelILFunction', expr_index: ExpressionIndex, as_ast: bool = True,
	    instr_index: Optional[InstructionIndex] = None
	) -> 'HighLevelILInstruction':
		assert func.arch is not None, "Attempted to create IL instruction with function missing an Architecture"
		instr = core.BNGetHighLevelILByIndex(func.handle, expr_index, as_ast)
		assert instr is not None, "core.BNGetHighLevelILByIndex returned None"
		core_instr = CoreHighLevelILInstruction.from_BNHighLevelILInstruction(instr)
		if instr_index is None:
			instr_index = core.BNGetHighLevelILInstructionForExpr(func.handle, expr_index)
			assert instr_index is not None, "core.BNGetHighLevelILInstructionForExpr returned None"
		return ILInstruction[instr.operation](func, expr_index, core_instr, as_ast, instr_index)

	def __str__(self):
		settings = function.DisassemblySettings.default_settings()
		settings.set_option(DisassemblyOption.DisableLineFormatting)
		lines = self.get_lines(settings)
		if lines is None:
			return "invalid"
		result = []
		for line in lines:
			cur = ""
			for token in line.tokens:
				cur += token.text
			result.append(cur)
		return '\n'.join(result)

	def __repr__(self):
		settings = function.DisassemblySettings.default_settings()
		settings.set_option(DisassemblyOption.DisableLineFormatting)
		lines = self.get_lines(settings)
		continuation = ""
		if lines is None:
			first_line = "<invalid>"
		else:
			first_line = ""
			for token in next(lines).tokens:
				first_line += token.text
			if len(list(lines)) > 1:
				continuation = "..."
		return f"<{self.__class__.__name__}: {first_line}{continuation}>"

	def __eq__(self, other: 'HighLevelILInstruction'):
		if not isinstance(other, HighLevelILInstruction):
			return NotImplemented
		return self.function == other.function and self.expr_index == other.expr_index

	def __lt__(self, other: 'HighLevelILInstruction'):
		if not isinstance(other, HighLevelILInstruction):
			return NotImplemented
		return self.function == other.function and self.expr_index < other.expr_index

	def __le__(self, other: 'HighLevelILInstruction'):
		if not isinstance(other, HighLevelILInstruction):
			return NotImplemented
		return self.function == other.function and self.expr_index <= other.expr_index

	def __gt__(self, other: 'HighLevelILInstruction'):
		if not isinstance(other, HighLevelILInstruction):
			return NotImplemented
		return self.function == other.function and self.expr_index > other.expr_index

	def __ge__(self, other: 'HighLevelILInstruction'):
		if not isinstance(other, HighLevelILInstruction):
			return NotImplemented
		return self.function == other.function and self.expr_index >= other.expr_index

	def __hash__(self):
		return hash((self.function, self.expr_index))

	@property
	def tokens(self) -> TokenList:
		"""HLIL tokens taken from the HLIL text lines (read-only) -- does not include newlines or indentation, use lines for that information"""
		settings = function.DisassemblySettings.default_settings()
		settings.set_option(DisassemblyOption.DisableLineFormatting)
		return [token for line in self.get_lines(settings) for token in line.tokens]

	@property
	def lines(self) -> LinesType:
		"""HLIL text lines (read-only)"""
		return self.get_lines()

	@property
	def prefix_operands(self) -> List[Union[HighLevelILOperandType, HighLevelILOperationAndSize]]:
		"""All operands in the expression tree in prefix order"""
		result: List[Union[HighLevelILOperandType,
		                   HighLevelILOperationAndSize]] = [HighLevelILOperationAndSize(self.operation, self.size)]
		for operand in self.operands:
			if isinstance(operand, HighLevelILInstruction):
				result.extend(operand.prefix_operands)
			else:
				result.append(operand)
		return result

	@property
	def postfix_operands(self) -> List[Union[HighLevelILOperandType, HighLevelILOperationAndSize]]:
		"""All operands in the expression tree in postfix order"""
		result: List[Union[HighLevelILOperandType, HighLevelILOperationAndSize]] = []
		for operand in self.operands:
			if isinstance(operand, HighLevelILInstruction):
				result.extend(operand.postfix_operands)
			else:
				result.append(operand)
		result.append(HighLevelILOperationAndSize(self.operation, self.size))
		return result

	@property
	def instr(self) -> 'HighLevelILInstruction':
		"""The statement that this expression belongs to (read-only)"""
		return self.function[self.instr_index]

	@property
	def ast(self) -> 'HighLevelILInstruction':
		"""
		This expression with full AST printing (read-only)

		See `AST and Non-AST Forms <https://docs.binary.ninja/dev/bnil-hlil.html#ast-and-non-ast-forms>`_
		"""
		if self.as_ast:
			return self
		return HighLevelILInstruction.create(self.function, self.expr_index, True)

	@property
	def non_ast(self) -> 'HighLevelILInstruction':
		"""
		This expression without full AST printing (read-only)

		See `AST and Non-AST Forms <https://docs.binary.ninja/dev/bnil-hlil.html#ast-and-non-ast-forms>`_
		"""
		if not self.as_ast:
			return self
		return HighLevelILInstruction.create(self.function, self.expr_index, False)

	@property
	def operation(self) -> HighLevelILOperation:
		return self.core_instr.operation

	@property
	def size(self) -> int:
		return self.core_instr.size

	@property
	def address(self) -> int:
		return self.core_instr.address

	@property
	def source_operand(self) -> ExpressionIndex:
		return ExpressionIndex(self.core_instr.source_operand)

	@property
	def source_location(self) -> ILSourceLocation:
		return ILSourceLocation.from_instruction(self)

	@property
	def core_operands(self) -> OperandsType:
		return self.core_instr.operands

	@property
	def instruction_operands(self) -> List['HighLevelILInstruction']:
		result = []
		for i in self.operands:
			if isinstance(i, list):
				result.extend([j for j in i if isinstance(j, HighLevelILInstruction)])
			elif isinstance(i, HighLevelILInstruction):
				result.append(i)
		return result

	@property
	def vars_written(self) -> VariablesList:
		"""List of variables value is written by this instruction"""
		result = []
		for i in self.operands:
			if isinstance(i, HighLevelILInstruction):
				result.extend(i.vars_written)
		return result

	@property
	def vars_read(self) -> VariablesList:
		"""Non-unique list of variables whose value is read by this instruction"""
		non_read = [*self.vars_written, *self.vars_address_taken]
		result = []
		for v in self.vars:
			if v in non_read:
				non_read.remove(v)
				continue
			result.append(v)
		return result

	@property
	def vars_address_taken(self) -> VariablesList:
		"""
		Non-unique list of variables whose address is taken by instruction

		.. note:: This property has some nuance to it, so use carefully. This property will return only those variable which \
			directly have their address taken such as `&var_4` or `&var_8.d` but not those which are involved in an address \
			calculation such as `&(var_4 + 0)` or `&var_4[0]` even though they may be functionally equivalent.
		"""
		result = []
		for operand in self.instruction_operands:
			result.extend(operand.vars_address_taken)
		return result

	@property
	def vars(self) -> VariablesList:
		"""Non-unique list of variables read by instruction"""
		result = []
		for operand in self.operands:
			if isinstance(operand, HighLevelILInstruction):
				result.extend(operand.vars)
			elif isinstance(operand, (variable.Variable, mediumlevelil.SSAVariable)):
				result.append(operand)
			elif isinstance(operand, list):
				for sub_operand in operand:
					if isinstance(sub_operand, (variable.Variable, mediumlevelil.SSAVariable)):
						result.append(sub_operand)
					elif isinstance(sub_operand, HighLevelILInstruction):
						result.extend(sub_operand.vars)
		return result

	@property
	def parent(self) -> Optional['HighLevelILInstruction']:
		if self.core_instr.parent >= core.BNGetHighLevelILExprCount(self.function.handle):
			return None
		return HighLevelILInstruction.create(self.function, self.core_instr.parent, self.as_ast)

	@property
	def ssa_form(self) -> 'HighLevelILInstruction':
		"""SSA form of expression (read-only)"""
		assert self.function.ssa_form is not None
		return HighLevelILInstruction.create(
		    self.function.ssa_form,
		    ExpressionIndex(core.BNGetHighLevelILSSAExprIndex(self.function.handle, self.expr_index)), self.as_ast
		)

	@property
	def non_ssa_form(self) -> Optional['HighLevelILInstruction']:
		"""Non-SSA form of expression (read-only)"""
		if self.function.non_ssa_form is None:
			return None
		return HighLevelILInstruction.create(
		    self.function.non_ssa_form,
		    ExpressionIndex(core.BNGetHighLevelILNonSSAExprIndex(self.function.handle, self.expr_index)), self.as_ast
		)

	@property
	def medium_level_il(self) -> Optional['mediumlevelil.MediumLevelILInstruction']:
		"""Medium level IL form of this expression"""
		expr = self.function.get_medium_level_il_expr_index(self.expr_index)
		if expr is None:
			return None
		mlil = self.function.medium_level_il
		if mlil is None:
			return None
		ssa_func = mlil.ssa_form
		assert ssa_func is not None, "medium_level_il.ssa_form is None"
		return mediumlevelil.MediumLevelILInstruction.create(ssa_func, expr)

	@property
	def mlil(self) -> Optional['mediumlevelil.MediumLevelILInstruction']:
		"""Alias for medium_level_il"""
		return self.medium_level_il

	@property
	def mlils(self) -> Optional[List['mediumlevelil.MediumLevelILInstruction']]:
		result = []
		for expr in self.function.get_medium_level_il_expr_indexes(self.expr_index):
			mlil = self.function.medium_level_il
			if mlil is None:
				return
			ssa_func = mlil.ssa_form
			assert ssa_func is not None, "medium_level_il.ssa_form is None"
			result.append(mediumlevelil.MediumLevelILInstruction.create(ssa_func, expr))
		return result

	@property
	def low_level_il(self) -> Optional['lowlevelil.LowLevelILInstruction']:
		"""Low level IL form of this expression"""
		if self.mlil is None:
			return None
		return self.mlil.llil

	@property
	def llil(self) -> Optional['lowlevelil.LowLevelILInstruction']:
		"""Alias for low_level_il"""
		return self.low_level_il

	@property
	def llils(self) -> List['lowlevelil.ExpressionIndex']:
		result = set()
		mlils = self.mlils
		if mlils is None:
			return []
		for mlil_expr in mlils:
			for llil_expr in mlil_expr.llils:
				result.add(llil_expr)
		return list(result)

	@property
	def il_basic_block(self) -> Optional['HighLevelILBasicBlock']:
		"""
		IL basic block object containing this expression (read-only) (only available on finalized functions).
		Returns None for HLIL_BLOCK expressions as these can contain multiple basic blocks.
		"""
		core_block = core.BNGetHighLevelILBasicBlockForInstruction(self.function.handle, self.instr_index)
		assert core_block is not None, "core.BNGetHighLevelILBasicBlockForInstruction returned None"
		if self.function.source_function is None:
			return None
		return HighLevelILBasicBlock(core_block, self.function, self.function.source_function.view)

	@property
	def value(self) -> 'variable.RegisterValue':
		"""Value of expression if constant or a known value (read-only)"""
		mlil = self.mlil
		if mlil is None:
			return variable.Undetermined()
		return mlil.value

	@property
	def possible_values(self) -> 'variable.PossibleValueSet':
		"""Possible values of expression using path-sensitive static data flow analysis (read-only)"""
		mlil = self.mlil
		if mlil is None:
			return variable.PossibleValueSet()
		return mlil.possible_values

	@property
	def expr_type(self) -> Optional['types.Type']:
		"""Type of expression"""
		result = core.BNGetHighLevelILExprType(self.function.handle, self.expr_index)
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
			if self.core_instr.attributes & flag.value != 0:
				result.add(flag)
		return result

	def get_possible_values(self, options: Optional[List[DataFlowQueryOption]] = None) -> 'variable.PossibleValueSet':
		mlil = self.mlil
		if mlil is None:
			return variable.PossibleValueSet()
		if options is None:
			options = []
		return mlil.get_possible_values(options)

	@property
	def ssa_memory_version(self) -> int:
		"""Version of active memory contents in SSA form for this instruction"""
		return core.BNGetHighLevelILSSAMemoryVersionAtILInstruction(self.function.handle, self.instr_index)

	def get_ssa_var_version(self, var: 'variable.Variable') -> int:
		var_data = var.to_BNVariable()
		return core.BNGetHighLevelILSSAVarVersionAtILInstruction(self.function.handle, var_data, self.instr_index)

	def _get_int(self, operand_index: int) -> int:
		value = self.core_instr.operands[operand_index]
		return (value & ((1 << 63) - 1)) - (value & (1 << 63))

	def _get_float(self, operand_index: int) -> float:
		value = self.core_instr.operands[operand_index]
		if self.core_instr.size == 4:
			return struct.unpack("f", struct.pack("I", value & 0xffffffff))[0]
		elif self.core_instr.size == 8:
			return struct.unpack("d", struct.pack("Q", value))[0]
		else:
			return float(value)

	def _get_constant_data(self, operand_index1: int, operand_index2: int) -> variable.ConstantData:
		state = variable.RegisterValueType(self.core_instr.operands[operand_index1])
		value = self.core_instr.operands[operand_index2]
		return variable.ConstantData(value, 0, state, core.max_confidence, self.core_instr.size, self.function.source_function)

	def _get_expr(self, operand_index: int) -> 'HighLevelILInstruction':
		return HighLevelILInstruction.create(
			self.function, ExpressionIndex(self.core_instr.operands[operand_index]),
			self.as_ast
		)

	def _get_intrinsic(self, operand_index: int) -> 'lowlevelil.ILIntrinsic':
		if self.function.arch is None:
			raise ValueError("Attempting to create ILIntrinsic from function with no Architecture")
		return lowlevelil.ILIntrinsic(
		    self.function.arch, architecture.IntrinsicIndex(self.core_instr.operands[operand_index])
		)

	def _get_var(self, operand_index: int) -> 'variable.Variable':
		value = self.core_instr.operands[operand_index]
		return variable.Variable.from_identifier(self.function, value)

	def _get_var_ssa(self, operand_index1: int, operand_index2: int) -> 'mediumlevelil.SSAVariable':
		var = variable.Variable.from_identifier(self.function, self.core_instr.operands[operand_index1])
		version = self.core_instr.operands[operand_index2]
		return mediumlevelil.SSAVariable(var, version)

	def _get_int_list(self, operand_index: int) -> List[int]:
		count = ctypes.c_ulonglong()
		operand_list = core.BNHighLevelILGetOperandList(self.function.handle, self.expr_index, operand_index, count)
		assert operand_list is not None, "core.BNHighLevelILGetOperandList returned None"
		value: List[int] = []
		try:
			for j in range(count.value):
				value.append(operand_list[j])
			return value
		finally:
			core.BNHighLevelILFreeOperandList(operand_list)

	def _get_expr_list(self, operand_index1: int, _: int) -> List['HighLevelILInstruction']:
		count = ctypes.c_ulonglong()
		operand_list = core.BNHighLevelILGetOperandList(self.function.handle, self.expr_index, operand_index1, count)
		assert operand_list is not None, "core.BNHighLevelILGetOperandList returned None"
		value: List[HighLevelILInstruction] = []
		try:
			for j in range(count.value):
				value.append(HighLevelILInstruction.create(self.function, operand_list[j], self.as_ast))
			return value
		finally:
			core.BNHighLevelILFreeOperandList(operand_list)

	def _get_var_ssa_list(self, operand_index1: int, _: int) -> List['mediumlevelil.SSAVariable']:
		count = ctypes.c_ulonglong()
		operand_list = core.BNHighLevelILGetOperandList(self.function.handle, self.expr_index, operand_index1, count)
		assert operand_list is not None, "core.BNHighLevelILGetOperandList returned None"
		value = []
		try:
			for j in range(count.value // 2):
				var_id = operand_list[j * 2]
				var_version = operand_list[(j*2) + 1]
				value.append(
				    mediumlevelil.SSAVariable(variable.Variable.from_identifier(self.function, var_id), var_version)
				)
			return value
		finally:
			core.BNMediumLevelILFreeOperandList(operand_list)

	def _get_member_index(self, operand_index: int) -> Optional[int]:
		value = self.core_instr.operands[operand_index]
		if (value & (1 << 63)) != 0:
			value = None
		return value

	def _get_label(self, operand_index: int) -> GotoLabel:
		return GotoLabel(self.function, self.core_instr.operands[operand_index])

	def _get_constraint(self, operand_index: int) -> variable.PossibleValueSet:
		value = core.BNGetCachedHighLevelILPossibleValueSet(self.function.handle, self.core_instr.operands[operand_index])
		result = variable.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	@property
	def raw_operands(self) -> OperandsType:
		"""Raw operand expression indices as specified by the core structure (read-only)"""
		return self.instr.operands

	@property
	def operands(self) -> List[HighLevelILOperandType]:
		"""
		Operands for the instruction

		Consider using more specific APIs for ``src``, ``dest``, ``params``, etc where appropriate.
		"""
		return list(map(lambda x: x[1], self.detailed_operands))

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		"""
		Returns a list of tuples containing the name of the operand, the operand, and the type of the operand.
		Useful for iterating over all operands of an instruction and sub-instructions.
		"""
		return []

	def traverse(self, cb: Callable[['HighLevelILInstruction', Any], Any], *args: Any, shallow: bool = True, **kwargs: Any) -> Iterator[Any]:
		"""
		``traverse`` is a generator that allows you to traverse the HLIL AST in a depth-first manner. It will yield the
		result of the callback function for each node in the AST. Arguments can be passed to the callback function using
		``args`` and ``kwargs``. See the `Developer Docs <https://docs.binary.ninja/dev/concepts.html#walking-ils>`_ for more examples.

		:param Callable[[HighLevelILInstruction, Any], Any] cb: The callback function to call for each node in the HighLevelILInstruction
		:param Any args: Custom user-defined arguments
		:param bool shallow: Whether traversal occurs on block instructions
		:param Any kwargs: Custom user-defined keyword arguments
		:return: An iterator of the results of the callback function
		:rtype: Iterator[Any]

		:Example:
			>>> def get_constant_less_than_value(inst: HighLevelILInstruction, value: int) -> int:
			... 	if isinstance(inst, Constant) and inst.constant < value:
			... 		return inst.constant
			>>>
			>>> for result in inst.traverse(get_constant_less_than_value, 10):
			... 	print(f"Found a constant {result} < 10 in {repr(inst)}")

		:Example:
			>>> def get_import_data_var_with_name(inst: HighLevelILInstruction, name: str) -> Optional['DataVariable']:
			... 	if isinstance(inst, HighLevelILImport):
			...			if bv.get_symbol_at(inst.constant).name == name:
			... 			return bv.get_data_var_at(inst.constant)
			>>>
			>>> for result in inst.traverse(get_import_data_var_with_name, "__cxa_finalize", shallow=False):
			... 	print(f"Found import at {result} in {repr(inst)}")
		"""
		if (result := cb(self, *args, **kwargs)) is not None:
			yield result
		blacklisted_op_names = {'true', 'false', 'body', 'cases', 'default'}
		for op_name, op, _ in self.detailed_operands:
			if shallow and op_name in blacklisted_op_names:
				continue
			if isinstance(op, HighLevelILInstruction):
				yield from op.traverse(cb, *args, shallow=shallow, **kwargs)
			elif isinstance(op, list) and all(isinstance(i, HighLevelILInstruction) for i in op):
				for i in op:
					yield from i.traverse(cb, *args, shallow=shallow, **kwargs) # type: ignore

	@deprecation.deprecated(deprecated_in="4.0.4907", details="Use :py:func:`HighLevelILInstruction.traverse` instead.")
	def visit_all(self, cb: HighLevelILVisitorCallback,
	       name: str = "root", parent: Optional['HighLevelILInstruction'] = None) -> bool:
		"""
		Visits all operands of this instruction and all operands of any sub-instructions.
		Using pre-order traversal.

		:param HighLevelILVisitorCallback cb: Callback function that takes the name of the operand, the operand, operand type, and parent instruction
		:return: True if all instructions were visited, False if the callback returned False

		"""
		if cb(name, self, "HighLevelILInstruction", parent) == False:
			return False
		for name, op, opType in self.detailed_operands:
			if isinstance(op, HighLevelILInstruction):
				if not op.visit_all(cb, name, self):
					return False
			elif isinstance(op, list) and all(isinstance(i, HighLevelILInstruction) for i in op):
				for i in op:
					if not i.visit_all(cb, name, self): # type: ignore
						return False
			elif cb(name, op, opType, self) == False:
				return False
		return True

	@deprecation.deprecated(deprecated_in="4.0.4907", details="Use :py:func:`HighLevelILInstruction.traverse` instead.")
	def visit_operands(self, cb: HighLevelILVisitorCallback,
	       name: str = "root", parent: Optional['HighLevelILInstruction'] = None) -> bool:
		"""
		Visits all leaf operands of this instruction and any sub-instructions.

		:param HighLevelILVisitorCallback cb: Callback function that takes the name of the operand, the operand, operand type, and parent instruction
		:return: True if all instructions were visited, False if the callback returned False
		"""
		for name, op, opType in self.detailed_operands:
			if isinstance(op, HighLevelILInstruction):
				if not op.visit_operands(cb, name, self):
					return False
			elif isinstance(op, list) and all(isinstance(i, HighLevelILInstruction) for i in op):
				for i in op:
					if not i.visit_operands(cb, name, self): # type: ignore
						return False
			elif cb(name, op, opType, self) == False:
				return False
		return True

	@deprecation.deprecated(deprecated_in="4.0.4907", details="Use :py:func:`HighLevelILInstruction.traverse` instead.")
	def visit(self, cb: HighLevelILVisitorCallback,
	       name: str = "root", parent: Optional['HighLevelILInstruction'] = None) -> bool:
		"""
		Visits all HighLevelILInstructions in the operands of this instruction and any sub-instructions.
		In the callback you provide, you likely only need to interact with the second argument (see the example below).

		:param HighLevelILVisitorCallback cb: Callback function that takes the name of the operand, the operand, operand type, and parent instruction
		:return: True if all instructions were visited, False if the callback returned False

		:Example:
			>>> def visitor(_a, inst, _c, _d) -> bool:
			>>>     if isinstance(inst, Constant):
			>>>         print(f"Found constant: {inst.constant}")
			>>>         return False # Stop recursion (once we find a constant, don't recurse in to any sub-instructions (which there won't actually be any...))
			>>>     # Otherwise, keep recursing the subexpressions of this instruction; if no return value is provided, it'll keep descending
			>>>
			>>> # Finds all constants used in the program
			>>> for inst in bv.hlil_instructions:
			>>>     inst.visit(visitor)
		"""
		if cb(name, self, "HighLevelILInstruction", parent) == False:
			return False
		for name, op, _ in self.detailed_operands:
			if isinstance(op, HighLevelILInstruction):
				if not op.visit(cb, name, self):
					return False
			elif isinstance(op, list) and all(isinstance(i, HighLevelILInstruction) for i in op):
				for i in op:
					if not i.visit(cb, name, self): # type: ignore
						return False
		return True

	@property
	def has_side_effects(self) -> bool:
		return core.BNHighLevelILHasSideEffects(self.function.handle, self.expr_index)

	def get_lines(self, settings: Optional['function.DisassemblySettings'] = None) -> LinesType:
		"""
		Gets HLIL text lines with optional settings

		.. note::
			The instruction renders in whichever form it is currently in, so one that is not in AST form renders
			without its nested body and ignores ``DisassemblyOption`` settings acting on nested bodies (such as
			``ShowCollapseIndicators``). Instructions from iterating a function or its basic blocks are not in AST
			form; use :py:func:`ast` or :py:func:`HighLevelILFunction.root`. See `AST and Non-AST Forms
			<https://docs.binary.ninja/dev/bnil-hlil.html#ast-and-non-ast-forms>`_.
		"""
		if settings is not None:
			settings = settings.handle
		count = ctypes.c_ulonglong()
		lines = core.BNGetHighLevelILExprText(self.function.handle, self.expr_index, self.as_ast, count, settings)
		assert lines is not None, "core.BNGetHighLevelILExprText returned None"
		try:
			for i in range(0, count.value):
				addr = lines[i].addr
				if lines[i].instrIndex != 0xffffffffffffffff:
					il_instr = self.function[lines[i].instrIndex]
				else:
					il_instr = None
				color = highlight.HighlightColor._from_core_struct(lines[i].highlight)
				tokens = function.InstructionTextToken._from_core_struct(lines[i].tokens, lines[i].count)
				yield function.DisassemblyTextLine(tokens, addr, il_instr, color)
		finally:
			core.BNFreeDisassemblyTextLines(lines, count.value)

	@property
	def can_collapse(self) -> bool:
		"""If this instruction can be collapsed in rendered lines"""
		return self.operation in [
			HighLevelILOperation.HLIL_IF,
			HighLevelILOperation.HLIL_WHILE,
			HighLevelILOperation.HLIL_WHILE_SSA,
			HighLevelILOperation.HLIL_DO_WHILE,
			HighLevelILOperation.HLIL_DO_WHILE_SSA,
			HighLevelILOperation.HLIL_FOR,
			HighLevelILOperation.HLIL_FOR_SSA,
			HighLevelILOperation.HLIL_SWITCH,
			HighLevelILOperation.HLIL_CASE
		]

	def get_instruction_hash(self, discriminator: int) -> int:
		"""
		Hash of instruction matching the C++ HighLevelILInstruction::GetInstructionHash,
		used for collapsed region matching.
		:param discriminator: Extra value to include in the hash to differentiate regions
		"""

		def rotl(value, shift):
			return ((value << shift) & 0xffffffffffffffff) | (value >> (64 - shift))

		hash = self.operation.value
		hash ^= rotl(self.address, 23)
		hash ^= rotl(discriminator, 47)
		return hash

	@property
	def derived_string_reference(self) -> Optional['binaryview.DerivedString']:
		str = core.BNDerivedString()
		if not core.BNGetHighLevelILDerivedStringReferenceForExpr(self.function.handle, self.expr_index, str):
			return None
		return binaryview.DerivedString._from_core_struct(str, True)


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILUnaryBase(HighLevelILInstruction, UnaryOperation):
	@property
	def src(self) -> HighLevelILInstruction:
		return self._get_expr(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("src", self.src, "HighLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILBinaryBase(HighLevelILInstruction, BinaryOperation):
	@property
	def left(self) -> HighLevelILInstruction:
		return self._get_expr(0)

	@property
	def right(self) -> HighLevelILInstruction:
		return self._get_expr(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("left", self.left, "HighLevelILInstruction"),
			("right", self.right, "HighLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILComparisonBase(HighLevelILBinaryBase, Comparison):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILCarryBase(HighLevelILInstruction, Arithmetic):
	@property
	def left(self) -> HighLevelILInstruction:
		return self._get_expr(0)

	@property
	def right(self) -> HighLevelILInstruction:
		return self._get_expr(1)

	@property
	def carry(self) -> HighLevelILInstruction:
		return self._get_expr(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("left", self.left, "HighLevelILInstruction"),
			("right", self.right, "HighLevelILInstruction"),
			("carry", self.carry, "HighLevelILInstruction"),
		]


class _BlockIteration:
	def __iter__(self) -> Generator['HighLevelILInstruction', None, None]:
		for expr in self.body:
			yield expr


class _DestVarWritten:
	@property
	def vars_written(self) -> VariablesList:
		return [self.dest]


class _ForceVerVars:
	@property
	def vars_written(self) -> VariablesList:
		return [self.dest]


class _AssignVars:
	@property
	def vars_written(self) -> VariablesList:
		if isinstance(self.dest, (HighLevelILSplit, HighLevelILVar, HighLevelILVarSsa)):
			return [*self.dest.vars, *self.src.vars_written]
		elif isinstance(self.dest, HighLevelILStructField):
			return [*self.dest.vars, *self.src.vars_written]
		else:
			return [*self.dest.vars_written, *self.src.vars_written]


class _AssignUnpackVars:
	@property
	def vars_written(self) -> VariablesList:
		result = []
		for i in self.dest:
			if isinstance(i, (HighLevelILVar, HighLevelILVarSsa)):
				result.append(i.var)
			else:
				result.extend(i.vars_written)
		return result


class _AddressOfVars:
	@property
	def vars_address_taken(self) -> VariablesList:
		if isinstance(self.src, (HighLevelILVar, HighLevelILVarSsa)):
			return [self.src.var]
		elif isinstance(self.src, HighLevelILStructField) and isinstance(self.src.src, (HighLevelILVar, HighLevelILVarSsa)):
			return [self.src.src.var]
		return [*self.src.vars_address_taken]


class _ConstPtrString:
	@property
	def string(self) -> Optional[Tuple[str, StringType]]:
		return self.function.view.check_for_string_annotation_type(self.constant, True, True, 0)


# BEGIN GENERATED hlil-classes: from api/il, do not edit
@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILNop(HighLevelILInstruction):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILBlock(_BlockIteration, HighLevelILInstruction):
	@property
	def body(self) -> List[HighLevelILInstruction]:
		return self._get_expr_list(0, 1)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("body", self.body, "List[HighLevelILInstruction]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILIf(HighLevelILInstruction, ControlFlow):
	@property
	def condition(self) -> HighLevelILInstruction:
		return self._get_expr(0)

	@property
	def true(self) -> HighLevelILInstruction:
		return self._get_expr(1)

	@property
	def false(self) -> HighLevelILInstruction:
		return self._get_expr(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("condition", self.condition, "HighLevelILInstruction"),
			("true", self.true, "HighLevelILInstruction"),
			("false", self.false, "HighLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILWhile(HighLevelILInstruction, Loop):
	@property
	def condition(self) -> HighLevelILInstruction:
		return self._get_expr(0)

	@property
	def body(self) -> HighLevelILInstruction:
		return self._get_expr(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("condition", self.condition, "HighLevelILInstruction"),
			("body", self.body, "HighLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILDoWhile(HighLevelILInstruction, Loop):
	@property
	def body(self) -> HighLevelILInstruction:
		return self._get_expr(0)

	@property
	def condition(self) -> HighLevelILInstruction:
		return self._get_expr(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("body", self.body, "HighLevelILInstruction"),
			("condition", self.condition, "HighLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILFor(HighLevelILInstruction, Loop):
	@property
	def init(self) -> HighLevelILInstruction:
		return self._get_expr(0)

	@property
	def condition(self) -> HighLevelILInstruction:
		return self._get_expr(1)

	@property
	def update(self) -> HighLevelILInstruction:
		return self._get_expr(2)

	@property
	def body(self) -> HighLevelILInstruction:
		return self._get_expr(3)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("init", self.init, "HighLevelILInstruction"),
			("condition", self.condition, "HighLevelILInstruction"),
			("update", self.update, "HighLevelILInstruction"),
			("body", self.body, "HighLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILSwitch(HighLevelILInstruction, ControlFlow):
	@property
	def condition(self) -> HighLevelILInstruction:
		return self._get_expr(0)

	@property
	def default(self) -> HighLevelILInstruction:
		return self._get_expr(1)

	@property
	def cases(self) -> List[HighLevelILInstruction]:
		return self._get_expr_list(2, 3)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("condition", self.condition, "HighLevelILInstruction"),
			("default", self.default, "HighLevelILInstruction"),
			("cases", self.cases, "List[HighLevelILInstruction]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILCase(HighLevelILInstruction):
	@property
	def values(self) -> List[HighLevelILInstruction]:
		return self._get_expr_list(0, 1)

	@property
	def body(self) -> HighLevelILInstruction:
		return self._get_expr(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("values", self.values, "List[HighLevelILInstruction]"),
			("body", self.body, "HighLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILBreak(HighLevelILInstruction, Terminal):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILContinue(HighLevelILInstruction, ControlFlow):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILJump(HighLevelILInstruction, Terminal):
	@property
	def dest(self) -> HighLevelILInstruction:
		return self._get_expr(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("dest", self.dest, "HighLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILRet(HighLevelILInstruction, Return):
	@property
	def src(self) -> List[HighLevelILInstruction]:
		return self._get_expr_list(0, 1)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("src", self.src, "List[HighLevelILInstruction]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILNoret(HighLevelILInstruction, Terminal):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILGoto(HighLevelILInstruction, Terminal):
	@property
	def target(self) -> GotoLabel:
		return self._get_label(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("target", self.target, "GotoLabel"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILLabel(HighLevelILInstruction):
	@property
	def target(self) -> GotoLabel:
		return self._get_label(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("target", self.target, "GotoLabel"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILVarDeclare(HighLevelILInstruction):
	@property
	def var(self) -> variable.Variable:
		return self._get_var(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("var", self.var, "Variable"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILVarInit(_DestVarWritten, HighLevelILInstruction, SetVar):
	@property
	def dest(self) -> variable.Variable:
		return self._get_var(0)

	@property
	def src(self) -> HighLevelILInstruction:
		return self._get_expr(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("dest", self.dest, "Variable"),
			("src", self.src, "HighLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILAssign(_AssignVars, HighLevelILInstruction, SetVar):
	@property
	def dest(self) -> HighLevelILInstruction:
		return self._get_expr(0)

	@property
	def src(self) -> HighLevelILInstruction:
		return self._get_expr(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("dest", self.dest, "HighLevelILInstruction"),
			("src", self.src, "HighLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILAssignUnpack(_AssignUnpackVars, HighLevelILInstruction, SetVar):
	@property
	def dest(self) -> List[HighLevelILInstruction]:
		return self._get_expr_list(0, 1)

	@property
	def src(self) -> HighLevelILInstruction:
		return self._get_expr(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("dest", self.dest, "List[HighLevelILInstruction]"),
			("src", self.src, "HighLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILForceVer(_ForceVerVars, HighLevelILInstruction):
	@property
	def dest(self) -> variable.Variable:
		return self._get_var(0)

	@property
	def src(self) -> variable.Variable:
		return self._get_var(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("dest", self.dest, "Variable"),
			("src", self.src, "Variable"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILAssert(HighLevelILInstruction):
	@property
	def src(self) -> variable.Variable:
		return self._get_var(0)

	@property
	def constraint(self) -> variable.PossibleValueSet:
		return self._get_constraint(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("src", self.src, "Variable"),
			("constraint", self.constraint, "PossibleValueSet"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILVar(HighLevelILInstruction, VariableInstruction):
	@property
	def var(self) -> variable.Variable:
		return self._get_var(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("var", self.var, "Variable"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILStructField(HighLevelILInstruction):
	@property
	def src(self) -> HighLevelILInstruction:
		return self._get_expr(0)

	@property
	def offset(self) -> int:
		return self._get_int(1)

	@property
	def member_index(self) -> Optional[int]:
		return self._get_member_index(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("src", self.src, "HighLevelILInstruction"),
			("offset", self.offset, "int"),
			("member_index", self.member_index, "Optional[int]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILArrayIndex(HighLevelILInstruction):
	@property
	def src(self) -> HighLevelILInstruction:
		return self._get_expr(0)

	@property
	def index(self) -> HighLevelILInstruction:
		return self._get_expr(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("src", self.src, "HighLevelILInstruction"),
			("index", self.index, "HighLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILSplit(HighLevelILInstruction):
	@property
	def high(self) -> HighLevelILInstruction:
		return self._get_expr(0)

	@property
	def low(self) -> HighLevelILInstruction:
		return self._get_expr(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("high", self.high, "HighLevelILInstruction"),
			("low", self.low, "HighLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILDeref(HighLevelILUnaryBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILDerefField(HighLevelILInstruction):
	@property
	def src(self) -> HighLevelILInstruction:
		return self._get_expr(0)

	@property
	def offset(self) -> int:
		return self._get_int(1)

	@property
	def member_index(self) -> Optional[int]:
		return self._get_member_index(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("src", self.src, "HighLevelILInstruction"),
			("offset", self.offset, "int"),
			("member_index", self.member_index, "Optional[int]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILAddressOf(_AddressOfVars, HighLevelILUnaryBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILPassByRef(HighLevelILUnaryBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILReturnByRef(HighLevelILUnaryBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILConst(HighLevelILInstruction, Constant):
	@property
	def constant(self) -> int:
		return self._get_int(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("constant", self.constant, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILConstData(HighLevelILInstruction, Constant):
	@property
	def constant_data(self) -> variable.ConstantData:
		return self._get_constant_data(0, 1)

	@property
	def constant(self) -> variable.ConstantData:
		return self.constant_data

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("constant", self.constant, "ConstantData"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILConstPtr(_ConstPtrString, HighLevelILInstruction, Constant):
	@property
	def constant(self) -> int:
		return self._get_int(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("constant", self.constant, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILExternPtr(HighLevelILInstruction, Constant):
	@property
	def constant(self) -> int:
		return self._get_int(0)

	@property
	def offset(self) -> int:
		return self._get_int(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("constant", self.constant, "int"),
			("offset", self.offset, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILFloatConst(HighLevelILInstruction, Constant):
	@property
	def constant(self) -> float:
		return self._get_float(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("constant", self.constant, "float"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILImport(HighLevelILInstruction, Constant):
	@property
	def constant(self) -> int:
		return self._get_int(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("constant", self.constant, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILAdd(HighLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILAdc(HighLevelILCarryBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILSub(HighLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILSbb(HighLevelILCarryBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILAnd(HighLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILOr(HighLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILXor(HighLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILLsl(HighLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILLsr(HighLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILAsr(HighLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILRol(HighLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILRlc(HighLevelILCarryBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILRor(HighLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILRrc(HighLevelILCarryBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILMul(HighLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILMuluDp(HighLevelILBinaryBase, DoublePrecision):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILMulsDp(HighLevelILBinaryBase, Signed, DoublePrecision):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILDivu(HighLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILDivuDp(HighLevelILBinaryBase, DoublePrecision):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILDivs(HighLevelILBinaryBase, Signed):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILDivsDp(HighLevelILBinaryBase, Signed, DoublePrecision):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILModu(HighLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILModuDp(HighLevelILBinaryBase, DoublePrecision):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILMods(HighLevelILBinaryBase, Signed):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILModsDp(HighLevelILBinaryBase, Signed, DoublePrecision):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILNeg(HighLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILNot(HighLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILSx(HighLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILZx(HighLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILLowPart(HighLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILCall(HighLevelILInstruction, Localcall):
	@property
	def dest(self) -> HighLevelILInstruction:
		return self._get_expr(0)

	@property
	def params(self) -> List[HighLevelILInstruction]:
		return self._get_expr_list(1, 2)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("dest", self.dest, "HighLevelILInstruction"),
			("params", self.params, "List[HighLevelILInstruction]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILCmpE(HighLevelILComparisonBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILCmpNe(HighLevelILComparisonBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILCmpSlt(HighLevelILComparisonBase, Signed):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILCmpUlt(HighLevelILComparisonBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILCmpSle(HighLevelILComparisonBase, Signed):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILCmpUle(HighLevelILComparisonBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILCmpSge(HighLevelILComparisonBase, Signed):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILCmpUge(HighLevelILComparisonBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILCmpSgt(HighLevelILComparisonBase, Signed):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILCmpUgt(HighLevelILComparisonBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILTestBit(HighLevelILComparisonBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILBoolToInt(HighLevelILUnaryBase):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILAddOverflow(HighLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILSyscall(HighLevelILInstruction, Syscall):
	@property
	def params(self) -> List[HighLevelILInstruction]:
		return self._get_expr_list(0, 1)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("params", self.params, "List[HighLevelILInstruction]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILTailcall(HighLevelILInstruction, Tailcall):
	@property
	def dest(self) -> HighLevelILInstruction:
		return self._get_expr(0)

	@property
	def params(self) -> List[HighLevelILInstruction]:
		return self._get_expr_list(1, 2)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("dest", self.dest, "HighLevelILInstruction"),
			("params", self.params, "List[HighLevelILInstruction]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILIntrinsic(HighLevelILInstruction, Intrinsic):
	@property
	def intrinsic(self) -> 'lowlevelil.ILIntrinsic':
		return self._get_intrinsic(0)

	@property
	def params(self) -> List[HighLevelILInstruction]:
		return self._get_expr_list(1, 2)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("intrinsic", self.intrinsic, "ILIntrinsic"),
			("params", self.params, "List[HighLevelILInstruction]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILBp(HighLevelILInstruction, Terminal):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILTrap(HighLevelILInstruction, Terminal):
	@property
	def vector(self) -> int:
		return self._get_int(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("vector", self.vector, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILUndef(HighLevelILInstruction, Terminal):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILUnimpl(HighLevelILInstruction):
	@property
	def unknown(self) -> bool:
		return self._get_int(0) != 0


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILUnimplMem(HighLevelILUnaryBase, Memory):
	@property
	def unknown(self) -> bool:
		return self._get_int(1) != 0


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILStructInit(HighLevelILInstruction):
	@property
	def fields(self) -> List[HighLevelILInstruction]:
		return self._get_expr_list(0, 1)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("fields", self.fields, "List[HighLevelILInstruction]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILStructInitField(HighLevelILInstruction):
	@property
	def offset(self) -> int:
		return self._get_int(0)

	@property
	def member_index(self) -> Optional[int]:
		return self._get_member_index(1)

	@property
	def src(self) -> HighLevelILInstruction:
		return self._get_expr(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("offset", self.offset, "int"),
			("member_index", self.member_index, "Optional[int]"),
			("src", self.src, "HighLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILFadd(HighLevelILBinaryBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILFsub(HighLevelILBinaryBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILFmul(HighLevelILBinaryBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILFdiv(HighLevelILBinaryBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILFsqrt(HighLevelILUnaryBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILFneg(HighLevelILUnaryBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILFabs(HighLevelILUnaryBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILFloatToInt(HighLevelILUnaryBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILIntToFloat(HighLevelILUnaryBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILFloatConv(HighLevelILUnaryBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILRoundToInt(HighLevelILUnaryBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILFloor(HighLevelILUnaryBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILCeil(HighLevelILUnaryBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILFtrunc(HighLevelILUnaryBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILFcmpE(HighLevelILComparisonBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILFcmpNe(HighLevelILComparisonBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILFcmpLt(HighLevelILComparisonBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILFcmpLe(HighLevelILComparisonBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILFcmpGe(HighLevelILComparisonBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILFcmpGt(HighLevelILComparisonBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILFcmpO(HighLevelILComparisonBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILFcmpUo(HighLevelILComparisonBase, FloatingPoint):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILUnreachable(HighLevelILInstruction, Terminal):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILWhileSsa(HighLevelILInstruction, Loop, SSA):
	@property
	def condition_phi(self) -> HighLevelILInstruction:
		return self._get_expr(0)

	@property
	def condition(self) -> HighLevelILInstruction:
		return self._get_expr(1)

	@property
	def body(self) -> HighLevelILInstruction:
		return self._get_expr(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("condition_phi", self.condition_phi, "HighLevelILInstruction"),
			("condition", self.condition, "HighLevelILInstruction"),
			("body", self.body, "HighLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILDoWhileSsa(HighLevelILInstruction, Loop, SSA):
	@property
	def body(self) -> HighLevelILInstruction:
		return self._get_expr(0)

	@property
	def condition_phi(self) -> HighLevelILInstruction:
		return self._get_expr(1)

	@property
	def condition(self) -> HighLevelILInstruction:
		return self._get_expr(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("body", self.body, "HighLevelILInstruction"),
			("condition_phi", self.condition_phi, "HighLevelILInstruction"),
			("condition", self.condition, "HighLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILForSsa(HighLevelILInstruction, Loop, SSA):
	@property
	def init(self) -> HighLevelILInstruction:
		return self._get_expr(0)

	@property
	def condition_phi(self) -> HighLevelILInstruction:
		return self._get_expr(1)

	@property
	def condition(self) -> HighLevelILInstruction:
		return self._get_expr(2)

	@property
	def update(self) -> HighLevelILInstruction:
		return self._get_expr(3)

	@property
	def body(self) -> HighLevelILInstruction:
		return self._get_expr(4)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("init", self.init, "HighLevelILInstruction"),
			("condition_phi", self.condition_phi, "HighLevelILInstruction"),
			("condition", self.condition, "HighLevelILInstruction"),
			("update", self.update, "HighLevelILInstruction"),
			("body", self.body, "HighLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILVarInitSsa(_DestVarWritten, HighLevelILInstruction, SetVar, SSA):
	@property
	def dest(self) -> 'mediumlevelil.SSAVariable':
		return self._get_var_ssa(0, 1)

	@property
	def src(self) -> HighLevelILInstruction:
		return self._get_expr(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("dest", self.dest, "SSAVariable"),
			("src", self.src, "HighLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILAssignMemSsa(HighLevelILInstruction, SSA):
	@property
	def dest(self) -> HighLevelILInstruction:
		return self._get_expr(0)

	@property
	def dest_memory(self) -> int:
		return self._get_int(1)

	@property
	def src(self) -> HighLevelILInstruction:
		return self._get_expr(2)

	@property
	def src_memory(self) -> int:
		return self._get_int(3)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("dest", self.dest, "HighLevelILInstruction"),
			("dest_memory", self.dest_memory, "int"),
			("src", self.src, "HighLevelILInstruction"),
			("src_memory", self.src_memory, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILAssignUnpackMemSsa(HighLevelILInstruction, SSA, Memory):
	@property
	def dest(self) -> List[HighLevelILInstruction]:
		return self._get_expr_list(0, 1)

	@property
	def dest_memory(self) -> int:
		return self._get_int(2)

	@property
	def src(self) -> HighLevelILInstruction:
		return self._get_expr(3)

	@property
	def src_memory(self) -> int:
		return self._get_int(4)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("dest", self.dest, "List[HighLevelILInstruction]"),
			("dest_memory", self.dest_memory, "int"),
			("src", self.src, "HighLevelILInstruction"),
			("src_memory", self.src_memory, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILForceVerSsa(_ForceVerVars, HighLevelILInstruction, SSA):
	@property
	def dest(self) -> 'mediumlevelil.SSAVariable':
		return self._get_var_ssa(0, 1)

	@property
	def src(self) -> 'mediumlevelil.SSAVariable':
		return self._get_var_ssa(2, 3)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("dest", self.dest, "SSAVariable"),
			("src", self.src, "SSAVariable"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILAssertSsa(HighLevelILInstruction, SSA):
	@property
	def src(self) -> 'mediumlevelil.SSAVariable':
		return self._get_var_ssa(0, 1)

	@property
	def constraint(self) -> variable.PossibleValueSet:
		return self._get_constraint(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("src", self.src, "SSAVariable"),
			("constraint", self.constraint, "PossibleValueSet"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILVarSsa(HighLevelILInstruction, SSAVariableInstruction):
	@property
	def var(self) -> 'mediumlevelil.SSAVariable':
		return self._get_var_ssa(0, 1)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("var", self.var, "SSAVariable"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILVarSsaPartial(HighLevelILInstruction, SSAVariableInstruction):
	@property
	def dest(self) -> 'mediumlevelil.SSAVariable':
		return self._get_var_ssa(0, 1)

	@property
	def prev(self) -> 'mediumlevelil.SSAVariable':
		return self._get_var_ssa(0, 2)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("dest", self.dest, "SSAVariable"),
			("prev", self.prev, "SSAVariable"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILArrayIndexSsa(HighLevelILInstruction, SSA):
	@property
	def src(self) -> HighLevelILInstruction:
		return self._get_expr(0)

	@property
	def src_memory(self) -> int:
		return self._get_int(1)

	@property
	def index(self) -> HighLevelILInstruction:
		return self._get_expr(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("src", self.src, "HighLevelILInstruction"),
			("src_memory", self.src_memory, "int"),
			("index", self.index, "HighLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILDerefSsa(HighLevelILInstruction, SSA):
	@property
	def src(self) -> HighLevelILInstruction:
		return self._get_expr(0)

	@property
	def src_memory(self) -> int:
		return self._get_int(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("src", self.src, "HighLevelILInstruction"),
			("src_memory", self.src_memory, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILDerefFieldSsa(HighLevelILInstruction, SSA):
	@property
	def src(self) -> HighLevelILInstruction:
		return self._get_expr(0)

	@property
	def src_memory(self) -> int:
		return self._get_int(1)

	@property
	def offset(self) -> int:
		return self._get_int(2)

	@property
	def member_index(self) -> Optional[int]:
		return self._get_member_index(3)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("src", self.src, "HighLevelILInstruction"),
			("src_memory", self.src_memory, "int"),
			("offset", self.offset, "int"),
			("member_index", self.member_index, "Optional[int]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILCallSsa(HighLevelILInstruction, Localcall, SSA):
	@property
	def dest(self) -> HighLevelILInstruction:
		return self._get_expr(0)

	@property
	def params(self) -> List[HighLevelILInstruction]:
		return self._get_expr_list(1, 2)

	@property
	def dest_memory(self) -> int:
		return self._get_int(3)

	@property
	def src_memory(self) -> int:
		return self._get_int(4)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("dest", self.dest, "HighLevelILInstruction"),
			("params", self.params, "List[HighLevelILInstruction]"),
			("dest_memory", self.dest_memory, "int"),
			("src_memory", self.src_memory, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILSyscallSsa(HighLevelILInstruction, Syscall, SSA):
	@property
	def params(self) -> List[HighLevelILInstruction]:
		return self._get_expr_list(0, 1)

	@property
	def dest_memory(self) -> int:
		return self._get_int(2)

	@property
	def src_memory(self) -> int:
		return self._get_int(3)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("params", self.params, "List[HighLevelILInstruction]"),
			("dest_memory", self.dest_memory, "int"),
			("src_memory", self.src_memory, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILIntrinsicSsa(HighLevelILInstruction, SSA):
	@property
	def intrinsic(self) -> 'lowlevelil.ILIntrinsic':
		return self._get_intrinsic(0)

	@property
	def params(self) -> List[HighLevelILInstruction]:
		return self._get_expr_list(1, 2)

	@property
	def dest_memory(self) -> int:
		return self._get_int(3)

	@property
	def src_memory(self) -> int:
		return self._get_int(4)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("intrinsic", self.intrinsic, "ILIntrinsic"),
			("params", self.params, "List[HighLevelILInstruction]"),
			("dest_memory", self.dest_memory, "int"),
			("src_memory", self.src_memory, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILVarPhi(_DestVarWritten, HighLevelILInstruction, Phi, SetVar):
	@property
	def dest(self) -> 'mediumlevelil.SSAVariable':
		return self._get_var_ssa(0, 1)

	@property
	def src(self) -> List['mediumlevelil.SSAVariable']:
		return self._get_var_ssa_list(2, 3)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("dest", self.dest, "SSAVariable"),
			("src", self.src, "List[SSAVariable]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILMemPhi(HighLevelILInstruction, Memory, Phi):
	@property
	def dest(self) -> int:
		return self._get_int(0)

	@property
	def src(self) -> List[int]:
		return self._get_int_list(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("dest", self.dest, "int"),
			("src", self.src, "List[int]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILBswap(HighLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILPopcnt(HighLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILClz(HighLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILCtz(HighLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILRbit(HighLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILCls(HighLevelILUnaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILMins(HighLevelILBinaryBase, Arithmetic, Signed):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILMaxs(HighLevelILBinaryBase, Arithmetic, Signed):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILMinu(HighLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILMaxu(HighLevelILBinaryBase, Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILAbs(HighLevelILUnaryBase, Arithmetic):
	pass


ILInstruction: Dict[HighLevelILOperation, type[HighLevelILInstruction]] = {
	HighLevelILOperation.HLIL_NOP: HighLevelILNop,
	HighLevelILOperation.HLIL_BLOCK: HighLevelILBlock,
	HighLevelILOperation.HLIL_IF: HighLevelILIf,
	HighLevelILOperation.HLIL_WHILE: HighLevelILWhile,
	HighLevelILOperation.HLIL_DO_WHILE: HighLevelILDoWhile,
	HighLevelILOperation.HLIL_FOR: HighLevelILFor,
	HighLevelILOperation.HLIL_SWITCH: HighLevelILSwitch,
	HighLevelILOperation.HLIL_CASE: HighLevelILCase,
	HighLevelILOperation.HLIL_BREAK: HighLevelILBreak,
	HighLevelILOperation.HLIL_CONTINUE: HighLevelILContinue,
	HighLevelILOperation.HLIL_JUMP: HighLevelILJump,
	HighLevelILOperation.HLIL_RET: HighLevelILRet,
	HighLevelILOperation.HLIL_NORET: HighLevelILNoret,
	HighLevelILOperation.HLIL_GOTO: HighLevelILGoto,
	HighLevelILOperation.HLIL_LABEL: HighLevelILLabel,
	HighLevelILOperation.HLIL_VAR_DECLARE: HighLevelILVarDeclare,
	HighLevelILOperation.HLIL_VAR_INIT: HighLevelILVarInit,
	HighLevelILOperation.HLIL_ASSIGN: HighLevelILAssign,
	HighLevelILOperation.HLIL_ASSIGN_UNPACK: HighLevelILAssignUnpack,
	HighLevelILOperation.HLIL_FORCE_VER: HighLevelILForceVer,
	HighLevelILOperation.HLIL_ASSERT: HighLevelILAssert,
	HighLevelILOperation.HLIL_VAR: HighLevelILVar,
	HighLevelILOperation.HLIL_STRUCT_FIELD: HighLevelILStructField,
	HighLevelILOperation.HLIL_ARRAY_INDEX: HighLevelILArrayIndex,
	HighLevelILOperation.HLIL_SPLIT: HighLevelILSplit,
	HighLevelILOperation.HLIL_DEREF: HighLevelILDeref,
	HighLevelILOperation.HLIL_DEREF_FIELD: HighLevelILDerefField,
	HighLevelILOperation.HLIL_ADDRESS_OF: HighLevelILAddressOf,
	HighLevelILOperation.HLIL_PASS_BY_REF: HighLevelILPassByRef,
	HighLevelILOperation.HLIL_RETURN_BY_REF: HighLevelILReturnByRef,
	HighLevelILOperation.HLIL_CONST: HighLevelILConst,
	HighLevelILOperation.HLIL_CONST_DATA: HighLevelILConstData,
	HighLevelILOperation.HLIL_CONST_PTR: HighLevelILConstPtr,
	HighLevelILOperation.HLIL_EXTERN_PTR: HighLevelILExternPtr,
	HighLevelILOperation.HLIL_FLOAT_CONST: HighLevelILFloatConst,
	HighLevelILOperation.HLIL_IMPORT: HighLevelILImport,
	HighLevelILOperation.HLIL_ADD: HighLevelILAdd,
	HighLevelILOperation.HLIL_ADC: HighLevelILAdc,
	HighLevelILOperation.HLIL_SUB: HighLevelILSub,
	HighLevelILOperation.HLIL_SBB: HighLevelILSbb,
	HighLevelILOperation.HLIL_AND: HighLevelILAnd,
	HighLevelILOperation.HLIL_OR: HighLevelILOr,
	HighLevelILOperation.HLIL_XOR: HighLevelILXor,
	HighLevelILOperation.HLIL_LSL: HighLevelILLsl,
	HighLevelILOperation.HLIL_LSR: HighLevelILLsr,
	HighLevelILOperation.HLIL_ASR: HighLevelILAsr,
	HighLevelILOperation.HLIL_ROL: HighLevelILRol,
	HighLevelILOperation.HLIL_RLC: HighLevelILRlc,
	HighLevelILOperation.HLIL_ROR: HighLevelILRor,
	HighLevelILOperation.HLIL_RRC: HighLevelILRrc,
	HighLevelILOperation.HLIL_MUL: HighLevelILMul,
	HighLevelILOperation.HLIL_MULU_DP: HighLevelILMuluDp,
	HighLevelILOperation.HLIL_MULS_DP: HighLevelILMulsDp,
	HighLevelILOperation.HLIL_DIVU: HighLevelILDivu,
	HighLevelILOperation.HLIL_DIVU_DP: HighLevelILDivuDp,
	HighLevelILOperation.HLIL_DIVS: HighLevelILDivs,
	HighLevelILOperation.HLIL_DIVS_DP: HighLevelILDivsDp,
	HighLevelILOperation.HLIL_MODU: HighLevelILModu,
	HighLevelILOperation.HLIL_MODU_DP: HighLevelILModuDp,
	HighLevelILOperation.HLIL_MODS: HighLevelILMods,
	HighLevelILOperation.HLIL_MODS_DP: HighLevelILModsDp,
	HighLevelILOperation.HLIL_NEG: HighLevelILNeg,
	HighLevelILOperation.HLIL_NOT: HighLevelILNot,
	HighLevelILOperation.HLIL_SX: HighLevelILSx,
	HighLevelILOperation.HLIL_ZX: HighLevelILZx,
	HighLevelILOperation.HLIL_LOW_PART: HighLevelILLowPart,
	HighLevelILOperation.HLIL_CALL: HighLevelILCall,
	HighLevelILOperation.HLIL_CMP_E: HighLevelILCmpE,
	HighLevelILOperation.HLIL_CMP_NE: HighLevelILCmpNe,
	HighLevelILOperation.HLIL_CMP_SLT: HighLevelILCmpSlt,
	HighLevelILOperation.HLIL_CMP_ULT: HighLevelILCmpUlt,
	HighLevelILOperation.HLIL_CMP_SLE: HighLevelILCmpSle,
	HighLevelILOperation.HLIL_CMP_ULE: HighLevelILCmpUle,
	HighLevelILOperation.HLIL_CMP_SGE: HighLevelILCmpSge,
	HighLevelILOperation.HLIL_CMP_UGE: HighLevelILCmpUge,
	HighLevelILOperation.HLIL_CMP_SGT: HighLevelILCmpSgt,
	HighLevelILOperation.HLIL_CMP_UGT: HighLevelILCmpUgt,
	HighLevelILOperation.HLIL_TEST_BIT: HighLevelILTestBit,
	HighLevelILOperation.HLIL_BOOL_TO_INT: HighLevelILBoolToInt,
	HighLevelILOperation.HLIL_ADD_OVERFLOW: HighLevelILAddOverflow,
	HighLevelILOperation.HLIL_SYSCALL: HighLevelILSyscall,
	HighLevelILOperation.HLIL_TAILCALL: HighLevelILTailcall,
	HighLevelILOperation.HLIL_INTRINSIC: HighLevelILIntrinsic,
	HighLevelILOperation.HLIL_BP: HighLevelILBp,
	HighLevelILOperation.HLIL_TRAP: HighLevelILTrap,
	HighLevelILOperation.HLIL_UNDEF: HighLevelILUndef,
	HighLevelILOperation.HLIL_UNIMPL: HighLevelILUnimpl,
	HighLevelILOperation.HLIL_UNIMPL_MEM: HighLevelILUnimplMem,
	HighLevelILOperation.HLIL_STRUCT_INIT: HighLevelILStructInit,
	HighLevelILOperation.HLIL_STRUCT_INIT_FIELD: HighLevelILStructInitField,
	HighLevelILOperation.HLIL_FADD: HighLevelILFadd,
	HighLevelILOperation.HLIL_FSUB: HighLevelILFsub,
	HighLevelILOperation.HLIL_FMUL: HighLevelILFmul,
	HighLevelILOperation.HLIL_FDIV: HighLevelILFdiv,
	HighLevelILOperation.HLIL_FSQRT: HighLevelILFsqrt,
	HighLevelILOperation.HLIL_FNEG: HighLevelILFneg,
	HighLevelILOperation.HLIL_FABS: HighLevelILFabs,
	HighLevelILOperation.HLIL_FLOAT_TO_INT: HighLevelILFloatToInt,
	HighLevelILOperation.HLIL_INT_TO_FLOAT: HighLevelILIntToFloat,
	HighLevelILOperation.HLIL_FLOAT_CONV: HighLevelILFloatConv,
	HighLevelILOperation.HLIL_ROUND_TO_INT: HighLevelILRoundToInt,
	HighLevelILOperation.HLIL_FLOOR: HighLevelILFloor,
	HighLevelILOperation.HLIL_CEIL: HighLevelILCeil,
	HighLevelILOperation.HLIL_FTRUNC: HighLevelILFtrunc,
	HighLevelILOperation.HLIL_FCMP_E: HighLevelILFcmpE,
	HighLevelILOperation.HLIL_FCMP_NE: HighLevelILFcmpNe,
	HighLevelILOperation.HLIL_FCMP_LT: HighLevelILFcmpLt,
	HighLevelILOperation.HLIL_FCMP_LE: HighLevelILFcmpLe,
	HighLevelILOperation.HLIL_FCMP_GE: HighLevelILFcmpGe,
	HighLevelILOperation.HLIL_FCMP_GT: HighLevelILFcmpGt,
	HighLevelILOperation.HLIL_FCMP_O: HighLevelILFcmpO,
	HighLevelILOperation.HLIL_FCMP_UO: HighLevelILFcmpUo,
	HighLevelILOperation.HLIL_UNREACHABLE: HighLevelILUnreachable,
	HighLevelILOperation.HLIL_WHILE_SSA: HighLevelILWhileSsa,
	HighLevelILOperation.HLIL_DO_WHILE_SSA: HighLevelILDoWhileSsa,
	HighLevelILOperation.HLIL_FOR_SSA: HighLevelILForSsa,
	HighLevelILOperation.HLIL_VAR_INIT_SSA: HighLevelILVarInitSsa,
	HighLevelILOperation.HLIL_ASSIGN_MEM_SSA: HighLevelILAssignMemSsa,
	HighLevelILOperation.HLIL_ASSIGN_UNPACK_MEM_SSA: HighLevelILAssignUnpackMemSsa,
	HighLevelILOperation.HLIL_FORCE_VER_SSA: HighLevelILForceVerSsa,
	HighLevelILOperation.HLIL_ASSERT_SSA: HighLevelILAssertSsa,
	HighLevelILOperation.HLIL_VAR_SSA: HighLevelILVarSsa,
	HighLevelILOperation.HLIL_VAR_SSA_PARTIAL: HighLevelILVarSsaPartial,
	HighLevelILOperation.HLIL_ARRAY_INDEX_SSA: HighLevelILArrayIndexSsa,
	HighLevelILOperation.HLIL_DEREF_SSA: HighLevelILDerefSsa,
	HighLevelILOperation.HLIL_DEREF_FIELD_SSA: HighLevelILDerefFieldSsa,
	HighLevelILOperation.HLIL_CALL_SSA: HighLevelILCallSsa,
	HighLevelILOperation.HLIL_SYSCALL_SSA: HighLevelILSyscallSsa,
	HighLevelILOperation.HLIL_INTRINSIC_SSA: HighLevelILIntrinsicSsa,
	HighLevelILOperation.HLIL_VAR_PHI: HighLevelILVarPhi,
	HighLevelILOperation.HLIL_MEM_PHI: HighLevelILMemPhi,
	HighLevelILOperation.HLIL_BSWAP: HighLevelILBswap,
	HighLevelILOperation.HLIL_POPCNT: HighLevelILPopcnt,
	HighLevelILOperation.HLIL_CLZ: HighLevelILClz,
	HighLevelILOperation.HLIL_CTZ: HighLevelILCtz,
	HighLevelILOperation.HLIL_RBIT: HighLevelILRbit,
	HighLevelILOperation.HLIL_CLS: HighLevelILCls,
	HighLevelILOperation.HLIL_MINS: HighLevelILMins,
	HighLevelILOperation.HLIL_MAXS: HighLevelILMaxs,
	HighLevelILOperation.HLIL_MINU: HighLevelILMinu,
	HighLevelILOperation.HLIL_MAXU: HighLevelILMaxu,
	HighLevelILOperation.HLIL_ABS: HighLevelILAbs,
}


# Lists the slots `copy_expr_to` copies for each op.
_COPY_LAYOUTS: Dict[HighLevelILOperation, Tuple] = {
	HighLevelILOperation.HLIL_NOP: (),
	HighLevelILOperation.HLIL_BLOCK: ("expr_list",),
	HighLevelILOperation.HLIL_IF: (
		"expr",
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_WHILE: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_DO_WHILE: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_FOR: (
		"expr",
		"expr",
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_SWITCH: (
		"expr",
		"expr",
		"expr_list",
	),
	HighLevelILOperation.HLIL_CASE: (
		"expr_list",
		"expr",
	),
	HighLevelILOperation.HLIL_BREAK: (),
	HighLevelILOperation.HLIL_CONTINUE: (),
	HighLevelILOperation.HLIL_JUMP: ("expr",),
	HighLevelILOperation.HLIL_RET: ("expr_list",),
	HighLevelILOperation.HLIL_NORET: (),
	HighLevelILOperation.HLIL_GOTO: ("value",),
	HighLevelILOperation.HLIL_LABEL: ("value",),
	HighLevelILOperation.HLIL_VAR_DECLARE: ("value",),
	HighLevelILOperation.HLIL_VAR_INIT: (
		"value",
		"expr",
	),
	HighLevelILOperation.HLIL_ASSIGN: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_ASSIGN_UNPACK: (
		"expr_list",
		"expr",
	),
	HighLevelILOperation.HLIL_FORCE_VER: (
		"value",
		"value",
	),
	HighLevelILOperation.HLIL_ASSERT: (
		"value",
		"constraint",
	),
	HighLevelILOperation.HLIL_VAR: ("value",),
	HighLevelILOperation.HLIL_STRUCT_FIELD: (
		"expr",
		"value",
		"value",
	),
	HighLevelILOperation.HLIL_ARRAY_INDEX: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_SPLIT: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_DEREF: ("expr",),
	HighLevelILOperation.HLIL_DEREF_FIELD: (
		"expr",
		"value",
		"value",
	),
	HighLevelILOperation.HLIL_ADDRESS_OF: ("expr",),
	HighLevelILOperation.HLIL_PASS_BY_REF: ("expr",),
	HighLevelILOperation.HLIL_RETURN_BY_REF: ("expr",),
	HighLevelILOperation.HLIL_CONST: ("value",),
	HighLevelILOperation.HLIL_CONST_DATA: (
		"value",
		"value",
	),
	HighLevelILOperation.HLIL_CONST_PTR: ("value",),
	HighLevelILOperation.HLIL_EXTERN_PTR: (
		"value",
		"value",
	),
	HighLevelILOperation.HLIL_FLOAT_CONST: ("value",),
	HighLevelILOperation.HLIL_IMPORT: ("value",),
	HighLevelILOperation.HLIL_ADD: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_ADC: (
		"expr",
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_SUB: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_SBB: (
		"expr",
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_AND: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_OR: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_XOR: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_LSL: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_LSR: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_ASR: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_ROL: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_RLC: (
		"expr",
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_ROR: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_RRC: (
		"expr",
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_MUL: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_MULU_DP: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_MULS_DP: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_DIVU: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_DIVU_DP: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_DIVS: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_DIVS_DP: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_MODU: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_MODU_DP: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_MODS: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_MODS_DP: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_NEG: ("expr",),
	HighLevelILOperation.HLIL_NOT: ("expr",),
	HighLevelILOperation.HLIL_SX: ("expr",),
	HighLevelILOperation.HLIL_ZX: ("expr",),
	HighLevelILOperation.HLIL_LOW_PART: ("expr",),
	HighLevelILOperation.HLIL_CALL: (
		"expr",
		"expr_list",
	),
	HighLevelILOperation.HLIL_CMP_E: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_CMP_NE: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_CMP_SLT: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_CMP_ULT: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_CMP_SLE: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_CMP_ULE: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_CMP_SGE: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_CMP_UGE: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_CMP_SGT: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_CMP_UGT: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_TEST_BIT: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_BOOL_TO_INT: ("expr",),
	HighLevelILOperation.HLIL_ADD_OVERFLOW: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_SYSCALL: ("expr_list",),
	HighLevelILOperation.HLIL_TAILCALL: (
		"expr",
		"expr_list",
	),
	HighLevelILOperation.HLIL_INTRINSIC: (
		"value",
		"expr_list",
	),
	HighLevelILOperation.HLIL_BP: (),
	HighLevelILOperation.HLIL_TRAP: ("value",),
	HighLevelILOperation.HLIL_UNDEF: (),
	HighLevelILOperation.HLIL_UNIMPL: ("value",),
	HighLevelILOperation.HLIL_UNIMPL_MEM: (
		"expr",
		"value",
	),
	HighLevelILOperation.HLIL_STRUCT_INIT: ("expr_list",),
	HighLevelILOperation.HLIL_STRUCT_INIT_FIELD: (
		"value",
		"value",
		"expr",
	),
	HighLevelILOperation.HLIL_FADD: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_FSUB: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_FMUL: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_FDIV: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_FSQRT: ("expr",),
	HighLevelILOperation.HLIL_FNEG: ("expr",),
	HighLevelILOperation.HLIL_FABS: ("expr",),
	HighLevelILOperation.HLIL_FLOAT_TO_INT: ("expr",),
	HighLevelILOperation.HLIL_INT_TO_FLOAT: ("expr",),
	HighLevelILOperation.HLIL_FLOAT_CONV: ("expr",),
	HighLevelILOperation.HLIL_ROUND_TO_INT: ("expr",),
	HighLevelILOperation.HLIL_FLOOR: ("expr",),
	HighLevelILOperation.HLIL_CEIL: ("expr",),
	HighLevelILOperation.HLIL_FTRUNC: ("expr",),
	HighLevelILOperation.HLIL_FCMP_E: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_FCMP_NE: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_FCMP_LT: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_FCMP_LE: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_FCMP_GE: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_FCMP_GT: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_FCMP_O: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_FCMP_UO: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_UNREACHABLE: (),
	HighLevelILOperation.HLIL_WHILE_SSA: (
		"expr",
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_DO_WHILE_SSA: (
		"expr",
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_FOR_SSA: (
		"expr",
		"expr",
		"expr",
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_VAR_INIT_SSA: (
		"value",
		"value",
		"expr",
	),
	HighLevelILOperation.HLIL_ASSIGN_MEM_SSA: (
		"expr",
		"value",
		"expr",
		"value",
	),
	HighLevelILOperation.HLIL_ASSIGN_UNPACK_MEM_SSA: (
		"expr_list",
		"value",
		"expr",
		"value",
	),
	HighLevelILOperation.HLIL_FORCE_VER_SSA: (
		"value",
		"value",
		"value",
		"value",
	),
	HighLevelILOperation.HLIL_ASSERT_SSA: (
		"value",
		"value",
		"constraint",
	),
	HighLevelILOperation.HLIL_VAR_SSA: (
		"value",
		"value",
	),
	HighLevelILOperation.HLIL_VAR_SSA_PARTIAL: (
		"value",
		"value",
		"value",
	),
	HighLevelILOperation.HLIL_ARRAY_INDEX_SSA: (
		"expr",
		"value",
		"expr",
	),
	HighLevelILOperation.HLIL_DEREF_SSA: (
		"expr",
		"value",
	),
	HighLevelILOperation.HLIL_DEREF_FIELD_SSA: (
		"expr",
		"value",
		"value",
		"value",
	),
	HighLevelILOperation.HLIL_CALL_SSA: (
		"expr",
		"expr_list",
		"value",
		"value",
	),
	HighLevelILOperation.HLIL_SYSCALL_SSA: (
		"expr_list",
		"value",
		"value",
	),
	HighLevelILOperation.HLIL_INTRINSIC_SSA: (
		"value",
		"expr_list",
		"value",
		"value",
	),
	HighLevelILOperation.HLIL_VAR_PHI: (
		"value",
		"value",
		"list",
	),
	HighLevelILOperation.HLIL_MEM_PHI: (
		"value",
		"list",
	),
	HighLevelILOperation.HLIL_BSWAP: ("expr",),
	HighLevelILOperation.HLIL_POPCNT: ("expr",),
	HighLevelILOperation.HLIL_CLZ: ("expr",),
	HighLevelILOperation.HLIL_CTZ: ("expr",),
	HighLevelILOperation.HLIL_RBIT: ("expr",),
	HighLevelILOperation.HLIL_CLS: ("expr",),
	HighLevelILOperation.HLIL_MINS: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_MAXS: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_MINU: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_MAXU: (
		"expr",
		"expr",
	),
	HighLevelILOperation.HLIL_ABS: ("expr",),
}
# END GENERATED hlil-classes


class HighLevelILFunction:
	"""
	``class HighLevelILFunction`` contains the a HighLevelILInstruction object that makes up the abstract syntax tree of
	a function.
	"""
	def __init__(
	    self, arch: Optional['architecture.Architecture'] = None, handle: Optional[core.BNHighLevelILFunction] = None,
	    source_func: Optional['function.Function'] = None
	):
		self._arch = arch
		self._source_function = source_func
		if handle is not None:
			HLILHandle = ctypes.POINTER(core.BNHighLevelILFunction)
			_handle = ctypes.cast(handle, HLILHandle)
			if self._source_function is None:
				self._source_function = function.Function(handle=core.BNGetHighLevelILOwnerFunction(_handle))
			if self._arch is None:
				self._arch = self._source_function.arch
		else:
			if self._source_function is None:
				raise ValueError("IL functions must be created with an associated function")
			if self._arch is None:
				self._arch = self._source_function.arch
				if self._arch is None:
					raise ValueError("IL functions must be created with an associated Architecture")
			func_handle = self._source_function.handle
			_handle = core.BNCreateHighLevelILFunction(self._arch.handle, func_handle)
		assert self._source_function is not None
		assert self._arch is not None
		assert _handle is not None
		self.handle = _handle

	def __del__(self):
		if core is not None:
			core.BNFreeHighLevelILFunction(self.handle)

	def __repr__(self):
		arch = self.source_function.arch
		form = ""
		if self.il_form == FunctionGraphType.HighLevelILSSAFormFunctionGraph:
			form += " ssa form"
		if arch:
			return f"<HighLevelILFunction{form}: {arch.name}@{self.source_function.start:#x}>"
		else:
			return f"<HighLevelILFunction{form}: {self.source_function.start:#x}>"

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(other.handle.contents)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash(('HLIL', self._source_function))

	def __len__(self):
		return int(core.BNGetHighLevelILInstructionCount(self.handle))

	def __getitem__(self, i: int) -> HighLevelILInstruction:
		if isinstance(i, slice) or isinstance(i, tuple):
			raise IndexError("expected integer index")
		if i < -len(self) or i >= len(self):
			raise IndexError("index out of range")
		if i < 0:
			i = len(self) + i
		return HighLevelILInstruction.create(
		    self, ExpressionIndex(core.BNGetHighLevelILIndexForInstruction(self.handle, i)), False, InstructionIndex(i)
		)

	def __setitem__(self, i, j):
		raise IndexError("instruction modification not implemented")

	def __iter__(self) -> Generator['HighLevelILBasicBlock', None, None]:
		count = ctypes.c_ulonglong()
		blocks = core.BNGetHighLevelILBasicBlockList(self.handle, count)
		assert blocks is not None, "core.BNGetHighLevelILBasicBlockList returned None"
		view = None
		if self._source_function is not None:
			view = self._source_function.view
		try:
			for i in range(0, count.value):
				core_block = core.BNNewBasicBlockReference(blocks[i])
				assert core_block is not None, "core.BNNewBasicBlockReference returned None"
				yield HighLevelILBasicBlock(core_block, self, view)
		finally:
			core.BNFreeBasicBlockList(blocks, count.value)

	def __str__(self) -> str:
		return str(self.root)

	@property
	def current_address(self) -> int:
		"""Current IL Address (read/write)"""
		return core.BNHighLevelILGetCurrentAddress(self.handle)

	@current_address.setter
	def current_address(self, value: int) -> None:
		core.BNHighLevelILSetCurrentAddress(self.handle, self.arch.handle, value)

	def set_current_address(self, value: int, arch: Optional['architecture.Architecture'] = None) -> None:
		if arch is None:
			arch = self.arch
		core.BNHighLevelILSetCurrentAddress(self.handle, arch.handle, value)

	@property
	def root(self) -> Optional[HighLevelILInstruction]:
		"""
		Root of the abstract syntax tree

		This is the AST form shown in linear view, where nested bodies are children of the statement containing them.
		:py:func:`instructions` and the function's basic blocks yield non-AST instructions instead. See `AST and
		Non-AST Forms <https://docs.binary.ninja/dev/bnil-hlil.html#ast-and-non-ast-forms>`_.
		"""
		expr_index = core.BNGetHighLevelILRootExpr(self.handle)
		if expr_index >= core.BNGetHighLevelILExprCount(self.handle):
			return None
		return HighLevelILInstruction.create(self, ExpressionIndex(expr_index))

	@root.setter
	def root(self, value: HighLevelILInstruction) -> None:
		core.BNSetHighLevelILRootExpr(self.handle, value.expr_index)

	def _basic_block_list(self):
		count = ctypes.c_ulonglong()
		blocks = core.BNGetHighLevelILBasicBlockList(self.handle, count)
		assert blocks is not None, "core.BNGetHighLevelILBasicBlockList returned None"
		return count, blocks

	def _instantiate_block(self, handle):
		return HighLevelILBasicBlock(handle, self, self.view)

	@property
	def basic_blocks(self) -> 'function.HighLevelILBasicBlockList':
		return function.HighLevelILBasicBlockList(self)

	def get_basic_block_at(self, index: int) -> Optional['HighLevelILBasicBlock']:
		"""
		``get_basic_block_at`` returns the BasicBlock at the given HLIL instruction ``index``.

		:param int index: Index of the HLIL instruction of the BasicBlock to retrieve.
		:Example:
			>>> current_il_function.get_basic_block_at(current_il_index)
			<llil block: x86@19-26>
		"""
		block = core.BNGetHighLevelILBasicBlockForInstruction(self.handle, index)
		if not block:
			return None

		view = None
		if self._source_function is not None:
			view = self._source_function.view

		return HighLevelILBasicBlock(block, self, view)

	def traverse(self, cb: Callable[['HighLevelILInstruction', Any], Any], *args: Any, **kwargs: Any) -> Iterator[Any]:
		"""
		``traverse`` iterates through all the instructions in the HighLevelILFunction and calls the callback function for
		each instruction and sub-instruction. See the `Developer Docs <https://docs.binary.ninja/dev/concepts.html#walking-ils>`_ for more examples.

		:param Callable[[HighLevelILInstruction, Any], Any] cb: The callback function to call for each node in the HighLevelILInstruction
		:param Any args: Custom user-defined arguments
		:param Any kwargs: Custom user-defined keyword arguments
		:return: An iterator of the results of the callback function
		:rtype: Iterator[Any]

		:Example:
			>>> # find all calls to memcpy where the third parameter is not a constant
			>>> def find_non_constant_memcpy(i, target) -> HighLevelILInstruction:
			... 	match i:
			... 		case Localcall(dest=Constant(constant=c), params=[_, _, p]) if c == target and not isinstance(p, Constant):
			... 			return i
			>>> target_address = bv.get_symbol_by_raw_name('_memcpy').address
			>>> for result in current_il_function.traverse(find_non_constant_memcpy, target_address):
			... 	print(f"Found suspicious memcpy: {repr(i)}")
		"""
		root = self.root
		if root is None:
			raise ValueError("HighLevelILFunction has no root")
		if not isinstance(root, HighLevelILBlock):
			root = [root]
		for instr in root:
			yield from instr.traverse(cb, *args, shallow=False, **kwargs)

	@deprecation.deprecated(deprecated_in="4.0.4907", details="Use :py:func:`HighLevelILFunction.traverse` instead.")
	def visit(self, cb: HighLevelILVisitorCallback) -> bool:
		"""
		Iterates over all the instructions in the function and calls the callback function
		for each instruction and each sub-instruction.

		:param HighLevelILVisitorCallback cb: Callback function that takes the name of the operand, the operand, operand type, and parent instruction
		:return: True if all instructions were visited, False if the callback function returned False.
		"""
		for instr in self.instructions:
			if not instr.visit(cb):
				return False
		return True

	@deprecation.deprecated(deprecated_in="4.0.4907", details="Use :py:func:`HighLevelILFunction.traverse` instead.")
	def visit_all(self, cb: HighLevelILVisitorCallback) -> bool:
		"""
		Iterates over all the instructions in the function and calls the callback function for each instruction and their operands.

		:param HighLevelILVisitorCallback cb: Callback function that takes the name of the operand, the operand, operand type, and parent instruction
		:return: True if all instructions were visited, False if the callback function returned False.
		"""
		for instr in self.instructions:
			if not instr.visit_all(cb):
				return False
		return True

	@deprecation.deprecated(deprecated_in="4.0.4907", details="Use :py:func:`HighLevelILFunction.traverse` instead.")
	def visit_operands(self, cb: HighLevelILVisitorCallback) -> bool:
		"""
		Iterates over all the instructions in the function and calls the callback function for each operand and
		 the operands of each sub-instruction.

		:param HighLevelILVisitorCallback cb: Callback function that takes the name of the operand, the operand, operand type, and parent instruction
		:return: True if all instructions were visited, False if the callback function returned False.
		"""
		for instr in self.instructions:
			if not instr.visit_operands(cb):
				return False
		return True

	@property
	def instructions(self) -> Generator[HighLevelILInstruction, None, None]:
		"""
		A generator of hlil instructions of the current function

		These instructions are not in AST form; nested bodies are not children of the statements containing them. Use
		:py:func:`root` for the AST form shown in linear view. See `AST and Non-AST Forms
		<https://docs.binary.ninja/dev/bnil-hlil.html#ast-and-non-ast-forms>`_.
		"""
		for block in self.basic_blocks:
			yield from block

	@property
	def ssa_form(self) -> 'HighLevelILFunction':
		"""High level IL in SSA form (read-only)"""
		result = core.BNGetHighLevelILSSAForm(self.handle)
		assert result is not None, "core.BNGetHighLevelILSSAForm returned None"
		return HighLevelILFunction(self._arch, result, self._source_function)

	@property
	def non_ssa_form(self) -> Optional['HighLevelILFunction']:
		"""High level IL in non-SSA (default) form (read-only)"""
		result = core.BNGetHighLevelILNonSSAForm(self.handle)
		if not result:
			return None
		return HighLevelILFunction(self._arch, result, self._source_function)

	@property
	def arch(self) -> 'architecture.Architecture':
		assert self._arch is not None
		return self._arch

	@property
	def view(self) -> 'binaryview.BinaryView':
		return self.source_function.view

	@property
	def source_function(self) -> 'function.Function':
		assert self._source_function is not None
		return self._source_function

	@source_function.setter
	def source_function(self, value: 'function.Function') -> None:
		self._source_function = value

	@property
	def medium_level_il(self) -> Optional['mediumlevelil.MediumLevelILFunction']:
		"""Medium level IL for this function"""
		result = core.BNGetMediumLevelILForHighLevelILFunction(self.handle)
		if not result:
			return None
		return mediumlevelil.MediumLevelILFunction(self._arch, result, self._source_function)

	@property
	def mlil(self) -> Optional['mediumlevelil.MediumLevelILFunction']:
		"""Alias for medium_level_il"""
		return self.medium_level_il

	def get_ssa_instruction_index(self, instr: int) -> int:
		return core.BNGetHighLevelILSSAInstructionIndex(self.handle, instr)

	def get_non_ssa_instruction_index(self, instr: int) -> int:
		return core.BNGetHighLevelILNonSSAInstructionIndex(self.handle, instr)

	def get_ssa_var_definition(self, ssa_var: Union['mediumlevelil.SSAVariable', HighLevelILVarSsa]) -> Optional[HighLevelILInstruction]:
		"""
		Gets the instruction that contains the given SSA variable's definition.

		Since SSA variables can only be defined once, this will return the single instruction where that occurs.
		For SSA variable version 0s, which don't have definitions, this will return None instead.
		"""
		if isinstance(ssa_var, HighLevelILVarSsa):
			ssa_var = ssa_var.var
		if not isinstance(ssa_var, mediumlevelil.SSAVariable):
			raise ValueError("Expected SSAVariable")
		var_data = ssa_var.var.to_BNVariable()
		result = core.BNGetHighLevelILSSAVarDefinition(self.handle, var_data, ssa_var.version)
		if result >= core.BNGetHighLevelILExprCount(self.handle):
			return None
		return HighLevelILInstruction.create(self, ExpressionIndex(result))

	def get_ssa_memory_definition(self, version: int) -> Optional[HighLevelILInstruction]:
		result = core.BNGetHighLevelILSSAMemoryDefinition(self.handle, version)
		if result >= core.BNGetHighLevelILExprCount(self.handle):
			return None
		return HighLevelILInstruction.create(self, ExpressionIndex(result))

	def get_ssa_var_uses(self, ssa_var: Union['mediumlevelil.SSAVariable', HighLevelILVarSsa]) -> List[HighLevelILInstruction]:
		"""
		Gets all the instructions that use the given SSA variable.
		"""
		if isinstance(ssa_var, HighLevelILVarSsa):
			ssa_var = ssa_var.var
		if not isinstance(ssa_var, mediumlevelil.SSAVariable):
			raise ValueError("Expected SSAVariable")
		count = ctypes.c_ulonglong()
		var_data = ssa_var.var.to_BNVariable()
		instrs = core.BNGetHighLevelILSSAVarUses(self.handle, var_data, ssa_var.version, count)
		assert instrs is not None, "core.BNGetHighLevelILSSAVarUses returned None"
		result = []
		for i in range(0, count.value):
			result.append(HighLevelILInstruction.create(self, instrs[i]))
		core.BNFreeILInstructionList(instrs)
		return result

	def get_ssa_memory_uses(self, version: int) -> List[HighLevelILInstruction]:
		count = ctypes.c_ulonglong()
		instrs = core.BNGetHighLevelILSSAMemoryUses(self.handle, version, count)
		assert instrs is not None, "core.BNGetHighLevelILSSAMemoryUses returned None"
		result = []
		for i in range(0, count.value):
			result.append(HighLevelILInstruction.create(self, instrs[i]))
		core.BNFreeILInstructionList(instrs)
		return result

	def is_ssa_var_live(self, ssa_var: 'mediumlevelil.SSAVariable') -> bool:
		"""
		``is_ssa_var_live`` determines if ``ssa_var`` is live at any point in the function

		:param SSAVariable ssa_var: the SSA variable to query
		:return: whether the variable is live at any point in the function
		:rtype: bool
		"""
		var_data = ssa_var.var.to_BNVariable()
		return core.BNIsHighLevelILSSAVarLive(self.handle, var_data, ssa_var.version)

	def is_var_live_at(self, var: 'variable.Variable', instr: InstructionIndex) -> bool:
		"""
		``is_var_live_at`` determines if ``var`` is live at a given point in the function
		"""
		return core.BNIsHighLevelILVarLiveAt(self.handle, var.to_BNVariable(), instr)

	def is_ssa_var_live_at(self, ssa_var: 'mediumlevelil.SSAVariable', instr: InstructionIndex) -> bool:
		"""
		``is_ssa_var_live_at`` determines if ``ssa_var`` is live at a given point in the function; counts phi's as uses
		"""
		return core.BNIsHighLevelILSSAVarLiveAt(self.handle, ssa_var.var.to_BNVariable(), ssa_var.version, instr)

	def get_var_definitions(self, var: 'variable.Variable') -> List[HighLevelILInstruction]:
		count = ctypes.c_ulonglong()
		var_data = var.to_BNVariable()
		instrs = core.BNGetHighLevelILVariableDefinitions(self.handle, var_data, count)
		assert instrs is not None, "core.BNGetHighLevelILVariableDefinitions returned None"
		result = []
		for i in range(0, count.value):
			result.append(HighLevelILInstruction.create(self, instrs[i]))
		core.BNFreeILInstructionList(instrs)
		return result

	def get_var_uses(self, var: 'variable.Variable') -> List[HighLevelILInstruction]:
		count = ctypes.c_ulonglong()
		var_data = var.to_BNVariable()
		instrs = core.BNGetHighLevelILVariableUses(self.handle, var_data, count)
		assert instrs is not None, "core.BNGetHighLevelILVariableUses returned None"
		result = []
		for i in range(0, count.value):
			result.append(HighLevelILInstruction.create(self, instrs[i]))
		core.BNFreeILInstructionList(instrs)
		return result

	def expr(
	    self, operation: Union[str, HighLevelILOperation], a: int = 0, b: int = 0, c: int = 0, d: int = 0, e: int = 0,
	    size: int = 0,
	    source_location: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		if isinstance(operation, str):
			operation_value = HighLevelILOperation[operation]
		else:
			assert isinstance(operation, HighLevelILOperation)
			operation_value = operation.value
		if source_location is not None:
			return ExpressionIndex(core.BNHighLevelILAddExprWithLocation(
				self.handle,
				operation_value,
				source_location.address,
				source_location.source_operand,
				size,
				a,
				b,
				c,
				d,
				e
			))
		else:
			return ExpressionIndex(core.BNHighLevelILAddExpr(self.handle, operation_value, size, a, b, c, d, e))

	def get_expr_count(self) -> int:
		"""
		``get_expr_count`` gives a the total number of expressions in this IL function

		You can use this to enumerate all expressions in conjunction with :py:func:`get_expr`

		.. warning :: Not all IL expressions are valid, even if their index is within the bounds of the function,
		              they might not be used by the function and might not contain properly structured data.

		:return: The number of expressions in the function
		"""
		return core.BNGetHighLevelILExprCount(self.handle)

	def get_expr(self, index: ExpressionIndex, as_ast: bool = True) -> Optional[HighLevelILInstruction]:
		"""
		``get_expr`` retrieves the IL expression at a given expression index in the function.

		.. warning :: Not all IL expressions are valid, even if their index is within the bounds of the function,
		              they might not be used by the function and might not contain properly structured data.

		:param index: Index of desired expression in function
		:param as_ast: Whether to return the expression as a full AST or a single instruction (defaults to AST)
		:return: A HighLevelILInstruction object for the expression, if it exists. Otherwise, None
		"""
		if index >= self.get_expr_count():
			return None

		return HighLevelILInstruction.create(self, index, as_ast)

	def copy_expr(self, original: HighLevelILInstruction) -> ExpressionIndex:
		"""
		``copy_expr`` adds an expression to the function which is equivalent to the given expression

		:param HighLevelILInstruction original: the original IL Instruction you want to copy
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
		``replace_expr`` allows modification of HLIL expressions

		:param ExpressionIndex original: the ExpressionIndex to replace (may also be an expression index)
		:param ExpressionIndex new: the ExpressionIndex to add to the current HighLevelILFunction (may also be an expression index)
		:rtype: None
		"""
		if isinstance(original, HighLevelILInstruction):
			original = original.expr_index
		elif isinstance(original, int):
			original = ExpressionIndex(original)

		if isinstance(new, HighLevelILInstruction):
			new = new.expr_index
		elif isinstance(new, int):
			new = ExpressionIndex(new)

		core.BNReplaceHighLevelILExpr(self.handle, original, new)

	def copy_expr_to(
		self,
		expr: HighLevelILInstruction,
		dest: 'HighLevelILFunction',
		sub_expr_handler: Optional[Callable[[HighLevelILInstruction], ExpressionIndex]] = None
	) -> ExpressionIndex:
		"""
		``copy_expr_to`` deep copies an expression from this function into a target function
		If provided, the function ``sub_expr_handler`` will be called on every copied sub-expression

		.. warning:: This function should ONLY be called as a part of a lifter or workflow. It will otherwise not do anything useful as analysis will not be running.

		:param HighLevelILInstruction expr: Expression in this function to copy
		:param HighLevelILFunction dest: Function to copy the expression to
		:param sub_expr_handler: Optional function to call on every copied sub-expression
		:return: Index of the copied expression in the target function
		"""

		if sub_expr_handler is None:
			sub_expr_handler = lambda sub_expr: self.copy_expr_to(sub_expr, dest)
		layout = _COPY_LAYOUTS.get(expr.operation)
		if layout is None:
			raise NotImplementedError(f"unknown expr operation {expr.operation} in copy_expr_to")
		loc = ILSourceLocation.from_instruction(expr)
		operands = self._copy_operands(expr, layout, dest, sub_expr_handler)
		new_index = dest.expr(expr.operation, *operands, size=expr.size, source_location=loc)
		dest.set_expr_attributes(new_index, expr.attributes)
		return new_index

	def _copy_operands(
		self, expr: HighLevelILInstruction, layout: Tuple, dest: 'HighLevelILFunction',
		sub_expr_handler: Callable[[HighLevelILInstruction], ExpressionIndex]
	) -> List[int]:
		operands: List[int] = []
		slot = 0
		for entry in layout:
			if entry == "value":
				operands.append(expr.core_instr.operands[slot])
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
				raise NotImplementedError(f"copying a {entry!r} operand")
		return operands

	def set_expr_attributes(self, expr: InstructionOrExpression, value: ILInstructionAttributeSet):
		"""
		``set_expr_attributes`` allows modification of instruction attributes but ONLY during lifting.

		.. warning:: This function should ONLY be called as a part of a lifter. It will otherwise not do anything useful as there's no way to trigger re-analysis of IL levels at this time.

		:param ExpressionIndex expr: the ExpressionIndex to replace (may also be an expression index)
		:param set(ILInstructionAttribute) value: the set of attributes to place on the instruction
		:rtype: None
		"""
		if isinstance(expr, HighLevelILInstruction):
			expr = expr.expr_index
		elif isinstance(expr, int):
			expr = ExpressionIndex(expr)

		result = 0
		for flag in value:
			result |= flag.value
		core.BNSetHighLevelILExprAttributes(self.handle, expr, result)

	def set_derived_string_reference_for_expr(self, expr: InstructionOrExpression, str: 'binaryview.DerivedString'):
		if isinstance(expr, HighLevelILInstruction):
			expr = expr.expr_index
		elif isinstance(expr, int):
			expr = ExpressionIndex(expr)

		str_obj = str._to_core_struct(False)
		core.BNSetHighLevelILDerivedStringReferenceForExpr(self.handle, expr, str_obj)

	def remove_derived_string_reference_for_expr(self, expr: InstructionOrExpression):
		if isinstance(expr, HighLevelILInstruction):
			expr = expr.expr_index
		elif isinstance(expr, int):
			expr = ExpressionIndex(expr)
		core.BNRemoveHighLevelILDerivedStringReferenceForExpr(self.handle, expr)

	# BEGIN GENERATED hlil-builders: from api/il, do not edit
	def nop(self, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Does nothing.

		:param loc: The IL location this expression was added from
		:return: The expression ``nop``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_NOP, source_location=loc)

	def block(self, exprs: List[ExpressionIndex], loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Runs the statements ``exprs`` in order.

		:param exprs: The statements
		:param loc: The IL location this expression was added from
		:return: The expression ``{ exprs }``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_BLOCK, len(exprs), self.add_operand_list(exprs), source_location=loc)

	def if_expr(
		self,
		condition: ExpressionIndex,
		true_expr: ExpressionIndex,
		false_expr: ExpressionIndex,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Runs ``true_expr`` if ``condition`` holds, and ``false_expr`` otherwise.

		:param condition: The condition
		:param true_expr: The statement to run when the condition holds
		:param false_expr: The statement to run otherwise, a NOP for none
		:param loc: The IL location this expression was added from
		:return: The expression ``if (condition) true_expr else false_expr``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_IF, condition, true_expr, false_expr, source_location=loc)

	def while_expr(
		self, condition: ExpressionIndex, loop_expr: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Runs ``loop_expr`` for as long as ``condition`` holds, testing it before each iteration.

		:param condition: The loop condition
		:param loop_expr: The loop body
		:param loc: The IL location this expression was added from
		:return: The expression ``while (condition) loop_expr``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_WHILE, condition, loop_expr, source_location=loc)

	def do_while_expr(
		self, loop_expr: ExpressionIndex, condition: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Runs ``loop_expr`` for as long as ``condition`` holds, testing it after each iteration.

		:param loop_expr: The loop body
		:param condition: The loop condition
		:param loc: The IL location this expression was added from
		:return: The expression ``do loop_expr while (condition)``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_DO_WHILE, loop_expr, condition, source_location=loc)

	def for_expr(
		self,
		init_expr: ExpressionIndex,
		condition: ExpressionIndex,
		update_expr: ExpressionIndex,
		loop_expr: ExpressionIndex,
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Runs ``init_expr``, then runs ``loop_expr`` followed by ``update_expr`` for as long as ``condition``
		holds.

		:param init_expr: The statement to run before the loop, a NOP for none
		:param condition: The loop condition
		:param update_expr: The statement to run after each iteration, a NOP for none
		:param loop_expr: The loop body
		:param loc: The IL location this expression was added from
		:return: The expression ``for (init_expr; condition; update_expr) loop_expr``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			HighLevelILOperation.HLIL_FOR, init_expr, condition, update_expr, loop_expr, source_location=loc
		)

	def switch(
		self,
		condition: ExpressionIndex,
		default_expr: ExpressionIndex,
		cases: List[ExpressionIndex],
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Runs the body of the case in ``cases`` whose values include ``condition``, or ``default_expr`` when
		none does.

		:param condition: The value to switch on
		:param default_expr: The statement to run when no case matches
		:param cases: The cases
		:param loc: The IL location this expression was added from
		:return: The expression ``switch (condition) cases default: default_expr``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			HighLevelILOperation.HLIL_SWITCH,
			condition,
			default_expr,
			len(cases),
			self.add_operand_list(cases),
			source_location=loc,
		)

	def case(
		self, values: List[ExpressionIndex], expr: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		A case of a SWITCH that runs ``expr`` when the switch's value is one of ``values``.

		:param values: The values the case matches
		:param expr: The statement to run
		:param loc: The IL location this expression was added from
		:return: The expression ``case values: expr``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			HighLevelILOperation.HLIL_CASE, len(values), self.add_operand_list(values), expr, source_location=loc
		)

	def break_expr(self, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Leaves the innermost enclosing loop or switch.

		:param loc: The IL location this expression was added from
		:return: The expression ``break``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_BREAK, source_location=loc)

	def continue_expr(self, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Starts the next iteration of the innermost enclosing loop.

		:param loc: The IL location this expression was added from
		:return: The expression ``continue``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_CONTINUE, source_location=loc)

	def jump(self, dest: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Jumps to ``dest``.

		:param dest: The address to jump to
		:param loc: The IL location this expression was added from
		:return: The expression ``jump(dest)``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_JUMP, dest, source_location=loc)

	def ret(self, sources: List[ExpressionIndex], loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Returns ``sources`` from the function.

		:param sources: The values to return
		:param loc: The IL location this expression was added from
		:return: The expression ``return sources``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			HighLevelILOperation.HLIL_RET, len(sources), self.add_operand_list(sources), source_location=loc
		)

	def no_ret(self, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Marks a point that execution doesn't pass, such as after a call that doesn't return.

		:param loc: The IL location this expression was added from
		:return: The expression ``noreturn``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_NORET, source_location=loc)

	def goto(self, target: int, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Jumps to the LABEL with ID ``target``.

		:param target: The label's ID
		:param loc: The IL location this expression was added from
		:return: The expression ``goto target``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_GOTO, target, source_location=loc)

	def label(self, target: int, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		A label with ID ``target``, which GOTO statements jump to.

		:param target: The label's ID
		:param loc: The IL location this expression was added from
		:return: The expression ``target:``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_LABEL, target, source_location=loc)

	def var_declare(self, var: 'variable.Variable', loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Declares variable ``var`` without initializing it.

		:param var: The variable to declare
		:param loc: The IL location this expression was added from
		:return: The expression ``var``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_VAR_DECLARE, var.identifier, source_location=loc)

	def var_init(
		self, size: int, dest: 'variable.Variable', src: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Declares variable ``dest`` and initializes it to ``src``.

		:param size: The size of ``src`` in bytes
		:param dest: The variable to declare
		:param src: Its initial value
		:param loc: The IL location this expression was added from
		:return: The expression ``dest = src``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_VAR_INIT, dest.identifier, src, size=size, source_location=loc)

	def assign(
		self, size: int, dest: ExpressionIndex, src: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Stores ``src`` to the location ``dest`` names, such as a variable, a structure field or a
		dereferenced pointer.

		:param size: The size of ``dest`` and ``src`` in bytes
		:param dest: Where to store the value
		:param src: The value to store
		:param loc: The IL location this expression was added from
		:return: The expression ``dest = src``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_ASSIGN, dest, src, size=size, source_location=loc)

	def assign_unpack(
		self, output: List[ExpressionIndex], src: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Stores the several values ``src`` produces, such as a call's results, to the locations ``output``
		names.

		:param output: Where to store the values
		:param src: The expression producing the values
		:param loc: The IL location this expression was added from
		:return: The expression ``output = src``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			HighLevelILOperation.HLIL_ASSIGN_UNPACK,
			len(output),
			self.add_operand_list(output),
			src,
			source_location=loc,
		)

	def force_ver(
		self, size: int, dest: 'variable.Variable', src: 'variable.Variable', loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Gives variable ``dest`` a new SSA version holding the value of ``src``. Analysis can then use this
		as a new variable definition site.

		:param size: The size of the variable in bytes
		:param dest: The variable to give a new version
		:param src: The variable whose value it takes
		:param loc: The IL location this expression was added from
		:return: The expression ``FORCE_VER(dest = src)``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			HighLevelILOperation.HLIL_FORCE_VER, dest.identifier, src.identifier, size=size, source_location=loc
		)

	def assert_expr(
		self,
		size: int,
		src: 'variable.Variable',
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
			HighLevelILOperation.HLIL_ASSERT,
			src.identifier,
			self.cache_possible_value_set(constraint),
			size=size,
			source_location=loc,
		)

	def var(self, size: int, src: 'variable.Variable', loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Reads variable ``src``.

		:param size: The size of the result in bytes
		:param src: The variable to read
		:param loc: The IL location this expression was added from
		:return: The expression ``src``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_VAR, src.identifier, size=size, source_location=loc)

	def struct_field(
		self, size: int, src: ExpressionIndex, offset: int, member_index: int, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Reads the ``size`` byte field at offset ``offset`` within the structure ``src``. Shows the member's
		name when the structure's type has a member at ``offset``.

		:param size: The size of the field in bytes
		:param src: The structure
		:param offset: The offset of the field within the structure, in bytes
		:param member_index: The index of the field among the structure type's members, or -1 for none
		:param loc: The IL location this expression was added from
		:return: The expression ``src:offset.<size>``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			HighLevelILOperation.HLIL_STRUCT_FIELD, src, offset, member_index, size=size, source_location=loc
		)

	def array_index(
		self, size: int, src: ExpressionIndex, idx: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Reads element ``idx`` of the array ``src``.

		:param size: The size of the element in bytes
		:param src: The array
		:param idx: The element's index
		:param loc: The IL location this expression was added from
		:return: The expression ``src[idx]``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_ARRAY_INDEX, src, idx, size=size, source_location=loc)

	def split(
		self, size: int, hi: ExpressionIndex, lo: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Joins ``hi`` and ``lo`` into one value of ``2 * size`` bytes, with ``hi`` as its high half.

		:param size: The size of each half in bytes
		:param hi: The high half
		:param lo: The low half
		:param loc: The IL location this expression was added from
		:return: The expression ``hi:lo``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_SPLIT, hi, lo, size=size, source_location=loc)

	def deref(self, size: int, src: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Reads ``size`` bytes from memory at ``src``.

		:param size: The size of the result in bytes
		:param src: The address to read from
		:param loc: The IL location this expression was added from
		:return: The expression ``*src``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_DEREF, src, size=size, source_location=loc)

	def deref_field(
		self, size: int, src: ExpressionIndex, offset: int, member_index: int, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Reads the ``size`` byte field at offset ``offset`` within the structure that ``src`` points to.
		Shows the member's name when the structure's type has a member at ``offset``.

		:param size: The size of the field in bytes
		:param src: The address of the structure
		:param offset: The offset of the field within the structure, in bytes
		:param member_index: The index of the field among the structure type's members, or -1 for none
		:param loc: The IL location this expression was added from
		:return: The expression ``src->:offset.<size>``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			HighLevelILOperation.HLIL_DEREF_FIELD, src, offset, member_index, size=size, source_location=loc
		)

	def address_of(self, src: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		The address of ``src``, such as a variable or structure field.

		:param src: The value to take the address of
		:param loc: The IL location this expression was added from
		:return: The expression ``&src``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_ADDRESS_OF, src, source_location=loc)

	def pass_by_ref(self, size: int, src: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Passes ``src`` to a call by reference, as the calling convention requires. ``src`` is a pointer to
		the value. Only appears as a call's parameter.

		:param size: The size of the pointer in bytes
		:param src: The address of the value being passed
		:param loc: The IL location this expression was added from
		:return: The expression ``ref *src``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_PASS_BY_REF, src, size=size, source_location=loc)

	def return_by_ref(
		self, size: int, dest: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Receives a call's result in ``dest`` through a pointer the caller supplies.

		:param size: The size of the result in bytes
		:param dest: Where the result goes
		:param loc: The IL location this expression was added from
		:return: The expression ``ref dest``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_RETURN_BY_REF, dest, size=size, source_location=loc)

	def const(self, size: int, value: int, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		An integer constant.

		:param size: The size of the result in bytes
		:param value: The value
		:param loc: The IL location this expression was added from
		:return: The expression ``value``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_CONST, value, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_CONST_DATA, data.type, data.value, size=size, source_location=loc)

	def const_pointer(self, size: int, value: int, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		A constant pointer to address ``value``.

		:param size: The size of the result in bytes
		:param value: The value
		:param loc: The IL location this expression was added from
		:return: The expression ``value``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_CONST_PTR, value, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_EXTERN_PTR, value, offset, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_FLOAT_CONST, value, size=size, source_location=loc)

	def imported_address(self, size: int, value: int, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		The constant address ``value`` of an imported symbol. Renders as the symbol's name where one is
		known.

		:param size: The size of the result in bytes
		:param value: The value
		:param loc: The IL location this expression was added from
		:return: The expression ``*value``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_IMPORT, value, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_ADD, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_ADC, a, b, carry, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_SUB, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_SBB, a, b, carry, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_AND, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_OR, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_XOR, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_LSL, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_LSR, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_ASR, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_ROL, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_RLC, a, b, carry, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_ROR, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_RRC, a, b, carry, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_MUL, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_MULU_DP, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_MULS_DP, a, b, size=size, source_location=loc)

	def div_unsigned(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Divides ``a`` by ``b`` as unsigned integers.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a u/ b``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_DIVU, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_DIVU_DP, a, b, size=size, source_location=loc)

	def div_signed(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Divides ``a`` by ``b`` as signed integers.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a s/ b``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_DIVS, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_DIVS_DP, a, b, size=size, source_location=loc)

	def mod_unsigned(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		The remainder of dividing ``a`` by ``b`` as unsigned integers.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a u% b``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_MODU, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_MODU_DP, a, b, size=size, source_location=loc)

	def mod_signed(
		self, size: int, a: ExpressionIndex, b: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		The remainder of dividing ``a`` by ``b`` as signed integers.

		:param size: The size of the result in bytes
		:param a: The left operand
		:param b: The right operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a s% b``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_MODS, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_MODS_DP, a, b, size=size, source_location=loc)

	def neg_expr(self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Negates ``value`` as a two's complement integer.

		:param size: The size of the result in bytes
		:param value: The operand
		:param loc: The IL location this expression was added from
		:return: The expression ``neg.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_NEG, value, size=size, source_location=loc)

	def not_expr(self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Inverts the bits of ``value``, or negates it logically when ``size`` is 0.

		:param size: The size of the result in bytes
		:param value: The operand
		:param loc: The IL location this expression was added from
		:return: The expression ``not.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_NOT, value, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_SX, value, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_ZX, value, size=size, source_location=loc)

	def low_part(self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Truncates ``value`` to its low ``size`` bytes.

		:param size: The size of the result in bytes
		:param value: The operand
		:param loc: The IL location this expression was added from
		:return: The expression ``(value).<size>``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_LOW_PART, value, size=size, source_location=loc)

	def call(
		self, dest: ExpressionIndex, params: List[ExpressionIndex], loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Calls ``dest`` with ``params``.

		:param dest: The address to call
		:param params: The parameters
		:param loc: The IL location this expression was added from
		:return: The expression ``dest(params)``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			HighLevelILOperation.HLIL_CALL, dest, len(params), self.add_operand_list(params), source_location=loc
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
		return self.expr(HighLevelILOperation.HLIL_CMP_E, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_CMP_NE, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_CMP_SLT, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_CMP_ULT, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_CMP_SLE, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_CMP_ULE, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_CMP_SGE, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_CMP_UGE, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_CMP_SGT, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_CMP_UGT, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_TEST_BIT, a, b, size=size, source_location=loc)

	def bool_to_int(self, size: int, a: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Converts ``a`` to the integer 1 if it's true, or 0 if it's false.

		:param size: The size of the result in bytes
		:param a: The operand
		:param loc: The IL location this expression was added from
		:return: The expression ``a ? 1 : 0``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_BOOL_TO_INT, a, size=size, source_location=loc)

	def system_call(self, params: List[ExpressionIndex], loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Makes a system call with ``params``.

		:param params: The parameters
		:param loc: The IL location this expression was added from
		:return: The expression ``syscall(params)``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			HighLevelILOperation.HLIL_SYSCALL, len(params), self.add_operand_list(params), source_location=loc
		)

	def tailcall(
		self, dest: ExpressionIndex, params: List[ExpressionIndex], loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		Jumps to ``dest`` with ``params`` as a tail call, returning its results.

		:param dest: The address to jump to
		:param params: The parameters
		:param loc: The IL location this expression was added from
		:return: The expression ``return dest(params) __tailcall``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			HighLevelILOperation.HLIL_TAILCALL, dest, len(params), self.add_operand_list(params), source_location=loc
		)

	def intrinsic(
		self,
		intrinsic: 'architecture.IntrinsicType',
		params: List[ExpressionIndex],
		loc: Optional['ILSourceLocation'] = None,
	) -> ExpressionIndex:
		"""
		Calls intrinsic ``intrinsic`` with ``params``. An intrinsic is an architecture operation lifted as a
		call to a built-in function that doesn't exist in the binary.

		:param intrinsic: The architecture intrinsic to call
		:param params: The parameters
		:param loc: The IL location this expression was added from
		:return: The expression ``intrinsic(params)``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			HighLevelILOperation.HLIL_INTRINSIC,
			self.arch.get_intrinsic_index(intrinsic),
			len(params),
			self.add_operand_list(params),
			source_location=loc,
		)

	def breakpoint(self, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		A processor breakpoint.

		:param loc: The IL location this expression was added from
		:return: The expression ``breakpoint``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_BP, source_location=loc)

	def trap(self, value: int, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		A processor trap, or interrupt, with number ``value``.

		:param value: The trap number
		:param loc: The IL location this expression was added from
		:return: The expression ``trap(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_TRAP, value, source_location=loc)

	def undefined(self, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		An undefined value or operation.

		:param loc: The IL location this expression was added from
		:return: The expression ``undefined``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_UNDEF, source_location=loc)

	def unimplemented(self, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		An unimplemented instruction or value.

		:param loc: The IL location this expression was added from
		:return: The expression ``unimplemented``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_UNIMPL, 0, source_location=loc)

	def unknown(self, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		A value that can't be known at analysis time. It doesn't produce the warning an unimplemented
		expression does.

		:param loc: The IL location this expression was added from
		:return: The expression ``unknown``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_UNIMPL, 1, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_UNIMPL_MEM, addr, 0, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_UNIMPL_MEM, addr, 1, size=size, source_location=loc)

	def struct_init(
		self, size: int, fields: List[ExpressionIndex], loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		A structure value of ``size`` bytes built from the field values ``fields``.

		:param size: The size of the result in bytes
		:param fields: The fields' values
		:param loc: The IL location this expression was added from
		:return: The expression ``{ fields }``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			HighLevelILOperation.HLIL_STRUCT_INIT,
			len(fields),
			self.add_operand_list(fields),
			size=size,
			source_location=loc,
		)

	def struct_init_field(
		self, size: int, offset: int, member_index: int, src: ExpressionIndex, loc: Optional['ILSourceLocation'] = None
	) -> ExpressionIndex:
		"""
		A STRUCT_INIT field that sets the ``size`` byte field at offset ``offset`` to ``src``.

		:param size: The size of the field in bytes
		:param offset: The offset of the field within the structure, in bytes
		:param member_index: The index of the field among the structure type's members, or -1 for none
		:param src: The field's value
		:param loc: The IL location this expression was added from
		:return: The expression ``.offset = src``
		:rtype: ExpressionIndex
		"""
		return self.expr(
			HighLevelILOperation.HLIL_STRUCT_INIT_FIELD, offset, member_index, src, size=size, source_location=loc
		)

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
		return self.expr(HighLevelILOperation.HLIL_FADD, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_FSUB, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_FMUL, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_FDIV, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_FSQRT, value, size=size, source_location=loc)

	def float_neg(self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Negates the floating point value ``value``.

		:param size: The size of the result in bytes
		:param value: The operand
		:param loc: The IL location this expression was added from
		:return: The expression ``fneg(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_FNEG, value, size=size, source_location=loc)

	def float_abs(self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		The absolute value of the floating point value ``value``.

		:param size: The size of the result in bytes
		:param value: The operand
		:param loc: The IL location this expression was added from
		:return: The expression ``fabs(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_FABS, value, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_FLOAT_TO_INT, value, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_INT_TO_FLOAT, value, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_FLOAT_CONV, value, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_ROUND_TO_INT, value, size=size, source_location=loc)

	def floor(self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Rounds the floating point value ``value`` to an integral value, towards negative infinity.

		:param size: The size of the result in bytes
		:param value: The operand
		:param loc: The IL location this expression was added from
		:return: The expression ``floor.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_FLOOR, value, size=size, source_location=loc)

	def ceil(self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Rounds the floating point value ``value`` to an integral value, towards positive infinity.

		:param size: The size of the result in bytes
		:param value: The operand
		:param loc: The IL location this expression was added from
		:return: The expression ``ceil.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_CEIL, value, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_FTRUNC, value, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_FCMP_E, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_FCMP_NE, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_FCMP_LT, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_FCMP_LE, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_FCMP_GE, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_FCMP_GT, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_FCMP_O, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_FCMP_UO, a, b, size=size, source_location=loc)

	def unreachable(self, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Marks a point analysis knows execution can't reach, such as a switch's default case when every value
		has a case.

		:param loc: The IL location this expression was added from
		:return: The expression ``unreachable``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_UNREACHABLE, source_location=loc)

	def byte_swap(self, size: int, value: ExpressionIndex, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		Reverses the byte order of ``value``.

		:param size: The size of the result in bytes
		:param value: The operand
		:param loc: The IL location this expression was added from
		:return: The expression ``bswap.<size>(value)``
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_BSWAP, value, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_POPCNT, value, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_CLZ, value, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_CTZ, value, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_RBIT, value, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_CLS, value, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_MINS, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_MAXS, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_MINU, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_MAXU, a, b, size=size, source_location=loc)

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
		return self.expr(HighLevelILOperation.HLIL_ABS, value, size=size, source_location=loc)

	# END GENERATED hlil-builders

	def float_const_single(self, value: float, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``float_const_single`` returns an expression for the single precision floating point value ``value``

		:param float value: float value for the constant
		:param ILSourceLocation loc: location of returned expression
		:return: A constant expression of given value and size
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_FLOAT_CONST, struct.unpack("I", struct.pack("f", value))[0], size=4, source_location=loc)

	def float_const_double(self, value: float, loc: Optional['ILSourceLocation'] = None) -> ExpressionIndex:
		"""
		``float_const_double`` returns an expression for the double precision floating point value ``value``

		:param float value: float value for the constant
		:param ILSourceLocation loc: location of returned expression
		:return: A constant expression of given value and size
		:rtype: ExpressionIndex
		"""
		return self.expr(HighLevelILOperation.HLIL_FLOAT_CONST, struct.unpack("Q", struct.pack("d", value))[0], size=8, source_location=loc)

	def add_operand_list(self, operands: List[int]) -> ExpressionIndex:
		"""
		``add_operand_list`` returns an operand list expression for the given list of integer operands.

		:param list(int) operands: list of operand numbers
		:return: an operand list expression
		:rtype: ExpressionIndex
		"""
		operand_list = (ctypes.c_ulonglong * len(operands))()
		for i in range(len(operands)):
			operand_list[i] = operands[i]
		return ExpressionIndex(core.BNHighLevelILAddOperandList(self.handle, operand_list, len(operands)))

	def cache_possible_value_set(self, pvs: 'variable.PossibleValueSet') -> int:
		"""
		Cache a PossibleValueSet in the IL function, returning its index for use in an expression operand
		:param pvs: PossibleValueSet to cache
		:return: Index of the PossibleValueSet in the cache
		"""
		return core.BNCacheHighLevelILPossibleValueSet(self.handle, pvs._to_core_struct())

	def finalize(self) -> None:
		"""
		``finalize`` ends the function and computes the list of basic blocks.

		:rtype: None
		"""
		core.BNFinalizeHighLevelILFunction(self.handle)

	def generate_ssa_form(self, variables: Optional[List["variable.Variable"]] = None) -> None:
		"""
		``generate_ssa_form`` generate SSA form given the current HLIL

		:param list(Variable) variables: optional list of aliased variables
		:rtype: None
		"""
		if variables is None:
			variables = []
		variable_list = (core.BNVariable * len(variables))()
		for i in range(len(variables)):
			variable_list[i] = variables[i].to_BNVariable()
		core.BNGenerateHighLevelILSSAForm(self.handle, variable_list, len(variable_list))

	def create_graph(self, settings: Optional['function.DisassemblySettings'] = None) -> 'flowgraph.CoreFlowGraph':
		if settings is not None:
			settings_obj = settings.handle
		else:
			settings_obj = None
		return flowgraph.CoreFlowGraph(core.BNCreateHighLevelILFunctionGraph(self.handle, settings_obj))

	def create_graph_immediate(self, settings: Optional['function.DisassemblySettings'] = None) -> 'flowgraph.CoreFlowGraph':
		if settings is not None:
			settings_obj = settings.handle
		else:
			settings_obj = None
		return flowgraph.CoreFlowGraph(core.BNCreateHighLevelILImmediateFunctionGraph(self.handle, settings_obj))

	@property
	def il_form(self) -> FunctionGraphType:
		if len(list(self.basic_blocks)) < 1:
			return FunctionGraphType.InvalidILViewType
		return FunctionGraphType(core.BNGetBasicBlockFunctionGraphType(list(self.basic_blocks)[0].handle))

	@property
	def vars(self) -> Union[List["variable.Variable"], List["mediumlevelil.SSAVariable"]]:
		"""This gets just the HLIL variables - you may be interested in the union of `HighLevelIlFunction.source_function.parameter_vars` and `HighLevelIlFunction.aliased_vars` as well for all the variables used in the function"""
		if self.source_function is None:
			return []

		if self.il_form == FunctionGraphType.HighLevelILSSAFormFunctionGraph:
			return self.ssa_vars

		if self.il_form == FunctionGraphType.HighLevelILFunctionGraph:
			count = ctypes.c_ulonglong()
			core_variables = core.BNGetHighLevelILVariables(self.handle, count)
			assert core_variables is not None, "core.BNGetHighLevelILVariables returned None"
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
	def aliased_vars(self) -> List["variable.Variable"]:
		"""This returns a list of Variables that are taken reference to and used elsewhere. You may also wish to consider `HighLevelIlFunction.vars` and `HighLevelIlFunction.source_function.parameter_vars`"""
		if self.source_function is None:
			return []

		if self.il_form in [
		    FunctionGraphType.HighLevelILFunctionGraph, FunctionGraphType.HighLevelILSSAFormFunctionGraph
		]:
			count = ctypes.c_ulonglong()
			core_variables = core.BNGetHighLevelILAliasedVariables(self.handle, count)
			assert core_variables is not None, "core.BNGetHighLevelILAliasedVariables returned None"
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
	def ssa_vars(self) -> List["mediumlevelil.SSAVariable"]:
		"""This gets just the HLIL SSA variables - you may be interested in the union of `HighLevelIlFunction.source_function.parameter_vars` and `HighLevelIlFunction.aliased_vars` for all the variables used in the function"""
		if self.source_function is None:
			return []

		if self.il_form == FunctionGraphType.HighLevelILSSAFormFunctionGraph:
			variable_count = ctypes.c_ulonglong()
			core_variables = core.BNGetHighLevelILVariables(self.handle, variable_count)
			assert core_variables is not None, "core.BNGetHighLevelILVariables returned None"
			try:
				result = []
				for var_i in range(variable_count.value):
					version_count = ctypes.c_ulonglong()
					versions = core.BNGetHighLevelILVariableSSAVersions(
					    self.handle, core_variables[var_i], version_count
					)
					assert versions is not None, "core.BNGetHighLevelILVariableSSAVersions returned None"
					try:
						for version_i in range(version_count.value):
							result.append(
							    mediumlevelil.SSAVariable(
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
		elif self.il_form == FunctionGraphType.HighLevelILFunctionGraph:
			return self.ssa_form.ssa_vars

		return []

	def get_instruction_index_for_expr(self, expr: ExpressionIndex) -> Optional[InstructionIndex]:
		result = core.BNGetHighLevelILInstructionForExpr(self.handle, expr)
		if result >= core.BNGetHighLevelILInstructionCount(self.handle):
			return None
		return InstructionIndex(result)

	def get_expr_index_for_instruction(self, instr: InstructionIndex) -> ExpressionIndex:
		result = core.BNGetHighLevelILIndexForInstruction(self.handle, instr)
		return ExpressionIndex(result)

	def get_medium_level_il_expr_index(self, expr: ExpressionIndex) -> Optional['mediumlevelil.ExpressionIndex']:
		medium_il = self.medium_level_il
		if medium_il is None:
			return None
		medium_il = medium_il.ssa_form
		if medium_il is None:
			return None
		result = core.BNGetMediumLevelILExprIndexFromHighLevelIL(self.handle, expr)
		if result >= core.BNGetMediumLevelILExprCount(medium_il.handle):
			return None
		return mediumlevelil.ExpressionIndex(result)

	def get_medium_level_il_expr_indexes(self, expr: ExpressionIndex) -> List['mediumlevelil.ExpressionIndex']:
		count = ctypes.c_ulonglong()
		exprs = core.BNGetMediumLevelILExprIndexesFromHighLevelIL(self.handle, expr, count)
		assert exprs is not None, "core.BNGetMediumLevelILExprIndexesFromHighLevelIL returned None"
		result = []
		for i in range(0, count.value):
			result.append(exprs[i])
		core.BNFreeILInstructionList(exprs)
		return result

	def get_label(self, label_idx: int) -> Optional[HighLevelILInstruction]:
		result = core.BNGetHighLevelILExprIndexForLabel(self.handle, label_idx)
		if result >= core.BNGetHighLevelILExprCount(self.handle):
			return None
		return HighLevelILInstruction.create(self, ExpressionIndex(result))

	def get_label_uses(self, label_idx: int) -> List[HighLevelILInstruction]:
		count = ctypes.c_ulonglong()
		uses = core.BNGetHighLevelILUsesForLabel(self.handle, label_idx, count)
		assert uses is not None, "core.BNGetHighLevelILUsesForLabel returned None"
		result = []
		for i in range(0, count.value):
			result.append(HighLevelILInstruction.create(self, uses[i]))
		core.BNFreeILInstructionList(uses)
		return result

	def get_expr_type(self, expr_index: int) -> Optional['types.Type']:
		"""
		Get type of expression

		:param int expr_index: index of the expression to retrieve
		:rtype: Optional['types.Type']
		"""
		result = core.BNGetHighLevelILExprType(self.handle, expr_index)
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
		ic = expr_type.immutable_copy()
		core.BNSetHighLevelILExprType(self.handle, expr_index, ic._to_core_struct())


class HighLevelILBasicBlock(basicblock.BasicBlock):
	"""
	The ``HighLevelILBasicBlock`` object is returned during analysis and should not be directly instantiated.
	"""
	def __init__(
	    self, handle: core.BNBasicBlockHandle, owner: HighLevelILFunction, view: Optional['binaryview.BinaryView']
	):
		super().__init__(handle, view)
		self._il_function = owner

	def __iter__(self) -> Generator[HighLevelILInstruction, None, None]:
		for idx in range(self.start, self.end):
			yield self.il_function[idx]

	@overload
	def __getitem__(self, idx: int) -> 'HighLevelILInstruction': ...

	@overload
	def __getitem__(self, idx: slice) -> List['HighLevelILInstruction']: ...

	def __getitem__(self, idx: Union[int, slice]) -> Union[List[HighLevelILInstruction], HighLevelILInstruction]:
		size = self.end - self.start
		if isinstance(idx, slice):
			return [self[index] for index in range(*idx.indices(size))]  # type: ignore
		if idx > size or idx < -size:
			raise IndexError("list index is out of range")
		if idx >= 0:
			return self.il_function[idx + self.start]
		else:
			return self.il_function[self.end + idx]

	def _create_instance(self, handle: core.BNBasicBlockHandle):
		"""Internal method by super to instantiate child instances"""
		return HighLevelILBasicBlock(handle, self.il_function, self.view)

	def __hash__(self):
		return hash((self.start, self.end, self.il_function))

	def __contains__(self, instruction):
		if not isinstance(instruction, HighLevelILInstruction) or instruction.il_basic_block != self:
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

	@property
	def instruction_count(self) -> int:
		return self.end - self.start

	@property
	def il_function(self) -> HighLevelILFunction:
		return self._il_function
