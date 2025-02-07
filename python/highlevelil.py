# Copyright (c) 2019-2024 Vector 35 Inc
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
from typing import Optional, Generator, List, Union, NewType, Tuple, ClassVar, Mapping, Set, Callable, Any, Iterator, overload
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
from . import types as _types
from .interaction import show_graph_report
from .commonil import (
    BaseILInstruction, Tailcall, Syscall, Localcall, Comparison, Signed, UnaryOperation, BinaryOperation, SSA, Phi,
    Loop, ControlFlow, Memory, Constant, Arithmetic, DoublePrecision, Terminal, FloatingPoint, Intrinsic, Return,
    VariableInstruction, SSAVariableInstruction, SetVar
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
	ILOperations: ClassVar[Mapping[HighLevelILOperation, List[Tuple[str, str]]]] = {
	    HighLevelILOperation.HLIL_NOP: [], HighLevelILOperation.HLIL_BLOCK: [("body", "expr_list")],
	    HighLevelILOperation.HLIL_IF: [("condition", "expr"), ("true", "expr"),
	                                   ("false", "expr")], HighLevelILOperation.HLIL_WHILE: [("condition", "expr"),
	                                                                                         ("body", "expr")],
	    HighLevelILOperation.HLIL_WHILE_SSA: [("condition_phi", "expr"), ("condition", "expr"),
	                                          ("body", "expr")], HighLevelILOperation.HLIL_DO_WHILE: [
	                                              ("body", "expr"), ("condition", "expr")
	                                          ], HighLevelILOperation.HLIL_DO_WHILE_SSA: [("body", "expr"),
	                                                                                      ("condition_phi", "expr"),
	                                                                                      ("condition", "expr")],
	    HighLevelILOperation.HLIL_FOR: [("init", "expr"), ("condition", "expr"), ("update", "expr"),
	                                    ("body", "expr")], HighLevelILOperation.HLIL_FOR_SSA: [
	                                        ("init", "expr"), ("condition_phi", "expr"), ("condition", "expr"),
	                                        ("update", "expr"), ("body", "expr")
	                                    ], HighLevelILOperation.HLIL_SWITCH: [
	                                        ("condition", "expr"), ("default", "expr"), ("cases", "expr_list")
	                                    ], HighLevelILOperation.HLIL_CASE: [("values", "expr_list"), ("body", "expr")],
	    HighLevelILOperation.HLIL_BREAK: [], HighLevelILOperation.HLIL_CONTINUE: [], HighLevelILOperation.HLIL_JUMP: [
	        ("dest", "expr")
	    ], HighLevelILOperation.HLIL_RET: [("src", "expr_list")], HighLevelILOperation.HLIL_NORET: [],
	    HighLevelILOperation.HLIL_UNREACHABLE: [],
	    HighLevelILOperation.HLIL_GOTO: [("target", "label")], HighLevelILOperation.HLIL_LABEL: [
	        ("target", "label")
	    ], HighLevelILOperation.HLIL_VAR_DECLARE: [("var", "var")], HighLevelILOperation.HLIL_VAR_INIT: [
	        ("dest", "var"), ("src", "expr")
	    ], HighLevelILOperation.HLIL_VAR_INIT_SSA: [
	        ("dest", "var_ssa"), ("src", "expr")
	    ], HighLevelILOperation.HLIL_ASSIGN: [("dest", "expr"),
	                                          ("src", "expr")], HighLevelILOperation.HLIL_ASSIGN_UNPACK: [
	                                              ("dest", "expr_list"), ("src", "expr")
	                                          ], HighLevelILOperation.HLIL_ASSIGN_MEM_SSA: [("dest", "expr"),
	                                                                                        ("dest_memory", "int"),
	                                                                                        ("src", "expr"),
	                                                                                        ("src_memory", "int")],
	    HighLevelILOperation.HLIL_ASSIGN_UNPACK_MEM_SSA: [
	        ("dest", "expr_list"), ("dest_memory", "int"), ("src", "expr"), ("src_memory", "int")
	    ], HighLevelILOperation.HLIL_VAR: [("var", "var")], HighLevelILOperation.HLIL_VAR_SSA: [
	        ("var", "var_ssa")
	    ], HighLevelILOperation.HLIL_VAR_PHI: [("dest", "var_ssa"),
	                                           ("src", "var_ssa_list")], HighLevelILOperation.HLIL_MEM_PHI: [
	                                               ("dest", "int"), ("src", "int_list")
	                                           ], HighLevelILOperation.HLIL_STRUCT_FIELD: [
	                                               ("src", "expr"), ("offset", "int"), ("member_index", "member_index")
	                                           ], HighLevelILOperation.HLIL_ARRAY_INDEX: [
	                                               ("src", "expr"), ("index", "expr")
	                                           ], HighLevelILOperation.HLIL_ARRAY_INDEX_SSA: [("src", "expr"),
	                                                                                          ("src_memory", "int"),
	                                                                                          ("index", "expr")],
	    HighLevelILOperation.HLIL_SPLIT: [("high", "expr"), ("low", "expr")], HighLevelILOperation.HLIL_DEREF: [
	        ("src", "expr")
	    ], HighLevelILOperation.HLIL_DEREF_FIELD: [
	        ("src", "expr"), ("offset", "int"), ("member_index", "member_index")
	    ], HighLevelILOperation.HLIL_DEREF_SSA: [
	        ("src", "expr"), ("src_memory", "int")
	    ], HighLevelILOperation.HLIL_DEREF_FIELD_SSA: [
	        ("src", "expr"), ("src_memory", "int"), ("offset", "int"),
	        ("member_index", "member_index")
	    ], HighLevelILOperation.HLIL_ADDRESS_OF: [("src", "expr")], HighLevelILOperation.HLIL_CONST: [
	        ("constant", "int")
	    ], HighLevelILOperation.HLIL_CONST_PTR: [("constant", "int")], HighLevelILOperation.HLIL_EXTERN_PTR: [
	        ("constant", "int"), ("offset", "int")
	    ], HighLevelILOperation.HLIL_FLOAT_CONST: [("constant", "float")], HighLevelILOperation.HLIL_IMPORT: [
	        ("constant", "int")
	    ], HighLevelILOperation.HLIL_CONST_DATA: [("constant_data", "constant_data")], HighLevelILOperation.HLIL_CONST_DATA: [
	        ("constant_data", "constant_data")
	    ], HighLevelILOperation.HLIL_ADD: [("left", "expr"), ("right", "expr")], HighLevelILOperation.HLIL_ADC: [
	        ("left", "expr"), ("right", "expr"), ("carry", "expr")
	    ], HighLevelILOperation.HLIL_SUB: [("left", "expr"), ("right", "expr")], HighLevelILOperation.HLIL_SBB: [
	        ("left", "expr"), ("right", "expr"), ("carry", "expr")
	    ], HighLevelILOperation.HLIL_AND: [("left", "expr"), ("right", "expr")], HighLevelILOperation.HLIL_OR: [
	        ("left", "expr"), ("right", "expr")
	    ], HighLevelILOperation.HLIL_XOR: [("left", "expr"), ("right", "expr")], HighLevelILOperation.HLIL_LSL: [
	        ("left", "expr"), ("right", "expr")
	    ], HighLevelILOperation.HLIL_LSR: [("left", "expr"), ("right", "expr")], HighLevelILOperation.HLIL_ASR: [
	        ("left", "expr"), ("right", "expr")
	    ], HighLevelILOperation.HLIL_ROL: [("left", "expr"), ("right", "expr")], HighLevelILOperation.HLIL_RLC: [
	        ("left", "expr"), ("right", "expr"), ("carry", "expr")
	    ], HighLevelILOperation.HLIL_ROR: [("left", "expr"), ("right", "expr")], HighLevelILOperation.HLIL_RRC: [
	        ("left", "expr"), ("right", "expr"), ("carry", "expr")
	    ], HighLevelILOperation.HLIL_MUL: [("left", "expr"), ("right", "expr")], HighLevelILOperation.HLIL_MULU_DP: [
	        ("left", "expr"), ("right", "expr")
	    ], HighLevelILOperation.HLIL_MULS_DP: [("left", "expr"), ("right", "expr")], HighLevelILOperation.HLIL_DIVU: [
	        ("left", "expr"), ("right", "expr")
	    ], HighLevelILOperation.HLIL_DIVU_DP: [("left", "expr"), ("right", "expr")], HighLevelILOperation.HLIL_DIVS: [
	        ("left", "expr"), ("right", "expr")
	    ], HighLevelILOperation.HLIL_DIVS_DP: [("left", "expr"), ("right", "expr")], HighLevelILOperation.HLIL_MODU: [
	        ("left", "expr"), ("right", "expr")
	    ], HighLevelILOperation.HLIL_MODU_DP: [("left", "expr"), ("right", "expr")], HighLevelILOperation.HLIL_MODS: [
	        ("left", "expr"), ("right", "expr")
	    ], HighLevelILOperation.HLIL_MODS_DP: [("left", "expr"), ("right", "expr")], HighLevelILOperation.HLIL_NEG: [
	        ("src", "expr")
	    ], HighLevelILOperation.HLIL_NOT: [("src", "expr")], HighLevelILOperation.HLIL_SX: [
	        ("src", "expr")
	    ], HighLevelILOperation.HLIL_ZX: [("src", "expr")], HighLevelILOperation.HLIL_LOW_PART: [
	        ("src", "expr")
	    ], HighLevelILOperation.HLIL_CALL: [
	        ("dest", "expr"), ("params", "expr_list")
	    ], HighLevelILOperation.HLIL_CALL_SSA: [
	        ("dest", "expr"), ("params", "expr_list"), ("dest_memory", "int"), ("src_memory", "int")
	    ], HighLevelILOperation.HLIL_CMP_E: [("left", "expr"), ("right", "expr")], HighLevelILOperation.HLIL_CMP_NE: [
	        ("left", "expr"), ("right", "expr")
	    ], HighLevelILOperation.HLIL_CMP_SLT: [("left", "expr"), ("right", "expr")],
	    HighLevelILOperation.HLIL_CMP_ULT: [("left", "expr"), ("right", "expr")], HighLevelILOperation.HLIL_CMP_SLE: [
	        ("left", "expr"), ("right", "expr")
	    ], HighLevelILOperation.HLIL_CMP_ULE: [("left", "expr"),
	                                           ("right", "expr")], HighLevelILOperation.HLIL_CMP_SGE: [
	                                               ("left", "expr"), ("right", "expr")
	                                           ], HighLevelILOperation.HLIL_CMP_UGE: [("left", "expr"),
	                                                                                  ("right", "expr")],
	    HighLevelILOperation.HLIL_CMP_SGT: [("left", "expr"), ("right", "expr")], HighLevelILOperation.HLIL_CMP_UGT: [
	        ("left", "expr"), ("right", "expr")
	    ], HighLevelILOperation.HLIL_TEST_BIT: [
	        ("left", "expr"), ("right", "expr")
	    ], HighLevelILOperation.HLIL_BOOL_TO_INT: [("src", "expr")], HighLevelILOperation.HLIL_ADD_OVERFLOW: [
	        ("left", "expr"), ("right", "expr")
	    ], HighLevelILOperation.HLIL_SYSCALL: [("params", "expr_list")], HighLevelILOperation.HLIL_SYSCALL_SSA: [
	        ("params", "expr_list"), ("dest_memory", "int"), ("src_memory", "int")
	    ], HighLevelILOperation.HLIL_TAILCALL: [
	        ("dest", "expr"), ("params", "expr_list")
	    ], HighLevelILOperation.HLIL_BP: [], HighLevelILOperation.HLIL_TRAP: [
	        ("vector", "int")
	    ], HighLevelILOperation.HLIL_INTRINSIC: [("intrinsic", "intrinsic"),
	                                             ("params", "expr_list")], HighLevelILOperation.HLIL_INTRINSIC_SSA: [
	                                                 ("intrinsic", "intrinsic"), ("params", "expr_list"),
	                                                 ("dest_memory", "int"), ("src_memory", "int")
	                                             ], HighLevelILOperation.HLIL_UNDEF: [],
	    HighLevelILOperation.HLIL_UNIMPL: [], HighLevelILOperation.HLIL_UNIMPL_MEM: [
	        ("src", "expr")
	    ], HighLevelILOperation.HLIL_FADD: [("left", "expr"), ("right", "expr")], HighLevelILOperation.HLIL_FSUB: [
	        ("left", "expr"), ("right", "expr")
	    ], HighLevelILOperation.HLIL_FMUL: [("left", "expr"), ("right", "expr")], HighLevelILOperation.HLIL_FDIV: [
	        ("left", "expr"), ("right", "expr")
	    ], HighLevelILOperation.HLIL_FSQRT: [("src", "expr")], HighLevelILOperation.HLIL_FNEG: [
	        ("src", "expr")
	    ], HighLevelILOperation.HLIL_FABS: [("src", "expr")], HighLevelILOperation.HLIL_FLOAT_TO_INT: [
	        ("src", "expr")
	    ], HighLevelILOperation.HLIL_INT_TO_FLOAT: [("src", "expr")], HighLevelILOperation.HLIL_FLOAT_CONV: [
	        ("src", "expr")
	    ], HighLevelILOperation.HLIL_ROUND_TO_INT: [("src", "expr")], HighLevelILOperation.HLIL_FLOOR: [
	        ("src", "expr")
	    ], HighLevelILOperation.HLIL_CEIL: [("src", "expr")], HighLevelILOperation.HLIL_FTRUNC: [
	        ("src", "expr")
	    ], HighLevelILOperation.HLIL_FCMP_E: [("left", "expr"), ("right", "expr")], HighLevelILOperation.HLIL_FCMP_NE: [
	        ("left", "expr"), ("right", "expr")
	    ], HighLevelILOperation.HLIL_FCMP_LT: [
	        ("left", "expr"), ("right", "expr")
	    ], HighLevelILOperation.HLIL_FCMP_LE: [
	        ("left", "expr"), ("right", "expr")
	    ], HighLevelILOperation.HLIL_FCMP_GE: [
	        ("left", "expr"), ("right", "expr")
	    ], HighLevelILOperation.HLIL_FCMP_GT: [("left", "expr"), ("right", "expr")], HighLevelILOperation.HLIL_FCMP_O: [
	        ("left", "expr"), ("right", "expr")
	    ], HighLevelILOperation.HLIL_FCMP_UO: [("left", "expr"), ("right", "expr")]
	}

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
		"""This expression with full AST printing (read-only)"""
		if self.as_ast:
			return self
		return HighLevelILInstruction.create(self.function, self.expr_index, True)

	@property
	def non_ast(self) -> 'HighLevelILInstruction':
		"""This expression without full AST printing (read-only)"""
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

	def get_int(self, operand_index: int) -> int:
		value = self.core_instr.operands[operand_index]
		return (value & ((1 << 63) - 1)) - (value & (1 << 63))

	def get_float(self, operand_index: int) -> float:
		value = self.core_instr.operands[operand_index]
		if self.core_instr.size == 4:
			return struct.unpack("f", struct.pack("I", value & 0xffffffff))[0]
		elif self.core_instr.size == 8:
			return struct.unpack("d", struct.pack("Q", value))[0]
		else:
			return float(value)

	def get_constant_data(self, operand_index1: int, operand_index2: int) -> variable.ConstantData:
		state = variable.RegisterValueType(self.core_instr.operands[operand_index1])
		value = self.core_instr.operands[operand_index2]
		return variable.ConstantData(value, 0, state, core.max_confidence, self.core_instr.size, self.function.source_function)

	def get_expr(self, operand_index: int) -> 'HighLevelILInstruction':
		return HighLevelILInstruction.create(
			self.function, ExpressionIndex(self.core_instr.operands[operand_index]),
			self.as_ast
		)

	def get_intrinsic(self, operand_index: int) -> 'lowlevelil.ILIntrinsic':
		if self.function.arch is None:
			raise ValueError("Attempting to create ILIntrinsic from function with no Architecture")
		return lowlevelil.ILIntrinsic(
		    self.function.arch, architecture.IntrinsicIndex(self.core_instr.operands[operand_index])
		)

	def get_var(self, operand_index: int) -> 'variable.Variable':
		value = self.core_instr.operands[operand_index]
		return variable.Variable.from_identifier(self.function, value)

	def get_var_ssa(self, operand_index1: int, operand_index2: int) -> 'mediumlevelil.SSAVariable':
		var = variable.Variable.from_identifier(self.function, self.core_instr.operands[operand_index1])
		version = self.core_instr.operands[operand_index2]
		return mediumlevelil.SSAVariable(var, version)

	def get_var_ssa_dest_and_src(self, operand_index1: int, operand_index2: int) -> 'mediumlevelil.SSAVariable':
		var = variable.Variable.from_identifier(self.function, self.core_instr.operands[operand_index1])
		dest_version = self.core_instr.operands[operand_index2]
		return mediumlevelil.SSAVariable(var, dest_version)

	def get_int_list(self, operand_index: int) -> List[int]:
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

	def get_expr_list(self, operand_index1: int, operand_index2: int) -> List['HighLevelILInstruction']:
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

	def get_var_ssa_list(self, operand_index1: int, _: int) -> List['mediumlevelil.SSAVariable']:
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

	def get_member_index(self, operand_index: int) -> Optional[int]:
		value = self.core_instr.operands[operand_index]
		if (value & (1 << 63)) != 0:
			value = None
		return value

	def get_label(self, operand_index: int) -> GotoLabel:
		return GotoLabel(self.function, self.core_instr.operands[operand_index])

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
		"""Gets HLIL text lines with optional settings"""
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


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILUnaryBase(HighLevelILInstruction, UnaryOperation):
	@property
	def src(self) -> HighLevelILInstruction:
		return self.get_expr(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("src", self.src, "HighLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILBinaryBase(HighLevelILInstruction, BinaryOperation):
	@property
	def left(self) -> HighLevelILInstruction:
		return self.get_expr(0)

	@property
	def right(self) -> HighLevelILInstruction:
		return self.get_expr(1)

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
		return self.get_expr(0)

	@property
	def right(self) -> HighLevelILInstruction:
		return self.get_expr(1)

	@property
	def carry(self) -> HighLevelILInstruction:
		return self.get_expr(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("left", self.left, "HighLevelILInstruction"),
			("right", self.right, "HighLevelILInstruction"),
			("carry", self.carry, "HighLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILNop(HighLevelILInstruction):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILBlock(HighLevelILInstruction):
	@property
	def body(self) -> List[HighLevelILInstruction]:
		return self.get_expr_list(0, 1)

	def __iter__(self) -> Generator['HighLevelILInstruction', None, None]:
		for expr in self.body:
			yield expr

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("body", self.body, "List[HighLevelILInstruction]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILIf(HighLevelILInstruction, ControlFlow):
	@property
	def condition(self) -> HighLevelILInstruction:
		return self.get_expr(0)

	@property
	def true(self) -> HighLevelILInstruction:
		return self.get_expr(1)

	@property
	def false(self) -> HighLevelILInstruction:
		return self.get_expr(2)

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
		return self.get_expr(0)

	@property
	def body(self) -> HighLevelILInstruction:
		return self.get_expr(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("condition", self.condition, "HighLevelILInstruction"),
			("body", self.body, "HighLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILWhileSsa(HighLevelILInstruction, Loop, SSA):
	@property
	def condition_phi(self) -> HighLevelILInstruction:
		return self.get_expr(0)

	@property
	def condition(self) -> HighLevelILInstruction:
		return self.get_expr(1)

	@property
	def body(self) -> HighLevelILInstruction:
		return self.get_expr(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("condition_phi", self.condition_phi, "HighLevelILInstruction"),
			("condition", self.condition, "HighLevelILInstruction"),
			("body", self.body, "HighLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILDoWhile(HighLevelILInstruction, Loop):
	@property
	def body(self) -> HighLevelILInstruction:
		return self.get_expr(0)

	@property
	def condition(self) -> HighLevelILInstruction:
		return self.get_expr(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("body", self.body, "HighLevelILInstruction"),
			("condition", self.condition, "HighLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILDoWhileSsa(HighLevelILInstruction, Loop, SSA):
	@property
	def body(self) -> HighLevelILInstruction:
		return self.get_expr(0)

	@property
	def condition_phi(self) -> HighLevelILInstruction:
		return self.get_expr(1)

	@property
	def condition(self) -> HighLevelILInstruction:
		return self.get_expr(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("body", self.body, "HighLevelILInstruction"),
			("condition_phi", self.condition_phi, "HighLevelILInstruction"),
			("condition", self.condition, "HighLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILFor(HighLevelILInstruction, Loop):
	@property
	def init(self) -> HighLevelILInstruction:
		return self.get_expr(0)

	@property
	def condition(self) -> HighLevelILInstruction:
		return self.get_expr(1)

	@property
	def update(self) -> HighLevelILInstruction:
		return self.get_expr(2)

	@property
	def body(self) -> HighLevelILInstruction:
		return self.get_expr(3)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("init", self.init, "HighLevelILInstruction"),
			("condition", self.condition, "HighLevelILInstruction"),
			("update", self.update, "HighLevelILInstruction"),
			("body", self.body, "HighLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILForSsa(HighLevelILInstruction, Loop, SSA):
	@property
	def init(self) -> HighLevelILInstruction:
		return self.get_expr(0)

	@property
	def condition_phi(self) -> HighLevelILInstruction:
		return self.get_expr(1)

	@property
	def condition(self) -> HighLevelILInstruction:
		return self.get_expr(2)

	@property
	def update(self) -> HighLevelILInstruction:
		return self.get_expr(3)

	@property
	def body(self) -> HighLevelILInstruction:
		return self.get_expr(4)

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
class HighLevelILSwitch(HighLevelILInstruction, ControlFlow):
	@property
	def condition(self) -> HighLevelILInstruction:
		return self.get_expr(0)

	@property
	def default(self) -> HighLevelILInstruction:
		return self.get_expr(1)

	@property
	def cases(self) -> List[HighLevelILInstruction]:
		return self.get_expr_list(2, 3)

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
		return self.get_expr_list(0, 1)

	@property
	def body(self) -> HighLevelILInstruction:
		return self.get_expr(2)

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
		return self.get_expr(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("dest", self.dest, "HighLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILRet(HighLevelILInstruction, Return):
	@property
	def src(self) -> List[HighLevelILInstruction]:
		return self.get_expr_list(0, 1)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("src", self.src, "List[HighLevelILInstruction]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILNoret(HighLevelILInstruction, Terminal):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILUnreachable(HighLevelILInstruction, Terminal):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILGoto(HighLevelILInstruction, Terminal):
	@property
	def target(self) -> GotoLabel:
		return self.get_label(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("target", self.target, "GotoLabel"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILLabel(HighLevelILInstruction):
	@property
	def target(self) -> GotoLabel:
		return self.get_label(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("target", self.target, "GotoLabel"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILVarDeclare(HighLevelILInstruction):
	@property
	def var(self) -> 'variable.Variable':
		return self.get_var(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("var", self.var, "Variable"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILVarInit(HighLevelILInstruction, SetVar):
	@property
	def dest(self) -> 'variable.Variable':
		return self.get_var(0)

	@property
	def src(self) -> HighLevelILInstruction:
		return self.get_expr(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("dest", self.dest, "Variable"),
			("src", self.src, "HighLevelILInstruction"),
		]

	@property
	def vars_written(self) -> VariablesList:
		return [self.dest]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILVarInitSsa(HighLevelILInstruction, SetVar, SSA):
	@property
	def dest(self) -> 'mediumlevelil.SSAVariable':
		return self.get_var_ssa(0, 1)

	@property
	def src(self) -> HighLevelILInstruction:
		return self.get_expr(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("dest", self.dest, "SSAVariable"),
			("src", self.src, "HighLevelILInstruction"),
		]

	@property
	def vars_written(self) -> VariablesList:
		return [self.dest]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILAssign(HighLevelILInstruction, SetVar):
	@property
	def dest(self) -> HighLevelILInstruction:
		return self.get_expr(0)

	@property
	def src(self) -> HighLevelILInstruction:
		return self.get_expr(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("dest", self.dest, "HighLevelILInstruction"),
			("src", self.src, "HighLevelILInstruction"),
		]

	@property
	def vars_written(self) -> VariablesList:
		if isinstance(self.dest, (HighLevelILSplit, HighLevelILVar, HighLevelILVarSsa)):
			return [*self.dest.vars, *self.src.vars_written]
		elif isinstance(self.dest, HighLevelILStructField):
			return [*self.dest.vars, *self.src.vars_written]
		else:
			return [*self.dest.vars_written, *self.src.vars_written]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILAssignUnpack(HighLevelILInstruction, SetVar):
	@property
	def dest(self) -> List[HighLevelILInstruction]:
		return self.get_expr_list(0, 1)

	@property
	def src(self) -> HighLevelILInstruction:
		return self.get_expr(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("dest", self.dest, "List[HighLevelILInstruction]"),
			("src", self.src, "HighLevelILInstruction"),
		]

	@property
	def vars_written(self) -> VariablesList:
		result = []
		for i in self.dest:
			if isinstance(i, (HighLevelILVar, HighLevelILVarSsa)):
				result.append(i.var)
			else:
				result.extend(i.vars_written)
		return result


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILAssignMemSsa(HighLevelILInstruction, SSA):
	@property
	def dest(self) -> HighLevelILInstruction:
		return self.get_expr(0)

	@property
	def dest_memory(self) -> int:
		return self.get_int(1)

	@property
	def src(self) -> HighLevelILInstruction:
		return self.get_expr(2)

	@property
	def src_memory(self) -> int:
		return self.get_int(3)

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
		return self.get_expr_list(0, 1)

	@property
	def dest_memory(self) -> int:
		return self.get_int(2)

	@property
	def src(self) -> HighLevelILInstruction:
		return self.get_expr(3)

	@property
	def src_memory(self) -> int:
		return self.get_int(4)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("dest", self.dest, "List[HighLevelILInstruction]"),
			("dest_memory", self.dest_memory, "int"),
			("src", self.src, "HighLevelILInstruction"),
			("src_memory", self.src_memory, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILVar(HighLevelILInstruction, VariableInstruction):
	@property
	def var(self) -> 'variable.Variable':
		return self.get_var(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("var", self.var, "Variable"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILVarSsa(HighLevelILInstruction, SSAVariableInstruction):
	@property
	def var(self) -> 'mediumlevelil.SSAVariable':
		return self.get_var_ssa(0, 1)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("var", self.var, "SSAVariable"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILVarPhi(HighLevelILInstruction, Phi, SetVar):
	@property
	def dest(self) -> 'mediumlevelil.SSAVariable':
		return self.get_var_ssa(0, 1)

	@property
	def src(self) -> List['mediumlevelil.SSAVariable']:
		return self.get_var_ssa_list(2, 3)

	@property
	def vars_written(self) -> VariablesList:
		return [self.dest]

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
		return self.get_int(0)

	@property
	def src(self) -> List[int]:
		return self.get_int_list(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("dest", self.dest, "int"),
			("src", self.src, "List[int]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILStructField(HighLevelILInstruction):
	@property
	def src(self) -> HighLevelILInstruction:
		return self.get_expr(0)

	@property
	def offset(self) -> int:
		return self.get_int(1)

	@property
	def member_index(self) -> Optional[int]:
		return self.get_member_index(2)

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
		return self.get_expr(0)

	@property
	def index(self) -> HighLevelILInstruction:
		return self.get_expr(1)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("src", self.src, "HighLevelILInstruction"),
			("index", self.index, "HighLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILArrayIndexSsa(HighLevelILInstruction, SSA):
	@property
	def src(self) -> HighLevelILInstruction:
		return self.get_expr(0)

	@property
	def src_memory(self) -> int:
		return self.get_int(1)

	@property
	def index(self) -> HighLevelILInstruction:
		return self.get_expr(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("src", self.src, "HighLevelILInstruction"),
			("src_memory", self.src_memory, "int"),
			("index", self.index, "HighLevelILInstruction"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILSplit(HighLevelILInstruction):
	@property
	def high(self) -> HighLevelILInstruction:
		return self.get_expr(0)

	@property
	def low(self) -> HighLevelILInstruction:
		return self.get_expr(1)

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
		return self.get_expr(0)

	@property
	def offset(self) -> int:
		return self.get_int(1)

	@property
	def member_index(self) -> Optional[int]:
		return self.get_member_index(2)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("src", self.src, "HighLevelILInstruction"),
			("offset", self.offset, "int"),
			("member_index", self.member_index, "Optional[int]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILDerefSsa(HighLevelILInstruction, SSA):
	@property
	def src(self) -> HighLevelILInstruction:
		return self.get_expr(0)

	@property
	def src_memory(self) -> int:
		return self.get_int(1)

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
		return self.get_expr(0)

	@property
	def src_memory(self) -> int:
		return self.get_int(1)

	@property
	def offset(self) -> int:
		return self.get_int(2)

	@property
	def member_index(self) -> Optional[int]:
		return self.get_member_index(3)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("src", self.src, "HighLevelILInstruction"),
			("src_memory", self.src_memory, "int"),
			("offset", self.offset, "int"),
			("member_index", self.member_index, "Optional[int]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILAddressOf(HighLevelILUnaryBase):
	@property
	def vars_address_taken(self) -> VariablesList:
		if isinstance(self.src, (HighLevelILVar, HighLevelILVarSsa)):
			return [self.src.var]
		elif isinstance(self.src, HighLevelILStructField) and isinstance(self.src.src, (HighLevelILVar, HighLevelILVarSsa)):
			return [self.src.src.var]
		return [*self.src.vars_address_taken]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILConst(HighLevelILInstruction, Constant):
	@property
	def constant(self) -> int:
		return self.get_int(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("constant", self.constant, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILConstPtr(HighLevelILInstruction, Constant):
	@property
	def constant(self) -> int:
		return self.get_int(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("constant", self.constant, "int"),
		]

	@property
	def string(self) -> Optional[Tuple[str, StringType]]:
		return self.function.view.check_for_string_annotation_type(self.constant, True, True, 0)


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILExternPtr(HighLevelILInstruction, Constant):
	@property
	def constant(self) -> int:
		return self.get_int(0)

	@property
	def offset(self) -> int:
		return self.get_int(1)

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
		return self.get_float(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("constant", self.constant, "float"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILImport(HighLevelILInstruction, Constant):
	@property
	def constant(self) -> int:
		return self.get_int(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("constant", self.constant, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILConstData(HighLevelILInstruction, Constant):
	@property
	def constant_data(self) -> variable.ConstantData:
		return self.get_constant_data(0, 1)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("constant_data", self.constant_data, "ConstantData"),
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
class HighLevelILRor(HighLevelILCarryBase):
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
class HighLevelILMulsDp(Signed, HighLevelILBinaryBase, DoublePrecision):
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
		return self.get_expr(0)

	@property
	def params(self) -> List[HighLevelILInstruction]:
		return self.get_expr_list(1, 2)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("dest", self.dest, "HighLevelILInstruction"),
			("params", self.params, "List[HighLevelILInstruction]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILCallSsa(HighLevelILInstruction, Localcall, SSA):
	@property
	def dest(self) -> HighLevelILInstruction:
		return self.get_expr(0)

	@property
	def params(self) -> List[HighLevelILInstruction]:
		return self.get_expr_list(1, 2)

	@property
	def dest_memory(self) -> int:
		return self.get_int(3)

	@property
	def src_memory(self) -> int:
		return self.get_int(4)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("dest", self.dest, "HighLevelILInstruction"),
			("params", self.params, "List[HighLevelILInstruction]"),
			("dest_memory", self.dest_memory, "int"),
			("src_memory", self.src_memory, "int"),
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
		return self.get_expr_list(0, 1)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("params", self.params, "List[HighLevelILInstruction]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILSyscallSsa(HighLevelILInstruction, Syscall, SSA):
	@property
	def params(self) -> List[HighLevelILInstruction]:
		return self.get_expr_list(0, 1)

	@property
	def dest_memory(self) -> int:
		return self.get_int(2)

	@property
	def src_memory(self) -> int:
		return self.get_int(3)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("params", self.params, "List[HighLevelILInstruction]"),
			("dest_memory", self.dest_memory, "int"),
			("src_memory", self.src_memory, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILTailcall(HighLevelILInstruction, Tailcall):
	@property
	def dest(self) -> HighLevelILInstruction:
		return self.get_expr(0)

	@property
	def params(self) -> List[HighLevelILInstruction]:
		return self.get_expr_list(1, 2)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("dest", self.dest, "HighLevelILInstruction"),
			("params", self.params, "List[HighLevelILInstruction]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILBp(HighLevelILInstruction, Terminal):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILTrap(HighLevelILInstruction, Terminal):
	@property
	def vector(self) -> int:
		return self.get_int(0)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("vector", self.vector, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILIntrinsic(HighLevelILInstruction, Intrinsic):
	@property
	def intrinsic(self) -> 'lowlevelil.ILIntrinsic':
		return self.get_intrinsic(0)

	@property
	def params(self) -> List[HighLevelILInstruction]:
		return self.get_expr_list(1, 2)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("intrinsic", self.intrinsic, "ILIntrinsic"),
			("params", self.params, "List[HighLevelILInstruction]"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILIntrinsicSsa(HighLevelILInstruction, SSA):
	@property
	def intrinsic(self) -> 'lowlevelil.ILIntrinsic':
		return self.get_intrinsic(0)

	@property
	def params(self) -> List[HighLevelILInstruction]:
		return self.get_expr_list(1, 2)

	@property
	def dest_memory(self) -> int:
		return self.get_int(3)

	@property
	def src_memory(self) -> int:
		return self.get_int(4)

	@property
	def detailed_operands(self) -> List[Tuple[str, HighLevelILOperandType, str]]:
		return [
			("intrinsic", self.intrinsic, "ILIntrinsic"),
			("params", self.params, "List[HighLevelILInstruction]"),
			("dest_memory", self.dest_memory, "int"),
			("src_memory", self.src_memory, "int"),
		]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILUndef(HighLevelILInstruction, Terminal):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILUnimpl(HighLevelILInstruction):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILUnimplMem(HighLevelILUnaryBase, Memory):
	pass


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


ILInstruction = {
    HighLevelILOperation.HLIL_NOP: HighLevelILNop,  #  ,
    HighLevelILOperation.HLIL_BLOCK: HighLevelILBlock,  #  ("body", "expr_list"),
    HighLevelILOperation.HLIL_IF: HighLevelILIf,  #  ("condition", "expr"), ("true", "expr"), ("false", "expr"),
    HighLevelILOperation.HLIL_WHILE: HighLevelILWhile,  #  ("condition", "expr"), ("body", "expr"),
    HighLevelILOperation.HLIL_WHILE_SSA:
        HighLevelILWhileSsa,  #  ("condition_phi", "expr"), ("condition", "expr"), ("body", "expr"),
    HighLevelILOperation.HLIL_DO_WHILE: HighLevelILDoWhile,  #  ("body", "expr"), ("condition", "expr"),
    HighLevelILOperation.HLIL_DO_WHILE_SSA:
        HighLevelILDoWhileSsa,  #  ("body", "expr"), ("condition_phi", "expr"), ("condition", "expr"),
    HighLevelILOperation.HLIL_FOR:
        HighLevelILFor,  #  ("init", "expr"), ("condition", "expr"), ("update", "expr"), ("body", "expr"),
    HighLevelILOperation.HLIL_FOR_SSA:
        HighLevelILForSsa,  #  ("init", "expr"), ("condition_phi", "expr"), ("condition", "expr"), ("update", "expr"), ("body", "expr"),
    HighLevelILOperation.HLIL_SWITCH:
        HighLevelILSwitch,  #  ("condition", "expr"), ("default", "expr"), ("cases", "expr_list"),
    HighLevelILOperation.HLIL_CASE: HighLevelILCase,  #  ("values", "expr_list"), ("body", "expr"),
    HighLevelILOperation.HLIL_BREAK: HighLevelILBreak,  #  ,
    HighLevelILOperation.HLIL_CONTINUE: HighLevelILContinue,  #  ,
    HighLevelILOperation.HLIL_JUMP: HighLevelILJump,  #  ("dest", "expr"),
    HighLevelILOperation.HLIL_RET: HighLevelILRet,  #  ("src", "expr_list"),
    HighLevelILOperation.HLIL_NORET: HighLevelILNoret,  #  ,
    HighLevelILOperation.HLIL_UNREACHABLE: HighLevelILUnreachable,  #  ,
    HighLevelILOperation.HLIL_GOTO: HighLevelILGoto,  #  ("target", "label"),
    HighLevelILOperation.HLIL_LABEL: HighLevelILLabel,  #  ("target", "label"),
    HighLevelILOperation.HLIL_VAR_DECLARE: HighLevelILVarDeclare,  #  ("var", "var"),
    HighLevelILOperation.HLIL_VAR_INIT: HighLevelILVarInit,  #  ("dest", "var"), ("src", "expr"),
    HighLevelILOperation.HLIL_VAR_INIT_SSA: HighLevelILVarInitSsa,  #  ("dest", "var_ssa"), ("src", "expr"),
    HighLevelILOperation.HLIL_ASSIGN: HighLevelILAssign,  #  ("dest", "expr"), ("src", "expr"),
    HighLevelILOperation.HLIL_ASSIGN_UNPACK: HighLevelILAssignUnpack,  #  ("dest", "expr_list"), ("src", "expr"),
    HighLevelILOperation.HLIL_ASSIGN_MEM_SSA:
        HighLevelILAssignMemSsa,  #  ("dest", "expr"), ("dest_memory", "int"), ("src", "expr"), ("src_memory", "int"),
    HighLevelILOperation.HLIL_ASSIGN_UNPACK_MEM_SSA:
        HighLevelILAssignUnpackMemSsa,  #  ("dest", "expr_list"), ("dest_memory", "int"), ("src", "expr"), ("src_memory", "int"),
    HighLevelILOperation.HLIL_VAR: HighLevelILVar,  #  ("var", "var"),
    HighLevelILOperation.HLIL_VAR_SSA: HighLevelILVarSsa,  #  ("var", "var_ssa"),
    HighLevelILOperation.HLIL_VAR_PHI: HighLevelILVarPhi,  #  ("dest", "var_ssa"), ("src", "var_ssa_list"),
    HighLevelILOperation.HLIL_MEM_PHI: HighLevelILMemPhi,  #  ("dest", "int"), ("src", "int_list"),
    HighLevelILOperation.HLIL_ARRAY_INDEX: HighLevelILArrayIndex,  #  ("src", "expr"), ("index", "expr"),
    HighLevelILOperation.HLIL_ARRAY_INDEX_SSA:
        HighLevelILArrayIndexSsa,  #  ("src", "expr"), ("src_memory", "int"), ("index", "expr"),
    HighLevelILOperation.HLIL_SPLIT: HighLevelILSplit,  #  ("high", "expr"), ("low", "expr"),
    HighLevelILOperation.HLIL_DEREF: HighLevelILDeref,  #  ("src", "expr"),
    HighLevelILOperation.HLIL_STRUCT_FIELD:
        HighLevelILStructField,  #  ("src", "expr"), ("offset", "int"), ("member_index", "member_index"),
    HighLevelILOperation.HLIL_DEREF_FIELD:
        HighLevelILDerefField,  #  ("src", "expr"), ("offset", "int"), ("member_index", "member_index"),
    HighLevelILOperation.HLIL_DEREF_SSA: HighLevelILDerefSsa,  #  ("src", "expr"), ("src_memory", "int"),
    HighLevelILOperation.HLIL_DEREF_FIELD_SSA:
        HighLevelILDerefFieldSsa,  #  ("src", "expr"), ("src_memory", "int"), ("offset", "int"), ("member_index", "member_index"),
    HighLevelILOperation.HLIL_ADDRESS_OF: HighLevelILAddressOf,  #  ("src", "expr"),
    HighLevelILOperation.HLIL_CONST: HighLevelILConst,  #  ("constant", "int"),
    HighLevelILOperation.HLIL_CONST_PTR: HighLevelILConstPtr,  #  ("constant", "int"),
    HighLevelILOperation.HLIL_EXTERN_PTR: HighLevelILExternPtr,  #  ("constant", "int"), ("offset", "int"),
    HighLevelILOperation.HLIL_FLOAT_CONST: HighLevelILFloatConst,  #  ("constant", "float"),
    HighLevelILOperation.HLIL_IMPORT: HighLevelILImport,  #  ("constant", "int"),
    HighLevelILOperation.HLIL_CONST_DATA: HighLevelILConstData,  # [("constant_data", "constant_data")],
    HighLevelILOperation.HLIL_ADD: HighLevelILAdd,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_ADC: HighLevelILAdc,  #  ("left", "expr"), ("right", "expr"), ("carry", "expr"),
    HighLevelILOperation.HLIL_SUB: HighLevelILSub,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_SBB: HighLevelILSbb,  #  ("left", "expr"), ("right", "expr"), ("carry", "expr"),
    HighLevelILOperation.HLIL_AND: HighLevelILAnd,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_OR: HighLevelILOr,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_XOR: HighLevelILXor,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_LSL: HighLevelILLsl,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_LSR: HighLevelILLsr,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_ASR: HighLevelILAsr,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_ROL: HighLevelILRol,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_RLC: HighLevelILRlc,  #  ("left", "expr"), ("right", "expr"), ("carry", "expr"),
    HighLevelILOperation.HLIL_ROR: HighLevelILRor,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_RRC: HighLevelILRrc,  #  ("left", "expr"), ("right", "expr"), ("carry", "expr"),
    HighLevelILOperation.HLIL_MUL: HighLevelILMul,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_MULU_DP: HighLevelILMuluDp,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_MULS_DP: HighLevelILMulsDp,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_DIVU: HighLevelILDivu,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_DIVU_DP: HighLevelILDivuDp,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_DIVS: HighLevelILDivs,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_DIVS_DP: HighLevelILDivsDp,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_MODU: HighLevelILModu,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_MODU_DP: HighLevelILModuDp,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_MODS: HighLevelILMods,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_MODS_DP: HighLevelILModsDp,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_NEG: HighLevelILNeg,  #  ("src", "expr"),
    HighLevelILOperation.HLIL_NOT: HighLevelILNot,  #  ("src", "expr"),
    HighLevelILOperation.HLIL_SX: HighLevelILSx,  #  ("src", "expr"),
    HighLevelILOperation.HLIL_ZX: HighLevelILZx,  #  ("src", "expr"),
    HighLevelILOperation.HLIL_LOW_PART: HighLevelILLowPart,  #  ("src", "expr"),
    HighLevelILOperation.HLIL_CALL: HighLevelILCall,  #  ("dest", "expr"), ("params", "expr_list"),
    HighLevelILOperation.HLIL_CALL_SSA:
        HighLevelILCallSsa,  #  ("dest", "expr"), ("params", "expr_list"), ("dest_memory", "int"), ("src_memory", "int"),
    HighLevelILOperation.HLIL_CMP_E: HighLevelILCmpE,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_CMP_NE: HighLevelILCmpNe,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_CMP_SLT: HighLevelILCmpSlt,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_CMP_ULT: HighLevelILCmpUlt,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_CMP_SLE: HighLevelILCmpSle,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_CMP_ULE: HighLevelILCmpUle,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_CMP_SGE: HighLevelILCmpSge,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_CMP_UGE: HighLevelILCmpUge,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_CMP_SGT: HighLevelILCmpSgt,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_CMP_UGT: HighLevelILCmpUgt,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_TEST_BIT: HighLevelILTestBit,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_BOOL_TO_INT: HighLevelILBoolToInt,  #  ("src", "expr"),
    HighLevelILOperation.HLIL_ADD_OVERFLOW: HighLevelILAddOverflow,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_SYSCALL: HighLevelILSyscall,  #  ("params", "expr_list"),
    HighLevelILOperation.HLIL_SYSCALL_SSA:
        HighLevelILSyscallSsa,  #  ("params", "expr_list"), ("dest_memory", "int"), ("src_memory", "int"),
    HighLevelILOperation.HLIL_TAILCALL: HighLevelILTailcall,  #  ("dest", "expr"), ("params", "expr_list"),
    HighLevelILOperation.HLIL_BP: HighLevelILBp,  #  ,
    HighLevelILOperation.HLIL_TRAP: HighLevelILTrap,  #  ("vector", "int"),
    HighLevelILOperation.HLIL_INTRINSIC: HighLevelILIntrinsic,  #  ("intrinsic", "intrinsic"), ("params", "expr_list"),
    HighLevelILOperation.HLIL_INTRINSIC_SSA:
        HighLevelILIntrinsicSsa,  #  ("intrinsic", "intrinsic"), ("params", "expr_list"), ("dest_memory", "int"), ("src_memory", "int"),
    HighLevelILOperation.HLIL_UNDEF: HighLevelILUndef,  #  ,
    HighLevelILOperation.HLIL_UNIMPL: HighLevelILUnimpl,  #  ,
    HighLevelILOperation.HLIL_UNIMPL_MEM: HighLevelILUnimplMem,  #  ("src", "expr"),
    HighLevelILOperation.HLIL_FADD: HighLevelILFadd,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_FSUB: HighLevelILFsub,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_FMUL: HighLevelILFmul,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_FDIV: HighLevelILFdiv,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_FSQRT: HighLevelILFsqrt,  #  ("src", "expr"),
    HighLevelILOperation.HLIL_FNEG: HighLevelILFneg,  #  ("src", "expr"),
    HighLevelILOperation.HLIL_FABS: HighLevelILFabs,  #  ("src", "expr"),
    HighLevelILOperation.HLIL_FLOAT_TO_INT: HighLevelILFloatToInt,  #  ("src", "expr"),
    HighLevelILOperation.HLIL_INT_TO_FLOAT: HighLevelILIntToFloat,  #  ("src", "expr"),
    HighLevelILOperation.HLIL_FLOAT_CONV: HighLevelILFloatConv,  #  ("src", "expr"),
    HighLevelILOperation.HLIL_ROUND_TO_INT: HighLevelILRoundToInt,  #  ("src", "expr"),
    HighLevelILOperation.HLIL_FLOOR: HighLevelILFloor,  #  ("src", "expr"),
    HighLevelILOperation.HLIL_CEIL: HighLevelILCeil,  #  ("src", "expr"),
    HighLevelILOperation.HLIL_FTRUNC: HighLevelILFtrunc,  #  ("src", "expr"),
    HighLevelILOperation.HLIL_FCMP_E: HighLevelILFcmpE,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_FCMP_NE: HighLevelILFcmpNe,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_FCMP_LT: HighLevelILFcmpLt,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_FCMP_LE: HighLevelILFcmpLe,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_FCMP_GE: HighLevelILFcmpGe,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_FCMP_GT: HighLevelILFcmpGt,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_FCMP_O: HighLevelILFcmpO,  #  ("left", "expr"), ("right", "expr"),
    HighLevelILOperation.HLIL_FCMP_UO: HighLevelILFcmpUo,  #  ("left", "expr"), ("right", "expr"),
}


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
		if arch:
			return "<hlil func: %s@%#x>" % (arch.name, self.source_function.start)
		else:
			return "<hlil func: %#x>" % self.source_function.start

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
		"""Root of the abstract syntax tree"""
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

	def get_basic_block_at(self, index: int) -> Optional['basicblock.BasicBlock']:
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
		"""A generator of hlil instructions of the current function"""
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
	    size: int = 0
	) -> ExpressionIndex:
		if isinstance(operation, str):
			operation_value = HighLevelILOperation[operation]
		else:
			assert isinstance(operation, HighLevelILOperation)
			operation_value = operation.value
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
		return self.expr(original.operation, original.raw_operands[0], original.raw_operands[1], original.raw_operands[2], original.raw_operands[3], original.raw_operands[4], original.size)

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
		tc = expr_type._to_core_struct()
		core.BNSetHighLevelILExprType(self.handle, expr_index, tc)


class HighLevelILBasicBlock(basicblock.BasicBlock):
	"""
	The ``HighLevelILBasicBlock`` object is returned during analysis and should not be directly instantiated.
	"""
	def __init__(
	    self, handle: core.BNBasicBlockHandle, owner: HighLevelILFunction, view: Optional['binaryview.BinaryView']
	):
		super(HighLevelILBasicBlock, self).__init__(handle, view)
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
