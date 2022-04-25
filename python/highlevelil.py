# Copyright (c) 2019-2022 Vector 35 Inc
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
from typing import Optional, Generator, List, Union, NewType, Tuple, ClassVar, Mapping
from dataclasses import dataclass
from enum import Enum

# Binary Ninja components
from . import _binaryninjacore as core
from .enums import HighLevelILOperation, DataFlowQueryOption, FunctionGraphType
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
from .interaction import show_graph_report
from .commonil import (
    BaseILInstruction, Tailcall, Syscall, Localcall, Comparison, Signed, UnaryOperation, BinaryOperation, SSA, Phi,
    Loop, ControlFlow, Memory, Constant, Arithmetic, DoublePrecision, Terminal, FloatingPoint, Intrinsic
)

LinesType = Generator['function.DisassemblyTextLine', None, None]
ExpressionIndex = NewType('ExpressionIndex', int)
InstructionIndex = NewType('InstructionIndex', int)
HLILInstructionsType = Generator['HighLevelILInstruction', None, None]
HLILBasicBlocksType = Generator['HighLevelILBasicBlock', None, None]
OperandsType = Tuple[ExpressionIndex, ExpressionIndex, ExpressionIndex, ExpressionIndex, ExpressionIndex]
HighLevelILOperandType = Union['HighLevelILInstruction', 'lowlevelil.ILIntrinsic', 'variable.Variable',
                               'mediumlevelil.SSAVariable', List[int], List['variable.Variable'],
                               List['mediumlevelil.SSAVariable'], List['HighLevelILInstruction'], Optional[int], float,
                               'GotoLabel']
VariablesList = List[Union['mediumlevelil.SSAVariable', 'variable.Variable']]


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
			return f"<{self.operation.name}>"
		return f"<{self.operation.name} {self.size}>"


@dataclass(frozen=True)
class GotoLabel:
	function: 'HighLevelILFunction'
	id: int

	def __repr__(self):
		return f"<label: {self.name}>"

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
	source_operand: int
	size: int
	operands: OperandsType
	address: int
	parent: ExpressionIndex

	@classmethod
	def from_BNHighLevelILInstruction(cls, instr: core.BNHighLevelILInstruction) -> 'CoreHighLevelILInstruction':
		operands: OperandsType = tuple([ExpressionIndex(instr.operands[i]) for i in range(5)])  # type: ignore
		return cls(
		    HighLevelILOperation(instr.operation), instr.sourceOperand, instr.size, operands, instr.address,
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
		lines = self.lines
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
		lines = self.lines
		continuation = ""
		if lines is None:
			first_line = "<invalid>"
		else:
			first_line = ""
			for token in next(lines).tokens:
				first_line += token.text
			if len(list(lines)) > 1:
				continuation = "..."
		return f"<{self.operation.name}: {first_line}{continuation}>"

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
	def lines(self) -> LinesType:
		"""HLIL text lines (read-only)"""
		count = ctypes.c_ulonglong()
		lines = core.BNGetHighLevelILExprText(self.function.handle, self.expr_index, self.as_ast, count, None)
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
			    core.BNNewTypeReference(result.type), platform=platform, confidence=result.confidence
			)
		return None

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

	def get_expr(self, operand_index: int) -> 'HighLevelILInstruction':
		return HighLevelILInstruction.create(self.function, ExpressionIndex(self.core_instr.operands[operand_index]))

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
	def operands(self) -> List[HighLevelILOperandType]:
		return []


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILUnaryBase(HighLevelILInstruction, UnaryOperation):
	@property
	def src(self) -> HighLevelILInstruction:
		return self.get_expr(0)

	@property
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.src]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILBinaryBase(HighLevelILInstruction, BinaryOperation):
	@property
	def left(self) -> HighLevelILInstruction:
		return self.get_expr(0)

	@property
	def right(self) -> HighLevelILInstruction:
		return self.get_expr(1)

	@property
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.left, self.right]


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
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.left, self.right, self.carry]


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
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.condition]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILWhile(HighLevelILInstruction, Loop):
	@property
	def condition(self) -> HighLevelILInstruction:
		return self.get_expr(0)

	@property
	def body(self) -> HighLevelILInstruction:
		return self.get_expr(1)

	@property
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.condition]


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
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.condition_phi, self.condition]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILDoWhile(HighLevelILInstruction, Loop):
	@property
	def body(self) -> HighLevelILInstruction:
		return self.get_expr(0)

	@property
	def condition(self) -> HighLevelILInstruction:
		return self.get_expr(1)

	@property
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.condition]


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
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.condition_phi, self.condition]


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
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.init, self.condition, self.update]


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
		return self.get_expr(3)

	@property
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.init, self.condition_phi, self.condition, self.update]


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
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.condition]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILCase(HighLevelILInstruction):
	@property
	def values(self) -> List[HighLevelILInstruction]:
		return self.get_expr_list(0, 1)

	@property
	def body(self) -> HighLevelILInstruction:
		return self.get_expr(2)

	@property
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.values]


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
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.dest]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILRet(HighLevelILInstruction, ControlFlow):
	@property
	def src(self) -> List[HighLevelILInstruction]:
		return self.get_expr_list(0, 1)

	@property
	def operands(self) -> List[HighLevelILInstruction]:
		return self.src


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILNoret(HighLevelILInstruction, Terminal):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILGoto(HighLevelILInstruction, Terminal):
	@property
	def target(self) -> GotoLabel:
		return self.get_label(0)

	@property
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.target]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILLabel(HighLevelILInstruction):
	@property
	def target(self) -> GotoLabel:
		return self.get_label(0)

	@property
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.target]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILVarDeclare(HighLevelILInstruction):
	@property
	def var(self) -> 'variable.Variable':
		return self.get_var(0)

	@property
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.var]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILVarInit(HighLevelILInstruction):
	@property
	def dest(self) -> 'variable.Variable':
		return self.get_var(0)

	@property
	def src(self) -> HighLevelILInstruction:
		return self.get_expr(1)

	@property
	def vars_written(self) -> VariablesList:
		return [self.dest]

	@property
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.dest, self.src]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILVarInitSsa(HighLevelILInstruction, SSA):
	@property
	def dest(self) -> 'mediumlevelil.SSAVariable':
		return self.get_var_ssa(0, 1)

	@property
	def src(self) -> HighLevelILInstruction:
		return self.get_expr(2)

	@property
	def vars_written(self) -> VariablesList:
		return [self.dest]

	@property
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.dest, self.src]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILAssign(HighLevelILInstruction):
	@property
	def dest(self) -> HighLevelILInstruction:
		return self.get_expr(0)

	@property
	def src(self) -> HighLevelILInstruction:
		return self.get_expr(1)

	@property
	def vars_written(self) -> VariablesList:
		if isinstance(self.dest, (HighLevelILSplit, HighLevelILVar)):
			return [*self.dest.vars, *self.src.vars_written]
		elif isinstance(self.dest, HighLevelILStructField):
			return [*self.dest.vars, *self.src.vars_written]
		else:
			return [*self.dest.vars_written, *self.src.vars_written]

	@property
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.dest, self.src]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILAssignUnpack(HighLevelILInstruction):
	@property
	def dest(self) -> List[HighLevelILInstruction]:
		return self.get_expr_list(0, 1)

	@property
	def src(self) -> HighLevelILInstruction:
		return self.get_expr(2)

	@property
	def vars_written(self) -> VariablesList:
		result = []
		for i in self.dest:
			if isinstance(i, HighLevelILVar):
				result.append(i.var)
			else:
				result.extend(i.vars_written)
		return result

	@property
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.dest, self.src]


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
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.dest, self.dest_memory, self.src, self.src_memory]


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
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.dest, self.dest_memory, self.src, self.src_memory]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILVar(HighLevelILInstruction):
	@property
	def var(self) -> 'variable.Variable':
		return self.get_var(0)

	@property
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.var]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILVarSsa(HighLevelILInstruction, SSA):
	@property
	def var(self) -> 'mediumlevelil.SSAVariable':
		return self.get_var_ssa(0, 1)

	@property
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.var]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILVarPhi(HighLevelILInstruction, Phi):
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
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.dest, self.src]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILMemPhi(HighLevelILInstruction, Memory, Phi):
	@property
	def dest(self) -> int:
		return self.get_int(0)

	@property
	def src(self) -> List[int]:
		return self.get_int_list(1)

	@property
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.dest, self.src]


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
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.src, self.offset, self.member_index]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILArrayIndex(HighLevelILInstruction):
	@property
	def src(self) -> HighLevelILInstruction:
		return self.get_expr(0)

	@property
	def index(self) -> HighLevelILInstruction:
		return self.get_expr(1)

	@property
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.src, self.index]


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
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.src, self.src_memory, self.index]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILSplit(HighLevelILInstruction):
	@property
	def high(self) -> HighLevelILInstruction:
		return self.get_expr(0)

	@property
	def low(self) -> HighLevelILInstruction:
		return self.get_expr(1)

	@property
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.high, self.low]


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
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.src, self.offset, self.member_index]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILDerefSsa(HighLevelILInstruction, SSA):
	@property
	def src(self) -> HighLevelILInstruction:
		return self.get_expr(0)

	@property
	def src_memory(self) -> int:
		return self.get_int(1)

	@property
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.src, self.src_memory]


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
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.src, self.src_memory, self.offset, self.member_index]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILAddressOf(HighLevelILUnaryBase):
	@property
	def vars_address_taken(self) -> VariablesList:
		if isinstance(self.src, HighLevelILVar):
			return [self.src.var]
		elif isinstance(self.src, HighLevelILStructField) and isinstance(self.src.src, HighLevelILVar):
			return [self.src.src.var]
		return [*self.src.vars_address_taken]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILConst(HighLevelILInstruction, Constant):
	@property
	def constant(self) -> int:
		return self.get_int(0)

	@property
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.constant]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILConstPtr(HighLevelILInstruction, Constant):
	@property
	def constant(self) -> int:
		return self.get_int(0)

	@property
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.constant]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILExternPtr(HighLevelILInstruction, Constant):
	@property
	def constant(self) -> int:
		return self.get_int(0)

	@property
	def offset(self) -> int:
		return self.get_int(1)

	@property
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.constant, self.offset]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILFloatConst(HighLevelILInstruction, Constant):
	@property
	def constant(self) -> float:
		return self.get_float(0)

	@property
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.constant]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILImport(HighLevelILInstruction, Constant):
	@property
	def constant(self) -> int:
		return self.get_int(0)

	@property
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.constant]


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
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.dest, self.params]


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
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.dest, self.params, self.dest_memory, self.src_memory]


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
	def operands(self) -> List[HighLevelILInstruction]:
		return self.params


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
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.params, self.dest_memory, self.src_memory]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILTailcall(HighLevelILInstruction, Tailcall):
	@property
	def dest(self) -> HighLevelILInstruction:
		return self.get_expr(0)

	@property
	def params(self) -> List[HighLevelILInstruction]:
		return self.get_expr_list(1, 2)

	@property
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.dest, self.params]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILBp(HighLevelILInstruction, Terminal):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILTrap(HighLevelILInstruction, Terminal):
	@property
	def vector(self) -> int:
		return self.get_int(0)

	@property
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.vector]


@dataclass(frozen=True, repr=False, eq=False)
class HighLevelILIntrinsic(HighLevelILInstruction, Intrinsic):
	@property
	def intrinsic(self) -> 'lowlevelil.ILIntrinsic':
		return self.get_intrinsic(0)

	@property
	def params(self) -> List[HighLevelILInstruction]:
		return self.get_expr_list(1, 2)

	@property
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.intrinsic, self.params]


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
		return self.get_int(2)

	@property
	def src_memory(self) -> int:
		return self.get_int(3)

	@property
	def operands(self) -> List[HighLevelILOperandType]:
		return [self.intrinsic, self.params, self.dest_memory, self.src_memory]


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


class HighLevelILExpr:
	"""
	``class HighLevelILExpr`` hold the index of IL Expressions.

	.. note:: Deprecated. Use ExpressionIndex instead
	"""
	def __init__(self, index: ExpressionIndex):
		self._index = index

	def __int__(self):
		return self._index

	@property
	def index(self) -> ExpressionIndex:
		return self._index


class HighLevelILFunction:
	"""
	``class HighLevelILFunction`` contains the a HighLevelILInstruction object that makes up the abstract syntax tree of
	a function.
	"""
	def __init__(
	    self, arch: Optional['architecture.Architecture'] = None, handle: core.BNHighLevelILFunction = None,
	    source_func: 'function.Function' = None
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

	def __getitem__(self, i: Union[HighLevelILExpr, int]) -> HighLevelILInstruction:
		if isinstance(i, slice) or isinstance(i, tuple):
			raise IndexError("expected integer instruction index")
		if isinstance(i, HighLevelILExpr):
			return HighLevelILInstruction.create(self, i.index)
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

	def get_ssa_var_definition(self, ssa_var: 'mediumlevelil.SSAVariable') -> Optional[HighLevelILInstruction]:
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

	def get_ssa_var_uses(self, ssa_var: 'mediumlevelil.SSAVariable') -> List[HighLevelILInstruction]:
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

	def create_graph(self, settings: 'function.DisassemblySettings' = None) -> 'flowgraph.CoreFlowGraph':
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
	def vars(self) -> List["variable.Variable"]:
		"""This gets just the HLIL variables - you may be interested in the union of `HighLevelIlFunction.source_function.param_vars` and `HighLevelIlFunction.aliased_vars` as well for all the variables used in the function"""
		if self.source_function is None:
			return []

		if self.il_form in [
		    FunctionGraphType.HighLevelILFunctionGraph, FunctionGraphType.HighLevelILSSAFormFunctionGraph
		]:
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
		"""This returns a list of Variables that are taken reference to and used elsewhere.  You may also wish to consider `HighLevelIlFunction.vars` and `HighLevelIlFunction.source_function.param_vars`"""
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
		"""This gets just the HLIL SSA variables - you may be interested in the union of `HighLevelIlFunction.source_function.param_vars` and `HighLevelIlFunction.aliased_vars` for all the variables used in the function"""
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

	def __getitem__(self, idx) -> Union[List[HighLevelILInstruction], HighLevelILInstruction]:
		size = self.end - self.start
		if isinstance(idx, slice):
			return [self[index] for index in range(*idx.indices(size))]  # type: ignore
		if idx > size or idx < -size:
			raise IndexError("list index is out of range")
		if idx >= 0:
			return self.il_function[idx + self.start]
		else:
			return self.il_function[self.end + idx]

	def _create_instance(self, handle: core.BNBasicBlockHandle, view: 'binaryview.BinaryView'):
		"""Internal method by super to instantiate child instances"""
		return HighLevelILBasicBlock(handle, self.il_function, view)

	def __hash__(self):
		return hash((self.start, self.end, self.il_function))

	def __contains__(self, instruction):
		if not isinstance(instruction, HighLevelILInstruction) or instruction.il_basic_block != self:
			return False
		if self.start <= instruction.instr_index <= self.end:
			return True
		else:
			return False

	@property
	def instruction_count(self) -> int:
		return self.end - self.start

	@property
	def il_function(self) -> HighLevelILFunction:
		return self._il_function
