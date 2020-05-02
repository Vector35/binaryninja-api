# Copyright (c) 2019 Vector 35 Inc
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

# Binary Ninja components
import binaryninja
from binaryninja import _binaryninjacore as core
from binaryninja.enums import HighLevelILOperation, InstructionTextTokenType
from binaryninja import function
from binaryninja import lowlevelil
from binaryninja import mediumlevelil
from binaryninja import basicblock
from binaryninja import types

# 2-3 compatibility
from binaryninja import range


class HighLevelILOperationAndSize(object):
	def __init__(self, operation, size):
		self._operation = operation
		self._size = size

	def __repr__(self):
		if self._size == 0:
			return "<%s>" % self._operation.name
		return "<%s %d>" % (self._operation.name, self._size)

	def __eq__(self, other):
		if isinstance(other, HighLevelILOperation):
			return other == self._operation
		if isinstance(other, self.__class__):
			return other.size == self._size and other.operation == self._operation
		return NotImplemented

	def __ne__(self, other):
		if isinstance(other, self.__class__) or isinstance(other, HighLevelILOperation):
			return not (self == other)
		return NotImplemented

	def __hash__(self):
		return hash((self._operation, self._size))

	@property
	def operation(self):
		""" """
		return self._operation

	@operation.setter
	def operation(self, value):
		self._operation = value

	@property
	def size(self):
		""" """
		return self._size

	@size.setter
	def size(self, value):
		self._size = value


class GotoLabel(object):
	def __init__(self, function, id):
		self._function = function
		self._id = id

	def __repr__(self):
		return "<label: %s>" % self.name

	def __str__(self):
		return self.name

	@property
	def label_id(self):
		return self._id

	@property
	def name(self):
		return core.BNGetGotoLabelName(self._function.source_function.handle, self._id)

	@name.setter
	def name(self, value):
		core.BNSetUserGotoLabelName(self._function.source_function.handle, self._id, value)

	@property
	def definition(self):
		return self._function.get_label(self._id)

	@property
	def uses(self):
		return self._function.get_label_uses(self._id)


class HighLevelILInstruction(object):
	"""
	``class HighLevelILInstruction`` High Level Intermediate Language Instructions form an abstract syntax tree of
	the code. Control flow structures are present as high level constructs in the HLIL tree.
	"""

	ILOperations = {
		HighLevelILOperation.HLIL_NOP: [],
		HighLevelILOperation.HLIL_BLOCK: [("body", "expr_list")],
		HighLevelILOperation.HLIL_IF: [("condition", "expr"), ("true", "expr"), ("false", "expr")],
		HighLevelILOperation.HLIL_WHILE: [("condition", "expr"), ("body", "expr")],
		HighLevelILOperation.HLIL_WHILE_SSA: [("condition_phi", "expr"), ("condition", "expr"), ("body", "expr")],
		HighLevelILOperation.HLIL_DO_WHILE: [("body", "expr"), ("condition", "expr")],
		HighLevelILOperation.HLIL_DO_WHILE_SSA: [("body", "expr"), ("condition_phi", "expr"), ("condition", "expr")],
		HighLevelILOperation.HLIL_FOR: [("init", "expr"), ("condition", "expr"), ("update", "expr"), ("body", "expr")],
		HighLevelILOperation.HLIL_FOR_SSA: [("init", "expr"), ("condition_phi", "expr"), ("condition", "expr"), ("update", "expr"), ("body", "expr")],
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
		HighLevelILOperation.HLIL_VAR_INIT_SSA: [("dest", "var_ssa"), ("src", "expr")],
		HighLevelILOperation.HLIL_ASSIGN: [("dest", "expr"), ("src", "expr")],
		HighLevelILOperation.HLIL_ASSIGN_UNPACK: [("dest", "expr_list"), ("src", "expr")],
		HighLevelILOperation.HLIL_ASSIGN_MEM_SSA: [("dest", "expr"), ("dest_memory", "int"), ("src", "expr"), ("src_memory", "int")],
		HighLevelILOperation.HLIL_ASSIGN_UNPACK_MEM_SSA: [("dest", "expr_list"), ("dest_memory", "int"), ("src", "expr"), ("src_memory", "int")],
		HighLevelILOperation.HLIL_VAR: [("var", "var")],
		HighLevelILOperation.HLIL_VAR_SSA: [("var", "var_ssa")],
		HighLevelILOperation.HLIL_VAR_PHI: [("dest", "var_ssa"), ("src", "var_ssa_list")],
		HighLevelILOperation.HLIL_MEM_PHI: [("dest", "int"), ("src", "int_list")],
		HighLevelILOperation.HLIL_STRUCT_FIELD: [("src", "expr"), ("offset", "int"), ("member_index", "member_index")],
		HighLevelILOperation.HLIL_ARRAY_INDEX: [("src", "expr"), ("index", "expr")],
		HighLevelILOperation.HLIL_ARRAY_INDEX_SSA: [("src", "expr"), ("src_memory", "int"), ("index", "expr")],
		HighLevelILOperation.HLIL_SPLIT: [("high", "expr"), ("low", "expr")],
		HighLevelILOperation.HLIL_DEREF: [("src", "expr")],
		HighLevelILOperation.HLIL_DEREF_FIELD: [("src", "expr"), ("offset", "int"), ("member_index", "member_index")],
		HighLevelILOperation.HLIL_DEREF_SSA: [("src", "expr"), ("src_memory", "int")],
		HighLevelILOperation.HLIL_DEREF_FIELD_SSA: [("src", "expr"), ("src_memory", "int"), ("offset", "int"), ("member_index", "member_index")],
		HighLevelILOperation.HLIL_ADDRESS_OF: [("src", "expr")],
		HighLevelILOperation.HLIL_CONST: [("constant", "int")],
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
		HighLevelILOperation.HLIL_CALL_SSA: [("dest", "expr"), ("params", "expr_list"), ("dest_memory", "int"), ("src_memory", "int")],
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
		HighLevelILOperation.HLIL_SYSCALL_SSA: [("params", "expr_list"), ("dest_memory", "int"), ("src_memory", "int")],
		HighLevelILOperation.HLIL_TAILCALL: [("dest", "expr"), ("params", "expr_list")],
		HighLevelILOperation.HLIL_BP: [],
		HighLevelILOperation.HLIL_TRAP: [("vector", "int")],
		HighLevelILOperation.HLIL_INTRINSIC: [("intrinsic", "intrinsic"), ("params", "expr_list")],
		HighLevelILOperation.HLIL_INTRINSIC_SSA: [("intrinsic", "intrinsic"), ("params", "expr_list"), ("dest_memory", "int"), ("src_memory", "int")],
		HighLevelILOperation.HLIL_UNDEF: [],
		HighLevelILOperation.HLIL_UNIMPL: [],
		HighLevelILOperation.HLIL_UNIMPL_MEM: [("src", "expr")],
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
		HighLevelILOperation.HLIL_FCMP_UO: [("left", "expr"), ("right", "expr")]
	}

	def __init__(self, func, expr_index, as_ast = True, instr_index = None):
		instr = core.BNGetHighLevelILByIndex(func.handle, expr_index, as_ast)
		self._function = func
		self._expr_index = expr_index
		if instr_index is None:
			self._instr_index = core.BNGetHighLevelILInstructionForExpr(func.handle, expr_index)
		else:
			self._instr_index = instr_index
		self._operation = HighLevelILOperation(instr.operation)
		self._size = instr.size
		self._address = instr.address
		self._source_operand = instr.sourceOperand
		self._parent = instr.parent
		self._as_ast = as_ast
		operands = HighLevelILInstruction.ILOperations[instr.operation]
		self._operands = []
		i = 0
		for operand in operands:
			name, operand_type = operand
			if operand_type == "int":
				value = instr.operands[i]
				value = (value & ((1 << 63) - 1)) - (value & (1 << 63))
			elif operand_type == "float":
				if instr.size == 4:
					value = struct.unpack("f", struct.pack("I", instr.operands[i] & 0xffffffff))[0]
				elif instr.size == 8:
					value = struct.unpack("d", struct.pack("Q", instr.operands[i]))[0]
				else:
					value = instr.operands[i]
			elif operand_type == "expr":
				value = HighLevelILInstruction(func, instr.operands[i], self._as_ast)
			elif operand_type == "intrinsic":
				value = lowlevelil.ILIntrinsic(func.arch, instr.operands[i])
			elif operand_type == "var":
				value = function.Variable.from_identifier(self._function.source_function, instr.operands[i])
			elif operand_type == "var_ssa":
				var = function.Variable.from_identifier(self._function.source_function, instr.operands[i])
				version = instr.operands[i + 1]
				i += 1
				value = mediumlevelil.SSAVariable(var, version)
			elif operand_type == "int_list":
				count = ctypes.c_ulonglong()
				operand_list = core.BNHighLevelILGetOperandList(func.handle, self._expr_index, i, count)
				value = []
				for j in range(count.value):
					value.append(operand_list[j])
				core.BNHighLevelILFreeOperandList(operand_list)
			elif operand_type == "expr_list":
				count = ctypes.c_ulonglong()
				operand_list = core.BNHighLevelILGetOperandList(func.handle, self._expr_index, i, count)
				i += 1
				value = []
				for j in range(count.value):
					value.append(HighLevelILInstruction(func, operand_list[j], self._as_ast))
				core.BNHighLevelILFreeOperandList(operand_list)
			elif operand_type == "var_ssa_list":
				count = ctypes.c_ulonglong()
				operand_list = core.BNHighLevelILGetOperandList(func.handle, self._expr_index, i, count)
				i += 1
				value = []
				for j in range(count.value // 2):
					var_id = operand_list[j * 2]
					var_version = operand_list[(j * 2) + 1]
					value.append(mediumlevelil.SSAVariable(function.Variable.from_identifier(self._function.source_function,
						var_id), var_version))
				core.BNHighLevelILFreeOperandList(operand_list)
			elif operand_type == "member_index":
				value = instr.operands[i]
				if (value & (1 << 63)) != 0:
					value = None
			elif operand_type == "label":
				value = GotoLabel(self.function, instr.operands[i])
			self._operands.append(value)
			self.__dict__[name] = value
			i += 1

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
			for token in lines[0].tokens:
				first_line += token.text
			if len(lines) > 1:
				continuation = "..."
		return "<%s: %s%s>" % (self._operation.name, first_line, continuation)

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return (self._function, self._expr_index) == (other._function, other._expr_index)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash((self._function, self._expr_index))

	@property
	def lines(self):
		"""HLIL text lines (read-only)"""
		count = ctypes.c_ulonglong()
		lines = core.BNGetHighLevelILExprText(self._function.handle, self._expr_index, self._as_ast, count)
		result = []
		for i in range(0, count.value):
			addr = lines[i].addr
			if lines[i].instrIndex != 0xffffffffffffffff:
				il_instr = self._function[lines[i].instrIndex]
			else:
				il_instr = None
			color = binaryninja.highlight.HighlightColor._from_core_struct(lines[i].highlight)
			tokens = binaryninja.function.InstructionTextToken.get_instruction_lines(lines[i].tokens, lines[i].count)
			result.append(binaryninja.function.DisassemblyTextLine(tokens, addr, il_instr, color))
		core.BNFreeDisassemblyTextLines(lines, count.value)
		return result

	@property
	def prefix_operands(self):
		"""All operands in the expression tree in prefix order"""
		result = [HighLevelILOperationAndSize(self._operation, self._size)]
		for operand in self._operands:
			if isinstance(operand, HighLevelILInstruction):
				result += operand.prefix_operands
			else:
				result.append(operand)
		return result

	@property
	def postfix_operands(self):
		"""All operands in the expression tree in postfix order"""
		result = []
		for operand in self._operands:
			if isinstance(operand, HighLevelILInstruction):
				result += operand.postfix_operands
			else:
				result.append(operand)
		result.append(HighLevelILOperationAndSize(self._operation, self._size))
		return result

	@property
	def function(self):
		""" """
		return self._function

	@property
	def expr_index(self):
		""" """
		return self._expr_index

	@expr_index.setter
	def expr_index(self, value):
		self._expr_index = value

	@property
	def instr_index(self):
		"""Index of the statement that this expression belongs to (read-only)"""
		return core.BNGetHighLevelILInstructionForExpr(self._function.handle, self._expr_index)

	@property
	def instr(self):
		"""The statement that this expression belongs to (read-only)"""
		return self._function[self.instr_index]

	@property
	def ast(self):
		"""This expression with full AST printing (read-only)"""
		if self._as_ast:
			return self
		return HighLevelILInstruction(self._function, self._expr_index, True)

	@property
	def non_ast(self):
		"""This expression without full AST printing (read-only)"""
		if not self._as_ast:
			return self
		return HighLevelILInstruction(self._function, self._expr_index, False)

	@property
	def operation(self):
		""" """
		return self._operation

	@operation.setter
	def operation(self, value):
		self._operation = value

	@property
	def size(self):
		""" """
		return self._size

	@size.setter
	def size(self, value):
		self._size = value

	@property
	def address(self):
		""" """
		return self._address

	@address.setter
	def address(self, value):
		self._address = value

	@property
	def source_operand(self):
		""" """
		return self._source_operand

	@source_operand.setter
	def source_operand(self, value):
		self._source_operand = value

	@property
	def operands(self):
		""" """
		return self._operands

	@operands.setter
	def operands(self, value):
		self._operands = value

	@property
	def parent(self):
		if self._parent >= core.BNGetHighLevelILExprCount(self._function.handle):
			return None
		return HighLevelILInstruction(self._function, self._parent, self._as_ast)

	@property
	def ssa_form(self):
		"""SSA form of expression (read-only)"""
		return HighLevelILInstruction(self._function.ssa_form,
			core.BNGetHighLevelILSSAExprIndex(self._function.handle, self._expr_index), self._as_ast)

	@property
	def non_ssa_form(self):
		"""Non-SSA form of expression (read-only)"""
		return HighLevelILInstruction(self._function.non_ssa_form,
			core.BNGetHighLevelILNonSSAExprIndex(self._function.handle, self._expr_index), self._as_ast)

	@property
	def medium_level_il(self):
		"""Medium level IL form of this expression"""
		expr = self._function.get_medium_level_il_expr_index(self._expr_index)
		if expr is None:
			return None
		return mediumlevelil.MediumLevelILInstruction(self._function.medium_level_il.ssa_form, expr)

	@property
	def mlil(self):
		"""Alias for medium_level_il"""
		return self.medium_level_il

	@property
	def il_basic_block(self):
		"""IL basic block object containing this expression (read-only) (only available on finalized functions)"""
		return HighLevelILBasicBlock(self._function.source_function.view, core.BNGetHighLevelILBasicBlockForInstruction(self._function.handle, self._instr_index), self._function)

	@property
	def value(self):
		"""Value of expression if constant or a known value (read-only)"""
		mlil = self.mlil
		if mlil is None:
			return function.RegisterValue()
		return mlil.value

	@property
	def possible_values(self):
		"""Possible values of expression using path-sensitive static data flow analysis (read-only)"""
		mlil = self.mlil
		if mlil is None:
			return function.PossibleValueSet()
		return mlil.possible_values

	@property
	def expr_type(self):
		"""Type of expression"""
		result = core.BNGetHighLevelILExprType(self._function.handle, self._expr_index)
		if result.type:
			platform = None
			if self._function.source_function:
				platform = self._function.source_function.platform
			return types.Type(result.type, platform = platform, confidence = result.confidence)
		return None

	def get_possible_values(self, options = []):
		mlil = self.mlil
		if mlil is None:
			return function.RegisterValue()
		return mlil.get_possible_values(options)

	@property
	def ssa_memory_version(self):
		"""Version of active memory contents in SSA form for this instruction"""
		return core.BNGetHighLevelILSSAMemoryVersionAtILInstruction(self._function.handle, self._instr_index)

	def get_ssa_var_version(self, var):
		var_data = core.BNVariable()
		var_data.type = var.source_type
		var_data.index = var.index
		var_data.storage = var.storage
		return core.BNGetHighLevelILSSAVarVersionAtILInstruction(self._function.handle, var_data, self._instr_index)


class HighLevelILExpr(object):
	"""
	``class HighLevelILExpr`` hold the index of IL Expressions.

	.. note:: This class shouldn't be instantiated directly. Rather the helper members of HighLevelILFunction should be \
	used instead.
	"""
	def __init__(self, index):
		self._index = index

	@property
	def index(self):
		""" """
		return self._index

	@index.setter
	def index(self, value):
		self._index = value


class HighLevelILFunction(object):
	"""
	``class HighLevelILFunction`` contains the a HighLevelILInstruction object that makes up the abstract syntax tree of
	a binaryninja.function.
	"""
	def __init__(self, arch = None, handle = None, source_func = None):
		self._arch = arch
		self._source_function = source_func
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNHighLevelILFunction)
			if self._source_function is None:
				self._source_function = binaryninja.function.Function(handle = core.BNGetHighLevelILOwnerFunction(self.handle))
			if self._arch is None:
				self._arch = self._source_function.arch
		else:
			if self._source_function is None:
				self.handle = None
				raise ValueError("IL functions must be created with an associated function")
			if self._arch is None:
				self._arch = self._source_function.arch
			func_handle = self._source_function.handle
			self.handle = core.BNCreateHighLevelILFunction(arch.handle, func_handle)

	def __del__(self):
		if self.handle is not None:
			core.BNFreeHighLevelILFunction(self.handle)

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

	@property
	def current_address(self):
		"""Current IL Address (read/write)"""
		return core.BNHighLevelILGetCurrentAddress(self.handle)

	@current_address.setter
	def current_address(self, value):
		core.BNHighLevelILSetCurrentAddress(self.handle, self._arch.handle, value)

	def set_current_address(self, value, arch = None):
		if arch is None:
			arch = self._arch
		core.BNHighLevelILSetCurrentAddress(self.handle, arch.handle, value)

	@property
	def root(self):
		"""Root of the abstract syntax tree"""
		expr_index = core.BNGetHighLevelILRootExpr(self.handle)
		if expr_index >= core.BNGetHighLevelILExprCount(self.handle):
			return None
		return HighLevelILInstruction(self, expr_index)

	@root.setter
	def root(self, value):
		core.BNSetHighLevelILRootExpr(value.expr_index)

	@property
	def basic_blocks(self):
		"""list of HighLevelILBasicBlock objects (read-only)"""
		count = ctypes.c_ulonglong()
		blocks = core.BNGetHighLevelILBasicBlockList(self.handle, count)
		result = []
		view = None
		if self._source_function is not None:
			view = self._source_function.view
		for i in range(0, count.value):
			result.append(HighLevelILBasicBlock(view, core.BNNewBasicBlockReference(blocks[i]), self))
		core.BNFreeBasicBlockList(blocks, count.value)
		return result

	@property
	def instructions(self):
		"""A generator of hlil instructions of the current function"""
		for block in self.basic_blocks:
			for i in block:
				yield i

	@property
	def ssa_form(self):
		"""High level IL in SSA form (read-only)"""
		result = core.BNGetHighLevelILSSAForm(self.handle)
		if not result:
			return None
		return HighLevelILFunction(self._arch, result, self._source_function)

	@property
	def non_ssa_form(self):
		"""High level IL in non-SSA (default) form (read-only)"""
		result = core.BNGetHighLevelILNonSSAForm(self.handle)
		if not result:
			return None
		return HighLevelILFunction(self._arch, result, self._source_function)

	def get_ssa_instruction_index(self, instr):
		return core.BNGetHighLevelILSSAInstructionIndex(self.handle, instr)

	def get_non_ssa_instruction_index(self, instr):
		return core.BNGetHighLevelILNonSSAInstructionIndex(self.handle, instr)

	def get_ssa_var_definition(self, ssa_var):
		var_data = core.BNVariable()
		var_data.type = ssa_var.var.source_type
		var_data.index = ssa_var.var.index
		var_data.storage = ssa_var.var.storage
		result = core.BNGetHighLevelILSSAVarDefinition(self.handle, var_data, ssa_var.version)
		if result >= core.BNGetHighLevelILExprCount(self.handle):
			return None
		return HighLevelILInstruction(self, result)

	def get_ssa_memory_definition(self, version):
		result = core.BNGetHighLevelILSSAMemoryDefinition(self.handle, version)
		if result >= core.BNGetHighLevelILExprCount(self.handle):
			return None
		return HighLevelILInstruction(self, result)

	def get_ssa_var_uses(self, ssa_var):
		count = ctypes.c_ulonglong()
		var_data = core.BNVariable()
		var_data.type = ssa_var.var.source_type
		var_data.index = ssa_var.var.index
		var_data.storage = ssa_var.var.storage
		instrs = core.BNGetHighLevelILSSAVarUses(self.handle, var_data, ssa_var.version, count)
		result = []
		for i in range(0, count.value):
			result.append(HighLevelILInstruction(self, instrs[i]))
		core.BNFreeILInstructionList(instrs)
		return result

	def get_ssa_memory_uses(self, version):
		count = ctypes.c_ulonglong()
		instrs = core.BNGetHighLevelILSSAMemoryUses(self.handle, version, count)
		result = []
		for i in range(0, count.value):
			result.append(HighLevelILInstruction(self, instrs[i]))
		core.BNFreeILInstructionList(instrs)
		return result

	def is_ssa_var_live(self, ssa_var):
		"""
		``is_ssa_var_live`` determines if ``ssa_var`` is live at any point in the function

		:param SSAVariable ssa_var: the SSA variable to query
		:return: whether the variable is live at any point in the function
		:rtype: bool
		"""
		var_data = core.BNVariable()
		var_data.type = ssa_var.var.source_type
		var_data.index = ssa_var.var.index
		var_data.storage = ssa_var.var.storage
		return core.BNIsHighLevelILSSAVarLive(self.handle, var_data, ssa_var.version)

	def get_var_definitions(self, var):
		count = ctypes.c_ulonglong()
		var_data = core.BNVariable()
		var_data.type = var.source_type
		var_data.index = var.index
		var_data.storage = var.storage
		instrs = core.BNGetHighLevelILVariableDefinitions(self.handle, var_data, count)
		result = []
		for i in range(0, count.value):
			result.append(HighLevelILInstruction(self, instrs[i]))
		core.BNFreeILInstructionList(instrs)
		return result

	def get_var_uses(self, var):
		count = ctypes.c_ulonglong()
		var_data = core.BNVariable()
		var_data.type = var.source_type
		var_data.index = var.index
		var_data.storage = var.storage
		instrs = core.BNGetHighLevelILVariableUses(self.handle, var_data, count)
		result = []
		for i in range(0, count.value):
			result.append(HighLevelILInstruction(self, instrs[i]))
		core.BNFreeILInstructionList(instrs)
		return result

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self, name, value)
		except AttributeError:
			raise AttributeError("attribute '%s' is read only" % name)

	def __len__(self):
		return int(core.BNGetHighLevelILInstructionCount(self.handle))

	def __getitem__(self, i):
		if isinstance(i, slice) or isinstance(i, tuple):
			raise IndexError("expected integer instruction index")
		if isinstance(i, HighLevelILExpr):
			return HighLevelILInstruction(self, i.index)
		# for backwards compatibility
		if isinstance(i, HighLevelILInstruction):
			return i
		if (i < 0) or (i >= len(self)):
			raise IndexError("index out of range")
		return HighLevelILInstruction(self, core.BNGetHighLevelILIndexForInstruction(self.handle, i), False, i)

	def __setitem__(self, i, j):
		raise IndexError("instruction modification not implemented")

	def __iter__(self):
		count = ctypes.c_ulonglong()
		blocks = core.BNGetHighLevelILBasicBlockList(self.handle, count)
		view = None
		if self._source_function is not None:
			view = self._source_function.view
		try:
			for i in range(0, count.value):
				yield HighLevelILBasicBlock(view, core.BNNewBasicBlockReference(blocks[i]), self)
		finally:
			core.BNFreeBasicBlockList(blocks, count.value)

	def __str__(self):
		return str(self.root)

	def expr(self, operation, a = 0, b = 0, c = 0, d = 0, e = 0, size = 0):
		if isinstance(operation, str):
			operation = HighLevelILOperation[operation]
		elif isinstance(operation, HighLevelILOperation):
			operation = operation.value
		return HighLevelILExpr(core.BNHighLevelILAddExpr(self.handle, operation, size, a, b, c, d, e))

	def append(self, expr):
		"""
		``append`` adds the HighLevelILExpr ``expr`` to the current HighLevelILFunction.

		:param HighLevelILExpr expr: the HighLevelILExpr to add to the current HighLevelILFunction
		:return: number of HighLevelILExpr in the current function
		:rtype: int
		"""
		return core.BNHighLevelILAddInstruction(self.handle, expr.index)

	def add_operand_list(self, operands):
		"""
		``add_operand_list`` returns an operand list expression for the given list of integer operands.

		:param list(int) operands: list of operand numbers
		:return: an operand list expression
		:rtype: HighLevelILExpr
		"""
		operand_list = (ctypes.c_ulonglong * len(operands))()
		for i in range(len(operands)):
			operand_list[i] = operands[i]
		return HighLevelILExpr(core.BNHighLevelILAddOperandList(self.handle, operand_list, len(operands)))

	def operand(self, n, expr):
		"""
		``operand`` sets the operand number of the expression ``expr`` and passes back ``expr`` without modification.

		:param int n:
		:param HighLevelILExpr expr:
		:return: returns the expression ``expr`` unmodified
		:rtype: HighLevelILExpr
		"""
		core.BNHighLevelILSetExprSourceOperand(self.handle, expr.index, n)
		return expr

	def finalize(self):
		"""
		``finalize`` ends the function and computes the list of basic blocks.

		:rtype: None
		"""
		core.BNFinalizeHighLevelILFunction(self.handle)

	def create_graph(self, settings = None):
		if settings is not None:
			settings_obj = settings.handle
		else:
			settings_obj = None
		return binaryninja.flowgraph.CoreFlowGraph(core.BNCreateHighLevelILFunctionGraph(self.handle, settings_obj))

	@property
	def arch(self):
		""" """
		return self._arch

	@arch.setter
	def arch(self, value):
		self._arch = value

	@property
	def source_function(self):
		""" """
		return self._source_function

	@source_function.setter
	def source_function(self, value):
		self._source_function = value

	@property
	def medium_level_il(self):
		"""Medium level IL for this function"""
		result = core.BNGetMediumLevelILForHighLevelILFunction(self.handle)
		if not result:
			return None
		return mediumlevelil.MediumLevelILFunction(self._arch, result, self._source_function)

	@property
	def mlil(self):
		"""Alias for medium_level_il"""
		return self.medium_level_il

	def get_medium_level_il_expr_index(self, expr):
		medium_il = self.medium_level_il
		if medium_il is None:
			return None
		medium_il = medium_il.ssa_form
		if medium_il is None:
			return None
		result = core.BNGetMediumLevelILExprIndexFromHighLevelIL(self.handle, expr)
		if result >= core.BNGetMediumLevelILExprCount(medium_il.handle):
			return None
		return result

	def get_label(self, label_idx):
		result = core.BNGetHighLevelILExprIndexForLabel(self.handle, label_idx)
		if result >= core.BNGetHighLevelILExprCount(self.handle):
			return None
		return HighLevelILInstruction(self, result)

	def get_label_uses(self, label_idx):
		count = ctypes.c_ulonglong()
		uses = core.BNGetHighLevelILUsesForLabel(self.handle, label_idx, count)
		result = []
		for i in range(0, count.value):
			result.append(HighLevelILInstruction(self, uses[i]))
		core.BNFreeILInstructionList(uses)
		return result


class HighLevelILBasicBlock(basicblock.BasicBlock):
	def __init__(self, view, handle, owner):
		super(HighLevelILBasicBlock, self).__init__(handle, view)
		self.il_function = owner

	def __iter__(self):
		for idx in range(self.start, self.end):
			yield self.il_function[idx]

	def __getitem__(self, idx):
		size = self.end - self.start
		if idx > size or idx < -size:
			raise IndexError("list index is out of range")
		if idx >= 0:
			return self.il_function[idx + self.start]
		else:
			return self.il_function[self.end + idx]

	def _create_instance(self, handle, view):
		"""Internal method by super to instantiate child instances"""
		return HighLevelILBasicBlock(view, handle, self.il_function)

	def __hash__(self):
		return hash((self.start, self.end, self.il_function))

	def __contains__(self, instruction):
		if type(instruction) != HighLevelILInstruction or instruction.il_basic_block != self:
			return False
		if instruction.instr_index >= self.start and instruction.instr_index <= self.end:
			return True
		else:
			return False

	@property
	def il_function(self):
		""" """
		return self._il_function

	@il_function.setter
	def il_function(self, value):
		self._il_function = value
