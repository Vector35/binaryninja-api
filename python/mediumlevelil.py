# Copyright (c) 2018-2020 Vector 35 Inc
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
from binaryninja.enums import MediumLevelILOperation, InstructionTextTokenType, ILBranchDependence, DataFlowQueryOption
from binaryninja import basicblock #required for MediumLevelILBasicBlock argument
from binaryninja import function
from binaryninja import types
from binaryninja import lowlevelil

# 2-3 compatibility
from binaryninja import range


class SSAVariable(object):
	def __init__(self, var, version):
		self._var = var
		self._version = version

	def __repr__(self):
		return "<ssa %s version %d>" % (repr(self._var), self._version)

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return (self._var, self._version) == (other.var, other.version)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash((self._var, self._version))

	@property
	def var(self):
		""" """
		return self._var

	@var.setter
	def var(self, value):
		self._var = value

	@property
	def version(self):
		""" """
		return self._version

	@version.setter
	def version(self, value):
		self._version = value


class MediumLevelILLabel(object):
	def __init__(self, handle = None):
		if handle is None:
			self.handle = (core.BNMediumLevelILLabel * 1)()
			core.BNMediumLevelILInitLabel(self.handle)
		else:
			self.handle = handle


class MediumLevelILOperationAndSize(object):
	def __init__(self, operation, size):
		self._operation = operation
		self._size = size

	def __repr__(self):
		if self._size == 0:
			return "<%s>" % self._operation.name
		return "<%s %d>" % (self._operation.name, self._size)

	def __eq__(self, other):
		if isinstance(other, MediumLevelILOperation):
			return other == self._operation
		if isinstance(other, self.__class__):
			return (other.size, other.operation) == (self._size, self._operation)
		return NotImplemented

	def __ne__(self, other):
		if isinstance(other, MediumLevelILOperation) or isinstance(other, self.__class__):
			return not (self == other)
		return NotImplemented

	def __hash__(self):
		return hash((self._operation, self._size))

	@property
	def operation(self):
		""" """
		return self._operation

	@property
	def size(self):
		""" """
		return self._size


class MediumLevelILInstruction(object):
	"""
	``class MediumLevelILInstruction`` Medium Level Intermediate Language Instructions are infinite length tree-based
	instructions. Tree-based instructions use infix notation with the left hand operand being the destination operand.
	Infix notation is thus more natural to read than other notations (e.g. x86 ``mov eax, 0`` vs. MLIL ``eax = 0``).
	"""

	ILOperations = {
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

	def __init__(self, func, expr_index, instr_index=None):
		instr = core.BNGetMediumLevelILByIndex(func.handle, expr_index)
		self._function = func
		self._expr_index = expr_index
		if instr_index is None:
			self._instr_index = core.BNGetMediumLevelILInstructionForExpr(func.handle, expr_index)
		else:
			self._instr_index = instr_index
		self._operation = MediumLevelILOperation(instr.operation)
		self._size = instr.size
		self._address = instr.address
		self._source_operand = instr.sourceOperand
		operands = MediumLevelILInstruction.ILOperations[instr.operation]
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
				value = MediumLevelILInstruction(func, instr.operands[i])
			elif operand_type == "intrinsic":
				value = lowlevelil.ILIntrinsic(func.arch, instr.operands[i])
			elif operand_type == "var":
				value = function.Variable.from_identifier(self._function.source_function, instr.operands[i])
			elif operand_type == "var_ssa":
				var = function.Variable.from_identifier(self._function.source_function, instr.operands[i])
				version = instr.operands[i + 1]
				i += 1
				value = SSAVariable(var, version)
			elif operand_type == "var_ssa_dest_and_src":
				var = function.Variable.from_identifier(self._function.source_function, instr.operands[i])
				dest_version = instr.operands[i + 1]
				src_version = instr.operands[i + 2]
				i += 2
				self._operands.append(SSAVariable(var, dest_version))
				#TODO: documentation for dest
				self.dest = SSAVariable(var, dest_version)
				value = SSAVariable(var, src_version)
			elif operand_type == "int_list":
				count = ctypes.c_ulonglong()
				operand_list = core.BNMediumLevelILGetOperandList(func.handle, self._expr_index, i, count)
				value = []
				for j in range(count.value):
					value.append(operand_list[j])
				core.BNMediumLevelILFreeOperandList(operand_list)
			elif operand_type == "var_list":
				count = ctypes.c_ulonglong()
				operand_list = core.BNMediumLevelILGetOperandList(func.handle, self._expr_index, i, count)
				i += 1
				value = []
				for j in range(count.value):
					value.append(function.Variable.from_identifier(self._function.source_function, operand_list[j]))
				core.BNMediumLevelILFreeOperandList(operand_list)
			elif operand_type == "var_ssa_list":
				count = ctypes.c_ulonglong()
				operand_list = core.BNMediumLevelILGetOperandList(func.handle, self._expr_index, i, count)
				i += 1
				value = []
				for j in range(count.value // 2):
					var_id = operand_list[j * 2]
					var_version = operand_list[(j * 2) + 1]
					value.append(SSAVariable(function.Variable.from_identifier(self._function.source_function,
						var_id), var_version))
				core.BNMediumLevelILFreeOperandList(operand_list)
			elif operand_type == "expr_list":
				count = ctypes.c_ulonglong()
				operand_list = core.BNMediumLevelILGetOperandList(func.handle, self._expr_index, i, count)
				i += 1
				value = []
				for j in range(count.value):
					value.append(MediumLevelILInstruction(func, operand_list[j]))
				core.BNMediumLevelILFreeOperandList(operand_list)
			elif operand_type == "target_map":
				count = ctypes.c_ulonglong()
				operand_list = core.BNMediumLevelILGetOperandList(func.handle, self._expr_index, i, count)
				i += 1
				value = {}
				for j in range(count.value // 2):
					key = operand_list[j * 2]
					target = operand_list[(j * 2) + 1]
					value[key] = target
				core.BNMediumLevelILFreeOperandList(operand_list)
			self._operands.append(value)
			self.__dict__[name] = value
			i += 1

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

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self._function == other.function and self._expr_index == other.expr_index

	def __lt__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self._function == other.function and self.expr_index < other.expr_index

	def __le__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self._function == other.function and self.expr_index <= other.expr_index

	def __gt__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self._function == other.function and self.expr_index > other.expr_index

	def __ge__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self._function == other.function and self.expr_index >= other.expr_index

	def __hash__(self):
		return hash((self._instr_index, self._function))

	@property
	def tokens(self):
		"""MLIL tokens (read-only)"""
		count = ctypes.c_ulonglong()
		tokens = ctypes.POINTER(core.BNInstructionTextToken)()
		if ((self._instr_index is not None) and (self._function.source_function is not None) and
			(self._expr_index == core.BNGetMediumLevelILIndexForInstruction(self._function.handle, self._instr_index))):
			if not core.BNGetMediumLevelILInstructionText(self._function.handle, self._function.source_function.handle,
				self._function.arch.handle, self._instr_index, tokens, count):
				return None
		else:
			if not core.BNGetMediumLevelILExprText(self._function.handle, self._function.arch.handle,
				self._expr_index, tokens, count):
				return None
		result = binaryninja.function.InstructionTextToken.get_instruction_lines(tokens, count.value)
		core.BNFreeInstructionText(tokens, count.value)
		return result

	@property
	def il_basic_block(self):
		"""IL basic block object containing this expression (read-only) (only available on finalized functions)"""
		return MediumLevelILBasicBlock(self._function.source_function.view, core.BNGetMediumLevelILBasicBlockForInstruction(self._function.handle, self._instr_index), self._function)

	@property
	def ssa_form(self):
		"""SSA form of expression (read-only)"""
		return MediumLevelILInstruction(self._function.ssa_form,
			core.BNGetMediumLevelILSSAExprIndex(self._function.handle, self._expr_index))

	@property
	def non_ssa_form(self):
		"""Non-SSA form of expression (read-only)"""
		return MediumLevelILInstruction(self._function.non_ssa_form,
			core.BNGetMediumLevelILNonSSAExprIndex(self._function.handle, self._expr_index))

	@property
	def value(self):
		"""Value of expression if constant or a known value (read-only)"""
		value = core.BNGetMediumLevelILExprValue(self._function.handle, self._expr_index)
		result = function.RegisterValue(self._function.arch, value)
		return result

	@property
	def possible_values(self):
		"""Possible values of expression using path-sensitive static data flow analysis (read-only)"""
		value = core.BNGetMediumLevelILPossibleExprValues(self._function.handle, self._expr_index, None, 0)
		result = function.PossibleValueSet(self._function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	@property
	def branch_dependence(self):
		"""Set of branching instructions that must take the true or false path to reach this instruction"""
		count = ctypes.c_ulonglong()
		deps = core.BNGetAllMediumLevelILBranchDependence(self._function.handle, self._instr_index, count)
		result = {}
		for i in range(0, count.value):
			result[deps[i].branch] = ILBranchDependence(deps[i].dependence)
		core.BNFreeILBranchDependenceList(deps)
		return result

	@property
	def low_level_il(self):
		"""Low level IL form of this expression"""
		expr = self._function.get_low_level_il_expr_index(self._expr_index)
		if expr is None:
			return None
		return lowlevelil.LowLevelILInstruction(self._function.low_level_il.ssa_form, expr)

	@property
	def llil(self):
		"""Alias for low_level_il"""
		return self.low_level_il

	@property
	def ssa_memory_version(self):
		"""Version of active memory contents in SSA form for this instruction"""
		return core.BNGetMediumLevelILSSAMemoryVersionAtILInstruction(self._function.handle, self._instr_index)

	@property
	def prefix_operands(self):
		"""All operands in the expression tree in prefix order"""
		result = [MediumLevelILOperationAndSize(self._operation, self._size)]
		for operand in self._operands:
			if isinstance(operand, MediumLevelILInstruction):
				result += operand.prefix_operands
			else:
				result.append(operand)
		return result

	@property
	def postfix_operands(self):
		"""All operands in the expression tree in postfix order"""
		result = []
		for operand in self._operands:
			if isinstance(operand, MediumLevelILInstruction):
				result += operand.postfix_operands
			else:
				result.append(operand)
		result.append(MediumLevelILOperationAndSize(self._operation, self._size))
		return result

	@property
	def vars_written(self):
		"""List of variables written by instruction"""
		if self._operation in [MediumLevelILOperation.MLIL_SET_VAR, MediumLevelILOperation.MLIL_SET_VAR_FIELD,
			MediumLevelILOperation.MLIL_SET_VAR_SSA, MediumLevelILOperation.MLIL_SET_VAR_SSA_FIELD,
			MediumLevelILOperation.MLIL_SET_VAR_ALIASED, MediumLevelILOperation.MLIL_SET_VAR_ALIASED_FIELD,
			MediumLevelILOperation.MLIL_VAR_PHI]:
			return [self.dest]
		elif self._operation in [MediumLevelILOperation.MLIL_SET_VAR_SPLIT, MediumLevelILOperation.MLIL_SET_VAR_SPLIT_SSA]:
			return [self.high, self.low]
		elif self._operation in [MediumLevelILOperation.MLIL_CALL, MediumLevelILOperation.MLIL_SYSCALL, MediumLevelILOperation.MLIL_TAILCALL]:
			return self.output
		elif self._operation in [MediumLevelILOperation.MLIL_CALL_UNTYPED, MediumLevelILOperation.MLIL_SYSCALL_UNTYPED, MediumLevelILOperation.MLIL_TAILCALL_UNTYPED,
			MediumLevelILOperation.MLIL_CALL_SSA, MediumLevelILOperation.MLIL_CALL_UNTYPED_SSA,
			MediumLevelILOperation.MLIL_SYSCALL_SSA, MediumLevelILOperation.MLIL_SYSCALL_UNTYPED_SSA,
			MediumLevelILOperation.MLIL_TAILCALL_SSA, MediumLevelILOperation.MLIL_TAILCALL_UNTYPED_SSA]:
			return self.output.vars_written
		elif self._operation in [MediumLevelILOperation.MLIL_CALL_OUTPUT, MediumLevelILOperation.MLIL_CALL_OUTPUT_SSA]:
			return self.dest
		return []

	@property
	def vars_read(self):
		"""List of variables read by instruction"""
		if self._operation in [MediumLevelILOperation.MLIL_SET_VAR, MediumLevelILOperation.MLIL_SET_VAR_FIELD,
			MediumLevelILOperation.MLIL_SET_VAR_SPLIT, MediumLevelILOperation.MLIL_SET_VAR_SSA,
			MediumLevelILOperation.MLIL_SET_VAR_SPLIT_SSA, MediumLevelILOperation.MLIL_SET_VAR_ALIASED]:
			return self.src.vars_read
		elif self._operation in [MediumLevelILOperation.MLIL_SET_VAR_SSA_FIELD,
			MediumLevelILOperation.MLIL_SET_VAR_ALIASED_FIELD]:
			return [self.prev] + self.src.vars_read
		elif self._operation in [MediumLevelILOperation.MLIL_CALL, MediumLevelILOperation.MLIL_SYSCALL, MediumLevelILOperation.MLIL_TAILCALL,
			MediumLevelILOperation.MLIL_CALL_SSA, MediumLevelILOperation.MLIL_SYSCALL_SSA, MediumLevelILOperation.MLIL_TAILCALL_SSA]:
			result = []
			for param in self.params:
				result += param.vars_read
			return result
		elif self._operation in [MediumLevelILOperation.MLIL_CALL_UNTYPED, MediumLevelILOperation.MLIL_SYSCALL_UNTYPED, MediumLevelILOperation.MLIL_TAILCALL_UNTYPED,
			MediumLevelILOperation.MLIL_CALL_UNTYPED_SSA, MediumLevelILOperation.MLIL_SYSCALL_UNTYPED_SSA, MediumLevelILOperation.MLIL_TAILCALL_UNTYPED_SSA]:
			return self.params.vars_read
		elif self._operation in [MediumLevelILOperation.MLIL_CALL_PARAM, MediumLevelILOperation.MLIL_CALL_PARAM_SSA,
			MediumLevelILOperation.MLIL_VAR_PHI]:
			return self.src
		elif self._operation in [MediumLevelILOperation.MLIL_CALL_OUTPUT, MediumLevelILOperation.MLIL_CALL_OUTPUT_SSA]:
			return []
		result = []
		for operand in self._operands:
			if (isinstance(operand, function.Variable)) or (isinstance(operand, SSAVariable)):
				result.append(operand)
			elif isinstance(operand, MediumLevelILInstruction):
				result += operand.vars_read
		return result

	@property
	def expr_type(self):
		"""Type of expression"""
		result = core.BNGetMediumLevelILExprType(self._function.handle, self._expr_index)
		if result.type:
			platform = None
			if self._function.source_function:
				platform = self._function.source_function.platform
			return types.Type(result.type, platform = platform, confidence = result.confidence)
		return None

	def get_possible_values(self, options = []):
		option_array = (ctypes.c_int * len(options))()
		idx = 0
		for option in options:
			option_array[idx] = option
			idx += 1
		value = core.BNGetMediumLevelILPossibleExprValues(self._function.handle, self._expr_index, option_array, len(options))
		result = function.PossibleValueSet(self._function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_ssa_var_possible_values(self, ssa_var, options = []):
		var_data = core.BNVariable()
		var_data.type = ssa_var.var.source_type
		var_data.index = ssa_var.var.index
		var_data.storage = ssa_var.var.storage
		option_array = (ctypes.c_int * len(options))()
		idx = 0
		for option in options:
			option_array[idx] = option
			idx += 1
		value = core.BNGetMediumLevelILPossibleSSAVarValues(self._function.handle, var_data, ssa_var.version,
			self._instr_index, option_array, len(options))
		result = function.PossibleValueSet(self._function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_ssa_var_version(self, var):
		var_data = core.BNVariable()
		var_data.type = var.source_type
		var_data.index = var.index
		var_data.storage = var.storage
		return core.BNGetMediumLevelILSSAVarVersionAtILInstruction(self._function.handle, var_data, self._instr_index)

	def get_var_for_reg(self, reg):
		reg = self._function.arch.get_reg_index(reg)
		result = core.BNGetMediumLevelILVariableForRegisterAtInstruction(self._function.handle, reg, self._instr_index)
		return function.Variable(self._function.source_function, result.type, result.index, result.storage)

	def get_var_for_flag(self, flag):
		flag = self._function.arch.get_flag_index(flag)
		result = core.BNGetMediumLevelILVariableForFlagAtInstruction(self._function.handle, flag, self._instr_index)
		return function.Variable(self._function.source_function, result.type, result.index, result.storage)

	def get_var_for_stack_location(self, offset):
		result = core.BNGetMediumLevelILVariableForStackLocationAtInstruction(self._function.handle, offset, self._instr_index)
		return function.Variable(self._function.source_function, result.type, result.index, result.storage)

	def get_reg_value(self, reg):
		reg = self._function.arch.get_reg_index(reg)
		value = core.BNGetMediumLevelILRegisterValueAtInstruction(self._function.handle, reg, self._instr_index)
		result = function.RegisterValue(self._function.arch, value)
		return result

	def get_reg_value_after(self, reg):
		reg = self._function.arch.get_reg_index(reg)
		value = core.BNGetMediumLevelILRegisterValueAfterInstruction(self._function.handle, reg, self._instr_index)
		result = function.RegisterValue(self._function.arch, value)
		return result

	def get_possible_reg_values(self, reg, options = []):
		reg = self._function.arch.get_reg_index(reg)
		option_array = (ctypes.c_int * len(options))()
		idx = 0
		for option in options:
			option_array[idx] = option
			idx += 1
		value = core.BNGetMediumLevelILPossibleRegisterValuesAtInstruction(self._function.handle, reg, self._instr_index,
			option_array, len(options))
		result = function.PossibleValueSet(self._function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_possible_reg_values_after(self, reg, options = []):
		reg = self._function.arch.get_reg_index(reg)
		option_array = (ctypes.c_int * len(options))()
		idx = 0
		for option in options:
			option_array[idx] = option
			idx += 1
		value = core.BNGetMediumLevelILPossibleRegisterValuesAfterInstruction(self._function.handle, reg, self._instr_index,
			option_array, len(options))
		result = function.PossibleValueSet(self._function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_flag_value(self, flag):
		flag = self._function.arch.get_flag_index(flag)
		value = core.BNGetMediumLevelILFlagValueAtInstruction(self._function.handle, flag, self._instr_index)
		result = function.RegisterValue(self._function.arch, value)
		return result

	def get_flag_value_after(self, flag):
		flag = self._function.arch.get_flag_index(flag)
		value = core.BNGetMediumLevelILFlagValueAfterInstruction(self._function.handle, flag, self._instr_index)
		result = function.RegisterValue(self._function.arch, value)
		return result

	def get_possible_flag_values(self, flag, options = []):
		flag = self._function.arch.get_flag_index(flag)
		option_array = (ctypes.c_int * len(options))()
		idx = 0
		for option in options:
			option_array[idx] = option
			idx += 1
		value = core.BNGetMediumLevelILPossibleFlagValuesAtInstruction(self._function.handle, flag, self._instr_index,
			option_array, len(options))
		result = function.PossibleValueSet(self._function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_possible_flag_values_after(self, flag, options = []):
		flag = self._function.arch.get_flag_index(flag)
		option_array = (ctypes.c_int * len(options))()
		idx = 0
		for option in options:
			option_array[idx] = option
			idx += 1
		value = core.BNGetMediumLevelILPossibleFlagValuesAfterInstruction(self._function.handle, flag, self._instr_index,
			option_array, len(options))
		result = function.PossibleValueSet(self._function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_stack_contents(self, offset, size):
		value = core.BNGetMediumLevelILStackContentsAtInstruction(self._function.handle, offset, size, self._instr_index)
		result = function.RegisterValue(self._function.arch, value)
		return result

	def get_stack_contents_after(self, offset, size):
		value = core.BNGetMediumLevelILStackContentsAfterInstruction(self._function.handle, offset, size, self._instr_index)
		result = function.RegisterValue(self._function.arch, value)
		return result

	def get_possible_stack_contents(self, offset, size, options = []):
		option_array = (ctypes.c_int * len(options))()
		idx = 0
		for option in options:
			option_array[idx] = option
			idx += 1
		value = core.BNGetMediumLevelILPossibleStackContentsAtInstruction(self._function.handle, offset, size, self._instr_index,
			option_array, len(options))
		result = function.PossibleValueSet(self._function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_possible_stack_contents_after(self, offset, size, options = []):
		option_array = (ctypes.c_int * len(options))()
		idx = 0
		for option in options:
			option_array[idx] = option
			idx += 1
		value = core.BNGetMediumLevelILPossibleStackContentsAfterInstruction(self._function.handle, offset, size, self._instr_index,
			option_array, len(options))
		result = function.PossibleValueSet(self._function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_branch_dependence(self, branch_instr):
		return ILBranchDependence(core.BNGetMediumLevelILBranchDependence(self._function.handle, self._instr_index, branch_instr))

	@property
	def function(self):
		""" """
		return self._function

	@property
	def expr_index(self):
		""" """
		return self._expr_index

	@property
	def instr_index(self):
		""" """
		return self._instr_index

	@property
	def operation(self):
		""" """
		return self._operation

	@property
	def size(self):
		""" """
		return self._size

	@property
	def address(self):
		""" """
		return self._address

	@property
	def source_operand(self):
		""" """
		return self._source_operand

	@property
	def operands(self):
		""" """
		return self._operands


class MediumLevelILExpr(object):
	"""
	``class MediumLevelILExpr`` hold the index of IL Expressions.

	.. note:: This class shouldn't be instantiated directly. Rather the helper members of MediumLevelILFunction should be \
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


class MediumLevelILFunction(object):
	"""
	``class MediumLevelILFunction`` contains the list of MediumLevelILExpr objects that make up a binaryninja.function. MediumLevelILExpr
	objects can be added to the MediumLevelILFunction by calling :func:`append` and passing the result of the various class
	methods which return MediumLevelILExpr objects.
	"""
	def __init__(self, arch = None, handle = None, source_func = None):
		self._arch = arch
		self._source_function = source_func
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNMediumLevelILFunction)
			if self._source_function is None:
				self._source_function = binaryninja.function.Function(handle = core.BNGetMediumLevelILOwnerFunction(self.handle))
			if self._arch is None:
				self._arch = self._source_function.arch
		else:
			if self._source_function is None:
				self.handle = None
				raise ValueError("IL functions must be created with an associated function")
			if self._arch is None:
				self._arch = self._source_function.arch
			func_handle = self._source_function.handle
			self.handle = core.BNCreateMediumLevelILFunction(arch.handle, func_handle)

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

	def __getitem__(self, i):
		if isinstance(i, slice) or isinstance(i, tuple):
			raise IndexError("expected integer instruction index")
		if isinstance(i, MediumLevelILExpr):
			return MediumLevelILInstruction(self, i.index)
		# for backwards compatibility
		if isinstance(i, MediumLevelILInstruction):
			return i
		if i < -len(self) or i >= len(self):
			raise IndexError("index out of range")
		if i < 0:
			i = len(self) + i
		return MediumLevelILInstruction(self, core.BNGetMediumLevelILIndexForInstruction(self.handle, i), i)

	def __setitem__(self, i, j):
		raise IndexError("instruction modification not implemented")

	def __iter__(self):
		count = ctypes.c_ulonglong()
		blocks = core.BNGetMediumLevelILBasicBlockList(self.handle, count)
		view = None
		if self._source_function is not None:
			view = self._source_function.view
		try:
			for i in range(0, count.value):
				yield MediumLevelILBasicBlock(view, core.BNNewBasicBlockReference(blocks[i]), self)
		finally:
			core.BNFreeBasicBlockList(blocks, count.value)

	@property
	def current_address(self):
		"""Current IL Address (read/write)"""
		return core.BNMediumLevelILGetCurrentAddress(self.handle)

	@current_address.setter
	def current_address(self, value):
		core.BNMediumLevelILSetCurrentAddress(self.handle, self._arch.handle, value)

	def set_current_address(self, value, arch = None):
		if arch is None:
			arch = self._arch
		core.BNMediumLevelILSetCurrentAddress(self.handle, arch.handle, value)

	@property
	def basic_blocks(self):
		"""list of MediumLevelILBasicBlock objects (read-only)"""
		count = ctypes.c_ulonglong()
		blocks = core.BNGetMediumLevelILBasicBlockList(self.handle, count)
		result = []
		view = None
		if self._source_function is not None:
			view = self._source_function.view
		for i in range(0, count.value):
			result.append(MediumLevelILBasicBlock(view, core.BNNewBasicBlockReference(blocks[i]), self))
		core.BNFreeBasicBlockList(blocks, count.value)
		return result

	@property
	def instructions(self):
		"""A generator of mlil instructions of the current function"""
		for block in self.basic_blocks:
			for i in block:
				yield i

	@property
	def ssa_form(self):
		"""Medium level IL in SSA form (read-only)"""
		result = core.BNGetMediumLevelILSSAForm(self.handle)
		if not result:
			return None
		return MediumLevelILFunction(self._arch, result, self._source_function)

	@property
	def non_ssa_form(self):
		"""Medium level IL in non-SSA (default) form (read-only)"""
		result = core.BNGetMediumLevelILNonSSAForm(self.handle)
		if not result:
			return None
		return MediumLevelILFunction(self._arch, result, self._source_function)

	@property
	def low_level_il(self):
		"""Low level IL for this function"""
		result = core.BNGetLowLevelILForMediumLevelIL(self.handle)
		if not result:
			return None
		return lowlevelil.LowLevelILFunction(self._arch, result, self._source_function)

	@property
	def llil(self):
		"""Alias for low_level_il"""
		return self.low_level_il

	def get_instruction_start(self, addr, arch = None):
		if arch is None:
			arch = self._arch
		result = core.BNMediumLevelILGetInstructionStart(self.handle, arch.handle, addr)
		if result >= core.BNGetMediumLevelILInstructionCount(self.handle):
			return None
		return result

	def expr(self, operation, a = 0, b = 0, c = 0, d = 0, e = 0, size = 0):
		if isinstance(operation, str):
			operation = MediumLevelILOperation[operation]
		elif isinstance(operation, MediumLevelILOperation):
			operation = operation.value
		return MediumLevelILExpr(core.BNMediumLevelILAddExpr(self.handle, operation, size, a, b, c, d, e))

	def append(self, expr):
		"""
		``append`` adds the MediumLevelILExpr ``expr`` to the current MediumLevelILFunction.

		:param MediumLevelILExpr expr: the MediumLevelILExpr to add to the current MediumLevelILFunction
		:return: number of MediumLevelILExpr in the current function
		:rtype: int
		"""
		return core.BNMediumLevelILAddInstruction(self.handle, expr.index)

	def goto(self, label):
		"""
		``goto`` returns a goto expression which jumps to the provided MediumLevelILLabel.

		:param MediumLevelILLabel label: Label to jump to
		:return: the MediumLevelILExpr that jumps to the provided label
		:rtype: MediumLevelILExpr
		"""
		return MediumLevelILExpr(core.BNMediumLevelILGoto(self.handle, label.handle))

	def if_expr(self, operand, t, f):
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

	def mark_label(self, label):
		"""
		``mark_label`` assigns a MediumLevelILLabel to the current IL address.

		:param MediumLevelILLabel label:
		:rtype: None
		"""
		core.BNMediumLevelILMarkLabel(self.handle, label.handle)

	def add_label_list(self, labels):
		"""
		``add_label_list`` returns a label list expression for the given list of MediumLevelILLabel objects.

		:param labels: the list of MediumLevelILLabel to get a label list expression from
		:type labels: list(MediumLevelILLabel)
		:return: the label list expression
		:rtype: MediumLevelILExpr
		"""
		label_list = (ctypes.POINTER(core.BNMediumLevelILLabel) * len(labels))()
		for i in range(len(labels)):
			label_list[i] = labels[i].handle
		return MediumLevelILExpr(core.BNMediumLevelILAddLabelList(self.handle, label_list, len(labels)))

	def add_operand_list(self, operands):
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

	def operand(self, n, expr):
		"""
		``operand`` sets the operand number of the expression ``expr`` and passes back ``expr`` without modification.

		:param int n:
		:param MediumLevelILExpr expr:
		:return: returns the expression ``expr`` unmodified
		:rtype: MediumLevelILExpr
		"""
		core.BNMediumLevelILSetExprSourceOperand(self.handle, expr.index, n)
		return expr

	def finalize(self):
		"""
		``finalize`` ends the function and computes the list of basic blocks.

		:rtype: None
		"""
		core.BNFinalizeMediumLevelILFunction(self.handle)

	def get_ssa_instruction_index(self, instr):
		return core.BNGetMediumLevelILSSAInstructionIndex(self.handle, instr)

	def get_non_ssa_instruction_index(self, instr):
		return core.BNGetMediumLevelILNonSSAInstructionIndex(self.handle, instr)

	def get_ssa_var_definition(self, ssa_var):
		var_data = core.BNVariable()
		var_data.type = ssa_var.var.source_type
		var_data.index = ssa_var.var.index
		var_data.storage = ssa_var.var.storage
		result = core.BNGetMediumLevelILSSAVarDefinition(self.handle, var_data, ssa_var.version)
		if result >= core.BNGetMediumLevelILInstructionCount(self.handle):
			return None
		return self[result]

	def get_ssa_memory_definition(self, version):
		result = core.BNGetMediumLevelILSSAMemoryDefinition(self.handle, version)
		if result >= core.BNGetMediumLevelILInstructionCount(self.handle):
			return None
		return self[result]

	def get_ssa_var_uses(self, ssa_var):
		count = ctypes.c_ulonglong()
		var_data = core.BNVariable()
		var_data.type = ssa_var.var.source_type
		var_data.index = ssa_var.var.index
		var_data.storage = ssa_var.var.storage
		instrs = core.BNGetMediumLevelILSSAVarUses(self.handle, var_data, ssa_var.version, count)
		result = []
		for i in range(0, count.value):
			result.append(self[instrs[i]])
		core.BNFreeILInstructionList(instrs)
		return result

	def get_ssa_memory_uses(self, version):
		count = ctypes.c_ulonglong()
		instrs = core.BNGetMediumLevelILSSAMemoryUses(self.handle, version, count)
		result = []
		for i in range(0, count.value):
			result.append(self[instrs[i]])
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
		return core.BNIsMediumLevelILSSAVarLive(self.handle, var_data, ssa_var.version)

	def get_var_definitions(self, var):
		count = ctypes.c_ulonglong()
		var_data = core.BNVariable()
		var_data.type = var.source_type
		var_data.index = var.index
		var_data.storage = var.storage
		instrs = core.BNGetMediumLevelILVariableDefinitions(self.handle, var_data, count)
		result = []
		for i in range(0, count.value):
			result.append(self[instrs[i]])
		core.BNFreeILInstructionList(instrs)
		return result

	def get_var_uses(self, var):
		count = ctypes.c_ulonglong()
		var_data = core.BNVariable()
		var_data.type = var.source_type
		var_data.index = var.index
		var_data.storage = var.storage
		instrs = core.BNGetMediumLevelILVariableUses(self.handle, var_data, count)
		result = []
		for i in range(0, count.value):
			result.append(self[instrs[i]])
		core.BNFreeILInstructionList(instrs)
		return result

	def get_ssa_var_value(self, ssa_var):
		var_data = core.BNVariable()
		var_data.type = ssa_var.var.source_type
		var_data.index = ssa_var.var.index
		var_data.storage = ssa_var.var.storage
		value = core.BNGetMediumLevelILSSAVarValue(self.handle, var_data, ssa_var.version)
		result = function.RegisterValue(self._arch, value)
		return result

	def get_low_level_il_instruction_index(self, instr):
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

	def get_low_level_il_expr_index(self, expr):
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

	def create_graph(self, settings = None):
		if settings is not None:
			settings_obj = settings.handle
		else:
			settings_obj = None
		return binaryninja.flowgraph.CoreFlowGraph(core.BNCreateMediumLevelILFunctionGraph(self.handle, settings_obj))

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


class MediumLevelILBasicBlock(basicblock.BasicBlock):
	def __init__(self, view, handle, owner):
		super(MediumLevelILBasicBlock, self).__init__(handle, view)
		self.il_function = owner

	def __repr__(self):
		arch = self.arch
		if arch:
			return "<mlil block: %s@%d-%d>" % (arch.name, self.start, self.end)
		else:
			return "<mlil block: %d-%d>" % (self.start, self.end)

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

	def __hash__(self):
		return hash((self.start, self.end, self.il_function))

	def __contains__(self, instruction):
		if type(instruction) != MediumLevelILInstruction or instruction.il_basic_block != self:
			return False
		if instruction.instr_index >= self.start and instruction.instr_index <= self.end:
			return True
		else:
			return False

	def _create_instance(self, handle, view):
		"""Internal method by super to instantiate child instances"""
		return MediumLevelILBasicBlock(view, handle, self.il_function)

	@property
	def il_function(self):
		""" """
		return self._il_function

	@il_function.setter
	def il_function(self, value):
		self._il_function = value
