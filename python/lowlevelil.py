# Copyright (c) 2015-2017 Vector 35 LLC
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

# Binary Ninja components
import _binaryninjacore as core
from .enums import LowLevelILOperation, LowLevelILFlagCondition, InstructionTextTokenType
import function
import basicblock
import mediumlevelil


class LowLevelILLabel(object):
	def __init__(self, handle = None):
		if handle is None:
			self.handle = (core.BNLowLevelILLabel * 1)()
			core.BNLowLevelILInitLabel(self.handle)
		else:
			self.handle = handle


class ILRegister(object):
	def __init__(self, arch, reg):
		self.arch = arch
		self.index = reg
		self.temp = (self.index & 0x80000000) != 0
		if self.temp:
			self.name = "temp%d" % (self.index & 0x7fffffff)
		else:
			self.name = self.arch.get_reg_name(self.index)

	@property
	def info(self):
		return self.arch.regs[self.name]

	def __str__(self):
		return self.name

	def __repr__(self):
		return self.name

	def __eq__(self, other):
		return self.info == other.info


class ILFlag(object):
	def __init__(self, arch, flag):
		self.arch = arch
		self.index = flag
		self.temp = (self.index & 0x80000000) != 0
		if self.temp:
			self.name = "cond:%d" % (self.index & 0x7fffffff)
		else:
			self.name = self.arch.get_flag_name(self.index)

	def __str__(self):
		return self.name

	def __repr__(self):
		return self.name


class SSARegister(object):
	def __init__(self, reg, version):
		self.reg = reg
		self.version = version

	def __repr__(self):
		return "<ssa %s version %d>" % (repr(self.reg), self.version)


class SSAFlag(object):
	def __init__(self, flag, version):
		self.flag = flag
		self.version = version

	def __repr__(self):
		return "<ssa %s version %d>" % (repr(self.flag), self.version)


class LowLevelILOperationAndSize(object):
	def __init__(self, operation, size):
		self.operation = operation
		self.size = size

	def __repr__(self):
		if self.size == 0:
			return "<%s>" % self.operation.name
		return "<%s %d>" % (self.operation.name, self.size)


class LowLevelILInstruction(object):
	"""
	``class LowLevelILInstruction`` Low Level Intermediate Language Instructions are infinite length tree-based
	instructions. Tree-based instructions use infix notation with the left hand operand being the destination operand.
	Infix notation is thus more natural to read than other notations (e.g. x86 ``mov eax, 0`` vs. LLIL ``eax = 0``).
	"""

	ILOperations = {
		LowLevelILOperation.LLIL_NOP: [],
		LowLevelILOperation.LLIL_SET_REG: [("dest", "reg"), ("src", "expr")],
		LowLevelILOperation.LLIL_SET_REG_SPLIT: [("hi", "reg"), ("lo", "reg"), ("src", "expr")],
		LowLevelILOperation.LLIL_SET_FLAG: [("dest", "flag"), ("src", "expr")],
		LowLevelILOperation.LLIL_LOAD: [("src", "expr")],
		LowLevelILOperation.LLIL_STORE: [("dest", "expr"), ("src", "expr")],
		LowLevelILOperation.LLIL_PUSH: [("src", "expr")],
		LowLevelILOperation.LLIL_POP: [],
		LowLevelILOperation.LLIL_REG: [("src", "reg")],
		LowLevelILOperation.LLIL_CONST: [("constant", "int")],
		LowLevelILOperation.LLIL_CONST_PTR: [("constant", "int")],
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
		LowLevelILOperation.LLIL_DIVU_DP: [("hi", "expr"), ("lo", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_DIVS: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_DIVS_DP: [("hi", "expr"), ("lo", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_MODU: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_MODU_DP: [("hi", "expr"), ("lo", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_MODS: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_MODS_DP: [("hi", "expr"), ("lo", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_NEG: [("src", "expr")],
		LowLevelILOperation.LLIL_NOT: [("src", "expr")],
		LowLevelILOperation.LLIL_SX: [("src", "expr")],
		LowLevelILOperation.LLIL_ZX: [("src", "expr")],
		LowLevelILOperation.LLIL_LOW_PART: [("src", "expr")],
		LowLevelILOperation.LLIL_JUMP: [("dest", "expr")],
		LowLevelILOperation.LLIL_JUMP_TO: [("dest", "expr"), ("targets", "int_list")],
		LowLevelILOperation.LLIL_CALL: [("dest", "expr")],
		LowLevelILOperation.LLIL_CALL_STACK_ADJUST: [("dest", "expr"), ("stack_adjustment", "int")],
		LowLevelILOperation.LLIL_RET: [("dest", "expr")],
		LowLevelILOperation.LLIL_NORET: [],
		LowLevelILOperation.LLIL_IF: [("condition", "expr"), ("true", "int"), ("false", "int")],
		LowLevelILOperation.LLIL_GOTO: [("dest", "int")],
		LowLevelILOperation.LLIL_FLAG_COND: [("condition", "cond")],
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
		LowLevelILOperation.LLIL_UNDEF: [],
		LowLevelILOperation.LLIL_UNIMPL: [],
		LowLevelILOperation.LLIL_UNIMPL_MEM: [("src", "expr")],
		LowLevelILOperation.LLIL_SET_REG_SSA: [("dest", "reg_ssa"), ("src", "expr")],
		LowLevelILOperation.LLIL_SET_REG_SSA_PARTIAL: [("full_reg", "reg_ssa"), ("dest", "reg"), ("src", "expr")],
		LowLevelILOperation.LLIL_SET_REG_SPLIT_SSA: [("hi", "expr"), ("lo", "expr"), ("src", "expr")],
		LowLevelILOperation.LLIL_REG_SPLIT_DEST_SSA: [("dest", "reg_ssa")],
		LowLevelILOperation.LLIL_REG_SSA: [("src", "reg_ssa")],
		LowLevelILOperation.LLIL_REG_SSA_PARTIAL: [("full_reg", "reg_ssa"), ("src", "reg")],
		LowLevelILOperation.LLIL_SET_FLAG_SSA: [("dest", "flag_ssa"), ("src", "expr")],
		LowLevelILOperation.LLIL_FLAG_SSA: [("src", "flag_ssa")],
		LowLevelILOperation.LLIL_FLAG_BIT_SSA: [("src", "flag_ssa"), ("bit", "int")],
		LowLevelILOperation.LLIL_CALL_SSA: [("output", "expr"), ("dest", "expr"), ("stack", "expr"), ("param", "expr")],
		LowLevelILOperation.LLIL_SYSCALL_SSA: [("output", "expr"), ("stack", "expr"), ("param", "expr")],
		LowLevelILOperation.LLIL_CALL_OUTPUT_SSA: [("dest_memory", "int"), ("dest", "reg_ssa_list")],
		LowLevelILOperation.LLIL_CALL_STACK_SSA: [("src", "reg_ssa"), ("src_memory", "int")],
		LowLevelILOperation.LLIL_CALL_PARAM_SSA: [("src", "reg_ssa_list")],
		LowLevelILOperation.LLIL_LOAD_SSA: [("src", "expr"), ("src_memory", "int")],
		LowLevelILOperation.LLIL_STORE_SSA: [("dest", "expr"), ("dest_memory", "int"), ("src_memory", "int"), ("src", "expr")],
		LowLevelILOperation.LLIL_REG_PHI: [("dest", "reg_ssa"), ("src", "reg_ssa_list")],
		LowLevelILOperation.LLIL_FLAG_PHI: [("dest", "flag_ssa"), ("src", "flag_ssa_list")],
		LowLevelILOperation.LLIL_MEM_PHI: [("dest_memory", "int"), ("src_memory", "int_list")]
	}

	def __init__(self, func, expr_index, instr_index=None):
		instr = core.BNGetLowLevelILByIndex(func.handle, expr_index)
		self.function = func
		self.expr_index = expr_index
		self.instr_index = instr_index
		self.operation = LowLevelILOperation(instr.operation)
		self.size = instr.size
		self.address = instr.address
		self.source_operand = instr.sourceOperand
		if instr.flags == 0:
			self.flags = None
		else:
			self.flags = func.arch.get_flag_write_type_name(instr.flags)
		if self.source_operand == 0xffffffff:
			self.source_operand = None
		operands = LowLevelILInstruction.ILOperations[instr.operation]
		self.operands = []
		i = 0
		for operand in operands:
			name, operand_type = operand
			if operand_type == "int":
				value = instr.operands[i]
			elif operand_type == "expr":
				value = LowLevelILInstruction(func, instr.operands[i])
			elif operand_type == "reg":
				value = ILRegister(func.arch, instr.operands[i])
			elif operand_type == "reg_ssa":
				reg = ILRegister(func.arch, instr.operands[i])
				i += 1
				value = SSARegister(reg, instr.operands[i])
			elif operand_type == "flag":
				value = ILFlag(func.arch, instr.operands[i])
			elif operand_type == "flag_ssa":
				flag = ILFlag(func.arch, instr.operands[i])
				i += 1
				value = SSAFlag(flag, instr.operands[i])
			elif operand_type == "cond":
				value = LowLevelILFlagCondition(instr.operands[i])
			elif operand_type == "int_list":
				count = ctypes.c_ulonglong()
				operand_list = core.BNLowLevelILGetOperandList(func.handle, self.expr_index, i, count)
				i += 1
				value = []
				for i in xrange(count.value):
					value.append(operand_list[i])
				core.BNLowLevelILFreeOperandList(operand_list)
			elif operand_type == "reg_ssa_list":
				count = ctypes.c_ulonglong()
				operand_list = core.BNLowLevelILGetOperandList(func.handle, self.expr_index, i, count)
				i += 1
				value = []
				for i in xrange(count.value / 2):
					reg = operand_list[i * 2]
					reg_version = operand_list[(i * 2) + 1]
					value.append(SSARegister(ILRegister(func.arch, reg), reg_version))
				core.BNLowLevelILFreeOperandList(operand_list)
			elif operand_type == "flag_ssa_list":
				count = ctypes.c_ulonglong()
				operand_list = core.BNLowLevelILGetOperandList(func.handle, self.expr_index, i, count)
				i += 1
				value = []
				for i in xrange(count.value / 2):
					flag = operand_list[i * 2]
					flag_version = operand_list[(i * 2) + 1]
					value.append(SSAFlag(ILFlag(func.arch, flag), flag_version))
				core.BNLowLevelILFreeOperandList(operand_list)
			self.operands.append(value)
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

	@property
	def tokens(self):
		"""LLIL tokens (read-only)"""
		count = ctypes.c_ulonglong()
		tokens = ctypes.POINTER(core.BNInstructionTextToken)()
		if (self.instr_index is not None) and (self.function.source_function is not None):
			if not core.BNGetLowLevelILInstructionText(self.function.handle, self.function.source_function.handle,
				self.function.arch.handle, self.instr_index, tokens, count):
				return None
		else:
			if not core.BNGetLowLevelILExprText(self.function.handle, self.function.arch.handle,
				self.expr_index, tokens, count):
				return None
		result = []
		for i in xrange(0, count.value):
			token_type = InstructionTextTokenType(tokens[i].type)
			text = tokens[i].text
			value = tokens[i].value
			size = tokens[i].size
			operand = tokens[i].operand
			context = tokens[i].context
			confidence = tokens[i].confidence
			address = tokens[i].address
			result.append(function.InstructionTextToken(token_type, text, value, size, operand, context, address, confidence))
		core.BNFreeInstructionText(tokens, count.value)
		return result

	@property
	def ssa_form(self):
		"""SSA form of expression (read-only)"""
		return LowLevelILInstruction(self.function.ssa_form,
			core.BNGetLowLevelILSSAExprIndex(self.function.handle, self.expr_index))

	@property
	def non_ssa_form(self):
		"""Non-SSA form of expression (read-only)"""
		return LowLevelILInstruction(self.function.non_ssa_form,
			core.BNGetLowLevelILNonSSAExprIndex(self.function.handle, self.expr_index))

	@property
	def medium_level_il(self):
		"""Gets the medium level IL expression corresponding to this expression (may be None for eliminated instructions)"""
		expr = self.function.get_medium_level_il_expr_index(self.expr_index)
		if expr is None:
			return None
		return mediumlevelil.MediumLevelILInstruction(self.function.medium_level_il, expr)

	@property
	def mapped_medium_level_il(self):
		"""Gets the mapped medium level IL expression corresponding to this expression"""
		expr = self.function.get_mapped_medium_level_il_expr_index(self.expr_index)
		if expr is None:
			return None
		return mediumlevelil.MediumLevelILInstruction(self.function.mapped_medium_level_il, expr)

	@property
	def value(self):
		"""Value of expression if constant or a known value (read-only)"""
		value = core.BNGetLowLevelILExprValue(self.function.handle, self.expr_index)
		result = function.RegisterValue(self.function.arch, value)
		return result

	@property
	def possible_values(self):
		"""Possible values of expression using path-sensitive static data flow analysis (read-only)"""
		value = core.BNGetLowLevelILPossibleExprValues(self.function.handle, self.expr_index)
		result = function.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	@property
	def prefix_operands(self):
		"""All operands in the expression tree in prefix order"""
		result = [LowLevelILOperationAndSize(self.operation, self.size)]
		for operand in self.operands:
			if isinstance(operand, LowLevelILInstruction):
				result += operand.prefix_operands
			else:
				result.append(operand)
		return result

	@property
	def postfix_operands(self):
		"""All operands in the expression tree in postfix order"""
		result = []
		for operand in self.operands:
			if isinstance(operand, LowLevelILInstruction):
				result += operand.postfix_operands
			else:
				result.append(operand)
		result.append(LowLevelILOperationAndSize(self.operation, self.size))
		return result

	def get_reg_value(self, reg):
		reg = self.function.arch.get_reg_index(reg)
		value = core.BNGetLowLevelILRegisterValueAtInstruction(self.function.handle, reg, self.instr_index)
		result = function.RegisterValue(self.function.arch, value)
		return result

	def get_reg_value_after(self, reg):
		reg = self.function.arch.get_reg_index(reg)
		value = core.BNGetLowLevelILRegisterValueAfterInstruction(self.function.handle, reg, self.instr_index)
		result = function.RegisterValue(self.function.arch, value)
		return result

	def get_possible_reg_values(self, reg):
		reg = self.function.arch.get_reg_index(reg)
		value = core.BNGetLowLevelILPossibleRegisterValuesAtInstruction(self.function.handle, reg, self.instr_index)
		result = function.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_possible_reg_values_after(self, reg):
		reg = self.function.arch.get_reg_index(reg)
		value = core.BNGetLowLevelILPossibleRegisterValuesAfterInstruction(self.function.handle, reg, self.instr_index)
		result = function.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_flag_value(self, flag):
		flag = self.function.arch.get_flag_index(flag)
		value = core.BNGetLowLevelILFlagValueAtInstruction(self.function.handle, flag, self.instr_index)
		result = function.RegisterValue(self.function.arch, value)
		return result

	def get_flag_value_after(self, flag):
		flag = self.function.arch.get_flag_index(flag)
		value = core.BNGetLowLevelILFlagValueAfterInstruction(self.function.handle, flag, self.instr_index)
		result = function.RegisterValue(self.function.arch, value)
		return result

	def get_possible_flag_values(self, flag):
		flag = self.function.arch.get_flag_index(flag)
		value = core.BNGetLowLevelILPossibleFlagValuesAtInstruction(self.function.handle, flag, self.instr_index)
		result = function.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_possible_flag_values_after(self, flag):
		flag = self.function.arch.get_flag_index(flag)
		value = core.BNGetLowLevelILPossibleFlagValuesAfterInstruction(self.function.handle, flag, self.instr_index)
		result = function.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_stack_contents(self, offset, size):
		value = core.BNGetLowLevelILStackContentsAtInstruction(self.function.handle, offset, size, self.instr_index)
		result = function.RegisterValue(self.function.arch, value)
		return result

	def get_stack_contents_after(self, offset, size):
		value = core.BNGetLowLevelILStackContentsAfterInstruction(self.function.handle, offset, size, self.instr_index)
		result = function.RegisterValue(self.function.arch, value)
		return result

	def get_possible_stack_contents(self, offset, size):
		value = core.BNGetLowLevelILPossibleStackContentsAtInstruction(self.function.handle, offset, size, self.instr_index)
		result = function.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_possible_stack_contents_after(self, offset, size):
		value = core.BNGetLowLevelILPossibleStackContentsAfterInstruction(self.function.handle, offset, size, self.instr_index)
		result = function.PossibleValueSet(self.function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self, name, value)
		except AttributeError:
			raise AttributeError("attribute '%s' is read only" % name)


class LowLevelILExpr(object):
	"""
	``class LowLevelILExpr`` hold the index of IL Expressions.

	.. note:: This class shouldn't be instantiated directly. Rather the helper members of LowLevelILFunction should be \
	used instead.
	"""
	def __init__(self, index):
		self.index = index


class LowLevelILFunction(object):
	"""
	``class LowLevelILFunction`` contains the list of LowLevelILExpr objects that make up a function. LowLevelILExpr
	objects can be added to the LowLevelILFunction by calling ``append`` and passing the result of the various class
	methods which return LowLevelILExpr objects.


	LowLevelILFlagCondition values used as parameters in the ``flag_condition`` method.

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
		LLFC_SGT                s>         Signed greather than
		LLFC_UGT                u>         Unsigned greater than
		LLFC_NEG                -          Negative
		LLFC_POS                +          Positive
		LLFC_O                  overflow   Overflow
		LLFC_NO                 !overflow  No overflow
		======================= ========== ===============================
	"""
	def __init__(self, arch, handle = None, source_func = None):
		self.arch = arch
		self.source_function = source_func
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNLowLevelILFunction)
		else:
			func_handle = None
			if self.source_function is not None:
				func_handle = self.source_function.handle
			self.handle = core.BNCreateLowLevelILFunction(arch.handle, func_handle)

	def __del__(self):
		core.BNFreeLowLevelILFunction(self.handle)

	def __eq__(self, value):
		if not isinstance(value, LowLevelILFunction):
			return False
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(value.handle.contents)

	def __ne__(self, value):
		if not isinstance(value, LowLevelILFunction):
			return True
		return ctypes.addressof(self.handle.contents) != ctypes.addressof(value.handle.contents)

	@property
	def current_address(self):
		"""Current IL Address (read/write)"""
		return core.BNLowLevelILGetCurrentAddress(self.handle)

	@current_address.setter
	def current_address(self, value):
		core.BNLowLevelILSetCurrentAddress(self.handle, self.arch.handle, value)

	def set_current_address(self, value, arch = None):
		if arch is None:
			arch = self.arch
		core.BNLowLevelILSetCurrentAddress(self.handle, arch.handle, value)

	@property
	def temp_reg_count(self):
		"""Number of temporary registers (read-only)"""
		return core.BNGetLowLevelILTemporaryRegisterCount(self.handle)

	@property
	def temp_flag_count(self):
		"""Number of temporary flags (read-only)"""
		return core.BNGetLowLevelILTemporaryFlagCount(self.handle)

	@property
	def basic_blocks(self):
		"""list of LowLevelILBasicBlock objects (read-only)"""
		count = ctypes.c_ulonglong()
		blocks = core.BNGetLowLevelILBasicBlockList(self.handle, count)
		result = []
		view = None
		if self.source_function is not None:
			view = self.source_function.view
		for i in xrange(0, count.value):
			result.append(LowLevelILBasicBlock(view, core.BNNewBasicBlockReference(blocks[i]), self))
		core.BNFreeBasicBlockList(blocks, count.value)
		return result

	@property
	def ssa_form(self):
		"""Low level IL in SSA form (read-only)"""
		result = core.BNGetLowLevelILSSAForm(self.handle)
		if not result:
			return None
		return LowLevelILFunction(self.arch, result, self.source_function)

	@property
	def non_ssa_form(self):
		"""Low level IL in non-SSA (default) form (read-only)"""
		result = core.BNGetLowLevelILNonSSAForm(self.handle)
		if not result:
			return None
		return LowLevelILFunction(self.arch, result, self.source_function)

	@property
	def medium_level_il(self):
		"""Medium level IL for this low level IL."""
		result = core.BNGetMediumLevelILForLowLevelIL(self.handle)
		if not result:
			return None
		return mediumlevelil.MediumLevelILFunction(self.arch, result, self.source_function)

	@property
	def mapped_medium_level_il(self):
		"""Medium level IL with mappings between low level IL and medium level IL. Unused stores are not removed.
		Typically, this should only be used to answer queries on assembly or low level IL where the query is
		easier to perform on medium level IL."""
		result = core.BNGetMappedMediumLevelIL(self.handle)
		if not result:
			return None
		return mediumlevelil.MediumLevelILFunction(self.arch, result, self.source_function)

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self, name, value)
		except AttributeError:
			raise AttributeError("attribute '%s' is read only" % name)

	def __len__(self):
		return int(core.BNGetLowLevelILInstructionCount(self.handle))

	def __getitem__(self, i):
		if isinstance(i, slice) or isinstance(i, tuple):
			raise IndexError("expected integer instruction index")
		if isinstance(i, LowLevelILExpr):
			return LowLevelILInstruction(self, i.index)
		if (i < 0) or (i >= len(self)):
			raise IndexError("index out of range")
		return LowLevelILInstruction(self, core.BNGetLowLevelILIndexForInstruction(self.handle, i), i)

	def __setitem__(self, i, j):
		raise IndexError("instruction modification not implemented")

	def __iter__(self):
		count = ctypes.c_ulonglong()
		blocks = core.BNGetLowLevelILBasicBlockList(self.handle, count)
		view = None
		if self.source_function is not None:
			view = self.source_function.view
		try:
			for i in xrange(0, count.value):
				yield LowLevelILBasicBlock(view, core.BNNewBasicBlockReference(blocks[i]), self)
		finally:
			core.BNFreeBasicBlockList(blocks, count.value)

	def get_instruction_start(self, addr, arch = None):
		if arch is None:
			arch = self.arch
		result = core.BNLowLevelILGetInstructionStart(self.handle, arch.handle, addr)
		if result >= core.BNGetLowLevelILInstructionCount(self.handle):
			return None
		return result

	def clear_indirect_branches(self):
		core.BNLowLevelILClearIndirectBranches(self.handle)

	def set_indirect_branches(self, branches):
		branch_list = (core.BNArchitectureAndAddress * len(branches))()
		for i in xrange(len(branches)):
			branch_list[i].arch = branches[i][0].handle
			branch_list[i].address = branches[i][1]
		core.BNLowLevelILSetIndirectBranches(self.handle, branch_list, len(branches))

	def expr(self, operation, a = 0, b = 0, c = 0, d = 0, size = 0, flags = None):
		if isinstance(operation, str):
			operation = LowLevelILOperation[operation]
		elif isinstance(operation, LowLevelILOperation):
			operation = operation.value
		if isinstance(flags, str):
			flags = self.arch.get_flag_write_type_by_name(flags)
		elif flags is None:
			flags = 0
		return LowLevelILExpr(core.BNLowLevelILAddExpr(self.handle, operation, size, flags, a, b, c, d))

	def append(self, expr):
		"""
		``append`` adds the LowLevelILExpr ``expr`` to the current LowLevelILFunction.

		:param LowLevelILExpr expr: the LowLevelILExpr to add to the current LowLevelILFunction
		:return: number of LowLevelILExpr in the current function
		:rtype: int
		"""
		return core.BNLowLevelILAddInstruction(self.handle, expr.index)

	def nop(self):
		"""
		``nop`` no operation, this instruction does nothing

		:return: The no operation expression
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_NOP)

	def set_reg(self, size, reg, value, flags = 0):
		"""
		``set_reg`` sets the register ``reg`` of size ``size`` to the expression ``value``

		:param int size: size of the register parameter in bytes
		:param str reg: the register name
		:param LowLevelILExpr value: an expression to set the register to
		:param str flags: which flags are set by this operation
		:return: The expression ``reg = value``
		:rtype: LowLevelILExpr
		"""
		reg = self.arch.get_reg_index(reg)
		return self.expr(LowLevelILOperation.LLIL_SET_REG, reg, value.index, size = size, flags = flags)

	def set_reg_split(self, size, hi, lo, value, flags = 0):
		"""
		``set_reg_split`` uses ``hi`` and ``lo`` as a single extended register setting ``hi:lo`` to the expression
		``value``.

		:param int size: size of the register parameter in bytes
		:param str hi: the high register name
		:param str lo: the low register name
		:param LowLevelILExpr value: an expression to set the split regiters to
		:param str flags: which flags are set by this operation
		:return: The expression ``hi:lo = value``
		:rtype: LowLevelILExpr
		"""
		hi = self.arch.get_reg_index(hi)
		lo = self.arch.get_reg_index(lo)
		return self.expr(LowLevelILOperation.LLIL_SET_REG_SPLIT, hi, lo, value.index, size = size, flags = flags)

	def set_flag(self, flag, value):
		"""
		``set_flag`` sets the flag ``flag`` to the LowLevelILExpr ``value``

		:param str flag: the low register name
		:param LowLevelILExpr value: an expression to set the flag to
		:return: The expression FLAG.flag = value
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_SET_FLAG, self.arch.get_flag_by_name(flag), value.index)

	def load(self, size, addr):
		"""
		``laod`` Reads ``size`` bytes from the expression ``addr``

		:param int size: number of bytes to read
		:param LowLevelILExpr addr: the expression to read memory from
		:return: The expression ``[addr].size``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_LOAD, addr.index, size=size)

	def store(self, size, addr, value, flags=None):
		"""
		``store`` Writes ``size`` bytes to expression ``addr`` read from expression ``value``

		:param int size: number of bytes to write
		:param LowLevelILExpr addr: the expression to write to
		:param LowLevelILExpr value: the expression to be written
		:param str flags: which flags are set by this operation
		:return: The expression ``[addr].size = value``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_STORE, addr.index, value.index, size=size, flags=flags)

	def push(self, size, value):
		"""
		``push`` writes ``size`` bytes from expression ``value`` to the stack, adjusting the stack by ``size``.

		:param int size: number of bytes to write and adjust the stack by
		:param LowLevelILExpr value: the expression to write
		:return: The expression push(value)
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_PUSH, value.index, size=size)

	def pop(self, size):
		"""
		``pop`` reads ``size`` bytes from the stack, adjusting the stack by ``size``.

		:param int size: number of bytes to read from the stack
		:return: The expression ``pop``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_POP, size=size)

	def reg(self, size, reg):
		"""
		``reg`` returns a register of size ``size`` with name ``name``

		:param int size: the size of the register in bytes
		:param str reg: the name of the register
		:return: A register expression for the given string
		:rtype: LowLevelILExpr
		"""
		reg = self.arch.get_reg_index(reg)
		return self.expr(LowLevelILOperation.LLIL_REG, reg, size=size)

	def const(self, size, value):
		"""
		``const`` returns an expression for the constant integer ``value`` with size ``size``

		:param int size: the size of the constant in bytes
		:param int value: integer value of the constant
		:return: A constant expression of given value and size
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_CONST, value, size=size)

	def const_pointer(self, size, value):
		"""
		``const_pointer`` returns an expression for the constant pointer ``value`` with size ``size``

		:param int size: the size of the pointer in bytes
		:param int value: address referenced by pointer
		:return: A constant expression of given value and size
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_CONST_PTR, value, size=size)

	def flag(self, reg):
		"""
		``flag`` returns a flag expression for the given flag name.

		:param str reg: name of the flag expression to retrieve
		:return: A flag expression of given flag name
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_FLAG, self.arch.get_flag_by_name(reg))

	def flag_bit(self, size, reg, bit):
		"""
		``flag_bit`` sets the flag named ``reg`` and size ``size`` to the constant integer value ``bit``

		:param int size: the size of the flag
		:param str reg: flag value
		:param int bit: integer value to set the bit to
		:return: A constant expression of given value and size ``FLAG.reg = bit``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_FLAG_BIT, self.arch.get_flag_by_name(reg), bit, size=size)

	def add(self, size, a, b, flags=None):
		"""
		``add`` adds expression ``a`` to expression ``b`` potentially setting flags ``flags`` and returning
		an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: flags to set
		:return: The expression ``add.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_ADD, a.index, b.index, size=size, flags=flags)

	def add_carry(self, size, a, b, carry, flags=None):
		"""
		``add_carry`` adds with carry expression ``a`` to expression ``b`` potentially setting flags ``flags`` and
		returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param LowLevelILExpr carry: Carry flag expression
		:param str flags: flags to set
		:return: The expression ``adc.<size>{<flags>}(a, b, carry)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_ADC, a.index, b.index, carry.index, size=size, flags=flags)

	def sub(self, size, a, b, flags=None):
		"""
		``sub`` subtracts expression ``b`` from expression ``a`` potentially setting flags ``flags`` and returning
		an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: flags to set
		:return: The expression ``sub.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_SUB, a.index, b.index, size=size, flags=flags)

	def sub_borrow(self, size, a, b, carry, flags=None):
		"""
		``sub_borrow`` subtracts with borrow expression ``b`` from expression ``a`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param LowLevelILExpr carry: Carry flag expression
		:param str flags: flags to set
		:return: The expression ``sbb.<size>{<flags>}(a, b, carry)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_SBB, a.index, b.index, carry.index, size=size, flags=flags)

	def and_expr(self, size, a, b, flags=None):
		"""
		``and_expr`` bitwise and's expression ``a`` and expression ``b`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``and.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_AND, a.index, b.index, size=size, flags=flags)

	def or_expr(self, size, a, b, flags=None):
		"""
		``or_expr`` bitwise or's expression ``a`` and expression ``b`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``or.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_OR, a.index, b.index, size=size, flags=flags)

	def xor_expr(self, size, a, b, flags=None):
		"""
		``xor_expr`` xor's expression ``a`` with expression ``b`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``xor.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_XOR, a.index, b.index, size=size, flags=flags)

	def shift_left(self, size, a, b, flags=None):
		"""
		``shift_left`` subtracts with borrow expression ``b`` from expression ``a`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``lsl.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_LSL, a.index, b.index, size=size, flags=flags)

	def logical_shift_right(self, size, a, b, flags=None):
		"""
		``logical_shift_right`` shifts logically right expression ``a`` by expression ``b`` potentially setting flags
		``flags``and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``lsr.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_LSR, a.index, b.index, size=size, flags=flags)

	def arith_shift_right(self, size, a, b, flags=None):
		"""
		``arith_shift_right`` shifts arithmatic right expression ``a`` by expression ``b``  potentially setting flags
		``flags`` and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``asr.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_ASR, a.index, b.index, size=size, flags=flags)

	def rotate_left(self, size, a, b, flags=None):
		"""
		``rotate_left`` bitwise rotates left expression ``a`` by expression ``b`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``rol.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_ROL, a.index, b.index, size=size, flags=flags)

	def rotate_left_carry(self, size, a, b, carry, flags=None):
		"""
		``rotate_left_carry`` bitwise rotates left with carry expression ``a`` by expression ``b`` potentially setting
		flags ``flags`` and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param LowLevelILExpr carry: Carry flag expression
		:param str flags: optional, flags to set
		:return: The expression ``rlc.<size>{<flags>}(a, b, carry)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_RLC, a.index, b.index, carry.index, size=size, flags=flags)

	def rotate_right(self, size, a, b, flags=None):
		"""
		``rotate_right`` bitwise rotates right expression ``a`` by expression ``b`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``ror.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_ROR, a.index, b.index, size=size, flags=flags)

	def rotate_right_carry(self, size, a, b, carry, flags=None):
		"""
		``rotate_right_carry`` bitwise rotates right with carry expression ``a`` by expression ``b`` potentially setting
		flags ``flags`` and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param LowLevelILExpr carry: Carry flag expression
		:param str flags: optional, flags to set
		:return: The expression ``rrc.<size>{<flags>}(a, b, carry)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_RRC, a.index, b.index, carry.index, size=size, flags=flags)

	def mult(self, size, a, b, flags=None):
		"""
		``mult`` multiplies expression ``a`` by expression ``b`` potentially setting flags ``flags`` and returning an
		expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``sbc.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_MUL, a.index, b.index, size=size, flags=flags)

	def mult_double_prec_signed(self, size, a, b, flags=None):
		"""
		``mult_double_prec_signed`` multiplies signed with double precision expression ``a`` by expression ``b``
		potentially setting flags ``flags`` and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``muls.dp.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_MULS_DP, a.index, b.index, size=size, flags=flags)

	def mult_double_prec_unsigned(self, size, a, b, flags=None):
		"""
		``mult_double_prec_unsigned`` multiplies unsigned with double precision expression ``a`` by expression ``b``
		potentially setting flags ``flags`` and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``muls.dp.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_MULU_DP, a.index, b.index, size=size, flags=flags)

	def div_signed(self, size, a, b, flags=None):
		"""
		``div_signed`` signed divide expression ``a`` by expression ``b`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``divs.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_DIVS, a.index, b.index, size=size, flags=flags)

	def div_double_prec_signed(self, size, hi, lo, b, flags=None):
		"""
		``div_double_prec_signed`` signed double precision divide using expression ``hi`` and expression ``lo`` as a
		single double precision register by expression ``b`` potentially  setting flags ``flags`` and returning an
		expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr hi: high LHS expression
		:param LowLevelILExpr lo: low LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``divs.dp.<size>{<flags>}(hi:lo, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_DIVS_DP, hi.index, lo.index, b.index, size=size, flags=flags)

	def div_unsigned(self, size, a, b, flags=None):
		"""
		``div_unsigned`` unsigned divide expression ``a`` by expression ``b`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``divs.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_DIVS, a.index, b.index, size=size, flags=flags)

	def div_double_prec_unsigned(self, size, hi, lo, b, flags=None):
		"""
		``div_double_prec_unsigned`` unsigned double precision divide using expression ``hi`` and expression ``lo`` as
		a single double precision register by expression ``b`` potentially  setting flags ``flags`` and returning an
		expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr hi: high LHS expression
		:param LowLevelILExpr lo: low LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``divs.dp.<size>{<flags>}(hi:lo, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_DIVS_DP, hi.index, lo.index, b.index, size=size, flags=flags)

	def mod_signed(self, size, a, b, flags=None):
		"""
		``mod_signed`` signed modulus expression ``a`` by expression ``b`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``mods.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_MODS, a.index, b.index, size=size, flags=flags)

	def mod_double_prec_signed(self, size, hi, lo, b, flags=None):
		"""
		``mod_double_prec_signed`` signed double precision modulus using expression ``hi`` and expression ``lo`` as a single
		double precision register by expression ``b`` potentially  setting flags ``flags`` and returning an expression
		of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr hi: high LHS expression
		:param LowLevelILExpr lo: low LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``mods.dp.<size>{<flags>}(hi:lo, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_MODS_DP, hi.index, lo.index, b.index, size=size, flags=flags)

	def mod_unsigned(self, size, a, b, flags=None):
		"""
		``mod_unsigned`` unsigned modulus expression ``a`` by expression ``b`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``modu.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_MODS, a.index, b.index, size=size, flags=flags)

	def mod_double_prec_unsigned(self, size, hi, lo, b, flags=None):
		"""
		``mod_double_prec_unsigned`` unsigned double precision modulus using expression ``hi`` and expression ``lo`` as
		a single double precision register by expression ``b`` potentially  setting flags ``flags`` and returning an
		expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr hi: high LHS expression
		:param LowLevelILExpr lo: low LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``modu.dp.<size>{<flags>}(hi:lo, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_MODS_DP, hi.index, lo.index, b.index, size=size, flags=flags)

	def neg_expr(self, size, value, flags=None):
		"""
		``neg_expr`` two's complement sign negation of expression ``value`` of size ``size`` potentially setting flags

		:param int size: the size of the result in bytes
		:param LowLevelILExpr value: the expression to negate
		:param str flags: optional, flags to set
		:return: The expression ``neg.<size>{<flags>}(value)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_NEG, value.index, size=size, flags=flags)

	def not_expr(self, size, value, flags=None):
		"""
		``not_expr`` bitwise inverse of expression ``value`` of size ``size`` potentially setting flags

		:param int size: the size of the result in bytes
		:param LowLevelILExpr value: the expression to bitwise invert
		:param str flags: optional, flags to set
		:return: The expression ``not.<size>{<flags>}(value)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_NOT, value.index, size=size, flags=flags)

	def sign_extend(self, size, value, flags=None):
		"""
		``sign_extend`` two's complement sign-extends the expression in ``value`` to ``size`` bytes

		:param int size: the size of the result in bytes
		:param LowLevelILExpr value: the expression to sign extn
		:param str flags: optional, flags to set
		:return: The expression ``sx.<size>(value)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_SX, value.index, size=size, flags=flags)

	def zero_extend(self, size, value, flags=None):
		"""
		``zero_extend`` zero-extends the expression in ``value`` to ``size`` bytes

		:param int size: the size of the result in bytes
		:param LowLevelILExpr value: the expression to zero extend
		:return: The expression ``sx.<size>(value)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_ZX, value.index, size=size, flags=flags)

	def low_part(self, size, value, flags=None):
		"""
		``low_part`` truncates ``value`` to ``size`` bytes

		:param int size: the size of the result in bytes
		:param LowLevelILExpr value: the expression to zero extend
		:return: The expression ``(value).<size>``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_LOW_PART, value.index, size=size, flags=flags)

	def jump(self, dest):
		"""
		``jump`` returns an expression which jumps (branches) to the expression ``dest``

		:param LowLevelILExpr dest: the expression to jump to
		:return: The expression ``jump(dest)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_JUMP, dest.index)

	def call(self, dest):
		"""
		``call`` returns an expression which first pushes the address of the next instruction onto the stack then jumps
		(branches) to the expression ``dest``

		:param LowLevelILExpr dest: the expression to call
		:return: The expression ``call(dest)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_CALL, dest.index)

	def call_stack_adjust(self, dest, stack_adjust):
		"""
		``call_stack_adjust`` returns an expression which first pushes the address of the next instruction onto the stack
		then jumps (branches) to the expression ``dest``. After the function exits, ``stack_adjust`` is added to the
		stack pointer register.

		:param LowLevelILExpr dest: the expression to call
		:return: The expression ``call(dest), stack += stack_adjust``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_CALL_STACK_ADJUST, dest.index, stack_adjust)

	def ret(self, dest):
		"""
		``ret`` returns an expression which jumps (branches) to the expression ``dest``. ``ret`` is a special alias for
		jump that makes the disassembler top disassembling.

		:param LowLevelILExpr dest: the expression to jump to
		:return: The expression ``jump(dest)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_RET, dest.index)

	def no_ret(self):
		"""
		``no_ret`` returns an expression halts disassembly

		:return: The expression ``noreturn``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_NORET)

	def flag_condition(self, cond):
		"""
		``flag_condition`` returns a flag_condition expression for the given LowLevelILFlagCondition

		:param LowLevelILFlagCondition cond: Flag condition expression to retrieve
		:return: A flag_condition expression
		:rtype: LowLevelILExpr
		"""
		if isinstance(cond, str):
			cond = LowLevelILFlagCondition[cond]
		elif isinstance(cond, LowLevelILFlagCondition):
			cond = cond.value
		return self.expr(LowLevelILOperation.LLIL_FLAG_COND, cond)

	def compare_equal(self, size, a, b):
		"""
		``compare_equal`` returns comparison expression of size ``size`` checking if expression ``a`` is equal to
		expression ``b``

		:param int size: size in bytes
		:param LowLevelILExpr a: LHS of comparison
		:param LowLevelILExpr b: RHS of comparison
		:return: a comparison expression.
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_CMP_E, a.index, b.index, size = size)

	def compare_not_equal(self, size, a, b):
		"""
		``compare_not_equal`` returns comparison expression of size ``size`` checking if expression ``a`` is not equal to
		expression ``b``

		:param int size: size in bytes
		:param LowLevelILExpr a: LHS of comparison
		:param LowLevelILExpr b: RHS of comparison
		:return: a comparison expression.
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_CMP_NE, a.index, b.index, size = size)

	def compare_signed_less_than(self, size, a, b):
		"""
		``compare_signed_less_than`` returns comparison expression of size ``size`` checking if expression ``a`` is
		signed less than expression ``b``

		:param int size: size in bytes
		:param LowLevelILExpr a: LHS of comparison
		:param LowLevelILExpr b: RHS of comparison
		:return: a comparison expression.
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_CMP_SLT, a.index, b.index, size = size)

	def compare_unsigned_less_than(self, size, a, b):
		"""
		``compare_unsigned_less_than`` returns comparison expression of size ``size`` checking if expression ``a`` is
		unsigned less than expression ``b``

		:param int size: size in bytes
		:param LowLevelILExpr a: LHS of comparison
		:param LowLevelILExpr b: RHS of comparison
		:return: a comparison expression.
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_CMP_ULT, a.index, b.index, size = size)

	def compare_signed_less_equal(self, size, a, b):
		"""
		``compare_signed_less_equal`` returns comparison expression of size ``size`` checking if expression ``a`` is
		signed less than or equal to expression ``b``

		:param int size: size in bytes
		:param LowLevelILExpr a: LHS of comparison
		:param LowLevelILExpr b: RHS of comparison
		:return: a comparison expression.
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_CMP_SLE, a.index, b.index, size = size)

	def compare_unsigned_less_equal(self, size, a, b):
		"""
		``compare_unsigned_less_equal`` returns comparison expression of size ``size`` checking if expression ``a`` is
		unsigned less than or equal to expression ``b``

		:param int size: size in bytes
		:param LowLevelILExpr a: LHS of comparison
		:param LowLevelILExpr b: RHS of comparison
		:return: a comparison expression.
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_CMP_ULE, a.index, b.index, size = size)

	def compare_signed_greater_equal(self, size, a, b):
		"""
		``compare_signed_greater_equal`` returns comparison expression of size ``size`` checking if expression ``a`` is
		signed greater than or equal toexpression ``b``

		:param int size: size in bytes
		:param LowLevelILExpr a: LHS of comparison
		:param LowLevelILExpr b: RHS of comparison
		:return: a comparison expression.
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_CMP_SGE, a.index, b.index, size = size)

	def compare_unsigned_greater_equal(self, size, a, b):
		"""
		``compare_unsigned_greater_equal`` returns comparison expression of size ``size`` checking if expression ``a``
		is unsigned greater than or equal to expression ``b``

		:param int size: size in bytes
		:param LowLevelILExpr a: LHS of comparison
		:param LowLevelILExpr b: RHS of comparison
		:return: a comparison expression.
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_CMP_UGE, a.index, b.index, size = size)

	def compare_signed_greater_than(self, size, a, b):
		"""
		``compare_signed_greater_than`` returns comparison expression of size ``size`` checking if expression ``a`` is
		signed greater than or equal to expression ``b``

		:param int size: size in bytes
		:param LowLevelILExpr a: LHS of comparison
		:param LowLevelILExpr b: RHS of comparison
		:return: a comparison expression.
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_CMP_SGT, a.index, b.index, size = size)

	def compare_unsigned_greater_than(self, size, a, b):
		"""
		``compare_unsigned_greater_than`` returns comparison expression of size ``size`` checking if expression ``a`` is
		unsigned greater than or equal to expression ``b``

		:param int size: size in bytes
		:param LowLevelILExpr a: LHS of comparison
		:param LowLevelILExpr b: RHS of comparison
		:return: a comparison expression.
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_CMP_UGT, a.index, b.index, size = size)

	def test_bit(self, size, a, b):
		return self.expr(LowLevelILOperation.LLIL_TEST_BIT, a.index, b.index, size = size)

	def system_call(self):
		"""
		``system_call`` return a system call expression.

		:return: a system call expression.
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_SYSCALL)

	def breakpoint(self):
		"""
		``breakpoint`` returns a processor breakpoint expression.

		:return: a breakpoint expression.
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_BP)

	def trap(self, value):
		"""
		``trap`` returns a processor trap (interrupt) expression of the given integer ``value``.

		:param int value: trap (interrupt) number
		:return: a trap expression.
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_TRAP, value)

	def undefined(self):
		"""
		``undefined`` returns the undefined expression. This should be used for instructions which perform functions but
		aren't important for dataflow or partial emulation purposes.

		:return: the unimplemented expression.
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_UNDEF)

	def unimplemented(self):
		"""
		``unimplemented`` returns the unimplemented expression. This should be used for all instructions which aren't
		implemented.

		:return: the unimplemented expression.
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_UNIMPL)

	def unimplemented_memory_ref(self, size, addr):
		"""
		``unimplemented_memory_ref`` a memory reference to expression ``addr`` of size ``size`` with unimplemented operation.

		:param int size: size in bytes of the memory reference
		:param LowLevelILExpr addr: expression to reference memory
		:return: the unimplemented memory reference expression.
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_UNIMPL_MEM, addr.index, size = size)

	def goto(self, label):
		"""
		``goto`` returns a goto expression which jumps to the provided LowLevelILLabel.

		:param LowLevelILLabel label: Label to jump to
		:return: the LowLevelILExpr that jumps to the provided label
		:rtype: LowLevelILExpr
		"""
		return LowLevelILExpr(core.BNLowLevelILGoto(self.handle, label.handle))

	def if_expr(self, operand, t, f):
		"""
		``if_expr`` returns the ``if`` expression which depending on condition ``operand`` jumps to the LowLevelILLabel
		``t`` when the condition expression ``operand`` is non-zero and ``f`` when it's zero.

		:param LowLevelILExpr operand: comparison expression to evaluate.
		:param LowLevelILLabel t: Label for the true branch
		:param LowLevelILLabel f: Label for the false branch
		:return: the LowLevelILExpr for the if expression
		:rtype: LowLevelILExpr
		"""
		return LowLevelILExpr(core.BNLowLevelILIf(self.handle, operand.index, t.handle, f.handle))

	def mark_label(self, label):
		"""
		``mark_label`` assigns a LowLevelILLabel to the current IL address.

		:param LowLevelILLabel label:
		:rtype: None
		"""
		core.BNLowLevelILMarkLabel(self.handle, label.handle)

	def add_label_list(self, labels):
		"""
		``add_label_list`` returns a label list expression for the given list of LowLevelILLabel objects.

		:param list(LowLevelILLabel) lables: the list of LowLevelILLabel to get a label list expression from
		:return: the label list expression
		:rtype: LowLevelILExpr
		"""
		label_list = (ctypes.POINTER(core.BNLowLevelILLabel) * len(labels))()
		for i in xrange(len(labels)):
			label_list[i] = labels[i].handle
		return LowLevelILExpr(core.BNLowLevelILAddLabelList(self.handle, label_list, len(labels)))

	def add_operand_list(self, operands):
		"""
		``add_operand_list`` returns an operand list expression for the given list of integer operands.

		:param list(int) operands: list of operand numbers
		:return: an operand list expression
		:rtype: LowLevelILExpr
		"""
		operand_list = (ctypes.c_ulonglong * len(operands))()
		for i in xrange(len(operands)):
			operand_list[i] = operands[i]
		return LowLevelILExpr(core.BNLowLevelILAddOperandList(self.handle, operand_list, len(operands)))

	def operand(self, n, expr):
		"""
		``operand`` sets the operand number of the expression ``expr`` and passes back ``expr`` without modification.

		:param int n:
		:param LowLevelILExpr expr:
		:return: returns the expression ``expr`` unmodified
		:rtype: LowLevelILExpr
		"""
		core.BNLowLevelILSetExprSourceOperand(self.handle, expr.index, n)
		return expr

	def finalize(self):
		"""
		``finalize`` ends the function and computes the list of basic blocks.

		:rtype: None
		"""
		core.BNFinalizeLowLevelILFunction(self.handle)

	def add_label_for_address(self, arch, addr):
		"""
		``add_label_for_address`` adds a low-level IL label for the given architecture ``arch`` at the given virtual
		address ``addr``

		:param Architecture arch: Architecture to add labels for
		:param int addr: the IL address to add a label at
		"""
		if arch is not None:
			arch = arch.handle
		core.BNAddLowLevelILLabelForAddress(self.handle, arch, addr)

	def get_label_for_address(self, arch, addr):
		"""
		``get_label_for_address`` returns the LowLevelILLabel for the given Architecture ``arch`` and IL address ``addr``.

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

	def get_ssa_instruction_index(self, instr):
		return core.BNGetLowLevelILSSAInstructionIndex(self.handle, instr)

	def get_non_ssa_instruction_index(self, instr):
		return core.BNGetLowLevelILNonSSAInstructionIndex(self.handle, instr)

	def get_ssa_reg_definition(self, reg_ssa):
		reg = self.arch.get_reg_index(reg_ssa.reg)
		result = core.BNGetLowLevelILSSARegisterDefinition(self.handle, reg, reg_ssa.version)
		if result >= core.BNGetLowLevelILInstructionCount(self.handle):
			return None
		return result

	def get_ssa_flag_definition(self, flag_ssa):
		flag = self.arch.get_flag_index(flag_ssa.flag)
		result = core.BNGetLowLevelILSSAFlagDefinition(self.handle, flag, flag_ssa.version)
		if result >= core.BNGetLowLevelILInstructionCount(self.handle):
			return None
		return result

	def get_ssa_memory_definition(self, index):
		result = core.BNGetLowLevelILSSAMemoryDefinition(self.handle, index)
		if result >= core.BNGetLowLevelILInstructionCount(self.handle):
			return None
		return result

	def get_ssa_reg_uses(self, reg_ssa):
		reg = self.arch.get_reg_index(reg_ssa.reg)
		count = ctypes.c_ulonglong()
		instrs = core.BNGetLowLevelILSSARegisterUses(self.handle, reg, reg_ssa.version, count)
		result = []
		for i in xrange(0, count.value):
			result.append(instrs[i])
		core.BNFreeILInstructionList(instrs)
		return result

	def get_ssa_flag_uses(self, flag_ssa):
		flag = self.arch.get_flag_index(flag_ssa.flag)
		count = ctypes.c_ulonglong()
		instrs = core.BNGetLowLevelILSSAFlagUses(self.handle, flag, flag_ssa.version, count)
		result = []
		for i in xrange(0, count.value):
			result.append(instrs[i])
		core.BNFreeILInstructionList(instrs)
		return result

	def get_ssa_memory_uses(self, index):
		count = ctypes.c_ulonglong()
		instrs = core.BNGetLowLevelILSSAMemoryUses(self.handle, index, count)
		result = []
		for i in xrange(0, count.value):
			result.append(instrs[i])
		core.BNFreeILInstructionList(instrs)
		return result

	def get_ssa_reg_value(self, reg_ssa):
		reg = self.arch.get_reg_index(reg_ssa.reg)
		value = core.BNGetLowLevelILSSARegisterValue(self.handle, reg, reg_ssa.version)
		result = function.RegisterValue(self.arch, value)
		return result

	def get_ssa_flag_value(self, flag_ssa):
		flag = self.arch.get_flag_index(flag_ssa.flag)
		value = core.BNGetLowLevelILSSAFlagValue(self.handle, flag, flag_ssa.version)
		result = function.RegisterValue(self.arch, value)
		return result

	def get_medium_level_il_instruction_index(self, instr):
		med_il = self.medium_level_il
		if med_il is None:
			return None
		result = core.BNGetMediumLevelILInstructionIndex(self.handle, instr)
		if result >= core.BNGetMediumLevelILInstructionCount(med_il.handle):
			return None
		return result

	def get_medium_level_il_expr_index(self, expr):
		med_il = self.medium_level_il
		if med_il is None:
			return None
		result = core.BNGetMediumLevelILExprIndex(self.handle, expr)
		if result >= core.BNGetMediumLevelILExprCount(med_il.handle):
			return None
		return result

	def get_mapped_medium_level_il_instruction_index(self, instr):
		med_il = self.mapped_medium_level_il
		if med_il is None:
			return None
		result = core.BNGetMappedMediumLevelILInstructionIndex(self.handle, instr)
		if result >= core.BNGetMediumLevelILInstructionCount(med_il.handle):
			return None
		return result

	def get_mapped_medium_level_il_expr_index(self, expr):
		med_il = self.mapped_medium_level_il
		if med_il is None:
			return None
		result = core.BNGetMappedMediumLevelILExprIndex(self.handle, expr)
		if result >= core.BNGetMediumLevelILExprCount(med_il.handle):
			return None
		return result


class LowLevelILBasicBlock(basicblock.BasicBlock):
	def __init__(self, view, handle, owner):
		super(LowLevelILBasicBlock, self).__init__(view, handle)
		self.il_function = owner

	def __iter__(self):
		for idx in xrange(self.start, self.end):
			yield self.il_function[idx]

	def __getitem__(self, idx):
		size = self.end - self.start
		if idx > size or idx < -size:
			raise IndexError("list index is out of range")
		if idx >= 0:
			return self.il_function[idx + self.start]
		else:
			return self.il_function[self.end + idx]

	def _create_instance(self, view, handle):
		"""Internal method by super to instantiante child instances"""
		return LowLevelILBasicBlock(view, handle, self.il_function)

def LLIL_TEMP(n):
	return n | 0x80000000


def LLIL_REG_IS_TEMP(n):
	return (n & 0x80000000) != 0


def LLIL_GET_TEMP_REG_INDEX(n):
	return n & 0x7fffffff
