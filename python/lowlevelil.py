# Copyright (c) 2015-2020 Vector 35 Inc
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
from binaryninja.enums import LowLevelILOperation, LowLevelILFlagCondition, InstructionTextTokenType
from binaryninja import basicblock #required for LowLevelILBasicBlock

# 2-3 compatibility
from binaryninja import range


class LowLevelILLabel(object):
	def __init__(self, handle = None):
		if handle is None:
			self.handle = (core.BNLowLevelILLabel * 1)()
			core.BNLowLevelILInitLabel(self.handle)
		else:
			self.handle = handle


class ILRegister(object):
	def __init__(self, arch, reg):
		self._arch = arch
		self._index = reg
		self._temp = (self._index & 0x80000000) != 0
		if self._temp:
			self._name = "temp%d" % (self._index & 0x7fffffff)
		else:
			self._name = self._arch.get_reg_name(self._index)

	@property
	def info(self):
		return self._arch.regs[self._name]

	def __repr__(self):
		return self._name

	def __str__(self):
		return self._name

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return (self._arch, self._index, self._name) == (other._arch, other._index, other._name)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash((self._arch, self._index, self._name))

	@property
	def arch(self):
		""" """
		return self._arch

	@arch.setter
	def arch(self, value):
		self._arch = value

	@property
	def index(self):
		""" """
		return self._index

	@index.setter
	def index(self, value):
		self._index = value

	@property
	def temp(self):
		""" """
		return self._temp

	@temp.setter
	def temp(self, value):
		self._temp = value

	@property
	def name(self):
		""" """
		return self._name

	@name.setter
	def name(self, value):
		self._name = value


class ILRegisterStack(object):
	def __init__(self, arch, reg_stack):
		self._arch = arch
		self._index = reg_stack
		self._name = self._arch.get_reg_stack_name(self._index)

	@property
	def info(self):
		return self._arch.reg_stacks[self._name]

	def __repr__(self):
		return self._name

	def __str__(self):
		return self._name

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return (self._arch, self._index, self._name) == (other._arch, other._index, other._name)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash((self._arch, self._index, self._name))

	@property
	def arch(self):
		""" """
		return self._arch

	@arch.setter
	def arch(self, value):
		self._arch = value

	@property
	def index(self):
		""" """
		return self._index

	@index.setter
	def index(self, value):
		self._index = value

	@property
	def name(self):
		""" """
		return self._name

	@name.setter
	def name(self, value):
		self._name = value


class ILFlag(object):
	def __init__(self, arch, flag):
		self._arch = arch
		self._index = flag
		self._temp = (self._index & 0x80000000) != 0
		if self._temp:
			self._name = "cond:%d" % (self._index & 0x7fffffff)
		else:
			self._name = self._arch.get_flag_name(self._index)

	def __repr__(self):
		return self._name

	def __str__(self):
		return self._name

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return (self._arch, self._index, self._name) == (other._arch, other._index, other._name)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash((self._arch, self._index, self._name))

	@property
	def arch(self):
		""" """
		return self._arch

	@arch.setter
	def arch(self, value):
		self._arch = value

	@property
	def index(self):
		""" """
		return self._index

	@index.setter
	def index(self, value):
		self._index = value

	@property
	def temp(self):
		""" """
		return self._temp

	@temp.setter
	def temp(self, value):
		self._temp = value

	@property
	def name(self):
		""" """
		return self._name

	@name.setter
	def name(self, value):
		self._name = value


class ILSemanticFlagClass(object):
	def __init__(self, arch, sem_class):
		self._arch = arch
		self._index = sem_class
		self._name = self._arch.get_semantic_flag_class_name(self._index)

	def __repr__(self):
		return self._name

	def __str__(self):
		return self._name

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return (self._arch, self._index, self._name) == (other._arch, other._index, other._name)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash((self._arch, self._index, self._name))

	@property
	def arch(self):
		""" """
		return self._arch

	@arch.setter
	def arch(self, value):
		self._arch = value

	@property
	def index(self):
		""" """
		return self._index

	@index.setter
	def index(self, value):
		self._index = value

	@property
	def name(self):
		""" """
		return self._name

	@name.setter
	def name(self, value):
		self._name = value


class ILSemanticFlagGroup(object):
	def __init__(self, arch, sem_group):
		self._arch = arch
		self._index = sem_group
		self._name = self._arch.get_semantic_flag_group_name(self._index)

	def __repr__(self):
		return self._name

	def __str__(self):
		return self._name

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return (self._arch, self._index, self._name) == (other._arch, other._index, other._name)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash((self._arch, self._index, self._name))

	@property
	def arch(self):
		""" """
		return self._arch

	@arch.setter
	def arch(self, value):
		self._arch = value

	@property
	def index(self):
		""" """
		return self._index

	@index.setter
	def index(self, value):
		self._index = value

	@property
	def name(self):
		""" """
		return self._name

	@name.setter
	def name(self, value):
		self._name = value


class ILIntrinsic(object):
	def __init__(self, arch, intrinsic):
		self._arch = arch
		self._index = intrinsic
		self._name = self._arch.get_intrinsic_name(self._index)
		if self._name in self._arch.intrinsics:
			self._inputs = self._arch.intrinsics[self._name].inputs
			self._outputs = self._arch.intrinsics[self._name].outputs

	def __repr__(self):
		return self._name

	def __str__(self):
		return self._name

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return (self._arch, self._index, self._name) == (other._arch, other._index, other._name)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash((self._arch, self._index, self._name))

	@property
	def arch(self):
		""" """
		return self._arch

	@arch.setter
	def arch(self, value):
		self._arch = value

	@property
	def index(self):
		""" """
		return self._index

	@index.setter
	def index(self, value):
		self._index = value

	@property
	def name(self):
		""" """
		return self._name

	@name.setter
	def name(self, value):
		self._name = value

	@property
	def inputs(self):
		"""``inputs`` is only available if the IL intrinsic is an Architecture intrinsic """
		return self._inputs

	@inputs.setter
	def inputs(self, value):
		self._inputs = value

	@property
	def outputs(self):
		"""``outputs`` is only available if the IL intrinsic is an Architecture intrinsic """
		return self._outputs

	@outputs.setter
	def outputs(self, value):
		self._outputs = value


class SSARegister(object):
	def __init__(self, reg, version):
		self._reg = reg
		self._version = version

	def __repr__(self):
		return "<ssa %s version %d>" % (repr(self._reg), self._version)

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return (self._reg, self._version) == (other._reg, other._version)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash((self._reg, self._version))

	@property
	def reg(self):
		""" """
		return self._reg

	@reg.setter
	def reg(self, value):
		self._reg = value

	@property
	def version(self):
		""" """
		return self._version

	@version.setter
	def version(self, value):
		self._version = value


class SSARegisterStack(object):
	def __init__(self, reg_stack, version):
		self._reg_stack = reg_stack
		self._version = version

	def __repr__(self):
		return "<ssa %s version %d>" % (repr(self._reg_stack), self._version)

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return (self._reg_stack, self._version) == (other._reg_stack, other._version)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash((self._reg_stack, self._version))

	@property
	def reg_stack(self):
		""" """
		return self._reg_stack

	@reg_stack.setter
	def reg_stack(self, value):
		self._reg_stack = value

	@property
	def version(self):
		""" """
		return self._version

	@version.setter
	def version(self, value):
		self._version = value


class SSAFlag(object):
	def __init__(self, flag, version):
		self._flag = flag
		self._version = version

	def __repr__(self):
		return "<ssa %s version %d>" % (repr(self._flag), self._version)

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return (self._flag, self._version) == (other._flag, other._version)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash((self._flag, self._version))

	@property
	def flag(self):
		""" """
		return self._flag

	@flag.setter
	def flag(self, value):
		self._flag = value

	@property
	def version(self):
		""" """
		return self._version

	@version.setter
	def version(self, value):
		self._version = value


class SSARegisterOrFlag(object):
	def __init__(self, reg_or_flag, version):
		self._reg_or_flag = reg_or_flag
		self._version = version

	def __repr__(self):
		return "<ssa %s version %d>" % (repr(self._reg_or_flag), self._version)

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return (self._reg_or_flag == other._reg_or_flag) and (self._version == other._version)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash((self._reg_or_flag, self._version))

	@property
	def reg_or_flag(self):
		""" """
		return self._reg_or_flag

	@reg_or_flag.setter
	def reg_or_flag(self, value):
		self._reg_or_flag = value

	@property
	def version(self):
		""" """
		return self._version

	@version.setter
	def version(self, value):
		self._version = value


class LowLevelILOperationAndSize(object):
	def __init__(self, operation, size):
		self._operation = operation
		self._size = size

	def __repr__(self):
		if self._size == 0:
			return "<%s>" % self._operation.name
		return "<%s %d>" % (self._operation.name, self._size)

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return (self._operation, self._size) == (other._operation, other._size)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

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
		LowLevelILOperation.LLIL_SET_REG_STACK_REL: [("stack", "reg_stack"), ("dest", "expr"), ("src", "expr")],
		LowLevelILOperation.LLIL_REG_STACK_PUSH: [("stack", "reg_stack"), ("src", "expr")],
		LowLevelILOperation.LLIL_SET_FLAG: [("dest", "flag"), ("src", "expr")],
		LowLevelILOperation.LLIL_LOAD: [("src", "expr")],
		LowLevelILOperation.LLIL_STORE: [("dest", "expr"), ("src", "expr")],
		LowLevelILOperation.LLIL_PUSH: [("src", "expr")],
		LowLevelILOperation.LLIL_POP: [],
		LowLevelILOperation.LLIL_REG: [("src", "reg")],
		LowLevelILOperation.LLIL_REG_SPLIT: [("hi", "reg"), ("lo", "reg")],
		LowLevelILOperation.LLIL_REG_STACK_REL: [("stack", "reg_stack"), ("src", "expr")],
		LowLevelILOperation.LLIL_REG_STACK_POP: [("stack", "reg_stack")],
		LowLevelILOperation.LLIL_REG_STACK_FREE_REG: [("dest", "reg")],
		LowLevelILOperation.LLIL_REG_STACK_FREE_REL: [("stack", "reg_stack"), ("dest", "expr")],
		LowLevelILOperation.LLIL_CONST: [("constant", "int")],
		LowLevelILOperation.LLIL_CONST_PTR: [("constant", "int")],
		LowLevelILOperation.LLIL_EXTERN_PTR: [("constant", "int"), ("offset", "int")],
		LowLevelILOperation.LLIL_FLOAT_CONST: [("constant", "float")],
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
		LowLevelILOperation.LLIL_DIVU_DP: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_DIVS: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_DIVS_DP: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_MODU: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_MODU_DP: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_MODS: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_MODS_DP: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_NEG: [("src", "expr")],
		LowLevelILOperation.LLIL_NOT: [("src", "expr")],
		LowLevelILOperation.LLIL_SX: [("src", "expr")],
		LowLevelILOperation.LLIL_ZX: [("src", "expr")],
		LowLevelILOperation.LLIL_LOW_PART: [("src", "expr")],
		LowLevelILOperation.LLIL_JUMP: [("dest", "expr")],
		LowLevelILOperation.LLIL_JUMP_TO: [("dest", "expr"), ("targets", "target_map")],
		LowLevelILOperation.LLIL_CALL: [("dest", "expr")],
		LowLevelILOperation.LLIL_CALL_STACK_ADJUST: [("dest", "expr"), ("stack_adjustment", "int"), ("reg_stack_adjustments", "reg_stack_adjust")],
		LowLevelILOperation.LLIL_TAILCALL: [("dest", "expr")],
		LowLevelILOperation.LLIL_RET: [("dest", "expr")],
		LowLevelILOperation.LLIL_NORET: [],
		LowLevelILOperation.LLIL_IF: [("condition", "expr"), ("true", "int"), ("false", "int")],
		LowLevelILOperation.LLIL_GOTO: [("dest", "int")],
		LowLevelILOperation.LLIL_FLAG_COND: [("condition", "cond"), ("semantic_class", "sem_class")],
		LowLevelILOperation.LLIL_FLAG_GROUP: [("semantic_group", "sem_group")],
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
		LowLevelILOperation.LLIL_INTRINSIC: [("output", "reg_or_flag_list"), ("intrinsic", "intrinsic"), ("param", "expr")],
		LowLevelILOperation.LLIL_INTRINSIC_SSA: [("output", "reg_or_flag_ssa_list"), ("intrinsic", "intrinsic"), ("param", "expr")],
		LowLevelILOperation.LLIL_BP: [],
		LowLevelILOperation.LLIL_TRAP: [("vector", "int")],
		LowLevelILOperation.LLIL_UNDEF: [],
		LowLevelILOperation.LLIL_UNIMPL: [],
		LowLevelILOperation.LLIL_UNIMPL_MEM: [("src", "expr")],
		LowLevelILOperation.LLIL_FADD: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_FSUB: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_FMUL: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_FDIV: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_FSQRT: [("src", "expr")],
		LowLevelILOperation.LLIL_FNEG: [("src", "expr")],
		LowLevelILOperation.LLIL_FABS: [("src", "expr")],
		LowLevelILOperation.LLIL_FLOAT_TO_INT: [("src", "expr")],
		LowLevelILOperation.LLIL_INT_TO_FLOAT: [("src", "expr")],
		LowLevelILOperation.LLIL_FLOAT_CONV: [("src", "expr")],
		LowLevelILOperation.LLIL_ROUND_TO_INT: [("src", "expr")],
		LowLevelILOperation.LLIL_FLOOR: [("src", "expr")],
		LowLevelILOperation.LLIL_CEIL: [("src", "expr")],
		LowLevelILOperation.LLIL_FTRUNC: [("src", "expr")],
		LowLevelILOperation.LLIL_FCMP_E: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_FCMP_NE: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_FCMP_LT: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_FCMP_LE: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_FCMP_GE: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_FCMP_GT: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_FCMP_O: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_FCMP_UO: [("left", "expr"), ("right", "expr")],
		LowLevelILOperation.LLIL_SET_REG_SSA: [("dest", "reg_ssa"), ("src", "expr")],
		LowLevelILOperation.LLIL_SET_REG_SSA_PARTIAL: [("full_reg", "reg_ssa"), ("dest", "reg"), ("src", "expr")],
		LowLevelILOperation.LLIL_SET_REG_SPLIT_SSA: [("hi", "expr"), ("lo", "expr"), ("src", "expr")],
		LowLevelILOperation.LLIL_SET_REG_STACK_REL_SSA: [("stack", "expr"), ("dest", "expr"), ("top", "expr"), ("src", "expr")],
		LowLevelILOperation.LLIL_SET_REG_STACK_ABS_SSA: [("stack", "expr"), ("dest", "reg"), ("src", "expr")],
		LowLevelILOperation.LLIL_REG_SPLIT_DEST_SSA: [("dest", "reg_ssa")],
		LowLevelILOperation.LLIL_REG_STACK_DEST_SSA: [("src", "reg_stack_ssa_dest_and_src")],
		LowLevelILOperation.LLIL_REG_SSA: [("src", "reg_ssa")],
		LowLevelILOperation.LLIL_REG_SSA_PARTIAL: [("full_reg", "reg_ssa"), ("src", "reg")],
		LowLevelILOperation.LLIL_REG_SPLIT_SSA: [("hi", "reg_ssa"), ("lo", "reg_ssa")],
		LowLevelILOperation.LLIL_REG_STACK_REL_SSA: [("stack", "reg_stack_ssa"), ("src", "expr"), ("top", "expr")],
		LowLevelILOperation.LLIL_REG_STACK_ABS_SSA: [("stack", "reg_stack_ssa"), ("src", "reg")],
		LowLevelILOperation.LLIL_REG_STACK_FREE_REL_SSA: [("stack", "expr"), ("dest", "expr"), ("top", "expr")],
		LowLevelILOperation.LLIL_REG_STACK_FREE_ABS_SSA: [("stack", "expr"), ("dest", "reg")],
		LowLevelILOperation.LLIL_SET_FLAG_SSA: [("dest", "flag_ssa"), ("src", "expr")],
		LowLevelILOperation.LLIL_FLAG_SSA: [("src", "flag_ssa")],
		LowLevelILOperation.LLIL_FLAG_BIT_SSA: [("src", "flag_ssa"), ("bit", "int")],
		LowLevelILOperation.LLIL_CALL_SSA: [("output", "expr"), ("dest", "expr"), ("stack", "expr"), ("param", "expr")],
		LowLevelILOperation.LLIL_SYSCALL_SSA: [("output", "expr"), ("stack", "expr"), ("param", "expr")],
		LowLevelILOperation.LLIL_TAILCALL_SSA: [("output", "expr"), ("dest", "expr"), ("stack", "expr"), ("param", "expr")],
		LowLevelILOperation.LLIL_CALL_OUTPUT_SSA: [("dest_memory", "int"), ("dest", "reg_ssa_list")],
		LowLevelILOperation.LLIL_CALL_STACK_SSA: [("src", "reg_ssa"), ("src_memory", "int")],
		LowLevelILOperation.LLIL_CALL_PARAM: [("src", "expr_list")],
		LowLevelILOperation.LLIL_LOAD_SSA: [("src", "expr"), ("src_memory", "int")],
		LowLevelILOperation.LLIL_STORE_SSA: [("dest", "expr"), ("dest_memory", "int"), ("src_memory", "int"), ("src", "expr")],
		LowLevelILOperation.LLIL_REG_PHI: [("dest", "reg_ssa"), ("src", "reg_ssa_list")],
		LowLevelILOperation.LLIL_REG_STACK_PHI: [("dest", "reg_stack_ssa"), ("src", "reg_stack_ssa_list")],
		LowLevelILOperation.LLIL_FLAG_PHI: [("dest", "flag_ssa"), ("src", "flag_ssa_list")],
		LowLevelILOperation.LLIL_MEM_PHI: [("dest_memory", "int"), ("src_memory", "int_list")]
	}

	def __init__(self, func, expr_index, instr_index=None):
		instr = core.BNGetLowLevelILByIndex(func.handle, expr_index)
		self._function = func
		self._expr_index = expr_index
		self._instr_index = instr_index
		self._operation = LowLevelILOperation(instr.operation)
		self._size = instr.size
		self._address = instr.address
		self._source_operand = instr.sourceOperand
		if instr.flags == 0:
			self._flags = None
		else:
			self._flags = func.arch.get_flag_write_type_name(instr.flags)
		if self._source_operand == 0xffffffff:
			self._source_operand = None
		operands = LowLevelILInstruction.ILOperations[instr.operation]
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
				value = LowLevelILInstruction(func, instr.operands[i])
			elif operand_type == "reg":
				value = ILRegister(func.arch, instr.operands[i])
			elif operand_type == "reg_stack":
				value = ILRegisterStack(func.arch, instr.operands[i])
			elif operand_type == "intrinsic":
				value = ILIntrinsic(func.arch, instr.operands[i])
			elif operand_type == "reg_ssa":
				reg = ILRegister(func.arch, instr.operands[i])
				i += 1
				value = SSARegister(reg, instr.operands[i])
			elif operand_type == "reg_stack_ssa":
				reg_stack = ILRegisterStack(func.arch, instr.operands[i])
				i += 1
				value = SSARegisterStack(reg_stack, instr.operands[i])
			elif operand_type == "reg_stack_ssa_dest_and_src":
				reg_stack = ILRegisterStack(func.arch, instr.operands[i])
				i += 1
				value = SSARegisterStack(reg_stack, instr.operands[i])
				i += 1
				self._operands.append(value)
				self.dest = value
				value = SSARegisterStack(reg_stack, instr.operands[i])
			elif operand_type == "flag":
				value = ILFlag(func.arch, instr.operands[i])
			elif operand_type == "flag_ssa":
				flag = ILFlag(func.arch, instr.operands[i])
				i += 1
				value = SSAFlag(flag, instr.operands[i])
			elif operand_type == "sem_class":
				if instr.operands[i] == 0:
					value = None
				else:
					value = ILSemanticFlagClass(func.arch, instr.operands[i])
			elif operand_type == "sem_group":
				value = ILSemanticFlagGroup(func.arch, instr.operands[i])
			elif operand_type == "cond":
				value = LowLevelILFlagCondition(instr.operands[i])
			elif operand_type == "int_list":
				count = ctypes.c_ulonglong()
				operand_list = core.BNLowLevelILGetOperandList(func.handle, self.expr_index, i, count)
				i += 1
				value = []
				for j in range(count.value):
					value.append(operand_list[j])
				core.BNLowLevelILFreeOperandList(operand_list)
			elif operand_type == "expr_list":
				count = ctypes.c_ulonglong()
				operand_list = core.BNLowLevelILGetOperandList(func.handle, self.expr_index, i, count)
				i += 1
				value = []
				for j in range(count.value):
					value.append(LowLevelILInstruction(func, operand_list[j]))
				core.BNLowLevelILFreeOperandList(operand_list)
			elif operand_type == "reg_or_flag_list":
				count = ctypes.c_ulonglong()
				operand_list = core.BNLowLevelILGetOperandList(func.handle, self.expr_index, i, count)
				i += 1
				value = []
				for j in range(count.value):
					if (operand_list[j] & (1 << 32)) != 0:
						value.append(ILFlag(func.arch, operand_list[j] & 0xffffffff))
					else:
						value.append(ILRegister(func.arch, operand_list[j] & 0xffffffff))
				core.BNLowLevelILFreeOperandList(operand_list)
			elif operand_type == "reg_ssa_list":
				count = ctypes.c_ulonglong()
				operand_list = core.BNLowLevelILGetOperandList(func.handle, self.expr_index, i, count)
				i += 1
				value = []
				for j in range(count.value // 2):
					reg = operand_list[j * 2]
					reg_version = operand_list[(j * 2) + 1]
					value.append(SSARegister(ILRegister(func.arch, reg), reg_version))
				core.BNLowLevelILFreeOperandList(operand_list)
			elif operand_type == "reg_stack_ssa_list":
				count = ctypes.c_ulonglong()
				operand_list = core.BNLowLevelILGetOperandList(func.handle, self.expr_index, i, count)
				i += 1
				value = []
				for j in range(count.value // 2):
					reg_stack = operand_list[j * 2]
					reg_version = operand_list[(j * 2) + 1]
					value.append(SSARegisterStack(ILRegisterStack(func.arch, reg_stack), reg_version))
				core.BNLowLevelILFreeOperandList(operand_list)
			elif operand_type == "flag_ssa_list":
				count = ctypes.c_ulonglong()
				operand_list = core.BNLowLevelILGetOperandList(func.handle, self.expr_index, i, count)
				i += 1
				value = []
				for j in range(count.value // 2):
					flag = operand_list[j * 2]
					flag_version = operand_list[(j * 2) + 1]
					value.append(SSAFlag(ILFlag(func.arch, flag), flag_version))
				core.BNLowLevelILFreeOperandList(operand_list)
			elif operand_type == "reg_or_flag_ssa_list":
				count = ctypes.c_ulonglong()
				operand_list = core.BNLowLevelILGetOperandList(func.handle, self.expr_index, i, count)
				i += 1
				value = []
				for j in range(count.value // 2):
					if (operand_list[j * 2] & (1 << 32)) != 0:
						reg_or_flag = ILFlag(func.arch, operand_list[j * 2] & 0xffffffff)
					else:
						reg_or_flag = ILRegister(func.arch, operand_list[j * 2] & 0xffffffff)
					reg_version = operand_list[(j * 2) + 1]
					value.append(SSARegisterOrFlag(reg_or_flag, reg_version))
				core.BNLowLevelILFreeOperandList(operand_list)
			elif operand_type == "reg_stack_adjust":
				count = ctypes.c_ulonglong()
				operand_list = core.BNLowLevelILGetOperandList(func.handle, self.expr_index, i, count)
				i += 1
				value = {}
				for j in range(count.value // 2):
					reg_stack = operand_list[j * 2]
					adjust = operand_list[(j * 2) + 1]
					if adjust & 0x80000000:
						adjust |= ~0x80000000
					value[func.arch.get_reg_stack_name(reg_stack)] = adjust
				core.BNLowLevelILFreeOperandList(operand_list)
			elif operand_type == "target_map":
				count = ctypes.c_ulonglong()
				operand_list = core.BNLowLevelILGetOperandList(func.handle, self.expr_index, i, count)
				i += 1
				value = {}
				for j in range(count.value // 2):
					key = operand_list[j * 2]
					target = operand_list[(j * 2) + 1]
					value[key] = target
				core.BNLowLevelILFreeOperandList(operand_list)
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
		return self._function == other.function and self.expr_index == other.expr_index

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

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
		return hash((self._function, self.expr_index))

	@property
	def tokens(self):
		"""LLIL tokens (read-only)"""
		count = ctypes.c_ulonglong()
		tokens = ctypes.POINTER(core.BNInstructionTextToken)()
		if (self._instr_index is not None) and (self._function.source_function is not None):
			if not core.BNGetLowLevelILInstructionText(self._function.handle, self._function.source_function.handle,
				self._function.arch.handle, self._instr_index, tokens, count):
				return None
		else:
			if not core.BNGetLowLevelILExprText(self._function.handle, self._function.arch.handle,
				self.expr_index, tokens, count):
				return None
		result = binaryninja.function.InstructionTextToken.get_instruction_lines(tokens, count.value)
		core.BNFreeInstructionText(tokens, count.value)
		return result

	@property
	def il_basic_block(self):
		"""IL basic block object containing this expression (read-only) (only available on finalized functions)"""
		view = None
		if self._function.source_function is not None:
			view = self._function.source_function.view
		return LowLevelILBasicBlock(view, core.BNGetLowLevelILBasicBlockForInstruction(self._function.handle, self._instr_index), self._function)

	@property
	def ssa_form(self):
		"""SSA form of expression (read-only)"""
		return LowLevelILInstruction(self._function.ssa_form,
			core.BNGetLowLevelILSSAExprIndex(self._function.handle, self.expr_index),
			core.BNGetLowLevelILSSAInstructionIndex(self._function.handle, self._instr_index) if self._instr_index is not None else None)

	@property
	def non_ssa_form(self):
		"""Non-SSA form of expression (read-only)"""
		return LowLevelILInstruction(self._function.non_ssa_form,
			core.BNGetLowLevelILNonSSAExprIndex(self._function.handle, self.expr_index),
			core.BNGetLowLevelILNonSSAInstructionIndex(self._function.handle, self._instr_index) if self._instr_index is not None else None)

	@property
	def medium_level_il(self):
		"""Gets the medium level IL expression corresponding to this expression (may be None for eliminated instructions)"""
		expr = self._function.get_medium_level_il_expr_index(self.expr_index)
		if expr is None:
			return None
		return binaryninja.mediumlevelil.MediumLevelILInstruction(self._function.medium_level_il, expr)

	@property
	def mlil(self):
		return self.medium_level_il

	@property
	def mapped_medium_level_il(self):
		"""Gets the mapped medium level IL expression corresponding to this expression"""
		expr = self._function.get_mapped_medium_level_il_expr_index(self.expr_index)
		if expr is None:
			return None
		return binaryninja.mediumlevelil.MediumLevelILInstruction(self._function.mapped_medium_level_il, expr)

	@property
	def mmlil(self):
		return self.mapped_medium_level_il

	@property
	def value(self):
		"""Value of expression if constant or a known value (read-only)"""
		value = core.BNGetLowLevelILExprValue(self._function.handle, self.expr_index)
		result = binaryninja.function.RegisterValue(self._function.arch, value)
		return result

	@property
	def possible_values(self):
		"""Possible values of expression using path-sensitive static data flow analysis (read-only)"""
		value = core.BNGetLowLevelILPossibleExprValues(self._function.handle, self.expr_index, None, 0)
		result = binaryninja.function.PossibleValueSet(self._function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	@property
	def prefix_operands(self):
		"""All operands in the expression tree in prefix order"""
		result = [LowLevelILOperationAndSize(self._operation, self._size)]
		for operand in self._operands:
			if isinstance(operand, LowLevelILInstruction):
				result += operand.prefix_operands
			else:
				result.append(operand)
		return result

	@property
	def postfix_operands(self):
		"""All operands in the expression tree in postfix order"""
		result = []
		for operand in self._operands:
			if isinstance(operand, LowLevelILInstruction):
				result += operand.postfix_operands
			else:
				result.append(operand)
		result.append(LowLevelILOperationAndSize(self._operation, self._size))
		return result

	def get_possible_values(self, options = []):
		option_array = (ctypes.c_int * len(options))()
		idx = 0
		for option in options:
			option_array[idx] = option
			idx += 1
		value = core.BNGetLowLevelILPossibleExprValues(self._function.handle, self.expr_index, option_array, len(options))
		result = binaryninja.function.PossibleValueSet(self._function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_reg_value(self, reg):
		reg = self._function.arch.get_reg_index(reg)
		value = core.BNGetLowLevelILRegisterValueAtInstruction(self._function.handle, reg, self._instr_index)
		result = binaryninja.function.RegisterValue(self._function.arch, value)
		return result

	def get_reg_value_after(self, reg):
		reg = self._function.arch.get_reg_index(reg)
		value = core.BNGetLowLevelILRegisterValueAfterInstruction(self._function.handle, reg, self._instr_index)
		result = binaryninja.function.RegisterValue(self._function.arch, value)
		return result

	def get_possible_reg_values(self, reg, options = []):
		reg = self._function.arch.get_reg_index(reg)
		option_array = (ctypes.c_int * len(options))()
		idx = 0
		for option in options:
			option_array[idx] = option
			idx += 1
		value = core.BNGetLowLevelILPossibleRegisterValuesAtInstruction(self._function.handle, reg, self._instr_index,
			option_array, len(options))
		result = binaryninja.function.PossibleValueSet(self._function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_possible_reg_values_after(self, reg, options = []):
		reg = self._function.arch.get_reg_index(reg)
		option_array = (ctypes.c_int * len(options))()
		idx = 0
		for option in options:
			option_array[idx] = option
			idx += 1
		value = core.BNGetLowLevelILPossibleRegisterValuesAfterInstruction(self._function.handle, reg, self._instr_index,
			option_array, len(options))
		result = binaryninja.function.PossibleValueSet(self._function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_flag_value(self, flag):
		flag = self._function.arch.get_flag_index(flag)
		value = core.BNGetLowLevelILFlagValueAtInstruction(self._function.handle, flag, self._instr_index)
		result = binaryninja.function.RegisterValue(self._function.arch, value)
		return result

	def get_flag_value_after(self, flag):
		flag = self._function.arch.get_flag_index(flag)
		value = core.BNGetLowLevelILFlagValueAfterInstruction(self._function.handle, flag, self._instr_index)
		result = binaryninja.function.RegisterValue(self._function.arch, value)
		return result

	def get_possible_flag_values(self, flag, options = []):
		flag = self._function.arch.get_flag_index(flag)
		option_array = (ctypes.c_int * len(options))()
		idx = 0
		for option in options:
			option_array[idx] = option
			idx += 1
		value = core.BNGetLowLevelILPossibleFlagValuesAtInstruction(self._function.handle, flag, self._instr_index,
			option_array, len(options))
		result = binaryninja.function.PossibleValueSet(self._function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_possible_flag_values_after(self, flag, options = []):
		flag = self._function.arch.get_flag_index(flag)
		option_array = (ctypes.c_int * len(options))()
		idx = 0
		for option in options:
			option_array[idx] = option
			idx += 1
		value = core.BNGetLowLevelILPossibleFlagValuesAfterInstruction(self._function.handle, flag, self._instr_index,
			option_array, len(options))
		result = binaryninja.function.PossibleValueSet(self._function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_stack_contents(self, offset, size):
		value = core.BNGetLowLevelILStackContentsAtInstruction(self._function.handle, offset, size, self._instr_index)
		result = binaryninja.function.RegisterValue(self._function.arch, value)
		return result

	def get_stack_contents_after(self, offset, size):
		value = core.BNGetLowLevelILStackContentsAfterInstruction(self._function.handle, offset, size, self._instr_index)
		result = binaryninja.function.RegisterValue(self._function.arch, value)
		return result

	def get_possible_stack_contents(self, offset, size, options = []):
		option_array = (ctypes.c_int * len(options))()
		idx = 0
		for option in options:
			option_array[idx] = option
			idx += 1
		value = core.BNGetLowLevelILPossibleStackContentsAtInstruction(self._function.handle, offset, size, self._instr_index,
			option_array, len(options))
		result = binaryninja.function.PossibleValueSet(self._function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

	def get_possible_stack_contents_after(self, offset, size, options = []):
		option_array = (ctypes.c_int * len(options))()
		idx = 0
		for option in options:
			option_array[idx] = option
			idx += 1
		value = core.BNGetLowLevelILPossibleStackContentsAfterInstruction(self._function.handle, offset, size, self._instr_index,
			option_array, len(options))
		result = binaryninja.function.PossibleValueSet(self._function.arch, value)
		core.BNFreePossibleValueSet(value)
		return result

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
	def flags(self):
		""" """
		return self._flags

	@property
	def operands(self):
		""" """
		return self._operands


class LowLevelILExpr(object):
	"""
	``class LowLevelILExpr`` hold the index of IL Expressions.

	.. note:: This class shouldn't be instantiated directly. Rather the helper members of LowLevelILFunction should be \
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


class LowLevelILFunction(object):
	"""
	``class LowLevelILFunction`` contains the list of LowLevelILExpr objects that make up a binaryninja.function. LowLevelILExpr
	objects can be added to the LowLevelILFunction by calling :func:`append` and passing the result of the various class
	methods which return LowLevelILExpr objects.


	LowLevelILFlagCondition values used as parameters in the :func:`flag_condition` method.

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
		LLFC_SGT                s>         Signed greater than
		LLFC_UGT                u>         Unsigned greater than
		LLFC_NEG                -          Negative
		LLFC_POS                +          Positive
		LLFC_O                  overflow   Overflow
		LLFC_NO                 !overflow  No overflow
		======================= ========== ===============================
	"""
	def __init__(self, arch = None, handle = None, source_func = None):
		self._arch = arch
		self._source_function = source_func
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNLowLevelILFunction)
			if self._source_function is None:
				source_handle = core.BNGetLowLevelILOwnerFunction(self.handle)
				if source_handle:
					self._source_function = binaryninja.function.Function(handle = source_handle)
				else:
					self._source_function = None
			if self._arch is None:
				self._arch = self._source_function.arch
		else:
			if self._arch is None:
				self._arch = self._source_function.arch
			if self._source_function is None:
				func_handle = None
			else:
				func_handle = self._source_function.handle
			self.handle = core.BNCreateLowLevelILFunction(arch.handle, func_handle)

	def __del__(self):
		if self.handle is not None:
			core.BNFreeLowLevelILFunction(self.handle)

	def __repr__(self):
		arch = self.source_function.arch
		if arch:
			return "<llil func: %s@%#x>" % (arch.name, self.source_function.start)
		else:
			return "<llil func: %#x>" % self.source_function.start

	def __len__(self):
		return int(core.BNGetLowLevelILInstructionCount(self.handle))

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(other.handle.contents)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash(('LLIL', self._source_function))

	def __getitem__(self, i):
		if isinstance(i, slice) or isinstance(i, tuple):
			raise IndexError("expected integer instruction index")
		if isinstance(i, LowLevelILExpr):
			return LowLevelILInstruction(self, i.index)
		# for backwards compatibility
		if isinstance(i, LowLevelILInstruction):
			return i
		if i < -len(self) or i >= len(self):
			raise IndexError("index out of range")
		if i < 0:
			i = len(self) + i
		return LowLevelILInstruction(self, core.BNGetLowLevelILIndexForInstruction(self.handle, i), i)

	def __setitem__(self, i, j):
		raise IndexError("instruction modification not implemented")

	def __iter__(self):
		count = ctypes.c_ulonglong()
		blocks = core.BNGetLowLevelILBasicBlockList(self.handle, count)
		view = None
		if self._source_function is not None:
			view = self._source_function.view
		try:
			for i in range(0, count.value):
				yield LowLevelILBasicBlock(view, core.BNNewBasicBlockReference(blocks[i]), self)
		finally:
			core.BNFreeBasicBlockList(blocks, count.value)

	@property
	def current_address(self):
		"""Current IL Address (read/write)"""
		return core.BNLowLevelILGetCurrentAddress(self.handle)

	@current_address.setter
	def current_address(self, value):
		core.BNLowLevelILSetCurrentAddress(self.handle, self._arch.handle, value)

	def set_current_address(self, value, arch = None):
		if arch is None:
			arch = self._arch
		core.BNLowLevelILSetCurrentAddress(self.handle, arch.handle, value)

	def set_current_source_block(self, block):
		core.BNLowLevelILSetCurrentSourceBlock(self.handle, block.handle)

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
		if self._source_function is not None:
			view = self._source_function.view
		for i in range(0, count.value):
			result.append(LowLevelILBasicBlock(view, core.BNNewBasicBlockReference(blocks[i]), self))
		core.BNFreeBasicBlockList(blocks, count.value)
		return result

	@property
	def instructions(self):
		"""A generator of llil instructions of the current llil function"""
		for block in self.basic_blocks:
			for i in block:
				yield i

	@property
	def ssa_form(self):
		"""Low level IL in SSA form (read-only)"""
		result = core.BNGetLowLevelILSSAForm(self.handle)
		if not result:
			return None
		return LowLevelILFunction(self._arch, result, self._source_function)

	@property
	def non_ssa_form(self):
		"""Low level IL in non-SSA (default) form (read-only)"""
		result = core.BNGetLowLevelILNonSSAForm(self.handle)
		if not result:
			return None
		return LowLevelILFunction(self._arch, result, self._source_function)

	@property
	def medium_level_il(self):
		"""Medium level IL for this low level IL."""
		result = core.BNGetMediumLevelILForLowLevelIL(self.handle)
		if not result:
			return None
		return binaryninja.mediumlevelil.MediumLevelILFunction(self._arch, result, self._source_function)

	@property
	def mlil(self):
		return self.medium_level_il

	@property
	def mapped_medium_level_il(self):
		"""Medium level IL with mappings between low level IL and medium level IL. Unused stores are not removed.
		Typically, this should only be used to answer queries on assembly or low level IL where the query is
		easier to perform on medium level IL."""
		result = core.BNGetMappedMediumLevelIL(self.handle)
		if not result:
			return None
		return binaryninja.mediumlevelil.MediumLevelILFunction(self._arch, result, self._source_function)

	@property
	def mmlil(self):
		return self.mapped_medium_level_il

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

	def get_instruction_start(self, addr, arch = None):
		if arch is None:
			arch = self._arch
		result = core.BNLowLevelILGetInstructionStart(self.handle, arch.handle, addr)
		if result >= core.BNGetLowLevelILInstructionCount(self.handle):
			return None
		return result

	def clear_indirect_branches(self):
		core.BNLowLevelILClearIndirectBranches(self.handle)

	def set_indirect_branches(self, branches):
		branch_list = (core.BNArchitectureAndAddress * len(branches))()
		for i in range(len(branches)):
			branch_list[i].arch = branches[i][0].handle
			branch_list[i].address = branches[i][1]
		core.BNLowLevelILSetIndirectBranches(self.handle, branch_list, len(branches))

	def expr(self, operation, a = 0, b = 0, c = 0, d = 0, size = 0, flags = None):
		if isinstance(operation, str):
			operation = LowLevelILOperation[operation]
		elif isinstance(operation, LowLevelILOperation):
			operation = operation.value
		if isinstance(flags, str):
			flags = self._arch.get_flag_write_type_by_name(flags)
		elif flags is None:
			flags = 0
		return LowLevelILExpr(core.BNLowLevelILAddExpr(self.handle, operation, size, flags, a, b, c, d))

	def replace_expr(self, original, new):
		"""
		``replace_expr`` allows modification of LowLevelILExpressions but ONLY during lifting.

		.. warning:: This function should ONLY be called as a part of a lifter. It will otherwise not do anything useful as there's no way to trigger re-analysis of IL levels at this time.

		:param LowLevelILExpr original: the LowLevelILExpr to replace (may also be an expression index)
		:param LowLevelILExpr new: the LowLevelILExpr to add to the current LowLevelILFunction (may also be an expression index)
		:rtype: None
		"""
		if isinstance(original, LowLevelILInstruction):
			original = original.expr_index
		elif isinstance(original, LowLevelILExpr):
			original = original.index

		if isinstance(new, LowLevelILInstruction):
			new = new.expr_index
		elif isinstance(new, LowLevelILExpr):
			new = new.index

		core.BNReplaceLowLevelILExpr(self.handle, original, new)

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
		reg = self._arch.get_reg_index(reg)
		return self.expr(LowLevelILOperation.LLIL_SET_REG, reg, value.index, size = size, flags = flags)

	def set_reg_split(self, size, hi, lo, value, flags = 0):
		"""
		``set_reg_split`` uses ``hi`` and ``lo`` as a single extended register setting ``hi:lo`` to the expression
		``value``.

		:param int size: size of the register parameter in bytes
		:param str hi: the high register name
		:param str lo: the low register name
		:param LowLevelILExpr value: an expression to set the split registers to
		:param str flags: which flags are set by this operation
		:return: The expression ``hi:lo = value``
		:rtype: LowLevelILExpr
		"""
		hi = self._arch.get_reg_index(hi)
		lo = self._arch.get_reg_index(lo)
		return self.expr(LowLevelILOperation.LLIL_SET_REG_SPLIT, hi, lo, value.index, size = size, flags = flags)

	def set_reg_stack_top_relative(self, size, reg_stack, entry, value, flags = 0):
		"""
		``set_reg_stack_top_relative`` sets the top-relative entry ``entry`` of size ``size`` in register
		stack ``reg_stack`` to the expression ``value``

		:param int size: size of the register parameter in bytes
		:param str reg_stack: the register stack name
		:param LowLevelILExpr entry: an expression for which stack entry to set
		:param LowLevelILExpr value: an expression to set the entry to
		:param str flags: which flags are set by this operation
		:return: The expression ``reg_stack[entry] = value``
		:rtype: LowLevelILExpr
		"""
		reg_stack = self._arch.get_reg_stack_index(reg_stack)
		return self.expr(LowLevelILOperation.LLIL_SET_REG_STACK_REL, reg_stack, entry.index, value.index,
			size = size, flags = flags)

	def reg_stack_push(self, size, reg_stack, value, flags = 0):
		"""
		``reg_stack_push`` pushes the expression ``value`` of size ``size`` onto the top of the register
		stack ``reg_stack``

		:param int size: size of the register parameter in bytes
		:param str reg_stack: the register stack name
		:param LowLevelILExpr value: an expression to push
		:param str flags: which flags are set by this operation
		:return: The expression ``reg_stack.push(value)``
		:rtype: LowLevelILExpr
		"""
		reg_stack = self._arch.get_reg_stack_index(reg_stack)
		return self.expr(LowLevelILOperation.LLIL_REG_STACK_PUSH, reg_stack, value.index, size = size, flags = flags)

	def set_flag(self, flag, value):
		"""
		``set_flag`` sets the flag ``flag`` to the LowLevelILExpr ``value``

		:param str flag: the low register name
		:param LowLevelILExpr value: an expression to set the flag to
		:return: The expression FLAG.flag = value
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_SET_FLAG, self._arch.get_flag_by_name(flag), value.index)

	def load(self, size, addr):
		"""
		``load`` Reads ``size`` bytes from the expression ``addr``

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
		``reg`` returns a register of size ``size`` with name ``reg``

		:param int size: the size of the register in bytes
		:param str reg: the name of the register
		:return: A register expression for the given string
		:rtype: LowLevelILExpr
		"""
		reg = self._arch.get_reg_index(reg)
		return self.expr(LowLevelILOperation.LLIL_REG, reg, size=size)

	def reg_split(self, size, hi, lo):
		"""
		``reg_split`` combines registers of size ``size`` with names ``hi`` and ``lo``

		:param int size: the size of the register in bytes
		:param str hi: register holding high part of value
		:param str lo: register holding low part of value
		:return: The expression ``hi:lo``
		:rtype: LowLevelILExpr
		"""
		hi = self._arch.get_reg_index(hi)
		lo = self._arch.get_reg_index(lo)
		return self.expr(LowLevelILOperation.LLIL_REG_SPLIT, hi, lo, size=size)

	def reg_stack_top_relative(self, size, reg_stack, entry):
		"""
		``reg_stack_top_relative`` returns a register stack entry of size ``size`` at top-relative
		location ``entry`` in register stack with name ``reg_stack``

		:param int size: the size of the register in bytes
		:param str reg_stack: the name of the register stack
		:param LowLevelILExpr entry: an expression for which stack entry to fetch
		:return: The expression ``reg_stack[entry]``
		:rtype: LowLevelILExpr
		"""
		reg_stack = self._arch.get_reg_stack_index(reg_stack)
		return self.expr(LowLevelILOperation.LLIL_REG_STACK_REL, reg_stack, entry.index, size=size)

	def reg_stack_pop(self, size, reg_stack):
		"""
		``reg_stack_pop`` returns the top entry of size ``size`` in register stack with name ``reg_stack``, and
		removes the entry from the stack

		:param int size: the size of the register in bytes
		:param str reg_stack: the name of the register stack
		:return: The expression ``reg_stack.pop``
		:rtype: LowLevelILExpr
		"""
		reg_stack = self._arch.get_reg_stack_index(reg_stack)
		return self.expr(LowLevelILOperation.LLIL_REG_STACK_POP, reg_stack, size=size)

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

	def reloc_pointer(self, size, value):
		"""
		``reloc_pointer`` returns an expression for the constant relocated pointer ``value`` with size ``size``

		:param int size: the size of the pointer in bytes
		:param int value: address referenced by pointer
		:return: A constant expression of given value and size
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_EXTERN_PTR, value, size=size)

	def float_const_raw(self, size, value):
		"""
		``float_const_raw`` returns an expression for the constant raw binary floating point
		value ``value`` with size ``size``

		:param int size: the size of the constant in bytes
		:param int value: integer value for the raw binary representation of the constant
		:return: A constant expression of given value and size
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_FLOAT_CONST, value, size=size)

	def float_const_single(self, value):
		"""
		``float_const_single`` returns an expression for the single precision floating point value ``value``

		:param float value: float value for the constant
		:return: A constant expression of given value and size
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_FLOAT_CONST, struct.unpack("I", struct.pack("f", value))[0], size=4)

	def float_const_double(self, value):
		"""
		``float_const_double`` returns an expression for the double precision floating point value ``value``

		:param float value: float value for the constant
		:return: A constant expression of given value and size
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_FLOAT_CONST, struct.unpack("Q", struct.pack("d", value))[0], size=8)

	def flag(self, reg):
		"""
		``flag`` returns a flag expression for the given flag name.

		:param str reg: name of the flag expression to retrieve
		:return: A flag expression of given flag name
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_FLAG, self._arch.get_flag_by_name(reg))

	def flag_bit(self, size, reg, bit):
		"""
		``flag_bit`` sets the flag named ``reg`` and size ``size`` to the constant integer value ``bit``

		:param int size: the size of the flag
		:param str reg: flag value
		:param int bit: integer value to set the bit to
		:return: A constant expression of given value and size ``FLAG.reg = bit``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_FLAG_BIT, self._arch.get_flag_by_name(reg), bit, size=size)

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
		:return: The expression ``mulu.dp.<size>{<flags>}(a, b)``
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

	def div_double_prec_signed(self, size, a, b, flags=None):
		"""
		``div_double_prec_signed`` signed double precision divide using expression ``a`` as a
		single double precision register by expression ``b`` potentially  setting flags ``flags`` and returning an
		expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``divs.dp.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_DIVS_DP, a.index, b.index, size=size, flags=flags)

	def div_unsigned(self, size, a, b, flags=None):
		"""
		``div_unsigned`` unsigned divide expression ``a`` by expression ``b`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``divu.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_DIVU, a.index, b.index, size=size, flags=flags)

	def div_double_prec_unsigned(self, size, a, b, flags=None):
		"""
		``div_double_prec_unsigned`` unsigned double precision divide using expression ``a`` as
		a single double precision register by expression ``b`` potentially  setting flags ``flags`` and returning an
		expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``divu.dp.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_DIVU_DP, a.index, b.index, size=size, flags=flags)

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

	def mod_double_prec_signed(self, size, a, b, flags=None):
		"""
		``mod_double_prec_signed`` signed double precision modulus using expression ``a`` as a single
		double precision register by expression ``b`` potentially  setting flags ``flags`` and returning an expression
		of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``mods.dp.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_MODS_DP, a.index, b.index, size=size, flags=flags)

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
		return self.expr(LowLevelILOperation.LLIL_MODU, a.index, b.index, size=size, flags=flags)

	def mod_double_prec_unsigned(self, size, a, b, flags=None):
		"""
		``mod_double_prec_unsigned`` unsigned double precision modulus using expression ``a`` as
		a single double precision register by expression ``b`` potentially  setting flags ``flags`` and returning an
		expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: optional, flags to set
		:return: The expression ``modu.dp.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_MODU_DP, a.index, b.index, size=size, flags=flags)

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
		:param LowLevelILExpr value: the expression to sign extend
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
		:return: The expression ``zx.<size>(value)``
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

	def tailcall(self, dest):
		"""
		``tailcall`` returns an expression which jumps (branches) to the expression ``dest``

		:param LowLevelILExpr dest: the expression to jump to
		:return: The expression ``tailcall(dest)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_TAILCALL, dest.index)

	def ret(self, dest):
		"""
		``ret`` returns an expression which jumps (branches) to the expression ``dest``. ``ret`` is a special alias for
		jump that makes the disassembler stop disassembling.

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

	def flag_condition(self, cond, sem_class = None):
		"""
		``flag_condition`` returns a flag_condition expression for the given LowLevelILFlagCondition

		:param LowLevelILFlagCondition cond: Flag condition expression to retrieve
		:param str sem_class: Optional semantic flag class
		:return: A flag_condition expression
		:rtype: LowLevelILExpr
		"""
		if isinstance(cond, str):
			cond = LowLevelILFlagCondition[cond]
		elif isinstance(cond, LowLevelILFlagCondition):
			cond = cond.value
		class_index = self._arch.get_semantic_flag_class_index(sem_class)
		return self.expr(LowLevelILOperation.LLIL_FLAG_COND, cond, class_index)

	def flag_group(self, sem_group):
		"""
		``flag_group`` returns a flag_group expression for the given semantic flag group

		:param str sem_group: Semantic flag group to access
		:return: A flag_group expression
		:rtype: LowLevelILExpr
		"""
		group = self._arch.get_semantic_flag_group_index(sem_group)
		return self.expr(LowLevelILOperation.LLIL_FLAG_GROUP, group)

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
		signed greater than or equal to expression ``b``

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

	def intrinsic(self, outputs, intrinsic, params, flags=None):
		"""
		``intrinsic`` return an intrinsic expression.

		:return: an intrinsic expression.
		:rtype: LowLevelILExpr
		"""
		output_list = []
		for output in outputs:
			if isinstance(output, ILFlag):
				output_list.append((1 << 32) | output.index)
			else:
				output_list.append(output.index)
		param_list = []
		for param in params:
			param_list.append(param.index)
		call_param = self.expr(LowLevelILOperation.LLIL_CALL_PARAM, len(params), self.add_operand_list(param_list).index)
		return self.expr(LowLevelILOperation.LLIL_INTRINSIC, len(outputs), self.add_operand_list(output_list).index,
			self._arch.get_intrinsic_index(intrinsic), call_param.index, flags = flags)

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

	def float_add(self, size, a, b, flags=None):
		"""
		``float_add`` adds floating point expression ``a`` to expression ``b`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: flags to set
		:return: The expression ``fadd.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_FADD, a.index, b.index, size=size, flags=flags)

	def float_sub(self, size, a, b, flags=None):
		"""
		``float_sub`` subtracts floating point expression ``b`` from expression ``a`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: flags to set
		:return: The expression ``fsub.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_FSUB, a.index, b.index, size=size, flags=flags)

	def float_mult(self, size, a, b, flags=None):
		"""
		``float_mult`` multiplies floating point expression ``a`` by expression ``b`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: flags to set
		:return: The expression ``fmul.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_FMUL, a.index, b.index, size=size, flags=flags)

	def float_div(self, size, a, b, flags=None):
		"""
		``float_div`` divides floating point expression ``a`` by expression ``b`` potentially setting flags ``flags``
		and returning an expression of ``size`` bytes.

		:param int size: the size of the result in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: flags to set
		:return: The expression ``fdiv.<size>{<flags>}(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_FDIV, a.index, b.index, size=size, flags=flags)

	def float_sqrt(self, size, value, flags=None):
		"""
		``float_sqrt`` returns square root of floating point expression ``value`` of size ``size`` potentially setting flags

		:param int size: the size of the result in bytes
		:param LowLevelILExpr value: the expression to negate
		:param str flags: optional, flags to set
		:return: The expression ``sqrt.<size>{<flags>}(value)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_FSQRT, value.index, size=size, flags=flags)

	def float_neg(self, size, value, flags=None):
		"""
		``float_neg`` returns sign negation of floating point expression ``value`` of size ``size`` potentially setting flags

		:param int size: the size of the result in bytes
		:param LowLevelILExpr value: the expression to negate
		:param str flags: optional, flags to set
		:return: The expression ``fneg.<size>{<flags>}(value)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_FNEG, value.index, size=size, flags=flags)

	def float_abs(self, size, value, flags=None):
		"""
		``float_abs`` returns absolute value of floating point expression ``value`` of size ``size`` potentially setting flags

		:param int size: the size of the result in bytes
		:param LowLevelILExpr value: the expression to negate
		:param str flags: optional, flags to set
		:return: The expression ``fabs.<size>{<flags>}(value)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_FABS, value.index, size=size, flags=flags)

	def float_to_int(self, size, value, flags=None):
		"""
		``float_to_int`` returns integer value of floating point expression ``value`` of size ``size`` potentially setting flags

		:param int size: the size of the result in bytes
		:param LowLevelILExpr value: the expression to negate
		:param str flags: optional, flags to set
		:return: The expression ``int.<size>{<flags>}(value)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_FLOAT_TO_INT, value.index, size=size, flags=flags)

	def int_to_float(self, size, value, flags=None):
		"""
		``int_to_float`` returns floating point value of integer expression ``value`` of size ``size`` potentially setting flags

		:param int size: the size of the result in bytes
		:param LowLevelILExpr value: the expression to negate
		:param str flags: optional, flags to set
		:return: The expression ``float.<size>{<flags>}(value)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_INT_TO_FLOAT, value.index, size=size, flags=flags)

	def float_convert(self, size, value, flags=None):
		"""
		``int_to_float`` converts floating point value of expression ``value`` to size ``size`` potentially setting flags

		:param int size: the size of the result in bytes
		:param LowLevelILExpr value: the expression to negate
		:param str flags: optional, flags to set
		:return: The expression ``fconvert.<size>{<flags>}(value)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_FLOAT_CONV, value.index, size=size, flags=flags)

	def round_to_int(self, size, value, flags=None):
		"""
		``round_to_int`` rounds a floating point value to the nearest integer

		:param int size: the size of the result in bytes
		:param LowLevelILExpr value: the expression to negate
		:param str flags: optional, flags to set
		:return: The expression ``roundint.<size>{<flags>}(value)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_ROUND_TO_INT, value.index, size=size, flags=flags)

	def floor(self, size, value, flags=None):
		"""
		``floor`` rounds a floating point value to an integer towards negative infinity

		:param int size: the size of the result in bytes
		:param LowLevelILExpr value: the expression to negate
		:param str flags: optional, flags to set
		:return: The expression ``roundint.<size>{<flags>}(value)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_FLOOR, value.index, size=size, flags=flags)

	def ceil(self, size, value, flags=None):
		"""
		``ceil`` rounds a floating point value to an integer towards positive infinity

		:param int size: the size of the result in bytes
		:param LowLevelILExpr value: the expression to negate
		:param str flags: optional, flags to set
		:return: The expression ``roundint.<size>{<flags>}(value)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_CEIL, value.index, size=size, flags=flags)

	def float_trunc(self, size, value, flags=None):
		"""
		``float_trunc`` rounds a floating point value to an integer towards zero

		:param int size: the size of the result in bytes
		:param LowLevelILExpr value: the expression to negate
		:param str flags: optional, flags to set
		:return: The expression ``roundint.<size>{<flags>}(value)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_FTRUNC, value.index, size=size, flags=flags)

	def float_compare_equal(self, size, a, b):
		"""
		``float_compare_equal`` returns floating point comparison expression of size ``size`` checking if
		expression ``a`` is equal to expression ``b``

		:param int size: the size of the operands in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: flags to set
		:return: The expression ``a f== b``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_FCMP_E, a.index, b.index)

	def float_compare_not_equal(self, size, a, b):
		"""
		``float_compare_not_equal`` returns floating point comparison expression of size ``size`` checking if
		expression ``a`` is not equal to expression ``b``

		:param int size: the size of the operands in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: flags to set
		:return: The expression ``a f!= b``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_FCMP_NE, a.index, b.index)

	def float_compare_less_than(self, size, a, b):
		"""
		``float_compare_less_than`` returns floating point comparison expression of size ``size`` checking if
		expression ``a`` is less than to expression ``b``

		:param int size: the size of the operands in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: flags to set
		:return: The expression ``a f< b``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_FCMP_LT, a.index, b.index)

	def float_compare_less_equal(self, size, a, b):
		"""
		``float_compare_less_equal`` returns floating point comparison expression of size ``size`` checking if
		expression ``a`` is less than or equal to expression ``b``

		:param int size: the size of the operands in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: flags to set
		:return: The expression ``a f<= b``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_FCMP_LE, a.index, b.index)

	def float_compare_greater_equal(self, size, a, b):
		"""
		``float_compare_greater_equal`` returns floating point comparison expression of size ``size`` checking if
		expression ``a`` is greater than or equal to expression ``b``

		:param int size: the size of the operands in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: flags to set
		:return: The expression ``a f>= b``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_FCMP_GE, a.index, b.index)

	def float_compare_greater_than(self, size, a, b):
		"""
		``float_compare_greater_than`` returns floating point comparison expression of size ``size`` checking if
		expression ``a`` is greater than or equal to expression ``b``

		:param int size: the size of the operands in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: flags to set
		:return: The expression ``a f> b``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_FCMP_GT, a.index, b.index)

	def float_compare_unordered(self, size, a, b):
		"""
		``float_compare_unordered`` returns floating point comparison expression of size ``size`` checking if
		expression ``a`` is unordered relative to expression ``b``

		:param int size: the size of the operands in bytes
		:param LowLevelILExpr a: LHS expression
		:param LowLevelILExpr b: RHS expression
		:param str flags: flags to set
		:return: The expression ``is_unordered(a, b)``
		:rtype: LowLevelILExpr
		"""
		return self.expr(LowLevelILOperation.LLIL_FCMP_UO, a.index, b.index)

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

		:param labels: the list of LowLevelILLabel to get a label list expression from
		:type labels: list(LowLevelILLabel)
		:return: the label list expression
		:rtype: LowLevelILExpr
		"""
		label_list = (ctypes.POINTER(core.BNLowLevelILLabel) * len(labels))()
		for i in range(len(labels)):
			label_list[i] = labels[i].handle
		return LowLevelILExpr(core.BNLowLevelILAddLabelList(self.handle, label_list, len(labels)))

	def add_operand_list(self, operands):
		"""
		``add_operand_list`` returns an operand list expression for the given list of integer operands.

		:param operands: list of operand numbers
		:type operands: list(int)
		:return: an operand list expression
		:rtype: LowLevelILExpr
		"""
		operand_list = (ctypes.c_ulonglong * len(operands))()
		for i in range(len(operands)):
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
		reg = self._arch.get_reg_index(reg_ssa.reg)
		result = core.BNGetLowLevelILSSARegisterDefinition(self.handle, reg, reg_ssa.version)
		if result >= core.BNGetLowLevelILInstructionCount(self.handle):
			return None
		return self[result]

	def get_ssa_flag_definition(self, flag_ssa):
		flag = self._arch.get_flag_index(flag_ssa.flag)
		result = core.BNGetLowLevelILSSAFlagDefinition(self.handle, flag, flag_ssa.version)
		if result >= core.BNGetLowLevelILInstructionCount(self.handle):
			return None
		return self[result]

	def get_ssa_memory_definition(self, index):
		result = core.BNGetLowLevelILSSAMemoryDefinition(self.handle, index)
		if result >= core.BNGetLowLevelILInstructionCount(self.handle):
			return None
		return self[result]

	def get_ssa_reg_uses(self, reg_ssa):
		reg = self._arch.get_reg_index(reg_ssa.reg)
		count = ctypes.c_ulonglong()
		instrs = core.BNGetLowLevelILSSARegisterUses(self.handle, reg, reg_ssa.version, count)
		result = []
		for i in range(0, count.value):
			result.append(self[instrs[i]])
		core.BNFreeILInstructionList(instrs)
		return result

	def get_ssa_flag_uses(self, flag_ssa):
		flag = self._arch.get_flag_index(flag_ssa.flag)
		count = ctypes.c_ulonglong()
		instrs = core.BNGetLowLevelILSSAFlagUses(self.handle, flag, flag_ssa.version, count)
		result = []
		for i in range(0, count.value):
			result.append(self[instrs[i]])
		core.BNFreeILInstructionList(instrs)
		return result

	def get_ssa_memory_uses(self, index):
		count = ctypes.c_ulonglong()
		instrs = core.BNGetLowLevelILSSAMemoryUses(self.handle, index, count)
		result = []
		for i in range(0, count.value):
			result.append(self[instrs[i]])
		core.BNFreeILInstructionList(instrs)
		return result

	def get_ssa_reg_value(self, reg_ssa):
		reg = self._arch.get_reg_index(reg_ssa.reg)
		value = core.BNGetLowLevelILSSARegisterValue(self.handle, reg, reg_ssa.version)
		result = binaryninja.function.RegisterValue(self._arch, value)
		return result

	def get_ssa_flag_value(self, flag_ssa):
		flag = self._arch.get_flag_index(flag_ssa.flag)
		value = core.BNGetLowLevelILSSAFlagValue(self.handle, flag, flag_ssa.version)
		result = binaryninja.function.RegisterValue(self._arch, value)
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

	def create_graph(self, settings = None):
		if settings is not None:
			settings_obj = settings.handle
		else:
			settings_obj = None
		return binaryninja.flowgraph.CoreFlowGraph(core.BNCreateLowLevelILFunctionGraph(self.handle, settings_obj))


class LowLevelILBasicBlock(basicblock.BasicBlock):
	def __init__(self, view, handle, owner):
		super(LowLevelILBasicBlock, self).__init__(handle, view)
		self._il_function = owner

	def __repr__(self):
		arch = self.arch
		if arch:
			return "<llil block: %s@%d-%d>" % (arch.name, self.start, self.end)
		else:
			return "<llil block: %d-%d>" % (self.start, self.end)

	def __hash__(self):
		return hash((self.start, self.end, self._il_function))

	def __contains__(self, instruction):
		if type(instruction) != LowLevelILInstruction or instruction.il_basic_block != self:
			return False
		return True

	def __iter__(self):
		for idx in range(self.start, self.end):
			yield self._il_function[idx]

	def __getitem__(self, idx):
		size = self.end - self.start
		if idx > size or idx < -size:
			raise IndexError("list index is out of range")
		if idx >= 0:
			return self._il_function[idx + self.start]
		else:
			return self._il_function[self.end + idx]

	def _create_instance(self, handle, view):
		"""Internal method by super to instantiate child instances"""
		return LowLevelILBasicBlock(view, handle, self._il_function)

	@property
	def il_function(self):
		""" """
		return self._il_function

	@il_function.setter
	def il_function(self, value):
		self._il_function = value


def LLIL_TEMP(n):
	return n | 0x80000000


def LLIL_REG_IS_TEMP(n):
	return (n & 0x80000000) != 0


def LLIL_GET_TEMP_REG_INDEX(n):
	return n & 0x7fffffff
