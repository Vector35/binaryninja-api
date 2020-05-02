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

from __future__ import absolute_import
import traceback
import ctypes
import abc

# Binary Ninja components
from binaryninja import _binaryninjacore as core
from binaryninja.enums import (Endianness, ImplicitRegisterExtend, BranchType,
	InstructionTextTokenType, LowLevelILFlagCondition, FlagRole)
import binaryninja
from binaryninja import log
from binaryninja import lowlevelil
from binaryninja import types
from binaryninja import databuffer
from binaryninja import platform
from binaryninja import callingconvention

# 2-3 compatibility
from binaryninja import range
from binaryninja import with_metaclass
import numbers


class _ArchitectureMetaClass(type):

	@property
	def list(self):
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		archs = core.BNGetArchitectureList(count)
		result = []
		for i in range(0, count.value):
			result.append(CoreArchitecture._from_cache(archs[i]))
		core.BNFreeArchitectureList(archs)
		return result

	def __iter__(self):
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		archs = core.BNGetArchitectureList(count)
		try:
			for i in range(0, count.value):
				yield CoreArchitecture._from_cache(archs[i])
		finally:
			core.BNFreeArchitectureList(archs)

	def __getitem__(cls, name):
		binaryninja._init_plugins()
		arch = core.BNGetArchitectureByName(name)
		if arch is None:
			raise KeyError("'%s' is not a valid architecture" % str(name))
		return CoreArchitecture._from_cache(arch)

	def register(cls):
		binaryninja._init_plugins()
		if cls.name is None:
			raise ValueError("architecture 'name' is not defined")
		arch = cls()
		cls._registered_cb = arch._cb
		arch.handle = core.BNRegisterArchitecture(cls.name, arch._cb)


class Architecture(with_metaclass(_ArchitectureMetaClass, object)):
	"""
	``class Architecture`` is the parent class for all CPU architectures. Subclasses of Architecture implement assembly,
	disassembly, IL lifting, and patching.

	``class Architecture`` has a metaclass with the additional methods ``register``, and supports
	iteration::

		>>> #List the architectures
		>>> list(Architecture)
		[<arch: aarch64>, <arch: armv7>, <arch: thumb2>, <arch: armv7eb>, <arch: thumb2eb>, <arch: mipsel32>, <arch: mips32>, <arch: ppc>, <arch: ppc64>, <arch: ppc_le>, <arch: ppc64_le>, <arch: x86_16>, <arch: x86>, <arch: x86_64>]
		>>> #Register a new Architecture
		>>> class MyArch(Architecture):
		...  name = "MyArch"
		...
		>>> MyArch.register()
		>>> list(Architecture)
		[<arch: aarch64>, <arch: armv7>, <arch: thumb2>, <arch: armv7eb>, <arch: thumb2eb>, <arch: mipsel32>, <arch: mips32>, <arch: ppc>, <arch: ppc64>, <arch: ppc_le>, <arch: ppc64_le>, <arch: x86_16>, <arch: x86>, <arch: x86_64>, <arch: MyArch>]
		>>>

	For the purposes of this documentation the variable ``arch`` will be used in the following context ::

		>>> from binaryninja import *
		>>> arch = Architecture['x86']
	"""
	name = None
	endianness = Endianness.LittleEndian
	address_size = 8
	default_int_size = 4
	instr_alignment = 1
	max_instr_length = 16
	opcode_display_length = 8
	regs = {}
	stack_pointer = None
	link_reg = None
	global_regs = []
	system_regs = []
	flags = []
	flag_write_types = []
	semantic_flag_classes = []
	semantic_flag_groups = []
	flag_roles = {}
	flags_required_for_flag_condition = {}
	flags_required_for_semantic_flag_group = {}
	flag_conditions_for_semantic_flag_group = {}
	flags_written_by_flag_write_type = {}
	semantic_class_for_flag_write_type = {}
	reg_stacks = {}
	intrinsics = {}
	next_address = 0

	def __init__(self):
		binaryninja._init_plugins()

		if self.__class__.opcode_display_length > self.__class__.max_instr_length:
			self.__class__.opcode_display_length = self.__class__.max_instr_length

		self._cb = core.BNCustomArchitecture()
		self._cb.context = 0
		self._cb.init = self._cb.init.__class__(self._init)
		self._cb.getEndianness = self._cb.getEndianness.__class__(self._get_endianness)
		self._cb.getAddressSize = self._cb.getAddressSize.__class__(self._get_address_size)
		self._cb.getDefaultIntegerSize = self._cb.getDefaultIntegerSize.__class__(self._get_default_integer_size)
		self._cb.getInstructionAlignment = self._cb.getInstructionAlignment.__class__(self._get_instruction_alignment)
		self._cb.getMaxInstructionLength = self._cb.getMaxInstructionLength.__class__(self._get_max_instruction_length)
		self._cb.getOpcodeDisplayLength = self._cb.getOpcodeDisplayLength.__class__(self._get_opcode_display_length)
		self._cb.getAssociatedArchitectureByAddress = \
			self._cb.getAssociatedArchitectureByAddress.__class__(self._get_associated_arch_by_address)
		self._cb.getInstructionInfo = self._cb.getInstructionInfo.__class__(self._get_instruction_info)
		self._cb.getInstructionText = self._cb.getInstructionText.__class__(self._get_instruction_text)
		self._cb.freeInstructionText = self._cb.freeInstructionText.__class__(self._free_instruction_text)
		self._cb.getInstructionLowLevelIL = self._cb.getInstructionLowLevelIL.__class__(
			self._get_instruction_low_level_il)
		self._cb.getRegisterName = self._cb.getRegisterName.__class__(self._get_register_name)
		self._cb.getFlagName = self._cb.getFlagName.__class__(self._get_flag_name)
		self._cb.getFlagWriteTypeName = self._cb.getFlagWriteTypeName.__class__(self._get_flag_write_type_name)
		self._cb.getSemanticFlagClassName = self._cb.getSemanticFlagClassName.__class__(self._get_semantic_flag_class_name)
		self._cb.getSemanticFlagGroupName = self._cb.getSemanticFlagGroupName.__class__(self._get_semantic_flag_group_name)
		self._cb.getFullWidthRegisters = self._cb.getFullWidthRegisters.__class__(self._get_full_width_registers)
		self._cb.getAllRegisters = self._cb.getAllRegisters.__class__(self._get_all_registers)
		self._cb.getAllFlags = self._cb.getAllRegisters.__class__(self._get_all_flags)
		self._cb.getAllFlagWriteTypes = self._cb.getAllRegisters.__class__(self._get_all_flag_write_types)
		self._cb.getAllSemanticFlagClasses = self._cb.getAllSemanticFlagClasses.__class__(self._get_all_semantic_flag_classes)
		self._cb.getAllSemanticFlagGroups = self._cb.getAllSemanticFlagGroups.__class__(self._get_all_semantic_flag_groups)
		self._cb.getFlagRole = self._cb.getFlagRole.__class__(self._get_flag_role)
		self._cb.getFlagsRequiredForFlagCondition = self._cb.getFlagsRequiredForFlagCondition.__class__(
			self._get_flags_required_for_flag_condition)
		self._cb.getFlagsRequiredForSemanticFlagGroup = self._cb.getFlagsRequiredForSemanticFlagGroup.__class__(
			self._get_flags_required_for_semantic_flag_group)
		self._cb.getFlagConditionsForSemanticFlagGroup = self._cb.getFlagConditionsForSemanticFlagGroup.__class__(
			self._get_flag_conditions_for_semantic_flag_group)
		self._cb.freeFlagConditionsForSemanticFlagGroup = self._cb.freeFlagConditionsForSemanticFlagGroup.__class__(
			self._free_flag_conditions_for_semantic_flag_group)
		self._cb.getFlagsWrittenByFlagWriteType = self._cb.getFlagsWrittenByFlagWriteType.__class__(
			self._get_flags_written_by_flag_write_type)
		self._cb.getSemanticClassForFlagWriteType = self._cb.getSemanticClassForFlagWriteType.__class__(
			self._get_semantic_class_for_flag_write_type)
		self._cb.getFlagWriteLowLevelIL = self._cb.getFlagWriteLowLevelIL.__class__(
			self._get_flag_write_low_level_il)
		self._cb.getFlagConditionLowLevelIL = self._cb.getFlagConditionLowLevelIL.__class__(
			self._get_flag_condition_low_level_il)
		self._cb.getSemanticFlagGroupLowLevelIL = self._cb.getSemanticFlagGroupLowLevelIL.__class__(
			self._get_semantic_flag_group_low_level_il)
		self._cb.freeRegisterList = self._cb.freeRegisterList.__class__(self._free_register_list)
		self._cb.getRegisterInfo = self._cb.getRegisterInfo.__class__(self._get_register_info)
		self._cb.getStackPointerRegister = self._cb.getStackPointerRegister.__class__(
			self._get_stack_pointer_register)
		self._cb.getLinkRegister = self._cb.getLinkRegister.__class__(self._get_link_register)
		self._cb.getGlobalRegisters = self._cb.getGlobalRegisters.__class__(self._get_global_registers)
		self._cb.getSystemRegisters = self._cb.getSystemRegisters.__class__(self._get_system_registers)
		self._cb.getRegisterStackName = self._cb.getRegisterStackName.__class__(self._get_register_stack_name)
		self._cb.getAllRegisterStacks = self._cb.getAllRegisterStacks.__class__(self._get_all_register_stacks)
		self._cb.getRegisterStackInfo = self._cb.getRegisterStackInfo.__class__(self._get_register_stack_info)
		self._cb.getIntrinsicName = self._cb.getIntrinsicName.__class__(self._get_intrinsic_name)
		self._cb.getAllIntrinsics = self._cb.getAllIntrinsics.__class__(self._get_all_intrinsics)
		self._cb.getIntrinsicInputs = self._cb.getIntrinsicInputs.__class__(self._get_intrinsic_inputs)
		self._cb.freeNameAndTypeList = self._cb.freeNameAndTypeList.__class__(self._free_name_and_type_list)
		self._cb.getIntrinsicOutputs = self._cb.getIntrinsicOutputs.__class__(self._get_intrinsic_outputs)
		self._cb.freeTypeList = self._cb.freeTypeList.__class__(self._free_type_list)
		self._cb.assemble = self._cb.assemble.__class__(self._assemble)
		self._cb.isNeverBranchPatchAvailable = self._cb.isNeverBranchPatchAvailable.__class__(
			self._is_never_branch_patch_available)
		self._cb.isAlwaysBranchPatchAvailable = self._cb.isAlwaysBranchPatchAvailable.__class__(
			self._is_always_branch_patch_available)
		self._cb.isInvertBranchPatchAvailable = self._cb.isInvertBranchPatchAvailable.__class__(
			self._is_invert_branch_patch_available)
		self._cb.isSkipAndReturnZeroPatchAvailable = self._cb.isSkipAndReturnZeroPatchAvailable.__class__(
			self._is_skip_and_return_zero_patch_available)
		self._cb.isSkipAndReturnValuePatchAvailable = self._cb.isSkipAndReturnValuePatchAvailable.__class__(
			self._is_skip_and_return_value_patch_available)
		self._cb.convertToNop = self._cb.convertToNop.__class__(self._convert_to_nop)
		self._cb.alwaysBranch = self._cb.alwaysBranch.__class__(self._always_branch)
		self._cb.invertBranch = self._cb.invertBranch.__class__(self._invert_branch)
		self._cb.skipAndReturnValue = self._cb.skipAndReturnValue.__class__(self._skip_and_return_value)

		self.__dict__["endianness"] = self.__class__.endianness
		self.__dict__["address_size"] = self.__class__.address_size
		self.__dict__["default_int_size"] = self.__class__.default_int_size
		self.__dict__["instr_alignment"] = self.__class__.instr_alignment
		self.__dict__["max_instr_length"] = self.__class__.max_instr_length
		self.__dict__["opcode_display_length"] = self.__class__.opcode_display_length
		self.__dict__["stack_pointer"] = self.__class__.stack_pointer
		self.__dict__["link_reg"] = self.__class__.link_reg

		self._all_regs = {}
		self._full_width_regs = {}
		self._regs_by_index = {}
		self.__dict__["regs"] = self.__class__.regs
		reg_index = 0

		# Registers used for storage in register stacks must be sequential, so allocate these in order first
		self._all_reg_stacks = {}
		self._reg_stacks_by_index = {}
		self.__dict__["reg_stacks"] = self.__class__.reg_stacks
		reg_stack_index = 0
		for reg_stack in self.reg_stacks:
			info = self.reg_stacks[reg_stack]
			for reg in info.storage_regs:
				self._all_regs[reg] = reg_index
				self._regs_by_index[reg_index] = reg
				self.regs[reg].index = reg_index
				reg_index += 1
			for reg in info.top_relative_regs:
				self._all_regs[reg] = reg_index
				self._regs_by_index[reg_index] = reg
				self.regs[reg].index = reg_index
				reg_index += 1
			if reg_stack not in self._all_reg_stacks:
				self._all_reg_stacks[reg_stack] = reg_stack_index
				self._reg_stacks_by_index[reg_stack_index] = reg_stack
				self.reg_stacks[reg_stack].index = reg_stack_index
				reg_stack_index += 1

		for reg in self.regs:
			info = self.regs[reg]
			if reg not in self._all_regs:
				self._all_regs[reg] = reg_index
				self._regs_by_index[reg_index] = reg
				self.regs[reg].index = reg_index
				reg_index += 1
			if info.full_width_reg not in self._all_regs:
				self._all_regs[info.full_width_reg] = reg_index
				self._regs_by_index[reg_index] = info.full_width_reg
				self.regs[info.full_width_reg].index = reg_index
				reg_index += 1
			if info.full_width_reg not in self._full_width_regs:
				self._full_width_regs[info.full_width_reg] = self._all_regs[info.full_width_reg]

		self._flags = {}
		self._flags_by_index = {}
		self.__dict__["flags"] = self.__class__.flags
		flag_index = 0
		for flag in self.__class__.flags:
			if flag not in self._flags:
				self._flags[flag] = flag_index
				self._flags_by_index[flag_index] = flag
				flag_index += 1

		self._flag_write_types = {}
		self._flag_write_types_by_index = {}
		self.__dict__["flag_write_types"] = self.__class__.flag_write_types
		write_type_index = 1
		for write_type in self.__class__.flag_write_types:
			if write_type not in self._flag_write_types:
				self._flag_write_types[write_type] = write_type_index
				self._flag_write_types_by_index[write_type_index] = write_type
				write_type_index += 1

		self._semantic_flag_classes = {}
		self._semantic_flag_classes_by_index = {}
		self.__dict__["semantic_flag_classes"] = self.__class__.semantic_flag_classes
		semantic_class_index = 1
		for sem_class in self.__class__.semantic_flag_classes:
			if sem_class not in self._semantic_flag_classes:
				self._semantic_flag_classes[sem_class] = semantic_class_index
				self._semantic_flag_classes_by_index[semantic_class_index] = sem_class
				semantic_class_index += 1

		self._semantic_flag_groups = {}
		self._semantic_flag_groups_by_index = {}
		self.__dict__["semantic_flag_groups"] = self.__class__.semantic_flag_groups
		semantic_group_index = 0
		for sem_group in self.__class__.semantic_flag_groups:
			if sem_group not in self._semantic_flag_groups:
				self._semantic_flag_groups[sem_group] = semantic_group_index
				self._semantic_flag_groups_by_index[semantic_group_index] = sem_group
				semantic_group_index += 1

		self._flag_roles = {}
		self.__dict__["flag_roles"] = self.__class__.flag_roles
		for flag in self.__class__.flag_roles:
			role = self.__class__.flag_roles[flag]
			if isinstance(role, str):
				role = FlagRole[role]
			self._flag_roles[self._flags[flag]] = role

		self.__dict__["flags_required_for_flag_condition"] = self.__class__.flags_required_for_flag_condition

		self._flags_required_by_semantic_flag_group = {}
		self.__dict__["flags_required_for_semantic_flag_group"] = self.__class__.flags_required_for_semantic_flag_group
		for group in self.__class__.flags_required_for_semantic_flag_group:
			flags = []
			for flag in self.__class__.flags_required_for_semantic_flag_group[group]:
				flags.append(self._flags[flag])
			self._flags_required_by_semantic_flag_group[self._semantic_flag_groups[group]] = flags

		self._flag_conditions_for_semantic_flag_group = {}
		self.__dict__["flag_conditions_for_semantic_flag_group"] = self.__class__.flag_conditions_for_semantic_flag_group
		for group in self.__class__.flag_conditions_for_semantic_flag_group:
			class_cond = {}
			for sem_class in self.__class__.flag_conditions_for_semantic_flag_group[group]:
				if sem_class is None:
					class_cond[0] = self.__class__.flag_conditions_for_semantic_flag_group[group][sem_class]
				else:
					class_cond[self._semantic_flag_classes[sem_class]] = self.__class__.flag_conditions_for_semantic_flag_group[group][sem_class]
			self._flag_conditions_for_semantic_flag_group[self._semantic_flag_groups[group]] = class_cond

		self._flags_written_by_flag_write_type = {}
		self.__dict__["flags_written_by_flag_write_type"] = self.__class__.flags_written_by_flag_write_type
		for write_type in self.__class__.flags_written_by_flag_write_type:
			flags = []
			for flag in self.__class__.flags_written_by_flag_write_type[write_type]:
				flags.append(self._flags[flag])
			self._flags_written_by_flag_write_type[self._flag_write_types[write_type]] = flags

		self._semantic_class_for_flag_write_type = {}
		self.__dict__["semantic_class_for_flag_write_type"] = self.__class__.semantic_class_for_flag_write_type
		for write_type in self.__class__.semantic_class_for_flag_write_type:
			sem_class = self.__class__.semantic_class_for_flag_write_type[write_type]
			if sem_class in self._semantic_flag_classes:
				sem_class_index = self._semantic_flag_classes[sem_class]
			else:
				sem_class_index = 0
			self._semantic_class_for_flag_write_type[self._flag_write_types[write_type]] = sem_class_index

		self.__dict__["global_regs"] = self.__class__.global_regs
		self.__dict__["system_regs"] = self.__class__.system_regs

		self._intrinsics = {}
		self._intrinsics_by_index = {}
		self.__dict__["intrinsics"] = self.__class__.intrinsics
		intrinsic_index = 0
		for intrinsic in self.__class__.intrinsics.keys():
			if intrinsic not in self._intrinsics:
				info = self.__class__.intrinsics[intrinsic]
				for i in range(0, len(info.inputs)):
					if isinstance(info.inputs[i], types.Type):
						info.inputs[i] = binaryninja.function.IntrinsicInput(info.inputs[i])
					elif isinstance(info.inputs[i], tuple):
						info.inputs[i] = binaryninja.function.IntrinsicInput(info.inputs[i][0], info.inputs[i][1])
				info.index = intrinsic_index
				self._intrinsics[intrinsic] = intrinsic_index
				self._intrinsics_by_index[intrinsic_index] = (intrinsic, info)
				intrinsic_index += 1

		self._pending_reg_lists = {}
		self._pending_token_lists = {}
		self._pending_condition_lists = {}
		self._pending_name_and_type_lists = {}
		self._pending_type_lists = {}

	def __repr__(self):
		return "<arch: %s>" % self.name

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(other.handle.contents)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash(ctypes.addressof(self.handle.contents))

	def __setattr__(self, name, value):
		if ((name == "name") or (name == "endianness") or (name == "address_size") or
			(name == "default_int_size") or (name == "regs") or (name == "get_max_instruction_length") or
			(name == "get_instruction_alignment")):
			raise AttributeError("attribute '%s' is read only" % name)
		else:
			try:
				object.__setattr__(self, name, value)
			except AttributeError:
				raise AttributeError("attribute '%s' is read only" % name)

	@property
	def list(self):
		"""Allow tab completion to discover metaclass list property"""
		pass

	@property
	def full_width_regs(self):
		"""List of full width register strings (read-only)"""
		count = ctypes.c_ulonglong()
		regs = core.BNGetFullWidthArchitectureRegisters(self.handle, count)
		result = []
		for i in range(0, count.value):
			result.append(core.BNGetArchitectureRegisterName(self.handle, regs[i]))
		core.BNFreeRegisterList(regs)
		return result

	@property
	def calling_conventions(self):
		"""Dict of CallingConvention objects (read-only)"""
		count = ctypes.c_ulonglong()
		cc = core.BNGetArchitectureCallingConventions(self.handle, count)
		result = {}
		for i in range(0, count.value):
			obj = callingconvention.CallingConvention(handle=core.BNNewCallingConventionReference(cc[i]))
			result[obj.name] = obj
		core.BNFreeCallingConventionList(cc, count)
		return result

	@property
	def standalone_platform(self):
		"""Architecture standalone platform (read-only)"""
		pl = core.BNGetArchitectureStandalonePlatform(self.handle)
		return platform.Platform(self, pl)

	@property
	def type_libraries(self):
		"""Architecture type libraries"""
		count = ctypes.c_ulonglong(0)
		result = []
		handles = core.BNGetArchitectureTypeLibraries(self.handle, count)
		for i in range(0, count.value):
			result.append(binaryninja.typelibrary.TypeLibrary(core.BNNewTypeLibraryReference(handles[i])))
		core.BNFreeTypeLibraryList(handles, count.value)
		return result

	def _init(self, ctxt, handle):
		self.handle = handle

	def _get_endianness(self, ctxt):
		try:
			return self.endianness
		except:
			log.log_error(traceback.format_exc())
			return Endianness.LittleEndian

	def _get_address_size(self, ctxt):
		try:
			return self.address_size
		except:
			log.log_error(traceback.format_exc())
			return 8

	def _get_default_integer_size(self, ctxt):
		try:
			return self.default_int_size
		except:
			log.log_error(traceback.format_exc())
			return 4

	def _get_instruction_alignment(self, ctxt):
		try:
			return self.instr_alignment
		except:
			log.log_error(traceback.format_exc())
			return 1

	def _get_max_instruction_length(self, ctxt):
		try:
			return self.max_instr_length
		except:
			log.log_error(traceback.format_exc())
			return 16

	def _get_opcode_display_length(self, ctxt):
		try:
			return self.opcode_display_length
		except:
			log.log_error(traceback.format_exc())
			return 8

	def _get_associated_arch_by_address(self, ctxt, addr):
		try:
			result, new_addr = self.get_associated_arch_by_address(addr[0])
			addr[0] = new_addr
			return ctypes.cast(result.handle, ctypes.c_void_p).value
		except:
			log.log_error(traceback.format_exc())
			return ctypes.cast(self.handle, ctypes.c_void_p).value

	def _get_instruction_info(self, ctxt, data, addr, max_len, result):
		try:
			buf = ctypes.create_string_buffer(max_len)
			ctypes.memmove(buf, data, max_len)
			info = self.get_instruction_info(buf.raw, addr)
			if info is None:
				return False
			result[0].length = info.length
			result[0].archTransitionByTargetAddr = info.arch_transition_by_target_addr
			result[0].branchDelay = info.branch_delay
			result[0].branchCount = len(info.branches)
			for i in range(0, len(info.branches)):
				if isinstance(info.branches[i].type, str):
					result[0].branchType[i] = BranchType[info.branches[i].type]
				else:
					result[0].branchType[i] = info.branches[i].type
				result[0].branchTarget[i] = info.branches[i].target
				if info.branches[i].arch is None:
					result[0].branchArch[i] = None
				else:
					result[0].branchArch[i] = info.branches[i].arch.handle
			return True
		except (KeyError, OSError):
			log.log_error(traceback.format_exc())
			return False

	def _get_instruction_text(self, ctxt, data, addr, length, result, count):
		try:
			buf = ctypes.create_string_buffer(length[0])
			ctypes.memmove(buf, data, length[0])
			info = self.get_instruction_text(buf.raw, addr)
			if info is None:
				return False
			tokens = info[0]
			length[0] = info[1]
			count[0] = len(tokens)
			token_buf = binaryninja.function.InstructionTextToken.get_instruction_lines(tokens)
			result[0] = token_buf
			ptr = ctypes.cast(token_buf, ctypes.c_void_p)
			self._pending_token_lists[ptr.value] = (ptr.value, token_buf)
			return True
		except (KeyError, OSError):
			log.log_error(traceback.format_exc())
			return False

	def _free_instruction_text(self, tokens, count):
		try:
			buf = ctypes.cast(tokens, ctypes.c_void_p)
			if buf.value not in self._pending_token_lists:
				raise ValueError("freeing token list that wasn't allocated")
			del self._pending_token_lists[buf.value]
		except KeyError:
			log.log_error(traceback.format_exc())

	def _get_instruction_low_level_il(self, ctxt, data, addr, length, il):
		try:
			buf = ctypes.create_string_buffer(length[0])
			ctypes.memmove(buf, data, length[0])
			result = self.get_instruction_low_level_il(buf.raw, addr,
				lowlevelil.LowLevelILFunction(self, core.BNNewLowLevelILFunctionReference(il)))
			if result is None:
				return False
			length[0] = result
			return True
		except OSError:
			log.log_error(traceback.format_exc())
			return False

	def _get_register_name(self, ctxt, reg):
		try:
			if reg in self._regs_by_index:
				return core.BNAllocString(self._regs_by_index[reg])
			return core.BNAllocString("")
		except (KeyError, OSError):
			log.log_error(traceback.format_exc())
			return core.BNAllocString("")

	def _get_flag_name(self, ctxt, flag):
		try:
			if flag in self._flags_by_index:
				return core.BNAllocString(self._flags_by_index[flag])
			return core.BNAllocString("")
		except (KeyError, OSError):
			log.log_error(traceback.format_exc())
			return core.BNAllocString("")

	def _get_flag_write_type_name(self, ctxt, write_type):
		try:
			if write_type in self._flag_write_types_by_index:
				return core.BNAllocString(self._flag_write_types_by_index[write_type])
			return core.BNAllocString("")
		except (KeyError, OSError):
			log.log_error(traceback.format_exc())
			return core.BNAllocString("")

	def _get_semantic_flag_class_name(self, ctxt, sem_class):
		try:
			if sem_class in self._semantic_flag_classes_by_index:
				return core.BNAllocString(self._semantic_flag_classes_by_index[sem_class])
			return core.BNAllocString("")
		except (KeyError, OSError):
			log.log_error(traceback.format_exc())
			return core.BNAllocString("")

	def _get_semantic_flag_group_name(self, ctxt, sem_group):
		try:
			if sem_group in self._semantic_flag_groups_by_index:
				return core.BNAllocString(self._semantic_flag_groups_by_index[sem_group])
			return core.BNAllocString("")
		except (KeyError, OSError):
			log.log_error(traceback.format_exc())
			return core.BNAllocString("")

	def _get_full_width_registers(self, ctxt, count):
		try:
			regs = list(self._full_width_regs.values())
			count[0] = len(regs)
			reg_buf = (ctypes.c_uint * len(regs))()
			for i in range(0, len(regs)):
				reg_buf[i] = regs[i]
			result = ctypes.cast(reg_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, reg_buf)
			return result.value
		except KeyError:
			log.log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _get_all_registers(self, ctxt, count):
		try:
			regs = list(self._regs_by_index.keys())
			count[0] = len(regs)
			reg_buf = (ctypes.c_uint * len(regs))()
			for i in range(0, len(regs)):
				reg_buf[i] = regs[i]
			result = ctypes.cast(reg_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, reg_buf)
			return result.value
		except KeyError:
			log.log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _get_all_flags(self, ctxt, count):
		try:
			flags = list(self._flags_by_index.keys())
			count[0] = len(flags)
			flag_buf = (ctypes.c_uint * len(flags))()
			for i in range(0, len(flags)):
				flag_buf[i] = flags[i]
			result = ctypes.cast(flag_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, flag_buf)
			return result.value
		except KeyError:
			log.log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _get_all_flag_write_types(self, ctxt, count):
		try:
			write_types = list(self._flag_write_types_by_index.keys())
			count[0] = len(write_types)
			type_buf = (ctypes.c_uint * len(write_types))()
			for i in range(0, len(write_types)):
				type_buf[i] = write_types[i]
			result = ctypes.cast(type_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, type_buf)
			return result.value
		except KeyError:
			log.log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _get_all_semantic_flag_classes(self, ctxt, count):
		try:
			sem_classes = list(self._semantic_flag_classes_by_index.keys())
			count[0] = len(sem_classes)
			class_buf = (ctypes.c_uint * len(sem_classes))()
			for i in range(0, len(sem_classes)):
				class_buf[i] = sem_classes[i]
			result = ctypes.cast(class_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, class_buf)
			return result.value
		except KeyError:
			log.log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _get_all_semantic_flag_groups(self, ctxt, count):
		try:
			sem_groups = list(self._semantic_flag_groups_by_index.keys())
			count[0] = len(sem_groups)
			group_buf = (ctypes.c_uint * len(sem_groups))()
			for i in range(0, len(sem_groups)):
				group_buf[i] = sem_groups[i]
			result = ctypes.cast(group_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, group_buf)
			return result.value
		except KeyError:
			log.log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _get_flag_role(self, ctxt, flag, sem_class):
		try:
			if sem_class in self._semantic_flag_classes_by_index:
				sem_class = self._semantic_flag_classes_by_index[sem_class]
			else:
				sem_class = None
			return self.get_flag_role(flag, sem_class)
		except KeyError:
			log.log_error(traceback.format_exc())
			return FlagRole.SpecialFlagRole

	def _get_flags_required_for_flag_condition(self, ctxt, cond, sem_class, count):
		try:
			if sem_class in self._semantic_flag_classes_by_index:
				sem_class = self._semantic_flag_classes_by_index[sem_class]
			else:
				sem_class = None
			flag_names = self.get_flags_required_for_flag_condition(cond, sem_class)
			flags = []
			for name in flag_names:
				flags.append(self._flags[name])
			count[0] = len(flags)
			flag_buf = (ctypes.c_uint * len(flags))()
			for i in range(0, len(flags)):
				flag_buf[i] = flags[i]
			result = ctypes.cast(flag_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, flag_buf)
			return result.value
		except KeyError:
			log.log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _get_flags_required_for_semantic_flag_group(self, ctxt, sem_group, count):
		try:
			if sem_group in self._flags_required_by_semantic_flag_group:
				flags = self._flags_required_by_semantic_flag_group[sem_group]
			else:
				flags = []
			count[0] = len(flags)
			flag_buf = (ctypes.c_uint * len(flags))()
			for i in range(0, len(flags)):
				flag_buf[i] = flags[i]
			result = ctypes.cast(flag_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, flag_buf)
			return result.value
		except (KeyError, OSError):
			log.log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _get_flag_conditions_for_semantic_flag_group(self, ctxt, sem_group, count):
		try:
			if sem_group in self._flag_conditions_for_semantic_flag_group:
				class_cond = self._flag_conditions_for_semantic_flag_group[sem_group]
			else:
				class_cond = {}
			count[0] = len(class_cond)
			cond_buf = (core.BNFlagConditionForSemanticClass * len(class_cond))()
			i = 0
			for class_index in class_cond.keys():
				cond_buf[i].semanticClass = class_index
				cond_buf[i].condition = class_cond[class_index]
				i += 1
			result = ctypes.cast(cond_buf, ctypes.c_void_p)
			self._pending_condition_lists[result.value] = (result, cond_buf)
			return result.value
		except (KeyError, OSError):
			log.log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _free_flag_conditions_for_semantic_flag_group(self, ctxt, conditions):
		try:
			buf = ctypes.cast(conditions, ctypes.c_void_p)
			if buf.value not in self._pending_condition_lists:
				raise ValueError("freeing condition list that wasn't allocated")
			del self._pending_condition_lists[buf.value]
		except (ValueError, KeyError):
			log.log_error(traceback.format_exc())

	def _get_flags_written_by_flag_write_type(self, ctxt, write_type, count):
		try:
			if write_type in self._flags_written_by_flag_write_type:
				flags = self._flags_written_by_flag_write_type[write_type]
			else:
				flags = []
			count[0] = len(flags)
			flag_buf = (ctypes.c_uint * len(flags))()
			for i in range(0, len(flags)):
				flag_buf[i] = flags[i]
			result = ctypes.cast(flag_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, flag_buf)
			return result.value
		except (KeyError, OSError):
			log.log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _get_semantic_class_for_flag_write_type(self, ctxt, write_type):
		try:
			if write_type in self._semantic_class_for_flag_write_type:
				return self._semantic_class_for_flag_write_type[write_type]
			else:
				return 0
		except (KeyError, OSError):
			log.log_error(traceback.format_exc())
			return 0

	def _get_flag_write_low_level_il(self, ctxt, op, size, write_type, flag, operands, operand_count, il):
		try:
			write_type_name = None
			if write_type != 0:
				write_type_name = self._flag_write_types_by_index[write_type]
			flag_name = self._flags_by_index[flag]
			operand_list = []
			for i in range(operand_count):
				if operands[i].constant:
					operand_list.append(operands[i].value)
				elif lowlevelil.LLIL_REG_IS_TEMP(operands[i].reg):
					operand_list.append(lowlevelil.ILRegister(self, operands[i].reg))
				else:
					operand_list.append(lowlevelil.ILRegister(self, operands[i].reg))
			return self.get_flag_write_low_level_il(op, size, write_type_name, flag_name, operand_list,
				lowlevelil.LowLevelILFunction(self, core.BNNewLowLevelILFunctionReference(il))).index
		except (KeyError, OSError):
			log.log_error(traceback.format_exc())
			return False

	def _get_flag_condition_low_level_il(self, ctxt, cond, sem_class, il):
		try:
			if sem_class in self._semantic_flag_classes_by_index:
				sem_class_name = self._semantic_flag_classes_by_index[sem_class]
			else:
				sem_class_name = None
			return self.get_flag_condition_low_level_il(cond, sem_class_name,
				lowlevelil.LowLevelILFunction(self, core.BNNewLowLevelILFunctionReference(il))).index
		except OSError:
			log.log_error(traceback.format_exc())
			return 0

	def _get_semantic_flag_group_low_level_il(self, ctxt, sem_group, il):
		try:
			if sem_group in self._semantic_flag_groups_by_index:
				sem_group_name = self._semantic_flag_groups_by_index[sem_group]
			else:
				sem_group_name = None
			return self.get_semantic_flag_group_low_level_il(sem_group_name,
				lowlevelil.LowLevelILFunction(self, core.BNNewLowLevelILFunctionReference(il))).index
		except OSError:
			log.log_error(traceback.format_exc())
			return 0

	def _free_register_list(self, ctxt, regs):
		try:
			buf = ctypes.cast(regs, ctypes.c_void_p)
			if buf.value not in self._pending_reg_lists:
				raise ValueError("freeing register list that wasn't allocated")
			del self._pending_reg_lists[buf.value]
		except (ValueError, KeyError):
			log.log_error(traceback.format_exc())

	def _get_register_info(self, ctxt, reg, result):
		try:
			if reg not in self._regs_by_index:
				result[0].fullWidthRegister = 0
				result[0].offset = 0
				result[0].size = 0
				result[0].extend = ImplicitRegisterExtend.NoExtend
				return
			info = self.regs[self._regs_by_index[reg]]
			result[0].fullWidthRegister = self._all_regs[info.full_width_reg]
			result[0].offset = info.offset
			result[0].size = info.size
			if isinstance(info.extend, str):
				result[0].extend = ImplicitRegisterExtend[info.extend]
			else:
				result[0].extend = info.extend
		except KeyError:
			log.log_error(traceback.format_exc())
			result[0].fullWidthRegister = 0
			result[0].offset = 0
			result[0].size = 0
			result[0].extend = ImplicitRegisterExtend.NoExtend

	def _get_stack_pointer_register(self, ctxt):
		try:
			return self._all_regs[self.stack_pointer]
		except KeyError:
			log.log_error(traceback.format_exc())
			return 0

	def _get_link_register(self, ctxt):
		try:
			if self.link_reg is None:
				return 0xffffffff
			return self._all_regs[self.link_reg]
		except KeyError:
			log.log_error(traceback.format_exc())
			return 0

	def _get_global_registers(self, ctxt, count):
		try:
			count[0] = len(self.global_regs)
			reg_buf = (ctypes.c_uint * len(self.global_regs))()
			for i in range(0, len(self.global_regs)):
				reg_buf[i] = self._all_regs[self.global_regs[i]]
			result = ctypes.cast(reg_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, reg_buf)
			return result.value
		except KeyError:
			log.log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _get_system_registers(self, ctxt, count):
		try:
			count[0] = len(self.system_regs)
			reg_buf = (ctypes.c_uint * len(self.system_regs))()
			for i in range(0, len(self.system_regs)):
				reg_buf[i] = self._all_regs[self.system_regs[i]]
			result = ctypes.cast(reg_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, reg_buf)
			return result.value
		except KeyError:
			log.log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _get_register_stack_name(self, ctxt, reg_stack):
		try:
			if reg_stack in self._reg_stacks_by_index:
				return core.BNAllocString(self._reg_stacks_by_index[reg_stack])
			return core.BNAllocString("")
		except (KeyError, OSError):
			log.log_error(traceback.format_exc())
			return core.BNAllocString("")

	def _get_all_register_stacks(self, ctxt, count):
		try:
			regs = list(self._reg_stacks_by_index.keys())
			count[0] = len(regs)
			reg_buf = (ctypes.c_uint * len(regs))()
			for i in range(0, len(regs)):
				reg_buf[i] = regs[i]
			result = ctypes.cast(reg_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, reg_buf)
			return result.value
		except KeyError:
			log.log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _get_register_stack_info(self, ctxt, reg_stack, result):
		try:
			if reg_stack not in self._reg_stacks_by_index:
				result[0].firstStorageReg = 0
				result[0].firstTopRelativeReg = 0
				result[0].storageCount = 0
				result[0].topRelativeCount = 0
				result[0].stackTopReg = 0
				return
			info = self.reg_stacks[self._reg_stacks_by_index[reg_stack]]
			result[0].firstStorageReg = self._all_regs[info.storage_regs[0]]
			result[0].storageCount = len(info.storage_regs)
			if len(info.top_relative_regs) > 0:
				result[0].firstTopRelativeReg = self._all_regs[info.top_relative_regs[0]]
				result[0].topRelativeCount = len(info.top_relative_regs)
			else:
				result[0].firstTopRelativeReg = 0
				result[0].topRelativeCount = 0
			result[0].stackTopReg = self._all_regs[info.stack_top_reg]
		except KeyError:
			log.log_error(traceback.format_exc())
			result[0].firstStorageReg = 0
			result[0].firstTopRelativeReg = 0
			result[0].storageCount = 0
			result[0].topRelativeCount = 0
			result[0].stackTopReg = 0

	def _get_intrinsic_name(self, ctxt, intrinsic):
		try:
			if intrinsic in self._intrinsics_by_index:
				return core.BNAllocString(self._intrinsics_by_index[intrinsic][0])
			return core.BNAllocString("")
		except (KeyError, OSError):
			log.log_error(traceback.format_exc())
			return core.BNAllocString("")

	def _get_all_intrinsics(self, ctxt, count):
		try:
			regs = list(self._intrinsics_by_index.keys())
			count[0] = len(regs)
			reg_buf = (ctypes.c_uint * len(regs))()
			for i in range(0, len(regs)):
				reg_buf[i] = regs[i]
			result = ctypes.cast(reg_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, reg_buf)
			return result.value
		except KeyError:
			log.log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _get_intrinsic_inputs(self, ctxt, intrinsic, count):
		try:
			if intrinsic in self._intrinsics_by_index:
				inputs = self._intrinsics_by_index[intrinsic][1].inputs
				count[0] = len(inputs)
				input_buf = (core.BNNameAndType * len(inputs))()
				for i in range(0, len(inputs)):
					input_buf[i].name = inputs[i].name
					input_buf[i].type = core.BNNewTypeReference(inputs[i].type.handle)
					input_buf[i].typeConfidence = inputs[i].type.confidence
				result = ctypes.cast(input_buf, ctypes.c_void_p)
				self._pending_name_and_type_lists[result.value] = (result, input_buf, len(inputs))
				return result.value
			count[0] = 0
			return None
		except:
			log.log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _free_name_and_type_list(self, ctxt, buf_raw, length):
		try:
			buf = ctypes.cast(buf_raw, ctypes.c_void_p)
			if buf.value not in self._pending_name_and_type_lists:
				raise ValueError("freeing name and type list that wasn't allocated")
			name_and_types = self._pending_name_and_type_lists[buf.value][1]
			count = self._pending_name_and_type_lists[buf.value][2]
			for i in range(0, count):
				core.BNFreeType(name_and_types[i].type)
			del self._pending_name_and_type_lists[buf.value]
		except (ValueError, KeyError):
			log.log_error(traceback.format_exc())

	def _get_intrinsic_outputs(self, ctxt, intrinsic, count):
		try:
			if intrinsic in self._intrinsics_by_index:
				outputs = self._intrinsics_by_index[intrinsic][1].outputs
				count[0] = len(outputs)
				output_buf = (core.BNTypeWithConfidence * len(outputs))()
				for i in range(0, len(outputs)):
					output_buf[i].type = core.BNNewTypeReference(outputs[i].handle)
					output_buf[i].confidence = outputs[i].confidence
				result = ctypes.cast(output_buf, ctypes.c_void_p)
				self._pending_type_lists[result.value] = (result, output_buf, len(outputs))
				return result.value
			count[0] = 0
			return None
		except:
			log.log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _free_type_list(self, ctxt, buf_raw, length):
		try:
			buf = ctypes.cast(buf_raw, ctypes.c_void_p)
			if buf.value not in self._pending_type_lists:
				raise ValueError("freeing type list that wasn't allocated")
			types = self._pending_type_lists[buf.value][1]
			count = self._pending_type_lists[buf.value][2]
			for i in range(0, count):
				core.BNFreeType(types[i].type)
			del self._pending_type_lists[buf.value]
		except (ValueError, KeyError):
			log.log_error(traceback.format_exc())

	def _assemble(self, ctxt, code, addr, result, errors):
		"""
		This function calls the `assemble` command for the actual architecture plugin.
		If the plugin does not provide an `assemble(self, code, addr)`-style function,
		it uses the default function provided in CoreArchitecture.
		"""
		try:
			data = self.assemble(code, addr)
			if data is None:
				return False
			buf = ctypes.create_string_buffer(len(data))
			ctypes.memmove(buf, data, len(data))
			core.BNSetDataBufferContents(result, buf, len(data))
			return True
		except ValueError as e:  # Overriden `assemble` functions should raise a ValueError if the input was invalid (with a reasonable error message)
			log.log_error(traceback.format_exc())
			errors[0] = core.BNAllocString(str(e))
			return False
		except:
			log.log_error(traceback.format_exc())
			errors[0] = core.BNAllocString("Unhandled exception during assembly.\n")
			return False

	def _is_never_branch_patch_available(self, ctxt, data, addr, length):
		try:
			buf = ctypes.create_string_buffer(length)
			ctypes.memmove(buf, data, length)
			return self.is_never_branch_patch_available(buf.raw, addr)
		except:
			log.log_error(traceback.format_exc())
			return False

	def _is_always_branch_patch_available(self, ctxt, data, addr, length):
		try:
			buf = ctypes.create_string_buffer(length)
			ctypes.memmove(buf, data, length)
			return self.is_always_branch_patch_available(buf.raw, addr)
		except:
			log.log_error(traceback.format_exc())
			return False

	def _is_invert_branch_patch_available(self, ctxt, data, addr, length):
		try:
			buf = ctypes.create_string_buffer(length)
			ctypes.memmove(buf, data, length)
			return self.is_invert_branch_patch_available(buf.raw, addr)
		except:
			log.log_error(traceback.format_exc())
			return False

	def _is_skip_and_return_zero_patch_available(self, ctxt, data, addr, length):
		try:
			buf = ctypes.create_string_buffer(length)
			ctypes.memmove(buf, data, length)
			return self.is_skip_and_return_zero_patch_available(buf.raw, addr)
		except:
			log.log_error(traceback.format_exc())
			return False

	def _is_skip_and_return_value_patch_available(self, ctxt, data, addr, length):
		try:
			buf = ctypes.create_string_buffer(length)
			ctypes.memmove(buf, data, length)
			return self.is_skip_and_return_value_patch_available(buf.raw, addr)
		except:
			log.log_error(traceback.format_exc())
			return False

	def _convert_to_nop(self, ctxt, data, addr, length):
		try:
			buf = ctypes.create_string_buffer(length)
			ctypes.memmove(buf, data, length)
			result = self.convert_to_nop(buf.raw, addr)
			if result is None:
				return False
			if len(result) > length:
				result = result[0:length]
			ctypes.memmove(data, result, len(result))
			return True
		except:
			log.log_error(traceback.format_exc())
			return False

	def _always_branch(self, ctxt, data, addr, length):
		try:
			buf = ctypes.create_string_buffer(length)
			ctypes.memmove(buf, data, length)
			result = self.always_branch(buf.raw, addr)
			if result is None:
				return False
			if len(result) > length:
				result = result[0:length]
			ctypes.memmove(data, result, len(result))
			return True
		except:
			log.log_error(traceback.format_exc())
			return False

	def _invert_branch(self, ctxt, data, addr, length):
		try:
			buf = ctypes.create_string_buffer(length)
			ctypes.memmove(buf, data, length)
			result = self.invert_branch(buf.raw, addr)
			if result is None:
				return False
			if len(result) > length:
				result = result[0:length]
			ctypes.memmove(data, result, len(result))
			return True
		except:
			log.log_error(traceback.format_exc())
			return False

	def _skip_and_return_value(self, ctxt, data, addr, length, value):
		try:
			buf = ctypes.create_string_buffer(length)
			ctypes.memmove(buf, data, length)
			result = self.skip_and_return_value(buf.raw, addr, value)
			if result is None:
				return False
			if len(result) > length:
				result = result[0:length]
			ctypes.memmove(data, result, len(result))
			return True
		except:
			log.log_error(traceback.format_exc())
			return False

	def perform_get_associated_arch_by_address(self, addr):
		"""
		Deprecated method provided for compatibility. Architecture plugins should override :func:`get_associated_arch_by_address`.
		"""
		return self, addr

	@abc.abstractmethod
	def perform_get_instruction_info(self, data, addr):
		"""
		Deprecated method provided for compatibility. Architecture plugins should override :func:`get_instruction_info`.

		:param str data: bytes to decode
		:param int addr: virtual address of the byte to be decoded
		:return: a :py:class:`InstructionInfo` object containing the length and branch types for the given instruction
		:rtype: InstructionInfo
		"""
		raise NotImplementedError

	@abc.abstractmethod
	def perform_get_instruction_text(self, data, addr):
		"""
		Deprecated method provided for compatibility. Architecture plugins should override :func:`get_instruction_text`.

		:param str data: bytes to decode
		:param int addr: virtual address of the byte to be decoded
		:return: a tuple of list(InstructionTextToken) and length of instruction decoded
		:rtype: tuple(list(InstructionTextToken), int)
		"""
		raise NotImplementedError

	@abc.abstractmethod
	def perform_get_instruction_low_level_il(self, data, addr, il):
		"""
		Deprecated method provided for compatibility. Architecture plugins should override :func:`get_instruction_low_level_il`.

		:param str data: bytes to be interpreted as low-level IL instructions
		:param int addr: virtual address of start of ``data``
		:param LowLevelILFunction il: LowLevelILFunction object to append LowLevelILExpr objects to
		:rtype: length of bytes read on success, None on failure
		"""
		raise NotImplementedError

	@abc.abstractmethod
	def perform_get_flag_write_low_level_il(self, op, size, write_type, flag, operands, il):
		"""
		Deprecated method provided for compatibility. Architecture plugins should override :func:`get_flag_write_low_level_il`.

		:param LowLevelILOperation op:
		:param int size:
		:param int write_type:
		:param int flag:
		:param operands:
		:type operands: list(str) or list(int)
		:param LowLevelILFunction il:
		:rtype: LowLevelILExpr
		"""
		flag = self.get_flag_index(flag)
		if flag not in self._flag_roles:
			return il.unimplemented()
		return self.get_default_flag_write_low_level_il(op, size, self._flag_roles[flag], operands, il)

	@abc.abstractmethod
	def perform_get_flag_condition_low_level_il(self, cond, sem_class, il):
		"""
		Deprecated method provided for compatibility. Architecture plugins should override :func:`get_flag_condition_low_level_il`.

		:param LowLevelILFlagCondition cond: Flag condition to be computed
		:param str sem_class: Semantic class to be used (None for default semantics)
		:param LowLevelILFunction il: LowLevelILFunction object to append LowLevelILExpr objects to
		:rtype: LowLevelILExpr
		"""
		return self.get_default_flag_condition_low_level_il(cond, sem_class, il)

	@abc.abstractmethod
	def perform_get_semantic_flag_group_low_level_il(self, sem_group, il):
		"""
		Deprecated method provided for compatibility. Architecture plugins should override :func:`get_semantic_flag_group_low_level_il`.

		:param str sem_group: Semantic group to be computed
		:param LowLevelILFunction il: LowLevelILFunction object to append LowLevelILExpr objects to
		:rtype: LowLevelILExpr
		"""
		return il.unimplemented()

	@abc.abstractmethod
	def perform_assemble(self, code, addr):
		"""
		Deprecated method provided for compatibility. Architecture plugins should override :func:`assemble`.

		:param str code: string representation of the instructions to be assembled
		:param int addr: virtual address that the instructions will be loaded at
		:return: the bytes for the assembled instructions or error string
		:rtype: (a tuple of instructions and empty string) or (or None and error string)
		"""
		raise NotImplementedError("Architecture does not implement an assembler.\n")

	@abc.abstractmethod
	def perform_is_never_branch_patch_available(self, data, addr):
		"""
		Deprecated method provided for compatibility. Architecture plugins should override :func:`is_never_branch_patch_available`.

		.. note:: Architecture subclasses should implement this method.

		.. warning:: This method should never be called directly.

		:param str data: bytes to be checked
		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		"""
		return False

	@abc.abstractmethod
	def perform_is_always_branch_patch_available(self, data, addr):
		"""
		Deprecated method provided for compatibility. Architecture plugins should override :func:`is_always_branch_patch_available`.

		:param str data: bytes to be checked
		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		"""
		return False

	@abc.abstractmethod
	def perform_is_invert_branch_patch_available(self, data, addr):
		"""
		Deprecated method provided for compatibility. Architecture plugins should override :func:`is_invert_branch_patch_available`.

		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		"""
		return False

	@abc.abstractmethod
	def perform_is_skip_and_return_zero_patch_available(self, data, addr):
		"""
		Deprecated method provided for compatibility. Architecture plugins should override :func:`is_skip_and_return_zero_patch_available`.

		:param str data: bytes to be checked
		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		"""
		return False

	@abc.abstractmethod
	def perform_is_skip_and_return_value_patch_available(self, data, addr):
		"""
		Deprecated method provided for compatibility. Architecture plugins should override :func:`is_skip_and_return_value_patch_available`.

		:param str data: bytes to be checked
		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		"""
		return False

	@abc.abstractmethod
	def perform_convert_to_nop(self, data, addr):
		"""
		Deprecated method provided for compatibility. Architecture plugins should override :func:`convert_to_nop`.

		:param str data: bytes at virtual address ``addr``
		:param int addr: the virtual address of the instruction to be patched
		:return: nop sequence of same length as ``data`` or None
		:rtype: str or None
		"""
		return None

	@abc.abstractmethod
	def perform_always_branch(self, data, addr):
		"""
		Deprecated method provided for compatibility. Architecture plugins should override :func:`always_branch`.

		:param str data: bytes to be checked
		:param int addr: the virtual address of the instruction to be patched
		:return: The bytes of the replacement unconditional branch instruction
		:rtype: str
		"""
		return None

	@abc.abstractmethod
	def perform_invert_branch(self, data, addr):
		"""
		Deprecated method provided for compatibility. Architecture plugins should override :func:`invert_branch`.

		:param str data: bytes to be checked
		:param int addr: the virtual address of the instruction to be patched
		:return: The bytes of the replacement unconditional branch instruction
		:rtype: str
		"""
		return None

	@abc.abstractmethod
	def perform_skip_and_return_value(self, data, addr, value):
		"""
		Deprecated method provided for compatibility. Architecture plugins should override :func:`skip_and_return_value`.

		:param str data: bytes to be checked
		:param int addr: the virtual address of the instruction to be patched
		:param int value: value to be returned
		:return: The bytes of the replacement unconditional branch instruction
		:rtype: str
		"""
		return None

	def perform_get_flag_role(self, flag, sem_class):
		"""
		Deprecated method provided for compatibility. Architecture plugins should override :func:`get_flag_role`.
		"""
		if flag in self._flag_roles:
			return self._flag_roles[flag]
		return FlagRole.SpecialFlagRole

	def perform_get_flags_required_for_flag_condition(self, cond, sem_class):
		"""
		Deprecated method provided for compatibility. Architecture plugins should override :func:`get_flags_required_for_flag_condition`.
		"""
		if cond in self.flags_required_for_flag_condition:
			return self.flags_required_for_flag_condition[cond]
		return []

	def get_associated_arch_by_address(self, addr):
		return self.perform_get_associated_arch_by_address(addr)

	def get_instruction_info(self, data, addr):
		"""
		``get_instruction_info`` returns an InstructionInfo object for the instruction at the given virtual address
		``addr`` with data ``data``.

		.. note:: Architecture subclasses should implement this method.

		.. note:: The instruction info object should always set the InstructionInfo.length to the instruction length, \
		and the branches of the proper types should be added if the instruction is a branch.

		If the instruction is a branch instruction architecture plugins should add a branch of the proper type:

			===================== ===================================================
			BranchType            Description
			===================== ===================================================
			UnconditionalBranch   Branch will always be taken
			FalseBranch           False branch condition
			TrueBranch            True branch condition
			CallDestination       Branch is a call instruction (Branch with Link)
			FunctionReturn        Branch returns from a function
			SystemCall            System call instruction
			IndirectBranch        Branch destination is a memory address or register
			UnresolvedBranch      Branch destination is an unknown address
			===================== ===================================================

		:param str data: max_instruction_length bytes from the binary at virtual address ``addr``
		:param int addr: virtual address of bytes in ``data``
		:return: the InstructionInfo for the current instruction
		:rtype: InstructionInfo
		"""
		return self.perform_get_instruction_info(data, addr)

	def get_instruction_text(self, data, addr):
		"""
		``get_instruction_text`` returns a tuple containing a list of decoded InstructionTextToken objects and the bytes used at the given virtual
		address ``addr`` with data ``data``.

		.. note:: Architecture subclasses should implement this method.

		:param str data: max_instruction_length bytes from the binary at virtual address ``addr``
		:param int addr: virtual address of bytes in ``data``
		:return: a tuple containing the InstructionTextToken list and length of bytes decoded
		:rtype: tuple(list(InstructionTextToken), int)
		"""
		return self.perform_get_instruction_text(data, addr)

	def get_instruction_low_level_il_instruction(self, bv, addr):
		il = lowlevelil.LowLevelILFunction(self)
		data = bv.read(addr, self.max_instr_length)
		self.get_instruction_low_level_il(data, addr, il)
		return il[0]

	def get_instruction_low_level_il(self, data, addr, il):
		"""
		``get_instruction_low_level_il`` appends LowLevelILExpr objects to ``il`` for the instruction at the given
		virtual address ``addr`` with data ``data``.

		This is used to analyze arbitrary data at an address, if you are working with an existing binary, you likely
		want to be using :func:`Function.get_low_level_il_at`.

		.. note:: Architecture subclasses should implement this method.

		:param str data: max_instruction_length bytes from the binary at virtual address ``addr``
		:param int addr: virtual address of bytes in ``data``
		:param LowLevelILFunction il: The function the current instruction belongs to
		:return: the length of the current instruction
		:rtype: int
		"""
		return self.perform_get_instruction_low_level_il(data, addr, il)

	def get_low_level_il_from_bytes(self, data, addr):
		"""
		``get_low_level_il_from_bytes`` converts the instruction in bytes to ``il`` at the given virtual address

		:param str data: the bytes of the instruction
		:param int addr: virtual address of bytes in ``data``
		:return: the instruction
		:rtype: LowLevelILInstruction
		:Example:

			>>> arch.get_low_level_il_from_bytes(b'\\xeb\\xfe', 0x40DEAD)
			<il: jump(0x40dead)>
			>>>
		"""
		func = lowlevelil.LowLevelILFunction(self)
		self.get_instruction_low_level_il(data, addr, func)
		return func[0]

	def get_reg_name(self, reg):
		"""
		``get_reg_name`` gets a register name from a register number.

		:param int reg: register number
		:return: the corresponding register string
		:rtype: str
		"""
		return core.BNGetArchitectureRegisterName(self.handle, reg)

	def get_reg_stack_name(self, reg_stack):
		"""
		``get_reg_stack_name`` gets a register stack name from a register stack number.

		:param int reg_stack: register stack number
		:return: the corresponding register string
		:rtype: str
		"""
		return core.BNGetArchitectureRegisterStackName(self.handle, reg_stack)

	def get_reg_stack_for_reg(self, reg):
		reg = self.get_reg_index(reg)
		result = core.BNGetArchitectureRegisterStackForRegister(self.handle, reg)
		if result == 0xffffffff:
			return None
		return self.get_reg_stack_name(result)

	def get_flag_name(self, flag):
		"""
		``get_flag_name`` gets a flag name from a flag number.

		:param int reg: register number
		:return: the corresponding register string
		:rtype: str
		"""
		return core.BNGetArchitectureFlagName(self.handle, flag)

	def get_reg_index(self, reg):
		if isinstance(reg, str):
			return self.regs[reg].index
		elif isinstance(reg, lowlevelil.ILRegister):
			return reg.index
		return reg

	def get_reg_stack_index(self, reg_stack):
		if isinstance(reg_stack, str):
			return self.reg_stacks[reg_stack].index
		elif isinstance(reg_stack, lowlevelil.ILRegisterStack):
			return reg_stack.index
		return reg_stack

	def get_flag_index(self, flag):
		if isinstance(flag, str):
			return self._flags[flag]
		elif isinstance(flag, lowlevelil.ILFlag):
			return flag.index
		return flag

	def get_semantic_flag_class_index(self, sem_class):
		if sem_class is None:
			return 0
		elif isinstance(sem_class, str):
			return self._semantic_flag_classes[sem_class]
		elif isinstance(sem_class, lowlevelil.ILSemanticFlagClass):
			return sem_class.index
		return sem_class

	def get_semantic_flag_class_name(self, class_index):
		"""
		``get_semantic_flag_class_name`` gets the name of a semantic flag class from the index.

		:param int _index: class_index
		:return: the name of the semantic flag class
		:rtype: str
		"""
		if not isinstance(class_index, numbers.Integral):
			raise ValueError("argument 'class_index' must be an integer")
		try:
			return self._semantic_flag_classes_by_index[class_index]
		except KeyError:
			raise AttributeError("argument class_index is not a valid class index")

	def get_semantic_flag_group_index(self, sem_group):
		if isinstance(sem_group, str):
			return self._semantic_flag_groups[sem_group]
		elif isinstance(sem_group, lowlevelil.ILSemanticFlagGroup):
			return sem_group.index
		return sem_group

	def get_semantic_flag_group_name(self, group_index):
		"""
		``get_semantic_flag_group_name`` gets the name of a semantic flag group from the index.

		:param int group_index: group_index
		:return: the name of the semantic flag group
		:rtype: str
		"""
		if not isinstance(group_index, numbers.Integral):
			raise ValueError("argument 'group_index' must be an integer")
		try:
			return self._semantic_flag_groups_by_index[group_index]
		except KeyError:
			raise AttributeError("argument group_index is not a valid group index")

	def get_intrinsic_name(self, intrinsic):
		"""
		``get_intrinsic_name`` gets an intrinsic name from an intrinsic number.

		:param int intrinsic: intrinsic number
		:return: the corresponding intrinsic string
		:rtype: str
		"""
		return core.BNGetArchitectureIntrinsicName(self.handle, intrinsic)

	def get_intrinsic_index(self, intrinsic):
		if isinstance(intrinsic, str):
			return self._intrinsics[intrinsic]
		elif isinstance(intrinsic, lowlevelil.ILIntrinsic):
			return intrinsic.index
		return intrinsic

	def get_flag_write_type_name(self, write_type):
		"""
		``get_flag_write_type_name`` gets the flag write type name for the given flag.

		:param int write_type: flag
		:return: flag write type name
		:rtype: str
		"""
		return core.BNGetArchitectureFlagWriteTypeName(self.handle, write_type)

	def get_flag_by_name(self, flag):
		"""
		``get_flag_by_name`` get flag name for flag index.

		:param int flag: flag index
		:return: flag name for flag index
		:rtype: str
		"""
		return self._flags[flag]

	def get_flag_write_type_by_name(self, write_type):
		"""
		``get_flag_write_type_by_name`` gets the flag write type name for the flag write type.

		:param int write_type: flag write type
		:return: flag write type
		:rtype: str
		"""
		return self._flag_write_types[write_type]

	def get_semantic_flag_class_by_name(self, sem_class):
		"""
		``get_semantic_flag_class_by_name`` gets the semantic flag class index by name.

		:param int sem_class: semantic flag class
		:return: semantic flag class index
		:rtype: str
		"""
		return self._semantic_flag_classes[sem_class]

	def get_semantic_flag_group_by_name(self, sem_group):
		"""
		``get_semantic_flag_group_by_name`` gets the semantic flag group index by name.

		:param int sem_group: semantic flag group
		:return: semantic flag group index
		:rtype: str
		"""
		return self._semantic_flag_groups[sem_group]

	def get_flag_role(self, flag, sem_class = None):
		"""
		``get_flag_role`` gets the role of a given flag.

		:param int flag: flag
		:param int sem_class: optional semantic flag class
		:return: flag role
		:rtype: FlagRole
		"""
		return self.perform_get_flag_role(flag, sem_class)

	def get_flag_write_low_level_il(self, op, size, write_type, flag, operands, il):
		"""
		:param LowLevelILOperation op:
		:param int size:
		:param str write_type:
		:param operands: a list of either items that are either string register names or constant \
		:type operands: list(str) or list(int)
		integer values
		:param LowLevelILFunction il:
		:rtype: LowLevelILExpr
		"""
		return self.perform_get_flag_write_low_level_il(op, size, write_type, flag, operands, il)

	def get_default_flag_write_low_level_il(self, op, size, role, operands, il):
		"""
		:param LowLevelILOperation op:
		:param int size:
		:param FlagRole role:
		:param operands: a list of either items that are either string register names or constant \
		:type operands: list(str) or list(int)
		integer values
		:param LowLevelILFunction il:
		:rtype: LowLevelILExpr index
		"""
		operand_list = (core.BNRegisterOrConstant * len(operands))()
		for i in range(len(operands)):
			if isinstance(operands[i], str):
				operand_list[i].constant = False
				operand_list[i].reg = self.regs[operands[i]].index
			elif isinstance(operands[i], lowlevelil.ILRegister):
				operand_list[i].constant = False
				operand_list[i].reg = operands[i].index
			else:
				operand_list[i].constant = True
				operand_list[i].value = operands[i]
		return lowlevelil.LowLevelILExpr(core.BNGetDefaultArchitectureFlagWriteLowLevelIL(self.handle, op, size,
			role, operand_list, len(operand_list), il.handle))

	def get_flag_condition_low_level_il(self, cond, sem_class, il):
		"""
		:param LowLevelILFlagCondition cond: Flag condition to be computed
		:param str sem_class: Semantic class to be used (None for default semantics)
		:param LowLevelILFunction il: LowLevelILFunction object to append LowLevelILExpr objects to
		:rtype: LowLevelILExpr
		"""
		return self.perform_get_flag_condition_low_level_il(cond, sem_class, il)

	def get_default_flag_condition_low_level_il(self, cond, sem_class, il):
		"""
		:param LowLevelILFlagCondition cond:
		:param LowLevelILFunction il:
		:param str sem_class:
		:rtype: LowLevelILExpr
		"""
		class_index = self.get_semantic_flag_class_index(sem_class)
		return lowlevelil.LowLevelILExpr(core.BNGetDefaultArchitectureFlagConditionLowLevelIL(self.handle, cond, class_index, il.handle))

	def get_semantic_flag_group_low_level_il(self, sem_group, il):
		"""
		:param str sem_group:
		:param LowLevelILFunction il:
		:rtype: LowLevelILExpr
		"""
		return self.perform_get_semantic_flag_group_low_level_il(sem_group, il)

	def get_flags_required_for_flag_condition(self, cond, sem_class = None):
		return self.perform_get_flags_required_for_flag_condition(cond, sem_class)

	def get_modified_regs_on_write(self, reg):
		"""
		``get_modified_regs_on_write`` returns a list of register names that are modified when ``reg`` is written.

		:param str reg: string register name
		:return: list of register names
		:rtype: list(str)
		"""
		reg = core.BNGetArchitectureRegisterByName(self.handle, str(reg))
		count = ctypes.c_ulonglong()
		regs = core.BNGetModifiedArchitectureRegistersOnWrite(self.handle, reg, count)
		result = []
		for i in range(0, count.value):
			result.append(core.BNGetArchitectureRegisterName(self.handle, regs[i]))
		core.BNFreeRegisterList(regs)
		return result

	def assemble(self, code, addr=0):
		"""
		``assemble`` converts the string of assembly instructions ``code`` loaded at virtual address ``addr`` to the
		byte representation of those instructions.

		.. note:: Architecture subclasses should implement this method.

		Architecture plugins can override this method to provide assembler functionality. This can be done by
		simply shelling out to an assembler like yasm or llvm-mc, since this method isn't performance sensitive.

		.. note:: It is important that the assembler used accepts a syntax identical to the one emitted by the \
		disassembler. This will prevent confusing the user.

		If there is an error in the input assembly, this function should raise a ValueError (with a reasonable error message).

		:param str code: string representation of the instructions to be assembled
		:param int addr: virtual address that the instructions will be loaded at
		:return: the bytes for the assembled instructions
		:rtype: Python3 - a 'bytes' object; Python2 - a 'bytes' object
		:Example:

			>>> arch.assemble("je 10")
			b'\\x0f\\x84\\x04\\x00\\x00\\x00'
			>>>
		"""
		return self.perform_assemble(code, addr)

	def is_never_branch_patch_available(self, data, addr):
		"""
		``is_never_branch_patch_available`` determines if the instruction ``data`` at ``addr`` can be made to **never branch**.

		.. note:: Architecture subclasses should implement this method.

		:param str data: bytes for the instruction to be checked
		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		:Example:

			>>> arch.is_never_branch_patch_available(arch.assemble("je 10"), 0)
			True
			>>> arch.is_never_branch_patch_available(arch.assemble("nop"), 0)
			False
			>>>
		"""
		return self.perform_is_never_branch_patch_available(data, addr)

	def is_always_branch_patch_available(self, data, addr):
		"""
		``is_always_branch_patch_available`` determines if the instruction ``data`` at ``addr`` can be made to
		**always branch**.

		.. note:: Architecture subclasses should implement this method.

		:param str data: bytes for the instruction to be checked
		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		:Example:

			>>> arch.is_always_branch_patch_available(arch.assemble("je 10"), 0)
			True
			>>> arch.is_always_branch_patch_available(arch.assemble("nop"), 0)
			False
			>>>
		"""
		return self.perform_is_always_branch_patch_available(data, addr)

	def is_invert_branch_patch_available(self, data, addr):
		"""
		``is_always_branch_patch_available`` determines if the instruction ``data`` at ``addr`` can be inverted.

		.. note:: Architecture subclasses should implement this method.

		:param str data: bytes for the instruction to be checked
		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		:Example:

			>>> arch.is_invert_branch_patch_available(arch.assemble("je 10"), 0)
			True
			>>> arch.is_invert_branch_patch_available(arch.assemble("nop"), 0)
			False
			>>>
		"""
		return self.perform_is_invert_branch_patch_available(data, addr)

	def is_skip_and_return_zero_patch_available(self, data, addr):
		"""
		``is_skip_and_return_zero_patch_available`` determines if the instruction ``data`` at ``addr`` is a *call-like*
		instruction that can be made into an instruction *returns zero*.

		.. note:: Architecture subclasses should implement this method.

		:param str data: bytes for the instruction to be checked
		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		:Example:

			>>> arch.is_skip_and_return_zero_patch_available(arch.assemble("call 0"), 0)
			True
			>>> arch.is_skip_and_return_zero_patch_available(arch.assemble("call eax"), 0)
			True
			>>> arch.is_skip_and_return_zero_patch_available(arch.assemble("jmp eax"), 0)
			False
			>>>
		"""
		return self.perform_is_skip_and_return_zero_patch_available(data, addr)

	def is_skip_and_return_value_patch_available(self, data, addr):
		"""
		``is_skip_and_return_value_patch_available`` determines if the instruction ``data`` at ``addr`` is a *call-like*
		instruction that can be made into an instruction *returns a value*.

		.. note:: Architecture subclasses should implement this method.

		:param str data: bytes for the instruction to be checked
		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		:Example:

			>>> arch.is_skip_and_return_value_patch_available(arch.assemble("call 0"), 0)
			True
			>>> arch.is_skip_and_return_value_patch_available(arch.assemble("jmp eax"), 0)
			False
			>>>
		"""
		return self.perform_is_skip_and_return_value_patch_available(data, addr)

	def convert_to_nop(self, data, addr):
		"""
		``convert_to_nop`` reads the instruction(s) in ``data`` at virtual address ``addr`` and returns a string of nop
		instructions of the same length as data.

		.. note:: Architecture subclasses should implement this method.

		:param str data: bytes for the instruction to be converted
		:param int addr: the virtual address of the instruction to be patched
		:return: string containing len(data) worth of no-operation instructions
		:rtype: str
		:Example:

			>>> arch.convert_to_nop(b"\\x00\\x00", 0)
			b'\\x90\\x90'
			>>>
		"""
		return self.perform_convert_to_nop(data, addr)

	def always_branch(self, data, addr):
		"""
		``always_branch`` reads the instruction(s) in ``data`` at virtual address ``addr`` and returns a string of bytes
		of the same length which always branches.

		.. note:: Architecture subclasses should implement this method.

		:param str data: bytes for the instruction to be converted
		:param int addr: the virtual address of the instruction to be patched
		:return: string containing len(data) which always branches to the same location as the provided instruction
		:rtype: str
		:Example:

			>>> bytes = arch.always_branch(arch.assemble("je 10"), 0)
			>>> arch.get_instruction_text(bytes, 0)
			(['nop', '     '], 1)
			>>> arch.get_instruction_text(bytes[1:], 0)
			(['jmp', '     ', '0x9'], 5)
			>>>
		"""
		return self.perform_always_branch(data, addr)

	def invert_branch(self, data, addr):
		"""
		``invert_branch`` reads the instruction(s) in ``data`` at virtual address ``addr`` and returns a string of bytes
		of the same length which inverts the branch of provided instruction.

		.. note:: Architecture subclasses should implement this method.

		:param str data: bytes for the instruction to be converted
		:param int addr: the virtual address of the instruction to be patched
		:return: string containing len(data) which always branches to the same location as the provided instruction
		:rtype: str
		:Example:

			>>> arch.get_instruction_text(arch.invert_branch(arch.assemble("je 10"), 0), 0)
			(['jne', '     ', '0xa'], 6)
			>>> arch.get_instruction_text(arch.invert_branch(arch.assemble("jo 10"), 0), 0)
			(['jno', '     ', '0xa'], 6)
			>>> arch.get_instruction_text(arch.invert_branch(arch.assemble("jge 10"), 0), 0)
			(['jl', '      ', '0xa'], 6)
			>>>
		"""
		return self.perform_invert_branch(data, addr)

	def skip_and_return_value(self, data, addr, value):
		"""
		``skip_and_return_value`` reads the instruction(s) in ``data`` at virtual address ``addr`` and returns a string of
		bytes of the same length which doesn't call and instead *return a value*.

		.. note:: Architecture subclasses should implement this method.

		:param str data: bytes for the instruction to be converted
		:param int addr: the virtual address of the instruction to be patched
		:return: string containing len(data) which always branches to the same location as the provided instruction
		:rtype: str
		:Example:

			>>> arch.get_instruction_text(arch.skip_and_return_value(arch.assemble("call 10"), 0, 0), 0)
			(['mov', '     ', 'eax', ', ', '0x0'], 5)
			>>>
		"""
		return self.perform_skip_and_return_value(data, addr, value)

	def is_view_type_constant_defined(self, type_name, const_name):
		"""

		:param str type_name: the BinaryView type name of the constant to query
		:param str const_name: the constant name to query
		:rtype: None
		:Example:

			>>> ELF_RELOC_COPY = 5
			>>> arch.set_view_type_constant("ELF", "R_COPY", ELF_RELOC_COPY)
			>>> arch.is_view_type_constant_defined("ELF", "R_COPY")
			True
			>>> arch.is_view_type_constant_defined("ELF", "NOT_THERE")
			False
			>>>
		"""
		return core.BNIsBinaryViewTypeArchitectureConstantDefined(self.handle, type_name, const_name)

	def get_view_type_constant(self, type_name, const_name, default_value=0):
		"""
		``get_view_type_constant`` retrieves the view type constant for the given type_name and const_name.

		:param str type_name: the BinaryView type name of the constant to be retrieved
		:param str const_name: the constant name to retrieved
		:param int value: optional default value if the type_name is not present. default value is zero.
		:return: The BinaryView type constant or the default_value if not found
		:rtype: int
		:Example:

			>>> ELF_RELOC_COPY = 5
			>>> arch.set_view_type_constant("ELF", "R_COPY", ELF_RELOC_COPY)
			>>> arch.get_view_type_constant("ELF", "R_COPY")
			5
			>>> arch.get_view_type_constant("ELF", "NOT_HERE", 100)
			100
		"""
		return core.BNGetBinaryViewTypeArchitectureConstant(self.handle, type_name, const_name, default_value)

	def set_view_type_constant(self, type_name, const_name, value):
		"""
		``set_view_type_constant`` creates a new binaryview type constant.

		:param str type_name: the BinaryView type name of the constant to be registered
		:param str const_name: the constant name to register
		:param int value: the value of the constant
		:rtype: None
		:Example:

			>>> ELF_RELOC_COPY = 5
			>>> arch.set_view_type_constant("ELF", "R_COPY", ELF_RELOC_COPY)
			>>>
		"""
		core.BNSetBinaryViewTypeArchitectureConstant(self.handle, type_name, const_name, value)

	def register_calling_convention(self, cc):
		"""
		``register_calling_convention`` registers a new calling convention for the Architecture.

		:param CallingConvention cc: CallingConvention object to be registered
		:rtype: None
		"""
		core.BNRegisterCallingConvention(self.handle, cc.handle)


_architecture_cache = {}
class CoreArchitecture(Architecture):
	def __init__(self, handle):
		super(CoreArchitecture, self).__init__()

		self.handle = core.handle_of_type(handle, core.BNArchitecture)
		self.__dict__["name"] = core.BNGetArchitectureName(self.handle)
		self.__dict__["endianness"] = Endianness(core.BNGetArchitectureEndianness(self.handle))
		self.__dict__["address_size"] = core.BNGetArchitectureAddressSize(self.handle)
		self.__dict__["default_int_size"] = core.BNGetArchitectureDefaultIntegerSize(self.handle)
		self.__dict__["instr_alignment"] = core.BNGetArchitectureInstructionAlignment(self.handle)
		self.__dict__["max_instr_length"] = core.BNGetArchitectureMaxInstructionLength(self.handle)
		self.__dict__["opcode_display_length"] = core.BNGetArchitectureOpcodeDisplayLength(self.handle)
		self.__dict__["stack_pointer"] = core.BNGetArchitectureRegisterName(self.handle,
			core.BNGetArchitectureStackPointerRegister(self.handle))

		link_reg = core.BNGetArchitectureLinkRegister(self.handle)
		if link_reg == 0xffffffff:
			self.__dict__["link_reg"] = None
		else:
			self.__dict__["link_reg"] = core.BNGetArchitectureRegisterName(self.handle, link_reg)

		count = ctypes.c_ulonglong()
		regs = core.BNGetAllArchitectureRegisters(self.handle, count)
		self._all_regs = {}
		self._regs_by_index = {}
		self._full_width_regs = {}
		self.__dict__["regs"] = {}
		for i in range(0, count.value):
			name = core.BNGetArchitectureRegisterName(self.handle, regs[i])
			info = core.BNGetArchitectureRegisterInfo(self.handle, regs[i])
			full_width_reg = core.BNGetArchitectureRegisterName(self.handle, info.fullWidthRegister)
			self.regs[name] = binaryninja.function.RegisterInfo(full_width_reg, info.size, info.offset,
				ImplicitRegisterExtend(info.extend), regs[i])
			self._all_regs[name] = regs[i]
			self._regs_by_index[regs[i]] = name
		for i in range(0, count.value):
			info = core.BNGetArchitectureRegisterInfo(self.handle, regs[i])
			full_width_reg = core.BNGetArchitectureRegisterName(self.handle, info.fullWidthRegister)
			if full_width_reg not in self._full_width_regs:
				self._full_width_regs[full_width_reg] = self._all_regs[full_width_reg]
		core.BNFreeRegisterList(regs)

		count = ctypes.c_ulonglong()
		flags = core.BNGetAllArchitectureFlags(self.handle, count)
		self._flags = {}
		self._flags_by_index = {}
		self.__dict__["flags"] = []
		for i in range(0, count.value):
			name = core.BNGetArchitectureFlagName(self.handle, flags[i])
			self._flags[name] = flags[i]
			self._flags_by_index[flags[i]] = name
			self.flags.append(name)
		core.BNFreeRegisterList(flags)

		count = ctypes.c_ulonglong()
		write_types = core.BNGetAllArchitectureFlagWriteTypes(self.handle, count)
		self._flag_write_types = {}
		self._flag_write_types_by_index = {}
		self.__dict__["flag_write_types"] = []
		for i in range(0, count.value):
			name = core.BNGetArchitectureFlagWriteTypeName(self.handle, write_types[i])
			self._flag_write_types[name] = write_types[i]
			self._flag_write_types_by_index[write_types[i]] = name
			self.flag_write_types.append(name)
		core.BNFreeRegisterList(write_types)

		count = ctypes.c_ulonglong()
		sem_classes = core.BNGetAllArchitectureSemanticFlagClasses(self.handle, count)
		self._semantic_flag_classes = {}
		self._semantic_flag_classes_by_index = {}
		self.__dict__["semantic_flag_classes"] = []
		for i in range(0, count.value):
			name = core.BNGetArchitectureSemanticFlagClassName(self.handle, sem_classes[i])
			self._semantic_flag_classes[name] = sem_classes[i]
			self._semantic_flag_classes_by_index[sem_classes[i]] = name
			self.semantic_flag_classes.append(name)
		core.BNFreeRegisterList(sem_classes)

		count = ctypes.c_ulonglong()
		sem_groups = core.BNGetAllArchitectureSemanticFlagGroups(self.handle, count)
		self._semantic_flag_groups = {}
		self._semantic_flag_groups_by_index = {}
		self.__dict__["semantic_flag_groups"] = []
		for i in range(0, count.value):
			name = core.BNGetArchitectureSemanticFlagGroupName(self.handle, sem_groups[i])
			self._semantic_flag_groups[name] = sem_groups[i]
			self._semantic_flag_groups_by_index[sem_groups[i]] = name
			self.semantic_flag_groups.append(name)
		core.BNFreeRegisterList(sem_groups)

		self._flag_roles = {}
		self.__dict__["flag_roles"] = {}
		for flag in self.__dict__["flags"]:
			role = FlagRole(core.BNGetArchitectureFlagRole(self.handle, self._flags[flag], 0))
			self.__dict__["flag_roles"][flag] = role
			self._flag_roles[self._flags[flag]] = role

		self.__dict__["flags_required_for_flag_condition"] = {}
		for cond in LowLevelILFlagCondition:
			count = ctypes.c_ulonglong()
			flags = core.BNGetArchitectureFlagsRequiredForFlagCondition(self.handle, cond, 0, count)
			flag_names = []
			for i in range(0, count.value):
				flag_names.append(self._flags_by_index[flags[i]])
			core.BNFreeRegisterList(flags)
			self.__dict__["flags_required_for_flag_condition"][cond] = flag_names

		self._flags_required_by_semantic_flag_group = {}
		self.__dict__["flags_required_for_semantic_flag_group"] = {}
		for group in self.semantic_flag_groups:
			count = ctypes.c_ulonglong()
			flags = core.BNGetArchitectureFlagsRequiredForSemanticFlagGroup(self.handle,
				self._semantic_flag_groups[group], count)
			flag_indexes = []
			flag_names = []
			for i in range(0, count.value):
				flag_indexes.append(flags[i])
				flag_names.append(self._flags_by_index[flags[i]])
			core.BNFreeRegisterList(flags)
			self._flags_required_by_semantic_flag_group[self._semantic_flag_groups[group]] = flag_indexes
			self.__dict__["flags_required_for_semantic_flag_group"][cond] = flag_names

		self._flag_conditions_for_semantic_flag_group = {}
		self.__dict__["flag_conditions_for_semantic_flag_group"] = {}
		for group in self.semantic_flag_groups:
			count = ctypes.c_ulonglong()
			conditions = core.BNGetArchitectureFlagConditionsForSemanticFlagGroup(self.handle,
				self._semantic_flag_groups[group], count)
			class_index_cond = {}
			class_cond = {}
			for i in range(0, count.value):
				class_index_cond[conditions[i].semanticClass] = conditions[i].condition
				if conditions[i].semanticClass == 0:
					class_cond[None] = conditions[i].condition
				elif conditions[i].semanticClass in self._semantic_flag_classes_by_index:
					class_cond[self._semantic_flag_classes_by_index[conditions[i].semanticClass]] = conditions[i].condition
			core.BNFreeFlagConditionsForSemanticFlagGroup(conditions)
			self._flag_conditions_for_semantic_flag_group[self._semantic_flag_groups[group]] = class_index_cond
			self.__dict__["flag_conditions_for_semantic_flag_group"][group] = class_cond

		self._flags_written_by_flag_write_type = {}
		self.__dict__["flags_written_by_flag_write_type"] = {}
		for write_type in self.flag_write_types:
			count = ctypes.c_ulonglong()
			flags = core.BNGetArchitectureFlagsWrittenByFlagWriteType(self.handle,
				self._flag_write_types[write_type], count)
			flag_indexes = []
			flag_names = []
			for i in range(0, count.value):
				flag_indexes.append(flags[i])
				flag_names.append(self._flags_by_index[flags[i]])
			core.BNFreeRegisterList(flags)
			self._flags_written_by_flag_write_type[self._flag_write_types[write_type]] = flag_indexes
			self.__dict__["flags_written_by_flag_write_type"][write_type] = flag_names

		self._semantic_class_for_flag_write_type = {}
		self.__dict__["semantic_class_for_flag_write_type"] = {}
		for write_type in self.flag_write_types:
			sem_class = core.BNGetArchitectureSemanticClassForFlagWriteType(self.handle,
				self._flag_write_types[write_type])
			if sem_class == 0:
				sem_class_name = None
			else:
				sem_class_name = self._semantic_flag_classes_by_index[sem_class]
			self._semantic_class_for_flag_write_type[self._flag_write_types[write_type]] = sem_class
			self.__dict__["semantic_class_for_flag_write_type"][write_type] = sem_class_name

		count = ctypes.c_ulonglong()
		regs = core.BNGetArchitectureGlobalRegisters(self.handle, count)
		self.__dict__["global_regs"] = []
		for i in range(0, count.value):
			self.global_regs.append(core.BNGetArchitectureRegisterName(self.handle, regs[i]))
		core.BNFreeRegisterList(regs)

		count = ctypes.c_ulonglong()
		regs = core.BNGetArchitectureSystemRegisters(self.handle, count)
		self.__dict__["system_regs"] = []
		for i in range(0, count.value):
			self.system_regs.append(core.BNGetArchitectureRegisterName(self.handle, regs[i]))
		core.BNFreeRegisterList(regs)

		count = ctypes.c_ulonglong()
		regs = core.BNGetAllArchitectureRegisterStacks(self.handle, count)
		self._all_reg_stacks = {}
		self._reg_stacks_by_index = {}
		self.__dict__["reg_stacks"] = {}
		for i in range(0, count.value):
			name = core.BNGetArchitectureRegisterStackName(self.handle, regs[i])
			info = core.BNGetArchitectureRegisterStackInfo(self.handle, regs[i])
			storage = []
			for j in range(0, info.storageCount):
				storage.append(core.BNGetArchitectureRegisterName(self.handle, info.firstStorageReg + j))
			top_rel = []
			for j in range(0, info.topRelativeCount):
				top_rel.append(core.BNGetArchitectureRegisterName(self.handle, info.firstTopRelativeReg + j))
			top = core.BNGetArchitectureRegisterName(self.handle, info.stackTopReg)
			self.reg_stacks[name] = binaryninja.function.RegisterStackInfo(storage, top_rel, top, regs[i])
			self._all_reg_stacks[name] = regs[i]
			self._reg_stacks_by_index[regs[i]] = name
		core.BNFreeRegisterList(regs)

		count = ctypes.c_ulonglong()
		intrinsics = core.BNGetAllArchitectureIntrinsics(self.handle, count)
		self._intrinsics = {}
		self._intrinsics_by_index = {}
		self.__dict__["intrinsics"] = {}
		for i in range(0, count.value):
			name = core.BNGetArchitectureIntrinsicName(self.handle, intrinsics[i])
			input_count = ctypes.c_ulonglong()
			inputs = core.BNGetArchitectureIntrinsicInputs(self.handle, intrinsics[i], input_count)
			input_list = []
			for j in range(0, input_count.value):
				input_name = inputs[j].name
				type_obj = types.Type(core.BNNewTypeReference(inputs[j].type), confidence = inputs[j].typeConfidence)
				input_list.append(binaryninja.function.IntrinsicInput(type_obj, input_name))
			core.BNFreeNameAndTypeList(inputs, input_count.value)
			output_count = ctypes.c_ulonglong()
			outputs = core.BNGetArchitectureIntrinsicOutputs(self.handle, intrinsics[i], output_count)
			output_list = []
			for j in range(0, output_count.value):
				output_list.append(types.Type(core.BNNewTypeReference(outputs[j].type), confidence = outputs[j].confidence))
			core.BNFreeOutputTypeList(outputs, output_count.value)
			self.intrinsics[name] = binaryninja.function.IntrinsicInfo(input_list, output_list)
			self._intrinsics[name] = intrinsics[i]
			self._intrinsics_by_index[intrinsics[i]] = (name, self.intrinsics[name])
		core.BNFreeRegisterList(intrinsics)
		if type(self) is CoreArchitecture:
			global _architecture_cache
			_architecture_cache[ctypes.addressof(handle.contents)] = self

	@classmethod
	def _from_cache(cls, handle):
		global _architecture_cache
		return _architecture_cache.get(ctypes.addressof(handle.contents)) or cls(handle)

	def get_associated_arch_by_address(self, addr):
		new_addr = ctypes.c_ulonglong()
		new_addr.value = addr
		result = core.BNGetAssociatedArchitectureByAddress(self.handle, new_addr)
		return CoreArchitecture._from_cache(handle = result), new_addr.value

	def get_instruction_info(self, data, addr):
		"""
		``get_instruction_info`` returns an InstructionInfo object for the instruction at the given virtual address
		``addr`` with data ``data``.

		.. note:: The instruction info object should always set the InstructionInfo.length to the instruction length, \
		and the branches of the proper types should be added if the instruction is a branch.

		:param str data: max_instruction_length bytes from the binary at virtual address ``addr``
		:param int addr: virtual address of bytes in ``data``
		:return: the InstructionInfo for the current instruction
		:rtype: InstructionInfo
		"""
		info = core.BNInstructionInfo()
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		if not core.BNGetInstructionInfo(self.handle, buf, addr, len(data), info):
			return None
		result = binaryninja.function.InstructionInfo()
		result.length = info.length
		result.arch_transition_by_target_addr = info.archTransitionByTargetAddr
		result.branch_delay = info.branchDelay
		for i in range(0, info.branchCount):
			target = info.branchTarget[i]
			if info.branchArch[i]:
				arch = CoreArchitecture._from_cache(info.branchArch[i])
			else:
				arch = None
			result.add_branch(BranchType(info.branchType[i]), target, arch)
		return result

	def get_instruction_text(self, data, addr):
		"""
		``get_instruction_text`` returns a list of InstructionTextToken objects for the instruction at the given virtual
		address ``addr`` with data ``data``.

		:param str data: max_instruction_length bytes from the binary at virtual address ``addr``
		:param int addr: virtual address of bytes in ``data``
		:return: an InstructionTextToken list for the current instruction
		:rtype: list(InstructionTextToken)
		"""
		if not isinstance(data, bytes):
			if isinstance(data, str):
				data=data.encode()
			else:
				raise TypeError("Must be bytes or str")
		count = ctypes.c_ulonglong()
		length = ctypes.c_ulonglong()
		length.value = len(data)
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		tokens = ctypes.POINTER(core.BNInstructionTextToken)()
		if not core.BNGetInstructionText(self.handle, buf, addr, length, tokens, count):
			return None, 0
		result = binaryninja.function.InstructionTextToken.get_instruction_lines(tokens, count.value)
		core.BNFreeInstructionText(tokens, count.value)
		return result, length.value

	def get_instruction_low_level_il(self, data, addr, il):
		"""
		``get_instruction_low_level_il`` appends LowLevelILExpr objects to ``il`` for the instruction at the given
		virtual address ``addr`` with data ``data``.

		This is used to analyze arbitrary data at an address, if you are working with an existing binary, you likely
		want to be using :func:`Function.get_low_level_il_at`.

		:param str data: max_instruction_length bytes from the binary at virtual address ``addr``
		:param int addr: virtual address of bytes in ``data``
		:param LowLevelILFunction il: The function the current instruction belongs to
		:return: the length of the current instruction
		:rtype: int
		"""
		length = ctypes.c_ulonglong()
		length.value = len(data)
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		core.BNGetInstructionLowLevelIL(self.handle, buf, addr, length, il.handle)
		return length.value

	def get_flag_write_low_level_il(self, op, size, write_type, flag, operands, il):
		"""
		:param LowLevelILOperation op:
		:param int size:
		:param str write_type:
		:param operands: a list of either items that are either string register names or constant \
		:type operands: list(str) or list(int)
		integer values
		:param LowLevelILFunction il:
		:rtype: LowLevelILExpr
		"""
		flag = self.get_flag_index(flag)
		operand_list = (core.BNRegisterOrConstant * len(operands))()
		for i in range(len(operands)):
			if isinstance(operands[i], str):
				operand_list[i].constant = False
				operand_list[i].reg = self.regs[operands[i]].index
			elif isinstance(operands[i], lowlevelil.ILRegister):
				operand_list[i].constant = False
				operand_list[i].reg = operands[i].index
			else:
				operand_list[i].constant = True
				operand_list[i].value = operands[i]
		return lowlevelil.LowLevelILExpr(core.BNGetArchitectureFlagWriteLowLevelIL(self.handle, op, size,
		        self._flag_write_types[write_type], flag, operand_list, len(operand_list), il.handle))

	def get_flag_condition_low_level_il(self, cond, sem_class, il):
		"""
		:param LowLevelILFlagCondition cond: Flag condition to be computed
		:param str sem_class: Semantic class to be used (None for default semantics)
		:param LowLevelILFunction il: LowLevelILFunction object to append LowLevelILExpr objects to
		:rtype: LowLevelILExpr
		"""
		class_index = self.get_semantic_flag_class_index(sem_class)
		return lowlevelil.LowLevelILExpr(core.BNGetArchitectureFlagConditionLowLevelIL(self.handle, cond,
			class_index, il.handle))

	def get_semantic_flag_group_low_level_il(self, sem_group, il):
		"""
		:param str sem_group:
		:param LowLevelILFunction il:
		:rtype: LowLevelILExpr
		"""
		group_index = self.get_semantic_flag_group_index(sem_group)
		return lowlevelil.LowLevelILExpr(core.BNGetArchitectureSemanticFlagGroupLowLevelIL(self.handle, group_index, il.handle))

	def assemble(self, code, addr=0):
		"""
		``assemble`` converts the string of assembly instructions ``code`` loaded at virtual address ``addr`` to the
		byte representation of those instructions.

		:param str code: string representation of the instructions to be assembled
		:param int addr: virtual address that the instructions will be loaded at
		:return: the bytes for the assembled instructions
		:rtype: Python3 - a 'bytes' object; Python2 - a 'bytes' object
		:Example:

			>>> arch.assemble("je 10")
			b'\\x0f\\x84\\x04\\x00\\x00\\x00'
			>>>
		"""
		result = databuffer.DataBuffer()
		errors = ctypes.c_char_p()
		if not core.BNAssemble(self.handle, code, addr, result.handle, errors):
			error_str = errors.value
			core.BNFreeString(ctypes.cast(errors, ctypes.POINTER(ctypes.c_byte)))
			raise ValueError("Could not assemble: %s" % error_str)
		if isinstance(str(result), bytes):
			return str(result)
		else:
			return bytes(result)

	def is_never_branch_patch_available(self, data, addr):
		"""
		``is_never_branch_patch_available`` determines if the instruction ``data`` at ``addr`` can be made to **never branch**.

		:param str data: bytes for the instruction to be checked
		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		:Example:

			>>> arch.is_never_branch_patch_available(arch.assemble("je 10"), 0)
			True
			>>> arch.is_never_branch_patch_available(arch.assemble("nop"), 0)
			False
			>>>
		"""
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		return core.BNIsArchitectureNeverBranchPatchAvailable(self.handle, buf, addr, len(data))

	def is_always_branch_patch_available(self, data, addr):
		"""
		``is_always_branch_patch_available`` determines if the instruction ``data`` at ``addr`` can be made to
		**always branch**.

		:param str data: bytes for the instruction to be checked
		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		:Example:

			>>> arch.is_always_branch_patch_available(arch.assemble("je 10"), 0)
			True
			>>> arch.is_always_branch_patch_available(arch.assemble("nop"), 0)
			False
			>>>
		"""
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		return core.BNIsArchitectureAlwaysBranchPatchAvailable(self.handle, buf, addr, len(data))

	def is_invert_branch_patch_available(self, data, addr):
		"""
		``is_always_branch_patch_available`` determines if the instruction ``data`` at ``addr`` can be inverted.

		:param str data: bytes for the instruction to be checked
		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		:Example:

			>>> arch.is_invert_branch_patch_available(arch.assemble("je 10"), 0)
			True
			>>> arch.is_invert_branch_patch_available(arch.assemble("nop"), 0)
			False
			>>>
		"""
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		return core.BNIsArchitectureInvertBranchPatchAvailable(self.handle, buf, addr, len(data))

	def is_skip_and_return_zero_patch_available(self, data, addr):
		"""
		``is_skip_and_return_zero_patch_available`` determines if the instruction ``data`` at ``addr`` is a *call-like*
		instruction that can be made into an instruction *returns zero*.

		:param str data: bytes for the instruction to be checked
		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		:Example:

			>>> arch.is_skip_and_return_zero_patch_available(arch.assemble("call 0"), 0)
			True
			>>> arch.is_skip_and_return_zero_patch_available(arch.assemble("call eax"), 0)
			True
			>>> arch.is_skip_and_return_zero_patch_available(arch.assemble("jmp eax"), 0)
			False
			>>>
		"""
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		return core.BNIsArchitectureSkipAndReturnZeroPatchAvailable(self.handle, buf, addr, len(data))

	def is_skip_and_return_value_patch_available(self, data, addr):
		"""
		``is_skip_and_return_value_patch_available`` determines if the instruction ``data`` at ``addr`` is a *call-like*
		instruction that can be made into an instruction *returns a value*.

		:param str data: bytes for the instruction to be checked
		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		:Example:

			>>> arch.is_skip_and_return_value_patch_available(arch.assemble("call 0"), 0)
			True
			>>> arch.is_skip_and_return_value_patch_available(arch.assemble("jmp eax"), 0)
			False
			>>>
		"""
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		return core.BNIsArchitectureSkipAndReturnValuePatchAvailable(self.handle, buf, addr, len(data))

	def convert_to_nop(self, data, addr):
		"""
		``convert_to_nop`` reads the instruction(s) in ``data`` at virtual address ``addr`` and returns a string of nop
		instructions of the same length as data.

		:param str data: bytes for the instruction to be converted
		:param int addr: the virtual address of the instruction to be patched
		:return: string containing len(data) worth of no-operation instructions
		:rtype: str
		:Example:

			>>> arch.convert_to_nop(b"\\x00\\x00", 0)
			b'\\x90\\x90'
			>>>
		"""
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		if not core.BNArchitectureConvertToNop(self.handle, buf, addr, len(data)):
			return None
		result = ctypes.create_string_buffer(len(data))
		ctypes.memmove(result, buf, len(data))
		return result.raw

	def always_branch(self, data, addr):
		"""
		``always_branch`` reads the instruction(s) in ``data`` at virtual address ``addr`` and returns a string of bytes
		of the same length which always branches.

		:param str data: bytes for the instruction to be converted
		:param int addr: the virtual address of the instruction to be patched
		:return: string containing len(data) which always branches to the same location as the provided instruction
		:rtype: str
		:Example:

			>>> bytes = arch.always_branch(arch.assemble("je 10"), 0)
			>>> arch.get_instruction_text(bytes, 0)
			(['nop', '     '], 1)
			>>> arch.get_instruction_text(bytes[1:], 0)
			(['jmp', '     ', '0x9'], 5)
			>>>
		"""
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		if not core.BNArchitectureAlwaysBranch(self.handle, buf, addr, len(data)):
			return None
		result = ctypes.create_string_buffer(len(data))
		ctypes.memmove(result, buf, len(data))
		return result.raw

	def invert_branch(self, data, addr):
		"""
		``invert_branch`` reads the instruction(s) in ``data`` at virtual address ``addr`` and returns a string of bytes
		of the same length which inverts the branch of provided instruction.

		:param str data: bytes for the instruction to be converted
		:param int addr: the virtual address of the instruction to be patched
		:return: string containing len(data) which always branches to the same location as the provided instruction
		:rtype: str
		:Example:

			>>> arch.get_instruction_text(arch.invert_branch(arch.assemble("je 10"), 0), 0)
			(['jne', '     ', '0xa'], 6)
			>>> arch.get_instruction_text(arch.invert_branch(arch.assemble("jo 10"), 0), 0)
			(['jno', '     ', '0xa'], 6)
			>>> arch.get_instruction_text(arch.invert_branch(arch.assemble("jge 10"), 0), 0)
			(['jl', '      ', '0xa'], 6)
			>>>
		"""
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		if not core.BNArchitectureInvertBranch(self.handle, buf, addr, len(data)):
			return None
		result = ctypes.create_string_buffer(len(data))
		ctypes.memmove(result, buf, len(data))
		return result.raw

	def skip_and_return_value(self, data, addr, value):
		"""
		``skip_and_return_value`` reads the instruction(s) in ``data`` at virtual address ``addr`` and returns a string of
		bytes of the same length which doesn't call and instead *return a value*.

		:param str data: bytes for the instruction to be converted
		:param int addr: the virtual address of the instruction to be patched
		:return: string containing len(data) which always branches to the same location as the provided instruction
		:rtype: str
		:Example:

			>>> arch.get_instruction_text(arch.skip_and_return_value(arch.assemble("call 10"), 0, 0), 0)
			(['mov', '     ', 'eax', ', ', '0x0'], 5)
			>>>
		"""
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		if not core.BNArchitectureSkipAndReturnValue(self.handle, buf, addr, len(data), value):
			return None
		result = ctypes.create_string_buffer(len(data))
		ctypes.memmove(result, buf, len(data))
		return result.raw

	def get_flag_role(self, flag, sem_class = None):
		"""
		``get_flag_role`` gets the role of a given flag.

		:param int flag: flag
		:param int sem_class: optional semantic flag class
		:return: flag role
		:rtype: FlagRole
		"""
		flag = self.get_flag_index(flag)
		sem_class = self.get_semantic_flag_class_index(sem_class)
		return FlagRole(core.BNGetArchitectureFlagRole(self.handle, flag, sem_class))

	def get_flags_required_for_flag_condition(self, cond, sem_class = None):
		sem_class = self.get_semantic_flag_class_index(sem_class)
		count = ctypes.c_ulonglong()
		flags = core.BNGetArchitectureFlagsRequiredForFlagCondition(self.handle, cond, sem_class, count)
		flag_names = []
		for i in range(0, count.value):
			flag_names.append(self._flags_by_index[flags[i]])
		core.BNFreeRegisterList(flags)
		return flag_names


class ArchitectureHook(CoreArchitecture):
	def __init__(self, base_arch):
		self._base_arch = base_arch
		super(ArchitectureHook, self).__init__(base_arch.handle)

		# To improve performance of simpler hooks, use null callback for functions that are not being overridden
		if self.get_associated_arch_by_address.__code__ == CoreArchitecture.get_associated_arch_by_address.__code__:
			self._cb.getAssociatedArchitectureByAddress = self._cb.getAssociatedArchitectureByAddress.__class__()
		if self.get_instruction_info.__code__ == CoreArchitecture.get_instruction_info.__code__:
			self._cb.getInstructionInfo = self._cb.getInstructionInfo.__class__()
		if self.get_instruction_text.__code__ == CoreArchitecture.get_instruction_text.__code__:
			self._cb.getInstructionText = self._cb.getInstructionText.__class__()
		if self.__class__.stack_pointer is None:
			self._cb.getStackPointerRegister = self._cb.getStackPointerRegister.__class__()
		if self.__class__.link_reg is None:
			self._cb.getLinkRegister = self._cb.getLinkRegister.__class__()
		if len(self.__class__.regs) == 0:
			self._cb.getRegisterInfo = self._cb.getRegisterInfo.__class__()
			self._cb.getRegisterName = self._cb.getRegisterName.__class__()
		if len(self.__class__.reg_stacks) == 0:
			self._cb.getRegisterStackName = self._cb.getRegisterStackName.__class__()
			self._cb.getRegisterStackInfo = self._cb.getRegisterStackInfo.__class__()
		if len(self.__class__.intrinsics) == 0:
			self._cb.getIntrinsicName = self._cb.getIntrinsicName.__class__()
			self._cb.getIntrinsicInputs = self._cb.getIntrinsicInputs.__class__()
			self._cb.freeNameAndTypeList = self._cb.freeNameAndTypeList.__class__()
			self._cb.getIntrinsicOutputs = self._cb.getIntrinsicOutputs.__class__()
			self._cb.freeTypeList = self._cb.freeTypeList.__class__()

	def register(self):
		self.__class__._registered_cb = self._cb
		self.handle = core.BNRegisterArchitectureHook(self._base_arch.handle, self._cb)
		core.BNFinalizeArchitectureHook(self._base_arch.handle)

	@property
	def base_arch(self):
		""" """
		return self._base_arch

	@base_arch.setter
	def base_arch(self, value):
		self._base_arch = value


class ReferenceSource(object):
	def __init__(self, func, arch, addr):
		self._function = func
		self._arch = arch
		self._address = addr

	def __repr__(self):
		if self._arch:
			return "<ref: %s@%#x>" % (self._arch.name, self._address)
		else:
			return "<ref: %#x>" % self._address

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return (self.function, self.arch, self.address) == (other.address, other.function, other.arch)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __lt__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self.address < other.address

	def __gt__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self.address > other.address

	def __gt__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self.address >= other.address

	def __le__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self.address <= other.address

	def __hash__(self):
		hash((self._function, self._arch, self._address))

	@property
	def function(self):
		""" """
		return self._function

	@function.setter
	def function(self, value):
		self._function = value

	@property
	def arch(self):
		""" """
		return self._arch

	@arch.setter
	def arch(self, value):
		self._arch = value

	@property
	def address(self):
		""" """
		return self._address

	@address.setter
	def address(self, value):
		self._address = value
