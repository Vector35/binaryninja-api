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

import traceback
import ctypes
import abc

# Binary Ninja components
import _binaryninjacore as core
from enums import (Endianness, ImplicitRegisterExtend, BranchType,
	InstructionTextTokenType, LowLevelILFlagCondition, FlagRole)
import startup
import function
import lowlevelil
import callingconvention
import platform
import log
import databuffer
import types


class _ArchitectureMetaClass(type):
	@property
	def list(self):
		startup._init_plugins()
		count = ctypes.c_ulonglong()
		archs = core.BNGetArchitectureList(count)
		result = []
		for i in xrange(0, count.value):
			result.append(Architecture(archs[i]))
		core.BNFreeArchitectureList(archs)
		return result

	def __iter__(self):
		startup._init_plugins()
		count = ctypes.c_ulonglong()
		archs = core.BNGetArchitectureList(count)
		try:
			for i in xrange(0, count.value):
				yield Architecture(archs[i])
		finally:
			core.BNFreeArchitectureList(archs)

	def __getitem__(cls, name):
		startup._init_plugins()
		arch = core.BNGetArchitectureByName(name)
		if arch is None:
			raise KeyError("'%s' is not a valid architecture" % str(name))
		return Architecture(arch)

	def register(cls):
		startup._init_plugins()
		if cls.name is None:
			raise ValueError("architecture 'name' is not defined")
		arch = cls()
		cls._registered_cb = arch._cb
		arch.handle = core.BNRegisterArchitecture(cls.name, arch._cb)

	def __setattr__(self, name, value):
		try:
			type.__setattr__(self, name, value)
		except AttributeError:
			raise AttributeError("attribute '%s' is read only" % name)


class Architecture(object):
	"""
	``class Architecture`` is the parent class for all CPU architectures. Subclasses of Architecture implement assembly,
	disassembly, IL lifting, and patching.

	``class Architecture`` has a ``__metaclass__`` with the additional methods ``register``, and supports
	iteration::

		>>> #List the architectures
		>>> list(Architecture)
		[<arch: aarch64>, <arch: armv7>, <arch: armv7eb>, <arch: mipsel32>, <arch: mips32>, <arch: powerpc>,
		<arch: x86>, <arch: x86_64>]
		>>> #Register a new Architecture
		>>> class MyArch(Architecture):
		...  name = "MyArch"
		...
		>>> MyArch.register()
		>>> list(Architecture)
		[<arch: aarch64>, <arch: armv7>, <arch: armv7eb>, <arch: mipsel32>, <arch: mips32>, <arch: powerpc>,
		<arch: x86>, <arch: x86_64>, <arch: MyArch>]
		>>>

	For the purposes of this documentation the variable ``arch`` will be used in the following context ::

		>>> from binaryninja import *
		>>> arch = Architecture['x86']
	"""
	name = None
	endianness = Endianness.LittleEndian
	address_size = 8
	default_int_size = 4
	max_instr_length = 16
	opcode_display_length = 8
	regs = {}
	stack_pointer = None
	link_reg = None
	global_regs = []
	flags = []
	flag_write_types = []
	flag_roles = {}
	flags_required_for_flag_condition = {}
	flags_written_by_flag_write_type = {}
	__metaclass__ = _ArchitectureMetaClass
	next_address = 0

	def __init__(self, handle=None):
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNArchitecture)
			self.__dict__["name"] = core.BNGetArchitectureName(self.handle)
			self.__dict__["endianness"] = Endianness(core.BNGetArchitectureEndianness(self.handle))
			self.__dict__["address_size"] = core.BNGetArchitectureAddressSize(self.handle)
			self.__dict__["default_int_size"] = core.BNGetArchitectureDefaultIntegerSize(self.handle)
			self.__dict__["max_instr_length"] = core.BNGetArchitectureMaxInstructionLength(self.handle)
			self.__dict__["opcode_display_length"] = core.BNGetArchitectureOpcodeDisplayLength(self.handle)
			self.__dict__["stack_pointer"] = core.BNGetArchitectureRegisterName(self.handle,
				core.BNGetArchitectureStackPointerRegister(self.handle))
			self.__dict__["link_reg"] = core.BNGetArchitectureRegisterName(self.handle,
				core.BNGetArchitectureLinkRegister(self.handle))

			count = ctypes.c_ulonglong()
			regs = core.BNGetAllArchitectureRegisters(self.handle, count)
			self.__dict__["regs"] = {}
			for i in xrange(0, count.value):
				name = core.BNGetArchitectureRegisterName(self.handle, regs[i])
				info = core.BNGetArchitectureRegisterInfo(self.handle, regs[i])
				full_width_reg = core.BNGetArchitectureRegisterName(self.handle, info.fullWidthRegister)
				self.regs[name] = function.RegisterInfo(full_width_reg, info.size, info.offset,
					ImplicitRegisterExtend(info.extend), regs[i])
			core.BNFreeRegisterList(regs)

			count = ctypes.c_ulonglong()
			flags = core.BNGetAllArchitectureFlags(self.handle, count)
			self._flags = {}
			self._flags_by_index = {}
			self.__dict__["flags"] = []
			for i in xrange(0, count.value):
				name = core.BNGetArchitectureFlagName(self.handle, flags[i])
				self._flags[name] = flags[i]
				self._flags_by_index[flags[i]] = name
				self.flags.append(name)
			core.BNFreeRegisterList(flags)

			count = ctypes.c_ulonglong()
			types = core.BNGetAllArchitectureFlagWriteTypes(self.handle, count)
			self._flag_write_types = {}
			self._flag_write_types_by_index = {}
			self.__dict__["flag_write_types"] = []
			for i in xrange(0, count.value):
				name = core.BNGetArchitectureFlagWriteTypeName(self.handle, types[i])
				self._flag_write_types[name] = types[i]
				self._flag_write_types_by_index[types[i]] = name
				self.flag_write_types.append(name)
			core.BNFreeRegisterList(types)

			self._flag_roles = {}
			self.__dict__["flag_roles"] = {}
			for flag in self.__dict__["flags"]:
				role = FlagRole(core.BNGetArchitectureFlagRole(self.handle, self._flags[flag]))
				self.__dict__["flag_roles"][flag] = role
				self._flag_roles[self._flags[flag]] = role

			self._flags_required_for_flag_condition = {}
			self.__dict__["flags_required_for_flag_condition"] = {}
			for cond in LowLevelILFlagCondition:
				count = ctypes.c_ulonglong()
				flags = core.BNGetArchitectureFlagsRequiredForFlagCondition(self.handle, cond, count)
				flag_indexes = []
				flag_names = []
				for i in xrange(0, count.value):
					flag_indexes.append(flags[i])
					flag_names.append(self._flags_by_index[flags[i]])
				core.BNFreeRegisterList(flags)
				self._flags_required_for_flag_condition[cond] = flag_indexes
				self.__dict__["flags_required_for_flag_condition"][cond] = flag_names

			self._flags_written_by_flag_write_type = {}
			self.__dict__["flags_written_by_flag_write_type"] = {}
			for write_type in self.flag_write_types:
				count = ctypes.c_ulonglong()
				flags = core.BNGetArchitectureFlagsWrittenByFlagWriteType(self.handle,
					self._flag_write_types[write_type], count)
				flag_indexes = []
				flag_names = []
				for i in xrange(0, count.value):
					flag_indexes.append(flags[i])
					flag_names.append(self._flags_by_index[flags[i]])
				core.BNFreeRegisterList(flags)
				self._flags_written_by_flag_write_type[self._flag_write_types[write_type]] = flag_indexes
				self.__dict__["flags_written_by_flag_write_type"][write_type] = flag_names

			count = ctypes.c_ulonglong()
			regs = core.BNGetArchitectureGlobalRegisters(self.handle, count)
			self.__dict__["global_regs"] = []
			for i in xrange(0, count.value):
				self.global_regs.append(core.BNGetArchitectureRegisterName(self.handle, regs[i]))
			core.BNFreeRegisterList(regs)
		else:
			startup._init_plugins()

			if self.__class__.opcode_display_length > self.__class__.max_instr_length:
				self.__class__.opcode_display_length = self.__class__.max_instr_length

			self._cb = core.BNCustomArchitecture()
			self._cb.context = 0
			self._cb.init = self._cb.init.__class__(self._init)
			self._cb.getEndianness = self._cb.getEndianness.__class__(self._get_endianness)
			self._cb.getAddressSize = self._cb.getAddressSize.__class__(self._get_address_size)
			self._cb.getDefaultIntegerSize = self._cb.getDefaultIntegerSize.__class__(self._get_default_integer_size)
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
			self._cb.getFullWidthRegisters = self._cb.getFullWidthRegisters.__class__(self._get_full_width_registers)
			self._cb.getAllRegisters = self._cb.getAllRegisters.__class__(self._get_all_registers)
			self._cb.getAllFlags = self._cb.getAllRegisters.__class__(self._get_all_flags)
			self._cb.getAllFlagWriteTypes = self._cb.getAllRegisters.__class__(self._get_all_flag_write_types)
			self._cb.getFlagRole = self._cb.getFlagRole.__class__(self._get_flag_role)
			self._cb.getFlagsRequiredForFlagCondition = self._cb.getFlagsRequiredForFlagCondition.__class__(
				self._get_flags_required_for_flag_condition)
			self._cb.getFlagsWrittenByFlagWriteType = self._cb.getFlagsWrittenByFlagWriteType.__class__(
				self._get_flags_written_by_flag_write_type)
			self._cb.getFlagWriteLowLevelIL = self._cb.getFlagWriteLowLevelIL.__class__(
				self._get_flag_write_low_level_il)
			self._cb.getFlagConditionLowLevelIL = self._cb.getFlagConditionLowLevelIL.__class__(
				self._get_flag_condition_low_level_il)
			self._cb.freeRegisterList = self._cb.freeRegisterList.__class__(self._free_register_list)
			self._cb.getRegisterInfo = self._cb.getRegisterInfo.__class__(self._get_register_info)
			self._cb.getStackPointerRegister = self._cb.getStackPointerRegister.__class__(
				self._get_stack_pointer_register)
			self._cb.getLinkRegister = self._cb.getLinkRegister.__class__(self._get_link_register)
			self._cb.getGlobalRegisters = self._cb.getGlobalRegisters.__class__(self._get_global_registers)
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

			self._all_regs = {}
			self._full_width_regs = {}
			self._regs_by_index = {}
			self.__dict__["regs"] = self.__class__.regs
			reg_index = 0
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
			write_type_index = 0
			for write_type in self.__class__.flag_write_types:
				if write_type not in self._flag_write_types:
					self._flag_write_types[write_type] = write_type_index
					self._flag_write_types_by_index[write_type_index] = write_type
					write_type_index += 1

			self._flag_roles = {}
			self.__dict__["flag_roles"] = self.__class__.flag_roles
			for flag in self.__class__.flag_roles:
				role = self.__class__.flag_roles[flag]
				if isinstance(role, str):
					role = FlagRole[role]
				self._flag_roles[self._flags[flag]] = role

			self._flags_required_for_flag_condition = {}
			self.__dict__["flags_required_for_flag_condition"] = self.__class__.flags_required_for_flag_condition
			for cond in self.__class__.flags_required_for_flag_condition:
				flags = []
				for flag in self.__class__.flags_required_for_flag_condition[cond]:
					flags.append(self._flags[flag])
				self._flags_required_for_flag_condition[cond] = flags

			self._flags_written_by_flag_write_type = {}
			self.__dict__["flags_written_by_flag_write_type"] = self.__class__.flags_written_by_flag_write_type
			for write_type in self.__class__.flags_written_by_flag_write_type:
				flags = []
				for flag in self.__class__.flags_written_by_flag_write_type[write_type]:
					flags.append(self._flags[flag])
				self._flags_written_by_flag_write_type[self._flag_write_types[write_type]] = flags

			self.__dict__["global_regs"] = self.__class__.global_regs

			self._pending_reg_lists = {}
			self._pending_token_lists = {}

	def __eq__(self, value):
		if not isinstance(value, Architecture):
			return False
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(value.handle.contents)

	def __ne__(self, value):
		if not isinstance(value, Architecture):
			return True
		return ctypes.addressof(self.handle.contents) != ctypes.addressof(value.handle.contents)

	@property
	def full_width_regs(self):
		"""List of full width register strings (read-only)"""
		count = ctypes.c_ulonglong()
		regs = core.BNGetFullWidthArchitectureRegisters(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			result.append(core.BNGetArchitectureRegisterName(self.handle, regs[i]))
		core.BNFreeRegisterList(regs)
		return result

	@property
	def calling_conventions(self):
		"""Dict of CallingConvention objects (read-only)"""
		count = ctypes.c_ulonglong()
		cc = core.BNGetArchitectureCallingConventions(self.handle, count)
		result = {}
		for i in xrange(0, count.value):
			obj = callingconvention.CallingConvention(handle=core.BNNewCallingConventionReference(cc[i]))
			result[obj.name] = obj
		core.BNFreeCallingConventionList(cc, count)
		return result

	@property
	def standalone_platform(self):
		"""Architecture standalone platform (read-only)"""
		pl = core.BNGetArchitectureStandalonePlatform(self.handle)
		return platform.Platform(self, pl)

	def __setattr__(self, name, value):
		if ((name == "name") or (name == "endianness") or (name == "address_size") or
			(name == "default_int_size") or (name == "regs") or (name == "get_max_instruction_length")):
			raise AttributeError("attribute '%s' is read only" % name)
		else:
			try:
				object.__setattr__(self, name, value)
			except AttributeError:
				raise AttributeError("attribute '%s' is read only" % name)

	def __repr__(self):
		return "<arch: %s>" % self.name

	def _init(self, ctxt, handle):
		self.handle = handle

	def _get_endianness(self, ctxt):
		try:
			return self.__class__.endianness
		except:
			log.log_error(traceback.format_exc())
			return Endianness.LittleEndian

	def _get_address_size(self, ctxt):
		try:
			return self.__class__.address_size
		except:
			log.log_error(traceback.format_exc())
			return 8

	def _get_default_integer_size(self, ctxt):
		try:
			return self.__class__.default_int_size
		except:
			log.log_error(traceback.format_exc())
			return 4

	def _get_max_instruction_length(self, ctxt):
		try:
			return self.__class__.max_instr_length
		except:
			log.log_error(traceback.format_exc())
			return 16

	def _get_opcode_display_length(self, ctxt):
		try:
			return self.__class__.opcode_display_length
		except:
			log.log_error(traceback.format_exc())
			return 8

	def _get_associated_arch_by_address(self, ctxt, addr):
		try:
			result, new_addr = self.perform_get_associated_arch_by_address(addr[0])
			addr[0] = new_addr
			return ctypes.cast(result.handle, ctypes.c_void_p).value
		except:
			log.log_error(traceback.format_exc())
			return ctypes.cast(self.handle, ctypes.c_void_p).value

	def _get_instruction_info(self, ctxt, data, addr, max_len, result):
		try:
			buf = ctypes.create_string_buffer(max_len)
			ctypes.memmove(buf, data, max_len)
			info = self.perform_get_instruction_info(buf.raw, addr)
			if info is None:
				return False
			result[0].length = info.length
			result[0].branchDelay = info.branch_delay
			result[0].branchCount = len(info.branches)
			for i in xrange(0, len(info.branches)):
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
			info = self.perform_get_instruction_text(buf.raw, addr)
			if info is None:
				return False
			tokens = info[0]
			length[0] = info[1]
			count[0] = len(tokens)
			token_buf = (core.BNInstructionTextToken * len(tokens))()
			for i in xrange(0, len(tokens)):
				if isinstance(tokens[i].type, str):
					token_buf[i].type = InstructionTextTokenType[tokens[i].type]
				else:
					token_buf[i].type = tokens[i].type
				token_buf[i].text = tokens[i].text
				token_buf[i].value = tokens[i].value
				token_buf[i].size = tokens[i].size
				token_buf[i].operand = tokens[i].operand
				token_buf[i].context = tokens[i].context
				token_buf[i].confidence = tokens[i].confidence
				token_buf[i].address = tokens[i].address
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
			result = self.perform_get_instruction_low_level_il(buf.raw, addr,
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

	def _get_full_width_registers(self, ctxt, count):
		try:
			regs = self._full_width_regs.values()
			count[0] = len(regs)
			reg_buf = (ctypes.c_uint * len(regs))()
			for i in xrange(0, len(regs)):
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
			regs = self._regs_by_index.keys()
			count[0] = len(regs)
			reg_buf = (ctypes.c_uint * len(regs))()
			for i in xrange(0, len(regs)):
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
			flags = self._flags_by_index.keys()
			count[0] = len(flags)
			flag_buf = (ctypes.c_uint * len(flags))()
			for i in xrange(0, len(flags)):
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
			types = self._flag_write_types_by_index.keys()
			count[0] = len(types)
			type_buf = (ctypes.c_uint * len(types))()
			for i in xrange(0, len(types)):
				type_buf[i] = types[i]
			result = ctypes.cast(type_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, type_buf)
			return result.value
		except KeyError:
			log.log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _get_flag_role(self, ctxt, flag):
		try:
			if flag in self._flag_roles:
				return self._flag_roles[flag]
			return FlagRole.SpecialFlagRole
		except KeyError:
			log.log_error(traceback.format_exc())
			return None

	def _get_flags_required_for_flag_condition(self, ctxt, cond, count):
		try:
			if cond in self._flags_required_for_flag_condition:
				flags = self._flags_required_for_flag_condition[cond]
			else:
				flags = []
			count[0] = len(flags)
			flag_buf = (ctypes.c_uint * len(flags))()
			for i in xrange(0, len(flags)):
				flag_buf[i] = flags[i]
			result = ctypes.cast(flag_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, flag_buf)
			return result.value
		except KeyError:
			log.log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _get_flags_written_by_flag_write_type(self, ctxt, write_type, count):
		try:
			if write_type in self._flags_written_by_flag_write_type:
				flags = self._flags_written_by_flag_write_type[write_type]
			else:
				flags = []
			count[0] = len(flags)
			flag_buf = (ctypes.c_uint * len(flags))()
			for i in xrange(0, len(flags)):
				flag_buf[i] = flags[i]
			result = ctypes.cast(flag_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, flag_buf)
			return result.value
		except (KeyError, OSError):
			log.log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _get_flag_write_low_level_il(self, ctxt, op, size, write_type, flag, operands, operand_count, il):
		try:
			write_type_name = None
			if write_type != 0:
				write_type_name = self._flag_write_types_by_index[write_type]
			flag_name = self._flags_by_index[flag]
			operand_list = []
			for i in xrange(operand_count):
				if operands[i].constant:
					operand_list.append(operands[i].value)
				elif lowlevelil.LLIL_REG_IS_TEMP(operands[i].reg):
					operand_list.append(lowlevelil.ILRegister(self, operands[i].reg))
				else:
					operand_list.append(lowlevelil.ILRegister(self, operands[i].reg))
			return self.perform_get_flag_write_low_level_il(op, size, write_type_name, flag_name, operand_list,
				lowlevelil.LowLevelILFunction(self, core.BNNewLowLevelILFunctionReference(il))).index
		except (KeyError, OSError):
			log.log_error(traceback.format_exc())
			return False

	def _get_flag_condition_low_level_il(self, ctxt, cond, il):
		try:
			return self.perform_get_flag_condition_low_level_il(cond,
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
			info = self.__class__.regs[self._regs_by_index[reg]]
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
			return self._all_regs[self.__class__.stack_pointer]
		except KeyError:
			log.log_error(traceback.format_exc())
			return 0

	def _get_link_register(self, ctxt):
		try:
			if self.__class__.link_reg is None:
				return 0xffffffff
			return self._all_regs[self.__class__.link_reg]
		except KeyError:
			log.log_error(traceback.format_exc())
			return 0

	def _get_global_registers(self, ctxt, count):
		try:
			count[0] = len(self.__class__.global_regs)
			reg_buf = (ctypes.c_uint * len(self.__class__.global_regs))()
			for i in xrange(0, len(self.__class__.global_regs)):
				reg_buf[i] = self._all_regs[self.__class__.global_regs[i]]
			result = ctypes.cast(reg_buf, ctypes.c_void_p)
			self._pending_reg_lists[result.value] = (result, reg_buf)
			return result.value
		except KeyError:
			log.log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _assemble(self, ctxt, code, addr, result, errors):
		try:
			data, error_str = self.perform_assemble(code, addr)
			errors[0] = core.BNAllocString(str(error_str))
			if data is None:
				return False
			data = str(data)
			buf = ctypes.create_string_buffer(len(data))
			ctypes.memmove(buf, data, len(data))
			core.BNSetDataBufferContents(result, buf, len(data))
			return True
		except:
			log.log_error(traceback.format_exc())
			errors[0] = core.BNAllocString("Unhandled exception during assembly.\n")
			return False

	def _is_never_branch_patch_available(self, ctxt, data, addr, length):
		try:
			buf = ctypes.create_string_buffer(length)
			ctypes.memmove(buf, data, length)
			return self.perform_is_never_branch_patch_available(buf.raw, addr)
		except:
			log.log_error(traceback.format_exc())
			return False

	def _is_always_branch_patch_available(self, ctxt, data, addr, length):
		try:
			buf = ctypes.create_string_buffer(length)
			ctypes.memmove(buf, data, length)
			return self.perform_is_always_branch_patch_available(buf.raw, addr)
		except:
			log.log_error(traceback.format_exc())
			return False

	def _is_invert_branch_patch_available(self, ctxt, data, addr, length):
		try:
			buf = ctypes.create_string_buffer(length)
			ctypes.memmove(buf, data, length)
			return self.perform_is_invert_branch_patch_available(buf.raw, addr)
		except:
			log.log_error(traceback.format_exc())
			return False

	def _is_skip_and_return_zero_patch_available(self, ctxt, data, addr, length):
		try:
			buf = ctypes.create_string_buffer(length)
			ctypes.memmove(buf, data, length)
			return self.perform_is_skip_and_return_zero_patch_available(buf.raw, addr)
		except:
			log.log_error(traceback.format_exc())
			return False

	def _is_skip_and_return_value_patch_available(self, ctxt, data, addr, length):
		try:
			buf = ctypes.create_string_buffer(length)
			ctypes.memmove(buf, data, length)
			return self.perform_is_skip_and_return_value_patch_available(buf.raw, addr)
		except:
			log.log_error(traceback.format_exc())
			return False

	def _convert_to_nop(self, ctxt, data, addr, length):
		try:
			buf = ctypes.create_string_buffer(length)
			ctypes.memmove(buf, data, length)
			result = self.perform_convert_to_nop(buf.raw, addr)
			if result is None:
				return False
			result = str(result)
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
			result = self.perform_always_branch(buf.raw, addr)
			if result is None:
				return False
			result = str(result)
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
			result = self.perform_invert_branch(buf.raw, addr)
			if result is None:
				return False
			result = str(result)
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
			result = self.perform_skip_and_return_value(buf.raw, addr, value)
			if result is None:
				return False
			result = str(result)
			if len(result) > length:
				result = result[0:length]
			ctypes.memmove(data, result, len(result))
			return True
		except:
			log.log_error(traceback.format_exc())
			return False

	def perform_get_associated_arch_by_address(self, addr):
		return self, addr

	@abc.abstractmethod
	def perform_get_instruction_info(self, data, addr):
		"""
		``perform_get_instruction_info`` implements a method which interpretes the bytes passed in ``data`` as an
		:py:Class:`InstructionInfo` object. The InstructionInfo object should have the length of the current instruction.
		If the instruction is a branch instruction the method should add a branch of the proper type:

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
			UnresolvedBranch      Call instruction that isn't
			===================== ===================================================

		:param str data: bytes to decode
		:param int addr: virtual address of the byte to be decoded
		:return: a :py:class:`InstructionInfo` object containing the length and branche types for the given instruction
		:rtype: InstructionInfo
		"""
		raise NotImplementedError

	@abc.abstractmethod
	def perform_get_instruction_text(self, data, addr):
		"""
		``perform_get_instruction_text`` implements a method which interpretes the bytes passed in ``data`` as a
		list of :py:class:`InstructionTextToken` objects.

		:param str data: bytes to decode
		:param int addr: virtual address of the byte to be decoded
		:return: a tuple of list(InstructionTextToken) and length of instruction decoded
		:rtype: tuple(list(InstructionTextToken), int)
		"""
		raise NotImplementedError

	@abc.abstractmethod
	def perform_get_instruction_low_level_il(self, data, addr, il):
		"""
		``perform_get_instruction_low_level_il`` implements a method to interpret the bytes passed in ``data`` to
		low-level IL instructions. The il instructions must be appended to the :py:class:`LowLevelILFunction`.

		.. note:: Architecture subclasses should implement this method.

		:param str data: bytes to be interpreted as low-level IL instructions
		:param int addr: virtual address of start of ``data``
		:param LowLevelILFunction il: LowLevelILFunction object to append LowLevelILExpr objects to
		:rtype: length of bytes read on success, None on failure
		"""
		raise NotImplementedError

	@abc.abstractmethod
	def perform_get_flag_write_low_level_il(self, op, size, write_type, flag, operands, il):
		"""
		.. note:: Architecture subclasses should implement this method.
		.. warning:: This method should never be called directly.

		:param LowLevelILOperation op:
		:param int size:
		:param int write_type:
		:param int flag:
		:param list(int_or_str):
		:param LowLevelILFunction il:
		:rtype: LowLevelILExpr
		"""
		flag = self.get_flag_index(flag)
		if flag not in self._flag_roles:
			return il.unimplemented()
		return self.get_default_flag_write_low_level_il(op, size, self._flag_roles[flag], operands, il)

	@abc.abstractmethod
	def perform_get_flag_condition_low_level_il(self, cond, il):
		"""
		.. note:: Architecture subclasses should implement this method.
		.. warning:: This method should never be called directly.

		:param LowLevelILFlagCondition cond:
		:param LowLevelILFunction il:
		:rtype: LowLevelILExpr
		"""
		return self.get_default_flag_condition_low_level_il(cond, il)

	@abc.abstractmethod
	def perform_assemble(self, code, addr):
		"""
		``perform_assemble`` implements a method to convert the string of assembly instructions ``code`` loaded at
		virtual address ``addr`` to the byte representation of those instructions. This can be done by simply shelling
		out to an assembler like yasm or llvm-mc, since this method isn't performance sensitive.

		.. note:: Architecture subclasses should implement this method.
		.. note :: It is important that the assembler used accepts a syntax identical to the one emitted by the \
		disassembler. This will prevent confusing the user.
		.. warning:: This method should never be called directly.

		:param str code: string representation of the instructions to be assembled
		:param int addr: virtual address that the instructions will be loaded at
		:return: the bytes for the assembled instructions or error string
		:rtype: (a tuple of instructions and empty string) or (or None and error string)
		"""
		return None, "Architecture does not implement an assembler.\n"

	@abc.abstractmethod
	def perform_is_never_branch_patch_available(self, data, addr):
		"""
		``perform_is_never_branch_patch_available`` implements a check to determine if the instruction represented by
		the bytes contained in ``data`` at address addr is a branch instruction that can be made to never branch.

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
		``perform_is_always_branch_patch_available`` implements a check to determine if the instruction represented by
		the bytes contained in ``data`` at address addr is a conditional branch that can be made unconditional.

		.. note:: Architecture subclasses should implement this method.
		.. warning:: This method should never be called directly.

		:param str data: bytes to be checked
		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		"""
		return False

	@abc.abstractmethod
	def perform_is_invert_branch_patch_available(self, data, addr):
		"""
		``perform_is_invert_branch_patch_available`` implements a check to determine if the instruction represented by
		the bytes contained in ``data`` at address addr is a conditional branch which can be inverted.

		.. note:: Architecture subclasses should implement this method.
		.. warning:: This method should never be called directly.

		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		"""
		return False

	@abc.abstractmethod
	def perform_is_skip_and_return_zero_patch_available(self, data, addr):
		"""
		``perform_is_skip_and_return_zero_patch_available`` implements a check to determine if the instruction represented by
		the bytes contained in ``data`` at address addr is a *call-like* instruction which can made into instructions
		that are equivilent to "return 0". For example if ``data`` was the x86 instruction ``call eax`` which could be
		converted into ``xor eax,eax`` thus this function would return True.

		.. note:: Architecture subclasses should implement this method.
		.. warning:: This method should never be called directly.

		:param str data: bytes to be checked
		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		"""
		return False

	@abc.abstractmethod
	def perform_is_skip_and_return_value_patch_available(self, data, addr):
		"""
		``perform_is_skip_and_return_value_patch_available`` implements a check to determine if the instruction represented by
		the bytes contained in ``data`` at address addr is a *call-like* instruction which can made into instructions
		that are equivilent to "return 0". For example if ``data`` was the x86 instruction ``call 0xdeadbeef`` which could be
		converted into ``mov eax, 42`` thus this function would return True.

		.. note:: Architecture subclasses should implement this method.
		.. warning:: This method should never be called directly.

		:param str data: bytes to be checked
		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		"""
		return False

	@abc.abstractmethod
	def perform_convert_to_nop(self, data, addr):
		"""
		``perform_convert_to_nop`` implements a method which returns a nop sequence of len(data) bytes long.

		.. note:: Architecture subclasses should implement this method.
		.. warning:: This method should never be called directly.

		:param str data: bytes at virtual address ``addr``
		:param int addr: the virtual address of the instruction to be patched
		:return: nop sequence of same length as ``data`` or None
		:rtype: str or None
		"""
		return None

	@abc.abstractmethod
	def perform_always_branch(self, data, addr):
		"""
		``perform_always_branch`` implements a method which converts the branch represented by the bytes in ``data`` to
		at ``addr`` to an unconditional branch.

		.. note:: Architecture subclasses should implement this method.
		.. warning:: This method should never be called directly.

		:param str data: bytes to be checked
		:param int addr: the virtual address of the instruction to be patched
		:return: The bytes of the replacement unconditional branch instruction
		:rtype: str
		"""
		return None

	@abc.abstractmethod
	def perform_invert_branch(self, data, addr):
		"""
		``perform_invert_branch`` implements a method which inverts the branch represented by the bytes in ``data`` to
		at ``addr``.

		.. note:: Architecture subclasses should implement this method.
		.. warning:: This method should never be called directly.

		:param str data: bytes to be checked
		:param int addr: the virtual address of the instruction to be patched
		:return: The bytes of the replacement unconditional branch instruction
		:rtype: str
		"""
		return None

	@abc.abstractmethod
	def perform_skip_and_return_value(self, data, addr, value):
		"""
		``perform_skip_and_return_value`` implements a method which converts a *call-like* instruction represented by
		the bytes in ``data`` at ``addr`` to one or more instructions that are equivilent to a function returning a
		value.

		.. note:: Architecture subclasses should implement this method.
		.. warning:: This method should never be called directly.

		:param str data: bytes to be checked
		:param int addr: the virtual address of the instruction to be patched
		:param int value: value to be returned
		:return: The bytes of the replacement unconditional branch instruction
		:rtype: str
		"""
		return None

	def get_associated_arch_by_address(self, addr):
		new_addr = ctypes.c_ulonglong()
		new_addr.value = addr
		result = core.BNGetAssociatedArchitectureByAddress(self.handle, new_addr)
		return Architecture(handle = result), new_addr.value

	def get_instruction_info(self, data, addr):
		"""
		``get_instruction_info`` returns an InstructionInfo object for the instruction at the given virtual address
		``addr`` with data ``data``.

		.. note :: The instruction info object should always set the InstructionInfo.length to the instruction length, \
		and the branches of the proper types shoulde be added if the instruction is a branch.

		:param str data: max_instruction_length bytes from the binary at virtual address ``addr``
		:param int addr: virtual address of bytes in ``data``
		:return: the InstructionInfo for the current instruction
		:rtype: InstructionInfo
		"""
		info = core.BNInstructionInfo()
		data = str(data)
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		if not core.BNGetInstructionInfo(self.handle, buf, addr, len(data), info):
			return None
		result = function.InstructionInfo()
		result.length = info.length
		result.branch_delay = info.branchDelay
		for i in xrange(0, info.branchCount):
			target = info.branchTarget[i]
			if info.branchArch[i]:
				arch = Architecture(info.branchArch[i])
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
		data = str(data)
		count = ctypes.c_ulonglong()
		length = ctypes.c_ulonglong()
		length.value = len(data)
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		tokens = ctypes.POINTER(core.BNInstructionTextToken)()
		if not core.BNGetInstructionText(self.handle, buf, addr, length, tokens, count):
			return None, 0
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
		return result, length.value

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
		want to be using ``Function.get_low_level_il_at``.

		:param str data: max_instruction_length bytes from the binary at virtual address ``addr``
		:param int addr: virtual address of bytes in ``data``
		:param LowLevelILFunction il: The function the current instruction belongs to
		:return: the length of the current instruction
		:rtype: int
		"""
		data = str(data)
		length = ctypes.c_ulonglong()
		length.value = len(data)
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		core.BNGetInstructionLowLevelIL(self.handle, buf, addr, length, il.handle)
		return length.value

	def get_low_level_il_from_bytes(self, data, addr):
		"""
		``get_low_level_il_from_bytes`` converts the instruction in bytes to ``il`` at the given virtual address

		:param str data: the bytes of the instruction
		:param int addr: virtual address of bytes in ``data``
		:return: the instruction
		:rtype: LowLevelILInstruction
		:Example:

			>>> arch.get_low_level_il_from_bytes('\xeb\xfe', 0x40DEAD)
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

	def get_flag_index(self, flag):
		if isinstance(flag, str):
			return self._flags[flag]
		elif isinstance(flag, lowlevelil.ILFlag):
			return flag.index
		return flag

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
		``get_flag_write_type_by_name`` gets the flag write type name for the flage write type.

		:param int write_type: flag write type
		:return: flag write type
		:rtype: str
		"""
		return self._flag_write_types[write_type]

	def get_flag_write_low_level_il(self, op, size, write_type, flag, operands, il):
		"""
		:param LowLevelILOperation op:
		:param int size:
		:param str write_type:
		:param list(str or int) operands: a list of either items that are either string register names or constant \
		integer values
		:param LowLevelILFunction il:
		:rtype: LowLevelILExpr
		"""
		flag = self.get_flag_index(flag)
		operand_list = (core.BNRegisterOrConstant * len(operands))()
		for i in xrange(len(operands)):
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

	def get_default_flag_write_low_level_il(self, op, size, role, operands, il):
		"""
		:param LowLevelILOperation op:
		:param int size:
		:param FlagRole role:
		:param list(str or int) operands: a list of either items that are either string register names or constant \
		integer values
		:param LowLevelILFunction il:
		:rtype: LowLevelILExpr index
		"""
		operand_list = (core.BNRegisterOrConstant * len(operands))()
		for i in xrange(len(operands)):
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

	def get_flag_condition_low_level_il(self, cond, il):
		"""
		:param LowLevelILFlagCondition cond:
		:param LowLevelILFunction il:
		:rtype: LowLevelILExpr
		"""
		return lowlevelil.LowLevelILExpr(core.BNGetArchitectureFlagConditionLowLevelIL(self.handle, cond, il.handle))

	def get_default_flag_condition_low_level_il(self, cond, il):
		"""
		:param LowLevelILFlagCondition cond:
		:param LowLevelILFunction il:
		:rtype: LowLevelILExpr
		"""
		return lowlevelil.LowLevelILExpr(core.BNGetDefaultArchitectureFlagConditionLowLevelIL(self.handle, cond, il.handle))

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
		for i in xrange(0, count.value):
			result.append(core.BNGetArchitectureRegisterName(self.handle, regs[i]))
		core.BNFreeRegisterList(regs)
		return result

	def assemble(self, code, addr=0):
		"""
		``assemble`` converts the string of assembly instructions ``code`` loaded at virtual address ``addr`` to the
		byte representation of those instructions.

		:param str code: string representation of the instructions to be assembled
		:param int addr: virtual address that the instructions will be loaded at
		:return: the bytes for the assembled instructions or error string
		:rtype: (a tuple of instructions and empty string) or (or None and error string)
		:Example:

			>>> arch.assemble("je 10")
			('\\x0f\\x84\\x04\\x00\\x00\\x00', '')
			>>>
		"""
		result = databuffer.DataBuffer()
		errors = ctypes.c_char_p()
		if not core.BNAssemble(self.handle, code, addr, result.handle, errors):
			return None, errors.value
		return str(result), errors.value

	def is_never_branch_patch_available(self, data, addr):
		"""
		``is_never_branch_patch_available`` determines if the instruction ``data`` at ``addr`` can be made to **never branch**.

		:param str data: bytes for the instruction to be checked
		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		:Example:

			>>> arch.is_never_branch_patch_available(arch.assemble("je 10")[0], 0)
			True
			>>> arch.is_never_branch_patch_available(arch.assemble("nop")[0], 0)
			False
			>>>
		"""
		data = str(data)
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

			>>> arch.is_always_branch_patch_available(arch.assemble("je 10")[0], 0)
			True
			>>> arch.is_always_branch_patch_available(arch.assemble("nop")[0], 0)
			False
			>>>
		"""
		data = str(data)
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

			>>> arch.is_invert_branch_patch_available(arch.assemble("je 10")[0], 0)
			True
			>>> arch.is_invert_branch_patch_available(arch.assemble("nop")[0], 0)
			False
			>>>
		"""
		data = str(data)
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

			>>> arch.is_skip_and_return_zero_patch_available(arch.assemble("call 0")[0], 0)
			True
			>>> arch.is_skip_and_return_zero_patch_available(arch.assemble("call eax")[0], 0)
			True
			>>> arch.is_skip_and_return_zero_patch_available(arch.assemble("jmp eax")[0], 0)
			False
			>>>
		"""
		data = str(data)
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		return core.BNIsArchitectureSkipAndReturnZeroPatchAvailable(self.handle, buf, addr, len(data))

	def is_skip_and_return_value_patch_available(self, data, addr):
		"""
		``is_skip_and_return_zero_patch_available`` determines if the instruction ``data`` at ``addr`` is a *call-like*
		instruction that can be made into an instruction *returns a value*.

		:param str data: bytes for the instruction to be checked
		:param int addr: the virtual address of the instruction to be patched
		:return: True if the instruction can be patched, False otherwise
		:rtype: bool
		:Example:

			>>> arch.is_skip_and_return_zero_patch_available(arch.assemble("call 0")[0], 0)
			True
			>>> arch.is_skip_and_return_zero_patch_available(arch.assemble("jmp eax")[0], 0)
			False
			>>>
		"""
		data = str(data)
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

			>>> arch.convert_to_nop("\\x00\\x00", 0)
			'\\x90\\x90'
			>>>
		"""
		data = str(data)
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

			>>> bytes = arch.always_branch(arch.assemble("je 10")[0], 0)
			>>> arch.get_instruction_text(bytes, 0)
			(['nop     '], 1L)
			>>> arch.get_instruction_text(bytes[1:], 0)
			(['jmp     ', '0x9'], 5L)
			>>>
		"""
		data = str(data)
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

			>>> arch.get_instruction_text(arch.invert_branch(arch.assemble("je 10")[0], 0), 0)
			(['jne     ', '0xa'], 6L)
			>>> arch.get_instruction_text(arch.invert_branch(arch.assemble("jo 10")[0], 0), 0)
			(['jno     ', '0xa'], 6L)
			>>> arch.get_instruction_text(arch.invert_branch(arch.assemble("jge 10")[0], 0), 0)
			(['jl      ', '0xa'], 6L)
			>>>
		"""
		data = str(data)
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

			>>> arch.get_instruction_text(arch.skip_and_return_value(arch.assemble("call 10")[0], 0, 0), 0)
			(['mov     ', 'eax', ', ', '0x0'], 5L)
			>>>
		"""
		data = str(data)
		buf = (ctypes.c_ubyte * len(data))()
		ctypes.memmove(buf, data, len(data))
		if not core.BNArchitectureSkipAndReturnValue(self.handle, buf, addr, len(data), value):
			return None
		result = ctypes.create_string_buffer(len(data))
		ctypes.memmove(result, buf, len(data))
		return result.raw

	def is_view_type_constant_defined(self, type_name, const_name):
		"""

		:param str type_name: the BinaryView type name of the constant to query
		:param str const_name: the constant name to query
		:rtype: None
		:Example:

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
			5L
			>>> arch.get_view_type_constant("ELF", "NOT_HERE", 100)
			100L
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


class ReferenceSource(object):
	def __init__(self, func, arch, addr):
		self.function = func
		self.arch = arch
		self.address = addr

	def __repr__(self):
		if self.arch:
			return "<ref: %s@%#x>" % (self.arch.name, self.address)
		else:
			return "<ref: %#x>" % self.address
