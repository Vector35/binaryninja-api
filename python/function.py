# Copyright (c) 2015-2016 Vector 35 LLC
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

import threading
import traceback
import ctypes

# Binary Ninja components
import _binaryninjacore as core
import architecture
import highlight
import associateddatastore
import bntype
import basicblock
import lowlevelil
import binaryview
import log


class LookupTableEntry(object):
	def __init__(self, from_values, to_value):
		self.from_values = from_values
		self.to_value = to_value

	def __repr__(self):
		return "[%s] -> %#x" % (', '.join(["%#x" % i for i in self.from_values]), self.to_value)


class RegisterValue(object):
	def __init__(self, arch, value):
		self.type = value.state
		if value.state == core.BNRegisterValueType.EntryValue:
			self.reg = arch.get_reg_name(value.reg)
		elif value.state == core.BNRegisterValueType.OffsetFromEntryValue:
			self.reg = arch.get_reg_name(value.reg)
			self.offset = value.value
		elif value.state == core.BNRegisterValueType.ConstantValue:
			self.value = value.value
		elif value.state == core.BNRegisterValueType.StackFrameOffset:
			self.offset = value.value
		elif value.state == core.BNRegisterValueType.SignedRangeValue:
			self.offset = value.value
			self.start = value.rangeStart
			self.end = value.rangeEnd
			self.step = value.rangeStep
			if self.start & (1 << 63):
				self.start |= ~((1 << 63) - 1)
			if self.end & (1 << 63):
				self.end |= ~((1 << 63) - 1)
		elif value.state == core.BNRegisterValueType.UnsignedRangeValue:
			self.offset = value.value
			self.start = value.rangeStart
			self.end = value.rangeEnd
			self.step = value.rangeStep
		elif value.state == core.BNRegisterValueType.LookupTableValue:
			self.table = []
			self.mapping = {}
			for i in xrange(0, value.rangeEnd):
				from_list = []
				for j in xrange(0, value.table[i].fromCount):
					from_list.append(value.table[i].fromValues[j])
					self.mapping[value.table[i].fromValues[j]] = value.table[i].toValue
				self.table.append(LookupTableEntry(from_list, value.table[i].toValue))
		elif value.state == core.BNRegisterValueType.OffsetFromUndeterminedValue:
			self.offset = value.value

	def __repr__(self):
		if self.type == core.BNRegisterValueType.EntryValue:
			return "<entry %s>" % self.reg
		if self.type == core.BNRegisterValueType.OffsetFromEntryValue:
			return "<entry %s + %#x>" % (self.reg, self.offset)
		if self.type == core.BNRegisterValueType.ConstantValue:
			return "<const %#x>" % self.value
		if self.type == core.BNRegisterValueType.StackFrameOffset:
			return "<stack frame offset %#x>" % self.offset
		if (self.type == core.BNRegisterValueType.SignedRangeValue) or (self.type == core.BNRegisterValueType.UnsignedRangeValue):
			if self.step == 1:
				return "<range: %#x to %#x>" % (self.start, self.end)
			return "<range: %#x to %#x, step %#x>" % (self.start, self.end, self.step)
		if self.type == core.BNRegisterValueType.LookupTableValue:
			return "<table: %s>" % ', '.join([repr(i) for i in self.table])
		if self.type == core.BNRegisterValueType.OffsetFromUndeterminedValue:
			return "<undetermined with offset %#x>" % self.offset
		return "<undetermined>"


class StackVariable(object):
	def __init__(self, ofs, name, t):
		self.offset = ofs
		self.name = name
		self.type = t

	def __repr__(self):
		return "<var@%x: %s %s>" % (self.offset, self.type, self.name)

	def __str__(self):
		return self.name


class StackVariableReference(object):
	def __init__(self, src_operand, t, name, start_ofs, ref_ofs):
		self.source_operand = src_operand
		self.type = t
		self.name = name
		self.starting_offset = start_ofs
		self.referenced_offset = ref_ofs
		if self.source_operand == 0xffffffff:
			self.source_operand = None

	def __repr__(self):
		if self.source_operand is None:
			if self.referenced_offset != self.starting_offset:
				return "<ref to %s%+#x>" % (self.name, self.referenced_offset - self.starting_offset)
			return "<ref to %s>" % self.name
		if self.referenced_offset != self.starting_offset:
			return "<operand %d ref to %s%+#x>" % (self.source_operand, self.name, self.referenced_offset)
		return "<operand %d ref to %s>" % (self.source_operand, self.name)


class ConstantReference(object):
	def __init__(self, val, size):
		self.value = val
		self.size = size

	def __repr__(self):
		if self.size == 0:
			return "<constant %#x>" % self.value
		return "<constant %#x size %d>" % (self.value, self.size)


class IndirectBranchInfo(object):
	def __init__(self, source_arch, source_addr, dest_arch, dest_addr, auto_defined):
		self.source_arch = source_arch
		self.source_addr = source_addr
		self.dest_arch = dest_arch
		self.dest_addr = dest_addr
		self.auto_defined = auto_defined

	def __repr__(self):
		return "<branch %s:%#x -> %s:%#x>" % (self.source_arch.name, self.source_addr, self.dest_arch.name, self.dest_addr)


class _FunctionAssociatedDataStore(associateddatastore._AssociatedDataStore):
	_defaults = {}


class Function(object):
	_associated_data = {}

	def __init__(self, view, handle):
		self._view = view
		self.handle = core.handle_of_type(handle, core.BNFunction)
		self._advanced_analysis_requests = 0

	def __del__(self):
		if self._advanced_analysis_requests > 0:
			core.BNReleaseAdvancedFunctionAnalysisDataMultiple(self.handle, self._advanced_analysis_requests)
		core.BNFreeFunction(self.handle)

	@classmethod
	def _unregister(cls, func):
		handle = ctypes.cast(func, ctypes.c_void_p)
		if handle.value in cls._associated_data:
			del cls._associated_data[handle.value]

	@classmethod
	def set_default_session_data(cls, name, value):
		_FunctionAssociatedDataStore.set_default(name, value)

	@property
	def name(self):
		"""Symbol name for the function"""
		return self.symbol.name

	@name.setter
	def name(self, value):
		if value is None:
			if self.symbol is not None:
				self.view.undefine_user_symbol(self.symbol)
		else:
			symbol = bntype.Symbol(core.BNSymbolType.FunctionSymbol, self.start, value)
			self.view.define_user_symbol(symbol)

	@property
	def view(self):
		"""Function view (read-only)"""
		return self._view

	@property
	def arch(self):
		"""Function architecture (read-only)"""
		arch = core.BNGetFunctionArchitecture(self.handle)
		if arch is None:
			return None
		return architecture.Architecture(arch)

	@property
	def platform(self):
		"""Function platform (read-only)"""
		platform = core.BNGetFunctionPlatform(self.handle)
		if platform is None:
			return None
		return platform.Platform(None, handle = platform)

	@property
	def start(self):
		"""Function start (read-only)"""
		return core.BNGetFunctionStart(self.handle)

	@property
	def symbol(self):
		"""Function symbol(read-only)"""
		sym = core.BNGetFunctionSymbol(self.handle)
		if sym is None:
			return None
		return bntype.Symbol(None, None, None, handle = sym)

	@property
	def auto(self):
		"""Whether function was automatically discovered (read-only)"""
		return core.BNWasFunctionAutomaticallyDiscovered(self.handle)

	@property
	def can_return(self):
		"""Whether function can return (read-only)"""
		return core.BNCanFunctionReturn(self.handle)

	@property
	def explicitly_defined_type(self):
		"""Whether function has explicitly defined types (read-only)"""
		return core.BNHasExplicitlyDefinedType(self.handle)

	@property
	def needs_update(self):
		"""Whether the function has analysis that needs to be updated (read-only)"""
		return core.BNIsFunctionUpdateNeeded(self.handle)

	@property
	def basic_blocks(self):
		"""List of basic blocks (read-only)"""
		count = ctypes.c_ulonglong()
		blocks = core.BNGetFunctionBasicBlockList(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			result.append(basicblock.BasicBlock(self._view, core.BNNewBasicBlockReference(blocks[i])))
		core.BNFreeBasicBlockList(blocks, count.value)
		return result

	@property
	def comments(self):
		"""Dict of comments (read-only)"""
		count = ctypes.c_ulonglong()
		addrs = core.BNGetCommentedAddresses(self.handle, count)
		result = {}
		for i in xrange(0, count.value):
			result[addrs[i]] = self.get_comment_at(addrs[i])
		core.BNFreeAddressList(addrs)
		return result

	@property
	def low_level_il(self):
		"""Function low level IL (read-only)"""
		return lowlevelil.LowLevelILFunction(self.arch, core.BNGetFunctionLowLevelIL(self.handle), self)

	@property
	def lifted_il(self):
		"""Function lifted IL (read-only)"""
		return lowlevelil.LowLevelILFunction(self.arch, core.BNGetFunctionLiftedIL(self.handle), self)

	@property
	def function_type(self):
		"""Function type"""
		return bntype.Type(core.BNGetFunctionType(self.handle))

	@function_type.setter
	def function_type(self, value):
		self.set_user_type(value)

	@property
	def stack_layout(self):
		"""List of function stack (read-only)"""
		count = ctypes.c_ulonglong()
		v = core.BNGetStackLayout(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			result.append(StackVariable(v[i].offset, v[i].name, bntype.Type(handle = core.BNNewTypeReference(v[i].type))))
		result.sort(key = lambda x: x.offset)
		core.BNFreeStackLayout(v, count.value)
		return result

	@property
	def indirect_branches(self):
		"""List of indirect branches (read-only)"""
		count = ctypes.c_ulonglong()
		branches = core.BNGetIndirectBranches(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			result.append(IndirectBranchInfo(architecture.Architecture(branches[i].sourceArch), branches[i].sourceAddr, architecture.Architecture(branches[i].destArch), branches[i].destAddr, branches[i].autoDefined))
		core.BNFreeIndirectBranchList(branches)
		return result

	@property
	def session_data(self):
		"""Dictionary object where plugins can store arbitrary data associated with the function"""
		handle = ctypes.cast(self.handle, ctypes.c_void_p)
		if handle.value not in Function._associated_data:
			obj = _FunctionAssociatedDataStore()
			Function._associated_data[handle.value] = obj
			return obj
		else:
			return Function._associated_data[handle.value]

	def __iter__(self):
		count = ctypes.c_ulonglong()
		blocks = core.BNGetFunctionBasicBlockList(self.handle, count)
		try:
			for i in xrange(0, count.value):
				yield basicblock.BasicBlock(self._view, core.BNNewBasicBlockReference(blocks[i]))
		finally:
			core.BNFreeBasicBlockList(blocks, count.value)

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self, name, value)
		except AttributeError:
			raise AttributeError("attribute '%s' is read only" % name)

	def __repr__(self):
		arch = self.arch
		if arch:
			return "<func: %s@%#x>" % (arch.name, self.start)
		else:
			return "<func: %#x>" % self.start

	def mark_recent_use(self):
		core.BNMarkFunctionAsRecentlyUsed(self.handle)

	def get_comment_at(self, addr):
		return core.BNGetCommentForAddress(self.handle, addr)

	def set_comment(self, addr, comment):
		core.BNSetCommentForAddress(self.handle, addr, comment)

	def get_low_level_il_at(self, arch, addr):
		return core.BNGetLowLevelILForInstruction(self.handle, arch.handle, addr)

	def get_low_level_il_exits_at(self, arch, addr):
		count = ctypes.c_ulonglong()
		exits = core.BNGetLowLevelILExitsForInstruction(self.handle, arch.handle, addr, count)
		result = []
		for i in xrange(0, count.value):
			result.append(exits[i])
		core.BNFreeLowLevelILInstructionList(exits)
		return result

	def get_reg_value_at(self, arch, addr, reg):
		if isinstance(reg, str):
			reg = arch.regs[reg].index
		value = core.BNGetRegisterValueAtInstruction(self.handle, arch.handle, addr, reg)
		result = RegisterValue(arch, value)
		core.BNFreeRegisterValue(value)
		return result

	def get_reg_value_after(self, arch, addr, reg):
		if isinstance(reg, str):
			reg = arch.regs[reg].index
		value = core.BNGetRegisterValueAfterInstruction(self.handle, arch.handle, addr, reg)
		result = RegisterValue(arch, value)
		core.BNFreeRegisterValue(value)
		return result

	def get_reg_value_at_low_level_il_instruction(self, i, reg):
		if isinstance(reg, str):
			reg = self.arch.regs[reg].index
		value = core.BNGetRegisterValueAtLowLevelILInstruction(self.handle, i, reg)
		result = RegisterValue(self.arch, value)
		core.BNFreeRegisterValue(value)
		return result

	def get_reg_value_after_low_level_il_instruction(self, i, reg):
		if isinstance(reg, str):
			reg = self.arch.regs[reg].index
		value = core.BNGetRegisterValueAfterLowLevelILInstruction(self.handle, i, reg)
		result = RegisterValue(self.arch, value)
		core.BNFreeRegisterValue(value)
		return result

	def get_stack_contents_at(self, arch, addr, offset, size):
		value = core.BNGetStackContentsAtInstruction(self.handle, arch.handle, addr, offset, size)
		result = RegisterValue(arch, value)
		core.BNFreeRegisterValue(value)
		return result

	def get_stack_contents_after(self, arch, addr, offset, size):
		value = core.BNGetStackContentsAfterInstruction(self.handle, arch.handle, addr, offset, size)
		result = RegisterValue(arch, value)
		core.BNFreeRegisterValue(value)
		return result

	def get_stack_contents_at_low_level_il_instruction(self, i, offset, size):
		value = core.BNGetStackContentsAtLowLevelILInstruction(self.handle, i, offset, size)
		result = RegisterValue(self.arch, value)
		core.BNFreeRegisterValue(value)
		return result

	def get_stack_contents_after_low_level_il_instruction(self, i, offset, size):
		value = core.BNGetStackContentsAfterInstruction(self.handle, i, offset, size)
		result = RegisterValue(self.arch, value)
		core.BNFreeRegisterValue(value)
		return result

	def get_parameter_at(self, arch, addr, func_type, i):
		if func_type is not None:
			func_type = func_type.handle
		value = core.BNGetParameterValueAtInstruction(self.handle, arch.handle, addr, func_type, i)
		result = RegisterValue(arch, value)
		core.BNFreeRegisterValue(value)
		return result

	def get_parameter_at_low_level_il_instruction(self, instr, func_type, i):
		if func_type is not None:
			func_type = func_type.handle
		value = core.BNGetParameterValueAtLowLevelILInstruction(self.handle, instr, func_type, i)
		result = RegisterValue(self.arch, value)
		core.BNFreeRegisterValue(value)
		return result

	def get_regs_read_by(self, arch, addr):
		count = ctypes.c_ulonglong()
		regs = core.BNGetRegistersReadByInstruction(self.handle, arch.handle, addr, count)
		result = []
		for i in xrange(0, count.value):
			result.append(arch.get_reg_name(regs[i]))
		core.BNFreeRegisterList(regs)
		return result

	def get_regs_written_by(self, arch, addr):
		count = ctypes.c_ulonglong()
		regs = core.BNGetRegistersWrittenByInstruction(self.handle, arch.handle, addr, count)
		result = []
		for i in xrange(0, count.value):
			result.append(arch.get_reg_name(regs[i]))
		core.BNFreeRegisterList(regs)
		return result

	def get_stack_vars_referenced_by(self, arch, addr):
		count = ctypes.c_ulonglong()
		refs = core.BNGetStackVariablesReferencedByInstruction(self.handle, arch.handle, addr, count)
		result = []
		for i in xrange(0, count.value):
			result.append(StackVariableReference(refs[i].sourceOperand, bntype.Type(core.BNNewTypeReference(refs[i].type)),
				refs[i].name, refs[i].startingOffset, refs[i].referencedOffset))
		core.BNFreeStackVariableReferenceList(refs, count.value)
		return result

	def get_constants_referenced_by(self, arch, addr):
		count = ctypes.c_ulonglong()
		refs = core.BNGetConstantsReferencedByInstruction(self.handle, arch.handle, addr, count)
		result = []
		for i in xrange(0, count.value):
			result.append(ConstantReference(refs[i].value, refs[i].size))
		core.BNFreeConstantReferenceList(refs)
		return result

	def get_lifted_il_at(self, arch, addr):
		return core.BNGetLiftedILForInstruction(self.handle, arch.handle, addr)

	def get_lifted_il_flag_uses_for_definition(self, i, flag):
		if isinstance(flag, str):
			flag = self.arch._flags[flag]
		count = ctypes.c_ulonglong()
		instrs = core.BNGetLiftedILFlagUsesForDefinition(self.handle, i, flag, count)
		result = []
		for i in xrange(0, count.value):
			result.append(instrs[i])
		core.BNFreeLowLevelILInstructionList(instrs)
		return result

	def get_lifted_il_flag_definitions_for_use(self, i, flag):
		if isinstance(flag, str):
			flag = self.arch._flags[flag]
		count = ctypes.c_ulonglong()
		instrs = core.BNGetLiftedILFlagDefinitionsForUse(self.handle, i, flag, count)
		result = []
		for i in xrange(0, count.value):
			result.append(instrs[i])
		core.BNFreeLowLevelILInstructionList(instrs)
		return result

	def get_flags_read_by_lifted_il_instruction(self, i):
		count = ctypes.c_ulonglong()
		flags = core.BNGetFlagsReadByLiftedILInstruction(self.handle, i, count)
		result = []
		for i in xrange(0, count.value):
			result.append(self.arch._flags_by_index[flags[i]])
		core.BNFreeRegisterList(flags)
		return result

	def get_flags_written_by_lifted_il_instruction(self, i):
		count = ctypes.c_ulonglong()
		flags = core.BNGetFlagsWrittenByLiftedILInstruction(self.handle, i, count)
		result = []
		for i in xrange(0, count.value):
			result.append(self.arch._flags_by_index[flags[i]])
		core.BNFreeRegisterList(flags)
		return result

	def create_graph(self):
		return FunctionGraph(self._view, core.BNCreateFunctionGraph(self.handle))

	def apply_imported_types(self, sym):
		core.BNApplyImportedTypes(self.handle, sym.handle)

	def apply_auto_discovered_type(self, func_type):
		core.BNApplyAutoDiscoveredFunctionType(self.handle, func_type.handle)

	def set_auto_indirect_branches(self, source_arch, source, branches):
		branch_list = (core.BNArchitectureAndAddress * len(branches))()
		for i in xrange(len(branches)):
			branch_list[i].arch = branches[i][0].handle
			branch_list[i].address = branches[i][1]
		core.BNSetAutoIndirectBranches(self.handle, source_arch.handle, source, branch_list, len(branches))

	def set_user_indirect_branches(self, source_arch, source, branches):
		branch_list = (core.BNArchitectureAndAddress * len(branches))()
		for i in xrange(len(branches)):
			branch_list[i].arch = branches[i][0].handle
			branch_list[i].address = branches[i][1]
		core.BNSetUserIndirectBranches(self.handle, source_arch.handle, source, branch_list, len(branches))

	def get_indirect_branches_at(self, arch, addr):
		count = ctypes.c_ulonglong()
		branches = core.BNGetIndirectBranchesAt(self.handle, arch.handle, addr, count)
		result = []
		for i in xrange(0, count.value):
			result.append(IndirectBranchInfo(architecture.Architecture(branches[i].sourceArch), branches[i].sourceAddr, architecture.Architecture(branches[i].destArch), branches[i].destAddr, branches[i].autoDefined))
		core.BNFreeIndirectBranchList(branches)
		return result

	def get_block_annotations(self, arch, addr):
		count = ctypes.c_ulonglong(0)
		lines = core.BNGetFunctionBlockAnnotations(self.handle, arch.handle, addr, count)
		result = []
		for i in xrange(0, count.value):
			tokens = []
			for j in xrange(0, lines[i].count):
				token_type = core.BNInstructionTextTokenType(lines[i].tokens[j].type)
				text = lines[i].tokens[j].text
				value = lines[i].tokens[j].value
				size = lines[i].tokens[j].size
				operand = lines[i].tokens[j].operand
				tokens.append(InstructionTextToken(token_type, text, value, size, operand))
			result.append(tokens)
		core.BNFreeInstructionTextLines(lines, count.value)
		return result

	def set_auto_type(self, value):
		core.BNSetFunctionAutoType(self.handle, value.handle)

	def set_user_type(self, value):
		core.BNSetFunctionUserType(self.handle, value.handle)

	def get_int_display_type(self, arch, instr_addr, value, operand):
		return core.BNGetIntegerConstantDisplayType(self.handle, arch.handle, instr_addr, value, operand)

	def set_int_display_type(self, arch, instr_addr, value, operand, display_type):
		if isinstance(display_type, str):
			display_type = core.BNIntegerDisplayType[display_type]
		core.BNSetIntegerConstantDisplayType(self.handle, arch.handle, instr_addr, value, operand, display_type)

	def reanalyze(self):
		"""
		``reanalyze`` causes this functions to be reanalyzed. This function does not wait for the analysis to finish.

		:rtype: None
		"""
		core.BNReanalyzeFunction(self.handle)

	def request_advanced_analysis_data(self):
		core.BNRequestAdvancedFunctionAnalysisData(self.handle)
		self._advanced_analysis_requests += 1

	def release_advanced_analysis_data(self):
		core.BNReleaseAdvancedFunctionAnalysisData(self.handle)
		self._advanced_analysis_requests -= 1

	def get_basic_block_at(self, arch, addr):
		block = core.BNGetFunctionBasicBlockAtAddress(self.handle, arch.handle, addr)
		if not block:
			return None
		return basicblock.BasicBlock(self._view, handle = block)

	def get_instr_highlight(self, arch, addr):
		color = core.BNGetInstructionHighlight(self.handle, arch.handle, addr)
		if color.style == core.BNHighlightColorStyle.StandardHighlightColor:
			return highlight.HighlightColor(color = color.color, alpha = color.alpha)
		elif color.style == core.BNHighlightColorStyle.MixedHighlightColor:
			return highlight.HighlightColor(color = color.color, mix_color = color.mixColor, mix = color.mix, alpha = color.alpha)
		elif color.style == core.BNHighlightColorStyle.CustomHighlightColor:
			return highlight.HighlightColor(red = color.r, green = color.g, blue = color.b, alpha = color.alpha)
		return highlight.HighlightColor(color = core.BNHighlightStandardColor.NoHighlightColor)

	def set_auto_instr_highlight(self, arch, addr, color):
		if not isinstance(color, highlight.HighlightColor):
			color = highlight.HighlightColor(color = color)
		core.BNSetAutoInstructionHighlight(self.handle, arch.handle, addr, color._get_core_struct())

	def set_user_instr_highlight(self, arch, addr, color):
		if not isinstance(color, highlight.HighlightColor):
			color = highlight.HighlightColor(color = color)
		core.BNSetUserInstructionHighlight(self.handle, arch.handle, addr, color._get_core_struct())


class AdvancedFunctionAnalysisDataRequestor(object):
	def __init__(self, func = None):
		self._function = func
		if self._function is not None:
			self._function.request_advanced_analysis_data()

	def __del__(self):
		if self._function is not None:
			self._function.release_advanced_analysis_data()

	@property
	def function(self):
		return self._function

	@function.setter
	def function(self, func):
		if self._function is not None:
			self._function.release_advanced_analysis_data()
		self._function = func
		if self._function is not None:
			self._function.request_advanced_analysis_data()

	def close(self):
		if self._function is not None:
			self._function.release_advanced_analysis_data()
		self._function = None


class DisassemblyTextLine(object):
	def __init__(self, addr, tokens):
		self.address = addr
		self.tokens = tokens

	def __str__(self):
		result = ""
		for token in self.tokens:
			result += token.text
		return result

	def __repr__(self):
		return "<%#x: %s>" % (self.address, str(self))


class FunctionGraphEdge:
	def __init__(self, branch_type, arch, target, points):
		self.type = branch_type
		self.arch = arch
		self.target = target
		self.points = points

	def __repr__(self):
		if self.arch:
			return "<%s: %s@%#x>" % (self.type.name, self.arch.name, self.target)
		return "<%s: %#x>" % (self.type, self.target)


class FunctionGraphBlock(object):
	def __init__(self, handle):
		self.handle = handle

	def __del__(self):
		core.BNFreeFunctionGraphBlock(self.handle)

	@property
	def basic_block(self):
		"""Basic block associated with this part of the funciton graph (read-only)"""
		block = core.BNGetFunctionGraphBasicBlock(self.handle)
		func = core.BNGetBasicBlockFunction(block)
		if func is None:
			core.BNFreeBasicBlock(block)
			block = None
		else:
			block = basicblock.BasicBlock(binaryview.BinaryView(handle = core.BNGetFunctionData(func)), block)
			core.BNFreeFunction(func)
		return block

	@property
	def arch(self):
		"""Function graph block architecture (read-only)"""
		arch = core.BNGetFunctionGraphBlockArchitecture(self.handle)
		if arch is None:
			return None
		return architecture.Architecture(arch)

	@property
	def start(self):
		"""Function graph block start (read-only)"""
		return core.BNGetFunctionGraphBlockStart(self.handle)

	@property
	def end(self):
		"""Function graph block end (read-only)"""
		return core.BNGetFunctionGraphBlockEnd(self.handle)

	@property
	def x(self):
		"""Function graph block X (read-only)"""
		return core.BNGetFunctionGraphBlockX(self.handle)

	@property
	def y(self):
		"""Function graph block Y (read-only)"""
		return core.BNGetFunctionGraphBlockY(self.handle)

	@property
	def width(self):
		"""Function graph block width (read-only)"""
		return core.BNGetFunctionGraphBlockWidth(self.handle)

	@property
	def height(self):
		"""Function graph block height (read-only)"""
		return core.BNGetFunctionGraphBlockHeight(self.handle)

	@property
	def lines(self):
		"""Function graph block list of lines (read-only)"""
		count = ctypes.c_ulonglong()
		lines = core.BNGetFunctionGraphBlockLines(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			addr = lines[i].addr
			tokens = []
			for j in xrange(0, lines[i].count):
				token_type = core.BNInstructionTextTokenType(lines[i].tokens[j].type)
				text = lines[i].tokens[j].text
				value = lines[i].tokens[j].value
				size = lines[i].tokens[j].size
				operand = lines[i].tokens[j].operand
				tokens.append(InstructionTextToken(token_type, text, value, size, operand))
			result.append(DisassemblyTextLine(addr, tokens))
		core.BNFreeDisassemblyTextLines(lines, count.value)
		return result

	@property
	def outgoing_edges(self):
		"""Function graph block list of outgoing edges (read-only)"""
		count = ctypes.c_ulonglong()
		edges = core.BNGetFunctionGraphBlockOutgoingEdges(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			branch_type = core.BNBranchType(edges[i].type)
			target = edges[i].target
			arch = None
			if edges[i].arch is not None:
				arch = architecture.Architecture(edges[i].arch)
			points = []
			for j in xrange(0, edges[i].pointCount):
				points.append((edges[i].points[j].x, edges[i].points[j].y))
			result.append(FunctionGraphEdge(branch_type, arch, target, points))
		core.BNFreeFunctionGraphBlockOutgoingEdgeList(edges, count.value)
		return result

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self, name, value)
		except AttributeError:
			raise AttributeError("attribute '%s' is read only" % name)

	def __repr__(self):
		arch = self.arch
		if arch:
			return "<graph block: %s@%#x-%#x>" % (arch.name, self.start, self.end)
		else:
			return "<graph block: %#x-%#x>" % (self.start, self.end)

	def __iter__(self):
		count = ctypes.c_ulonglong()
		lines = core.BNGetFunctionGraphBlockLines(self.handle, count)
		try:
			for i in xrange(0, count.value):
				addr = lines[i].addr
				tokens = []
				for j in xrange(0, lines[i].count):
					token_type = core.BNInstructionTextTokenType(lines[i].tokens[j].type)
					text = lines[i].tokens[j].text
					value = lines[i].tokens[j].value
					size = lines[i].tokens[j].size
					operand = lines[i].tokens[j].operand
					tokens.append(InstructionTextToken(token_type, text, value, size, operand))
				yield DisassemblyTextLine(addr, tokens)
		finally:
			core.BNFreeDisassemblyTextLines(lines, count.value)


class DisassemblySettings(object):
	def __init__(self, handle = None):
		if handle is None:
			self.handle = core.BNCreateDisassemblySettings()
		else:
			self.handle = handle

	def __del__(self):
		core.BNFreeDisassemblySettings(self.handle)

	@property
	def width(self):
		return core.BNGetDisassemblyWidth(self.handle)

	@width.setter
	def width(self, value):
		core.BNSetDisassemblyWidth(self.handle, value)

	@property
	def max_symbol_width(self):
		return core.BNGetDisassemblyMaximumSymbolWidth(self.handle)

	@max_symbol_width.setter
	def max_symbol_width(self, value):
		core.BNSetDisassemblyMaximumSymbolWidth(self.handle, value)

	def is_option_set(self, option):
		if isinstance(option, str):
			option = core.BNDisassemblyOption[option]
		return core.BNIsDisassemblySettingsOptionSet(self.handle, option)

	def set_option(self, option, state = True):
		if isinstance(option, str):
			option = core.BNDisassemblyOption[option]
		core.BNSetDisassemblySettingsOption(self.handle, option, state)


class FunctionGraph(object):
	def __init__(self, view, handle):
		self.view = view
		self.handle = handle
		self._on_complete = None
		self._cb = ctypes.CFUNCTYPE(None, ctypes.c_void_p)(self._complete)

	def __del__(self):
		self.abort()
		core.BNFreeFunctionGraph(self.handle)

	@property
	def function(self):
		"""Function for a function graph (read-only)"""
		func = core.BNGetFunctionForFunctionGraph(self.handle)
		if func is None:
			return None
		return Function(self.view, func)

	@property
	def complete(self):
		"""Whether function graph layout is complete (read-only)"""
		return core.BNIsFunctionGraphLayoutComplete(self.handle)

	@property
	def type(self):
		"""Function graph type (read-only)"""
		return core.BNFunctionGraphType(core.BNGetFunctionGraphType(self.handle))

	@property
	def blocks(self):
		"""List of basic blocks in function (read-only)"""
		count = ctypes.c_ulonglong()
		blocks = core.BNGetFunctionGraphBlocks(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			result.append(FunctionGraphBlock(core.BNNewFunctionGraphBlockReference(blocks[i])))
		core.BNFreeFunctionGraphBlockList(blocks, count.value)
		return result

	@property
	def width(self):
		"""Function graph width (read-only)"""
		return core.BNGetFunctionGraphWidth(self.handle)

	@property
	def height(self):
		"""Function graph height (read-only)"""
		return core.BNGetFunctionGraphHeight(self.handle)

	@property
	def horizontal_block_margin(self):
		return core.BNGetHorizontalFunctionGraphBlockMargin(self.handle)

	@horizontal_block_margin.setter
	def horizontal_block_margin(self, value):
		core.BNSetFunctionGraphBlockMargins(self.handle, value, self.vertical_block_margin)

	@property
	def vertical_block_margin(self):
		return core.BNGetVerticalFunctionGraphBlockMargin(self.handle)

	@vertical_block_margin.setter
	def vertical_block_margin(self, value):
		core.BNSetFunctionGraphBlockMargins(self.handle, self.horizontal_block_margin, value)

	@property
	def settings(self):
		return DisassemblySettings(core.BNGetFunctionGraphSettings(self.handle))

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self, name, value)
		except AttributeError:
			raise AttributeError("attribute '%s' is read only" % name)

	def __repr__(self):
		return "<graph of %s>" % repr(self.function)

	def __iter__(self):
		count = ctypes.c_ulonglong()
		blocks = core.BNGetFunctionGraphBlocks(self.handle, count)
		try:
			for i in xrange(0, count.value):
				yield FunctionGraphBlock(core.BNNewFunctionGraphBlockReference(blocks[i]))
		finally:
			core.BNFreeFunctionGraphBlockList(blocks, count.value)

	def _complete(self, ctxt):
		try:
			if self._on_complete is not None:
				self._on_complete()
		except:
			log.log_error(traceback.format_exc())

	def layout(self, graph_type = core.BNFunctionGraphType.NormalFunctionGraph):
		if isinstance(graph_type, str):
			graph_type = core.BNFunctionGraphType[graph_type]
		core.BNStartFunctionGraphLayout(self.handle, graph_type)

	def _wait_complete(self):
		self._wait_cond.acquire()
		self._wait_cond.notify()
		self._wait_cond.release()

	def layout_and_wait(self, graph_type = core.BNFunctionGraphType.NormalFunctionGraph):
		self._wait_cond = threading.Condition()
		self.on_complete(self._wait_complete)
		self.layout(graph_type)

		self._wait_cond.acquire()
		while not self.complete:
			self._wait_cond.wait()
		self._wait_cond.release()

	def on_complete(self, callback):
		self._on_complete = callback
		core.BNSetFunctionGraphCompleteCallback(self.handle, None, self._cb)

	def abort(self):
		core.BNAbortFunctionGraph(self.handle)

	def get_blocks_in_region(self, left, top, right, bottom):
		count = ctypes.c_ulonglong()
		blocks = core.BNGetFunctionGraphBlocksInRegion(self.handle, left, top, right, bottom, count)
		result = []
		for i in xrange(0, count.value):
			result.append(FunctionGraphBlock(core.BNNewFunctionGraphBlockReference(blocks[i])))
		core.BNFreeFunctionGraphBlockList(blocks, count.value)
		return result

	def is_option_set(self, option):
		if isinstance(option, str):
			option = core.BNDisassemblyOption[option]
		return core.BNIsFunctionGraphOptionSet(self.handle, option)

	def set_option(self, option, state = True):
		if isinstance(option, str):
			option = core.BNDisassemblyOption[option]
		core.BNSetFunctionGraphOption(self.handle, option, state)


class RegisterInfo(object):
	def __init__(self, full_width_reg, size, offset = 0, extend = core.BNImplicitRegisterExtend.NoExtend, index = None):
		self.full_width_reg = full_width_reg
		self.offset = offset
		self.size = size
		self.extend = extend
		self.index = index

	def __repr__(self):
		if self.extend == core.BNImplicitRegisterExtend.ZeroExtendToFullWidth:
			extend = ", zero extend"
		elif self.extend == core.BNImplicitRegisterExtend.SignExtendToFullWidth:
			extend = ", sign extend"
		else:
			extend = ""
		return "<reg: size %d, offset %d in %s%s>" % (self.size, self.offset, self.full_width_reg, extend)


class InstructionBranch(object):
	def __init__(self, branch_type, target = 0, arch = None):
		self.type = branch_type
		self.target = target
		self.arch = arch

	def __repr__(self):
		branch_type = self.type
		if self.arch is not None:
			return "<%s: %s@%#x>" % (branch_type.name, self.arch.name, self.target)
		return "<%s: %#x>" % (branch_type, self.target)


class InstructionInfo(object):
	def __init__(self):
		self.length = 0
		self.branch_delay = False
		self.branches = []

	def add_branch(self, branch_type, target = 0, arch = None):
		self.branches.append(InstructionBranch(branch_type, target, arch))

	def __repr__(self):
		branch_delay = ""
		if self.branch_delay:
			branch_delay = ", delay slot"
		return "<instr: %d bytes%s, %s>" % (self.length, branch_delay, repr(self.branches))


class InstructionTextToken(object):
	"""
	``class InstructionTextToken`` is used to tell the core about the various components in the disassembly views.

		========================== ============================================
		BNInstructionTextTokenType Description
		========================== ============================================
		TextToken                  Text that doesn't fit into the other tokens
		InstructionToken           The instruction mnemonic
		OperandSeparatorToken      The comma or whatever else separates tokens
		RegisterToken              Registers
		IntegerToken               Integers
		PossibleAddressToken       Integers that are likely addresses
		BeginMemoryOperandToken    The start of memory operand
		EndMemoryOperandToken      The end of a memory operand
		FloatingPointToken         Floating point number
		AnnotationToken            **For internal use only**
		CodeRelativeAddressToken   **For internal use only**
		StackVariableTypeToken     **For internal use only**
		DataVariableTypeToken      **For internal use only**
		FunctionReturnTypeToken    **For internal use only**
		FunctionAttributeToken     **For internal use only**
		ArgumentTypeToken          **For internal use only**
		ArgumentNameToken          **For internal use only**
		HexDumpByteValueToken      **For internal use only**
		HexDumpSkippedByteToken    **For internal use only**
		HexDumpInvalidByteToken    **For internal use only**
		HexDumpTextToken           **For internal use only**
		OpcodeToken                **For internal use only**
		StringToken                **For internal use only**
		CharacterConstantToken     **For internal use only**
		CodeSymbolToken            **For internal use only**
		DataSymbolToken            **For internal use only**
		StackVariableToken         **For internal use only**
		ImportToken                **For internal use only**
		AddressDisplayToken        **For internal use only**
		========================== ============================================

	"""
	def __init__(self, token_type, text, value = 0, size = 0, operand = 0xffffffff):
		self.type = token_type
		self.text = text
		self.value = value
		self.size = size
		self.operand = operand

	def __str__(self):
		return self.text

	def __repr__(self):
		return repr(self.text)
