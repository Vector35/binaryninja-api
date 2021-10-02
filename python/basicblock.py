# Copyright (c) 2015-2021 Vector 35 Inc
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
from dataclasses import dataclass
from typing import Generator, Optional, List, Tuple

# Binary Ninja components
from . import _binaryninjacore as core
from .enums import BranchType, HighlightStandardColor
from . import binaryview
from . import architecture
from . import highlight as _highlight
from . import function as _function

@dataclass(frozen=True)
class BasicBlockEdge:
	type:BranchType
	source:'BasicBlock'
	target:'BasicBlock'
	back_edge:bool
	fall_through:bool

	def __repr__(self):
		if self.type == BranchType.UnresolvedBranch:
			return f"<{self.type.name}>"
		elif self.target.arch:
			return f"<{self.type.name}: {self.target.arch.name}@{self.target.start:#x}>"
		else:
			return f"<{self.type.name}: {self.target.start:#x}>"


class BasicBlock:
	def __init__(self, handle:core.BNBasicBlockHandle, view:Optional['binaryview.BinaryView']=None):
		self._view = view
		_handle = core.BNBasicBlockHandle
		self.handle:core.BNBasicBlockHandle = ctypes.cast(handle, _handle)
		self._arch = None
		self._func = None
		self._instStarts:Optional[List[int]] = None
		self._instLengths:Optional[List[int]] = None

	def __del__(self):
		if core is not None:
			core.BNFreeBasicBlock(self.handle)

	def __repr__(self):
		arch = self.arch
		if arch:
			return f"<block: {arch.name}@{self.start:#x}-{self.end:#x}>"
		else:
			return f"<block: {self.start:#x}-{self.end:#x}>"

	def __len__(self):
		return int(core.BNGetBasicBlockLength(self.handle))

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(other.handle.contents)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash((self.start, self.end, self.arch))

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self, name, value)
		except AttributeError:
			raise AttributeError(f"attribute '{name}' is read only")

	def __iter__(self) -> Generator[Tuple[List['_function.InstructionTextToken'], int], None, None]:
		if self.arch is None:
			raise Exception("Attempting to iterate a BasicBlock object with no Architecture set")
		if self.view is None:
			raise Exception("Attempting to iterate a Basic Block with no BinaryView")
		if self._instStarts is None:
			# don't add instruction start cache--the object is likely ephemeral
			idx = self.start
			while idx < self.end:
				data = self.view.read(idx, min(self.arch.max_instr_length, self.end - idx))
				text, size = self.arch.get_instruction_text(data, idx)
				if size == 0:
					break
				yield text, size
				idx += size
		else:
			assert self._instLengths is not None
			for start, length in zip(self._instStarts, self._instLengths):
				text, size = self.arch.get_instruction_text(self.view.read(start, length), start)
				if size == 0:
					break
				yield text, size

	def __getitem__(self, i):
		self._buildStartCache()
		assert self._instStarts is not None
		assert self._instLengths is not None
		if self.arch is None:
			raise Exception("Attempting to iterate a BasicBlock object with no Architecture set")
		if self.view is None:
			raise Exception("Attempting to iterate a Basic Block with no BinaryView")

		if isinstance(i, slice):
			return [self[index] for index in range(*i.indices(len(self._instStarts)))]
		start = self._instStarts[i]
		length = self._instLengths[i]
		data = self.view.read(start, length)
		return self.arch.get_instruction_text(data, start)

	def __contains__(self, i:int):
		return i >= self.start and i < self.end

	def _buildStartCache(self) -> None:
		if self._instStarts is None:
			# build the instruction start cache
			if self.view is None:
				raise Exception("Attempting to buildStartCache when BinaryView for BasicBlock is None")
			self._instStarts = []
			self._instLengths = []
			start = self.start
			while start < self.end:
				length = self.view.get_instruction_length(start, self.arch)
				if length == 0: # invalid instruction. avoid infinite loop
					break
				self._instLengths.append(length)
				self._instStarts.append(start)
				start += length

	def _create_instance(self, handle:core.BNBasicBlockHandle, view:'binaryview.BinaryView') -> 'BasicBlock':
		"""Internal method used to instantiate child instances"""
		return BasicBlock(handle, view)

	@property
	def instruction_count(self) -> int:
		self._buildStartCache()
		assert self._instStarts is not None
		return len(self._instStarts)

	@property
	def function(self) -> Optional['_function.Function']:
		"""Basic block function (read-only)"""
		if self._func is not None:
			return self._func
		func = core.BNGetBasicBlockFunction(self.handle)
		if func is None:
			return None
		self._func = _function.Function(self._view, func)
		return self._func

	@property
	def view(self) -> Optional['binaryview.BinaryView']:
		"""BinaryView that contains the basic block (read-only)"""
		if self._view is not None:
			return self._view
		if self.function is None:
			return None
		self._view = self.function.view
		return self._view

	@property
	def arch(self) -> Optional['architecture.Architecture']:
		"""Basic block architecture (read-only)"""
		# The arch for a BasicBlock isn't going to change so just cache
		# it the first time we need it
		if self._arch is not None:
			return self._arch
		arch = core.BNGetBasicBlockArchitecture(self.handle)
		if arch is None:
			return None
		self._arch = architecture.CoreArchitecture._from_cache(arch)
		return self._arch

	@property
	def source_block(self) -> Optional['BasicBlock']:
		"""Basic block source block (read-only)"""
		block = core.BNGetBasicBlockSource(self.handle)
		if block is None:
			return None
		return BasicBlock(block, self._view)

	@property
	def start(self) -> int:
		"""Basic block start (read-only)"""
		return core.BNGetBasicBlockStart(self.handle)

	@property
	def end(self) -> int:
		"""Basic block end (read-only)"""
		return core.BNGetBasicBlockEnd(self.handle)

	@property
	def length(self) -> int:
		"""Basic block length (read-only)"""
		return core.BNGetBasicBlockLength(self.handle)

	@property
	def index(self) -> int:
		"""Basic block index in list of blocks for the function (read-only)"""
		return core.BNGetBasicBlockIndex(self.handle)

	@property
	def outgoing_edges(self) -> List[BasicBlockEdge]:
		"""List of basic block outgoing edges (read-only)"""
		if self.view is None:
			raise Exception("Attempting to call BasicBlock.outgoing_edges when BinaryView is None")
		count = ctypes.c_ulonglong(0)
		edges = core.BNGetBasicBlockOutgoingEdges(self.handle, count)
		assert edges is not None, "core.BNGetBasicBlockOutgoingEdges returned None"
		result = []
		try:
			for i in range(0, count.value):
				branch_type = BranchType(edges[i].type)
				handle = core.BNNewBasicBlockReference(edges[i].target)
				assert handle is not None
				target = self._create_instance(handle, self.view)
				result.append(BasicBlockEdge(branch_type, self, target, edges[i].backEdge, edges[i].fallThrough))
			return result
		finally:
			core.BNFreeBasicBlockEdgeList(edges, count.value)

	@property
	def incoming_edges(self) -> List[BasicBlockEdge]:
		"""List of basic block incoming edges (read-only)"""
		count = ctypes.c_ulonglong(0)
		if self.view is None:
			raise Exception("Attempting to buildStartCache when BinaryView for BasicBlock is None")

		edges = core.BNGetBasicBlockIncomingEdges(self.handle, count)
		assert edges is not None, "core.BNGetBasicBlockIncomingEdges returned None"
		result = []
		try:
			for i in range(0, count.value):
				branch_type = BranchType(edges[i].type)
				handle = core.BNNewBasicBlockReference(edges[i].target)
				assert handle is not None
				target = self._create_instance(handle, self.view)
				result.append(BasicBlockEdge(branch_type, target, self, edges[i].backEdge, edges[i].fallThrough))
			return result
		finally:
			core.BNFreeBasicBlockEdgeList(edges, count.value)

	@property
	def has_undetermined_outgoing_edges(self) -> bool:
		"""Whether basic block has undetermined outgoing edges (read-only)"""
		return core.BNBasicBlockHasUndeterminedOutgoingEdges(self.handle)

	@property
	def can_exit(self) -> bool:
		"""Whether basic block can return or is tagged as 'No Return' (read-only)"""
		return core.BNBasicBlockCanExit(self.handle)

	@can_exit.setter
	def can_exit(self, value:bool) -> None:
		"""Sets whether basic block can return or is tagged as 'No Return'"""
		core.BNBasicBlockSetCanExit(self.handle, value)

	@property
	def has_invalid_instructions(self) -> bool:
		"""Whether basic block has any invalid instructions (read-only)"""
		return core.BNBasicBlockHasInvalidInstructions(self.handle)

	@property
	def dominators(self) -> List['BasicBlock']:
		"""List of dominators for this basic block (read-only)"""
		if self.view is None:
			raise Exception("Attempting to call BasicBlock.dominators when BinaryView is None")
		count = ctypes.c_ulonglong()
		blocks = core.BNGetBasicBlockDominators(self.handle, count, False)
		assert blocks is not None, "core.BNGetBasicBlockDominators returned None"
		result = []
		try:
			for i in range(0, count.value):
				handle = core.BNNewBasicBlockReference(blocks[i])
				assert handle is not None
				result.append(self._create_instance(handle, self.view))
			return result
		finally:
			core.BNFreeBasicBlockList(blocks, count.value)

	@property
	def post_dominators(self) -> List['BasicBlock']:
		"""List of dominators for this basic block (read-only)"""
		if self.view is None:
					raise Exception("Attempting to call BasicBlock.post_dominators when BinaryView is None")
		count = ctypes.c_ulonglong()
		blocks = core.BNGetBasicBlockDominators(self.handle, count, True)
		assert blocks is not None, "core.BNGetBasicBlockDominators returned None"
		result = []
		try:
			for i in range(0, count.value):
				handle = core.BNNewBasicBlockReference(blocks[i])
				assert handle is not None, "core.BNNewBasicBlockReference returned None"
				result.append(self._create_instance(handle, self.view))
			return result
		finally:
			core.BNFreeBasicBlockList(blocks, count.value)

	@property
	def strict_dominators(self) -> List['BasicBlock']:
		"""List of strict dominators for this basic block (read-only)"""
		if self.view is None:
			raise Exception("Attempting to call BasicBlock.strict_dominators when BinaryView is None")
		count = ctypes.c_ulonglong()
		blocks = core.BNGetBasicBlockStrictDominators(self.handle, count, False)
		assert blocks is not None, "core.BNGetBasicBlockStrictDominators returned None"
		result = []
		try:
			for i in range(0, count.value):
				handle = core.BNNewBasicBlockReference(blocks[i])
				assert handle is not None
				result.append(self._create_instance(handle, self.view))
			return result
		finally:
			core.BNFreeBasicBlockList(blocks, count.value)

	@property
	def immediate_dominator(self) -> Optional['BasicBlock']:
		"""Immediate dominator of this basic block (read-only)"""
		if self.view is None:
			raise Exception("Attempting to call BasicBlock.immediate_dominator when BinaryView is None")

		result = core.BNGetBasicBlockImmediateDominator(self.handle, False)
		if not result:
			return None
		return self._create_instance(result, self.view)

	@property
	def immediate_post_dominator(self) -> Optional['BasicBlock']:
		"""Immediate dominator of this basic block (read-only)"""
		if self.view is None:
			raise Exception("Attempting to call BasicBlock.immediate_post_dominator when BinaryView is None")

		result = core.BNGetBasicBlockImmediateDominator(self.handle, True)
		if not result:
			return None
		return self._create_instance(result, self.view)

	@property
	def dominator_tree_children(self) -> List['BasicBlock']:
		"""List of child blocks in the dominator tree for this basic block (read-only)"""
		if self.view is None:
			raise Exception("Attempting to call BasicBlock.dominator_tree_children when BinaryView is None")

		count = ctypes.c_ulonglong()
		blocks = core.BNGetBasicBlockDominatorTreeChildren(self.handle, count, False)
		assert blocks is not None, "core.BNGetBasicBlockDominatorTreeChildren returned None"
		result = []
		try:
			for i in range(0, count.value):
				handle = core.BNNewBasicBlockReference(blocks[i])
				assert handle is not None
				result.append(self._create_instance(handle, self.view))
			return result
		finally:
			core.BNFreeBasicBlockList(blocks, count.value)

	@property
	def post_dominator_tree_children(self) -> List['BasicBlock']:
		"""List of child blocks in the post dominator tree for this basic block (read-only)"""
		if self.view is None:
			raise Exception("Attempting to call BasicBlock.post_dominator_tree_children when BinaryView is None")

		count = ctypes.c_ulonglong()
		blocks = core.BNGetBasicBlockDominatorTreeChildren(self.handle, count, True)
		assert blocks is not None, "core.BNGetBasicBlockDominatorTreeChildren returned None"
		result = []
		try:
			for i in range(0, count.value):
				handle = core.BNNewBasicBlockReference(blocks[i])
				assert handle is not None
				result.append(self._create_instance(handle, self.view))
			return result
		finally:
			core.BNFreeBasicBlockList(blocks, count.value)

	@property
	def dominance_frontier(self) -> List['BasicBlock']:
		"""Dominance frontier for this basic block (read-only)"""
		if self.view is None:
			raise Exception("Attempting to call BasicBlock.dominance_frontier when BinaryView is None")

		count = ctypes.c_ulonglong()
		blocks = core.BNGetBasicBlockDominanceFrontier(self.handle, count, False)
		assert blocks is not None, "core.BNGetBasicBlockDominanceFrontier returned None"
		result = []
		try:
			for i in range(0, count.value):
				handle = core.BNNewBasicBlockReference(blocks[i])
				assert handle is not None
				result.append(self._create_instance(handle, self.view))
			return result
		finally:
			core.BNFreeBasicBlockList(blocks, count.value)

	@property
	def post_dominance_frontier(self) -> List['BasicBlock']:
		"""Post dominance frontier for this basic block (read-only)"""
		if self.view is None:
			raise Exception("Attempting to call BasicBlock.post_dominance_frontier when BinaryView is None")
		count = ctypes.c_ulonglong()
		blocks = core.BNGetBasicBlockDominanceFrontier(self.handle, count, True)
		assert blocks is not None, "core.BNGetBasicBlockDominanceFrontier returned None"
		result = []
		try:
			for i in range(0, count.value):
				handle = core.BNNewBasicBlockReference(blocks[i])
				assert handle is not None
				result.append(self._create_instance(handle, self.view))
			return result
		finally:
			core.BNFreeBasicBlockList(blocks, count.value)

	@property
	def annotations(self) -> List[List['_function.InstructionTextToken']]:
		"""List of automatic annotations for the start of this block (read-only)"""
		assert self.arch is not None, "attempting to get annotation from BasicBlock without architecture"
		if self.function is None:
			raise Exception("Attempting to call BasicBlock.annotations when BinaryView is None")

		return self.function.get_block_annotations(self.start, self.arch)

	@property
	def disassembly_text(self) -> List['_function.DisassemblyTextLine']:
		"""
		``disassembly_text`` property which returns a list of function.DisassemblyTextLine objects for the current basic block.
		:Example:

			>>> current_basic_block.disassembly_text
			[<0x100000f30: _main:>, ...]
		"""
		return self.get_disassembly_text()

	@property
	def highlight(self) -> '_highlight.HighlightColor':
		"""Gets or sets the highlight color for basic block

		:Example:

			>>> current_basic_block.highlight = HighlightStandardColor.BlueHighlightColor
			>>> current_basic_block.highlight
			<color: blue>
		"""
		return _highlight.HighlightColor._from_core_struct(core.BNGetBasicBlockHighlight(self.handle))

	@highlight.setter
	def highlight(self, value:'_highlight.HighlightColor') -> None:
		self.set_user_highlight(value)

	@property
	def is_il(self) -> bool:
		"""Whether the basic block contains IL"""
		return core.BNIsILBasicBlock(self.handle)

	@property
	def is_low_level_il(self) -> bool:
		"""Whether the basic block contains Low Level IL"""
		return core.BNIsLowLevelILBasicBlock(self.handle)

	@property
	def is_medium_level_il(self) -> bool:
		"""Whether the basic block contains Medium Level IL"""
		return core.BNIsMediumLevelILBasicBlock(self.handle)

	@property
	def is_high_level_il(self) -> bool:
		"""Whether the basic block contains High Level IL"""
		return core.BNIsHighLevelILBasicBlock(self.handle)

	@staticmethod
	def get_iterated_dominance_frontier(blocks:List['BasicBlock']) -> List['BasicBlock']:
		if len(blocks) == 0:
			return []
		block_set = (ctypes.POINTER(core.BNBasicBlock) * len(blocks))() # type: ignore
		for i in range(len(blocks)):
			block_set[i] = blocks[i].handle
		count = ctypes.c_ulonglong()
		out_blocks = core.BNGetBasicBlockIteratedDominanceFrontier(block_set, len(blocks), count)
		assert out_blocks is not None, "core.BNGetBasicBlockIteratedDominanceFrontier returned None"
		result = []
		try:
			for i in range(0, count.value):
				handle = core.BNNewBasicBlockReference(out_blocks[i])
				assert handle is not None
				result.append(BasicBlock(handle, blocks[0].view))
			return result
		finally:
			core.BNFreeBasicBlockList(out_blocks, count.value)

	def mark_recent_use(self) -> None:
		core.BNMarkBasicBlockAsRecentlyUsed(self.handle)

	def get_disassembly_text(self, settings:'_function.DisassemblySettings'=None) -> List['_function.DisassemblyTextLine']:
		"""
		``get_disassembly_text`` returns a list of DisassemblyTextLine objects for the current basic block.

		:param DisassemblySettings settings: (optional) DisassemblySettings object
		:Example:

			>>> current_basic_block.get_disassembly_text()
			[<0x100000f30: _main:>, <0x100000f30: push    rbp>, ... ]
		"""
		settings_obj = None
		if settings:
			settings_obj = settings.handle

		count = ctypes.c_ulonglong()
		lines = core.BNGetBasicBlockDisassemblyText(self.handle, settings_obj, count)
		assert lines is not None, "core.BNGetBasicBlockDisassemblyText returned None"
		result = []
		try:
			for i in range(0, count.value):
				addr = lines[i].addr
				if (lines[i].instrIndex != 0xffffffffffffffff) and hasattr(self, 'il_function'):
					il_instr = self.il_function[lines[i].instrIndex] # type: ignore
				else:
					il_instr = None
				color = _highlight.HighlightColor._from_core_struct(lines[i].highlight)
				tokens = _function.InstructionTextToken._from_core_struct(lines[i].tokens, lines[i].count)
				result.append(_function.DisassemblyTextLine(tokens, addr, il_instr, color))
			return result
		finally:
			core.BNFreeDisassemblyTextLines(lines, count.value)

	def set_auto_highlight(self, color:'_highlight.HighlightColor') -> None:
		"""
		``set_auto_highlight`` highlights the current BasicBlock with the supplied color.

		.. warning:: Use only in analysis plugins. Do not use in regular plugins, as colors won't be saved to the database.

		:param HighlightStandardColor or HighlightColor color: Color value to use for highlighting
		"""
		if not isinstance(color, HighlightStandardColor) and not isinstance(color, _highlight.HighlightColor):
			raise ValueError("Specified color is not one of HighlightStandardColor, HighlightColor")
		if isinstance(color, HighlightStandardColor):
			color = _highlight.HighlightColor(color)
		core.BNSetAutoBasicBlockHighlight(self.handle, color._to_core_struct())

	def set_user_highlight(self, color:'_highlight.HighlightColor') -> None:
		"""
		``set_user_highlight`` highlights the current BasicBlock with the supplied color

		:param HighlightStandardColor or HighlightColor color: Color value to use for highlighting
		:Example:

			>>> current_basic_block.set_user_highlight(HighlightColor(red=0xff, blue=0xff, green=0))
			>>> current_basic_block.set_user_highlight(HighlightStandardColor.BlueHighlightColor)
		"""
		if not isinstance(color, HighlightStandardColor) and not isinstance(color, _highlight.HighlightColor):
			raise ValueError("Specified color is not one of HighlightStandardColor, HighlightColor")
		if isinstance(color, HighlightStandardColor):
			color = _highlight.HighlightColor(color)
		core.BNSetUserBasicBlockHighlight(self.handle, color._to_core_struct())

	def get_instruction_containing_address(self, addr:int) -> Tuple[bool, int]:
		start = ctypes.c_uint64()
		ret:bool = core.BNGetBasicBlockInstructionContainingAddress(self.handle, addr, start)
		return ret, start.value
