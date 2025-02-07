# Copyright (c) 2015-2024 Vector 35 Inc
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
import binaryninja
from . import _binaryninjacore as core
from .enums import BranchType, HighlightStandardColor
from . import binaryview
from . import architecture
from . import highlight as _highlight
from . import function as _function


@dataclass(frozen=True)
class BasicBlockEdge:
	"""
	``class BasicBlockEdge`` represents the edges that connect basic blocks in graph view.

	:cvar type: The :py:meth:`enums.BranchType` of the edge; Whether the edge is a true branch, false branch, unconditional, etc.
	:cvar source: The basic block that the edge originates from.
	:cvar target: The basic block that the edge is going to.
	:cvar backedge: Whether this edge targets to a node whose control flow can eventually flow back through the source node of this edge.
	:Example:

	>>> current_basic_block.outgoing_edges
	[<TrueBranch: x86_64@0x6>, <FalseBranch: x86_64@0x1f>]
	"""
	type: BranchType
	source: 'BasicBlock'
	target: 'BasicBlock'
	back_edge: bool
	fall_through: bool

	def __repr__(self):
		if self.type == BranchType.UnresolvedBranch:
			return f"<{self.type.name}>"
		elif self.target.arch:
			return f"<{self.type.name}: {self.target.arch.name}@{self.target.start:#x}>"
		else:
			return f"<{self.type.name}: {self.target.start:#x}>"


class BasicBlock:
	"""
	The ``class BasicBlock`` object is returned during analysis and should not be directly instantiated.

	Basic blocks contain a sequence of instructions that must execute in-order with no branches.
	We include calls in basic blocks, which technically violates that assumption, but you can mark
	functions as `func.can_return = False` if a given function should terminate basic blocks.
	:Example:

	>>> for func in bv.functions:
	>>>   for bb in func:
	>>>     # Any block-based analysis could start here
	>>>     for inst in bb:
	>>>       pass # Optionally do something here with instructions
	"""
	def __init__(self, handle: core.BNBasicBlockHandle, view: Optional['binaryview.BinaryView'] = None):
		self._view = view
		_handle = core.BNBasicBlockHandle
		self.handle: core.BNBasicBlockHandle = ctypes.cast(handle, _handle)
		self._arch = None
		self._func = None
		self._instStarts: Optional[List[int]] = None
		self._instLengths: Optional[List[int]] = None

	def __del__(self):
		if core is not None:
			core.BNFreeBasicBlock(self.handle)

	@classmethod
	def _from_core_block(cls, block: core.BNBasicBlockHandle) -> Optional['BasicBlock']:
		"""From a BNBasicBlockHandle, get a BasicBlock or one of the IL subclasses (takes ref)"""
		func_handle = core.BNGetBasicBlockFunction(block)
		if not func_handle:
			core.BNFreeBasicBlock(block)
			return None

		view = binaryview.BinaryView(handle=core.BNGetFunctionData(func_handle))
		func = _function.Function(view, func_handle)

		if core.BNIsLowLevelILBasicBlock(block):
			return binaryninja.lowlevelil.LowLevelILBasicBlock(
				block, binaryninja.lowlevelil.LowLevelILFunction(func.arch, core.BNGetBasicBlockLowLevelILFunction(block), func),
				view
			)
		elif core.BNIsMediumLevelILBasicBlock(block):
			mlil_func = binaryninja.mediumlevelil.MediumLevelILFunction(
				func.arch, core.BNGetBasicBlockMediumLevelILFunction(block), func
			)
			return binaryninja.mediumlevelil.MediumLevelILBasicBlock(block, mlil_func, view)
		elif core.BNIsHighLevelILBasicBlock(block):
			hlil_func = binaryninja.highlevelil.HighLevelILFunction(func.arch, core.BNGetBasicBlockHighLevelILFunction(block), func)
			return binaryninja.highlevelil.HighLevelILBasicBlock(block, hlil_func, view)
		else:
			return BasicBlock(block, view)

	def __repr__(self):
		arch = self.arch
		if arch:
			return f"<{self.__class__.__name__}: {arch.name}@{self.start:#x}-{self.end:#x}>"
		else:
			return f"<{self.__class__.__name__}: {self.start:#x}-{self.end:#x}>"

	def __len__(self):
		return int(core.BNGetBasicBlockLength(self.handle))

	def __lt__(self, other: 'BasicBlock') -> bool:
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self.start < other.start

	def __gt__(self, other: 'BasicBlock') -> bool:
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self.start > other.start

	def __le__(self, other: 'BasicBlock') -> bool:
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self.start <= other.start

	def __ge__(self, other: 'BasicBlock') -> bool:
		if not isinstance(other, self.__class__):
			return NotImplemented
		return self.start >= other.start

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

	def __iter__(self) -> Generator[Tuple[List['_function.InstructionTextToken'], int], None, None]:
		if self.view is None:
			raise Exception("Attempting to iterate a Basic Block with no BinaryView")
		if self._instStarts is None:
			# don't add instruction start cache--the object is likely ephemeral
			idx = self.start
			while idx < self.end:
				data = self.view.read(idx, min(self.arch.max_instr_length, self.end - idx))
				result = self.arch.get_instruction_text(data, idx)
				assert result is not None
				text, size = result
				if size == 0:
					break
				yield text, size
				idx += size
		else:
			assert self._instLengths is not None
			for start, length in zip(self._instStarts, self._instLengths):
				result = self.arch.get_instruction_text(self.view.read(start, length), start)
				assert result is not None
				text, size = result
				if size == 0:
					break
				yield text, size

	def __getitem__(self, i):
		self._buildStartCache()
		assert self._instStarts is not None
		assert self._instLengths is not None
		if self.view is None:
			raise Exception("Attempting to iterate a Basic Block with no BinaryView")

		if isinstance(i, slice):
			return [self[index] for index in range(*i.indices(len(self._instStarts)))]
		start = self._instStarts[i]
		length = self._instLengths[i]
		data = self.view.read(start, length)
		return self.arch.get_instruction_text(data, start)

	def __contains__(self, i: int):
		return self.start <= i < self.end

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
				if length == 0:  # invalid instruction. avoid infinite loop
					break
				self._instLengths.append(length)
				self._instStarts.append(start)
				start += length

	def _create_instance(self, handle: core.BNBasicBlockHandle) -> 'BasicBlock':
		"""Internal method used to instantiate child instances"""
		return BasicBlock(handle, self.view)

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
	def il_function(self) -> Optional['_function.ILFunctionType']:
		"""IL Function of which this block is a part, if the block is part of an IL Function."""
		func = self.function
		if func is None:
			return None
		il_type = self.function_graph_type
		if il_type == _function.FunctionGraphType.NormalFunctionGraph:
			return None
		elif il_type == _function.FunctionGraphType.LowLevelILFunctionGraph:
			return func.low_level_il
		elif il_type == _function.FunctionGraphType.LiftedILFunctionGraph:
			return func.lifted_il
		elif il_type == _function.FunctionGraphType.LowLevelILSSAFormFunctionGraph:
			return func.low_level_il.ssa_form
		elif il_type == _function.FunctionGraphType.MediumLevelILFunctionGraph:
			return func.medium_level_il
		elif il_type == _function.FunctionGraphType.MediumLevelILSSAFormFunctionGraph:
			return func.medium_level_il.ssa_form
		elif il_type == _function.FunctionGraphType.MappedMediumLevelILFunctionGraph:
			return func.mapped_medium_level_il
		elif il_type == _function.FunctionGraphType.MappedMediumLevelILSSAFormFunctionGraph:
			return func.mapped_medium_level_il.ssa_form
		elif il_type == _function.FunctionGraphType.HighLevelILFunctionGraph:
			return func.high_level_il
		elif il_type == _function.FunctionGraphType.HighLevelILSSAFormFunctionGraph:
			return func.high_level_il.ssa_form
		elif il_type == _function.FunctionGraphType.HighLevelLanguageRepresentationFunctionGraph:
			return func.high_level_il
		else:
			return None

	@property
	def il_function_if_available(self) -> Optional['_function.ILFunctionType']:
		"""IL Function of which this block is a part, if the block is part of an IL Function, and if the function has generated IL already."""
		func = self.function
		if func is None:
			return None
		il_type = self.function_graph_type
		if il_type == _function.FunctionGraphType.NormalFunctionGraph:
			return None
		elif il_type == _function.FunctionGraphType.LowLevelILFunctionGraph:
			return func.llil_if_available
		elif il_type == _function.FunctionGraphType.LiftedILFunctionGraph:
			return func.lifted_il_if_available
		elif il_type == _function.FunctionGraphType.LowLevelILSSAFormFunctionGraph:
			if func.llil_if_available is None:
				return None
			return func.llil_if_available.ssa_form
		elif il_type == _function.FunctionGraphType.MediumLevelILFunctionGraph:
			return func.mlil_if_available
		elif il_type == _function.FunctionGraphType.MediumLevelILSSAFormFunctionGraph:
			if func.mlil_if_available is None:
				return None
			return func.mlil_if_available.ssa_form
		elif il_type == _function.FunctionGraphType.MappedMediumLevelILFunctionGraph:
			return func.mmlil_if_available
		elif il_type == _function.FunctionGraphType.MappedMediumLevelILSSAFormFunctionGraph:
			if func.mmlil_if_available is None:
				return None
			return func.mmlil_if_available.ssa_form
		elif il_type == _function.FunctionGraphType.HighLevelILFunctionGraph:
			return func.hlil_if_available
		elif il_type == _function.FunctionGraphType.HighLevelILSSAFormFunctionGraph:
			if func.hlil_if_available is None:
				return None
			return func.hlil_if_available.ssa_form
		elif il_type == _function.FunctionGraphType.HighLevelLanguageRepresentationFunctionGraph:
			return func.hlil_if_available
		else:
			return None

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
	def arch(self) -> 'architecture.Architecture':
		"""Basic block architecture (read-only)"""
		# The arch for a BasicBlock isn't going to change so just cache
		# it the first time we need it
		if self._arch is not None:
			return self._arch
		arch = core.BNGetBasicBlockArchitecture(self.handle)
		assert arch is not None, "core.BNGetBasicBlockArchitecture returned None"
		self._arch = architecture.CoreArchitecture._from_cache(arch)
		return self._arch

	@property
	def source_block(self) -> Optional['BasicBlock']:
		"""The corresponding assembly-level basic block for this basic block (read-only)"""
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

	def _make_edges(self, edges, count: int, direction: bool) -> List[BasicBlockEdge]:
		assert edges is not None, "Got empty edges list from core"
		if self.view is None:
			raise ValueError("Attempting to get BasicBlock edges when BinaryView is None")
		result: List[BasicBlockEdge] = []
		try:
			for i in range(0, count):
				branch_type = BranchType(edges[i].type)
				handle = core.BNNewBasicBlockReference(edges[i].target)
				assert handle is not None
				target = self._create_instance(handle)
				if direction:
					sink, source = target, self
				else:
					sink, source = self, target
				result.append(BasicBlockEdge(branch_type, sink, source, edges[i].backEdge, edges[i].fallThrough))
			return result
		finally:
			core.BNFreeBasicBlockEdgeList(edges, count)

	@property
	def outgoing_edges(self) -> List[BasicBlockEdge]:
		"""List of basic block outgoing edges (read-only)"""
		count = ctypes.c_ulonglong(0)
		return self._make_edges(core.BNGetBasicBlockOutgoingEdges(self.handle, count), count.value, False)

	@property
	def incoming_edges(self) -> List[BasicBlockEdge]:
		"""List of basic block incoming edges (read-only)"""
		count = ctypes.c_ulonglong(0)
		return self._make_edges(core.BNGetBasicBlockIncomingEdges(self.handle, count), count.value, True)

	@property
	def has_undetermined_outgoing_edges(self) -> bool:
		"""Whether basic block has undetermined outgoing edges (read-only)"""
		return core.BNBasicBlockHasUndeterminedOutgoingEdges(self.handle)

	@property
	def can_exit(self) -> bool:
		"""Whether basic block can return or is tagged as 'No Return' (read-only)"""
		return core.BNBasicBlockCanExit(self.handle)

	@can_exit.setter
	def can_exit(self, value: bool) -> None:
		"""Sets whether basic block can return or is tagged as 'No Return'"""
		core.BNBasicBlockSetCanExit(self.handle, value)

	@property
	def has_invalid_instructions(self) -> bool:
		"""Whether basic block has any invalid instructions (read-only)"""
		return core.BNBasicBlockHasInvalidInstructions(self.handle)

	def _make_blocks(self, blocks, count: int) -> List['BasicBlock']:
		assert blocks is not None, "core returned empty block list"
		try:
			result: List['BasicBlock'] = []
			for i in range(0, count):
				handle = core.BNNewBasicBlockReference(blocks[i])
				assert handle is not None
				result.append(self._create_instance(handle))
			return result
		finally:
			core.BNFreeBasicBlockList(blocks, count)

	@property
	def dominators(self) -> List['BasicBlock']:
		"""List of dominators for this basic block (read-only)"""
		count = ctypes.c_ulonglong()
		blocks = core.BNGetBasicBlockDominators(self.handle, count, False)
		return self._make_blocks(blocks, count.value)

	@property
	def post_dominators(self) -> List['BasicBlock']:
		"""List of dominators for this basic block (read-only)"""
		count = ctypes.c_ulonglong()
		blocks = core.BNGetBasicBlockDominators(self.handle, count, True)
		return self._make_blocks(blocks, count.value)

	@property
	def strict_dominators(self) -> List['BasicBlock']:
		"""List of strict dominators for this basic block (read-only)"""
		count = ctypes.c_ulonglong()
		blocks = core.BNGetBasicBlockStrictDominators(self.handle, count, False)
		return self._make_blocks(blocks, count.value)

	@property
	def immediate_dominator(self) -> Optional['BasicBlock']:
		"""Immediate dominator of this basic block (read-only)"""
		result = core.BNGetBasicBlockImmediateDominator(self.handle, False)
		if not result:
			return None
		return self._create_instance(result)

	@property
	def immediate_post_dominator(self) -> Optional['BasicBlock']:
		"""Immediate dominator of this basic block (read-only)"""
		result = core.BNGetBasicBlockImmediateDominator(self.handle, True)
		if not result:
			return None
		return self._create_instance(result)

	@property
	def dominator_tree_children(self) -> List['BasicBlock']:
		"""List of child blocks in the dominator tree for this basic block (read-only)"""
		count = ctypes.c_ulonglong()
		blocks = core.BNGetBasicBlockDominatorTreeChildren(self.handle, count, False)
		return self._make_blocks(blocks, count.value)

	@property
	def post_dominator_tree_children(self) -> List['BasicBlock']:
		"""List of child blocks in the post dominator tree for this basic block (read-only)"""
		count = ctypes.c_ulonglong()
		blocks = core.BNGetBasicBlockDominatorTreeChildren(self.handle, count, True)
		return self._make_blocks(blocks, count.value)

	@property
	def dominance_frontier(self) -> List['BasicBlock']:
		"""Dominance frontier for this basic block (read-only)"""
		count = ctypes.c_ulonglong()
		blocks = core.BNGetBasicBlockDominanceFrontier(self.handle, count, False)
		return self._make_blocks(blocks, count.value)

	@property
	def post_dominance_frontier(self) -> List['BasicBlock']:
		"""Post dominance frontier for this basic block (read-only)"""
		count = ctypes.c_ulonglong()
		blocks = core.BNGetBasicBlockDominanceFrontier(self.handle, count, True)
		return self._make_blocks(blocks, count.value)

	@property
	def annotations(self) -> List[List['_function.InstructionTextToken']]:
		"""List of automatic annotations for the start of this block (read-only)"""
		if self.function is None:
			raise ValueError("Attempting to call BasicBlock.annotations when Function is None")

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
	def highlight(self, value: '_highlight.HighlightColor') -> None:
		self.set_user_highlight(value)

	@property
	def function_graph_type(self) -> '_function.FunctionGraphType':
		"""Type of function graph from which this block represents instructions"""
		return _function.FunctionGraphType(core.BNGetBasicBlockFunctionGraphType(self.handle))

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

	def get_iterated_dominance_frontier(self, blocks: List['BasicBlock']) -> List['BasicBlock']:
		"""Calculates the iterated dominance frontier of the given blocks (this is used to determine φ node placement)"""
		if len(blocks) == 0:
			return []

		block_set = (ctypes.POINTER(core.BNBasicBlock) * len(blocks))()  # type: ignore
		for i in range(len(blocks)):
			block_set[i] = blocks[i].handle
		count = ctypes.c_ulonglong()
		out_blocks = core.BNGetBasicBlockIteratedDominanceFrontier(block_set, len(blocks), count)
		return self._make_blocks(out_blocks, count.value)

	def mark_recent_use(self) -> None:
		core.BNMarkBasicBlockAsRecentlyUsed(self.handle)

	def get_disassembly_text(self,
	                         settings: Optional['_function.DisassemblySettings'] = None) -> List['_function.DisassemblyTextLine']:
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
					il_instr = self.il_function[lines[i].instrIndex]  # type: ignore
				else:
					il_instr = None
				color = _highlight.HighlightColor._from_core_struct(lines[i].highlight)
				tokens = _function.InstructionTextToken._from_core_struct(lines[i].tokens, lines[i].count)
				result.append(_function.DisassemblyTextLine(tokens, addr, il_instr, color))
			return result
		finally:
			core.BNFreeDisassemblyTextLines(lines, count.value)

	def set_auto_highlight(self, color: '_highlight.HighlightColor') -> None:
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

	def set_user_highlight(self, color: '_highlight.HighlightColor') -> None:
		"""
		``set_user_highlight`` highlights the current BasicBlock with the supplied color

		:param HighlightStandardColor or HighlightColor color: Color value to use for highlighting
		:Example:

			>>> current_basic_block.set_user_highlight(_highlight.HighlightColor(red=0xff, blue=0xff, green=0))
			>>> current_basic_block.set_user_highlight(HighlightStandardColor.BlueHighlightColor)
		"""
		if not isinstance(color, HighlightStandardColor) and not isinstance(color, _highlight.HighlightColor):
			raise ValueError("Specified color is not one of HighlightStandardColor, HighlightColor")
		if isinstance(color, HighlightStandardColor):
			color = _highlight.HighlightColor(color)
		core.BNSetUserBasicBlockHighlight(self.handle, color._to_core_struct())

	def get_instruction_containing_address(self, addr: int) -> Tuple[bool, int]:
		start = ctypes.c_uint64()
		ret: bool = core.BNGetBasicBlockInstructionContainingAddress(self.handle, addr, start)
		return ret, start.value
