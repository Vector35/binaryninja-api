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
from enums import BranchType, HighlightColorStyle, HighlightStandardColor, InstructionTextTokenType
import architecture
import highlight
import function


class BasicBlockEdge(object):
	def __init__(self, branch_type, source, target, back_edge):
		self.type = branch_type
		self.source = source
		self.target = target
		self.back_edge = back_edge

	def __repr__(self):
		if self.type == BranchType.UnresolvedBranch:
			return "<%s>" % BranchType(self.type).name
		elif self.target.arch:
			return "<%s: %s@%#x>" % (BranchType(self.type).name, self.target.arch.name, self.target.start)
		else:
			return "<%s: %#x>" % (BranchType(self.type).name, self.target.start)


class BasicBlock(object):
	def __init__(self, view, handle):
		self.view = view
		self.handle = core.handle_of_type(handle, core.BNBasicBlock)
		self._arch = None
		self._func = None

	def __del__(self):
		core.BNFreeBasicBlock(self.handle)

	def __eq__(self, value):
		if not isinstance(value, BasicBlock):
			return False
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(value.handle.contents)

	def __ne__(self, value):
		if not isinstance(value, BasicBlock):
			return True
		return ctypes.addressof(self.handle.contents) != ctypes.addressof(value.handle.contents)

	def _create_instance(self, view, handle):
		"""Internal method used to instantiante child instances"""
		return BasicBlock(view, handle)

	@property
	def function(self):
		"""Basic block function (read-only)"""
		if self._func is not None:
			return self._func
		func = core.BNGetBasicBlockFunction(self.handle)
		if func is None:
			return None
		self._func = function.Function(self.view, func)
		return self._func

	@property
	def arch(self):
		"""Basic block architecture (read-only)"""
		# The arch for a BasicBlock isn't going to change so just cache
		# it the first time we need it
		if self._arch is not None:
			return self._arch
		arch = core.BNGetBasicBlockArchitecture(self.handle)
		if arch is None:
			return None
		self._arch = architecture.Architecture(arch)
		return self._arch

	@property
	def start(self):
		"""Basic block start (read-only)"""
		return core.BNGetBasicBlockStart(self.handle)

	@property
	def end(self):
		"""Basic block end (read-only)"""
		return core.BNGetBasicBlockEnd(self.handle)

	@property
	def length(self):
		"""Basic block length (read-only)"""
		return core.BNGetBasicBlockLength(self.handle)

	@property
	def index(self):
		"""Basic block index in list of blocks for the function (read-only)"""
		return core.BNGetBasicBlockIndex(self.handle)

	@property
	def outgoing_edges(self):
		"""List of basic block outgoing edges (read-only)"""
		count = ctypes.c_ulonglong(0)
		edges = core.BNGetBasicBlockOutgoingEdges(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			branch_type = BranchType(edges[i].type)
			if edges[i].target:
				target = self._create_instance(self.view, core.BNNewBasicBlockReference(edges[i].target))
			else:
				target = None
			result.append(BasicBlockEdge(branch_type, self, target, edges[i].backEdge))
		core.BNFreeBasicBlockEdgeList(edges, count.value)
		return result

	@property
	def incoming_edges(self):
		"""List of basic block incoming edges (read-only)"""
		count = ctypes.c_ulonglong(0)
		edges = core.BNGetBasicBlockIncomingEdges(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			branch_type = BranchType(edges[i].type)
			if edges[i].target:
				target = self._create_instance(self.view, core.BNNewBasicBlockReference(edges[i].target))
			else:
				target = None
			result.append(BasicBlockEdge(branch_type, self, target, edges[i].backEdge))
		core.BNFreeBasicBlockEdgeList(edges, count.value)
		return result

	@property
	def has_undetermined_outgoing_edges(self):
		"""Whether basic block has undetermined outgoing edges (read-only)"""
		return core.BNBasicBlockHasUndeterminedOutgoingEdges(self.handle)

	@property
	def can_exit(self):
		"""Whether basic block can return or is tagged as 'No Return' (read-only)"""
		return core.BNBasicBlockCanExit(self.handle)

	@property
	def dominators(self):
		"""List of dominators for this basic block (read-only)"""
		count = ctypes.c_ulonglong()
		blocks = core.BNGetBasicBlockDominators(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			result.append(self._create_instance(self.view, core.BNNewBasicBlockReference(blocks[i])))
		core.BNFreeBasicBlockList(blocks, count.value)
		return result

	@property
	def strict_dominators(self):
		"""List of strict dominators for this basic block (read-only)"""
		count = ctypes.c_ulonglong()
		blocks = core.BNGetBasicBlockStrictDominators(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			result.append(self._create_instance(self.view, core.BNNewBasicBlockReference(blocks[i])))
		core.BNFreeBasicBlockList(blocks, count.value)
		return result

	@property
	def immediate_dominator(self):
		"""Immediate dominator of this basic block (read-only)"""
		result = core.BNGetBasicBlockImmediateDominator(self.handle)
		if not result:
			return None
		return self._create_instance(self.view, result)

	@property
	def dominator_tree_children(self):
		"""List of child blocks in the dominator tree for this basic block (read-only)"""
		count = ctypes.c_ulonglong()
		blocks = core.BNGetBasicBlockDominatorTreeChildren(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			result.append(self._create_instance(self.view, core.BNNewBasicBlockReference(blocks[i])))
		core.BNFreeBasicBlockList(blocks, count.value)
		return result

	@property
	def dominance_frontier(self):
		"""Dominance frontier for this basic block (read-only)"""
		count = ctypes.c_ulonglong()
		blocks = core.BNGetBasicBlockDominanceFrontier(self.handle, count)
		result = []
		for i in xrange(0, count.value):
			result.append(self._create_instance(self.view, core.BNNewBasicBlockReference(blocks[i])))
		core.BNFreeBasicBlockList(blocks, count.value)
		return result

	@property
	def annotations(self):
		"""List of automatic annotations for the start of this block (read-only)"""
		return self.function.get_block_annotations(self.start, self.arch)

	@property
	def disassembly_text(self):
		"""
		``disassembly_text`` property which returns a list of function.DisassemblyTextLine objects for the current basic block.
		:Example:

			>>> current_basic_block.disassembly_text
			[<0x100000f30: _main:>, ...]
		"""
		return self.get_disassembly_text()

	@property
	def highlight(self):
		"""Gets or sets the highlight color for basic block

		:Example:

			>>> current_basic_block.highlight = HighlightStandardColor.BlueHighlightColor
			>>> current_basic_block.highlight
			<color: blue>
		"""
		color = core.BNGetBasicBlockHighlight(self.handle)
		if color.style == HighlightColorStyle.StandardHighlightColor:
			return highlight.HighlightColor(color=color.color, alpha=color.alpha)
		elif color.style == HighlightColorStyle.MixedHighlightColor:
			return highlight.HighlightColor(color=color.color, mix_color=color.mixColor, mix=color.mix, alpha=color.alpha)
		elif color.style == HighlightColorStyle.CustomHighlightColor:
			return highlight.HighlightColor(red=color.r, green=color.g, blue=color.b, alpha=color.alpha)
		return highlight.HighlightColor(color=HighlightStandardColor.NoHighlightColor)

	@highlight.setter
	def highlight(self, value):
		self.set_user_highlight(value)

	@classmethod
	def get_iterated_dominance_frontier(self, blocks):
		if len(blocks) == 0:
			return []
		block_set = (ctypes.POINTER(core.BNBasicBlock) * len(blocks))()
		for i in xrange(len(blocks)):
			block_set[i] = blocks[i].handle
		count = ctypes.c_ulonglong()
		out_blocks = core.BNGetBasicBlockIteratedDominanceFrontier(block_set, len(blocks), count)
		result = []
		for i in xrange(0, count.value):
			result.append(BasicBlock(blocks[0].view, core.BNNewBasicBlockReference(out_blocks[i])))
		core.BNFreeBasicBlockList(out_blocks, count.value)
		return result

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self, name, value)
		except AttributeError:
			raise AttributeError("attribute '%s' is read only" % name)

	def __len__(self):
		return int(core.BNGetBasicBlockLength(self.handle))

	def __repr__(self):
		arch = self.arch
		if arch:
			return "<block: %s@%#x-%#x>" % (arch.name, self.start, self.end)
		else:
			return "<block: %#x-%#x>" % (self.start, self.end)

	def __iter__(self):
		start = self.start
		end = self.end

		idx = start
		while idx < end:
			data = self.view.read(idx, 16)
			inst_info = self.arch.get_instruction_info(data, idx)
			inst_text = self.arch.get_instruction_text(data, idx)

			yield inst_text
			idx += inst_info.length

	def mark_recent_use(self):
		core.BNMarkBasicBlockAsRecentlyUsed(self.handle)

	def get_disassembly_text(self, settings=None):
		"""
		``get_disassembly_text`` returns a list of function.DisassemblyTextLine objects for the current basic block.

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
		result = []
		for i in xrange(0, count.value):
			addr = lines[i].addr
			tokens = []
			for j in xrange(0, lines[i].count):
				token_type = InstructionTextTokenType(lines[i].tokens[j].type)
				text = lines[i].tokens[j].text
				value = lines[i].tokens[j].value
				size = lines[i].tokens[j].size
				operand = lines[i].tokens[j].operand
				context = lines[i].tokens[j].context
				confidence = lines[i].tokens[j].confidence
				address = lines[i].tokens[j].address
				tokens.append(function.InstructionTextToken(token_type, text, value, size, operand, context, address, confidence))
			result.append(function.DisassemblyTextLine(addr, tokens))
		core.BNFreeDisassemblyTextLines(lines, count.value)
		return result

	def set_auto_highlight(self, color):
		"""
		``set_auto_highlight`` highlights the current BasicBlock with the supplied color.

		..warning:: Use only in analysis plugins. Do not use in regular plugins, as colors won't be saved to the database.

		:param HighlightStandardColor or highlight.HighlightColor color: Color value to use for highlighting
		"""
		if not isinstance(color, HighlightStandardColor) and not isinstance(color, highlight.HighlightColor):
			raise ValueError("Specified color is not one of HighlightStandardColor, highlight.HighlightColor")
		if isinstance(color, HighlightStandardColor):
			color = highlight.HighlightColor(color)
		core.BNSetAutoBasicBlockHighlight(self.handle, color._get_core_struct())

	def set_user_highlight(self, color):
		"""
		``set_user_highlight`` highlights the current BasicBlock with the supplied color

		:param HighlightStandardColor or highlight.HighlightColor color: Color value to use for highlighting
		:Example:

			>>> current_basic_block.set_user_highlight(highlight.HighlightColor(red=0xff, blue=0xff, green=0))
			>>> current_basic_block.set_user_highlight(HighlightStandardColor.BlueHighlightColor)
		"""
		if not isinstance(color, HighlightStandardColor) and not isinstance(color, highlight.HighlightColor):
			raise ValueError("Specified color is not one of HighlightStandardColor, highlight.HighlightColor")
		if isinstance(color, HighlightStandardColor):
			color = highlight.HighlightColor(color)
		core.BNSetUserBasicBlockHighlight(self.handle, color._get_core_struct())
