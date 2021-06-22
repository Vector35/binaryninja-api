# Copyright (c) 2019-2021 Vector 35 Inc
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

from binaryninja.function import DisassemblyTextRenderer, InstructionTextToken, InstructionContext
from binaryninja.flowgraph import FlowGraph, FlowGraphNode
from binaryninja.enums import InstructionTextTokenType
from binaryninjaui import FlowGraphWidget, ViewType


# Flow graph class for creating a graph with both assembly and Low Level IL in one view
class DisassemblyAndLowLevelILGraph(FlowGraph):
	def __init__(self, func):
		super(DisassemblyAndLowLevelILGraph, self).__init__()
		self.function = func
		il = func.low_level_il
		self.il_function = il

		# Support user annotations for this graph
		self.uses_block_highlights = True
		self.uses_instruction_highlights = True
		self.includes_user_comments = True
		self.allows_patching = True
		self.shows_secondary_reg_highlighting = True

	def populate_nodes(self):
		# Create disassembly text renderers for assembly and IL
		func = self.function
		il = self.il_function
		asm_renderer = DisassemblyTextRenderer(func)
		il_renderer = DisassemblyTextRenderer(il)

		# First create nodes for every block in the function
		nodes = {}
		for block in il:
			node = FlowGraphNode(self)
			node.basic_block = block
			nodes[block.start] = node
			self.append(node)

		# Construct graph
		for block in il:
			il_renderer.basic_block = block

			# Add outgoing edges for the node
			for edge in block.outgoing_edges:
				nodes[block.start].add_outgoing_edge(edge.type, nodes[edge.target.start])

			# Get instruction starts for assembly instructions in the block
			start_addr = il[block.start].address
			asm_block = func.get_basic_block_at(start_addr)
			if asm_block is None:
				# If first IL instruction was removed in IL translation, the previous call will fail. Find
				# the block that contains the instruction
				for i in func.basic_blocks:
					if start_addr >= i.start and start_addr < i.end:
						asm_block = i
						break
			asm_instrs = []
			if asm_block is not None:
				asm_renderer.basic_block = asm_block
				start = asm_block.start
				end = asm_block.end
				addr = start
				while addr < end:
					asm_instrs.append(addr)
					data = func.view.read(addr, min(asm_block.arch.max_instr_length, end - addr))
					context = InstructionContext(bv=func.view)
					info = asm_block.arch.get_instruction_info(data, addr, context)
					addr += info.length
					if info.length == 0:
						break

			# Iterate through instructions in this block and add disassembly lines
			lines = []
			for i in block:
				# Display assembly instructions at or before the current IL instruction
				while len(asm_instrs) > 0 and i.address >= asm_instrs[0]:
					asm_lines, length = asm_renderer.get_disassembly_text(asm_instrs[0])
					lines += asm_lines
					asm_instrs = asm_instrs[1:]

				# Display IL instruction
				il_lines, length = il_renderer.get_disassembly_text(i.instr_index)
				lines += il_lines

			# Go through lines and add addresses to them
			for line in lines:
				if line.il_instruction is None:
					# For assembly lines, show address
					line.tokens.insert(0, InstructionTextToken(InstructionTextTokenType.AddressDisplayToken,
						"%.8x" % line.address, line.address))
					line.tokens.insert(1, InstructionTextToken(InstructionTextTokenType.TextToken, "  "))
				else:
					# For IL lines, show IL instruction index
					line.tokens.insert(0, InstructionTextToken(InstructionTextTokenType.AnnotationToken,
						"%8s" % ("[%d]" % line.il_instruction.instr_index)))
					line.tokens.insert(1, InstructionTextToken(InstructionTextTokenType.AnnotationToken, "   => "))

			nodes[block.start].lines = lines

	def update(self):
		return DisassemblyAndLowLevelILGraph(self.function)


# Flow graph widget subclass that displays the graphs described above
class DisassemblyAndLowLevelILView(FlowGraphWidget):
	def __init__(self, parent, data):
		# Start view with entry function
		self.data = data
		self.function = data.entry_function
		if self.function is None:
			graph = None
		else:
			graph = DisassemblyAndLowLevelILGraph(self.function)
		super(DisassemblyAndLowLevelILView, self).__init__(parent, data, graph)

	def navigate(self, addr):
		# Find correct function based on most recent use
		block = self.data.get_recent_basic_block_at(addr)
		if block is None:
			# If function isn't done analyzing yet, it may have a function start but no basic blocks
			func = self.data.get_recent_function_at(addr)
		else:
			func = block.function

		if func is None:
			# No function contains this address, fail navigation in this view
			return False

		return self.navigateToFunction(func, addr)

	def navigateToFunction(self, func, addr):
		if func == self.function:
			# Address is within current function, go directly there
			self.showAddress(addr, True)
			return True

		# Navigate to the correct function
		self.function = func
		graph = DisassemblyAndLowLevelILGraph(func)
		self.setGraph(graph, addr)
		return True


# View type for the new view
class DisassemblyAndLowLevelILViewType(ViewType):
	def __init__(self):
		super(DisassemblyAndLowLevelILViewType, self).__init__("Asm -> LLIL", "Assembly to Low Level IL")

	def getPriority(self, data, filename):
		if data.executable:
			# Use low priority so that this view is not picked by default
			return 1
		return 0

	def create(self, data, view_frame):
		return DisassemblyAndLowLevelILView(view_frame, data)


# Register the view type so that it can be chosen by the user
ViewType.registerViewType(DisassemblyAndLowLevelILViewType())
