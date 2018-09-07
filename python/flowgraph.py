# Copyright (c) 2018 Vector 35 LLC
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
import threading
import traceback

# Binary Ninja components
import binaryninja
from binaryninja.enums import (BranchType, InstructionTextTokenType, HighlightStandardColor)
from binaryninja import _binaryninjacore as core
from binaryninja import function
from binaryninja import binaryview
from binaryninja import lowlevelil
from binaryninja import mediumlevelil
from binaryninja import basicblock
from binaryninja import log
from binaryninja import highlight

# 2-3 compatibility
from binaryninja import range


class FlowGraphEdge(object):
	def __init__(self, branch_type, source, target, points, back_edge):
		self.type = BranchType(branch_type)
		self.source = source
		self.target = target
		self.points = points
		self.back_edge = back_edge

	def __repr__(self):
		return "<%s: %s>" % (self.type.name, repr(self.target))


class FlowGraphNode(object):
	def __init__(self, graph, handle = None):
		if handle is None:
			handle = core.BNCreateFlowGraphNode(graph.handle)
		self.handle = handle
		self.graph = graph

	def __del__(self):
		core.BNFreeFlowGraphNode(self.handle)

	def __eq__(self, value):
		if not isinstance(value, FlowGraphNode):
			return False
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(value.handle.contents)

	def __ne__(self, value):
		if not isinstance(value, FlowGraphNode):
			return True
		return ctypes.addressof(self.handle.contents) != ctypes.addressof(value.handle.contents)

	@property
	def basic_block(self):
		"""Basic block associated with this part of the flow graph (read-only)"""
		block = core.BNGetFlowGraphBasicBlock(self.handle)
		if not block:
			return None
		func_handle = core.BNGetBasicBlockFunction(block)
		if not func_handle:
			core.BNFreeBasicBlock(block)
			return None

		view = binaryview.BinaryView(handle = core.BNGetFunctionData(func_handle))
		func = function.Function(view, func_handle)

		if core.BNIsLowLevelILBasicBlock(block):
			block = lowlevelil.LowLevelILBasicBlock(view, block,
				lowlevelil.LowLevelILFunction(func.arch, core.BNGetBasicBlockLowLevelILFunction(block), func))
		elif core.BNIsMediumLevelILBasicBlock(block):
			block = mediumlevelil.MediumLevelILBasicBlock(view, block,
				mediumlevelil.MediumLevelILFunction(func.arch, core.BNGetBasicBlockMediumLevelILFunction(block), func))
		else:
			block = basicblock.BasicBlock(view, block)
		return block

	@property
	def x(self):
		"""Flow graph block X (read-only)"""
		return core.BNGetFlowGraphNodeX(self.handle)

	@property
	def y(self):
		"""Flow graph block Y (read-only)"""
		return core.BNGetFlowGraphNodeY(self.handle)

	@property
	def width(self):
		"""Flow graph block width (read-only)"""
		return core.BNGetFlowGraphNodeWidth(self.handle)

	@property
	def height(self):
		"""Flow graph block height (read-only)"""
		return core.BNGetFlowGraphNodeHeight(self.handle)

	@property
	def lines(self):
		"""Flow graph block list of text lines"""
		count = ctypes.c_ulonglong()
		lines = core.BNGetFlowGraphNodeLines(self.handle, count)
		block = self.basic_block
		result = []
		for i in range(0, count.value):
			addr = lines[i].addr
			if (lines[i].instrIndex != 0xffffffffffffffff) and (block is not None) and hasattr(block, 'il_function'):
				il_instr = block.il_function[lines[i].instrIndex]
			else:
				il_instr = None
			color = highlight.HighlightColor._from_core_struct(lines[i].highlight)
			tokens = []
			for j in range(0, lines[i].count):
				token_type = InstructionTextTokenType(lines[i].tokens[j].type)
				text = lines[i].tokens[j].text
				value = lines[i].tokens[j].value
				size = lines[i].tokens[j].size
				operand = lines[i].tokens[j].operand
				context = lines[i].tokens[j].context
				confidence = lines[i].tokens[j].confidence
				address = lines[i].tokens[j].address
				tokens.append(function.InstructionTextToken(token_type, text, value, size, operand, context, address, confidence))
			result.append(function.DisassemblyTextLine(tokens, addr, il_instr, color))
		core.BNFreeDisassemblyTextLines(lines, count.value)
		return result

	@lines.setter
	def lines(self, lines):
		if isinstance(lines, str):
			lines = lines.split('\n')
		line_buf = (core.BNDisassemblyTextLine * len(lines))()
		for i in range(0, len(lines)):
			line = lines[i]
			if isinstance(line, str):
				line = function.DisassemblyTextLine([function.InstructionTextToken(InstructionTextTokenType.TextToken, line)])
			if not isinstance(line, function.DisassemblyTextLine):
				line = function.DisassemblyTextLine(line)
			if line.address is None:
				if len(line.tokens) > 0:
					line_buf[i].addr = line.tokens[0].address
				else:
					line_buf[i].addr = 0
			else:
				line_buf[i].addr = line.address
			if line.il_instruction is not None:
				line_buf[i].instrIndex = line.il_instruction.instr_index
			else:
				line_buf[i].instrIndex = 0xffffffffffffffff
			color = line.highlight
			if not isinstance(color, HighlightStandardColor) and not isinstance(color, highlight.HighlightColor):
				raise ValueError("Specified color is not one of HighlightStandardColor, highlight.HighlightColor")
			if isinstance(color, HighlightStandardColor):
				color = highlight.HighlightColor(color)
			line_buf[i].highlight = color._get_core_struct()
			line_buf[i].count = len(line.tokens)
			line_buf[i].tokens = (core.BNInstructionTextToken * len(line.tokens))()
			for j in range(0, len(line.tokens)):
				line_buf[i].tokens[j].type = line.tokens[j].type
				line_buf[i].tokens[j].text = line.tokens[j].text
				line_buf[i].tokens[j].value = line.tokens[j].value
				line_buf[i].tokens[j].size = line.tokens[j].size
				line_buf[i].tokens[j].operand = line.tokens[j].operand
				line_buf[i].tokens[j].context = line.tokens[j].context
				line_buf[i].tokens[j].confidence = line.tokens[j].confidence
				line_buf[i].tokens[j].address = line.tokens[j].address
		core.BNSetFlowGraphNodeLines(self.handle, line_buf, len(lines))

	@property
	def outgoing_edges(self):
		"""Flow graph block list of outgoing edges (read-only)"""
		count = ctypes.c_ulonglong()
		edges = core.BNGetFlowGraphNodeOutgoingEdges(self.handle, count)
		result = []
		for i in range(0, count.value):
			branch_type = BranchType(edges[i].type)
			target = edges[i].target
			if target:
				target = FlowGraphNode(self.graph, core.BNNewFlowGraphNodeReference(target))
			points = []
			for j in range(0, edges[i].pointCount):
				points.append((edges[i].points[j].x, edges[i].points[j].y))
			result.append(FlowGraphEdge(branch_type, self, target, points, edges[i].backEdge))
		core.BNFreeFlowGraphNodeOutgoingEdgeList(edges, count.value)
		return result

	@property
	def highlight(self):
		"""Gets or sets the highlight color for the node

		:Example:
			>>> g = FlowGraph()
			>>> node = FlowGraphNode(g)
			>>> node.highlight = HighlightStandardColor.BlueHighlightColor
			>>> node.highlight
			<color: blue>
		"""
		return highlight.HighlightColor._from_core_struct(core.BNGetFlowGraphNodeHighlight(self.handle))

	@highlight.setter
	def highlight(self, color):
		if not isinstance(color, HighlightStandardColor) and not isinstance(color, highlight.HighlightColor):
			raise ValueError("Specified color is not one of HighlightStandardColor, highlight.HighlightColor")
		if isinstance(color, HighlightStandardColor):
			color = highlight.HighlightColor(color)
		core.BNSetFlowGraphNodeHighlight(self.handle, color._get_core_struct())

	def __repr__(self):
		block = self.basic_block
		if block:
			arch = block.arch
			if arch:
				return "<graph node: %s@%#x-%#x>" % (arch.name, block.start, block.end)
			else:
				return "<graph node: %#x-%#x>" % (block.start, block.end)
		return "<graph node>"

	def __iter__(self):
		count = ctypes.c_ulonglong()
		lines = core.BNGetFlowGraphNodeLines(self.handle, count)
		block = self.basic_block
		try:
			for i in range(0, count.value):
				addr = lines[i].addr
				if (lines[i].instrIndex != 0xffffffffffffffff) and (block is not None) and hasattr(block, 'il_function'):
					il_instr = block.il_function[lines[i].instrIndex]
				else:
					il_instr = None
				tokens = []
				for j in range(0, lines[i].count):
					token_type = InstructionTextTokenType(lines[i].tokens[j].type)
					text = lines[i].tokens[j].text
					value = lines[i].tokens[j].value
					size = lines[i].tokens[j].size
					operand = lines[i].tokens[j].operand
					context = lines[i].tokens[j].context
					confidence = lines[i].tokens[j].confidence
					address = lines[i].tokens[j].address
					tokens.append(function.InstructionTextToken(token_type, text, value, size, operand, context, address, confidence))
				yield function.DisassemblyTextLine(tokens, addr, il_instr)
		finally:
			core.BNFreeDisassemblyTextLines(lines, count.value)

	def add_outgoing_edge(self, edge_type, target):
		"""
		``add_outgoing_edge`` connects two flow graph nodes with an edge.

		:param BranchType edge_type: Type of edge to add
		:param FlowGraphNode target: Target node object
		"""
		core.BNAddFlowGraphNodeOutgoingEdge(self.handle, edge_type, target.handle)


class FlowGraphLayoutRequest(object):
	def __init__(self, graph, callback = None):
		self.on_complete = callback
		self._cb = ctypes.CFUNCTYPE(None, ctypes.c_void_p)(self._complete)
		self.handle = core.BNStartFlowGraphLayout(graph.handle, None, self._cb)

	def __del__(self):
		self.abort()
		core.BNFreeFlowGraphLayoutRequest(self.handle)

	def _complete(self, ctxt):
		try:
			if self.on_complete is not None:
				self.on_complete()
		except:
			log.log_error(traceback.format_exc())

	@property
	def complete(self):
		"""Whether flow graph layout is complete (read-only)"""
		return core.BNIsFlowGraphLayoutRequestComplete(self.handle)

	@property
	def graph(self):
		"""Flow graph that is being processed (read-only)"""
		return CoreFlowGraph(core.BNGetGraphForFlowGraphLayoutRequest(self.handle))

	def abort(self):
		core.BNAbortFlowGraphLayoutRequest(self.handle)
		self.on_complete = None


class FlowGraph(object):
	"""
	``class FlowGraph`` implements a directed flow graph to be shown in the UI. This class allows plugins to
	create custom flow graphs and render them in the UI using the flow graph report API.

	An example of creating a flow graph and presenting it in the UI:

		>>> graph = FlowGraph()
		>>> node_a = FlowGraphNode(graph)
		>>> node_a.lines = ["Node A"]
		>>> node_b = FlowGraphNode(graph)
		>>> node_b.lines = ["Node B"]
		>>> node_c = FlowGraphNode(graph)
		>>> node_c.lines = ["Node C"]
		>>> graph.append(node_a)
		0
		>>> graph.append(node_b)
		1
		>>> graph.append(node_c)
		2
		>>> node_a.add_outgoing_edge(BranchType.UnconditionalBranch, node_b)
		>>> node_a.add_outgoing_edge(BranchType.UnconditionalBranch, node_c)
		>>> show_graph_report("Custom Graph", graph)

	.. note:: In the current implementation, only graphs that have a single start node where all other nodes are \
	reachable from outgoing edges can be rendered correctly. This describes the natural limitations of a control \
	flow graph, which is what the rendering logic was designed for. Graphs that have nodes that are only reachable \
	from incoming edges, or graphs that have disjoint subgraphs will not render correctly. This will be fixed \
	in a future version.
	"""
	def __init__(self, handle = None):
		if handle is None:
			self._ext_cb = core.BNCustomFlowGraph()
			self._ext_cb.context = 0
			self._ext_cb.prepareForLayout = self._ext_cb.prepareForLayout.__class__(self._prepare_for_layout)
			self._ext_cb.populateNodes = self._ext_cb.populateNodes.__class__(self._populate_nodes)
			self._ext_cb.completeLayout = self._ext_cb.completeLayout.__class__(self._complete_layout)
			self._ext_cb.update = self._ext_cb.update.__class__(self._update)
			handle = core.BNCreateCustomFlowGraph(self._ext_cb)
		self.handle = handle

	def __del__(self):
		core.BNFreeFlowGraph(self.handle)

	def __eq__(self, value):
		if not isinstance(value, FlowGraph):
			return False
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(value.handle.contents)

	def __ne__(self, value):
		if not isinstance(value, FlowGraph):
			return True
		return ctypes.addressof(self.handle.contents) != ctypes.addressof(value.handle.contents)

	def _prepare_for_layout(self, ctxt):
		try:
			self.prepare_for_layout()
		except:
			log.log_error(traceback.format_exc())

	def _populate_nodes(self, ctxt):
		try:
			self.populate_nodes()
		except:
			log.log_error(traceback.format_exc())

	def _complete_layout(self, ctxt):
		try:
			self.complete_layout()
		except:
			log.log_error(traceback.format_exc())

	def _update(self, ctxt):
		try:
			graph = self.update()
			if graph is None:
				return None
			return core.BNNewFlowGraphReference(graph.handle)
		except:
			log.log_error(traceback.format_exc())
			return None

	def finish_prepare_for_layout(self):
		"""
		``finish_prepare_for_layout`` signals that preparations for rendering a graph are complete.
		This method should only be called by a ``prepare_for_layout`` reimplementation.
		"""
		core.BNFinishPrepareForLayout(self.handle)

	def prepare_for_layout(self):
		"""
		``prepare_for_layout`` can be overridden by subclasses to handling preparations that must take
		place before a flow graph is rendered, such as waiting for a function to finish analysis. If
		this function is overridden, the ``finish_prepare_for_layout`` method must be called once
		preparations are completed.
		"""
		self.finish_prepare_for_layout()

	def populate_nodes(self):
		"""
		``prepare_for_layout`` can be overridden by subclasses to create nodes in a graph when a flow
		graph needs to be rendered. This will happen on a worker thread and will not block the UI.
		"""
		pass

	def complete_layout(self):
		"""
		``complete_layout`` can be overridden by subclasses and is called when a graph layout is completed.
		"""
		pass

	@property
	def function(self):
		"""Function for a flow graph"""
		func = core.BNGetFunctionForFlowGraph(self.handle)
		if func is None:
			return None
		return function.Function(binaryview.BinaryView(handle = core.BNGetFunctionData(func)), func)

	@function.setter
	def function(self, func):
		if func is not None:
			func = func.handle
		core.BNSetFunctionForFlowGraph(self.handle, func)

	@property
	def complete(self):
		"""Whether flow graph layout is complete (read-only)"""
		return core.BNIsFlowGraphLayoutComplete(self.handle)

	@property
	def nodes(self):
		"""List of nodes in graph (read-only)"""
		count = ctypes.c_ulonglong()
		blocks = core.BNGetFlowGraphNodes(self.handle, count)
		result = []
		for i in range(0, count.value):
			result.append(FlowGraphNode(self, core.BNNewFlowGraphNodeReference(blocks[i])))
		core.BNFreeFlowGraphNodeList(blocks, count.value)
		return result

	@property
	def has_nodes(self):
		"""Whether the flow graph has at least one node (read-only)"""
		return core.BNFlowGraphHasNodes(self.handle)

	@property
	def width(self):
		"""Flow graph width (read-only)"""
		return core.BNGetFlowGraphWidth(self.handle)

	@property
	def height(self):
		"""Flow graph height (read-only)"""
		return core.BNGetFlowGraphHeight(self.handle)

	@property
	def horizontal_block_margin(self):
		return core.BNGetHorizontalFlowGraphBlockMargin(self.handle)

	@horizontal_block_margin.setter
	def horizontal_block_margin(self, value):
		core.BNSetFlowGraphBlockMargins(self.handle, value, self.vertical_block_margin)

	@property
	def vertical_block_margin(self):
		return core.BNGetVerticalFlowGraphBlockMargin(self.handle)

	@vertical_block_margin.setter
	def vertical_block_margin(self, value):
		core.BNSetFlowGraphBlockMargins(self.handle, self.horizontal_block_margin, value)

	@property
	def is_il(self):
		return core.BNIsILFlowGraph(self.handle)

	@property
	def is_low_level_il(self):
		return core.BNIsLowLevelILFlowGraph(self.handle)

	@property
	def is_medium_level_il(self):
		return core.BNIsMediumLevelILFlowGraph(self.handle)

	@property
	def il_function(self):
		if self.is_low_level_il:
			il_func = core.BNGetFlowGraphLowLevelILFunction(self.handle)
			if not il_func:
				return None
			function = self.function
			if function is None:
				return None
			return lowlevelil.LowLevelILFunction(function.arch, il_func, function)
		if self.is_medium_level_il:
			il_func = core.BNGetFlowGraphMediumLevelILFunction(self.handle)
			if not il_func:
				return None
			function = self.function
			if function is None:
				return None
			return mediumlevelil.MediumLevelILFunction(function.arch, il_func, function)
		return None

	@il_function.setter
	def il_function(self, func):
		if isinstance(func, lowlevelil.LowLevelILFunction):
			core.BNSetFlowGraphLowLevelILFunction(self.handle, func.handle)
			core.BNSetFlowGraphMediumLevelILFunction(self.handle, None)
		elif isinstance(func, mediumlevelil.MediumLevelILFunction):
			core.BNSetFlowGraphLowLevelILFunction(self.handle, None)
			core.BNSetFlowGraphMediumLevelILFunction(self.handle, func.handle)
		elif func is None:
			core.BNSetFlowGraphLowLevelILFunction(self.handle, None)
			core.BNSetFlowGraphMediumLevelILFunction(self.handle, None)
		else:
			raise TypeError("expected IL function for setting il_function property")

	def __setattr__(self, name, value):
		try:
			object.__setattr__(self, name, value)
		except AttributeError:
			raise AttributeError("attribute '%s' is read only" % name)

	def __repr__(self):
		function = self.function
		if function is None:
			return "<flow graph>"
		return "<graph of %s>" % repr(function)

	def __iter__(self):
		count = ctypes.c_ulonglong()
		nodes = core.BNGetFlowGraphNodes(self.handle, count)
		try:
			for i in range(0, count.value):
				yield FlowGraphNode(self, core.BNNewFlowGraphNodeReference(nodes[i]))
		finally:
			core.BNFreeFlowGraphNodeList(nodes, count.value)

	def layout(self, callback = None):
		"""
		``layout`` starts rendering a graph for display. Once a layout is complete, each node will contain
		coordinates and extents that can be used to render a graph with minimum additional computation.
		This function does not wait for the graph to be ready to display, but a callback can be provided
		to signal when the graph is ready.

		:param callable() callback: Function to be called when the graph is ready to display
		:return: Pending flow graph layout request object
		:rtype: FlowGraphLayoutRequest
		"""
		return FlowGraphLayoutRequest(self, callback)

	def _wait_complete(self):
		self._wait_cond.acquire()
		self._wait_cond.notify()
		self._wait_cond.release()

	def layout_and_wait(self):
		"""
		``layout_and_wait`` starts rendering a graph for display, and waits for the graph to be ready to
		display. After this function returns, each node will contain coordinates and extents that can be
		used to render a graph with minimum additional computation.

		Do not use this API on the UI thread (use ``layout`` with a callback instead).
		"""
		self._wait_cond = threading.Condition()
		request = self.layout(self._wait_complete)

		self._wait_cond.acquire()
		while not request.complete:
			self._wait_cond.wait()
		self._wait_cond.release()

	def get_nodes_in_region(self, left, top, right, bottom):
		count = ctypes.c_ulonglong()
		nodes = core.BNGetFlowGraphNodesInRegion(self.handle, left, top, right, bottom, count)
		result = []
		for i in range(0, count.value):
			result.append(FlowGraphNode(self, core.BNNewFlowGraphNodeReference(nodes[i])))
		core.BNFreeFlowGraphNodeList(nodes, count.value)
		return result

	def append(self, node):
		"""
		``append`` adds a node to a flow graph.

		:param FlowGraphNode node: Node to add
		:return: Index of node
		:rtype: int
		"""
		return core.BNAddFlowGraphNode(self.handle, node.handle)

	def __getitem__(self, i):
		node = core.BNGetFlowGraphNode(self.handle, i)
		if node is None:
			return None
		return FlowGraphNode(self, node)

	def show(self, title):
		"""
		``show`` displays the graph in a new tab in the UI.

		:param str title: Title to show in the new tab
		"""
		binaryninja.interaction.show_graph_report(title, self)

	def update(self):
		"""
		``update`` can be overridden by subclasses to allow a graph to be updated after it has been
		presented in the UI. This will automatically occur if the function referenced by the ``function``
		property has been updated.

		Return a new ``FlowGraph`` object with the new information if updates are desired. If the graph
		does not need updating, ``None`` can be returned to leave the graph in its current state.

		:return: Updated graph, or ``None``
		:rtype: FlowGraph
		"""
		return None


class CoreFlowGraph(FlowGraph):
	def __init__(self, handle):
		super(CoreFlowGraph, self).__init__(handle)

	def update(self):
		graph = core.BNUpdateFlowGraph(self.handle)
		if not graph:
			return None
		return CoreFlowGraph(graph)
