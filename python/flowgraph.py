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
import threading
import traceback
from typing import List, Optional, Tuple

# Binary Ninja components
import binaryninja
from . import _binaryninjacore as core
from .enums import (
    BranchType, InstructionTextTokenType, HighlightStandardColor, FlowGraphOption, EdgePenStyle, ThemeColor
)
from . import function
from . import binaryview
from . import lowlevelil
from . import mediumlevelil
from . import highlevelil
from . import basicblock
from .log import log_error
from . import highlight
from . import interaction


class FlowGraphEdge:
	def __init__(self, branch_type, source, target, points, back_edge, style):
		self.type = BranchType(branch_type)
		self.source = source
		self.target = target
		self.points = points
		self.back_edge = back_edge
		self.style = style

	def __repr__(self):
		return "<%s: %s>" % (self.type.name, repr(self.target))

	def __eq__(self, other):
		return (self.type, self.source, self.target, self.points, self.back_edge,
		        self.style) == (other.type, other.source, other.target, other.points, other.back_edge, other.style)

	def __hash__(self):
		return hash((self.type, self.source, self.target, self.points, self.back_edge, self.style))


class EdgeStyle:
	def __init__(self, style: Optional[EdgePenStyle] = None, width: Optional[int] = None, theme_color: Optional[ThemeColor] = None):
		self.style = style if style is not None else EdgePenStyle.SolidLine
		self.width = width if width is not None else 0
		self.color = theme_color if theme_color is not None else ThemeColor.AddressColor

	def _to_core_struct(self) -> core.BNEdgeStyle:
		result = core.BNEdgeStyle()
		result.style = int(self.style)
		result.width = self.width
		result.color = self.color
		return result

	@staticmethod
	def from_core_struct(edge_style):
		return EdgeStyle(edge_style.style, edge_style.width, edge_style.color)

	def __eq__(self, other):
		return (self.style, self.width, self.color) == (other.style, other.width, other.color)

	def __hash__(self):
		return hash((self.style, self.width, self.color))


class FlowGraphNode:
	def __init__(self, graph=None, handle=None):
		_handle = handle
		if _handle is None:
			if graph is None:
				raise ValueError("flow graph node must be associated with a graph")
			_handle = core.BNCreateFlowGraphNode(graph.handle)
		assert _handle is not None
		self.handle = _handle
		self._graph = graph
		if self._graph is None:
			self._graph = FlowGraph(handle=core.BNGetFlowGraphNodeOwner(self.handle))

	def __del__(self):
		if core is not None:
			core.BNFreeFlowGraphNode(self.handle)

	def __repr__(self):
		block = self.basic_block
		if block:
			arch = block.arch
			if arch:
				return "<graph node: %s@%#x-%#x>" % (arch.name, block.start, block.end)
			else:
				return "<graph node: %#x-%#x>" % (block.start, block.end)
		return "<graph node>"

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

	def __iter__(self):
		count = ctypes.c_ulonglong()
		lines = core.BNGetFlowGraphNodeLines(self.handle, count)
		assert lines is not None, "core.BNGetFlowGraphNodeLines returned None"
		block = self.basic_block
		try:
			for i in range(0, count.value):
				addr = lines[i].addr
				if (lines[i].instrIndex != 0xffffffffffffffff) and (block
				                                                    is not None) and hasattr(block, 'il_function'):
					il_instr = block.il_function[lines[i].instrIndex]
				else:
					il_instr = None
				tokens = function.InstructionTextToken._from_core_struct(lines[i].tokens, lines[i].count)
				yield function.DisassemblyTextLine(tokens, addr, il_instr)
		finally:
			core.BNFreeDisassemblyTextLines(lines, count.value)

	@property
	def graph(self):
		return self._graph

	@graph.setter
	def graph(self, value):
		self._graph = value

	@property
	def basic_block(self):
		"""Basic block associated with this part of the flow graph (well not automatically cause the node to render as a native basic block)"""
		block = core.BNGetFlowGraphBasicBlock(self.handle)
		if not block:
			return None
		return basicblock.BasicBlock._from_core_block(block)

	@basic_block.setter
	def basic_block(self, block):
		if block is None:
			core.BNSetFlowGraphBasicBlock(self.handle, None)
		else:
			core.BNSetFlowGraphBasicBlock(self.handle, block.handle)

	@property
	def x(self):
		"""Flow graph block X"""
		return core.BNGetFlowGraphNodeX(self.handle)

	@x.setter
	def x(self, x: int):
		return core.BNFlowGraphNodeSetX(self.handle, x)

	@property
	def y(self):
		"""Flow graph block Y"""
		return core.BNGetFlowGraphNodeY(self.handle)

	@y.setter
	def y(self, y: int):
		return core.BNFlowGraphNodeSetY(self.handle, y)

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
		assert lines is not None, "core.BNGetFlowGraphNodeLines returned None"
		block = self.basic_block
		result = []
		for i in range(0, count.value):
			addr = lines[i].addr
			if (lines[i].instrIndex != 0xffffffffffffffff) and (block is not None) and hasattr(block, 'il_function'):
				il_instr = block.il_function[lines[i].instrIndex]
			else:
				il_instr = None
			color = highlight.HighlightColor._from_core_struct(lines[i].highlight)
			tokens = function.InstructionTextToken._from_core_struct(lines[i].tokens, lines[i].count)
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
				line = function.DisassemblyTextLine([
				    function.InstructionTextToken(InstructionTextTokenType.TextToken, line)
				])
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
			line_buf[i].highlight = color._to_core_struct()
			line_buf[i].count = len(line.tokens)
			line_buf[i].tokens = function.InstructionTextToken._get_core_struct(line.tokens)
		core.BNSetFlowGraphNodeLines(self.handle, line_buf, len(lines))

	@property
	def outgoing_edges(self) -> List[FlowGraphEdge]:
		"""Flow graph block list of outgoing edges (read-only)"""
		count = ctypes.c_ulonglong()
		edges = core.BNGetFlowGraphNodeOutgoingEdges(self.handle, count)
		assert edges is not None, "core.BNGetFlowGraphNodeOutgoingEdges returned None"
		result = []
		for i in range(0, count.value):
			branch_type = BranchType(edges[i].type)
			target = edges[i].target
			if target:
				target = FlowGraphNode(self._graph, core.BNNewFlowGraphNodeReference(target))
			points = []
			for j in range(0, edges[i].pointCount):
				points.append((edges[i].points[j].x, edges[i].points[j].y))
			result.append(
			    FlowGraphEdge(branch_type, self, target, points, edges[i].backEdge, EdgeStyle(edges[i].style))
			)
		core.BNFreeFlowGraphNodeEdgeList(edges, count.value)
		return result

	@property
	def incoming_edges(self):
		"""Flow graph block list of incoming edges (read-only)"""
		count = ctypes.c_ulonglong()
		edges = core.BNGetFlowGraphNodeIncomingEdges(self.handle, count)
		assert edges is not None, "core.BNGetFlowGraphNodeIncomingEdges returned None"
		result = []
		for i in range(0, count.value):
			branch_type = BranchType(edges[i].type)
			target = edges[i].target
			if target:
				target = FlowGraphNode(self._graph, core.BNNewFlowGraphNodeReference(target))
			points = []
			for j in range(0, edges[i].pointCount):
				points.append((edges[i].points[j].x, edges[i].points[j].y))
			result.append(
			    FlowGraphEdge(branch_type, self, target, points, edges[i].backEdge, EdgeStyle(edges[i].style))
			)
		core.BNFreeFlowGraphNodeEdgeList(edges, count.value)
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
		core.BNSetFlowGraphNodeHighlight(self.handle, color._to_core_struct())

	def add_outgoing_edge(self, edge_type, target, style=None):
		"""
		``add_outgoing_edge`` connects two flow graph nodes with an edge.

		:param BranchType edge_type: Type of edge to add
		:param FlowGraphNode target: Target node object
		:param EdgeStyle style: (optional) Styling for graph edge Branch Type must be set to UserDefinedBranch
		"""
		if not target.is_valid_for_graph(self._graph):
			raise ValueError("Target of edge has not been added to the owning graph")

		if style is None:
			style = EdgeStyle()
		elif not isinstance(style, EdgeStyle):
			raise AttributeError("style must be of type EdgeStyle")

		core.BNAddFlowGraphNodeOutgoingEdge(self.handle, edge_type, target.handle, style._to_core_struct())

	def is_valid_for_graph(self, graph):
		return core.BNIsNodeValidForFlowGraph(graph.handle, self.handle)

	def set_visibility_region(self, x: int, y: int, w: int, h: int):
		core.BNFlowGraphNodeSetVisibilityRegion(self.handle, x, y, w, h)

	def set_outgoing_edge_points(self, edge_num: int, points: List[Tuple[float, float]]):
		point_buf = (core.BNPoint * len(points))()
		for i in range(0, len(points)):
			point_buf[i].x = points[i][0]
			point_buf[i].y = points[i][1]
		core.BNFlowGraphNodeSetOutgoingEdgePoints(self.handle, edge_num, point_buf, len(points))


class FlowGraphLayoutRequest:
	def __init__(self, graph, callback=None):
		self.on_complete = callback
		self._cb = ctypes.CFUNCTYPE(None, ctypes.c_void_p)(self._complete)
		self.handle = core.BNStartFlowGraphLayout(graph.handle, None, self._cb)

	def __del__(self):
		if core is None:
			return
		self.abort()
		core.BNFreeFlowGraphLayoutRequest(self.handle)

	def _complete(self, ctxt):
		try:
			if self.on_complete is not None:
				self.on_complete()
		except:
			log_error(traceback.format_exc())

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


class FlowGraph:
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
		>>> edge = EdgeStyle(EdgePenStyle.DashDotDotLine, 2, ThemeColor.AddressColor)
		>>> node_a.add_outgoing_edge(BranchType.UserDefinedBranch, node_b, edge)
		>>> node_a.add_outgoing_edge(BranchType.UnconditionalBranch, node_c)
		>>> show_graph_report("Custom Graph", graph)

	.. note:: In the current implementation, only graphs that have a single start node where all other nodes are \
	reachable from outgoing edges can be rendered correctly. This describes the natural limitations of a control \
	flow graph, which is what the rendering logic was designed for. Graphs that have nodes that are only reachable \
	from incoming edges, or graphs that have disjoint subgraphs will not render correctly. This will be fixed \
	in a future version.
	"""
	_registered_instances = []

	def __init__(self, handle: Optional[core.BNCustomFlowGraphHandle] = None):
		_handle = handle
		if _handle is None:
			self._ext_cb = core.BNCustomFlowGraph()
			self._ext_cb.context = 0
			self._ext_cb.prepareForLayout = self._ext_cb.prepareForLayout.__class__(self._prepare_for_layout)
			self._ext_cb.populateNodes = self._ext_cb.populateNodes.__class__(self._populate_nodes)
			self._ext_cb.completeLayout = self._ext_cb.completeLayout.__class__(self._complete_layout)
			self._ext_cb.update = self._ext_cb.update.__class__(self._update)
			self._ext_cb.externalRefTaken = self._ext_cb.externalRefTaken.__class__(self._external_ref_taken)
			self._ext_cb.externalRefReleased = self._ext_cb.externalRefReleased.__class__(self._external_ref_released)
			_handle = core.BNCreateCustomFlowGraph(self._ext_cb)
		assert _handle is not None
		self.handle = _handle

	def __del__(self):
		if core is not None:
			core.BNFreeFlowGraph(self.handle)

	def __repr__(self):
		function = self.function
		if function is None:
			return "<flow graph>"
		return "<graph of %s>" % repr(function)

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
		try:
			object.__setattr__(self, name, value)
		except AttributeError:
			raise AttributeError("attribute '%s' is read only" % name)

	def __iter__(self):
		count = ctypes.c_ulonglong()
		nodes = core.BNGetFlowGraphNodes(self.handle, count)
		assert nodes is not None, "core.BNGetFlowGraphNodes returned None"
		try:
			for i in range(0, count.value):
				fg_node = core.BNNewFlowGraphNodeReference(nodes[i])
				assert fg_node is not None, "core.BNNewFlowGraphNodeReference returned None"
				yield FlowGraphNode(self, fg_node)
		finally:
			core.BNFreeFlowGraphNodeList(nodes, count.value)

	def __getitem__(self, i):
		node = core.BNGetFlowGraphNode(self.handle, i)
		if node is None:
			return None
		return FlowGraphNode(self, node)

	def _prepare_for_layout(self, ctxt):
		try:
			self.prepare_for_layout()
		except:
			log_error(traceback.format_exc())

	def _populate_nodes(self, ctxt):
		try:
			self.populate_nodes()
		except:
			log_error(traceback.format_exc())

	def _complete_layout(self, ctxt):
		try:
			self.complete_layout()
		except:
			log_error(traceback.format_exc())

	def _update(self, ctxt):
		try:
			graph = self.update()
			if graph is NotImplemented:
				return None
			flow_graph = core.BNNewFlowGraphReference(graph.handle)
			assert flow_graph is not None, "core.BNNewFlowGraphReference returned None"
			return ctypes.cast(flow_graph, ctypes.c_void_p).value
		except:
			log_error(traceback.format_exc())
			return None

	def _external_ref_taken(self, ctxt):
		try:
			self.__class__._registered_instances.append(self)
		except:
			log_error(traceback.format_exc())

	def _external_ref_released(self, ctxt):
		try:
			self.__class__._registered_instances.remove(self)
		except:
			log_error(traceback.format_exc())

	def finish_prepare_for_layout(self):
		"""
		``finish_prepare_for_layout`` signals that preparations for rendering a graph are complete.
		This method should only be called by a :func:`prepare_for_layout` reimplementation.
		"""
		core.BNFinishPrepareForLayout(self.handle)

	def prepare_for_layout(self):
		"""
		``prepare_for_layout`` can be overridden by subclasses to handling preparations that must take
		place before a flow graph is rendered, such as waiting for a function to finish analysis. If
		this function is overridden, the :func:`finish_prepare_for_layout` method must be called once
		preparations are completed.
		"""
		self.finish_prepare_for_layout()

	def populate_nodes(self):
		"""
		``populate_nodes`` can be overridden by subclasses to create nodes in a graph when a flow
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
		return function.Function(handle=func)

	@function.setter
	def function(self, func):
		if func is not None:
			func = func.handle
		core.BNSetFunctionForFlowGraph(self.handle, func)

	@property
	def view(self):
		"""Binary view for a flow graph"""
		view = core.BNGetViewForFlowGraph(self.handle)
		if view is None:
			return None
		return binaryview.BinaryView(handle=view)

	@view.setter
	def view(self, view):
		if view is not None:
			view = view.handle
		core.BNSetViewForFlowGraph(self.handle, view)

	@property
	def complete(self):
		"""Whether flow graph layout is complete (read-only)"""
		return core.BNIsFlowGraphLayoutComplete(self.handle)

	@property
	def nodes(self):
		"""List of nodes in graph (read-only)"""
		count = ctypes.c_ulonglong()
		blocks = core.BNGetFlowGraphNodes(self.handle, count)
		assert blocks is not None, "core.BNGetFlowGraphNodes returned None"
		result = []
		for i in range(0, count.value):
			fg_node = core.BNNewFlowGraphNodeReference(blocks[i])
			assert fg_node is not None, "core.BNNewFlowGraphNodeReference returned None"
			result.append(FlowGraphNode(self, fg_node))
		core.BNFreeFlowGraphNodeList(blocks, count.value)
		return result

	@property
	def node_count(self) -> int:
		"""Number of nodes in graph (read-only)"""
		return core.BNGetFlowGraphNodeCount(self.handle)

	@property
	def has_nodes(self):
		"""Whether the flow graph has at least one node (read-only)"""
		return core.BNFlowGraphHasNodes(self.handle)

	@property
	def width(self):
		"""Flow graph width"""
		return core.BNGetFlowGraphWidth(self.handle)

	@width.setter
	def width(self, width: int):
		return core.BNFlowGraphSetWidth(self.handle, width)

	@property
	def height(self):
		"""Flow graph height"""
		return core.BNGetFlowGraphHeight(self.handle)

	@height.setter
	def height(self, height: int):
		return core.BNFlowGraphSetHeight(self.handle, height)

	@property
	def horizontal_block_margin(self):
		return core.BNGetHorizontalFlowGraphNodeMargin(self.handle)

	@horizontal_block_margin.setter
	def horizontal_block_margin(self, value):
		core.BNSetFlowGraphNodeMargins(self.handle, value, self.vertical_block_margin)

	@property
	def vertical_block_margin(self):
		return core.BNGetVerticalFlowGraphNodeMargin(self.handle)

	@vertical_block_margin.setter
	def vertical_block_margin(self, value):
		core.BNSetFlowGraphNodeMargins(self.handle, self.horizontal_block_margin, value)

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
	def is_high_level_il(self):
		return core.BNIsHighLevelILFlowGraph(self.handle)

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
		if self.is_high_level_il:
			il_func = core.BNGetFlowGraphHighLevelILFunction(self.handle)
			if not il_func:
				return None
			function = self.function
			if function is None:
				return None
			return highlevelil.HighLevelILFunction(function.arch, il_func, function)
		return None

	@il_function.setter
	def il_function(self, func):
		if isinstance(func, lowlevelil.LowLevelILFunction):
			core.BNSetFlowGraphLowLevelILFunction(self.handle, func.handle)
			core.BNSetFlowGraphMediumLevelILFunction(self.handle, None)
			core.BNSetFlowGraphHighLevelILFunction(self.handle, None)
		elif isinstance(func, mediumlevelil.MediumLevelILFunction):
			core.BNSetFlowGraphLowLevelILFunction(self.handle, None)
			core.BNSetFlowGraphMediumLevelILFunction(self.handle, func.handle)
			core.BNSetFlowGraphHighLevelILFunction(self.handle, None)
		elif isinstance(func, highlevelil.HighLevelILFunction):
			core.BNSetFlowGraphLowLevelILFunction(self.handle, None)
			core.BNSetFlowGraphMediumLevelILFunction(self.handle, None)
			core.BNSetFlowGraphHighLevelILFunction(self.handle, func.handle)
		elif func is None:
			core.BNSetFlowGraphLowLevelILFunction(self.handle, None)
			core.BNSetFlowGraphMediumLevelILFunction(self.handle, None)
			core.BNSetFlowGraphHighLevelILFunction(self.handle, None)
		else:
			raise TypeError("expected IL function for setting il_function property")

	@property
	def uses_block_highlights(self):
		"""Set if flow graph uses the standard basic block highlighting settings"""
		return self.is_option_set(FlowGraphOption.FlowGraphUsesBlockHighlights)

	@uses_block_highlights.setter
	def uses_block_highlights(self, value):
		self.set_option(FlowGraphOption.FlowGraphUsesBlockHighlights, value)

	@property
	def uses_instruction_highlights(self):
		"""Set if flow graph uses the standard instruction highlighting settings"""
		return self.is_option_set(FlowGraphOption.FlowGraphUsesInstructionHighlights)

	@uses_instruction_highlights.setter
	def uses_instruction_highlights(self, value):
		self.set_option(FlowGraphOption.FlowGraphUsesInstructionHighlights, value)

	@property
	def includes_user_comments(self):
		"""Set if flow graph includes comments made by the user"""
		return self.is_option_set(FlowGraphOption.FlowGraphIncludesUserComments)

	@includes_user_comments.setter
	def includes_user_comments(self, value):
		self.set_option(FlowGraphOption.FlowGraphIncludesUserComments, value)

	@property
	def allows_patching(self):
		"""Set if flow graph should allow modification of code from within the graph view"""
		return self.is_option_set(FlowGraphOption.FlowGraphAllowsPatching)

	@allows_patching.setter
	def allows_patching(self, value):
		self.set_option(FlowGraphOption.FlowGraphAllowsPatching, value)

	@property
	def allows_inline_instruction_editing(self):
		"""Set if flow graph should allow inline instruction editing (assembly only)"""
		return self.is_option_set(FlowGraphOption.FlowGraphAllowsInlineInstructionEditing)

	@allows_inline_instruction_editing.setter
	def allows_inline_instruction_editing(self, value):
		self.set_option(FlowGraphOption.FlowGraphAllowsInlineInstructionEditing, value)

	@property
	def shows_secondary_reg_highlighting(self):
		"""Set if flow graph should highlight associated registers in the UI"""
		return self.is_option_set(FlowGraphOption.FlowGraphShowsSecondaryRegisterHighlighting)

	@shows_secondary_reg_highlighting.setter
	def shows_secondary_reg_highlighting(self, value):
		self.set_option(FlowGraphOption.FlowGraphShowsSecondaryRegisterHighlighting, value)

	@property
	def is_addressable(self):
		"""Set if flow graph should make use of address information"""
		return self.is_option_set(FlowGraphOption.FlowGraphIsAddressable)

	@is_addressable.setter
	def is_addressable(self, value):
		self.set_option(FlowGraphOption.FlowGraphIsAddressable, value)

	@property
	def is_workflow_graph(self):
		"""Set if flow graph should be treated as a workflow graph"""
		return self.is_option_set(FlowGraphOption.FlowGraphIsWorkflowGraph)

	@is_workflow_graph.setter
	def is_workflow_graph(self, value):
		self.set_option(FlowGraphOption.FlowGraphIsWorkflowGraph, value)

	def layout(self, callback=None):
		"""
		``layout`` starts rendering a graph for display. Once a layout is complete, each node will contain
		coordinates and extents that can be used to render a graph with minimum additional computation.
		This function does not wait for the graph to be ready to display, but a callback can be provided
		to signal when the graph is ready.

		:param callback callback: Function to be called when the graph is ready to display
		:return: Pending flow graph layout request object
		:rtype: FlowGraphLayoutRequest
		"""
		return FlowGraphLayoutRequest(self, callback)

	def _wait_complete(self):
		self._wait_cond.release()

	def layout_and_wait(self):
		"""
		``layout_and_wait`` starts rendering a graph for display, and waits for the graph to be ready to
		display. After this function returns, each node will contain coordinates and extents that can be
		used to render a graph with minimum additional computation.

		Do not use this API on the UI thread (use :func:`layout` with a callback instead).
		"""
		self._wait_cond = threading.Lock()
		self._wait_cond.acquire()
		_ = self.layout(self._wait_complete)

		self._wait_cond.acquire()
		self._wait_cond.release()

	def get_nodes_in_region(self, left, top, right, bottom):
		count = ctypes.c_ulonglong()
		nodes = core.BNGetFlowGraphNodesInRegion(self.handle, left, top, right, bottom, count)
		assert nodes is not None, "core.BNGetFlowGraphNodesInRegion returned None"
		result = []
		for i in range(0, count.value):
			fg_node = core.BNNewFlowGraphNodeReference(nodes[i])
			assert fg_node is not None, "core.BNNewFlowGraphNodeReference returned None"
			result.append(FlowGraphNode(self, fg_node))
		core.BNFreeFlowGraphNodeList(nodes, count.value)
		return result

	def append(self, node):
		"""
		``append`` adds a node to a flow graph.

		.. note:: After the graph has completed layout, this function has no effect.

		:param FlowGraphNode node: Node to add
		:return: Index of node
		:rtype: int
		"""
		return core.BNAddFlowGraphNode(self.handle, node.handle)

	def replace(self, index, node):
		"""
		``replace`` replaces an existing node in the graph with a new node.
		Any existing edges referencing the old node will be updated to point to
		the new node.

		.. note:: After the graph has completed layout, this function has no effect.

		:param index: Index of the node to replace
		:param node: New node with which to replace the old node
		"""
		core.BNReplaceFlowGraphNode(self.handle, index, node.handle)

	def clear(self):
		"""
		``clear`` clears all the nodes in the graph

		.. note:: After the graph has completed layout, this function has no effect.
		"""
		core.BNClearFlowGraphNodes(self.handle)

	def show(self, title):
		"""
		``show`` displays the graph in a new tab in the UI.

		:param str title: Title to show in the new tab
		"""
		interaction.show_graph_report(title, self)

	def update(self):
		"""
		``update`` can be overridden by subclasses to allow a graph to be updated after it has been
		presented in the UI. This will automatically occur if the function referenced by the :py:attr:`function`
		property has been updated.

		Return a new :class:`FlowGraph` object with the new information if updates are desired. If the graph
		does not need updating, ``None`` can be returned to leave the graph in its current state.

		:return: Updated graph, or ``None``
		:rtype: FlowGraph
		"""
		return NotImplemented

	def set_option(self, option, value=True):
		core.BNSetFlowGraphOption(self.handle, option, value)

	def is_option_set(self, option):
		return core.BNIsFlowGraphOptionSet(self.handle, option)

	@property
	def render_layers(self) -> List['binaryninja.RenderLayer']:
		"""
		Get the list of Render Layers which will be applied to this Flow Graph,
		after it calls populate_nodes.
		:return: List of Render Layers
		"""
		count = ctypes.c_size_t(0)
		layers = core.BNGetFlowGraphRenderLayers(self.handle, count)
		assert layers is not None, "core.BNGetFlowGraphRenderLayers returned None"

		try:
			result = []
			for i in range(0, count.value):
				result.append(binaryninja.RenderLayer(handle=layers[i]))

			return result
		finally:
			core.BNFreeRenderLayerList(layers)

	@render_layers.setter
	def render_layers(self, render_layers: List['binaryninja.RenderLayer']):
		for layer in self.render_layers:
			self.remove_render_layer(layer)
		for layer in render_layers:
			self.add_render_layer(layer)

	def add_render_layer(self, layer: 'binaryninja.RenderLayer'):
		"""
		Add a Render Layer to be applied to this Flow Graph. Note that layers will
		be applied in the order in which they are added.

		:param layer: Render Layer to add
		"""
		core.BNAddFlowGraphRenderLayer(self.handle, layer.handle)

	def remove_render_layer(self, layer: 'binaryninja.RenderLayer'):
		"""
		Remove a Render Layer from being applied to this Flow Graph

		:param layer: Render Layer to remove
		"""
		core.BNRemoveFlowGraphRenderLayer(self.handle, layer.handle)


class CoreFlowGraph(FlowGraph):
	def __init__(self, handle):
		super(CoreFlowGraph, self).__init__(handle)

	def update(self):
		graph = core.BNUpdateFlowGraph(self.handle)
		if not graph:
			return None
		return CoreFlowGraph(graph)


class FlowGraphLayout:
	def __init__(self, handle: Optional[core.BNCustomFlowGraphLayout] = None):
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNFlowGraphLayout)

	def register(self, name: str):
		"""
		Register a custom layout with the API
		"""
		self._cb = core.BNCustomFlowGraphLayout()
		self._cb.context = 0
		self._cb.layout = self._cb.layout.__class__(self._layout)
		self.handle = core.BNRegisterFlowGraphLayout(name, self._cb)

	def _layout(self, ctxt, graph_handle: core.BNFlowGraphHandle, node_handles: 'ctypes.pointer[core.BNFlowGraphNodeHandle]', node_handle_count: int) -> bool:
		try:
			graph = FlowGraph(handle=graph_handle)
			nodes = []
			for i in range(node_handle_count):
				nodes.append(FlowGraphNode(graph=graph, handle=node_handles[i]))
			return self.layout(graph, nodes)
		except:
			log_error(traceback.format_exc())
			return False

	def layout(self, graph: FlowGraph, nodes: List[FlowGraphNode]) -> bool:
		return False
