# Copyright (c) 2019-2022 Vector 35 Inc
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

from dataclasses import dataclass
from .flowgraph import FlowGraph, FlowGraphNode
from .enums import BranchType
from .interaction import show_graph_report
from .log import log_warn

# This file contains a list of top level abstract classes for implementing BNIL instructions
@dataclass(frozen=True, repr=False)
class BaseILInstruction:
	@classmethod
	def prepend_parent(cls, graph:FlowGraph, node:FlowGraphNode, nodes={}):
		for parent in cls.__bases__:
			if not issubclass(parent, BaseILInstruction):
				continue
			if parent.__name__ in nodes:
				nodes[parent.__name__].add_outgoing_edge(BranchType.UnconditionalBranch, node)
			else:
				parent_node = FlowGraphNode(graph)
				parent_node.lines = [f"{parent.__name__}"]
				parent_node.add_outgoing_edge(BranchType.UnconditionalBranch, node)
				graph.append(parent_node)
				nodes[parent.__name__] = parent_node
				parent.prepend_parent(graph, parent_node, nodes)

	@classmethod
	def add_subgraph(cls, graph, nodes):
		node = FlowGraphNode(graph)
		node.lines = [f"{cls.__name__}"]
		graph.append(node)
		cls.prepend_parent(graph, node, nodes)
		return graph

	@classmethod
	def show_hierarchy_graph(cls):
		show_graph_report(f"{cls.__name__}", cls.add_subgraph(FlowGraph(), {}))

@dataclass(frozen=True, repr=False)
class Constant(BaseILInstruction):
	pass


@dataclass(frozen=True, repr=False)
class BinaryOperation(BaseILInstruction):
	pass


@dataclass(frozen=True, repr=False)
class UnaryOperation(BaseILInstruction):
	pass


@dataclass(frozen=True, repr=False)
class Comparison(BinaryOperation):
	pass


@dataclass(frozen=True, repr=False)
class SSA(BaseILInstruction):
	pass


@dataclass(frozen=True, repr=False)
class Phi(SSA):
	pass


@dataclass(frozen=True, repr=False)
class FloatingPoint(BaseILInstruction):
	pass


@dataclass(frozen=True, repr=False)
class ControlFlow(BaseILInstruction):
	pass


@dataclass(frozen=True, repr=False)
class Terminal(ControlFlow):
	pass


@dataclass(frozen=True, repr=False)
class Loop(ControlFlow):
	pass


@dataclass(frozen=True, repr=False)
class Call(ControlFlow):
	pass


@dataclass(frozen=True, repr=False)
class Syscall(Call):
	pass


@dataclass(frozen=True, repr=False)
class Tailcall(Call):
	pass

@dataclass(frozen=True, repr=False)
class Return(Terminal):
	pass


@dataclass(frozen=True, repr=False)
class Signed(BaseILInstruction):
	pass


@dataclass(frozen=True, repr=False)
class Arithmetic(BaseILInstruction):
	pass


@dataclass(frozen=True, repr=False)
class Carry(Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class DoublePrecision(Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class Memory(BaseILInstruction):
	pass


@dataclass(frozen=True, repr=False)
class Load(BaseILInstruction):
	pass


@dataclass(frozen=True, repr=False)
class Store(BaseILInstruction):
	pass


@dataclass(frozen=True, repr=False)
class RegisterStack(BaseILInstruction):
	pass


@dataclass(frozen=True, repr=False)
class SetVar(BaseILInstruction):
	pass


@dataclass(frozen=True, repr=False)
class StackOperation(BaseILInstruction):
	pass


@dataclass(frozen=True, repr=False)
class SetReg:
	pass
