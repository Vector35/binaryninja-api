# Copyright (c) 2019-2026 Vector 35 Inc
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
from typing import Union, Optional
from .flowgraph import FlowGraph, FlowGraphNode
from .enums import BranchType
from .interaction import show_graph_report
from .log import log_warn
from . import lowlevelil
from . import mediumlevelil
from . import highlevelil


invalid_il_index = 0xffffffffffffffff


# This file contains a list of top level abstract classes for implementing BNIL instructions
@dataclass(frozen=True, repr=False, eq=False)
class BaseILInstruction:
	@classmethod
	def prepend_parent(cls, graph: FlowGraph, node: FlowGraphNode, nodes={}):
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
	def add_subgraph(cls, graph: FlowGraph, nodes) -> FlowGraph:
		node = FlowGraphNode(graph)
		node.lines = [f"{cls.__name__}"]
		graph.append(node)
		cls.prepend_parent(graph, node, nodes)
		return graph

	@classmethod
	def show_hierarchy_graph(cls):
		show_graph_report(f"{cls.__name__}", cls.add_subgraph(FlowGraph(), {}))


@dataclass(frozen=True, repr=False, eq=False)
class Constant(BaseILInstruction):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class BinaryOperation(BaseILInstruction):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class UnaryOperation(BaseILInstruction):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class Comparison(BinaryOperation):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class SSA(BaseILInstruction):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class Phi(SSA):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class FloatingPoint(BaseILInstruction):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class ControlFlow(BaseILInstruction):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class Terminal(ControlFlow):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class Loop(ControlFlow):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class Call(ControlFlow):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class Syscall(Call):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class Localcall(Call):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class Tailcall(Localcall):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class Return(Terminal):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class Signed(BaseILInstruction):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class Arithmetic(BaseILInstruction):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class Carry(Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class DoublePrecision(Arithmetic):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class Memory(BaseILInstruction):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class Load(BaseILInstruction):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class Store(BaseILInstruction):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class RegisterStack(BaseILInstruction):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class SetVar(BaseILInstruction):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class StackOperation(BaseILInstruction):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class SetReg:
	pass


@dataclass(frozen=True, repr=False, eq=False)
class Intrinsic(BaseILInstruction):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class VariableInstruction(BaseILInstruction):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class SSAVariableInstruction(SSA, VariableInstruction):
	pass


@dataclass(frozen=True, repr=False, eq=False)
class AliasedVariableInstruction(VariableInstruction):
	pass


class ILSourceLocation:
	"""
	ILSourceLocation is used to indicate where expressions were defined during the lifting process
	and gets propagated through the lifting process as an instruction's address/source_operand properties.
	These are used for, for example, integer display types and expression addresses.
	"""
	address: int
	source_operand: int

	source_llil_instruction: Optional['lowlevelil.LowLevelILInstruction'] = None
	source_mlil_instruction: Optional['mediumlevelil.MediumLevelILInstruction'] = None
	source_hlil_instruction: Optional['highlevelil.HighLevelILInstruction'] = None
	il_direct: bool = True

	def __init__(self, address: int, source_operand: int):
		self.address = address
		self.source_operand = source_operand

	def __repr__(self):
		instr = ""
		if self.source_llil_instruction is not None:
			instr = f" (from LLIL {self.source_llil_instruction})"
		if self.source_mlil_instruction is not None:
			instr = f" (from MLIL {self.source_mlil_instruction})"
		if self.source_hlil_instruction is not None:
			instr = f" (from HLIL {self.source_hlil_instruction})"
		return f"<ILSourceLocation: {self.address:x}, {self.source_operand}{instr}>"

	def __hash__(self):
		return hash((self.address, self.source_operand))

	def __eq__(self, other):
		if not isinstance(other, ILSourceLocation):
			return False
		return self.address == other.address and self.source_operand == other.source_operand

	@classmethod
	def from_instruction(
			cls,
			instr: Union['lowlevelil.LowLevelILInstruction', 'mediumlevelil.MediumLevelILInstruction', 'highlevelil.HighLevelILInstruction'],
			il_direct: bool = True
	) -> 'ILSourceLocation':
		"""
		Get the source location of a given instruction
		:param instr: Instruction, Low, Medium, or High level
		:return: Its location
		"""
		loc = cls(instr.address, instr.source_operand)
		if isinstance(instr, lowlevelil.LowLevelILInstruction):
			loc.source_llil_instruction = instr
		elif isinstance(instr, mediumlevelil.MediumLevelILInstruction):
			loc.source_mlil_instruction = instr
		elif isinstance(instr, highlevelil.HighLevelILInstruction):
			loc.source_hlil_instruction = instr
		else:
			log_warn(f"Unknown instruction type {type(instr)}")
		loc.il_direct = il_direct
		return loc
