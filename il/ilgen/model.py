"""The IL schema as a typed model. loader.py builds it from the schema files, and the generators read only the model."""

import functools
import os
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

# The schema files sit beside this package.
DATA = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class SchemaError(Exception):
	"""A schema that can't be generated."""


@dataclass(frozen=True)
class CppKind:
	"""How C++ spells, reads and writes a value of a kind. il.xsd's CppKind documents each field."""

	suffix: str = ''
	type: str | None = None
	reader: str | None = None
	partial_reader: str | None = None
	decoder: str | None = None
	verb: str = 'Get'
	operand: str | None = None
	operand_type: str | None = None
	arg: str | None = None
	signed_arg: str | None = None
	reference: bool = False
	key: str | None = None
	value: str | None = None
	adder: str | None = None
	writer: str | None = None
	encoder: str | None = None
	version_setter: str | None = None


@dataclass(frozen=True)
class PyKind:
	"""How Python spells, reads and writes a value of a kind. il.xsd's PyKind documents each field."""

	type: str | None = None
	detailed_type: str | None = None
	reader: str | None = None
	reader_slots: int = 1
	construct: bool = False
	decoder: str | None = None
	tag: str | None = None
	param: str | None = None
	param_optional: bool = False
	converter: str | None = None
	default: str | None = None
	adder: str | None = None
	item_slots: int | None = None


@dataclass(frozen=True)
class RustKind:
	"""How Rust spells and decodes a value of a kind. il.xsd's RustKind documents each field."""

	suffix: str = ''
	type: str | None = None
	decoder: str | None = None


@dataclass(eq=False)
class Kind:
	"""A kind of value an operand can hold and how each language handles it. il.xsd's kind element documents what a
	value of it is."""

	name: str
	slots: int
	cpp: CppKind
	py: PyKind
	rust: RustKind
	expression: bool = False
	label: bool = False
	version: bool = False
	cached: bool = False
	item: 'Kind | None' = None
	ssa_of: 'Kind | None' = None

	@property
	def is_list(self):
		return self.item is not None

	@property
	def holds_expressions(self):
		"""Whether a value is a child expression or a list of them."""
		return self.expression or (self.is_list and self.item.expression)

	@property
	def holds_labels(self):
		"""Whether a value is a label or a list of them."""
		return self.label or (self.is_list and self.item.label)

	@property
	def width(self):
		"""The slots a value of the kind takes in an instruction. A list takes two, for its count and offset."""
		return 2 if self.is_list else self.slots


@dataclass(frozen=True)
class Name:
	"""A value name's entry in names.xml."""

	role: str
	# The C++ type of the level's generic accessor for the value, where it isn't the kind's.
	cpp_type: str | None
	# The role Rust names the accessor after, where it isn't the role.
	rust_role: str | None


@dataclass(frozen=True)
class Sort:
	"""What sort of value an expression operand holds or an op produces, and its width. A boolean has none."""

	sort: str
	width: str | None

	@property
	def boolean(self):
		return self.sort == 'boolean'


@dataclass(frozen=True)
class Location:
	"""Where a stored value is read from. That's its own slot, or the slot holding the part it's read through and its
	field in that part. A pair's `version` is the slot of its version, in the same op or part as its first slot."""

	slot: int
	field: int | None = None
	version: int | None = None

	@property
	def in_part(self):
		return self.field is not None

	@property
	def first(self):
		"""The value's first slot in the instruction that holds it, which is the op or the part."""
		return self.slot if self.field is None else self.field

	@property
	def second(self):
		"""The slot of the value's second half, such as an SSA register's version."""
		return self.first + 1 if self.version is None else self.version


@dataclass(eq=False)
class Value:
	"""A value an op exposes, which it reads from its location."""

	name: str
	kind: Kind

	@property
	def version_index(self):
		"""Which of its register or variable's versions a pair reads, when the register or variable is stored once
		for several pairs."""
		return 0

	@property
	def written(self):
		return False

	@property
	def is_part(self):
		"""Whether the value is a part operand, which holds a part rather than a value."""
		return False

	@property
	def listed(self):
		"""Whether the bindings' default operand lists include the value."""
		return True


@dataclass(eq=False)
class Operand(Value):
	"""One stored operand. A part operand holds a subexpression that the op reads values through, rather than a child
	expression."""

	slot: int = 0
	part: 'Op | None' = None
	sort: Sort | None = None
	is_written: bool = False
	signed: bool = False
	is_listed: bool = True
	description: ET.Element | None = None
	accessors: list = field(default_factory=list)
	# The pairs that combine this operand with another, in order.
	pairs: list = field(default_factory=list)

	@property
	def location(self):
		return Location(self.slot)

	@property
	def written(self):
		return self.is_written

	@property
	def listed(self):
		return self.is_listed

	@property
	def is_part(self):
		return self.part is not None

	@property
	def slots(self):
		return 1 if self.is_part else self.kind.width

	@property
	def copied_as(self):
		"""How CopyTo copies the operand's slots. A constraint is a possible value set, cached again in the
		destination."""
		if self.is_part:
			return 'part'

		if self.kind.holds_expressions:
			return 'expr_list' if self.kind.is_list else 'expr'

		if self.kind.holds_labels:
			return 'label'

		if self.kind.is_list:
			return 'list'

		if self.kind.cached:
			return 'constraint'

		return 'value'


@dataclass(eq=False)
class Pair(Value):
	"""A value combining two operands, such as an SSA register stack stored once with two versions."""

	of: Operand | None = None
	version: Operand | None = None

	@property
	def location(self):
		return Location(self.of.slot, version=self.version.slot)

	@property
	def version_index(self):
		return self.of.pairs.index(self)


@dataclass(eq=False)
class PartAccessor(Value):
	"""One of a part's values, which the op reads through a part operand."""

	owner: Operand | None = None
	target: Value | None = None
	description: ET.Element | None = None

	@property
	def location(self):
		inner = self.target.location
		return Location(self.owner.slot, inner.slot, inner.version)

	@property
	def version_index(self):
		return self.target.version_index

	@property
	def written(self):
		return self.target.written


@dataclass(eq=False)
class Arg:
	"""A builder argument. A value stored in a part that no accessor reads is qualified by its part."""

	# The name of the value the argument writes.
	value: str
	operand: Operand
	# The part operand the value is stored through, if any.
	part: Operand | None
	description: ET.Element | None
	qualified: bool = False
	# Whether another of the op's args writes a value of the same name, so the arg's parameter names its part too.
	clashes: bool = False

	@property
	def name(self):
		"""How builder params and documentation refer to the argument. A qualified argument's name is `part.value`."""
		return f'{self.part.name}.{self.value}' if self.qualified else self.value

	@property
	def param_words(self):
		"""The words of the arg's parameter name, which each binding spells in its own case."""
		return (self.part.name, self.value) if self.clashes else (self.value,)

	@property
	def kind(self):
		return self.operand.kind


@dataclass(frozen=True)
class Slot:
	"""What a builder stores in one operand: an arg, a fixed value, or a part, which it builds from the part's own
	slots."""

	operand: Operand
	arg: Arg | None = None
	fixed: str | None = None
	part: list | None = None
	part_size: str | None = None


@dataclass(eq=False)
class Builder:
	"""A function that constructs an op. `args` leaves out fixed operands and flags."""

	name: str
	handwritten: bool
	args: list
	# {operand name: the value the builder stores in it}
	fixed: dict
	# The names of the optional args.
	defaults: set
	size: str | None
	# {part operand name: size}
	part_sizes: dict
	description: ET.Element | None
	form: ET.Element | None

	def stored(self, operand, part):
		"""The arg that writes `operand`, stored through `part` or directly."""
		return next(arg for arg in self.args if arg.operand is operand and arg.part is part)

	def slots(self, op, part=None):
		"""[Slot] for each operand of `op`, which is the built op, or a part stored through the part operand `part`."""
		result = []
		for operand in op.operands:
			if operand.is_part:
				size = self.part_sizes.get(operand.name, '0')
				result.append(Slot(operand, part=self.slots(operand.part, operand), part_size=size))
			elif part is None and operand.name in self.fixed:
				result.append(Slot(operand, fixed=self.fixed[operand.name]))
			else:
				result.append(Slot(operand, arg=self.stored(operand, part)))

		return result

	def arg(self, name):
		return next((arg for arg in self.args if arg.name == name), None)


@dataclass(eq=False)
class CppOp:
	# {value name: the C++ accessor's name after its verb}
	renames: dict = field(default_factory=dict)
	usages: dict = field(default_factory=dict)
	parent_usages: dict = field(default_factory=dict)
	types: dict = field(default_factory=dict)
	operands: list | None = None


@dataclass(eq=False)
class PyOp:
	renames: dict = field(default_factory=dict)
	# {arg name: the builder parameter's name}
	params: dict = field(default_factory=dict)
	# The method name of an op with one builder group, where it isn't the group's name.
	builder: str | None = None
	# Whether Python has no builder for the op.
	no_builder: bool = False
	operands: list | None = None
	mixin: str | None = None
	# The traits whose mixins the op's class derives from, in order.
	traits: tuple = ()


@dataclass(eq=False)
class RustOp:
	variant: str | None = None
	marker: str | None = None
	# {builder name: lifter name}, where it isn't the op's name in lower case.
	lifters: dict = field(default_factory=dict)
	renames: dict = field(default_factory=dict)
	# The names of the values whose LLIL accessors drop the suffix their naming rule appends.
	unsuffixed: set = field(default_factory=set)
	# {operand name: the width its lifter builds a bare value at}
	lifts: dict = field(default_factory=dict)
	types: dict = field(default_factory=dict)


@dataclass(frozen=True)
class RustMarker:
	"""An LLIL Rust operation marker, as declared in llil.xml."""

	# The accessor names its ops share, as {value name: Rust name}.
	renames: dict
	# The names of the values whose accessors drop the suffix their naming rule appends.
	unsuffixed: frozenset
	# Whether operation.rs defines the whole marker by hand.
	handwritten: bool
	# The accessors operation.rs defines by hand on a generated marker.
	accessors: tuple
	# The LowLevelILExpressionKind method that returns an operation holding the marker.
	as_method: str | None


@dataclass(frozen=True)
class ShapeOperand:
	name: str
	kind: Kind


@dataclass(frozen=True)
class PyShape:
	"""A shape's hand-written Python base class."""

	# The base class's name after the level's class stem.
	base: str | None
	# The trait whose mixin the base class derives from.
	trait: str | None
	# The shape operands the base class decodes.
	decodes: tuple


@dataclass(eq=False)
class Shape:
	"""Operands and facts many ops share, which each op of the shape merges into its own."""

	name: str
	operands: list
	# The C++ base class, after the level's class stem.
	cpp_base: str | None
	py: PyShape

	@property
	def values(self):
		"""The names of the values the shape gives."""
		return [operand.name for operand in self.operands]


@dataclass(eq=False)
class Op:
	name: str
	placement: str
	sized: bool
	flags: bool
	shape: Shape | None
	# The SSA ops that take the op's place, or ('expanded',) where SSA form expands it, or () where it's valid in SSA
	# form.
	ssa_form: tuple
	doc: list
	description: ET.Element | None
	size: ET.Element | None
	form: ET.Element | None
	operands: list = field(default_factory=list)
	pairs: list = field(default_factory=list)
	result: Sort | None = None
	# Whether the op is only valid in SSA form.
	ssa_only: bool = False
	builders: list = field(default_factory=list)
	cpp: CppOp = field(default_factory=CppOp)
	py: PyOp = field(default_factory=PyOp)
	rust: RustOp = field(default_factory=RustOp)
	# The ops that contain this one, in schema order.
	parents: list = field(default_factory=list)

	@property
	def is_part(self):
		return self.placement == 'part'

	@property
	def inline_part(self):
		"""Whether the op is a part that only its parents' builders build, so it's never an instruction of its own."""
		return self.is_part and not self.builders

	@property
	def produces(self):
		return self.placement in ('expression', 'either')

	@property
	def slot_count(self):
		return sum(operand.slots for operand in self.operands)

	def operand(self, name):
		return next((operand for operand in self.operands if operand.name == name), None)

	@functools.cached_property
	def values(self):
		"""{name: value} for every operand, pair and part accessor."""
		found = {}
		for operand in self.operands:
			found[operand.name] = operand
			found.update((accessor.name, accessor) for accessor in operand.accessors)

		found.update((pair.name, pair) for pair in self.pairs)
		return found

	@functools.cached_property
	def default_values(self):
		"""The default operand list. It has the values in storage order, with each part operand replaced by its
		accessors and each pair in place of the operands it combines."""
		result = []
		for operand in self.operands:
			for value in operand.accessors or [operand]:
				pairs = value.pairs if isinstance(value, Operand) else []
				if not pairs:
					result.append(value)

				result += [pair for pair in pairs if pair not in result]

		return result

	@functools.cached_property
	def listed_values(self):
		"""The default values the bindings' default operand lists include."""
		return [value for value in self.default_values if value.listed]

	@property
	def sizeless(self):
		"""Whether the op's size means nothing. It's unsized but produces a value that isn't a boolean."""
		return not self.sized and self.result is not None and not self.result.boolean

	@functools.cached_property
	def members(self):
		"""Each part operand followed by its accessors, and each other operand or the first pair it's in, in storage
		order."""
		result = []
		for operand in self.operands:
			if operand.is_part:
				result += [operand, *operand.accessors]
				continue

			value = operand.pairs[0] if operand.pairs else operand
			if value not in result:
				result.append(value)

		return result


@dataclass(eq=False)
class Schema:
	"""One IL level's schema."""

	# The levels.Level that spells the level's names.
	level: object
	# {name: Kind}
	kinds: dict
	# {value name: Name}
	names: dict
	# {name: Shape}
	shapes: dict
	# {name: Op} in schema order.
	ops: dict
	# [(title or None, [Op])] in schema order. Ops outside any group have no title.
	groups: list
	# How many operand slots an instruction of the level holds.
	slots: int
	# Whether the level's instructions hold the flags they write.
	flags: bool
	# {marker: RustMarker} for the LLIL Rust operation markers declared in llil.xml.
	rust_markers: dict

	def name(self, value_name):
		"""The value name's entry in names.xml. A name without one is its own role."""
		return self.names.get(value_name) or Name(value_name, None, None)

	@functools.cached_property
	def read_through_parents(self):
		"""The parts some op holds in a part operand."""
		return {
			operand.part
			for op in self.ops.values()
			for operand in op.operands
			if operand.is_part and operand.part.is_part
		}
