"""An IL level's instruction accessors. Each op that `accessible` returns has an accessor specialization. The level's
instruction class has generic getters, both templated on the op and untemplated, and generic setters templated on the
op."""

from collections import defaultdict
from dataclasses import dataclass

from ..model import Operand, Pair, SchemaError
from ..patch import Region
from .kinds import HEADER_CONTAINERS, Kinds
from .naming import Names


@dataclass(frozen=True)
class Setter:
	"""A setter taking one parameter, whose body is a single statement."""

	name: str
	param_type: str
	param: str
	body: str

	def declaration(self):
		return f'void {self.name}({self.param_type} {self.param})'

	def definition(self):
		return f'{self.declaration()} {{ {self.body} }}'


class Accessors:
	def __init__(self, schema, containers):
		self.schema = schema
		self.level = schema.level
		self.kinds = Kinds(schema, containers)
		self.names = Names(schema)

	def base(self, op):
		return self.level.stem + (op.shape.cpp_base if op.shape is not None else 'InstructionBase')

	def read(self, value):
		location = value.location
		call = f'GetRawOperandAs{self.kinds.reader(value)}({location.first})'
		if location.in_part:
			call = f'GetRawOperandAsExpr({location.slot}).{call}'

		return self.kinds.read(value.kind, call)

	def generic_type(self, value):
		"""The type of the level's generic accessor for a value. names.xml can give one for its name, and otherwise it's
		the kind's."""
		cpp_type = self.schema.name(value.name).cpp_type
		return cpp_type if cpp_type is not None else self.kinds.type(value.kind)

	def value_type(self, op, value):
		"""The type an op's accessor returns. That's the op's own type for it, its kind's signed type, or the generic
		type."""
		if value.name in op.cpp.types:
			return op.cpp.types[value.name]

		if isinstance(value, Operand) and value.signed and value.kind.cpp.signed_arg is not None:
			return value.kind.cpp.signed_arg

		return self.generic_type(value)

	def derived_type(self, value):
		"""The type a shape base class's hand-written accessor returns. A list kind's is a vector of its items, because
		the value is computed rather than read from a stored list."""
		if value.kind.is_list:
			return self.kinds.vector(self.kinds.type(value.kind.item))

		return self.kinds.type(value.kind)

	def getter(self, op, value):
		return f'{self.value_type(op, value)} {self.names.getter(op, value)}() const {{ return {self.read(value)}; }}'

	def setters(self, op, value):
		"""[Setter] for the version a value holds, a list the op's setters name, and a written list whose kind has a
		writer."""
		location = value.location
		if location is None:
			return []

		kind = value.kind
		accessor = self.names.accessor(op, value)
		# Version setters are named after the role, so a value whose rename gives its whole name has none.
		role = accessor.role
		prefix = f'GetRawOperandAsExpr({location.slot}).' if location.in_part else ''
		setter_name = 'Set' + accessor.rest

		def setter(name, param_type, param, update, slot=location.first):
			"""A setter whose body calls UpdateRawOperand{`update`} on `slot`."""
			return Setter(name, param_type, param, f'{prefix}UpdateRawOperand{update}({slot}, {param});')

		def items(item):
			return f'const {self.kinds.vector(item)}&'

		def version_setter(version_kind, slot):
			if version_kind.cpp.version_setter is None:
				raise SchemaError(f'{op.name}.{value.name}: kind {version_kind.name} has no C++ version setter')

			return [setter(f'Set{role}{version_kind.cpp.version_setter}', 'size_t', 'version', '', slot)]

		if kind.ssa_of is not None and role is not None:
			# A pair sets its version, which can be a memory version, as an aliased variable's is.
			return version_setter(value.version.kind if isinstance(value, Pair) else kind, location.second)

		if value.name in op.cpp.setters or value.written and kind.cpp.writer is not None:
			update = 'As' + kind.cpp.writer
			if kind.holds_expressions:
				lists = (f'{self.level.stem}Instruction', 'ExprId')
				return [setter(setter_name, items(item), 'exprs', update) for item in lists]

			return [setter(setter_name, items(self.kinds.type(kind.item)), 'values', update)]

		if kind.version and role is not None:
			return version_setter(kind, location.first)

		return []

	def inherited(self, op):
		"""The names of the values the op's shape base class reads, unless the op gives one its own C++ type."""
		return set(op.shape.cpp_values) - set(op.cpp.types) if op.shape is not None else set()

	def accessible(self):
		"""The ops with a specialization. That's all but the parts with no values or read through their parents."""
		skipped = self.schema.read_through_parents
		return [op for op in self.schema.ops.values() if not (op.is_part and (not op.default_values or op in skipped))]

	def specializations(self):
		blocks = []
		for op in self.accessible():
			inherited = self.inherited(op)
			values = [value for value in op.default_values if value.name not in inherited]
			if any(value.derived for value in values):
				raise SchemaError(f'{op.name}: a derived accessor that no shape base class implements')

			members = [self.getter(op, value) for value in values]
			members += [setter.definition() for value in values for setter in self.setters(op, value)]
			lines = [
				'template <>',
				f'struct {self.level.stem}InstructionAccessor<{self.names.operation(op)}> : public {self.base(op)}',
			]
			lines += ['{', *[f'\t{member}' for member in members], '};'] if members else ['{};']
			blocks.append('\n'.join(lines))

		return '\n'.join(blocks)

	def generic(self):
		"""({getter: C++ type}, {getter: [Op]}, {setter declaration: Setter})."""
		stored, derived, getter_ops, setters = defaultdict(set), defaultdict(set), defaultdict(list), {}
		for op in self.accessible():
			for value in op.default_values:
				getter = self.names.getter(op, value)
				if value.derived:
					derived[getter].add(self.derived_type(value))
				else:
					stored[getter].add(self.generic_type(value))

				getter_ops[getter].append(op)
				for setter in self.setters(op, value):
					setters[setter.declaration()] = setter

		getters = {}
		for getter in getter_ops:
			# Where a value is stored on some ops and derived on others, the stored form converts to the derived one.
			found = derived[getter] or stored[getter]
			if len(found) > 1:
				raise SchemaError(f'{getter}: {sorted(found)} on different ops')

			getters[getter] = next(iter(found))

		return getters, getter_ops, setters

	def templated(self):
		getters, _, setters = self.generic()
		operation = f'BN{self.level.stem}Operation'
		lines = []
		for getter, generic_type in sorted(getters.items()):
			lines += [
				f'template <{operation} N>',
				f'{generic_type} {getter}() const',
				'{',
				f'\treturn As<N>().{getter}();',
				'}',
			]

		for declaration, setter in sorted(setters.items()):
			lines += [f'template <{operation} N>', declaration, '{', f'\tAs<N>().{setter.name}({setter.param});', '}']

		return '\n'.join(lines)

	def declarations(self):
		getters, _, _ = self.generic()
		return '\n'.join(f'{generic_type} {getter}() const;' for getter, generic_type in sorted(getters.items()))


def regions(schema):
	accessors = Accessors(schema, HEADER_CONTAINERS)
	level = schema.level
	return [
		Region(level.header, level.region('accessors'), accessors.specializations()),
		Region(level.header, level.region('instruction-templates'), accessors.templated()),
		Region(level.header, level.region('instruction-getters'), accessors.declarations()),
	]
