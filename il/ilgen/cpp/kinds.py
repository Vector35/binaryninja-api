"""How C++ reads, spells and writes each kind of value, from the model's CppKind records."""

from dataclasses import dataclass

from ..model import SchemaError


def flattened_map(expr, prelude):
	"""Encodes a map as a list of its keys and values in turn, adding the statements that build the list to
	`prelude`."""
	prelude += [
		f'vector<size_t> {expr}List;',
		f'{expr}List.reserve({expr}.size() * 2);',
		f'for (auto& i : {expr})',
		'{',
		f'\t{expr}List.push_back(i.first);',
		f'\t{expr}List.push_back(i.second);',
		'}',
	]
	return [f'{expr}List.size()', f'AddIndexList({expr}List)']


# The decoders that kinds.xml's cpp elements name, each formatted with the raw read.
DECODERS = {'nonzero': '{} != 0'}
# The encoders that kinds.xml's cpp elements name. Each gives the expressions a builder stores a value's slots with,
# and may add statements to the prelude before the store.
ENCODERS = {
	'ssa_register': lambda expr, prelude: [f'{expr}.reg', f'{expr}.version'],
	'ssa_register_stack': lambda expr, prelude: [f'{expr}.regStack', f'{expr}.version'],
	'ssa_flag': lambda expr, prelude: [f'{expr}.flag', f'{expr}.version'],
	'cached_value_set': lambda expr, prelude: [f'CachePossibleValueSet({expr})'],
	'flattened_map': flattened_map,
}


@dataclass(frozen=True)
class Containers:
	"""How a file spells std::vector and std::map."""

	vector: str
	map: str


# How instruction headers and sources spell the containers. Sources use namespace std.
HEADER_CONTAINERS = Containers('_STD_VECTOR', '_STD_MAP')
SOURCE_CONTAINERS = Containers('vector', 'map')


class Kinds:
	def __init__(self, schema, containers):
		self.containers = containers
		for kind in schema.kinds.values():
			if kind.cpp.decoder is not None and kind.cpp.decoder not in DECODERS:
				raise SchemaError(f'kind {kind.name}: no cpp decoder named {kind.cpp.decoder}')

			if kind.cpp.encoder is not None and kind.cpp.encoder not in ENCODERS:
				raise SchemaError(f'kind {kind.name}: no cpp encoder named {kind.cpp.encoder}')

	def type(self, kind):
		"""The type an accessor of the kind returns. A kind with a key and no type of its own returns a map."""
		if kind.cpp.type is None and kind.cpp.key is not None:
			return self.map(kind)

		return kind.cpp.type

	def map(self, kind):
		return f'{self.containers.map}<{kind.cpp.key}, {kind.cpp.value}>'

	def vector(self, item):
		return f'{self.containers.vector}<{item}>'

	@staticmethod
	def partial(value):
		"""Whether C++ reads the value with its kind's partial reader, which reads the second version of a register or
		variable stored once for two pairs."""
		return value.version_index > 0

	@staticmethod
	def reader(value):
		"""What reads the value, after GetRawOperandAs."""
		kind = value.kind
		if not Kinds.partial(value):
			return kind.cpp.reader

		if value.version_index > 1 or kind.cpp.partial_reader is None:
			raise SchemaError(
				f'kind {kind.name}: a pair reading version {value.version_index + 1} of its {kind.ssa_of.name}, '
				'which C++ has no reader for'
			)

		return kind.cpp.partial_reader

	@staticmethod
	def read(kind, call):
		"""An accessor's expression for a value of the kind, from its raw read."""
		if kind.cpp.decoder is not None:
			return DECODERS[kind.cpp.decoder].format(call)

		return call

	def operand_getters(self, kinds):
		"""{operand type: (the operand class's getter for it, its return type in the .cpp)}."""
		getters = {}
		for kind in kinds:
			if kind.cpp.operand is None:
				continue

			returned = kind.cpp.operand_type or self.type(kind)
			getter = ('Get' + kind.cpp.operand, returned)
			if getters.setdefault(kind.cpp.operand, getter) != getter:
				raise SchemaError(
					f'{kind.name}: operand {kind.cpp.operand} returns {returned} here but '
					f'{getters[kind.cpp.operand][1]} elsewhere'
				)

		return getters

	def arg(self, kind, signed):
		"""A builder argument's type."""
		if signed and kind.cpp.signed_arg is not None:
			return kind.cpp.signed_arg

		if kind.cpp.key is not None:
			return f'const {self.map(kind)}&'

		if kind.is_list:
			return f'const {self.vector(kind.item.cpp.arg or self.type(kind.item))}&'

		base = kind.cpp.arg or self.type(kind)
		return f'const {base}&' if kind.cpp.reference else base

	@staticmethod
	def encode(kind, expr, prelude):
		"""The expressions a builder stores each of a value's slots with. Any statements they need are added to
		`prelude`."""
		if kind.cpp.encoder is not None:
			return ENCODERS[kind.cpp.encoder](expr, prelude)

		if kind.is_list:
			count = f'{expr}.size()' + (f' * {kind.item.slots}' if kind.item.slots > 1 else '')
			return [count, f'{kind.cpp.adder}({expr})']

		return [expr]
