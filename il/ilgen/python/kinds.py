"""How Python reads, annotates and writes each kind of value at a level, from the model's PyKind records."""

from ..model import SchemaError

# The decoders that kinds.xml's py elements name, each formatted with the raw read.
DECODERS = {'nonzero': '{} != 0'}
# The encoders that kinds.xml's py elements name. Each gives an expression of {p} for each slot the value takes.
ENCODERS = {
	'identifier': ('{p}.identifier',),
	'ssa_variable': ('{p}.var.identifier', '{p}.version'),
	'constant_data': ('{p}.type', '{p}.value'),
}


class Kinds:
	def __init__(self, schema):
		self.stem = schema.level.stem
		for kind in schema.kinds.values():
			if kind.py.decoder is not None and kind.py.decoder not in DECODERS:
				raise SchemaError(f'kind {kind.name}: no py decoder named {kind.py.decoder}')

			if kind.py.encoder is not None and kind.py.encoder not in ENCODERS:
				raise SchemaError(f'kind {kind.name}: no py encoder named {kind.py.encoder}')

	def type(self, kind):
		"""A property's type annotation."""
		if kind.py.stem_type is not None:
			return self.stem + kind.py.stem_type

		if kind.py.type is not None:
			return kind.py.type

		return f'List[{self.type(kind.item)}]'

	def detailed_type(self, kind):
		"""The type detailed_operands names, without quotes or module qualifiers."""
		if kind.py.detailed_type is not None:
			return kind.py.detailed_type

		if kind.py.stem_type is not None or kind.py.type is not None:
			return self.type(kind)

		return f'List[{self.detailed_type(kind.item)}]'

	def read(self, kind, location):
		"""A property's expression for a value of the kind stored inline at `location`."""
		slots = f'{location.first}, {location.second}' if kind.py.reader_slots == 2 else f'{location.first}'
		read = f'self._get_{kind.py.reader}({slots})'
		if kind.py.decoder is not None:
			return DECODERS[kind.py.decoder].format(read)

		return f'{self.type(kind)}({read})' if kind.py.construct else read

	@staticmethod
	def tag(kind, shared):
		"""The value's ILOperations tag, which is its kind's tag or else its reader's name. `shared` is whether
		another pair shares the value's register or variable, which can give it a different tag."""
		if shared and kind.py.shared_tag is not None:
			return kind.py.shared_tag

		return kind.py.tag if kind.py.tag is not None else kind.py.reader

	def param(self, kind):
		"""A builder parameter's type annotation."""
		if kind.py.param is None:
			return f'List[{self.param(kind.item)}]'

		return f'Optional[{kind.py.param}]' if kind.py.param_optional else kind.py.param

	@staticmethod
	def converts(kind):
		"""Whether a builder converts a parameter of the kind before storing it."""
		return kind.py.encoder is not None or kind.py.converter is not None

	@staticmethod
	def conversions(kind):
		"""An expression of the parameter {p} for each slot the value takes."""
		if kind.py.encoder is not None:
			return ENCODERS[kind.py.encoder]

		if kind.py.converter is not None:
			return (f'{kind.py.converter}({{p}})',)

		return ('{p}',)

	@staticmethod
	def adder(kind):
		"""(the function method that stores a list of the kind, the slots each item takes)."""
		if kind.py.adder is None:
			raise SchemaError(f'kind {kind.name}: no Python method stores it')

		return kind.py.adder, kind.py.item_slots or kind.item.slots
