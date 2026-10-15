"""An IL level's Python op classes with their properties and detailed_operands, the ILInstruction and ILOperations
maps, and copy_expr_to's slot layouts.

The shape base classes, such as LowLevelILBinaryBase, and the mixins that ops name are hand-written in the level's
Python module, such as lowlevelil.py."""

from ..model import Pair, PyShape
from .kinds import Kinds
from .naming import Names

DECORATOR = '@dataclass(frozen=True, repr=False, eq=False)'
# What an op without a shape derives from, after the level's class stem.
NO_SHAPE = PyShape('Instruction', None, ())


def listed(op):
	"""The names of the values .operands returns, which the py element can list in place of the default operand
	list."""
	return op.py.operands if op.py.operands is not None else [value.name for value in op.listed_values]


def python_property(name, annotation, body):
	"""A property's lines in a class body, starting with the blank line that sets it apart from the member before."""
	return ['', '\t@property', f'\tdef {name}(self) -> {annotation}:', *[f'\t\t{line}' for line in body]]


def kind(op, name):
	"""The kind of a value, an alias of one, or a value only Python has."""
	if name in op.py.accessors:
		return op.py.accessors[name]

	return op.values[op.py.aliases.get(name, name)].kind


class Classes:
	def __init__(self, schema):
		self.schema = schema
		self.level = schema.level
		self.kinds = Kinds(schema)
		self.names = Names(schema)

	def bases(self, op):
		"""The op's mixin, its shape's mixin, its shape's base class or the instruction class, then a mixin for each of
		its traits."""
		base = op.shape.py if op.shape is not None else NO_SHAPE
		traits = [self.names.mixin(trait) for trait in op.py.traits]
		mixins = [mixin for mixin in (op.py.mixin, base.mixin) if mixin]
		return ', '.join(mixins + [self.level.stem + base.base] + traits)

	def inherited(self, op):
		"""The names of the values the op's shape base class already decodes the same way, and the shape's derived
		values, which its base or a mixin implements by hand."""
		if op.shape is None:
			return set()

		decodes = op.shape.py.decodes
		names = set()
		for shaped in op.shape.operands:
			own = op.operand(shaped.name)
			if shaped.name in decodes and own is not None and own.kind.name == shaped.kind.name:
				names.add(shaped.name)

		return names | set(op.shape.derived)

	def decode(self, op, value):
		if value.location.in_part:
			part = self.names.property(op, value.owner.name)
			return f'self.{part}.{self.names.property(value.owner.part, value.target.name)}'

		return self.kinds.read(value.kind, value.location)

	def properties(self, op, skip):
		"""Properties for part operands and for stored values the op's bases don't decode, in storage order, then for
		aliases."""
		order = [member for member in op.members if member.is_part or member in op.default_values]
		order += [value for value in op.default_values if value not in order]
		lines = []
		for value in order:
			name = self.names.property(op, value.name)
			if value.is_part:
				part = self.names.class_name(value.part)
				body = [f'result = self._get_expr({value.slot})', f'assert isinstance(result, {part})', 'return result']
				lines += python_property(name, f"'{part}'", body)
			elif value.name not in skip and not value.derived:
				lines += python_property(name, self.kinds.type(value.kind), [f'return {self.decode(op, value)}'])

		for alias, of in op.py.aliases.items():
			lines += python_property(
				alias, self.kinds.type(kind(op, of)), [f'return self.{self.names.property(op, of)}']
			)

		return lines

	def detailed_operands(self, op):
		entries = []
		for name in listed(op):
			prop = self.names.property(op, name)
			entries.append(f'\t("{prop}", self.{prop}, "{self.kinds.detailed_type(kind(op, name))}"),')

		annotation = f'List[Tuple[str, {self.level.stem}OperandType, str]]'
		return python_property('detailed_operands', annotation, ['return [', *entries, ']'])

	def op_class(self, op):
		inherited = self.inherited(op)
		body = self.properties(op, inherited)
		values = listed(op)
		if (values and set(values) != inherited) or (inherited and len(values) != len(inherited)):
			body += self.detailed_operands(op)

		header = [DECORATOR, f'class {self.names.class_name(op)}({self.bases(op)}):']
		# Each member starts with a blank line, which the first one after the class line doesn't need.
		return '\n'.join(header + (body[1:] if body else ['\tpass']))

	def il_instruction(self):
		stem = self.level.stem
		lines = [f'ILInstruction: Dict[{stem}Operation, type[{stem}Instruction]] = {{']
		lines += [f'\t{self.names.operation(op)}: {self.names.class_name(op)},' for op in self.schema.ops.values()]
		return '\n'.join(lines + ['}'])

	def tag(self, op, name):
		value = op.values.get(name)
		shared = isinstance(value, Pair) and sum(pair.of is value.of for pair in op.pairs) > 1
		return self.kinds.tag(kind(op, name), shared)

	def il_operations(self):
		lines = [f'ILOperations: ClassVar[Dict[{self.level.stem}Operation, List[Tuple[str, str]]]] = {{']
		for op in self.schema.ops.values():
			entries = ', '.join(f'("{self.names.property(op, name)}", "{self.tag(op, name)}")' for name in listed(op))
			lines.append(f'\t{self.names.operation(op)}: [{entries}],')

		return '\n'.join(lines + ['}'])

	def copy_layout(self, op):
		"""The op's slots as copy_expr_to's layout entries, or None where they hold labels."""
		entries = []
		for operand in op.operands:
			match operand.copied_as:
				case 'part':
					entries.append(
						f'("part", {self.names.operation(operand.part)}, ({self.copy_layout(operand.part)}))'
					)
				case 'label':
					return None
				case 'value':
					entries += ['"value"'] * operand.slots
				case copied:
					entries.append(f'"{copied}"')

		return ' '.join(f'{entry},' for entry in entries)

	def copy_layouts(self):
		entries = []
		has_labels = False
		for op in self.schema.ops.values():
			if op.inline_part:
				continue

			layout = self.copy_layout(op)
			if layout is None:
				has_labels = True
			else:
				entries.append(f'\t{self.names.operation(op)}: ({layout}),')

		lines = ['# Lists the slots `copy_expr_to` copies for each op.']
		if has_labels:
			lines = [
				"# Lists the slots `copy_expr_to` copies for each op. Ops that hold labels aren't listed because",
				'# `copy_expr_to` copies them itself.',
			]

		lines.append(f'_COPY_LAYOUTS: Dict[{self.level.stem}Operation, Tuple] = {{')
		return '\n'.join(lines + entries + ['}'])

	def classes(self):
		return '\n\n\n'.join(
			[*(self.op_class(op) for op in self.schema.ops.values()), self.il_instruction(), self.copy_layouts()]
		)
