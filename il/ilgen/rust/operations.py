"""The Rust MLIL API. That's the operation structs and their lifted forms, the instruction kind enum with its
decoding and lifting, the lifted kind enum, and the lifted instruction's name and operands.

An operation struct holds an op's values as stored. It holds expressions as indices, lists as the start and length of
their items, and parts as the part's expression index. Its lifted form replaces each of those with the lifted value.
Ops that name the same struct share it, so their Rust values must match. Derived accessors are hand-written in the
other bindings and have no Rust form."""

from dataclasses import dataclass

from ..levels import Level
from ..model import SchemaError
from ..patch import Region
from .naming import Names
from .shared import cached_value_set

# The kinds.xml rust attributes MLIL reads.
ATTRIBUTES = (
	'type',
	'implements',
	'decoder',
	'field-suffix',
	'lifted-type',
	'lifted-boxed',
	'lifted-implements',
	'lifter',
	'operand',
)
# The traits a struct derives where all its field types implement them, beyond Clone, Debug and PartialEq.
DERIVABLE = frozenset({'Copy', 'Hash', 'Eq'})
# What the Rust primitives a struct stores implement. kinds.xml declares every other type's with implements and
# lifted-implements.
PRIMITIVES = {'u64': DERIVABLE, 'u32': DERIVABLE, 'i64': DERIVABLE, 'usize': DERIVABLE, 'f64': frozenset({'Copy'})}
# The MLIL decoders that kinds.xml's rust elements name. {0} and {1} are the value's slots. Each decodes a stored
# field of the kind's type, or gives several fields as (suffix, type, decode). A suffix of SIZE names the struct's size
# field.
DECODERS = {
	'expr_index': '{type}::from(op.operands[{0}])',
	'raw': 'op.operands[{0}]',
	'cast': 'op.operands[{0}] as {type}',
	'float': 'get_float(op.operands[{0}], op.size)',
	'instruction_index': '{type}(op.operands[{0}] as usize)',
	'variable': 'get_var(op.operands[{0}])',
	'ssa_variable': 'get_var_ssa(op.operands[{0}], op.operands[{1}] as usize)',
	# Core only stores valid reasons.
	'force_version_reason': 'unsafe {{ std::mem::transmute::<u8, ForceVersionReason>(op.operands[{0}] as u8) }}',
	'constant_data': [
		('_kind', 'u32', 'op.operands[{0}] as u32'),
		('_value', 'i64', 'op.operands[{1}] as i64'),
		('SIZE', 'usize', 'op.size'),
	],
}
# The lifters that kinds.xml's rust elements name. {f} is the stored field, {slot} is a list's first slot, and {stem}
# is the level's type stem.
LIFTERS = {
	'expr': 'self.lift_operand(op.{f})',
	'intrinsic': 'CoreIntrinsic::new(self.function.function().arch(), IntrinsicId(op.{f})).expect("Valid intrinsic")',
	'cached_value_set': cached_value_set('{stem}', 'op.{f}_index'),
	# The register value state is stored as its BNRegisterValueType.
	'constant_data': 'ConstantData::new(self.function.function(), RegisterValue {{ state: unsafe {{ '
	'std::mem::transmute::<u32, BNRegisterValueType>(op.{f}_kind) }}, value: op.{f}_value, offset: 0, '
	'size: op.size }})',
	'expr_list': 'self.lift_expr_list({slot})',
	'variable_list': 'self.get_var_list({slot})',
	'ssa_variable_list': 'self.get_ssa_var_list({slot})',
	'version_list': 'self.get_operand_list({slot})',
	'target_map': 'self.get_target_map({slot})',
}


@dataclass(frozen=True)
class RustLevel:
	"""A level's Rust module and the names of its types."""

	level: Level

	@property
	def stem(self):
		return self.level.camel_name

	@property
	def operation(self):
		return self.level.rust_path('operation')

	@property
	def instruction(self):
		return self.level.rust_path('instruction')

	@property
	def lift(self):
		return self.level.rust_path('lift')

	@property
	def expr(self):
		return f'{self.stem}ExpressionIndex'

	@property
	def lifted(self):
		return f'{self.stem}ILLiftedInstruction'

	@property
	def kind(self):
		return f'{self.stem}ILInstructionKind'

	@property
	def lifted_kind(self):
		return f'{self.stem}ILLiftedInstructionKind'

	@property
	def operand(self):
		return f'{self.stem}ILLiftedOperand'


@dataclass(frozen=True)
class StoredKind:
	"""How the operation structs store a kind and lift it."""

	# The stored fields as (suffix, type, decode from {0} and {1}), or None for a list, which stores the start and count
	# of its items.
	stored: list | None
	# The lifted type, or None where the kind lifts to itself.
	lifted_type: str | None
	# How the kind lifts from the stored field {f}, or from a list's first slot {slot}.
	lift: str | None
	# The lifted operand that reports the kind from {f}.
	report: str


@dataclass(frozen=True)
class Field:
	"""One Rust value of an op."""

	name: str
	# The stored fields as (name, type, decode).
	stored: list
	lifted_type: str | None
	lift: str | None
	operand: str
	# Whether lifting reads the operation struct, rather than only the instruction's slots.
	reads_op: bool = True


def traits(implemented, rust_type):
	if rust_type not in implemented:
		raise SchemaError(f'no kind gives the Rust type {rust_type}, so what it implements is unknown')

	return implemented[rust_type]


def derives(implemented, types, copy):
	common = frozenset.intersection(*(traits(implemented, t) for t in types)) if types else DERIVABLE
	names = (['Copy'] if copy and 'Copy' in common else []) + ['Clone', 'Debug']
	names += (['Hash'] if 'Hash' in common else []) + ['PartialEq'] + (['Eq'] if 'Eq' in common else [])
	return f"#[derive({', '.join(names)})]"


class Kinds:
	"""Each kind the level's operation structs can store, by name, as a StoredKind, and what each Rust type they hold
	implements."""

	def __init__(self, schema, level):
		self.level = level
		self.reported = [kind for kind in schema.kinds.values() if kind.rust.operand is not None]
		for kind in self.reported:
			if kind.rust.decoder is not None and kind.rust.decoder not in DECODERS:
				raise SchemaError(f'kind {kind.name}: no {schema.level.name} rust decoder named {kind.rust.decoder}')

			if kind.rust.lifter is not None and kind.rust.lifter not in LIFTERS:
				raise SchemaError(f'kind {kind.name}: no {schema.level.name} rust lifter named {kind.rust.lifter}')

		self.where = schema.level.name
		self.implemented = self.implementations()
		self.stored = {kind.name: self.stored_kind(kind) for kind in self.reported}

	def type(self, kind):
		return kind.rust.type

	@staticmethod
	def lifted_type(kind):
		if kind.rust.lifted_type is None:
			return None

		return f'Box<{kind.rust.lifted_type}>' if kind.rust.lifted_boxed else kind.rust.lifted_type

	def implementations(self):
		"""{Rust type: the traits it implements beyond Clone, Debug and PartialEq}. It covers the primitives, each type
		the level's kinds name, and the Vec that a list without a lifted type lifts to. A Vec implements its item type's
		traits, except Copy."""
		result = dict(PRIMITIVES)
		declarers = {}
		for kind in self.reported:
			for rust_type, declared in (
				(self.type(kind), kind.rust.implements),
				(self.lifted_type(kind), kind.rust.lifted_implements),
			):
				if rust_type is None or rust_type in PRIMITIVES and declared is None:
					continue

				if rust_type in PRIMITIVES:
					raise SchemaError(f'kind {kind.name}: declares what the Rust primitive {rust_type} implements')

				if declared is None:
					raise SchemaError(
						f"kind {kind.name}: doesn't say what the {self.where} Rust type {rust_type} implements"
					)

				first = declarers.setdefault(rust_type, kind.name)
				if result.setdefault(rust_type, declared) != declared:
					raise SchemaError(
						f'kinds {first} and {kind.name}: different traits for the {self.where} Rust type {rust_type}'
					)

		for kind in self.reported:
			if kind.is_list and kind.rust.lifted_type is None:
				item = self.type(kind.item)
				result[f'Vec<{item}>'] = traits(result, item) - {'Copy'}

		return result

	def report(self, kind, lifted_type):
		"""The lifted operand that reports a value of the kind from {f}. It reports a boxed value unboxed from a clone,
		and any other value that isn't Copy as a clone."""
		if kind.rust.lifted_boxed:
			return f'{kind.rust.operand}((*op.{{f}}).clone())'

		if 'Copy' not in traits(self.implemented, lifted_type):
			return f'{kind.rust.operand}(op.{{f}}.clone())'

		return f'{kind.rust.operand}(op.{{f}})'

	def stored_kind(self, kind):
		rust_type = self.type(kind)
		stored = None
		if kind.rust.decoder is not None:
			decoder = DECODERS[kind.rust.decoder]
			if isinstance(decoder, str):
				decoder = [(kind.rust.field_suffix, rust_type, decoder.replace('{type}', rust_type))]

			stored = decoder

		lifted_type = self.lifted_type(kind)
		if lifted_type is None and kind.is_list:
			lifted_type = f'Vec<{self.type(kind.item)}>'

		lift = LIFTERS[kind.rust.lifter].replace('{stem}', self.level.stem) if kind.rust.lifter is not None else None
		return StoredKind(stored, lifted_type, lift, self.report(kind, lifted_type or rust_type))


class Operations:
	def __init__(self, schema):
		self.schema = schema
		self.level = RustLevel(schema.level)
		self.names = Names(schema)
		self.kinds = Kinds(schema, self.level)
		self.fields = {op: self.op_fields(op) for op in schema.ops.values()}
		# {struct: [Op]} for the ops with values.
		self.structs = {}
		for op, fields in self.fields.items():
			if fields:
				self.structs.setdefault(self.names.struct(op), []).append(op)

		for struct, ops in self.structs.items():
			# Ops that share a struct may store their values in different slots, so only the fields' names and types
			# must match.
			layouts = {
				tuple(sorted((f.name, tuple((n, t) for n, t, _ in f.stored), f.lifted_type) for f in self.fields[op]))
				for op in ops
			}
			if len(layouts) > 1 or len({self.lifted(op) for op in ops}) > 1:
				raise SchemaError(
					f'Rust struct {struct} is shared by ops with different values: {[op.name for op in ops]}'
				)

	def lifted(self, op):
		"""The lifted struct, or None where every value lifts to itself."""
		return self.names.lifted(op) if any(f.lifted_type for f in self.fields[op]) else None

	def values(self, op):
		if op.rust.operands is not None:
			return [op.values[name] for name in op.rust.operands]

		return [value for value in op.listed_values if not value.derived]

	def op_fields(self, op):
		fields = []
		for value in self.values(op):
			name = self.names.field(op, value)
			location = value.location
			if location.in_part:
				# A value read through a part stores the part's expression and lifts from the part's list.
				if not (value.kind.holds_expressions and value.kind.is_list):
					raise SchemaError(f'{op.name}.{value.name}: Rust only reads expression lists through parts')

				expr = self.level.expr
				kind = self.kinds.stored[value.kind.name]
				fields.append(
					Field(
						name,
						[(name, expr, f'{expr}::from(op.operands[{location.slot}])')],
						kind.lifted_type,
						f'self.lift_part_expr_list(op.{name}, {self.names.operation(value.owner.part)}, {location.field})',
						kind.report.format(f=name),
					)
				)
				continue

			if value.kind.name not in self.kinds.stored:
				raise SchemaError(
					f'{op.name}.{value.name}: kind {value.kind.name} has no {self.schema.level.name} Rust operand'
				)

			kind = self.kinds.stored[value.kind.name]
			report = kind.report.format(f=name)
			if kind.stored is None:
				# A list lifts from the instruction's slots, and any other value from its stored field.
				item = self.names.list_item(op, value)
				stored = [
					(f'first_{item}', 'usize', f'op.operands[{location.slot + 1}] as usize'),
					(f'num_{item}s', 'usize', f'op.operands[{location.slot}] as usize'),
				]
				fields.append(
					Field(name, stored, kind.lifted_type, kind.lift.format(slot=location.slot), report, reads_op=False)
				)
				continue

			stored = [
				(
					'size' if suffix == 'SIZE' else name + suffix,
					rust_type,
					decode.format(location.first, location.second),
				)
				for suffix, rust_type, decode in kind.stored
			]
			fields.append(
				Field(name, stored, kind.lifted_type, kind.lift.format(f=name) if kind.lift else None, report)
			)

		return fields

	def struct_code(self, struct, ops):
		op = ops[0]
		fields = self.fields[op]
		stored = [s for f in fields for s in f.stored]
		lines = [
			'// ' + ', '.join(o.name for o in ops),
			derives(self.kinds.implemented, [t for _, t, _ in stored], copy=True),
			f'pub struct {struct} {{',
			*[f'    pub {n}: {t},' for n, t, _ in stored],
			'}',
		]
		lifted = self.lifted(op)
		if lifted:
			types = [f.lifted_type or f.stored[0][1] for f in fields]
			lines += [derives(self.kinds.implemented, types, copy=False), f'pub struct {lifted} {{']
			lines += [f'    pub {f.name}: {t},' for f, t in zip(fields, types)] + ['}']

		return '\n'.join(lines)

	def operation_rs(self):
		return '\n\n'.join(self.struct_code(struct, ops) for struct, ops in self.structs.items()) + '\n'

	def instruction_kind(self):
		lines = ['#[derive(Debug, Copy, Clone)]', f'pub enum {self.level.kind} {{']
		for op in self.schema.ops.values():
			variant = self.names.variant(op)
			lines.append(f'    {variant}({self.names.struct(op)}),' if self.fields[op] else f'    {variant},')

		return '\n'.join(lines + ['}'])

	def decode_arms(self):
		arms = []
		for op in self.schema.ops.values():
			variant = self.names.variant(op)
			if not self.fields[op]:
				arms.append(f'{self.names.operation(op)} => Op::{variant},')
				continue

			inits = ''.join(f' {n}: {d},' for f in self.fields[op] for n, _, d in f.stored)
			arms.append(f'{self.names.operation(op)} => Op::{variant}({self.names.struct(op)} {{{inits} }}),')

		return '\n'.join(arms)

	def lift_arms(self):
		arms = []
		for op in self.schema.ops.values():
			variant = self.names.variant(op)
			fields = self.fields[op]
			lifted = self.lifted(op)
			if not fields:
				arms.append(f'{variant} => Lifted::{variant},')
			elif not lifted:
				arms.append(f'{variant}(op) => Lifted::{variant}(op),')
			else:
				inits = ' '.join(f"{f.name}: {f.lift or 'op.' + f.name}," for f in fields)
				binding = 'op' if any(f.reads_op for f in fields) else '_op'
				arms.append(f'{variant}({binding}) => Lifted::{variant}({lifted} {{ {inits} }}),')

		return '\n'.join(arms)

	def lifted_rs(self):
		level = self.level
		enum = ['#[derive(Clone, Debug, PartialEq)]', f'pub enum {level.lifted_kind} {{']
		names = []
		operands = []
		for op in self.schema.ops.values():
			variant = self.names.variant(op)
			fields = self.fields[op]
			if not fields:
				enum.append(f'    {variant},')
				names.append(f'            {variant} => "{variant}",')
				operands.append(f'            {variant} => vec![],')
				continue

			enum.append(f'    {variant}({self.lifted(op) or self.names.struct(op)}),')
			names.append(f'            {variant}(_) => "{variant}",')
			entries = ''.join(f'("{f.name}", Operand::{f.operand}),' for f in fields)
			operands.append(f'            {variant}(op) => vec![{entries}],')

		enum.append('}')
		name_arms = '\n'.join(names)
		operand_arms = '\n'.join(operands)
		return (
			'\n'.join(enum)
			+ f"""

impl {level.lifted} {{
    pub fn name(&self) -> &'static str {{
        use {level.lifted_kind}::*;
        match self.kind {{
{name_arms}
        }}
    }}

    pub fn operands(&self) -> Vec<(&'static str, {level.operand})> {{
        use {level.lifted_kind}::*;
        use {level.operand} as Operand;
        match &self.kind {{
{operand_arms}
        }}
    }}
}}
"""
		)


def regions(schema):
	operations = Operations(schema)
	level = operations.level
	region = schema.level.region
	return [
		Region(level.operation, region('operations'), operations.operation_rs()),
		Region(level.instruction, region('instruction-kind'), operations.instruction_kind()),
		Region(level.instruction, region('decode'), operations.decode_arms()),
		Region(level.instruction, region('lift'), operations.lift_arms()),
		Region(level.lift, region('lifted-kind'), operations.lifted_rs()),
	]
