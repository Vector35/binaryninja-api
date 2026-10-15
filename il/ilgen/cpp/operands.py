"""The data behind an IL level's GetOperands(). That's the operand usage enum, each usage's operand type, each op's
usages with the location they read, and the untemplated instruction getters that read them."""

from dataclasses import dataclass

from ..model import PartAccessor, SchemaError
from ..patch import Region
from .accessors import Accessors
from .kinds import SOURCE_CONTAINERS, Kinds
from .naming import Names


@dataclass(frozen=True)
class Entry:
	"""A stored value an op reports through GetOperands(), under its usage."""

	usage: str
	value: object
	getter: str


def reported(op):
	"""The values GetOperands() returns, which the cpp element can list in place of the default operand list."""
	return [op.values[name] for name in op.cpp.operands] if op.cpp.operands is not None else op.listed_values


class Operands:
	def __init__(self, schema):
		self.schema = schema
		self.level = schema.level
		self.kinds = Kinds(schema, SOURCE_CONTAINERS)
		self.names = Names(schema)
		self.getters = self.kinds.operand_getters(schema.kinds.values())

	def usage(self, op, value):
		"""The usage a value reports. That's the parent usage of the part it's read through, the op's own usage for it,
		its kind's partial reader for a partial value, or its accessor's name after the verb."""
		if isinstance(value, PartAccessor):
			explicit = value.owner.part.cpp.parent_usages.get(value.target.name)
			if explicit:
				return explicit

		if value.name in op.cpp.usages:
			return op.cpp.usages[value.name]

		if Kinds.partial(value):
			return value.kind.cpp.partial_reader

		return self.names.accessor(op, value).rest

	def entries(self, op):
		result = [Entry(self.usage(op, value), value, self.names.getter(op, value)) for value in reported(op)]
		if len({entry.usage for entry in result}) != len(result):
			raise SchemaError(f'{op.name}: two operands report the same usage')

		return result

	def tables(self):
		"""(usages in order of first use, {usage: operand type}, {Op: [Entry]})."""
		usages, types, tables = [], {}, {}
		for op in self.schema.ops.values():
			tables[op] = self.entries(op)
			for entry in tables[op]:
				operand_type = entry.value.kind.cpp.operand
				if operand_type is None:
					raise SchemaError(
						f'{op.name}.{entry.value.name}: kind {entry.value.kind.name} has no C++ operand type'
					)

				if entry.usage not in types:
					usages.append(entry.usage)
					types[entry.usage] = operand_type
				elif types[entry.usage] != operand_type:
					raise SchemaError(
						f'{op.name}: usage {entry.usage} is {operand_type} here but {types[entry.usage]} elsewhere'
					)

		return usages, types, tables

	def enumerator(self, usage):
		return f'{usage}{self.level.camel_name}OperandUsage'

	def usage_enum(self):
		usages, _, _ = self.tables()
		lines = [f'\t{self.enumerator(usage)},' for usage in usages]
		return '\n'.join([f'enum {self.level.stem}OperandUsage : uint8_t', '{', *lines, '};'])

	def location(self, entry, has_fields):
		location = entry.value.location
		fields = [self.enumerator(entry.usage), str(location.slot)]
		partial = Kinds.partial(entry.value)
		if has_fields and (location.in_part or partial):
			fields.append(str(location.field) if location.in_part else 'std::nullopt')

		if partial:
			fields.append('true')

		return '{' + ', '.join(fields) + '}'

	def operand_tables(self):
		il = self.level.stem
		usages, types, tables = self.tables()
		max_operands = max(len(entries) for entries in tables.values())
		lines = ['static constexpr std::array s_operandTypeForUsage = {']
		lines += [
			f'\tOperandUsageType{{{self.enumerator(u)}, {types[u]}{self.level.camel_name}Operand}},' for u in usages
		]
		lines += [
			'};',
			'',
			'static_assert(std::is_sorted(s_operandTypeForUsage.begin(), s_operandTypeForUsage.end()),',
			'\t"Operand type mapping array is not sorted by usage value");',
			'',
			'',
			f'constexpr inline {il}OperandType OperandTypeForUsage({il}OperandUsage usage)',
			'{',
			'\tif (static_cast<size_t>(usage) < s_operandTypeForUsage.size())',
			'\t\treturn s_operandTypeForUsage[usage].type;',
			'',
			f'\tthrow {il}InstructionAccessException();',
			'}',
			'',
			'',
			f'static constexpr size_t MaxOperands = {max_operands};',
			'using OperandLocations = InstructionOperandLocations<MaxOperands>;',
			'',
			'static constexpr std::array s_operandLocations = {',
		]
		# A level that stores no value in a part has no field in its location struct.
		has_fields = any(entry.value.location.in_part for entries in tables.values() for entry in entries)
		for op, entries in tables.items():
			locations = ', '.join(self.location(entry, has_fields) for entry in entries)
			lines.append(
				f'\tOperandLocations{{{self.names.operation(op)}' + (f', {{{locations}}}' if entries else '') + '},'
			)

		lines += ['};', '', '', 'VALIDATE_INSTRUCTION_ORDER(s_operandLocations);']
		return '\n'.join(lines)

	def instruction_getters(self, accessors):
		"""The level's untemplated instruction getters. Each reads the operand an op reports under the getter's usage.
		Ops that have the value but don't report it through GetOperands() call its templated getter."""
		il = self.level.stem
		getters, getter_ops, _ = accessors.generic()
		_, types, tables = self.tables()
		definitions = []
		for getter, generic_type in sorted(getters.items()):
			reporting = {
				op: [entry.usage for entry in tables[op] if entry.getter == getter] for op in getter_ops[getter]
			}
			usages = list(dict.fromkeys(usage for found in reporting.values() for usage in found))
			unreported = [op for op, found in reporting.items() if not found]
			if usages:
				if len({types[usage] for usage in usages}) != 1:
					raise SchemaError(f'{getter}: its usages have different operand types')

				listed = ', '.join(self.enumerator(usage) for usage in usages)
				fallback = f'return OperandForUsages(*this, {{{listed}}}).{self.getters[types[usages[0]]][0]}();'
			else:
				fallback = f'throw {il}InstructionAccessException();'

			if unreported:
				cases = []
				for op in unreported:
					operation = self.names.operation(op)
					cases += [f'\tcase {operation}:', f'\t\treturn {getter}<{operation}>();']

				body = '\tswitch (operation)\n\t{\n' + '\n'.join(cases) + f'\n\tdefault:\n\t\t{fallback}\n\t}}'
			else:
				body = f'\t{fallback}'

			definitions.append(f'{generic_type} {il}Instruction::{getter}() const\n{{\n{body}\n}}')

		return '\n\n\n'.join(definitions)


def regions(schema):
	operands = Operands(schema)
	getters = operands.instruction_getters(Accessors(schema, SOURCE_CONTAINERS))
	level = schema.level
	return [
		Region(level.header, level.region('operand-usages'), operands.usage_enum()),
		# Left unformatted so that each op's table stays on one line.
		Region(level.source, level.region('operand-tables'), operands.operand_tables(), formatted=False),
		Region(level.source, level.region('instruction-getters'), getters),
	]
