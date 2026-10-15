"""CompareExprs for an ordered level. It compares by operation, then size, then each stored value in storage order,
recursing into child expressions and lists. A sized op whose shape is ordered by value alone skips the size.
HighLevelILInstruction's operator< and operator== use it."""

from ..model import SchemaError
from ..patch import Region
from .naming import Names


class Comparer:
	def __init__(self, schema):
		self.schema = schema
		self.names = Names(schema)

	def comparisons(self, op):
		"""Three-way comparisons of `a` and `b` in storage order, after the size where the op is ordered by it. A value
		whose kind isn't comparable compares each of its raw slots."""
		result = []
		if op.sized and (op.shape is None or op.shape.ordered_by_size):
			result.append('CompareValues(a.size, b.size)')

		for value in op.default_values:
			if value.derived:
				continue

			if value.location.in_part:
				raise SchemaError(f"{op.name}: {value.name} is read through a part, which CompareExprs doesn't handle")

			if not value.kind.cpp.comparable:
				slots = range(value.location.slot, value.location.slot + value.kind.width)
				result += [
					f'CompareValues(a.GetRawOperandAsInteger({slot}), b.GetRawOperandAsInteger({slot}))'
					for slot in slots
				]
				continue

			getter = f'{self.names.getter(op, value)}<{self.names.operation(op)}>()'
			compare = 'CompareLists' if value.kind.is_list else 'CompareValues'
			result.append(f'{compare}(a.{getter}, b.{getter})')

		return result

	def compare_exprs(self):
		il = self.schema.level.stem
		cases = []
		for op in self.schema.ops.values():
			found = self.comparisons(op)
			if not found:
				continue

			lines = [f'\tcase {self.names.operation(op)}:']
			for comparison in found[:-1]:
				lines += [f'\t\tif (int result = {comparison})', '\t\t\treturn result;']

			lines.append(f'\t\treturn {found[-1]};')
			cases.append('\n'.join(lines))

		return (
			f'static int CompareExprs(const {il}Instruction& a, const {il}Instruction& b)\n{{\n'
			'\tif (int result = CompareValues(a.operation, b.operation))\n\t\treturn result;\n'
			'\tswitch (a.operation)\n\t{\n' + '\n'.join(cases) + '\n\tdefault:\n\t\treturn 0;\n\t}\n}'
		)


def regions(schema):
	if not schema.ordered:
		return []

	return [Region(schema.level.source, schema.level.region('compare'), Comparer(schema).compare_exprs())]
