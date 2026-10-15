"""An IL level's VisitExprs, visiting each op's child expressions and expression lists in storage order."""

from dataclasses import dataclass

from ..patch import Region
from .naming import Names


@dataclass(frozen=True)
class Child:
	getter: str
	is_list: bool


def children(names, op):
	"""[Child] for the op's child expressions and expression lists, in storage order."""
	result = []
	for operand in op.operands:
		for value in operand.accessors if operand.is_part else [operand]:
			if value.kind.holds_expressions:
				result.append(Child(names.getter(op, value), value.kind.is_list))

	return result


def visit_exprs(schema):
	level = schema.level
	names = Names(schema)
	cases = []
	for op in schema.ops.values():
		if op.inline_part:
			continue

		found = children(names, op)
		if not found:
			continue

		operation = names.operation(op)
		lines = [f'\tcase {operation}:']
		for child in found:
			if child.is_list:
				lines += [f'\t\tfor (const auto& expr : {child.getter}<{operation}>())', '\t\t\texpr.VisitExprs(func);']
			else:
				lines.append(f'\t\t{child.getter}<{operation}>().VisitExprs(func);')

		lines.append('\t\tbreak;')
		cases.append('\n'.join(lines))

	instruction = f'{level.stem}Instruction'
	return (
		f'void {instruction}::VisitExprs(bn::base::function_ref<bool(const {instruction}& expr)> func) const\n'
		'{\n\tif (!func(*this))\n\t\treturn;\n\tswitch (operation)\n\t{\n'
		+ '\n'.join(cases)
		+ '\n\tdefault:\n\t\tbreak;\n\t}\n}'
	)


def regions(schema):
	return [Region(schema.level.source, schema.level.region('visit'), visit_exprs(schema))]
