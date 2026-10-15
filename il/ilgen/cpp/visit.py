"""An IL level's expression walk, which visits each op's child expressions and expression lists in its visit order.
LLIL and MLIL walk with VisitExprs. HLIL's VisitExprs walks without recursing, using CollectSubExprs."""

from dataclasses import dataclass

from ..patch import Region
from .naming import Names


@dataclass(frozen=True)
class Child:
	getter: str
	is_list: bool
	visited: bool
	# Whether only the AST form visits it.
	ast_only: bool


def children(names, op):
	"""[Child] for the op's child expressions and expression lists, in its visit order."""
	result = []
	for operand in op.visit_ordered():
		for value in operand.accessors if operand.is_part else [operand]:
			if value.kind.holds_expressions:
				result.append(Child(names.getter(op, value), value.kind.is_list, operand.visited, operand.ast_only))

	return result


def visit_exprs(schema):
	level = schema.level
	names = Names(schema)
	cases = []
	for op in schema.ops.values():
		if op.inline_part:
			continue

		found = [child for child in children(names, op) if child.visited]
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


def push(child, operation):
	"""Lines that push a child, or a list's items, so that they're popped in order."""
	if child.is_list:
		return [
			f'exprs = {child.getter}<{operation}>();',
			'for (auto i = exprs.rbegin(); i != exprs.rend(); ++i)',
			'\ttoProcess.push(i->exprIndex);',
		]

	return [f'toProcess.push({child.getter}<{operation}>().exprIndex);']


def collect_sub_exprs(schema):
	"""CollectSubExprs, which pushes an op's children onto a stack, last first, so that they're popped in order. The
	AST-only children are pushed only in the AST form."""
	level = schema.level
	names = Names(schema)
	cases = []
	for op in schema.ops.values():
		if op.inline_part:
			continue

		found = [child for child in children(names, op) if child.visited]
		if not found:
			continue

		operation = names.operation(op)
		lines = [f'\tcase {operation}:']
		# Push children in reverse, and wrap each run of AST-only children in one check.
		runs = []
		for child in reversed(found):
			if runs and runs[-1][0] == child.ast_only:
				runs[-1][1].append(child)
			else:
				runs.append((child.ast_only, [child]))

		for ast_only, members in runs:
			body = [line for child in members for line in push(child, operation)]
			if not ast_only:
				lines += [f'\t\t{line}' for line in body]
			elif len(body) == 1:
				lines += ['\t\tif (ast)', f'\t\t\t{body[0]}']
			else:
				lines += ['\t\tif (ast)', '\t\t{', *[f'\t\t\t{line}' for line in body], '\t\t}']

		lines.append('\t\tbreak;')
		cases.append('\n'.join(lines))

	instruction = f'{level.stem}Instruction'
	return (
		f'void {instruction}::CollectSubExprs(stack<size_t>& toProcess) const\n{{\n'
		f'\tvector<{instruction}> exprs;\n\tswitch (operation)\n\t{{\n'
		+ '\n'.join(cases)
		+ '\n\tdefault:\n\t\tbreak;\n\t}\n}'
	)


def regions(schema):
	level = schema.level
	text = collect_sub_exprs(schema) if schema.walker == 'collect' else visit_exprs(schema)
	return [Region(level.source, level.region('visit'), text)]
