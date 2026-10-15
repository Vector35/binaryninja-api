"""An IL level's operation enum in binaryninjacore.h. It has one enumerator per op in schema order, with each group
under its title. Each op's trailing comment gives its SSA form and doc, and each part's comment names the ops that contain it.
clang-format aligns and wraps the comments."""

from .patch import Region

HEADER = 'binaryninjacore.h'


def alternatives(names):
	"""`names` joined as A, B or C."""
	return names[0] if len(names) == 1 else f"{', '.join(names[:-1])} or {names[-1]}"


def ssa_note(schema, op):
	"""What the op's comment says about SSA form, where the op isn't valid in it."""
	if not op.ssa_form:
		return []

	if op.ssa_form == ('expanded',):
		return ['Not valid in SSA form (expanded)']

	return [f'Not valid in SSA form (see {alternatives([schema.level.op(name) for name in op.ssa_form])})']


def comment(schema, op):
	"""The op's trailing comment. It gives the op's SSA form and doc, or for a part, the ops that contain it."""
	if not op.is_part:
		return ' '.join(ssa_note(schema, op) + op.doc)

	return f'Only valid within {alternatives([schema.level.op(parent.name) for parent in op.parents])}'


def enumerators(schema):
	last = schema.groups[-1][1][-1]
	body = []
	for index, (title, ops) in enumerate(schema.groups):
		if index:
			body.append('')

		if title is not None:
			body.append(f'// {title}')

		for op in ops:
			enumerator = schema.level.op(op.name) + ('' if op is last else ',')
			text = comment(schema, op)
			body.append(f'{enumerator}  // {text}' if text else enumerator)

	return '\n'.join(body)


def regions(schema):
	return [Region(HEADER, schema.level.region('operations'), enumerators(schema))]
