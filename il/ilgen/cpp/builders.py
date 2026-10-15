"""An IL level's function builders. It declares them for the API's function class or another one, such as core's, and
defines them once for both."""

from dataclasses import dataclass

from .. import docs
from ..patch import Region
from .kinds import SOURCE_CONTAINERS, Containers, Kinds
from .naming import Names

API_HEADER = 'binaryninjaapi.h'
# How the API's header spells the containers builders take.
API_CONTAINERS = Containers('std::vector', 'std::map')


@dataclass(frozen=True)
class Param:
	"""A builder parameter. Only its declaration gives the default."""

	type: str
	name: str
	default: str | None = None

	def declaration(self):
		return f'{self.type} {self.name}' + (f' = {self.default}' if self.default is not None else '')

	def definition(self):
		return f'{self.type} {self.name}'


@dataclass(frozen=True)
class Function:
	"""A generated builder's declared parameters and documentation, and its definition."""

	name: str
	params: list
	doc: object
	doc_params: list
	definition: str

	def declaration(self):
		return f"ExprId {self.name}({', '.join(p.declaration() for p in self.params)});"


class Builders:
	def __init__(self, schema, containers):
		self.schema = schema
		self.level = schema.level
		self.kinds = Kinds(schema, containers)
		self.names = Names(schema)

	def params(self, op, builder, names):
		"""The declared parameters in declaration order, and the [(schema name, C++ name)] pairs that document them."""
		required = [arg for arg in builder.args if arg.name not in builder.defaults]
		optional = [arg for arg in builder.args if arg.name in builder.defaults]
		params = [Param(self.kinds.arg(arg.kind, arg.operand.signed), names[arg]) for arg in required]
		doc_params = [(arg.name, names[arg]) for arg in required]
		if op.flags:
			params.append(Param('uint32_t', 'flags', '0'))
			doc_params.append(('flags', 'flags'))

		params += [
			Param(self.kinds.arg(arg.kind, arg.operand.signed), names[arg], '{}' if arg.kind.is_list else '0')
			for arg in optional
		]
		doc_params += [(arg.name, names[arg]) for arg in optional]
		if op.sized and builder.size is None:
			params.insert(0, Param('size_t', 'size'))
			doc_params.insert(0, ('size', 'size'))

		params.append(Param('const ILSourceLocation&', 'loc', 'ILSourceLocation()'))
		return params, doc_params + [('loc', 'loc')]

	def slots(self, slots, names, prelude):
		"""The expressions that store each of the [Slot]."""
		out = []
		for slot in slots:
			if slot.part is not None:
				fields = ', '.join(self.slots(slot.part, names, prelude))
				flags = ', 0' if self.schema.flags else ''
				operation = self.level.op(slot.operand.part.name)
				out.append(f'AddExprWithLocation({operation}, loc, {slot.part_size}{flags}, {fields})')
			elif slot.fixed is not None:
				out.append(slot.fixed)
			else:
				out += self.kinds.encode(slot.operand.kind, names[slot.arg], prelude)

		return out

	def function(self, op, builder, name):
		names = self.names.params(builder.args)
		params, doc_params = self.params(op, builder, names)
		prelude = []
		slots = self.slots(builder.slots(op), names, prelude)
		size = builder.size or ('size' if op.sized else '0')
		flags = ['flags' if op.flags else '0'] if self.schema.flags else []
		call = ', '.join([self.level.op(op.name), 'loc', size, *flags, *slots])
		body = [f'\t{line}' for line in prelude] + [f'\treturn AddExprWithLocation({call});']
		definition_params = ', '.join(p.definition() for p in params)
		definition = f'ExprId {self.level.stem}Function::{name}({definition_params})\n{{\n' + '\n'.join(body) + '\n}'
		return Function(name, params, docs.builder_doc(op, builder), doc_params, definition)

	def functions(self):
		result = []
		for op in self.schema.ops.values():
			for builder, name in zip(op.builders, self.names.builders(op)):
				if not builder.handwritten:
					result.append(self.function(op, builder, name))

		return result


def declarations(schema, containers):
	"""The level's builder declarations, undocumented. `containers` is how the header spells std::vector and
	std::map."""
	return '\n'.join(function.declaration() for function in Builders(schema, containers).functions())


def regions(schema):
	declarations = []
	for function in Builders(schema, API_CONTAINERS).functions():
		declaration = function.declaration()
		if function.doc is not None:
			declaration = '\n'.join(['', *docs.cpp_comment(function.doc, function.doc_params), declaration])

		declarations.append(declaration)

	definitions = [function.definition for function in Builders(schema, SOURCE_CONTAINERS).functions()]
	level = schema.level
	return [
		Region(API_HEADER, level.region('builders'), '\n'.join(declarations).strip('\n')),
		Region(level.source, level.region('builders'), '\n\n\n'.join(definitions)),
	]
