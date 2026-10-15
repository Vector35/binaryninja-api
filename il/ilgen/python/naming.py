"""How the Python API names an IL level's classes, properties, builder methods and builder parameters.

A property is named after its value, unless the op renames it. A builder method is named after its builder."""

from ..case import camel, capitalized


class Names:
	def __init__(self, schema):
		self.level = schema.level
		self.stem = schema.level.stem

	@staticmethod
	def property(op, name):
		return op.py.renames.get(name, name)

	def class_name(self, op):
		return self.stem + capitalized(op.name)

	def operation(self, op):
		return f'{self.stem}Operation.{self.level.op(op.name)}'

	@staticmethod
	def mixin(trait):
		return camel(trait)

	def param(self, op, arg):
		"""The builder parameter for an arg. The op's py param can name it. Otherwise it's the property name of the
		value it writes, or its parameter words in snake_case where another arg writes a value of the same name."""
		param = op.py.params.get(arg.name)
		if param is not None:
			return param

		if arg.clashes:
			return '_'.join(arg.param_words)

		return self.property(op, arg.value)

	@staticmethod
	def methods(op):
		"""[(method name, builder)] for each builder that Python has a method for. Python has none for an op that's only
		valid in SSA form, unless the op names one."""
		if op.py.no_builder or (op.ssa_only and op.py.builder is None):
			return []

		if op.py.builder is not None:
			return [(op.py.builder, op.builders[0])]

		return [(builder.name, builder) for builder in op.builders]
