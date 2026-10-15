"""How the Rust API names an IL level's kind enum variants, operation markers, lifters and accessors.

A variant is the op's name with each word capitalized. An operation marker is named after the variant unless an op names
its own. An accessor is named after its value's role, then its kind's suffix, such as dest_reg."""

from ..case import capitalized
from ..model import SchemaError


class Names:
	def __init__(self, schema):
		self.level = schema.level
		self.schema = schema
		self.markers = schema.rust_markers

	@staticmethod
	def variant(op):
		return op.rust.variant or capitalized(op.name)

	def marker(self, op):
		"""The operation marker type the op's variant holds."""
		return op.rust.marker or self.variant(op)

	@staticmethod
	def lifters(op):
		"""Each builder's lifter name, where the op names one, or else the op's name in lower case."""
		return [op.rust.lifters.get(builder.name, op.name.lower()) for builder in op.builders]

	def operation(self, op):
		return self.level.op(op.name)

	def accessor(self, op, value):
		"""A marker's accessor for a value. The op or its marker can rename it. Otherwise a part operand's accessor is
		its name then _expr, and any other's is the value's role then its kind's suffix. A value the op or its marker
		marks unsuffixed has no suffix."""
		renamed = op.rust.renames.get(value.name)
		marker = self.markers.get(self.marker(op))
		if renamed is None and marker is not None:
			renamed = marker.renames.get(value.name)

		if renamed is not None:
			return renamed

		unsuffixed = value.name in op.rust.unsuffixed or (marker is not None and value.name in marker.unsuffixed)
		if value.is_part:
			return value.name if unsuffixed else f'{value.name}_expr'

		name = self.schema.name(value.name)
		role = name.role if name.rust_role is None else name.rust_role
		suffix = '' if unsuffixed else value.kind.rust.suffix
		spelled = '_'.join(part for part in (role, suffix) if part)
		if not spelled:
			raise SchemaError(f'{op.name}.{value.name}: neither its role nor its kind gives it a Rust name')

		return spelled
