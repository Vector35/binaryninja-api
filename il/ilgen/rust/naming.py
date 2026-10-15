"""How the Rust API names an IL level's kind enum variants, operation types, lifters and values.

A variant is the op's name with each word capitalized. LLIL's operation markers and MLIL's and HLIL's operation
structs are named after the variant unless an op names its own. LLIL names a value's accessor after its role, then its
kind's suffix, such as dest_reg. MLIL and HLIL name a struct's field after the value itself."""

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
		"""The LLIL operation marker type the op's variant holds."""
		return op.rust.marker or self.variant(op)

	def struct(self, op):
		"""The MLIL or HLIL operation struct the op's variant holds."""
		return op.rust.struct or self.variant(op)

	def lifted(self, op):
		"""The MLIL or HLIL lifted operation struct, where the op has one."""
		return op.rust.lifted or 'Lifted' + self.struct(op)

	@staticmethod
	def lifters(op):
		"""Each builder's LLIL lifter name, where the op names one, or else the op's name in lower case."""
		return [op.rust.lifters.get(builder.name, op.name.lower()) for builder in op.builders]

	def operation(self, op):
		return self.level.op(op.name)

	def accessor(self, op, value):
		"""An LLIL marker's accessor for a value. The op or its marker can rename it. Otherwise a part operand's
		accessor is its name then _expr, and any other's is the value's role then its kind's suffix. A value the op or
		its marker marks unsuffixed has no suffix."""
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

	@staticmethod
	def field(op, value):
		"""An MLIL or HLIL operation struct's field for a value, which is the value's name unless the op renames it."""
		if value.name in op.rust.unsuffixed:
			raise SchemaError(f'{op.name}.{value.name}: suffix="false" renames an LLIL accessor, not a struct field')

		return op.rust.renames.get(value.name, value.name)

	def list_item(self, op, value):
		"""The {item} in the names of an MLIL or HLIL list's stored fields, first_{item} and num_{item}s. It's the op's
		name for the list, or else names.xml's for the value."""
		item = op.rust.lists.get(value.name) or self.schema.name(value.name).rust_item
		if item is None:
			raise SchemaError(f'{op.name}.{value.name}: a Rust list without an item name, in names.xml or the op')

		return item
