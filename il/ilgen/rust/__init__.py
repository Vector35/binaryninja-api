"""The Rust API's IL code. For LLIL that's the operation markers, the kind enums and the lifters, and for MLIL it's the
operation structs and the kind enums."""

from . import decode, lifting, operations


def regions(schema):
	if schema.level.rust_structs:
		return operations.regions(schema)

	return decode.regions(schema) + lifting.regions(schema)
