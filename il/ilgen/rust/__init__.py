"""The Rust API's LLIL code, which is the operation markers, the kind enums and the lifters."""

from . import decode, lifting


def regions(schema):
	return decode.regions(schema) + lifting.regions(schema)
