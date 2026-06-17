"""
Example Rust ``&str`` string recognizer and data renderer.

Rust represents a string slice (``&str``) as a two word "fat pointer": a pointer
to the UTF-8 bytes followed by the length of the slice. The type for it looks like::

	struct &str
	{
		char* string;     // offset 0: pointer to the UTF-8 bytes
		uint64_t length;  // offset 8: number of bytes
	};

This plugin allows Binary Ninja to recover the underlying text in two situations:

* **Structure initializers.** When the optimizer folds the field assignments of
  a ``&str`` value into a single ``HLIL_STRUCT_INIT`` expression, the recognizer
  reads ``length`` bytes from ``string`` and renders the literal in place.

* **Constant pointers to ``&str`` data variables.** When code takes the address
  of a ``&str`` data variable, the recognizer reads the fat pointer out of that
  data variable and renders the string it points at.

The recognized strings use the ``rs`` prefix, so they render as ``rs"..."``. A
matching data renderer renders ``&str`` data variables the same way in linear view.
"""

from typing import Dict, List, Optional

from binaryninja import BinaryView, Type
from binaryninja.datarender import DataRenderer, TypeContext
from binaryninja.enums import (
	DerivedStringLocationType, InstructionTextTokenType, TypeClass)
from binaryninja.function import DisassemblyTextLine, InstructionTextToken
from binaryninja.highlevelil import HighLevelILFunction, HighLevelILInstruction
from binaryninja.stringrecognizer import CustomStringType, StringRecognizer
from binaryninja.types import NamedTypeReferenceType
from binaryninja.binaryview import DerivedString, DerivedStringLocation

# Exact name of the Rust string slice type we recognize.
str_type_name = "&str"

# Register a custom string type so the core knows how to render the strings we
# recover. The prefix turns "..." into rs"...".
rust_str_type = CustomStringType.register(str_type_name, string_prefix="rs")


def _type_name(type: Optional[Type]) -> Optional[str]:
	"""Return the registered/reference name of a type, or None if it has none.

	A `&str` value arrives either as a named type reference (`type.name`) or,
	once resolved, as the underlying structure carrying a registered name."""
	if type is None:
		return None
	if isinstance(type, NamedTypeReferenceType):
		return str(type.name)
	registered = type.registered_name
	if registered is not None:
		return str(registered.name)
	return None


def _is_str_type(type: Optional[Type]) -> bool:
	"""True if `type` is exactly the `&str` type."""
	return _type_name(type) == str_type_name


def _is_pointer_to_str(type: Optional[Type]) -> bool:
	"""True if `type` is a pointer to the `&str` type."""
	return type is not None and type.type_class == TypeClass.PointerTypeClass and _is_str_type(type.target)


def _derived_string_from_slice(bv: BinaryView, pointer: int, length: int) -> Optional[DerivedString]:
	"""Read `length` UTF-8 bytes at `pointer` and wrap them in a DerivedString.

	The returned string is data-backed location pointing at the bytes so
	that the rendered literal cross-references the underlying string data."""
	if length < 0:
		return None
	data = bv.read(pointer, length)
	if data is None or len(data) != length:
		return None
	location = DerivedStringLocation(DerivedStringLocationType.DataBackedStringLocation, pointer, length)
	return DerivedString(data, location, rust_str_type)


def _read_str_data_var(bv: BinaryView, addr: int) -> Optional[DerivedString]:
	"""Reads the `&str` fat pointer stored at `addr` and renders the string it points to."""
	addr_size = bv.address_size
	pointer = bv.read_pointer(addr)
	raw_length = bv.read(addr + addr_size, addr_size)
	if raw_length is None or len(raw_length) != addr_size:
		return None
	length = int.from_bytes(raw_length, "little")
	return _derived_string_from_slice(bv, pointer, length)


class RustStrRecognizer(StringRecognizer):
	"""Recognizes Rust `&str` slices in HLIL expressions."""
	recognizer_name = "Rust &str"

	def is_valid_for_type(self, func: HighLevelILFunction, type: Type) -> bool:
		# Run for `&str` structure initializers and for constant pointers to a
		# `&str` data variable; skip every other expression type.
		return _is_str_type(type) or _is_pointer_to_str(type)

	def recognize_struct_init(
		self, instr: HighLevelILInstruction, type: Type, vals: Dict[int, int]
	) -> Optional[DerivedString]:
		# `vals` maps each constant field offset to its value: offset 0 is the
		# pointer to the bytes, offset at address size is the length of the slice.
		addr_size = instr.function.view.address_size
		if 0 not in vals or addr_size not in vals:
			return None
		pointer = vals[0]
		length = vals[addr_size]
		return _derived_string_from_slice(instr.function.view, pointer, length)

	def recognize_constant_pointer(
		self, instr: HighLevelILInstruction, type: Type, val: int
	) -> Optional[DerivedString]:
		# Only resolve when a `&str` data variable actually lives at the pointer.
		bv = instr.function.view
		data_var = bv.get_data_var_at(val)
		if data_var is None or not _is_str_type(data_var.type):
			return None
		return _read_str_data_var(bv, val)


class RustStrDataRenderer(DataRenderer):
	"""Renders `&str` data variables as `rs"..."` in linear view."""

	def perform_is_valid_for_data(
		self, ctxt, view: BinaryView, addr: int, type: Type, context: List[TypeContext]
	) -> bool:
		return _is_str_type(type) and _read_str_data_var(view, addr) is not None

	def perform_get_lines_for_data(
		self, ctxt, view: BinaryView, addr: int, type: Type, prefix: List[InstructionTextToken],
		width: int, context: List[TypeContext]
	) -> List[DisassemblyTextLine]:
		derived = _read_str_data_var(view, addr)
		tokens = list(prefix)
		if derived is None:
			# We verified this in `perform_is_valid_for_data`, but handle the case of failing to
			# fetch the string in case the data variable has changed since the check.
			tokens.append(InstructionTextToken(InstructionTextTokenType.TextToken, str(type)))
			return [DisassemblyTextLine(tokens, addr)]
		# `&str` is UTF-8 by definition; escape control characters and quotes for display.
		text = bytes(derived.value).decode("utf-8", "replace")
		escaped = text.encode("unicode_escape").decode("ascii").replace('"', '\\"')
		# `prefix` already carries the `<type> <name> = ` tokens, just append the literal.
		tokens.append(InstructionTextToken(InstructionTextTokenType.BraceToken, f'rs"'))
		tokens.append(InstructionTextToken(InstructionTextTokenType.StringToken, escaped))
		tokens.append(InstructionTextToken(InstructionTextTokenType.BraceToken, '"'))
		return [DisassemblyTextLine(tokens, addr)]

	def __del__(self):
		pass


RustStrRecognizer().register()
RustStrDataRenderer().register_type_specific()
