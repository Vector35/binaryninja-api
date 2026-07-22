# Copyright (c) 2015-2026 Vector 35 Inc
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

from typing import Optional, Union, Any, Dict
from dataclasses import dataclass
import ctypes

import binaryninja
from . import _binaryninjacore as core
from .log import log_error_for_exception
from . import types
from . import highlevelil
from . import binaryview


class _CustomStringTypeMetaClass(type):
	def __iter__(self):
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		types = core.BNGetCustomStringTypeList(count)
		assert types is not None, "core.BNGetCustomStringTypeList returned None"
		try:
			for i in range(0, count.value):
				yield CustomStringType(handle=types[i])
		finally:
			core.BNFreeCustomStringTypeList(types)

	def __getitem__(cls, value):
		binaryninja._init_plugins()
		string_type = core.BNGetCustomStringTypeByName(str(value))
		if string_type is None:
			raise KeyError("'%s' is not a valid type" % str(value))
		return CustomStringType(handle=string_type)

	def __contains__(cls: '_CustomStringTypeMetaClass', name: object) -> bool:
		if not isinstance(name, str):
			return False
		try:
			cls[name]
			return True
		except KeyError:
			return False

	def get(cls: '_CustomStringTypeMetaClass', name: str, default: Any = None) -> Optional['CustomStringType']:
		try:
			return cls[name]
		except KeyError:
			if default is not None:
				return default
			return None


class CustomStringType(metaclass=_CustomStringTypeMetaClass):
	"""
	Represents a custom string type. String types contain the name of the string type and the prefix
	and postfix used to render them in code.
	"""
	def __init__(self, handle):
		self.handle = core.handle_of_type(handle, core.BNCustomStringType)

	def __str__(self):
		return self.name

	def __repr__(self):
		return f"<{self.__class__.__name__}: {self.name}>"

	def __eq__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return ctypes.addressof(self.handle.contents) == ctypes.addressof(other.handle.contents)

	def __ne__(self, other):
		if not isinstance(other, self.__class__):
			return NotImplemented
		return not (self == other)

	def __hash__(self):
		return hash(ctypes.addressof(self.handle.contents))

	@staticmethod
	def register(name: str, string_prefix="", string_postfix="") -> 'CustomStringType':
		"""
		Registers a new custom string type. This can be used when creating new
		:py:class:`~binaryninja.binaryview.DerivedString` objects.
		"""
		info = core.BNCustomStringTypeInfo()
		info.name = name
		info.stringPrefix = string_prefix
		info.stringPostfix = string_postfix
		handle = core.BNRegisterCustomStringType(info)
		return CustomStringType(handle)

	@property
	def name(self) -> str:
		"""Name of the custom string type."""
		return core.BNGetCustomStringTypeName(self.handle)

	@property
	def string_prefix(self) -> str:
		"""Prefix added before the opening quote in a custom string."""
		return core.BNGetCustomStringTypePrefix(self.handle)

	@property
	def string_postfix(self) -> str:
		"""Postfix added after the closing quote in a custom string."""
		return core.BNGetCustomStringTypePostfix(self.handle)


class _StringRecognizerMetaClass(type):
	def __iter__(self):
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		recognizers = core.BNGetStringRecognizerList(count)
		assert recognizers is not None, "core.BNGetStringRecognizerList returned None"
		try:
			for i in range(0, count.value):
				yield CoreStringRecognizer(handle=recognizers[i])
		finally:
			core.BNFreeStringRecognizerList(recognizers)

	def __getitem__(cls, value):
		binaryninja._init_plugins()
		recognizer = core.BNGetStringRecognizerByName(str(value))
		if recognizer is None:
			raise KeyError("'%s' is not a valid recognizer" % str(value))
		return CoreStringRecognizer(handle=recognizer)

	def __contains__(cls: '_StringRecognizerMetaClass', name: object) -> bool:
		if not isinstance(name, str):
			return False
		try:
			cls[name]
			return True
		except KeyError:
			return False

	def get(cls: '_StringRecognizerMetaClass', name: str, default: Any = None) -> Optional['StringRecognizer']:
		try:
			return cls[name]
		except KeyError:
			if default is not None:
				return default
			return None


class StringRecognizer(metaclass=_StringRecognizerMetaClass):
	"""
	``class StringRecognizer`` recognizes custom strings found in high level expressions.

	The :py:func:`recognize_constant`, :py:func:`recognize_constant_pointer`,
	:py:func:`recognize_extern_pointer`, and :py:func:`recognize_import` methods will be called for
	the respective expression types. These methods can return a :py:class:`~binaryninja.binaryview.DerivedString`
	containing the string information if a custom string is found for the expression. The
	:py:func:`is_valid_for_type` method can be optionally overridden to call the recognizer methods
	only when the expression type matches a custom filter.
	"""
	_registered_recognizers = []
	recognizer_name = None

	def __init__(self, handle=None):
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNStringRecognizer)

	def register(self):
		"""Registers the string recognizer."""
		if self.__class__.recognizer_name is None:
			raise ValueError("Recognizer name is missing")
		self._cb = core.BNCustomStringRecognizer()
		self._cb.context = 0
		if self.is_valid_for_type.__func__ != StringRecognizer.is_valid_for_type:
			self._cb.isValidForType = self._cb.isValidForType.__class__(self._is_valid_for_type)
		if self.recognize_constant.__func__ != StringRecognizer.recognize_constant:
			self._cb.recognizeConstant = self._cb.recognizeConstant.__class__(self._recognize_constant)
		if self.recognize_constant_pointer.__func__ != StringRecognizer.recognize_constant_pointer:
			self._cb.recognizeConstantPointer = self._cb.recognizeConstantPointer.__class__(
				self._recognize_constant_pointer)
		if self.recognize_extern_pointer.__func__ != StringRecognizer.recognize_extern_pointer:
			self._cb.recognizeExternPointer = self._cb.recognizeExternPointer.__class__(self._recognize_extern_pointer)
		if self.recognize_import.__func__ != StringRecognizer.recognize_import:
			self._cb.recognizeImport = self._cb.recognizeImport.__class__(self._recognize_import)
		if self.recognize_constant_data.__func__ != StringRecognizer.recognize_constant_data:
			self._cb.recognizeConstantData = self._cb.recognizeConstantData.__class__(
				self._recognize_constant_data)
		if self.recognize_struct_init.__func__ != StringRecognizer.recognize_struct_init:
			self._cb.recognizeStructInit = self._cb.recognizeStructInit.__class__(self._recognize_struct_init)
		self.handle = core.BNRegisterStringRecognizer(self.__class__.recognizer_name, self._cb)
		self.__class__._registered_recognizers.append(self)

	def _is_valid_for_type(self, ctxt, hlil, type):
		try:
			hlil = highlevelil.HighLevelILFunction(handle=core.BNNewHighLevelILFunctionReference(hlil))
			type = types.Type.create(handle=core.BNNewTypeReference(type))
			return self.is_valid_for_type(hlil, type)
		except Exception:
			log_error_for_exception("Unhandled Python exception in StringRecognizer._is_valid_for_type")
			return False

	def _recognize_constant(self, ctxt, hlil, expr, type, val, result):
		try:
			hlil = highlevelil.HighLevelILFunction(handle=core.BNNewHighLevelILFunctionReference(hlil))
			type = types.Type.create(handle=core.BNNewTypeReference(type))
			instr = hlil.get_expr(highlevelil.ExpressionIndex(expr))
			ref = self.recognize_constant(instr, type, val)
			if ref is None:
				return False
			result[0] = ref._to_core_struct(True)
			return True
		except Exception:
			log_error_for_exception("Unhandled Python exception in StringRecognizer._recognize_constant")
			return False

	def _recognize_constant_pointer(self, ctxt, hlil, expr, type, val, result):
		try:
			hlil = highlevelil.HighLevelILFunction(handle=core.BNNewHighLevelILFunctionReference(hlil))
			type = types.Type.create(handle=core.BNNewTypeReference(type))
			instr = hlil.get_expr(highlevelil.ExpressionIndex(expr))
			ref = self.recognize_constant_pointer(instr, type, val)
			if ref is None:
				return False
			result[0] = ref._to_core_struct(True)
			return True
		except Exception:
			log_error_for_exception("Unhandled Python exception in StringRecognizer._recognize_constant_pointer")
			return False

	def _recognize_extern_pointer(self, ctxt, hlil, expr, type, val, offset, result):
		try:
			hlil = highlevelil.HighLevelILFunction(handle=core.BNNewHighLevelILFunctionReference(hlil))
			type = types.Type.create(handle=core.BNNewTypeReference(type))
			instr = hlil.get_expr(highlevelil.ExpressionIndex(expr))
			ref = self.recognize_extern_pointer(instr, type, val, offset)
			if ref is None:
				return False
			result[0] = ref._to_core_struct(True)
			return True
		except Exception:
			log_error_for_exception("Unhandled Python exception in StringRecognizer._recognize_extern_pointer")
			return False

	def _recognize_import(self, ctxt, hlil, expr, type, val, result):
		try:
			hlil = highlevelil.HighLevelILFunction(handle=core.BNNewHighLevelILFunctionReference(hlil))
			type = types.Type.create(handle=core.BNNewTypeReference(type))
			instr = hlil.get_expr(highlevelil.ExpressionIndex(expr))
			ref = self.recognize_import(instr, type, val)
			if ref is None:
				return False
			result[0] = ref._to_core_struct(True)
			return True
		except Exception:
			log_error_for_exception("Unhandled Python exception in StringRecognizer._recognize_import")
			return False

	def _recognize_constant_data(self, ctxt, hlil, expr, result):
		try:
			hlil = highlevelil.HighLevelILFunction(handle=core.BNNewHighLevelILFunctionReference(hlil))
			instr = hlil.get_expr(highlevelil.ExpressionIndex(expr))
			ref = self.recognize_constant_data(instr)
			if ref is None:
				return False
			result[0] = ref._to_core_struct(True)
			return True
		except Exception:
			log_error_for_exception("Unhandled Python exception in StringRecognizer._recognize_constant_data")
			return False

	def _recognize_struct_init(self, ctxt, hlil, expr, type, field_offsets, field_values, field_count, result):
		try:
			hlil = highlevelil.HighLevelILFunction(handle=core.BNNewHighLevelILFunctionReference(hlil))
			type = types.Type.create(handle=core.BNNewTypeReference(type))
			instr = hlil.get_expr(highlevelil.ExpressionIndex(expr))
			vals = {field_offsets[i]: field_values[i] for i in range(field_count)}
			ref = self.recognize_struct_init(instr, type, vals)
			if ref is None:
				return False
			result[0] = ref._to_core_struct(True)
			return True
		except Exception:
			log_error_for_exception("Unhandled Python exception in StringRecognizer._recognize_struct_init")
			return False

	@property
	def name(self) -> str:
		if hasattr(self, 'handle'):
			return core.BNGetStringRecognizerName(self.handle)
		return self.__class__.recognizer_name

	def is_valid_for_type(self, func: 'highlevelil.HighLevelILFunction', type: 'types.Type') -> bool:
		"""
		Determines if the string recognizer should be called for the given expression type. It is optional
		to override this method. If the method isn't overridden, all expression types are passed to the
		string recognizer.

		:param func: `HighLevelILFunction` representing the high level function to be queried
		:param type: Type of the expression
		:return: `True` if the expression should be passed to the string recognizer, `False` otherwise
		"""
		return True

	def recognize_constant(
		self, instr: 'highlevelil.HighLevelILInstruction', type: 'types.Type', val: int
	) -> Optional['binaryview.DerivedString']:
		"""
		Can be overridden to recognize strings for a constant that is not a pointer. The expression type and
		value of the expression are given. If no string is found for this expression, this method should
		return `None`.

		If a string is found, return a :py:class:`~binaryninja.binaryview.DerivedString` with the string information.

		:param instr: High level expression
		:param type: Type of the expression
		:param val: Value of the expression
		:return: Optional :py:class:`~binaryninja.binaryview.DerivedString` for any string that is found.
		"""
		return None

	def recognize_constant_pointer(
		self, instr: 'highlevelil.HighLevelILInstruction', type: 'types.Type', val: int
	) -> Optional['binaryview.DerivedString']:
		"""
		Can be overridden to recognize strings for a constant pointer. The expression type and value of the
		expression are given. If no string is found for this expression, this method should return `None`.

		If a string is found, return a :py:class:`~binaryninja.binaryview.DerivedString` with the string information.

		:param instr: High level expression
		:param type: Type of the expression
		:param val: Value of the expression
		:return: Optional :py:class:`~binaryninja.binaryview.DerivedString` for any string that is found.
		"""
		return None

	def recognize_extern_pointer(
		self, instr: 'highlevelil.HighLevelILInstruction', type: 'types.Type', val: int, offset: int
	) -> Optional['binaryview.DerivedString']:
		"""
		Can be overridden to recognize strings for an external symbol. The expression type and value of the
		expression are given. If no string is found for this expression, this method should return `None`.

		If a string is found, return a :py:class:`~binaryninja.binaryview.DerivedString` with the string information.

		:param instr: High level expression
		:param type: Type of the expression
		:param val: Value of the expression
		:param offset: Offset into the external symbol
		:return: Optional :py:class:`~binaryninja.binaryview.DerivedString` for any string that is found.
		"""
		return None

	def recognize_import(
		self, instr: 'highlevelil.HighLevelILInstruction', type: 'types.Type', val: int
	) -> Optional['binaryview.DerivedString']:
		"""
		Can be overridden to recognize strings for an imported symbol. The expression type and value of the
		expression are given. If no string is found for this expression, this method should return `None`.

		If a string is found, return a :py:class:`~binaryninja.binaryview.DerivedString` with the string information.

		:param instr: High level expression
		:param type: Type of the expression
		:param val: Value of the expression
		:return: Optional :py:class:`~binaryninja.binaryview.DerivedString` for any string that is found.
		"""
		return None

	def recognize_constant_data(
		self, instr: 'highlevelil.HighLevelILInstruction'
	) -> Optional['binaryview.DerivedString']:
		"""
		Can be overridden to recognize strings for constant data expressions (HLIL_CONST_DATA).
		These expressions are generated by the outline resolver when it recovers constant data
		streams from scattered stores. The instruction provides access to the data buffer and
		builtin type via its ``constant_data`` accessor.

		If a string is found, return a :py:class:`~binaryninja.binaryview.DerivedString` with the string information.

		:param instr: High level expression containing the constant data
		:return: Optional :py:class:`~binaryninja.binaryview.DerivedString` for any string that is found.
		"""
		return None

	def recognize_struct_init(
		self, instr: 'highlevelil.HighLevelILInstruction', type: 'types.Type', vals: Dict[int, int]
	) -> Optional['binaryview.DerivedString']:
		"""
		Can be overridden to recognize strings for a structure initializer expression (HLIL_STRUCT_INIT).
		These are produced when the optimizer folds a run of structure field assignments into a single
		initializer. This is only called when all fields of the structure are assigned constants.
		The ``vals`` dictionary maps each field's byte offset within the structure to the constant value
		assigned to that field. If no string is found, this method should return `None`.

		If a string is found, return a :py:class:`~binaryninja.binaryview.DerivedString` with the string information.

		:param instr: High level structure initializer expression
		:param type: Structure type of the initializer
		:param vals: Dictionary mapping field offset to the constant value assigned to that field
		:return: Optional :py:class:`~binaryninja.binaryview.DerivedString` for any string that is found.
		"""
		return None


_recognizer_cache = {}


class CoreStringRecognizer(StringRecognizer):
	def __init__(self, handle: core.BNStringRecognizer):
		super().__init__(handle=handle)
		if type(self) is CoreStringRecognizer:
			global _recognizer_cache
			_recognizer_cache[ctypes.addressof(handle.contents)] = self

	@classmethod
	def _from_cache(cls, handle) -> 'StringRecognizer':
		"""
		Look up a recognizer from a given BNStringRecognizer handle
		:param handle: BNStringRecognizer pointer
		:return: Recognizer instance responsible for this handle
		"""
		global _recognizer_cache
		return _recognizer_cache.get(ctypes.addressof(handle.contents)) or cls(handle)

	def is_valid_for_type(self, func: 'highlevelil.HighLevelILFunction', type: 'types.Type') -> bool:
		return core.BNIsStringRecognizerValidForType(self.handle, func.handle, type.handle)

	def recognize_constant(
		self, instr: 'highlevelil.HighLevelILInstruction', type: 'types.Type', val: int
	) -> Optional['binaryview.DerivedString']:
		string = core.BNDerivedString()
		if not core.BNStringRecognizerRecognizeConstant(self.handle, instr.function.handle, instr.expr_index, type.handle, val, string):
			return None
		return binaryview.DerivedString._from_core_struct(string, True)

	def recognize_constant_pointer(
		self, instr: 'highlevelil.HighLevelILInstruction', type: 'types.Type', val: int
	) -> Optional['binaryview.DerivedString']:
		string = core.BNDerivedString()
		if not core.BNStringRecognizerRecognizeConstantPointer(self.handle, instr.function.handle, instr.expr_index, type.handle, val, string):
			return None
		return binaryview.DerivedString._from_core_struct(string, True)

	def recognize_extern_pointer(
		self, instr: 'highlevelil.HighLevelILInstruction', type: 'types.Type', val: int, offset: int
	) -> Optional['binaryview.DerivedString']:
		string = core.BNDerivedString()
		if not core.BNStringRecognizerRecognizeExternPointer(self.handle, instr.function.handle, instr.expr_index, type.handle, val, offset, string):
			return None
		return binaryview.DerivedString._from_core_struct(string, True)

	def recognize_import(
		self, instr: 'highlevelil.HighLevelILInstruction', type: 'types.Type', val: int
	) -> Optional['binaryview.DerivedString']:
		string = core.BNDerivedString()
		if not core.BNStringRecognizerRecognizeImport(self.handle, instr.function.handle, instr.expr_index, type.handle, val, string):
			return None
		return binaryview.DerivedString._from_core_struct(string, True)

	def recognize_constant_data(
		self, instr: 'highlevelil.HighLevelILInstruction'
	) -> Optional['binaryview.DerivedString']:
		string = core.BNDerivedString()
		if not core.BNStringRecognizerRecognizeConstantData(self.handle, instr.function.handle, instr.expr_index, string):
			return None
		return binaryview.DerivedString._from_core_struct(string, True)

	def recognize_struct_init(
		self, instr: 'highlevelil.HighLevelILInstruction', type: 'types.Type', vals: Dict[int, int]
	) -> Optional['binaryview.DerivedString']:
		count = len(vals)
		field_offsets = (ctypes.c_ulonglong * count)()
		field_values = (ctypes.c_longlong * count)()
		for i, (offset, value) in enumerate(vals.items()):
			field_offsets[i] = offset
			field_values[i] = value
		string = core.BNDerivedString()
		if not core.BNStringRecognizerRecognizeStructInit(self.handle, instr.function.handle, instr.expr_index, type.handle, field_offsets, field_values, count, string):
			return None
		return binaryview.DerivedString._from_core_struct(string, True)
