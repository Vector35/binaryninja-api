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

import traceback
import ctypes
from typing import Optional, Any

import binaryninja
from . import _binaryninjacore as core
from . import function
from . import enums
from .log import log_error_for_exception
from . import types
from . import highlevelil
from . import languagerepresentation


class _ConstantRendererMetaClass(type):
	def __iter__(self):
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		renderers = core.BNGetConstantRendererList(count)
		assert renderers is not None, "core.BNGetConstantRendererList returned None"
		try:
			for i in range(0, count.value):
				yield CoreConstantRenderer(handle=renderers[i])
		finally:
			core.BNFreeConstantRendererList(renderers)

	def __getitem__(cls, value):
		binaryninja._init_plugins()
		renderer = core.BNGetConstantRendererByName(str(value))
		if renderer is None:
			raise KeyError("'%s' is not a valid renderer" % str(value))
		return CoreConstantRenderer(handle=renderer)

	def __contains__(cls: '_ConstantRendererMetaClass', name: object) -> bool:
		if not isinstance(name, str):
			return False
		try:
			cls[name]
			return True
		except KeyError:
			return False

	def get(cls: '_ConstantRendererMetaClass', name: str, default: Any = None) -> Optional['ConstantRenderer']:
		try:
			return cls[name]
		except KeyError:
			if default is not None:
				return default
			return None


class ConstantRenderer(metaclass=_ConstantRendererMetaClass):
	"""
	``class ConstantRenderer`` allows custom rendering of constants in high level representations.

	The :py:func:`render_constant` method will be called when rendering constants that aren't pointers, while the
	:py:func:`render_constant_pointer` method will be called when rendering constant pointers. The
	:py:func:`is_valid_for_type` method can be optionally overridden to call the rendering methods only when
	the expression type matches a custom filter.

	.. warning:: Python constant renderers can be slow. The callbacks run while rendering every \
	constant, and each call crosses the FFI boundary, builds wrapper objects, and takes the GIL, \
	serializing analysis threads. Always override :py:func:`is_valid_for_type` to reject types you do \
	not handle. For large binaries, write the renderer in C++ instead.
	"""
	_registered_renderers = []
	renderer_name = None

	def __init__(self, handle=None):
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNConstantRenderer)

	def register(self):
		"""Registers the constant renderer."""
		if self.__class__.renderer_name is None:
			raise ValueError("Renderer name is missing")
		self._cb = core.BNCustomConstantRenderer()
		self._cb.context = 0
		if self.is_valid_for_type.__func__ != ConstantRenderer.is_valid_for_type:
			self._cb.isValidForType = self._cb.isValidForType.__class__(self._is_valid_for_type)
		if self.render_constant.__func__ != ConstantRenderer.render_constant:
			self._cb.renderConstant = self._cb.renderConstant.__class__(self._render_constant)
		if self.render_constant_pointer.__func__ != ConstantRenderer.render_constant_pointer:
			self._cb.renderConstantPointer = self._cb.renderConstantPointer.__class__(self._render_constant_pointer)
		self.handle = core.BNRegisterConstantRenderer(self.__class__.renderer_name, self._cb)
		self.__class__._registered_renderers.append(self)

	def _is_valid_for_type(self, ctxt, hlil, type):
		try:
			hlil = highlevelil.HighLevelILFunction(handle=core.BNNewHighLevelILFunctionReference(hlil))
			type = types.Type.create(handle=core.BNNewTypeReference(type))
			return self.is_valid_for_type(hlil, type)
		except Exception:
			log_error_for_exception("Unhandled Python exception in ConstantRenderer._is_valid_for_type")
			return False

	def _render_constant(self, ctxt, hlil, expr, type, val, tokens, settings, precedence):
		try:
			hlil = highlevelil.HighLevelILFunction(handle=core.BNNewHighLevelILFunctionReference(hlil))
			type = types.Type.create(handle=core.BNNewTypeReference(type))
			tokens = languagerepresentation.HighLevelILTokenEmitter(core.BNNewHighLevelILTokenEmitterReference(tokens))
			if settings:
				settings = function.DisassemblySettings(core.BNNewDisassemblySettingsReference(settings))
			instr = hlil.get_expr(highlevelil.ExpressionIndex(expr))
			return self.render_constant(instr, type, val, tokens, settings, precedence)
		except Exception:
			log_error_for_exception("Unhandled Python exception in ConstantRenderer._render_constant_pointer")
			return False

	def _render_constant_pointer(self, ctxt, hlil, expr, type, val, tokens, settings, symbol_display, precedence):
		try:
			hlil = highlevelil.HighLevelILFunction(handle=core.BNNewHighLevelILFunctionReference(hlil))
			type = types.Type.create(handle=core.BNNewTypeReference(type))
			tokens = languagerepresentation.HighLevelILTokenEmitter(core.BNNewHighLevelILTokenEmitterReference(tokens))
			if settings:
				settings = function.DisassemblySettings(core.BNNewDisassemblySettingsReference(settings))
			symbol_display = enums.SymbolDisplayType(symbol_display)
			instr = hlil.get_expr(highlevelil.ExpressionIndex(expr))
			return self.render_constant_pointer(instr, type, val, tokens, settings, symbol_display, precedence)
		except Exception:
			log_error_for_exception("Unhandled Python exception in ConstantRenderer._render_constant_pointer")
			return False

	@property
	def name(self) -> str:
		if hasattr(self, 'handle'):
			return core.BNGetConstantRendererName(self.handle)
		return self.__class__.renderer_name

	def is_valid_for_type(self, func: 'highlevelil.HighLevelILFunction', type: 'types.Type') -> bool:
		"""
		Determines if the rendering methods should be called for the given expression type. It is optional
		to override this method. If the method isn't overridden, all expression types are passed to the
		rendering methods.

		:param func: `HighLevelILFunction` representing the high level function to be rendered
		:param type: Type of the expression
		:return: `True` if the constant should be passed to the rendering methods, `False` otherwise
		"""
		return True

	def render_constant(
		self, instr: 'highlevelil.HighLevelILInstruction', type: 'types.Type', val: int,
		tokens: 'languagerepresentation.HighLevelILTokenEmitter',
		settings: Optional['function.DisassemblySettings'], precedence: 'enums.OperatorPrecedence'
	) -> bool:
		"""
		Can be overridden to render a constant that is not a pointer. The expression type and value of the
		expression are given. If the expression is not handled by this constant renderer, this method should
		return `False`.

		To render a constant, emit the tokens to the `tokens` object and return `True`.

		:param instr: High level expression
		:param type: Type of the expression
		:param val: Value of the expression
		:param tokens: Token emitter for adding the rendered tokens
		:param settings: Settings for rendering
		:param precedence: Operator precedence of the expression
		:return: `True` if the constant was rendered, `False` otherwise
		"""
		return False

	def render_constant_pointer(
		self, instr: 'highlevelil.HighLevelILInstruction', type: 'types.Type', val: int,
		tokens: 'languagerepresentation.HighLevelILTokenEmitter',
		settings: Optional['function.DisassemblySettings'], symbol_display: 'enums.SymbolDisplayType',
		precedence: 'enums.OperatorPrecedence'
	) -> bool:
		"""
		Can be overridden to render a constant pointer. The expression type and value of the expression are given.
		If the expression is not handled by this constant renderer, this method should return `False`.

		To render a constant pointer, emit the tokens to the `tokens` object and return `True`.

		:param instr: High level expression
		:param type: Type of the expression
		:param val: Value of the expression
		:param tokens: Token emitter for adding the rendered tokens
		:param settings: Settings for rendering
		:param symbol_display: Type of symbol to display
		:param precedence: Operator precedence of the expression
		:return: `True` if the constant was rendered, `False` otherwise
		"""
		return False


_renderer_cache = {}


class CoreConstantRenderer(ConstantRenderer):
	def __init__(self, handle: core.BNConstantRenderer):
		super().__init__(handle=handle)
		if type(self) is CoreConstantRenderer:
			global _renderer_cache
			_renderer_cache[ctypes.addressof(handle.contents)] = self

	@classmethod
	def _from_cache(cls, handle) -> 'ConstantRenderer':
		"""
		Look up a renderer type from a given BNConstantRenderer handle
		:param handle: BNConstantRenderer pointer
		:return: Renderer type instance responsible for this handle
		"""
		global _renderer_cache
		return _renderer_cache.get(ctypes.addressof(handle.contents)) or cls(handle)

	def is_valid_for_type(self, func: 'highlevelil.HighLevelILFunction', type: 'types.Type') -> bool:
		return core.BNIsConstantRendererValidForType(self.handle, func.handle, type.handle)

	def render_constant(
		self, instr: 'highlevelil.HighLevelILInstruction', type: 'types.Type', val: int,
		tokens: 'languagerepresentation.HighLevelILTokenEmitter',
		settings: Optional['function.DisassemblySettings'], precedence: 'enums.OperatorPrecedence'
	) -> bool:
		if settings is not None:
			settings = settings.handle
		return core.BNConstantRendererRenderConstant(self.handle, instr.function.handle, instr.expr_index,
			type.handle, val, tokens.handle, settings, precedence)

	def render_constant_pointer(
		self, instr: 'highlevelil.HighLevelILInstruction', type: 'types.Type', val: int,
		tokens: 'languagerepresentation.HighLevelILTokenEmitter',
		settings: Optional['function.DisassemblySettings'], symbol_display: 'enums.SymbolDisplayType',
		precedence: 'enums.OperatorPrecedence'
	) -> bool:
		if settings is not None:
			settings = settings.handle
		return core.BNConstantRendererRenderConstantPointer(self.handle, instr.function.handle, instr.expr_index,
			type.handle, val, tokens.handle, settings, symbol_display, precedence)
