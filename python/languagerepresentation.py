# Copyright (c) 2024 Vector 35 Inc
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

import ctypes
import traceback
from typing import List, Optional, Union

# Binary Ninja components
import binaryninja
from . import _binaryninjacore as core
from . import architecture
from . import binaryview
from . import function
from . import highlevelil
from . import highlight
from . import lineformatter
from . import variable
from . import types
from .log import log_error
from .enums import BraceRequirement, HighlightStandardColor, InstructionTextTokenType, OperatorPrecedence, ScopeType, \
	SymbolDisplayType, SymbolDisplayResult


class HighLevelILTokenEmitter:
	"""
	``class HighLevelILTokenEmitter`` contains methods for emitting text tokens for High Level IL instructions.
	Methods are provided for typical patterns found in various high level languages.

	This class cannot be instantiated directly. An instance of the class will be provided when the methods
	in ``class LanguageRepresentationFunction`` are called.
	"""
	def __init__(self, handle: core.BNHighLevelILTokenEmitterHandle):
		self.handle = handle

	def __del__(self):
		if core is not None:
			core.BNFreeHighLevelILTokenEmitter(self.handle)

	def new_line(self):
		"""Starts a new line in the output."""
		core.BNHighLevelILTokenEmitterNewLine(self.handle)

	def increase_indent(self):
		"""Increases the indentation level by one."""
		core.BNHighLevelILTokenEmitterIncreaseIndent(self.handle)

	def decrease_indent(self):
		"""Decreases the indentation level by one."""
		core.BNHighLevelILTokenEmitterDecreaseIndent(self.handle)

	def scope_separator(self):
		"""
		Indicates that visual separation of scopes is desirable at the current position. By default,
		this will insert a blank line, but this can be configured by the user.
		"""
		core.BNHighLevelILTokenEmitterScopeSeparator(self.handle)

	def begin_scope(self, scope_type: ScopeType):
		"""Begins a new scope. Insertion of newlines and braces will be handled using the current settings."""
		core.BNHighLevelILTokenEmitterBeginScope(self.handle, scope_type)

	def end_scope(self, scope_type: ScopeType):
		"""Ends the current scope."""
		core.BNHighLevelILTokenEmitterEndScope(self.handle, scope_type)

	def scope_continuation(self, force_same_line: bool):
		"""Continues the previous scope with a new associated scope. This is most commonly used for ``else`` statements."""
		core.BNHighLevelILTokenEmitterScopeContinuation(self.handle, force_same_line)

	def finalize_scope(self):
		"""Finalizes the previous scope, indicating that there are no more associated scopes."""
		core.BNHighLevelILTokenEmitterFinalizeScope(self.handle)

	def no_indent_for_this_line(self):
		"""Forces there to be no indentation for the next line."""
		core.BNHighLevelILTokenEmitterNoIndentForThisLine(self.handle)

	class ZeroConfidenceContext:
		"""
		``class ZeroConfidenceContext`` is a context manager that optionally forces tokens to be of zero confidence
		inside the context.
		"""
		def __init__(self, emitter: 'HighLevelILTokenEmitter', enabled: bool):
			self.emitter = emitter
			self.enabled = enabled

		def __enter__(self):
			if self.enabled:
				core.BNHighLevelILTokenEmitterBeginForceZeroConfidence(self.emitter.handle)

		def __exit__(self, exc_type, exc_val, exc_tb):
			if self.enabled:
				core.BNHighLevelILTokenEmitterEndForceZeroConfidence(self.emitter.handle)

	def force_zero_confidence(self, enabled: bool = True) -> 'HighLevelILTokenEmitter.ZeroConfidenceContext':
		"""
		Returns a context manager that forces tokens inside of it to be of zero confidence. If ``False`` is passed
		to this method, the context has no effect, allowing the caller to conditionally apply this behavior.
		"""
		return HighLevelILTokenEmitter.ZeroConfidenceContext(self, enabled)

	class ExprContext:
		"""
		``class ExprContext`` is a context manager that associates the tokens inside the context with the given
		High Level IL expression.
		"""
		def __init__(self, emitter: 'HighLevelILTokenEmitter', hlil_expr: highlevelil.HighLevelILInstruction):
			self.emitter = emitter
			self.expr = hlil_expr
			self.prev_expr = None

		def __enter__(self):
			expr = core.BNTokenEmitterExpr()
			expr.address = self.expr.address
			expr.sourceOperand = self.expr.source_operand
			expr.exprIndex = self.expr.expr_index
			expr.instrIndex = self.expr.instr_index
			self.prev_expr = core.BNHighLevelILTokenEmitterSetCurrentExpr(self.emitter.handle, expr)

		def __exit__(self, exc_type, exc_val, exc_tb):
			if self.prev_expr is not None:
				core.BNHighLevelILTokenEmitterRestoreCurrentExpr(self.emitter.handle, self.prev_expr)

	def expr(self, hlil_expr: 'highlevelil.HighLevelILInstruction') -> 'HighLevelILTokenEmitter.ExprContext':
		"""
		Returns a context manager that associates the tokens inside the context with the given High Level IL expression.
		"""
		return HighLevelILTokenEmitter.ExprContext(self, hlil_expr)

	def finalize(self):
		"""Finalizes all tokens in the output."""
		core.BNHighLevelILTokenEmitterFinalize(self.handle)

	def append(self, tokens: Union['architecture.InstructionTextToken', List['architecture.InstructionTextToken']]):
		"""Appends a token or list of tokens to the output."""
		if not isinstance(tokens, list):
			tokens = [tokens]
		buf = architecture.InstructionTextToken._get_core_struct(tokens)
		for i in range(len(tokens)):
			core.BNHighLevelILTokenEmitterAppend(self.handle, buf[i])

	def append_open_paren(self):
		"""Appends an open parenthesis (``(``) to the output."""
		core.BNHighLevelILTokenEmitterAppendOpenParen(self.handle)

	def append_close_paren(self):
		"""Appends a close parenthesis (``)``) to the output."""
		core.BNHighLevelILTokenEmitterAppendCloseParen(self.handle)

	def append_open_bracket(self):
		"""Appends an open bracket (``[``) to the output."""
		core.BNHighLevelILTokenEmitterAppendOpenBracket(self.handle)

	def append_close_bracket(self):
		"""Appends a close bracket (``]``) to the output."""
		core.BNHighLevelILTokenEmitterAppendCloseBracket(self.handle)

	def append_open_brace(self):
		"""Appends an open brace (``{``) to the output."""
		core.BNHighLevelILTokenEmitterAppendOpenBrace(self.handle)

	def append_close_brace(self):
		"""Appends a close brace (``}``) to the output."""
		core.BNHighLevelILTokenEmitterAppendCloseBrace(self.handle)

	def append_semicolon(self):
		"""Appends a semicolon (``;``) to the output."""
		core.BNHighLevelILTokenEmitterAppendSemicolon(self.handle)

	@property
	def current_tokens(self) -> List['function.InstructionTextToken']:
		"""The list of tokens on the current line (read-only)."""
		count = ctypes.c_ulonglong()
		tokens = core.BNHighLevelILTokenEmitterGetCurrentTokens(self.handle, count)
		result = []
		if tokens is not None:
			result = function.InstructionTextToken._from_core_struct(tokens, count.value)
			core.BNFreeInstructionText(tokens, count.value)
		return result

	@property
	def lines(self) -> List['function.DisassemblyTextLine']:
		"""The list of lines in the output (read-only)."""
		count = ctypes.c_ulonglong()
		lines = core.BNHighLevelILTokenEmitterGetLines(self.handle, count)
		result = []
		if lines is not None:
			result = []
			for i in range(0, count.value):
				addr = lines[i].addr
				color = highlight.HighlightColor._from_core_struct(lines[i].highlight)
				tokens = function.InstructionTextToken._from_core_struct(lines[i].tokens, lines[i].count)
				result.append(function.DisassemblyTextLine(tokens, addr, color=color))
			core.BNFreeDisassemblyTextLines(lines, count.value)
		return result

	@property
	def brace_requirement(self) -> BraceRequirement:
		"""The requirement for insertion of braces around scopes in the output."""
		return core.BNHighLevelILTokenEmitterGetBraceRequirement(self.handle)

	@brace_requirement.setter
	def brace_requirement(self, value: BraceRequirement):
		core.BNHighLevelILTokenEmitterSetBraceRequirement(self.handle, value)

	@property
	def braces_around_switch_cases(self):
		"""Whether cases within switch statements should always have braces around them."""
		return core.BNHighLevelILTokenEmitterHasBracesAroundSwitchCases(self.handle)

	@braces_around_switch_cases.setter
	def braces_around_switch_cases(self, value: bool):
		core.BNHighLevelILTokenEmitterSetBracesAroundSwitchCases(self.handle, value)

	@property
	def default_braces_on_same_line(self):
		"""
		Whether braces should default to being on the same line as the statement that begins the scope.
		If the user has explicitly set a preference, this setting will be ignored and the user's preference
		will be used instead.
		"""
		return core.BNHighLevelILTokenEmitterGetDefaultBracesOnSameLine(self.handle)

	@default_braces_on_same_line.setter
	def default_braces_on_same_line(self, value: bool):
		core.BNHighLevelILTokenEmitterSetDefaultBracesOnSameLine(self.handle, value)

	@property
	def simple_scope_allowed(self):
		"""Whether omitting braces around single-line scopes is allowed."""
		return core.BNHighLevelILTokenEmitterIsSimpleScopeAllowed(self.handle)

	@simple_scope_allowed.setter
	def simple_scope_allowed(self, value: bool):
		core.BNHighLevelILTokenEmitterSetSimpleScopeAllowed(self.handle, value)

	def append_size_token(self, size: int, token_type: InstructionTextTokenType):
		"""Appends a size token for the given size in the High Level IL syntax."""
		core.BNAddHighLevelILSizeToken(size, token_type, self.handle)

	def append_float_size_token(self, size: int, token_type: InstructionTextTokenType):
		"""Appends a floating point size token for the given size in the High Level IL syntax."""
		core.BNAddHighLevelILFloatSizeToken(size, token_type, self.handle)

	def append_var_text_token(
			self, var: 'variable.CoreVariable', instr: 'highlevelil.HighLevelILInstruction',
			size: int
	):
		"""Appends tokens for access to a variable."""
		core.BNAddHighLevelILVarTextToken(
			instr.function.handle, var.to_BNVariable(), self.handle, instr.expr_index, size)

	def append_integer_text_token(self, instr: 'highlevelil.HighLevelILInstruction', value: int, size: int):
		"""Appends tokens for a constant intenger value."""
		core.BNAddHighLevelILIntegerTextToken(instr.function.handle, instr.expr_index, value, size, self.handle)

	def append_array_index_token(
			self, instr: 'highlevelil.HighLevelILInstruction', value: int, size: int, address: int = 0):
		"""Appends tokens for accessing an array by index."""
		core.BNAddHighLevelILArrayIndexToken(instr.function.handle, instr.expr_index, value, size, self.handle, address)

	def append_pointer_text_token(
			self, instr: 'highlevelil.HighLevelILInstruction', value: int,
			settings: Optional['function.DisassemblySettings'], symbol_display: SymbolDisplayType,
			precedence: OperatorPrecedence, allow_short_string: bool = False
	) -> SymbolDisplayResult:
		"""Appends tokens for displaying a constant pointer value."""
		if settings is not None:
			settings = settings.handle
		return SymbolDisplayResult(core.BNAddHighLevelILPointerTextToken(
			instr.function.handle, instr.expr_index, value, self.handle, settings, symbol_display, precedence,
			allow_short_string))

	def append_constant_text_token(
			self, instr: 'highlevelil.HighLevelILInstruction', value: int, size: int,
			settings: Optional['function.DisassemblySettings'], precedence: OperatorPrecedence
	):
		"""Appends tokens for a constant value."""
		if settings is not None:
			settings = settings.handle
		core.BNAddHighLevelILConstantTextToken(
			instr.function.handle, instr.expr_index, value, size, self.handle, settings, precedence)

	@staticmethod
	def names_for_outer_structure_members(
			view: 'binaryview.BinaryView', struct_type: 'types.Type', var: 'highlevelil.HighLevelILInstruction',
	) -> List[str]:
		"""
		Gets the list of names for the outer structure members when accessing a structure member. This list
		can be passed for the ``typeNames`` parameter of the ``class InstructionTextToken`` constructor.
		"""
		count = ctypes.c_ulonglong()
		result = core.BNAddNamesForOuterStructureMembers(
			view.handle, struct_type.handle, var.function.handle, var.expr_index, count)
		names = []
		if result is not None:
			for i in range(count.value):
				names.append(result[i].decode("utf-8"))
			core.BNFreeStringList(result, count.value)
		return names


class LanguageRepresentationFunction:
	"""
	``class LanguageRepresentationFunction`` represents a single function in a registered high level language.
	"""
	_registered_instances = []
	comment_start_string = "// "
	comment_end_string = ""
	annotation_start_string = "{"
	annotation_end_string = "}"

	def __init__(
			self, func_type: Optional['LanguageRepresentationFunctionType'] = None,
			arch: Optional['architecture.Architecture'] = None, owner: Optional['function.Function'] = None,
			hlil: Optional['highlevelil.HighLevelILFunction'] = None, handle=None
	):
		if handle is None:
			if arch is None:
				raise ValueError("function representation must have an associated architecture")
			if owner is None:
				raise ValueError("function representation must have an owning function")
			if hlil is None:
				raise ValueError("function representation must have an associated High Level IL function")
			self._cb = core.BNCustomLanguageRepresentationFunction()
			self._cb.context = 0
			self._cb.externalRefTaken = self._cb.externalRefTaken.__class__(self._external_ref_taken)
			self._cb.externalRefReleased = self._cb.externalRefReleased.__class__(self._external_ref_released)
			self._cb.initTokenEmitter = self._cb.initTokenEmitter.__class__(self._init_token_emitter)
			self._cb.getExprText = self._cb.getExprText.__class__(self._get_expr_text)
			self._cb.beginLines = self._cb.beginLines.__class__(self._begin_lines)
			self._cb.endLines = self._cb.endLines.__class__(self._end_lines)
			self._cb.getCommentStartString = self._cb.getCommentStartString.__class__(self._comment_start_string)
			self._cb.getCommentEndString = self._cb.getCommentEndString.__class__(self._comment_end_string)
			self._cb.getAnnotationStartString = self._cb.getAnnotationStartString.__class__(
				self._annotation_start_string)
			self._cb.getAnnotationEndString = self._cb.getAnnotationEndString.__class__(self._annotation_end_string)
			self.comment_start_string = self.__class__.comment_start_string
			self.comment_end_string = self.__class__.comment_end_string
			self.annotation_start_string = self.__class__.annotation_start_string
			self.annotation_end_string = self.__class__.annotation_end_string
			_handle = core.BNCreateCustomLanguageRepresentationFunction(
				func_type.handle, arch.handle, owner.handle, hlil.handle, self._cb
			)
			assert _handle is not None
		else:
			self.comment_start_string = core.BNGetLanguageRepresentationFunctionCommentStartString(handle)
			self.comment_end_string = core.BNGetLanguageRepresentationFunctionCommentEndString(handle)
			self.annotation_start_string = core.BNGetLanguageRepresentationFunctionAnnotationStartString(handle)
			self.annotation_end_string = core.BNGetLanguageRepresentationFunctionAnnotationEndString(handle)
			_handle = handle
		assert _handle is not None
		self.handle: core.BNLanguageRepresentationFunctionHandle = _handle

	def __del__(self):
		if core is not None:
			core.BNFreeLanguageRepresentationFunction(self.handle)

	def _external_ref_taken(self, ctxt):
		try:
			self.__class__._registered_instances.append(self)
		except:
			log_error(traceback.format_exc())

	def _external_ref_released(self, ctxt):
		try:
			self.__class__._registered_instances.remove(self)
		except:
			log_error(traceback.format_exc())

	def _init_token_emitter(self, ctxt, emitter: core.BNHighLevelILTokenEmitterHandle):
		try:
			emitter = HighLevelILTokenEmitter(core.BNNewHighLevelILTokenEmitterReference(emitter))
			self.perform_init_token_emitter(emitter)
		except:
			log_error(traceback.format_exc())

	def _get_expr_text(
			self, ctxt, hlil: core.BNHighLevelILFunctionHandle, expr_index: int,
			tokens: core.BNHighLevelILTokenEmitterHandle, settings: Optional[core.BNDisassemblySettingsHandle],
			as_full_ast: bool, precedence: OperatorPrecedence, statement: bool
	):
		try:
			hlil = highlevelil.HighLevelILFunction(handle=core.BNNewHighLevelILFunctionReference(hlil))
			instr = hlil.get_expr(highlevelil.ExpressionIndex(expr_index), as_full_ast)
			tokens = HighLevelILTokenEmitter(core.BNNewHighLevelILTokenEmitterReference(tokens))
			if settings is not None:
				settings = function.DisassemblySettings(core.BNNewDisassemblySettingsReference(settings))
			self.perform_get_expr_text(instr, tokens, settings, precedence, statement)
		except:
			log_error(traceback.format_exc())

	def _begin_lines(
			self, ctxt, hlil: core.BNHighLevelILFunctionHandle, expr_index: int,
			tokens: core.BNHighLevelILTokenEmitterHandle
	):
		try:
			hlil = highlevelil.HighLevelILFunction(handle=core.BNNewHighLevelILFunctionReference(hlil))
			instr = hlil.get_expr(highlevelil.ExpressionIndex(expr_index))
			tokens = HighLevelILTokenEmitter(core.BNNewHighLevelILTokenEmitterReference(tokens))
			self.perform_begin_lines(instr, tokens)
		except:
			log_error(traceback.format_exc())

	def _end_lines(
			self, ctxt, hlil: core.BNHighLevelILFunctionHandle, expr_index: int,
			tokens: core.BNHighLevelILTokenEmitterHandle
	):
		try:
			hlil = highlevelil.HighLevelILFunction(handle=core.BNNewHighLevelILFunctionReference(hlil))
			instr = hlil.get_expr(highlevelil.ExpressionIndex(expr_index))
			tokens = HighLevelILTokenEmitter(core.BNNewHighLevelILTokenEmitterReference(tokens))
			self.perform_end_lines(instr, tokens)
		except:
			log_error(traceback.format_exc())

	def _comment_start_string(self, ctxt):
		try:
			return core.BNAllocString(self.comment_start_string)
		except:
			log_error(traceback.format_exc())
			return core.BNAllocString("// ")

	def _comment_end_string(self, ctxt):
		try:
			return core.BNAllocString(self.comment_end_string)
		except:
			log_error(traceback.format_exc())
			return core.BNAllocString("")

	def _annotation_start_string(self, ctxt):
		try:
			return core.BNAllocString(self.annotation_start_string)
		except:
			log_error(traceback.format_exc())
			return core.BNAllocString("{")

	def _annotation_end_string(self, ctxt):
		try:
			return core.BNAllocString(self.annotation_end_string)
		except:
			log_error(traceback.format_exc())
			return core.BNAllocString("}")

	def perform_init_token_emitter(self, emitter: HighLevelILTokenEmitter):
		"""Override this method to initialize the options for the token emitter before it is used."""
		pass

	def perform_get_expr_text(
			self, instr: 'highlevelil.HighLevelILInstruction', tokens: HighLevelILTokenEmitter,
			settings: Optional['function.DisassemblySettings'],
			precedence: OperatorPrecedence = OperatorPrecedence.TopLevelOperatorPrecedence, statement: bool = False
	):
		"""
		This method must be overridden by all language representation plugins.

		This method is called to emit the tokens for a given High Level IL instruction.
		"""
		raise NotImplementedError

	def perform_begin_lines(self, instr: highlevelil.HighLevelILInstruction, tokens: HighLevelILTokenEmitter):
		"""This method can be overridden to emit tokens at the start of a function."""
		pass

	def perform_end_lines(self, instr: highlevelil.HighLevelILInstruction, tokens: HighLevelILTokenEmitter):
		"""This method can be overridden to emit tokens at the end of a function."""
		pass

	def get_expr_text(
			self, instr: 'highlevelil.HighLevelILInstruction', settings: Optional['function.DisassemblySettings'],
			precedence: OperatorPrecedence = OperatorPrecedence.TopLevelOperatorPrecedence,
			statement: bool = False
	) -> List['function.DisassemblyTextLine']:
		"""Gets the lines of tokens for a given High Level IL instruction."""
		count = ctypes.c_ulonglong()
		if settings is not None:
			settings = settings.handle
		lines = core.BNGetLanguageRepresentationFunctionExprText(
			self.handle, instr.function.handle, instr.expr_index,
			settings, instr.as_ast, precedence, statement, count
		)
		result = []
		if lines is not None:
			result = []
			for i in range(0, count.value):
				addr = lines[i].addr
				if lines[i].instrIndex != 0xffffffffffffffff:
					il_instr = instr.function[lines[i].instrIndex]  # type: ignore
				else:
					il_instr = None
				color = highlight.HighlightColor._from_core_struct(lines[i].highlight)
				tokens = function.InstructionTextToken._from_core_struct(lines[i].tokens, lines[i].count)
				result.append(function.DisassemblyTextLine(tokens, addr, il_instr, color))
			core.BNFreeDisassemblyTextLines(lines, count.value)
		return result

	def get_linear_lines(
			self, instr: 'highlevelil.HighLevelILInstruction',
			settings: Optional['function.DisassemblySettings'] = None
	) -> List['function.DisassemblyTextLine']:
		"""
		Generates lines for the given High Level IL instruction in the style of the linear view. To get the lines
		for the entire function, pass the ``root`` property of a ``class HighLevelILFunction``.
		"""
		count = ctypes.c_ulonglong()
		if settings is not None:
			settings = settings.handle
		lines = core.BNGetLanguageRepresentationFunctionLinearLines(
			self.handle, instr.function.handle, instr.expr_index,
			settings, instr.as_ast, count
		)
		result = []
		if lines is not None:
			result = []
			for i in range(0, count.value):
				addr = lines[i].addr
				if lines[i].instrIndex != 0xffffffffffffffff:
					il_instr = instr.function[lines[i].instrIndex]  # type: ignore
				else:
					il_instr = None
				color = highlight.HighlightColor._from_core_struct(lines[i].highlight)
				tokens = function.InstructionTextToken._from_core_struct(lines[i].tokens, lines[i].count)
				result.append(function.DisassemblyTextLine(tokens, addr, il_instr, color))
			core.BNFreeDisassemblyTextLines(lines, count.value)
		return result

	def get_block_lines(
			self, block: 'highlevelil.HighLevelILBasicBlock', settings: Optional['function.DisassemblySettings'] = None
	) -> List['function.DisassemblyTextLine']:
		"""Generates lines for a single High Level IL basic block."""
		count = ctypes.c_ulonglong()
		if settings is not None:
			settings = settings.handle
		lines = core.BNGetLanguageRepresentationFunctionBlockLines(self.handle, block.handle, settings, count)
		result = []
		if lines is not None:
			result = []
			for i in range(0, count.value):
				addr = lines[i].addr
				if lines[i].instrIndex != 0xffffffffffffffff:
					il_instr = instr.function[lines[i].instrIndex]  # type: ignore
				else:
					il_instr = None
				color = highlight.HighlightColor._from_core_struct(lines[i].highlight)
				tokens = function.InstructionTextToken._from_core_struct(lines[i].tokens, lines[i].count)
				result.append(function.DisassemblyTextLine(tokens, addr, il_instr, color))
			core.BNFreeDisassemblyTextLines(lines, count.value)
		return result

	@property
	def arch(self) -> 'architecture.Architecture':
		return architecture.CoreArchitecture._from_cache(core.BNGetLanguageRepresentationArchitecture(self.handle))

	@property
	def function(self) -> 'function.Function':
		return function.Function(handle=core.BNGetLanguageRepresentationOwnerFunction(self.handle))

	@property
	def high_level_il(self) -> 'highlevelil.HighLevelILFunction':
		return self.hlil

	@property
	def hlil(self) -> 'highlevelil.HighLevelILFunction':
		return highlevelil.HighLevelILFunction(arch=self.arch,
			handle=core.BNGetLanguageRepresentationILFunction(self.handle), source_func=self.function)


class _LanguageRepresentationFunctionTypeMetaClass(type):
	def __iter__(self):
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		types = core.BNGetLanguageRepresentationFunctionTypeList(count)
		assert types is not None, "core.BNGetLanguageRepresentationFunctionTypeList returned None"
		try:
			for i in range(0, count.value):
				yield CoreLanguageRepresentationFunctionType(handle=types[i])
		finally:
			core.BNFreeLanguageRepresentationFunctionTypeList(types)

	def __getitem__(cls, value):
		binaryninja._init_plugins()
		lang = core.BNGetLanguageRepresentationFunctionTypeByName(str(value))
		if lang is None:
			raise KeyError("'%s' is not a valid language" % str(value))
		return CoreLanguageRepresentationFunctionType(handle=lang)


class LanguageRepresentationFunctionType(metaclass=_LanguageRepresentationFunctionTypeMetaClass):
	"""
	``class LanguageRepresentationFunctionType`` represents a custom language representation function type.
	This class provides methods to create ``class LanguageRepresentationFunction`` instances for functions, as well
	as manage the printing and parsing of types.
	"""
	_registered_languages = []
	language_name = None

	def __init__(self, handle=None):
		if handle is not None:
			self.handle = core.handle_of_type(handle, core.BNLanguageRepresentationFunctionType)

	def register(self):
		"""Registers the language representation function type."""
		if self.__class__.language_name is None:
			raise ValueError("Language name is missing")
		self._cb = core.BNCustomLanguageRepresentationFunctionType()
		self._cb.context = 0
		self._cb.create = self._cb.create.__class__(self._create)
		self._cb.isValid = self._cb.isValid.__class__(self._is_valid)
		self._cb.getTypePrinter = self._cb.getTypePrinter.__class__(self._type_printer)
		self._cb.getTypeParser = self._cb.getTypeParser.__class__(self._type_parser)
		self._cb.getLineFormatter = self._cb.getLineFormatter.__class__(self._line_formatter)
		self._cb.getFunctionTypeTokens = self._cb.getFunctionTypeTokens.__class__(self._function_type_tokens)
		self._cb.freeLines = self._cb.freeLines.__class__(self._free_lines)
		self.handle = core.BNRegisterLanguageRepresentationFunctionType(self.__class__.language_name, self._cb)
		self.__class__._registered_languages.append(self)

	def _create(
			self, ctxt, arch: core.BNArchitectureHandle, owner: core.BNFunctionHandle,
			hlil: core.BNHighLevelILFunctionHandle
	):
		try:
			arch = architecture.CoreArchitecture._from_cache(arch)
			owner = function.Function(handle=core.BNNewFunctionReference(owner))
			hlil = highlevelil.HighLevelILFunction(handle=core.BNNewHighLevelILFunctionReference(hlil))
			result = self.create(arch, owner, hlil)
			if result is None:
				raise ValueError(f"create returned None for language representation '{self.name}'")
			handle = core.BNNewLanguageRepresentationFunctionReference(result.handle)
			assert handle is not None, "core.BNNewLanguageRepresentationFunctionReference returned None"
			return ctypes.cast(handle, ctypes.c_void_p).value
		except:
			log_error(traceback.format_exc())
			return None

	def _is_valid(self, ctxt, view: core.BNBinaryViewHandle) -> bool:
		try:
			view = binaryview.BinaryView(handle=core.BNNewViewReference(view))
			return self.is_valid(view)
		except:
			log_error(traceback.format_exc())
			return False

	def _type_printer(self, ctxt):
		try:
			result = self.type_printer
			if result is None:
				return None
			return ctypes.cast(result.handle, ctypes.c_void_p).value
		except:
			log_error(traceback.format_exc())
			return None

	def _type_parser(self, ctxt):
		try:
			result = self.type_parser
			if result is None:
				return None
			return ctypes.cast(result.handle, ctypes.c_void_p).value
		except:
			log_error(traceback.format_exc())
			return None

	def _line_formatter(self, ctxt):
		try:
			result = self.line_formatter
			if result is None:
				return None
			return ctypes.cast(result.handle, ctypes.c_void_p).value
		except:
			log_error(traceback.format_exc())
			return None

	def _function_type_tokens(
			self, ctxt, func: core.BNFunctionHandle, settings: Optional[core.BNDisassemblySettingsHandle],
			count: ctypes.POINTER(ctypes.c_ulonglong)
	):
		try:
			func = function.Function(handle=core.BNNewFunctionReference(func))
			if settings is not None:
				settings = function.DisassemblySettings(handle=core.BNNewDisassemblySettingsReference(settings))
			lines = self.function_type_tokens(func, settings)

			count[0] = len(lines)
			self.line_buf = (core.BNDisassemblyTextLine * len(lines))()
			for i in range(len(lines)):
				line = lines[i]
				color = line.highlight
				if not isinstance(color, HighlightStandardColor) and not isinstance(color, highlight.HighlightColor):
					raise ValueError("Specified color is not one of HighlightStandardColor, highlight.HighlightColor")
				if isinstance(color, HighlightStandardColor):
					color = highlight.HighlightColor(color)
				self.line_buf[i].highlight = color._to_core_struct()
				if line.address is None:
					if len(line.tokens) > 0:
						self.line_buf[i].addr = line.tokens[0].address
					else:
						self.line_buf[i].addr = 0
				else:
					self.line_buf[i].addr = line.address
				if line.il_instruction is not None:
					self.line_buf[i].instrIndex = line.il_instruction.instr_index
				else:
					self.line_buf[i].instrIndex = 0xffffffffffffffff

				self.line_buf[i].count = len(line.tokens)
				self.line_buf[i].tokens = function.InstructionTextToken._get_core_struct(line.tokens)

			return ctypes.cast(self.line_buf, ctypes.c_void_p).value
		except:
			log_error(traceback.format_exc())
			count[0] = 0
			return None

	def _free_lines(self, ctxt, lines, count):
		self.line_buf = None

	@property
	def name(self) -> str:
		if hasattr(self, 'handle'):
			return core.BNGetLanguageRepresentationFunctionTypeName(self.handle)
		return self.__class__.language_name

	def create(
		self, arch: 'architecture.Architecture', owner: 'function.Function', hlil: 'highlevelil.HighLevelILFunction'
	) -> LanguageRepresentationFunction:
		"""
		This method must be overridden. This creates the ``class LanguageRepresentationFunction`` object for the
		given architecture, owner function, and High Level IL function.
		"""
		raise NotImplementedError

	def is_valid(self, view: 'binaryview.BinaryView') -> bool:
		"""Returns whether the language is valid for the given binary view."""
		return True

	@property
	def type_printer(self) -> Optional['binaryninja.typeprinter.TypePrinter']:
		"""
		Returns the type printer for displaying types in this language. If ``None`` is returned, the default type
		printer will be used.
		"""
		return None

	@property
	def type_parser(self) -> Optional['binaryninja.typeparser.TypeParser']:
		"""
		Returns the type parser for parsing types in this language. If ``None`` is returned, the default type
		parser will be used.
        """
		return None

	@property
	def line_formatter(self) -> Optional['lineformatter.LineFormatter']:
		"""
		Returns the line formatter for formatting lines in this language. If ``None`` is returned, the default
		line formatter will be used.
		"""
		return None

	def function_type_tokens(
			self, func: 'function.Function', settings: Optional['function.DisassemblySettings']
	) -> List['function.DisassemblyTextLine']:
		"""
		Returns a list of lines representing a function prototype in this language. If no lines are returned, the
		default C-style prototype will be used.
		"""
		return []

	def __repr__(self):
		return f"<LanguageRepresentationFunctionType: {self.name}>"


_language_cache = {}


class CoreLanguageRepresentationFunctionType(LanguageRepresentationFunctionType):
	def __init__(self, handle: core.BNLanguageRepresentationFunctionTypeHandle):
		super(CoreLanguageRepresentationFunctionType, self).__init__(handle=handle)
		if type(self) is CoreLanguageRepresentationFunctionType:
			global _language_cache
			_language_cache[ctypes.addressof(handle.contents)] = self

	@classmethod
	def _from_cache(cls, handle) -> 'LanguageRepresentationFunctionType':
		"""
		Look up a representation type from a given BNLanguageRepresentationFunctionType handle
		:param handle: BNLanguageRepresentationFunctionType pointer
		:return: Respresentation type instance responsible for this handle
		"""
		global _language_cache
		return _language_cache.get(ctypes.addressof(handle.contents)) or cls(handle)

	def create(
			self, arch: 'architecture.Architecture', owner: 'function.Function', hlil: 'highlevelil.HighLevelILFunction'
	) -> LanguageRepresentationFunction:
		raise NotImplementedError

	def is_valid(self, view: 'binaryview.BinaryView') -> bool:
		return core.BNIsLanguageRepresentationFunctionTypeValid(self.handle, view.handle)

	@property
	def type_printer(self) -> Optional['binaryninja.typeprinter.TypePrinter']:
		result = core.BNGetLanguageRepresentationFunctionTypePrinter(self.handle)
		if result is None:
			return None
		return binaryninja.typeprinter.TypePrinter(handle=result)

	@property
	def type_parser(self) -> Optional['binaryninja.typeparser.TypeParser']:
		result = core.BNGetLanguageRepresentationFunctionTypeParser(self.handle)
		if result is None:
			return None
		return binaryninja.typeparser.TypeParser(handle=result)

	@property
	def line_formatter(self) -> Optional['lineformatter.LineFormatter']:
		result = core.BNGetLanguageRepresentationFunctionTypeLineFormatter(self.handle)
		if result is None:
			return None
		return binaryninja.lineformatter.LineFormatter(handle=result)

	def function_type_tokens(
			self, func: 'function.Function', settings: Optional['function.DisassemblySettings']
	) -> List['function.DisassemblyTextLine']:
		count = ctypes.c_ulonglong()
		if settings is not None:
			settings = settings.handle
		lines = core.BNGetLanguageRepresentationFunctionTypeFunctionTypeTokens(self.handle, func.handle, settings, count)
		result = []
		if lines is not None:
			result = []
			for i in range(0, count.value):
				addr = lines[i].addr
				color = highlight.HighlightColor._from_core_struct(lines[i].highlight)
				tokens = function.InstructionTextToken._from_core_struct(lines[i].tokens, lines[i].count)
				result.append(function.DisassemblyTextLine(tokens, addr, color=color))
			core.BNFreeDisassemblyTextLines(lines, count.value)
		return result
