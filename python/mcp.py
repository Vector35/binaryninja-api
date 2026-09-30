# Copyright (c) 2026 Vector 35 Inc
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
"""
Tools for Binary Ninja's Model Context Protocol (MCP) server.

A tool registered here is offered by every MCP server in the process, alongside the built-in ``bn_*``
tools. The simplest way to write one is the :py:func:`tool` decorator, which builds the tool's JSON
Schema from the function's signature and docstring::

	from binaryninja import mcp

	@mcp.tool(read_only=True)
	def myplugin_function_count(call: mcp.ToolCall, min_size: int = 0) -> dict:
		\"\"\"Count the functions in the active binary view.

		:param min_size: Only count functions with at least this many bytes.
		\"\"\"
		functions = [f for f in call.binary_view.functions if f.total_bytes >= min_size]
		return {"count": len(functions)}
"""

import ctypes
import enum
import inspect
import json
import re
import types
import typing
from typing import Any, Callable, Dict, List, Literal, Optional, Tuple, Union

import binaryninja
from . import _binaryninjacore as core
from . import binaryview
from .enums import McpToolAnnotation, McpToolScope
from .log import log_error_for_exception

__all__ = [
	"Address",
	"ClampTo",
	"IntegerExpression",
	"Maximum",
	"Minimum",
	"NonEmpty",
	"RelativeTo",
	"Schema",
	"Tool",
	"ToolCall",
	"ToolError",
	"ToolResult",
	"register_tool",
	"tool",
]

class Address(int):
	"""
	A parameter annotated ``Address`` accepts an address expression string, evaluated against the call's
	binary view. The function receives an ``int``.
	"""

	__slots__ = ()


class IntegerExpression(int):
	"""
	A parameter annotated ``IntegerExpression`` accepts an unsigned integer or an expression string,
	evaluated against the call's binary view. The function receives an ``int``.
	"""

	__slots__ = ()

_TOOL_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

# The origin of a T | None annotation, which is not typing.Union on Python 3.10 and later.
_UnionType = getattr(types, "UnionType", Union)

# Keeps each registered tool's ctypes callbacks alive until the tool is freed.
_registered_tools: List["_RegisteredTool"] = []


class Schema:
	"""
	Supplies the JSON Schema for a parameter the other annotations cannot describe. Use it as
	``Annotated[dict, mcp.Schema({...})]``. The function receives the argument as decoded JSON.
	"""

	def __init__(self, schema: dict):
		self.schema = schema


class RelativeTo:
	"""
	Evaluates an :py:class:`IntegerExpression` parameter's expression with an earlier :py:class:`Address`,
	:py:class:`IntegerExpression` or ``int`` parameter's value as ``$here``. When that argument is absent,
	its default is used, or 0 when it has none. Use it as
	``Annotated[mcp.IntegerExpression, mcp.RelativeTo("address")]``, for example for a length measured
	from an address, or on the items of a ``List`` of them.
	"""

	def __init__(self, parameter: str):
		self.parameter = parameter


class Minimum:
	"""Rejects an ``int`` parameter's values below ``value``. Use it as ``Annotated[int, mcp.Minimum(0)]``."""

	def __init__(self, value: int):
		self.value = value


class Maximum:
	"""Rejects an ``int`` parameter's values above ``value``. Use it as ``Annotated[int, mcp.Maximum(100)]``."""

	def __init__(self, value: int):
		self.value = value


class ClampTo:
	"""
	Clamps an ``int`` parameter's value to the range ``minimum`` to ``maximum`` instead of rejecting values
	outside it. Use it as ``Annotated[int, mcp.ClampTo(0, 1000)]``.
	"""

	def __init__(self, minimum: int, maximum: int):
		self.minimum = minimum
		self.maximum = maximum


class NonEmpty:
	"""Rejects an empty ``str`` parameter. Use it as ``Annotated[str, mcp.NonEmpty()]``."""


class ToolError(Exception):
	"""Raised by a tool to return an error result with a machine-readable code."""

	def __init__(self, code: str, message: str, details: Any = None):
		super().__init__(message)
		self.code = code
		self.message = message
		self.details = details


class ToolResult:
	"""
	The result of a tool. A tool may instead return a ``str`` (text), a ``dict`` (structured content) or
	``None`` (an empty result).
	"""

	def __init__(self, text: Optional[Union[str, List[str]]] = None, structured: Optional[dict] = None):
		if text is None:
			self.text: List[str] = []
		elif isinstance(text, str):
			self.text = [text]
		else:
			self.text = list(text)
		self.structured = structured
		self.error: Optional[ToolError] = None
		self.warnings: List[Tuple[str, str]] = []

	def add_warning(self, code: str, message: str) -> "ToolResult":
		"""
		Adds an advisory warning about the result, such as analysis that has not finished. Clients see it
		in the structured content's reserved ``warnings`` member, and after any text.
		"""
		self.warnings.append((code, message))
		return self

	@staticmethod
	def from_error(error: ToolError) -> "ToolResult":
		result = ToolResult()
		result.error = error
		return result

	def _apply(self, handle) -> None:
		# Anything that can fail does so before the result is written, so the caller can report an error in
		# its place.
		if not all(isinstance(text, str) for text in self.text):
			raise TypeError("A ToolResult's text must be a str or a list of str")
		if not all(isinstance(code, str) and isinstance(message, str) for code, message in self.warnings):
			raise TypeError("A ToolResult's warning code and message must be str")
		if self.error is not None:
			if not isinstance(self.error.code, str) or not isinstance(self.error.message, str):
				raise TypeError("A ToolError's code and message must be str")
			details = None if self.error.details is None else json.dumps(self.error.details, allow_nan=False)
			core.BNSetMcpToolResultError(handle, self.error.code, self.error.message, details)
		elif self.structured is not None:
			structured = json.dumps(self.structured, allow_nan=False)
			if not core.BNSetMcpToolResultStructuredContent(handle, structured):
				core.BNSetMcpToolResultError(
					handle, "internal_error", "The tool produced structured content that is not a JSON object", None
				)
				return
		for text in self.text:
			core.BNAddMcpToolResultText(handle, text)
		for code, message in self.warnings:
			core.BNAddMcpToolResultWarning(handle, code, message)

	@staticmethod
	def _from_value(value: Any) -> "ToolResult":
		if isinstance(value, ToolResult):
			return value
		if value is None:
			return ToolResult()
		if isinstance(value, str):
			return ToolResult(text=value)
		if isinstance(value, dict):
			return ToolResult(structured=value)
		raise TypeError(f"A tool must return a str, dict, ToolResult or None, not {type(value).__name__}")


class ToolCall:
	"""
	One invocation of a tool. Once the tool returns, ``binary_view`` is ``None`` and ``is_cancelled`` is
	``True``.
	"""

	def __init__(self, handle):
		self.handle = core.BNNewMcpToolCallReference(handle)

	def __del__(self):
		if core is not None:
			core.BNFreeMcpToolCall(self.handle)

	@property
	def binary_view(self) -> Optional["binaryview.BinaryView"]:
		"""The binary view the MCP session targets. Never ``None`` while a BinaryView-scoped tool runs."""
		handle = core.BNGetMcpToolCallBinaryView(self.handle)
		if not handle:
			return None
		return binaryview.BinaryView(handle=handle)

	@property
	def is_cancelled(self) -> bool:
		return core.BNIsMcpToolCallCancelled(self.handle)

	def report_progress(self, progress: float, total: float, message: str = "") -> None:
		core.BNReportMcpToolCallProgress(self.handle, progress, total, message)

	def parse_address(self, value: Any, here: int = 0) -> int:
		"""
		Evaluates an address expression string, with ``here`` as the value of ``$here``. Raises
		``ValueError`` when it is invalid.
		"""
		return self._parse(core.BNParseMcpToolCallAddress, value, here)

	def parse_integer(self, value: Any, here: int = 0) -> int:
		"""
		Evaluates an unsigned integer or an expression string, with ``here`` as the value of ``$here``.
		Raises ``ValueError`` when it is invalid.
		"""
		return self._parse(core.BNParseMcpToolCallInteger, value, here)

	def _parse(self, parse, value: Any, here: int) -> int:
		result = ctypes.c_uint64()
		error = ctypes.c_char_p()
		if not parse(self.handle, json.dumps(value), result, here, error):
			message = core.pyNativeStr(error.value) if error.value is not None else ""
			core.free_string(error)
			raise ValueError(message)
		return result.value


class _ToolMetaclass(type):
	def __iter__(cls):
		binaryninja._init_plugins()
		count = ctypes.c_ulonglong()
		tools = core.BNGetMcpToolList(count)
		try:
			for i in range(count.value):
				yield Tool(core.BNNewMcpToolReference(tools[i]))
		finally:
			core.BNFreeMcpToolList(tools, count.value)


class Tool(metaclass=_ToolMetaclass):
	"""
	A tool in the tool registry. Iterating over ``Tool`` lists every registered tool, sorted by name.
	"""

	def __init__(self, handle):
		self.handle = handle

	def __del__(self):
		if core is not None:
			core.BNFreeMcpTool(self.handle)

	@staticmethod
	def list() -> List["Tool"]:
		return list(Tool)

	@staticmethod
	def by_name(name: str) -> Optional["Tool"]:
		binaryninja._init_plugins()
		handle = core.BNGetMcpToolByName(name)
		return Tool(handle) if handle else None

	@property
	def name(self) -> str:
		return core.BNGetMcpToolName(self.handle)

	@property
	def title(self) -> str:
		return core.BNGetMcpToolTitle(self.handle)

	@property
	def description(self) -> str:
		return core.BNGetMcpToolDescription(self.handle)

	@property
	def input_schema(self) -> dict:
		return json.loads(core.BNGetMcpToolInputSchema(self.handle))

	@property
	def output_schema(self) -> Optional[dict]:
		schema = core.BNGetMcpToolOutputSchema(self.handle)
		return json.loads(schema) if schema else None

	@property
	def scope(self) -> McpToolScope:
		return McpToolScope(core.BNGetMcpToolScope(self.handle))

	@property
	def annotations(self) -> McpToolAnnotation:
		"""A combination of :py:class:`McpToolAnnotation` flags."""
		return McpToolAnnotation(core.BNGetMcpToolAnnotations(self.handle))

	def invoke(self, arguments: Optional[dict] = None, view: Optional["binaryview.BinaryView"] = None) -> dict:
		"""
		Runs the tool as an MCP server would, against ``view``, and returns the MCP ``CallToolResult``.
		"""
		callbacks = core.BNMcpToolCallCallbacks()
		callbacks.context = 0

		def get_binary_view(ctxt):
			try:
				if view is None:
					return None
				return ctypes.cast(core.BNNewViewReference(view.handle), ctypes.c_void_p).value
			except Exception:
				log_error_for_exception("Unhandled Python exception in Tool.invoke")
				return None

		callbacks.getBinaryView = callbacks.getBinaryView.__class__(get_binary_view)
		callbacks.isCancelled = callbacks.isCancelled.__class__(lambda ctxt: False)
		callbacks.reportProgress = callbacks.reportProgress.__class__(lambda ctxt, progress, total, message: None)

		call = core.BNCreateMcpToolCall(callbacks)
		result = core.BNCreateMcpToolResult()
		try:
			core.BNInvokeMcpTool(self.handle, call, json.dumps(arguments or {}), result)
			return json.loads(core.BNGetMcpToolResultJson(result))
		finally:
			core.BNFreeMcpToolResult(result)
			core.BNFreeMcpToolCall(call)

	def __repr__(self):
		return f"<Tool: {self.name}>"

	def __eq__(self, other):
		return isinstance(other, Tool) and self.name == other.name

	def __hash__(self):
		return hash(self.name)


class _RegisteredTool:
	def __init__(self, handler: Callable[[ToolCall, dict], Any]):
		self.handler = handler
		self.callbacks = core.BNMcpToolCallbacks()
		self.callbacks.context = 0
		self.callbacks.invoke = self.callbacks.invoke.__class__(self._invoke)
		self.callbacks.freeObject = self.callbacks.freeObject.__class__(self._free_object)

	def _free_object(self, ctxt):
		try:
			_registered_tools.remove(self)
		except Exception:
			log_error_for_exception("Unhandled Python exception freeing an MCP tool")

	def _invoke(self, ctxt, call_handle, arguments, result_handle):
		try:
			try:
				decoded = json.loads(core.pyNativeStr(arguments))
				result = ToolResult._from_value(self.handler(ToolCall(call_handle), decoded))
			except ToolError as error:
				result = ToolResult.from_error(error)
			result._apply(result_handle)
		except Exception as error:
			log_error_for_exception("Unhandled Python exception in MCP tool")
			try:
				ToolResult.from_error(ToolError("internal_error", str(error)))._apply(result_handle)
			except Exception:
				log_error_for_exception("Unhandled Python exception applying an MCP tool result")


def register_tool(
	name: str,
	description: str,
	input_schema: dict,
	handler: Callable[[ToolCall, dict], Any],
	*,
	title: str = "",
	scope: McpToolScope = McpToolScope.BinaryViewScope,
	annotations: McpToolAnnotation = McpToolAnnotation(0),
	output_schema: Optional[dict] = None,
) -> Tool:
	"""
	Registers a tool for the life of the process.

	:param handler: Called as ``handler(call, arguments)`` with the decoded arguments object. Returns a
		``str``, ``dict``, :py:class:`ToolResult` or ``None``, or raises :py:class:`ToolError`.
	:raises ValueError: The definition is invalid or its name is already registered.
	"""
	registered = _RegisteredTool(handler)
	definition = core.BNMcpToolDefinition()
	definition.name = name
	definition.title = title
	definition.description = description
	definition.inputSchema = json.dumps(input_schema)
	definition.outputSchema = json.dumps(output_schema) if output_schema is not None else None
	definition.scope = scope
	definition.annotations = annotations
	handle = core.BNRegisterMcpTool(definition, registered.callbacks)
	if not handle:
		raise ValueError(f"Binary Ninja rejected the MCP tool '{name}'; see the log for why")
	_registered_tools.append(registered)
	return Tool(handle)


# Converts one argument, given the arguments converted before it.
_Converter = Callable[[ToolCall, Any, Dict[str, Any]], Any]


class _Parameter:
	def __init__(
		self, name: str, schema: dict, kind: str, convert: _Converter, required: bool, default: Any,
		relative_to: Optional[str]
	):
		self.name = name
		self.schema = schema
		self.kind = kind
		self.convert = convert
		self.required = required
		self.default = default
		self.relative_to = relative_to


def _is_integer(value: Any) -> bool:
	return isinstance(value, int) and not isinstance(value, bool)


def _relative_to(annotation) -> Optional[str]:
	"""
	Returns the parameter named by an ``Annotated[IntegerExpression, RelativeTo(...)]`` annotation, or by
	the item annotation of a ``List``.
	"""
	origin = typing.get_origin(annotation)
	if origin in (list, List):
		arguments = typing.get_args(annotation)
		return _relative_to(arguments[0]) if arguments else None
	if origin is not typing.Annotated:
		return None
	base, *metadata = typing.get_args(annotation)
	names = [item.parameter for item in metadata if isinstance(item, RelativeTo)]
	if not names:
		return None
	if base is not IntegerExpression:
		raise TypeError("RelativeTo only applies to parameters annotated mcp.IntegerExpression")
	return names[0]


def _describe(annotation, name: str, relative_to: Optional[str] = None) -> Tuple[dict, str, _Converter]:
	"""Returns the schema, the kind named in error messages, and the conversion for one annotation."""

	def expect(kind: str, check: Callable[[Any], bool], convert: Callable[[Any], Any] = lambda value: value):
		def run(call: ToolCall, value: Any, converted: Dict[str, Any]) -> Any:
			if not check(value):
				raise ToolError("invalid_params", f"Expected {kind} parameter '{name}'")
			return convert(value)

		return run

	if annotation is Address:

		def address(call: ToolCall, value: Any, converted: Dict[str, Any]) -> int:
			try:
				return call.parse_address(value)
			except ValueError as error:
				raise ToolError("invalid_params", f"Invalid address expression parameter '{name}': {error}")

		return {"type": "string"}, "address expression", address

	if annotation is IntegerExpression:

		def integer(call: ToolCall, value: Any, converted: Dict[str, Any]) -> int:
			here = converted.get(relative_to) if relative_to is not None else None
			try:
				# A negative int parameter used as $here wraps to 64 bits.
				return call.parse_integer(value, (here or 0) & 0xFFFFFFFFFFFFFFFF)
			except ValueError as error:
				raise ToolError("invalid_params", f"Invalid unsigned integer parameter '{name}': {error}")

		return {"type": ["integer", "string"], "minimum": 0}, "unsigned integer", integer

	if annotation is str:
		return {"type": "string"}, "string", expect("string", lambda value: isinstance(value, str))
	if annotation is bool:
		return {"type": "boolean"}, "boolean", expect("boolean", lambda value: isinstance(value, bool))
	if annotation is int:
		return {"type": "integer"}, "integer", expect("integer", _is_integer)
	if annotation is float:
		return (
			{"type": "number"},
			"number",
			expect("number", lambda value: _is_integer(value) or isinstance(value, float), float),
		)
	if inspect.isclass(annotation) and issubclass(annotation, enum.Enum):
		names = [member.name for member in annotation]

		def member(call: ToolCall, value: Any, converted: Dict[str, Any]):
			if not isinstance(value, str):
				raise ToolError("invalid_params", f"Expected string parameter '{name}'")
			if value not in names:
				raise ToolError("invalid_params", f"Invalid enum value for parameter '{name}'")
			return annotation[value]

		return {"type": "string", "enum": names}, "string", member

	origin = typing.get_origin(annotation)
	arguments = typing.get_args(annotation)
	if origin is Literal:
		choices = list(arguments)
		if not all(isinstance(choice, str) for choice in choices):
			raise TypeError(f"Parameter '{name}': only string Literal choices are supported")

		def choice(call: ToolCall, value: Any, converted: Dict[str, Any]) -> str:
			if not isinstance(value, str):
				raise ToolError("invalid_params", f"Expected string parameter '{name}'")
			if value not in choices:
				raise ToolError("invalid_params", f"Invalid enum value for parameter '{name}'")
			return value

		return {"type": "string", "enum": choices}, "string", choice
	if origin in (list, List):
		item_schema, item_kind, item_convert = _describe(arguments[0] if arguments else str, name, relative_to)

		def items(call: ToolCall, value: Any, converted: Dict[str, Any]) -> list:
			if not isinstance(value, list):
				raise ToolError("invalid_params", f"Expected {item_kind} array parameter '{name}'")
			return [item_convert(call, item, converted) for item in value]

		return {"type": "array", "items": item_schema}, f"{item_kind} array", items
	if origin is typing.Annotated:
		base, *metadata = arguments
		for item in metadata:
			if isinstance(item, Schema):
				return dict(item.schema), "JSON", lambda call, value, converted: value
		limits = [item for item in metadata if isinstance(item, (Minimum, Maximum, ClampTo))]
		if limits:
			return _describe_limited_int(base, name, limits)
		if any(item is NonEmpty or isinstance(item, NonEmpty) for item in metadata):
			if base is not str:
				raise TypeError(f"Parameter '{name}': NonEmpty only applies to str")
			return (
				{"type": "string", "minLength": 1},
				"non-empty string",
				expect("non-empty string", lambda value: isinstance(value, str) and value != ""),
			)
		return _describe(base, name, relative_to)
	raise TypeError(f"Parameter '{name}': unsupported annotation {annotation!r}")


def _describe_limited_int(base, name: str, limits: list) -> Tuple[dict, str, _Converter]:
	if base is not int:
		raise TypeError(f"Parameter '{name}': Minimum, Maximum and ClampTo only apply to int")
	minimum: Optional[int] = None
	maximum: Optional[int] = None
	clamp = False
	for limit in limits:
		if isinstance(limit, Minimum):
			minimum = limit.value
		elif isinstance(limit, Maximum):
			maximum = limit.value
		else:
			minimum, maximum, clamp = limit.minimum, limit.maximum, True

	schema: Dict[str, Any] = {"type": "integer"}
	if minimum is not None:
		schema["minimum"] = minimum
	if maximum is not None:
		schema["maximum"] = maximum

	def convert(call: ToolCall, value: Any, converted: Dict[str, Any]) -> int:
		if not _is_integer(value):
			raise ToolError("invalid_params", f"Expected integer parameter '{name}'")
		if minimum is not None and value < minimum:
			if clamp:
				return minimum
			raise ToolError("invalid_params", f"Invalid integer parameter '{name}': Must be at least {minimum}")
		if maximum is not None and value > maximum:
			if clamp:
				return maximum
			raise ToolError("invalid_params", f"Invalid integer parameter '{name}': Must be at most {maximum}")
		return value

	return schema, "integer", convert


def _optional_inner(annotation):
	"""Returns T for Optional[T] or T | None, or None when the annotation is not optional."""
	origin = typing.get_origin(annotation)
	if origin is Union or origin is _UnionType:
		arguments = [argument for argument in typing.get_args(annotation) if argument is not type(None)]
		if len(arguments) == 1 and len(typing.get_args(annotation)) == 2:
			return arguments[0]
	return None


def _parse_docstring(docstring: Optional[str]) -> Tuple[str, Dict[str, str]]:
	"""Returns the leading paragraph and the ``:param name:`` descriptions."""
	text = inspect.cleandoc(docstring or "")
	# The description ends at the first blank line or ":field:" line. A field's continuation lines are
	# indented and non-blank.
	summary = re.split(r"\n\s*\n|\n(?=:)", text, maxsplit=1)[0]
	description = " ".join(line.strip() for line in summary.splitlines())
	params: Dict[str, str] = {}
	for match in re.finditer(r"^:param\s+(\w+):\s*(.*(?:\n[ \t]+\S.*)*)", text, re.MULTILINE):
		params[match.group(1)] = " ".join(part.strip() for part in match.group(2).splitlines())
	return description, params


def _default_json(annotation, value: Any) -> Any:
	"""Returns a default value in the form the parameter's schema describes."""
	if annotation is Address:
		return hex(value)
	if isinstance(value, enum.Enum):
		return value.name
	origin = typing.get_origin(annotation)
	arguments = typing.get_args(annotation)
	if origin in (list, List):
		return [_default_json(arguments[0] if arguments else str, item) for item in value]
	if origin is typing.Annotated:
		return _default_json(arguments[0], value)
	return value


def _parameters(function: Callable, descriptions: Dict[str, str]) -> List[_Parameter]:
	signature = inspect.signature(function)
	hints = typing.get_type_hints(function, include_extras=True)
	parameters = list(signature.parameters.values())
	if not parameters:
		raise TypeError(f"MCP tool '{function.__name__}' must take the ToolCall as its first parameter")

	result: List[_Parameter] = []
	for parameter in parameters[1:]:
		name = parameter.name
		if parameter.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
			raise TypeError(f"MCP tool '{function.__name__}': *args and **kwargs are not supported")
		if parameter.kind == inspect.Parameter.POSITIONAL_ONLY:
			raise TypeError(f"MCP tool '{function.__name__}': parameter '{name}' cannot be positional-only")
		if name not in hints:
			raise TypeError(f"MCP tool '{function.__name__}': parameter '{name}' needs a type annotation")
		if name not in descriptions:
			raise TypeError(f"MCP tool '{function.__name__}': parameter '{name}' needs a ':param {name}:' description")

		annotation = hints[name]
		inner = _optional_inner(annotation)
		target = inner if inner is not None else annotation
		relative_to = _relative_to(target)
		if relative_to is not None and not any(
			earlier.name == relative_to and earlier.kind in ("address expression", "unsigned integer", "integer")
			for earlier in result
		):
			raise TypeError(
				f"MCP tool '{function.__name__}': parameter '{name}' is relative to '{relative_to}', which must be an "
				"earlier integer parameter"
			)
		schema, kind, convert = _describe(target, name, relative_to)
		schema = dict(schema)
		schema["description"] = descriptions[name]
		if has_default := parameter.default is not inspect.Parameter.empty:
			if parameter.default is not None:
				schema["default"] = _default_json(target, parameter.default)
		required = inner is None and not has_default
		default = parameter.default if has_default else None
		result.append(_Parameter(name, schema, kind, convert, required, default, relative_to))
	return result


def tool(
	name: Optional[str] = None,
	*,
	title: str = "",
	scope: McpToolScope = McpToolScope.BinaryViewScope,
	read_only: bool = False,
	destructive: bool = False,
	idempotent: bool = False,
	open_world: bool = False,
	output_schema: Optional[dict] = None,
):
	"""
	Registers the decorated function as a tool. The function's first parameter receives the
	:py:class:`ToolCall`. Every other parameter becomes a tool parameter, and needs a type annotation and
	a ``:param name:`` line in the docstring. The docstring's leading paragraph becomes the tool's
	description.

	Supported annotations are ``str``, ``int``, ``float``, ``bool``, :py:class:`Address`,
	:py:class:`IntegerExpression`, Binary Ninja enums (by member name), ``Literal`` of strings, ``List[T]``,
	``Annotated[T, Schema({...})]``, ``Annotated[IntegerExpression, RelativeTo("name")]``,
	``Annotated[str, NonEmpty()]`` and ``int`` annotated with :py:class:`Minimum`, :py:class:`Maximum` or
	:py:class:`ClampTo`. ``Optional[T]``,
	``T | None`` or a default value makes a parameter optional, and a null argument for one is treated as
	absent.

	Use it with parentheses or without, as ``@mcp.tool()`` or ``@mcp.tool``.

	The tool's name defaults to the function's name. Arguments are checked before the function runs, and
	a missing, invalid or undeclared argument produces an ``invalid_params`` error without calling it.
	"""
	if callable(name):
		return tool()(name)

	def register(function: Callable) -> Callable:
		tool_name = name or function.__name__
		if not _TOOL_NAME.match(tool_name):
			raise ValueError(f"MCP tool name '{tool_name}' must be 1 to 64 letters, digits, '_' or '-'")
		description, descriptions = _parse_docstring(function.__doc__)
		if not description:
			raise TypeError(f"MCP tool '{tool_name}' needs a docstring describing it")
		parameters = _parameters(function, descriptions)

		input_schema: Dict[str, Any] = {
			"type": "object",
			"properties": {parameter.name: parameter.schema for parameter in parameters},
		}
		required = [parameter.name for parameter in parameters if parameter.required]
		if required:
			input_schema["required"] = required
		input_schema["additionalProperties"] = False

		declared = {parameter.name for parameter in parameters}

		def handler(call: ToolCall, arguments: Any) -> Any:
			if not isinstance(arguments, dict):
				raise ToolError("invalid_params", "Expected object arguments")
			for argument in arguments:
				if argument not in declared:
					raise ToolError("invalid_params", f"Unexpected parameter '{argument}'")
			values = {}
			for parameter in parameters:
				# Clients may send null for an optional argument they leave unset.
				if parameter.name in arguments and (parameter.required or arguments[parameter.name] is not None):
					values[parameter.name] = parameter.convert(call, arguments[parameter.name], values)
				elif parameter.required:
					raise ToolError("invalid_params", f"Expected {parameter.kind} parameter '{parameter.name}'")
				else:
					values[parameter.name] = parameter.default
			return function(call, **values)

		annotations = 0
		if read_only:
			annotations |= McpToolAnnotation.ReadOnlyHint
		if destructive:
			annotations |= McpToolAnnotation.DestructiveHint
		if idempotent:
			annotations |= McpToolAnnotation.IdempotentHint
		if open_world:
			annotations |= McpToolAnnotation.OpenWorldHint

		register_tool(
			tool_name,
			description,
			input_schema,
			handler,
			title=title,
			scope=scope,
			annotations=annotations,
			output_schema=output_schema,
		)
		return function

	return register
