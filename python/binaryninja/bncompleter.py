""" This file is a modified version of rlcompleter.py from the Python
project under the Python Software Foundation License 2:
https://github.com/python/cpython/blob/master/Lib/rlcompleter.py
https://github.com/python/cpython/blob/master/LICENSE

The only changes made were to modify the regular expression in attr_matches
and all code that relied on GNU readline (the later more for readability as
it wasn't required).

--------------

Word completion for GNU readline.

The completer completes keywords, built-ins and globals in a selectable
namespace (which defaults to __main__); when completing NAME.NAME..., it
evaluates (!) the expression up to the last dot and completes its attributes.

It's very cool to do "import sys" type "sys.", hit the completion key (twice),
and see the list of names defined by the sys module!

Tip: to use the tab key as the completion key, call

	readline.parse_and_bind("tab: complete")

Notes:

- Exceptions raised by the completer function are *ignored* (and generally cause
  the completion to fail). This is a feature -- since readline sets the tty
  device in raw (or cbreak) mode, printing a traceback wouldn't work well
  without some complicated hoopla to save, reset and restore the tty state.

- The evaluation of the NAME.NAME... form may cause arbitrary application
  defined code to be executed if an object with a __getattr__ hook is found.
  Since it is the responsibility of the application (or the user) to enable this
  feature, I consider this an acceptable risk. More complicated expressions
  (e.g. function calls or indexing operations) are *not* evaluated.

- When the original stdin is not a tty device, GNU readline is never
  used, and this module (and the readline module) are silently inactive.

"""

import atexit
import html
import io
import tokenize
import typing

import binaryninja
import __main__
import inspect
import sys
from typing import Optional

__all__ = ["Completer"]


def fuzzy_match(target, query):
	if query == "":
		return 1
	if binaryninja.Settings().get_bool("ui.scripting.fuzzySearch"):
		return binaryninja.fuzzy_match_single(target, query)
	else:
		return 1 if target.startswith(query) else None


def fnsignature(obj):
	try:
		sig = str(inspect.signature(obj))
	except Exception:
		sig = "()"
	return sig


def _format_annotation(annotation):
	if isinstance(annotation, str):
		return annotation
	if isinstance(annotation, typing.ForwardRef):
		return annotation.__forward_arg__
	try:
		return inspect.formatannotation(annotation)
	except Exception:
		return repr(annotation)


class Completer:
	def __init__(self, namespace=None):
		"""Create a new completer for the command line.

		Completer([namespace]) -> completer instance.

		If unspecified, the default namespace where completions are performed
		is __main__ (technically, __main__.__dict__). Namespaces should be
		given as dictionaries.

		Completer instances should be used as the completion mechanism of
		readline via the set_completer() call:

		readline.set_completer(Completer(my_namespace).complete)
		"""

		if namespace and not isinstance(namespace, dict):
			raise TypeError('namespace must be a dictionary')

		# Don't bind to namespace quite yet, but flag whether the user wants a
		# specific namespace or to use __main__.__dict__. This will allow us
		# to bind to __main__.__dict__ at completion time, not now.
		if namespace is None:
			self.use_main_ns = 1
		else:
			self.use_main_ns = 0
			self.namespace = namespace

	def _resolve_callable(self, callable_path: str):
		if self.use_main_ns:
			self.namespace = __main__.__dict__
		namespace = self.namespace
		parts = callable_path.split(".")

		if not parts:
			return None

		function_obj = namespace.get(parts[0])
		if function_obj is None:
			if hasattr(__builtins__, '__dict__'):
				function_obj = __builtins__.__dict__.get(parts[0])
			else:
				function_obj = __builtins__.get(parts[0])
		if function_obj is None:
			return None

		for attr in parts[1:]:
			try:
				function_obj = getattr(function_obj, attr)
			except Exception:
				return None

		return function_obj

	@staticmethod
	def _split_call_arguments(
		tokens: typing.List[tokenize.TokenInfo], opening_paren_index: int
	) -> typing.List[typing.List[tokenize.TokenInfo]]:
		arguments = []
		current_argument = []
		depth = 0

		for tok in tokens[opening_paren_index + 1:]:
			if tok.type == tokenize.OP:
				if tok.string in "([{":
					depth += 1
				elif tok.string in ")]}":
					if depth == 0:
						break
					depth -= 1
				elif tok.string == "," and depth == 0:
					arguments.append(current_argument)
					current_argument = []
					continue

			current_argument.append(tok)

		arguments.append(current_argument)
		return arguments

	@staticmethod
	def _keyword_argument_name(
		argument_tokens: typing.List[tokenize.TokenInfo]
	) -> Optional[str]:
		depth = 0

		for index, tok in enumerate(argument_tokens):
			if tok.type != tokenize.OP:
				continue

			if tok.string in "([{":
				depth += 1
			elif tok.string in ")]}":
				if depth > 0:
					depth -= 1
			elif tok.string == "=" and depth == 0:
				if index == 1 and argument_tokens[0].type == tokenize.NAME:
					return argument_tokens[0].string
				return None

		return None

	@staticmethod
	def _is_keyword_unpack_argument(
		argument_tokens: typing.List[tokenize.TokenInfo]
	) -> bool:
		return (
			len(argument_tokens) > 0
			and argument_tokens[0].type == tokenize.OP
			and argument_tokens[0].string == "**"
		)

	@staticmethod
	def _is_iterable_unpack_argument(
		argument_tokens: typing.List[tokenize.TokenInfo]
	) -> bool:
		return (
			len(argument_tokens) > 0
			and argument_tokens[0].type == tokenize.OP
			and argument_tokens[0].string == "*"
		)

	@staticmethod
	def _var_positional_parameter_index(
		parameters: typing.List[inspect.Parameter]
	) -> Optional[int]:
		return next(
			(
				index for index, parameter in enumerate(parameters)
				if parameter.kind == inspect.Parameter.VAR_POSITIONAL
			),
			None,
		)

	@staticmethod
	def _keyword_only_parameter_index(
		parameters: typing.List[inspect.Parameter], used_keyword_parameters: typing.Set[str]
	) -> Optional[int]:
		return next(
			(
				index for index, parameter in enumerate(parameters)
				if parameter.kind == inspect.Parameter.KEYWORD_ONLY
				and parameter.name not in used_keyword_parameters
			),
			None,
		)

	@staticmethod
	def _keyword_parameter_index(
		parameters: typing.List[inspect.Parameter], keyword_name: str
	) -> Optional[int]:
		var_keyword_index = None

		for index, parameter in enumerate(parameters):
			if parameter.kind == inspect.Parameter.VAR_KEYWORD:
				var_keyword_index = index
			elif (
				parameter.name == keyword_name
				and parameter.kind
				in {
					inspect.Parameter.POSITIONAL_OR_KEYWORD,
					inspect.Parameter.KEYWORD_ONLY,
				}
			):
				return index

		return var_keyword_index

	@staticmethod
	def _positional_parameter_index(
		parameters: typing.List[inspect.Parameter],
		positional_argument_count: int,
		used_keyword_parameters: typing.Set[str],
	) -> Optional[int]:
		positional_parameter_count = 0
		var_positional_index = None

		for index, parameter in enumerate(parameters):
			if parameter.kind == inspect.Parameter.VAR_POSITIONAL:
				var_positional_index = index
			elif parameter.kind in {
				inspect.Parameter.POSITIONAL_ONLY,
				inspect.Parameter.POSITIONAL_OR_KEYWORD,
			}:
				if (
					parameter.kind == inspect.Parameter.POSITIONAL_OR_KEYWORD
					and parameter.name in used_keyword_parameters
				):
					continue

				if positional_parameter_count == positional_argument_count:
					return index
				positional_parameter_count += 1

		return var_positional_index

	@classmethod
	def _current_argument_index(
		cls,
		parameters: typing.List[inspect.Parameter],
		arguments: typing.List[typing.List[tokenize.TokenInfo]],
	) -> Optional[int]:
		positional_argument_count = 0
		used_keyword_parameters = set()
		var_keyword_index = next(
			(
				index for index, parameter in enumerate(parameters)
				if parameter.kind == inspect.Parameter.VAR_KEYWORD
			),
			None,
		)
		seen_var_keyword_argument = False
		seen_iterable_unpack_argument = False

		for argument_tokens in arguments[:-1]:
			keyword_name = cls._keyword_argument_name(argument_tokens)
			if keyword_name is not None:
				parameter_index = cls._keyword_parameter_index(parameters, keyword_name)
				if parameter_index is not None:
					used_keyword_parameters.add(parameters[parameter_index].name)
					if parameter_index == var_keyword_index:
						seen_var_keyword_argument = True
			elif cls._is_iterable_unpack_argument(argument_tokens):
				seen_iterable_unpack_argument = True
			elif not cls._is_keyword_unpack_argument(argument_tokens):
				positional_argument_count += 1

		current_argument = arguments[-1]
		keyword_name = cls._keyword_argument_name(current_argument)
		if keyword_name is not None:
			return cls._keyword_parameter_index(parameters, keyword_name)

		if cls._is_keyword_unpack_argument(current_argument):
			return var_keyword_index
		if cls._is_iterable_unpack_argument(current_argument):
			return cls._var_positional_parameter_index(parameters)

		if seen_var_keyword_argument:
			return var_keyword_index
		if seen_iterable_unpack_argument:
			return cls._var_positional_parameter_index(parameters)

		parameter_index = cls._positional_parameter_index(
			parameters, positional_argument_count, used_keyword_parameters
		)
		if parameter_index is not None:
			return parameter_index

		return cls._keyword_only_parameter_index(parameters, used_keyword_parameters)

	def _get_argument_completion_context(
		self, text: str
	) -> typing.Optional[typing.Dict[str, typing.Any]]:
		if "(" not in text:
			return None

		line_offsets = [0]
		for line in text.splitlines(keepends=True):
			line_offsets.append(line_offsets[-1] + len(line))

		def absolute_byte_index(position: typing.Tuple[int, int]) -> int:
			line, column = position
			return len(text[:line_offsets[line - 1] + column].encode("utf-8"))

		reader = io.StringIO(text).readline
		stream = tokenize.generate_tokens(reader)

		tokens = []
		try:
			for tok in stream:
				if tok.type in {
					tokenize.ENCODING,
					tokenize.NL,
					tokenize.NEWLINE,
					tokenize.INDENT,
					tokenize.DEDENT,
					tokenize.ENDMARKER,
					tokenize.COMMENT,
				}:
					continue
				tokens.append(tok)
		except tokenize.TokenError:
			pass

		if not tokens:
			return None

		stack = []
		for index, tok in enumerate(tokens):
			if tok.type == tokenize.OP and tok.string in "([{":
				callable_path = None

				if tok.string == "(":
					i = index - 1
					parts = []

					if i >= 0 and tokens[i].type == tokenize.NAME:
						parts.append(tokens[i].string)
						i -= 1

						while i >= 1:
							if (
								tokens[i].type == tokenize.OP
								and tokens[i].string == "."
								and tokens[i - 1].type == tokenize.NAME
							):
								parts.append(tokens[i - 1].string)
								i -= 2
							else:
								break

						parts.reverse()
						callable_path = ".".join(parts)

				stack.append(
					{
						"bracket": tok.string,
						"token_index": index,
						"callable_path": callable_path,
					}
				)
			elif tok.type == tokenize.OP and tok.string in ")]}":
				if stack:
					stack.pop()

		call_context = None
		for entry in reversed(stack):
			if entry["bracket"] == "(" and entry["callable_path"] is not None:
				call_context = entry
				break

		if call_context is None:
			return None

		function_obj = self._resolve_callable(call_context["callable_path"])
		if function_obj is None:
			return None

		try:
			signature = inspect.signature(function_obj)
		except Exception:
			return None

		parameters = list(signature.parameters.values())

		arguments = self._split_call_arguments(tokens, call_context["token_index"])

		return {
			"signature": signature,
			"parameters": parameters,
			"current_argument_index": self._current_argument_index(parameters, arguments),
			"start_index": absolute_byte_index(tokens[call_context["token_index"]].end),
		}

	def can_complete_arguments(self, text: str) -> bool:
		"""
		A faster check to see if argument assistance is even needed currently.

		:param text:
		:return:
		"""
		return self._get_argument_completion_context(text) is not None

	def complete_arguments(self, text: str) -> typing.Tuple[Optional[str], int]:
		"""Given input up to the contents of 'text', return a HTML string containing
		the arguments for the function.

		Used in UI to display and highlight arguments of a function as the user types them.
		"""
		context = self._get_argument_completion_context(text)
		if context is None:
			return None, 0

		signature = context["signature"]
		parameters = context["parameters"]
		current_argument_index = context["current_argument_index"]

		return_args = []
		positional_only_count = sum(
			1 for p in parameters if p.kind == inspect.Parameter.POSITIONAL_ONLY
		)

		for i, parameter in enumerate(parameters):
			if (
				parameter.kind == inspect.Parameter.KEYWORD_ONLY
				and "*" not in return_args
				and not any(
					p.kind == inspect.Parameter.VAR_POSITIONAL
					for p in parameters[:i]
				)
			):
				return_args.append("*")

			if parameter.kind == inspect.Parameter.VAR_POSITIONAL:
				arg = f"*{parameter.name}"
			elif parameter.kind == inspect.Parameter.VAR_KEYWORD:
				arg = f"**{parameter.name}"
			else:
				arg = parameter.name

			if i == current_argument_index:
				arg_postfix = ''
				if parameter.annotation is not inspect.Signature.empty:
					annotation = _format_annotation(parameter.annotation)
					arg_postfix += f": {annotation}"

				if parameter.default is not inspect.Signature.empty:
					arg_postfix += f" = {parameter.default!r}"
				arg = html.escape(arg)
				arg_postfix = html.escape(arg_postfix)
				arg = f'<span class="currentArgument"><b>{arg}</b>{arg_postfix}</span>'
			else:
				arg = html.escape(arg)

			return_args.append(arg)

			if positional_only_count > 0 and i + 1 == positional_only_count:
				return_args.append("/")

		result = ", ".join(return_args)

		if signature.return_annotation is not inspect.Signature.empty:
			return_annotation = _format_annotation(signature.return_annotation)
			result += f'<span class="returnType"> -&gt; {html.escape(return_annotation)}</span>'

		return result, context["start_index"]

	def complete(self, text: str, state) -> Optional[str]:
		"""Return the next possible completion for 'text'.

		This is called successively with state == 0, 1, 2, ... until it
		returns None. The completion should begin with 'text'.

		"""
		if self.use_main_ns:
			self.namespace = __main__.__dict__

		if not text.strip():
			if state == 0:
				return '\t'
			else:
				return None

		if state == 0:
			if "." in text:
				self.matches = self.attr_matches(text)
			else:
				self.matches = self.global_matches(text)
		try:
			return self.matches[state]
		except IndexError:
			return None

	def _callable_postfix(self, val, word):
		if callable(val) and not inspect.isclass(val):
			word = word + fnsignature(val)
		return word

	def global_matches(self, text):
		"""Compute matches when text is a simple name.

		Return a list of all keywords, built-in functions and names currently
		defined in self.namespace that match.

		"""
		import keyword
		matches = []
		seen = {"__builtins__"}
		n = len(text)
		for word in keyword.kwlist:
			score = fuzzy_match(word, text)
			if score is not None:
				seen.add(word)
				if word in {'finally', 'try'}:
					word = word + ':'
				elif word not in {'False', 'None', 'True', 'break', 'continue', 'pass', 'else'}:
					word = word + ' '
				matches.append((-score, word))
		#Not sure why in the console builtins becomes a dict but this works for now.
		if hasattr(__builtins__, '__dict__'):  # type: ignore # remove this ignore > pyright 1.1.149
			builtins = __builtins__.__dict__  # type: ignore # remove this ignore > pyright 1.1.149
		else:
			builtins = __builtins__  # type: ignore # remove this ignore > pyright 1.1.149

		for nspace in [self.namespace, builtins]:
			for word, val in nspace.items():
				score = fuzzy_match(word, text)
				if score is not None and word not in seen:
				# if word[:n] == text and word not in seen:
					seen.add(word)
					matches.append((-score, self._callable_postfix(val, word)))
		matches.sort()
		return [match for (_, match) in matches]

	def attr_matches(self, text):
		"""Compute matches when text contains a dot.

		Assuming the text is of the form NAME.NAME....[NAME], and is
		evaluable in self.namespace, it will be evaluated and its attributes
		(as revealed by dir()) are used as possible completions. (For class
		instances, class members are also considered.)

		WARNING: this can still invoke arbitrary C code, if an object
		with a __getattr__ hook is evaluated.

		"""
		import re
		m = re.match(r"([\w\[\]]+(\.[\w\[\]]+)*)\.([\w\[\]]*)", text)
		if not m:
			return []
		expr, attr = m.group(1, 3)
		try:
			thisobject = eval(expr, self.namespace)
		except Exception:
			return []

		# get the content of the object, except __builtins__
		words = set(dir(thisobject))
		words.discard("__builtins__")

		if hasattr(thisobject, '__class__'):
			words.add('__class__')
			words.update(get_class_members(thisobject.__class__))
		matches = []
		n = len(attr)
		if attr == '':
			noprefix = '_'
		elif attr == '_':
			noprefix = '__'
		else:
			noprefix = None
		while True:
			for word in words:
				score = fuzzy_match(word, attr)
				if score is not None and (word[:n] == attr and not (noprefix and word[:n + 1] == noprefix)):
					match = f"{expr}.{word}"
					try:
						val = inspect.getattr_static(thisobject, word)
					except Exception:
						pass  # Include even if attribute not set
					else:
						match = self._callable_postfix(val, match)
					matches.append((-score, match))
			if matches or not noprefix:
				break
			if noprefix == '_':
				noprefix = '__'
			else:
				noprefix = None
		matches.sort()
		return [match for (_, match) in matches]


def get_class_members(klass):
	ret = dir(klass)
	if hasattr(klass, '__bases__'):
		for base in klass.__bases__:
			ret = ret + get_class_members(base)
	return ret
