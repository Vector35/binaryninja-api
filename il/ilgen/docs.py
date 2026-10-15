"""Builder documentation, rendered in each binding's documentation syntax from the description, size and form
elements and the descriptions of the builder's args."""

import textwrap
import xml.etree.ElementTree as ET
from dataclasses import dataclass

from .model import SchemaError

WIDTH = 100

FLAGS = 'The flag write type that selects the flags the operation sets'
LOC = 'The IL location this expression was added from'


# Stands in for a space inside code until wrap has laid out the lines, so that code never breaks across lines.
CODE_SPACE = '\0'


@dataclass(frozen=True)
class Style:
	"""How a binding's documentation spells refs, code, schema text and placeholders such as <size>."""

	# The text before and after code.
	code_open: str
	code_close: str
	escape: object
	placeholder: object

	def ref(self, name):
		return self.code(name)

	def code(self, text):
		"""Code from already escaped text, with its whitespace collapsed into spaces that wrap never breaks at."""
		return self.code_open + CODE_SPACE.join(text.split()) + self.code_close


def doxygen_escape(text):
	"""Text that Doxygen shows as it is, rather than reading HTML tags or entities in it."""
	return text.replace('&', '\\&').replace('<', '\\<').replace('>', '\\>')


CPP = Style('<tt>', '</tt>', doxygen_escape, lambda name: f'\\<{name}\\>')
PY = Style('``', '``', lambda text: text, lambda name: f'<{name}>')
RUST = Style('`', '`', lambda text: text, lambda name: f'<{name}>')


def prose(text):
	"""A Prose element holding plain text."""
	element = ET.Element('description')
	element.text = text
	return element


class BuilderDoc:
	"""One builder's documentation. It says what the builder does, each parameter it takes and the expression it
	returns."""

	def __init__(self, op, builder):
		self.op = op
		self.builder = builder
		self.description = builder.description
		self.form = builder.form

	def param(self, name):
		"""The description of a builder parameter, which is size, flags, loc or one of the builder's args."""
		if name == 'size':
			return self.op.size if self.op.size is not None else self.size()

		if name == 'flags':
			return prose(FLAGS)

		if name == 'loc':
			return prose(LOC)

		arg = self.builder.arg(name)
		if arg is None or arg.description is None:
			raise SchemaError(f'{self.op.name}: the builder parameter {name} has no description')

		return arg.description

	def size(self):
		"""The size of the result where its width is size, else of the operands whose width is size."""
		if self.op.result is not None and self.op.result.width == 'size':
			return prose('The size of the result in bytes')

		sized = [o.name for o in self.op.operands if o.sort is not None and o.sort.width == 'size']
		if not sized:
			raise SchemaError(
				f'{self.op.name}: neither its result nor an operand has width size, so it needs a size element'
			)

		element = prose('The size of ')
		for index, name in enumerate(sized):
			ref = ET.SubElement(element, 'ref', name=name)
			ref.tail = ' and ' if index < len(sized) - 1 else ' in bytes'

		return element


def builder_doc(op, builder):
	"""The builder's documentation, or None where neither it nor its op has a description."""
	return BuilderDoc(op, builder) if builder.description is not None else None


def text(element, style, names, in_code=False):
	"""An element's text with each ref and code rendered in a binding's style, whitespace collapsed. Inside code, a
	ref is the bare parameter name."""

	def name(ref):
		value = ref.get('name')
		if value not in names:
			raise SchemaError(f'a ref to {value}, which this builder has no parameter for')

		return names[value]

	def inline(element, in_code):
		out = [style.escape(element.text or '')]
		for child in element:
			if child.tag == 'ref':
				out.append(name(child) if in_code else style.ref(name(child)))
			elif child.tag == 'code':
				out.append(style.code(inline(child, True)))
			elif child.tag == 'size':
				out.append('.' + style.placeholder('size'))
			elif child.tag == 'flags':
				out.append('{' + style.placeholder('flags') + '}')

			out.append(style.escape(child.tail or ''))

		return ''.join(out)

	return ' '.join(inline(element, in_code).split())


def form(doc, style, names):
	"""The return line's text."""
	return f'The expression {style.code(text(doc.form, style, names, in_code=True))}'


def wrap(line, indent=''):
	"""Wrapped lines, never breaking inside code."""
	lines = textwrap.wrap(line, WIDTH, subsequent_indent=indent, break_long_words=False, break_on_hyphens=False)
	return [line.replace(CODE_SPACE, ' ') for line in lines]


def cpp_comment(doc, params):
	"""A C++ doc comment's lines, for parameters [(name, C++ name)] in declaration order."""
	names = dict(params)
	lines = wrap(text(doc.description, CPP, names)) + ['']
	for name, spelled in params:
		lines += wrap(f'\\param {spelled} {text(doc.param(name), CPP, names)}')

	lines += wrap(f'\\return {form(doc, CPP, names)}')
	return ['/*! ' + lines[0]] + [f'\t{line}' if line else '' for line in lines[1:]] + ['*/']


def py_docstring(doc, params):
	"""A Python docstring's lines, for parameters [(name, Python name)] in signature order."""
	names = dict(params)
	lines = wrap(text(doc.description, PY, names)) + ['']
	for name, spelled in params:
		lines += wrap(f':param {spelled}: {text(doc.param(name), PY, names)}', '\t')

	lines += wrap(f':return: {form(doc, PY, names)}', '\t') + [':rtype: ExpressionIndex']
	return ['"""'] + lines + ['"""']


def rust_doc(doc, params):
	"""A Rust doc comment's lines, for parameters [(name, Rust name)]."""
	names = dict(params)
	lines = wrap(text(doc.description, RUST, names))
	lines += [''] + wrap(f'Returns the expression {RUST.code(text(doc.form, RUST, names, in_code=True))}.')
	if doc.op.flags:
		lines += [''] + wrap('Set its flag write type with [`ExpressionBuilder::with_flag_write`].')

	return [f'/// {line}' if line else '///' for line in lines]
