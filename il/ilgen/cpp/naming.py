"""How the C++ API names an IL level's accessors, setters, builders and builder parameters.

An accessor's name is its kind's verb, then the value's role in CamelCase, then its kind's suffix. The verb is Get
unless the kind gives another. A src operand of kind expr is GetSourceExpr. A rename can replace the role, or everything
after the verb."""

from dataclasses import dataclass

from ..case import camel, lower_camel

# Value names that can't be C++ parameter names.
KEYWORDS = frozenset(
	"""
	alignas alignof and asm auto bool break case catch char class const continue default delete do double else enum
	explicit export extern false float for friend goto if inline int long mutable namespace new not operator or private
	protected public register return short signed sizeof static struct switch template this throw true try typedef
	typename union unsigned using virtual void volatile while xor
""".split()
)


@dataclass(frozen=True)
class AccessorName:
	"""An accessor's name, split after its verb."""

	verb: str
	rest: str
	# The role in CamelCase that `rest` starts with, or None where a rename gives `rest` outright.
	role: str | None

	def __str__(self):
		return self.verb + self.rest


class Names:
	def __init__(self, schema):
		self.level = schema.level
		self.schema = schema

	def accessor(self, op, value):
		verb = value.kind.cpp.verb
		rename = op.cpp.renames.get(value.name)
		if rename is not None and rename.to is not None:
			return AccessorName(verb, rename.to, None)

		role = camel(rename.role if rename is not None else self.schema.name(value.name).role)
		return AccessorName(verb, role + value.kind.cpp.suffix, role)

	def getter(self, op, value):
		return str(self.accessor(op, value))

	def operation(self, op):
		return self.level.op(op.name)

	@staticmethod
	def builders(op):
		"""Each builder's name in CamelCase."""
		return [camel(builder.name) for builder in op.builders]

	@staticmethod
	def params(args):
		"""{arg: parameter name}. Each is the arg's parameter words in lowerCamelCase. A name that's a C++ keyword gets
		its kind's suffix, such as trueExpr."""
		names = {}
		for arg in args:
			name = lower_camel('_'.join(arg.param_words))
			names[arg] = name + arg.kind.cpp.suffix if name in KEYWORDS else name

		return names
