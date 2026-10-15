"""An IL level's Python builder methods on the function class, one for each builder."""

from .. import docs
from ..model import SchemaError
from .kinds import Kinds
from .naming import Names

FLAGS = "flags: Optional['architecture.FlagWriteType'] = None"
LOC = "loc: Optional['ILSourceLocation'] = None"


class Builders:
	def __init__(self, schema):
		self.schema = schema
		self.kinds = Kinds(schema)
		self.names = Names(schema)

	def annotation(self, op, arg):
		"""(the parameter's type annotation, whether it already takes None)."""
		param = op.py.params.get(arg.name)
		if param is not None and param.annotation is not None:
			return param.annotation, False

		return self.kinds.param(arg.kind), arg.kind.py.param_optional

	def signature(self, op, builder, names, required, optional, own):
		"""The method's parameters, in declaration order. `own` maps optional args to defaults that aren't their
		kind's."""
		signature = ['self'] + (['size: int'] if op.sized and builder.size is None else [])
		signature += [f'{names[arg]}: {self.annotation(op, arg)[0]}' for arg in required]
		signature += [FLAGS] if op.flags else []
		for arg in optional:
			hint, takes_none = self.annotation(op, arg)
			if arg in own:
				signature.append(f'{names[arg]}: {hint} = {own[arg]}')
				continue

			default = arg.kind.py.default
			if default is None and not takes_none:
				hint = f'Optional[{hint}]'

			signature.append(f"{names[arg]}: {hint} = {'None' if default is None else default}")

		return signature + [LOC]

	def converts(self, op, arg):
		"""Whether the method converts the arg's parameter before storing it."""
		param = op.py.params.get(arg.name)
		return param is not None and param.conversion is not None or self.kinds.converts(arg.kind)

	def converted(self, op, arg, names):
		"""The expression for each slot the arg's value takes."""
		expr = names[arg]
		param = op.py.params.get(arg.name)
		if param is not None and param.conversion is not None:
			expr = param.conversion.format(p=expr)

		return [conversion.format(p=expr) for conversion in self.kinds.conversions(arg.kind)]

	def slots(self, op, slots, names, prelude):
		"""The expressions that store each of the [Slot] of the built op `op`, which also gives the params of the args
		stored through its parts."""
		out = []
		for slot in slots:
			operand = slot.operand
			if slot.part is not None:
				inner = ', '.join(self.slots(op, slot.part, names, prelude))
				operation = self.names.operation(operand.part)
				out.append(f'self.expr({operation}, {inner}, size={slot.part_size}, source_location=loc)')
				continue

			if slot.fixed is not None:
				out.append(slot.fixed)
				continue

			arg = slot.arg
			value = self.converted(op, arg, names)
			if not operand.kind.is_list:
				if len(value) != operand.kind.width:
					raise SchemaError(
						f'{op.name}: {operand.kind.name} takes {operand.kind.width} slots, but its Python '
						f'conversion gives {len(value)}'
					)

				out += value
				continue

			local = names[arg]
			if self.converts(op, arg):
				local = f'_{names[arg]}'
				prelude.append(f'{local} = {value[0]}')

			adder, width = self.kinds.adder(operand.kind)
			out += [f'len({local})' + (f' * {width}' if width > 1 else ''), f'self.{adder}({local})']

		return out

	def method(self, op, name, builder):
		names = {arg: self.names.param(op, arg) for arg in builder.args}
		# The op's py params can give args defaults that aren't their kind's.
		own = {}
		for arg in builder.args:
			param = op.py.params.get(arg.name)
			if param is not None and param.default is not None:
				own[arg] = param.default

		required = [arg for arg in builder.args if arg.name not in builder.defaults and arg not in own]
		optional = [arg for arg in builder.args if arg.name in builder.defaults or arg in own]
		signature = self.signature(op, builder, names, required, optional, own)

		prelude = []
		slots = self.slots(op, builder.slots(op), names, prelude)
		sized = op.sized and builder.size is None
		size = builder.size or ('size' if sized else None)
		keywords = (f', size={size}' if size else '') + (', flags=flags' if op.flags else '') + ', source_location=loc'
		call = f'self.expr({self.names.operation(op)}' + ''.join(f', {slot}' for slot in slots) + keywords + ')'

		lines = [f'def {name}(', f"\t{', '.join(signature)}", ') -> ExpressionIndex:']
		doc = docs.builder_doc(op, builder)
		if doc is not None:
			doc_params = [('size', 'size')] if sized else []
			doc_params += [(arg.name, names[arg]) for arg in required] + ([('flags', 'flags')] if op.flags else [])
			doc_params += [(arg.name, names[arg]) for arg in optional] + [('loc', 'loc')]
			lines += [f'\t{line}' if line else '' for line in docs.py_docstring(doc, doc_params)]

		lines += [f'\t{line}' for line in prelude] + [f'\treturn {call}']
		return '\n'.join(lines)

	def methods(self):
		methods = []
		for op in self.schema.ops.values():
			for name, builder in self.names.methods(op):
				if not builder.handwritten:
					methods.append(self.method(op, name, builder))

		return '\n\n'.join(methods)
