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

	def signature(self, op, builder, names, required, optional):
		"""The method's parameters, in declaration order."""
		signature = ['self'] + (['size: int'] if op.sized and builder.size is None else [])
		signature += [f'{names[arg]}: {self.kinds.param(arg.kind)}' for arg in required]
		signature += [FLAGS] if op.flags else []
		for arg in optional:
			hint = self.kinds.param(arg.kind)
			default = arg.kind.py.default
			if default is None and not arg.kind.py.param_optional:
				hint = f'Optional[{hint}]'

			signature.append(f"{names[arg]}: {hint} = {'None' if default is None else default}")

		return signature + [LOC]

	def converted(self, arg, names):
		"""The expression for each slot the arg's value takes."""
		return [conversion.format(p=names[arg]) for conversion in self.kinds.conversions(arg.kind)]

	def slots(self, op, slots, names, prelude):
		"""The expressions that store each of the [Slot] of the built op `op`."""
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
			value = self.converted(arg, names)
			if not operand.kind.is_list:
				if len(value) != operand.kind.width:
					raise SchemaError(
						f'{op.name}: {operand.kind.name} takes {operand.kind.width} slots, but its Python '
						f'conversion gives {len(value)}'
					)

				out += value
				continue

			local = names[arg]
			if self.kinds.converts(arg.kind):
				local = f'_{names[arg]}'
				prelude.append(f'{local} = {value[0]}')

			adder, width = self.kinds.adder(operand.kind)
			out += [f'len({local})' + (f' * {width}' if width > 1 else ''), f'self.{adder}({local})']

		return out

	def method(self, op, name, builder):
		names = {arg: self.names.param(op, arg) for arg in builder.args}
		required = [arg for arg in builder.args if arg.name not in builder.defaults]
		optional = [arg for arg in builder.args if arg.name in builder.defaults]
		signature = self.signature(op, builder, names, required, optional)

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
