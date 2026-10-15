"""The lifting side of the Rust LLIL API. It generates the lifters il.xsd's rust element describes, and result_width,
which gives the width of the value each expression produces. Other lifters are hand-written in lifting.rs outside its
generated region."""

from .. import docs
from ..case import capitalized
from ..model import SchemaError
from ..patch import Region
from .naming import Names

# The size a bare constant or register is built at, for each width the generator can build at.
LIFT_SIZES = {'size': 'size', 'twice-size': 'size * 2'}


def lift_size(op, operand):
	"""The size a bare constant or register for the operand is built at, or None if it only takes an expression."""
	if operand.name in op.rust.lifts:
		return LIFT_SIZES.get(op.rust.lifts[operand.name])

	if operand.sort.boolean:
		return '0'

	return LIFT_SIZES.get(operand.sort.width)


def result_width(sort):
	return '0' if sort.boolean else LIFT_SIZES.get(sort.width)


class Lifters:
	def __init__(self, schema):
		self.schema = schema
		self.names = Names(schema)

	def lifted(self, op):
		"""[(method name, builder)] for each builder that gets a generated lifter."""
		if op.is_part:
			return []

		result = []
		for method, builder in zip(self.names.lifters(op), op.builders, strict=True):
			if builder.handwritten:
				continue

			if all(o.kind.expression and not o.is_part for o in op.operands if o.name not in builder.fixed):
				result.append((method, builder))

		return result

	def lifter(self, op, method, builder):
		result = 'VoidExpr' if op.placement == 'statement' else 'ValueExpr'
		values = ['0'] * self.schema.slots
		for name, value in builder.fixed.items():
			values[op.operand(name).slot] = value

		params, bounds, lets = [], [], []
		for operand in op.operands:
			if operand.name in builder.fixed:
				continue

			param, generic = operand.name, capitalized(operand.name)
			size = lift_size(op, operand)
			if size is not None and not op.sized:
				raise SchemaError(f"{op.name}.{param}: an unsized op can't lift at its size")

			params.append((param, generic))
			if size is None:
				bounds.append(f"{generic}: LiftableLowLevelIL<'a, Result = ValueExpr>")
				lets.append(f'let {param} = {generic}::lift(self, {param});')
			else:
				bounds.append(f"{generic}: LiftableLowLevelILWithSize<'a>")
				lets.append(f'let {param} = {generic}::lift_with_size(self, {param}, {size});')

			values[operand.slot] = f'{param}.index.0 as u64'

		operation = self.names.operation(op)
		lifetime = "'a" if params else "'_"
		receiver = "&'a self" if params else '&self'
		args = [receiver] + (['size: usize'] if op.sized else []) + [f'{param}: {generic}' for param, generic in params]
		type_params = f"<'a, {', '.join(generic for _, generic in params)}>" if params else ''
		if op.sized:
			returns = f'ExpressionBuilder<{lifetime}, {result}>'
		else:
			returns = f'LowLevelILExpression<{lifetime}, Mutable, NonSSA, {result}>'

		lines = [f"    pub fn {method}{type_params}({', '.join(args)}) -> {returns}"]
		doc = docs.builder_doc(op, builder)
		if doc is not None:
			doc_params = ([('size', 'size')] if op.sized else []) + [(param, param) for param, _ in params]
			lines = [f'    {line}' for line in docs.rust_doc(doc, doc_params)] + lines

		if bounds:
			lines += ['    where', *[f'        {bound},' for bound in bounds], '    {']
		else:
			lines[-1] += ' {'

		if not op.sized:
			lines.append('        use binaryninjacore_sys::BNLowLevelILAddExpr;')

		lines += [f'        use binaryninjacore_sys::BNLowLevelILOperation::{operation};', '']
		if lets:
			lines += [f'        {let}' for let in lets] + ['']

		if op.sized:
			lines += [
				'        ExpressionBuilder {',
				'            function: self,',
				f'            op: {operation},',
				'            size,',
				'            flag_write: FlagWriteId(0),',
			]
			lines += [f'            op{index + 1}: {value},' for index, value in enumerate(values)]
			lines += ['            _ty: PhantomData,', '        }']
		else:
			call = f"BNLowLevelILAddExpr(self.handle, {operation}, 0, 0, {', '.join(values)})"
			lines += [
				'        let expr_idx = unsafe {',
				f'            {call}',
				'        };',
				'',
				'        LowLevelILExpression::new(self, LowLevelExpressionIndex(expr_idx))',
			]

		lines.append('    }')
		return '\n'.join(lines)

	def result_width(self):
		groups = {}
		for op in self.schema.ops.values():
			width = result_width(op.result) if op.result is not None else None
			if width is not None:
				groups.setdefault(width, []).append(self.names.operation(op))

		lines = [
			'/// The width of the value an expression produces given its size field, or `None` where its width',
			"/// isn't tied to its size.",
			'#[cfg(debug_assertions)]',
			'pub(crate) fn result_width(op: BNLowLevelILOperation, size: usize) -> Option<usize> {',
			'    use binaryninjacore_sys::BNLowLevelILOperation::*;',
			'',
			'    match op {',
		]
		for width, operations in groups.items():
			lines += [
				('        ' if index == 0 else '        | ') + operation for index, operation in enumerate(operations)
			]
			lines[-1] += f' => Some({width}),'

		lines += ['        _ => None,', '    }', '}']
		return '\n'.join(lines)

	def lifters(self):
		methods = [
			self.lifter(op, method, builder) for op in self.schema.ops.values() for method, builder in self.lifted(op)
		]
		return self.result_width() + '\n\nimpl LowLevelILMutableFunction {\n' + '\n\n'.join(methods) + '\n}'


def regions(schema):
	level = schema.level
	return [Region(level.rust_path('lifting'), level.region('lifters'), Lifters(schema).lifters())]
