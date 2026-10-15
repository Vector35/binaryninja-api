"""An IL level's CopyTo, which copies every op's slots and passes child expressions through subExprHandler in storage
order. Ops with label operands need `dest`'s labels, so they forward to the hand-written CopyBranchTo."""

from ..case import lower_camel
from ..model import SchemaError
from ..patch import Region

# CopyTo's own locals, which a part's local mustn't shadow.
LOCALS = ('dest', 'size', 'flags', 'loc', 'expr')


class Copier:
	def __init__(self, schema):
		self.schema = schema
		self.level = schema.level

	def add_expr(self, op, size, flags, values):
		"""`dest`'s AddExprWithLocation call for `op`. Only levels whose instructions have flags take them."""
		flags_arg = f', {flags}' if self.schema.flags else ''
		return (
			f'dest->AddExprWithLocation({self.level.op(op.name)}, loc, {size}{flags_arg}'
			+ ''.join(f', {v}' for v in values)
			+ ')'
		)

	def slot_values(self, op, instr, prefix, statements):
		"""The expressions for each of op's slots, read from instr, or from this instruction where instr is None,
		adding any statements they need."""
		reader = f'{instr}.' if instr else ''
		values = []
		for operand in op.operands:
			name = lower_camel('_'.join([*prefix, operand.name]))
			slot = operand.slot
			match operand.copied_as:
				case 'part':
					if name in LOCALS:
						raise SchemaError(f'{op.name}: part {name} would shadow a CopyTo local')

					statements.append(f'{self.level.stem}Instruction {name} = {reader}GetRawOperandAsExpr({slot});')
					fields = self.slot_values(operand.part, name, [*prefix, operand.name], statements)
					statements.append(
						f'ExprId {name}Copy = {self.add_expr(operand.part, f"{name}.size", f"{name}.flags", fields)};'
					)
					values.append(f'{name}Copy')
				case 'expr':
					statements.append(f'ExprId {name}Copy = subExprHandler({reader}GetRawOperandAsExpr({slot}));')
					values.append(f'{name}Copy')
				case 'expr_list':
					statements += [
						f'vector<ExprId> {name}Copy;',
						f'for (const auto& expr : {reader}GetRawOperandAsExprList({slot}))',
						f'\t{name}Copy.push_back(subExprHandler(expr));',
					]
					values += [f'{name}Copy.size()', f'dest->AddOperandList({name}Copy)']
				case 'label':
					raise SchemaError(f'{op.name}: label operand {operand.name} needs CopyBranchTo')
				case 'list':
					values += [
						f'{reader}GetRawOperandAsInteger({slot})',
						f'CopyOperandList(dest, {instr or "*this"}, {slot})',
					]
				case 'constraint':
					values.append(f'dest->CachePossibleValueSet({reader}GetRawOperandAsPossibleValueSet({slot}))')
				case 'value':
					values += [f'{reader}GetRawOperandAsInteger({slot + i})' for i in range(operand.slots)]

		return values

	def case(self, op):
		statements = []
		values = self.slot_values(op, None, [], statements)
		call = self.add_expr(op, 'size', 'flags', values)
		case = f'\tcase {self.level.op(op.name)}:'
		if not statements:
			return [case, f'\t\treturn {call};']

		return [case, '\t{', *[f'\t\t{s}' for s in statements], f'\t\treturn {call};', '\t}']

	def copy_to(self):
		branch_cases, cases = [], []
		for op in self.schema.ops.values():
			if op.inline_part:
				continue

			if any(operand.copied_as == 'label' for operand in op.operands):
				branch_cases.append(f'\tcase {self.level.op(op.name)}:')
			else:
				cases += self.case(op)

		il = self.level.stem
		branches = (
			'\n'.join(branch_cases) + '\n\t\treturn CopyBranchTo(*this, dest, subExprHandler, loc);\n'
			if branch_cases
			else ''
		)
		return (
			f'static ExprId CopyOperandList({il}Function* dest, const {il}Instruction& instr, size_t operand)\n'
			'{\n\tvector<uint64_t> items = instr.function->GetOperandList(instr.exprIndex, operand);\n'
			'\treturn dest->AddIndexList(vector<size_t>(items.begin(), items.end()));\n}\n\n\n'
			f'ExprId {il}Instruction::CopyTo({il}Function* dest,\n'
			f'\tbn::base::function_ref<ExprId(const {il}Instruction& subExpr)> subExprHandler,\n'
			'\tconst ILSourceLocation& sourceLocation) const\n{\n'
			'\tconst auto& loc = sourceLocation.valid ? sourceLocation : ILSourceLocation{*this};\n'
			'\tswitch (operation)\n\t{\n'
			+ branches
			+ '\n'.join(cases)
			+ f'\n\tdefault:\n\t\tthrow {il}InstructionAccessException();\n\t}}\n}}'
		)


def regions(schema):
	return [Region(schema.level.source, schema.level.region('copy'), Copier(schema).copy_to())]
