"""The decoding side of the Rust LLIL API. That's the operation markers with their accessors and Debug impls, the
expression kind enum with from_raw, size, the as_* helpers, visit_sub_expressions, raw_struct and flag_write, and the
instruction kind enum with from_raw and visit_sub_expressions.

A marker is one Rust type that every op naming it shares, so their layouts must match. Markers whose ops differ, and
accessors that do more than decode a value, are hand-written in operation.rs outside its generated region, and
llil.xml's rust-marker elements name them."""

from dataclasses import dataclass

from .. import docs
from ..model import SchemaError
from ..patch import Region
from .naming import Names

EXPR = "LowLevelILExpression<'func, M, F, ValueExpr>"
REG = 'LowLevelILRegisterKind::from_raw(&self.function.arch(), RegisterId({0} as u32)).expect("Bad register ID")'
FLAG = 'self.function.arch().flag_from_id(FlagId({0} as u32)).expect("Bad flag ID")'
REG_STACK = 'self.function.arch().register_stack_from_id(RegisterStackId({0} as u32)).expect("Bad register stack ID")'

# The kinds.xml rust attributes LLIL reads.
ATTRIBUTES = ('type', 'decoder')
# The LLIL decoders that kinds.xml's rust elements name. {0} and {1} are a value's slots, and {list} is a list's items.
DECODERS = {
	'expr': 'LowLevelILExpression::new(self.function, LowLevelExpressionIndex({0} as usize))',
	'instruction': 'LowLevelILInstruction::new(self.function, LowLevelInstructionIndex({0} as usize))',
	'raw': '{0}',
	'nonzero': '{0} != 0',
	'register': REG,
	'flag': FLAG,
	'register_stack': REG_STACK,
	'intrinsic': 'self.function.arch().intrinsic_from_id(IntrinsicId({0} as u32))',
	'flag_class': 'self.function.arch().flag_class_from_id(FlagClassId({0} as u32))',
	'flag_group': 'self.function.arch().flag_group_from_id(FlagGroupId({0} as u32)).expect("Bad flag group ID")',
	# Core only stores valid conditions.
	'flag_condition': 'unsafe {{ mem::transmute::<u8, FlagCondition>({0} as u8) }}',
	'cached_value_set': 'PossibleValueSet::from_owned_core_raw(unsafe {{ '
	'BNGetCachedLowLevelILPossibleValueSet(self.function.handle, {0} as usize) }})',
	'ssa_register': 'LowLevelILSSARegisterKind::new_full(' + REG + ', {1} as u32)',
	'ssa_flag': 'LowLevelILSSAFlag::new(' + FLAG + ', {1} as u32)',
	'ssa_register_stack': 'LowLevelILSSARegisterStack::new(' + REG_STACK + ', {1} as u32)',
	'expr_list': '{list}.into_iter().map(|index| LowLevelILExpression::new(self.function, '
	'LowLevelExpressionIndex(index as usize))).collect()',
	'version_list': '{list}.into_iter().map(|version| version as usize).collect()',
	'label_map': '{list}.as_chunks::<2>().0.iter()'
	'.map(|pair| (pair[0], LowLevelInstructionIndex(pair[1] as usize))).collect()',
	'ssa_register_list': '{list}.as_chunks::<2>().0.iter().map(|pair| '
	'LowLevelILSSARegisterKind::new_full(' + REG.format('pair[0]') + ', pair[1] as u32)).collect()',
	'ssa_flag_list': '{list}.as_chunks::<2>().0.iter().map(|pair| '
	'LowLevelILSSAFlag::new(' + FLAG.format('pair[0]') + ', pair[1] as u32)).collect()',
	'ssa_register_stack_list': '{list}.as_chunks::<2>().0.iter()'
	'.map(|pair| LowLevelILSSARegisterStack::new(' + REG_STACK.format('pair[0]') + ', pair[1] as u32)).collect()',
	'register_or_flag_list': 'let arch = self.function.arch(); {list}.into_iter()'
	'.map(|raw| IntrinsicOutput::from_raw(&arch, raw)).collect()',
	'ssa_register_or_flag_list': 'let arch = self.function.arch(); '
	'{list}.as_chunks::<2>().0.iter().map(|pair| SSAIntrinsicOutput {{ output: IntrinsicOutput::from_raw(&arch, pair[0]), '
	'version: pair[1] as u32 }}).collect()',
}
# The Rust types a <rust><type> can give a value, and how each converts the decoded value.
TYPE_CONVERSIONS = {'usize': '{0} as usize'}
BOUNDS = 'where\n    M: FunctionMutability,\n    F: FunctionForm,\n'
# The placements of the ops each kind enum decodes.
PLACEMENTS = {'instruction': ('statement', 'either'), 'expression': ('expression', 'part', 'either')}


@dataclass(frozen=True)
class Child:
	"""A marker's accessor for a child expression or expression list."""

	accessor: str
	is_list: bool


def rust_type(kind):
	"""The type an accessor of the kind returns. A list's is a Vec of its item kind's type unless given."""
	return kind.rust.type if kind.rust.type is not None else f'Vec<{rust_type(kind.item)}>'


class Decoder:
	def __init__(self, schema):
		self.schema = schema
		self.names = Names(schema)
		self.handwritten_markers = {name for name, marker in schema.rust_markers.items() if marker.handwritten}
		for kind in schema.kinds.values():
			if kind.rust.decoder is not None and kind.rust.decoder not in DECODERS:
				raise SchemaError(f'kind {kind.name}: no LLIL rust decoder named {kind.rust.decoder}')

		# {marker: [Op]}
		self.markers = {}
		for op in schema.ops.values():
			self.markers.setdefault(self.names.marker(op), []).append(op)

		for marker, ops in self.markers.items():
			layouts = {
				tuple((o.name, o.kind.name, o.part.name if o.is_part else None) for o in op.operands) for op in ops
			}
			if len(layouts) > 1 and marker not in self.handwritten_markers:
				raise SchemaError(
					f'marker {marker} is shared by ops with different layouts {[op.name for op in ops]}, so it '
					'must be hand-written'
				)

	def accessor(self, value):
		"""(the type a marker's accessor for the value returns, its body)."""
		location = value.location
		if value.is_part:
			return EXPR, DECODERS['expr'].format(f'self.op.operands[{location.slot}]')

		if value.kind.rust.decoder is None:
			raise SchemaError(f'kind {value.kind.name}: no LLIL rust decoder')

		if location.in_part:
			raws = (
				f'self.get_sub_operand({location.slot}, {location.first})',
				f'self.get_sub_operand({location.slot}, {location.second})',
			)
			items = f'self.get_sub_operand_list({location.slot}, {location.first})'
		else:
			raws = (f'self.op.operands[{location.first}]', f'self.op.operands[{location.second}]')
			items = f'self.get_operand_list({location.first})'

		return rust_type(value.kind), DECODERS[value.kind.rust.decoder].format(*raws, list=items)

	def marker_code(self, marker, ops):
		op = ops[0]
		declared = self.schema.rust_markers.get(marker)
		handwritten = set(declared.accessors) if declared is not None else set()
		accessors = ['    pub fn size(&self) -> usize {\n        self.op.size\n    }'] if op.sized else []
		fields = ['address'] + (['size'] if op.sized else [])
		for value in op.members:
			name = self.names.accessor(op, value)
			fields.append(name)
			if name in handwritten:
				continue

			returned, body = self.accessor(value)
			converted = op.rust.types.get(value.name)
			if converted is not None:
				returned, body = converted, TYPE_CONVERSIONS[converted].format(body)

			accessors.append(f'    pub fn {name}(&self) -> {returned} {{\n        {body}\n    }}')

		fields += sorted(handwritten - set(fields))
		lines = docs.wrap('// ' + ', '.join(self.names.operation(o) for o in ops), indent='// ')
		lines += [f'pub struct {marker};', '']
		if accessors:
			lines += [
				f"impl<'func, M, F> Operation<'func, M, F, {marker}>",
				BOUNDS + '{',
				'\n\n'.join(accessors),
				'}',
				'',
			]

		debug = ''.join(f'\n            .field("{field}", &self.{field}())' for field in fields)
		lines += [
			f"impl<M, F> Debug for Operation<'_, M, F, {marker}>",
			BOUNDS + '{',
			"    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {",
			f'        f.debug_struct("{marker}"){debug}\n            .finish()',
			'    }',
			'}',
		]
		return '\n'.join(lines)

	def operation_rs(self):
		parts = [
			self.marker_code(marker, ops)
			for marker, ops in self.markers.items()
			if marker not in self.handwritten_markers
		]
		parts.append(
			"pub trait OperationArguments: 'static {}\n\n"
			+ '\n'.join(f'impl OperationArguments for {marker} {{}}' for marker in self.markers)
		)
		return '\n\n'.join(parts) + '\n'

	def variants(self, enum):
		"""{variant: (marker, [Op])} for the ops the kind enum decodes."""
		variants = {}
		for op in self.schema.ops.values():
			if op.placement in PLACEMENTS[enum]:
				variants.setdefault(self.names.variant(op), (self.names.marker(op), []))[1].append(op)

		return variants

	def children(self, op):
		"""[Child] for an op's part operands, child expressions and expression lists, in storage order."""
		result = []
		for operand in op.operands:
			if operand.is_part or operand.kind.holds_expressions:
				result.append(Child(self.names.accessor(op, operand), not operand.is_part and operand.kind.is_list))

		return tuple(result)

	@staticmethod
	def visit(child, by_reference):
		"""The expression visiting a child, or each expression of a list."""
		ref = '&' if by_reference else ''
		if child.is_list:
			return f'for expr in op.{child.accessor}() {{\n                    visit!({ref}expr);\n                }}'

		return f'visit!({ref}op.{child.accessor}())'

	def visit_arms(self, variants, by_reference):
		"""The match arms visiting each variant's children, one arm per group of variants that share a marker and visit
		the same children, and the variants with no children."""
		groups = {}
		leaves = []
		for variant, (marker, ops) in variants.items():
			children = self.children(ops[0])
			if children:
				groups.setdefault((marker, children), []).append(variant)
			else:
				leaves.append(f'{variant}(_)')

		arms = []
		for (_, children), grouped in groups.items():
			pattern = ' | '.join(f'{variant}(ref op)' for variant in grouped)
			if len(children) == 1:
				arms.append(f'            {pattern} => {self.visit(children[0], by_reference)},')
				continue

			# A for loop is a statement already, and a visit! needs a semicolon to be one.
			statements = [self.visit(child, by_reference) + ('' if child.is_list else ';') for child in children]
			arms.append(
				f'            {pattern} => {{\n'
				+ ''.join(f'                {statement}\n' for statement in statements)
				+ '            }'
			)

		return arms, leaves

	def expression_rs(self):
		variants = self.variants('expression')
		# Ops that aren't expressions decode as Undef.
		variants.setdefault('Undef', ('NoArgs', []))
		enum = ['#[derive(Debug)]', "pub enum LowLevelILExpressionKind<'func, M, F>", BOUNDS + '{']
		enum += [
			f"    {variant}(Operation<'func, M, F, operation::{marker}>)," for variant, (marker, _) in variants.items()
		]
		enum.append('}')
		decode = '\n'.join(
			f"            {' | '.join(self.names.operation(op) for op in ops)} => {{\n"
			f'                LowLevelILExpressionKind::{variant}(Operation::new(function, op, index))\n            }}'
			for variant, (_, ops) in variants.items()
			if ops
		)
		size_none = [variant for variant, (_, ops) in variants.items() if any(op.sizeless for op in ops)]
		size_zero = [
			variant
			for variant, (_, ops) in variants.items()
			if ops and not any(op.sizeless for op in ops) and not ops[0].sized
		]
		as_helpers = []
		for marker, declared in self.schema.rust_markers.items():
			helper = declared.as_method
			if helper is None:
				continue

			matching = ' | '.join(f'{variant}(ref op)' for variant, (m, _) in variants.items() if m == marker)
			as_helpers.append(
				f"    pub fn {helper}(&self) -> Option<&Operation<'func, M, F, operation::{marker}>> {{\n"
				'        use self::LowLevelILExpressionKind::*;\n\n        match *self {\n'
				f'            {matching} => Some(op),\n            _ => None,\n        }}\n    }}'
			)

		visit_arms, leaves = self.visit_arms(variants, by_reference=False)
		raw_struct = '\n'.join(f'            {variant}(ref op) => &op.op,' for variant in variants)
		# Any expression can carry a flag write, not only those whose C++ builders take flags, and core honors it.
		by_marker = {}
		for variant, (marker, _) in variants.items():
			by_marker.setdefault(marker, []).append(variant)

		flag_writes = '\n'.join(
			f"            {' | '.join(f'{variant}(ref op)' for variant in grouped)} => op.flag_write(),"
			for grouped in by_marker.values()
		)
		as_methods = '\n'.join(helper + '\n' for helper in as_helpers)
		visits = '\n'.join(visit_arms)
		return (
			'\n'.join(enum)
			+ f"""

impl<'func, M, F> LowLevelILExpressionKind<'func, M, F>
{BOUNDS}{{
    pub(crate) fn from_raw(
        function: &'func LowLevelILFunction<M, F>,
        op: BNLowLevelILInstruction,
        index: LowLevelExpressionIndex,
    ) -> Self {{
        use binaryninjacore_sys::BNLowLevelILOperation::*;

        match op.operation {{
{decode}
            _ => {{
                tracing::error!(
                    "Got unexpected operation {{:?}} in value expr at 0x{{:x}}",
                    op.operation,
                    op.address
                );

                LowLevelILExpressionKind::Undef(Operation::new(function, op, index))
            }}
        }}
    }}

    /// Returns the size of the operation in bytes
    ///
    /// If the expression is malformed or is `Unimpl` there
    /// is no meaningful size associated with the result.
    pub fn size(&self) -> Option<usize> {{
        use self::LowLevelILExpressionKind::*;

        match *self {{
            {' | '.join(f'{variant}(..)' for variant in size_none)} => None,
            {' | '.join(f'{variant}(..)' for variant in size_zero)} => Some(0),
            _ => Some(self.raw_struct().size),
        }}
    }}

    pub fn address(&self) -> u64 {{
        self.raw_struct().address
    }}

    /// Determines if the expressions represent the same operation
    ///
    /// It does not examine the operands for equality.
    pub fn is_same_op_as(&self, other: &Self) -> bool {{
        self.raw_struct().operation == other.raw_struct().operation
    }}

{as_methods}
    pub fn visit_sub_expressions<T>(&self, mut visitor: T) -> VisitorAction
    where
        T: FnMut(LowLevelILExpression<'func, M, F, ValueExpr>) -> VisitorAction,
    {{
        use LowLevelILExpressionKind::*;

        macro_rules! visit {{
            ($expr:expr) => {{
                if let VisitorAction::Halt = visitor($expr) {{
                    return VisitorAction::Halt;
                }}
            }};
        }}

        match self {{
{visits}
            // Do not have any sub expressions.
            {' | '.join(leaves)} => {{}}
        }}

        VisitorAction::Sibling
    }}

    pub(crate) fn raw_struct(&self) -> &BNLowLevelILInstruction {{
        use self::LowLevelILExpressionKind::*;

        match *self {{
{raw_struct}
        }}
    }}
}}

impl LowLevelILExpressionKind<'_, Mutable, NonSSA> {{
    pub fn flag_write(&self) -> Option<CoreFlagWrite> {{
        use self::LowLevelILExpressionKind::*;

        match *self {{
{flag_writes}
        }}
    }}
}}
"""
		)

	def instruction_rs(self):
		variants = self.variants('instruction')
		enum = ['#[derive(Debug)]', "pub enum LowLevelILInstructionKind<'func, M, F>", BOUNDS + '{']
		enum += [
			f"    {variant}(Operation<'func, M, F, operation::{marker}>)," for variant, (marker, _) in variants.items()
		]
		enum += [
			'',
			'    /// The instruction is an expression.',
			"    Value(LowLevelILExpression<'func, M, F, ValueExpr>),",
			'}',
		]
		decode = '\n'.join(
			f"            {' | '.join(self.names.operation(op) for op in ops)} => {{\n"
			f'                LowLevelILInstructionKind::{variant}(Operation::new(function, op, expr_index))\n            }}'
			for variant, (_, ops) in variants.items()
		)
		visit_arms, leaves = self.visit_arms(variants, by_reference=True)
		visits = '\n'.join(visit_arms)
		return (
			'\n'.join(enum)
			+ f"""

impl<'func, M, F> LowLevelILInstructionKind<'func, M, F>
{BOUNDS}{{
    pub(crate) unsafe fn from_raw(
        function: &'func LowLevelILFunction<M, F>,
        expr_index: LowLevelExpressionIndex,
        op: BNLowLevelILInstruction,
    ) -> Self {{
        use binaryninjacore_sys::BNLowLevelILOperation::*;

        match op.operation {{
{decode}
            _ => LowLevelILInstructionKind::Value(LowLevelILExpression::new(function, expr_index)),
        }}
    }}

    fn visit_sub_expressions<T>(&self, mut visitor: T) -> VisitorAction
    where
        T: FnMut(&LowLevelILExpression<'func, M, F, ValueExpr>) -> VisitorAction,
    {{
        use LowLevelILInstructionKind::*;

        macro_rules! visit {{
            ($expr:expr) => {{
                if let VisitorAction::Halt = visitor($expr) {{
                    return VisitorAction::Halt;
                }}
            }};
        }}

        match self {{
{visits}
            Value(e) => visit!(e),
            // Do not have any sub expressions.
            {' | '.join(leaves)} => {{}}
        }}

        VisitorAction::Sibling
    }}
}}
"""
		)


def regions(schema):
	decoder = Decoder(schema)
	level = schema.level
	return [
		Region(level.rust_path('operation'), level.region('operations'), decoder.operation_rs()),
		Region(level.rust_path('expression'), level.region('expression-kind'), decoder.expression_rs()),
		Region(level.rust_path('instruction'), level.region('instruction-kind'), decoder.instruction_rs()),
	]
