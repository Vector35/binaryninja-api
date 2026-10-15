"""Loads the schema files into the model, checking everything the generators rely on that il.xsd can't express.

load() raises one SchemaError naming every problem it finds in a level, or in the kinds every level shares."""

import dataclasses
import functools
import os
import xml.etree.ElementTree as ET

from . import levels
from .model import (
	DATA,
	Arg,
	Builder,
	CppKind,
	Kind,
	Name,
	Op,
	Operand,
	Pair,
	PartAccessor,
	PyKind,
	PyShape,
	RustKind,
	RustMarker,
	Schema,
	SchemaError,
	Shape,
	ShapeOperand,
	Sort,
)

LANGUAGES = ('cpp', 'py', 'rust')
BINDINGS = {'cpp': CppKind, 'py': PyKind, 'rust': RustKind}
SORTS = ('integer', 'float', 'bits', 'boolean')
# The kind element's attributes that say what a value of the kind is.
KIND_FACTS = ('expression', 'label', 'version', 'cached')


def words(value):
	return value.split() if value else []


def flag(element, name, default=False):
	value = element.get(name)
	return default if value is None else value == 'true'


def listed(element, attribute):
	"""The words of an attribute that lists names, or None where it's absent. An empty attribute lists none."""
	if element is None or element.get(attribute) is None:
		return None

	return words(element.get(attribute))


def children(element, path):
	return element.findall(path) if element is not None else []


@dataclasses.dataclass(frozen=True)
class KindDeclaration:
	"""A kind, as declared in kinds.xml."""

	name: str
	slots: int
	# The kind this is a list of.
	item: str | None
	# The kind this is the SSA form of.
	ssa_of: str | None
	# What a value of the kind is, as {Kind field: bool}, such as expression.
	facts: dict
	# Each language's attributes.
	attributes: dict


@functools.cache
def kind_declarations():
	"""{name: KindDeclaration}."""
	root = ET.parse(os.path.join(DATA, 'kinds.xml')).getroot()
	declarations = {}
	for element in root.findall('kind'):
		attributes = {}
		for language in LANGUAGES:
			child = element.find(language)
			attributes[language] = dict(child.attrib) if child is not None else {}

		name = element.get('name')
		declarations[name] = KindDeclaration(
			name,
			int(element.get('slots', '1')),
			element.get('list'),
			element.get('ssa-of'),
			{fact: flag(element, fact) for fact in KIND_FACTS},
			attributes,
		)

	return declarations


@functools.cache
def names():
	"""{value name: Name}."""
	root = ET.parse(os.path.join(DATA, 'names.xml')).getroot()
	result = {}
	for element in root.findall('name'):
		cpp, rust = element.find('cpp'), element.find('rust')
		result[element.get('name')] = Name(
			element.get('role', element.get('name')),
			cpp.get('type') if cpp is not None else None,
			rust.get('role') if rust is not None else None,
		)

	return result


def check_kinds(problems):
	declarations = kind_declarations()
	for name, declaration in declarations.items():
		if declaration.item is not None and declaration.item not in declarations:
			problems.append(f'kind {name}: a list of unknown kind {declaration.item}')

		if declaration.ssa_of is not None and declaration.ssa_of not in declarations:
			problems.append(f'kind {name}: the SSA form of unknown kind {declaration.ssa_of}')


def typed(binding, kind, attributes, problems):
	"""A binding record from a kind's attributes, leaving out the attributes it has no field for."""
	types = {f.name: f.type for f in dataclasses.fields(binding)}
	values = {}
	for name, text in attributes.items():
		attribute = name.replace('-', '_')
		if attribute not in types:
			problems.append(f'kind {kind}: {binding.__name__} has no attribute {name}')
			continue

		if types[attribute] is bool:
			values[attribute] = text == 'true'
		elif types[attribute] in (int, int | None):
			values[attribute] = int(text)
		else:
			values[attribute] = text

	return binding(**values)


def resolve_kinds(problems):
	"""{name: Kind}."""
	kinds = {}
	for name, declaration in kind_declarations().items():
		bindings = {
			language: typed(BINDINGS[language], name, attributes, problems)
			for language, attributes in declaration.attributes.items()
		}
		kinds[name] = Kind(name, declaration.slots, **bindings, **declaration.facts)

	for name, declaration in kind_declarations().items():
		kinds[name].item = kinds.get(declaration.item)
		kinds[name].ssa_of = kinds.get(declaration.ssa_of)

	return kinds


def sort_of(element):
	for sort in SORTS:
		child = element.find(sort)
		if child is not None:
			return Sort(sort, child.get('width'))

	return None


def op_elements(root):
	"""The op elements in schema order, whether or not they're in a group."""
	return [e for child in root for e in ([child] if child.tag == 'op' else children(child, 'op'))]


def groups(root, ops):
	"""[(title or None, [Op])] in schema order. Ops outside any group join the run before them if it has no title."""
	runs = []
	for child in root:
		if child.tag == 'group':
			runs.append((child.get('title'), [ops[e.get('name')] for e in child.findall('op')]))
		elif child.tag == 'op' and runs and runs[-1][0] is None:
			runs[-1][1].append(ops[child.get('name')])
		elif child.tag == 'op':
			runs.append((None, [ops[child.get('name')]]))

	return runs


class Loader:
	"""Loads one level's schema, collecting every problem it finds."""

	def __init__(self, level, problems):
		self.level = level
		self.problems = problems
		self.kinds = resolve_kinds(problems)
		self.root = ET.parse(os.path.join(DATA, f'{level.name}.xml')).getroot()
		self.op_elements = {e.get('name'): e for e in op_elements(self.root)}
		self.shape_elements = {e.get('name'): e for e in self.root.findall('shape')}
		self.shapes = {name: self.shape(e) for name, e in self.shape_elements.items()}
		# {Op or Operand: its element}, for the methods that read attributes the model doesn't keep.
		self.elements = {}

	def problem(self, where, message):
		self.problems.append(f'{self.level.name} {where}: {message}')

	def kind(self, where, name):
		if name not in self.kinds:
			self.problem(where, f'unknown kind {name}')
			return self.kinds['expr']

		return self.kinds[name]

	def exposed(self, element):
		"""[(accessor name, the part value it reads, its description or None)] for an operand element. They come from a
		part operand's accessor elements, or else from the values its part exposes."""
		accessors = element.findall('accessor')
		part = self.op_elements.get(element.get('part'))
		if accessors or part is None:
			return [(a.get('name'), a.get('operand', a.get('name')), a.find('description')) for a in accessors]

		return [(name, name, None) for name in words(part.get('exposes'))]

	def shape(self, element):
		where = f"shape {element.get('name')}"
		operands = [
			ShapeOperand(e.get('name'), self.kind(where, e.get('kind', 'expr'))) for e in element.findall('operand')
		]
		cpp, py = element.find('cpp'), element.find('py')
		cpp_base = cpp.get('base') if cpp is not None else None
		py_facts = py.attrib if py is not None else {}
		py_shape = PyShape(py_facts.get('base'), py_facts.get('trait'), tuple(words(py_facts.get('decodes'))))
		if cpp_base is None:
			self.problem(where, 'no C++ base class')

		if py_shape.base is None:
			self.problem(where, 'no Python base class')

		return Shape(element.get('name'), operands, cpp_base, py_shape)

	def shape_element(self, op, tag=None):
		"""The op's shape's element, or its child with `tag`, or None."""
		if op.shape is None:
			return None

		element = self.shape_elements[op.shape.name]
		return element if tag is None else element.find(tag)

	def operand_elements(self, element):
		"""[(operand element, the description it falls back on)] for the shape's operands, then the op's own. The op's
		refinement of a shape operand replaces it, and falls back on the shape operand's description."""
		own = element.findall('operand')
		shape = self.shape_elements.get(element.get('shape'))
		if shape is None:
			return [(e, None) for e in own]

		refined = {e.get('name'): e for e in own}
		merged = []
		for shaped in shape.findall('operand'):
			replacement = refined.pop(shaped.get('name'), None)
			merged.append((shaped, None) if replacement is None else (replacement, shaped.find('description')))

		return merged + [(e, None) for e in own if e.get('name') in refined]

	def operand(self, where, element, slot, fallback):
		description = element.find('description')
		return Operand(
			element.get('name'),
			self.kind(where, element.get('kind', 'expr')),
			slot=slot,
			sort=sort_of(element),
			is_written=flag(element, 'written'),
			signed=flag(element, 'signed'),
			is_listed=flag(element, 'listed', True),
			description=fallback if description is None else description,
		)

	def op(self, element):
		where = element.get('name')
		doc = element.find('doc')
		op = Op(
			element.get('name'),
			element.get('placement', 'expression'),
			flag(element, 'sized', True),
			flag(element, 'flags'),
			self.shapes.get(element.get('shape')),
			tuple(words(element.get('ssa-form'))),
			[line.strip() for line in doc.text.strip().split('\n')] if doc is not None and doc.text else [],
			element.find('description'),
			element.find('size'),
			element.find('form'),
		)
		self.elements[op] = element
		if element.get('shape') is not None and op.shape is None:
			self.problem(where, f"shape {element.get('shape')} isn't a shape")

		slot = 0
		for child, fallback in self.operand_elements(element):
			operand = self.operand(where, child, slot, fallback)
			self.elements[operand] = child
			op.operands.append(operand)
			slot += 1 if child.get('part') is not None else operand.kind.width

		for child in element.findall('pair'):
			pair = Pair(
				child.get('name'),
				self.kind(where, child.get('kind')),
				op.operand(child.get('of')),
				op.operand(child.get('version')),
			)
			if pair.of is None or pair.version is None:
				self.problem(f'{where}.{pair.name}', 'of and version must name operands')
				continue

			op.pairs.append(pair)
			pair.of.pairs.append(pair)
			pair.version.pairs.append(pair)

		result = element.find('result')
		if result is None and op.produces:
			result = self.shape_element(op, 'result')

		op.result = sort_of(result) if result is not None else None
		return op

	def link(self, ops):
		"""Points each part operand at its part's op, and gives it the accessors that read the part's values."""
		for op in ops.values():
			for operand in op.operands:
				part = self.elements[operand].get('part')
				if part is not None:
					operand.part = ops.get(part)
					if operand.part is None:
						self.problem(op.name, f"refers to {part}, which isn't an op")

		readable = {op: self.readable(op) for op in ops.values()}
		for op in ops.values():
			for operand in op.operands:
				accessors = self.exposed(self.elements[operand])
				if accessors and not operand.is_part:
					self.problem(f'{op.name}.{operand.name}', "accessors on an operand that isn't a part")
					continue

				for name, reads, description in accessors:
					target = readable[operand.part].get(reads)
					if target is None:
						self.problem(
							f'{op.name}.{operand.name}',
							f"accessor {name} reads {reads}, which {operand.part.name} doesn't have",
						)
						continue

					if description is None and isinstance(target, Operand):
						description = target.description

					operand.accessors.append(
						PartAccessor(name, target.kind, owner=operand, target=target, description=description)
					)

		for op in ops.values():
			if op.is_part:
				continue

			for name in words(self.elements[op].get('exposes')):
				self.problem(op.name, f"exposes {name}, but only a part exposes values")

	def readable(self, op):
		"""{name: value} for the values of `op` that an accessor can read. These are its operands, pairs and derived
		values, other than the part operands it reads through."""
		result = {}
		for operand in op.operands:
			if not self.exposed(self.elements[operand]):
				for value in operand.pairs or [operand]:
					result.setdefault(value.name, value)

		return result

	@staticmethod
	def description(op, name):
		"""The description of the operand or accessor of `op` that a builder argument names."""
		for operand in op.operands:
			if operand.name == name and not operand.is_part:
				return operand.description

			for accessor in operand.accessors:
				if accessor.name == name:
					return accessor.description

		return None

	def default_args(self, op):
		"""The args of a builder that takes them in the default order. That's the operands in order, with each part
		replaced by the values stored in it. Each such value is named by the accessor that reads it, or as part.operand
		where none does."""
		args = []
		for operand in op.operands:
			if not operand.is_part:
				args.append(Arg(operand.name, operand, None, operand.description))
				continue

			readers = {accessor.target.name: accessor for accessor in operand.accessors}
			for stored in operand.part.operands:
				reader = readers.get(stored.name)
				if reader is not None:
					args.append(Arg(reader.name, stored, operand, reader.description))
				else:
					description = self.description(operand.part, stored.name)
					args.append(Arg(stored.name, stored, operand, description, qualified=True))

		for arg in args:
			if sum(other.value == arg.value for other in args) > 1:
				if arg.qualified:
					arg.clashes = True
				else:
					self.problem(op.name, f'two builder args write values named {arg.value}')

		return args

	def builder(self, op, element, name, default_args):
		by_name = {arg.name: arg for arg in default_args}
		fixed = {child.get('operand'): child.get('value') for child in element.findall('fixed')}
		for operand in fixed:
			if op.operand(operand) is None or op.operand(operand).is_part:
				self.problem(op.name, f"a builder fixes {operand}, which isn't an operand of it")

		params = words(element.get('params'))
		for param in params:
			if param not in by_name:
				self.problem(op.name, f"builder param {param} isn't one of {sorted(by_name)}")

		if params and sorted(params + list(fixed)) != sorted(by_name):
			self.problem(op.name, f"builder params {params} and fixed {list(fixed)} don't cover {sorted(by_name)}")

		ordered = [param for param in params or by_name if param not in fixed]
		args = [by_name[param] for param in ordered if param in by_name]
		defaults = {child.get('operand') for child in element.findall('default')}
		for default in sorted(defaults - {arg.name for arg in args}):
			self.problem(op.name, f"a builder defaults {default}, which isn't one of its args")

		part_sizes = {child.get('part'): child.get('size') for child in element.findall('part-size')}
		for part in part_sizes:
			if op.operand(part) is None or not op.operand(part).is_part:
				self.problem(op.name, f"a builder sizes part {part}, which isn't a part operand")

		handwritten = flag(element, 'handwritten')
		description, form = element.find('description'), element.find('form')
		if handwritten and (description is not None or form is not None):
			self.problem(op.name, 'documentation on a hand-written builder')

		return Builder(
			name,
			handwritten,
			args,
			fixed,
			defaults,
			element.get('size'),
			part_sizes,
			op.description if description is None else description,
			op.form if form is None else form,
		)

	def builders(self, op, default_args):
		"""Gives the op the builders it lists. An op that lists none and isn't a part gets one taking the default args.
		Each is named by its own name, the op's builder attribute, or the op's name in lower case."""
		element = self.elements[op]
		builders = element.findall('builder')
		if not builders and not op.is_part:
			builders = [ET.Element('builder')]

		default = element.get('builder', op.name.lower())
		op.builders = [self.builder(op, builder, builder.get('name', default), default_args) for builder in builders]
		if element.get('builder') is not None and all(builder.get('name') is not None for builder in builders):
			self.problem(op.name, 'a builder attribute, but every builder names itself')

		generated = [builder for builder in op.builders if not builder.handwritten]
		if op.description is not None and element.findall('builder') and not generated:
			self.problem(op.name, 'a description, but every builder is hand-written')

		for builder in generated:
			if builder.description is not None and builder.form is None:
				self.problem(op.name, 'a documented builder without a form')

	def check_builder_names(self, ops):
		"""Checks that no two builders at the level share a name. Python has no overloads, and the generators give each
		name one signature."""
		owners = {}
		for op in ops.values():
			for builder in op.builders:
				if builder.name in owners:
					self.problem(op.name, f'a builder named {builder.name}, as {owners[builder.name].name} has')

				owners.setdefault(builder.name, op)

	def check_references(self, op, known, element, path):
		"""Checks that each element at `path` names a value in `known`."""
		for child in children(element, path):
			if child.get('operand') not in known:
				self.problem(op.name, f"<{path}> names unknown {child.get('operand')}")

	def operand_list(self, op, element, language, known):
		names = listed(element, 'operands')
		for name in names or []:
			if name not in known:
				self.problem(op.name, f'<{language}> operands names unknown {name}')

		return names

	def cpp(self, op, known):
		own = self.elements[op].find('cpp')
		facts = op.cpp
		facts.renames = {child.get('operand'): child.get('to') for child in children(own, 'rename')}
		for path in ('rename', 'usage', 'parent-usage', 'type'):
			self.check_references(op, known, own, path)

		facts.usages = {e.get('operand'): e.get('name') for e in children(own, 'usage')}
		facts.parent_usages = {e.get('operand'): e.get('name') for e in children(own, 'parent-usage')}
		facts.types = {e.get('operand'): e.get('is') for e in children(own, 'type')}
		if facts.parent_usages and not op.is_part:
			self.problem(op.name, 'parent-usage only applies to placement="part"')

		facts.operands = self.operand_list(op, own, 'cpp', known)

	def py(self, op, known):
		own = self.elements[op].find('py')
		shared = self.shape_element(op, 'py')
		facts = op.py
		facts.renames = {e.get('operand'): e.get('to') for e in children(own, 'rename')}
		self.check_references(op, known, own, 'rename')
		facts.mixin = own.get('mixin') if own is not None else None
		# The op's own params override its shape's.
		for source in (own, shared):
			self.check_references(op, known, source, 'param')
			for child in children(source, 'param'):
				facts.params.setdefault(child.get('operand'), child.get('name'))

		facts.builder = own.get('builder') if own is not None else None
		if facts.builder is not None and len(op.builders) != 1:
			self.problem(op.name, f'a Python builder name for {len(op.builders)} builders')

		facts.no_builder = flag(own, 'no-builder') if own is not None else False
		if facts.no_builder and facts.builder is not None:
			self.problem(op.name, 'a Python builder name, but no Python builder')

		facts.traits = tuple(words(own.get('traits'))) if own is not None else ()
		shape_trait = op.shape.py.trait if op.shape is not None else None
		if shape_trait in facts.traits:
			self.problem(op.name, f'Python trait {shape_trait}, which its shape base class already carries')

		facts.operands = self.operand_list(op, own, 'py', known)

	def rust_renames(self, where, elements):
		"""({value name: Rust name}, {the names of values whose accessors drop their suffix}) from rename elements."""
		renames, unsuffixed = {}, set()
		for child in elements:
			name = child.get('operand')
			if (child.get('to') is None) == flag(child, 'suffix', True):
				self.problem(where, f'the Rust rename of {name} gives neither or both of to and suffix="false"')

			if child.get('to') is not None:
				renames[name] = child.get('to')
			else:
				unsuffixed.add(name)

		return renames, unsuffixed

	def rust(self, op, known):
		own = self.elements[op].find('rust')
		shared = self.shape_element(op, 'rust')
		facts = op.rust
		for path in ('rename', 'type', 'lift'):
			self.check_references(op, known, own, path)

		self.check_references(op, known, shared, 'lift')
		# The op's own marker overrides its shape's.
		facts.marker = own.get('marker') if own is not None else None
		if facts.marker is None and shared is not None:
			facts.marker = shared.get('marker')

		facts.variant = own.get('variant') if own is not None else None
		facts.renames, facts.unsuffixed = self.rust_renames(op.name, children(own, 'rename'))
		# The op's own lifts override its shape's.
		facts.lifts = {e.get('operand'): e.get('width') for e in children(shared, 'lift') + children(own, 'lift')}
		facts.types = {e.get('operand'): e.get('is') for e in children(own, 'type')}
		builder_names = [builder.name for builder in op.builders]
		if own is not None and own.get('lifter') is not None:
			if len(builder_names) != 1:
				self.problem(op.name, f'a Rust lifter name for {len(builder_names)} builders')

			facts.lifters = dict.fromkeys(builder_names, own.get('lifter'))

		for child in children(own, 'lifter'):
			if child.get('builder') not in builder_names:
				self.problem(op.name, f"a Rust lifter for {child.get('builder')}, which isn't one of its builder names")

			facts.lifters[child.get('builder')] = child.get('name')

	def check(self, op, ops, slots):
		element = self.elements[op]
		if op.slot_count > slots:
			self.problem(op.name, f"needs more than the level's {slots} operand slots")

		if op.flags and not flag(self.root, 'flags'):
			self.problem(op.name, "sets flags, but the level's instructions hold none")

		for name in op.ssa_form if op.ssa_form != ('expanded',) else ():
			if name not in ops or not ops[name].ssa_only:
				self.problem(op.name, f"ssa-form names {name}, which isn't an SSA op")

		if element.get('part-of') is not None and not op.is_part:
			self.problem(op.name, 'part-of only applies to placement="part"')

		if op.is_part and not op.parents:
			self.problem(op.name, 'part that no op contains')

		if op.is_part and op.doc:
			self.problem(op.name, "a part's doc is generated from the ops that contain it")

		for operand in op.operands:
			where = f'{op.name}.{operand.name}'
			holds_expressions = operand.kind.holds_expressions and not operand.is_part
			if holds_expressions and operand.sort is None:
				self.problem(where, "doesn't say what sort of value it holds")
			elif operand.sort is not None and not holds_expressions:
				self.problem(where, "a value sort on an operand that isn't an expression")

		if op.produces and op.result is None:
			self.problem(op.name, 'an expression without a result')
		elif not op.produces and element.find('result') is not None:
			self.problem(op.name, f'a {op.placement} with a result')

		for pair in op.pairs:
			where = f'{op.name}.{pair.name}'
			base = pair.kind.ssa_of
			if base is None:
				self.problem(where, f"{pair.kind.name} can't be a pair")
			elif pair.of.kind is not base:
				self.problem(where, f'of={pair.of.name} is {pair.of.kind.name}, not {base.name}')

			if not pair.version.kind.version:
				self.problem(where, f'version={pair.version.name} is {pair.version.kind.name}, not a version')

			# The readers expect each version of a register or variable to follow it, in the order of its pairs.
			if pair.version.slot != pair.of.slot + 1 + pair.version_index:
				self.problem(
					where, f"version={pair.version.name} doesn't follow of={pair.of.name} and its earlier versions"
				)

	def parents(self, ops):
		"""Gives each op the ops that contain it. These are the ops with a part operand naming it, and those its part-of
		names."""
		for op in ops.values():
			for name in {o.part.name for o in op.operands if o.is_part}:
				ops[name].parents.append(op)

		for op in ops.values():
			for name in words(self.elements[op].get('part-of')):
				if name not in ops:
					self.problem(op.name, f"part-of names {name}, which isn't an op")
				elif ops[name] not in op.parents:
					op.parents.append(ops[name])

			op.parents.sort(key=list(ops.values()).index)

	def load(self):
		ops = {}
		for element in op_elements(self.root):
			op = self.op(element)
			if op.name in ops:
				self.problem(op.name, 'defined twice')
				continue

			ops[op.name] = op

		for group in self.root.findall('group'):
			if flag(group, 'ssa-only'):
				for element in group.findall('op'):
					ops[element.get('name')].ssa_only = True

		self.link(ops)
		for op in ops.values():
			default_args = self.default_args(op)
			self.builders(op, default_args)
			known = set(op.values) | {arg.name for arg in default_args}
			self.cpp(op, known)
			self.py(op, known)
			self.rust(op, known)

		self.check_builder_names(ops)
		self.parents(ops)
		slots = int(self.root.get('slots'))
		for op in ops.values():
			self.check(op, ops, slots)

		markers = {}
		for e in self.root.findall('rust-marker'):
			renames, unsuffixed = self.rust_renames(f"rust-marker {e.get('name')}", e.findall('rename'))
			markers[e.get('name')] = RustMarker(
				renames,
				frozenset(unsuffixed),
				flag(e, 'handwritten'),
				tuple(a.get('name') for a in e.findall('accessor')),
				e.get('as'),
			)

		return Schema(
			self.level,
			self.kinds,
			names(),
			self.shapes,
			ops,
			groups(self.root, ops),
			slots,
			flag(self.root, 'flags'),
			markers,
		)


@functools.cache
def load(level):
	"""The level's Schema, by name."""
	problems = []
	check_kinds(problems)
	if problems:
		raise SchemaError('\n'.join(problems))

	schema = Loader(levels.LEVELS[level], problems).load()
	if problems:
		raise SchemaError('\n'.join(problems))

	return schema
