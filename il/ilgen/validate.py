"""Checks the schema. It validates the files against il.xsd with xmllint and loads every level, which checks each one.
Then it checks what no single level shows. Each kind's level elements must name levels that use the kind, and
common.xml must hold only what more than one level uses. Each level's generators must read the attributes its kinds
set, and some kind must name every special case a generator defines."""

import os
import shutil
import subprocess
import sys

from . import levels, loader, model
from .cpp import kinds as cpp_kinds
from .python import kinds as py_kinds
from .rust import decode, operations

# Each language's generators, by the levels they serve. Each entry pairs the kind attributes the generator reads
# (None for all of them) with its special cases as {attribute: {special case name: implementation}}. `suffix` is
# exempt because only rust/naming.py reads it, for LLIL's accessor names.
GENERATORS = {
	'cpp': {tuple(levels.LEVELS): (None, {'decoder': cpp_kinds.DECODERS, 'encoder': cpp_kinds.ENCODERS})},
	'py': {tuple(levels.LEVELS): (None, {'decoder': py_kinds.DECODERS, 'encoder': py_kinds.ENCODERS})},
	'rust': {
		tuple(name for name, level in levels.LEVELS.items() if not level.rust_structs): (
			decode.ATTRIBUTES,
			{'decoder': decode.DECODERS},
		),
		tuple(name for name, level in levels.LEVELS.items() if level.rust_structs): (
			operations.ATTRIBUTES,
			{'decoder': operations.DECODERS, 'lifter': operations.LIFTERS},
		),
	},
}


def validate_files(problems):
	xmllint = shutil.which('xmllint')
	if xmllint is None:
		print('xmllint not found, so the schema files were not validated against il.xsd', file=sys.stderr)
		return

	files = ['kinds.xml', 'names.xml', 'common.xml'] + [f'{level}.xml' for level in levels.LEVELS]
	result = subprocess.run(
		[xmllint, '--noout', '--schema', os.path.join(model.DATA, 'il.xsd')]
		+ [os.path.join(model.DATA, name) for name in files],
		capture_output=True,
		text=True,
	)
	found = [line for line in result.stderr.splitlines() if not line.endswith(('validates', 'fails to validate'))]
	if result.returncode != 0 and not found:
		found.append(
			f'xmllint failed with exit code {result.returncode} without reporting a problem: '
			+ (result.stderr.strip() or 'no output')
		)

	problems += found


def used_kinds(schema):
	"""The names of the kinds the level's ops use, and of the kinds the lists among them hold."""
	used = set()
	for op in schema.ops.values():
		used |= {value.kind for value in op.values.values()} | set(op.py.accessors.values())

	return {kind.name for kind in used} | {kind.item.name for kind in used if kind.is_list}


def check_kind_levels(schemas, problems):
	"""Checks that each level a kind's level elements name has an op that uses the kind or a list of it."""
	used = {level: used_kinds(schema) for level, schema in schemas.items()}
	for name, declaration in loader.kind_declarations().items():
		for language, element in declaration.elements.items():
			for named, _ in element.levels:
				for level in sorted(named & used.keys()):
					if name not in used[level]:
						problems.append(f'kind {name}: a {language} level element names {level}, where no op uses it')


def check_common(schemas, problems):
	"""Checks that every shape and op in common.xml is used by at least two levels."""
	for tag, name in loader.common_elements():
		found = 'shapes' if tag == 'shape' else 'ops'
		having = [level for level, schema in schemas.items() if name in getattr(schema, found)]
		if len(having) < 2:
			problems.append(f'common.xml {tag} {name}: only {having or "no level"} has it')


def check_generators(problems):
	"""Checks that each level's generator reads every attribute its kinds set, and that some kind names every special
	case a generator defines."""
	for language, generators in GENERATORS.items():
		for served, (read, cases) in generators.items():
			named = {attribute: set() for attribute in cases}
			for name, declaration in loader.kind_declarations().items():
				for level in served:
					attributes = declaration.elements[language].at(level)
					for attribute in sorted(set(attributes) - set(read or attributes) - {'suffix'}):
						problems.append(f"kind {name}: the {level} {language} generator doesn't read {attribute}")

					for attribute in cases:
						if attribute in attributes:
							named[attribute].add(attributes[attribute])

			for attribute, defined in cases.items():
				for case in sorted(set(defined) - named[attribute]):
					problems.append(f'{language} {attribute} {case}: no kind names it')


def check():
	"""[problem] for every way the schema is invalid or inconsistent."""
	problems = []
	validate_files(problems)
	schemas = {}
	for level in levels.LEVELS:
		try:
			schemas[level] = loader.load(level)
		except model.SchemaError as error:
			problems += str(error).split('\n')

	if len(schemas) == len(levels.LEVELS):
		check_kind_levels(schemas, problems)
		check_common(schemas, problems)
		check_generators(problems)

	# A problem with a kind shows up at every level.
	return list(dict.fromkeys(problems))
