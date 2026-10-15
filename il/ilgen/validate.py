"""Checks the schema. It validates the files against il.xsd with xmllint and loads every level, which checks each one.
Then it checks that every special case a generator defines is one some kind names."""

import os
import shutil
import subprocess
import sys

from . import levels, loader, model
from .cpp import kinds as cpp_kinds
from .python import kinds as py_kinds
from .rust import decode

# Each language's special cases, as {attribute: {special case name: implementation}}.
SPECIAL_CASES = {
	'cpp': {'decoder': cpp_kinds.DECODERS, 'encoder': cpp_kinds.ENCODERS},
	'py': {'decoder': py_kinds.DECODERS},
	'rust': {'decoder': decode.DECODERS},
}


def validate_files(problems):
	xmllint = shutil.which('xmllint')
	if xmllint is None:
		print('xmllint not found, so the schema files were not validated against il.xsd', file=sys.stderr)
		return

	files = ['kinds.xml', 'names.xml'] + [f'{level}.xml' for level in levels.LEVELS]
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


def check_special_cases(problems):
	"""Every special case a generator defines is one some kind names."""
	for language, cases in SPECIAL_CASES.items():
		for attribute, defined in cases.items():
			named = set()
			for declaration in loader.kind_declarations().values():
				value = declaration.attributes[language].get(attribute)
				if value is not None:
					named.add(value)

			for case in sorted(set(defined) - named):
				problems.append(f'{language} {attribute} {case}: no kind names it')


def check():
	"""[problem] for every way the schema is invalid or inconsistent."""
	problems = []
	validate_files(problems)
	for level in levels.LEVELS:
		try:
			loader.load(level)
		except model.SchemaError as error:
			problems += str(error).split('\n')

	check_special_cases(problems)
	return problems
