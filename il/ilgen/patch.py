"""Patches generated regions into files in place.

A region is the text between a pair of marker comments:

	// BEGIN GENERATED name: from api/il, do not edit
	...
	// END GENERATED name

Generators produce each region's text without indentation. The region is indented to match its BEGIN marker,
and everything outside the markers is left exactly as it is. Markers are placed by hand, so a host file decides
where each region goes. A formatted region is laid out by its language's formatter, which formats the file with
the region in place, and only the region's lines are taken from the result."""

import os
import re
import subprocess
from dataclasses import dataclass

COMMENTS = {'.h': '//', '.cpp': '//', '.rs': '//', '.py': '#'}
BEGIN = 'BEGIN GENERATED'
END = 'END GENERATED'


@dataclass(frozen=True)
class Region:
	path: str
	name: str
	text: str
	# Whether its language's formatter lays out the region after it's patched in.
	formatted: bool = True


def pinned(path, pattern):
	"""The first group of the first match of `pattern` in the file at `path`, such as a tool version it pins."""
	with open(path, encoding='utf-8') as f:
		match = re.search(pattern, f.read(), re.M)

	if match is None:
		raise PatchError(f'{path}: nothing matches {pattern}')

	return match.group(1)


def run(path, args, text):
	try:
		result = subprocess.run(args, input=text, capture_output=True, encoding='utf-8')
	except OSError as error:
		raise PatchError(f'{path}: can\'t run {args[0]}: {error.strerror}') from error

	if result.returncode != 0:
		raise PatchError(f'{path}: {os.path.basename(args[0])} failed: {result.stderr.strip()}')

	return result.stdout


@dataclass(frozen=True)
class ClangFormat:
	"""A clang-format binary and the style file it formats C++ regions with."""

	binary: str
	style: str

	def format(self, path, text, ranges):
		"""Returns `text` with clang-format applied to the 1-based line ranges [(first, last)]. `path` tells
		clang-format which file `text` came from."""
		args = [self.binary, f'--style=file:{self.style}', f'--assume-filename={path}']
		return run(path, args + [f'--lines={first}:{last}' for first, last in ranges], text)


@dataclass(frozen=True)
class Rustfmt:
	"""A rustfmt command and the config file it formats Rust with. It formats the whole file, because rustfmt can't
	format line ranges."""

	command: tuple
	edition: str
	config: str

	def format(self, path, text, ranges):
		# Reading stdin keeps rustfmt from following mod declarations into other files. The explicit config keeps it
		# from searching the file's parent directories and the user's config directory for a rustfmt.toml.
		args = [f'--edition={self.edition}', f'--config-path={self.config}', '--emit=stdout']
		return run(path, list(self.command) + args, text)


@dataclass(frozen=True)
class Ruff:
	"""A ruff command and the config file it formats Python with. It formats the whole file, since its range
	formatting reaches into the statements around a range."""

	command: tuple
	config: str

	def format(self, path, text, ranges):
		return run(
			path, list(self.command) + ['format', f'--config={self.config}', f'--stdin-filename={path}', '-'], text
		)


class PatchError(Exception):
	pass


def comment_for(path):
	comment = COMMENTS.get(os.path.splitext(path)[1])
	if comment is None:
		raise PatchError(f'{path}: no comment syntax for this kind of file')

	return comment


def find_regions(path, text):
	"""{name: (index of the BEGIN line, index of the END line, indentation)} for the file's lines."""
	comment = re.escape(comment_for(path))
	begin = re.compile(rf'^(\s*){comment} {BEGIN} ([\w-]+)\b')
	end = re.compile(rf'^\s*{comment} {END} ([\w-]+)\s*$')
	regions = {}
	open_region = None
	for index, line in enumerate(text.split('\n')):
		start = begin.match(line)
		if start:
			if open_region is not None:
				raise PatchError(f'{path}:{index + 1}: region {start.group(2)} starts inside region {open_region[0]}')

			if start.group(2) in regions:
				raise PatchError(f'{path}:{index + 1}: region {start.group(2)} appears twice')

			open_region = (start.group(2), index, start.group(1))
			continue

		finish = end.match(line)
		if finish:
			if open_region is None or finish.group(1) != open_region[0]:
				raise PatchError(f'{path}:{index + 1}: END of {finish.group(1)} without its BEGIN')

			regions[open_region[0]] = (open_region[1], index, open_region[2])
			open_region = None

	if open_region is not None:
		raise PatchError(f'{path}: region {open_region[0]} has no END')

	return regions


def indent(text, prefix):
	return [prefix + line if line else line for line in text.rstrip('\n').split('\n')] if text.strip() else []


def patch(path, text, regions):
	"""The file's text with each region's contents replaced. `regions` maps each region's name to its generated text."""
	found = find_regions(path, text)
	missing = sorted(set(regions) - set(found))
	if missing:
		raise PatchError(f'{path}: no markers for regions {missing}')

	unknown = sorted(set(found) - set(regions))
	if unknown:
		raise PatchError(f'{path}: no generator produces regions {unknown}')

	lines = text.split('\n')
	for name, (begin, end, prefix) in sorted(found.items(), key=lambda item: item[1][0], reverse=True):
		lines[begin + 1 : end] = indent(regions[name], prefix)

	return '\n'.join(lines)


def splice(path, target, source, names):
	"""Returns `target` with the named regions' contents taken from `source`, which is `target` after formatting."""
	target_regions, source_regions = find_regions(path, target), find_regions(path, source)
	target_lines, source_lines = target.split('\n'), source.split('\n')
	for name in sorted(names, key=lambda n: target_regions[n][0], reverse=True):
		begin, end, _ = target_regions[name]
		source_begin, source_end, _ = source_regions[name]
		target_lines[begin + 1 : end] = source_lines[source_begin + 1 : source_end]

	return '\n'.join(target_lines)


def formatted_ranges(path, text, names):
	"""The 1-based line ranges of the named regions' contents, leaving out empty regions."""
	found = find_regions(path, text)
	return [(begin + 2, end) for name, (begin, end, _) in found.items() if name in names and end > begin + 1]


def apply(root, regions, write, formatters):
	"""Patches every file the regions belong to under `root`, formatting the formatted regions with the formatter in
	`formatters` for their file's extension. Returns the paths that changed, and writes them when `write` is true."""
	by_file = {}
	formatted = {}
	for region in regions:
		if region.name in by_file.setdefault(region.path, {}):
			raise PatchError(f'{region.path}: two generators produce region {region.name}')

		by_file[region.path][region.name] = region.text
		if region.formatted:
			formatted.setdefault(region.path, set()).add(region.name)

	changed = []
	for path, file_regions in sorted(by_file.items()):
		full = os.path.join(root, path)
		if not os.path.exists(full):
			raise PatchError(f'{path}: no such file')

		with open(full, encoding='utf-8', newline='') as f:
			original = f.read()

		# A checkout can end lines with CRLF, as Git does on Windows by default. Patching works on LF, and the file
		# keeps its own line endings.
		crlf = '\r\n' in original
		text = original.replace('\r\n', '\n')
		patched = patch(path, text, file_regions)
		ranges = formatted_ranges(path, patched, formatted.get(path, ()))
		if ranges:
			formatter = formatters.get(os.path.splitext(path)[1])
			if formatter is None:
				raise PatchError(f'{path}: no formatter for this kind of file')

			patched = splice(path, patched, formatter.format(path, patched, ranges), formatted[path])

		if crlf:
			patched = patched.replace('\n', '\r\n')

		if patched != original:
			changed.append(path)
			if write:
				with open(full, 'w', encoding='utf-8', newline='') as f:
					f.write(patched)

	return changed
