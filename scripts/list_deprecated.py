#!/usr/bin/env python3
"""
Script to list all Python APIs marked as deprecated.

Walks the Python API source looking for functions, methods, and classes
decorated with @deprecation.deprecated(...) and prints a table showing the
qualified name, the version it was deprecated in, and any replacement
details.

Usage:
  python list_deprecated.py [paths...]
  python list_deprecated.py --markdown [paths...]
  python list_deprecated.py --sort version [paths...]

If no paths are specified, defaults to ../python relative to this script.
"""

import argparse
import ast
import re
import sys
from pathlib import Path

SKIP_FILES = {"deprecation.py", "_binaryninjacore.py"}
SKIP_DIRECTORIES = {"__pycache__", "examples"}


def literal_or_source(node):
	"""Return the value of a constant node, or its source text as a fallback."""
	if isinstance(node, ast.Constant):
		return node.value
	return ast.unparse(node)


def find_deprecations(filepath):
	"""Yield (qualified_name, kind, lineno, deprecated_in, removed_in, details) for each deprecated API."""
	tree = ast.parse(filepath.read_text(encoding="utf-8"), filename=str(filepath))

	def walk(node, scope):
		for child in ast.iter_child_nodes(node):
			if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
				qualname = scope + [child.name]
				for dec in child.decorator_list:
					if not isinstance(dec, ast.Call):
						continue
					func = dec.func
					name = ast.unparse(func)
					if name not in ("deprecation.deprecated", "deprecated"):
						continue
					kwargs = {kw.arg: literal_or_source(kw.value) for kw in dec.keywords if kw.arg}
					kind = "class" if isinstance(child, ast.ClassDef) else "method" if len(scope) else "function"
					yield (
					    ".".join(qualname), kind, child.lineno, str(kwargs.get("deprecated_in", "")),
					    str(kwargs.get("removed_in", "")), str(kwargs.get("details", ""))
					)
				yield from walk(child, qualname)

	yield from walk(tree, [])


def clean_details(details):
	"""Strip Sphinx roles like :py:func:`foo` down to just foo."""
	return re.sub(r":py:\w+:`([^`]*)`", r"\1", details).strip()


def version_key(version):
	"""Sort key for version strings like 4.0.4907; non-numeric parts sort last."""
	parts = []
	for p in version.split("."):
		parts.append(int(p) if p.isdigit() else 0)
	return parts


def main():
	parser = argparse.ArgumentParser(description="List deprecated Python APIs")
	parser.add_argument("paths", nargs="*", help="Files or directories to scan (default: ../python)")
	parser.add_argument("--markdown", action="store_true", help="Output a markdown table")
	parser.add_argument("--sort", choices=["name", "version"], default="name", help="Sort order (default: name)")
	parser.add_argument(
		"--include-examples",
		action="store_true",
		help="include example directories when scanning recursively",
	)
	args = parser.parse_args()

	if args.paths:
		paths = [Path(p) for p in args.paths]
	else:
		paths = [Path(__file__).resolve().parent.parent / "python"]

	files = []
	for path in paths:
		if path.is_dir():
			for filepath in sorted(path.rglob("*.py")):
				if args.include_examples or not SKIP_DIRECTORIES.intersection(filepath.relative_to(path).parts):
					files.append(filepath)
		else:
			files.append(path)

	rows = []
	parse_errors = []
	for filepath in files:
		if filepath.name in SKIP_FILES:
			continue
		try:
			deprecations = find_deprecations(filepath)
			for qualname, kind, lineno, deprecated_in, removed_in, details in deprecations:
				rows.append((qualname, kind, deprecated_in, removed_in, clean_details(details), f"{filepath.name}:{lineno}"))
		except (SyntaxError, UnicodeDecodeError) as error:
			parse_errors.append((filepath, error))

	if parse_errors:
		for filepath, error in parse_errors:
			print(f"error: failed to parse {filepath}: {error}", file=sys.stderr)
		print("deprecated API report is incomplete", file=sys.stderr)
		return 1

	if args.sort == "version":
		rows.sort(key=lambda r: (version_key(r[2]), r[0]))
	else:
		rows.sort(key=lambda r: r[0])

	if not rows:
		print("No deprecated APIs found")
		return 0

	headers = ("API", "Kind", "Deprecated In", "Removed In", "Details", "Location")
	if args.markdown:
		print("| " + " | ".join(headers) + " |")
		print("|" + "|".join("---" for _ in headers) + "|")
		for row in rows:
			print("| " + " | ".join(row) + " |")
	else:
		widths = [max(len(headers[i]), max(len(row[i]) for row in rows)) for i in range(len(headers))]
		print("  ".join(h.ljust(widths[i]) for i, h in enumerate(headers)))
		print("  ".join("-" * w for w in widths))
		for row in rows:
			print("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)))

	print(f"\n{len(rows)} deprecated API(s) found", file=sys.stderr)
	return 0


if __name__ == "__main__":
	sys.exit(main())
