"""Generates the IL code of the C++, Python and Rust APIs from the schema beside this package.

A driver validates the schema with `validate.check()`, gathers the API's regions with `api_regions()`, and patches
them in place with `patch.apply()`, formatting each with the style files named here. `builder_declarations()` gives
the region of builder declarations for another function class, such as core's."""

import os

from . import cpp, levels, loader, model, operation_enum, patch, python, rust, validate
from .cpp import builders
from .cpp.kinds import Containers
from .patch import Region

# How the API's generated code is laid out, for each formatter.
CLANG_FORMAT_STYLE = os.path.join(model.DATA, 'generated.clang-format')
RUFF_CONFIG = os.path.join(model.DATA, 'generated.ruff.toml')
RUSTFMT_CONFIG = os.path.join(model.DATA, 'generated.rustfmt.toml')
# The files that pin the toolchain the Rust API is built with and its edition.
RUST_API = os.path.join(os.path.dirname(model.DATA), 'rust')
RUST_PINS = (os.path.join(RUST_API, 'CMakeLists.txt'), os.path.join(RUST_API, 'Cargo.toml'))

__all__ = [
	'CLANG_FORMAT_STYLE',
	'RUFF_CONFIG',
	'RUSTFMT_CONFIG',
	'RUST_PINS',
	'api_regions',
	'builder_declarations',
	'model',
	'patch',
	'rustfmt',
	'validate',
]


def rustfmt(rustup):
	"""Runs rustfmt through rustup, from the Rust API's toolchain and for its edition."""
	version = patch.pinned(RUST_PINS[0], r'set\(CARGO_API_VERSION (\S+)\)')
	edition = patch.pinned(RUST_PINS[1], r'^edition = "(\w+)"')
	return patch.Rustfmt((rustup, 'run', version, 'rustfmt'), edition, RUSTFMT_CONFIG)


def api_regions():
	"""Every region of the API's generated code, with paths relative to api."""
	found = []
	for level in levels.LEVELS:
		schema = loader.load(level)
		found += operation_enum.regions(schema) + cpp.regions(schema) + python.regions(schema) + rust.regions(schema)

	return found


def builder_declarations(level, path, containers):
	"""The region of the level's builder declarations in the header at `path`. `containers` is how the header spells
	std::vector and std::map, as (vector, map)."""
	schema = loader.load(level)
	return Region(path, schema.level.region('builders'), builders.declarations(schema, Containers(*containers)))
