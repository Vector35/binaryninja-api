"""Each IL level's names and the files its code is patched into."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Level:
	name: str
	# The level's name in CamelCase, which its class and type names start with.
	camel_name: str
	# The Rust API's module for the level, under rust/src.
	rust_module: str

	@property
	def prefix(self):
		"""The enum prefix, such as LLIL for LLIL_ADD."""
		return self.name.upper()

	@property
	def stem(self):
		"""The start of every C++ class name, such as LowLevelIL for LowLevelILInstruction."""
		return f'{self.camel_name}IL'

	@property
	def header(self):
		return f'{self.stem.lower()}instruction.h'

	@property
	def source(self):
		return f'{self.stem.lower()}instruction.cpp'

	@property
	def python_path(self):
		return f'python/{self.stem.lower()}.py'

	def rust_path(self, name):
		"""The path of the file `name` in the level's Rust module, such as operation."""
		return f'rust/src/{self.rust_module}/{name}.rs'

	def region(self, name):
		return f'{self.name}-{name}'

	def op(self, name):
		return f'{self.prefix}_{name}'


LEVELS = {
	'llil': Level('llil', 'LowLevel', 'low_level_il'),
}
