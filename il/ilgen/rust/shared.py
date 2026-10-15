"""Rust that both LLIL's operation markers and MLIL's and HLIL's operation structs read values with."""


def cached_value_set(stem, index):
	"""Reads the possible value set cached at `index` in a function of the level whose types start with `stem`. The
	result is a template for str.format, so its literal braces are doubled."""
	return (
		f'PossibleValueSet::from_owned_core_raw(unsafe {{{{ BNGetCached{stem}ILPossibleValueSet(self.function.handle, '
		f'{index}) }}}})'
	)
