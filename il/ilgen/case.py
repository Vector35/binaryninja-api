"""Spells schema names, which are words separated by underscores, in the bindings' cases."""


def camel(name):
	"""CamelCase with SSA in capitals, such as call_ssa to CallSSA."""
	return ''.join('SSA' if word.upper() == 'SSA' else word.capitalize() for word in name.split('_'))


def capitalized(name):
	"""Each word capitalized, acronyms included, such as call_ssa to CallSsa."""
	return ''.join(word.capitalize() for word in name.split('_'))


def lower_camel(name):
	"""dest_memory to destMemory."""
	first, *rest = name.split('_')
	return first + capitalized('_'.join(rest))
