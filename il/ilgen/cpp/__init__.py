"""The C++ API's code for an IL level, which is its accessors, operand tables, builders, VisitExprs, CopyTo and the
expression ordering of an ordered level."""

from . import accessors, builders, compare, copy, operands, visit


def regions(schema):
	return (
		accessors.regions(schema)
		+ operands.regions(schema)
		+ builders.regions(schema)
		+ visit.regions(schema)
		+ copy.regions(schema)
		+ compare.regions(schema)
	)
