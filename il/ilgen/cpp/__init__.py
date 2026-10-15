"""The C++ API's code for an IL level, which is its accessors, operand tables, builders, VisitExprs and CopyTo."""

from . import accessors, builders, copy, operands, visit


def regions(schema):
	return (
		accessors.regions(schema)
		+ operands.regions(schema)
		+ builders.regions(schema)
		+ visit.regions(schema)
		+ copy.regions(schema)
	)
