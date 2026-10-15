"""The Python API's code for an IL level. That's the ILOperations map, the op classes with ILInstruction and
copy_expr_to's layouts, and the function class's builder methods."""

from ..patch import Region
from .builders import Builders
from .classes import Classes


def regions(schema):
	classes = Classes(schema)
	level = schema.level
	return [
		Region(level.python_path, level.region('operations'), classes.il_operations()),
		Region(level.python_path, level.region('classes'), classes.classes()),
		Region(level.python_path, level.region('builders'), Builders(schema).methods()),
	]
