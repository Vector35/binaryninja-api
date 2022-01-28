#!/usr/bin/env python
# binja type library info utility

import os, sys, re, random
import binaryninja
from binaryninja.enums import *
from binaryninja import typelibrary

# The class Type as defined in api/python/types.py is nearly a discriminated union.
# By examining the .type_class member you can decide which properties make sense to access.
#
# For example, if .type_class == FunctionTypeClass then you can access:
#   .return_value    binaryninja.types.Type
#   .parameters      [binaryninja.types.FunctionParameter]
#
# For example, if .type_class == StructureTypeClass then you can access:
#   .structure       binaryninja.types.Structure
#
# etc...


def obj2str(t, depth=0):
	indent = '  ' * depth
	result = ''

	if type(t) == binaryninja.types.StructureType:
		result = '%sStructure\n' % (indent)
		for m in t.members:
			result += obj2str(m, depth + 1)
	elif type(t) == binaryninja.types.StructureMember:
		result = '%sStructureMember "%s"\n' % (indent, t._name)
		result += type2str(t.type, depth + 1)
	elif type(t) == binaryninja.types.FunctionParameter:
		result = '%sFunctionParameter "%s"\n' % (indent, t.name)
		result += type2str(t.type, depth + 1)
	elif type(t) == binaryninja.types.NamedTypeReferenceType:
		result = '%sNamedTypeReference %s\n' % (indent, repr(t))
	elif type(t) == binaryninja.types.EnumerationType:
		result = '%sEnumeration\n' % indent
		for m in t.members:
			result += obj2str(m, depth + 1)
	elif type(t) == binaryninja.types.EnumerationMember:
		result = '%sEnumerationMember %s==%d\n' % (indent, t.name, t.value)
	elif t == None:
		result = 'unimplemented'

	return result


def type2str(t: binaryninja.types.Type, depth=0):
	indent = '  ' * depth
	result = 'unimplemented'

	assert isinstance(t, binaryninja.types.Type)
	tc = t.type_class

	if tc == TypeClass.VoidTypeClass:
		result = '%sType class=Void\n' % indent
	elif tc == TypeClass.BoolTypeClass:
		result = '%sType class=Bool\n' % indent
	elif tc == TypeClass.IntegerTypeClass:
		result = '%sType class=Integer width=%d\n' % (indent, t.width)
	elif tc == TypeClass.FloatTypeClass:
		result = '%sType class=Float\n' % indent
	elif tc == TypeClass.StructureTypeClass:
		result = '%sType class=Structure\n' % indent
		result += obj2str(t.structure, depth + 1)
	elif tc == TypeClass.EnumerationTypeClass:
		result = '%sType class=Enumeration\n' % indent
		result += obj2str(t.enumeration, depth + 1)
	elif tc == TypeClass.PointerTypeClass:
		result = '%sType class=Pointer\n' % indent
		result += type2str(t.target, depth + 1)
	elif tc == TypeClass.ArrayTypeClass:
		result = '%sType class=Array\n' % indent
	elif tc == TypeClass.FunctionTypeClass:
		result = '%sType class=Function\n' % indent
		result += type2str(t.return_value, depth + 1)
		for param in t.parameters:
			result += obj2str(param, depth + 1)
	elif tc == TypeClass.VarArgsTypeClass:
		result = '%sType class=VarArgs\n' % indent
	elif tc == TypeClass.ValueTypeClass:
		result = '%sType class=Value\n' % indent
	elif tc == TypeClass.NamedTypeReferenceClass:
		result = '%sType class=NamedTypeReference\n' % indent
		result += obj2str(t.named_type_reference, depth + 1)
	elif tc == TypeClass.WideCharTypeClass:
		result = '%sType class=WideChar\n' % indent

	return result


if __name__ == '__main__':
	binaryninja._init_plugins()

	if len(sys.argv) <= 1:
		raise Exception('supply typelib file')

	fpath = sys.argv[-1]
	print('        reading: %s' % fpath)

	tl = typelibrary.TypeLibrary.load_from_file(fpath)
	print('           name: %s' % tl.name)
	print('           arch: %s' % tl.arch)
	print('           guid: %s' % tl.guid)
	print('dependency_name: %s' % tl.dependency_name)
	print('alternate_names: %s' % tl.alternate_names)
	print(' platform_names: %s' % tl.platform_names)
	print('')

	print('  named_objects: %d' % len(tl.named_objects))
	for (key, val) in tl.named_objects.items():
		print('\t"%s" %s' % (str(key), str(val)))

	print('')

	print('    named_types: %d' % len(tl.named_types))
	for (key, val) in tl.named_types.items():
		line = 'typelib.named_types["%s"] =' % (str(key))
		print(line)
		print('-' * len(line))
		print(type2str(val))
