#!/usr/bin/env python
# demonstrate creating a type library

import binaryninja
from binaryninja.enums import NamedTypeReferenceClass
from binaryninja.types import Type, NamedTypeReferenceType, StructureBuilder, EnumerationBuilder

arch = binaryninja.Architecture['x86_64']
typelib = binaryninja.typelibrary.TypeLibrary.new(arch, 'libtest.so.1')
typelib.add_platform(binaryninja.Platform['mac-x86_64'])
typelib.add_alternate_name('libtest.so')

#------------------------------------------------------------------------------
# PART1: Named Types
#------------------------------------------------------------------------------

# example: VoidTypeClass
typelib.add_named_type('MyVoidType', Type.void())

# example: BoolTypeClass
typelib.add_named_type('MyBoolType', Type.bool())

# example: IntegerTypeClass
typelib.add_named_type('MyCharType', Type.char())
typelib.add_named_type('MyIntType', Type.int(4, True))
typelib.add_named_type('MyUnsignedIntType', Type.int(4, False))

# example: FloatTypeClass
typelib.add_named_type('MyFloatType', Type.float(4))

# example: PointerTypeClass
# char *
typelib.add_named_type('MyPointerType', Type.pointer(arch, Type.char()))

# example of typedef to primitive type
# typedef int MyTypedefType;
typelib.add_named_type('MyTypedefType', Type.int(4))


# example of typedef to typedef
# typedef MyTypedefType MySuperSpecialType;
def create_named_type_reference(type_name: str, to_what: NamedTypeReferenceClass):
	return NamedTypeReferenceType.create(named_type_class=to_what, guid=None, name=type_name)


typelib.add_named_type(
  'MySuperSpecialType', create_named_type_reference('MySpecialType', NamedTypeReferenceClass.TypedefNamedTypeClass)
)

# We can demonstrate three type classes in the following example:
#   StructureTypeClass, PointerTypeClass, NamedTypeReferenceClass

# add a named type "Rectangle":
#
# struct
# {
#     int width;
#     int height;
#     struct Point *center; // pointer to possibly undeclared struct
# }

with StructureBuilder.builder(typelib, 'Rectangle') as struct_type:
	struct_type.append(Type.int(4), 'width')
	struct_type.append(Type.int(4), 'height')
	struct_type.append(
	  Type.pointer(arch, create_named_type_reference('Point', NamedTypeReferenceClass.StructNamedTypeClass)), 'center'
	)

# add a named type "Rectangle2":
# this type cannot be applied to variables until struct Point is declared
#
# struct
# {
#     int width;
#     int height;
#     struct Point center; // actual undeclared struct
# }

with StructureBuilder.builder(typelib, 'Rectangle2') as struct_type:
	struct_type.append(Type.int(4), 'width')
	struct_type.append(Type.int(4), 'height')
	struct_type.append(create_named_type_reference('Point', NamedTypeReferenceClass.StructNamedTypeClass), 'center')

# example: EnumerationTypeClass
enum_type = EnumerationBuilder.create([], None, arch=arch)
enum_type.append('RED', 0)
enum_type.append('ORANGE', 1)
enum_type.append('YELLOW', 2)
enum_type.append('GREEN', 3)
enum_type.append('BLUE', 4)
enum_type.append('INDIGO', 5)
enum_type.append('VIOLET', 6)
typelib.add_named_type('MyEnumerationType', enum_type)

# example: ArrayTypeClass
#
# unsigned char[256]
typelib.add_named_type('MyArrayType', Type.array(Type.int(1), 256))

# example: FunctionTypeClass
#
# int ()(int, int, int)
ret = Type.int(4)
params = [Type.int(4), Type.int(4), Type.int(4)]
ftype = Type.function(ret, params)
typelib.add_named_type('MyFunctionType', ftype)

#------------------------------------------------------------------------------
# PART2: Named Objects
#------------------------------------------------------------------------------

# example: any external/imported functions named _MySuperComputation
#  are typed int _MySuperComputation(int, int)

ret = Type.int(4)
params = [Type.int(4), Type.int(4)]
ftype = Type.function(ret, params)
typelib.add_named_object('_MySuperComputation', ftype)

# finalize
typelib.finalize()
print('writing test.bntl')
typelib.write_to_file('test.bntl')
