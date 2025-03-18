## Type Libraries

Type Libraries are collections of type information (structs, enums, function types, etc.) stored in a file with the extension `.bntl`.

Relative to the binaryninja executable, the default type library location is `../Resources/typelib` on macOS and `./typelib` on Linux and Windows. Individual .bntl files are organized in subdirectories named for the supported architecture. Users may include their own type libraries in the `typelib` folder in their [user folder](../guide/index.md#user-folder).

The information in a type library is contained in two key-value stores:

1. named types: key is the type name, value is the type
1. named objects: key is external symbol name, value is the type

## How Binary Ninja Loads Type Libraries

When a binary is opened, its platform is determined, all .bntl's are processed, and those matching the platform of the loaded binary are registered. A debug log will show:

```
Registered library 'libc.so.6' with platform 'linux-x86_64'
```

Then, those with either a filename or an alternative name matching the exact text of the binary's import command are imported, much like the native linker/loader. For example, in ELF, the .dynstr entry is used.

```
elf: searching for 'libc.so.6' in type libraries
Type library 'libc.so.6' imported
```

Type libraries for linux are ideally named after their realname, preserving the library minor version from which they were generated, and the soname in the alternatives list. In practice, naming them after their soname suffices. Using the linkname with no alternatives will prevent your library from loading.

This requested name should be a soname, like "libfoo.so.1" but could be a linkname like "libfoo.so". (The ldconfig tool is responsible for creating symlinks from soname to realnames, like `/usr/lib/libfoo.so.1` -> `/usr/lib/libfoo.so.1.0`. See [tldp.org](https://tldp.org/HOWTO/Program-Library-HOWTO/shared-libraries.html) for more information.).

Binary Ninja's logic for determining a match is straightforward:

```
typelibname.removesuffix('.bntl') == requestedname or requestedname in alternativenames
```

Therefore, without any alternative names, `libc.so.bntl` will not be loaded by Binary Ninja if an ELF requests libc.so.6.

We recommend and use the following convention:

Type libraries should be named for the filename from which they were generated with the phrase ".bntl" added. When the source library contains additional minor and release number, like `libfoo.so.1.2.3` Binary Ninja would not load the resulting type library `libfoo.so.1.2.3.bntl` for an ELF requesting soname `libfoo.so.1`. Therefore the alternative names list should include the most specific version numbers, incrementally stripped down to the soname, and finally a linkname for good measure.

Example:

`libfoo.so.1.2.3` is used to generated `libfoo.so.1.2.3.bntl`

The alternative names list should have:

```
libfoo.so.1.2.3 <-- includes version, minor, release (most specific)
libfoo.so.1.2   <-- includes version, minor (less specific)
libfoo.so.1     <-- includes version (soname)
libfoo.so       <-- linkname
```

## Acquiring a Handle

The platform class exposes handles to these imported type libraries with its `type_libraries` list and its `get_type_libraries_by_name()` function:

```python
>>> bv.platform.type_libraries
[<typelib 'libm.so.6':x86_64':x86_64>, <typelib 'SYSCALLS':x86_64]
>>> bv.platform.get_type_libraries_by_name('libm.so.6')
[<typelib 'libm.so.6':x86_64>]
```

That requires the type library having been loaded. A more direct way is to load from a file path with the `load_from_file()` from `Typelibrary` class from `typelibrary` module:

```python
>>> typelibrary.TypeLibrary.load_from_file('/path/to/libm_x86_64.so.6.bntl')
<typelib 'libm_x86_64.so.6':x86_64>
```

## Contents of Libraries

The following demonstrates attributes of interest on a loaded type library in variable `tl`:

```python
	print('           name: %s' % tl.name)
	print('           arch: %s' % tl.arch)
	print('           guid: %s' % tl.guid)
	print('dependency_name: %s' % tl.dependency_name)
	print('alternate_names: %s' % tl.alternate_names)
	print(' platform_names: %s' % tl.platform_names)

	print('  named_objects: %d' % len(tl.named_objects))
	for (key, val) in tl.named_objects.items():
		print('\t"%s" %s' % (str(key), str(val)))

	print('    named_types: %d' % len(tl.named_types))
	for (key,val) in tl.named_types.items():
		print('\t"%s" %s' % (str(key), str(val)))
```

Named objects (via dictionary `.named_objects` are functions signatures and a module's exported variables. Named types (via dictionary `.named_types`) are the textual names you might use to declare a variable. For example,

For example, `.named_objects['fegetexceptionflag']` looks up its function prototype: `int32_t (fexcept_t* flagp)` and `.named_types['fexcept_t']` looks up `uint16_t`, its typedef.

## Creating

You may also wish to use the [typelib_create.py](https://github.com/Vector35/binaryninja-api/blob/dev/python/examples/typelib_create.py) example script included both online and offline in your installation path.

Types entered by manual entry can be exported from the binary view using `export_type_to_library()`.

Manual creation is achieved by creating a new type library, associating the correct platform and architecture, adding types, finalizing, and writing to a file. Example:

```python
arch = binaryninja.Architecture['x86_64']

struct = Structure()
struct.append(Type.pointer(arch, Type.char()), 'name')
struct.append(Type.int(4), 'age')
struct.append(Type.int(4), 'height')
struct.append(Type.int(4), 'weight')

typelib = binaryninja.typelibrary.TypeLibrary.new(arch, 'test.so.1.4')
typelib.add_named_type('human', binaryninja.types.Type.structure_type(struct))
typelib.add_alternate_name('test.so.1') #don't forget this step!
typelib.add_alternate_name('test.so')
typelib.finalize()
typelib.write_to_file('test.so.1.bntl')
```

## Other Type Library Questions

_What's a named type vs. just a type?_

Some variable definitions have type information, but don't produce a type name useful for future definitions, examples:

- `enum {A=1,B=2} foo;` : foo has type with no type name (it does have a variable name)
- `struct {int A; int B;} bar;` : bar has type with no type name

In C, enum and struct definitions can create a new type name as a byproduct of a definition by using a "tag name":

- `enum MyEnum {A=1,B=2} foo;` : foo has the type named `MyEnum`
- `struct MyStruct {int A; int B;} bar;` : bar has the type named `MyStruct`

In the second set of examples, the types are named, and that name could be used to declare other variables, like `enum MyEnum bar2;` and `struct MyStruct bar2`.

Functions' types are not named. The function name is considered the name of a function object, and the function's type is anonymous.

In summary:

```c
typedef int foo; // type:int, name:foo

// structs, without and with a "tag name"
struct {int A; int B;} foo; // type:struct{int A, intB;}, name:<anonymous>
struct MyStruct {int A; int B;} foo; // type:struct{int A, intB;}, name:MyStruct

// enumerations, without and with a "tag name"
enum {A=1,B=2} foo; // type:enum{A=1,B=2}, name:<anonymous>
enum MyEnum {A=1,B=2} foo; // type:enum{A=1,B=2}, name:MyEnum

// functions
int main(int ac, char **av); // type int ()(int, char **), name:<anonymous>
typedef int (MyFunc)(int ac, char **av); // type int ()(int, char **), name:MyFunc

```

_How does Binary Ninja decide when to use a typelibrary (.bntl) file?_

Type Libraries are loaded when the corresponding library is imported by a BinaryView. (i.e. if an exe imports `ntdll.dll`, binja will look in the bv's platform for type libraries named ntdll.bntl and load the first one it finds)

_What's the difference between a named type and a named object?_

A named type is a type with a name that can identify it. For example, `color` is the name of type `enum {RED=0, ORANGE=1, YELLOW=2, ...}`.

A named object is the name of an external/imported symbol for which the type library has type information. For example, `MessageBoxA` is the name of a function whose type is `int ()(HWND, LPCSTR, LPCSTR, UINT)`.

_How do I find what type of type a type object is? How many are there?_

I've seen "types of types", "sorts of types", "kinds of types", "classes of types" used to differentiate the varieties of possible types, and there are probably more. Binary Ninja uses "class", example:

```
>>> type_obj.type_class
<TypeClass.FunctionTypeClass: 8>
```

In [enums.py](https://api.binary.ninja/_modules/binaryninja/enums.html#TypeClass) we can see Binary Ninja currently thinks of types falling into 13 classes: `Void`, `Bool`, `Integer`, `Float`, `Structure`, `Enumeration`, `Pointer`, `Array`, `Function`, `VarArgs`, `Value`, `NamedTypeReference`, `WideCharType`.

Compare this to LLDB, which also uses the term "class", and currently has 19 of them: `Array`, `BlockPointer`, `Builtin`, `Class`, `ComplexFloat`, `ComplexInteger`, `Enumeration`, `Function`, `MemberPointer`, `ObjCObject`, `ObjCInterface`, `ObjCObjectPointer`, `Pointer`, `Reference`, `Struct`, `Typedef`, `Union`, `Vector`, `Other`.

Compare this to GDB, which uses the term "type code" and has 25 of them.

_Where are function parameter names stored?_

While technically not part of the type, having names of function parameters is very useful and can thus be optionally stored in a type.

Function types (types with `.type_class == FunctionTypeClass`) have a `.parameters` attribute, a list of [`FunctionParameter`](https://api.binary.ninja/binaryninja.types-module.html#binaryninja.types.FunctionParameter) objects. When those objects have `.name==''` you get the bare bones function types like `int ()(int, char **)`. When those objects have their `.name` populated you get the more meaningful `int ()(int argc, char **argv)`.

_How do I manually load a type library?_

```
>>> bv.add_type_library(TypeLibrary.load_from_file('test.bntl'))
```

_How can I manually load a type object?_

```
>>> bv.import_library_object('_MySuperComputation')
<type: int32_t (int32_t, int32_t, char*)>
```

_Why doesn't the types view show the types imported from type libraries?_

Because the type libraries added to a binary view only makes their type information _available_ for use. The types view will show a type from a type library only after it is used (on demand).

Try this experiment:

- note `bv.type_libraries`, `bv.types`
- add a type library with `bv.add_type_library(TypeLibrary.load_from_file('test.bntl'))`
- note that `bv.type_libraries` is extended, but `bv.types` is unchanged!
- note `bv.get_type_by_name('Rectangle')` returns nothing
- set the type of some data to `struct Rectangle` (using `y` in linear view or via any other method described above)
- `bv.types` is extended, and the types view shows `struct Rectangle` in the auto types

_What's a named type reference?_

Named Type References are a way to refer to a type by name without having its declaration immediately available.

For example, examine this struct from [typelib_create.py](https://github.com/Vector35/binaryninja-api/blob/dev/python/examples/typelib_create.py):

```
struct Rectangle2 {
  int width;
  int height;
  struct Point center;
}
```

We don't know at this moment what a `struct Point is`. Maybe we've already added it. Maybe we'll add it later. Maybe it's in another type library. But we want to add a Rectangle now. So we leave the center field as a reference to the named type `struct Point`.

Load the resulting `test.bntl` in your binary and try to set some data to type `struct Rectangle2` and you'll be met with this message:

```
TypeLibrary: failed to import type 'Point'; referenced but not present in library 'libtest.so.1`
```

This makes sense! Now go to types view and `define struct Point { int x; int y; }` and try again, success!

```
100001000  struct rectangle_unresolved data_100001000 =
100001000  {
100001000      int32_t width = 0x5f0100
100001004      int32_t height = 0x5f030005
100001008      struct Point center =
100001008      {
100001008          int32_t x = 0x655f686d
10000100c          int32_t y = 0x75636578
100001010      }
100001008  }
```

You should repeat the experiment using `struct Rectangle` and see that you're allowed to create variables with type containing _pointers_ to unresolved type references.

_How are types represented?_

By a hierarchy of objects from [api/python/types.py](https://github.com/Vector35/binaryninja-api/blob/dev/python/types.py) referencing one another. The "glue" object is [`binaryninja.types.Type`](https://api.binary.ninja/binaryninja.types-module.html#binaryninja.types.Type) and depending on the complexity of the type it represents (stored in its `.type_class` attribute), it could have an attribute with more information. For instance, if the `binaryninja.types.Type` has `.type_class == FunctionTypeClass` then its `.parameters` attribute is a list of [`binaryninja.types.FunctionParameter`](https://api.binary.ninja/binaryninja.types-module.html#binaryninja.types.FunctionParameter). See  [typelib_dump.py](https://github.com/Vector35/binaryninja-api/blob/dev/python/examples/typelib_dump.py) for how this can work.

As an example, here is the hierarchical representation of `type struct Rectangle` from [typelib_create.py](https://github.com/Vector35/binaryninja-api/blob/dev/python/examples/typelib_create.py)

```
typelib.named_types["Rectangle"] =
----------------------------------
Type class=Structure
  Structure
    StructureMember "width"
      Type class=Integer width=4
    StructureMember "height"
      Type class=Integer width=4
    StructureMember "center"
      Type class=Pointer
        Type class=NamedTypeReference
          NamedTypeReference <named type: struct Point>
```

Here is the representation of `type int ()(int, int)` named `MyFunctionType` from [typelib_create.py](https://github.com/Vector35/binaryninja-api/blob/dev/python/examples/typelib_create.py):

_When do named objects get used?_

When a binary is loaded and its external symbols is processed, the symbol names are searched against the named objects from type libraries. If there is a match, it obeys the type from the type library. Upon success, you'll see a message like:

```
type library test.bntl found hit for _DoSuperComputation
```

At this moment, there is no built in functionality to apply named objects to an existing Binary Ninja database.
