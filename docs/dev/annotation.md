# Applying Annotations

This document is organized into five sections describing how to work with various types of annotations in Binary Ninja using the API. Note that its [companion documentation](../guide/types/index.md) describes how to interact with many of the same elements via the UI.

1. [Symbols](#symbols) covers how to work with Symbols in a binary
1. [Types](#types) documents creating and interacting with types through the API
1. [Tags](#tags) describes how to create tags and bookmarks
1. [Type Libraries](typelibraries.md) explains how to work with Type Libraries, including multiple sources of information from which Binary Ninja can automatically source for type information from and how you can add to them
1. [Signature Libraries](#signature-libraries) explains how to work with the signature library which match statically compiled functions which are then matched with type libraries

## Symbols

From an API perspective there are several helper functions available for working with Symbols. For example, to rename a function:

```py
>>> current_function.name
'main'
>>> current_function.name = "newName"
>>> current_function.name
'newName'
```

Other objects or variables may need a [symbol](https://api.binary.ninja/binaryninja.types-module.html#binaryninja.types.Symbol) created and applied (this can also be done even if not using a helper function on objects such as functions):

```py
>>> mysym = Symbol(SymbolType.FunctionSymbol, here, "myVariableName")
>>> mysym
<SymbolType.FunctionSymbol: "myVariableName" @ 0x80498d0>
>>> bv.define_user_symbol(mysym)
```

Note that `here` and `bv` are used in many of the previous examples. These shortcuts and [several others](../guide/index.md#script-python-console) are only available when running in the Binary Ninja python console and are used here for convenience.

Valid symbol types [include](https://api.binary.ninja/binaryninja.enums-module.html#binaryninja.enums.SymbolType):

| SymbolType | Description |
| ---------- | ----------- |
| FunctionSymbol |            Symbol for function that exists in the current binary |
| ImportAddressSymbol |       Symbol defined in the Import Address Table |
| ImportedFunctionSymbol |    Symbol for a function that is not defined in the current binary |
| DataSymbol |                Symbol for data in the current binary |
| ImportedDataSymbol |        Symbol for data that is not defined in the current binary |
| ExternalSymbol |            Symbols for data and code that reside outside the BinaryView |
| LibraryFunctionSymbol |     Symbols for functions identified as belonging to a shared library |
| SymbolicFunctionSymbol |    Symbols for functions without a concrete implementation or which have been abstractly represented|
| LocalLabelSymbol |          Symbol for a local label in the current binary |

## Tags

The tags API has been reworked in 3.4 to be easier to use and understand.

### TagTypes

A [TagType](https://api.binary.ninja/binaryninja.binaryview-module.html#binaryninja.binaryview.TagType) is the object that represents the "type" of tag something is. By default, a binary view starts off with several tag types, include "Bugs," "Crashes," "Important," and so on.

Before you can create a tag of a type that's not already in the BinaryView, you need to create the tag type.

Previously you'd have to handle this object and pass it around to other functions, but now you only need to remember its identifier:

```py
>>> bv.create_tag_type("Really good looking code", "🦀")
<tag type Really good looking code: 🦀 >
```

Where now you won't need the TagType object to create new tags.

### Creating Tags

There are three main types of tags: data tags, function tags, and address tags. All three of these use a similar `.add_tag` API.

#### Data Tags

Data tags are tags you create on a [BinaryView](https://api.binary.ninja/binaryninja.binaryview-module.html), with a given address and some associated data. It also has optional fields for if you'd like to create this as a auto tag.

These tags can be at any address. If they happen to overlap with the address in a function, it will add the tag to the appropriate lines of disassembly/IL/decompilation. This is not the best way to get tags into a function, however.

```py
>>> bv.add_tag(0xdeadbeef, "Vulnerabilities", "Some associated comment or serialized metadata")
```


#### Function and Address Tags

Function tags are tags you create on a [Function](https://api.binary.ninja/binaryninja.function-module.html) with some associated data. Function tags appear at the top of a function and are a good way to label an entire function with some information.

```py
>>> bv.add_tag_type("Cheese", "🧀")
<tag type Cheese: 🧀 >
>>> current_function.add_tag("Cheese", "This function smells funny")
```

If you include an address when you call `Function.add_tag`, you'll create an address tag. These are good for labeling specific instructions.

```py
>>> current_function.add_tag("Bug", "This is comparing an unsigned number with a signed number!", 0xdeadbeef)
```

### Auto Tags

Auto Tags are tags that are created automatically by some process or plugin. They will not be saved into the database as the assumption is that they are automatically created each time the file is to be opened. This is unlikely to be true for most use cases which is why the auto API was deprecated in favor of a unified API that defaults to `auto=false`.

If you want to create auto tags as of 3.4, provide the `auto=True` flag to the above calls.

```py
>>> bv.add_tag(0xdeadbeef, "Vulnerability", "Buffer overflooooowwwww!!!", auto=True)
```

## Types

Binary Ninja provides a flexible API for creating and defining types explicitly. Binary Ninja `Type` objects are immutable, we provide two different methods for creating them. For simple types there are one-shot APIs that allow you to define the type with a single function call. Some situations are more complex and incremental construction is preferred, so we provide an additional `TypeBuilder` interface. The `TypeBuilder` interface is also useful for when you want to modify an existing type.

### Simple Type Creation

There are a number of different type objects available for creation:

- Integer Types
- Characters Types (technically an integer)
- Wide Characters Types (also technically an integer)
- Boolean (guess what? also technically an integer)
- Float Types (definitely not an integer)
- Pointers
- Void (like an integer but if its size was zero)
- Functions
- Arrays
- Enumeration (kind of an integer)
- Structures (probably has integers in it)
- Type Definitions

#### Creating Types Using the Type Parser

Binary Ninja's built-in type parser provides a very convenient way of creating types when you can't remember the exact API to call. The `parse_type_string` API returns a tuple of `Type` and `string` name for the string passed.

```python
>>> bv.parse_type_string("uint64_t")
(<type: uint64_t>, '')
```

Though convenient it is many orders of magnitude slower than simply calling the APIs directly. For applications where performance is at all desired the following APIs should be used.

#### Integer Types

```python
Type.int(4) # Creates a 4 byte signed integer
Type.int(8, False) # Creates an 8 bytes unsigned integer
Type.int(2, alternate_name="short") # Creates a 2 byte signed integer named 'short'
# Similarly through their classes directly
IntegerType.create(4)
IntegerType.create(8, False)
IntegerType.create(2, alternate_name="short")
```

#### Character Types

```python
Type.char() # This is just a 1 byte signed integer and can be used as such
Type.wide_char(2, alternate_name="wchar_t") # Creates a wide character with the name 'wchar_t'
# Similarly through their classes directly
CharType.create()
WideCharType.create(2)
```

#### Boolean

```python
Type.bool()
# Similarly through its class directly
BoolType.create()
```

#### Floating-point Types

_All floating point numbers are assumed to be signed_

```python
Type.float(4) # Creates a 4 byte ieee754 'float'
Type.float(8) # Creates a 8 byte ieee754 'double'
Type.float(10) # Creates a 10 byte ieee754 'long double'
Type.float(16) # Creates a 16 byte ieee754 'float128'
# Similarly through their classes directly
FloatType.create(4)
FloatType.create(8)
FloatType.create(10)
FloatType.create(16)
```

#### Void

```python
Type.void() # Create a void type which has zero size
# Similarly through its class directly
VoidType.create()
```

#### Pointers

```python
Type.pointer(bv.arch, Type.int(4)) # Create a pointer to a signed 4 byte integer
Type.pointer(type=Type.int(4), width=bv.arch.address_size) # Equivalent to the above but doesn't require an Architecture object be passed around
Type.pointer(bv.arch, Type.void(), const=True, volatile=False) # Creates a constant non volatile void pointer.
# Similarly through their classes directly
PointerType.create(bv.arch, Type.int(4))
PointerType.create(type=Type.int(4), width=bv.arch.address_size)
PointerType.create(bv.arch, Type.void(), const=True, volatile=False)
```

#### Arrays

```python
Type.array(Type.int(4), 2) # Create an array of 2 - 4 byte integers
# Similarly through their classes directly
ArrayType.create(Type.int(4), 2)
```

#### Function Types

```python
Type.function() # Creates a function with which takes no parameters and returns void
Type.function(Type.void(), [('arg1', Type.int(4))]) # Create a function type which takes an integer as parameter and returns void
Type.function(params=[('arg1', Type.int(4))]) # Same as the above
# Similarly through their classes directly
FunctionType.create()
FunctionType.create(Type.void(), [('arg1', Type.int(4))])
FunctionType.create(params=[('arg1', Type.int(4))])
```

#### Create Anonymous Structures/Class/Unions

In Binary Ninja's type system supports anonymous and named structures. Anonymous structures are the simplest
to understand, and what most people would expect.

```python
Type.structure(members=[(Type.int(4), 'field_0')], type=StructureVariant.UnionStructureType) # Create a union with one integer members
Type.structure(members=[(Type.int(4), 'field_0'), (Type.int(4), 'field_4')], packed=True) # Created a packed structure containing two integer members
Type.structure(members=[(Type.int(4), 'field_0')], type=StructureVariant.ClassStructureType) # Create a class with one integer members
# Similarly through their classes directly
StructureType.create(members=[(Type.int(4), 'field_0')], type=StructureVariant.UnionStructureType)
StructureType.create(members=[(Type.int(4), 'field_0'), (Type.int(4), 'field_4')], packed=True)
StructureType.create(members=[(Type.int(4), 'field_0')], type=StructureVariant.ClassStructureType)
```

#### Create Enumerations

```python
Type.enumeration(members=[('ENUM_2', 2), ('ENUM_4', 4), ('ENUM_8', 8)])
Type.enumeration(members=['ENUM_0', 'ENUM_1', 'ENUM_2'])

# Anonymous Enumeration
enum = Type.enumeration(arch.bv.arch, members={
    "ZERO": 0,
    "ONE": 1,
    "TWO": 2
}, width = 4)

# Named Enumeration
builder = TypeBuilder.enumeration()
for member in enum.members:
    builder.append(member.name, member.value)

registered_type = bv.define_user_type("Enum_Name", builder.immutable_copy())
```

### Accessing Types

You may end up accessing types via a variety of APIs. In some cases, you're already working with a variable, function, or other object that has a type property:

```python
>>> current_function.type
<type: immutable:FunctionTypeClass 'int32_t(int32_t argc, char** argv, char** envp)'>
>>> current_function.parameter_vars[2]
<var char** envp>
>>> current_function.parameter_vars[2].type
<type: immutable:PointerTypeClass 'char**'>
```

#### Explicit Type Lookup

Of course, there are also methods to directly access a type independent of its association with any given object in analysis:

```python
>>> bv.types['Elf64_Header']
<type: immutable:StructureTypeClass 'struct Elf64_Header'>
# Or
>>> s = bv.get_type_by_name('Elf64_Header')
>>> s
<type: immutable:StructureTypeClass 'struct Elf64_Header'>
>>> s.members
[<struct Elf64_Ident ident, offset 0x0>, <enum e_type type, offset 0x10>, <enum e_machine machine, offset 0x12>, <uint32_t version, offset 0x14>, <void (* entry)(), offset 0x18>, <uint64_t program_header_offset, offset 0x20>, <uint64_t section_header_offset, offset 0x28>, <uint32_t flags, offset 0x30>, <uint16_t header_size, offset 0x34>, <uint16_t program_header_size, offset 0x36>, <uint16_t program_header_count, offset 0x38>, <uint16_t section_header_size, offset 0x3a>, <uint16_t section_header_count, offset 0x3c>, <uint16_t string_table, offset 0x3e>]
```

#### Accessing Data Variable Values

Even more powerful are the APIs when a type is applied to a specific data variable because you can directly query members or values according to the type:

```python
>>> header = bv.get_data_var_at(bv.start)
>>> header
<var 0x0: struct Elf64_Header>
>>> header['ident']
<TypedDataAccessor type:struct Elf64_Ident value:{'signature': b'\x7fELF', 'file_class': 2, 'encoding': 1, 'version': 1, 'os': 0, 'abi_version': 0, 'pad': b'\x00\x00\x00\x00\x00\x00\x00'}>
>>> header['ident']['signature'].value
b'\x7fELF'
```

### Important Concepts

Here's a few useful concepts when working Binary Ninja's type system.
#### Named Types

In Binary Ninja the name of a class/struct/union or enumeration is separate from its type definition. This
is much like how it's done in C. The mapping between a structure's definition and its name is kept in the Binary View.
Thus if we want to associate a name with our type we need an extra step.

```python
bv.define_user_type('Foo', Type.structure(members=[(Type.int(4), 'field_0')]))
```

To reference a named type a `NamedTypeReference` object must be used. Say we want to add the struct `Foo` to our a new
structure `Bar`.

```python
t = Type.structure(members=[(Type.int(4), 'inner')])
n = 'Foo'
bv.define_user_type(n, t)
ntr = Type.named_type_from_registered_type(bv, n)
bv.define_user_type('Bar', Type.structure(members=[(ntr, 'outer')]))
```

The above is equivalent to the following C

```C
struct Foo {
    int32_t inner;
};

struct Bar {
    struct Foo outer;
};
```

It is also possible to add the type referenced by `Foo` directly as an anonymous structure and thus there would be no need for a `NamedTypeReference`

```python
t = Type.structure(members=[(Type.int(4), 'inner')])
bv.define_user_type('Bas', Type.structure(members=[(t, 'outer')]))
```

Yielding the following C equivalent:

```C
struct Bas
{
    struct { int32_t inner; } outer;
}
```


#### Mutable Types

As `Type` objects are immutable, the Binary Ninja API provides a pure python implementation of types to provide mutability, these all inherit from `MutableType` and keep the same names as their immutable counterparts minus the `Type` part. Thus `Structure` is the mutable version of `StructureType` and `Enumeration` is the mutable version of `MutableType`. `Type` objects can be converted to `MutableType` objects using the `Type.mutable_copy` API and, `MutableType` objects can be converted to `Type` objects through the `MutableType.immutable_copy` API. Generally speaking you shouldn't need the mutable type variants for anything except creation of structures and enumerations, mutable type variants are provided for convenience and consistency. Building and defining a new structure can be done in a few ways. The first way would be the two step process of creating the structure then defining it.

```python
s = StructureBuilder.create(members=[(IntegerType.create(4), 'field_0')])
bv.define_user_type('Foo', s)
```

A second option for more complicated situations you can opt for incremental initialization of the type:

```python
s = StructureBuilder.create()
s.packed = True
s.append(IntegerType.create(2))
s.append(IntegerType.create(4))
bv.define_user_type('Foo', s)
```

Finally you can use the built-in context manager which automatically registers the created type with the provided `BinaryView` (`bv`) and name(`Foo`). Additionally when creating TypeLibraries a `Type` can be passed instead of a `BinaryView`

```python
with StructureBuilder.builder(bv, 'Foo') as s:
    s.packed = True
    s.append(Type.int(2))
    s.append(Type.int(4))
```

### Type Modification

Sometimes it's desired to modify a type which has already been registered with a Binary View. The hard way would be as follows:

1. Look up the type you want to modify
2. Get a mutable version of that type
3. Modify the type how you wish
4. Register that type with the Binary View again

```python
s = bv.types['Foo'].mutable_copy()
s.append(Type.int(2))
bv.define_user_type('Foo', s)
```

This is a bit easier by using the builder context manager as follows:

```python
with Type.builder(bv, 'Foo') as s:
    s.append(Type.int(2))
```

### Applying Types

There are 3 categories of object which can have `Type` objects applied to them.

* Functions
* Variables (i.e. local variables)
* DataVariables (i.e. global variables)

As of the 3.0 API its much easier to apply types to Variables and DataVariables

#### Applying a type to a `Function`

Change a functions type to a function which returns void and takes zero parameters:
```python
current_function.type = Type.function(Type.void(), [])
```

#### Applying a type to a `Variable`

Change the parameter of a function's zeroth parameter to a pointer to a character:
```python
current_function.parameter_vars[0].type = Type.pointer(bv.arch, Type.char())
```

#### Applying a type to a `DataVariable`

```python
>>> bv.get_data_var_at(here)
<var 0x408104: void>
>>> bv.get_data_var_at(here).type
<type: immutable:VoidTypeClass 'void'>
>>> bv.get_data_var_at(here).type = Type.char()
```

#### Applying a type where non exists yet

In some instances you may need to first create a `DataVariable` before you can set the type at a given location:

```python
>>> bv.get_data_var_at(here)
# Nothing there yet!
>>> bv.define_user_data_var(here, "char*")
<var 0x22d50787c: char*>
```

Note that most of the APIs that take a Type object also take a C-style type string as a convenience helper as demonstrated as a difference between the last two examples.

### Headers

#### Importing a Header

Importing a header goes through the same code path as parsing source directly. You will just have to read the file and specify the appropriate command-line arguments as an array. See [user type guide](../guide/types/typeimportexport.md#import-header-file) for directions for choosing arguments.

```python
>>> with open('C:\projects\stdafx.h', 'r') as f:
...     TypeParser.default.parse_types_from_source(f.read(), 'stdafx.h', Platform['windows-x86_64'], [], ['--target=x86_64-pc-windows-msvc', '-x', 'c', '-std', 'c99', r'-isystemC:\Program Files (x86)\Microsoft Visual Studio\2019\Professional\VC\Tools\MSVC\14.28.29333\include', r'-isystemC:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0\ucrt', r'-isystemC:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0\shared', r'-isystemC:\Program Files (x86)\Windows Kits\10\Include\10.0.19041.0\um'])
(<types: [...], variables: [...], functions: [...]>, [])
```

Using these APIs will give you a Python object with all of the results, but won't actually apply them to the analysis in any way. If you want to replicate the importing behavior seen in the UI widget, there are a few additional steps you will need to take:

1. Use `BinaryView.define_user_types()` to add all the created types to the analysis
1. Update the function and data variable types
    1. Look up matching functions and symbols by using `BinaryView.get_symbol_by_raw_name`. Also look up potentially modified function names starting with `_` or `__`
    1. Once you have found a function whose name matches one found in the header file, set its type using `Function.type = ftype`
    1. Similarly for Data Variables, once one is found with a matching name, set its type using `DataVariable.type = dvtype`

#### Exporting a Header

Exporting a header uses the `TypePrinter.print_all_types` api, and outputs a string.

```python
>>> print(TypePrinter.default.print_all_types(bv.types.items(), bv))
//------------------------------------------------------------------------------
// Types for /bin/ls
//
// This header file generated by Binary Ninja
//------------------------------------------------------------------------------

#ifndef BN_TYPE_PARSER
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <wchar.h>

#define __packed
#define __noreturn
#define __convention(name)
...
```


## Type Libraries

Type Library documentation has outgrown this section and now lives [in a separate file](typelibraries.md).

## Signature Libraries

There are now two different signature library systems: [SigKit](#sigkit-signature-libraries), and [WARP](#warp-signature-libraries). SigKit will be deprecated in the near future as WARP represents a superset of its features.

### SigKit Signature Libraries

While many signatures are [built-in](https://github.com/Vector35/binaryninja-api/issues/1551) and require no interaction to automatically match functions, you may wish to add or modify your own. First, install the [SigKit](https://github.com/Vector35/sigkit/) plugin from the [plugin manager](../guide/plugins.md#plugin-manager).

#### Running the signature matcher

The signature matcher runs automatically by default once analysis completes. You can turn this off in `Settings > Analysis > Autorun Function Signature Matcher` (or, [analysis.signatureMatcher.autorun](../guide/settings.md#analysis.signatureMatcher.autorun) in Settings).

You can also trigger the signature matcher to run from the menu `Tools > Run Analysis Module > Signature Matcher`.

Once the signature matcher runs, it will print a brief report to the console detailing how many functions it matched and will rename matched functions. For example:

``` text
1 functions matched total, 0 name-only matches, 0 thunks resolved, 33 functions skipped because they were too small
```

#### Generating signature libraries

To generate a signature library for the currently-open binary, use `Tools > Signature Library > Generate Signature Library`. This will generate signatures for all functions in the binary that have a name attached to them. Note that functions with automatically-chosen names such as `sub_401000` will be skipped. Once it's generated, you'll be prompted where to save the resulting signature library.

For headless users, you can generate signature libraries by using the sigkit API ([examples](https://github.com/Vector35/sigkit/tree/master/examples) and [documentation](https://github.com/Vector35/sigkit/blob/master/__init__.py#L46)). For more detailed information, see our blog post describing [signature generation](https://binary.ninja/2020/03/11/signature-libraries.html#signature-generation).

If you are accessing the sigkit API through the Binary Ninja GUI and you've installed the sigkit plugin through the plugin manager, you will need to import sigkit under a different name:

``` python
import Vector35_sigkit as sigkit
```

#### Installing signature libraries

Binary Ninja loads signature libraries from 2 locations:

 - [$INSTALL_DIR](https://docs.binary.ninja/guide/#binary-path)/signatures/$PLATFORM
 - [$USER_DIR](https://docs.binary.ninja/guide/#user-folder)/signatures/$PLATFORM

???+ Danger "Warning"
    Always place your signature libraries in your user directory. The install path is wiped whenever Binary Ninja auto-updates. You can locate it with `Open Plugin Folder` in the command palette and navigate "up" a directory.

Inside the signatures folder, each platform has its own folder for its set of signatures. For example, `windows-x86_64` and `linux-ppc32` are two sample platforms. When the signature matcher runs, it uses the signature libraries that are relevant to the current binary's platform. (You can check the platform of any binary you have open in the UI using the console and typing `bv.platform`)

#### Manipulating signature libraries

You can edit signature libraries programmatically using the sigkit API. A very basic [example](https://github.com/Vector35/sigkit/blob/master/examples/convert_siglib.py) shows how to load and save signature libraries. Note that Binary Ninja only supports signatures in the `.sig` format; the other formats are for debugging. The easiest way to load and save signature libraries in this format are the [`sigkit.load_signature_library()`](https://github.com/Vector35/sigkit/blob/master/__init__.py) and [`sigkit.save_signature_library()`](https://github.com/Vector35/sigkit/blob/master/__init__.py) functions.

To help debug and optimize your signature libraries in a Signature Explorer GUI by using `Tools > Signature Library > Explore Signature Library`. This GUI can be opened through the sigkit API using [`sigkit.signature_explorer()`](https://github.com/Vector35/sigkit/blob/master/__init__.py) and [`sigkit.explore_signature_library()`](https://github.com/Vector35/sigkit/blob/master/sigkit/sigexplorer.py).

For a text-based approach, you can also export your signature libraries to JSON using the Signature Explorer. Then, you can edit them in a text editor and convert them back to a .sig using the Signature Explorer afterwards. Of course, these conversions are also accessible through the API as the [`sigkit.sig_serialize_json`](https://github.com/Vector35/sigkit/blob/master/sigkit/sig_serialize_json.py) module, which provides a pickle-like interface. Likewise, [`sigkit.sig_serialize_fb`](https://github.com/Vector35/sigkit/blob/master/sigkit/sig_serialize_fb.py) provides serialization for the standard .sig format.


### WARP Signature Libraries

WARP integration is included with Binary Ninja but turned **off** by default, for more information about WARP itself visit the open source repository [here](https://github.com/Vector35/warp)!

The benefit to using WARP over SigKit is that WARP signatures are more comprehensive and as such will have fewer false positives.
Alongside fewer false positives WARP will match more functions with less information due to the matching algorithm taking into account function locality (i.e. functions next to each other).
After matching has completed WARP functions will be tagged and the types for those functions will be transferred, this means less work for those looking to 
transfer analysis information from one version of a binary to another version.

#### Configuration

Binary Ninja by default will _only_ use [SigKit signatures](#sigkit-signature-libraries) to match functions, to **enable** WARP signatures you must enable the `analysis.warp` option and restart, after which you will have a few options:

- **WARP GUID** (`analysis.warp.guid`): make the function GUID required for **WARP Matcher** to run on the function, enabled by default.
- **WARP Matcher** (`analysis.warp.matcher`): match and apply known functions, enabled by default.
- **Trivial Function Length** (`analysis.warp.trivialFunctionLength`): functions below this length will be required to match on constraints, `20` by default.
- **Minimum Function Length** (`analysis.warp.minimumFunctionLength`): functions below this length will not be matched, `1` by default.
- **Maximum Function Length** (`analysis.warp.maximumFunctionLength`): functions above this length will not be matched, a value of **0** will disable this check, `0` by default.
- **Minimum Matched Constraints** (`analysis.warp.minimumMatchedConstraints`): functions which require constraints must match at-least this number, `1` by default. A Higher number will mean fewer matches due to fewer functions meeting the threshold.
- **Trivial Function Adjacent Constraints Allowed** (`analysis.warp.trivialFunctionAdjacentAllowed`): if this is enabled functions can match based off trivial adjacent functions (i.e. ones which are below `analysis.warp.trivialFunctionLength`). This is disabled by default.

**WARP GUID** and **WARP Matcher** are complimentary, for **WARP Matcher** to actually start matching known functions there first must be a set of functions with WARP GUID's attached.
The primary way to create this set of GUID's is to have **WARP GUID** enabled.

???+ Danger "Warning"
    These settings are cached internally to not slow down analysis, it is best to restart after changing any of these settings.

#### Consumer Usage

**WARP** function matching will occur automatically whenever you first open a binary, this process runs at the end of analysis and will trigger reanalysis on matched functions.

After the function matching has finished, all the matched functions are tagged with "WARP" and can be found in the [Tags Sidebar](../guide/index.md#tagsbookmarks).

#### Producer Usage

Before you create signatures you must first identify the binary for which you want to produce said signatures for and whether that format is directly supported by Binary Ninja.

#### Producing Directly in Binary Ninja

If you have a binary that can be opened within Binary Ninja then the process is straightforward:

1. Open the binary in Binary Ninja
2. Run `WARP\\Generate Signature File`

Once step 2 completes it will ask for a file name, then it will store the signature file in your user signatures folder (see [Signature Files](#signature-files)).

#### Producing Headlessly with Binary Ninja

If what you are trying to do requires anything more than a single binary (i.e. static library archives) than you will need to use a headless script.

Currently, the only script that exists is `sigem`, which is what is used internally for creation of shipped signature files. The source code and more instructions can be found [here](https://github.com/Vector35/binaryninja-api/tree/dev/plugins/warp).

### Signature Files

The signature files are simple flatbuffers, if you intend on consuming them directly (without Binary Ninja), please visit the open source repository [here](https://github.com/Vector35/warp)!

The signatures that are applied can come from two locations: one in the [install directory](https://docs.binary.ninja/guide/#binary-folder) under `signatures` and one in the [user directory](https://docs.binary.ninja/guide/#user-folder) under `signatures`.

- [Install Directory](https://docs.binary.ninja/guide/#binary-folder)/signatures/{PLATFORM}
- [User Directory](https://docs.binary.ninja/guide/#user-folder)/signatures/{PLATFORM}

???+ Danger "Warning"
    Always place your signature libraries in your user directory. The install path is wiped whenever Binary Ninja auto-updates. You can locate it with `Open Plugin Folder` in the command palette and navigate "up" a directory.

Inside the signatures folder, each platform has its own folder for its set of signatures (e.g., windows-x86_64 and linux-ppc32). When the signature matcher runs, it uses the signature libraries relevant to the current binary's platform. (You can check the platform of any binary you have open in the UI by typing `bv.platform` in the console.)
