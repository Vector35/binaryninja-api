# Type Attributes and Annotations

There are a number of custom attributes and annotations you can add to types in Binary Ninja. They can modify type details, analysis, and presentation.

## Structure Packing

Use the attribute `__packed` in a structure definition to indicate that structure fields should be packed without padding. This is similar to `#pragma pack(1)` in MSVC and `__attribute__((packed))` in GCC/Clang. 

### Examples

``` C
/* Normally, fields are padded to their type's alignment */
struct UnpackedHeader
{
    uint16_t size;        /* Offset:  0x0 */
    char *name;           /* Offset:  0x8 */
    uint32_t version;     /* Offset: 0x10 */
    void (* callback)();  /* Offset: 0x18 */
};

/* Fields in a packed structure will never be padded, regardless of pointer or integer alignment preference */
struct PackedHeader __packed
{
    uint16_t size;        /* Offset: 0x0 */
    char *name;           /* Offset: 0x2 */
    uint32_t version;     /* Offset: 0xA */
    void (* callback)();  /* Offset: 0xE */
};
  
/* These also work, thanks to Clang's broad feature support across targets */ 
struct __attribute__((packed)) Header
{
    uint16_t size;        /* Offset: 0x0 */
    char *name;           /* Offset: 0x2 */
    uint32_t version;     /* Offset: 0xA */
    void (* callback)();  /* Offset: 0xE */
};
/* Or with the MSVC pragma */
#pragma pack(1)
struct Header
{
    uint16_t size;        /* Offset: 0x0 */
    char *name;           /* Offset: 0x2 */
    uint32_t version;     /* Offset: 0xA */
    void (* callback)();  /* Offset: 0xE */
};
```

## Structure Padding

You can manually specify padding members to fill empty space in structure definitions. This is commonly used when turning structures into text for use by C/C++ type parsers like GCC/Clang/MSVC. The `__padding` attribute informs Binary Ninja that the member is present simply to fill space, and it will be discarded during parsing.

### Examples

When inputting this type to the type parser...
``` C
struct Foo
{
    uint32_t field_0;        /* Offset: 0x0 */
    __padding char _4[0xc];  /* Will be empty space when type is parsed */
    char* field_10;          /* Offset: 0x10 */
};
```
...the following type is produced:
``` C
struct Foo
{
    uint32_t field_0;    /* Offset: 0x0 */
            ?? ?? ?? ??  /* Empty padding 0x4 -> 0x7 */
?? ?? ?? ?? ?? ?? ?? ??  /* Empty padding 0x8 -> 0xF */
    char* field_10;      /* Offset: 0x10 */
};
```

## Structures with Base Classes and Inheritence

See [Working with C++ Types and Virtual Function Tables](cpp.md).

## Functions That Don't Return

If you know that a function does not return (either via infinite loop, or terminating the process), you can annotate their definition with `__noreturn` to inform the analysis of this. Any calls to these functions will cause disassembly in the caller to stop, assuming execution does not continue. 

### Examples

``` C
/* Function definitions put the attribute at the end */
void exit(int code) __noreturn;

/* Function pointers put the attribute atfer the definition */
void (* func_ptr)() __noreturn;
typedef void (* func_ptr_t)() __noreturn;
void takes_callback(int (* param_func_ptr)() __noreturn);

/* It also works in other places */
__noreturn void (* func_ptr)();
void (__noreturn * func_ptr)();
void (* __noreturn func_ptr)();
```

## Function Calling Conventions

Function prototypes support various keywords to indicate their calling convention:

``` text
__cdecl
__stdcall
__fastcall
__convention("convention_name")
```

Due to the nature of parsing with Clang, most dedicated convention keywords are only available on their relevant targets. For example, `__stdcall` and `__fastcall` only apply to X86-based targets.

If you have a custom calling convention, or one with no dedicated keyword, you can specify the convention name with the `__convention("name")` attribute. 

### Examples

``` C
/* Functions put the attribute between the return type and name */
void __fastcall func();

/* Function pointers put the attribute before the pointer */
void (__stdcall* func_ptr)();
typedef void (__stdcall* func_ptr_t)();
void takes_callback(int (__stdcall* param_func_ptr)());

/* Other calling conventions can be specified by name */
void __convention("regparm") func();
```

## System Call Functions for Type Libraries

[Type Libraries](typelibraries.md) can annotate system calls by adding functions with the special `__syscall()` attribute, specifying names and arguments for each syscall number. This attribute has no effect outside of [Type Libraries](typelibraries.md) and [Platform Types](platformtypes.md).

### Examples

``` C
/* From linux-x86_64's SYSCALLS Type Library */
int64_t sys_read(int32_t fd, void* buf, uint64_t count) __syscall(0);
int64_t sys_write(int32_t fd, void const* buf, uint64_t count) __syscall(1);

/* From linux-x86_64.c (Platform Types) */
void sys_exit(int status) __noreturn __syscall(60);
void sys_exit_group(int status) __noreturn __syscall(231);
```

## Pure Functions

Functions whose result depends entirely on their input parameters can be marked as "pure." If they are called and their result value is not used, they are eliminated as dead code (as their only effect comes from their return value). Generally speaking, auto analysis will only mark functions as pure if the following conditions are met:

* Function has no instructions that access memory
* Function has no unresolved indirect branches
* Function has no unimplemented or intrinsic instructions
* Function does not call any other functions or syscalls
* Function can return

These functions are annotated in the type system with the `__pure` attribute, which you can apply like the other function attributes.

### Examples

``` C
int get_twice(int arg) __pure
{
    return arg * 2;
}
int main()
{
    (void)get_twice(1); /* result is unused, this will be dead code eliminated */ 
}
```

## Offset Pointers

Offset pointers, often called shifted pointers or relative pointers, are used to provide extra information about the "origin" of a pointer. They can include offset information about a struct and member, for example. These are used by analysis to keep track of shifted references to a structure and resolve member field accesses to be relative to the base.

More discussion about Offset Pointers can be found [on our blog](https://binary.ninja/2022/10/28/3.2-released.html#offset-pointers).

### Examples

``` C
/* rbx_1 is a void* located 0x2b0 bytes from the start of a _KSDEVICE */
void* __offset(_KSDEVICE, 0x2b0) rbx_1 = &device->__offset(0x2b0).q;

/* Further relative accesses through rbx_1 are annotated and displayed relative to the structure */
(rbx_1 - 0x2b0)->field18 = 0; /* mov qword [rbx_1-0x298], 0x0 */
```

## Based Pointers

Many binary formats contain pointers that reference addresses based on the start of memory or the address of the variable itself. You can annotate the base of these pointers using the `__based()` attribute. Binary Ninja supports these formats of based pointers:

* `__based(start)` Pointer based on the image start (BinaryView start address)
  * `__based(start, 0x100)` You can specify a constant offset to add to the pointer
  * `__based(start, -0x100)` Offsets can be negative too
* `__based(var)` Pointer based relative to a Data Variable typed with the pointer
  * `__based(var, 0x100)` You can specify a constant offset to add to the pointer
  * `__based(var, -0x100)` Offsets can be negative too
* `__based(const, 0x100)` Pointer based relative to some constant value

### Examples

These are used by MSVC RTTI on x86_64 binaries:
``` C
/* This structure definition... */
struct BaseClassDescriptor
{
    TypeDescriptor* __ptr32 __based(start) pTypeDescriptor;
    uint32_t numContainedBases;
    int32_t mdisp;
    int32_t pdisp;
    int32_t vdisp;
    uint32_t attributes;
    ClassHierarchyDescriptor* __ptr32 __based(start) pClassDescriptor;
};

/* ...results in the following presentation in Linear View */
struct BaseClassDescriptor type_info::`RTTI Base Class Descriptor at (0,32,4,82)' = 
{
    struct TypeDescriptor* __ptr32 __based(start) pTypeDescriptor = class type_info `RTTI Type Descriptor'  { 0x180000000 + 0x11180 }
    uint32_t numContainedBases = 0x0
    int32_t mdisp = 0x0
    int32_t pdisp = 0x20
    int32_t vdisp = 0x4
    uint32_t attributes = 0x52
    struct ClassHierarchyDescriptor* __ptr32 __based(start) pClassDescriptor = type_info::`RTTI Class Hierarchy Descriptor'  { 0x180000000 + 0xdfd0 }
}
```

You can define structures who reference other structures relative to their variable address in memory. Address references are _relative to the pointer, not the base of the structure._ 

``` C
/* This structure definition... */
struct Texture
{
    uint32_t width;
    uint32_t height;
    char* __based(var) texNameOffset;
    uint32_t mask;
    uint32_t flags;
};

/* ...results in the following presentation in Linear View */
struct Texture tile_red
{
    uint32_t width = 128
    uint32_t height = 128
    char* __based(var, 0x10) texNameOffset = string_tile_red  { &tile_red->texNameOffset + 0x10 } 
    uint32_t mask = 0
    uint32_t flags = 0
}
char string_tile_red[9] = "tile_red", 0;
```

## Pointers with Custom Sizes

Some structures store pointers with a size different than the platform's address width. For example, a 32-bit image base-relative pointer used on an 64-bit architecture. These sized pointers can be annotated with the `__ptr8`, `__ptr16`, `__ptr32`, `__ptr64`, or `__ptr_width()` attributes.

These are often combined with [Based Pointers](#based-pointers), since pointers smaller than the address width cannot point to parts of memory without being shifted first. 

### Examples

These are seen in places like MSVC RTTI on x86_64 binaries:

``` C
struct BaseClassDescriptor
{
    TypeDescriptor* __ptr32 __based(start) pTypeDescriptor;
    uint32_t numContainedBases;
    int32_t mdisp;
    int32_t pdisp;
    int32_t vdisp;
    uint32_t attributes;
    ClassHierarchyDescriptor* __ptr32 __based(start) pClassDescriptor;
};

struct BaseClassDescriptor* __ptr32 __based(start) `type_info::\`RTTI Base Class Array'`[0x1];
```
