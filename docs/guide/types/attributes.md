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

## Structures with Base Classes and Inheritance

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

### Built-in Calling Conventions

The following built-in calling conventions without dedicated keywords are available in Binary Ninja:

|Name|Valid architectures|Description|
|---|---|---|
|`linux-syscall`|Most|Linux system call|
|`windows-syscall`|aarch64|Windows system call|
|`apple-syscall`|aarch64|macOS and iOS system calls|
|`go-stack`|x86, x86_64|Stack-based calling convention used by the Go compiler on 32-bit x86 or older compilers|
|`pascal`|x86|Pascal stack-based convention with left-to-right parameter passing and callee stack cleanup|
|`register`|x86|Register-based calling convention with left-to-right parameter passing (used by default in Delphi)|
|`gcc-fastcall`|x86|The `fastcall` calling convention as implemented in GCC on non-Windows platforms|
|`clang-fastcall`|x86|The `fastcall` calling convention as implemented in Clang on non-Windows platforms|
|`gcc-thiscall`|x86|The `thiscall` calling convention as implemented in GCC on non-Windows platforms|
|`clang-thiscall`|x86|The `thiscall` calling convention as implemented in Clang on non-Windows platforms|

!!! Warning "Linux x86 / x86_64 default convention rename"
    Prior to version 5.4, the default Linux convention on x86/x86_64 was named `cdecl` (and the stdcall variant was `stdcall`). It is now `sysv` (and `sysv-stdcall`) to deconflict with the Windows behavior of `cdecl`/`stdcall`. Both names continue to be registered on the architecture, so `__convention("cdecl")` will still resolve to the Windows version of `cdecl` even on Linux. If you have scripts that match calling conventions by string name, update them to recognize `sysv` and `sysv-stdcall`.

## Custom Parameter and Return Value Locations

Calling conventions describe the default placement of parameters and return values, but many real-world ABIs have functions whose locations diverge from those defaults (for example, hand-tuned assembly, custom register conventions, or high-level language features). You can override the default location for individual parameters with the `@` syntax or for a function's return value with the `__location("...")` attribute. The argument is a string in Binary Ninja's value-location syntax (described below).

### Examples

``` C
/* Parameter locations: place this parameter in a specific register or stack slot */
int foo(int reg_param @ rdi, int stack_param @ 0x10);

/* Return-value location: return through rsi instead of the default rax */
int bar() __location("rsi");

/* A 16-byte value returned with the high half in rdx and the low half in rax;
   components are written left-to-right from high to low */
struct pair get_pair() __location("rdx:rax");

/* A parameter value in two registers. Complex locations for parameters are quoted. */
struct void set_pair(struct pair value @ "rdx:rax");

/* A return value spanning two registers with explicit field offsets */
struct mixed get_mixed() __location("[0x0: rax, 0x8: xmm0]");

/* An indirect return through a caller-supplied pointer; the leading * marks the
   location as a pointer to the storage, and "-> *rax" says the same pointer is
   returned in rax */
struct big get_big() __location("*rdi -> *rax");
```

### Value Location Syntax

The string that makes up a location describes one or more storage components (the locations holding the bytes of a single value). The grammar is:

* **Register component:** the register name, e.g., `rax`, `xmm0`, `r1`.
* **Stack component:** an integer offset into the caller's stack frame (decimal or `0x`-prefixed hex), e.g., `0x10`, `-4`.
* **Component size suffix:** append `.b`, `.w`, `.d`, `.q`, `.t`, or `.o` for 1/2/4/8/10/16-byte sizes, or `.<n>` for an explicit byte count, e.g., `eax.d`, `r0.q`, `rax.b`. Without a suffix, the natural register width is used (for stack components, sizes are inferred from the type).
* **Multi-component (concatenated):** components separated by `:`, written **high-to-low**, e.g., `rdx:rax` puts the low half in `rax` and the high half in `rdx`. This form requires that components are contiguous.
* **Multi-component with offsets:** when components are not contiguous, list them inside `[ ... ]` as `offset: component`, e.g., `[0x0: rax, 0x8: xmm0]`. Offsets are byte offsets within the value being passed/returned.
* **Indirect:** prefix the entire location with `*` to indicate the location holds a pointer to the value rather than the value itself, e.g., `*rdi`.
* **Returned-pointer hint:** for indirect returns where the same pointer is also returned in a register, append `-> *<reg>`, e.g., `*rdi -> *rax`.

### Pass By Value and By Reference

For composite types (structures, arrays) the calling convention decides whether to pass the value packed into registers, on the stack, or indirectly through a pointer. When that default is wrong for a particular declaration (most commonly in C++ where non-trivial type rules are applied that cannot always be determined at the binary level) you can override it with `__by_value` or `__by_ref`:

``` C
/* Force this argument to be passed by value (in registers or on the stack)
   even when the convention would normally pass it indirectly */
void takes_value(struct value_type __by_value arg);

/* Force this argument to be passed by reference (as a pointer) even when the
   convention would normally pass it by value */
void takes_object(struct object_type __by_ref arg);
```

`__by_value` and `__by_ref` apply per-parameter and affect only the location chosen for the parameter (the parameter's type in the signature is unchanged). If you need to override the *exact* register or stack slot, use the `@` syntax or `__location()` attribute described above instead (it implies a custom location and overrides any by-value/by-ref decision).

## System Call Functions for Import Libraries

[Import Libraries](importlibraries.md) can annotate system calls by adding functions with the special `__syscall()` attribute, specifying names and arguments for each syscall number. This attribute has no effect outside of [Import Libraries](importlibraries.md) and [Platform Types](platformtypes.md).

### Examples

``` C
/* From linux-x86_64's SYSCALLS Import Library */
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

Offset pointers, often called shifted pointers, relative pointers, or adjusted pointers, represent a pointer to a structure that has been offset by a certain number of bytes.
Annotating these offset pointers allows Binary Ninja to deduce types for dereferences through them, find the structure's start, and render proper member names.

These are often seen in intrusive linked lists, where structures have a pointer to the next item in the list, but the pointer is offset from the base of the structure and
instead points to the member containing the pointer to the next item. Iterating through the items in the list involves following the pointer, then shifting the result by the offset
of the pointer in the structure, to get the base of the structure. Because of this, many compilers will use the offset pointer to access structure members, accounting for the shift
in any dereferences, and saving a couple instructions.

### Examples

You will see uses of the offset pointers annotated with `(var - offset)` in IL views and `ADJ(var)` in Pseudo-C.

``` C
/* High Level IL */
void* __offset(perf_event, 0x50) next = event->migrate_entry_next
void* __offset(perf_event, 0x50) prev = event->migrate_entry_prev
(next - 0x50)->migrate_entry_prev = prev
(prev - 0x50)->migrate_entry_next = next

/* Pseudo-C */
void* __offset(perf_event, 0x50) next = event->migrate_entry_next;
void* __offset(perf_event, 0x50) prev = event->migrate_entry_prev;
ADJ(next)->migrate_entry_prev = prev;
ADJ(prev)->migrate_entry_next = next;
```

If we don't annotate the pointers in the list (as is the default), this intrusive linked list
will just do math on the pointers.

``` C
/* This structure... */
struct perf_event __packed
{
    ...
    void* sibling_list_next; /* Offset: 0x10 */
    void* sibling_list_prev; /* Offset: 0x18 */
    ...
};

/* ...yields this decompilation */
void* event = leader->sibling_list_next - 0x10

while (leader != event)
    /* Note these fields are not annotated */
    if (*(event + 0x98) == &pmu && *(event + 0xa8) s>= 0)
        if (collect_event(cpuc, event, max_count, n: n_events) != 0)
            break

        n_events += 1

    event = *(event + 0x10) - 0x10
```

We can instead use offset pointers for the intrusive linked list members and improve our output:

``` C
/* Now the pointers have offsets annotated */
struct perf_event __packed
{
    ...
    /* These pointers are pointing to &perf_event::sibling_list_next, 0x10 bytes from
     * the start of a perf_event structure. */
    void* __offset(perf_event, 0x10) sibling_list_next; /* Offset: 0x10 */
    void* __offset(perf_event, 0x10) sibling_list_prev; /* Offset: 0x18 */
    ...
};

/* Now the decompilation shows member accesses properly */
struct perf_event* event = leader->sibling_list_next - 0x10

while (leader != event)
    if (event->pmu == &pmu && event->state s>= PERF_EVENT_STATE_INACTIVE)
        if (collect_event(cpuc, event, max_count, n: n_events) != 0)
            break

        n_events += 1

    event = event->sibling_list_next - 0x10
```

!!! Tip "Tip"
    Normally, intrusive linked lists are a structure containing pointers to that structure
    inside the next object, but we're inlining the structure members here, so we can
    specialize their pointer offsets.

## Type Fragments

Fragment types are displayed using `__frag` for a little-endian mapping and `__frag_be` for a
big-endian mapping. These annotations describe how an in-flight bitwise slice maps back to a
larger source type; they do not imply that a particular load instruction created the fragment.
See [Type Fragments](fragments.md) for the analysis model, syntax, and examples.

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

Some structures store pointers with a size different from the platform's address width. For example, a 32-bit image base-relative pointer used on an 64-bit architecture. These sized pointers can be annotated with the `__ptr8`, `__ptr16`, `__ptr32`, `__ptr64`, or `__ptr_width()` attributes.

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

## Custom Attributes

Binary Ninja allows you to add custom attributes to types, which do not affect analysis but can be used by plugins and scripts. You can add these with the `__attr` annotation. Scripts can then query a `Type` object's `attributes` field to see the attribute keys and values.

### Examples

``` C
typedef int __attr("a") test;
typedef int __attr("a", "b") test;
```

```py
>>> TypeParser.default.parse_type_string('int __attr("a", "b") test', Platform["windows-x86"])[0][1].attributes
{'a': 'b'}
```

Attributes on function pointers can be applied to many different places:
``` C
typedef void (*__attr("ptr", "attr") test)();      // Applies to the pointer 
typedef void (__attr("function", "attr")* test)(); // Applies to the function
typedef __attr("return", "attr") void (* test)();  // Applies to the return type
typedef void __attr("return", "attr") (* test)();  // Applies to the return type
```

Attributes propagate with the type during analysis, so they can select and parameterize a [string recognizer or constant renderer](../../dev/customstrings.md). With the [encoded_strings.py](https://github.com/Vector35/binaryninja-api/blob/dev/python/examples/encoded_strings.py) example plugin loaded, applying this type to a decoding routine's parameter deobfuscates every string passed to it:

``` C
typedef char __attr("sub_encoded", "31656537366531313932396130373434")* deobfuscate;
```
