# Defining types using native Rust syntax

Writing a Binary Ninja plugin often involves defining one or more types inside a Binary View. The easiest way to do this using the C++ or Python APIs is to use the `TypeBuilder` class, or one of its variants, like `StructureBuilder` or `EnumerationBuilder`. The Rust API also has equivalent builders for this. However, the newly added `AbstractType` trait allows you to automatically generate a type object ready for ingestion into Binary Ninja by simply decorating a Rust type definition with `#[derive(AbstractType)]`, with no additional effort required!

As an example, say you'd like to define the following type inside of a Binary View:

```c
struct MyStruct {
    uint8_t first;
    uint32_t second;
    int16_t third[2];
};
```

Using the `StructureBuilder` API, you could generate the type as follows:

```rust
use binaryninja::types::{Structure, Type};

let ty = Type::structure(
    Structure::builder()
        .with_members([
            (&Type::int(1, false), "first"),
            (&Type::int(4, false), "second"),
            (&Type::array(&Type::int(2, true), 2), "third"),
        ])
        .finalize()
        .as_ref(),
);
```

Or, you could generate the same type using a native Rust struct definition instead:

```rust
use binaryninja::types::AbstractType;

#[derive(AbstractType)]
#[repr(C)]
struct MyStruct {
    first: u8,
    second: u32,
    third: [i16; 2],
}

let ty = MyStruct::resolve_type();
```

By deriving the `AbstractType` trait for a type `T`, the `resolve_type` method will automatically construct a `Type` corresponding to the layout of `T`. This has multiple benefits, the first of which is improved readability. Another is that if your plugin performs some additional processing that makes use of `T`, you can define it once in Rust and use that definition both for processing actual data as well as defining types inside of Binary Ninja.

## Deriving `AbstractType` for a type

While the trait itself is public, the derive macro for `AbstractType` is gated behind the `derive` crate feature. In order to make use of it, include the following line in your `Cargo.toml`: 

```toml
[dependencies]
binaryninja = { git = "https://github.com/Vector35/binaryninja-api.git", branch = "dev", features = ["derive"] }
```

Furthermore, in order for `AbstractType::resolve_type` to produce unambiguous results, some restrictions are enforced when deriving the trait that ensure the generated implementation correctly produces the intended corresponding C type.

### Structs and Unions

Structs and unions must be marked `#[repr(C)]`. This is because the `AbstractType` derive macro relies on compiler-generated layout information in order to accurately generate equivalent C type definitions. Because we are targeting the C ABI (and because the Rust ABI is not stable), deriving `AbstractType` requires opting into the C ABI as well.

### Enums
In contrast to structs, the fundamental representation of enums in Rust is different compared to C; decorating a Rust enum with `#[repr(C)]` produces a "tagged union" whose layout is not the same as a C-style enum. Therefore, Rust enums that derive `AbstractType` must instead be decorated with `#[repr(<int>)]`, for example `u32` or `u64`. Additionally, their variants must not contain any data, and all variants must have an explicitly assigned discriminant. As an example:

```rust
#[derive(AbstractType)]
#[repr(u32)]
enum Color {
    Red = 0xff0000,
    Green = 0x00ff00,
    Blue = 0x0000ff,
}
```

## Special cases

### Pointers

Creating pointers using the Binary Ninja API requires either defining them with respect to a specific architecture (if using the `Type::pointer` constructor), or otherwise manually specifying their width using `Type::pointer_of_width`. Likewise, deriving `AbstractType` for a type `T` that contains any pointer fields requires decorating `T` with a `#[binja(pointer_width)]` attribute:

```rust
#[derive(AbstractType)]
#[binja(pointer_width = 4)] // Explicitly required because `A` contains pointers
#[repr(C)]
struct A {
    first: u8,
    second: *const u64, // 4 bytes wide
    third: *const u32, // also 4 bytes wide - all pointers inside `A` are given the same width
}
```

Part of the reason for this requirement is that the architecture of the Binary View may be different than the host system - therefore, the Rust compiler would otherwise report an incorrect size for any pointers compared to what the Binary View expects.

### Named types

If you wish to define a type containing a non-primitive field, by default the type of that field will be defined inline in Binja, which may initially feel surprising. As an example, let's say we want to express the following construct:

```c
struct A {
    uint8_t first;
    struct B second;
}

struct B {
    uint16_t third;
    uint32_t fourth;
}
```

If we simply define the types `A` and `B` in Rust like so:

```rust
#[derive(AbstractType)]
#[repr(C)]
struct A {
    first: u8,
    second: B,
}

#[derive(AbstractType)]
#[repr(C)]
struct B {
    third: u16,
    fourth: u32,
}
```

...then, calling `A::resolve_type()` and passing the result to a Binary View will result in the following definition in the view:

```c
struct A {
    uint8_t first;
    struct {
        uint16_t third; 
        uint32_t fourth;
    } second;
}
```

Obviously, this is not quite what we intended. To fix this, decorate the `A::second` field with a `#[binja(named)]` attribute to signal to the compiler to used a named type for the field rather than inlining the type's definition:

```rust
#[derive(AbstractType)]
#[repr(C)]
struct A {
    first: u8,
    #[binja(named)]
    second: B,
}
```

...resulting in the correct C definition:

```c
struct A {
    uint8_t first;
    struct B second;
}
```

The `named` attribute will use the name of the Rust type (in this case, `B`) as the name for the defined type in Binja. If you would like a different name to be used, you can explicitly specify it by instead using the `#[binja(name = "...")]` attribute:

```rust
#[derive(AbstractType)]
#[repr(C)]
struct A {
    first: u8,
    #[binja(name = "C")]
    second: B,
}
```

...which will result in the following C-type:

```c
struct A {
    uint8_t first;
    struct C second;
}
```

Note that defining structs with named fields does not require that the types with the specified names are already defined inside the Binary View. In other words, in the example above, the order in which you define `A` and `B` (e.g. by calling `BinaryView::define_user_type`) does not matter.

## Additional Notes

### Modifying default alignment

Decorating a Rust type with `#[repr(packed)]` or `#[repr(align)]` can change the alignment of a struct and its fields. These changes will also be reflected inside Binary Ninja. For example, decorating a struct with `#[repr(packed)]` will cause it to be marked `__packed` when defined in the Binary View.
