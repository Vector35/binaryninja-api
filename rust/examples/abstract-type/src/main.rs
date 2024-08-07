use binaryninja::rc::Ref;
use binaryninja::types::{AbstractType, EnumerationBuilder, StructureBuilder, StructureType, Type};

fn create_struct<F>(f: F) -> Ref<Type>
where
    F: FnOnce(&StructureBuilder) -> &StructureBuilder,
{
    Type::structure(&f(&StructureBuilder::new()).finalize())
}

fn create_enum<F>(width: usize, signed: bool, f: F) -> Ref<Type>
where
    F: FnOnce(&EnumerationBuilder) -> &EnumerationBuilder,
{
    Type::enumeration(&f(&EnumerationBuilder::new()).finalize(), width, signed)
}

fn primitive() {
    assert_eq!(u8::resolve_type(), Type::int(1, false));
    assert_eq!(u16::resolve_type(), Type::int(2, false));
    assert_eq!(u32::resolve_type(), Type::int(4, false));
    assert_eq!(u64::resolve_type(), Type::int(8, false));
    assert_eq!(u128::resolve_type(), Type::int(16, false));

    assert_eq!(i8::resolve_type(), Type::int(1, true));
    assert_eq!(i16::resolve_type(), Type::int(2, true));
    assert_eq!(i32::resolve_type(), Type::int(4, true));
    assert_eq!(i64::resolve_type(), Type::int(8, true));
    assert_eq!(i128::resolve_type(), Type::int(16, true));

    assert_eq!(f32::resolve_type(), Type::float(4));
    assert_eq!(f64::resolve_type(), Type::float(8));
}

fn basic_struct() {
    #[derive(AbstractType)]
    #[repr(C)]
    struct A {
        first: u8,
        second: u32,
        third: u16,
    }

    assert_eq!(
        A::resolve_type(),
        create_struct(|s| {
            s.with_members([
                (&Type::int(1, false), "first"),
                (&Type::int(4, false), "second"),
                (&Type::int(2, false), "third"),
            ])
        })
    );
}

fn packed_struct() {
    #[derive(AbstractType)]
    #[repr(C, packed)]
    struct A {
        first: u8,
        second: u32,
        third: u16,
    }

    assert_eq!(
        A::resolve_type(),
        create_struct(|s| {
            s.set_packed(true).with_members([
                (&Type::int(1, false), "first"),
                (&Type::int(4, false), "second"),
                (&Type::int(2, false), "third"),
            ])
        })
    );
}

fn custom_alignment() {
    #[derive(AbstractType)]
    #[repr(C, align(16))]
    struct A {
        first: u8,
        second: u32,
        third: u16,
    }

    assert_eq!(
        A::resolve_type(),
        create_struct(|s| {
            s.set_alignment(16).with_members([
                (&Type::int(1, false), "first"),
                (&Type::int(4, false), "second"),
                (&Type::int(2, false), "third"),
            ])
        })
    );
}

fn named_field() {
    #[derive(AbstractType)]
    #[repr(C)]
    struct A {
        first: u8,
        #[binja(named)]
        second: B,
    }

    #[derive(AbstractType)]
    #[repr(C)]
    struct B {
        third: u16,
    }

    assert_eq!(
        A::resolve_type(),
        create_struct(|s| {
            s.with_members([
                (&Type::int(1, false), "first"),
                (
                    &Type::named_type_from_type("B", &B::resolve_type()),
                    "second",
                ),
            ])
        })
    );
    assert_eq!(
        B::resolve_type(),
        create_struct(|s| { s.with_members([(&Type::int(2, false), "third")]) })
    );
}

fn pointer_field() {
    #[derive(AbstractType)]
    #[repr(C)]
    #[binja(pointer_width = 4)]
    struct A {
        first: u8,
        second: *const u32,
    }

    assert_eq!(
        A::resolve_type(),
        create_struct(|s| {
            s.with_members([
                (&Type::int(1, false), "first"),
                (
                    &Type::pointer_of_width(&Type::int(4, false), 4, false, false, None),
                    "second",
                ),
            ])
        })
    );
}

fn nested_pointer_field() {
    #[derive(AbstractType)]
    #[repr(C)]
    struct A {
        first: u8,
        #[binja(named)]
        second: B,
    }

    #[derive(AbstractType)]
    #[repr(C)]
    #[binja(pointer_width = 4)]
    struct B {
        third: u32,
        fourth: *const u16,
    }

    assert_eq!(
        A::resolve_type(),
        create_struct(|s| {
            s.with_members([
                (&Type::int(1, false), "first"),
                (
                    &Type::named_type_from_type("B", &B::resolve_type()),
                    "second",
                ),
            ])
        })
    );
    assert_eq!(
        B::resolve_type(),
        create_struct(|s| {
            s.with_members([
                (&Type::int(4, false), "third"),
                (
                    &Type::pointer_of_width(&Type::int(2, false), 4, false, false, None),
                    "fourth",
                ),
            ])
        })
    );
}

fn named_pointer_field() {
    #[derive(AbstractType)]
    #[repr(C)]
    #[binja(pointer_width = 4)]
    struct A {
        first: u8,
        #[binja(named)]
        second: *const B,
    }

    #[derive(AbstractType)]
    #[repr(C)]
    struct B {
        third: u32,
        fourth: u16,
    }

    assert_eq!(
        A::resolve_type(),
        create_struct(|s| {
            s.with_members([
                (&Type::int(1, false), "first"),
                (
                    &Type::pointer_of_width(
                        &Type::named_type_from_type("B", &B::resolve_type()),
                        4,
                        false,
                        false,
                        None,
                    ),
                    "second",
                ),
            ])
        })
    );
    assert_eq!(
        B::resolve_type(),
        create_struct(|s| {
            s.with_members([
                (&Type::int(4, false), "third"),
                (&Type::int(2, false), "fourth"),
            ])
        })
    )
}

fn union() {
    #[derive(AbstractType)]
    #[repr(C)]
    union A {
        first: u32,
        second: [u16; 2],
        third: [u8; 4],
    }

    assert_eq!(
        A::resolve_type(),
        create_struct(|s| {
            s.set_structure_type(StructureType::UnionStructureType)
                .with_members([
                    (&Type::int(4, false), "first"),
                    (&Type::array(&Type::int(2, false), 2), "second"),
                    (&Type::array(&Type::int(1, false), 4), "third"),
                ])
        })
    );
}

fn enumeration() {
    #[derive(AbstractType)]
    #[repr(u32)]
    #[allow(dead_code)]
    enum Color {
        Red = 0xff0000,
        Green = 0x00ff00,
        Blue = 0x0000ff,
    }

    assert_eq!(
        Color::resolve_type(),
        create_enum(4, false, |e| {
            e.insert("Red", 0xff0000)
                .insert("Green", 0x00ff00)
                .insert("Blue", 0x0000ff)
        })
    );
}

fn main() {
    let _ = binaryninja::headless::Session::new();
    primitive();
    basic_struct();
    packed_struct();
    custom_alignment();
    named_field();
    pointer_field();
    nested_pointer_field();
    named_pointer_field();
    union();
    enumeration();
}
