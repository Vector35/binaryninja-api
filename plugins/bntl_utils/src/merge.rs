//! Merge multiple similar types into one, useful when deduplicating types across different type libraries.

use binaryninja::rc::Ref;
use binaryninja::types::{
    Enumeration, EnumerationBuilder, MemberAccess, MemberScope, Structure, StructureBuilder, Type,
    TypeClass,
};
use std::cmp::max_by_key;
use std::collections::{BTreeMap, HashMap};
use std::num::NonZeroUsize;

/// Merges a series of types into a single [`Type`], if possible.
pub fn merge_types(types: &[Ref<Type>]) -> Option<Ref<Type>> {
    let first = types.first()?.to_owned();
    types
        .iter()
        .skip(1)
        .try_fold(first, |acc, t| merge_recursive(&acc, t))
}

fn merge_recursive(t1: &Type, t2: &Type) -> Option<Ref<Type>> {
    // Identical types, this is what we hope happens so we can skip the expensive merge step.
    if t1 == t2 {
        return Some(t1.to_owned());
    }

    // TODO: Move t1.width != t2.width check up here? I don't think there is a scenerio where it is safe.

    match (t1.type_class(), t2.type_class()) {
        // Void is a wildcard for us, we will pick `t2`.
        (TypeClass::VoidTypeClass, _) => Some(t2.to_owned()),
        // Void is a wildcard for us, we will pick `t1`.
        (_, TypeClass::VoidTypeClass) => Some(t1.to_owned()),
        (TypeClass::IntegerTypeClass, TypeClass::IntegerTypeClass) => {
            if t1.width() != t2.width() {
                return None;
            }
            // Use the signedness with higher confidence
            let signed = max_by_key(t1.is_signed(), t2.is_signed(), |c| c.confidence);
            Some(Type::int(t1.width() as usize, signed.contents))
        }
        (TypeClass::FloatTypeClass, TypeClass::FloatTypeClass) => {
            if t1.width() != t2.width() {
                return None;
            }
            Some(Type::float(t1.width() as usize))
        }
        (TypeClass::PointerTypeClass, TypeClass::PointerTypeClass) => {
            // Recursive merge of target; fail if targets are incompatible
            let target = merge_recursive(&t1.target()?.contents, &t2.target()?.contents)?;

            let is_const = max_by_key(t1.is_const(), t2.is_const(), |c| c.confidence);
            let is_vol = max_by_key(t1.is_volatile(), t2.is_volatile(), |c| c.confidence);

            Some(Type::pointer_of_width(
                &target,
                t1.width() as usize,
                is_const.contents,
                is_vol.contents,
                None,
            ))
        }
        (TypeClass::ArrayTypeClass, TypeClass::ArrayTypeClass) => {
            if t1.count() != t2.count() {
                return None;
            }
            let elem = merge_recursive(&t1.element_type()?.contents, &t2.element_type()?.contents)?;
            Some(Type::array(&elem, t1.count()))
        }
        (TypeClass::StructureTypeClass, TypeClass::StructureTypeClass) => {
            let s1 = t1.get_structure()?;
            let s2 = t2.get_structure()?;
            let merged = merge_structures(&s1, &s2)?;
            Some(Type::structure(&merged))
        }
        (TypeClass::EnumerationTypeClass, TypeClass::EnumerationTypeClass) => {
            let e1 = t1.get_enumeration()?;
            let e2 = t2.get_enumeration()?;
            let merged = merge_enumerations(&e1, &e2)?;

            let signed = max_by_key(t1.is_signed(), t2.is_signed(), |c| c.confidence);
            let width = NonZeroUsize::new(t1.width() as usize)?;
            Some(Type::enumeration(&merged, width, signed))
        }
        // Functions, NamedTypeReferences, etc. fall through here.
        // Since we checked t1 == t2 at the start, if we reach here, they are different.
        _ => None,
    }
}

fn merge_structures(s1: &Structure, s2: &Structure) -> Option<Ref<Structure>> {
    let mut builder = StructureBuilder::new();
    builder.alignment(s1.alignment().max(s2.alignment()));
    builder.packed(s1.is_packed());
    builder.structure_type(s1.structure_type());
    builder.width(s1.width().max(s2.width()));

    // TODO: Handle base structures (man we really should have just made those regular members)
    let mut members: BTreeMap<u64, (String, Ref<Type>)> = BTreeMap::new();
    let mut merge_into_map = |s: &Structure| {
        for m in &s.members() {
            members
                .entry(m.offset)
                .and_modify(|(_existing_name, existing_ty)| {
                    // Update type if merge succeeds
                    if let Some(merged) = merge_recursive(existing_ty, &m.ty.contents) {
                        *existing_ty = merged;
                    }
                })
                .or_insert_with(|| (m.name.clone(), m.ty.contents.to_owned()));
        }
    };

    merge_into_map(s1);
    merge_into_map(s2);

    for (offset, (name, ty)) in members {
        builder.insert(
            &ty,
            &name,
            offset,
            false,
            MemberAccess::PublicAccess,
            MemberScope::NoScope,
        );
    }

    Some(builder.finalize())
}

fn merge_enumerations(e1: &Enumeration, e2: &Enumeration) -> Option<Ref<Enumeration>> {
    let mut mapped_members = HashMap::new();
    for m in &e1.members() {
        mapped_members.insert(m.name.clone(), m.value);
    }
    for m in &e2.members() {
        mapped_members.insert(m.name.clone(), m.value);
    }

    let mut builder = EnumerationBuilder::new();
    for (name, value) in mapped_members {
        builder.insert(&name, value);
    }
    Some(builder.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use binaryninja::headless::Session;

    #[test]
    fn test_merge_integers() {
        let _session = Session::new().expect("Failed to initialize session");
        let t1 = Type::int(4, true); // int32_t
        let t2 = Type::int(4, false); // uint32_t (if conf is same, first wins? or default?)

        // Construct specific confidence to test strict merging logic
        // t3 is signed with 0 confidence
        let t3 = Type::named_int(4, false, "weak_uint");
        // t4 is signed with 255 confidence
        let t4 = Type::named_int(4, true, "strong_int");

        let merged = merge_types(&[t3, t4]).expect("Merge failed");
        assert!(merged.is_signed().contents); // Stronger confidence should win
        assert_eq!(merged.width(), 4);
    }

    #[test]
    fn test_merge_void_wildcard() {
        let _session = Session::new().expect("Failed to initialize session");
        let t_void = Type::void();
        let t_int = Type::int(4, true);

        // Void + Int -> Int
        let merged1 = merge_types(&[t_void.clone(), t_int.clone()]).unwrap();
        assert_eq!(merged1.type_class(), TypeClass::IntegerTypeClass);

        // Int + Void -> Int
        let merged2 = merge_types(&[t_int, t_void]).unwrap();
        assert_eq!(merged2.type_class(), TypeClass::IntegerTypeClass);
    }

    #[test]
    fn test_merge_structures_union_members() {
        let _session = Session::new().expect("Failed to initialize session");

        // Struct A: { 0: int32 }
        let mut b1 = StructureBuilder::new();
        b1.insert(
            &Type::int(4, true),
            "a",
            0,
            false,
            MemberAccess::PublicAccess,
            MemberScope::NoScope,
        );
        let s1 = Type::structure(&b1.finalize());

        // Struct B: { 4: float }
        let mut b2 = StructureBuilder::new();
        b2.insert(
            &Type::float(8),
            "b",
            4,
            false,
            MemberAccess::PublicAccess,
            MemberScope::NoScope,
        );
        let s2 = Type::structure(&b2.finalize());

        let merged_ty = merge_types(&[s1, s2]).expect("Struct merge failed");
        let merged_struct = merged_ty.get_structure().unwrap();
        let members = merged_struct.members();

        assert_eq!(members.len(), 2);
        // Members are sorted by offset
        assert_eq!(members[0].offset, 0);
        assert_eq!(
            members[0].ty.contents.type_class(),
            TypeClass::IntegerTypeClass
        );
        assert_eq!(members[1].offset, 4);
        assert_eq!(
            members[1].ty.contents.type_class(),
            TypeClass::FloatTypeClass
        );
    }

    #[test]
    fn test_merge_structures_overlap_conflict() {
        let _session = Session::new().expect("Failed to initialize session");

        // Struct A: { 0: int32 }
        let mut b1 = StructureBuilder::new();
        b1.insert(
            &Type::int(4, true),
            "a",
            0,
            false,
            MemberAccess::PublicAccess,
            MemberScope::NoScope,
        );
        let s1 = Type::structure(&b1.finalize());

        // Struct B: { 0: float } -> Conflict with A
        let mut b2 = StructureBuilder::new();
        b2.insert(
            &Type::float(4),
            "b",
            0,
            false,
            MemberAccess::PublicAccess,
            MemberScope::NoScope,
        );
        let s2 = Type::structure(&b2.finalize());

        let merged_ty = merge_types(&[s1, s2]).expect("Struct merge failed");
        let merged_struct = merged_ty.get_structure().unwrap();
        let members = merged_struct.members();

        // Best effort: Keep existing if incompatible.
        // Since s1 was first, it keeps int32.
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].offset, 0);
        assert_eq!(
            members[0].ty.contents.type_class(),
            TypeClass::IntegerTypeClass
        );
    }

    #[test]
    fn test_merge_pointers() {
        let _session = Session::new().expect("Failed to initialize session");
        // void*
        let p1 = Type::pointer_of_width(&Type::void(), 4, false, false, None);
        // int32*
        let p2 = Type::pointer_of_width(&Type::int(4, true), 4, false, false, None);

        let merged = merge_types(&[p1, p2]).unwrap();
        assert_eq!(merged.type_class(), TypeClass::PointerTypeClass);

        let target = merged.target().unwrap();
        // void + int -> int
        assert_eq!(target.contents.type_class(), TypeClass::IntegerTypeClass);
    }

    #[test]
    fn test_merge_structures_name_priority() {
        let _session = Session::new().expect("Failed to initialize session");

        // Struct 1: { 0: "original_name" (int) }
        let mut b1 = StructureBuilder::new();
        b1.insert(
            &Type::int(4, true),
            "original_name",
            0,
            false,
            MemberAccess::PublicAccess,
            MemberScope::NoScope,
        );
        let s1 = Type::structure(&b1.finalize());

        // Struct 2: { 0: "conflict_name" (int), 4: "new_field" (int) }
        let mut b2 = StructureBuilder::new();
        b2.insert(
            &Type::int(4, true),
            "conflict_name", // Should be ignored in favor of "original_name"
            0,
            false,
            MemberAccess::PublicAccess,
            MemberScope::NoScope,
        );
        b2.insert(
            &Type::int(4, true),
            "new_field",
            4,
            false,
            MemberAccess::PublicAccess,
            MemberScope::NoScope,
        );
        let s2 = Type::structure(&b2.finalize());

        let merged_ty = merge_types(&[s1, s2]).expect("Struct merge failed");
        let merged_struct = merged_ty.get_structure().unwrap();
        let members = merged_struct.members();

        assert_eq!(members.len(), 2);

        // Verify offset 0 kept the name from s1
        let m0 = members.iter().find(|m| m.offset == 0).unwrap();
        assert_eq!(m0.name, "original_name");

        // Verify offset 4 was added with its name from s2
        let m4 = members.iter().find(|m| m.offset == 4).unwrap();
        assert_eq!(m4.name, "new_field");
    }
}
