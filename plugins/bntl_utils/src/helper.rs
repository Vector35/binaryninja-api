use binaryninja::rc::Ref;
use binaryninja::types::{NamedTypeReference, Type, TypeClass, TypeLibrary};
use std::path::Path;
use walkdir::WalkDir;

pub fn path_to_type_libraries(path: &Path) -> Vec<Ref<TypeLibrary>> {
    WalkDir::new(path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "bntl"))
        .filter_map(|e| TypeLibrary::load_from_file(e.path()))
        .collect::<Vec<_>>()
}

pub fn visit_type_reference(ty: &Type, visit: &mut impl FnMut(&NamedTypeReference)) {
    if let Some(ntr) = ty.get_named_type_reference() {
        visit(&ntr);
    }
    match ty.type_class() {
        TypeClass::StructureTypeClass => {
            let structure = ty.get_structure().unwrap();
            for field in structure.members() {
                visit_type_reference(&field.ty.contents, visit);
            }
            for base in structure.base_structures() {
                visit(&base.ty);
            }
        }
        TypeClass::PointerTypeClass => {
            visit_type_reference(&ty.child_type().unwrap().contents, visit);
        }
        TypeClass::ArrayTypeClass => {
            visit_type_reference(&ty.child_type().unwrap().contents, visit);
        }
        TypeClass::FunctionTypeClass => {
            let params = ty.parameters().unwrap();
            for param in params {
                visit_type_reference(&param.ty.contents, visit);
            }
            visit_type_reference(&ty.return_value().unwrap().contents, visit);
        }
        _ => {}
    }
}
