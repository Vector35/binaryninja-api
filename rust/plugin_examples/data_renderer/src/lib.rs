use binaryninja::binary_view::{BinaryView, BinaryViewBase};
use binaryninja::data_renderer::{
    register_data_renderer, CustomDataRenderer, RegistrationType, TypeContext,
};
use binaryninja::disassembly::{
    DisassemblyTextLine, InstructionTextToken, InstructionTextTokenKind,
};
use binaryninja::types::{Type, TypeClass};
use uuid::Uuid;

struct UuidDataRenderer {}

impl CustomDataRenderer for UuidDataRenderer {
    const REGISTRATION_TYPE: RegistrationType = RegistrationType::Specific;

    fn is_valid_for_data(
        &self,
        _view: &BinaryView,
        _addr: u64,
        type_: &Type,
        types: &[TypeContext],
    ) -> bool {
        // We only want to render arrays with a size of 16 elements
        if type_.type_class() != TypeClass::ArrayTypeClass {
            return false;
        }
        if type_.count() != 0x10 {
            return false;
        }

        // The array elements must be of the type uint8_t
        let Some(element_type_conf) = type_.element_type() else {
            return false;
        };
        let element_type = element_type_conf.contents;
        if element_type.type_class() != TypeClass::IntegerTypeClass {
            return false;
        }
        if element_type.width() != 1 {
            return false;
        }

        // The array should be embedded in a named type reference with the id macho:["uuid"]
        for type_ctx in types {
            if type_ctx.ty().type_class() != TypeClass::NamedTypeReferenceClass {
                continue;
            }

            let Some(name_ref) = type_ctx.ty().get_named_type_reference() else {
                continue;
            };

            if name_ref.id() == "macho:[\"uuid\"]" {
                return true;
            }
        }

        false
    }

    fn lines_for_data(
        &self,
        view: &BinaryView,
        addr: u64,
        _type_: &Type,
        prefix: Vec<InstructionTextToken>,
        _width: usize,
        _types_ctx: &[TypeContext],
        _language: &str,
    ) -> Vec<DisassemblyTextLine> {
        let mut tokens = prefix.clone();

        let mut buf = [0u8; 0x10];
        let bytes_read = view.read(&mut buf, addr);

        // Make sure that we've read all UUID bytes and convert them to token
        if bytes_read == 0x10 {
            tokens.extend([
                InstructionTextToken::new("UUID(\"", InstructionTextTokenKind::Text),
                InstructionTextToken::new(
                    Uuid::from_bytes(buf).to_string(),
                    InstructionTextTokenKind::String { value: 0 },
                ),
                InstructionTextToken::new("\")", InstructionTextTokenKind::Text),
            ]);
        } else {
            tokens.push(InstructionTextToken::new(
                "error: cannot read 0x10 bytes",
                InstructionTextTokenKind::Annotation,
            ));
        }

        vec![DisassemblyTextLine::new_with_addr(tokens, addr)]
    }
}

/// # Safety
/// This function is called from Binary Ninja once to initialize the plugin.
#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CorePluginInit() -> bool {
    // Initialize logging
    binaryninja::tracing_init!();
    tracing::info!("Core plugin initialized");

    // Register data renderer
    register_data_renderer(UuidDataRenderer {});

    true
}
