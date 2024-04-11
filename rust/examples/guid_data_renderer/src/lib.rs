use std::io::{Seek, SeekFrom};

use binaryninja::binaryreader::BinaryReader;
use binaryninja::binaryview::{BinaryView, BinaryViewBase, BinaryViewExt};
use binaryninja::datarenderer::{register_datarenderer, DataRenderer};
use binaryninja::disassembly::{
    DisassemblyTextLine, InstructionTextToken, InstructionTextTokenContents,
};
use binaryninja::types::{Type, TypeClass, TypeContext};

struct FuidDataRenderer;

impl DataRenderer for FuidDataRenderer {
    fn is_valid_for_data(
        &mut self,
        view: &BinaryView,
        addr: u64,
        data_type: &Type,
        _type_ctx: &[TypeContext],
    ) -> bool {
        if view.default_platform().is_none() {
            return false;
        }
        let Ok(ntr) = data_type.registered_name() else {
            return false;
        };

        let is_name_guid = ntr.name().string() == "_GUID";
        let is_struct = data_type.type_class() == TypeClass::StructureTypeClass;

        is_name_guid && is_struct && view.offset_valid(addr) && view.offset_valid(addr + 16)
    }

    fn get_lines_for_data(
        &mut self,
        view: &BinaryView,
        addr: u64,
        _data_type: &Type,
        prefix: &[InstructionTextToken],
        _width: usize,
        _type_ctx: &[TypeContext],
    ) -> Vec<DisassemblyTextLine> {
        let mut result = Vec::with_capacity(3);
        let line = DisassemblyTextLine::from(prefix.to_vec());
        result.push(line);

        let mut reader = BinaryReader::new(view, view.default_endianness());
        reader.seek(SeekFrom::Start(addr)).unwrap();
        let data1 = reader.read_u32().unwrap();
        let data2 = reader.read_u16().unwrap();
        let data3 = reader.read_u16().unwrap();
        let data_end = reader.read_u64_be().unwrap();
        let data4 = (data_end >> 48) & 0xffff;
        let data5 = data_end & 0x0000FFFFFFFFFFFF;
        let guid_str = format!("{data1:08x}-{data2:04x}-{data3:04x}-{data4:04x}-{data5:012x}");

        use InstructionTextTokenContents::*;
        result.push(DisassemblyTextLine::from(vec![
            InstructionTextToken::new("  [Guid(\"", Text),
            InstructionTextToken::new(&guid_str, Text),
            InstructionTextToken::new("\")]", Text),
        ]));

        // Check for type name by GUID and add it to the display
        if let Some(type_name) = view.get_type_name_by_id(&guid_str) {
            result.push(DisassemblyTextLine::from(vec![
                InstructionTextToken::new("  interface ", Text),
                InstructionTextToken::new(&type_name.to_string(), TypeName),
            ]));
        }

        result
    }
}

#[no_mangle]
pub extern "C" fn CorePluginInit() -> bool {
    register_datarenderer(|_h| FuidDataRenderer);
    true
}
