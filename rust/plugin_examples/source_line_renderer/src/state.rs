use binaryninja::binary_view::{BinaryView, BinaryViewBase};
use binaryninja::Endianness;
use gimli::{DebugInfoOffset, RunTimeEndian, UnitSectionOffset};
use std::borrow::Cow;
use std::collections::BTreeMap;

pub struct DebugLineInfo {
    pub file: String,
    pub line_number: u64,
}

impl std::fmt::Display for DebugLineInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.file, self.line_number)
    }
}

pub struct DebugLineState {
    sections: gimli::DwarfSections<Cow<'static, [u8]>>,
    endian: RunTimeEndian,
    address_mapping: BTreeMap<u64, UnitSectionOffset>,
}

impl DebugLineState {
    // TODO: Support supplementary files and networked files.
    pub fn new(view: &BinaryView) -> Result<Self, Box<dyn std::error::Error>> {
        let section_reader =
            |name: &str| -> Result<Cow<'static, [u8]>, Box<dyn std::error::Error>> {
                let mut section = view.section_by_name(name);
                if section.is_none() {
                    // Looks like macho uses underscores instead of dots for section names.
                    let alt_name = name.replace(".", "__");
                    section = view.section_by_name(alt_name);
                }

                match section {
                    Some(section) => Ok(Cow::Owned(view.read_vec(section.start(), section.len()))),
                    // TODO: Instead of failing, we return empty section so we can continue.
                    None => Ok(Cow::Owned(Vec::new())),
                }
            };

        let loader = |section: gimli::SectionId| section_reader(section.name());
        let dwarf_sections = gimli::DwarfSections::load(loader)?;

        let endian = match view.default_endianness() {
            Endianness::LittleEndian => RunTimeEndian::Little,
            Endianness::BigEndian => RunTimeEndian::Big,
        };

        let borrow_section = |section| gimli::EndianSlice::new(Cow::as_ref(section), endian);
        let dwarf = dwarf_sections.borrow(borrow_section);

        // TODO: The row.address() will not be adjusted for the view image base.
        // let base_address = view.image_base();
        let mut address_mapping = BTreeMap::new();
        let mut units = dwarf.units();
        while let Ok(Some(unit_header)) = units.next() {
            let Ok(unit) = dwarf.unit(unit_header) else {
                continue;
            };
            let Some(line_program) = unit.line_program.as_ref() else {
                continue;
            };

            let mut program_rows = line_program.clone().rows();
            while let Ok(Some((_, row))) = program_rows.next_row() {
                if row.end_sequence() {
                    continue;
                }
                address_mapping.insert(row.address(), unit_header.offset());
            }
        }

        Ok(Self {
            sections: dwarf_sections,
            endian,
            address_mapping,
        })
    }

    pub fn line_info(&self, address: u64) -> Option<DebugLineInfo> {
        // TODO: This can approximte the lie number, and should be more refined before shipping, most of
        // TODO: it to do with the address mapping being a tree and we selecting for the closest.
        let (_, unit_offset) = self.address_mapping.range(..=address).next_back()?;
        let borrow_section = |section| gimli::EndianSlice::new(Cow::as_ref(section), self.endian);
        let dwarf = self.sections.borrow(borrow_section);
        let unit_offset = DebugInfoOffset(unit_offset.0);
        let unit_header = dwarf.debug_info.header_from_offset(unit_offset).ok()?;
        let unit = dwarf.unit(unit_header).ok()?;

        let line_program = unit.line_program.as_ref()?;
        let mut rows = line_program.clone().rows();

        let mut current_file_index = 0;
        let mut current_line = None;
        while let Ok(Some((_, row))) = rows.next_row() {
            if row.address() > address {
                break;
            }
            if row.end_sequence() {
                continue;
            }
            current_file_index = row.file_index();
            if let Some(line) = row.line() {
                current_line = Some(line.get());
            }
        }

        let header = line_program.header();
        let file = header.file(current_file_index)?;
        let mut file_name = "<unknown file>".to_string();
        if let Ok(attr_str) = dwarf.attr_string(&unit, file.path_name()) {
            file_name = attr_str.to_string_lossy().into_owned();
        }

        Some(DebugLineInfo {
            file: file_name,
            line_number: current_line?,
        })
    }
}
