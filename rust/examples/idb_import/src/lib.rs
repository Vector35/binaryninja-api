mod types;
use types::*;
mod addr_info;
use addr_info::*;

use binaryninja::binaryview::{BinaryView, BinaryViewBase, BinaryViewExt};
use binaryninja::debuginfo::{
    CustomDebugInfoParser, DebugFunctionInfo, DebugInfo, DebugInfoParser,
};

use idb_rs::id0::{ID0Section, IDBParam1, IDBParam2};
use idb_rs::til::section::TILSection;
use idb_rs::til::Type as TILType;

use log::{error, trace, warn, LevelFilter};

use anyhow::Result;
use binaryninja::logger::Logger;

struct IDBDebugInfoParser;
impl CustomDebugInfoParser for IDBDebugInfoParser {
    fn is_valid(&self, view: &BinaryView) -> bool {
        if let Some(project_file) = view.file().get_project_file() {
            project_file.name().as_str().ends_with(".i64")
                || project_file.name().as_str().ends_with(".idb")
        } else {
            view.file().filename().as_str().ends_with(".i64")
                || view.file().filename().as_str().ends_with(".idb")
        }
    }

    fn parse_info(
        &self,
        debug_info: &mut DebugInfo,
        bv: &BinaryView,
        debug_file: &BinaryView,
        progress: Box<dyn Fn(usize, usize) -> Result<(), ()>>,
    ) -> bool {
        match parse_idb_info(debug_info, bv, debug_file, progress) {
            Ok(()) => true,
            Err(error) => {
                error!("Unable to parse IDB file: {error}");
                false
            }
        }
    }
}

struct TILDebugInfoParser;
impl CustomDebugInfoParser for TILDebugInfoParser {
    fn is_valid(&self, view: &BinaryView) -> bool {
        if let Some(project_file) = view.file().get_project_file() {
            project_file.name().as_str().ends_with(".til")
        } else {
            view.file().filename().as_str().ends_with(".til")
        }
    }

    fn parse_info(
        &self,
        debug_info: &mut DebugInfo,
        _bv: &BinaryView,
        debug_file: &BinaryView,
        progress: Box<dyn Fn(usize, usize) -> Result<(), ()>>,
    ) -> bool {
        match parse_til_info(debug_info, debug_file, progress) {
            Ok(()) => true,
            Err(error) => {
                error!("Unable to parse TIL file: {error}");
                false
            }
        }
    }
}

struct BinaryViewReader<'a> {
    bv: &'a BinaryView,
    offset: u64,
}
impl std::io::Read for BinaryViewReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.bv.offset_valid(self.offset) {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, ""));
        }
        let len = self.bv.read(buf, self.offset);
        self.offset += u64::try_from(len).unwrap();
        Ok(len)
    }
}

impl std::io::Seek for BinaryViewReader<'_> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        let new_offset = match pos {
            std::io::SeekFrom::Start(offset) => Some(offset),
            std::io::SeekFrom::End(end) => u64::try_from(self.bv.len())
                .unwrap()
                .checked_add_signed(end),
            std::io::SeekFrom::Current(next) => self.offset.checked_add_signed(next),
        };
        let new_offset =
            new_offset.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, ""))?;
        if !self.bv.offset_valid(new_offset) {
            return Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, ""));
        }
        self.offset = new_offset;
        Ok(new_offset)
    }
}

fn parse_idb_info(
    debug_info: &mut DebugInfo,
    bv: &BinaryView,
    debug_file: &BinaryView,
    progress: Box<dyn Fn(usize, usize) -> Result<(), ()>>,
) -> Result<()> {
    trace!("Opening a IDB file");
    let file = BinaryViewReader {
        bv: debug_file,
        offset: 0,
    };
    trace!("Parsing a IDB file");
    let file = std::io::BufReader::new(file);
    let mut parser = idb_rs::IDBParser::new(file)?;
    if let Some(til_section) = parser.til_section_offset() {
        trace!("Parsing the TIL section");
        let til = parser.read_til_section(til_section)?;
        // progress 0%-50%
        import_til_section(debug_info, debug_file, &til, progress)?;
    }

    if let Some(id0_section) = parser.id0_section_offset() {
        trace!("Parsing the ID0 section");
        let id0 = parser.read_id0_section(id0_section)?;
        // progress 50%-100%
        parse_id0_section_info(debug_info, bv, debug_file, &id0)?;
    }

    Ok(())
}

fn parse_til_info(
    debug_info: &mut DebugInfo,
    debug_file: &BinaryView,
    progress: Box<dyn Fn(usize, usize) -> Result<(), ()>>,
) -> Result<()> {
    trace!("Opening a TIL file");
    let file = BinaryViewReader {
        bv: debug_file,
        offset: 0,
    };
    let file = std::io::BufReader::new(file);
    trace!("Parsing the TIL section");
    let til = TILSection::parse(file)?;
    import_til_section(debug_info, debug_file, &til, progress)
}

pub fn import_til_section(
    debug_info: &mut DebugInfo,
    debug_file: &BinaryView,
    til: &TILSection,
    progress: impl Fn(usize, usize) -> Result<(), ()>,
) -> Result<()> {
    let types = types::translate_til_types(debug_file.default_arch().unwrap(), til, progress)?;

    // print any errors
    for ty in &types {
        match &ty.ty {
            TranslateTypeResult::NotYet => {
                panic!(
                    "type could not be processed `{}`: {:#?}",
                    &String::from_utf8_lossy(&ty.name),
                    &ty.og_ty
                );
            }
            TranslateTypeResult::Error(error) => {
                error!(
                    "Unable to parse type `{}`: {error}",
                    &String::from_utf8_lossy(&ty.name)
                );
            }
            TranslateTypeResult::PartiallyTranslated(_, error) => {
                if let Some(error) = error {
                    error!(
                        "Unable to parse type `{}` correctly: {error}",
                        &String::from_utf8_lossy(&ty.name)
                    );
                } else {
                    warn!(
                        "Type `{}` maybe not be fully translated",
                        &String::from_utf8_lossy(&ty.name)
                    );
                }
            }
            TranslateTypeResult::Translated(_) => {}
        };
    }

    // add all type to binary ninja
    for ty in &types {
        if let TranslateTypeResult::Translated(bn_ty)
        | TranslateTypeResult::PartiallyTranslated(bn_ty, _) = &ty.ty
        {
            if !debug_info.add_type(&String::from_utf8_lossy(&ty.name), bn_ty, &[/* TODO */]) {
                error!(
                    "Unable to add type `{}`",
                    &String::from_utf8_lossy(&ty.name)
                )
            }
        }
    }

    // add a second time to fix the references LOL
    for ty in &types {
        if let TranslateTypeResult::Translated(bn_ty)
        | TranslateTypeResult::PartiallyTranslated(bn_ty, _) = &ty.ty
        {
            if !debug_info.add_type(&String::from_utf8_lossy(&ty.name), bn_ty, &[/* TODO */]) {
                error!(
                    "Unable to fix type `{}`",
                    &String::from_utf8_lossy(&ty.name)
                )
            }
        }
    }

    Ok(())
}

fn parse_id0_section_info(
    debug_info: &mut DebugInfo,
    bv: &BinaryView,
    debug_file: &BinaryView,
    id0: &ID0Section,
) -> Result<()> {
    let version = match id0.ida_info()? {
        idb_rs::id0::IDBParam::V1(IDBParam1 { version, .. })
        | idb_rs::id0::IDBParam::V2(IDBParam2 { version, .. }) => version,
    };

    for (addr, info) in get_info(id0, version)? {
        // just in case we change this struct in the future, this line will for us to review this code
        // TODO merge this data with folder locations
        let AddrInfo {
            comments,
            label,
            ty,
        } = info;
        // TODO set comments to address here
        for function in &bv.functions_containing(addr) {
            function.set_comment_at(
                addr,
                String::from_utf8_lossy(&comments.join(&b"\n"[..])).to_string(),
            );
        }

        let bnty = ty
            .as_ref()
            .and_then(|ty| match translate_ephemeral_type(debug_file, ty) {
                TranslateTypeResult::Translated(result) => Some(result),
                TranslateTypeResult::PartiallyTranslated(result, None) => {
                    warn!("Unable to fully translate the type at {addr:#x}");
                    Some(result)
                }
                TranslateTypeResult::NotYet => {
                    error!("Unable to translate the type at {addr:#x}");
                    None
                }
                TranslateTypeResult::PartiallyTranslated(_, Some(bn_type_error))
                | TranslateTypeResult::Error(bn_type_error) => {
                    error!("Unable to translate the type at {addr:#x}: {bn_type_error}",);
                    None
                }
            });

        match (label, &ty, bnty) {
            (_, Some(TILType::Function(_)), bnty) => {
                if bnty.is_none() {
                    error!("Unable to convert the function type at {addr:#x}",)
                }
                if !debug_info.add_function(DebugFunctionInfo::new(
                    None,
                    None,
                    label.map(str::to_string),
                    bnty,
                    Some(addr),
                    None,
                    vec![],
                    vec![],
                )) {
                    error!("Unable to add the function at {addr:#x}")
                }
            }
            (_, Some(_ty), Some(bnty)) => {
                if !debug_info.add_data_variable(addr, &bnty, label, &[]) {
                    error!("Unable to add the type at {addr:#x}")
                }
            }
            (_, Some(_ty), None) => {
                // TODO types come from the TIL sections, can we make all types be just NamedTypes?
                error!("Unable to convert type {addr:#x}");
                // TODO how to add a label without a type associacted with it?
                if let Some(name) = label {
                    if !debug_info.add_data_variable(
                        addr,
                        &binaryninja::types::Type::void(),
                        Some(name),
                        &[],
                    ) {
                        error!("Unable to add the label at {addr:#x}")
                    }
                }
            }
            (Some(name), None, None) => {
                // TODO how to add a label without a type associacted with it?
                if !debug_info.add_data_variable(
                    addr,
                    &binaryninja::types::Type::void(),
                    Some(name),
                    &[],
                ) {
                    error!("Unable to add the label at {addr:#x}")
                }
            }

            // just comments at this address
            (None, None, None) => {}

            (_, None, Some(_)) => unreachable!(),
        }
    }

    Ok(())
}

#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn CorePluginInit() -> bool {
    Logger::new("IDB Import")
        .with_level(LevelFilter::Error)
        .init();
    DebugInfoParser::register("IDB Parser", IDBDebugInfoParser);
    DebugInfoParser::register("TIL Parser", TILDebugInfoParser);
    true
}
