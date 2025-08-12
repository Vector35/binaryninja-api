mod types;
use std::borrow::Cow;
use std::io::{BufRead, Cursor, Seek};

use idb_rs::id1::ID1Section;
use idb_rs::id2::{ID2Section, ID2SectionVariants};
use idb_rs::{IDAKind, IDAUsize, IDBFormat};
use types::*;
mod addr_info;
use addr_info::*;

use binaryninja::binary_view::{BinaryView, BinaryViewBase, BinaryViewExt};
use binaryninja::debuginfo::{
    CustomDebugInfoParser, DebugFunctionInfo, DebugInfo, DebugInfoParser,
};

use idb_rs::id0::{ID0Section, ID0SectionVariants};
use idb_rs::til::section::TILSection;
use idb_rs::til::TypeVariant as TILTypeVariant;

use log::{error, trace, warn, LevelFilter};

use anyhow::{anyhow, Result};
use binaryninja::logger::Logger;

struct IDBDebugInfoParser;
impl CustomDebugInfoParser for IDBDebugInfoParser {
    fn is_valid(&self, view: &BinaryView) -> bool {
        if let Some(project_file) = view.file().project_file() {
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
        if let Some(project_file) = view.file().project_file() {
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
            // TODO check if this is truly a EoF hit, `self.bv.len()` is not
            // reliable, it's returning a size bigger then the original file.
            return Ok(0);
        }
        let len = BinaryView::read(self.bv, buf, self.offset);
        self.offset += u64::try_from(len).unwrap();
        Ok(len)
    }
}

impl std::io::Seek for BinaryViewReader<'_> {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        let new_offset = match pos {
            std::io::SeekFrom::Start(offset) => Some(offset),
            std::io::SeekFrom::End(end) => self.bv.len().checked_add_signed(end),
            std::io::SeekFrom::Current(next) => self.offset.checked_add_signed(next),
        };
        let new_offset = new_offset.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Unable to calculate new offset in BinaryViewReader",
            )
        })?;
        if !self.bv.offset_valid(new_offset) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Try to set invalid offset in BinaryViewReader",
            ));
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
    let mut file = std::io::BufReader::new(file);
    let idb_kind = idb_rs::identify_idb_file(&mut file)?;
    match idb_kind {
        idb_rs::IDBFormats::Separated(sep) => {
            parse_idb_info_format(debug_info, bv, debug_file, sep, file, progress)
        }
        idb_rs::IDBFormats::InlineUncompressed(inline) => {
            parse_idb_info_format(debug_info, bv, debug_file, inline, file, progress)
        }
        idb_rs::IDBFormats::InlineCompressed(compressed) => {
            let mut buf = vec![];
            let inline = compressed.decompress_into_memory(&mut file, &mut buf)?;
            parse_idb_info_format(
                debug_info,
                bv,
                debug_file,
                inline,
                Cursor::new(&buf[..]),
                progress,
            )
        }
    }
}

fn parse_idb_info_format(
    debug_info: &mut DebugInfo,
    bv: &BinaryView,
    debug_file: &BinaryView,
    format: impl IDBFormat,
    mut idb_data: impl BufRead + Seek,
    progress: Box<dyn Fn(usize, usize) -> Result<(), ()>>,
) -> Result<()> {
    let Some(id0_idx) = format.id0_location() else {
        return Err(anyhow!("Unable to find the ID0 section"));
    };
    let Some(id1_idx) = format.id1_location() else {
        return Err(anyhow!("Unable to find the ID1 section"));
    };
    let id2_idx = format.id2_location();

    if let Some(til_idx) = format.til_location() {
        trace!("Parsing the TIL section");
        let til = format.read_til(&mut idb_data, til_idx)?;
        // progress 0%-50%
        import_til_section(debug_info, debug_file, &til, progress)?;
    };

    let id0 = format.read_id0(&mut idb_data, id0_idx)?;
    let id1 = format.read_id1(&mut idb_data, id1_idx)?;
    let id2 = id2_idx
        .map(|id2_idx| format.read_id2(&mut idb_data, id2_idx))
        .transpose()?;

    match (id0, id2) {
        (ID0SectionVariants::IDA32(id0), Some(ID2SectionVariants::IDA32(id2))) => {
            parse_id0_section_info(debug_info, bv, debug_file, &id0, &id1, Some(&id2))?
        }
        (ID0SectionVariants::IDA32(id0), None) => {
            parse_id0_section_info(debug_info, bv, debug_file, &id0, &id1, None)?
        }
        (ID0SectionVariants::IDA64(id0), Some(ID2SectionVariants::IDA64(id2))) => {
            parse_id0_section_info(debug_info, bv, debug_file, &id0, &id1, Some(&id2))?
        }
        (ID0SectionVariants::IDA64(id0), None) => {
            parse_id0_section_info(debug_info, bv, debug_file, &id0, &id1, None)?
        }
        _ => unreachable!(),
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
    let mut file = std::io::BufReader::new(file);
    trace!("Parsing the TIL section");
    let til = TILSection::read(&mut file)?;
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
                    ty.name.as_utf8_lossy(),
                    &ty.og_ty
                );
            }
            TranslateTypeResult::Error(error) => {
                error!(
                    "Unable to parse type `{}`: {error}",
                    ty.name.as_utf8_lossy(),
                );
            }
            TranslateTypeResult::PartiallyTranslated(_, error) => {
                if let Some(error) = error {
                    error!(
                        "Unable to parse type `{}` correctly: {error}",
                        ty.name.as_utf8_lossy(),
                    );
                } else {
                    warn!(
                        "Type `{}` maybe not be fully translated",
                        ty.name.as_utf8_lossy(),
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
            if !debug_info.add_type(&ty.name.as_utf8_lossy(), bn_ty, &[/* TODO */]) {
                error!("Unable to add type `{}`", ty.name.as_utf8_lossy())
            }
        }
    }

    // add a second time to fix the references LOL
    for ty in &types {
        if let TranslateTypeResult::Translated(bn_ty)
        | TranslateTypeResult::PartiallyTranslated(bn_ty, _) = &ty.ty
        {
            if !debug_info.add_type(&ty.name.as_utf8_lossy(), bn_ty, &[/* TODO */]) {
                error!("Unable to fix type `{}`", ty.name.as_utf8_lossy())
            }
        }
    }

    Ok(())
}

fn parse_id0_section_info<K: IDAKind>(
    debug_info: &mut DebugInfo,
    bv: &BinaryView,
    debug_file: &BinaryView,
    id0: &ID0Section<K>,
    id1: &ID1Section,
    id2: Option<&ID2Section<K>>,
) -> Result<()> {
    let ida_info_idx = id0.root_node()?;
    let ida_info = id0.ida_info(ida_info_idx)?;
    let idb_baseaddr = ida_info.addresses.loading_base.into_u64();
    let bv_baseaddr = bv.start();
    let netdelta = ida_info.netdelta();
    // just addr this value to the address to translate from ida to bn
    // NOTE this delta could wrap here and while using translating
    let addr_delta = bv_baseaddr.wrapping_sub(idb_baseaddr);

    for (idb_addr, info) in get_info(id0, id1, id2, netdelta)? {
        let addr = addr_delta.wrapping_add(idb_addr.into_raw().into_u64());
        // just in case we change this struct in the future, this line will for us to review this code
        // TODO merge this data with folder locations
        let AddrInfo {
            comments,
            label,
            ty,
        } = info;
        // TODO set comments to address here
        for function in &bv.functions_containing(addr) {
            function.set_comment_at(addr, &String::from_utf8_lossy(&comments.join(&b"\n"[..])));
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

        let label: Option<Cow<'_, str>> =
            label.as_ref().map(Cow::as_ref).map(String::from_utf8_lossy);
        match (label, &ty, bnty) {
            (label, Some(ty), bnty) if matches!(&ty.type_variant, TILTypeVariant::Function(_)) => {
                if bnty.is_none() {
                    error!("Unable to convert the function type at {addr:#x}",)
                }
                if !debug_info.add_function(&DebugFunctionInfo::new(
                    None,
                    None,
                    label.map(Cow::into_owned),
                    bnty,
                    Some(addr),
                    None,
                    vec![],
                    vec![],
                )) {
                    error!("Unable to add the function at {addr:#x}")
                }
            }
            (label, Some(_ty), Some(bnty)) => {
                if !debug_info.add_data_variable(addr, &bnty, label.as_ref().map(Cow::as_ref), &[])
                {
                    error!("Unable to add the type at {addr:#x}")
                }
            }
            (label, Some(_ty), None) => {
                // TODO types come from the TIL sections, can we make all types be just NamedTypes?
                error!("Unable to convert type {addr:#x}");
                // TODO how to add a label without a type associated with it?
                if let Some(name) = label {
                    if !debug_info.add_data_variable(
                        addr,
                        &binaryninja::types::Type::void(),
                        Some(&name),
                        &[],
                    ) {
                        error!("Unable to add the label at {addr:#x}")
                    }
                }
            }
            (Some(name), None, None) => {
                // TODO how to add a label without a type associated with it?
                if !debug_info.add_data_variable(
                    addr,
                    &binaryninja::types::Type::void(),
                    Some(&name),
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
