mod types;
use std::fs::File;
use std::io::BufReader;

use binaryninja::background_task::BackgroundTask;
use binaryninja::command::Command;
use binaryninja::string::BnStrCompatible;
use binaryninja::type_library::TypeLibrary;
use binaryninja::types::QualifiedName;
use types::*;
mod addr_info;
use addr_info::*;

use binaryninja::binary_view::{BinaryView, BinaryViewBase, BinaryViewExt};
use binaryninja::debuginfo::{
    CustomDebugInfoParser, DebugFunctionInfo, DebugInfo, DebugInfoParser,
};

use idb_rs::id0::{ID0Section, IDBParam1, IDBParam2};
use idb_rs::til::section::TILSection;
use idb_rs::til::TypeVariant as TILTypeVariant;

use log::{error, trace, warn, LevelFilter};

use anyhow::{anyhow, Context, Result};
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
        match import_idb_info(debug_info, bv, debug_file, progress) {
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
        bv: &BinaryView,
        debug_file: &BinaryView,
        progress: Box<dyn Fn(usize, usize) -> Result<(), ()>>,
    ) -> bool {
        match import_til_info_from_debug_file(debug_info, bv, debug_file, progress) {
            Ok(()) => true,
            Err(error) => {
                error!("Unable to parse TIL file: {error}");
                false
            }
        }
    }
}

struct LoadTilFile;

impl Command for LoadTilFile {
    fn action(&self, view: &BinaryView) {
        if let Err(error) = background_import_til(view) {
            error!("Unable to convert TIL file: {error}");
        }
    }

    fn valid(&self, _view: &BinaryView) -> bool {
        true
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
            std::io::SeekFrom::End(end) => self.bv.len().checked_add_signed(end),
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

fn import_idb_info<P: Fn(usize, usize) -> Result<(), ()>>(
    debug_info: &mut DebugInfo,
    bv: &BinaryView,
    debug_file: &BinaryView,
    progress: P,
) -> Result<()> {
    trace!("Opening a IDB file");
    let file = BufReader::new(BinaryViewReader {
        bv: debug_file,
        offset: 0,
    });
    trace!("Parsing a IDB file");
    let mut parser = idb_rs::IDBParser::new(file)?;

    if let Some(til_section) = parser.til_section_offset() {
        // TODO handle dependency, create a function for that with closures
        trace!("Parsing the TIL section");
        let til = parser.read_til_section(til_section)?;
        let filename = debug_file.file().filename();
        // TODO progress 0%-50%
        import_til_to_type_library(til, filename, bv, progress)?;
    }

    if let Some(id0_section) = parser.id0_section_offset() {
        trace!("Parsing the ID0 section");
        let id0 = parser.read_id0_section(id0_section)?;
        // TODO progress 50%-100%
        parse_id0_section_info(debug_info, bv, debug_file, &id0)?;
    }

    Ok(())
}

fn import_til_info_from_debug_file<P: Fn(usize, usize) -> Result<(), ()>>(
    _debug_info: &mut DebugInfo,
    bv: &BinaryView,
    debug_file: &BinaryView,
    progress: P,
) -> Result<()> {
    trace!("Opening a TIL file");
    let file = BinaryViewReader {
        bv: debug_file,
        offset: 0,
    };
    let filename = debug_file.file().filename();
    let mut file = std::io::BufReader::new(file);
    let til = TILSection::read(&mut file, idb_rs::IDBSectionCompression::None)?;

    import_til_to_type_library(til, filename, bv, progress)
}

fn background_import_til(view: &BinaryView) -> Result<()> {
    let moved_view = view.to_owned();
    binaryninja::worker_thread::execute_on_worker_thread_interactive(c"Til Import", move || {
        if let Err(err) = interactive_import_til(&moved_view) {
            error!("Unable to import TIL: {err}");
        }
    });
    Ok(())
}

fn interactive_import_til(view: &BinaryView) -> Result<()> {
    let bt = BackgroundTask::new("Import TIL", true);
    let Some(file) =
        binaryninja::interaction::get_open_filename_input("Select a .til file", "*.til")
    else {
        return Ok(());
    };

    let filename = file.file_name().unwrap().to_string_lossy();
    let mut file = BufReader::new(File::open(&file)?);
    let til = TILSection::read(&mut file, idb_rs::IDBSectionCompression::None)?;

    let progress = |current, total| {
        if bt.is_cancelled() {
            return Err(());
        }
        bt.set_progress_text(format!(
            "Import TIL progress: {}%",
            ((current as f32 / total as f32) * 100f32) as u32
        ));
        Ok(())
    };
    import_til_to_type_library(til, filename, view, progress)?;
    bt.finish();
    Ok(())
}

fn import_til_to_type_library<S, P>(
    til: TILSection,
    type_lib_name: S,
    view: &BinaryView,
    progress: P,
) -> Result<()>
where
    S: BnStrCompatible,
    P: Fn(usize, usize) -> Result<(), ()>,
{
    let default_arch = view
        .default_arch()
        .ok_or_else(|| anyhow!("Unable to get the default arch"))?;
    let mut type_lib = TypeLibrary::new(default_arch, type_lib_name);

    // TODO create a background task to not freeze bn, also create a progress
    // user interface feedback
    import_til_file(til, view, &mut type_lib, progress)?;
    if !type_lib.finalize() {
        return Err(anyhow!("Unable to finalize TypeLibrary"));
    };
    view.add_type_library(&type_lib);
    Ok(())
}

fn import_til_file<P: Fn(usize, usize) -> Result<(), ()>>(
    til: TILSection,
    view: &BinaryView,
    type_library: &mut TypeLibrary,
    progress: P,
) -> Result<()> {
    trace!("Parsing the TIL section");
    // TODO
    let mut tils = vec![til];
    import_til_dependency(&mut tils, 0, &progress)?;
    import_til_section(type_library, view, &tils, progress)
}

fn import_til_dependency<P: Fn(usize, usize) -> Result<(), ()>>(
    tils: &mut Vec<TILSection>,
    til_idx: usize,
    _progress: &P,
) -> Result<()> {
    let names: Vec<_> = tils[til_idx].header.dependencies.to_vec();
    for name in names {
        let name = name.as_utf8_lossy();
        let message = format!("Select the dependency \"{name}.til\"",);
        let Some(dep_file) = binaryninja::interaction::get_open_filename_input(&message, "*.til")
        else {
            return Err(anyhow!("Unable to get the dependency {name}"));
        };

        let mut dep_file = BufReader::new(File::open(&dep_file)?);
        let dep_til = TILSection::read(&mut dep_file, idb_rs::IDBSectionCompression::None)?;
        tils.push(dep_til);
    }
    if tils.len() > til_idx + 1 {
        // add dependencies of dependencies
        // TODO handle progress
        // TODO identify ciclycal dependencies
        import_til_dependency(tils, til_idx + 1, _progress)
            .context("While importing dependency {name}")?;
    }
    Ok(())
}

fn import_til_section<P: Fn(usize, usize) -> Result<(), ()>>(
    type_library: &mut TypeLibrary,
    view: &BinaryView,
    tils: &[TILSection],
    progress: P,
) -> Result<()> {
    let default_arch = view
        .default_arch()
        .ok_or_else(|| anyhow!("Unable to get the default arch"))?;
    let types = types::translate_til_types(default_arch, tils, progress)?;

    // print any errors
    print_til_convertsion_errors(&types)?;

    // add all type to the type library
    for ty in &types {
        if let TranslateTypeResult::Translated(bn_ty)
        | TranslateTypeResult::PartiallyTranslated(bn_ty, _) = &ty.ty
        {
            let name = QualifiedName::new(vec![ty.name.as_utf8_lossy().to_string()]);
            type_library.add_named_type(name, bn_ty);
        }
    }

    Ok(())
}

fn print_til_convertsion_errors(types: &[TranslatesIDBType]) -> Result<()> {
    for ty in types {
        match &ty.ty {
            TranslateTypeResult::NotYet => {
                // NOTE this should be unreachable
                error!(
                    "Unable to finish parsing type `{}`",
                    ty.name.as_utf8_lossy(),
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
                        "Unable to correctly parse type `{}`: {error}",
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
            (_, Some(ty), bnty) if matches!(&ty.type_variant, TILTypeVariant::Function(_)) => {
                if bnty.is_none() {
                    error!("Unable to convert the function type at {addr:#x}",)
                }
                if !debug_info.add_function(&DebugFunctionInfo::new(
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
    binaryninja::command::register_command(
        c"Import TIL types",
        c"Convert and import a TIL file into a TypeLibrary",
        LoadTilFile,
    );
    DebugInfoParser::register(c"IDB Parser", IDBDebugInfoParser);
    DebugInfoParser::register(c"TIL Parser", TILDebugInfoParser);
    true
}
