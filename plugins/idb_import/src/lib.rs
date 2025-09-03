mod types;
use std::borrow::Cow;
use std::io::{BufRead, Cursor, Seek};

use binaryninja::architecture::CoreArchitecture;
use idb_rs::id0::segment_register::SrareasIdx;
use idb_rs::id1::ID1Section;
use idb_rs::id2::ID2Section;
use idb_rs::{Address, IDAKind, IDAUsize, IDAVariants, IDBFormat, IDBString};
use types::*;
mod addr_info;
use addr_info::*;

use binaryninja::binary_view::{BinaryView, BinaryViewBase, BinaryViewExt};
use binaryninja::debuginfo::{
    CustomDebugInfoParser, DebugFunctionInfo, DebugInfo, DebugInfoParser,
};

use idb_rs::id0::{ID0Section, RootInfo, SegmentIdx};
use idb_rs::til::section::TILSection;
use idb_rs::til::TypeVariant as TILTypeVariant;

use log::{error, trace, warn, LevelFilter};

use anyhow::{anyhow, ensure, Result};
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
        idb_rs::IDBFormats::Separated(IDAVariants::IDA32(sep32)) => {
            parse_idb_info_format(debug_info, bv, debug_file, sep32, file, progress)
        }
        idb_rs::IDBFormats::Separated(IDAVariants::IDA64(sep64)) => {
            parse_idb_info_format(debug_info, bv, debug_file, sep64, file, progress)
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

fn parse_idb_info_format<K: IDAKind>(
    debug_info: &mut DebugInfo,
    bv: &BinaryView,
    debug_file: &BinaryView,
    format: impl IDBFormat<K>,
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

    parse_id0_section_info(debug_info, bv, debug_file, &id0, &id1, id2.as_ref())?;

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
    _debug_file: &BinaryView,
    id0: &ID0Section<K>,
    id1: &ID1Section<K>,
    id2: Option<&ID2Section<K>>,
) -> Result<()> {
    let ida_info_idx = id0.root_node()?;
    let ida_info = id0.ida_info(ida_info_idx)?;
    let idb_baseaddr = ida_info.addresses.loading_base.into_u64();
    let bv_baseaddr = bv.start();
    // just addr this value to the address to translate from ida to bn
    // NOTE this delta could wrap here and while using translating
    let addr_delta = bv_baseaddr.wrapping_sub(idb_baseaddr);

    for (idb_addr, info) in get_info(id0, id1, id2, &ida_info)? {
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
            let comments: Vec<String> = comments
                .iter()
                .map(idb_rs::IDBString::as_utf8_lossy)
                .map(Cow::into_owned)
                .collect();
            function.set_comment_at(addr, &comments.join("\n"));
        }

        let srarea_idx = id0.srareas_idx()?;
        let segment_idx = id0.segments_idx()?;
        let bnty = ty.as_ref().and_then(|ty| {
            match translate_ephemeral_type(
                bv,
                id0,
                srarea_idx,
                segment_idx,
                &ida_info,
                idb_addr,
                ty,
            ) {
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
            }
        });

        let label: Option<Cow<'_, str>> = label.as_ref().map(IDBString::as_utf8_lossy);
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

fn read_true_false_segreg<K: IDAKind>(
    id0: &ID0Section<K>,
    addr: Address<K>,
    srarea_idx: Option<SrareasIdx<K>>,
    segment_idx: Option<SegmentIdx<K>>,
    segreg_idx: usize,
) -> Result<bool> {
    // default into false for the thumb value?
    let segreg_raw = srarea_idx
        .zip(segment_idx)
        .map(|(srarea_idx, segment_idx)| {
            id0.segment_register_value(addr, srarea_idx, segment_idx, segreg_idx)
        })
        .transpose()?
        .flatten();
    match segreg_raw.map(<K::Usize as IDAUsize>::into_u64) {
        None | Some(0) => Ok(false),
        Some(1) => Ok(true),
        Some(2..) => Err(anyhow!("Invalid segment register value")),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CpuSize {
    B16,
    B32,
    B64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CpuEndian {
    Be,
    Le,
}

fn architecture_from_ida<K: IDAKind>(
    id0: &ID0Section<K>,
    srarea_idx: Option<SrareasIdx<K>>,
    segment_idx: Option<SegmentIdx<K>>,
    root_info: &RootInfo<K>,
    addr: Address<K>,
) -> Result<Option<CoreArchitecture>> {
    let Some(proc) = id0.processor(root_info) else {
        return Ok(None);
    };
    use idb_rs::processors::*;
    let lflags_32 = root_info.lflags.is_program_32b_or_bigger();
    let lflags_64 = root_info.lflags.is_program_64b();
    use CpuSize::*;
    let bits = match (lflags_32, lflags_64) {
        (true, true) => B64,
        (true, false) => B32,
        (false, false) => B16,
        (false, true) => {
            return Err(anyhow!(
                "Unknown architecture size without lflags 32b and with 64b flag"
            ))
        }
    };
    use CpuEndian::*;
    let endian = if root_info.lflags.is_big_endian() {
        Be
    } else {
        Le
    };
    match proc {
        Processor::Msp430(Msp430::Msp430) => {
            ensure!(bits == B16, "MSP430 with non-16bits size is unknown");
            ensure!(endian == Le, "MSP430 BigEndian is unknown");
            Ok(CoreArchitecture::by_name("msp430"))
        }
        Processor::Arm(arm) => {
            use idb_rs::processors::Arm::*;
            if bits == B64 {
                // TODO aarch64
                return Ok(None);
            }
            let is_thumb = read_true_false_segreg(
                id0,
                addr,
                srarea_idx,
                segment_idx,
                usize::from(ArmReg::T) - ArmReg::SEGMENT_REGISTERS_START,
            )?;
            match (arm, endian, bits, is_thumb) {
                // see above
                (_, _, B64, _) => unreachable!(),
                (_, _, B16, _) => Err(anyhow!("ARM 16bits is unknown")),
                (Arm | ProcAltXScaleL, Be, _, _) | (Armb | ProcAltXScaleB, Le, _, _) => {
                    Err(anyhow!("ARM with conflicting endian: {arm:?} {endian:?}"))
                }

                (Arm, Le, B32, false) => Ok(CoreArchitecture::by_name("armv7")),
                (Armb, Be, B32, false) => Ok(CoreArchitecture::by_name("armv7eb")),
                (Arm, Le, B32, true) => Ok(CoreArchitecture::by_name("thumb2")),
                (Armb, Be, B32, true) => Ok(CoreArchitecture::by_name("thumb2eb")),

                // TODO default into armv7/thumb2?
                (ProcAltArm710A | ProcAltXScaleL, Le, B32, true) => {
                    Ok(CoreArchitecture::by_name("thumb2"))
                }
                (ProcAltArm710A | ProcAltXScaleB, Be, B32, true) => {
                    Ok(CoreArchitecture::by_name("thumb2eb"))
                }
                (ProcAltArm710A | ProcAltXScaleL, Le, B32, false) => {
                    Ok(CoreArchitecture::by_name("armv7"))
                }
                (ProcAltArm710A | ProcAltXScaleB, Be, B32, false) => {
                    Ok(CoreArchitecture::by_name("armv7eb"))
                }
            }
        }
        Processor::Mips(mips) => {
            use idb_rs::processors::Mips::*;
            // TODO
            // the mips16 pseudoregister is used to switch between standard MIPS and MIPS16 or microMIPS
            let is_mips16 = read_true_false_segreg(
                id0,
                addr,
                srarea_idx,
                segment_idx,
                usize::from(MipsReg::Mips16) - MipsReg::SEGMENT_REGISTERS_START,
            )?;

            match (mips, endian, bits, is_mips16) {
                (_, _, B16, _) => Err(anyhow!("Mips 16bits is unknown")),
                (Mipsl | Mipsrl | R5900L | Octeonl | Tx19Al, Be, _, _)
                | (Mipsb | Mipsr | R5900B | Octeonb | Tx19Ab, Le, _, _) => {
                    Err(anyhow!("Mips with conflicting endian: {mips:?} {endian:?}"))
                }

                // TODO there is any MIPS cpu here that don't support mips16?
                // TODO binaja don't implement mips16?
                (
                    Mipsl | Mipsb | Mipsrl | Mipsr | R5900L | R5900B | Octeonl | Octeonb | Psp
                    | Tx19Al | Tx19Ab,
                    _,
                    _,
                    true,
                ) => Ok(None),

                // TODO I don't know what Mipsr means, just leave it unimplemented for now
                (Mipsr | Mipsrl, _, _, _) => Ok(None),

                (Mipsl, Le, B32, false) => Ok(CoreArchitecture::by_name("mipsel32")),
                (Mipsl, Le, B64, false) => Ok(CoreArchitecture::by_name("mipsel64")),
                (Mipsb, Be, B32, false) => Ok(CoreArchitecture::by_name("mips32")),
                (Mipsb, Be, B64, false) => Ok(CoreArchitecture::by_name("mips64")),

                (R5900L | R5900B, _, B64, _) => Err(anyhow!("Mips R5900 64bits is unknown")),

                (Tx19Al | Tx19Ab, _, B64, _) => Err(anyhow!("Mips Tx19A 64bits is unknown")),
                (Tx19Al | Tx19Ab, _, B32, _) => Ok(None),

                (R5900L, Le, B32, false) => Ok(CoreArchitecture::by_name("r5900l")),
                (R5900B, Be, B32, false) => Ok(CoreArchitecture::by_name("r5900b")),

                (Octeonl | Octeonb, _, B32, _) => Err(anyhow!("Mips Octeon 32bits is unknown")),
                (Octeonb, Be, B64, false) => Ok(CoreArchitecture::by_name("cavium-mips64")),
                (Octeonl, Le, B64, false) => Ok(CoreArchitecture::by_name("cavium-mipsel64")),

                (Psp, Be, _, _) => Err(anyhow!("Mips PSP BigEndian is unknown")),
                (Psp, _, B64, _) => Err(anyhow!("Mips PSP 64bits is unknown")),
                (Psp, Le, B32, _) => Ok(None),
            }

            // TODO identify the translation for
            //mips3
            //mipsel3
        }
        Processor::Ppc(ppc) => {
            use idb_rs::processors::Ppc::*;
            let is_vle = read_true_false_segreg(
                id0,
                addr,
                srarea_idx,
                segment_idx,
                usize::from(PpcReg::Vle) - PpcReg::SEGMENT_REGISTERS_START,
            )?;

            match (ppc, endian, bits, is_vle) {
                (_, _, B16, _) => Err(anyhow!("PPC 16bits is unknown")),
                (Ppcl, Be, _, _) | (Ppc, Le, _, _) => {
                    Err(anyhow!("PPC with conflicting endian: {ppc:?} {endian:?}"))
                }
                (Ppcl, Le, _, true) => Err(anyhow!("PPC with VLE Little Endian is unknown")),
                // but ghidra declares it, so I'll put this as possible:
                // https://github.com/NationalSecurityAgency/ghidra/blob/1ca9e32a5712bc48a603f9e60d8f692220071eb7/Ghidra/Processors/PowerPC/data/languages/ppc_64_isa_vle_be.slaspec
                (Ppc, Be, B64, true) => Ok(None),
                (Ppc, Be, B32, true) => Ok(CoreArchitecture::by_name("ppcvle")),
                (Ppcl, Le, B32, false) => Ok(CoreArchitecture::by_name("ppc_le")),
                (Ppc, Be, B32, false) => Ok(CoreArchitecture::by_name("ppc")),
                (Ppc, Be, B64, false) => Ok(CoreArchitecture::by_name("ppc64")),
                (Ppcl, Le, B64, false) => Ok(CoreArchitecture::by_name("ppc64_le")),
            }
            // TODO what about those?
            //ppc_qpx
            //ppc_spe
            //ppc_ps
        }
        Processor::Riscv(Riscv::Riscv) => match (endian, bits) {
            (Le, B64) => Ok(CoreArchitecture::by_name("rv64gc")),
            (Le, B32) => Ok(CoreArchitecture::by_name("rv32gc")),
            (_, B16) => Err(anyhow!("RiscV 16bits is unknown")),
            (Be, _) => Err(anyhow!("RiscV BigEndian is unknown")),
        },
        Processor::Pc(pc) => {
            use Pc::*;
            if endian == Be {
                return Err(anyhow!(
                    "Unknown PC BigEndian, all X86 family is LittleEndian"
                ));
            }
            match (pc, bits) {
                (ProcAlt8086 | ProcAlt80286R | ProcAlt80286P, B32 | B64) => {
                    return Err(anyhow!(
                        "Unknown PC {pc:?} {bits:?}, this cpu is 16bits only"
                    ))
                }
                (
                    ProcAlt80386R | ProcAlt80386P | ProcAlt80486R | ProcAlt80486P | ProcAlt80586R
                    | ProcAlt80586P | ProcAlt80686P | P2 | K62 | P3 | Athlon,
                    B64,
                ) => {
                    return Err(anyhow!(
                        "Unknown PC {pc:?} {bits:?}, this cpu is 32/16bits only"
                    ))
                }

                // all x86 can execute x86-16
                (_, B16) => Ok(CoreArchitecture::by_name("x86_16")),
                // all cpus after 80386 (AKA i386) can execute x86_32
                (
                    ProcAlt80386R | ProcAlt80386P | ProcAlt80486R | ProcAlt80486P | ProcAlt80586R
                    | ProcAlt80586P | ProcAlt80686P | P2 | K62 | P3 | Athlon | P4 | Metapc,
                    B32,
                ) => Ok(CoreArchitecture::by_name("x86_32")),
                // only P4 and after can execute x86_64
                (P4 | Metapc, B64) => Ok(CoreArchitecture::by_name("x86_32")),
            }
        }
        Processor::Tricore(Tricore::Tricore) => {
            ensure!(bits == B32, "Tricore {bits:?} CPU is unknown");
            ensure!(endian == Le, "Tricore BigEndian is unknown");
            Ok(CoreArchitecture::by_name("tricore"))
        }
        Processor::Script(_) => Ok(None),
        Processor::M740(_)
        | Processor::Ia(_)
        | Processor::M7900(_)
        | Processor::Avr(_)
        | Processor::Alpha(_)
        | Processor::Nec850(_)
        | Processor::Sparc(_)
        | Processor::Arc(_)
        | Processor::Fr(_)
        | Processor::Tms320C3(_)
        | Processor::M65816(_)
        | Processor::F2Mc(_)
        | Processor::Rl78(_)
        | Processor::Proc78K0(_)
        | Processor::Dsp56K(_)
        | Processor::M65(_)
        | Processor::Kr1878(_)
        | Processor::S390(_)
        | Processor::Sam8(_)
        | Processor::C166(_)
        | Processor::Dalvik(_)
        | Processor::Mc68K(_)
        | Processor::Tms320C1(_)
        | Processor::Spc700(_)
        | Processor::I196(_)
        | Processor::Mc6812(_)
        | Processor::I960(_)
        | Processor::M16C(_)
        | Processor::Pdp11(_)
        | Processor::Tms320C6(_)
        | Processor::M32R(_)
        | Processor::Java(_)
        | Processor::Mc6816(_)
        | Processor::Z80(_)
        | Processor::Cli(_)
        | Processor::Hppa(_)
        | Processor::H8(_)
        | Processor::Oakdsp(_)
        | Processor::Xtensa(_)
        | Processor::Pic16(_)
        | Processor::H8500(_)
        | Processor::Tms32028(_)
        | Processor::Proc78K0S(_)
        | Processor::Tms320C5(_)
        | Processor::Z8(_)
        | Processor::Mc8(_)
        | Processor::M7700(_)
        | Processor::Tms32054(_)
        | Processor::Unsp(_)
        | Processor::Rx(_)
        | Processor::Wasm(_)
        | Processor::Sh3(_)
        | Processor::St7(_)
        | Processor::Ad218X(_)
        | Processor::St9(_)
        | Processor::Tms32055(_)
        | Processor::Pic(_)
        | Processor::I860(_)
        | Processor::St20(_)
        | Processor::I51(_)
        | Processor::Xa(_)
        | Processor::Ebc(_)
        | Processor::Spu(_) => Ok(None),
    }
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
