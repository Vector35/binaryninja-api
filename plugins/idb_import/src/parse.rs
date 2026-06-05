//! Parse the provided IDB / TIL file and extract information into a struct for further processing.

use idb_rs::addr_info::{all_address_info, AddressInfo};
use idb_rs::id0::function::{FuncIdx, FuncordsIdx, IDBFunctionType};
use idb_rs::id0::{DirTreeEntry, ID0Section, Netdelta, SegmentType};
use idb_rs::id1::ID1Section;
use idb_rs::id2::ID2Section;
use idb_rs::til::section::TILSection;
use idb_rs::til::TILTypeInfo;
use idb_rs::{identify_idb_file, Address, IDAKind, IDAUsize, IDAVariants, IDBFormat, IDBFormats};
use serde::Serialize;
use std::ffi::CString;
use std::io::{BufRead, Seek};
use std::ops::Range;

#[derive(Debug, Clone, Serialize)]
pub struct SegmentInfo {
    pub name: String,
    pub region: Range<u64>,
    pub ty: SegmentType,
}

#[derive(Debug, Clone, Serialize)]
pub struct FunctionInfo {
    pub name: Option<String>,
    pub ty: Option<idb_rs::til::Type>,
    pub address: u64,
    pub is_library: bool,
    pub is_no_return: bool,
    pub register_vars: Vec<RegisterVarInfo>,
    pub stack_frame: Option<StackFrameInfo>,
}

/// A register renamed by the user within a function (IDA "regvar"), e.g. `eax` -> `count`.
#[derive(Debug, Clone, Serialize)]
pub struct RegisterVarInfo {
    /// Architecture register the variable lives in (e.g. `eax`).
    pub register: String,
    /// User-assigned name for the register over its range.
    pub name: String,
    pub start: u64,
    pub end: u64,
    pub comment: String,
}

/// A function's stack frame, as recorded by IDA.
///
/// The `frame` UDT describes every member of the frame (locals, saved registers, return
/// address and arguments). `local_size` (IDA's `frsize`) and `saved_regs_size` (`frregs`) give
/// the geometry needed to translate IDA frame offsets into Binary Ninja's frame convention.
#[derive(Debug, Clone, Serialize)]
pub struct StackFrameInfo {
    /// Size in bytes of the local variables area (IDA `frsize`).
    pub local_size: u64,
    /// Size in bytes of the saved registers area (IDA `frregs`).
    pub saved_regs_size: u64,
    /// The frame structure describing each stack member.
    pub frame: idb_rs::til::udt::UDT,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExportInfo {
    pub name: String,
    pub address: u64,
    pub ty: Option<idb_rs::til::Type>,
}

#[derive(Debug, Clone, Serialize)]
pub struct NameInfo {
    pub address: u64,
    pub ty: Option<idb_rs::til::Type>,
    pub label: Option<String>,
    pub exported: bool,
}

/// A typed data item IDA has defined at an address (e.g. a dword, a float, a string, or a
/// struct), recovered from the byte flags so that even unnamed/untyped-in-the-TIL data still gets
/// a Binary Ninja data variable of the right type.
#[derive(Debug, Clone, Serialize)]
pub struct DataInfo {
    pub address: u64,
    /// The explicit IDA type for this item, when one is recorded (e.g. a struct instance).
    pub ty: Option<idb_rs::til::Type>,
    /// The byte-flag-derived kind, used when there is no explicit type.
    pub kind: Option<DataKind>,
}

/// The kind of a [`DataInfo`], with the size IDA recorded for the item.
#[derive(Debug, Clone, Copy, Serialize)]
pub enum DataKind {
    /// Integer of the given size in bytes.
    Int(u8),
    /// Floating point value of the given size in bytes.
    Float(u8),
    /// String literal of the given total length in bytes.
    String(u64),
}

/// The per-operand number formats IDA recorded for an instruction.
#[derive(Debug, Clone, Serialize)]
pub struct OperandFormatInfo {
    pub address: u64,
    /// `(operand index, format)` pairs for the operands that have a non-default format.
    pub formats: Vec<(u8, OperandFormat)>,
}

/// How IDA displays an instruction operand's number.
#[derive(Debug, Clone, Copy, Serialize)]
pub enum OperandFormat {
    Hex,
    Dec,
    Char,
    Oct,
    Bin,
    Offset,
}

#[derive(Debug, Clone, Serialize)]
pub struct CommentInfo {
    pub address: u64,
    pub comment: String,
    pub is_repeatable: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct LabelInfo {
    pub address: u64,
    pub label: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct FunctionCordInfo {
    comments: Vec<CommentInfo>,
    labels: Vec<LabelInfo>,
}

#[derive(Debug, Clone, Serialize)]
pub enum BaseAddressInfo {
    /// The base address is not specified in the IDB.
    None,
    /// The base address is the absolute address of the first byte of the executable.
    ///
    /// To get a delta, calculate the difference between the base address and the address of the lowest segment.
    BaseSegment(u64),
    /// The base address is the address of the first byte of the lowest section.
    ///
    /// To get a delta, calculate the difference between the base address and the address of the lowest section.
    BaseSection(u64),
}

#[derive(Debug, Clone, Serialize)]
pub struct ID0Info {
    pub base_address: BaseAddressInfo,
    pub segments: Vec<SegmentInfo>,
    pub functions: Vec<FunctionInfo>,
    pub comments: Vec<CommentInfo>,
    pub labels: Vec<LabelInfo>,
    pub exports: Vec<ExportInfo>,
    /// Processor register names indexed by IDA register number, used to resolve the registers
    /// referenced by argument/return value locations into Binary Ninja registers.
    pub register_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DirTreeInfo {
    pub functions: Vec<FunctionInfo>,
    pub types: Vec<TILTypeInfo>,
    /// Contains both function and data names (along with their types).
    pub names: Vec<NameInfo>,
    pub comments: Vec<CommentInfo>,
    /// The IDA "Functions" window folder hierarchy (root-level entries).
    pub function_folders: Vec<FunctionFolderEntry>,
}

/// An entry in IDA's function folder tree: either a function (by address) or a named folder
/// containing further entries. Mirrors IDA's dirtree so it can be recreated as Binary Ninja
/// components.
#[derive(Debug, Clone, Serialize)]
pub enum FunctionFolderEntry {
    Function(u64),
    Folder {
        name: String,
        entries: Vec<FunctionFolderEntry>,
    },
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct IDBInfo {
    pub sha256: Option<String>,
    pub id0: Option<ID0Info>,
    // NOTE: TILSection is self-contained, so we do no pre-processing.
    pub til: Option<TILSection>,
    pub dir_tree: Option<DirTreeInfo>,
    /// Typed data items recovered from the byte flags (id1).
    pub data_items: Vec<DataInfo>,
    /// Per-operand number formats recovered from the byte flags (id1).
    pub operand_formats: Vec<OperandFormatInfo>,
}

impl IDBInfo {
    /// Retrieve the functions from both the `id0` and `dir_tree` sections, with function information
    /// merged; this is the "sanitized" version of the functions contained in an IDB.
    pub fn merged_functions(&self) -> Vec<FunctionInfo> {
        let mut id0_functions = self
            .id0
            .as_ref()
            .map(|id0| id0.functions.clone())
            .unwrap_or_default();
        let dir_tree_functions = self
            .dir_tree
            .as_ref()
            .map(|dir_tree| dir_tree.functions.clone())
            .unwrap_or_default();
        id0_functions.extend(dir_tree_functions);
        id0_functions.sort_by_key(|f| f.address);
        id0_functions.dedup_by(|a, b| {
            if a.address != b.address {
                return false;
            }
            // We need to move data from one function to another, if a name is missing
            // in one of the functions, add it to the function we are keeping, if we are missing
            // a type, do the same.
            if a.name.is_some() {
                b.name = a.name.clone();
            }
            if a.ty.is_some() {
                b.ty = a.ty.clone();
            }
            if !a.register_vars.is_empty() {
                b.register_vars = a.register_vars.clone();
            }
            if a.stack_frame.is_some() {
                b.stack_frame = a.stack_frame.clone();
            }
            true
        });
        id0_functions
    }

    pub fn merged_names(&self) -> Vec<NameInfo> {
        let mut names = Vec::new();
        if let Some(id0) = &self.id0 {
            for label in &id0.labels {
                names.push(NameInfo {
                    address: label.address,
                    ty: None,
                    label: Some(label.label.clone()),
                    exported: false,
                });
            }

            for func in &id0.functions {
                names.push(NameInfo {
                    address: func.address,
                    ty: func.ty.clone(),
                    label: func.name.clone(),
                    exported: false,
                });
            }
        }
        if let Some(dir_tree) = &self.dir_tree {
            names.extend(dir_tree.names.clone());
        }
        names.sort_by_key(|n| n.address);
        names.dedup_by(|a, b| {
            if a.address != b.address {
                return false;
            }
            if a.label.is_some() {
                b.label = a.label.clone();
            }
            if a.ty.is_some() {
                b.ty = a.ty.clone();
            }
            true
        });
        names
    }

    pub fn merged_types(&self) -> Vec<TILTypeInfo> {
        let mut types = Vec::new();
        if let Some(dir_tree) = &self.dir_tree {
            types.extend(dir_tree.types.clone());
        }
        if let Some(til) = &self.til {
            types.extend(til.types.clone());
        }
        types.sort_by_key(|t| t.name.to_string());
        // `a` is the later (dir_tree-then-til) duplicate being removed and `b` is the one we
        // keep. In practice the dir_tree types are clones pulled from the same TIL (see
        // `parse_dir_tree`), so the definitions are identical; we still carry over an ordinal if
        // the kept entry happens to be missing one, so name/ordinal lookups stay resolvable.
        types.dedup_by(|a, b| {
            if a.name.to_string() != b.name.to_string() {
                return false;
            }
            if b.ordinal == 0 && a.ordinal != 0 {
                b.ordinal = a.ordinal;
            }
            true
        });
        types
    }

    pub fn merged_comments(&self) -> Vec<CommentInfo> {
        let mut comments = Vec::new();
        if let Some(id0) = &self.id0 {
            comments.extend(id0.comments.clone());
        }
        if let Some(dir_tree) = &self.dir_tree {
            comments.extend(dir_tree.comments.clone());
        }
        comments.sort_by_key(|c| c.address);
        comments.dedup_by(|a, b| {
            if a.address != b.address {
                return false;
            }
            a.is_repeatable == b.is_repeatable
        });
        comments
    }
}

/// Parsed the IDB data into [`IDBInfo`].
pub struct IDBFileParser;

impl IDBFileParser {
    pub fn new() -> Self {
        Self {}
    }

    pub fn parse<I: BufRead + Seek>(&self, data: &mut I) -> anyhow::Result<IDBInfo> {
        match identify_idb_file(data)? {
            IDBFormats::Separated(f) => match f {
                IDAVariants::IDA32(f_32) => self.parse_format(&mut *data, f_32),
                IDAVariants::IDA64(f_64) => self.parse_format(&mut *data, f_64),
            },
            IDBFormats::InlineUncompressed(f) => self.parse_format(&mut *data, f),
            IDBFormats::InlineCompressed(f) => {
                let mut decompressed = Vec::new();
                let uncompressed_format = f.decompress_into_memory(data, &mut decompressed)?;
                let mut decompressed_data = std::io::Cursor::new(decompressed);
                self.parse_format(&mut decompressed_data, uncompressed_format)
            }
        }
    }

    pub fn parse_format<I: BufRead + Seek, K: IDAKind>(
        &self,
        data: &mut I,
        format: impl IDBFormat<K>,
    ) -> anyhow::Result<IDBInfo> {
        let mut id0 = None;
        if let Some(id0_loc) = format.id0_location() {
            id0 = Some(format.read_id0(&mut *data, id0_loc)?);
        }

        let mut id1 = None;
        if let Some(id1_loc) = format.id1_location() {
            id1 = Some(format.read_id1(&mut *data, id1_loc)?);
        }

        let mut id2 = None;
        if let Some(id2_loc) = format.id2_location() {
            id2 = Some(format.read_id2(&mut *data, id2_loc)?);
        }

        // NOTE: `read_til` reads the section header and transparently inflates Zlib/Zstd
        // compressed TIL sections, so no explicit decompression step is needed here.
        let mut til = None;
        if let Some(til_loc) = format.til_location() {
            til = Some(format.read_til(&mut *data, til_loc)?);
        };

        let dir_tree_info = match (id0.as_ref(), id1.as_ref(), id2.as_ref(), til.as_ref()) {
            (Some(id0), Some(id1), id2, til) => Some(self.parse_dir_tree(id0, id1, id2, til)?),
            _ => None,
        };

        // The IDB records the SHA256 of the original input file; surface it so consumers (and a
        // future verifier) can confirm the IDB matches the binary being mapped.
        let sha256 = id0.as_ref().and_then(|id0| {
            let root_idx = id0.root_node().ok()?;
            let hash = id0.input_file_sha256(root_idx).ok()??;
            Some(hash.iter().map(|b| format!("{:02x}", b)).collect::<String>())
        });

        let id0_info = id0.as_ref().map(|id0| self.parse_id0(id0)).transpose()?;

        // Recover typed data items from the byte flags so unnamed data still gets a data variable.
        let data_items = match (id0.as_ref(), id1.as_ref()) {
            (Some(id0), Some(id1)) => self.parse_data_items(id0, id1, id2.as_ref())?,
            _ => Vec::new(),
        };

        // Recover per-operand number formats (applied only when the user opts in).
        let operand_formats = id1
            .as_ref()
            .map(|id1| self.parse_operand_formats(id1))
            .unwrap_or_default();

        Ok(IDBInfo {
            sha256,
            id0: id0_info,
            til,
            dir_tree: dir_tree_info,
            data_items,
            operand_formats,
        })
    }

    /// Walk the byte flags and recover the per-operand number formats IDA assigned to code.
    pub fn parse_operand_formats<K: IDAKind>(
        &self,
        id1: &ID1Section<K>,
    ) -> Vec<OperandFormatInfo> {
        let mut operand_formats = Vec::new();
        for (address, byte_info, _size) in id1.all_bytes_no_tails() {
            let idb_rs::id1::ByteType::Code(code) = byte_info.byte_type() else {
                continue;
            };
            let mut formats = Vec::new();
            if let Ok(Some(op)) = code.operand0() {
                if let Some(format) = operand_format_from_byte_op(op) {
                    formats.push((0, format));
                }
            }
            if let Ok(Some(op)) = code.operand1() {
                if let Some(format) = operand_format_from_byte_op(op) {
                    formats.push((1, format));
                }
            }
            if !formats.is_empty() {
                operand_formats.push(OperandFormatInfo {
                    address: address.into_raw().into_u64(),
                    formats,
                });
            }
        }
        operand_formats
    }

    /// Walk the byte flags and recover every defined data item along with the kind/size IDA gave
    /// it. Items whose data type has no straightforward Binary Ninja scalar/string equivalent
    /// (structs, alignment fill, vector/custom types) are left for the type-driven name path.
    pub fn parse_data_items<K: IDAKind>(
        &self,
        id0: &ID0Section<K>,
        id1: &ID1Section<K>,
        id2: Option<&ID2Section<K>>,
    ) -> anyhow::Result<Vec<DataInfo>> {
        use idb_rs::id1::{ByteDataType, ByteType};

        let root_info = id0.ida_info(id0.root_node()?)?;
        let netdelta = root_info.netdelta();

        let mut data_items = Vec::new();
        for (address, byte_info, size) in id1.all_bytes_no_tails() {
            let ByteType::Data(data) = byte_info.byte_type() else {
                continue;
            };
            let kind = match data.data_type() {
                ByteDataType::Byte => Some(DataKind::Int(1)),
                ByteDataType::Word => Some(DataKind::Int(2)),
                ByteDataType::Dword => Some(DataKind::Int(4)),
                ByteDataType::Qword => Some(DataKind::Int(8)),
                ByteDataType::Oword => Some(DataKind::Int(16)),
                ByteDataType::Float => Some(DataKind::Float(4)),
                ByteDataType::Double => Some(DataKind::Float(8)),
                ByteDataType::Tbyte => Some(DataKind::Float(10)),
                ByteDataType::Strlit => Some(DataKind::String(size as u64)),
                // Structs carry their actual type in the TIL; resolve it below. Alignment fill
                // and vector/custom kinds have no simple mapping and are skipped.
                _ => None,
            };

            // A struct item only makes sense with its real type; look it up. Avoid the per-item
            // type lookup for the (vastly more common) scalar/string items.
            let ty = if matches!(data.data_type(), ByteDataType::Struct) {
                AddressInfo::new(id0, id1, id2, netdelta, address)
                    .and_then(|info| info.tinfo(&root_info).ok().flatten())
            } else {
                None
            };

            if ty.is_none() && kind.is_none() {
                continue;
            }
            data_items.push(DataInfo {
                address: address.into_raw().into_u64(),
                ty,
                kind,
            });
        }
        Ok(data_items)
    }

    pub fn parse_id0<K: IDAKind>(&self, id0: &ID0Section<K>) -> anyhow::Result<ID0Info> {
        let root_info_idx = id0.root_node()?;
        let root_info = id0.ida_info(root_info_idx)?;
        let netdelta = root_info.netdelta();

        let mut segments = Vec::new();
        if let Some(seg_idx) = id0.segments_idx()? {
            for entry in id0.segments(seg_idx) {
                let Ok(segment) = entry else {
                    tracing::warn!("Failed to read segment entry");
                    continue;
                };
                let name = id0.segment_name(segment.name)?.map(|s| s.to_string());
                let seg_start = segment.address.start.into_raw().into_u64();
                let seg_end = segment.address.end.into_raw().into_u64();
                segments.push(SegmentInfo {
                    name: name.unwrap_or_else(|| format!("seg_{:0x}", seg_start)),
                    region: seg_start..seg_end,
                    ty: segment.seg_type,
                });
            }
        }

        let mut functions = Vec::new();
        let mut comments = Vec::new();
        let mut labels = Vec::new();
        if let Some(funcs_idx) = id0.funcs_idx()? {
            if let Some(funcords_idx) = id0.funcords_idx()? {
                let info = self.parse_func_cord(&id0, netdelta, funcords_idx, funcs_idx)?;
                comments.extend(info.comments);
                labels.extend(info.labels);
            }

            for entry in id0.fchunks(funcs_idx) {
                let Ok(func) = entry else {
                    tracing::warn!("Failed to read function entry");
                    continue;
                };

                let func_start = func.address.start.into_raw().into_u64();
                match &func.extra {
                    IDBFunctionType::Tail(_) => {
                        tracing::debug!("Skipping tail function... {:0x}", func_start);
                    }
                    IDBFunctionType::NonTail(func_ext) => {
                        if func.flags.is_outline() {
                            tracing::debug!("Skipping outlined function... {:0x}", func_start);
                            continue;
                        }

                        // Collect register variables (IDA "regvars"): registers the user renamed
                        // over a range within the function. The register is given by name, so it
                        // maps cleanly onto a Binary Ninja register in the mapper.
                        let mut register_vars = Vec::new();
                        for reg in id0.function_defined_registers(netdelta, &func, func_ext) {
                            let reg = match reg {
                                Ok(reg) => reg,
                                Err(err) => {
                                    tracing::warn!(
                                        "Failed to read register variable for {:0x}: {}",
                                        func_start,
                                        err
                                    );
                                    continue;
                                }
                            };
                            register_vars.push(RegisterVarInfo {
                                register: reg.register_name.to_string(),
                                name: reg.variable_name.to_string(),
                                start: reg.range.start.into_raw().into_u64(),
                                end: reg.range.end.into_raw().into_u64(),
                                comment: reg.cmt.to_string(),
                            });
                        }

                        // Collect the function's stack frame (named locals, saved registers and
                        // stack arguments) along with the frame geometry needed to place them.
                        let stack_frame = match id0
                            .function_defined_variables(&root_info, &func, func_ext)
                        {
                            Ok(stack_names) => stack_names.ty.map(|frame| StackFrameInfo {
                                local_size: func_ext.frsize.into_u64(),
                                saved_regs_size: func_ext.frregs as u64,
                                frame,
                            }),
                            Err(err) => {
                                tracing::warn!(
                                    "Failed to read stack frame for {:0x}: {}",
                                    func_start,
                                    err
                                );
                                None
                            }
                        };

                        functions.push(FunctionInfo {
                            name: None,
                            ty: None,
                            address: func_start,
                            is_library: func.flags.is_lib(),
                            is_no_return: func.flags.is_no_return(),
                            register_vars,
                            stack_frame,
                        });
                    }
                }
            }
        }

        let mut exports = Vec::new();
        if let Ok(entry_points) = id0.entry_points(&root_info) {
            for entry in entry_points {
                exports.push(ExportInfo {
                    name: entry.name,
                    address: entry.address.into_u64(),
                    ty: entry.entry_type,
                });
            }
        }

        let min_ea = root_info.addresses.min_ea.into_raw().into_u64();
        let loading_base = root_info.addresses.loading_base.into_u64();
        let base_address = match (loading_base, min_ea) {
            (0, 0) => BaseAddressInfo::None,
            // An IDB with zero loading base is possibly not loaded there.
            // For example, see the FlawedGrace.idb in the idb-rs resources directory.
            // Instead, we will want to use the lowest section address.
            (0, min_ea) => BaseAddressInfo::BaseSection(min_ea),
            (loading_base, _) => BaseAddressInfo::BaseSegment(loading_base.into_u64()),
        };

        // The processor module defines the register names by index; this lets us resolve the
        // registers referenced by argument/return value locations into real registers.
        let register_names = id0
            .processor(&root_info)
            .and_then(|processor| processor.registers_info())
            .map(|info| info.names.iter().map(|name| name.to_string()).collect())
            .unwrap_or_default();

        Ok(ID0Info {
            base_address,
            segments,
            functions,
            comments,
            labels,
            exports,
            register_names,
        })
    }

    pub fn parse_func_cord<K: IDAKind>(
        &self,
        id0: &ID0Section<K>,
        netdelta: Netdelta<K>,
        funcords_idx: FuncordsIdx<K>,
        funcs_idx: FuncIdx<K>,
    ) -> anyhow::Result<FunctionCordInfo> {
        let mut comments = Vec::new();
        let mut labels = Vec::new();

        for entry in id0.funcords(funcords_idx)? {
            let Ok(address) = entry else {
                tracing::warn!("Failed to read function address entry");
                continue;
            };

            for (label_addr, label_data) in id0.local_labels(netdelta, address)? {
                if let Ok(label_data_cstr) = CString::new(label_data) {
                    let label_data_str = label_data_cstr.to_string_lossy();
                    labels.push(LabelInfo {
                        address: label_addr.into_raw().into_u64(),
                        label: label_data_str.to_string(),
                    });
                }
            }

            if let Some(comment) = id0.func_cmt(funcs_idx, netdelta, address)? {
                comments.push(CommentInfo {
                    address: address.into_raw().into_u64(),
                    comment: comment.to_string(),
                    is_repeatable: false,
                });
            }

            if let Some(comment) = id0.func_repeatable_cmt(funcs_idx, netdelta, address)? {
                comments.push(CommentInfo {
                    address: address.into_raw().into_u64(),
                    comment: comment.to_string(),
                    is_repeatable: true,
                });
            }
        }

        Ok(FunctionCordInfo { comments, labels })
    }

    pub fn parse_dir_tree<K: IDAKind>(
        &self,
        id0: &ID0Section<K>,
        id1: &ID1Section<K>,
        id2: Option<&ID2Section<K>>,
        til: Option<&TILSection>,
    ) -> anyhow::Result<DirTreeInfo> {
        let root_info_idx = id0.root_node()?;
        let root_info = id0.ida_info(root_info_idx)?;
        let netdelta = root_info.netdelta();

        let func_info_from_addr =
            |addr_info: &AddressInfo<K>| -> anyhow::Result<Option<FunctionInfo>> {
                let func_name = addr_info.label()?.map(|s| s.to_string());
                let func_ty = addr_info.tinfo(&root_info)?;
                let func_addr = addr_info.address().into_raw().into_u64();
                Ok(Some(FunctionInfo {
                    name: func_name,
                    ty: func_ty,
                    address: func_addr,
                    is_library: false,
                    is_no_return: false,
                    register_vars: Vec::new(),
                    stack_frame: None,
                }))
            };

        let comment_info_from_addr = |addr_info: &AddressInfo<K>| -> Vec<CommentInfo> {
            let mut comments = Vec::new();
            if let Some(comment) = addr_info.comment() {
                comments.push(CommentInfo {
                    address: addr_info.address().into_raw().into_u64(),
                    comment: comment.to_string(),
                    is_repeatable: false,
                });
            }
            if let Some(comment) = addr_info.comment_repeatable() {
                comments.push(CommentInfo {
                    address: addr_info.address().into_raw().into_u64(),
                    comment: comment.to_string(),
                    is_repeatable: true,
                })
            }
            if let Some(pre_comments) = addr_info.comment_pre() {
                for comment in pre_comments {
                    comments.push(CommentInfo {
                        address: addr_info.address().into_raw().into_u64(),
                        comment: comment.to_string(),
                        is_repeatable: false,
                    })
                }
            }
            if let Some(post_comments) = addr_info.comment_post() {
                for comment in post_comments {
                    comments.push(CommentInfo {
                        address: addr_info.address().into_raw().into_u64(),
                        comment: comment.to_string(),
                        is_repeatable: false,
                    })
                }
            }
            comments
        };

        let mut comments = Vec::new();
        for (addr_info, _) in all_address_info(id0, id1, id2, netdelta) {
            comments.extend(comment_info_from_addr(&addr_info));
        }

        let func_dir_tree = id0.dirtree_function_address()?;
        let mut functions = Vec::new();
        if let Some(func_dir_tree) = &func_dir_tree {
            func_dir_tree.visit_leafs(|addr_raw| {
                let addr = Address::from_raw(*addr_raw);
                if let Some(info) = AddressInfo::new(id0, id1, id2, netdelta, addr) {
                    if let Ok(Some(func_info)) = func_info_from_addr(&info) {
                        functions.push(func_info);
                    }
                }
            });
        }

        // Preserve the folder hierarchy (not just the leaf functions) so it can be recreated as
        // Binary Ninja components.
        let function_folders = func_dir_tree
            .as_ref()
            .map(|tree| build_function_folders::<K>(&tree.entries))
            .unwrap_or_default();

        let mut names = Vec::new();
        if let Some(names_dir_tree) = id0.dirtree_names()? {
            names_dir_tree.visit_leafs(|name_raw| {
                let addr = Address::from_raw(*name_raw);
                if let Some(info) = AddressInfo::new(id0, id1, id2, netdelta, addr) {
                    names.push(NameInfo {
                        address: info.address().into_raw().into_u64(),
                        ty: info.tinfo(&root_info).ok().flatten().map(|t| t.clone()),
                        label: info.label().ok().flatten().map(|s| s.to_string()),
                        exported: false,
                    });
                }
            });
        }

        let mut types = Vec::new();
        if let Some(til) = til {
            if let Some(type_dir_tree) = id0.dirtree_tinfos()? {
                type_dir_tree.visit_leafs(|type_ord_raw| {
                    if let Some(type_info) = til.get_ord(type_ord_raw.into_u64()) {
                        types.push(type_info.clone());
                    }
                })
            }
        }

        Ok(DirTreeInfo {
            functions,
            types,
            names,
            comments,
            function_folders,
        })
    }
}

/// Map an IDA operand representation to the subset of number formats we can apply directly.
///
/// Enum, segment, stack-variable, struct-offset, forced and custom representations need extra
/// context (a resolved enum/struct/variable) and are left to other paths.
fn operand_format_from_byte_op(op: idb_rs::id1::ByteOp) -> Option<OperandFormat> {
    use idb_rs::id1::ByteOp;
    match op {
        ByteOp::Hex => Some(OperandFormat::Hex),
        ByteOp::Dec => Some(OperandFormat::Dec),
        ByteOp::Char => Some(OperandFormat::Char),
        ByteOp::Oct => Some(OperandFormat::Oct),
        ByteOp::Bin => Some(OperandFormat::Bin),
        ByteOp::Offset => Some(OperandFormat::Offset),
        _ => None,
    }
}

/// Recursively convert an IDA function dirtree into our [`FunctionFolderEntry`] tree.
fn build_function_folders<K: IDAKind>(
    entries: &[DirTreeEntry<K::Usize>],
) -> Vec<FunctionFolderEntry> {
    entries
        .iter()
        .map(|entry| match entry {
            DirTreeEntry::Leaf(address) => FunctionFolderEntry::Function((*address).into_u64()),
            DirTreeEntry::Directory { name, entries } => FunctionFolderEntry::Folder {
                name: String::from_utf8_lossy(name).to_string(),
                entries: build_function_folders::<K>(entries),
            },
        })
        .collect()
}
