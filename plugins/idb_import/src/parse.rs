//! Parse the provided IDB / TIL file and extract information into a struct for further processing.

use idb_rs::addr_info::{all_address_info, AddressInfo};
use idb_rs::id0::function::{FuncIdx, FuncordsIdx, IDBFunctionType};
use idb_rs::id0::{ID0Section, Netdelta, SegmentType};
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
}

#[derive(Debug, Clone, Serialize)]
pub struct DirTreeInfo {
    pub functions: Vec<FunctionInfo>,
    pub types: Vec<TILTypeInfo>,
    /// Contains both function and data names (along with their types).
    pub names: Vec<NameInfo>,
    pub comments: Vec<CommentInfo>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct IDBInfo {
    pub sha256: Option<String>,
    pub id0: Option<ID0Info>,
    // NOTE: TILSection is self-contained, so we do no pre-processing.
    pub til: Option<TILSection>,
    pub dir_tree: Option<DirTreeInfo>,
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
        types.dedup_by(|a, b| {
            if a.name.to_string() != b.name.to_string() {
                return false;
            }
            // TODO: Merge types instead of just picking b and not transferring.
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

        // TODO: Decompress til
        let mut til = None;
        if let Some(til_loc) = format.til_location() {
            til = Some(format.read_til(&mut *data, til_loc)?);
        };

        let dir_tree_info = match (id0.as_ref(), id1.as_ref(), id2.as_ref(), til.as_ref()) {
            (Some(id0), Some(id1), id2, til) => Some(self.parse_dir_tree(id0, id1, id2, til)?),
            _ => None,
        };

        let id0_info = id0.as_ref().map(|id0| self.parse_id0(id0)).transpose()?;

        Ok(IDBInfo {
            sha256: None,
            id0: id0_info,
            til,
            dir_tree: dir_tree_info,
        })
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
                    IDBFunctionType::NonTail(_func_ext) => {
                        if func.flags.is_outline() {
                            tracing::debug!("Skipping outlined function... {:0x}", func_start);
                            continue;
                        }

                        // TODO: Parse function registers and params
                        // for def_reg in id0.function_defined_registers(netdelta, &func, &func_ext) {
                        //     tracing::info!("{:0x} : Function register: {:?}", func_start, def_reg);
                        //     let Ok(_def_reg) = def_reg else {
                        //         tracing::warn!("Failed to read function register entry");
                        //         continue;
                        //     };
                        // }

                        // if let Ok(stack_names) =
                        //     id0.function_defined_variables(&root_info, &func, &func_ext)
                        // {
                        //     tracing::info!(
                        //         "{:0x} : Function stack variables: {:#?}",
                        //         func_start,
                        //         stack_names
                        //     );
                        // }

                        functions.push(FunctionInfo {
                            name: None,
                            ty: None,
                            address: func_start,
                            is_library: func.flags.is_lib(),
                            is_no_return: func.flags.is_no_return(),
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

        Ok(ID0Info {
            base_address,
            segments,
            functions,
            comments,
            labels,
            exports,
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

        // sha256

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

        let mut functions = Vec::new();
        if let Some(func_dir_tree) = id0.dirtree_function_address()? {
            func_dir_tree.visit_leafs(|addr_raw| {
                let addr = Address::from_raw(*addr_raw);
                if let Some(info) = AddressInfo::new(id0, id1, id2, netdelta, addr) {
                    if let Ok(Some(func_info)) = func_info_from_addr(&info) {
                        functions.push(func_info);
                    }
                }
            });
        }

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
        })
    }
}
