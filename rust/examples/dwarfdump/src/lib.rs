// Copyright 2021-2023 Vector 35 Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use binaryninja::{
    binaryview::{BinaryView, BinaryViewExt},
    command::{register, Command},
    databuffer::DataBuffer,
    disassembly::{DisassemblyTextLine, InstructionTextToken, InstructionTextTokenContents},
    flowgraph::{BranchType, EdgeStyle, FlowGraph, FlowGraphNode, FlowGraphOption},
    string::BnString,
};

use gimli::{
    AttributeValue::{Encoding, Flag, UnitRef},
    // BigEndian,
    DebuggingInformationEntry,
    Dwarf,
    EntriesTreeNode,
    Error,
    LittleEndian,
    Reader,
    ReaderOffset,
    SectionId,
    Unit,
    UnitSectionOffset,
};

use std::{fmt, ops::Deref, sync::Arc};

static PADDING: [&str; 23] = [
    "",
    " ",
    "  ",
    "   ",
    "    ",
    "     ",
    "      ",
    "       ",
    "        ",
    "         ",
    "          ",
    "           ",
    "            ",
    "             ",
    "              ",
    "               ",
    "                ",
    "                 ",
    "                  ",
    "                   ",
    "                    ",
    "                     ",
    "                      ",
];

// TODO : This isn't comprehensive
fn is_valid(view: &BinaryView) -> bool {
    view.section_by_name(".debug_info").is_ok()
        || (view.parent_view().is_ok()
            && view
                .parent_view()
                .unwrap()
                .section_by_name(".debug_info")
                .is_ok())
}

// gimli::read::load only takes structures containing &[u8]'s, but we need to keep the data buffer alive until it's done using that
//   I don't think that the `Arc` is needed, but I couldn't figure out how else to implement the traits properly without it
#[derive(Clone)]
struct DataBufferWrapper(Arc<DataBuffer>);

impl DataBufferWrapper {
    fn new(buf: DataBuffer) -> Self {
        DataBufferWrapper(Arc::new(buf))
    }
}

impl Deref for DataBufferWrapper {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.0.get_data()
    }
}

impl fmt::Debug for DataBufferWrapper {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DataBufferWrapper")
            .field("0", &"I'm too lazy to do this right")
            .finish()
    }
}

unsafe impl gimli::StableDeref for DataBufferWrapper {}
unsafe impl gimli::CloneStableDeref for DataBufferWrapper {}

type CustomReader<Endian> = gimli::EndianReader<Endian, DataBufferWrapper>;

// TODO : This is very much not comprehensive: see https://github.com/gimli-rs/gimli/blob/master/examples/dwarfdump.rs
fn get_info_string<R: Reader>(
    view: &BinaryView,
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    die_node: &DebuggingInformationEntry<R>,
) -> Vec<DisassemblyTextLine> {
    let mut disassembly_lines: Vec<DisassemblyTextLine> = Vec::with_capacity(10); // This is an estimate so "most" things won't need to resize

    let label_value = match die_node.offset().to_unit_section_offset(unit) {
        UnitSectionOffset::DebugInfoOffset(o) => o.0,
        UnitSectionOffset::DebugTypesOffset(o) => o.0,
    }
    .into_u64();
    let label_string = format!("#0x{:08x}", label_value);
    disassembly_lines.push(DisassemblyTextLine::from(vec![
        InstructionTextToken::new(
            BnString::new(label_string),
            InstructionTextTokenContents::GotoLabel(label_value),
        ),
        InstructionTextToken::new(BnString::new(":"), InstructionTextTokenContents::Text),
    ]));

    disassembly_lines.push(DisassemblyTextLine::from(vec![InstructionTextToken::new(
        BnString::new(die_node.tag().static_string().unwrap()),
        InstructionTextTokenContents::TypeName, // TODO : KeywordToken?
    )]));

    let mut attrs = die_node.attrs();
    while let Some(attr) = attrs.next().unwrap() {
        let mut attr_line: Vec<InstructionTextToken> = Vec::with_capacity(5);
        attr_line.push(InstructionTextToken::new(
            BnString::new("  "),
            InstructionTextTokenContents::Indentation,
        ));

        let len;
        if let Some(n) = attr.name().static_string() {
            len = n.len();
            attr_line.push(InstructionTextToken::new(
                BnString::new(n),
                InstructionTextTokenContents::FieldName,
            ));
        } else {
            // This is rather unlikely, I think
            len = 1;
            attr_line.push(InstructionTextToken::new(
                BnString::new("?"),
                InstructionTextTokenContents::FieldName,
            ));
        }

        // On command line the magic number that looks good is 22, but that's too much whitespace in a basic block, so I chose 18 (22 is the max with the current padding provided)
        if len < 18 {
            attr_line.push(InstructionTextToken::new(
                BnString::new(PADDING[18 - len]),
                InstructionTextTokenContents::Text,
            ));
        }
        attr_line.push(InstructionTextToken::new(
            BnString::new(" = "),
            InstructionTextTokenContents::Text,
        ));

        if let Ok(Some(addr)) = dwarf.attr_address(unit, attr.value()) {
            let addr_string = format!("0x{:08x}", addr);
            attr_line.push(InstructionTextToken::new(
                BnString::new(addr_string),
                InstructionTextTokenContents::Integer(addr),
            ));
        } else if let Ok(attr_reader) = dwarf.attr_string(unit, attr.value()) {
            if let Ok(attr_string) = attr_reader.to_string() {
                attr_line.push(InstructionTextToken::new(
                    BnString::new(attr_string.as_ref()),
                    InstructionTextTokenContents::String({
                        let (_, id, offset) =
                            dwarf.lookup_offset_id(attr_reader.offset_id()).unwrap();
                        offset.into_u64() + view.section_by_name(id.name()).unwrap().start()
                    }),
                ));
            } else {
                attr_line.push(InstructionTextToken::new(
                    BnString::new("??"),
                    InstructionTextTokenContents::Text,
                ));
            }
        } else if let Encoding(type_class) = attr.value() {
            attr_line.push(InstructionTextToken::new(
                BnString::new(type_class.static_string().unwrap()),
                InstructionTextTokenContents::TypeName,
            ));
        } else if let UnitRef(offset) = attr.value() {
            let addr = match offset.to_unit_section_offset(unit) {
                UnitSectionOffset::DebugInfoOffset(o) => o.0,
                UnitSectionOffset::DebugTypesOffset(o) => o.0,
            }
            .into_u64();
            let addr_string = format!("#0x{:08x}", addr);
            attr_line.push(InstructionTextToken::new(
                BnString::new(addr_string),
                InstructionTextTokenContents::GotoLabel(addr),
            ));
        } else if let Flag(true) = attr.value() {
            attr_line.push(InstructionTextToken::new(
                BnString::new("true"),
                InstructionTextTokenContents::Integer(1),
            ));
        } else if let Flag(false) = attr.value() {
            attr_line.push(InstructionTextToken::new(
                BnString::new("false"),
                InstructionTextTokenContents::Integer(1),
            ));

        // Fall-back cases
        } else if let Some(value) = attr.u8_value() {
            let value_string = format!("{}", value);
            attr_line.push(InstructionTextToken::new(
                BnString::new(value_string),
                InstructionTextTokenContents::Integer(value.into()),
            ));
        } else if let Some(value) = attr.u16_value() {
            let value_string = format!("{}", value);
            attr_line.push(InstructionTextToken::new(
                BnString::new(value_string),
                InstructionTextTokenContents::Integer(value.into()),
            ));
        } else if let Some(value) = attr.udata_value() {
            let value_string = format!("{}", value);
            attr_line.push(InstructionTextToken::new(
                BnString::new(value_string),
                InstructionTextTokenContents::Integer(value),
            ));
        } else if let Some(value) = attr.sdata_value() {
            let value_string = format!("{}", value);
            attr_line.push(InstructionTextToken::new(
                BnString::new(value_string),
                InstructionTextTokenContents::Integer(value as u64),
            ));
        } else {
            let attr_string = format!("{:?}", attr.value());
            attr_line.push(InstructionTextToken::new(
                BnString::new(attr_string),
                InstructionTextTokenContents::Text,
            ));
        }
        disassembly_lines.push(DisassemblyTextLine::from(attr_line));
    }

    disassembly_lines
}

fn process_tree<R: Reader>(
    view: &BinaryView,
    dwarf: &Dwarf<R>,
    unit: &Unit<R>,
    graph: &FlowGraph,
    graph_parent: &FlowGraphNode,
    die_node: EntriesTreeNode<R>,
) {
    // Namespaces only - really interesting to look at!
    // if (die_node.entry().tag() == constants::DW_TAG_namespace)
    //   || (die_node.entry().tag() == constants::DW_TAG_class_type)
    //   || (die_node.entry().tag() == constants::DW_TAG_compile_unit)
    //   || (die_node.entry().tag() == constants::DW_TAG_subprogram)
    // {
    let new_node = FlowGraphNode::new(graph);

    let attr_string = get_info_string(view, dwarf, unit, die_node.entry());
    new_node.set_disassembly_lines(&attr_string);

    graph.append(&new_node);
    graph_parent.add_outgoing_edge(
        BranchType::UnconditionalBranch,
        &new_node,
        &EdgeStyle::default(),
    );

    let mut children = die_node.children();
    while let Some(child) = children.next().unwrap() {
        process_tree(view, dwarf, unit, graph, &new_node, child);
    }
    // }
}

fn dump_dwarf(bv: &BinaryView) {
    let view = if bv.section_by_name(".debug_info").is_ok() {
        bv.to_owned()
    } else {
        bv.parent_view().unwrap()
    };

    // TODO : Accommodate Endianity
    let get_section_data_little =
        |section_id: SectionId| -> Result<CustomReader<LittleEndian>, Error> {
            if let Ok(section) = view.section_by_name(section_id.name()) {
                let offset = section.start();
                let len = section.len();
                if len == 0 {
                    Ok(CustomReader::new(
                        DataBufferWrapper::new(DataBuffer::default()),
                        LittleEndian,
                    ))
                } else if let Ok(read_buffer) = view.read_buffer(offset, len) {
                    Ok(CustomReader::new(
                        DataBufferWrapper::new(read_buffer),
                        LittleEndian,
                    ))
                } else {
                    Err(Error::Io)
                }
            } else {
                Ok(CustomReader::new(
                    DataBufferWrapper::new(DataBuffer::default()),
                    LittleEndian,
                ))
            }
        };

    let empty_reader_little = |_: SectionId| -> Result<CustomReader<LittleEndian>, Error> {
        Ok(CustomReader::new(
            DataBufferWrapper::new(DataBuffer::default()),
            LittleEndian,
        ))
    };

    let graph = FlowGraph::new();
    graph.set_option(FlowGraphOption::FlowGraphUsesBlockHighlights, true);
    graph.set_option(FlowGraphOption::FlowGraphUsesInstructionHighlights, true);

    let graph_root = FlowGraphNode::new(&graph);
    graph_root.set_lines(vec!["Graph Root"]);
    graph.append(&graph_root);

    let dwarf = Dwarf::load(&get_section_data_little, &empty_reader_little).unwrap();

    let mut iter = dwarf.units();
    while let Some(header) = iter.next().unwrap() {
        let unit = dwarf.unit(header).unwrap();
        let mut entries = unit.entries();
        let mut depth = 0;

        if let Some((delta_depth, entry)) = entries.next_dfs().unwrap() {
            depth += delta_depth;
            assert!(depth >= 0);

            let mut tree = unit.entries_tree(Some(entry.offset())).unwrap();
            let root = tree.root().unwrap();

            process_tree(&view, &dwarf, &unit, &graph, &graph_root, root);
        }
    }

    view.show_graph_report("DWARF", graph);
}

struct DWARFDump;

impl Command for DWARFDump {
    fn action(&self, view: &BinaryView) {
        dump_dwarf(view);
    }

    fn valid(&self, view: &BinaryView) -> bool {
        is_valid(view)
    }
}

#[no_mangle]
pub extern "C" fn UIPluginInit() -> bool {
    register(
        "DWARF Dump",
        "Show embedded DWARF info as a tree structure for you to navigate",
        DWARFDump {},
    );
    true
}
