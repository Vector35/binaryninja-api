// Copyright 2021-2024 Vector 35 Inc.
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
    binary_view::{BinaryView, BinaryViewExt},
    command::{register_command, Command},
    disassembly::{DisassemblyTextLine, InstructionTextToken, InstructionTextTokenKind},
    flowgraph::{BranchType, EdgeStyle, FlowGraph, FlowGraphNode, FlowGraphOption},
};
use dwarfreader::is_valid;

use binaryninja::disassembly::StringType;
use gimli::{
    AttributeValue::{Encoding, Flag, UnitRef},
    // BigEndian,
    DebuggingInformationEntry,
    Dwarf,
    EntriesTreeNode,
    Reader,
    ReaderOffset,
    SectionId,
    Unit,
    UnitSectionOffset,
};

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

// TODO : This is very much not comprehensive: see https://github.com/gimli-rs/gimli/blob/master/examples/dwarfdump.rs
fn get_info_string<R: Reader>(
    _view: &BinaryView,
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
    disassembly_lines.push(DisassemblyTextLine::new(vec![
        InstructionTextToken::new(
            &label_string,
            InstructionTextTokenKind::GotoLabel {
                target: label_value,
            },
        ),
        InstructionTextToken::new(":", InstructionTextTokenKind::Text),
    ]));

    disassembly_lines.push(DisassemblyTextLine::new(vec![InstructionTextToken::new(
        die_node.tag().static_string().unwrap(),
        InstructionTextTokenKind::TypeName, // TODO : KeywordToken?
    )]));

    let mut attrs = die_node.attrs();
    while let Some(attr) = attrs.next().unwrap() {
        let mut attr_line: Vec<InstructionTextToken> = Vec::with_capacity(5);
        attr_line.push(InstructionTextToken::new(
            "  ",
            InstructionTextTokenKind::Indentation,
        ));

        let len;
        if let Some(n) = attr.name().static_string() {
            len = n.len();
            attr_line.push(InstructionTextToken::new(
                n,
                // TODO: Using field name for this is weird.
                InstructionTextTokenKind::FieldName {
                    offset: 0,
                    type_names: vec![],
                },
            ));
        } else {
            // This is rather unlikely, I think
            len = 1;
            attr_line.push(InstructionTextToken::new(
                "?",
                // TODO: Using field name for this is weird.
                InstructionTextTokenKind::FieldName {
                    offset: 0,
                    type_names: vec![],
                },
            ));
        }

        // On command line the magic number that looks good is 22, but that's too much whitespace in a basic block, so I chose 18 (22 is the max with the current padding provided)
        if len < 18 {
            attr_line.push(InstructionTextToken::new(
                PADDING[18 - len],
                InstructionTextTokenKind::Text,
            ));
        }
        attr_line.push(InstructionTextToken::new(
            " = ",
            InstructionTextTokenKind::Text,
        ));

        if let Ok(Some(addr)) = dwarf.attr_address(unit, attr.value()) {
            let addr_string = format!("0x{:08x}", addr);
            attr_line.push(InstructionTextToken::new(
                &addr_string,
                InstructionTextTokenKind::Integer {
                    value: addr,
                    size: None,
                },
            ));
        } else if let Ok(attr_reader) = dwarf.attr_string(unit, attr.value()) {
            if let Ok(attr_string) = attr_reader.to_string() {
                attr_line.push(InstructionTextToken::new(
                    attr_string.as_ref(),
                    InstructionTextTokenKind::String {
                        ty: StringType::Utf8String,
                    },
                ));
            } else {
                attr_line.push(InstructionTextToken::new(
                    "??",
                    InstructionTextTokenKind::Text,
                ));
            }
        } else if let Encoding(type_class) = attr.value() {
            attr_line.push(InstructionTextToken::new(
                type_class.static_string().unwrap(),
                InstructionTextTokenKind::TypeName,
            ));
        } else if let UnitRef(offset) = attr.value() {
            let addr = match offset.to_unit_section_offset(unit) {
                UnitSectionOffset::DebugInfoOffset(o) => o.0,
                UnitSectionOffset::DebugTypesOffset(o) => o.0,
            }
            .into_u64();
            let addr_string = format!("#0x{:08x}", addr);
            attr_line.push(InstructionTextToken::new(
                &addr_string,
                InstructionTextTokenKind::GotoLabel { target: addr },
            ));
        } else if let Flag(true) = attr.value() {
            attr_line.push(InstructionTextToken::new(
                "true",
                InstructionTextTokenKind::Integer {
                    value: 1,
                    size: None,
                },
            ));
        } else if let Flag(false) = attr.value() {
            attr_line.push(InstructionTextToken::new(
                "false",
                InstructionTextTokenKind::Integer {
                    value: 0,
                    size: None,
                },
            ));

        // Fall-back cases
        } else if let Some(value) = attr.u8_value() {
            let value_string = format!("{}", value);
            attr_line.push(InstructionTextToken::new(
                &value_string,
                InstructionTextTokenKind::Integer {
                    value: value as u64,
                    size: None,
                },
            ));
        } else if let Some(value) = attr.u16_value() {
            let value_string = format!("{}", value);
            attr_line.push(InstructionTextToken::new(
                &value_string,
                InstructionTextTokenKind::Integer {
                    value: value as u64,
                    size: None,
                },
            ));
        } else if let Some(value) = attr.udata_value() {
            let value_string = format!("{}", value);
            attr_line.push(InstructionTextToken::new(
                &value_string,
                InstructionTextTokenKind::Integer { value, size: None },
            ));
        } else if let Some(value) = attr.sdata_value() {
            let value_string = format!("{}", value);
            attr_line.push(InstructionTextToken::new(
                &value_string,
                InstructionTextTokenKind::Integer {
                    value: value as u64,
                    size: None,
                },
            ));
        } else {
            let attr_string = format!("{:?}", attr.value());
            attr_line.push(InstructionTextToken::new(
                &attr_string,
                InstructionTextTokenKind::Text,
            ));
        }
        disassembly_lines.push(DisassemblyTextLine::new(attr_line));
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
    new_node.set_lines(attr_string);

    graph.append(&new_node);
    graph_parent.add_outgoing_edge(
        BranchType::UnconditionalBranch,
        &new_node,
        EdgeStyle::default(),
    );

    let mut children = die_node.children();
    while let Some(child) = children.next().unwrap() {
        process_tree(view, dwarf, unit, graph, &new_node, child);
    }
    // }
}

fn dump_dwarf(bv: &BinaryView) {
    let view = if bv.section_by_name(".debug_info").is_some() {
        bv.to_owned()
    } else {
        bv.parent_view().unwrap()
    };

    let graph = FlowGraph::new();
    graph.set_option(FlowGraphOption::FlowGraphUsesBlockHighlights, true);
    graph.set_option(FlowGraphOption::FlowGraphUsesInstructionHighlights, true);

    let graph_root = FlowGraphNode::new(&graph);
    graph_root.set_lines(["Graph Root".into()]);
    graph.append(&graph_root);

    let endian = dwarfreader::get_endian(bv);
    let section_reader = |section_id: SectionId| -> _ {
        dwarfreader::create_section_reader(section_id, bv, endian, false)
    };
    let dwarf = Dwarf::load(&section_reader).unwrap();

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

    view.show_graph_report("DWARF", &graph);
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
    register_command(
        "DWARF Dump",
        "Show embedded DWARF info as a tree structure for you to navigate",
        DWARFDump {},
    );
    true
}
