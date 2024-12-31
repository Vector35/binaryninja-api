use binaryninja::{
    binaryview::{BinaryView, BinaryViewExt},
    disassembly::{DisassemblyTextLine, InstructionTextToken, InstructionTextTokenContents},
    flowgraph::{BranchType, EdgePenStyle, EdgeStyle, FlowGraph, FlowGraphNode, ThemeColor},
};

fn test_graph(view: &BinaryView) {
    let graph = FlowGraph::new();

    let disassembly_lines_a = vec![DisassemblyTextLine::from(vec![
        InstructionTextToken::new("Li", InstructionTextTokenContents::Text),
        InstructionTextToken::new("ne", InstructionTextTokenContents::Text),
        InstructionTextToken::new(" 1", InstructionTextTokenContents::Text),
    ])];

    let node_a = FlowGraphNode::new(&graph);
    node_a.set_disassembly_lines(&disassembly_lines_a);

    let node_b = FlowGraphNode::new(&graph);
    let disassembly_lines_b = vec![DisassemblyTextLine::from(&vec!["Li", "ne", " 2"])];
    node_b.set_disassembly_lines(&disassembly_lines_b);

    let node_c = FlowGraphNode::new(&graph);
    node_c.set_lines(vec!["Line 3", "Line 4", "Line 5"]);

    graph.append(&node_a);
    graph.append(&node_b);
    graph.append(&node_c);

    let edge = EdgeStyle::new(EdgePenStyle::DashDotDotLine, 2, ThemeColor::AddressColor);
    node_a.add_outgoing_edge(BranchType::UserDefinedBranch, &node_b, &edge);
    node_a.add_outgoing_edge(
        BranchType::UnconditionalBranch,
        &node_c,
        &EdgeStyle::default(),
    );

    view.show_graph_report("Rust Graph Title", &graph);
}

fn main() {
    println!("Starting session...");
    // This loads all the core architecture, platform, etc plugins
    let headless_session = binaryninja::headless::Session::new();

    println!("Loading binary...");
    let bv = headless_session
        .load("/bin/cat")
        .expect("Couldn't open `/bin/cat`");

    // TODO: Register BNInteractionHandlerCallbacks with showGraphReport pointing at our function
    // TODO: Idea: register showGraphReport that dumps a dotgraph to stdin

    test_graph(&bv);
}