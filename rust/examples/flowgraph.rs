use binaryninja::{
    binary_view::{BinaryView, BinaryViewExt},
    disassembly::{DisassemblyTextLine, InstructionTextToken, InstructionTextTokenKind},
    flowgraph::{BranchType, EdgePenStyle, EdgeStyle, FlowGraph, FlowGraphNode, ThemeColor},
};

fn test_graph(view: &BinaryView) {
    let graph = FlowGraph::new();

    let disassembly_lines_a = vec![DisassemblyTextLine::new(vec![
        InstructionTextToken::new("Li", InstructionTextTokenKind::Text),
        InstructionTextToken::new("ne", InstructionTextTokenKind::Text),
        InstructionTextToken::new(" 1", InstructionTextTokenKind::Text),
    ])];

    let node_a = FlowGraphNode::new(&graph);
    node_a.set_lines(disassembly_lines_a);

    let node_b = FlowGraphNode::new(&graph);
    let disassembly_lines_b = vec![DisassemblyTextLine::new(vec![
        InstructionTextToken::new("Li", InstructionTextTokenKind::Text),
        InstructionTextToken::new("ne", InstructionTextTokenKind::Text),
        InstructionTextToken::new(" 2", InstructionTextTokenKind::Text),
    ])];
    node_b.set_lines(disassembly_lines_b);

    graph.append(&node_a);
    graph.append(&node_b);

    let edge = EdgeStyle::new(EdgePenStyle::DashDotDotLine, 2, ThemeColor::AddressColor);
    node_a.add_outgoing_edge(BranchType::UserDefinedBranch, &node_b, edge);
    node_b.add_outgoing_edge(
        BranchType::UnconditionalBranch,
        &node_a,
        EdgeStyle::default(),
    );

    view.show_graph_report("Rust Graph Title", &graph);
}

fn main() {
    println!("Starting session...");
    // This loads all the core architecture, platform, etc plugins
    let headless_session =
        binaryninja::headless::Session::new().expect("Failed to initialize session");

    println!("Loading binary...");
    let bv = headless_session
        .load("/bin/cat")
        .expect("Couldn't open `/bin/cat`");

    // TODO: Register BNInteractionHandlerCallbacks with showGraphReport pointing at our function
    // TODO: Idea: register showGraphReport that dumps a dotgraph to stdin

    test_graph(&bv);
}
