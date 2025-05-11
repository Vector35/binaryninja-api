use binaryninja::flowgraph::edge::EdgeStyle;
use binaryninja::flowgraph::FlowGraphNode;
use binaryninja::function::FunctionViewType;
use binaryninja::interaction::form::Form;
use binaryninja::interaction::handler::{
    register_interaction_handler, InteractionHandler, InteractionHandlerTask,
};
use binaryninja::interaction::{MessageBoxButtonResult, MessageBoxButtonSet, MessageBoxIcon};
use binaryninja::{
    binary_view::{BinaryView, BinaryViewExt},
    disassembly::{DisassemblyTextLine, InstructionTextToken, InstructionTextTokenKind},
    flowgraph::{BranchType, EdgePenStyle, FlowGraph, ThemeColor},
};

pub struct GraphPrinter;

impl GraphPrinter {
    pub fn print_graph(&self, graph: &FlowGraph) {
        println!("Printing flow graph:");
        for node in &graph.nodes() {
            // Print all disassembly lines in the node
            println!("Node @ {:?}:", node.position());
            println!("------------------");
            println!("Disassembly lines:");
            for line in &node.lines() {
                println!("  {}", line);
            }

            // Print outgoing edges
            println!("Outgoing edges:");
            for edge in &node.outgoing_edges() {
                println!("  {:?} => {:?}", edge.branch_type, edge.target.position());
            }
            println!("------------------");
        }
    }
}

impl InteractionHandler for GraphPrinter {
    fn show_message_box(
        &mut self,
        _title: &str,
        _text: &str,
        _buttons: MessageBoxButtonSet,
        _icon: MessageBoxIcon,
    ) -> MessageBoxButtonResult {
        MessageBoxButtonResult::CancelButton
    }

    fn open_url(&mut self, _url: &str) -> bool {
        false
    }

    fn run_progress_dialog(
        &mut self,
        _title: &str,
        _can_cancel: bool,
        _task: &InteractionHandlerTask,
    ) -> bool {
        false
    }

    fn show_plain_text_report(&mut self, _view: Option<&BinaryView>, title: &str, contents: &str) {
        println!("Plain text report");
        println!("Title: {}", title);
        println!("Contents: {}", contents);
    }

    fn show_graph_report(&mut self, _view: Option<&BinaryView>, title: &str, graph: &FlowGraph) {
        println!("Graph report");
        println!("Title: {}", title);
        self.print_graph(graph);
    }

    fn get_form_input(&mut self, _form: &mut Form) -> bool {
        false
    }
}

fn test_graph() {
    let graph = FlowGraph::new();

    let disassembly_lines_a = vec![DisassemblyTextLine::new(vec![
        InstructionTextToken::new("Li", InstructionTextTokenKind::Text),
        InstructionTextToken::new("ne", InstructionTextTokenKind::Text),
        InstructionTextToken::new(" 1", InstructionTextTokenKind::Text),
    ])];

    let node_a = FlowGraphNode::new(&graph);
    node_a.set_lines(disassembly_lines_a);
    node_a.set_position(1337, 7331);

    let node_b = FlowGraphNode::new(&graph);
    node_b.set_position(100, 200);
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

    graph.show("Rust Example Graph");
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

    // Register the interaction handler so we can see the graph report headlessly.
    register_interaction_handler(GraphPrinter);

    test_graph();

    for func in bv.functions().iter().take(5) {
        // TODO: Why are the nodes empty? Python its empty until its shown...
        let graph = func.create_graph(FunctionViewType::MediumLevelIL, None);
        let func_name = func.symbol().short_name();
        let title = func_name.to_string_lossy();
        bv.show_graph_report(&title, &graph);
    }
}
