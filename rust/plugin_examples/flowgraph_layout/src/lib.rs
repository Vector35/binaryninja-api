use binaryninja::flowgraph::edge::Point;
use binaryninja::flowgraph::layout::{register_flowgraph_layout, FlowGraphLayout};
use binaryninja::flowgraph::{FlowGraph, FlowGraphNode};
use binaryninja::rc::Ref;
use std::collections::HashMap;

pub struct StableGraphBuilder;

impl StableGraphBuilder {
    pub fn new() -> Self {
        Self {}
    }

    pub fn build(
        self,
        nodes: &[FlowGraphNode],
    ) -> petgraph::stable_graph::StableDiGraph<Ref<FlowGraphNode>, ()> {
        let mut graph = petgraph::stable_graph::StableDiGraph::<Ref<FlowGraphNode>, ()>::new();
        let mut node_idx_map = HashMap::<Ref<FlowGraphNode>, petgraph::graph::NodeIndex>::new();
        for node in nodes {
            let owned_node = node.to_owned();
            node_idx_map.insert(owned_node.clone(), graph.add_node(owned_node));
        }
        for node in nodes {
            let node_idx = node_idx_map.get(node).unwrap();
            for edge in &node.outgoing_edges() {
                let target_node_idx = node_idx_map.get(&edge.target).unwrap();
                graph.add_edge(*node_idx, *target_node_idx, ());
            }
        }
        graph
    }
}

struct SugiyamaLayout;

impl FlowGraphLayout for SugiyamaLayout {
    fn layout(&self, graph: &FlowGraph, nodes: &[FlowGraphNode]) -> bool {
        let mut config = rust_sugiyama::configure::Config::default();
        config.vertex_spacing = 5.0;

        let vertex_size = |_, node: &Ref<FlowGraphNode>| {
            let (width, height) = node.size();
            (width as f64 * 1.2, height as f64)
        };
        let pet_graph = StableGraphBuilder::new().build(nodes);
        let layouts = rust_sugiyama::from_graph(&pet_graph, &vertex_size, &config);

        // Position graph nodes
        for (nodes, _, _) in &layouts {
            for (node_idx, (x, y)) in nodes {
                let node = pet_graph.node_weight(*node_idx).unwrap();
                node.set_position(*x as i32, *y as i32);
            }
        }

        // Add edges to graph nodes
        for (nodes, _, _) in &layouts {
            for (node_idx, (x, y)) in nodes {
                let node = pet_graph.node_weight(*node_idx).unwrap();
                let (width, height) = node.size();
                for (edge_idx, edge) in node.outgoing_edges().iter().enumerate() {
                    let from_point_x = x + (width as f64 / 2.0);
                    let from_point_y = y + height as f64;
                    let from_point = Point {
                        x: from_point_x as f32,
                        y: from_point_y as f32,
                    };
                    let (target_node_x, target_node_y) = edge.target.position();
                    let (target_node_width, _) = edge.target.size();
                    let to_point_x = target_node_x as f64 + (target_node_width as f64 / 2.0);
                    let to_point_y = target_node_y;
                    let to_point = Point {
                        x: to_point_x as f32,
                        y: to_point_y as f32,
                    };
                    // NOTE: This does not do proper routing, this will add edge points from the outgoing node
                    // to the target node, this will lead to lines overlapping nodes and other rendering oddities.
                    // The reason we do not do proper routing is because that is quite a bit more code with some
                    // dependence on a navigation algorithm like a-star.
                    node.set_outgoing_edge_points(edge_idx, &[from_point, to_point]);
                }
            }
        }

        // Calculate graph size and node visibility
        let mut min_x = f32::MAX;
        let mut min_y = f32::MAX;
        let mut max_x = f32::MIN;
        let mut max_y = f32::MIN;

        for node in nodes {
            let (node_x, node_y) = node.position();
            let (node_width, node_height) = node.size();

            // Initialize per-node bounds based on the node's current box
            let mut min_node_x = node_x;
            let mut max_node_x = node_x + node_width;
            let mut min_node_y = node_y;
            let mut max_node_y = node_y + node_height;

            for edge in &node.outgoing_edges() {
                for point in &edge.points {
                    let px = point.x;
                    let py = point.y;

                    // Update Global Graph Bounds
                    min_x = min_x.min(px);
                    min_y = min_y.min(py);
                    max_x = max_x.max(px + 1.0);
                    max_y = max_y.max(py + 1.0);

                    // Update Node Visibility Bounds
                    min_node_x = min_node_x.min(px as i32);
                    max_node_x = max_node_x.max(px as i32 + 1);
                    min_node_y = min_node_y.min(py as i32);
                    max_node_y = max_node_y.max(py as i32 + 1);
                }
            }

            node.set_visibility_region(
                min_node_x,
                min_node_y,
                max_node_x - min_node_x,
                max_node_y - min_node_y,
            );
        }

        // Set final graph dimensions
        if min_x != f32::MAX {
            let (horiz_node_margin, vert_node_margin) = graph.node_margins();
            let final_graph_width = (max_x - min_x) as i32 + horiz_node_margin * 2;
            let final_graph_height = (max_y - min_y) as i32 + vert_node_margin * 2;
            graph.set_size(final_graph_width, final_graph_height);
        }

        true
    }
}

/// # Safety
/// This function is called from Binary Ninja once to initialize the plugin.
#[allow(non_snake_case)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn CorePluginInit() -> bool {
    // Register flow graph layout
    register_flowgraph_layout("Sugiyama", SugiyamaLayout);
    true
}
