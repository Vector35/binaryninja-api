# FlowGraph Layout Example

This example implements a simple flow graph layout using the rust crate `rust-sugiyama`. After building and placing this
in the plugin directory, override the default flow graph layout setting `rendering.graph.defaultLayout`.

This example is complete _except_ for edge routing, we simply draw the edge from the outgoing nodes bottom to the 
incoming nodes top, a real layout would route the edges around nodes to avoid overlaps and other rendering oddities.

## Building

```sh
# Build from the root directory (binaryninja-api)
cargo build -p example_flowgraph_layout
# Link binary on macOS
ln -sf $PWD/target/debug/libexample_flowgraph_layout.dylib ~/Library/Application\ Support/Binary\ Ninja/plugins
```
