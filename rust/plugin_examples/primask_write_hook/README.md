# PRIMASK Write Hook Example

This example registers a Rust architecture hook on `thumb2` that appends ` ; Toggling interrupts` to the disassembly
of `msr primask` instructions.

## Building

```sh
# Build from the root directory (binaryninja-api)
cargo build -p example_primask_write_hook
# Link binary on macOS
ln -sf "$PWD/target/debug/libexample_primask_write_hook.dylib" ~/Library/Application\ Support/Binary\ Ninja/plugins/
```
