# DWARF Dump Example

This is actually a fully-developed plugin, rather than a measly example.

Two features this does not support are: files in big endian, and .dwo files

## How to use

Simply `cargo build --release` in this directory, and copy the `.so` from the target directory to your plugin directory

### Attribution

This example makes use of:
  - [gimli] ([gimli license] - MIT)

[gimli license]: https://github.com/gimli-rs/gimli/blob/master/LICENSE-MIT
[gimli]: https://github.com/gimli-rs/gimli
