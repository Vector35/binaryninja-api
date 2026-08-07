# arch-riscv

This is the RISC-V architecture plugin that ships with Binary Ninja.

## Building

Building the architecture plugin requires the Rust language development tools.

Run `cargo build --release` to build the plugin. The plugin can be found in the `target/release` directory as `libarch_riscv.so`, `libarch_riscv.dylib` or `arch_riscv.dll` depending on your platform.

To install the plugin, copy it into the user plugins directory (you can locate this by using the "Open Plugin Folder" option in the Binary Ninja UI). This local plugin takes precedence over the bundled RISC-V architecture plugin. Restart Binary Ninja to load the local version.

**Do not replace the architecture plugin in the Binary Ninja install directory.  This will be overwritten every time there is a Binary Ninja update. Use the above process to ensure that updates do not automatically uninstall your custom build.**

## Pull Requests

Please follow whatever formatting conventions are present in the file you edit.  Pay attention to curly brackets, spacing, tabs vs. spaces, etc.
