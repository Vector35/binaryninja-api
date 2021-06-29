# Template

[The only official method of providing linker arguments to a crate is through that crate's `build.rs`](https://github.com/rust-lang/cargo/issues/9554), thus this template.

Please see `Cargo.toml` for further configuration options.

## Plugins

Enable
```
[lib]
crate-type = ["cdylib"]
```
in `Cargo.toml`.

## Standalone executables

All standalone executables should call both `binaryninja::headless::init()` and `binaryninja::headless::shutdown()` (see [`src/main.rs`](src/main.rs)).
Standalone executables will fail to link if you do not provide a `build.rs`.  The one provided here should work.
