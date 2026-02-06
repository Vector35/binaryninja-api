# binaryninja-rs

Official Rust bindings for [Binary Ninja].

- [Getting Started](#getting-started)
- [Examples](https://github.com/Vector35/binaryninja-api/tree/dev/rust/examples)
- [Documentation](https://dev-rust.binary.ninja/)
- [Offline Documentation](#offline-documentation)

## WARNING

These bindings are still actively under development. Compatibility _will_ break and conventions _will_ change!
It is encouraged that you reference a specific commit to avoid having your plugin/application break when the API changes.
To specify a specific commit, see the cargo documentation [here](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#choice-of-commit).

If you are worried about breaking changes, avoid modules with warnings about instability!

**MSRV**: The Rust version specified in the `Cargo.toml`.

## Example

```rust
use binaryninja::headless::Session;
use binaryninja::binary_view::{BinaryViewBase, BinaryViewExt};

fn main() {
    let headless_session = Session::new().expect("Failed to initialize session");
    let bv = headless_session
        .load("/bin/cat")
        .expect("Couldn't open `/bin/cat`");
    
    println!("File:  `{}`", bv.file());
    println!("File size: `{:#x}`", bv.len());
    println!("Function count: {}", bv.functions().len());
    
    for func in &bv.functions() {
        println!("{}: {}", func.start(), func.symbol());
    }
}
```

More examples can be found in [here](https://github.com/Vector35/binaryninja-api/tree/dev/rust/examples).

## Getting Started

### Requirements

- Having [Binary Ninja] installed (and your license registered)
  - For headless operation you must have a headless supporting license.
- Clang
- Rust

### Link to Binary Ninja

Writing a standalone executable _or_ a plugin requires that you link to `binaryninjacore` directly. The process of locating that however
is done for you within the `binaryninjacore-sys` crate. Because linker arguments are _not_ transitive for executables, you
must specify them within your `build.rs`.

`Cargo.toml`:
```toml
[dependencies]
binaryninja = { git = "https://github.com/Vector35/binaryninja-api.git", branch = "dev"}
# Locates binaryninjacore on your system.
binaryninjacore-sys = { git = "https://github.com/Vector35/binaryninja-api.git", branch = "dev"}
```

`build.rs`:
```rust
fn main() {
    let link_path =
        std::env::var_os("DEP_BINARYNINJACORE_PATH").expect("DEP_BINARYNINJACORE_PATH not specified");
    
    println!("cargo::rustc-link-lib=dylib=binaryninjacore");
    println!("cargo::rustc-link-search={}", link_path.to_str().unwrap());
    
    #[cfg(target_os = "linux")]
    {
        println!(
            "cargo::rustc-link-arg=-Wl,-rpath,{0},-L{0}",
            link_path.to_string_lossy()
        );
    }

    #[cfg(target_os = "macos")]
    {
        let crate_name = std::env::var("CARGO_PKG_NAME").expect("CARGO_PKG_NAME not set");
        let lib_name = crate_name.replace('-', "_");
        println!("cargo::rustc-link-arg=-Wl,-install_name,@rpath/lib{}.dylib", lib_name);
    }
}
```

### Write a Plugin

Plugins are loaded at runtime and as such will have their own initialization routine.

`Cargo.toml`:
```toml
[lib]
crate-type = ["cdylib"]
```

`lib.rs`:
```rust
#[allow(non_snake_case)]
#[no_mangle]
pub extern "C" fn CorePluginInit() -> bool {
    // Initialize logging
    // Register custom architectures, workflows, demanglers, 
    // function recognizers, platforms and views!
    true
}
```

Examples for writing a plugin can be found [here](https://github.com/Vector35/binaryninja-api/tree/dev/rust/plugin_examples) and [here](https://github.com/Vector35/binaryninja-api/tree/dev/plugins).

#### Sending Logs

To send logs from your plugin to Binary Ninja, you can use the [tracing](https://docs.rs/tracing/latest/tracing/) crate.
At the beginning of your plugin's initialization routine, register the tracing subscriber with [`crate::tracing_init!`],
for more details see the documentation of that macro.

#### Plugin Compatibility

A built plugin can only be loaded into a compatible Binary Ninja version, this is determined by the ABI version of the 
plugin. The ABI version is located at the top of the `binaryninjacore.h` header file, and as such plugins should pin
their binary ninja dependency to a specific tag or commit hash. See the cargo documentation [here](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#choice-of-commit)
for more details.

### Write a Standalone Executable

If you have a headless supporting license, you are able to use Binary Ninja as a regular dynamically loaded library.

Standalone executables must initialize the core themselves. [`crate::headless::init()`] to initialize the core, and
[`crate::headless::shutdown()`] to shutdown the core. Prefer using [`crate::headless::Session`] as it will 
shut down for you once it is dropped.

`main.rs`:
```rust
fn main() {
  // You must initialize the core to use Binary Ninja.
  let session = binaryninja::headless::Session::new().expect("Failed to initialize!");
  // Once `session` is dropped, the core will be shutdown!
}
```

#### Capturing Logs

To capture logs from Binary Ninja, you can use the [tracing](https://docs.rs/tracing/latest/tracing/) crate. Before initializing
the core but after registering your tracing subscriber, register a [`crate::tracing::TracingLogListener`], for more details see
the documentation for that type.

## Offline Documentation

Offline documentation can be generated like any other rust crate, using `cargo doc`.

```shell
git clone https://github.com/Vector35/binaryninja-api
cd binaryninja-api
cargo doc --no-deps --open -p binaryninja
```

## Contributing

If you're thinking of contributing to the Rust API, we encourage you to join the #rust-api channel in our [Slack](https://slack.binary.ninja), especially for large-effort PRs.

### Testing

When contributing new APIs or refactoring existing APIs, it is vital that you test your code! If you do not have a 
headless supported license, you should still be able to write them and open your PR. Once open, a 
maintainer will approve tests to run and from there you can refine the test so that it passes in CI.

### Documentation

When refactoring or making new changes, make sure that the documentation for the respective APIs is up to date and not missing.
Much of the APIs documentation exists only in the python bindings, so use that as a guide. If there is an API that confuses you,
it will likely confuse someone else, and you should make an issue or ask for guidance in the Slack channel above.

---

#### Attribution

For attribution, please refer to the [Rust Licenses section](https://docs.binary.ninja/about/open-source.html#rust-licenses) of the user documentation.

[Binary Ninja]: https://binary.ninja/