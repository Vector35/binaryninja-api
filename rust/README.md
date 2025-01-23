# binaryninja-rs

Official Rust bindings for [Binary Ninja].

- [Getting Started](#getting-started)
- [Examples](https://github.com/Vector35/binaryninja-api/tree/dev/rust/examples)
- [Documentation](https://dev-rust.binary.ninja/)
- [Offline Documentation](#offline-documentation)

## WARNING

These bindings are still actively under development. Compatibility _will_ break and conventions _will_ change!
It is encouraged that you reference a specific commit to avoid having your plugin/application break when the API changes.
To specify a specific commit see the cargo documentation [here](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html#choice-of-commit).

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
    
    println!("Filename:  `{}`", bv.file().filename());
    println!("File size: `{:#x}`", bv.len());
    println!("Function count: {}", bv.functions().len());
    
    for func in &bv.functions() {
        println!("{}:", func.symbol().full_name());
    }
}
```

More examples can be found in [here](https://github.com/Vector35/binaryninja-api/tree/dev/rust/examples).

## Getting Started

### Requirements

- Having BinaryNinja installed (and your license registered)
  - For headless operation you must have a headless supporting license.
- Clang
- Rust

### Link to Binary Ninja

Writing a standalone executable _or_ a plugin requires that you link to `binaryninjacore` directly. The process of locating that however
is done for you within the `binaryninjacore-sys` crate. Because linker arguments are _not_ transitive for executables you
must specify them within your `build.rs`.

`Cargo.toml`:
```toml
[dependencies]
binaryninja = { git = "https://github.com/Vector35/binaryninja-api.git", branch = "dev"}
# Locates binaryninjacore on your system.
binaryninjacore-sys = { git = "https://github.com/Vector35/binaryninja-api.git", branch = "dev"}
```

`build.rs`:
```doctestinjectablerust
fn main() {
    let link_path =
        std::env::var_os("DEP_BINARYNINJACORE_PATH").expect("DEP_BINARYNINJACORE_PATH not specified");
    
    println!("cargo::rustc-link-lib=dylib=binaryninjacore");
    println!("cargo::rustc-link-search={}", link_path.to_str().unwrap());
    
    #[cfg(not(target_os = "windows"))]
    {
        println!(
            "cargo::rustc-link-arg=-Wl,-rpath,{0},-L{0}",
            link_path.to_string_lossy()
        );
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

Examples for writing a plugin can be found [here](https://github.com/Vector35/binaryninja-api/tree/dev/plugins).

### Write a Standalone Executable

If you have a headless supporting license you are able to use Binary Ninja as a regular dynamically loaded library.

Standalone executables must initialize the core themselves. `binaryninja::headless::init()` to initialize the core, and
`binaryninja::headless::shutdown()` to shutdown the core. Prefer using `binaryninja::headless::Session` as it will 
shut down for you once it is dropped.

`main.rs`:
```rust
fn main() {
  // You must initialize the core to use Binary Ninja.
  let session = binaryninja::headless::Session::new().expect("Failed to initialize!");
  // Once `session` is dropped, the core will be shutdown!
}
```

## Offline Documentation

Offline documentation can be generated like any other rust crate, using `cargo doc`.

```shell
git clone https://github.com/Vector35/binaryninja-api
cd binaryninja-api
cargo doc --no-deps --open -p binaryninja
```

## Contributing

If you're thinking of contributing to the Rust API, we encourage you to join the #rust-api channel in our [Slack](https://slack.binary.ninja), especially for large-effort PRs.

---

#### Attribution

This project makes use of:
  - [log] ([log license] - MIT)
  - [rayon] ([rayon license] - MIT)
  - [thiserror] ([thiserror license] - MIT)

[log]: https://github.com/rust-lang/log
[log license]: https://github.com/rust-lang/log/blob/master/LICENSE-MIT
[rayon]: https://github.com/rayon-rs/rayon
[rayon license]: https://github.com/rayon-rs/rayon/blob/master/LICENSE-MIT
[thiserror]: https://github.com/dtolnay/thiserror
[thiserror license]: https://github.com/dtolnay/thiserror/blob/master/LICENSE-MIT
[Binary Ninja]: https://binary.ninja