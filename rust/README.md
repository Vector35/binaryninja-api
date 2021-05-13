# BinaryNinja-rs

<img align="right" src="./under_construction.png" width="175" height="175">

> :warning: **These bindings are in a very early beta, only have partial support for the core APIs and are still actively under development. Compatibility _will_ break and conventions _will_ change! They are being used for core Binary Ninja features however, so we expect much of what is already there to be reliable enough to build on, just don't be surprised if your plugins/scripts need to hit a moving target.**

> :warning: This project requires Rust Nightly to build with those fancy linker arguments


## Dependencies

Having BinaryNinja installed (and your license registered)
Clang
Rust **Nightly**


## How to use

### To write a plugin:

`Cargo.toml`:
```
[lib]
crate-type = ["cdylib"]

[dependencies]
binaryninja = {git = "https://github.com/Vector35/binaryninja-api.git", branch = "dev"}
```

`src/main.rs`:
See the `./examples/`.  Plugin registration commands are in `binaryninja::command::*`


### To write a headless script:

`Cargo.toml`:
```
[dependencies]
binaryninja = { git = "https://github.com/Vector35/binaryninja-api.git", branch = "dev"}
```

`src/main.rs`:
```
use binaryninja::version;
use binaryninja::architecture::Architecture;
use binaryninja::binaryview::{BinaryViewBase, BinaryViewExt};

fn main() {
    println!("BinaryNinja Version: `{}`", version());

    println!("Loading plugins..."); // This loads all the core architecture, platform, etc plugins
    binaryninja::headless::init();

    println!("Loading binary...");
    let bv = binaryninja::open_view("/bin/cat").expect("Couldn't open `/bin/cat`");

    println!("Filename:  `{}`", bv.metadata().filename());
    println!("File size: `{:#x}`", bv.len());
    println!("Function count: {}", bv.functions().len());

    for func in &bv.functions() {
        println!("  `{}`:", func.symbol().full_name());
    }

    // Important!  You need to call shutdown or your script will hang forever
    binaryninja::headless::shutdown();
}
```

All headless scripts should call both `binaryninja::headless::init()` and `binaryninja::headless::shutdown()`.

---

#### Attribution

This project makes use of:
  - [log] ([log license] - MIT)
  - [rayon] ([rayon license] - MIT)

[log]: https://github.com/rust-lang/log
[log license]: https://github.com/rust-lang/log/blob/master/LICENSE-MIT
[rayon]: https://github.com/rayon-rs/rayon
[rayon license]: https://github.com/rayon-rs/rayon/blob/master/LICENSE-MIT
