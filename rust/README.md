# BinaryNinja-rs

> :warning: **These bindings are in a very early beta, only have partial support for the core APIs and are still actively under development. Compatibility _will_ break and conventions _will_ change! They are being used for core Binary Ninja features however, so we expect much of what is already there to be reliable enough to build on, just don't be surprised if your plugins/scripts need to hit a moving target.**

## Dependencies

Having BinaryNinja installed (and your license registered)
Clang

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
See the `./examples/`

### To write a headless script

`Cargo.toml`:
```
[dependencies]
binaryninja = { git = "https://github.com/Vector35/binaryninja-api.git", branch = "dev", features = ["headless"] }

```

`src/main.rs`:
```
use binaryninja::version;

fn main() {
    println!("BinaryNinja Version: `{}`", version());
}
```

## Contributing

If you want to advance the binaryninjacore.h reference, simply change the commit ID in `build.rs`

## WIP : TODO

 - Logging needs to be redone
 - Update libc requirement on binaryninja::
 - Rename `section_by_name` to `get_section_by_name` and similar
many other todos are still scattered in the codebase

---

#### Attribution

This project makes use of:
  - [log] ([log license] - MIT)
  - [rayon] ([rayon license] - MIT)

[log]: https://github.com/rust-lang/log
[log license]: https://github.com/rust-lang/log/blob/master/LICENSE-MIT
[rayon]: https://github.com/rayon-rs/rayon
[rayon license]: https://github.com/rayon-rs/rayon/blob/master/LICENSE-MIT
