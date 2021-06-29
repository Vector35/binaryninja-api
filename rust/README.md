# BinaryNinja-rs

<img align="right" src="./under_construction.png" width="175" height="175">

> :warning: **These bindings are in a very early beta, only have partial support for the core APIs and are still actively under development. Compatibility _will_ break and conventions _will_ change! They are being used for core Binary Ninja features however, so we expect much of what is already there to be reliable enough to build on, just don't be surprised if your plugins/scripts need to hit a moving target.**

> :warning: This project requires **Rust Nightly** to build with those fancy linker arguments


## Dependencies

Having BinaryNinja installed (and your license registered)
Clang
Rust **Nightly**


## How to use

See [`examples/template`](examples/template).

---

#### Attribution

This project makes use of:
  - [log] ([log license] - MIT)
  - [rayon] ([rayon license] - MIT)

[log]: https://github.com/rust-lang/log
[log license]: https://github.com/rust-lang/log/blob/master/LICENSE-MIT
[rayon]: https://github.com/rayon-rs/rayon
[rayon license]: https://github.com/rayon-rs/rayon/blob/master/LICENSE-MIT
