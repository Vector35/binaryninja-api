fn main() {
    // TODO : Enable the following when https://github.com/rust-lang/rust/issues/43781 stabilizes
    // #[cfg(doc)]
    let _ = std::fs::create_dir("target");
    let _ = std::fs::create_dir("target/doc");
    let _ = std::fs::copy("../docs/img/favicon.ico", "target/doc/favicon.ico");
    let _ = std::fs::copy(
        "under_construction.png",
        "target/doc/under_construction.png",
    );
    let _ = std::fs::copy("../docs/img/logo.png", "target/doc/logo.png");
}
