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

    let link_path =
        std::env::var_os("DEP_BINARYNINJACORE_PATH").expect("DEP_BINARYNINJACORE_PATH specified");

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
