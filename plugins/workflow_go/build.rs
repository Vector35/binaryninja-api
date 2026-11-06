fn main() {
    let link_path = std::env::var_os("DEP_BINARYNINJACORE_PATH")
        .expect("DEP_BINARYNINJACORE_PATH not specified");

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
        println!(
            "cargo::rustc-link-arg=-Wl,-install_name,@rpath/lib{}.dylib",
            lib_name
        );
    }
}
