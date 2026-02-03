use std::path::{Path, PathBuf};

// For static builds, CARGO_MANIFEST_DIR points to the generated crate directory,
// so we read the original source path from source_dir.txt written by generate_static_crate.py.
#[cfg(feature = "demo")]
const SOURCE_DIR: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/source_dir.txt"));
#[cfg(not(feature = "demo"))]
const SOURCE_DIR: &str = env!("CARGO_MANIFEST_DIR");

const TEMPLATES_DIR: &str = const_str::concat!(SOURCE_DIR, "/src/templates");
const FIXTURES_DIR: &str = const_str::concat!(SOURCE_DIR, "/fixtures");

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

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR specified");
    let out_dir_path = PathBuf::from(out_dir);

    println!("cargo::rerun-if-changed={}", FIXTURES_DIR);
    // Copy all binaries to OUT_DIR for unit tests.
    let bin_dir = Path::new(FIXTURES_DIR).join("bin");
    if let Ok(entries) = std::fs::read_dir(bin_dir) {
        for entry in entries {
            let entry = entry.unwrap();
            let path = entry.path();
            if path.is_file() {
                let file_name = path.file_name().unwrap();
                let dest_path = out_dir_path.join(file_name);
                std::fs::copy(&path, &dest_path).expect("failed to copy binary to OUT_DIR");
            }
        }
    }

    println!("cargo::rerun-if-changed={}", TEMPLATES_DIR);
    // Templates used for rendering reports.
    minijinja_embed::embed_templates!(TEMPLATES_DIR);
}
