extern crate bindgen;

use std::env;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=../../binaryninjacore.h");

    //Cargo's output directory
    let out_dir = env::var("OUT_DIR").unwrap();

    let current_line = "#define BN_CURRENT_UI_ABI_VERSION ";
    let minimum_line = "#define BN_MINIMUM_UI_ABI_VERSION ";
    let mut current_version = "0".to_string();
    let mut minimum_version = "0".to_string();
    let file = File::open("../../ui/uitypes.h").expect("Couldn't open uitypes.h");
    for line in BufReader::new(file).lines() {
        let line = line.unwrap();
        if line.starts_with(current_line) {
            current_version = (&line[current_line.len()..]).to_owned();
        } else if line.starts_with(minimum_line) {
            minimum_version = (&line[minimum_line.len()..]).to_owned();
        }
    }

    let mut bindings = bindgen::builder()
        .header("../../binaryninjacore.h")
        .clang_arg("-std=c++17")
        .clang_arg("-x")
        .clang_arg("c++")
        .size_t_is_usize(true)
        .generate_comments(false)
        .allowlist_function("BN.*")
        .allowlist_var("BN_CURRENT_CORE_ABI_VERSION")
        .allowlist_var("BN_MINIMUM_CORE_ABI_VERSION")
        .raw_line(format!(
            "pub const BN_CURRENT_UI_ABI_VERSION: u32 = {};",
            current_version
        ))
        .raw_line(format!(
            "pub const BN_MINIMUM_UI_ABI_VERSION: u32 = {};",
            minimum_version
        ))
        .rustified_enum("BN.*");

    // Difference between global LLVM/Clang install and custom LLVM/Clang install...
    //  First option is for the build server, second option is being nice to our dev who have `LLVM_INSTALL_DIR` set, default is for people with "normal" setups (and Macs)
    #[cfg(not(target_os = "macos"))]
    {
        // Detect for custom Clang or LLVM installations (BN devs/build server)
        let llvm_dir = env::var("LIBCLANG_PATH");
        let llvm_version = env::var("LLVM_VERSION");
        let llvm_install_dir = env::var("LLVM_INSTALL_DIR");

        if let (Ok(llvm_dir), Ok(llvm_version)) = (llvm_dir, llvm_version) {
            let llvm_include_path = format!("-I{}/clang/{}/include", llvm_dir, llvm_version);
            bindings = bindings.clang_arg(llvm_include_path);
        } else if let Ok(llvm_install_dir) = llvm_install_dir {
            let llvm_include_path =
                format!("-I{}/12.0.0/lib/clang/12.0.0/include", llvm_install_dir);
            env::set_var("LIBCLANG_PATH", format!("{}/12.0.0/lib", llvm_install_dir));
            bindings = bindings.clang_arg(llvm_include_path);
        }
    }

    bindings
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(PathBuf::from(out_dir).join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
