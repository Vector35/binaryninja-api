use std::env;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::path::PathBuf;

#[cfg(target_os = "macos")]
static LASTRUN_PATH: (&str, &str) = ("HOME", "Library/Application Support/Binary Ninja/lastrun");

#[cfg(target_os = "linux")]
static LASTRUN_PATH: (&str, &str) = ("HOME", ".binaryninja/lastrun");

#[cfg(windows)]
static LASTRUN_PATH: (&str, &str) = ("APPDATA", "Binary Ninja\\lastrun");

// Check last run location for path to BinaryNinja; Otherwise check the default install locations
fn link_path() -> PathBuf {
    use std::io::prelude::*;

    let home = PathBuf::from(env::var(LASTRUN_PATH.0).unwrap());
    let lastrun = PathBuf::from(&home).join(LASTRUN_PATH.1);

    File::open(lastrun)
        .and_then(|f| {
            let mut binja_path = String::new();
            let mut reader = BufReader::new(f);

            reader.read_line(&mut binja_path)?;
            Ok(PathBuf::from(binja_path.trim()))
        })
        .unwrap_or_else(|_| {
            #[cfg(target_os = "macos")]
            return PathBuf::from("/Applications/Binary Ninja.app/Contents/MacOS");

            #[cfg(target_os = "linux")]
            return home.join("binaryninja");

            #[cfg(windows)]
            return PathBuf::from(env::var("PROGRAMFILES").unwrap())
                .join("Vector35\\BinaryNinja\\");
        })
}

fn main() {
    println!("cargo:rerun-if-changed=../../binaryninjacore.h");

    //Cargo's output directory
    let out_dir = env::var("OUT_DIR").unwrap();

    let link_path = env::var("BINARYNINJADIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| link_path());

    // Linux builds of binaryninja ship with libbinaryninjacore.so.1 in the
    // application folder and no symlink. The linker will attempt to link with
    // libbinaryninjacore.so. Since this is likely going to fail, we detect this
    // ahead of time and create an appropriately named symlink inside of OUT_DIR
    // and add it to the library search path.
    #[cfg(target_os = "linux")]
    {
        let symlink_source = PathBuf::from(&out_dir).join("libbinaryninjacore.so");
        let symlink_target = link_path.join("libbinaryninjacore.so.1");
        // Make a symlink "libbinaryninjacore.so" pointing to "libbinaryninjacore.so.1"
        if symlink_target.exists() && symlink_source.symlink_metadata().is_err() {
            use std::os::unix::fs;
            fs::symlink(symlink_target, symlink_source).expect("failed to create required symlink");
        }
        println!("cargo:rustc-link-search={}", out_dir);
    }

    // Emit the path to binaryninjacore consumers of this crate should pass to the linker.
    println!("cargo:path={}", link_path.to_str().unwrap());

    let current_line = "#define BN_CURRENT_UI_ABI_VERSION ";
    let minimum_line = "#define BN_MINIMUM_UI_ABI_VERSION ";
    let mut current_version = "0".to_string();
    let mut minimum_version = "0".to_string();
    let file = File::open("../../ui/uitypes.h").expect("Couldn't open uitypes.h");
    for line in BufReader::new(file).lines() {
        let line = line.unwrap();
        if let Some(version) = line.strip_prefix(current_line) {
            version.clone_into(&mut current_version);
        } else if let Some(version) = line.strip_prefix(minimum_line) {
            version.clone_into(&mut minimum_version);
        }
    }

    bindgen::builder()
        .header("../../binaryninjacore.h")
        .clang_arg("-std=c++17")
        .clang_arg("-x")
        .clang_arg("c++")
        .size_t_is_usize(true)
        .generate_comments(false)
        .derive_default(true)
        .generate_comments(true)
        .clang_arg("-fparse-all-comments")
        .allowlist_function("BN.*")
        .allowlist_var("BN_CURRENT_CORE_ABI_VERSION")
        .allowlist_var("BN_MINIMUM_CORE_ABI_VERSION")
        .allowlist_var("MAX_RELOCATION_SIZE")
        .raw_line(format!(
            "pub const BN_CURRENT_UI_ABI_VERSION: u32 = {};",
            current_version
        ))
        .raw_line(format!(
            "pub const BN_MINIMUM_UI_ABI_VERSION: u32 = {};",
            minimum_version
        ))
        .rustified_enum("BN.*")
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file(PathBuf::from(out_dir).join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
