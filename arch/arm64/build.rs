use std::env;
use std::fs;
use std::path::{Path, PathBuf};

// Copy the C headers of the exarmo-aarch64-capi this crate links into arm64-exarmo/include under
// BN_RUST_TARGET_DIR, where the plugin includes them from.
fn main() {
    let source = PathBuf::from(
        env::var("DEP_EXARMO_AARCH64_INCLUDE").expect("exarmo-aarch64-capi reports its include directory"),
    );
    let dest = match env::var("BN_RUST_TARGET_DIR") {
        Ok(target_dir) => PathBuf::from(target_dir).join("arm64-exarmo").join("include"),
        Err(_) => PathBuf::from(env::var("OUT_DIR").unwrap()).join("include"),
    };

    println!("cargo::rerun-if-env-changed=DEP_EXARMO_AARCH64_INCLUDE");
    println!("cargo::rerun-if-env-changed=BN_RUST_TARGET_DIR");
    println!("cargo::rerun-if-changed={}", source.display());
    println!("cargo::rerun-if-changed={}", dest.display());

    copy_headers(&source, &dest);
}

// Copy only the headers whose contents differ, so that an unchanged header keeps its timestamp and
// does not trigger a rebuild of the plugin.
fn copy_headers(source: &Path, dest: &Path) {
    fs::create_dir_all(dest).unwrap();
    for entry in fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let from = entry.path();
        let to = dest.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_headers(&from, &to);
            continue;
        }

        let contents = fs::read(&from).unwrap();
        if fs::read(&to).ok().as_deref() != Some(contents.as_slice()) {
            fs::write(&to, contents).unwrap();
        }
    }
}
