use std::path::PathBuf;

fn main() {
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

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR specified");
    let out_dir_path = PathBuf::from(out_dir);

    // Copy all binaries to OUT_DIR for unit tests.
    let bin_dir: PathBuf = "fixtures/bin".into();
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
}
