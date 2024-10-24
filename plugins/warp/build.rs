use std::path::PathBuf;
use std::process::Command;

fn compile_rust(file: PathBuf) -> bool {
    let out_dir = std::env::var_os("OUT_DIR").unwrap();
    let rustc = std::env::var_os("RUSTC").unwrap();
    let rustc = rustc.to_str().unwrap();
    let mut rustc = rustc.split('\x1f');
    let mut cmd = Command::new(rustc.next().unwrap());
    cmd.args(rustc)
        .arg("--crate-type=rlib")
        .arg("--out-dir")
        .arg(out_dir)
        .arg(file);
    cmd.status().expect("failed to invoke rustc").success()
}

fn main() {
    let link_path = std::env::var_os("BINARYNINJADIR").expect("BINARYNINJADIR specified");
    let out_dir = std::env::var_os("OUT_DIR").expect("OUT_DIR specified");
    let out_dir_path = PathBuf::from(out_dir);

    println!("cargo::rustc-link-lib=dylib=binaryninjacore");
    println!("cargo::rustc-link-search={}", link_path.to_str().unwrap());

    #[cfg(not(target_os = "windows"))]
    {
        println!(
            "cargo::rustc-link-arg=-Wl,-rpath,{0},-L{0}",
            link_path.to_string_lossy()
        );
    }

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

    // Compile all .c files in fixtures/src directory for unit tests.
    let src_dir: PathBuf = "fixtures/src".into();
    if let Ok(entries) = std::fs::read_dir(src_dir) {
        for entry in entries {
            let entry = entry.unwrap();
            let path = entry.path();
            match path.extension().map(|s| s.to_str().unwrap()) {
                Some("c") => {
                    cc::Build::new()
                        .file(&path)
                        .compile(path.file_stem().unwrap().to_str().unwrap());
                }
                Some("rs") => {
                    compile_rust(path);
                }
                _ => {}
            }
        }
    }
}
