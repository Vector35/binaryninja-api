#![allow(unused_imports)]
use std::env;
use std::path::PathBuf;
use std::process::Command;

#[cfg(target_os = "macos")]
static LASTRUN_PATH: (&str, &str) = ("HOME", "Library/Application Support/Binary Ninja/lastrun");

#[cfg(target_os = "linux")]
static LASTRUN_PATH: (&str, &str) = ("HOME", ".binaryninja/lastrun");

#[cfg(windows)]
static LASTRUN_PATH: (&str, &str) = ("APPDATA", "Binary Ninja\\lastrun");

// Check last run location for path to BinaryNinja; Otherwise check the default install locations
fn link_path() -> PathBuf {
    use std::io::prelude::*;
    use std::io::BufReader;

    let home = PathBuf::from(env::var(LASTRUN_PATH.0).unwrap());
    let lastrun = PathBuf::from(&home).join(LASTRUN_PATH.1);

    std::fs::File::open(lastrun)
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

#[cfg(feature = "test")]
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
    // Use BINARYNINJADIR first for custom BN builds/configurations (BN devs/build server), fallback on defaults
    let link_path = env::var("BINARYNINJADIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| link_path());
    let link_path_str = link_path.to_str().unwrap();
    println!("cargo::rustc-link-lib=dylib=binaryninjacore");
    println!("cargo::rustc-link-search={}", link_path_str);
    #[cfg(not(target_os = "windows"))]
    {
        println!("cargo::rustc-link-arg=-Wl,-rpath,{0},-L{0}", link_path_str);
    }

    #[cfg(feature = "test")]
    {
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
}
