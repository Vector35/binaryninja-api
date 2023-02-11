use std::env;
use std::fs::File;
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
    // Use BINARYNINJADIR first for custom BN builds/configurations (BN devs/build server), fallback on defaults
    let install_path = env::var("BINARYNINJADIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| link_path());

    #[cfg(target_os = "linux")]
    println!(
        "cargo:rustc-link-arg=-Wl,-rpath,{},-L{},-l:libbinaryninjacore.so.1",
        install_path.to_str().unwrap(),
        install_path.to_str().unwrap(),
    );

    #[cfg(target_os = "macos")]
    println!(
        "cargo:rustc-link-arg=-Wl,-rpath,{},-L{},-lbinaryninjacore",
        install_path.to_str().unwrap(),
        install_path.to_str().unwrap(),
    );

    #[cfg(target_os = "windows")]
    {
        println!("cargo:rustc-link-lib=binaryninjacore");
        println!("cargo:rustc-link-search={}", install_path.to_str().unwrap());
    }
}
