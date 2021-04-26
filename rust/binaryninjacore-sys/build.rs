extern crate bindgen;

use std::env;
use std::path::PathBuf;

#[cfg(any(not(target_os = "linux"), feature = "headless"))]
use std::fs::File;
#[cfg(any(not(target_os = "linux"), feature = "headless"))]
use std::io::prelude::*;
#[cfg(any(not(target_os = "linux"), feature = "headless"))]
use std::io::BufReader;

#[cfg(target_os = "macos")]
static LASTRUN_PATH: (&str, &str) = ("HOME", "Library/Application Support/Binary Ninja/lastrun");

#[cfg(all(target_os = "linux", feature = "headless"))]
static LASTRUN_PATH: (&str, &str) = ("HOME", ".binaryninja/lastrun");

#[cfg(windows)]
static LASTRUN_PATH: (&str, &str) = ("APPDATA", "Binary Ninja\\lastrun");

#[cfg(any(not(target_os = "linux"), feature = "headless"))]
fn link_path() -> PathBuf {
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

    // Allow the library search path to be overridden for internal dev builds, but
    // otherwise search the usual install paths
    let out_dir = env::var("OUT_DIR").unwrap();
    let llvm_dir = env::var("LIBCLANG_PATH");
    let llvm_version = env::var("LLVM_VERSION");
    let llvm_install_dir = env::var("LLVM_INSTALL_DIR");

    #[cfg(any(not(target_os = "linux"), feature = "headless"))]
    let link_path = env::var("BINARYNINJADIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| link_path());

    #[cfg(all(unix, feature = "headless"))]
    {
        use std::process::Command;

        // Spectacularly evil linking hack due to Cargo shortcomings. In a nutshell,
        // due to the inability for our .rlib crate to contribute linker arguments
        // (or even just an rpath!) to our consumers, any resulting binaries will
        // fail to run unless loaded into a process that already has the core loaded.
        //
        // For plugins this restriction is fine as they'll only be loaded by the core;
        // headless binaries on the other hand (consider `cargo test`, too!) will fail
        // because libbinaryninjacore is not in the library path on pretty much any
        // system anywhere. If only we could trick the linker into linking with an
        // absolute path...
        //
        // LOOK ON MY WORKS, YE MIGHTY, AND DESPAIR
        //
        // We build a simple do-nothing library called liblinkhack and add it as a
        // native dependency. Crucially, we ensure that LC_ID_DYLIB (macos) or DT_SONAME
        // (linux) is set to the absolute path of libbinaryninjacore. This has the effect
        // that any binary attempting to link with liblinkhack will have its dependency
        // on liblinkhack recorded as the path to the binaryninja core. Later on, the
        // actual core will get linked and that dependency will be recorded in the normal
        // way.
        //
        // tl;dr we're linking against a fake, shim library that actually results in
        // the binaryninja core getting linked twice, once with an absolute path and once
        // correctly. yes, this is as horrifying as you think it is. no, there is no other
        // way to make `cargo test` work.
        //
        // I'm not happy about it either.

        #[cfg(target_os = "macos")]
        Command::new("clang")
            .args(&["-Wl,-dylib", "-o"])
            .arg(&format!("{}/liblinkhack.dylib", out_dir))
            .arg(&format!(
                "-Wl,-install_name,{}/libbinaryninjacore.dylib",
                &link_path.to_str().unwrap()
            ))
            .arg(&format!(
                "{}/linkhack/linkhack.c",
                env::var("CARGO_MANIFEST_DIR").unwrap()
            ))
            .status()
            .unwrap();

        #[cfg(target_os = "linux")]
        {
            Command::new("gcc")
                .args(&["-shared", "-o"])
                .arg(&format!("{}/liblinkhack.so", out_dir))
                .arg(&format!(
                    "-Wl,-soname,{}libbinaryninjacore.so.1",
                    &link_path.to_str().unwrap()
                )) // TODO : Check mac to see if I need to remove the extra slash as well
                .arg(&format!(
                    "{}/linkhack/linkhack.c",
                    env::var("CARGO_MANIFEST_DIR").unwrap()
                ))
                .status()
                .unwrap();

            // Linux builds of binaryninja ship with libbinaryninjacore.so.1 in the
            // application folder and no symlink. The linker will attempt to link with
            // libbinaryninjacore.so. Since this is likely going to fail, we detect this
            // ahead of time and create an appropriately named symlink inside of OUT_DIR
            // and add it to the library search path.
            let symlink_target = PathBuf::from(&out_dir).join("libbinaryninjacore.so");
            if !link_path.join("libbinaryninjacore.so").exists() && !symlink_target.exists() {
                use std::os::unix::fs;
                fs::symlink(
                    link_path.join("libbinaryninjacore.so.1"),
                    PathBuf::from(&out_dir).join("libbinaryninjacore.so"),
                )
                .expect("failed to create required symlink");
            }
        }

        println!("cargo:rustc-link-lib=linkhack");
        println!("cargo:rustc-link-search={}", out_dir);
    }

    #[cfg(any(not(target_os = "linux"), feature = "headless"))]
    {
        println!("cargo:rustc-link-lib=binaryninjacore");
        println!("cargo:rustc-link-search={}", link_path.to_str().unwrap());
    }

    #[warn(unused_assignments)]
    let mut is_mac = false;
    #[cfg(target_os = "macos")]
    {
        is_mac = true;
    }

    // Difference between global LLVM/Clang install and custom LLVM/Clang install...
    //  First option is for the build server, second option is being nice to our dev who have `LLVM_INSTALL_DIR` set, third is for people with "normal" setups (and Macs)
    let bindings;
    if let (false, Ok(llvm_dir), Ok(llvm_version)) = (is_mac, llvm_dir, llvm_version) {
        let llvm_include_path = format!("-I{}/clang/{}/include", llvm_dir, llvm_version);
        bindings = bindgen::builder()
            .header("../../binaryninjacore.h")
            .clang_arg("-std=c++17")
            .clang_arg("-x")
            .clang_arg("c++")
            .clang_arg(llvm_include_path)
            .size_t_is_usize(true)
            .generate_comments(false)
            .whitelist_function("BN.*")
            .whitelist_var("BN_CURRENT_CORE_ABI_VERSION")
            .whitelist_var("BN_MINIMUM_CORE_ABI_VERSION")
            .rustified_enum("BN.*")
            .generate()
            .expect("Unable to generate bindings");
    } else if let (false, Ok(llvm_install_dir)) = (is_mac, llvm_install_dir) {
        let llvm_include_path = format!("-I{}/11.0.0/lib/clang/11.0.0/include", llvm_install_dir);
        env::set_var("LIBCLANG_PATH", format!("{}/11.0.0/lib", llvm_install_dir));
        bindings = bindgen::builder()
            .header("../../binaryninjacore.h")
            .clang_arg("-std=c++17")
            .clang_arg("-x")
            .clang_arg("c++")
            .clang_arg(llvm_include_path)
            .size_t_is_usize(true)
            .generate_comments(false)
            .whitelist_function("BN.*")
            .whitelist_var("BN_CURRENT_CORE_ABI_VERSION")
            .whitelist_var("BN_MINIMUM_CORE_ABI_VERSION")
            .rustified_enum("BN.*")
            .generate()
            .expect("Unable to generate bindings");
    } else {
        bindings = bindgen::builder()
            .header("../../binaryninjacore.h")
            .clang_arg("-std=c++17")
            .clang_arg("-x")
            .clang_arg("c++")
            .size_t_is_usize(true)
            .generate_comments(false)
            .whitelist_function("BN.*")
            .whitelist_var("BN_CURRENT_CORE_ABI_VERSION")
            .whitelist_var("BN_MINIMUM_CORE_ABI_VERSION")
            .rustified_enum("BN.*")
            .generate()
            .expect("Unable to generate bindings");
    }

    bindings
        .write_to_file(PathBuf::from(out_dir).join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
