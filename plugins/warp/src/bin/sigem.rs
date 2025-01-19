use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use ar::Archive;
use clap::{arg, Parser};
use rayon::prelude::*;

use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::function::Function as BNFunction;
use binaryninja::rc::Guard as BNGuard;
use binaryninja::settings::Settings;
use serde_json::{json, Value};
use walkdir::WalkDir;
use warp::signature::Data;
use warp_ninja::cache::{cached_type_references, register_cache_destructor};

#[derive(Parser, Debug)]
#[command(about, long_about)]
/// A simple CLI utility to generate WARP signature files headlessly using Binary Ninja.
///
/// NOTE: This requires a headless compatible Binary Ninja, make sure it's in your path.
struct Args {
    /// Path to create signatures from, this can be:
    /// - A binary (that can be opened with Binary Ninja)
    /// - A directory (all files will be merged)
    /// - An archive (with ext: a, lib, rlib)
    /// - A BNDB
    /// - A Signature file (sbin)
    #[arg(index = 1, verbatim_doc_comment)]
    path: PathBuf,

    /// The signature output file
    ///
    /// NOTE: If not specified the output will be the input path with the sbin extension
    /// as an example `mylib.a` will output `mylib.sbin`.
    #[arg(index = 2)]
    output: Option<PathBuf>,

    /// Should we overwrite output file
    ///
    /// NOTE: If the file exists we will exit early to prevent wasted effort.
    #[arg(short, long)]
    overwrite: Option<bool>,

    /// The external debug information file to use
    #[arg(short, long)]
    debug_info: Option<PathBuf>,
    // TODO: Add a file filter and default to filter out files starting with "."
}

fn default_settings(bn_settings: &Settings) -> Value {
    // TODO: Make these settings configurable through the CLI
    let mut settings = json!({
        "analysis.linearSweep.autorun": false,
        "analysis.signatureMatcher.autorun": false,
        "analysis.mode": "full",
        // The reason we need to do this is a little unfortunate.
        // Basically some of the COFF's have really low image bases that confuses
        // Analysis and also our basic block GUID when a constant value points to a low address section.
        // TODO: This might not exist, we should set this based on the view.
        "loader.imageBase": 0x1000000,
    });

    // If WARP is enabled we must turn it off to prevent matching on other stuff.
    if bn_settings.contains("analysis.warp.matcher") {
        settings["analysis.warp.matcher"] = json!(false);
        settings["analysis.warp.guid"] = json!(false);
    }

    settings
}

fn main() {
    let args = Args::parse();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // TODO: After analysis finishes for a file we should save off the bndb to another directory called the bndb cache
    // TODO: This cache should be used before opening a file for first analysis.

    // TODO: We should resolve the path to something sensible in cases where user is passing CWD.
    // If no output file was given, just prepend binary with extension sbin
    let output_file = args
        .output
        .unwrap_or(args.path.to_owned())
        .with_extension("sbin");

    if output_file.exists() && !args.overwrite.unwrap_or(false) {
        log::info!("Output file already exists, skipping... {:?}", output_file);
        return;
    }

    log::debug!("Starting Binary Ninja session...");
    let _headless_session =
        binaryninja::headless::Session::new().expect("Failed to initialize session");

    // Adjust the amount of worker threads so that we can actually free BinaryViews.
    let worker_count = rayon::current_num_threads() * 4;
    log::debug!("Adjusting Binary Ninja worker count to {}...", worker_count);
    binaryninja::worker_thread::set_worker_thread_count(worker_count);

    // Make sure caches are flushed when the views get destructed.
    register_cache_destructor();

    let bn_settings = Settings::new();
    let settings = default_settings(&bn_settings);

    log::info!("Creating functions for {:?}...", args.path);
    let start = std::time::Instant::now();
    let data = data_from_file(&settings, &args.path)
        .expect("Failed to read data, check your license and Binary Ninja version!");
    log::info!("Functions created in {:?}", start.elapsed());

    // TODO: Add a way to override the symbol type to make it a different function symbol.
    // TODO: Right now the consumers must dictate that.
    // TODO: The binja_warp consumer sets this to library function fwiw

    if !data.functions.is_empty() {
        std::fs::write(&output_file, data.to_bytes()).expect("Failed to write functions to file");
        log::info!(
            "{} functions written to {:?}...",
            data.functions.len(),
            output_file
        );
    } else {
        log::warn!("No functions found for binary {:?}...", args.path);
    }
}

fn data_from_view(view: &BinaryView) -> Data {
    let mut data = Data::default();
    let is_function_named = |f: &BNGuard<BNFunction>| {
        !f.symbol().short_name().as_str().contains("sub_") || f.has_user_annotations()
    };

    data.functions = view
        .functions()
        .iter()
        .filter(is_function_named)
        .filter_map(|f| {
            let llil = f.low_level_il().ok()?;
            Some(warp_ninja::cache::cached_function(&f, &llil))
        })
        .collect::<Vec<_>>();

    if let Some(ref_ty_cache) = cached_type_references(view) {
        let referenced_types = ref_ty_cache
            .cache
            .iter()
            .filter_map(|t| t.to_owned())
            .collect::<Vec<_>>();

        data.types.extend(referenced_types);
    }

    data
}

fn data_from_archive<R: Read>(settings: &Value, mut archive: Archive<R>) -> Option<Data> {
    // TODO: I feel like this is a hack...
    let temp_dir = tempdir::TempDir::new("tmp_archive").ok()?;
    // Iterate through the entries in the ar file and make a temp dir with them
    let mut entry_files: HashSet<PathBuf> = HashSet::new();
    while let Some(entry) = archive.next_entry() {
        match entry {
            Ok(mut entry) => {
                let name = String::from_utf8_lossy(entry.header().identifier()).to_string();
                // Write entry data to a temp directory
                let output_path = temp_dir.path().join(&name);
                if !entry_files.contains(&output_path) {
                    let mut output_file =
                        File::create(&output_path).expect("Failed to create entry file");
                    std::io::copy(&mut entry, &mut output_file).expect("Failed to read entry data");
                    entry_files.insert(output_path);
                } else {
                    log::debug!("Skipping already inserted entry: {}", name);
                }
            }
            Err(e) => {
                log::error!("Failed to read archive entry: {}", e);
            }
        }
    }

    // Create the data.
    let entry_data = entry_files
        .into_par_iter()
        .filter_map(|path| {
            log::debug!("Creating data for ENTRY {:?}...", path);
            data_from_file(settings, &path)
        })
        .collect::<Vec<_>>();

    Some(Data::merge(entry_data))
}

fn data_from_directory(settings: &Value, dir: PathBuf) -> Option<Data> {
    let files = WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| {
            let path = e.ok()?.into_path();
            if path.is_file() {
                Some(path)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let unmerged_data = files
        .into_par_iter()
        .filter_map(|path| {
            log::info!("Creating data for FILE {:?}...", path);
            data_from_file(settings, &path)
        })
        .collect::<Vec<_>>();

    if !unmerged_data.is_empty() {
        Some(Data::merge(unmerged_data))
    } else {
        None
    }
}

fn data_from_file(settings: &Value, path: &Path) -> Option<Data> {
    match path.extension() {
        Some(ext) if ext == "a" || ext == "lib" || ext == "rlib" => {
            let archive_file = File::open(path).expect("Failed to open archive file");
            let archive = Archive::new(archive_file);
            data_from_archive(settings, archive)
        }
        Some(ext) if ext == "sbin" => {
            let contents = std::fs::read(path).ok()?;
            Data::from_bytes(&contents)
        }
        _ if path.is_dir() => data_from_directory(settings, path.into()),
        _ => {
            let path_str = path.to_str().unwrap();
            let view = binaryninja::load_with_options(path_str, true, Some(settings.to_string()))?;
            let data = data_from_view(&view);
            view.file().close();
            Some(data)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_data_from_file() {
        env_logger::init();
        // TODO: Store oracles here to get more out of this test.
        let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
        let _headless_session =
            binaryninja::headless::Session::new().expect("Failed to initialize session");
        let bn_settings = Settings::new();
        let settings = default_settings(&bn_settings);
        for entry in std::fs::read_dir(out_dir).expect("Failed to read OUT_DIR") {
            let entry = entry.expect("Failed to read directory entry");
            let path = entry.path();
            if path.is_file() {
                let result = data_from_file(&settings, &path);
                assert!(result.is_some());
            }
        }
    }
}
