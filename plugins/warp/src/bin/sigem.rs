use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use ar::Archive;
use clap::{arg, Parser};
use rayon::prelude::*;

use binaryninja::binaryview::{BinaryView, BinaryViewExt};
use serde_json::json;
use warp::signature::Data;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path of the binary/BNDB to generate signatures of
    #[arg(index = 1)]
    binary: PathBuf,

    /// The signature output file
    #[arg(index = 2)]
    output: Option<PathBuf>,

    /// Should we overwrite output file
    ///
    /// NOTE: If the file exists we will exit early to prevent wasted effort.
    /// NOTE: If the file is created while we are running it will still be overwritten.
    #[arg(short, long)]
    overwrite: Option<bool>,

    /// The external debug information file to use
    #[arg(short, long)]
    debug_info: Option<PathBuf>,
}

fn main() {
    let args = Args::parse();
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // If no output file was given, just prepend binary with extension sbin
    let output_file = args.output.unwrap_or(args.binary.with_extension("sbin"));

    if output_file.exists() && !args.overwrite.unwrap_or(false) {
        log::info!("Output file already exists, skipping... {:?}", output_file);
        return;
    }

    log::debug!("Starting Binary Ninja session...");
    let _headless_session = binaryninja::headless::Session::new();

    log::info!("Creating functions for {:?}...", args.binary);
    let start = std::time::Instant::now();
    let data = data_from_file(&args.binary).expect("Failed to read data");
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
        log::warn!("No functions found for binary {:?}...", args.binary);
    }
}

fn data_from_view(view: &BinaryView) -> Data {
    let mut data = Data::default();

    let functions = view
        .functions()
        .par_iter()
        .filter(|f| !f.symbol().short_name().as_str().contains("sub_") || f.has_user_annotations())
        .filter_map(|f| {
            let llil = f.low_level_il().ok()?;
            Some(warp_ninja::cache::cached_function(&f, &llil))
        })
        .collect::<Vec<_>>();

    data.functions = functions;
    data
}

fn data_from_archive<R: Read>(mut archive: Archive<R>) -> Option<Data> {
    // TODO: I feel like this is a hack...
    let temp_dir = tempdir::TempDir::new("tmp_archive").ok()?;
    // Iterate through the entries in the ar file and make a temp dir with them
    let mut entry_files = Vec::new();
    while let Some(entry) = archive.next_entry() {
        match entry {
            Ok(mut entry) => {
                let name = String::from_utf8_lossy(entry.header().identifier()).to_string();
                // Write entry data to a temp directory
                let output_path = temp_dir.path().join(name);
                let mut output_file =
                    File::create(&output_path).expect("Failed to create entry file");
                std::io::copy(&mut entry, &mut output_file).expect("Failed to read entry data");
                entry_files.push(output_path);
            }
            Err(e) => {
                log::error!("Failed to read archive entry: {}", e);
            }
        }
    }

    // Create the data.
    // TODO: into_par_iter will corrupt the heap frequently, you should basically always restrict
    // TODO: With RAYON_NUM_THREADS (set to like... 1)
    let entry_data = entry_files
        .into_par_iter()
        .filter_map(|path| {
            log::debug!("Creating data for ENTRY {:?}...", path);
            data_from_file(&path)
        })
        .collect::<Vec<_>>();

    // TODO: Cloning here is unnecessary
    Some(Data {
        functions: entry_data
            .iter()
            .flat_map(|d| d.functions.to_owned())
            .collect(),
        types: entry_data.iter().flat_map(|d| d.types.to_owned()).collect(),
    })
}

// TODO: Pass settings.
fn data_from_file(path: &Path) -> Option<Data> {
    // TODO: Add external debug info files.
    // TODO: Support IDB's through debug info
    let settings_json = json!({
        "analysis.linearSweep.autorun": true,
        "analysis.signatureMatcher.autorun": false,
        "analysis.plugins.WARPMatcher": true,
    });

    match path.extension() {
        Some(ext) if ext == "a" || ext == "lib" || ext == "rlib" => {
            let archive_file = File::open(path).expect("Failed to open archive file");
            let archive = Archive::new(archive_file);
            data_from_archive(archive)
        }
        _ => {
            let path_str = path.to_str().unwrap();
            let view =
                binaryninja::load_with_options(path_str, true, Some(settings_json.to_string()))?;
            Some(data_from_view(&view))
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
        let _headless_session = binaryninja::headless::Session::new();
        for entry in std::fs::read_dir(out_dir).expect("Failed to read OUT_DIR") {
            let entry = entry.expect("Failed to read directory entry");
            let path = entry.path();
            if path.is_file() {
                let result = data_from_file(&path);
                assert!(result.is_some());
            }
        }
    }
}
