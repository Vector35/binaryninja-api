use binaryninja::headless::Session;
use clap::Parser;
use indicatif::{ProgressBar, ProgressStyle};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use warp_ninja::processor::{
    CompressionTypeField, ProcessingFileState, ProcessingState, WarpFileProcessor,
};
use warp_ninja::warp::WarpFile;

/// Generate WARP files using Binary Ninja
///
/// Examples:
///
/// - Merge multiple inputs into a single output:
///   ./binaryninja-warp-headless -o result.warp ./bin1 ./bin2
///
/// - Write one .warp per input into a directory:
///   ./binaryninja-warp-headless -o ./results ./bin1 ./bin2 ./dir_with_bins
///
/// - Skip already-existing .warp files inside inputs:
///   ./binaryninja-warp-headless -o ./results --skip-warp-files ./dir_with_mixed_inputs
///
/// - Use a cache directory to speed up repeated runs:
///   ./binaryninja-warp-headless -o ./results --cache-dir ./bn-cache ./binaries
#[derive(Parser, Debug)]
#[command(version, about, long_about)]
struct Args {
    /// Input files and directories (positional).
    #[arg(value_name = "PATH", required = true)]
    input: Vec<PathBuf>,

    /// Output destination: file path or directory for per-input output
    #[arg(short = 'o', long = "output")]
    output: PathBuf,

    /// Skip processing of any existing WARP files within any input path
    #[arg(long, default_value_t = false)]
    skip_warp_files: bool,

    /// Optional directory to cache analysis information to
    #[arg(long)]
    cache_dir: Option<PathBuf>,

    /// Whether to compress the output file data
    #[arg(short, long, default_value_t = true)]
    compressed: bool,
}

fn main() {
    let _session = Session::new().expect("Failed to create session");
    let args = Args::parse();
    env_logger::init();

    let compression_ty = match args.compressed {
        true => CompressionTypeField::Zstd,
        false => CompressionTypeField::None,
    };
    let mut processor = WarpFileProcessor::new()
        .with_skip_warp_files(args.skip_warp_files)
        .with_compression_type(compression_ty);
    if let Some(cache_dir) = args.cache_dir {
        processor = processor.with_cache_path(cache_dir);
    }

    // Cancel the processor on ctrl+c, otherwise it will block forever.
    let ctrlc_state = processor.state().clone();
    ctrlc::set_handler(move || {
        ctrlc_state.cancel();
    })
    .expect("Error setting Ctrl-C handler");

    let progress_guard = run_progress_bar(processor.state());

    let outputs: HashMap<PathBuf, WarpFile<'static>> = args
        .input
        .into_iter()
        .filter_map(|i| match processor.process(i.clone()) {
            Ok(o) => Some((i, o)),
            Err(err) => {
                log::error!("{}", err);
                None
            }
        })
        .collect();

    // Stop progress UI
    progress_guard.finish();

    match args.output.is_dir() {
        true => {
            // Given a directory, place each output individually using the input name.
            for (input, output) in &outputs {
                let output_name = match input.file_name() {
                    Some(name) => name,
                    None => input.components().last().unwrap().as_os_str(),
                };
                let output_path = args.output.join(output_name).with_extension("warp");
                log::info!("Writing to {:?}", output_path);
                std::fs::write(output_path, output.to_bytes()).unwrap();
            }
        }
        false => {
            // Given a non-existing directory, merge all outputs and place at the output path.
            match processor.merge_files(outputs.values().cloned().collect()) {
                Ok(output) => {
                    log::info!("Writing to {:?}", args.output);
                    std::fs::write(args.output, output.to_bytes()).unwrap();
                }
                Err(err) => {
                    log::error!("{}", err);
                }
            }
        }
    }
}

// TODO: Also poll for background tasks and display them as independent progress bars.
fn run_progress_bar(state: Arc<ProcessingState>) -> ProgressGuard {
    let pb = ProgressBar::new(0);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner} {bar:40.cyan/blue} {pos}/{len} ({percent}%) [{elapsed_precise}] {msg}",
        )
        .unwrap()
        .progress_chars("=>-"),
    );

    let pb_clone = pb.clone();
    let state_clone = state.clone();
    let handle = std::thread::spawn(move || loop {
        let total = state_clone.total_files() as u64;
        let done = state_clone.files_with_state(ProcessingFileState::Processed) as u64;
        let unprocessed = state_clone.files_with_state(ProcessingFileState::Unprocessed);
        let analyzing = state_clone.files_with_state(ProcessingFileState::Analyzing);
        let processing = state_clone.files_with_state(ProcessingFileState::Processing);

        if pb_clone.length().unwrap_or(0) != total {
            pb_clone.set_length(total);
        }
        pb_clone.set_position(done.min(total));
        pb_clone.set_message(format!(
            "{{u:{}|a:{}|p:{}|d:{}}}",
            unprocessed, analyzing, processing, done
        ));

        if pb_clone.is_finished() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    });

    ProgressGuard {
        pb,
        handle: Some(handle),
    }
}

struct ProgressGuard {
    pb: ProgressBar,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl ProgressGuard {
    fn finish(mut self) {
        self.pb.finish_and_clear();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for ProgressGuard {
    fn drop(&mut self) {
        self.pb.finish_and_clear();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}
