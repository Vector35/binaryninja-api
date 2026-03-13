use binaryninja::headless::Session;
use binaryninja::tracing::TracingLogListener;
use clap::Parser;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing_indicatif::span_ext::IndicatifSpanExt;
use tracing_indicatif::style::ProgressStyle;
use tracing_indicatif::IndicatifLayer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use warp_ninja::processor::{ProcessingFileState, ProcessingState, WarpFileProcessor};
use warp_ninja::warp::chunk::CompressionType;
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
    let indicatif_layer = IndicatifLayer::new();
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(indicatif_layer.get_stderr_writer()))
        .with(indicatif_layer)
        .init();
    let _listener = TracingLogListener::new().register();

    let _session = Session::new().expect("Failed to create session");
    let args = Args::parse();

    let compression_ty = match args.compressed {
        true => CompressionType::Zstd,
        false => CompressionType::None,
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

    let finished_signal = Arc::new(AtomicBool::new(false));
    // Report progress to the terminal.
    let progress_state = processor.state();
    let progress_finished_signal = finished_signal.clone();
    let progress_thread =
        std::thread::spawn(|| run_progress_bar(progress_state, progress_finished_signal));

    let outputs: HashMap<PathBuf, WarpFile<'static>> = args
        .input
        .into_iter()
        .filter_map(|i| match processor.process_path(i.clone()) {
            Ok(o) => Some((i, o)),
            Err(err) => {
                tracing::error!("{}", err);
                None
            }
        })
        .collect();

    finished_signal.store(true, Ordering::Relaxed);
    progress_thread.join().expect("Progress thread exited");

    match args.output.is_dir() {
        true => {
            // Given a directory, place each output individually using the input name.
            for (input, output) in &outputs {
                let output_name = match input.file_name() {
                    Some(name) => name,
                    None => input.components().last().unwrap().as_os_str(),
                };
                let output_path = args.output.join(output_name).with_extension("warp");
                tracing::info!("Writing to {:?}", output_path);
                std::fs::write(output_path, output.to_bytes()).unwrap();
            }
        }
        false => {
            // Given a non-existing directory, merge all outputs and place at the output path.
            match processor.merge_files(outputs.values().cloned().collect()) {
                Ok(output) => {
                    tracing::info!("Writing to {:?}", args.output);
                    std::fs::write(args.output, output.to_bytes()).unwrap();
                }
                Err(err) => {
                    tracing::error!("{}", err);
                }
            }
        }
    }
}

// TODO: Also poll for background tasks and display them as independent progress bars.
fn run_progress_bar(state: Arc<ProcessingState>, finished: Arc<AtomicBool>) {
    let progress_span = tracing::info_span!("loading");
    let progress_style = ProgressStyle::with_template("{msg} {elapsed} {wide_bar}").unwrap();
    progress_span.pb_set_style(&progress_style);
    progress_span.pb_set_message("Processing files");
    progress_span.pb_set_finish_message("Files processed");

    let elapsed = std::time::Instant::now();
    progress_span.in_scope(|| loop {
        let total = state.total_files() as u64;
        let done = state.files_with_state(ProcessingFileState::Processed) as u64;
        let unprocessed = state.files_with_state(ProcessingFileState::Unprocessed);
        let analyzing = state.files_with_state(ProcessingFileState::Analyzing);
        let processing = state.files_with_state(ProcessingFileState::Processing);

        progress_span.pb_set_length(total);
        progress_span.pb_set_position(done.min(total));
        progress_span.pb_set_message(&format!(
            "{{u:{}|a:{}|p:{}|d:{}}}",
            unprocessed, analyzing, processing, done
        ));

        if state.is_cancelled() || finished.load(Ordering::Relaxed) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    });

    tracing::info!(
        "Finished processing in {:.2} seconds",
        elapsed.elapsed().as_secs_f32()
    );
}
