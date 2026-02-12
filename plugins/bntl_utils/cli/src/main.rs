use clap::Parser;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

mod create;
mod diff;
mod dump;
mod input;
mod validate;

/// Generate, inspect, and validate Binary Ninja type libraries (BNTL)
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Parser, Debug)]
pub enum Command {
    /// Create a new type library from a set of files.
    Create(create::CreateArgs),
    /// Dump the type library to a C header file.
    Dump(dump::DumpArgs),
    /// Generate a diff between two type libraries.
    Diff(diff::DiffArgs),
    /// Validate the type libraries for common errors.
    Validate(validate::ValidateArgs),
}

impl Command {
    pub fn execute(&self) {
        match self {
            Command::Create(args) => {
                args.execute();
            }
            Command::Dump(args) => {
                args.execute();
            }
            Command::Diff(args) => {
                args.execute();
            }
            Command::Validate(args) => {
                args.execute();
            }
        }
    }
}

fn main() {
    let cli = Cli::parse();
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();

    // Capture logs from Binary Ninja
    let _listener = binaryninja::tracing::TracingLogListener::new().register();

    // Initialize Binary Ninja, requires a headless compatible license like commercial or ultimate.
    let _session = binaryninja::headless::Session::new()
        .expect("Failed to create headless binary ninja session");

    cli.command.execute();
}
