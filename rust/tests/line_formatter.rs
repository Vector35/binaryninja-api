use binaryninja::disassembly::DisassemblyTextLine;
use binaryninja::headless::Session;
use binaryninja::line_formatter::{register_line_formatter, LineFormatter, LineFormatterSettings};
use std::path::PathBuf;

struct MyLineFormatter;

impl LineFormatter for MyLineFormatter {
    fn format_lines(
        &self,
        lines: &[DisassemblyTextLine],
        _settings: &LineFormatterSettings,
    ) -> Vec<DisassemblyTextLine> {
        lines.to_vec()
    }
}

#[test]
fn test_custom_line_formatter() {
    let _session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let line_formatter = register_line_formatter("my_line_formatter", MyLineFormatter {});
    assert_eq!(line_formatter.name().as_str(), "my_line_formatter");
}
