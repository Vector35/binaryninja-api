use crate::report::ReportGenerator;
use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::command::Command;

pub struct ShowFileReport;

impl Command for ShowFileReport {
    fn action(&self, view: &BinaryView) {
        let view = view.to_owned();
        std::thread::spawn(move || {
            let Some(path) =
                binaryninja::interaction::get_open_filename_input("Select file to show", "*.warp")
            else {
                return;
            };

            let Ok(bytes) = std::fs::read(&path) else {
                log::error!("Failed to read file: {:?}", path);
                return;
            };

            let Some(file) = warp::WarpFile::from_bytes(&bytes) else {
                log::error!("Failed to parse file: {:?}", path);
                return;
            };

            let report_generator = ReportGenerator::new();
            if let Some(html_string) = report_generator.html_report(&file) {
                view.show_html_report(
                    &format!("WARP File: {}", path.to_string_lossy()),
                    html_string.as_str(),
                    "",
                );
            }
        });
    }

    fn valid(&self, _view: &BinaryView) -> bool {
        true
    }
}
