use crate::commands::LoadFileField;
use crate::mapper::IDBMapper;
use crate::parse::IDBFileParser;
use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::command::Command;
use binaryninja::interaction::Form;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

pub struct LoadIDBFile;

impl Command for LoadIDBFile {
    fn action(&self, view: &BinaryView) {
        let mut form = Form::new("Load IDB File");
        let mut default_path = PathBuf::from(&view.file().file_path());
        default_path.set_extension("idb");
        let file_field = LoadFileField::with_default(
            "IDA Files (*.idb *.i64 *.til)",
            &default_path.to_string_lossy(),
        );
        form.add_field(file_field.field());
        if !form.prompt() {
            return;
        }
        let Some(file_path) = LoadFileField::from_form(&form) else {
            return;
        };
        let Ok(file) = File::open(&file_path) else {
            tracing::error!("Failed to open file: {}", file_path.display());
            return;
        };
        let mut file_reader = BufReader::new(file);
        let file_parser = IDBFileParser::new();
        match file_parser.parse(&mut file_reader) {
            Ok(idb_info) => {
                IDBMapper::new(idb_info).map_to_view(view);
            }
            Err(e) => {
                tracing::error!("Failed to parse IDB file: {}", e);
            }
        }
    }

    fn valid(&self, _view: &BinaryView) -> bool {
        true
    }
}
