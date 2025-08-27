//! Commit file to a source.

use crate::cache::container::cached_containers;
use crate::container::{SourceId, SourcePath};
use crate::plugin::create::OpenFileField;
use binaryninja::binary_view::BinaryView;
use binaryninja::command::Command;
use binaryninja::interaction::{Form, FormInputField};
use warp::chunk::ChunkKind;
use warp::WarpFile;

pub struct SelectedSourceField {
    sources: Vec<(SourceId, SourcePath)>,
}

impl SelectedSourceField {
    pub fn field(&self) -> FormInputField {
        FormInputField::Choice {
            prompt: "Selected Source".to_string(),
            choices: self
                .sources
                .iter()
                .map(|(id, path)| {
                    // For display purposes we only want to show the last path item.
                    let path_name = path
                        .to_string()
                        .rsplit_once('/')
                        .map_or(path.to_string(), |(_, last_path_item)| {
                            last_path_item.to_string()
                        });
                    // TODO: Probably have a truncation limit here, this is just for display after all.
                    format!("{} ({})", path_name, id)
                })
                .collect(),
            default: None,
            value: 0,
        }
    }

    pub fn from_form(&self, form: &Form) -> Option<SourceId> {
        let field = form.get_field_with_name("Selected Source")?;
        let field_value = field.try_value_index()?;
        self.sources.get(field_value).map(|(id, _)| *id)
    }
}

pub struct CommitFile;

impl CommitFile {
    pub fn selected_source_field() -> SelectedSourceField {
        let mut writable_sources = Vec::new();
        for container in cached_containers() {
            if let Ok(container) = container.read() {
                for source in container.sources().unwrap_or_default() {
                    if let Ok(true) = container.is_source_writable(&source) {
                        if let Ok(source_path) = container.source_path(&source) {
                            writable_sources.push((source, source_path));
                        }
                    }
                }
            }
        }
        SelectedSourceField {
            sources: writable_sources,
        }
    }

    pub fn execute() -> Option<()> {
        let mut form = Form::new("Commit File");

        // Users are going to get confused between this and adding functions to a source then commiting.
        // So we should make it clear with a label, and also probably deprecate this command and replace it with "add functions to source" and "commit source".
        form.add_field(FormInputField::Label {
            prompt: "Commits a WARP file to an existing source, this is primarily used for committing to network containers".to_string()
        });

        form.add_field(OpenFileField::field());
        let source_field = Self::selected_source_field();
        form.add_field(source_field.field());

        if !form.prompt() {
            return None;
        }

        let open_file_path = OpenFileField::from_form(&form)?;
        let source_id = source_field.from_form(&form)?;
        log::info!("Committing file to source: {}", source_id);

        let bytes = std::fs::read(open_file_path).ok()?;
        let Some(warp_file) = WarpFile::from_bytes(&bytes) else {
            log::error!("Failed to parse warp file!");
            return None;
        };

        for container in cached_containers() {
            let Ok(mut container) = container.write() else {
                continue;
            };

            if let Ok(true) = container.is_source_writable(&source_id) {
                // TODO: We need to find a sane way to do this procedure through the FFI.
                for chunk in &warp_file.chunks {
                    match &chunk.kind {
                        ChunkKind::Signature(sc) => {
                            let functions: Vec<_> = sc.functions().collect();
                            log::info!(
                                "Adding {} functions to source: {}",
                                functions.len(),
                                source_id
                            );
                            if let Err(e) = container.add_functions(
                                &chunk.header.target,
                                &source_id,
                                &functions,
                            ) {
                                log::error!("Failed to add functions to source: {}", e);
                            }
                        }
                        ChunkKind::Type(sc) => {
                            let types: Vec<_> = sc.types().collect();
                            log::info!("Adding {} types to source: {}", types.len(), source_id);
                            if let Err(e) = container.add_computed_types(&source_id, &types) {
                                log::error!("Failed to add types to source: {}", e);
                            }
                        }
                    }
                }
                if let Err(e) = container.commit_source(&source_id) {
                    log::error!("Failed to commit source: {}", e);
                }
                log::info!("Committed file to source: {}", source_id);
                return Some(());
            }
        }

        Some(())
    }
}

impl Command for CommitFile {
    fn action(&self, _view: &BinaryView) {
        std::thread::spawn(move || {
            Self::execute();
        });
    }

    fn valid(&self, _view: &BinaryView) -> bool {
        true
    }
}
