use crate::cache::container::{add_cached_container, for_cached_containers};
use crate::container::disk::{DiskContainer, DiskContainerSource};
use crate::container::{ContainerError, SourcePath};
use crate::convert::platform_to_target;
use crate::plugin::workflow::run_matcher;
use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::command::Command;
use binaryninja::interaction::{
    show_message_box, Form, FormInputField, MessageBoxButtonResult, MessageBoxButtonSet,
    MessageBoxIcon,
};
use binaryninja::rc::Ref;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::thread;
use warp::WarpFile;

pub struct LoadFileField;

impl LoadFileField {
    pub fn field() -> FormInputField {
        FormInputField::OpenFileName {
            prompt: "File Path".to_string(),
            // TODO: This is called extension but is really a filter.
            extension: Some("*.warp".to_string()),
            default: None,
            value: None,
        }
    }

    pub fn from_form(form: &Form) -> Option<PathBuf> {
        let field = form.get_field_with_name("File Path")?;
        let field_value = field.try_value_string()?;
        Some(PathBuf::from(field_value))
    }
}

pub struct RunMatcherField;

impl RunMatcherField {
    pub fn field() -> FormInputField {
        FormInputField::Checkbox {
            prompt: "Rerun Matcher".to_string(),
            default: Some(true),
            value: false,
        }
    }

    pub fn from_form(form: &Form) -> Option<bool> {
        let field = form.get_field_with_name("Rerun Matcher")?;
        let field_value = field.try_value_index()?;
        match field_value {
            1 => Some(true),
            _ => Some(false),
        }
    }
}

pub struct LoadSignatureFile;

impl LoadSignatureFile {
    pub fn read_file(
        view: &BinaryView,
        path: SourcePath,
    ) -> Result<WarpFile<'static>, ContainerError> {
        let contents = std::fs::read(&path).map_err(|e| ContainerError::FailedIO(e.kind()))?;
        let mut file = WarpFile::from_owned_bytes(contents).ok_or(
            ContainerError::CorruptedData("file data failed to validate"),
        )?;

        let view_target = view
            .default_platform()
            .map(|p| platform_to_target(&p))
            .unwrap_or_default();
        let file_has_target = file
            .chunks
            .iter()
            .find(|c| c.header.target == view_target)
            .is_some();

        if !file_has_target {
            // File does not contain a view target, alert user if they would like to override the file chunks to the view target.
            let text = format!(
                "Attempting to load WARP file with no target `{:?}`, continue loading anyways?",
                &view_target
            );
            let res = show_message_box(
                "Override file target?",
                &text,
                MessageBoxButtonSet::YesNoButtonSet,
                MessageBoxIcon::WarningIcon,
            );
            if res != MessageBoxButtonResult::YesButton {
                return Err(ContainerError::CorruptedData(
                    "User does not want to load file",
                ));
            }

            // Take all the chunks and convert them to the target, so we load them.
            // If we do not do this, the user will be surprised when they get no new matches.
            for chunk in &mut file.chunks {
                chunk.header.target = view_target.clone();
            }
        }

        Ok(file)
    }

    pub fn execute(view: Ref<BinaryView>) {
        let mut form = Form::new("Load Signature File");
        form.add_field(LoadFileField::field());
        // let fd_field = FileDataKindField::default();
        // form.add_field(fd_field.to_field());
        form.add_field(RunMatcherField::field());
        if !form.prompt() {
            return;
        }

        let Some(file_path) = LoadFileField::from_form(&form) else {
            return;
        };
        // TODO: Decide what to pull using the file data kind.
        // let _file_data_kind = FileDataKindField::from_form(&form).unwrap_or_default();
        let rerun_matcher = RunMatcherField::from_form(&form).unwrap_or(false);

        let source_file_path = SourcePath::new(file_path.clone());
        let source_file_id = source_file_path.to_source_id();

        let file = match LoadSignatureFile::read_file(&view, source_file_path.clone()) {
            Ok(file) => file,
            Err(e) => {
                log::error!("Failed to read signature file: {}", e);
                return;
            }
        };

        // Verify we have not already loaded the file.
        let already_exists = AtomicBool::new(false);
        for_cached_containers(|c| {
            if let Ok(_) = c.source_path(&source_file_id) {
                // TODO: What happens if path differs? Warn?
                already_exists.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        });
        if already_exists.load(std::sync::atomic::Ordering::SeqCst) {
            let res = show_message_box(
                "Load again?",
                "File already loaded, would you like to load it again?",
                MessageBoxButtonSet::YesNoButtonSet,
                MessageBoxIcon::WarningIcon,
            );
            if res != MessageBoxButtonResult::YesButton {
                return;
            }
        }

        let container_source = DiskContainerSource::new(source_file_path.clone(), file);
        log::info!("Loading container source: '{}'", container_source.path);
        let mut map = HashMap::new();
        map.insert(source_file_path.to_source_id(), container_source);
        let container = DiskContainer::new("Loaded signatures".to_string(), map);
        // TODO: See notes in the matcher about doing this, we really need to load it into an existing container.
        add_cached_container(container);

        if rerun_matcher {
            thread::spawn(move || {
                run_matcher(&view);
            });
        }
    }
}

impl Command for LoadSignatureFile {
    fn action(&self, view: &BinaryView) {
        let view = view.to_owned();
        thread::spawn(move || {
            LoadSignatureFile::execute(view);
        });
    }

    fn valid(&self, _view: &BinaryView) -> bool {
        true
    }
}
