use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Formatter};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering::Relaxed;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ar::Archive;
use dashmap::DashMap;
use rayon::iter::IntoParallelIterator;
use rayon::iter::{IntoParallelRefIterator, ParallelIterator};
use rayon::prelude::ParallelSlice;
use regex::Regex;
use serde_json::{json, Value};
use tempdir::TempDir;
use thiserror::Error;
use walkdir::WalkDir;

use binaryninja::background_task::BackgroundTask;
use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::function::Function as BNFunction;
use binaryninja::interaction::{Form, FormInputField};
use binaryninja::project::file::ProjectFile;
use binaryninja::project::Project;
use binaryninja::rc::{Guard, Ref};

use warp::chunk::{Chunk, ChunkKind, CompressionType};
use warp::r#type::chunk::TypeChunk;
use warp::signature::chunk::SignatureChunk;
use warp::signature::function::Function;
use warp::target::Target;
use warp::{WarpFile, WarpFileHeader};

use crate::cache::cached_type_references;
use crate::convert::platform_to_target;
use crate::{build_function, INCLUDE_TAG_ICON, INCLUDE_TAG_NAME};

/// Ensure we never exceed these many functions per signature chunk.
///
/// This was added to fix running into the max table limit on certain files.
const MAX_FUNCTIONS_PER_CHUNK: usize = 1_000_000;

#[derive(Error, Debug)]
pub enum ProcessingError {
    #[error("Failed to open archive: {0}")]
    ArchiveOpen(std::io::Error),

    #[error("Failed to read archive entry: {0}")]
    ArchiveRead(std::io::Error),

    #[error("Binary view load error: {0}")]
    BinaryViewLoad(PathBuf),

    #[error("Existing data load error: {0}")]
    ExistingDataLoad(PathBuf),

    #[error("Temporary directory creation failed: {0}")]
    TempDirCreation(std::io::Error),

    #[error("Failed to read file: {0}")]
    FileRead(std::io::Error),

    #[error("Failed to create chunk, possibly too large")]
    ChunkCreationFailed,

    #[error("Failed to retrieve path to project file: {0:?}")]
    NoPathToProjectFile(Ref<ProjectFile>),

    #[error("Processing state has been poisoned")]
    StatePoisoned,

    #[error("Processing has been cancelled")]
    Cancelled,

    #[error("Skipping file: {0}")]
    SkippedFile(PathBuf),
}

#[derive(Debug, Clone, Default)]
pub struct FileFilterField;

impl FileFilterField {
    pub fn to_field() -> FormInputField {
        FormInputField::TextLine {
            prompt: "File Filter".to_string(),
            default: None,
            value: None,
        }
    }

    pub fn from_form(form: &Form) -> Option<Regex> {
        let field = form.get_field_with_name("File Filter")?;
        let field_value = field.try_value_string()?;

        // TODO: This is pretty absurd but whatever.
        let pattern = if field_value.contains(['*', '.', '[', '(']) {
            // Assume it's a regex if it contains meta-characters.
            field_value
        } else {
            // Treat it as a substring
            format!(".*{}.*", regex::escape(&field_value))
        };

        Regex::new(&pattern).ok()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum FileDataKindField {
    Symbols,
    Signatures,
    Types,
    #[default]
    All,
}

impl FileDataKindField {
    pub fn to_field(&self) -> FormInputField {
        FormInputField::Choice {
            prompt: "File Data".to_string(),
            choices: vec![
                "Symbols".to_string(),
                "Signatures".to_string(),
                "Types".to_string(),
                "All".to_string(),
            ],
            default: Some(match self {
                Self::Symbols => 0,
                Self::Signatures => 1,
                Self::Types => 2,
                Self::All => 3,
            }),
            value: 0,
        }
    }

    pub fn from_form(form: &Form) -> Option<Self> {
        let field = form.get_field_with_name("File Data")?;
        let field_value = field.try_value_index()?;
        match field_value {
            3 => Some(Self::All),
            2 => Some(Self::Types),
            1 => Some(Self::Signatures),
            0 => Some(Self::Symbols),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum IncludedFunctionsField {
    Selected,
    #[default]
    Annotated,
    All,
}

impl IncludedFunctionsField {
    pub fn to_field(&self) -> FormInputField {
        // If the user has selected any functions, change the default value of the included functions field.
        FormInputField::Choice {
            prompt: "Included Functions".to_string(),
            choices: vec![
                format!("Selected {}", INCLUDE_TAG_ICON),
                "Annotated".to_string(),
                "All".to_string(),
            ],
            default: Some(match self {
                Self::Selected => 0,
                Self::Annotated => 1,
                Self::All => 2,
            }),
            value: 0,
        }
    }

    pub fn from_form(form: &Form) -> Option<Self> {
        let field = form.get_field_with_name("Included Functions")?;
        let field_value = field.try_value_index()?;
        match field_value {
            2 => Some(Self::All),
            1 => Some(Self::Annotated),
            0 => Some(Self::Selected),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum SaveReportToDiskField {
    No,
    #[default]
    Yes,
}

impl SaveReportToDiskField {
    pub fn to_field(&self) -> FormInputField {
        FormInputField::Checkbox {
            prompt: "Save Report to Disk".to_string(),
            default: Some(true),
            value: false,
        }
    }

    pub fn from_form(form: &Form) -> Option<Self> {
        let field = form.get_field_with_name("Save Report to Disk")?;
        let field_value = field.try_value_int()?;
        match field_value {
            1 => Some(Self::Yes),
            _ => Some(Self::No),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum CompressionTypeField {
    None,
    #[default]
    Zstd,
}

impl CompressionTypeField {
    pub fn to_field(&self) -> FormInputField {
        FormInputField::Choice {
            prompt: "Compression Type".to_string(),
            choices: vec!["None".to_string(), "Zstd".to_string()],
            default: Some(match self {
                Self::None => 0,
                Self::Zstd => 1,
            }),
            value: 0,
        }
    }

    pub fn from_form(form: &Form) -> Option<Self> {
        let field = form.get_field_with_name("Compression Type")?;
        let field_value = field.try_value_index()?;
        match field_value {
            1 => Some(Self::Zstd),
            _ => Some(Self::None),
        }
    }
}

impl From<CompressionTypeField> for CompressionType {
    fn from(field: CompressionTypeField) -> Self {
        match field {
            CompressionTypeField::None => CompressionType::None,
            CompressionTypeField::Zstd => CompressionType::Zstd,
        }
    }
}

pub fn new_processing_state_background_thread(
    task: Ref<BackgroundTask>,
    state: Arc<ProcessingState>,
) {
    std::thread::spawn(move || {
        let start = Instant::now();
        while !task.is_finished() {
            std::thread::sleep(Duration::from_millis(100));
            // Check if the user wants to cancel the processing.
            if task.is_cancelled() {
                state.cancel();
            }

            let total = state.total_files();
            let processed = state.files_with_state(ProcessingFileState::Processed);
            let unprocessed = state.files_with_state(ProcessingFileState::Unprocessed);
            let analyzing = state.files_with_state(ProcessingFileState::Analyzing);
            let processing = state.files_with_state(ProcessingFileState::Processing);
            let completion = (processed as f64 / total as f64) * 100.0;
            let elapsed = start.elapsed().as_secs_f32();
            let text = format!(
                "Processing {} files... {{{}|{}|{}|{}}} ({:.2}%) [{:.2}s]",
                total, unprocessed, analyzing, processing, processed, completion, elapsed
            );
            task.set_progress_text(&text);
        }
    });
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ProcessingFileState {
    /// File is yet to be processed.
    Unprocessed,
    /// File is being analyzed by Binary Ninja.
    Analyzing,
    /// File is currently generating WARP data.
    /// TODO: (AtomicUsize) for the total and done functions, we can then write to it with Relaxed when processing.
    Processing,
    /// File is done being processed.
    Processed,
}

/// A callback for when a file has been processed, use this if you intend to save off individual
/// files inside a directory, project or archive.
pub type ProcessedFileCallback = Arc<dyn Fn(&Path, &WarpFile) + Send + Sync>;

#[derive(Debug, Default)]
pub struct ProcessingState {
    pub cancelled: AtomicBool,
    pub files: DashMap<PathBuf, ProcessingFileState>,
    pub total_functions: AtomicUsize,
}

impl ProcessingState {
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Relaxed)
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Relaxed)
    }

    pub fn increment_functions(&self) {
        self.total_functions.fetch_add(1, Relaxed);
    }

    pub fn total_files(&self) -> usize {
        self.files.len()
    }

    pub fn files_with_state(&self, state: ProcessingFileState) -> usize {
        self.files.iter().filter(|f| *f.value() == state).count()
    }

    pub fn set_file_state(&self, path: PathBuf, state: ProcessingFileState) {
        self.files.insert(path, state);
    }
}

/// Create a new [`WarpFile`] from files, projects, and directories.
#[derive(Clone)]
pub struct WarpFileProcessor {
    /// The Binary Ninja settings to use when analyzing the binaries.
    analysis_settings: Value,
    /// For any function without an LLIL, request analysis to be run, waiting for analysis to
    /// complete to include in the analysis.
    request_analysis: bool,
    // TODO: Project cache path, so we save to a project instead of some temp path.
    // TODO: Databases will require regenerating LLIL in some cases, so we must support generating the LLIL.
    /// The path to a folder to intake and output analysis artifacts.
    cache_path: Option<PathBuf>,
    file_data: FileDataKindField,
    included_functions: IncludedFunctionsField,
    compression_type: CompressionTypeField,
    processed_file_callback: Option<ProcessedFileCallback>,
    /// Regex pattern used to filter out files.
    file_filter: Option<Regex>,
    // TODO: Merge with file filter.
    /// Whether to skip processing warp files.
    skip_warp_files: bool,
    /// Processor state, this is shareable between threads, so the processor and the consumer can
    /// read / write to the state, use this if you want to show a progress indicator.
    state: Arc<ProcessingState>,
}

impl WarpFileProcessor {
    pub fn new() -> Self {
        Self {
            analysis_settings: json!({
                "analysis.linearSweep.autorun": false,
                "analysis.signatureMatcher.autorun": false,
                "analysis.mode": "full",
                // Disable warp when opening views.
                "analysis.warp.guid": false,
                "analysis.warp.matcher": false,
                "analysis.warp.apply": false,
            }),
            request_analysis: true,
            cache_path: None,
            file_data: Default::default(),
            included_functions: Default::default(),
            compression_type: Default::default(),
            processed_file_callback: None,
            file_filter: None,
            skip_warp_files: false,
            state: Arc::new(ProcessingState::default()),
        }
    }

    /// Retrieve a thread-safe shared reference to the [`ProcessingState`].
    pub fn state(&self) -> Arc<ProcessingState> {
        self.state.clone()
    }

    pub fn with_analysis_settings(mut self, analysis_settings: Value) -> Self {
        self.analysis_settings = analysis_settings;
        self
    }

    pub fn with_request_analysis(mut self, request_analysis: bool) -> Self {
        self.request_analysis = request_analysis;
        self
    }

    pub fn with_cache_path(mut self, cache_path: PathBuf) -> Self {
        self.cache_path = Some(cache_path);
        self
    }

    pub fn with_file_data(mut self, file_data: FileDataKindField) -> Self {
        self.file_data = file_data;
        self
    }

    pub fn with_included_functions(mut self, included_functions: IncludedFunctionsField) -> Self {
        self.included_functions = included_functions;
        self
    }

    pub fn with_compression_type(mut self, compression_type: CompressionTypeField) -> Self {
        self.compression_type = compression_type;
        self
    }

    pub fn with_processed_file_callback(
        mut self,
        processed_file_callback: impl Fn(&Path, &WarpFile) + Send + Sync + 'static,
    ) -> Self {
        self.processed_file_callback = Some(Arc::new(processed_file_callback));
        self
    }

    pub fn with_file_filter(mut self, file_filter: Regex) -> Self {
        self.file_filter = Some(file_filter);
        self
    }

    pub fn file_filter(&self, path: &Path) -> bool {
        match (&self.file_filter, path.to_str()) {
            (Some(filter), Some(path)) => filter.is_match(path),
            _ => true,
        }
    }

    pub fn with_skip_warp_files(mut self, skip: bool) -> Self {
        self.skip_warp_files = skip;
        self
    }

    /// Place a call to this in places to interrupt when canceled.
    fn check_cancelled(&self) -> Result<(), ProcessingError> {
        match self.state.is_cancelled() {
            true => Err(ProcessingError::Cancelled),
            false => Ok(()),
        }
    }

    pub fn merge_files(
        &self,
        files: Vec<WarpFile<'static>>,
    ) -> Result<WarpFile<'static>, ProcessingError> {
        let chunks: Vec<_> = files.into_iter().flat_map(|f| f.chunks.clone()).collect();
        let merged_chunks = Chunk::merge(&chunks, self.compression_type.into());
        Ok(WarpFile::new(WarpFileHeader::new(), merged_chunks))
    }

    pub fn process(&self, path: PathBuf) -> Result<WarpFile<'static>, ProcessingError> {
        let file = match path.extension() {
            Some(ext) if ext == "a" || ext == "lib" || ext == "rlib" => {
                self.process_archive(path.clone())
            }
            Some(ext) if ext == "warp" => self.process_warp_file(path.clone()),
            _ if path.is_dir() => self.process_directory(&path),
            // TODO: process_database?
            _ => self.process_file(path.clone()),
        }?;

        // We do this right after we process the file so that all possible paths to this will be caught.
        // This callback is typically used to write the file out to some other place for caching or
        // for distributing smaller unmerged files.
        if let Some(callback) = &self.processed_file_callback {
            callback(&path, &file);
        }

        Ok(file)
    }

    pub fn process_project(&self, project: &Project) -> Result<WarpFile<'static>, ProcessingError> {
        let filter_project_file = |file: &Guard<ProjectFile>| {
            let path = project_file_path(file);
            self.file_filter(&path)
        };

        let files: Vec<_> = project
            .files()
            .iter()
            .filter(filter_project_file)
            .map(|f| f.to_owned())
            .collect();

        // Inform the state of the new unprocessed project files.
        for project_file in &files {
            // NOTE: We use the on disk path here because the downstream file state uses that.
            if let Some(path) = project_file.path_on_disk() {
                self.state
                    .set_file_state(path, ProcessingFileState::Unprocessed);
            }
        }

        let unmerged_files: Result<Vec<_>, _> = files
            .par_iter()
            .map(|file| {
                self.check_cancelled()?;
                self.process_project_file(file)
            })
            .filter_map(|res| match res {
                Ok(result) => Some(Ok(result)),
                Err(ProcessingError::Cancelled) => Some(Err(ProcessingError::Cancelled)),
                Err(ProcessingError::SkippedFile(path)) => {
                    log::debug!("Skipping project file: {:?}", path);
                    None
                }
                Err(e) => {
                    log::error!("Project file processing error: {:?}", e);
                    None
                }
            })
            .collect();

        self.merge_files(unmerged_files?)
    }

    pub fn process_project_file(
        &self,
        project_file: &ProjectFile,
    ) -> Result<WarpFile<'static>, ProcessingError> {
        let file_name = project_file.name();
        let extension = file_name.split('.').last();
        let path = project_file
            .path_on_disk()
            .ok_or_else(|| ProcessingError::NoPathToProjectFile(project_file.to_owned()))?;
        let file = match extension {
            Some(ext) if ext == "a" || ext == "lib" || ext == "rlib" => {
                self.process_archive(path.clone())
            }
            Some("warp") => self.process_warp_file(path.clone()),
            _ => self.process_file(path.clone()),
        }?;

        // We do this right after we process the file so that all possible paths to this will be caught.
        // This callback is typically used to write the file out to some other place for caching or
        // for distributing smaller unmerged files.
        if let Some(callback) = &self.processed_file_callback {
            callback(&path, &file);
        }

        Ok(file)
    }

    pub fn process_warp_file(&self, path: PathBuf) -> Result<WarpFile<'static>, ProcessingError> {
        // TODO: In the future this really should just be a file filter.
        if self.skip_warp_files {
            return Err(ProcessingError::SkippedFile(path));
        }

        let contents = std::fs::read(&path).map_err(ProcessingError::FileRead)?;
        let file = WarpFile::from_owned_bytes(contents)
            .ok_or(ProcessingError::ExistingDataLoad(path.clone()));

        // Inform the state of the new processed warp file.
        self.state
            .set_file_state(path, ProcessingFileState::Processed);

        file
    }

    pub fn process_file(&self, path: PathBuf) -> Result<WarpFile<'static>, ProcessingError> {
        // Inform the state of the new analyzing file.
        self.state
            .set_file_state(path.clone(), ProcessingFileState::Analyzing);

        // Load the view, either from the cache or from the given path.
        // Using the cache can speed up the processing, especially for larger binaries.
        let settings_str = self.analysis_settings.to_string();
        let view = match &self.cache_path {
            Some(cache_path) => {
                // Processor is caching analysis, try and find our file in the cache.
                let file_cache_path = cache_path
                    .join(path.file_name().unwrap())
                    .with_extension("bndb");
                if file_cache_path.exists() {
                    // TODO: Update analysis and wait option
                    log::debug!("Analysis database found in cache: {:?}", file_cache_path);
                    binaryninja::load_with_options(&file_cache_path, true, Some(settings_str))
                } else {
                    log::debug!("No database found in cache: {:?}", file_cache_path);
                    binaryninja::load_with_options(&path, true, Some(settings_str))
                }
            }
            None => {
                // Processor is not caching analysis
                binaryninja::load_with_options(&path, true, Some(settings_str))
            }
        }
        .ok_or(ProcessingError::BinaryViewLoad(path.clone()))?;

        // Analysis is complete, if needed, save the database to cache.
        if let Some(cache_path) = &self.cache_path {
            // Before we process the view we should cache the analysis database.
            // Only cache the analysis database if there has been a change.
            // TODO: What if there is multiple paths with the same name?
            // TODO: We need more context than just the path, likely we need a processing path stack.
            let file_cache_path = cache_path
                .join(path.file_name().unwrap())
                .with_extension("bndb");
            // TODO: We should also update the cache if analysis has changed!
            if !view.file().is_database_backed() {
                // Update the cache.
                log::debug!("Saving analysis database to {:?}", file_cache_path);
                if !view.file().create_database(&file_cache_path) {
                    // TODO: We might want to error here...
                    log::warn!("Failed to save analysis database to {:?}", file_cache_path);
                }
            } else {
                log::debug!(
                    "Analysis database unchanged, skipping save to {:?}",
                    file_cache_path
                );
            }
        }

        // In the future we may want to do something with a view that has no functions, but for now
        // we do not care to create any chunks. By skipping this we can avoid merging of empty chunks,
        // which is quick, but it still requires some allocations that we can avoid.
        if view.functions().is_empty() {
            self.state
                .set_file_state(path.clone(), ProcessingFileState::Processed);
            return Err(ProcessingError::SkippedFile(path));
        }

        // Process the view
        let warp_file = self.process_view(path, &view);
        // Close the view manually, see comment in [`BinaryView`].
        view.file().close();
        warp_file
    }

    pub fn process_directory(&self, path: &Path) -> Result<WarpFile<'static>, ProcessingError> {
        // Collect all files in the directory
        let files = WalkDir::new(path)
            .into_iter()
            .filter_map(|e| {
                let path = e.ok()?.into_path();
                if path.is_file() && self.file_filter(&path) {
                    Some(path)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        // Inform the state of the new unprocessed files.
        for entry_file in &files {
            self.state
                .set_file_state(entry_file.clone(), ProcessingFileState::Unprocessed);
        }

        // Process all the files.
        let unmerged_files: Result<Vec<_>, _> = files
            .into_par_iter()
            .inspect(|path| log::debug!("Processing file: {:?}", path))
            .map(|path| {
                self.check_cancelled()?;
                self.process(path)
            })
            .filter_map(|res| match res {
                Ok(result) => Some(Ok(result)),
                Err(ProcessingError::SkippedFile(path)) => {
                    log::debug!("Skipping directory file: {:?}", path);
                    None
                }
                Err(ProcessingError::Cancelled) => Some(Err(ProcessingError::Cancelled)),
                Err(e) => {
                    log::error!("Directory file processing error: {:?}", e);
                    None
                }
            })
            .collect();

        self.merge_files(unmerged_files?)
    }

    pub fn process_archive(&self, path: PathBuf) -> Result<WarpFile<'static>, ProcessingError> {
        // Open the archive.
        let archive_file = File::open(&path).map_err(ProcessingError::ArchiveOpen)?;
        let mut archive = Archive::new(archive_file);

        // Create a temp directory to store the archive entries.
        let temp_dir = TempDir::new("tmp_archive").map_err(ProcessingError::TempDirCreation)?;

        // TODO: Use the file_filter? We would need to normalize the path then.
        // Iterate through the entries in the ar file and make a temp dir with them
        let mut entry_files: HashSet<PathBuf> = HashSet::new();
        while let Some(entry) = archive.next_entry() {
            let mut entry = entry.map_err(ProcessingError::ArchiveRead)?;
            // NOTE: The entry name here may resemble a full path, on unix this is fine, but
            // on Windows this will prevent a file from being created, so we "normalize" the file name.
            let name = String::from_utf8_lossy(entry.header().identifier()).to_string();
            // Normalize file name for Windows compatibility
            let normalized_name = name
                .replace(':', "_")
                .replace('/', "_")
                .replace('\\', "_")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join("_");
            let output_path = temp_dir.path().join(&normalized_name);
            if !entry_files.contains(&output_path) {
                let mut output_file =
                    File::create(&output_path).map_err(ProcessingError::TempDirCreation)?;
                std::io::copy(&mut entry, &mut output_file).map_err(ProcessingError::FileRead)?;
                entry_files.insert(output_path);
            } else {
                log::debug!("Skipping already inserted entry: {}", normalized_name);
            }
        }

        // Inform the state of the new unprocessed files.
        for entry_file in &entry_files {
            self.state
                .set_file_state(entry_file.clone(), ProcessingFileState::Unprocessed);
        }

        // Process all the entries.
        let unmerged_files: Result<Vec<_>, _> = entry_files
            .into_par_iter()
            .inspect(|path| log::debug!("Processing entry: {:?}", path))
            .map(|path| {
                self.check_cancelled()?;
                self.process_file(path)
            })
            .filter_map(|res| match res {
                Ok(result) => Some(Ok(result)),
                Err(ProcessingError::Cancelled) => Some(Err(ProcessingError::Cancelled)),
                Err(e) => {
                    log::error!("Archive file processing error: {:?}", e);
                    None
                }
            })
            .collect();

        self.merge_files(unmerged_files?)
    }

    pub fn process_view(
        &self,
        path: PathBuf,
        view: &BinaryView,
    ) -> Result<WarpFile<'static>, ProcessingError> {
        self.state
            .set_file_state(path.clone(), ProcessingFileState::Processing);

        let mut chunks = Vec::new();
        if self.file_data != FileDataKindField::Types {
            let mut signature_chunks = self.create_signature_chunks(view)?;
            for (target, mut target_chunks) in signature_chunks.drain() {
                for signature_chunk in target_chunks.drain(..) {
                    if signature_chunk.raw_functions().next().is_some() {
                        let chunk = Chunk::new_with_target(
                            ChunkKind::Signature(signature_chunk),
                            self.compression_type.into(),
                            target.clone(),
                        );
                        chunks.push(chunk)
                    }
                }
            }
        }

        if self.file_data != FileDataKindField::Signatures {
            let type_chunk = self.create_type_chunk(view)?;
            if type_chunk.raw_types().next().is_some() {
                chunks.push(Chunk::new(
                    ChunkKind::Type(type_chunk),
                    self.compression_type.into(),
                ));
            }
        }

        self.state
            .set_file_state(path, ProcessingFileState::Processed);

        Ok(WarpFile::new(WarpFileHeader::new(), chunks))
    }

    /// Create signature chunks for each unique [`Target`].
    ///
    /// A [`Target`] in Binary Ninja is a [`Platform`], so we just fill in that information.
    pub fn create_signature_chunks(
        &self,
        view: &BinaryView,
    ) -> Result<HashMap<Target, Vec<SignatureChunk<'static>>>, ProcessingError> {
        let is_function_named = |f: &Guard<BNFunction>| {
            self.included_functions == IncludedFunctionsField::All
                || view.symbol_by_address(f.start()).is_some()
                || f.has_user_annotations()
        };
        let is_function_tagged = |f: &Guard<BNFunction>| {
            self.included_functions != IncludedFunctionsField::Selected
                || !f.function_tags(None, Some(INCLUDE_TAG_NAME)).is_empty()
        };
        // TODO: is_function_blacklisted (use tag)

        // TODO: Move this background task to use the ProcessingState.
        let view_functions = view.functions();
        let total_functions = view_functions.len();
        let done_functions = AtomicUsize::default();
        let background_task = BackgroundTask::new(
            &format!("Generating signatures... ({}/{})", 0, total_functions),
            true,
        );

        // Create all of the "built" functions, for the chunk.
        // NOTE: This does a bit of filtering to remove undesired functions, look at this if
        // a desired function is not in the created chunk.
        // TODO: Make this interruptable. with background_task.is_cancelled.
        let start = Instant::now();
        let built_functions: DashMap<Target, Vec<Function>> = view_functions
            .par_iter()
            .inspect(|_| {
                done_functions.fetch_add(1, Relaxed);
                background_task.set_progress_text(&format!(
                    "Generating signatures... ({}/{}) [{}s]",
                    done_functions.load(Relaxed),
                    total_functions,
                    start.elapsed().as_secs_f32()
                ))
            })
            .filter(is_function_tagged)
            .filter(is_function_named)
            .filter(|f| !f.analysis_skipped())
            .filter_map(|func| {
                let target = platform_to_target(&func.platform());
                let built_function = build_function(
                    &func,
                    || func.lifted_il().ok(),
                    self.file_data == FileDataKindField::Symbols,
                )?;
                Some((target, built_function))
            })
            .fold(
                DashMap::new,
                |acc: DashMap<Target, Vec<Function>>, (target, function)| {
                    acc.entry(target).or_default().push(function);
                    acc
                },
            )
            .reduce(DashMap::new, |acc, other| {
                other.into_iter().for_each(|(key, value)| {
                    acc.entry(key).or_default().extend(value);
                });
                acc
            });

        // Split into multiple chunks if a target has more than MAX_FUNCTIONS_PER_CHUNK functions.
        // We do this because otherwise some chunks may have too many flatbuffer tables for the verifier to handle.
        let chunks: Result<HashMap<Target, Vec<SignatureChunk<'static>>>, ProcessingError> =
            built_functions
                .into_par_iter()
                .map(|(target, functions)| {
                    let chunks: Result<Vec<_>, _> = functions
                        .par_chunks(MAX_FUNCTIONS_PER_CHUNK)
                        .map(|f| {
                            SignatureChunk::new(&f).ok_or(ProcessingError::ChunkCreationFailed)
                        })
                        .collect();
                    Ok((target, chunks?))
                })
                .collect();

        background_task.finish();
        chunks
    }

    // TODO: Add a background task here.
    pub fn create_type_chunk(
        &self,
        view: &BinaryView,
    ) -> Result<TypeChunk<'static>, ProcessingError> {
        let mut referenced_types = Vec::new();
        if let Some(ref_ty_cache) = cached_type_references(view) {
            referenced_types = ref_ty_cache
                .cache
                .iter()
                .filter_map(|t| t.to_owned())
                .collect::<Vec<_>>();
        }
        TypeChunk::new_with_computed(&referenced_types).ok_or(ProcessingError::ChunkCreationFailed)
    }
}

impl Debug for WarpFileProcessor {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WarpFileProcessor")
            .field("file_data", &self.file_data)
            .field("compression_type", &self.compression_type)
            .field("included_functions", &self.included_functions)
            .field("file_filter", &self.file_filter)
            .field("state", &self.state)
            .field("cache_path", &self.cache_path)
            .field("analysis_settings", &self.analysis_settings)
            .finish()
    }
}

fn project_file_path(file: &ProjectFile) -> PathBuf {
    // Recurse up the folders to build a string like /foldera/folderb/myfile
    let mut path = PathBuf::new();
    // Add file name
    path.push(file.name());
    // Recursively add parent folder names
    let mut current = file.folder();
    while let Some(folder) = current {
        path = PathBuf::from(folder.name()).join(path);
        current = folder.parent();
    }
    path
}
