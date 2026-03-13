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
use rayon::{ThreadPoolBuildError, ThreadPoolBuilder};
use serde_json::{json, Value};
use tempdir::TempDir;
use thiserror::Error;
use walkdir::WalkDir;

use binaryninja::background_task::BackgroundTask;
use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::function::Function as BNFunction;
use binaryninja::project::file::ProjectFile;
use binaryninja::project::Project;
use binaryninja::rc::{Guard, Ref};

use crate::cache::cached_type_references;
use crate::convert::platform_to_target;
use crate::{build_function, INCLUDE_TAG_NAME};
use binaryninja::file_metadata::{SaveOption, SaveSettings};
use warp::chunk::{Chunk, ChunkKind, CompressionType};
use warp::r#type::chunk::TypeChunk;
use warp::signature::chunk::SignatureChunk;
use warp::signature::function::Function;
use warp::target::Target;
use warp::{WarpFile, WarpFileHeader};

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

    #[error("Failed to create thread pool: {0}")]
    ThreadPoolCreation(ThreadPoolBuildError),
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum IncludedDataField {
    Symbols = 0,
    Signatures = 1,
    Types = 2,
    #[default]
    All = 3,
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum IncludedFunctionsField {
    Selected = 0,
    #[default]
    Annotated = 1,
    All = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub enum RequestAnalysisField {
    No,
    #[default]
    Yes,
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

/// An entry stored in the [`WarpFileProcessor`] to be processed.
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum WarpFileProcessorEntry {
    Path(PathBuf),
    Project(Ref<Project>),
    ProjectFile(Ref<ProjectFile>),
    BinaryView(Ref<BinaryView>),
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
    file_data: IncludedDataField,
    included_functions: IncludedFunctionsField,
    compression_type: CompressionType,
    processed_file_callback: Option<ProcessedFileCallback>,
    /// Whether to skip processing warp files.
    skip_warp_files: bool,
    /// Processor state, this is shareable between threads, so the processor and the consumer can
    /// read / write to the state, use this if you want to show a progress indicator.
    state: Arc<ProcessingState>,
    /// The list of entries to process.
    entries: HashSet<WarpFileProcessorEntry>,
    /// When processing entries with [`WarpFileProcessor::process_entries`], this will
    /// be used to specify the number of worker threads to use for processing entries.
    entry_worker_count: Option<usize>,
}

impl WarpFileProcessor {
    pub fn new() -> Self {
        Self {
            analysis_settings: json!({
                "analysis.linearSweep.autorun": false,
                "analysis.signatureMatcher.autorun": false,
                "analysis.mode": "intermediate",
                // Disable warp when opening views.
                "analysis.warp.guid": true,
                "analysis.warp.matcher": false,
                "analysis.warp.apply": false,
            }),
            // We expect the `build_function` call to be run, so this should be a fine default.
            request_analysis: false,
            cache_path: None,
            file_data: Default::default(),
            included_functions: Default::default(),
            compression_type: Default::default(),
            processed_file_callback: None,
            skip_warp_files: false,
            state: Arc::new(ProcessingState::default()),
            entries: HashSet::new(),
            entry_worker_count: None,
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

    pub fn with_file_data(mut self, file_data: IncludedDataField) -> Self {
        self.file_data = file_data;
        self
    }

    pub fn with_included_functions(mut self, included_functions: IncludedFunctionsField) -> Self {
        self.included_functions = included_functions;
        self
    }

    pub fn with_compression_type(mut self, compression_type: CompressionType) -> Self {
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

    pub fn with_skip_warp_files(mut self, skip: bool) -> Self {
        self.skip_warp_files = skip;
        self
    }

    pub fn with_entry_worker_count(mut self, count: usize) -> Self {
        self.entry_worker_count = Some(count);
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

    /// Add an entry to be processed later by [`WarpFileProcessor::process_entries`].
    pub fn add_entry(&mut self, entry: WarpFileProcessorEntry) {
        self.entries.insert(entry);
    }

    /// Process all entries in the processor, merging them into a single [`WarpFile`].
    ///
    /// The entries list will be cleared after processing to allow the processor to be reused.
    ///
    /// Because entries are processed in parallel, it is advised to set the worker count to a reasonable
    /// amount to avoid excessive resource usage and to ensure optimal performance.
    pub fn process_entries(&mut self) -> Result<WarpFile<'static>, ProcessingError> {
        let thread_pool = match self.entry_worker_count {
            Some(count) => ThreadPoolBuilder::new()
                .num_threads(count)
                .build()
                .map_err(ProcessingError::ThreadPoolCreation)?,
            None => ThreadPoolBuilder::new()
                .build()
                .map_err(ProcessingError::ThreadPoolCreation)?,
        };

        let unmerged_files: Result<Vec<_>, _> = thread_pool.install(|| {
            self.entries
                .par_iter()
                .map(|e| self.process_entry(e))
                .collect()
        });
        self.entries.clear();
        self.merge_files(unmerged_files?)
    }

    pub fn process_entry(
        &self,
        entry: &WarpFileProcessorEntry,
    ) -> Result<WarpFile<'static>, ProcessingError> {
        match entry {
            WarpFileProcessorEntry::Path(path) => self.process_path(path.clone()),
            WarpFileProcessorEntry::Project(project) => self.process_project(&project),
            WarpFileProcessorEntry::ProjectFile(project_file) => {
                self.process_project_file(&project_file)
            }
            WarpFileProcessorEntry::BinaryView(view) => {
                self.process_view(view.file().file_path(), &view)
            }
        }
    }

    pub fn process_path(&self, path: PathBuf) -> Result<WarpFile<'static>, ProcessingError> {
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
        let files = project.files();
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
                self.process_project_file(&file)
            })
            .filter_map(|res| match res {
                Ok(result) => Some(Ok(result)),
                Err(ProcessingError::Cancelled) => Some(Err(ProcessingError::Cancelled)),
                Err(ProcessingError::NoPathToProjectFile(path)) => {
                    tracing::debug!("Skipping non-pulled project file: {:?}", path);
                    None
                }
                Err(ProcessingError::SkippedFile(path)) => {
                    tracing::debug!("Skipping project file: {:?}", path);
                    None
                }
                Err(e) => {
                    tracing::error!("Project file processing error: {:?}", e);
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
                    tracing::debug!("Analysis database found in cache: {:?}", file_cache_path);
                    binaryninja::load_with_options(
                        &file_cache_path,
                        self.request_analysis,
                        Some(settings_str),
                    )
                } else {
                    tracing::debug!("No database found in cache: {:?}", file_cache_path);
                    binaryninja::load_with_options(&path, self.request_analysis, Some(settings_str))
                }
            }
            None => {
                // Processor is not caching analysis
                binaryninja::load_with_options(&path, self.request_analysis, Some(settings_str))
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
                tracing::debug!("Saving analysis database to {:?}", file_cache_path);
                let save_settings = SaveSettings::new().with_option(SaveOption::RemoveUndoData);
                if !view
                    .file()
                    .create_database(&file_cache_path, &save_settings)
                {
                    // TODO: We might want to error here...
                    tracing::warn!("Failed to save analysis database to {:?}", file_cache_path);
                }
            } else {
                tracing::debug!(
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
            // Close the view manually, see comment in [`BinaryView`].
            view.file().close();
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
                if path.is_file() {
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
            .inspect(|path| tracing::debug!("Processing file: {:?}", path))
            .map(|path| {
                self.check_cancelled()?;
                self.process_path(path)
            })
            .filter_map(|res| match res {
                Ok(result) => Some(Ok(result)),
                Err(ProcessingError::SkippedFile(path)) => {
                    tracing::debug!("Skipping directory file: {:?}", path);
                    None
                }
                Err(ProcessingError::Cancelled) => Some(Err(ProcessingError::Cancelled)),
                Err(e) => {
                    tracing::error!("Directory file processing error: {:?}", e);
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
                tracing::debug!("Skipping already inserted entry: {}", normalized_name);
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
            .inspect(|path| tracing::debug!("Processing entry: {:?}", path))
            .map(|path| {
                self.check_cancelled()?;
                self.process_file(path)
            })
            .filter_map(|res| match res {
                Ok(result) => Some(Ok(result)),
                Err(ProcessingError::SkippedFile(path)) => {
                    tracing::debug!("Skipping archive file: {:?}", path);
                    None
                }
                Err(ProcessingError::Cancelled) => Some(Err(ProcessingError::Cancelled)),
                Err(e) => {
                    tracing::error!("Archive file processing error: {:?}", e);
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
        if self.file_data != IncludedDataField::Types {
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

        if self.file_data != IncludedDataField::Signatures {
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
                || f.defined_symbol().is_some()
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
        )
        .enter();

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
                    self.file_data == IncludedDataField::Symbols,
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
            .field("state", &self.state)
            .field("cache_path", &self.cache_path)
            .field("analysis_settings", &self.analysis_settings)
            .field("request_analysis", &self.request_analysis)
            .finish()
    }
}
