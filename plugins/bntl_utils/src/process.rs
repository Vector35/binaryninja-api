//! Process different types of files into Binary Ninja type libraries.

use binaryninja::architecture::CoreArchitecture;
use dashmap::DashMap;
use std::collections::{HashMap, HashSet};
use std::env::temp_dir;
use std::ffi::OsStr;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use walkdir::WalkDir;

use crate::helper::visit_type_reference;
use crate::merge::merge_types;
use crate::schema::BntlSchema;
use crate::tbd::{parse_tbd_info, TbdArchitecture};
use crate::winmd::WindowsMetadataImporter;
use binaryninja::background_task::BackgroundTask;
use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::custom_binary_view::BinaryViewType;
use binaryninja::file_metadata::FileMetadata;
use binaryninja::metadata::Metadata;
use binaryninja::platform::Platform;
use binaryninja::project::file::ProjectFile;
use binaryninja::project::folder::ProjectFolder;
use binaryninja::project::Project;
use binaryninja::qualified_name::QualifiedName;
use binaryninja::rc::Ref;
use binaryninja::section::Section;
use binaryninja::types::{
    CoreTypeParser, NamedTypeReference, Type, TypeClass, TypeLibrary, TypeParser, TypeParserError,
};
use nt_apiset::{ApiSetMap, NtApiSetError};

#[derive(Error, Debug)]
pub enum ProcessingError {
    #[error("Binary view load error: {0}")]
    BinaryViewLoad(PathBuf),

    #[error("Failed to read binary view at offset {0:?} with length {1:?}")]
    BinaryViewRead(u64, usize),

    #[error("Failed to read .apiset section: {0}")]
    FailedToReadApiSet(#[from] NtApiSetError),

    #[error("Failed to read file: {0}")]
    FileRead(std::io::Error),

    #[error("Failed to retrieve path to project file: {0:?}")]
    NoPathToProjectFile(Ref<ProjectFile>),

    #[error("Processing state has been poisoned")]
    StatePoisoned,

    #[error("Processing has been cancelled")]
    Cancelled,

    #[error("Skipping file: {0}")]
    SkippedFile(PathBuf),

    #[error("Failed to find platform: {0}")]
    PlatformNotFound(String),

    #[error("Failed to parse types: {0:?}")]
    TypeParsingFailed(Vec<TypeParserError>),

    #[error("Failed to import winmd: {0}")]
    WinMdFailedImport(crate::winmd::ImportError),

    #[error("Failed to parse type library: {0}")]
    InvalidTypeLibrary(PathBuf),
}

#[derive(Default, Debug)]
pub struct ProcessingState {
    pub cancelled: AtomicBool,
    pub files: DashMap<PathBuf, bool>,
}

impl ProcessingState {
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Relaxed)
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Relaxed)
    }

    pub fn files_with_state(&self, state: bool) -> usize {
        self.files.iter().filter(|f| *f.value() == state).count()
    }

    pub fn set_file_state(&self, path: PathBuf, state: bool) {
        self.files.insert(path, state);
    }

    pub fn total_files(&self) -> usize {
        self.files.len()
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
            let processed = state.files_with_state(true);
            let unprocessed = state.files_with_state(false);
            let completion = (processed as f64 / total as f64) * 100.0;
            let elapsed = start.elapsed().as_secs_f32();
            let text = format!(
                "Processing {} files... {{{}|{}}} ({:.2}%) [{:.2}s]",
                total, unprocessed, processed, completion, elapsed
            );
            task.set_progress_text(&text);
        }
    });
}

/// The result of running [`TypeLibProcessor`].
#[derive(Debug, Clone)]
pub struct ProcessedData {
    pub type_libraries: HashSet<Ref<TypeLibrary>>,
}

impl ProcessedData {
    pub fn new(type_libraries: Vec<Ref<TypeLibrary>>) -> Self {
        Self {
            type_libraries: type_libraries.into_iter().collect(),
        }
    }

    /// Finalizes the processed data, deduplicating types and pruning empty type libraries.
    ///
    /// The `default_name` should be the library name for which you want deduplicated types to be
    /// relocated to. This does not need to be a logical-shared library name like `mylib.dll` as it will
    /// be only referenced by other loaded type libraries (it cannot contain named objects).
    pub fn finalized(mut self, default_name: &str) -> Self {
        self.deduplicate_types(default_name);
        // TODO: Run remap.
        self.prune()
    }

    /// Prune empty type libraries from the processed data.
    ///
    /// This is useful if you intend to save the type libraries to disk in a finalized form.
    pub fn prune(self) -> Self {
        let is_empty =
            |tl: &TypeLibrary| tl.named_types().is_empty() && tl.named_objects().is_empty();
        let pruned_type_libraries = self
            .type_libraries
            .into_iter()
            .filter(|tl| !is_empty(tl))
            .collect::<Vec<_>>();
        Self::new(pruned_type_libraries)
    }

    /// Merges multiple [`ProcessedData`] into one, deduplicating type libraries.
    ///
    /// This is necessary to allow the [`TypeLibProcessor`] to operate on a wide range of formats whilst
    /// also guaranteeing no collisions and valid external references. Without merging libraries with
    /// identical dependency names would be separate, which is not a supported scenario when loading
    /// type libraries into Binary Ninja.
    pub fn merge(list: &[ProcessedData]) -> Self {
        let mut type_libraries = Vec::new();
        for data in list {
            type_libraries.extend(data.type_libraries.iter().cloned());
        }

        // We merge type libraries with the same dependency name, as that is what needs to be unique
        // when we go to load them into Binary Ninja.
        let mut mapped_type_libraries: HashMap<(String, CoreArchitecture), Vec<Ref<TypeLibrary>>> =
            HashMap::new();
        for tl in type_libraries.iter() {
            mapped_type_libraries
                .entry((tl.dependency_name(), tl.arch()))
                .or_default()
                .push(tl.clone());
        }

        let mut merged_type_libraries = Vec::new();
        for ((dependency_name, arch), type_libraries) in mapped_type_libraries {
            // Skip the more expensive merging if there is only a single type library.
            if type_libraries.len() == 1 {
                merged_type_libraries.push(type_libraries[0].clone());
                continue;
            }

            let merged_type_library = TypeLibrary::new(arch, &dependency_name);
            merged_type_library.set_dependency_name(&dependency_name);
            for tl in type_libraries {
                // TODO: Cheap type overrides (if one type is set as void* and the other as Foo* we take Foo*)
                for named_type in &tl.named_types() {
                    merged_type_library.add_named_type(named_type.name.clone(), &named_type.ty);
                }
                for named_object in &tl.named_objects() {
                    merged_type_library
                        .add_named_object(named_object.name.clone(), &named_object.ty);
                }
                for alt_name in &tl.alternate_names() {
                    merged_type_library.add_alternate_name(alt_name);
                }
                for platform_name in &tl.platform_names() {
                    if let Some(platform) = Platform::by_name(platform_name) {
                        merged_type_library.add_platform(&platform);
                    } else {
                        // TODO: Upgrade this to an error?
                        tracing::warn!(
                            "Unknown platform name when merging '{}': '{}'",
                            dependency_name,
                            platform_name
                        );
                    }
                }
                // TODO: Stealing the type sources is literally impossible there is no getter, incredible...
                // TODO: Replace this with a getter to type sources :/
                let tmp_file = temp_dir().join(format!("{}_{}.json", dependency_name, tl.guid()));
                if tl.decompress_to_file(&tmp_file) {
                    let schema = BntlSchema::from_path(&tmp_file);
                    for type_source in schema.type_sources {
                        merged_type_library
                            .add_type_source(type_source.name.into(), &type_source.source);
                    }
                }

                // Merge type library metadata, which can contain ordinal mappings.
                if let Some(metadata_kv) = tl.metadata().get_value_store() {
                    // TODO: Handle merging of inner key values.
                    for (key, value) in metadata_kv {
                        let _ = merged_type_library.metadata().insert(&key, &value);
                    }
                }
            }
            merged_type_libraries.push(merged_type_library);
        }

        Self::new(merged_type_libraries)
    }

    /// Maps the default type library objects into their locatable type libraries, if available.
    ///
    /// This process is necessary only when the source of the processed data could not determine,
    /// like in the case of header files, where the type library dependency name (e.g. "sqlite3.dll")
    /// cannot be determined in a vacuum.
    ///
    /// In the absence of that dependency name, the processor also parses auxiliary information like
    /// apples TBD (text-based dylib stubs) to find out where to relocate those objects. For more
    /// information see [`TypeLibProcessor::process_tbd`]
    pub fn remap(&mut self, default_type_library: &str) {
        let Some(default_type_library) = self
            .type_libraries
            .iter()
            .find(|tl| tl.name() == default_type_library)
        else {
            tracing::error!(
                "Default type library '{}' not found in processed data",
                default_type_library
            );
            return;
        };

        // Go through all named objects and search for that symbol in another type library, if
        // we find a match relocate the object. To relocate, we delete the object from the default
        // type library and conditionally swap the type (to whichever is not void), recording
        // visible referenced types to later relocate as well.
        let mut recorded_references: HashMap<QualifiedName, HashSet<Ref<TypeLibrary>>> =
            HashMap::new();
        for tl in &self.type_libraries {
            for named_object in &tl.named_objects() {
                if let Some(relocated_type) =
                    default_type_library.get_named_object(named_object.name.clone())
                {
                    // Move the type over to the target type library.
                    if named_object.ty.type_class() == TypeClass::VoidTypeClass {
                        // TODO: This visit actually needs to be a
                        visit_type_reference(&relocated_type, &mut |ntr| {
                            let ntr_name = ntr.name();
                            // Copy over the referenced types source library so the target type library
                            // can use it to resolve the reference at load time.
                            if let Some(type_source) =
                                default_type_library.get_named_type_source(ntr_name.clone())
                            {
                                tl.add_type_source(ntr_name.clone(), &type_source)
                            }
                            // Record all referenced types that reside in the same type library, so
                            // we can relocate them as well, assuming no other type library also uses it.
                            let is_associated = default_type_library
                                .get_named_type(ntr_name.clone())
                                .is_some();
                            if is_associated {
                                recorded_references
                                    .entry(ntr_name)
                                    .or_default()
                                    .insert(tl.clone());
                            }
                        });
                        tl.add_named_object(named_object.name.clone(), &relocated_type);
                    }

                    // TODO: Not technically necessary because the imports are keyed off dependency name.
                    // Remove from the default type library.
                    default_type_library.remove_named_object(named_object.name.clone());
                }
            }
        }

        // TODO: After we have gone through the named objects and moved their types over, we need to
        // TODO: enumerate all types in the default type library and determine if they should be relocated
        // TODO: to the new type library. Apart of this is also calling `add_type_source(ntr_name, default_type_lib)`
        // TODO: for every type that is not relocated, as we now need to tell the target type library
        // TODO: that the reference is external and exists in the default type library.

        // TODO: Ugh, this needs to be a work list, we have to continue to drill down to relocate.
        for (qualified_name, type_libraries) in recorded_references {
            if type_libraries.len() == 1 {
                // Only one type library uses this type, so we can safely relocate it.
                let type_library = type_libraries.iter().next().unwrap();
                let named_ty = default_type_library
                    .get_named_type(qualified_name.clone())
                    .unwrap();
                type_library.add_named_type(qualified_name, &named_ty);
            }
        }
    }

    /// Locates named types which exist in multiple distinct type libraries and merges them into
    /// a single type library (default type library).
    ///
    /// Example: `Qt5Core.dll.bndb` and `Qt5Charts.dll.bndb` both had pdb info, and both have `QObject`.
    /// Assuming `QObject` is mergeable, we will merge it into the default type library.
    pub fn deduplicate_types(&mut self, default_type_library_name: &str) {
        let mut default_libraries = HashMap::new();
        let mut get_default_type_library = |arch: CoreArchitecture| {
            default_libraries
                .entry(arch)
                .or_insert_with(move || TypeLibrary::new(arch, default_type_library_name))
                .to_owned()
        };

        let mut mapped_named_types: HashMap<
            (QualifiedName, CoreArchitecture),
            Vec<Ref<TypeLibrary>>,
        > = HashMap::new();
        for tl in &self.type_libraries {
            for named_type in &tl.named_types() {
                mapped_named_types
                    .entry((named_type.name.clone(), tl.arch()))
                    .or_default()
                    .push(tl.clone());
            }
        }

        for ((qualified_name, arch), type_libraries) in mapped_named_types {
            if type_libraries.len() == 1 {
                continue;
            }
            let default_type_library = get_default_type_library(arch);

            let unmerged_types: Vec<_> = type_libraries
                .iter()
                .filter_map(|tl| tl.get_named_type(qualified_name.clone()))
                .collect();
            if let Some(merged_type) = merge_types(&unmerged_types) {
                // Add the merged type to the default type library, then we need to point the type
                // libraries to use this newly merged type instead of their type.
                default_type_library.add_named_type(qualified_name.clone(), &merged_type);
                for type_library in type_libraries {
                    // If the default type library does not have the platform, it will not be pulled in.
                    for platform_name in &type_library.platform_names() {
                        if let Some(platform) = Platform::by_name(platform_name) {
                            default_type_library.add_platform(&platform);
                        }
                    }

                    type_library.remove_named_type(qualified_name.clone());
                    type_library.add_type_source(qualified_name.clone(), default_type_library_name);
                }
            } else {
                // TODO: Probably demote this to debug, since they might just be disparate types.
                tracing::warn!(
                    "Unable to merge type for duplicated name: {}",
                    qualified_name
                );
            }
        }

        // Make sure all the default type libraries are within the processed data, if not already.
        for (_, default_type_library) in default_libraries {
            self.type_libraries.insert(default_type_library);
        }
    }
}

pub struct TypeLibProcessor {
    state: Arc<ProcessingState>,
    /// The Binary Ninja settings to use when analyzing the binaries.
    analysis_settings: serde_json::Value,
    /// The default name to use for the type library dependency name (e.g. "sqlite.dll").
    ///
    /// When processing information that does not contain the dependency name, this will be used,
    /// such as processing header files. We need to set a dependency name, otherwise the library
    /// will not be able to be referenced by other libraries and/or the binary view.
    ///
    /// This dependency name will NOT be used when it can otherwise be inferred by the processing
    /// data, if you wish to override the resulting dependency name, you can do so by calling
    /// [`TypeLibrary::set_dependency_name`] on the libraries returned via [`ProcessedData::type_libraries`].
    default_dependency_name: String,
    /// The default platform name to use when processing (e.g. "windows-x86_64").
    ///
    /// When processing information that does not have an associated platform, this will be used,
    /// such as processing header files or processing winmd files. When processing binary files,
    /// the platform will be derived from the binary view default platform.
    ///
    /// For WINMD files you typically want to run the processor for each of the following platforms:
    ///
    /// - "windows-x86_64"
    /// - "windows-x86"
    /// - "windows-aarch64"
    default_platform_name: String,
    /// Set the include directories to use when processing header files. These will be passed to the
    /// Clang type parser, which will use them to resolve header file includes.
    include_directories: Vec<PathBuf>,
    /// Whether to process existing type libraries when processing a binary file.
    process_existing_type_libraries: bool,
}

impl TypeLibProcessor {
    pub fn new(default_dependency_name: &str, default_platform_name: &str) -> Self {
        Self {
            state: Arc::new(ProcessingState::default()),
            analysis_settings: serde_json::json!({
                "analysis.linearSweep.autorun": false,
                "analysis.mode": "full",
            }),
            default_dependency_name: default_dependency_name.to_owned(),
            default_platform_name: default_platform_name.to_owned(),
            include_directories: Vec::new(),
            process_existing_type_libraries: false,
        }
    }

    /// Retrieve a thread-safe shared reference to the [`ProcessingState`].
    pub fn state(&self) -> Arc<ProcessingState> {
        self.state.clone()
    }

    pub fn with_include_directories(mut self, include_directories: Vec<PathBuf>) -> Self {
        self.include_directories = include_directories;
        self
    }

    /// Whether to process existing type libraries when processing a binary file.
    ///
    /// If you open `mymodule.dll` and it imports functions from `kernel32.dll`, any import found
    /// within the associated `kernel32.dll.bntl` will not be processed if this is `true`.
    pub fn process_existing_type_libraries(
        mut self,
        process_existing_type_libraries: bool,
    ) -> Self {
        self.process_existing_type_libraries = process_existing_type_libraries;
        self
    }

    /// Place a call to this in places to interrupt when canceled.
    fn check_cancelled(&self) -> Result<(), ProcessingError> {
        match self.state.is_cancelled() {
            true => Err(ProcessingError::Cancelled),
            false => Ok(()),
        }
    }

    pub fn process(&self, path: &Path) -> Result<ProcessedData, ProcessingError> {
        match path.extension() {
            Some(ext) if ext == "bntl" => self.process_type_library(path),
            Some(ext) if ext == "h" || ext == "hpp" => self.process_source(path),
            // NOTE: A typical processor will not go down this path where we only provide a single
            // winmd file to be processed. You almost always want to process multiple winmd files,
            // which can be done by passing a directory with the relevant winmd files.
            Some(ext) if ext == "winmd" => self.process_winmd(&[path.to_owned()]),
            Some(ext) if ext == "tbd" => self.process_tbd(path),
            _ if path.is_dir() => self.process_directory(path),
            _ => self.process_file(path),
        }
    }

    pub fn process_directory(&self, path: &Path) -> Result<ProcessedData, ProcessingError> {
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

        // TODO: Parallel processing of files?
        let unmerged_data: Result<Vec<_>, _> = files
            .iter()
            .map(|file| {
                self.check_cancelled()?;
                self.process(file)
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

        Ok(ProcessedData::merge(&unmerged_data?))
    }

    pub fn process_project(&self, project: &Project) -> Result<ProcessedData, ProcessingError> {
        // Inform the state of the new unprocessed project files.
        for project_file in &project.files() {
            // NOTE: We use the on disk path here because the downstream file state uses that.
            if let Some(path) = project_file.path_on_disk() {
                self.state.set_file_state(path, false);
            }
        }

        let data: Result<Vec<_>, _> = project
            .files()
            .iter()
            .map(|file| {
                self.check_cancelled()?;
                self.process_project_file(&file)
            })
            .filter_map(|res| match res {
                Ok(result) => Some(Ok(result)),
                Err(ProcessingError::SkippedFile(path)) => {
                    tracing::debug!("Skipping project file: {:?}", path);
                    None
                }
                Err(ProcessingError::Cancelled) => Some(Err(ProcessingError::Cancelled)),
                Err(ProcessingError::NoPathToProjectFile(path)) => {
                    tracing::warn!("Project file not downloaded: {:?}", path);
                    None
                }
                Err(e) => {
                    tracing::error!("Project file processing error: {:?}", e);
                    None
                }
            })
            .collect();

        Ok(ProcessedData::merge(&data?))
    }

    pub fn process_project_folder(
        &self,
        project_folder: &ProjectFolder,
    ) -> Result<ProcessedData, ProcessingError> {
        for project_file in &project_folder.files() {
            // NOTE: We use the on disk path here because the downstream file state uses that.
            if let Some(path) = project_file.path_on_disk() {
                self.state.set_file_state(path, false);
            }
        }

        let unmerged_data: Result<Vec<_>, _> = project_folder
            .files()
            .iter()
            .map(|file| {
                self.check_cancelled()?;
                self.process_project_file(&file)
            })
            .filter_map(|res| match res {
                Ok(result) => Some(Ok(result)),
                Err(ProcessingError::SkippedFile(path)) => {
                    tracing::debug!("Skipping project file: {:?}", path);
                    None
                }
                Err(ProcessingError::Cancelled) => Some(Err(ProcessingError::Cancelled)),
                Err(ProcessingError::NoPathToProjectFile(path)) => {
                    tracing::warn!("Project file not downloaded: {:?}", path);
                    None
                }
                Err(e) => {
                    tracing::error!("Project file processing error: {:?}", e);
                    None
                }
            })
            .collect();

        Ok(ProcessedData::merge(&unmerged_data?))
    }

    pub fn process_project_file(
        &self,
        project_file: &ProjectFile,
    ) -> Result<ProcessedData, ProcessingError> {
        let file_name = project_file.name();
        let extension = file_name.split('.').next_back();
        let path = project_file
            .path_on_disk()
            .ok_or_else(|| ProcessingError::NoPathToProjectFile(project_file.to_owned()))?;
        match extension {
            Some("bntl") => self.process_type_library(&path),
            Some(ext) if ext == "h" || ext == "hpp" => self.process_source(&path),
            // NOTE: A typical processor will not go down this path where we only provide a single
            // winmd file to be processed. You almost always want to process multiple winmd files,
            // which can be done by passing a directory with the relevant winmd files.
            Some("winmd") => self.process_winmd(&[path]),
            Some("tbd") => self.process_tbd(&path),
            _ => {
                // If the file cannot be parsed, it should be skipped to avoid a load error.
                if !is_parsable(&path) {
                    return Err(ProcessingError::SkippedFile(path.to_owned()));
                }

                let settings_str = self.analysis_settings.to_string();
                let file = binaryninja::load_project_file_with_progress(
                    project_file,
                    false,
                    Some(settings_str),
                    |_pos, _total| {
                        // TODO: Report progress
                        true
                    },
                )
                .ok_or_else(|| ProcessingError::BinaryViewLoad(path.to_owned()))?;
                let data = self.process_view(path.to_owned(), &file);
                file.file().close();
                data
            }
        }
    }

    // TODO: Process mapping file
    // TODO: A json file that maps type names to their type dlls
    // TODO: Apples format (tbd to move symbols from default type lib to their actual place)

    /// NOTE: Never pass a project file into this function, use [`TypeLibProcessor::process_project_file`]
    /// instead as the file metadata will not attach to the project file to the view otherwise, leading
    /// to incorrect dependency names.
    pub fn process_file(&self, path: &Path) -> Result<ProcessedData, ProcessingError> {
        // If the file cannot be parsed, it should be skipped to avoid a load error.
        if !is_parsable(path) {
            return Err(ProcessingError::SkippedFile(path.to_owned()));
        }

        let settings_str = self.analysis_settings.to_string();
        let file = binaryninja::load_with_options_and_progress(
            path,
            false,
            Some(settings_str),
            |_pos, _total| {
                // TODO: Report progress
                true
            },
        )
        .ok_or_else(|| ProcessingError::BinaryViewLoad(path.to_owned()))?;
        let data = self.process_view(path.to_owned(), &file);
        file.file().close();
        data
    }

    pub fn process_view(
        &self,
        path: PathBuf,
        view: &BinaryView,
    ) -> Result<ProcessedData, ProcessingError> {
        self.state.set_file_state(path.to_owned(), false);
        let view_platform = view.default_platform().unwrap_or(self.default_platform()?);

        // Try and get the original file name, if not fall back to the default dependency name.
        // TODO: I give up trying to actually make this reasonable, in the future we need to revisit
        // TODO: how we save this information in the core so that its not a dozen lines of code to get
        let dependency_name = match view.file().project_file() {
            Some(project) => {
                // We have to strip the .bndb extension because the project file path on disk is a guid
                // so we just grab the project files "display name", because view.file().display_name()
                // does not actually do what we want. We for some reason in the core rewrite the file
                // name and display the name to be that of the bndb path instead of the file name associated
                // with the actual view (which is actually useful information).
                project
                    .path_in_project()
                    .file_name()
                    .unwrap_or(OsStr::new(&self.default_dependency_name))
                    .to_string_lossy()
                    .strip_suffix(".bndb")
                    .unwrap_or(&self.default_dependency_name)
                    .to_string()
            }
            None => view
                .file()
                .original_file_path()
                .unwrap_or(path.clone())
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_else(|| self.default_dependency_name.clone()),
        };

        let type_library = TypeLibrary::new(view_platform.arch(), &dependency_name);
        type_library.add_platform(&view_platform);

        // TODO: This has to be extremely slow
        let platform_types = view_platform
            .types()
            .iter()
            .map(|t| t.name.clone())
            .collect::<HashSet<_>>();
        let mut type_name_to_library = HashMap::new();
        for tl in view.type_libraries().iter() {
            let lib_name = tl.name().to_string();
            for t in tl.named_types().iter() {
                type_name_to_library.insert(t.name.clone(), lib_name.clone());
            }
        }

        let add_referenced_types = |type_library: &TypeLibrary, ty: &Type| {
            let mut referenced_ntrs: Vec<Ref<NamedTypeReference>> = Vec::new();
            visit_type_reference(ty, &mut |ntr| {
                referenced_ntrs.push(ntr.to_owned());
            });

            // Pull in all referenced types recursively.
            while let Some(ntr) = referenced_ntrs.pop() {
                let referenced_name = ntr.name();
                if type_library
                    .get_named_type(referenced_name.clone())
                    .is_some()
                {
                    continue;
                }
                if platform_types.contains(&referenced_name) {
                    // The type referenced comes from the platform, so we do not need to do anything.
                } else if let Some(source) = type_name_to_library.get(&referenced_name) {
                    type_library.add_type_source(referenced_name, source);
                } else {
                    // Type does not belong to another type library, so we add it to the current one.
                    if let Some(referenced_ty) = view.type_by_ref(&ntr) {
                        visit_type_reference(&referenced_ty, &mut |ntr| {
                            referenced_ntrs.push(ntr.to_owned());
                        });
                        type_library.add_named_type(referenced_name, &referenced_ty);
                    } else {
                        tracing::debug!(
                            "Type '{}' referenced by '{}' not found in view, skipping...",
                            referenced_name,
                            ty
                        );
                    }
                }
            }
        };

        let mut ordinals: HashMap<String, String> = HashMap::new();
        let functions = view.functions();
        tracing::info!("Adding {} functions", functions.len());
        for func in &functions {
            if !func.is_exported() {
                continue;
            }
            let Some(defined_symbol) = func.defined_symbol() else {
                tracing::debug!(
                    "Function '{}' has no defined symbol, skipping...",
                    func.symbol()
                );
                continue;
            };
            // Common case where we attach a "j_" prefix to the exported name, which ruins the symbol
            // since it's expected to be imported by name. https://github.com/Vector35/binaryninja-api/issues/7970
            let name = defined_symbol
                .raw_name()
                .to_string_lossy()
                .replace("j_", "");
            let qualified_name = QualifiedName::from(name.clone());
            type_library.add_named_object(qualified_name, &func.function_type());
            add_referenced_types(&type_library, &func.function_type());

            if let Some(ordinal) = defined_symbol.ordinal() {
                ordinals.insert(ordinal.to_string(), name);
            }
        }

        if !ordinals.is_empty() {
            tracing::info!(
                "Found {} ordinals in '{}', adding metadata...",
                ordinals.len(),
                view.file(),
            );
            // TODO: The ordinal version is OSMAJOR_OSMINOR, pull from pe metadata (use object crate)
            let key_md: Ref<Metadata> = String::from("ordinals_10_0").into();
            type_library.store_metadata("ordinals", &key_md);
            let map_md: Ref<Metadata> = ordinals.into();
            type_library.store_metadata("ordinals_10_0", &map_md);
        }

        let mut processed_data = self.process_external_libraries(view)?;
        processed_data.type_libraries.insert(type_library);
        if let Some(api_set_section) = view.section_by_name(".apiset") {
            let processed_api_set = self.process_api_set(view, &api_set_section)?;
            tracing::info!(
                "Found {} api set libraries in '{}', adding alternative names...",
                processed_api_set.type_libraries.len(),
                view.file(),
            );
            processed_data = ProcessedData::merge(&[processed_data, processed_api_set]);
        }
        self.state.set_file_state(path.to_owned(), true);
        Ok(processed_data)
    }

    pub fn process_external_libraries(
        &self,
        view: &BinaryView,
    ) -> Result<ProcessedData, ProcessingError> {
        let view_platform = view.default_platform().unwrap_or(self.default_platform()?);
        let mut extern_type_libraries = HashMap::new();
        for extern_lib in &view.external_libraries() {
            let extern_type_library = TypeLibrary::new(view_platform.arch(), &extern_lib.name());
            extern_type_library.add_platform(&view_platform);
            extern_type_library.set_dependency_name(&extern_lib.name());
            extern_type_libraries.insert(extern_lib.name(), extern_type_library);
        }

        // Pull import types and add them to respective type libraries.
        for extern_loc in &view.external_locations() {
            // The source symbol represents the symbol represented in the binary, while the target
            // symbol represents the symbol that we intend to map the information to.
            let src_sym = extern_loc.source_symbol();
            let Some(extern_lib) = extern_loc.library() else {
                tracing::debug!(
                    "External location '{}' has no library, skipping...",
                    src_sym
                );
                continue;
            };
            let Some(extern_type_library) = extern_type_libraries.get_mut(&extern_lib.name())
            else {
                tracing::warn!(
                    "External location '{}' is referencing a detached external library, skipping...",
                    src_sym
                );
                continue;
            };
            let Some(src_data_var) = view.data_variable_at_address(src_sym.address()) else {
                tracing::debug!(
                    "External location '{}' has no data variable, skipping...",
                    src_sym
                );
                continue;
            };
            if src_data_var.auto_discovered {
                // We do not want to record objects which are not modified by the user, otherwise
                // we are recording the object each time we visit a binary view, possibly retrieving
                // the old definition of the object.
                tracing::debug!(
                    "External location '{}' is auto discovered, skipping...",
                    src_sym
                );
                continue;
            }
            let target_sym_name = extern_loc
                .target_symbol()
                .unwrap_or_else(|| src_sym.raw_name());

            if !self.process_existing_type_libraries
                && view
                    .import_type_library_object(target_sym_name.clone(), None)
                    .is_some()
            {
                tracing::debug!(
                    "Skipping external location '{}' as it is already present in a type library",
                    target_sym_name.to_string_lossy()
                );
                continue;
            }

            // TODO: Need to visit all types referenced and add it to the type library.
            extern_type_library.add_named_object(target_sym_name.into(), &src_data_var.ty.contents);
        }

        Ok(ProcessedData::new(
            extern_type_libraries.values().cloned().collect(),
        ))
    }

    /// Process API sets on Windows binaries, so we can fill in the alternative names for type libraries
    /// we are processing.
    ///
    /// Creates an empty type library for the host and adds the alternative names to it. This should then
    /// be passed to the [`ProcessedData::merge`] set to be merged with the type library of the host name.
    ///
    /// For more information see: https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets
    pub fn process_api_set(
        &self,
        view: &BinaryView,
        section: &Section,
    ) -> Result<ProcessedData, ProcessingError> {
        let section_bytes = view
            .read_buffer(section.start(), section.len())
            .ok_or_else(|| ProcessingError::BinaryViewRead(section.start(), section.len()))?;
        let api_set_map = ApiSetMap::try_from_apiset_section_bytes(section_bytes.get_data())?;

        let mut target_map: HashMap<String, HashSet<String>> = HashMap::new();
        for entry in api_set_map.namespace_entries()? {
            let alternative_name = entry.name()?.to_string_lossy();
            for value_entry in entry.value_entries()? {
                // TODO: In cases where alt -> kernel32.dll -> kernelbase.dll we currently associate
                // TODO: with kernel32.dll as its assumed there is a wrapper function that calls into
                // TODO: kernelbase.dll. This keeps us from having to validate against both, in the case
                // TODO: of kernelbase.dll being before the function was moved there.
                let _forwarder_name = value_entry.name()?.to_string_lossy();
                let target_name = value_entry.value()?.to_string_lossy();
                target_map
                    .entry(target_name)
                    .or_default()
                    .insert(alternative_name.clone());
            }
        }

        // Instead of using the view, we use the user-provided platform, the reason is because the
        // 'apisetschema.dll' is shared across multiple archs, and we need to be able to merge its data
        // with other platforms so that they get the correct alternative names.
        let platform = self.default_platform()?;
        let mut mapping_type_libraries = Vec::new();
        for (target_name, alternative_names) in target_map {
            let type_library = TypeLibrary::new(platform.arch(), &target_name);
            for alt_name in alternative_names {
                type_library.add_alternate_name(&alt_name);
            }
            mapping_type_libraries.push(type_library);
        }

        Ok(ProcessedData::new(mapping_type_libraries))
    }

    /// We want to be able to process already created type libraries so that they can be consulted
    /// during the [`ProcessedData::merge`] step. This lets us add overrides like extra platforms.
    pub fn process_type_library(&self, path: &Path) -> Result<ProcessedData, ProcessingError> {
        self.state.set_file_state(path.to_owned(), false);
        let finalized_type_library = TypeLibrary::load_from_file(path)
            .ok_or_else(|| ProcessingError::InvalidTypeLibrary(path.to_owned()))?;
        self.state.set_file_state(path.to_owned(), true);
        Ok(ProcessedData::new(vec![finalized_type_library]))
    }

    pub fn process_source(&self, path: &Path) -> Result<ProcessedData, ProcessingError> {
        self.state.set_file_state(path.to_owned(), false);
        let platform = self.default_platform()?;
        let parser =
            CoreTypeParser::parser_by_name("ClangTypeParser").expect("Failed to get clang parser");
        let platform_type_container = platform.type_container();

        let header_contents = std::fs::read_to_string(path).map_err(ProcessingError::FileRead)?;

        let file_name = path
            .file_name()
            .unwrap_or(OsStr::new("source.hpp"))
            .to_string_lossy();
        // TODO: Allow specifying options?
        let mut include_dirs = self.include_directories.clone();
        // TODO: This will not work for projects, we need to remove this parent call
        // TODO: and place it in the `include_directories`, where we parse that from the user input
        // TODO: To the
        if let Some(p) = path.parent() {
            include_dirs.push(p.to_owned());
        }
        let parsed_types = parser
            .parse_types_from_source(
                &header_contents,
                &file_name,
                &platform,
                &platform_type_container,
                &[],
                &include_dirs,
                "",
            )
            .map_err(ProcessingError::TypeParsingFailed)?;

        let type_library = TypeLibrary::new(platform.arch(), &self.default_dependency_name);
        type_library.add_platform(&platform);
        for ty in parsed_types.types {
            type_library.add_named_type(ty.name, &ty.ty);
        }
        for func in parsed_types.functions {
            type_library.add_named_object(func.name, &func.ty);
        }
        self.state.set_file_state(path.to_owned(), true);
        Ok(ProcessedData::new(vec![type_library]))
    }

    /// Processes Apples TBD file format, which is a YAML file that contains information about a dylib,
    /// most important for us is the list of exported symbols, which we can use to relocate objects
    /// in the default type library (specified by `default_dependency_name`) to the correct type library.
    pub fn process_tbd(&self, path: &Path) -> Result<ProcessedData, ProcessingError> {
        let mut file = File::open(path).map_err(ProcessingError::FileRead)?;
        let mut type_libraries = Vec::new();
        for tbd_info in parse_tbd_info(&mut file).unwrap() {
            let install_path = PathBuf::from(tbd_info.install_name);
            let library_name = install_path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string();

            let mut mapped_type_libraries: HashMap<TbdArchitecture, Vec<Ref<TypeLibrary>>> =
                HashMap::new();
            for target in tbd_info.targets {
                let Some(target_platform) = target.binary_ninja_platform() else {
                    tracing::error!(
                        "Failed to find platform '{:?}' when parsing file: {}",
                        target,
                        path.display()
                    );
                    continue;
                };
                let type_library = TypeLibrary::new(target_platform.arch(), &library_name);
                type_library.add_platform(&target_platform);
                mapped_type_libraries
                    .entry(target.arch)
                    .or_default()
                    .push(type_library);
            }

            for exports in tbd_info.exports {
                for export_target in exports.targets {
                    let type_libraries = mapped_type_libraries.get(&export_target.arch).unwrap();
                    for type_library in type_libraries {
                        // TODO: Handle `objc_classes`?
                        for symbol in &exports.symbols {
                            // TODO: We need more than just a void type to differentiate, because we have
                            // TODO: NTRs that might be pointing to void types, i dont really want to
                            // TODO: detach the backing type there.
                            // Create a void type for the symbol, we prune these at the end, so if
                            // nothing remaps to this library with the given symbol, it will go away.
                            type_library.add_named_object(symbol.into(), &Type::void());
                        }
                    }
                }
            }

            for (_, libs) in mapped_type_libraries {
                type_libraries.extend(libs);
            }
        }

        Ok(ProcessedData::new(type_libraries))
    }

    /// Unlike [`TypeLibProcessor::process_source`] which can pass include directories, this processing
    /// requires us to actually load multiple files to parse the correct information.
    ///
    /// A specific example of this is the "Windows.Wdk.winmd" references types in "Windows.Win32.winmd".
    /// If we did not process them together, we would have unresolved references when loading kernel
    /// type libraries.
    pub fn process_winmd(&self, paths: &[PathBuf]) -> Result<ProcessedData, ProcessingError> {
        for path in paths {
            self.state.set_file_state(path.to_owned(), false);
        }
        let platform = self.default_platform()?;
        let type_libraries = WindowsMetadataImporter::new()
            .with_files(paths)
            .map_err(ProcessingError::WinMdFailedImport)?
            .import(&platform)
            .map_err(ProcessingError::WinMdFailedImport)?;
        for path in paths {
            self.state.set_file_state(path.to_owned(), true);
        }
        Ok(ProcessedData::new(type_libraries))
    }

    pub fn default_platform(&self) -> Result<Ref<Platform>, ProcessingError> {
        Platform::by_name(&self.default_platform_name)
            .ok_or_else(|| ProcessingError::PlatformNotFound(self.default_platform_name.clone()))
    }
}

pub fn is_parsable(path: &Path) -> bool {
    if binaryninja::is_database(path) {
        return true;
    }
    // For some reason these pass to a view type?
    if path.extension() == Some(OsStr::new("pdb")) {
        return false;
    }
    let metadata = FileMetadata::with_file_path(path);
    let Ok(view) = BinaryView::from_metadata(&metadata) else {
        return false;
    };
    // If any view type parses this file, consider it for this source.
    // All files will have a "Raw" file type, so we account for that.
    BinaryViewType::valid_types_for_data(&view).len() > 1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_parsable() {
        let _session =
            binaryninja::headless::Session::new().expect("Failed to create headless session");
        let data_dir = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("Cargo workspace directory")
            .join("data");
        let x86_file_path = data_dir.join("x86").join("mfc42.dll.bndb");
        assert!(x86_file_path.exists());
        assert!(is_parsable(&x86_file_path));
        let header_file_path = data_dir.join("headers").join("test.h");
        assert!(header_file_path.exists());
        assert!(!is_parsable(&header_file_path));
    }

    #[test]
    fn test_process_winmd() {
        let _session =
            binaryninja::headless::Session::new().expect("Failed to create headless session");
        let data_dir = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("Cargo workspace directory")
            .join("data");
        let win32_winmd_path = data_dir.join("winmd").join("Windows.Win32.winmd");
        assert!(win32_winmd_path.exists());
        let wdk_winmd_path = data_dir.join("winmd").join("Windows.Wdk.winmd");
        assert!(wdk_winmd_path.exists());

        let processor = TypeLibProcessor::new("foo", "windows-x86_64");
        let processed_data = processor
            .process_winmd(&[win32_winmd_path, wdk_winmd_path])
            .expect("Failed to process winmd");
        assert_eq!(processed_data.type_libraries.len(), 591);

        // Make sure processing a directory will correctly group winmd files.
        let processed_folder_data = processor
            .process_directory(&data_dir.join("winmd"))
            .expect("Failed to process directory");
        assert_eq!(processed_folder_data.type_libraries.len(), 591);
    }

    #[test]
    fn test_process_source() {
        let _session =
            binaryninja::headless::Session::new().expect("Failed to create headless session");
        let data_dir = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("Cargo workspace directory")
            .join("data");
        let header_file_path = data_dir.join("headers").join("test.h");
        assert!(header_file_path.exists());

        let processor = TypeLibProcessor::new("test.dll", "windows-x86_64");
        let processed_data = processor
            .process_source(&header_file_path)
            .expect("Failed to process source");
        assert_eq!(processed_data.type_libraries.len(), 1);
        let processed_library = &processed_data.type_libraries.iter().next().unwrap();
        assert_eq!(processed_library.name(), "test.dll");
        assert_eq!(processed_library.dependency_name(), "test.dll");
        assert_eq!(
            processed_library.platform_names().to_vec(),
            vec!["windows-x86_64"]
        );

        processed_library
            .get_named_type("MyStruct".into())
            .expect("Failed to get type");

        // Make sure includes are pulled into the type library.
        let header2_file_path = data_dir.join("headers").join("test2.hpp");
        let processed_data_2 = processor
            .process_source(&header2_file_path)
            .expect("Failed to process source");
        assert_eq!(processed_data_2.type_libraries.len(), 1);
        let processed_library_2 = &processed_data_2.type_libraries.iter().next().unwrap();
        assert_eq!(processed_library_2.name(), "test.dll");
        assert_eq!(processed_library_2.dependency_name(), "test.dll");
        assert_eq!(
            processed_library_2.platform_names().to_vec(),
            vec!["windows-x86_64"]
        );
        processed_library_2
            .get_named_type("MyStruct2".into())
            .expect("Failed to get type");
        processed_library_2
            .get_named_type("MyStruct".into())
            .expect("Failed to get included type");
    }

    #[test]
    fn test_process_file() {
        let _session =
            binaryninja::headless::Session::new().expect("Failed to create headless session");
        let data_dir = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("Cargo workspace directory")
            .join("data");
        let x86_file_path = data_dir.join("x86_64").join("mfc42.dll.bndb");
        assert!(x86_file_path.exists());
        let processor = TypeLibProcessor::new("mfc42.dll", "windows-x86_64");
        let processed_data = processor
            .process_file(&x86_file_path)
            .expect("Failed to process file");
        assert_eq!(processed_data.type_libraries.len(), 27);
        let processed_library = processed_data
            .type_libraries
            .iter()
            .find(|lib| lib.name() == "mfc42.dll")
            .expect("Failed to find mfc42.dll library");
        assert_eq!(processed_library.name(), "mfc42.dll");
        assert_eq!(processed_library.dependency_name(), "mfc42.dll");
        assert_eq!(
            processed_library.platform_names().to_vec(),
            vec!["windows-x86_64"]
        );
    }

    #[test]
    fn test_process_api_set() {
        let _session =
            binaryninja::headless::Session::new().expect("Failed to create headless session");
        let data_dir = Path::new(&env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("Cargo workspace directory")
            .join("data");
        let apiset_file_path = data_dir.join("apiset").join("apisetschema.dll");
        assert!(apiset_file_path.exists());
        let processor = TypeLibProcessor::new("foo", "windows-x86_64");
        let processed_data = processor
            .process_file(&apiset_file_path)
            .expect("Failed to process file");

        assert_eq!(processed_data.type_libraries.len(), 287);
        let combase_library = processed_data
            .type_libraries
            .iter()
            .find(|tl| tl.name() == "combase.dll")
            .expect("Failed to find combase.dll type library");
        assert_eq!(
            combase_library.alternate_names().to_vec(),
            vec![
                "api-ms-win-core-com-l1-1-3",
                "api-ms-win-core-com-midlproxystub-l1-1-0",
                "api-ms-win-core-com-private-l1-1-1",
                "api-ms-win-core-com-private-l1-2-0",
                "api-ms-win-core-com-private-l1-3-1",
                "api-ms-win-core-marshal-l1-1-0",
                "api-ms-win-core-winrt-error-l1-1-1",
                "api-ms-win-core-winrt-errorprivate-l1-1-1",
                "api-ms-win-core-winrt-l1-1-0",
                "api-ms-win-core-winrt-registration-l1-1-0",
                "api-ms-win-core-winrt-roparameterizediid-l1-1-0",
                "api-ms-win-core-winrt-string-l1-1-1",
                "api-ms-win-downlevel-ole32-l1-1-0"
            ]
        );
    }

    #[test]
    fn test_data_merging() {
        let _session =
            binaryninja::headless::Session::new().expect("Failed to create headless session");
        let x86_platform = Platform::by_name("x86").expect("Failed to get x86 platform");
        let x86_windows_platform =
            Platform::by_name("windows-x86").expect("Failed to get windows x86 platform");
        // Make two type libraries with the same name, but different dependencies.
        let tl1 = TypeLibrary::new(x86_platform.arch(), "foo");
        tl1.set_dependency_name("foo");
        tl1.add_platform(&x86_platform);
        tl1.add_named_type("bar".into(), &Type::named_float(3, "bla"));
        let tl1_data = ProcessedData::new(vec![tl1]);

        let tl2 = TypeLibrary::new(x86_platform.arch(), "bar");
        tl2.set_dependency_name("foo");
        tl2.add_platform(&x86_windows_platform);
        tl2.add_named_type("baz".into(), &Type::named_int(64, false, "fre"));
        let tl2_data = ProcessedData::new(vec![tl2]);

        let merged_data = ProcessedData::merge(&[tl1_data, tl2_data]);
        assert_eq!(merged_data.type_libraries.len(), 1);
        let merged_tl = &merged_data.type_libraries.iter().next().unwrap();
        assert_eq!(merged_tl.name(), "foo");
        assert_eq!(merged_tl.dependency_name(), "foo");
        assert_eq!(merged_tl.platform_names().len(), 2);
        assert_eq!(merged_tl.named_types().len(), 2);
    }
}
