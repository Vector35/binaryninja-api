use binaryninja::collaboration::RemoteFile;
use binaryninja::project::Project;
use binaryninja::project::file::ProjectFile;
use binaryninja::project::folder::ProjectFolder;
use binaryninja::rc::Ref;
use bntl_utils::url::{BnParsedUrl, BnResource};
use std::fmt::Display;
use std::path::PathBuf;
use std::str::FromStr;
use thiserror::Error;

#[derive(Debug)]
pub enum ResolvedInput {
    Path(PathBuf),
    Project(Ref<Project>),
    ProjectFolder(Ref<ProjectFolder>),
    ProjectFile(Ref<ProjectFile>),
}

#[derive(Error, Debug)]
pub enum InputResolveError {
    #[error("Resource resolution failed: {0}")]
    ResourceError(#[from] bntl_utils::url::BnResourceError),

    #[error("Collaboration API error: {0}")]
    CollaborationError(String),

    #[error("Download failed for {url}: status {status}")]
    DownloadFailed { url: String, status: u16 },

    #[error("Download provider error: {0}")]
    DownloadProviderError(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Environment error: {0}")]
    EnvError(String),
}

/// An input to the CLI to locate a "resource", such as a file or directory.
#[derive(Debug, Clone)]
pub enum Input {
    /// A URL which references a Binary Ninja resource, such as a remote project or file.
    ParsedUrl(BnParsedUrl),
    /// A local filesystem path pointing to a file or directory.
    LocalPath(PathBuf),
}

impl Input {
    /// Attempt to acquire a path from this input, this can download files over the network and
    /// is meant to be called when the file contents are desired.
    pub fn resolve(&self) -> Result<ResolvedInput, InputResolveError> {
        let try_download_file = |file: &RemoteFile| -> Result<(), InputResolveError> {
            if !file.core_file().unwrap().exists_on_disk() {
                let _span =
                    tracing::info_span!("Downloading project file", file = %file.name()).entered();
                file.download().map_err(|_| {
                    InputResolveError::CollaborationError("Failed to download project file".into())
                })?;
            }
            Ok(())
        };

        match self {
            Input::ParsedUrl(url) => match url.to_resource()? {
                BnResource::RemoteProject(project) => {
                    let files = project.files().map_err(|_| {
                        InputResolveError::CollaborationError("Failed to get files".into())
                    })?;

                    for file in &files {
                        try_download_file(&file)?;
                    }

                    let core = project.core_project().map_err(|_| {
                        InputResolveError::CollaborationError("Missing core project".into())
                    })?;
                    Ok(ResolvedInput::Project(core))
                }

                BnResource::RemoteProjectFile(file) => {
                    try_download_file(&file)?;
                    let core = file.core_file().expect("Missing core file");
                    Ok(ResolvedInput::ProjectFile(core))
                }

                BnResource::RemoteProjectFolder(folder) => {
                    let project = folder.project().map_err(|_| {
                        InputResolveError::CollaborationError("Failed to get project".into())
                    })?;
                    let files = project.files().map_err(|_| {
                        InputResolveError::CollaborationError("Failed to get files".into())
                    })?;

                    for file in &files {
                        if let Some(file_folder) = file.folder().ok().flatten() {
                            if file_folder == folder {
                                try_download_file(&file)?;
                            }
                        }
                    }

                    let core = folder.core_folder().map_err(|_| {
                        InputResolveError::CollaborationError("Missing core folder".into())
                    })?;
                    Ok(ResolvedInput::ProjectFolder(core))
                }

                BnResource::RemoteFile(url) => {
                    let safe_name = url.to_string().replace(['/', ':', '?'], "_");
                    let cached_file_path = std::env::temp_dir().join(safe_name);
                    if cached_file_path.exists() {
                        return Ok(ResolvedInput::Path(cached_file_path));
                    }

                    let download_provider = binaryninja::download::DownloadProvider::try_default()
                        .expect("Failed to get default download provider");
                    let mut instance = download_provider
                        .create_instance()
                        .expect("Failed to create download provider instance");
                    let _span =
                        tracing::info_span!("Downloading remote file", url = %url).entered();
                    let response = instance
                        .get(&url.to_string(), Vec::new())
                        .map_err(|e| InputResolveError::DownloadProviderError(e.to_string()))?;
                    if response.is_success() {
                        std::fs::write(&cached_file_path, response.data)?;
                        Ok(ResolvedInput::Path(cached_file_path))
                    } else {
                        Err(InputResolveError::DownloadFailed {
                            url: url.to_string(),
                            status: response.status_code,
                        })
                    }
                }

                BnResource::LocalFile(path) => Ok(ResolvedInput::Path(path.clone())),
            },
            Input::LocalPath(path) => Ok(ResolvedInput::Path(path.clone())),
        }
    }
}

impl FromStr for Input {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Try to parse as a Binary Ninja URL
        if s.starts_with("binaryninja:") {
            let url = BnParsedUrl::parse(s).map_err(|e| format!("URL Parse Error: {}", e))?;
            return Ok(Input::ParsedUrl(url));
        }

        let path = PathBuf::from(s);
        Ok(Input::LocalPath(path))
    }
}

impl Display for Input {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Input::ParsedUrl(url) => write!(f, "{}", url),
            Input::LocalPath(path) => write!(f, "{}", path.display()),
        }
    }
}
