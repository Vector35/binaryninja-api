use crate::dump::TILDump;
use crate::helper::path_to_type_libraries;
use binaryninja::rc::Ref;
use binaryninja::types::TypeLibrary;
use similar::{Algorithm, TextDiff};
use std::path::{Path, PathBuf};
use std::time::Duration;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TILDiffError {
    #[error("Could not determine parent directory for path: {0}")]
    InvalidPath(PathBuf),

    #[error("Failed to dump type library: {0}")]
    DumpError(String),
}

pub struct DiffResult {
    pub ratio: f32,
    pub diff: String,
}

pub struct TILDiff {
    timeout: Duration,
}

impl TILDiff {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(180),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn diff(
        &self,
        (a_path, a_type_lib): (&Path, &TypeLibrary),
        (b_path, b_type_lib): (&Path, &TypeLibrary),
    ) -> Result<DiffResult, TILDiffError> {
        let a_parent = a_path
            .parent()
            .ok_or_else(|| TILDiffError::InvalidPath(a_path.to_path_buf()))?;
        let b_parent = b_path
            .parent()
            .ok_or_else(|| TILDiffError::InvalidPath(b_path.to_path_buf()))?;

        self.diff_with_dependencies(
            (&a_type_lib, path_to_type_libraries(a_parent)),
            (&b_type_lib, path_to_type_libraries(b_parent)),
        )
    }

    pub fn diff_with_dependencies(
        &self,
        (a_type_lib, a_dependencies): (&TypeLibrary, Vec<Ref<TypeLibrary>>),
        (b_type_lib, b_dependencies): (&TypeLibrary, Vec<Ref<TypeLibrary>>),
    ) -> Result<DiffResult, TILDiffError> {
        let dumped_a = TILDump::new()
            .with_type_libs(a_dependencies)
            .dump(a_type_lib)
            .map_err(|e| TILDiffError::DumpError(e.to_string()))?;

        let dumped_b = TILDump::new()
            .with_type_libs(b_dependencies)
            .dump(b_type_lib)
            .map_err(|e| TILDiffError::DumpError(e.to_string()))?;

        let diff = TextDiff::configure()
            .algorithm(Algorithm::Patience)
            .timeout(self.timeout)
            .diff_lines(&dumped_a, &dumped_b);

        let diff_content = diff
            .unified_diff()
            .context_radius(3)
            .header(
                &format!("A/{}", a_type_lib.name()),
                &format!("B/{}", b_type_lib.name()),
            )
            .to_string();

        Ok(DiffResult {
            ratio: diff.ratio(),
            diff: diff_content,
        })
    }
}
