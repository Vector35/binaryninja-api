use crate::container::disk::NAMESPACE_DISK_SOURCE;
use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use thiserror::Error;
use uuid::Uuid;
use warp::r#type::guid::TypeGUID;
use warp::r#type::{ComputedType, Type};
use warp::signature::function::{Function, FunctionGUID};
use warp::symbol::Symbol;
use warp::target::Target;

pub mod disk;
pub mod memory;
pub mod network;

pub type ContainerResult<T> = Result<T, ContainerError>;

#[derive(Debug, Error, PartialEq, Eq, Hash)]
pub enum ContainerError {
    #[error("source {0} was not found")]
    SourceNotFound(SourceId),
    #[error("source {0} is not writable")]
    SourceNotWritable(SourceId),
    #[error("source with path {0} already exists")]
    SourceAlreadyExists(SourcePath),
    #[error("source with path {0} cannot be created in container")]
    CannotCreateSource(SourcePath),
    #[error("operation failed due to corrupted data: {0}")]
    CorruptedData(&'static str),
    #[error("failed io operation: {0}")]
    FailedIO(io::ErrorKind),
    #[error("source {0} does not have an available path")]
    SourcePathUnavailable(SourceId),
}

/// Represents the ID for a single container source.
///
/// A [`SourceId`] can be used in multiple separate containers, but **must** be unique in a container.
///
/// A source is used to relate types and functions separate from the container. This allows
/// type name lookups and for containers which are bandwidth sensitive to exist.
///
/// An example of a bandwidth-sensitive container would be a container that pulls functions over
/// the network instead of from memory.
///
/// This type is marked `repr(transparent)` to the underlying `[u8; 16]` type, so it is safe to use in FFI.
#[repr(transparent)]
#[derive(Clone, Debug, Eq, PartialEq, Hash, Copy)]
pub struct SourceId(Uuid);

impl SourceId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl From<Uuid> for SourceId {
    fn from(value: Uuid) -> Self {
        Self(value)
    }
}

impl FromStr for SourceId {
    type Err = uuid::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(s).map(Into::into)
    }
}

impl Display for SourceId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Represents a unique path to a source.
///
/// This is used when first creating a source for a container, the path is given to the container
/// as otherwise the user has no control over source creation and where the source is ultimately located.
///
/// While the underlying type is a [`PathBuf`], a source path can be really anything, the [`PathBuf`]
/// just provides an easier way to join segments for nested source locations.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SourcePath(PathBuf);

impl SourcePath {
    pub fn new(path: PathBuf) -> Self {
        Self(path)
    }

    pub fn new_with_str(value: &str) -> Self {
        Self(PathBuf::from(value))
    }

    pub fn to_source_id(&self) -> SourceId {
        // TODO: This path is not relative to the disk container is it?
        // TODO: The path here should be relative to the container I think?
        // TODO: The above is important so that the id is the same across users.
        let value: Vec<u8> = self.to_string().into_bytes();
        SourceId(Uuid::new_v5(&NAMESPACE_DISK_SOURCE, &value))
    }
}

impl AsRef<PathBuf> for SourcePath {
    fn as_ref(&self) -> &PathBuf {
        &self.0
    }
}

impl AsRef<Path> for SourcePath {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Display for SourcePath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.display())
    }
}

/// A tag associated with a source in a container.
///
/// Tags can be used to categorize and filter sources when querying the container.
pub type SourceTag = compact_str::CompactString;

/// A search query for finding items in a container.
///
/// This struct represents a search request that can be used to find functions, types and any other
/// items associated with the container.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContainerSearchQuery {
    /// The search query string to match against items.
    pub query: String,
    /// Optional offset into the results for pagination.
    pub offset: Option<usize>,
    /// Optional maximum number of results to return.
    pub limit: Option<usize>,
    /// Optional source ID to restrict the search to.
    pub source: Option<SourceId>,
    /// Optional list of tags to restrict the search to.
    pub tags: Vec<SourceTag>,
    // TODO: Add field for function guid? conceivable someone wants to filter through those.
}

impl ContainerSearchQuery {
    pub fn new(query: String) -> Self {
        Self {
            query,
            offset: None,
            limit: None,
            source: None,
            tags: Vec::new(),
        }
    }
}

/// An item returned from a container search.
///
/// Contains the source ID where the item was found and the specific kind of item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerSearchItem {
    /// The source ID where this item was found
    pub source: SourceId,
    /// The specific kind of item that was found
    pub kind: ContainerSearchItemKind,
}

/// The kind of item found in a container search.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerSearchItemKind {
    /// A source identified by its ID
    Source { path: SourcePath, id: SourceId },
    /// A function definition
    Function(Function),
    /// A type definition
    Type(Type),
    /// A symbol definition
    Symbol(Symbol),
}

/// Response containing the results of a container search.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ContainerSearchResponse {
    /// The matching items found in the search
    pub items: Vec<ContainerSearchItem>,
    /// Total number of matching items available
    pub total: usize,
    /// Starting offset of these results in the total set
    pub offset: usize,
}

/// Storage for WARP information.
///
/// Containers are made up of sources, see [`SourceId`] for more details.
pub trait Container: Send + Sync + Display + Debug {
    /// Available container sources.
    ///
    /// NOTE: Due to the nature of some containers, this list of sources may be incomplete. Do not
    /// rely on this list to retrieve data, instead prefer:
    /// - [Container::sources_with_type_guid]
    /// - [Container::sources_with_type_guids]
    /// - [Container::sources_with_function_guid]
    /// - [Container::sources_with_function_guids]
    fn sources(&self) -> ContainerResult<Vec<SourceId>>;

    /// Create a new source in the container or add the existing source at the given path to known sources.
    ///
    /// The returned [`SourceId`] can be used to add, query and remove information from the source.
    ///
    /// NOTE: Adding a source does **NOT** mean that it, and the data associated with it, has been
    /// persisted, you **MUST** call [`Container::commit_source`] to persist the created source.
    ///
    /// NOTE: Adding a source does **NOT** mean that you can write to it, use [`Container::is_source_writable`]
    /// to verify the permissions of the source.
    fn add_source(&mut self, path: SourcePath) -> ContainerResult<SourceId>;

    /// Flush changes made to a source.
    ///
    /// Because writing to a source can require file or network operations, we let the container
    /// offer the ability to hold off performing that operation until the data needs to be committed.
    fn commit_source(&mut self, source: &SourceId) -> ContainerResult<bool>;

    /// Whether the source can be written to.
    ///
    /// The source must be mutable to perform the following:
    /// - [Container::add_types]
    /// - [Container::add_computed_types]
    /// - [Container::remove_types]
    /// - [Container::add_functions]
    /// - [Container::remove_functions]
    fn is_source_writable(&self, source: &SourceId) -> ContainerResult<bool>;

    /// Whether the source has uncommitted changes or not.
    ///
    /// NOTE: This is **NOT** whether the source has been committed at all, rather a flag to indicate
    /// that a source has uncommitted changes.
    fn is_source_uncommitted(&self, source: &SourceId) -> ContainerResult<bool>;

    /// Retrieves the set of [`SourceTag`] for the given source.
    fn source_tags(&self, source: &SourceId) -> ContainerResult<HashSet<SourceTag>>;

    /// Retrieve the [`SourcePath`] for the given source.
    ///
    /// NOTE: This does not have to be a filesystem path, its representation is dictated
    /// by the implementation.
    fn source_path(&self, source: &SourceId) -> ContainerResult<SourcePath>;

    // TODO: Note about commit_source
    fn add_types(&mut self, source: &SourceId, types: &[Type]) -> ContainerResult<()> {
        let computed_types: Vec<_> = types.iter().cloned().map(ComputedType::new).collect();
        self.add_computed_types(source, &computed_types)
    }

    // TODO: Note about commit_source
    fn add_computed_types(
        &mut self,
        source: &SourceId,
        types: &[ComputedType],
    ) -> ContainerResult<()>;

    // TODO: Note about commit_source
    fn remove_types(&mut self, source: &SourceId, guids: &[TypeGUID]) -> ContainerResult<()>;

    // TODO: Note about commit_source
    fn add_functions(
        &mut self,
        target: &Target,
        source: &SourceId,
        functions: &[Function],
    ) -> ContainerResult<()>;

    // TODO: Note about commit_source
    fn remove_functions(
        &mut self,
        target: &Target,
        source: &SourceId,
        functions: &[Function],
    ) -> ContainerResult<()>;

    /// Fetches WARP information for the associated functions.
    ///
    /// Typically, a container that resides only in memory has nothing to fetch, so the default implementation
    /// will do nothing. This function is blocking, so assume it will take a few seconds for a container
    /// that intends to fetch over the network.
    fn fetch_functions(
        &mut self,
        _target: &Target,
        _tags: &[SourceTag],
        _functions: &[FunctionGUID],
    ) -> ContainerResult<()> {
        Ok(())
    }

    /// Get the sources that contain a type with the given [`TypeGUID`].
    fn sources_with_type_guid(&self, guid: &TypeGUID) -> ContainerResult<Vec<SourceId>>;

    /// Plural version of [`Container::sources_with_type_guid`].
    ///
    /// Each source will have a list of the containing GUID's so that when looking up a source, you give
    /// it only the GUID's that it knows about, for networking this means cutting down traffic significantly.
    fn sources_with_type_guids(
        &self,
        guids: &[TypeGUID],
    ) -> ContainerResult<HashMap<TypeGUID, Vec<SourceId>>>;

    /// Retrieve all [`TypeGUID`]'s with the given name.
    fn type_guids_with_name(&self, source: &SourceId, name: &str)
        -> ContainerResult<Vec<TypeGUID>>;

    fn type_with_guid(&self, source: &SourceId, guid: &TypeGUID) -> ContainerResult<Option<Type>>;

    fn has_type_with_guid(&self, source: &SourceId, guid: &TypeGUID) -> ContainerResult<bool> {
        Ok(self.type_with_guid(source, guid)?.is_some())
    }

    /// Get the sources that contain functions with the given [`FunctionGUID`].
    fn sources_with_function_guid(
        &self,
        target: &Target,
        guid: &FunctionGUID,
    ) -> ContainerResult<Vec<SourceId>>;

    /// Plural version of [`Container::sources_with_function_guid`].
    ///
    /// Each source will have a list of the containing GUID's so that when looking up a source you give
    /// it only the GUID's that it knows about, for networking this means cutting down traffic significantly.
    fn sources_with_function_guids(
        &self,
        target: &Target,
        guids: &[FunctionGUID],
    ) -> ContainerResult<HashMap<FunctionGUID, Vec<SourceId>>>;

    fn functions_with_guid(
        &self,
        target: &Target,
        source: &SourceId,
        guid: &FunctionGUID,
    ) -> ContainerResult<Vec<Function>>;

    fn has_function_with_guid(
        &self,
        target: &Target,
        source: &SourceId,
        guid: &FunctionGUID,
    ) -> ContainerResult<bool> {
        Ok(!self.functions_with_guid(target, source, guid)?.is_empty())
    }

    /// Perform a paginated search over the container contents.
    ///
    /// The container implementation is responsible for interpreting [`ContainerSearchQuery::query`]
    /// for example, locally you may not have the capabilities to perform a sane fuzzy search, so the query
    /// is exact, whereas a database-backed container may opt to instead perform a fuzzy search.
    ///
    /// NOTE: This is intended for user-performed actions, as the query may look up over the network.
    fn search(&self, _query: &ContainerSearchQuery) -> ContainerResult<ContainerSearchResponse> {
        Ok(ContainerSearchResponse::default())
    }
}
