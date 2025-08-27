use crate::container::disk::DiskContainer;
use crate::container::{
    Container, ContainerError, ContainerResult, ContainerSearchQuery, ContainerSearchResponse,
    SourceId, SourcePath, SourceTag,
};
use directories::ProjectDirs;
use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Display, Formatter};
use std::path::PathBuf;
use warp::chunk::{Chunk, ChunkKind, CompressionType};
use warp::r#type::guid::TypeGUID;
use warp::r#type::{ComputedType, Type};
use warp::signature::chunk::SignatureChunk;
use warp::signature::function::{Function, FunctionGUID};
use warp::target::Target;
use warp::{WarpFile, WarpFileHeader};

pub mod client;

use crate::container::ContainerError::CannotCreateSource;
pub use client::NetworkClient;

/// This is the id on the server for the [`Target`], we can get it via [`NetworkClient::query_target_id`].
pub type NetworkTargetId = i32;

pub struct NetworkContainer {
    client: NetworkClient,
    /// This is the store that the interface will write to; then we have special functions for pulling
    /// and pushing to the network source.
    cache: DiskContainer,
    /// Where to place newly created sources.
    ///
    /// This is typically a directory inside [`NetworkContainer::root_cache_location`].
    cache_path: PathBuf,
    /// Populated when targets are queried.
    known_targets: HashMap<Target, Option<NetworkTargetId>>,
    /// Populated when function sources are queried.
    known_function_sources: HashMap<FunctionGUID, Vec<SourceId>>,
    /// Populated when user adds function, this is used for writing back to the server.
    added_chunks: HashMap<SourceId, Vec<Chunk<'static>>>,
    /// Populated when connecting to the server, this is used to determine which sources are writable.
    ///
    /// NOTE: This is only populated when logged in, as guest users do not have write permissions.
    writable_sources: HashSet<SourceId>,
}

impl NetworkContainer {
    pub fn new(client: NetworkClient, cache_path: PathBuf, writable_sources: &[SourceId]) -> Self {
        let mut container = Self {
            cache: DiskContainer::new_from_dir(cache_path.clone()),
            cache_path,
            client,
            known_targets: HashMap::new(),
            known_function_sources: HashMap::new(),
            added_chunks: HashMap::new(),
            writable_sources: writable_sources.into_iter().copied().collect(),
        };

        // TODO: Because of this little hack, methinks we should move writable sources to after the
        // TODO: container is actually created, but before it is moved into the global container cache.
        // Probe all writable sources, so the container knows about them properly.
        for source in writable_sources {
            container.probe_source(*source);
        }

        container
    }

    /// Gets the network id for the `target`, this will be used in later function queries.
    ///
    /// **This is blocking**
    ///
    /// # Caching policy
    ///
    /// The [`NetworkTargetId`] is unique and immutable, so they will be persisted indefinitely.
    pub fn get_target_id(&mut self, target: &Target) -> Option<NetworkTargetId> {
        // It's highly probable we have previously queried the target, check that first.
        if let Some(target_id) = self.known_targets.get(target) {
            return target_id.clone();
        }

        let target_id = self.client.query_target_id(target);
        // Keep the target id so the next lookup is free.
        self.known_targets.insert(target.clone(), target_id);
        target_id
    }

    /// Pulls sources for the set of unseen function guids.
    ///
    /// **This is blocking**
    ///
    /// # Caching policy
    ///
    /// When we get the source, we store the results indefinitely in the container; this is fine
    /// for now as the requests for functions come at the request of some user interaction. Any guid
    /// with no sources will still be cached.
    pub fn get_unseen_functions_source(
        &mut self,
        target: Option<&Target>,
        tags: &[SourceTag],
        guids: &[FunctionGUID],
    ) -> HashMap<SourceId, Vec<FunctionGUID>> {
        let Some(target_id) = target.and_then(|t| self.get_target_id(t)) else {
            log::debug!("Cannot query functions source without a target, skipping...");
            return HashMap::new();
        };

        // Split guids into known and unknown
        let (_known, unknown): (Vec<_>, Vec<_>) = guids
            .into_iter()
            .cloned()
            .partition(|guid| self.known_function_sources.contains_key(guid));

        let mut result: HashMap<SourceId, Vec<FunctionGUID>> = HashMap::new();
        // Only query server for unknown guids if we have any.
        if !unknown.is_empty() {
            if let Some(queried_results) =
                self.client
                    .query_functions_source(Some(target_id), tags, &unknown)
            {
                // Cache the new results, this means we will not try and contact the server for that guids source.
                // NOTE: Here we do not just simply list the queried results because we also
                // want to cache function guids which have no source, this is important so that we never
                // attempt to contact the server for that guid.
                for guid in &unknown {
                    let sources = queried_results
                        .keys()
                        .filter(|source_id| queried_results[source_id].contains(guid))
                        .cloned()
                        .collect();
                    self.known_function_sources.insert(*guid, sources);
                }

                for (source_id, guids) in queried_results {
                    result.entry(source_id).or_default().extend(guids);
                }
            }
        }

        result
    }

    /// Pulls function metadata from the server and adds it into the container cache.
    ///
    /// **This is blocking**
    ///
    /// # Caching policy
    ///
    /// Every request we store the returned objects on disk, this means that users will first
    /// query against the disk objects, then the server. This also means we need to cache functions f
    /// or which we have not received any functions for, as otherwise we would keep trying to query it.
    pub fn pull_functions(
        &mut self,
        target: &Target,
        source: &SourceId,
        functions: &[FunctionGUID],
    ) {
        let target_id = self.get_target_id(target);
        if let Some(file) = self
            .client
            .query_functions(target_id, Some(*source), functions)
        {
            log::debug!("Got {} chunks from server", file.chunks.len());
            for chunk in &file.chunks {
                match &chunk.kind {
                    ChunkKind::Signature(sc) => {
                        let functions: Vec<_> = sc.functions().collect();
                        // Probe the source before attempting to access it, as it might not exist locally.
                        self.probe_source(*source);
                        match self.cache.add_functions(target, source, &functions) {
                            Ok(_) => log::debug!(
                                "Added {} functions into cached source '{}'",
                                functions.len(),
                                source
                            ),
                            Err(err) => log::error!(
                                "Failed to add {} function into cached source '{}': {}",
                                functions.len(),
                                source,
                                err
                            ),
                        }
                    }
                    // TODO; Probably want to pull type in with this.
                    ChunkKind::Type(_) => {}
                }
            }
        }
    }

    /// Push a file to the network source.
    ///
    /// **This is blocking**
    pub fn push_file(&mut self, source_id: SourceId, file: &WarpFile) {
        // TODO: We need a better name for the commit. I would like to derive it automatically from
        // TODO: something instead of having the user give it TBH.
        self.client.push_file(source_id, file, "commit");
    }

    /// Probe the source to make sure it exists in the cache. Retrieving the name from the server.
    ///
    /// **This is blocking**
    pub fn probe_source(&mut self, source_id: SourceId) {
        if !self.cache.source_path(&source_id).is_ok() {
            // Add the source to the cache. Using the source id and source name as the source path.
            match self.client.source_name(source_id) {
                Ok(source_name) => {
                    // To prevent two sources with the same name colliding, we add the source id to the source name.
                    let source_path = self
                        .cache_path
                        .join(source_id.to_string())
                        .join(source_name);
                    let _ = self.cache.insert_source(source_id, SourcePath(source_path));
                }
                Err(e) => {
                    log::error!("Failed to probe source '{}': {}", source_id, e);
                }
            }
        }
    }

    pub fn root_cache_location() -> PathBuf {
        // - Windows: %LOCALAPPDATA%\<org>\<app>\cache
        // - macOS:   ~/Library/Caches/<org>.<app>
        // - Linux:   $XDG_CACHE_HOME/<app> or ~/.cache/<app>
        if let Some(proj_dirs) = ProjectDirs::from("", "Vector35", "Binary Ninja") {
            proj_dirs.cache_dir().to_path_buf()
        } else {
            // Fallback if OS dirs cannot be determined
            std::env::current_dir()
                .unwrap_or_else(|_| PathBuf::from("."))
                .join(".cache")
                .join("binaryninja")
        }
    }
}

impl Container for NetworkContainer {
    fn sources(&self) -> ContainerResult<Vec<SourceId>> {
        self.cache.sources()
    }

    fn add_source(&mut self, path: SourcePath) -> ContainerResult<SourceId> {
        // Send a **blocking** request to the server to create the source.
        // NOTE: The user must be logged in for this to work.
        // TODO: Some better error handling to alert the user that they are not logged in / creating existing sources.
        let source = self
            .client
            .create_source(&path.to_string())
            .map_err(|_| CannotCreateSource(path))?;
        // Must probe the source before attempting to access it, as it does not exist locally.
        self.probe_source(source);
        Ok(source)
    }

    fn commit_source(&mut self, source: &SourceId) -> ContainerResult<bool> {
        let chunks = self
            .added_chunks
            .remove(source)
            .ok_or(ContainerError::SourceNotFound(source.clone()))?;
        // Because each add operation is its own chunk, we should merge them into larger chunks before sending.
        let merged_chunks = Chunk::merge(&chunks, CompressionType::Zstd);
        let file = WarpFile::new(WarpFileHeader::new(), merged_chunks);
        self.push_file(*source, &file);
        Ok(true)
    }

    fn is_source_writable(&self, source: &SourceId) -> ContainerResult<bool> {
        // Assume that all writable_sources are also in the cache (through `probe_source`).
        Ok(self.writable_sources.contains(source))
    }

    fn is_source_uncommitted(&self, source: &SourceId) -> ContainerResult<bool> {
        Ok(self.added_chunks.contains_key(source))
    }

    fn source_tags(&self, source: &SourceId) -> ContainerResult<HashSet<SourceTag>> {
        self.cache.source_tags(source)
    }

    fn source_path(&self, source: &SourceId) -> ContainerResult<SourcePath> {
        self.cache.source_path(source)
    }

    fn add_computed_types(
        &mut self,
        source: &SourceId,
        types: &[ComputedType],
    ) -> ContainerResult<()> {
        self.cache.add_computed_types(source, types)
    }

    fn remove_types(&mut self, source: &SourceId, guids: &[TypeGUID]) -> ContainerResult<()> {
        self.cache.remove_types(source, guids)
    }

    fn add_functions(
        &mut self,
        target: &Target,
        source: &SourceId,
        functions: &[Function],
    ) -> ContainerResult<()> {
        let signature_chunk = SignatureChunk::new(functions).ok_or(
            ContainerError::CorruptedData("signature chunk failed to validate"),
        )?;
        let chunk = Chunk::new_with_target(
            ChunkKind::Signature(signature_chunk),
            CompressionType::None,
            target.clone(),
        );
        self.added_chunks.entry(*source).or_default().push(chunk);
        Ok(())
    }

    fn remove_functions(
        &mut self,
        target: &Target,
        source: &SourceId,
        functions: &[Function],
    ) -> ContainerResult<()> {
        // TODO: Wont persist, need to add remote removal.
        self.cache.remove_functions(target, source, functions)
    }

    fn fetch_functions(
        &mut self,
        target: &Target,
        tags: &[SourceTag],
        functions: &[FunctionGUID],
    ) -> ContainerResult<()> {
        // NOTE: Blocking request to get the mapped function sources.
        let mapped_unseen_functions =
            self.get_unseen_functions_source(Some(&target), tags, functions);

        // Actually get the function data for the unseen guids, we really only want to do this once per
        // session, anymore, and this is annoying!
        for (source, unseen_guids) in mapped_unseen_functions {
            // NOTE: Blocking request to get the function data in the container cache.
            self.pull_functions(&target, &source, &unseen_guids);
        }

        Ok(())
    }

    fn sources_with_type_guid(&self, guid: &TypeGUID) -> ContainerResult<Vec<SourceId>> {
        self.cache.sources_with_type_guid(guid)
    }

    fn sources_with_type_guids(
        &self,
        guids: &[TypeGUID],
    ) -> ContainerResult<HashMap<TypeGUID, Vec<SourceId>>> {
        self.cache.sources_with_type_guids(guids)
    }

    fn type_guids_with_name(
        &self,
        source: &SourceId,
        name: &str,
    ) -> ContainerResult<Vec<TypeGUID>> {
        self.cache.type_guids_with_name(source, name)
    }

    fn type_with_guid(&self, source: &SourceId, guid: &TypeGUID) -> ContainerResult<Option<Type>> {
        self.cache.type_with_guid(source, guid)
    }

    fn sources_with_function_guid(
        &self,
        target: &Target,
        guid: &FunctionGUID,
    ) -> ContainerResult<Vec<SourceId>> {
        self.cache.sources_with_function_guid(target, guid)
    }

    fn sources_with_function_guids(
        &self,
        target: &Target,
        guids: &[FunctionGUID],
    ) -> ContainerResult<HashMap<FunctionGUID, Vec<SourceId>>> {
        self.cache.sources_with_function_guids(target, guids)
    }

    fn functions_with_guid(
        &self,
        target: &Target,
        source: &SourceId,
        guid: &FunctionGUID,
    ) -> ContainerResult<Vec<Function>> {
        self.cache.functions_with_guid(target, source, guid)
    }

    fn search(&self, query: &ContainerSearchQuery) -> ContainerResult<ContainerSearchResponse> {
        // TODO: Give this an actual network error.
        self.client
            .search(query)
            .ok_or(ContainerError::CorruptedData(
                "search query failed to validate",
            ))
    }
}

impl Debug for NetworkContainer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NetworkContainer")
            .field("client", &self.client)
            .field("cache_path", &self.cache_path)
            .finish()
    }
}

impl Display for NetworkContainer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.client.server_url, f)
    }
}
