use crate::container::{
    Container, ContainerError, ContainerResult, SourceId, SourcePath, SourceTag,
};
use std::collections::{HashMap, HashSet};
use std::fmt::{Debug, Display, Formatter};
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use uuid::{uuid, Uuid};
use walkdir::{DirEntry, WalkDir};
use warp::chunk::{Chunk, ChunkKind, CompressionType};
use warp::r#type::chunk::TypeChunk;
use warp::r#type::guid::TypeGUID;
use warp::r#type::{ComputedType, Type};
use warp::signature::chunk::SignatureChunk;
use warp::signature::function::{Function, FunctionGUID};
use warp::target::Target;
use warp::{WarpFile, WarpFileHeader};

pub const NAMESPACE_DISK_SOURCE: Uuid = uuid!("ea89e8ab-a27a-432b-8fbd-77b026cd5f41");

// TODO: How to support remote projects? I.e. collaboration?
pub struct DiskContainer {
    pub name: String,
    pub sources: HashMap<SourceId, DiskContainerSource>,
    pub writable: bool,
}

impl DiskContainer {
    pub fn new(name: String, sources: HashMap<SourceId, DiskContainerSource>) -> Self {
        Self {
            name,
            sources,
            writable: true,
        }
    }

    pub fn new_from_dir(dir_path: PathBuf) -> Self {
        let source_from_entry = |entry: DirEntry| {
            let path = SourcePath(entry.into_path());
            let source_id = path.to_source_id();
            let path_ext = path.0.extension().unwrap_or_default().to_str();
            match (DiskContainerSource::new_from_path(path.clone()), path_ext) {
                (Ok(source), _) => Some((source_id, source)),
                (Err(err), Some("warp")) => {
                    tracing::error!("Failed to load source '{}' from disk: {}", path, err);
                    None
                }
                // We don't care to show errors loading for non-warp files.
                (Err(_), _) => None,
            }
        };

        // TODO: For now, any file that does not have the "warp" extension will be filtered out.
        // TODO: cont. in the future we might want to remove this for convenience.
        let name = dir_path.to_string_lossy().to_string();
        let sources = WalkDir::new(dir_path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .filter(|e| e.path().extension().is_some_and(|e| e == "warp"))
            .filter_map(source_from_entry)
            .collect();

        Self::new(name, sources)
    }

    pub fn insert_source(&mut self, id: SourceId, path: SourcePath) -> ContainerResult<()> {
        if !self.writable || self.sources.contains_key(&id) {
            return Err(ContainerError::SourceAlreadyExists(path));
        }
        // NOTE: We let anyone add a file from anywhere on the file system because of this.
        let disk_source = match path.0.exists() {
            true => DiskContainerSource::new_from_path(path.clone())?,
            false => {
                let file = WarpFile::new(WarpFileHeader::new(), vec![]);
                DiskContainerSource::new(path, file)
            }
        };
        self.sources.insert(id, disk_source);
        Ok(())
    }
}

impl Container for DiskContainer {
    fn sources(&self) -> ContainerResult<Vec<SourceId>> {
        Ok(self.sources.keys().copied().collect())
    }

    fn add_source(&mut self, path: SourcePath) -> ContainerResult<SourceId> {
        // Disk sources have there source id computed from the path.
        let source_id = path.to_source_id();
        match self.insert_source(source_id, path) {
            Ok(()) => {}
            Err(ContainerError::SourceAlreadyExists(_)) => {}
            Err(err) => return Err(err),
        }
        Ok(source_id)
    }

    fn commit_source(&mut self, source: &SourceId) -> ContainerResult<bool> {
        let disk_source = self
            .sources
            .get_mut(source)
            .ok_or(ContainerError::SourceNotFound(*source))?;

        disk_source.commit_to_disk()
    }

    fn is_source_writable(&self, source: &SourceId) -> ContainerResult<bool> {
        let _disk_source = self
            .sources
            .get(source)
            .ok_or(ContainerError::SourceNotFound(*source))?;
        Ok(self.writable)
    }

    fn is_source_uncommitted(&self, source: &SourceId) -> ContainerResult<bool> {
        let disk_source = self
            .sources
            .get(source)
            .ok_or(ContainerError::SourceNotFound(*source))?;
        Ok(disk_source.uncommitted)
    }

    fn source_tags(&self, source: &SourceId) -> ContainerResult<HashSet<SourceTag>> {
        let disk_source = self
            .sources
            .get(source)
            .ok_or(ContainerError::SourceNotFound(*source))?;
        Ok(disk_source.tags.clone())
    }

    fn source_path(&self, source: &SourceId) -> ContainerResult<SourcePath> {
        let disk_source = self
            .sources
            .get(source)
            .ok_or(ContainerError::SourceNotFound(*source))?;
        Ok(disk_source.path.clone())
    }

    fn add_computed_types(
        &mut self,
        source: &SourceId,
        types: &[ComputedType],
    ) -> ContainerResult<()> {
        let disk_source = self
            .sources
            .get_mut(source)
            .ok_or(ContainerError::SourceNotFound(*source))?;

        disk_source.add_computed_types(types)
    }

    // TODO: I believe any remove has to happen immediately, i.e. we cant add an uncommitted for this?
    fn remove_types(&mut self, source: &SourceId, _guids: &[TypeGUID]) -> ContainerResult<()> {
        let _disk_source = self
            .sources
            .get(source)
            .ok_or(ContainerError::SourceNotFound(*source))?;

        // TODO: Do this.
        Err(ContainerError::SourceNotWritable(*source))
    }

    fn add_functions(
        &mut self,
        target: &Target,
        source: &SourceId,
        functions: &[Function],
    ) -> ContainerResult<()> {
        let disk_source = self
            .sources
            .get_mut(source)
            .ok_or(ContainerError::SourceNotFound(*source))?;

        disk_source.add_functions(target.clone(), functions)
    }

    // TODO: I believe any remove has to happen immediately, i.e. we cant add an uncommitted for this?
    fn remove_functions(
        &mut self,
        _target: &Target,
        source: &SourceId,
        _functions: &[Function],
    ) -> ContainerResult<()> {
        let _disk_source = self
            .sources
            .get(source)
            .ok_or(ContainerError::SourceNotFound(*source))?;

        // TODO: Do this.
        Err(ContainerError::SourceNotWritable(*source))
    }

    fn sources_with_type_guid(&self, guid: &TypeGUID) -> ContainerResult<Vec<SourceId>> {
        let sources = self
            .sources
            .iter()
            .filter(|(_, source)| source.has_type_with_guid(guid))
            .map(|(id, _)| *id)
            .collect();
        Ok(sources)
    }

    fn sources_with_type_guids<'a>(
        &'a self,
        guids: &'a [TypeGUID],
    ) -> ContainerResult<HashMap<TypeGUID, Vec<SourceId>>> {
        let mut result: HashMap<TypeGUID, Vec<SourceId>> = HashMap::new();
        for (source_id, source) in &self.sources {
            guids
                .iter()
                .filter(|guid| source.has_type_with_guid(guid))
                .for_each(|guid| result.entry(*guid).or_default().push(*source_id));
        }
        Ok(result)
    }

    fn type_guids_with_name(
        &self,
        source: &SourceId,
        name: &str,
    ) -> ContainerResult<Vec<TypeGUID>> {
        let disk_source = self
            .sources
            .get(source)
            .ok_or(ContainerError::SourceNotFound(*source))?;
        Ok(disk_source.type_guids_with_name(name))
    }

    fn type_with_guid(&self, source: &SourceId, guid: &TypeGUID) -> ContainerResult<Option<Type>> {
        let disk_source = self
            .sources
            .get(source)
            .ok_or(ContainerError::SourceNotFound(*source))?;
        Ok(disk_source.type_with_guid(guid))
    }

    fn sources_with_function_guid(
        &self,
        target: &Target,
        guid: &FunctionGUID,
    ) -> ContainerResult<Vec<SourceId>> {
        let sources = self
            .sources
            .iter()
            .filter(|(_, source)| source.has_function_with_guid(target, guid))
            .map(|(id, _)| *id)
            .collect();
        Ok(sources)
    }

    fn sources_with_function_guids<'a>(
        &self,
        target: &Target,
        guids: &[FunctionGUID],
    ) -> ContainerResult<HashMap<FunctionGUID, Vec<SourceId>>> {
        let mut result: HashMap<FunctionGUID, Vec<SourceId>> = HashMap::new();
        for (source_id, source) in &self.sources {
            guids
                .iter()
                .filter(|guid| source.has_function_with_guid(target, guid))
                .for_each(|guid| result.entry(*guid).or_default().push(*source_id));
        }
        Ok(result)
    }

    fn functions_with_guid(
        &self,
        target: &Target,
        source: &SourceId,
        guid: &FunctionGUID,
    ) -> ContainerResult<Vec<Function>> {
        let disk_source = self
            .sources
            .get(source)
            .ok_or(ContainerError::SourceNotFound(*source))?;
        Ok(disk_source.functions_with_guid(target, guid))
    }
}

impl Display for DiskContainer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

impl Debug for DiskContainer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiskContainer")
            .field("name", &self.name)
            .field("sources", &self.sources)
            .finish()
    }
}

pub struct DiskContainerSource {
    pub path: SourcePath,
    pub tags: HashSet<SourceTag>,
    file: WarpFile<'static>,
    uncommitted: bool,
}

impl DiskContainerSource {
    pub fn new(path: SourcePath, file: WarpFile<'static>) -> Self {
        Self {
            path,
            tags: HashSet::new(),
            file,
            uncommitted: false,
        }
    }

    pub fn new_from_path(path: SourcePath) -> ContainerResult<Self> {
        // TODO: To keep the lifetime out of DiskContainerSource we do not allow mapping file to memory.
        let contents = std::fs::read(&path).map_err(|e| ContainerError::FailedIO(e.kind()))?;
        let file = WarpFile::from_owned_bytes(contents).ok_or(ContainerError::CorruptedData(
            "file data failed to validate",
        ))?;
        Ok(Self::new(path, file))
    }

    fn add_computed_types(&mut self, types: &[ComputedType]) -> ContainerResult<()> {
        let type_chunk = TypeChunk::new_with_computed(types).ok_or(
            ContainerError::CorruptedData("type chunk failed to validate"),
        )?;
        let chunk = Chunk::new(ChunkKind::Type(type_chunk), CompressionType::None);
        self.file.chunks.push(chunk);
        self.uncommitted = true;
        Ok(())
    }

    fn add_functions(&mut self, target: Target, functions: &[Function]) -> ContainerResult<()> {
        let signature_chunk = SignatureChunk::new(functions).ok_or(
            ContainerError::CorruptedData("signature chunk failed to validate"),
        )?;
        let chunk = Chunk::new_with_target(
            ChunkKind::Signature(signature_chunk),
            CompressionType::None,
            target,
        );
        self.file.chunks.push(chunk);
        self.uncommitted = true;
        Ok(())
    }

    fn commit_to_disk(&mut self) -> ContainerResult<bool> {
        let file = self.file.to_bytes();
        std::fs::write(&self.path, file).map_err(|e| ContainerError::FailedIO(e.kind()))?;
        self.uncommitted = false;
        Ok(true)
    }

    fn type_guids_with_name(&self, name: &str) -> Vec<TypeGUID> {
        let mut found: Vec<TypeGUID> = Vec::new();
        for chunk in &self.file.chunks {
            if let ChunkKind::Type(tc) = &chunk.kind {
                found.extend(
                    tc.raw_type_with_name(name)
                        .into_iter()
                        .map(|t| TypeGUID::from(t.guid())),
                );
            }
        }
        found
    }

    fn type_with_guid(&self, guid: &TypeGUID) -> Option<Type> {
        self.file.chunks.iter().find_map(|chunk| {
            if let ChunkKind::Type(tc) = &chunk.kind {
                tc.type_with_guid(guid)
            } else {
                None
            }
        })
    }

    // TODO: When we support reading lazily instead of all in memory.
    fn has_type_with_guid(&self, guid: &TypeGUID) -> bool {
        self.type_with_guid(guid).is_some()
    }

    fn functions_with_guid(&self, target: &Target, guid: &FunctionGUID) -> Vec<Function> {
        let mut found: Vec<Function> = Vec::new();
        for chunk in &self.file.chunks {
            if chunk.header.target != *target {
                continue;
            }
            if let ChunkKind::Signature(sc) = &chunk.kind {
                found.extend(sc.functions_with_guid(guid));
            }
        }
        found
    }

    // TODO: When we support reading lazily instead of all in memory.
    fn has_function_with_guid(&self, target: &Target, guid: &FunctionGUID) -> bool {
        // TODO: How about we dont clone.
        !self.functions_with_guid(target, guid).is_empty()
    }
}

impl Hash for DiskContainerSource {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.path.hash(state);
    }
}

impl Display for DiskContainerSource {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.path)
    }
}

impl Debug for DiskContainerSource {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DiskContainerSource")
            .field("path", &self.path)
            .field("file_header", &self.file.header)
            .field("file_chunks", &self.file.chunks.len())
            .finish()
    }
}
