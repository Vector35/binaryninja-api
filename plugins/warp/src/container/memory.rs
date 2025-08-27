use crate::container::{
    Container, ContainerError, ContainerResult, SourceId, SourcePath, SourceTag,
};
use std::collections::{HashMap, HashSet};
use std::fmt::Display;
use warp::r#type::guid::TypeGUID;
use warp::r#type::{ComputedType, Type};
use warp::signature::function::{Function, FunctionGUID};
use warp::target::Target;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MemoryContainer {
    sources: HashMap<SourceId, MemorySource>,
}

impl MemoryContainer {
    pub fn new() -> Self {
        MemoryContainer::default()
    }

    pub fn with_source(mut self, id: SourceId, source: MemorySource) -> Self {
        self.sources.insert(id, source);
        self
    }

    pub fn with_source_function(
        mut self,
        id: SourceId,
        guid: FunctionGUID,
        func: Function,
    ) -> Self {
        self.sources
            .entry(id)
            .or_default()
            .functions
            .entry(guid)
            .or_default()
            .push(func);
        self
    }

    pub fn with_source_type(mut self, id: SourceId, guid: TypeGUID, ty: Type) -> Self {
        self.sources.entry(id).or_default().types.insert(guid, ty);
        self
    }
}

impl Container for MemoryContainer {
    fn sources(&self) -> ContainerResult<Vec<SourceId>> {
        todo!()
    }

    fn add_source(&mut self, path: SourcePath) -> ContainerResult<SourceId> {
        Err(ContainerError::CannotCreateSource(path))
    }

    fn commit_source(&mut self, _source: &SourceId) -> ContainerResult<bool> {
        Ok(false)
    }

    fn is_source_writable(&self, source: &SourceId) -> ContainerResult<bool> {
        let memory_source = self
            .sources
            .get(source)
            .ok_or(ContainerError::SourceNotFound(*source))?;
        Ok(memory_source.writable)
    }

    fn is_source_uncommitted(&self, source: &SourceId) -> ContainerResult<bool> {
        let _memory_source = self
            .sources
            .get(source)
            .ok_or(ContainerError::SourceNotFound(*source))?;
        // NOTE: Memory containers do not have a notion of uncommitted data.
        Ok(false)
    }

    fn source_tags(&self, source: &SourceId) -> ContainerResult<HashSet<SourceTag>> {
        let _memory_source = self
            .sources
            .get(source)
            .ok_or(ContainerError::SourceNotFound(*source))?;
        // NOTE: Memory containers do not have a notion of tags.
        Ok(HashSet::default())
    }

    fn source_path(&self, source: &SourceId) -> ContainerResult<SourcePath> {
        Err(ContainerError::SourcePathUnavailable(*source))
    }

    fn add_computed_types(
        &mut self,
        source: &SourceId,
        types: &[ComputedType],
    ) -> ContainerResult<()> {
        let memory_source = self
            .sources
            .get_mut(source)
            .ok_or(ContainerError::SourceNotFound(*source))?;
        match memory_source.writable {
            true => {
                for ty in types {
                    memory_source.types.insert(ty.guid, ty.ty.clone());
                }
                Ok(())
            }
            false => Err(ContainerError::SourceNotWritable(*source)),
        }
    }

    fn remove_types(&mut self, source: &SourceId, guids: &[TypeGUID]) -> ContainerResult<()> {
        let memory_source = self
            .sources
            .get_mut(source)
            .ok_or(ContainerError::SourceNotFound(*source))?;
        match memory_source.writable {
            true => {
                for guid in guids {
                    memory_source.types.remove(guid);
                }
                Ok(())
            }
            false => Err(ContainerError::SourceNotWritable(*source)),
        }
    }

    fn add_functions(
        &mut self,
        _target: &Target,
        source: &SourceId,
        functions: &[Function],
    ) -> ContainerResult<()> {
        let memory_source = self
            .sources
            .get_mut(source)
            .ok_or(ContainerError::SourceNotFound(*source))?;
        match memory_source.writable {
            true => {
                for function in functions {
                    memory_source
                        .functions
                        .entry(function.guid)
                        .or_default()
                        .push(function.clone());
                }
                Ok(())
            }
            false => Err(ContainerError::SourceNotWritable(*source)),
        }
    }

    fn remove_functions(
        &mut self,
        _target: &Target,
        source: &SourceId,
        functions: &[Function],
    ) -> ContainerResult<()> {
        let memory_source = self
            .sources
            .get_mut(source)
            .ok_or(ContainerError::SourceNotFound(*source))?;
        match memory_source.writable {
            true => {
                for function in functions {
                    if let Some(src_funcs) = memory_source.functions.get_mut(&function.guid) {
                        src_funcs.retain(|f| f != function);
                        if src_funcs.is_empty() {
                            memory_source.functions.remove(&function.guid);
                        }
                    }
                }
                Ok(())
            }
            false => Err(ContainerError::SourceNotWritable(*source)),
        }
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

    fn sources_with_type_guids(
        &self,
        guids: &[TypeGUID],
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
        let memory_source = self
            .sources
            .get(source)
            .ok_or(ContainerError::SourceNotFound(*source))?;
        Ok(memory_source.type_guids_with_name(name))
    }

    fn type_with_guid(&self, source: &SourceId, guid: &TypeGUID) -> ContainerResult<Option<Type>> {
        let memory_source = self
            .sources
            .get(source)
            .ok_or(ContainerError::SourceNotFound(*source))?;
        Ok(memory_source.type_with_guid(guid))
    }

    fn sources_with_function_guid(
        &self,
        _target: &Target,
        guid: &FunctionGUID,
    ) -> ContainerResult<Vec<SourceId>> {
        let sources = self
            .sources
            .iter()
            .filter(|(_, source)| source.has_function_with_guid(guid))
            .map(|(id, _)| *id)
            .collect();
        Ok(sources)
    }

    fn sources_with_function_guids(
        &self,
        _target: &Target,
        guids: &[FunctionGUID],
    ) -> ContainerResult<HashMap<FunctionGUID, Vec<SourceId>>> {
        let mut result: HashMap<FunctionGUID, Vec<SourceId>> = HashMap::new();
        for (source_id, source) in &self.sources {
            guids
                .iter()
                .filter(|guid| source.has_function_with_guid(guid))
                .for_each(|guid| result.entry(*guid).or_default().push(*source_id));
        }
        Ok(result)
    }

    fn functions_with_guid(
        &self,
        _target: &Target,
        source: &SourceId,
        guid: &FunctionGUID,
    ) -> ContainerResult<Vec<Function>> {
        let memory_source = self
            .sources
            .get(source)
            .ok_or(ContainerError::SourceNotFound(*source))?;
        Ok(memory_source.functions_with_guid(guid))
    }
}

impl Display for MemoryContainer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MemoryContainer")
    }
}

/// An in-memory store of functions.
///
/// This is typically an overlay on top of a container source.
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct MemorySource {
    pub writable: bool,
    pub functions: HashMap<FunctionGUID, Vec<Function>>,
    pub types: HashMap<TypeGUID, Type>,
    pub named_types: HashMap<String, Vec<TypeGUID>>,
}

impl MemorySource {
    pub fn type_guids_with_name(&self, name: &str) -> Vec<TypeGUID> {
        // TODO: The function here is a little goofy.
        // TODO: This is cloned.
        self.named_types.get(name).cloned().unwrap_or_default()
    }

    pub fn type_with_guid(&self, guid: &TypeGUID) -> Option<Type> {
        // TODO: This is cloned.
        self.types.get(guid).cloned()
    }

    pub fn functions_with_guid(&self, guid: &FunctionGUID) -> Vec<Function> {
        // TODO: The function here is a little goofy.
        // TODO: This is cloned.
        self.functions.get(guid).cloned().unwrap_or_default()
    }

    pub fn has_type_with_guid(&self, guid: &TypeGUID) -> bool {
        self.type_with_guid(guid).is_some()
    }

    pub fn has_function_with_guid(&self, guid: &FunctionGUID) -> bool {
        !self.functions_with_guid(guid).is_empty()
    }
}

impl Default for MemorySource {
    fn default() -> Self {
        Self {
            writable: true,
            functions: HashMap::new(),
            types: HashMap::new(),
            named_types: HashMap::new(),
        }
    }
}
