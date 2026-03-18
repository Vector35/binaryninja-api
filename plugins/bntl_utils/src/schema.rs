use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::path::Path;

#[derive(Deserialize, Debug)]
pub struct BntlSchema {
    /// The list of library names this library depends on
    pub dependencies: Vec<String>,
    /// Maps internal type IDs or names to their external sources
    pub type_sources: Vec<TypeSource>,
}

impl BntlSchema {
    pub fn from_file(file: &File) -> Self {
        serde_json::from_reader(file).expect("JSON schema mismatch")
    }

    pub fn from_path(path: &Path) -> Self {
        Self::from_file(&File::open(path).expect("Failed to open schema file"))
    }

    pub fn to_source_map(&self) -> HashMap<String, HashSet<String>> {
        let mut dependencies_map: HashMap<String, HashSet<String>> = HashMap::new();
        for ts in &self.type_sources {
            let full_name = ts.name.join("::");
            dependencies_map
                .entry(ts.source.clone())
                .or_default()
                .insert(full_name);
        }
        dependencies_map
    }
}

#[derive(Deserialize, Debug)]
pub struct TypeSource {
    /// The components of the name, e.g., ["std", "string"]
    pub name: Vec<String>,
    /// The name of the dependency library it comes from
    pub source: String,
}
