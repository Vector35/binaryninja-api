use std::collections::HashMap;
use binaryninja::collaboration::{register_conflict_splitter, ConflictSplitter, MergeConflict};
use binaryninja::database::kvs::KeyValueStore;
use binaryninja::rc::Ref;

pub struct ConflictHandler {}

impl ConflictHandler {
    pub fn register() {
        register_conflict_splitter(ConflictHandler {});
    }
}

impl ConflictSplitter for ConflictHandler {
    fn name(&self) -> String {
        "WARPFunctionGUIDIgnorer".to_string()
    }

    fn can_split(&mut self, key: &str, _conflict: &MergeConflict) -> bool {
        key.ends_with("/warp_function_guid")
    }

    fn split(&mut self, _original_key: &str, original_conflict: &MergeConflict, _result: &KeyValueStore) -> Option<HashMap<String, Ref<MergeConflict>>> {
        // If there's a conflict on these, we should just delete them
        original_conflict.success(None).ok()?;
        Some(HashMap::new())
    }
}
