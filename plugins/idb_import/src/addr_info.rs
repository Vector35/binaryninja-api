use std::collections::HashMap;

use anyhow::Result;

use idb_rs::addr_info::all_address_info;
use idb_rs::id0::{ID0Section, RootInfo};
use idb_rs::id1::ID1Section;
use idb_rs::id2::ID2Section;
use idb_rs::{til, Address, IDAKind, IDBString};

#[derive(Default)]
pub struct AddrInfo {
    // TODO does binja differentiate comments types on the API?
    pub comments: Vec<IDBString>,
    pub label: Option<IDBString>,
    // TODO make this a ref
    pub ty: Option<til::Type>,
}

pub fn get_info<K: IDAKind>(
    id0: &ID0Section<K>,
    id1: &ID1Section<K>,
    id2: Option<&ID2Section<K>>,
    root_info: &RootInfo<K>,
) -> Result<HashMap<Address<K>, AddrInfo>> {
    let mut addr_info: HashMap<Address<K>, AddrInfo> = HashMap::new();

    // comments defined on the address information
    let netdelta = root_info.netdelta();
    for (info, _info_size) in all_address_info(id0, id1, id2, netdelta) {
        let entry = addr_info.entry(info.address()).or_default();
        if let Some(comment) = info.comment() {
            entry.comments.push(comment.to_idb_string());
        }
        if let Some(comment) = info.comment_repeatable() {
            entry.comments.push(comment.to_idb_string());
        }
        if let Some(comment) = info.comment_pre() {
            entry
                .comments
                .extend(comment.map(|line| line.to_idb_string()));
        }
        if let Some(comment) = info.comment_post() {
            entry
                .comments
                .extend(comment.map(|line| line.to_idb_string()));
        }
        if let Some(label) = info.label()? {
            entry.label = Some(label);
        }
        if let Some(ty) = info.tinfo(root_info)? {
            entry.ty = Some(ty);
        }
    }

    Ok(addr_info)
}
