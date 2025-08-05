use std::borrow::Cow;
use std::collections::HashMap;

use anyhow::Result;

use idb_rs::addr_info::all_address_info;
use idb_rs::id0::{ID0Section, Netdelta};
use idb_rs::id1::ID1Section;
use idb_rs::id2::ID2Section;
use idb_rs::{til, Address, IDAKind};

#[derive(Default)]
pub struct AddrInfo<'a> {
    // TODO does binja differentiate comments types on the API?
    pub comments: Vec<Vec<u8>>,
    pub label: Option<Cow<'a, [u8]>>,
    // TODO make this a ref
    pub ty: Option<til::Type>,
}

pub fn get_info<'a, K: IDAKind>(
    id0: &'a ID0Section<K>,
    id1: &ID1Section,
    id2: Option<&ID2Section<K>>,
    netdelta: Netdelta<K>,
) -> Result<HashMap<Address<K>, AddrInfo<'a>>> {
    let mut addr_info: HashMap<Address<K>, AddrInfo> = HashMap::new();

    // comments defined on the address information
    for (info, _info_size) in all_address_info(id0, id1, id2, netdelta) {
        let entry = addr_info.entry(info.address()).or_default();
        if let Some(comment) = info.comment() {
            entry.comments.push(comment.to_vec());
        }
        if let Some(comment) = info.comment_repeatable() {
            entry.comments.push(comment.to_vec());
        }
        if let Some(comment) = info.comment_pre() {
            entry.comments.extend(comment.map(|line| line.to_vec()));
        }
        if let Some(comment) = info.comment_post() {
            entry.comments.extend(comment.map(|line| line.to_vec()));
        }
        if let Some(label) = info.label()? {
            entry.label = Some(label);
        }
        if let Some(ty) = info.tinfo()? {
            entry.ty = Some(ty);
        }
    }

    Ok(addr_info)
}
