use std::collections::HashMap;

use anyhow::Result;

use idb_rs::id0::ID0Section;
use idb_rs::til;

#[derive(Default)]
pub struct AddrInfo<'a> {
    // TODO does binja diferenciate comments types on the API?
    pub comments: Vec<&'a [u8]>,
    pub label: Option<&'a str>,
    // TODO make this a ref
    pub ty: Option<til::Type>,
}

pub fn get_info(id0: &ID0Section, version: u16) -> Result<HashMap<u64, AddrInfo<'_>>> {
    let mut addr_info: HashMap<u64, AddrInfo> = HashMap::new();

    // the old style comments, most likely empty on new versions
    let old_comments = id0.functions_and_comments()?.filter_map(|fc| {
        use idb_rs::id0::FunctionsAndComments::*;
        match fc {
            Err(e) => Some(Err(e)),
            Ok(Comment { address, comment }) => Some(Ok((address, comment))),
            Ok(Name | Function(_) | Unknown { .. }) => None,
        }
    });
    for old_comment in old_comments {
        let (addr, comment) = old_comment?;
        let comment = comment.message();
        addr_info.entry(addr).or_default().comments.push(comment);
    }

    // comments defined on the address information
    for info in id0.address_info(version)? {
        use idb_rs::id0::AddressInfo::*;
        let (addr, info) = info?;
        let entry = addr_info.entry(addr).or_default();
        match info {
            Comment(comments) => entry.comments.push(comments.message()),
            Label(name) => {
                if let Some(_old) = entry.label.replace(name) {
                    panic!("Duplicated label for an address should be impossible this is most likelly a programing error")
                }
            }
            TilType(ty) => {
                if let Some(_old) = entry.ty.replace(ty) {
                    panic!("Duplicated type for an address should be impossible this is most likelly a programing error")
                }
            }
            Other { .. } => {}
        }
    }

    Ok(addr_info)
}
