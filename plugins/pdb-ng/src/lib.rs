// Copyright 2022-2024 Vector 35 Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#![allow(dead_code)]

use std::collections::HashMap;
use std::env::{current_dir, current_exe, temp_dir};
use std::io::Cursor;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::mpsc;
use std::{env, fs};

use anyhow::{anyhow, Result};
use log::{debug, error, info};
use pdb::PDB;

use binaryninja::binary_view::{BinaryView, BinaryViewBase, BinaryViewExt};
use binaryninja::debuginfo::{CustomDebugInfoParser, DebugInfo, DebugInfoParser};
use binaryninja::download_provider::{DownloadInstanceInputOutputCallbacks, DownloadProvider};
use binaryninja::interaction::{MessageBoxButtonResult, MessageBoxButtonSet};
use binaryninja::logger::Logger;
use binaryninja::settings::{QueryOptions, Settings};
use binaryninja::string::BnString;
use binaryninja::{interaction, user_directory};
use parser::PDBParserInstance;

/// PDB Parser!!
///
/// General project structure:
/// - lib.rs: Interaction with DebugInfoParser and plugin actions
/// - parser.rs: PDB Parser base functionality, puts the internal structures into the DebugInfo
/// - type_parser.rs: Parses all the TPI type stream information into both named and indexed types
/// - symbol_parser.rs: Parses, one module at a time, symbol information into named symbols
/// - struct_grouper.rs: Ugly algorithm for handling union and structure members
mod parser;
mod struct_grouper;
mod symbol_parser;
mod type_parser;

// struct PDBLoad;
// struct PDBLoadFile;
// struct PDBSetSymbolPath;

#[allow(dead_code)]
struct PDBInfo {
    path: String,
    file_name: String,
    age: u32,
    guid: Vec<u8>,
    guid_age_string: String,
}

fn is_pdb(view: &BinaryView) -> bool {
    let pdb_magic_bytes = "Microsoft C/C++ MSF 7.00\r\n\x1A\x44\x53\x00\x00\x00";
    if let Some(raw_view) = view.raw_view() {
        raw_view.read_vec(0, pdb_magic_bytes.len()) == pdb_magic_bytes.as_bytes()
    } else {
        false
    }
}

fn default_local_cache() -> Result<String> {
    // The default value is a directory named "sym" immediately below the program directory
    // of the calling application. This is sometimes referred to as the default local cache.
    let current_path = current_exe()?;
    let parent_path = current_path
        .parent()
        .ok_or_else(|| anyhow!("No parent to current exe"))?;
    let mut cache_path = PathBuf::from(parent_path);
    cache_path.push("sym");
    return Ok(cache_path
        .to_str()
        .ok_or_else(|| anyhow!("Could not convert cache path to string"))?
        .to_string());
}

fn active_local_cache(view: Option<&BinaryView>) -> Result<String> {
    // Check the local symbol store
    let mut settings_query_options = view.map(QueryOptions::new_with_view).unwrap_or_default();
    let settings = Settings::new();
    let mut local_store_path = settings
        .get_string_with_opts("pdb.files.localStoreAbsolute", &mut settings_query_options)
        .to_string();
    if local_store_path.is_empty() {
        let relative_local_store = settings
            .get_string_with_opts("pdb.files.localStoreRelative", &mut settings_query_options)
            .to_string();
        local_store_path = user_directory()
            .join(relative_local_store)
            .to_string_lossy()
            .to_string();
    }
    if !local_store_path.is_empty() {
        Ok(local_store_path)
    } else if let Ok(default_cache) = default_local_cache() {
        Ok(default_cache)
    } else if let Ok(current) = current_dir().map(|d| {
        d.to_str()
            .expect("Expected current dir to be a valid string")
            .to_string()
    }) {
        Ok(current)
    } else {
        Ok(temp_dir()
            .to_str()
            .expect("Expected temp dir to be a valid string")
            .to_string())
    }
}

fn parse_sym_srv(symbol_path: &str, default_store: String) -> Result<impl Iterator<Item = String>> {
    // https://docs.microsoft.com/en-us/windows/win32/debug/using-symsrv
    // Why

    // ... the symbol path (_NT_SYMBOL_PATH environment variable) can be made up of several path
    // elements separated by semicolons. If any one or more of these path elements begins with
    // the text "srv*", then the element is a symbol server and will use SymSrv to locate
    // symbol files.

    // If the "srv*" text is not specified but the actual path element is a symbol server store,
    // then the symbol handler will act as if "srv*" were specified. The symbol handler makes
    // this determination by searching for the existence of a file called "pingme.txt" in
    // the root directory of the specified path.

    // ... symbol servers are made up of symbol store elements separated by asterisks. There can
    // be up to 10 symbol stores after the "srv*" prefix.

    let mut sym_srv_results: Vec<String> = vec![];

    // 'path elements separated by semicolons'
    for path_element in symbol_path.split(';') {
        // 'begins with the text "srv*"'
        if path_element.to_lowercase().starts_with("srv*") {
            // 'symbol store elements separated by asterisks'
            for store_element in path_element[4..].split('*') {
                if store_element.is_empty() {
                    sym_srv_results.push(default_store.clone());
                } else {
                    sym_srv_results.push(store_element.to_string());
                }
            }
        } else if PathBuf::from(path_element).exists() {
            // 'searching for the existence of a file called "pingme.txt" in the root directory'
            let pingme_txt = path_element.to_string() + "/" + "pingme.txt";
            if PathBuf::from(pingme_txt).exists() {
                sym_srv_results.push(path_element.to_string());
            }
        }
    }

    Ok(sym_srv_results.into_iter())
}

fn read_from_sym_store(bv: &BinaryView, path: &str) -> Result<(bool, Vec<u8>)> {
    if !path.contains("://") {
        // Local file
        info!("Read local file: {}", path);
        let conts = fs::read(path)?;
        return Ok((false, conts));
    }

    let mut query_options = QueryOptions::new_with_view(bv);
    if !Settings::new().get_bool_with_opts("network.pdbAutoDownload", &mut query_options) {
        return Err(anyhow!("Auto download disabled"));
    }

    // Download from remote
    let (tx, rx) = mpsc::channel();
    let write = move |data: &[u8]| -> usize {
        if tx.send(Vec::from(data)).is_ok() {
            data.len()
        } else {
            0
        }
    };

    info!("GET: {}", path);

    let dp =
        DownloadProvider::try_default().map_err(|_| anyhow!("No default download provider"))?;
    let mut inst = dp
        .create_instance()
        .map_err(|_| anyhow!("Couldn't create download instance"))?;
    let result = inst
        .perform_custom_request(
            "GET",
            path,
            HashMap::<BnString, BnString>::new(),
            DownloadInstanceInputOutputCallbacks {
                read: None,
                write: Some(Box::new(write)),
                progress: None,
            },
        )
        .map_err(|e| anyhow!(e.to_string()))?;
    if result.status_code != 200 {
        return Err(anyhow!("Path does not exist"));
    }

    let mut expected_length = None;
    for (k, v) in result.headers.iter() {
        if k.to_lowercase() == "content-length" {
            expected_length = Some(usize::from_str(v)?);
        }
    }

    let mut data = vec![];
    while let Ok(packet) = rx.try_recv() {
        data.extend(packet.into_iter());
    }

    if let Some(length) = expected_length {
        if data.len() != length {
            return Err(anyhow!(format!(
                "Bad length: expected {} got {}",
                length,
                data.len()
            )));
        }
    }

    Ok((true, data))
}

fn search_sym_store(
    bv: &BinaryView,
    store_path: String,
    pdb_info: &PDBInfo,
) -> Result<Option<Vec<u8>>> {
    // https://www.technlg.net/windows/symbol-server-path-windbg-debugging/
    // For symbol servers, to identify the files path easily, Windbg uses the format
    // binaryname.pdb/GUID

    // Doesn't actually say what the format is, just gives an example:
    // https://docs.microsoft.com/en-us/windows/win32/debug/using-symstore
    // In this example, the lookup path for the acpi.dbg symbol file might look something
    // like this: \\mybuilds\symsrv\acpi.dbg\37cdb03962040.
    let base_path = store_path + "/" + &pdb_info.file_name + "/" + &pdb_info.guid_age_string;

    // Three files may exist inside the lookup directory:
    // 1. If the file was stored, then acpi.dbg will exist there.
    // 2. If a pointer was stored, then a file called file.ptr will exist and contain the path
    // to the actual symbol file.
    // 3. A file called refs.ptr, which contains a list of all the current locations for
    // acpi.dbg with this timestamp and image size that are currently added to the
    // symbol store.

    // We don't care about #3 because it says we don't

    let direct_path = base_path.clone() + "/" + &pdb_info.file_name;
    if let Ok((_remote, conts)) = read_from_sym_store(bv, &direct_path) {
        return Ok(Some(conts));
    }

    let file_ptr = base_path.clone() + "/" + "file.ptr";
    if let Ok((_remote, conts)) = read_from_sym_store(bv, &file_ptr) {
        let path = String::from_utf8(conts)?;
        // PATH:https://full/path
        if let Some(stripped) = path.strip_prefix("PATH:") {
            if let Ok((_remote, conts)) = read_from_sym_store(bv, stripped) {
                return Ok(Some(conts));
            }
        }
    }

    Ok(None)
}

fn parse_pdb_info(view: &BinaryView) -> Option<PDBInfo> {
    match view.get_metadata::<u64, _>("DEBUG_INFO_TYPE") {
        Some(Ok(0x53445352 /* 'SDSR' */)) => {}
        _ => return None,
    }

    // This is stored in the BV by the PE loader
    let file_path = match view.get_metadata::<String, _>("PDB_FILENAME") {
        Some(Ok(md)) => md,
        _ => return None,
    };
    let mut guid = match view.get_metadata::<Vec<u8>, _>("PDB_GUID") {
        Some(Ok(md)) => md,
        _ => return None,
    };
    let age = match view.get_metadata::<u64, _>("PDB_AGE") {
        Some(Ok(md)) => md as u32,
        _ => return None,
    };

    if guid.len() != 16 {
        return None;
    }

    // struct _GUID {
    //     uint32_t Data1;
    //     uint16_t Data2;
    //     uint16_t Data3;
    //     uint8_t  Data4[8];
    // };

    // Endian swap
    // Data1
    guid.swap(0, 3);
    guid.swap(1, 2);
    // Data2
    guid.swap(4, 5);
    // Data3
    guid.swap(6, 7);

    let guid_age_string = guid
        .iter()
        .take(16)
        .map(|ch| format!("{:02X}", ch))
        .collect::<Vec<_>>()
        .join("")
        + &format!("{:X}", age);

    // Just assume all the paths are /
    let file_path = if cfg!(windows) {
        file_path
    } else {
        file_path.replace("\\", "/")
    };
    let path = file_path;
    let file_name = if let Some(idx) = path.rfind("\\") {
        path[(idx + 1)..].to_string()
    } else if let Some(idx) = path.rfind("/") {
        path[(idx + 1)..].to_string()
    } else {
        path.clone()
    };

    Some(PDBInfo {
        path,
        file_name,
        age,
        guid,
        guid_age_string,
    })
}

struct PDBParser;
impl PDBParser {
    fn load_from_file(
        &self,
        conts: &Vec<u8>,
        debug_info: &mut DebugInfo,
        view: &BinaryView,
        progress: &dyn Fn(usize, usize) -> Result<(), ()>,
        check_guid: bool,
        did_download: bool,
    ) -> Result<()> {
        let mut pdb = PDB::open(Cursor::new(&conts))?;

        let settings = Settings::new();
        let mut settings_query_opts = QueryOptions::new_with_view(view);

        if let Some(info) = parse_pdb_info(view) {
            let pdb_info = &pdb.pdb_information()?;
            if info.guid.as_slice() != pdb_info.guid.as_bytes() {
                if check_guid {
                    return Err(anyhow!("PDB GUID does not match"));
                } else {
                    let ask = settings.get_string_with_opts(
                        "pdb.features.loadMismatchedPDB",
                        &mut settings_query_opts,
                    );

                    match ask.as_str() {
                        "true" => {},
                        "ask" => {
                            if interaction::show_message_box(
                                "Mismatched PDB",
                                "This PDB does not look like it matches your binary. Do you want to load it anyway?",
                                MessageBoxButtonSet::YesNoButtonSet,
                                binaryninja::interaction::MessageBoxIcon::QuestionIcon
                            ) == MessageBoxButtonResult::NoButton {
                                return Err(anyhow!("User cancelled mismatched load"));
                            }
                        }
                        _ => {
                            return Err(anyhow!("PDB GUID does not match"));
                        }
                    }
                }
            }

            // Microsoft's symbol server sometimes gives us a different version of the PDB
            // than what we ask for. It's weird, but if they're doing it, I trust it will work.
            if info.age != pdb_info.age {
                if info.age > pdb_info.age {
                    // Have not seen this case, so I'm not sure if this is fatal
                    info!("PDB age is older than our binary! Loading it anyway, but there may be missing information.");
                } else {
                    info!("PDB age is newer than our binary! Loading it anyway, there probably shouldn't be any issues.");
                }
            }

            if did_download && settings.get_bool("pdb.files.localStoreCache") {
                match active_local_cache(Some(view)) {
                    Ok(cache) => {
                        let mut cab_path = PathBuf::from(&cache);
                        cab_path.push(&info.file_name);
                        cab_path.push(
                            pdb_info
                                .guid
                                .as_bytes()
                                .iter()
                                .map(|ch| format!("{:02X}", ch))
                                .collect::<Vec<_>>()
                                .join("")
                                + &format!("{:X}", pdb_info.age),
                        );
                        let has_dir = if cab_path.is_dir() {
                            true
                        } else {
                            match fs::create_dir_all(&cab_path) {
                                Ok(_) => true,
                                Err(e) => {
                                    error!("Could not create PDB cache dir: {}", e);
                                    false
                                }
                            }
                        };
                        if has_dir {
                            cab_path.push(&info.file_name);
                            match fs::write(&cab_path, conts) {
                                Ok(_) => {
                                    info!("Downloaded to: {}", cab_path.to_string_lossy());
                                }
                                Err(e) => error!("Could not write PDB to cache: {}", e),
                            }
                        }

                        // Also write with the age we expect in our binary view
                        if info.age < pdb_info.age {
                            let mut cab_path = PathBuf::from(&cache);
                            cab_path.push(&info.file_name);
                            cab_path.push(
                                pdb_info
                                    .guid
                                    .as_bytes()
                                    .iter()
                                    .map(|ch| format!("{:02X}", ch))
                                    .collect::<Vec<_>>()
                                    .join("")
                                    + &format!("{:X}", info.age), // XXX: BV's pdb age
                            );
                            let has_dir = if cab_path.is_dir() {
                                true
                            } else {
                                match fs::create_dir_all(&cab_path) {
                                    Ok(_) => true,
                                    Err(e) => {
                                        error!("Could not create PDB cache dir: {}", e);
                                        false
                                    }
                                }
                            };
                            if has_dir {
                                cab_path.push(&info.file_name);
                                match fs::write(&cab_path, conts) {
                                    Ok(_) => {
                                        info!("Downloaded to: {}", cab_path.to_string_lossy());
                                    }
                                    Err(e) => error!("Could not write PDB to cache: {}", e),
                                }
                            }
                        }
                    }
                    Err(e) => error!("Could not get local cache for writing: {}", e),
                }
            }
        } else {
            if check_guid {
                return Err(anyhow!("File not compiled with PDB information"));
            } else {
                let ask = settings.get_string_with_opts(
                    "pdb.features.loadMismatchedPDB",
                    &mut settings_query_opts,
                );

                match ask.as_str() {
                    "true" => {},
                    "ask" => {
                        if interaction::show_message_box(
                            "No PDB Information",
                            "This file does not look like it was compiled with a PDB, so your PDB might not correctly apply to the analysis. Do you want to load it anyway?",
                            MessageBoxButtonSet::YesNoButtonSet,
                            binaryninja::interaction::MessageBoxIcon::QuestionIcon
                        ) == MessageBoxButtonResult::NoButton {
                            return Err(anyhow!("User cancelled missing info load"));
                        }
                    }
                    _ => {
                        return Err(anyhow!("File not compiled with PDB information"));
                    }
                }
            }
        }

        let mut inst = match PDBParserInstance::new(debug_info, view, pdb) {
            Ok(inst) => {
                info!("Loaded PDB, parsing...");
                inst
            }
            Err(e) => {
                error!("Could not open PDB: {}", e);
                return Err(e);
            }
        };
        match inst.try_parse_info(Box::new(|cur, max| {
            (*progress)(cur, max).map_err(|_| anyhow!("Cancelled"))
        })) {
            Ok(()) => {
                info!("Parsed pdb");
                Ok(())
            }
            Err(e) => {
                error!("Could not parse PDB: {}", e);
                if e.to_string() == "Todo" {
                    Ok(())
                } else {
                    Err(e)
                }
            }
        }
    }
}

impl CustomDebugInfoParser for PDBParser {
    fn is_valid(&self, view: &BinaryView) -> bool {
        view.type_name().to_string() == "PE" || is_pdb(view)
    }

    fn parse_info(
        &self,
        debug_info: &mut DebugInfo,
        view: &BinaryView,
        debug_file: &BinaryView,
        progress: Box<dyn Fn(usize, usize) -> Result<(), ()>>,
    ) -> bool {
        if is_pdb(debug_file) {
            match self.load_from_file(
                &debug_file.read_vec(0, debug_file.len() as usize),
                debug_info,
                view,
                &progress,
                false,
                false,
            ) {
                Ok(_) => return true,
                Err(e) if e.to_string() == "Cancelled" => return false,
                Err(_) => {
                    error!("Chosen PDB file failed to load");
                    return false;
                }
            }
        }

        // See if we can get pdb info from the view
        if let Some(info) = parse_pdb_info(view) {
            // First, check _NT_SYMBOL_PATH
            if let Ok(sym_path) = env::var("_NT_SYMBOL_PATH") {
                let stores = if let Ok(default_cache) = active_local_cache(Some(view)) {
                    parse_sym_srv(&sym_path, default_cache)
                } else {
                    Err(anyhow!("No local cache found"))
                };
                if let Ok(stores) = stores {
                    for store in stores {
                        match search_sym_store(view, store.clone(), &info) {
                            Ok(Some(conts)) => {
                                match self
                                    .load_from_file(&conts, debug_info, view, &progress, true, true)
                                {
                                    Ok(_) => return true,
                                    Err(e) if e.to_string() == "Cancelled" => return false,
                                    Err(e) => debug!("Skipping, {}", e.to_string()),
                                }
                            }
                            Ok(None) => {}
                            e => error!("Error searching symbol store {}: {:?}", store, e),
                        }
                    }
                }
            }

            // Does the raw path just exist?
            if PathBuf::from(&info.path).exists() {
                match fs::read(&info.path) {
                    Ok(conts) => match self
                        .load_from_file(&conts, debug_info, view, &progress, true, false)
                    {
                        Ok(_) => return true,
                        Err(e) if e.to_string() == "Cancelled" => return false,
                        Err(e) => debug!("Skipping, {}", e.to_string()),
                    },
                    Err(e) if e.to_string() == "Cancelled" => return false,
                    Err(e) => debug!("Could not read pdb: {}", e.to_string()),
                }
            }

            // Try in the same directory as the file
            let mut potential_path = PathBuf::from(view.file().filename().to_string());
            potential_path.pop();
            potential_path.push(&info.file_name);
            if potential_path.exists() {
                match fs::read(
                    potential_path
                        .to_str()
                        .expect("Potential path is a real string"),
                ) {
                    Ok(conts) => match self
                        .load_from_file(&conts, debug_info, view, &progress, true, false)
                    {
                        Ok(_) => return true,
                        Err(e) if e.to_string() == "Cancelled" => return false,
                        Err(e) => debug!("Skipping, {}", e.to_string()),
                    },
                    Err(e) if e.to_string() == "Cancelled" => return false,
                    Err(e) => debug!("Could not read pdb: {}", e.to_string()),
                }
            }

            // Check the local symbol store
            if let Ok(local_store_path) = active_local_cache(Some(view)) {
                match search_sym_store(view, local_store_path.clone(), &info) {
                    Ok(Some(conts)) => {
                        match self.load_from_file(&conts, debug_info, view, &progress, true, false)
                        {
                            Ok(_) => return true,
                            Err(e) if e.to_string() == "Cancelled" => return false,
                            Err(e) => debug!("Skipping, {}", e.to_string()),
                        }
                    }
                    Ok(None) => {}
                    e => error!(
                        "Error searching local symbol store {}: {:?}",
                        local_store_path, e
                    ),
                }
            }

            // Next, try downloading from all symbol servers in the server list
            let mut query_options = QueryOptions::new_with_view(view);
            let server_list = Settings::new()
                .get_string_list_with_opts("pdb.files.symbolServerList", &mut query_options);

            for server in server_list.iter() {
                match search_sym_store(view, server.to_string(), &info) {
                    Ok(Some(conts)) => {
                        match self.load_from_file(&conts, debug_info, view, &progress, true, true) {
                            Ok(_) => return true,
                            Err(e) if e.to_string() == "Cancelled" => return false,
                            Err(e) => debug!("Skipping, {}", e.to_string()),
                        }
                    }
                    Ok(None) => {}
                    e => error!("Error searching remote symbol server {}: {:?}", server, e),
                }
            }
        }
        false
    }
}

#[cfg(not(feature = "demo"))]
#[no_mangle]
pub extern "C" fn CorePluginDependencies() {
    use binaryninja::add_optional_plugin_dependency;
    add_optional_plugin_dependency("view_pe");
}

#[cfg(not(feature = "demo"))]
#[no_mangle]
pub extern "C" fn CorePluginInit() -> bool {
    init_plugin()
}

#[cfg(feature = "demo")]
#[no_mangle]
pub extern "C" fn PDBPluginInit() -> bool {
    init_plugin()
}

fn init_plugin() -> bool {
    Logger::new("PDB").init();
    DebugInfoParser::register("PDB", PDBParser {});

    let settings = Settings::new();
    settings.register_group("pdb", "PDB Loader");
    settings.register_setting_json(
        "pdb.files.localStoreAbsolute",
        r#"{
            "title" : "Local Symbol Store Absolute Path",
            "type" : "string",
            "default" : "",
            "aliases" : ["pdb.local-store-absolute", "pdb.localStoreAbsolute"],
            "description" : "Absolute path specifying where the PDB symbol store exists on this machine, overrides relative path.",
            "ignore" : []
        }"#,
    );

    settings.register_setting_json(
        "pdb.files.localStoreRelative",
        r#"{
            "title" : "Local Symbol Store Relative Path",
            "type" : "string",
            "default" : "symbols",
            "aliases" : ["pdb.local-store-relative", "pdb.localStoreRelative"],
            "description" : "Path *relative* to the binaryninja _user_ directory, specifying the pdb symbol store. If the Local Symbol Store Absolute Path is specified, this is ignored.",
            "ignore" : []
        }"#,
    );

    settings.register_setting_json(
        "pdb.files.localStoreCache",
        r#"{
            "title" : "Cache Downloaded PDBs in Local Store",
            "type" : "boolean",
            "default" : true,
            "aliases" : ["pdb.localStoreCache"],
            "description" : "Store PDBs downloaded from Symbol Servers in the local Symbol Store Path.",
            "ignore" : []
        }"#,
    );

    settings.register_setting_json(
        "network.pdbAutoDownload",
        r#"{
            "title" : "Enable Auto Downloading PDBs",
            "type" : "boolean",
            "default" : true,
            "aliases" : ["pdb.autoDownload", "pdb.auto-download-pdb"],
            "description" : "Automatically search for and download pdb files from specified symbol servers.",
            "ignore" : []
        }"#,
    );

    settings.register_setting_json(
        "pdb.files.symbolServerList",
        r#"{
            "title" : "Symbol Server List",
            "type" : "array",
            "sorted" : false,
            "default" : ["https://msdl.microsoft.com/download/symbols"],
            "aliases" : ["pdb.symbol-server-list", "pdb.symbolServerList"],
            "description" : "List of servers to query for pdb symbols.",
            "ignore" : []
        }"#,
    );

    settings.register_setting_json(
        "pdb.features.expandRTTIStructures",
        r#"{
            "title" : "Expand RTTI Structures",
            "type" : "boolean",
            "default" : true,
            "aliases" : ["pdb.expandRTTIStructures"],
            "description" : "Create structures for RTTI symbols with variable-sized names and arrays.",
            "ignore" : []
        }"#,
    );

    settings.register_setting_json(
        "pdb.features.generateVTables",
        r#"{
            "title" : "Generate Virtual Table Structures",
            "type" : "boolean",
            "default" : true,
            "aliases" : ["pdb.generateVTables"],
            "description" : "Create Virtual Table (VTable) structures for C++ classes found when parsing.",
            "ignore" : []
        }"#,
    );

    settings.register_setting_json(
        "pdb.features.loadGlobalSymbols",
        r#"{
            "title" : "Load Global Module Symbols",
            "type" : "boolean",
            "default" : true,
            "aliases" : ["pdb.loadGlobalSymbols"],
            "description" : "Load symbols in the Global module of the PDB. These symbols have generally lower quality types due to relying on the demangler.",
            "ignore" : []
        }"#,
    );

    settings.register_setting_json(
        "pdb.features.allowUnnamedVoidSymbols",
        r#"{
            "title" : "Allow Unnamed Untyped Symbols",
            "type" : "boolean",
            "default" : false,
            "aliases" : ["pdb.allowUnnamedVoidSymbols"],
            "description" : "Allow creation of symbols with no name and void types, often used as static local variables. Generally, these are just noisy and not relevant.",
            "ignore" : []
        }"#,
    );

    settings.register_setting_json(
        "pdb.features.allowVoidGlobals",
        r#"{
            "title" : "Allow Untyped Symbols",
            "type" : "boolean",
            "default" : true,
            "aliases" : ["pdb.allowVoidGlobals"],
            "description" : "Allow creation of symbols that have no type, and will be created as void-typed symbols. Generally, this happens in a stripped PDB when a Global symbol's mangled name does not contain type information.",
            "ignore" : []
        }"#,
    );

    settings.register_setting_json(
        "pdb.features.createMissingNamedTypes",
        r#"{
            "title" : "Create Missing Named Types",
            "type" : "boolean",
            "default" : true,
            "aliases" : ["pdb.createMissingNamedTypes"],
            "description" : "Allow creation of types named by function signatures which are not found in the PDB's types list or the Binary View. These types are usually found in stripped PDBs that have no type information but function signatures reference the stripped types.",
            "ignore" : []
        }"#,
    );

    settings.register_setting_json(
        "pdb.features.loadMismatchedPDB",
        r#"{
            "title" : "Load Mismatched PDB",
            "type" : "string",
            "default" : "ask",
            "enum" : ["true", "ask", "false"],
            "enumDescriptions" : [
                "Always load the PDB",
                "Use the Interaction system to ask if the PDB should be loaded",
                "Never load the PDB"
            ],
            "aliases" : [],
            "description" : "If a manually loaded PDB has a mismatched GUID, should it be loaded?",
            "ignore" : []
        }"#,
    );

    settings.register_setting_json(
        "pdb.features.parseSymbols",
        r#"{
            "title" : "Parse PDB Symbols",
            "type" : "boolean",
            "default" : true,
            "aliases" : [],
            "description" : "Parse Symbol names and types. If you turn this off, you will only load Types.",
            "ignore" : []
        }"#,
    );

    true
}

#[test]
fn test_default_cache_path() {
    println!("{:?}", default_local_cache());
}

#[test]
fn test_sym_srv() {
    assert_eq!(
        parse_sym_srv(
            &r"srv*\\mybuilds\mysymbols".to_string(),
            r"DEFAULT_STORE".to_string()
        )
        .expect("parse success")
        .collect::<Vec<_>>(),
        vec![r"\\mybuilds\mysymbols".to_string()]
    );
    assert_eq!(
        parse_sym_srv(
            &r"srv*c:\localsymbols*\\mybuilds\mysymbols".to_string(),
            r"DEFAULT_STORE".to_string()
        )
        .expect("parse success")
        .collect::<Vec<_>>(),
        vec![
            r"c:\localsymbols".to_string(),
            r"\\mybuilds\mysymbols".to_string()
        ]
    );
    assert_eq!(
        parse_sym_srv(
            &r"srv**\\mybuilds\mysymbols".to_string(),
            r"DEFAULT_STORE".to_string()
        )
        .expect("parse success")
        .collect::<Vec<_>>(),
        vec![
            r"DEFAULT_STORE".to_string(),
            r"\\mybuilds\mysymbols".to_string()
        ]
    );
    assert_eq!(
        parse_sym_srv(
            &r"srv*c:\localsymbols*\\NearbyServer\store*https://DistantServer".to_string(),
            r"DEFAULT_STORE".to_string()
        )
        .expect("parse success")
        .collect::<Vec<_>>(),
        vec![
            r"c:\localsymbols".to_string(),
            r"\\NearbyServer\store".to_string(),
            r"https://DistantServer".to_string()
        ]
    );
    assert_eq!(
        parse_sym_srv(
            &r"srv*c:\DownstreamStore*https://msdl.microsoft.com/download/symbols".to_string(),
            r"DEFAULT_STORE".to_string()
        )
        .expect("parse success")
        .collect::<Vec<_>>(),
        vec![
            r"c:\DownstreamStore".to_string(),
            r"https://msdl.microsoft.com/download/symbols".to_string()
        ]
    );
}
