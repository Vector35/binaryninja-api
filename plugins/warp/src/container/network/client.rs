use crate::container::network::NetworkTargetId;
use crate::container::{
    ContainerSearchItem, ContainerSearchItemKind, ContainerSearchQuery, ContainerSearchResponse,
    SourceId, SourcePath, SourceTag,
};
use base64::Engine;
use binaryninja::download::DownloadProvider;
use serde::Deserialize;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::str::FromStr;
use uuid::Uuid;
use warp::chunk::ChunkKind;
use warp::r#type::guid::TypeGUID;
use warp::r#type::{ComputedType, Type};
use warp::signature::constraint::ConstraintGUID;
use warp::signature::function::{Function, FunctionGUID};
use warp::target::Target;
use warp::WarpFile;

/// Responsible for sending and receiving data from the server.
///
/// NOTE: **All requests are blocking**.
#[derive(Clone, Debug)]
pub struct NetworkClient {
    provider: DownloadProvider,
    headers: Vec<(String, String)>,
    pub server_url: String,
}

impl NetworkClient {
    pub fn new(server_url: String, server_token: Option<String>) -> Self {
        // TODO: This might want to be kept for the request header?
        let mut headers: Vec<(String, String)> =
            vec![("Content-Encoding".to_string(), "gzip".to_string())];
        if let Some(token) = &server_token {
            headers.push(("authorization".to_string(), format!("Bearer {}", token)));
        }
        // NOTE: Because we pull in the system certificates as well in the enterprise download provider
        // it is safe to assume that provider when available, so that we can connect to enterprise servers
        // when a client is running under an enterprise client build.
        let provider = DownloadProvider::get("_EnterpriseDownloadProvider").unwrap_or_else(|| {
            // Not running under an enterprise client, fallback to the default download provider.
            DownloadProvider::try_default().expect("No default download provider")
        });
        Self {
            provider,
            headers,
            // We place the '/' already in the materialized URLs we query, so strip it here.
            server_url: server_url
                .strip_suffix('/')
                .unwrap_or(&server_url)
                .to_string(),
        }
    }

    /// Check to see the status of the server.
    ///
    /// This is useful if you want to fail early and prevent constructing a network container to a
    /// server that is unresponsive.
    ///
    /// Route: `api/v1/status`
    pub fn status(&self) -> Result<(), String> {
        let status_url = format!("{}/api/v1/status", self.server_url);
        let mut inst = self.provider.create_instance().unwrap();
        let resp = inst.get(&status_url, self.headers.clone())?;
        match resp.is_success() {
            true => Ok(()),
            false => Err(format!("Server returned an error: {}", resp.status_code)),
        }
    }

    /// Query the logged in user.
    ///
    /// NOTE: **THIS IS BLOCKING**
    ///
    /// Route: `api/v1/users/me` (TODO: Comment about the query)
    pub fn current_user(&self) -> Result<(i32, String), String> {
        let current_user_url = format!("{}/api/v1/users/me", self.server_url);
        let mut inst = self.provider.create_instance().unwrap();

        #[derive(Deserialize)]
        struct CurrentUser {
            username: String,
            id: i32,
        }

        let resp = inst.get(&current_user_url, self.headers.clone())?;
        if !resp.is_success() {
            return Err(format!(
                "'{}' returned {}",
                current_user_url, resp.status_code
            ));
        }
        let user: CurrentUser = resp.json().map_err(|e| e.to_string())?;
        Ok((user.id, user.username))
    }

    /// Query the logged in user.
    ///
    /// NOTE: **THIS IS BLOCKING**
    ///
    /// Route: `api/v1/users/me` (TODO: Comment about the query)
    pub fn source_name(&self, id: SourceId) -> Result<String, String> {
        let source_url = format!("{}/api/v1/sources/{}", self.server_url, id);
        let mut inst = self.provider.create_instance().unwrap();

        #[derive(Deserialize)]
        struct Source {
            name: String,
        }

        let resp = inst.get(&source_url, self.headers.clone())?;
        if !resp.is_success() {
            return Err(format!("'{}' returned {}", source_url, resp.status_code));
        }
        let src: Source = resp.json().map_err(|e| e.to_string())?;
        Ok(src.name)
    }

    /// Create a new source with the given name.
    ///
    /// The current user will be added to the source.
    ///
    /// NOTE: You must be logged in to create a source.
    ///
    /// NOTE: **THIS IS BLOCKING**
    ///
    /// Route: `api/v1/sources/`
    pub fn create_source(&self, name: &str) -> Result<SourceId, String> {
        let source_url = format!("{}/api/v1/sources", self.server_url);
        let mut inst = self.provider.create_instance().unwrap();

        let body = json!({
            "name": name,
            // Passing nothing here will add the current user to the source.
            "user_ids": []
        });

        #[derive(Deserialize)]
        struct CreateSourceResponse {
            id: Uuid,
        }

        let resp = inst.post_json(&source_url, self.headers.clone(), &body)?;
        if !resp.is_success() {
            return Err(format!("'{}' returned {}", source_url, resp.status_code));
        }
        let parsed: CreateSourceResponse = resp.json().map_err(|e| e.to_string())?;
        Ok(SourceId(parsed.id))
    }

    /// Query the [`SourceId`]s for the given user.
    ///
    /// NOTE: **THIS IS BLOCKING**
    ///
    /// Route: `api/v1/sources/query` (TODO: Comment about the query)
    pub fn query_sources(&self, user_id: Option<i32>) -> Result<Vec<SourceId>, String> {
        let sources_url = format!("{}/api/v1/sources/query", self.server_url);
        let mut inst = self.provider.create_instance().unwrap();

        #[derive(Deserialize)]
        struct SourceItem {
            id: Uuid,
        }

        #[derive(Deserialize)]
        struct SourcesQueryResponse {
            items: Vec<SourceItem>,
        }

        let mut query = HashMap::new();
        if let Some(user_id) = user_id {
            query.insert("user_id", user_id);
        }

        let resp = inst.post_json(&sources_url, self.headers.clone(), &json!(query))?;
        if !resp.is_success() {
            return Err(format!("'{}' returned {}", sources_url, resp.status_code));
        }
        let parsed: SourcesQueryResponse = resp.json().map_err(|e| e.to_string())?;
        Ok(parsed.items.into_iter().map(|it| SourceId(it.id)).collect())
    }

    /// Query the [`NetworkTargetId`] for the given [`Target`].
    ///
    /// NOTE: **THIS IS BLOCKING**
    ///
    /// Route: `api/v1/targets/query` (TODO: Comment about the query)
    pub fn query_target_id(&self, target: &Target) -> Option<NetworkTargetId> {
        let query_target_url = format!("{}/api/v1/targets/query", self.server_url);
        let mut inst = self.provider.create_instance().unwrap();

        #[derive(Deserialize)]
        struct TargetQueryResponse {
            id: NetworkTargetId,
        }

        let mut query = HashMap::new();
        if let Some(platform) = &target.platform {
            query.insert("platform", platform);
        }
        if let Some(architecture) = &target.architecture {
            query.insert("arch", architecture);
        }

        let resp = inst
            .post_json(&query_target_url, self.headers.clone(), &json!(query))
            .ok()?;
        // Assuming the first response is the one we want.
        // TODO: Handle multiple responses, or error out.
        let json_response: Vec<TargetQueryResponse> = resp.json().ok()?;
        let first_response = json_response.first()?;

        Some(first_response.id)
    }

    fn query_functions_body(
        target: Option<NetworkTargetId>,
        source: Option<SourceId>,
        source_tags: &[SourceTag],
        guids: &[FunctionGUID],
        constraints: &[ConstraintGUID],
    ) -> serde_json::Value {
        let guids_str: HashSet<String> = guids.iter().map(|g| g.to_string()).collect();
        // TODO: The limit here needs to be somewhat flexible. But 1000 will do for now.
        let mut body = json!({
            "format": "flatbuffer",
            "guids": guids_str,
            "limit": 10000,
        });
        if let Some(target_id) = target {
            body["target_id"] = json!(target_id);
        }
        if let Some(source_id) = source {
            body["source_id"] = json!(source_id.to_string());
        }
        if !source_tags.is_empty() {
            body["source_tags"] = json!(source_tags);
        }
        if !constraints.is_empty() {
            let constraint_guids_str: HashSet<String> =
                constraints.iter().map(|g| g.to_string()).collect();
            body["constraints"] = json!(constraint_guids_str);
        }
        body
    }

    /// Query the functions, returning the warp file response containing the entries.
    ///
    /// NOTE: **THIS IS BLOCKING**
    ///
    /// Route: `api/v1/functions/query` (TODO: Comment about the query)
    pub fn query_functions(
        &self,
        target: Option<NetworkTargetId>,
        source: Option<SourceId>,
        guids: &[FunctionGUID],
        constraints: &[ConstraintGUID],
    ) -> Result<WarpFile<'static>, String> {
        let query_functions_url = format!("{}/api/v1/functions/query", self.server_url);
        // TODO: Allow for source tags? We really only need this in query_functions_source as that
        // TODO: is what prevents a undesired source from being "known" to the container.
        let payload = Self::query_functions_body(target, source, &[], guids, constraints);
        let mut inst = self.provider.create_instance().unwrap();
        let resp = inst.post_json(&query_functions_url, self.headers.clone(), &payload)?;
        if !resp.is_success() {
            return Err(format!(
                "'{}' returned {}",
                query_functions_url, resp.status_code
            ));
        }
        // Get response bytes and convert to WarpFile
        WarpFile::from_owned_bytes(resp.data).ok_or("Failed to parse WARP data".to_string())
    }

    /// Query the functions, returning the sources and the corresponding function guids.
    ///
    /// NOTE: **THIS IS BLOCKING**
    ///
    /// Route: `api/v1/functions/query/source` (TODO: Comment about the query)
    pub fn query_functions_source(
        &self,
        target: Option<NetworkTargetId>,
        tags: &[SourceTag],
        guids: &[FunctionGUID],
    ) -> Result<HashMap<SourceId, Vec<FunctionGUID>>, String> {
        let query_functions_source_url =
            format!("{}/api/v1/functions/query/source", self.server_url);
        // NOTE: We do not filter by constraint guids here since this pass is only responsible for
        // returning the source ids, not the actual function data, see [`NetworkClient::query_functions`]
        // for the place where the constraints are applied, and _do_ matter.
        let payload = Self::query_functions_body(target, None, tags, guids, &[]);
        let mut inst = self.provider.create_instance().unwrap();

        let resp = inst.post_json(&query_functions_source_url, self.headers.clone(), &payload)?;
        if !resp.is_success() {
            return Err(format!(
                "'{}' returned {}",
                query_functions_source_url, resp.status_code
            ));
        }
        // Mapping of source id to function guids
        let json_response: HashMap<String, Vec<String>> = resp.json().map_err(|e| e.to_string())?;
        let mapped_function_guids = json_response
            .into_iter()
            .filter_map(|(source_str, guid_strs)| {
                let source_id = SourceId::from_str(&source_str).ok()?;
                let guids = guid_strs
                    .into_iter()
                    .filter_map(|guid_str| FunctionGUID::from_str(&guid_str).ok())
                    .collect();
                Some((source_id, guids))
            })
            .collect();

        Ok(mapped_function_guids)
    }

    /// Pushes the file to the remote source, returning the commit id.
    ///
    /// NOTE: **THIS IS BLOCKING**
    ///
    /// Route: `api/v1/files/json`
    pub fn push_file(
        &self,
        source_id: SourceId,
        file: &WarpFile,
        name: &str,
    ) -> Result<i32, String> {
        let push_file_url = format!("{}/api/v1/files/json", self.server_url);
        // Convert WarpFile to base64 encoded bytes
        let file_bytes_base64 = base64::engine::general_purpose::STANDARD.encode(&file.to_bytes());
        let mut inst = self.provider.create_instance().unwrap();

        #[derive(Deserialize)]
        struct UploadResponse {
            commit_id: i32,
        }

        let body = json!({
            "file": file_bytes_base64,
            "name": name,
            "source": source_id.to_string(),
            "description": serde_json::Value::Null,
        });

        let resp = inst.post_json(&push_file_url, self.headers.clone(), &body)?;
        if !resp.is_success() {
            return Err(format!("'{}' returned {}", push_file_url, resp.status_code));
        }
        let out: UploadResponse = resp.json().map_err(|e| e.to_string())?;
        Ok(out.commit_id)
    }

    pub fn function_data(&self, id: i32) -> Result<Function, String> {
        let function_data_url = format!("{}/api/v1/functions/{}/data", self.server_url, id);
        let mut inst = self.provider.create_instance().unwrap();

        let resp = inst.get(&function_data_url, self.headers.clone())?;
        if !resp.is_success() {
            return Err(format!(
                "'{}' returned {}",
                function_data_url, resp.status_code
            ));
        }
        Function::from_bytes(&resp.data)
            .ok_or_else(|| format!("Failed to parse function data for function {}", id,))
    }

    pub fn function_datas(&self, ids: &[i32]) -> Result<Vec<Function>, String> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let function_data_url = format!("{}/api/v1/functions/data", self.server_url);
        let mut inst = self.provider.create_instance().unwrap();

        let body = json!({
            "ids": ids,
        });
        let resp = inst.post_json(&function_data_url, self.headers.clone(), &body)?;
        if !resp.is_success() {
            return Err(format!(
                "'{}' returned {}",
                function_data_url, resp.status_code
            ));
        }
        let file = WarpFile::from_bytes(&resp.data)
            .ok_or_else(|| format!("Failed to parse function data for functions {:?}", ids))?;
        let mut functions = Vec::with_capacity(ids.len());
        for chunk in file.chunks {
            let ChunkKind::Signature(sc) = chunk.kind else {
                continue;
            };
            functions.extend(sc.functions());
        }
        Ok(functions)
    }

    pub fn type_data(&self, guid: TypeGUID) -> Result<Type, String> {
        let type_data_url = format!("{}/api/v1/types/{}/data", self.server_url, guid.to_string());
        let mut inst = self.provider.create_instance().unwrap();

        let resp = inst.get(&type_data_url, self.headers.clone())?;
        if !resp.is_success() {
            return Err(format!("'{}' returned {}", type_data_url, resp.status_code));
        }
        Type::from_bytes(&resp.data)
            .ok_or_else(|| format!("Failed to parse type data for type {}", guid))
    }

    pub fn type_datas(&self, guids: &[TypeGUID]) -> Result<Vec<ComputedType>, String> {
        if guids.is_empty() {
            return Ok(Vec::new());
        }
        let type_data_url = format!("{}/api/v1/types/data", self.server_url);
        let mut inst = self.provider.create_instance().unwrap();

        let body = json!({
            "ids": guids.iter().map(|g| g.to_string()).collect::<Vec<_>>(),
        });
        let resp = inst.post_json(&type_data_url, self.headers.clone(), &body)?;
        if !resp.is_success() {
            return Err(format!("'{}' returned {}", type_data_url, resp.status_code));
        }
        let file = WarpFile::from_bytes(&resp.data)
            .ok_or_else(|| format!("Failed to parse type data for types {:?}", guids))?;
        let mut types = Vec::with_capacity(guids.len());
        for chunk in file.chunks {
            let ChunkKind::Type(tc) = chunk.kind else {
                continue;
            };
            types.extend(tc.types());
        }
        Ok(types)
    }

    pub fn search(&self, query: &ContainerSearchQuery) -> Result<ContainerSearchResponse, String> {
        #[derive(serde::Serialize)]
        struct SearchRequest<'a> {
            #[serde(rename = "q")]
            q: &'a str,
            #[serde(skip_serializing_if = "Option::is_none")]
            limit: Option<usize>,
            #[serde(skip_serializing_if = "Option::is_none")]
            offset: Option<usize>,
            #[serde(rename = "source_id", skip_serializing_if = "Option::is_none")]
            source_id: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            source_tags: Option<Vec<SourceTag>>,
            #[serde(skip_serializing_if = "Option::is_none")]
            retrieve_data: Option<bool>,
        }
        let source_id_str = query.source.map(|s| s.to_string());
        let request = SearchRequest {
            q: &query.query,
            limit: query.limit,
            offset: query.offset,
            source_id: source_id_str,
            source_tags: match query.tags.is_empty() {
                true => None,
                false => Some(query.tags.clone()),
            },
            // This must be passed to retrieve the function and type data.
            retrieve_data: Some(true),
        };
        let request_qs = serde_qs::to_string(&request).map_err(|e| e.to_string())?;
        let search_url = match request_qs.is_empty() {
            true => format!("{}/api/v1/search", self.server_url),
            false => format!("{}/api/v1/search?{}", self.server_url, request_qs),
        };

        let mut inst = self.provider.create_instance().unwrap();

        #[derive(serde::Deserialize)]
        struct SearchResponse {
            items: Vec<SearchItem>,
            offset: usize,
            total: usize,
        }

        #[derive(serde::Deserialize)]
        struct SearchItem {
            id: String,
            kind: String,
            #[serde(default)]
            name: Option<String>,
            #[serde(default)]
            source_id: Option<Uuid>,
            #[serde(default)]
            data: Option<Vec<u8>>,
        }

        let resp = inst.get(&search_url, self.headers.clone())?;
        if !resp.is_success() {
            return Err(format!("'{}' returned {}", search_url, resp.status_code));
        }
        let parsed: SearchResponse = resp.json().map_err(|e| e.to_string())?;

        // TODO: This is quite scuffed, but it works for now. (Mostly just that it looks bad and queries a lot)
        // TODO: Here I think would be a good place to sort it so sources always come first.
        // TODO: Users searching will want to get to the source first, likely to whitelist or blacklist.
        let mut items = Vec::with_capacity(parsed.items.len());
        for item in parsed.items {
            let Some(source_uuid) = item.source_id else {
                // Currently not interested in items without a source id.
                // Things like symbols do not have a source id.
                continue;
            };

            let kind = match item.kind.as_str() {
                "function" => {
                    let Some(data) = &item.data else {
                        tracing::warn!(
                            "Function item {} has no data from network, skipping...",
                            item.id
                        );
                        continue;
                    };
                    let Some(func) = Function::from_bytes(&data) else {
                        tracing::warn!(
                            "Function item {} has invalid data from network, skipping...",
                            item.id
                        );
                        continue;
                    };
                    ContainerSearchItemKind::Function(func)
                }
                "source" => ContainerSearchItemKind::Source {
                    path: match item.name {
                        None => {
                            tracing::warn!("Source item {} has no name", item.id);
                            continue;
                        }
                        Some(name) => SourcePath(format!("{}/{}", self.server_url, name).into()),
                    },
                    id: SourceId(source_uuid),
                },
                "type" => {
                    let Some(data) = &item.data else {
                        tracing::warn!(
                            "Type item {} has no data from network, skipping...",
                            item.id
                        );
                        continue;
                    };
                    let Some(ty) = Type::from_bytes(&data) else {
                        tracing::warn!(
                            "Type item {} has invalid data from network, skipping...",
                            item.id
                        );
                        continue;
                    };
                    ContainerSearchItemKind::Type(ty)
                }
                _ => continue,
            };

            items.push(ContainerSearchItem {
                source: SourceId(source_uuid),
                kind,
            });
        }

        Ok(ContainerSearchResponse {
            items,
            total: parsed.total,
            offset: parsed.offset,
        })
    }
}
