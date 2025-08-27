use crate::container::network::NetworkTargetId;
use crate::container::{
    ContainerSearchItem, ContainerSearchItemKind, ContainerSearchQuery, ContainerSearchResponse,
    SourceId, SourcePath, SourceTag,
};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use reqwest::StatusCode;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::str::FromStr;
use uuid::Uuid;
use warp::chunk::ChunkKind;
use warp::r#type::guid::TypeGUID;
use warp::r#type::{ComputedType, Type};
use warp::signature::function::{Function, FunctionGUID};
use warp::target::Target;
use warp::WarpFile;

/// Responsible for sending and receiving data from the server.
///
/// NOTE: **All requests are blocking**.
#[derive(Clone, Debug)]
pub struct NetworkClient {
    client: Client,
    pub server_url: String,
}

impl NetworkClient {
    pub fn new(
        server_url: String,
        server_token: Option<String>,
        https_proxy: Option<String>,
    ) -> reqwest::Result<Self> {
        let version_info = binaryninja::version_info();
        // TODO: IIRC we had a user agent format already for some other thing.
        let client_agent = format!(
            "Binary Ninja/{}.{}.{}",
            version_info.major, version_info.minor, version_info.build
        );
        // TODO: This might want to be kept for the request header?
        let mut headers = HeaderMap::new();
        if let Some(token) = &server_token {
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&format!("Bearer {}", token)).unwrap(),
            );
        }
        // TODO: Configurable timeout?
        let mut client_builder = Client::builder()
            .connect_timeout(std::time::Duration::from_secs(10))
            .default_headers(headers)
            .user_agent(client_agent);
        if let Some(https_proxy) = https_proxy {
            client_builder = client_builder.proxy(reqwest::Proxy::all(&https_proxy)?);
        }
        Ok(Self {
            client: client_builder.build()?,
            server_url,
        })
    }

    /// Check to see the status of the server.
    ///
    /// This is useful if you want to fail early and prevent constructing a network container to a
    /// server that is unresponsive.
    ///
    /// Route: `api/v1/status`
    pub fn status(&self) -> reqwest::Result<StatusCode> {
        let status_url = format!("{}/api/v1/status", self.server_url);
        let resp = self.client.get(&status_url).send()?;
        Ok(resp.status())
    }

    /// Query the logged in user.
    ///
    /// NOTE: **THIS IS BLOCKING**
    ///
    /// Route: `api/v1/users/me` (TODO: Comment about the query)
    pub fn current_user(&self) -> reqwest::Result<(i32, String)> {
        let current_user_url = format!("{}/api/v1/users/me", self.server_url);

        #[derive(Deserialize)]
        struct CurrentUser {
            username: String,
            id: i32,
        }

        let resp = self
            .client
            .get(&current_user_url)
            .send()?
            .error_for_status()?;
        let user: CurrentUser = resp.json()?;
        Ok((user.id, user.username))
    }

    /// Query the logged in user.
    ///
    /// NOTE: **THIS IS BLOCKING**
    ///
    /// Route: `api/v1/users/me` (TODO: Comment about the query)
    pub fn source_name(&self, id: SourceId) -> reqwest::Result<String> {
        let source_url = format!("{}/api/v1/sources/{}", self.server_url, id);

        #[derive(Deserialize)]
        struct Source {
            name: String,
        }

        let resp = self.client.get(&source_url).send()?.error_for_status()?;
        let src: Source = resp.json()?;
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
    pub fn create_source(&self, name: &str) -> reqwest::Result<SourceId> {
        let source_url = format!("{}/api/v1/sources", self.server_url);

        let body = json!({
            "name": name,
            // Passing nothing here will add the current user to the source.
            "user_ids": []
        });

        #[derive(Deserialize)]
        struct CreateSourceResponse {
            id: Uuid,
        }

        let resp = self
            .client
            .post(&source_url)
            .json(&body)
            .send()?
            .error_for_status()?;

        let parsed: CreateSourceResponse = resp.json()?;
        Ok(SourceId(parsed.id))
    }

    /// Query the [`SourceId`]s for the given user.
    ///
    /// NOTE: **THIS IS BLOCKING**
    ///
    /// Route: `api/v1/sources/query` (TODO: Comment about the query)
    pub fn query_sources(&self, user_id: Option<i32>) -> reqwest::Result<Vec<SourceId>> {
        let sources_url = format!("{}/api/v1/sources/query", self.server_url);

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
        let query_str = json!(query).to_string();
        let resp = self
            .client
            .post(&sources_url)
            .body(query_str)
            .header("Content-Type", "application/json")
            .send()?
            .error_for_status()?;

        let parsed: SourcesQueryResponse = resp.json()?;
        Ok(parsed.items.into_iter().map(|it| SourceId(it.id)).collect())
    }

    /// Query the [`NetworkTargetId`] for the given [`Target`].
    ///
    /// NOTE: **THIS IS BLOCKING**
    ///
    /// Route: `api/v1/targets/query` (TODO: Comment about the query)
    pub fn query_target_id(&self, target: &Target) -> Option<NetworkTargetId> {
        let query_target_url = format!("{}/api/v1/targets/query", self.server_url);

        let mut query = HashMap::new();
        if let Some(platform) = &target.platform {
            query.insert("platform", platform);
        }
        if let Some(architecture) = &target.architecture {
            query.insert("arch", architecture);
        }
        let query_str = json!(query).to_string();

        #[derive(Deserialize)]
        struct TargetQueryResponse {
            id: NetworkTargetId,
        }

        // NOTE: This is blocking.
        let response = self
            .client
            .post(query_target_url)
            .body(query_str)
            .header("Content-Type", "application/json")
            .send()
            .ok()?;

        // Assuming the first response is the one we want.
        // TODO: Handle multiple responses, or error out.
        let json_response: Vec<TargetQueryResponse> = response.json().ok()?;
        let first_response = json_response.first()?;

        Some(first_response.id)
    }

    fn query_functions_body(
        target: Option<NetworkTargetId>,
        source: Option<SourceId>,
        source_tags: &[SourceTag],
        guids: &[FunctionGUID],
    ) -> serde_json::Value {
        let guids_str: Vec<String> = guids.iter().map(|g| g.to_string()).collect();
        // TODO: The limit here needs to be somewhat flexible. But 1000 will do for now.
        let mut body = json!({
            "format": "flatbuffer",
            "guids": guids_str,
            "limit": 1000
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
    ) -> Option<WarpFile<'static>> {
        let query_functions_url = format!("{}/api/v1/functions/query", self.server_url);
        // TODO: Allow for source tags? We really only need this in query_functions_source as that
        // TODO: is what prevents a undesired source from being "known" to the container.
        let payload = Self::query_functions_body(target, source, &[], guids);

        // Make the POST request
        let response = self
            .client
            .post(&query_functions_url)
            .json(&payload)
            .send()
            .ok()?;
        if !response.status().is_success() {
            log::error!("Failed to query functions: {}", response.status());
            return None;
        }

        // Get response bytes and convert to WarpFile
        let bytes = response.bytes().ok()?;
        WarpFile::from_owned_bytes(bytes.to_vec())
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
    ) -> Option<HashMap<SourceId, Vec<FunctionGUID>>> {
        let query_functions_source_url =
            format!("{}/api/v1/functions/query/source", self.server_url);
        let payload = Self::query_functions_body(target, None, tags, guids);

        // Make the POST request
        let response = self
            .client
            .post(&query_functions_source_url)
            .json(&payload)
            .send()
            .ok()?;
        if !response.status().is_success() {
            log::error!("Failed to query functions source: {}", response.status());
            return None;
        }

        // Mapping of source id to function guids
        let json_response: HashMap<String, Vec<String>> = response.json().ok()?;
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

        Some(mapped_function_guids)
    }

    /// Pushes the file to the remote source.
    ///
    /// NOTE: **THIS IS BLOCKING**
    ///
    /// Route: `api/v1/files/{source}`
    pub fn push_file(&self, source_id: SourceId, file: &WarpFile, name: &str) -> bool {
        let push_file_url = format!("{}/api/v1/files", self.server_url);

        // Convert WarpFile to bytes
        let file_bytes = file.to_bytes();

        let Ok(file_part) = reqwest::blocking::multipart::Part::bytes(file_bytes)
            .file_name("data.warp")
            .mime_str("application/octet-stream")
        else {
            log::error!("Failed to create file part");
            return false;
        };

        let form = reqwest::blocking::multipart::Form::new()
            .part("file", file_part)
            .text("name", name.to_string())
            .text("source", source_id.to_string());

        // Send the request
        match self.client.post(&push_file_url).multipart(form).send() {
            Ok(response) => {
                if response.status().is_success() {
                    true
                } else {
                    log::error!("Failed to push file: {}", response.status());
                    false
                }
            }
            Err(e) => {
                log::error!("Failed to send push request: {}", e);
                false
            }
        }
    }

    pub fn function_data(&self, id: i32) -> Option<Function> {
        let function_data_url = format!("{}/api/v1/functions/{}/data", self.server_url, id);
        let response = self.client.get(&function_data_url).send().ok()?;
        if !response.status().is_success() {
            log::error!(
                "Failed to fetch function data for {}: {}",
                id,
                response.status()
            );
            return None;
        }
        let bytes = response.bytes().ok()?;
        Function::from_bytes(bytes.as_ref())
    }

    pub fn function_datas(&self, ids: &[i32]) -> Option<Vec<Function>> {
        if ids.is_empty() {
            return Some(Vec::new());
        }
        let function_data_url = format!("{}/api/v1/functions/data", self.server_url);
        let body = json!({
            "ids": ids,
        });
        let response = self
            .client
            .post(&function_data_url)
            .json(&body)
            .send()
            .ok()?;
        if !response.status().is_success() {
            log::error!("Failed to fetch function data: {}", response.status());
            return None;
        }
        let bytes = response.bytes().ok()?;
        let file = WarpFile::from_bytes(bytes.as_ref())?;
        let mut functions = Vec::with_capacity(ids.len());
        for chunk in file.chunks {
            let ChunkKind::Signature(sc) = chunk.kind else {
                continue;
            };
            functions.extend(sc.functions());
        }
        Some(functions)
    }

    pub fn type_data(&self, guid: TypeGUID) -> Option<Type> {
        let type_data_url = format!("{}/api/v1/types/{}/data", self.server_url, guid.to_string());
        let response = self.client.get(&type_data_url).send().ok()?;
        if !response.status().is_success() {
            log::error!(
                "Failed to fetch type data for {}: {}",
                guid.to_string(),
                response.status()
            );
            return None;
        }
        let bytes = response.bytes().ok()?;
        Type::from_bytes(bytes.as_ref())
    }

    pub fn type_datas(&self, guids: &[TypeGUID]) -> Option<Vec<ComputedType>> {
        if guids.is_empty() {
            return Some(Vec::new());
        }
        let type_data_url = format!("{}/api/v1/types/data", self.server_url);
        let body = json!({
            "ids": guids.iter().map(|g| g.to_string()).collect::<Vec<_>>(),
        });
        let response = self.client.post(&type_data_url).json(&body).send().ok()?;
        if !response.status().is_success() {
            log::error!("Failed to fetch type data: {}", response.status());
            return None;
        }
        let bytes = response.bytes().ok()?;
        let file = WarpFile::from_bytes(bytes.as_ref())?;
        let mut types = Vec::with_capacity(guids.len());
        for chunk in file.chunks {
            let ChunkKind::Type(tc) = chunk.kind else {
                continue;
            };
            types.extend(tc.types());
        }
        Some(types)
    }

    pub fn search(&self, query: &ContainerSearchQuery) -> Option<ContainerSearchResponse> {
        let search_url = format!("{}/api/v1/search", self.server_url);

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

        let resp = match self.client.get(search_url).query(&request).send() {
            Ok(r) => r,
            Err(err) => {
                log::error!("Failed to send search request: {}", err);
                return None;
            }
        };

        let Ok(parsed) = resp.json::<SearchResponse>() else {
            log::error!("Failed to parse search response");
            return None;
        };

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
                        log::warn!(
                            "Function item {} has no data from network, skipping...",
                            item.id
                        );
                        continue;
                    };
                    let Some(func) = Function::from_bytes(&data) else {
                        log::warn!(
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
                            log::warn!("Source item {} has no name", item.id);
                            continue;
                        }
                        Some(name) => SourcePath(format!("{}/{}", self.server_url, name).into()),
                    },
                    id: SourceId(source_uuid),
                },
                "type" => {
                    let Some(data) = &item.data else {
                        log::warn!(
                            "Type item {} has no data from network, skipping...",
                            item.id
                        );
                        continue;
                    };
                    let Some(ty) = Type::from_bytes(&data) else {
                        log::warn!(
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

        Some(ContainerSearchResponse {
            items,
            total: parsed.total,
            offset: parsed.offset,
        })
    }
}
