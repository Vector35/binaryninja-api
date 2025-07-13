use crate::container::network::NetworkTargetId;
use crate::container::SourceId;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION};
use reqwest::StatusCode;
use serde_json::json;
use std::collections::HashMap;
use std::str::FromStr;
use warp::signature::function::FunctionGUID;
use warp::target::Target;
use warp::WarpFile;

/// Responsible for sending and receiving data from the server.
///
/// NOTE: **All requests are blocking**.
#[derive(Clone, Debug)]
pub struct NetworkClient {
    client: Client,
    server_url: String,
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
            query.insert("architecture", architecture);
        }

        // NOTE: This is blocking.
        let target_id: NetworkTargetId = self
            .client
            .get(query_target_url)
            .query(&query)
            .send()
            .ok()?
            .json::<NetworkTargetId>()
            .ok()?;

        Some(target_id)
    }

    fn query_functions_body(
        target: Option<NetworkTargetId>,
        source: Option<SourceId>,
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
        let payload = Self::query_functions_body(target, source, guids);

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
        guids: &[FunctionGUID],
    ) -> Option<HashMap<SourceId, Vec<FunctionGUID>>> {
        let query_functions_source_url =
            format!("{}/api/v1/functions/query/source", self.server_url);
        let payload = Self::query_functions_body(target, None, guids);

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
    pub fn push_file(&self, source_id: SourceId, file: &WarpFile) -> bool {
        let push_file_url = format!("{}/api/v1/files/{}", self.server_url, source_id.to_string());

        // Convert WarpFile to bytes
        let file_bytes = file.to_bytes();

        // Create the form part with the file
        let form = reqwest::blocking::multipart::Form::new().part(
            "file",
            reqwest::blocking::multipart::Part::bytes(file_bytes)
                .file_name("data.warp")
                .mime_str("application/octet-stream")
                .unwrap(),
        );

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
}
