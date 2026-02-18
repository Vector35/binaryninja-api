use binaryninja::collaboration::{RemoteFile, RemoteFolder, RemoteProject};
use binaryninja::rc::Ref;
use std::fmt::Display;
use std::path::PathBuf;
use thiserror::Error;
use url::Url;
use uuid::Uuid;

#[derive(Error, Debug, PartialEq)]
pub enum BnUrlParsingError {
    #[error("Invalid URL format: {0}")]
    UrlParseError(#[from] url::ParseError),

    #[error("Invalid scheme: expected 'binaryninja', found '{0}'")]
    InvalidScheme(String),

    #[error("Invalid Enterprise path: missing server or project GUID")]
    InvalidEnterprisePath,

    #[error("Invalid server URL in enterprise path")]
    InvalidServerUrl,

    #[error("Invalid UUID: {0}")]
    InvalidUuid(#[from] uuid::Error),

    #[error("Unknown or unsupported URL format")]
    UnknownFormat,
}

#[derive(Error, Debug)]
pub enum BnResourceError {
    #[error("Enterprise server not found for address: {0}")]
    RemoteNotFound(String),

    #[error("Remote connection error: {0}")]
    RemoteConnectionError(String),

    #[error("Project not found with GUID: {0}")]
    ProjectNotFound(String),

    #[error("Project resource not found with GUID: {0}")]
    ItemNotFound(String),

    #[error("Local filesystem error: {0}")]
    IoError(#[from] std::io::Error),
}

#[derive(Debug, Clone)]
pub enum BnResource {
    RemoteProject(Ref<RemoteProject>),
    RemoteProjectFile(Ref<RemoteFile>),
    RemoteProjectFolder(Ref<RemoteFolder>),
    /// A remote file.
    RemoteFile(Url),
    /// A regular file on the local filesystem.
    LocalFile(PathBuf),
}

// TODO: Make the BnUrl from this.
impl Display for BnResource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BnResource::RemoteProject(project) => write!(f, "RemoteProject({})", project.id()),
            BnResource::RemoteProjectFile(file) => write!(f, "RemoteFile({})", file.id()),
            BnResource::RemoteProjectFolder(folder) => write!(f, "RemoteFolder({})", folder.id()),
            BnResource::RemoteFile(url) => write!(f, "RemoteFile({})", url),
            BnResource::LocalFile(path) => write!(f, "LocalFile({})", path.display()),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum BnParsedUrlKind {
    Enterprise {
        server: Url,
        project_guid: Uuid,
        /// Optional GUID of the project item, currently can be a folder or a file.
        item_guid: Option<Uuid>,
    },
    // TODO: Local projects?
    RemoteFile(Url),
    LocalFile(PathBuf),
}

#[derive(Debug, Clone)]
pub struct BnParsedUrl {
    pub kind: BnParsedUrlKind,
    pub expression: Option<String>,
}

impl BnParsedUrl {
    pub fn parse(input: &str) -> Result<Self, BnUrlParsingError> {
        let parsed = Url::parse(input)?;
        if parsed.scheme() != "binaryninja" {
            return Err(BnUrlParsingError::InvalidScheme(
                parsed.scheme().to_string(),
            ));
        }

        let expression = parsed
            .query_pairs()
            .find(|(k, _)| k == "expr")
            .map(|(_, v)| v.into_owned());

        let kind = match parsed.host_str() {
            // TODO: This should really go down the same path as the remote file parsing, if it
            // TODO: matches the host of an enterprise server... But that requires us to change how
            // TODO: the core outputs these enterprise URLs...
            // Case: binaryninja://enterprise/...
            Some("enterprise") => {
                let segments: Vec<&str> =
                    parsed.path().split('/').filter(|s| !s.is_empty()).collect();

                if segments.len() < 3 {
                    return Err(BnUrlParsingError::InvalidEnterprisePath);
                }

                let (server_parts, resource_parts) = if segments.len() >= 4 {
                    (
                        &segments[..segments.len() - 2],
                        &segments[segments.len() - 2..],
                    )
                } else {
                    (
                        &segments[..segments.len() - 1],
                        &segments[segments.len() - 1..],
                    )
                };

                BnParsedUrlKind::Enterprise {
                    server: Url::parse(&server_parts.join("/"))
                        .map_err(|_| BnUrlParsingError::InvalidServerUrl)?,
                    project_guid: Uuid::parse_str(resource_parts[0])?,
                    item_guid: resource_parts
                        .get(1)
                        .map(|s| Uuid::parse_str(s))
                        .transpose()?,
                }
            }
            // Case: binaryninja:///bin/ls
            None | Some("")
                if parsed.path().starts_with('/') && !parsed.path().starts_with("/https") =>
            {
                BnParsedUrlKind::LocalFile(PathBuf::from(parsed.path()))
            }
            // Case: binaryninja:https://...
            _ => {
                let path = parsed.path();
                if path.starts_with("https:/") || path.starts_with("http:/") {
                    let nested_url = path.replacen(":/", "://", 1);
                    BnParsedUrlKind::RemoteFile(
                        Url::parse(&nested_url).map_err(BnUrlParsingError::UrlParseError)?,
                    )
                } else {
                    return Err(BnUrlParsingError::UnknownFormat);
                }
            }
        };

        Ok(BnParsedUrl { kind, expression })
    }

    pub fn to_resource(&self) -> Result<BnResource, BnResourceError> {
        match &self.kind {
            BnParsedUrlKind::Enterprise {
                server,
                project_guid,
                item_guid,
            } => {
                // NOTE: We must strip the trailing slash from the server URL, because the core will
                // not accept it otherwise, we should probably have a fuzzy get_remote_by_address here,
                // so we can accept either with or without the trailing slash, but for now we'll just
                // strip it.
                let server_addr = server.as_str().strip_suffix('/').unwrap_or(server.as_str());
                let remote = binaryninja::collaboration::get_remote_by_address(server_addr)
                    .ok_or_else(|| BnResourceError::RemoteNotFound(server_addr.to_string()))?;
                if !remote.is_connected() {
                    remote.connect().map_err(|_| {
                        BnResourceError::RemoteConnectionError(server_addr.to_string())
                    })?;
                }

                let project = remote
                    .get_project_by_id(&project_guid.to_string())
                    .ok()
                    .flatten()
                    .ok_or_else(|| BnResourceError::ProjectNotFound(project_guid.to_string()))?;

                match item_guid {
                    Some(item_guid) => {
                        let item_guid_str = item_guid.to_string();

                        // Check if it's a folder first
                        if let Some(folder) =
                            project.get_folder_by_id(&item_guid_str).ok().flatten()
                        {
                            return Ok(BnResource::RemoteProjectFolder(folder));
                        }

                        // Then check if it's a file
                        let file = project
                            .get_file_by_id(&item_guid_str)
                            .ok()
                            .flatten()
                            .ok_or(BnResourceError::ItemNotFound(item_guid_str))?;

                        Ok(BnResource::RemoteProjectFile(file))
                    }
                    None => Ok(BnResource::RemoteProject(project)),
                }
            }
            BnParsedUrlKind::RemoteFile(remote_url) => {
                Ok(BnResource::RemoteFile(remote_url.clone()))
            }
            BnParsedUrlKind::LocalFile(local_path) => Ok(BnResource::LocalFile(local_path.clone())),
        }
    }
}

impl Display for BnParsedUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.kind {
            BnParsedUrlKind::Enterprise {
                server,
                project_guid,
                item_guid,
            } => write!(
                f,
                "binaryninja://enterprise/{}/{}{}",
                server.as_str().strip_suffix('/').unwrap_or(server.as_str()),
                project_guid,
                item_guid
                    .map(|guid| format!("/{}", guid))
                    .unwrap_or_default()
            ),
            BnParsedUrlKind::RemoteFile(remote_url) => write!(f, "{}", remote_url),
            BnParsedUrlKind::LocalFile(local_path) => {
                write!(f, "binaryninja:///{}", local_path.display())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_enterprise_full() {
        let input = "binaryninja://enterprise/https://enterprise.test.com/0268b954-0d7b-41c3-a603-960a59fdd0f7/0268b954-0d7b-41c3-a603-960a59fdd0f6?expr=sub_1234";
        let action = BnParsedUrl::parse(input).unwrap();

        if let BnParsedUrlKind::Enterprise {
            server,
            project_guid,
            item_guid: project_file,
        } = action.kind
        {
            assert_eq!(server.as_str(), "https://enterprise.test.com/");
            assert_eq!(
                project_guid,
                Uuid::parse_str("0268b954-0d7b-41c3-a603-960a59fdd0f7").unwrap()
            );
            assert_eq!(
                project_file,
                Some(Uuid::parse_str("0268b954-0d7b-41c3-a603-960a59fdd0f6").unwrap())
            );
        } else {
            panic!("Wrong target type");
        }
        assert_eq!(action.expression, Some("sub_1234".to_string()));
    }

    #[test]
    fn test_parse_enterprise_no_file() {
        let input = "binaryninja://enterprise/https://enterprise.test.com/0268b954-0d7b-41c3-a603-960a59fdd0f7/";
        let action = BnParsedUrl::parse(input).unwrap();

        if let BnParsedUrlKind::Enterprise {
            project_guid,
            item_guid: project_file,
            ..
        } = action.kind
        {
            assert_eq!(
                project_guid,
                Uuid::parse_str("0268b954-0d7b-41c3-a603-960a59fdd0f7").unwrap()
            );
            assert_eq!(project_file, None);
        } else {
            panic!("Wrong target type");
        }
    }

    #[test]
    fn test_parse_remote_file() {
        let input = "binaryninja:https://captf.com/2015/plaidctf/pwnable/datastore.elf?expr=main";
        let action = BnParsedUrl::parse(input).unwrap();

        match action.kind {
            BnParsedUrlKind::RemoteFile(url) => {
                assert_eq!(url.host_str(), Some("captf.com"));
                assert!(url.path().ends_with("datastore.elf"));
            }
            _ => panic!("Expected RemoteFile"),
        }
        assert_eq!(action.expression, Some("main".to_string()));
    }

    #[test]
    fn test_parse_local_file() {
        let input = "binaryninja:///bin/ls?expr=sub_2830";
        let action = BnParsedUrl::parse(input).unwrap();

        match action.kind {
            BnParsedUrlKind::LocalFile(path) => assert_eq!(path.to_string_lossy(), "/bin/ls"),
            _ => panic!("Expected LocalFile"),
        }
        assert_eq!(action.expression, Some("sub_2830".to_string()));
    }

    #[test]
    fn test_invalid_scheme() {
        let input = "https://google.com";
        let result = BnParsedUrl::parse(input);
        assert!(matches!(result, Err(BnUrlParsingError::InvalidScheme(_))));
    }

    #[test]
    fn test_missing_enterprise_guid() {
        let input = "binaryninja://enterprise/https://internal.us/";
        let result = BnParsedUrl::parse(input);
        assert_eq!(
            result.unwrap_err(),
            BnUrlParsingError::InvalidEnterprisePath
        );
    }

    #[test]
    fn test_invalid_uuid_format() {
        let input = "binaryninja://enterprise/https://internal.us/not-a-uuid/";
        let result = BnParsedUrl::parse(input);
        assert!(matches!(result, Err(BnUrlParsingError::InvalidUuid(_))));
    }
}
