use crate::container::SourceTag;
use binaryninja::settings::{QueryOptions, Settings as BNSettings};
use serde_json::json;
use std::string::ToString;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PluginSettings {
    /// Whether to load bundled WARP files on startup. Turn this off if you want to manually load them.
    ///
    /// This is set to [PluginSettings::LOAD_BUNDLED_FILES_DEFAULT] by default.
    pub load_bundled_files: bool,
    /// Whether to load user WARP files on startup. Turn this off if you want to manually load them.
    ///
    /// This is set to [PluginSettings::LOAD_USER_FILES_DEFAULT] by default.
    pub load_user_files: bool,
    /// The WARP server to use.
    ///
    /// This is set to [PluginSettings::SERVER_URL_DEFAULT] by default.
    pub server_url: String,
    /// The API key to use for the selected WARP server, if not specified, you will be unable to push data and may be rate-limited.
    ///
    /// This is set to [PluginSettings::SERVER_API_KEY_DEFAULT] by default.
    pub server_api_key: Option<String>,
    pub second_server_url: Option<String>,
    pub second_server_api_key: Option<String>,
    /// A source must have at least one of these tags to be considered a valid source.
    ///
    /// This is set to [PluginSettings::SOURCE_TAGS_DEFAULT] by default.
    pub allowed_source_tags: Vec<SourceTag>,
    /// The maximum number of functions to fetch in a single batch.
    ///
    /// This is set to [PluginSettings::FETCH_BATCH_SIZE_DEFAULT] by default.
    pub fetch_batch_size: usize,
    /// Whether to allow networked WARP requests. Turning this off will not disable local WARP functionality.
    ///
    /// This is set to [PluginSettings::ENABLE_SERVER_DEFAULT] by default.
    pub enable_server: bool,
}

impl PluginSettings {
    pub const ALLOWED_SOURCE_TAGS_DEFAULT: [&'static str; 2] = ["official", "trusted"];
    pub const ALLOWED_SOURCE_TAGS_SETTING: &'static str = "warp.fetcher.allowedSourceTags";
    pub const FETCH_BATCH_SIZE_DEFAULT: usize = 10000;
    pub const FETCH_BATCH_SIZE_SETTING: &'static str = "warp.fetcher.fetchBatchSize";
    pub const LOAD_BUNDLED_FILES_DEFAULT: bool = true;
    pub const LOAD_BUNDLED_FILES_SETTING: &'static str = "warp.container.loadBundledFiles";
    pub const LOAD_BUNDLED_FILES_SETTING_ALIAS: [&'static str; 1] =
        ["analysis.warp.loadBundledFiles"];
    pub const LOAD_USER_FILES_DEFAULT: bool = true;
    pub const LOAD_USER_FILES_SETTING: &'static str = "warp.container.loadUserFiles";
    pub const LOAD_USER_FILES_SETTING_ALIAS: [&'static str; 1] = ["analysis.warp.loadUserFiles"];
    pub const SERVER_URL_DEFAULT: &'static str = "https://warp.binary.ninja";
    pub const SERVER_URL_SETTING: &'static str = "warp.container.serverUrl";
    pub const SERVER_URL_SETTING_ALIAS: [&'static str; 1] = ["analysis.warp.serverUrl"];
    pub const SERVER_API_KEY_DEFAULT: Option<String> = None;
    pub const SERVER_API_KEY_SETTING: &'static str = "warp.container.serverApiKey";
    pub const SERVER_API_KEY_SETTING_ALIAS: [&'static str; 1] = ["analysis.warp.serverApiKey"];
    pub const SECONDARY_SERVER_URL_DEFAULT: Option<String> = None;
    pub const SECONDARY_SERVER_URL_SETTING: &'static str = "warp.container.secondServerUrl";
    pub const SECONDARY_SERVER_URL_SETTING_ALIAS: [&'static str; 1] =
        ["analysis.warp.secondServerUrl"];
    pub const SECONDARY_SERVER_API_KEY_DEFAULT: Option<String> = None;
    pub const SECONDARY_SERVER_API_KEY_SETTING: &'static str = "warp.container.secondServerApiKey";
    pub const SECONDARY_SERVER_API_KEY_SETTING_ALIAS: [&'static str; 1] =
        ["analysis.warp.secondServerApiKey"];
    pub const ENABLE_SERVER_DEFAULT: bool = false;
    pub const ENABLE_SERVER_SETTING: &'static str = "network.enableWARP";

    pub fn register(bn_settings: &mut BNSettings) {
        let allowed_source_tags_prop = json!({
            "title" : "Allowed Source Tags",
            "type" : "array",
            "default" : Self::ALLOWED_SOURCE_TAGS_DEFAULT,
            "description" : "The source tags that are allowed to be fetched from the server. Any source that does not have at least one of these tags will be ignored.",
            "ignore" : [],
        });
        bn_settings.register_setting_json(
            Self::ALLOWED_SOURCE_TAGS_SETTING,
            &allowed_source_tags_prop.to_string(),
        );
        let fetch_size_props = json!({
            "title" : "Fetch Batch Limit",
            "type" : "number",
            "minValue" : 100,
            "maxValue" : 20000,
            "default" : Self::FETCH_BATCH_SIZE_DEFAULT,
            "description" : "The maximum number of functions to fetch in a single batch. This is used to limit the amount of functions to fetch at once, lowering this value will make the fetch process more comprehensive at the cost of more network requests.",
            "ignore" : [],
        });
        bn_settings.register_setting_json(
            Self::FETCH_BATCH_SIZE_SETTING,
            &fetch_size_props.to_string(),
        );
        let load_bundled_files_prop = json!({
            "title" : "Load Bundled Files",
            "type" : "boolean",
            "default" : Self::LOAD_BUNDLED_FILES_DEFAULT,
            "description" : "Whether to load bundled WARP files on startup. Turn this off if you want to manually load them.",
            "ignore" : ["SettingsProjectScope", "SettingsResourceScope"],
            "aliases" : Self::LOAD_BUNDLED_FILES_SETTING_ALIAS,
            "requiresRestart" : true
        });
        bn_settings.register_setting_json(
            Self::LOAD_BUNDLED_FILES_SETTING,
            &load_bundled_files_prop.to_string(),
        );
        let load_user_files_prop = json!({
            "title" : "Load User Files",
            "type" : "boolean",
            "default" : Self::LOAD_USER_FILES_DEFAULT,
            "description" : "Whether to load user WARP files on startup. Turn this off if you want to manually load them.",
            "ignore" : ["SettingsProjectScope", "SettingsResourceScope"],
            "requiresRestart" : true,
            "aliases" : Self::LOAD_USER_FILES_SETTING_ALIAS,
        });
        bn_settings.register_setting_json(
            Self::LOAD_USER_FILES_SETTING,
            &load_user_files_prop.to_string(),
        );
        let server_url_prop = json!({
            "title" : "Server URL",
            "type" : "string",
            "default" : Self::SERVER_URL_DEFAULT,
            "description" : "The WARP server to use.",
            "ignore" : ["SettingsProjectScope", "SettingsResourceScope"],
            "requiresRestart" : true,
            "aliases" : Self::SERVER_URL_SETTING_ALIAS,
        });
        bn_settings.register_setting_json(Self::SERVER_URL_SETTING, &server_url_prop.to_string());
        let server_api_key_prop = json!({
            "title" : "Server API Key",
            "type" : "string",
            "default" : Self::SERVER_API_KEY_DEFAULT,
            "description" : "The API key to use for the selected WARP server, if not specified you will be unable to push data, and may be rate limited.",
            "ignore" : ["SettingsProjectScope", "SettingsResourceScope"],
            "hidden": true,
            "requiresRestart" : true,
            "aliases" : Self::SERVER_API_KEY_SETTING_ALIAS,
        });
        bn_settings.register_setting_json(
            Self::SERVER_API_KEY_SETTING,
            &server_api_key_prop.to_string(),
        );
        let second_server_url_prop = json!({
            "title" : "Secondary Server URL",
            "type" : "string",
            "default" : Self::SECONDARY_SERVER_URL_DEFAULT,
            "description" : "",
            "ignore" : ["SettingsProjectScope", "SettingsResourceScope"],
            "requiresRestart" : true,
            "aliases" : Self::SECONDARY_SERVER_URL_SETTING_ALIAS
        });
        bn_settings.register_setting_json(
            Self::SECONDARY_SERVER_URL_SETTING,
            &second_server_url_prop.to_string(),
        );
        let second_server_api_key_prop = json!({
            "title" : "Secondary Server API Key",
            "type" : "string",
            "default" : Self::SECONDARY_SERVER_API_KEY_DEFAULT,
            "description" : "",
            "ignore" : ["SettingsProjectScope", "SettingsResourceScope"],
            "hidden": true,
            "requiresRestart" : true,
            "aliases" : Self::SECONDARY_SERVER_API_KEY_SETTING_ALIAS
        });
        bn_settings.register_setting_json(
            Self::SECONDARY_SERVER_API_KEY_SETTING,
            &second_server_api_key_prop.to_string(),
        );
        let server_enabled_prop = json!({
            "title" : "Enable WARP",
            "type" : "boolean",
            "default" : Self::ENABLE_SERVER_DEFAULT,
            "description" : "Whether or not to allow networked WARP requests. Turning this off will not disable local WARP functionality.",
            "ignore" : ["SettingsProjectScope", "SettingsResourceScope"],
            "requiresRestart" : true
        });
        bn_settings.register_setting_json(
            Self::ENABLE_SERVER_SETTING,
            &server_enabled_prop.to_string(),
        );
    }

    /// Retrieve plugin settings from [`BNSettings`].
    pub fn from_settings(bn_settings: &BNSettings, query_opts: &mut QueryOptions) -> Self {
        let mut settings = PluginSettings::default();
        if bn_settings.contains(Self::LOAD_BUNDLED_FILES_SETTING) {
            settings.load_bundled_files = bn_settings.get_bool(Self::LOAD_BUNDLED_FILES_SETTING);
        }
        if bn_settings.contains(Self::LOAD_USER_FILES_SETTING) {
            settings.load_user_files = bn_settings.get_bool(Self::LOAD_USER_FILES_SETTING);
        }
        if bn_settings.contains(Self::SERVER_URL_SETTING) {
            settings.server_url = bn_settings.get_string(Self::SERVER_URL_SETTING);
        }
        if bn_settings.contains(Self::SERVER_API_KEY_SETTING) {
            let server_api_key_str = bn_settings.get_string(Self::SERVER_API_KEY_SETTING);
            let trimmed_server_api_key_str = server_api_key_str.trim();
            if !trimmed_server_api_key_str.is_empty() {
                settings.server_api_key = Some(trimmed_server_api_key_str.to_string());
            }
        }
        if bn_settings.contains(Self::SECONDARY_SERVER_URL_SETTING) {
            let server_api_key_str = bn_settings.get_string(Self::SECONDARY_SERVER_URL_SETTING);
            if !server_api_key_str.is_empty() {
                settings.second_server_url = Some(server_api_key_str);
            }
        }
        if bn_settings.contains(Self::SECONDARY_SERVER_API_KEY_SETTING) {
            let server_api_key_str = bn_settings.get_string(Self::SECONDARY_SERVER_API_KEY_SETTING);
            let trimmed_server_api_key_str = server_api_key_str.trim();
            if !trimmed_server_api_key_str.is_empty() {
                settings.second_server_api_key = Some(trimmed_server_api_key_str.to_string());
            }
        }
        if bn_settings.contains(Self::ENABLE_SERVER_SETTING) {
            settings.enable_server = bn_settings.get_bool(Self::ENABLE_SERVER_SETTING);
        }

        if bn_settings.contains(Self::ALLOWED_SOURCE_TAGS_SETTING) {
            let whitelisted_source_tags_str = bn_settings
                .get_string_list_with_opts(Self::ALLOWED_SOURCE_TAGS_SETTING, query_opts);
            settings.allowed_source_tags = whitelisted_source_tags_str
                .iter()
                .map(SourceTag::from)
                .collect();
        }
        if bn_settings.contains(Self::FETCH_BATCH_SIZE_SETTING) {
            settings.fetch_batch_size = bn_settings
                .get_integer_with_opts(Self::FETCH_BATCH_SIZE_SETTING, query_opts)
                as usize;
        }
        settings
    }
}

impl Default for PluginSettings {
    fn default() -> Self {
        Self {
            allowed_source_tags: PluginSettings::ALLOWED_SOURCE_TAGS_DEFAULT
                .into_iter()
                .map(SourceTag::from)
                .collect(),
            fetch_batch_size: PluginSettings::FETCH_BATCH_SIZE_DEFAULT,
            load_bundled_files: PluginSettings::LOAD_BUNDLED_FILES_DEFAULT,
            load_user_files: PluginSettings::LOAD_USER_FILES_DEFAULT,
            server_url: PluginSettings::SERVER_URL_DEFAULT.to_string(),
            server_api_key: PluginSettings::SERVER_API_KEY_DEFAULT,
            second_server_url: PluginSettings::SECONDARY_SERVER_URL_DEFAULT,
            second_server_api_key: PluginSettings::SECONDARY_SERVER_API_KEY_DEFAULT,
            enable_server: PluginSettings::ENABLE_SERVER_DEFAULT,
        }
    }
}
