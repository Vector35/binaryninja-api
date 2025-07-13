use binaryninja::settings::Settings as BNSettings;
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
    /// Whether to allow networked WARP requests. Turning this off will not disable local WARP functionality.
    ///
    /// This is set to [PluginSettings::ENABLE_SERVER_DEFAULT] by default.
    pub enable_server: bool,
}

impl PluginSettings {
    pub const LOAD_BUNDLED_FILES_DEFAULT: bool = true;
    pub const LOAD_BUNDLED_FILES_SETTING: &'static str = "analysis.warp.loadBundledFiles";
    pub const LOAD_USER_FILES_DEFAULT: bool = true;
    pub const LOAD_USER_FILES_SETTING: &'static str = "analysis.warp.loadUserFiles";
    pub const SERVER_URL_DEFAULT: &'static str = "https://warp.binary.ninja";
    pub const SERVER_URL_SETTING: &'static str = "analysis.warp.serverUrl";
    pub const SERVER_API_KEY_DEFAULT: Option<String> = None;
    pub const SERVER_API_KEY_SETTING: &'static str = "analysis.warp.serverApiKey";
    pub const ENABLE_SERVER_DEFAULT: bool = false;
    pub const ENABLE_SERVER_SETTING: &'static str = "network.enableWARP";

    pub fn register(bn_settings: &mut BNSettings) {
        let load_bundled_files_prop = json!({
            "title" : "Load Bundled Files",
            "type" : "boolean",
            "default" : Self::LOAD_BUNDLED_FILES_DEFAULT,
            "description" : "Whether to load bundled WARP files on startup. Turn this off if you want to manually load them.",
            "ignore" : ["SettingsProjectScope", "SettingsResourceScope"],
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
            "requiresRestart" : true
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
            "requiresRestart" : true
        });
        bn_settings.register_setting_json(Self::SERVER_URL_SETTING, &server_url_prop.to_string());
        let server_api_key_prop = json!({
            "title" : "Server API Key",
            "type" : "string",
            "default" : Self::SERVER_API_KEY_DEFAULT,
            "description" : "The API key to use for the selected WARP server, if not specified you will be unable to push data, and may be rate limited.",
            "ignore" : ["SettingsProjectScope", "SettingsResourceScope"],
            "hidden": true,
            "requiresRestart" : true
        });
        bn_settings.register_setting_json(
            Self::SERVER_API_KEY_SETTING,
            &server_api_key_prop.to_string(),
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
    pub fn from_settings(bn_settings: &BNSettings) -> Self {
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
            if !server_api_key_str.is_empty() {
                settings.server_api_key = Some(server_api_key_str);
            }
        }
        if bn_settings.contains(Self::ENABLE_SERVER_SETTING) {
            settings.enable_server = bn_settings.get_bool(Self::ENABLE_SERVER_SETTING);
        }
        settings
    }
}

impl Default for PluginSettings {
    fn default() -> Self {
        Self {
            load_bundled_files: PluginSettings::LOAD_BUNDLED_FILES_DEFAULT,
            load_user_files: PluginSettings::LOAD_USER_FILES_DEFAULT,
            server_url: PluginSettings::SERVER_URL_DEFAULT.to_string(),
            server_api_key: PluginSettings::SERVER_API_KEY_DEFAULT,
            enable_server: PluginSettings::ENABLE_SERVER_DEFAULT,
        }
    }
}
