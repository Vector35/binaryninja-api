use binaryninja::settings::Settings as BNSettings;
use serde_json::json;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PluginSettings {
    /// Whether to load bundled WARP files on startup. Turn this off if you want to manually load them.
    ///
    /// This is set to [PluginSettings::LOAD_BUNDLED_FILES_DEFAULT] by default.
    pub load_bundled_files: bool,
    /// Whether to load user WARP files on startup. Turn this off if you want to manually load them.
    ///
    /// This is set to [PluginSettings::LOAD_USER_FILES_DEFAULT] by default.
    pub load_user_files: bool,
}

impl PluginSettings {
    pub const LOAD_BUNDLED_FILES_DEFAULT: bool = true;
    pub const LOAD_BUNDLED_FILES_SETTING: &'static str = "analysis.warp.loadBundledFiles";
    pub const LOAD_USER_FILES_DEFAULT: bool = true;
    pub const LOAD_USER_FILES_SETTING: &'static str = "analysis.warp.loadUserFiles";

    pub fn register(bn_settings: &mut BNSettings) {
        let load_bundled_files_prop = json!({
            "title" : "Load Bundled Files",
            "type" : "boolean",
            "default" : Self::LOAD_BUNDLED_FILES_DEFAULT,
            "description" : "Whether to load bundled WARP files on startup. Turn this off if you want to manually load them.",
            "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
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
            "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
        });
        bn_settings.register_setting_json(
            Self::LOAD_USER_FILES_SETTING,
            &load_user_files_prop.to_string(),
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
        settings
    }
}

impl Default for PluginSettings {
    fn default() -> Self {
        Self {
            load_bundled_files: PluginSettings::LOAD_BUNDLED_FILES_DEFAULT,
            load_user_files: PluginSettings::LOAD_USER_FILES_DEFAULT,
        }
    }
}
