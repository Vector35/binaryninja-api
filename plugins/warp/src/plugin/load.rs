use crate::matcher::{Matcher, PlatformID, PLAT_MATCHER_CACHE};
use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::command::Command;
pub struct LoadSignatureFile;

impl Command for LoadSignatureFile {
    fn action(&self, view: &BinaryView) {
        let Some(platform) = view.default_platform() else {
            log::error!("Default platform must be set to load signature!");
            return;
        };

        // NOTE: Because we only can consume signatures from a specific directory, we don't need to use the interaction API.
        // If we did need to load signature files from a project than this would need to change.
        let Some(file) = rfd::FileDialog::new()
            .add_filter("Signature Files", &["sbin"])
            .set_file_name(format!("{}.sbin", view.file().filename()))
            .pick_file()
        else {
            return;
        };

        let Ok(data) = std::fs::read(&file) else {
            log::error!("Could not read signature file: {:?}", file);
            return;
        };

        let Some(data) = warp::signature::Data::from_bytes(&data) else {
            log::error!("Could not get data from signature file: {:?}", file);
            return;
        };

        let new_matcher = Matcher::from_data(data);
        log::info!(
            "Loading signature file with {} functions and {} types...",
            new_matcher.functions.len(),
            new_matcher.types.len()
        );
        let platform_id = PlatformID::from(platform.as_ref());
        let matcher_cache = PLAT_MATCHER_CACHE.get_or_init(Default::default);
        match matcher_cache.get_mut(&platform_id) {
            Some(mut matcher) => matcher.extend_with_matcher(new_matcher),
            None => {
                // We still must uphold `from_platform` in case we are running this before the matcher workflow
                // is kicked off. Other-wise we only will have the `new_matcher` data.
                let mut matcher = Matcher::from_platform(platform);
                matcher.extend_with_matcher(new_matcher);
                matcher_cache.insert(platform_id, matcher);
            }
        }
    }

    fn valid(&self, _view: &BinaryView) -> bool {
        true
    }
}
