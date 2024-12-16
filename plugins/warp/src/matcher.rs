use binaryninja::architecture::Architecture as BNArchitecture;
use binaryninja::binaryview::{BinaryView, BinaryViewExt};
use binaryninja::function::Function as BNFunction;
use binaryninja::platform::Platform;
use binaryninja::rc::Guard;
use binaryninja::rc::Ref as BNRef;
use dashmap::DashMap;
use serde_json::json;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::PathBuf;
use std::sync::OnceLock;
use walkdir::{DirEntry, WalkDir};
use warp::r#type::class::TypeClass;
use warp::r#type::guid::TypeGUID;
use warp::r#type::Type;
use warp::signature::function::{Function, FunctionGUID};
use warp::signature::Data;

use crate::cache::{
    cached_adjacency_constraints, cached_call_site_constraints, cached_function_match,
    try_cached_function_guid,
};
use crate::convert::to_bn_type;
use crate::plugin::on_matched_function;
use crate::{core_signature_dir, user_signature_dir};

pub static PLAT_MATCHER_CACHE: OnceLock<DashMap<PlatformID, Matcher>> = OnceLock::new();

pub fn cached_function_matcher(function: &BNFunction) {
    let platform = function.platform();
    let platform_id = PlatformID::from(platform.as_ref());
    let matcher_cache = PLAT_MATCHER_CACHE.get_or_init(Default::default);
    match matcher_cache.get(&platform_id) {
        Some(matcher) => matcher.match_function(function),
        None => {
            let matcher = Matcher::from_platform(platform);
            matcher.match_function(function);
            matcher_cache.insert(platform_id, matcher);
        }
    }
}

// TODO: Maybe just clear individual platforms? This works well enough either way.
pub fn invalidate_function_matcher_cache() {
    let matcher_cache = PLAT_MATCHER_CACHE.get_or_init(Default::default);
    matcher_cache.clear();
}

#[derive(Debug, Default, Clone)]
pub struct Matcher {
    // TODO: Storing the settings here means that they are effectively global.
    // TODO: If we want scoped or view settings they must be moved out.
    pub settings: MatcherSettings,
    pub functions: DashMap<FunctionGUID, Vec<Function>>,
    pub types: DashMap<TypeGUID, Type>,
    pub named_types: DashMap<String, Type>,
}

impl Matcher {
    /// Create a matcher from the platforms signature subdirectory.
    pub fn from_platform(platform: BNRef<Platform>) -> Self {
        let platform_name = platform.name().to_string();

        // Get core and user signatures.
        // TODO: Separate each file into own bucket for filtering?
        let plat_core_sig_dir = core_signature_dir().join(&platform_name);
        let mut data = get_data_from_dir(&plat_core_sig_dir);
        let plat_user_sig_dir = user_signature_dir().join(&platform_name);
        let user_data = get_data_from_dir(&plat_user_sig_dir);

        data.extend(user_data);
        let merged_data = Data::merge(data.values().cloned().collect::<Vec<_>>());
        log::debug!("Loaded signatures: {:?}", data.keys());
        Matcher::from_data(merged_data)
    }

    pub fn from_data(data: Data) -> Self {
        let functions = data.functions.into_iter().fold(
            DashMap::new(),
            |map: DashMap<FunctionGUID, Vec<_>>, func| {
                map.entry(func.guid).or_default().push(func);
                map
            },
        );
        let types = data
            .types
            .iter()
            .map(|ty| (ty.guid, ty.ty.clone()))
            .collect();
        let named_types = data
            .types
            .into_iter()
            .filter_map(|ty| ty.ty.name.to_owned().map(|name| (name, ty.ty)))
            .collect();

        Self {
            // NOTE: Settings will be retrieved from global state every time this is called.
            settings: MatcherSettings::global(),
            functions,
            types,
            named_types,
        }
    }

    pub fn extend_with_matcher(&mut self, matcher: Matcher) {
        self.functions.extend(matcher.functions);
        self.types.extend(matcher.types);
        self.named_types.extend(matcher.named_types);
    }

    pub fn add_type_to_view<A: BNArchitecture>(&self, view: &BinaryView, arch: &A, ty: &Type) {
        fn inner_add_type_to_view<A: BNArchitecture>(
            matcher: &Matcher,
            view: &BinaryView,
            arch: &A,
            visited_refs: &mut HashSet<String>,
            ty: &Type,
        ) {
            let ty_id_str = TypeGUID::from(ty).to_string();
            if view.get_type_by_id(&ty_id_str).is_some() {
                // Type already added.
                return;
            }
            // Type not already added to the view.
            // Verify all nested types are added before adding type.
            match ty.class.as_ref() {
                TypeClass::Pointer(c) => {
                    inner_add_type_to_view(matcher, view, arch, visited_refs, &c.child_type)
                }
                TypeClass::Array(c) => {
                    inner_add_type_to_view(matcher, view, arch, visited_refs, &c.member_type)
                }
                TypeClass::Structure(c) => {
                    for member in &c.members {
                        inner_add_type_to_view(matcher, view, arch, visited_refs, &member.ty)
                    }
                }
                TypeClass::Enumeration(c) => {
                    inner_add_type_to_view(matcher, view, arch, visited_refs, &c.member_type)
                }
                TypeClass::Union(c) => {
                    for member in &c.members {
                        inner_add_type_to_view(matcher, view, arch, visited_refs, &member.ty)
                    }
                }
                TypeClass::Function(c) => {
                    for out_member in &c.out_members {
                        inner_add_type_to_view(matcher, view, arch, visited_refs, &out_member.ty)
                    }
                    for in_member in &c.in_members {
                        inner_add_type_to_view(matcher, view, arch, visited_refs, &in_member.ty)
                    }
                }
                TypeClass::Referrer(c) => {
                    // Check to see if the referrer has been added to the view.
                    let mut resolved = false;
                    if let Some(ref_guid) = c.guid {
                        // NOTE: We do not need to check for cyclic reference here because
                        // NOTE: GUID references are unable to be referenced by themselves.
                        if view.get_type_by_id(ref_guid.to_string()).is_none() {
                            // Add the referrer to the view if it is in the Matcher types
                            if let Some(ref_ty) = matcher.types.get(&ref_guid) {
                                inner_add_type_to_view(matcher, view, arch, visited_refs, &ref_ty);
                                resolved = true;
                            }
                        }
                    }

                    if let Some(ref_name) = &c.name {
                        // Only try and resolve by name if not already visiting.
                        if !resolved
                            && visited_refs.insert(ref_name.to_string())
                            && view.get_type_by_name(ref_name).is_none()
                        {
                            // Add the ref to the view if it is in the Matcher types
                            if let Some(ref_ty) = matcher.named_types.get(ref_name) {
                                inner_add_type_to_view(matcher, view, arch, visited_refs, &ref_ty);
                            }
                            // No longer visiting type.
                            visited_refs.remove(ref_name);
                        }
                    }

                    // All nested types _should_ be added now, we can add this type.
                    // TODO: Do we want to make unnamed types visible? I think we should, but some people might be opposed.
                    let ty_name = ty.name.to_owned().unwrap_or_else(|| ty_id_str.clone());
                    view.define_auto_type_with_id(ty_name, ty_id_str, &to_bn_type(arch, ty));
                }
                _ => {}
            }
        }
        inner_add_type_to_view(self, view, arch, &mut HashSet::new(), ty)
    }

    pub fn match_function(&self, function: &BNFunction) {
        // Call this the first time you matched on the function.
        let resolve_new_types = |matched: &Function| {
            // We also want to resolve the types here.
            if let TypeClass::Function(c) = matched.ty.class.as_ref() {
                // Recursively go through the function type and resolve referrers
                let view = function.view();
                let arch = function.arch();
                for out_member in &c.out_members {
                    self.add_type_to_view(&view, &arch, &out_member.ty);
                }
                for in_member in &c.in_members {
                    self.add_type_to_view(&view, &arch, &in_member.ty);
                }
            }
        };

        if let Some(matched_function) = cached_function_match(function, || {
            // We have yet to match on this function.
            let function_len = function.highest_address() - function.lowest_address();
            let is_function_trivial = { function_len < self.settings.trivial_function_len };
            let is_function_allowed = {
                function_len > self.settings.minimum_function_len
                    && function_len < self.settings.maximum_function_len.unwrap_or(u64::MAX)
            };
            let warp_func_guid = try_cached_function_guid(function)?;
            match self.functions.get(&warp_func_guid) {
                _ if !is_function_allowed => None,
                Some(matched) if matched.len() == 1 && !is_function_trivial => {
                    resolve_new_types(&matched[0]);
                    Some(matched[0].to_owned())
                }
                Some(matched) => {
                    let matched_on = self.match_function_from_constraints(function, &matched)?;
                    resolve_new_types(matched_on);
                    Some(matched_on.to_owned())
                }
                None => None,
            }
        }) {
            on_matched_function(function, &matched_function);
        }
    }

    pub fn match_function_from_constraints<'a>(
        &self,
        function: &BNFunction,
        matched_functions: &'a [Function],
    ) -> Option<&'a Function> {
        // Filter out adjacent functions which are trivial, this helps avoid false positives.
        // NOTE: If the user sets `trivial_function_adjacent_allowed` to true we will always match.
        // TODO: Expand on this more later. We might want to match on adjacent functions smaller than this.
        let adjacent_function_filter = |adj_func: &BNFunction| {
            let adj_func_len = adj_func.highest_address() - adj_func.lowest_address();
            adj_func_len > self.settings.trivial_function_len
                || self.settings.trivial_function_adjacent_allowed
        };

        let call_sites = cached_call_site_constraints(function);
        let adjacent = cached_adjacency_constraints(function, adjacent_function_filter);

        // "common" being the intersection between the observed and matched.
        fn find_highest_common_count<'a, F, T>(
            observed_items: &HashSet<T>,
            matched_functions: &'a [Function],
            extract_items: F,
        ) -> (usize, Option<&'a Function>)
        where
            F: Fn(&Function) -> HashSet<T>,
            T: Hash + Eq,
        {
            let mut highest_count = 0;
            let mut matched_func = None;
            for matched in matched_functions {
                let matched_items = extract_items(matched);
                let common_count = observed_items.intersection(&matched_items).count();
                match common_count.cmp(&highest_count) {
                    Ordering::Equal => matched_func = None,
                    Ordering::Greater => {
                        highest_count = common_count;
                        matched_func = Some(matched);
                    }
                    Ordering::Less => {}
                }
            }
            (highest_count, matched_func)
        }

        let call_site_guids: HashSet<_> = call_sites.iter().filter_map(|c| c.guid).collect();
        let call_site_symbol_names: HashSet<_> = call_sites
            .into_iter()
            .filter_map(|c| c.symbol.map(|s| s.name))
            .collect();
        let adjacent_guids: HashSet<_> = adjacent.iter().filter_map(|c| c.guid).collect();
        let adjacent_symbol_names: HashSet<_> = adjacent
            .into_iter()
            .filter_map(|c| c.symbol.map(|s| s.name))
            .collect();

        // Ordered from the lowest confidence to the highest confidence constraint.
        let checked_constraints = [
            find_highest_common_count(&adjacent_symbol_names, matched_functions, |matched| {
                matched
                    .constraints
                    .adjacent
                    .iter()
                    .filter_map(|c| c.symbol.to_owned().map(|s| s.name))
                    .collect()
            }),
            find_highest_common_count(&adjacent_guids, matched_functions, |matched| {
                matched
                    .constraints
                    .adjacent
                    .iter()
                    .filter_map(|c| c.guid)
                    .collect()
            }),
            find_highest_common_count(&call_site_symbol_names, matched_functions, |matched| {
                matched
                    .constraints
                    .call_sites
                    .iter()
                    .filter_map(|c| c.symbol.to_owned().map(|s| s.name))
                    .collect()
            }),
            find_highest_common_count(&call_site_guids, matched_functions, |matched| {
                matched
                    .constraints
                    .call_sites
                    .iter()
                    .filter_map(|c| c.guid)
                    .collect()
            }),
        ];

        // If there is a tie, the last one wins, which should be call_site guid.
        checked_constraints
            .into_iter()
            .max_by_key(|&(count, _)| count)
            .filter(|&(count, _)| count >= self.settings.minimum_matched_constraints)
            .and_then(|(_, func)| func)
    }
}

fn get_data_from_dir(dir: &PathBuf) -> HashMap<PathBuf, Data> {
    let data_from_entry = |entry: DirEntry| {
        let path = entry.path();
        let contents = std::fs::read(path).ok()?;
        Data::from_bytes(&contents)
    };

    WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter_map(|e| Some((e.clone().into_path(), data_from_entry(e)?)))
        .collect()
}

#[derive(Debug, Clone)]
pub struct MatcherSettings {
    /// Any function under this length will be required to constrain.
    ///
    /// This is set to [MatcherSettings::DEFAULT_TRIVIAL_FUNCTION_LEN] by default.
    pub trivial_function_len: u64,
    /// Any function under this length will not match.
    ///
    /// This is set to [MatcherSettings::MINIMUM_FUNCTION_LEN_DEFAULT] by default.
    pub minimum_function_len: u64,
    /// Any function above this length will not match.
    ///
    /// This is set to [MatcherSettings::MAXIMUM_FUNCTION_LEN_DEFAULT] by default.
    pub maximum_function_len: Option<u64>,
    /// For a successful constrained function match the number of matches must be above this.
    ///
    /// This is set to [MatcherSettings::DEFAULT_TRIVIAL_FUNCTION_LEN] by default.
    pub minimum_matched_constraints: usize,
    /// For a successful constrained function match the number of matches must be above this.
    ///
    /// This is set to [MatcherSettings::DEFAULT_TRIVIAL_FUNCTION_LEN] by default.
    pub trivial_function_adjacent_allowed: bool,
}

impl MatcherSettings {
    pub const TRIVIAL_FUNCTION_LEN_DEFAULT: u64 = 20;
    pub const TRIVIAL_FUNCTION_LEN_SETTING: &'static str = "analysis.warp.trivialFunctionLength";
    pub const MINIMUM_FUNCTION_LEN_DEFAULT: u64 = 0;
    pub const MINIMUM_FUNCTION_LEN_SETTING: &'static str = "analysis.warp.minimumFunctionLength";
    pub const MAXIMUM_FUNCTION_LEN_DEFAULT: u64 = 0;
    pub const MAXIMUM_FUNCTION_LEN_SETTING: &'static str = "analysis.warp.maximumFunctionLength";
    pub const MINIMUM_MATCHED_CONSTRAINTS_DEFAULT: usize = 1;
    pub const MINIMUM_MATCHED_CONSTRAINTS_SETTING: &'static str =
        "analysis.warp.minimumMatchedConstraints";
    pub const TRIVIAL_FUNCTION_ADJACENT_ALLOWED_DEFAULT: bool = false;
    pub const TRIVIAL_FUNCTION_ADJACENT_ALLOWED_SETTING: &'static str =
        "analysis.warp.trivialFunctionAdjacentAllowed";

    /// Populates the [MatcherSettings] to the current Binary Ninja settings instance.
    ///
    /// Call this once when you initialize so that the settings exist.
    ///
    /// NOTE: If you are using this as a library then just modify the MatcherSettings directly
    /// in the matcher instance, that way you don't need to round-trip through Binary Ninja.
    pub fn register() {
        let bn_settings = binaryninja::settings::Settings::new("");

        let trivial_function_len_props = json!({
            "title" : "Trivial Function Length",
            "type" : "number",
            "default" : Self::TRIVIAL_FUNCTION_LEN_DEFAULT,
            "description" : "Functions below this length in bytes will be required to match on constraints.",
            "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
        });
        bn_settings.register_setting_json(
            Self::TRIVIAL_FUNCTION_LEN_SETTING,
            trivial_function_len_props.to_string(),
        );

        let minimum_function_len_props = json!({
            "title" : "Minimum Function Length",
            "type" : "number",
            "default" : Self::MINIMUM_FUNCTION_LEN_DEFAULT,
            "description" : "Functions below this length will not be matched.",
            "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
        });
        bn_settings.register_setting_json(
            Self::MINIMUM_FUNCTION_LEN_SETTING,
            minimum_function_len_props.to_string(),
        );

        let maximum_function_len_props = json!({
            "title" : "Maximum Function Length",
            "type" : "number",
            "default" : Self::MAXIMUM_FUNCTION_LEN_DEFAULT,
            "description" : "Functions above this length will not be matched. A value of 0 will disable this check.",
            "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
        });
        bn_settings.register_setting_json(
            Self::MAXIMUM_FUNCTION_LEN_SETTING,
            maximum_function_len_props.to_string(),
        );

        let minimum_matched_constraints_props = json!({
            "title" : "Minimum Matched Constraints",
            "type" : "number",
            "default" : Self::MINIMUM_MATCHED_CONSTRAINTS_DEFAULT,
            "description" : "When function constraints are checked the amount of constraints matched must be at-least this.",
            "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
        });
        bn_settings.register_setting_json(
            Self::MINIMUM_MATCHED_CONSTRAINTS_SETTING,
            minimum_matched_constraints_props.to_string(),
        );

        let trivial_function_adjacent_allowed_props = json!({
            "title" : "Trivial Function Adjacent Constraints Allowed",
            "type" : "boolean",
            "default" : Self::TRIVIAL_FUNCTION_ADJACENT_ALLOWED_DEFAULT,
            "description" : "When function constraints are checked if this is enabled functions can match based off trivial adjacent functions.",
            "ignore" : ["SettingsProjectScope", "SettingsResourceScope"]
        });
        bn_settings.register_setting_json(
            Self::TRIVIAL_FUNCTION_ADJACENT_ALLOWED_SETTING,
            trivial_function_adjacent_allowed_props.to_string(),
        );
    }

    pub fn global() -> Self {
        let mut settings = MatcherSettings::default();
        let bn_settings = binaryninja::settings::Settings::new("");
        if bn_settings.contains(Self::TRIVIAL_FUNCTION_LEN_SETTING) {
            settings.trivial_function_len =
                bn_settings.get_integer(Self::TRIVIAL_FUNCTION_LEN_SETTING, None, None);
        }
        if bn_settings.contains(Self::MINIMUM_FUNCTION_LEN_SETTING) {
            settings.minimum_function_len =
                bn_settings.get_integer(Self::MINIMUM_FUNCTION_LEN_SETTING, None, None);
        }
        if bn_settings.contains(Self::MAXIMUM_FUNCTION_LEN_SETTING) {
            match bn_settings.get_integer(Self::MAXIMUM_FUNCTION_LEN_SETTING, None, None) {
                0 => settings.maximum_function_len = None,
                len => settings.maximum_function_len = Some(len),
            }
        }
        if bn_settings.contains(Self::MINIMUM_MATCHED_CONSTRAINTS_SETTING) {
            settings.minimum_matched_constraints =
                bn_settings.get_integer(Self::MINIMUM_MATCHED_CONSTRAINTS_SETTING, None, None)
                    as usize;
        }
        settings
    }
}

impl Default for MatcherSettings {
    fn default() -> Self {
        Self {
            trivial_function_len: MatcherSettings::TRIVIAL_FUNCTION_LEN_DEFAULT,
            minimum_function_len: MatcherSettings::MINIMUM_FUNCTION_LEN_DEFAULT,
            maximum_function_len: None,
            minimum_matched_constraints: MatcherSettings::MINIMUM_MATCHED_CONSTRAINTS_DEFAULT,
            trivial_function_adjacent_allowed:
                MatcherSettings::TRIVIAL_FUNCTION_ADJACENT_ALLOWED_DEFAULT,
        }
    }
}

/// A unique platform ID, used for caching.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord)]
pub struct PlatformID(u64);

impl From<&Platform> for PlatformID {
    fn from(value: &Platform) -> Self {
        let mut hasher = DefaultHasher::new();
        hasher.write(value.name().to_bytes());
        Self(hasher.finish())
    }
}

impl From<BNRef<Platform>> for PlatformID {
    fn from(value: BNRef<Platform>) -> Self {
        Self::from(value.as_ref())
    }
}

impl From<Guard<'_, Platform>> for PlatformID {
    fn from(value: Guard<'_, Platform>) -> Self {
        Self::from(value.as_ref())
    }
}
