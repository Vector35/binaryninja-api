use crate::cache::cached_constraints;
use crate::container::{Container, SourceId};
use crate::convert::to_bn_type;
use binaryninja::architecture::Architecture as BNArchitecture;
use binaryninja::binary_view::{BinaryView, BinaryViewExt};
use binaryninja::function::Function as BNFunction;
use binaryninja::settings::{QueryOptions, Settings as BNSettings};
use serde_json::json;
use std::cmp::Ordering;
use std::collections::HashSet;
use std::hash::Hash;
use warp::r#type::class::TypeClass;
use warp::r#type::Type;
use warp::signature::function::Function;

/// A matcher represents a specific configuration for identify functions using WARP. A matcher
/// does not store/own any WARP information directly, instead the matcher is given a [`Container`]
/// that holds all of that information.
///
/// The separation of the WARP information from the [`Matcher`] allows a greater degree of control and
/// provides a clean interface for further logic to be built on top of. A matcher instance, unlike
/// a typical [`Container`] implementation, is cheap to create.
#[derive(Debug, Clone, Copy)]
pub struct Matcher {
    pub settings: MatcherSettings,
}

impl Matcher {
    pub fn new(settings: MatcherSettings) -> Self {
        Matcher { settings }
    }

    pub fn match_function_from_constraints<'a>(
        &self,
        function: &BNFunction,
        matched_functions: &'a [Function],
    ) -> Option<&'a Function> {
        let function_len = function.highest_address() - function.lowest_address();
        let is_function_trivial = { function_len < self.settings.trivial_function_len };
        let is_function_allowed = {
            function_len >= self.settings.minimum_function_len
                && function_len < self.settings.maximum_function_len.unwrap_or(u64::MAX)
        };

        // Function isn't allowed, or no matches so stop early.
        if !is_function_allowed || matched_functions.is_empty() {
            return None;
        }

        // The number of possible functions is too high, skip.
        // This can happen if the function is extremely common, in cases like that we are already unlikely to match.
        // It is unfortunate that we have to do this, but it is the best we can do. In the future we
        // may find a way to chunk up the possible functions and only match on a subset of them.
        if self
            .settings
            .maximum_possible_functions
            .is_some_and(|max| max < matched_functions.len() as u64)
        {
            return None;
        }

        // If we have a single possible match than that must be our function.
        // We must also not be a trivial function, as those will likely be artifacts of an incomplete dataset
        if matched_functions.len() == 1 && !is_function_trivial {
            return matched_functions.first();
        }
        // Filter out adjacent functions which are trivial, this helps avoid false positives.
        // NOTE: If the user sets `trivial_function_adjacent_allowed` to true we will always match.
        // TODO: Expand on this more later. We might want to match on adjacent functions smaller than this.
        let adjacent_function_filter = |adj_func: &BNFunction| {
            let adj_func_len = adj_func.highest_address() - adj_func.lowest_address();
            adj_func_len >= self.settings.trivial_function_len
                || self.settings.trivial_function_adjacent_allowed
        };

        // TODO: When the highest count has two matches we return None. Need to alert the user.
        // "common" being the intersection between the observed and matched.
        let constraints = cached_constraints(function, adjacent_function_filter);
        let mut highest_count = 0;
        let mut matched_func = None;
        for matched in matched_functions {
            let common_count = constraints.intersection(&matched.constraints).count();
            match common_count.cmp(&highest_count) {
                Ordering::Equal => matched_func = None,
                Ordering::Greater => {
                    highest_count = common_count;
                    matched_func = Some(matched);
                }
                Ordering::Less => {}
            }
        }

        // If we have a match below the minimum threshold, ignore.
        match highest_count.cmp(&self.settings.minimum_matched_constraints) {
            Ordering::Equal => matched_func,
            Ordering::Greater => matched_func,
            Ordering::Less => None,
        }
    }

    // TODO: I would really like for WARP types to be added in a seperate type container, so that we don't
    // TODO: just add them as system or user types.
    pub fn add_type_to_view<A: BNArchitecture + Copy>(
        &self,
        container: &dyn Container,
        source: &SourceId,
        view: &BinaryView,
        arch: A,
        ty: &Type,
    ) where
        Self: Sized,
    {
        fn inner_add_type_to_view<A: BNArchitecture + Copy>(
            container: &dyn Container,
            source: &SourceId,
            view: &BinaryView,
            arch: A,
            visited_refs: &mut HashSet<String>,
            ty: &Type,
        ) {
            // Type not already added to the view.
            // Verify all nested types are added before adding type.
            match &ty.class {
                TypeClass::Pointer(c) => inner_add_type_to_view(
                    container,
                    source,
                    view,
                    arch,
                    visited_refs,
                    &c.child_type,
                ),
                TypeClass::Array(c) => inner_add_type_to_view(
                    container,
                    source,
                    view,
                    arch,
                    visited_refs,
                    &c.member_type,
                ),
                TypeClass::Structure(c) => {
                    for member in &c.members {
                        inner_add_type_to_view(
                            container,
                            source,
                            view,
                            arch,
                            visited_refs,
                            &member.ty,
                        )
                    }
                }
                TypeClass::Enumeration(c) => inner_add_type_to_view(
                    container,
                    source,
                    view,
                    arch,
                    visited_refs,
                    &c.member_type,
                ),
                TypeClass::Union(c) => {
                    for member in &c.members {
                        inner_add_type_to_view(
                            container,
                            source,
                            view,
                            arch,
                            visited_refs,
                            &member.ty,
                        )
                    }
                }
                TypeClass::Function(c) => {
                    for out_member in &c.out_members {
                        inner_add_type_to_view(
                            container,
                            source,
                            view,
                            arch,
                            visited_refs,
                            &out_member.ty,
                        )
                    }
                    for in_member in &c.in_members {
                        inner_add_type_to_view(
                            container,
                            source,
                            view,
                            arch,
                            visited_refs,
                            &in_member.ty,
                        )
                    }
                }
                TypeClass::Referrer(c) => {
                    // Check to see if the referrer has been added to the view.
                    let mut resolved_ty = None;
                    if let Some(ref_guid) = c.guid {
                        // NOTE: We do not need to check for cyclic reference here because
                        // NOTE: GUID references are unable to be referenced by themselves.
                        if view.type_by_id(&ref_guid.to_string()).is_none() {
                            // Add the referrer to the view if it is in the Matcher types
                            if let Ok(Some(ref_ty)) = container.type_with_guid(source, &ref_guid) {
                                inner_add_type_to_view(
                                    container,
                                    source,
                                    view,
                                    arch,
                                    visited_refs,
                                    &ref_ty,
                                );
                                resolved_ty = Some(ref_ty);
                            }
                        }
                    }

                    if let Some(ref_name) = &c.name {
                        // Only try and resolve by name if not already visiting.
                        if resolved_ty.is_none()
                            && visited_refs.insert(ref_name.to_string())
                            && view.type_by_name(ref_name).is_none()
                        {
                            // Add the ref to the view if it is in the Matcher types
                            let type_guids = container
                                .type_guids_with_name(source, ref_name)
                                .unwrap_or_default();
                            // TODO: What happens if we have more than one?
                            if type_guids.len() == 1 {
                                // TODO: What happens if we cant get the guid?
                                if let Ok(Some(ref_ty)) =
                                    container.type_with_guid(source, &type_guids[0])
                                {
                                    inner_add_type_to_view(
                                        container,
                                        source,
                                        view,
                                        arch,
                                        visited_refs,
                                        &ref_ty,
                                    );
                                    resolved_ty = Some(ref_ty);
                                }
                            }
                            // No longer visiting type.
                            visited_refs.remove(ref_name);
                        }
                    }

                    // Adds the ref'd type to the view.
                    match (c.guid, &c.name, resolved_ty) {
                        (Some(guid), Some(name), Some(ref_ty)) => {
                            view.define_auto_type_with_id(
                                name,
                                &guid.to_string(),
                                &to_bn_type(Some(arch), &ref_ty),
                            );
                        }
                        (Some(_guid), Some(_name), None) => {
                            // TODO: Got name and guid but no type? Do we add a bare NTR?
                        }
                        (Some(_guid), None, _) => {
                            // TODO: How would we reference this type without a name???
                        }
                        (None, Some(_name), _) => {
                            // TODO: Cyclic type reference if no guid, so... dont define?
                        }
                        (None, None, _) => {
                            // TODO: What?!?!?
                        }
                    }
                }
                TypeClass::Void
                | TypeClass::Boolean(_)
                | TypeClass::Integer(_)
                | TypeClass::Character(_)
                | TypeClass::Float(_) => {}
            }

            // TODO: Some refs likely need to ommitted because they are just that, refs to another type.
            // let guid = TypeGUID::from(ty);
            // let name = ty.name.clone().unwrap_or(guid.to_string());
            // view.define_auto_type_with_id(name, &guid.to_string(), &to_bn_type(arch, ty));
        }
        inner_add_type_to_view(container, source, view, arch, &mut HashSet::new(), ty)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MatcherSettings {
    /// Any function under this length will be required to constrain.
    ///
    /// This is set to [MatcherSettings::TRIVIAL_FUNCTION_LEN_DEFAULT] by default.
    pub trivial_function_len: u64,
    /// Any function under this length will not match.
    ///
    /// This is set to [MatcherSettings::MINIMUM_FUNCTION_LEN_DEFAULT] by default.
    pub minimum_function_len: u64,
    /// Any function above this length will not match.
    ///
    /// This is set to [MatcherSettings::MAXIMUM_FUNCTION_LEN_DEFAULT] by default.
    pub maximum_function_len: Option<u64>,
    /// For a successful constrained function match, the number of matches must be above this.
    ///
    /// This is set to [MatcherSettings::MINIMUM_MATCHED_CONSTRAINTS_DEFAULT] by default.
    pub minimum_matched_constraints: usize,
    /// When function constraints are checked, if this is enabled, functions can match based off trivial adjacent functions.
    ///
    /// Any function under `trivial_function_len` will be considered trivial.
    ///
    /// This is set to [MatcherSettings::TRIVIAL_FUNCTION_ADJACENT_ALLOWED_DEFAULT] by default.
    pub trivial_function_adjacent_allowed: bool,
    /// The maximum number of WARP functions that can be used to match a Binary Ninja function.
    ///
    /// This is set to [MatcherSettings::MAXIMUM_POSSIBLE_FUNCTIONS_DEFAULT] by default.
    pub maximum_possible_functions: Option<u64>,
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
    pub const MAXIMUM_POSSIBLE_FUNCTIONS_SETTING: &'static str =
        "analysis.warp.maximumPossibleFunctions";
    pub const MAXIMUM_POSSIBLE_FUNCTIONS_DEFAULT: u64 = 1000;

    /// Populates the [MatcherSettings] to the current Binary Ninja settings instance.
    ///
    /// Call this once when you initialize so that the settings exist.
    ///
    /// NOTE: If you are using this as a library, then modify the [`MatcherSettings`] directly
    /// in the matcher instance, that way you don't need to round-trip through Binary Ninja.
    pub fn register(bn_settings: &mut BNSettings) {
        let trivial_function_len_props = json!({
            "title" : "Trivial Function Length",
            "type" : "number",
            "default" : Self::TRIVIAL_FUNCTION_LEN_DEFAULT,
            "description" : "Functions below this length in bytes will be required to match on constraints.",
            "ignore" : []
        });
        bn_settings.register_setting_json(
            Self::TRIVIAL_FUNCTION_LEN_SETTING,
            &trivial_function_len_props.to_string(),
        );

        let minimum_function_len_props = json!({
            "title" : "Minimum Function Length",
            "type" : "number",
            "default" : Self::MINIMUM_FUNCTION_LEN_DEFAULT,
            "description" : "Functions below this length will not be matched.",
            "ignore" : []
        });
        bn_settings.register_setting_json(
            Self::MINIMUM_FUNCTION_LEN_SETTING,
            &minimum_function_len_props.to_string(),
        );

        let maximum_function_len_props = json!({
            "title" : "Maximum Function Length",
            "type" : "number",
            "default" : Self::MAXIMUM_FUNCTION_LEN_DEFAULT,
            "description" : "Functions above this length will not be matched. A value of 0 will disable this check.",
            "ignore" : []
        });
        bn_settings.register_setting_json(
            Self::MAXIMUM_FUNCTION_LEN_SETTING,
            &maximum_function_len_props.to_string(),
        );

        let minimum_matched_constraints_props = json!({
            "title" : "Minimum Matched Constraints",
            "type" : "number",
            "default" : Self::MINIMUM_MATCHED_CONSTRAINTS_DEFAULT,
            "description" : "When function constraints are checked the amount of constraints matched must be at-least this.",
            "ignore" : []
        });
        bn_settings.register_setting_json(
            Self::MINIMUM_MATCHED_CONSTRAINTS_SETTING,
            &minimum_matched_constraints_props.to_string(),
        );

        let trivial_function_adjacent_allowed_props = json!({
            "title" : "Trivial Function Adjacent Constraints Allowed",
            "type" : "boolean",
            "default" : Self::TRIVIAL_FUNCTION_ADJACENT_ALLOWED_DEFAULT,
            "description" : "When function constraints are checked if this is enabled functions can match based off trivial adjacent functions.",
            "ignore" : []
        });
        bn_settings.register_setting_json(
            Self::TRIVIAL_FUNCTION_ADJACENT_ALLOWED_SETTING,
            &trivial_function_adjacent_allowed_props.to_string(),
        );

        let maximum_possible_functions_props = json!({
            "title" : "Maximum Possible Functions",
            "type" : "number",
            "default" : Self::MAXIMUM_POSSIBLE_FUNCTIONS_DEFAULT,
            "description" : "When matching any function that has a list of possible functions greater than this number will be skipped. A value of 0 will disable this check.",
            "ignore" : []
        });
        bn_settings.register_setting_json(
            Self::MAXIMUM_POSSIBLE_FUNCTIONS_SETTING,
            &maximum_possible_functions_props.to_string(),
        );
    }

    /// Retrieve matcher settings from [`BNSettings`].
    pub fn from_settings(bn_settings: &BNSettings, query_opts: &mut QueryOptions) -> Self {
        let mut settings = MatcherSettings::default();
        if bn_settings.contains(Self::TRIVIAL_FUNCTION_LEN_SETTING) {
            settings.trivial_function_len =
                bn_settings.get_integer_with_opts(Self::TRIVIAL_FUNCTION_LEN_SETTING, query_opts);
        }
        if bn_settings.contains(Self::MINIMUM_FUNCTION_LEN_SETTING) {
            settings.minimum_function_len =
                bn_settings.get_integer_with_opts(Self::MINIMUM_FUNCTION_LEN_SETTING, query_opts);
        }
        if bn_settings.contains(Self::MAXIMUM_FUNCTION_LEN_SETTING) {
            match bn_settings.get_integer_with_opts(Self::MAXIMUM_FUNCTION_LEN_SETTING, query_opts)
            {
                0 => settings.maximum_function_len = None,
                len => settings.maximum_function_len = Some(len),
            }
        }
        if bn_settings.contains(Self::MINIMUM_MATCHED_CONSTRAINTS_SETTING) {
            settings.minimum_matched_constraints = bn_settings
                .get_integer_with_opts(Self::MINIMUM_MATCHED_CONSTRAINTS_SETTING, query_opts)
                as usize;
        }
        if bn_settings.contains(Self::TRIVIAL_FUNCTION_ADJACENT_ALLOWED_SETTING) {
            settings.trivial_function_adjacent_allowed = bn_settings
                .get_bool_with_opts(Self::TRIVIAL_FUNCTION_ADJACENT_ALLOWED_SETTING, query_opts);
        }
        if bn_settings.contains(Self::MAXIMUM_POSSIBLE_FUNCTIONS_SETTING) {
            match bn_settings
                .get_integer_with_opts(Self::MAXIMUM_POSSIBLE_FUNCTIONS_SETTING, query_opts)
            {
                0 => settings.maximum_possible_functions = None,
                len => settings.maximum_possible_functions = Some(len),
            }
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
            maximum_possible_functions: Some(MatcherSettings::MAXIMUM_POSSIBLE_FUNCTIONS_DEFAULT),
        }
    }
}
