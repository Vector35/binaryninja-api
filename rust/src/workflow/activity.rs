use std::{
    ffi::{c_void, CString},
    ptr::NonNull,
};

use binaryninjacore_sys::*;
use serde_derive::{Deserialize, Serialize};

use crate::{
    rc::{Ref, RefCountable},
    string::{BnString, IntoCStr},
    workflow::AnalysisContext,
};

// TODO: This needs to be made into a trait similar to that of `Command`.
/// An `Activity` represents a fundamental unit of work within a workflow. It encapsulates
/// a specific analysis step or action as a callback function, which is augmented by a configuration.
/// The configuration defines the activity's metadata, eligibility criteria, and execution semantics,
/// allowing it to seamlessly integrate into the workflow system.
///
/// ```
/// use binaryninja::workflow::{activity, Activity, AnalysisContext};
///
/// fn activity_callback(context: &AnalysisContext) {
///     // Perform custom analysis using data provided in the context.
/// }
///
/// let config = activity::Config::action(
///     "example.analysis.analyzeFunction",
///     "Analyze functions",
///     "This activity performs custom analysis on each function"
/// ).eligibility(activity::Eligibility::auto());
/// let activity = Activity::new_with_action(config, activity_callback);
///
/// // Register the activity in a `Workflow`.
/// ```
///
/// See [Activity Fundamentals](https://docs.binary.ninja/dev/workflows.html#activity-fundamentals) for more information.
#[repr(transparent)]
pub struct Activity {
    pub(crate) handle: NonNull<BNActivity>,
}

impl Activity {
    #[allow(unused)]
    pub(crate) unsafe fn from_raw(handle: NonNull<BNActivity>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: NonNull<BNActivity>) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    pub fn new(config: impl AsConfig) -> Ref<Self> {
        unsafe extern "C" fn cb_action_nop(_: *mut c_void, _: *mut BNAnalysisContext) {}
        let config = config.as_config();
        let result =
            unsafe { BNCreateActivity(config.as_ptr(), std::ptr::null_mut(), Some(cb_action_nop)) };
        unsafe { Activity::ref_from_raw(NonNull::new(result).unwrap()) }
    }

    pub fn new_with_action<F>(config: impl AsConfig, mut action: F) -> Ref<Self>
    where
        F: FnMut(&AnalysisContext),
    {
        unsafe extern "C" fn cb_action<F: FnMut(&AnalysisContext)>(
            ctxt: *mut c_void,
            analysis: *mut BNAnalysisContext,
        ) {
            let ctxt = &mut *(ctxt as *mut F);
            if let Some(analysis) = NonNull::new(analysis) {
                let analysis = AnalysisContext::from_raw(analysis);
                let _span = ffi_span!("Activity::action", analysis.view());
                ctxt(&analysis)
            }
        }
        let config = config.as_config();
        let result = unsafe {
            BNCreateActivity(
                config.as_ptr(),
                &mut action as *mut F as *mut c_void,
                Some(cb_action::<F>),
            )
        };
        unsafe { Activity::ref_from_raw(NonNull::new(result).unwrap()) }
    }

    pub fn name(&self) -> String {
        let result = unsafe { BNActivityGetName(self.handle.as_ptr()) };
        assert!(!result.is_null());
        unsafe { BnString::into_string(result) }
    }
}

impl ToOwned for Activity {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for Activity {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: NonNull::new(BNNewActivityReference(handle.handle.as_ptr()))
                .expect("valid handle"),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeActivity(handle.handle.as_ptr());
    }
}

pub trait AsConfig {
    fn as_config(&self) -> CString;
}

impl AsConfig for &str {
    fn as_config(&self) -> std::ffi::CString {
        self.to_cstr()
    }
}

/// The configuration for an `Activity`, defining its metadata, eligibility criteria, and execution semantics.
#[must_use]
#[derive(Deserialize, Serialize, Debug)]
pub struct Config {
    /// A unique identifier for the activity.
    pub name: String,

    /// A human-readable title for the activity.
    pub title: String,

    /// A brief description of the activity's purpose and functionality.
    pub description: String,

    /// The role of the activity within the workflow, determining its behavior and interaction with other activities.
    #[serde(default)]
    pub role: Role,

    /// Names by which this activity has previously been known.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub aliases: Vec<String>,

    /// The conditions that determine when the activity should execute.
    #[serde(default)]
    pub eligibility: Eligibility,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub dependencies: Option<Dependencies>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct Dependencies {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub downstream: Vec<String>,
}

impl Config {
    /// Creates a new instance with role [`Role::Action`] and the specified name, title, and description.
    pub fn action(
        name: impl Into<String>,
        title: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            title: title.into(),
            description: description.into(),
            role: Role::Action,
            aliases: Vec::new(),
            eligibility: Eligibility::default(),
            dependencies: None,
        }
    }

    /// Sets the [`aliases`](field@Config::aliases) field, which contains names by which this activity has previously been known.
    pub fn aliases<I, S>(mut self, aliases: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.aliases = aliases.into_iter().map(|s| s.into()).collect();
        self
    }

    /// Sets the [`eligibility`](field@Config::eligibility) field, which defines the conditions under which this activity is eligible for execution.
    pub fn eligibility(mut self, eligibility: Eligibility) -> Self {
        self.eligibility = eligibility;
        self
    }

    /// Sets the [`dependencies`](field@Config::dependencies) field to specify dependencies that should be triggered after this activity completes.
    pub fn downstream_dependencies<I, S>(mut self, dependencies: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.dependencies = Some(Dependencies {
            downstream: dependencies.into_iter().map(|s| s.into()).collect(),
        });
        self
    }
}

impl AsConfig for &Config {
    fn as_config(&self) -> CString {
        serde_json::to_string(self)
            .expect("Failed to serialize Config")
            .to_cstr()
    }
}

impl AsConfig for Config {
    fn as_config(&self) -> CString {
        (&self).as_config()
    }
}

/// Defines the behavior of the activity in the workflow.
///
/// NOTE: Activities with the subflow role are only permitted in module workflows.
/// Subflows are not supported within function workflows.
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
#[derive(Default)]
pub enum Role {
    /// The default role; performs a specific task.
    #[default]
    Action,

    /// Contains child activities and uses an eligibility handler to determine which child activities to execute.
    /// This enables the ability to have a dynamic and reactive execution pipeline.
    Selector,

    /// Creates a new task context and asynchronously processes its workflow sub-graph on a new thread within
    /// the workflow machine. The subflow executes asynchronously from the requestor, allowing the original
    /// thread to return immediately. Within this context, multiple task actions can be enqueued, enabling
    /// extensive parallel processing. After completing its workflow sub-graph, it enters a stall state,
    /// waiting for all its asynchronous task actions to complete.
    Subflow,

    /// Asynchronously processes the workflow graph on a new thread within the workflow machine.
    /// `Task` activities enable the pipeline to execute asynchronously from its requestor. `Task` activities
    /// require a task context to be present; if no task context exists, they execute immediately in the
    /// current thread.
    Task,

    Sequence,
    Listener,
}

/// The conditions that determine when an activity should execute.
#[must_use]
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Eligibility {
    /// An object that automatically generates a boolean control setting and corresponding predicate.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto: Option<Auto>,

    /// Indicates whether the activity should run only once across all file/analysis sessions.
    /// Once the activity runs, its state is saved persistently, and it will not run again unless
    /// explicitly reset. This is useful for activities that only need to be performed exactly once,
    /// such as initial setup tasks.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_once: Option<bool>,

    /// Indicates whether the activity should run only once per session. Its state is not
    /// persisted, so it will run again in a new session. This is useful for activities
    /// that should be performed once per analysis session, such as initialization steps
    /// specific to a particular execution context.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_once_per_session: Option<bool>,

    /// Indicates if a subflow is eligible for re-execution based on its eligibility logic.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuation: Option<bool>,

    /// Objects that define the condition that must be met for the activity to be eligible to run.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub predicates: Vec<Predicate>,

    /// Logical operator that defines how multiple predicates are combined.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logical_operator: Option<PredicateLogicalOperator>,
}

impl Eligibility {
    /// Creates a new instance without an automatically generated boolean control setting.
    /// The activity is eligible to run by default.
    pub fn without_setting() -> Self {
        Eligibility {
            auto: None,
            run_once: None,
            run_once_per_session: None,
            continuation: None,
            predicates: vec![],
            logical_operator: None,
        }
    }

    /// Creates a new instance with an automatically generated boolean control setting and corresponding predicate.
    /// The setting is enabled by default.
    pub fn auto() -> Self {
        Eligibility {
            auto: Some(Auto::new()),
            run_once: None,
            run_once_per_session: None,
            continuation: None,
            predicates: vec![],
            logical_operator: None,
        }
    }

    /// Creates a new instance with an automatically generated boolean control setting and corresponding predicate.
    /// The setting has the value `value` by default.
    pub fn auto_with_default(value: bool) -> Self {
        Eligibility {
            auto: Some(Auto::new().default(value)),
            run_once: None,
            run_once_per_session: None,
            continuation: None,
            predicates: vec![],
            logical_operator: None,
        }
    }

    /// Sets the [`run_once`](field@Eligibility::run_once) field, indicating whether the activity should run only once across all file/analysis sessions.
    pub fn run_once(mut self, value: bool) -> Self {
        self.run_once = Some(value);
        self
    }

    /// Sets the [`run_once_per_session`](field@Eligibility::run_once_per_session) field, indicating whether the activity should run only once per session.
    pub fn run_once_per_session(mut self, value: bool) -> Self {
        self.run_once_per_session = Some(value);
        self
    }

    /// Sets the [`continuation`](field@Eligibility::continuation) field, indicating whether a subflow is eligible for re-execution based on its eligibility logic.
    pub fn continuation(mut self, value: bool) -> Self {
        self.continuation = Some(value);
        self
    }

    /// Sets the predicate that must be satisfied for the activity to be eligible to run.
    pub fn predicate(mut self, predicate: impl Into<Predicate>) -> Self {
        self.predicates = vec![predicate.into()];
        self
    }

    /// Sets the predicates that must be satisfied for the activity to be eligible to run.
    /// If multiple predicates are provided, they are combined using a logical OR.
    pub fn matching_any_predicate(mut self, predicates: &[Predicate]) -> Self {
        self.predicates = predicates.to_vec();
        self.logical_operator = Some(PredicateLogicalOperator::Or);
        self
    }

    /// Sets the predicates that must be satisfied for the activity to be eligible to run.
    /// If multiple predicates are provided, they are combined using a logical AND.
    pub fn matching_all_predicates(mut self, predicates: &[Predicate]) -> Self {
        self.predicates = predicates.to_vec();
        self.logical_operator = Some(PredicateLogicalOperator::And);
        self
    }
}

impl Default for Eligibility {
    fn default() -> Self {
        Self::auto()
    }
}

/// Represents the request for an automatically generated boolean control setting and corresponding predicate.
#[must_use]
#[derive(Deserialize, Serialize, Debug, Default)]
pub struct Auto {
    /// The default value for the setting. If `None`, the setting is enabled by default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<bool>,
}

impl Auto {
    /// Creates a new `Auto` instance that represents a setting that is enabled by default.
    pub fn new() -> Self {
        Self { default: None }
    }

    /// Sets the `default` value for the setting.
    pub fn default(mut self, value: bool) -> Self {
        self.default = Some(value);
        self
    }
}

/// A predicate that can be used to determine the eligibility of an activity.
///
/// See [`ViewType`] and [`Setting`] for specific predicates that can be used.
#[must_use]
#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Predicate {
    #[serde(flatten)]
    predicate_type: PredicateType,
    operator: Operator,
    value: serde_json::Value,
}

/// A predicate that checks the type of the [`BinaryView`](crate::binary_view::BinaryView).
#[must_use]
pub enum ViewType {
    In(Vec<String>),
    NotIn(Vec<String>),
}

impl ViewType {
    /// Creates a new predicate that checks if the type of the [`BinaryView`](crate::binary_view::BinaryView)
    /// _is_ in the provided list.
    pub fn in_<I, S>(values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        ViewType::In(values.into_iter().map(|s| s.as_ref().to_string()).collect())
    }

    /// Creates a new predicate that checks if the type of the [`BinaryView`](crate::binary_view::BinaryView)
    /// _is not_ in the provided list.
    pub fn not_in<I, S>(values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        ViewType::NotIn(values.into_iter().map(|s| s.as_ref().to_string()).collect())
    }
}

impl From<ViewType> for Predicate {
    fn from(predicate: ViewType) -> Self {
        match predicate {
            ViewType::In(value) => Predicate {
                predicate_type: PredicateType::ViewType,
                operator: Operator::In,
                value: serde_json::json!(value),
            },
            ViewType::NotIn(value) => Predicate {
                predicate_type: PredicateType::ViewType,
                operator: Operator::NotIn,
                value: serde_json::json!(value),
            },
        }
    }
}

/// A predicate that checks the platform of the [`BinaryView`](crate::binary_view::BinaryView).
#[must_use]
pub enum Platform {
    In(Vec<String>),
    NotIn(Vec<String>),
}

impl Platform {
    /// Creates a new predicate that checks if the platform of the [`BinaryView`](crate::binary_view::BinaryView)
    /// _is_ in the provided list.
    pub fn in_<I, S>(values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Platform::In(values.into_iter().map(|s| s.as_ref().to_string()).collect())
    }

    /// Creates a new predicate that checks if the platform of the [`BinaryView`](crate::binary_view::BinaryView)
    /// _is not_ in the provided list.
    pub fn not_in<I, S>(values: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Platform::NotIn(values.into_iter().map(|s| s.as_ref().to_string()).collect())
    }
}

impl From<Platform> for Predicate {
    fn from(predicate: Platform) -> Self {
        match predicate {
            Platform::In(value) => Predicate {
                predicate_type: PredicateType::Platform,
                operator: Operator::In,
                value: serde_json::json!(value),
            },
            Platform::NotIn(value) => Predicate {
                predicate_type: PredicateType::Platform,
                operator: Operator::NotIn,
                value: serde_json::json!(value),
            },
        }
    }
}

/// A predicate that evaluates the value of a specific setting.
#[must_use]
pub struct Setting {
    identifier: String,
    operator: Operator,
    value: serde_json::Value,
}

impl Setting {
    /// Creates a new predicate that evaluates the value of a specific setting against `value` using `operator`.
    pub fn new(
        identifier: impl Into<String>,
        operator: Operator,
        value: impl serde::Serialize,
    ) -> Self {
        Self {
            identifier: identifier.into(),
            operator,
            value: serde_json::json!(value),
        }
    }

    /// Creates a new predicate that checks if the value of the setting is equal to `value`.
    pub fn eq(identifier: impl Into<String>, value: impl serde::Serialize) -> Self {
        Self::new(identifier, Operator::Eq, value)
    }

    /// Creates a new predicate that checks if the value of the setting is not equal to `value`.
    pub fn ne(identifier: impl Into<String>, value: impl serde::Serialize) -> Self {
        Self::new(identifier, Operator::Ne, value)
    }

    /// Creates a new predicate that checks if the value of the setting is less than `value`.
    pub fn lt(identifier: impl Into<String>, value: impl serde::Serialize) -> Self {
        Self::new(identifier, Operator::Lt, value)
    }

    /// Creates a new predicate that checks if the value of the setting is less than or equal to `value`.
    pub fn lte(identifier: impl Into<String>, value: impl serde::Serialize) -> Self {
        Self::new(identifier, Operator::Lte, value)
    }

    /// Creates a new predicate that checks if the value of the setting is greater than `value`.
    pub fn gt(identifier: impl Into<String>, value: impl serde::Serialize) -> Self {
        Self::new(identifier, Operator::Gt, value)
    }

    /// Creates a new predicate that checks if the value of the setting is greater than or equal to `value`.
    pub fn gte(identifier: impl Into<String>, value: impl serde::Serialize) -> Self {
        Self::new(identifier, Operator::Gte, value)
    }

    /// Creates a new predicate that checks if the value of the setting is in the provided list.
    pub fn in_(identifier: impl Into<String>, value: impl serde::Serialize) -> Self {
        Self::new(identifier, Operator::In, value)
    }

    /// Creates a new predicate that checks if the value of the setting is not in the provided list.
    pub fn not_in(identifier: impl Into<String>, value: impl serde::Serialize) -> Self {
        Self::new(identifier, Operator::NotIn, value)
    }
}

impl From<Setting> for Predicate {
    fn from(setting: Setting) -> Self {
        Predicate {
            predicate_type: PredicateType::Setting {
                identifier: setting.identifier,
            },
            operator: setting.operator,
            value: setting.value,
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase", tag = "type")]
enum PredicateType {
    Setting { identifier: String },
    ViewType,
    Platform,
}

#[derive(Deserialize, Serialize, Debug, Copy, Clone)]
pub enum Operator {
    #[serde(rename = "==")]
    Eq,
    #[serde(rename = "!=")]
    Ne,
    #[serde(rename = "<")]
    Lt,
    #[serde(rename = "<=")]
    Lte,
    #[serde(rename = ">")]
    Gt,
    #[serde(rename = ">=")]
    Gte,
    #[serde(rename = "in")]
    In,
    #[serde(rename = "not in")]
    NotIn,
}

#[derive(Deserialize, Serialize, Debug, Clone, Copy)]
#[serde(rename_all = "camelCase")]
pub enum PredicateLogicalOperator {
    And,
    Or,
}
