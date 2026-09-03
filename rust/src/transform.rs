use crate::binary_view::{BinaryReader, BinaryView};
use crate::data_buffer::DataBuffer;
use crate::metadata::Metadata;
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Ref, RefCountable};
use crate::settings::Settings;
use crate::string::{raw_to_string, strings_to_string_list, BnString, IntoCStr};
use binaryninjacore_sys::*;
use std::borrow::Cow;
use std::collections::HashMap;
use std::ffi::{c_char, c_void, CStr};
use std::fmt::{Debug, Formatter};
use std::mem::ManuallyDrop;
use std::path::Path;

pub type TransformType = BNTransformType;
pub type TransformResult = BNTransformResult;
pub type TransformSessionMode = BNTransformSessionMode;

/// Represents the input parameters for a transform operation, derived from the transforms [`TransformParameterInfo`]s.
pub type TransformInputParameters = HashMap<String, DataBuffer>;

bitflags::bitflags! {
    pub struct TransformCapabilities: u32 {
        const NONE = 0b00000000;
        const SUPPORTS_DETECTION = 0b00000001;
        const SUPPORTS_CONTEXT = 0b00000010;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessResult {
    /// if processing is incomplete and requires user input (file selection, password),
    /// additional parameters, or if an error occurred during transformation.
    Incomplete,
    /// If processing completed successfully (all transforms applied and no user input required).
    Complete,
}

/// Registers a custom transform without detection or context capabilities.
pub fn register_transform<C: CustomTransform>(custom: C) -> (&'static mut C, Transform) {
    register_transform_with_callbacks(custom, TransformCapabilities::NONE, None, None)
}

/// Registers a custom transform with the detection capability.
pub fn register_transform_with_detection<C>(custom: C) -> (&'static mut C, Transform)
where
    C: CustomTransform + DetectionTransform,
{
    register_transform_with_callbacks(
        custom,
        TransformCapabilities::SUPPORTS_DETECTION,
        Some(cb_can_decode::<C>),
        None,
    )
}

/// Registers a custom transform with the context capability.
pub fn register_transform_with_context<C>(custom: C) -> (&'static mut C, Transform)
where
    C: CustomTransform + ContextTransform,
{
    register_transform_with_callbacks(
        custom,
        TransformCapabilities::SUPPORTS_CONTEXT,
        None,
        Some(cb_decode_with_context::<C>),
    )
}

/// Registers a custom transform with both detection and context capabilities.
pub fn register_transform_with_detection_and_context<C>(custom: C) -> (&'static mut C, Transform)
where
    C: CustomTransform + DetectionTransform + ContextTransform,
{
    register_transform_with_callbacks(
        custom,
        TransformCapabilities::SUPPORTS_DETECTION | TransformCapabilities::SUPPORTS_CONTEXT,
        Some(cb_can_decode::<C>),
        Some(cb_decode_with_context::<C>),
    )
}

fn register_transform_with_callbacks<C: CustomTransform>(
    custom: C,
    capabilities: TransformCapabilities,
    can_decode: Option<unsafe extern "C" fn(*mut c_void, *mut BNBinaryView) -> bool>,
    decode_with_context: Option<
        unsafe extern "C" fn(
            *mut c_void,
            *mut BNTransformContext,
            *mut BNTransformParameter,
            usize,
        ) -> bool,
    >,
) -> (&'static mut C, Transform) {
    let name = C::NAME.to_cstr();
    let long_name = C::LONG_NAME.to_cstr();
    let group = C::GROUP.to_cstr();
    let transform = Box::leak(Box::new(custom));
    let mut callbacks = BNCustomTransform {
        context: transform as *mut _ as *mut c_void,
        getParameters: Some(cb_get_params::<C>),
        freeParameters: Some(cb_free_params),
        decode: Some(cb_decode::<C>),
        encode: Some(cb_encode::<C>),
        decodeWithContext: decode_with_context,
        canDecode: can_decode,
    };
    let result = unsafe {
        BNRegisterTransformTypeWithCapabilities(
            C::TYPE,
            capabilities.bits(),
            name.as_ptr(),
            long_name.as_ptr(),
            group.as_ptr(),
            &mut callbacks,
        )
    };
    assert!(
        !result.is_null(),
        "Should always be a valid pointer returned"
    );
    let core = unsafe { Transform::from_raw(result) };
    (transform, core)
}

pub trait CustomTransform {
    const TYPE: TransformType;
    const NAME: &'static str;
    const LONG_NAME: &'static str = Self::NAME;
    const GROUP: &'static str;
    const PARAMETERS: &'static [TransformParameterInfo] = &[];

    fn decode(&self, input: &[u8], params: &TransformInputParameters) -> Option<DataBuffer>;

    fn encode(&self, input: &[u8], params: &TransformInputParameters) -> Option<DataBuffer>;
}

/// A custom transform that can detect whether it can decode an input.
pub trait DetectionTransform: CustomTransform {
    fn can_decode(&self, reader: &mut BinaryReader) -> bool;
}

/// A custom transform that can decode an input within a [`TransformContext`].
pub trait ContextTransform: CustomTransform {
    fn decode_within_context(
        &self,
        context: &TransformContext,
        params: &TransformInputParameters,
    ) -> bool;
}

/// A [`Transform`] manages the decoding and encoding of data for a given format, such as a cryptographic
/// routine like AES, or a compression routine like LZMA.
///
/// Besides simple routines like the ones above, transforms can also be registered for "container" like
/// formats like ZIP, these formats are used to encapsulate multiple files or other data, and are operated
/// on using a [`TransformSession`].
pub struct Transform {
    handle: *mut BNTransform,
}

impl Transform {
    pub(crate) unsafe fn from_raw(handle: *mut BNTransform) -> Self {
        assert!(!handle.is_null());
        Self { handle }
    }

    pub fn by_name(name: &str) -> Option<Self> {
        let name = name.to_cstr();
        let handle = unsafe { BNGetTransformByName(name.as_ptr()) };
        if handle.is_null() {
            None
        } else {
            Some(unsafe { Self::from_raw(handle) })
        }
    }

    pub fn transform_type(&self) -> TransformType {
        unsafe { BNGetTransformType(self.handle) }
    }

    pub fn name(&self) -> String {
        unsafe { BnString::into_string(BNGetTransformName(self.handle)) }
    }

    pub fn long_name(&self) -> String {
        unsafe { BnString::into_string(BNGetTransformLongName(self.handle)) }
    }

    pub fn group(&self) -> String {
        unsafe { BnString::into_string(BNGetTransformGroup(self.handle)) }
    }

    pub fn capabilities(&self) -> TransformCapabilities {
        TransformCapabilities::from_bits_retain(unsafe { BNGetTransformCapabilities(self.handle) })
    }

    pub fn supports_detection(&self) -> bool {
        unsafe { BNTransformSupportsDetection(self.handle) }
    }

    pub fn supports_context(&self) -> bool {
        unsafe { BNTransformSupportsContext(self.handle) }
    }

    pub fn params(&self) -> Array<TransformParameterInfo> {
        let mut count = 0;
        let list = unsafe { BNGetTransformParameterList(self.handle, &mut count) };
        unsafe { Array::new(list, count, ()) }
    }

    pub fn can_decode(&self, input: &BinaryView) -> bool {
        unsafe { BNCanDecode(self.handle, input.handle) }
    }

    pub fn decode(&self, input: &[u8], params: &TransformInputParameters) -> Option<DataBuffer> {
        let buffer = DataBuffer::new(input);
        let output = DataBuffer::new(&[]);
        let mut param_list: Vec<BNTransformParameter> = params
            .iter()
            .map(|(name, value)| BNTransformParameter {
                name: BnString::into_raw(BnString::new(name)),
                value: value.as_raw(),
            })
            .collect();
        let result = unsafe {
            BNDecode(
                self.handle,
                buffer.as_raw(),
                output.as_raw(),
                param_list.as_mut_ptr(),
                param_list.len(),
            )
        };
        for param in param_list {
            unsafe { BnString::free_raw(param.name as *mut c_char) };
        }
        match result {
            true => Some(output),
            false => None,
        }
    }

    pub fn encode(&self, input: &[u8], params: &TransformInputParameters) -> Option<DataBuffer> {
        let buffer = DataBuffer::new(input);
        let output = DataBuffer::new(&[]);
        let mut param_list: Vec<BNTransformParameter> = params
            .iter()
            .map(|(name, value)| BNTransformParameter {
                name: BnString::into_raw(BnString::new(name)),
                value: value.as_raw(),
            })
            .collect();
        let result = unsafe {
            BNEncode(
                self.handle,
                buffer.as_raw(),
                output.as_raw(),
                param_list.as_mut_ptr(),
                param_list.len(),
            )
        };
        for param in param_list {
            unsafe { BnString::free_raw(param.name as *mut c_char) };
        }
        match result {
            true => Some(output),
            false => None,
        }
    }

    pub fn decode_within_context(
        &self,
        context: &TransformContext,
        params: &TransformInputParameters,
    ) -> bool {
        let mut param_list: Vec<BNTransformParameter> = params
            .iter()
            .map(|(name, value)| BNTransformParameter {
                name: BnString::into_raw(BnString::new(name)),
                value: value.as_raw(),
            })
            .collect();
        let result = unsafe {
            BNDecodeWithContext(
                self.handle,
                context.handle,
                param_list.as_mut_ptr(),
                param_list.len(),
            )
        };
        // Free the parameter name strings we allocated with `into_raw` above,
        // matching `decode`/`encode` (this was previously leaked).
        for param in param_list {
            unsafe { BnString::free_raw(param.name as *mut c_char) };
        }
        result
    }
}

impl Debug for Transform {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Transform")
            .field("name", &self.name())
            .field("long_name", &self.long_name())
            .field("group", &self.group())
            .field("params", &self.params().to_vec())
            .finish()
    }
}

/// A [`TransformContext`] represents a node in the transform tree, for use in a [`TransformSession`].
pub struct TransformContext {
    handle: *mut BNTransformContext,
}

impl TransformContext {
    pub(crate) unsafe fn from_raw(handle: *mut BNTransformContext) -> Self {
        assert!(!handle.is_null());
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: *mut BNTransformContext) -> Ref<Self> {
        Ref::new(Self::from_raw(handle))
    }

    /// The [`BinaryView`] that this context is associated with.
    ///
    /// This contains the data that is to be processed by the selected transform.
    pub fn input(&self) -> Ref<BinaryView> {
        unsafe { BinaryView::ref_from_raw(BNTransformContextGetInput(self.handle)) }
    }

    /// The name associated with this context, typically the name of the file in the case of a container like zip or archive.
    pub fn name(&self) -> String {
        unsafe { BnString::into_string(BNTransformContextGetFileName(self.handle)) }
    }

    /// A list of transforms that can be used to process this context.
    ///
    /// The list of available transforms is gathered by checking [`Transform::can_decode`] on all
    /// the registered transforms.
    pub fn available_transforms(&self) -> Array<BnString> {
        let mut count = 0;
        let transforms_raw =
            unsafe { BNTransformContextGetAvailableTransforms(self.handle, &mut count) };
        unsafe { Array::new(transforms_raw, count, ()) }
    }

    /// The name of the transform that created this context.
    pub fn transform_name(&self) -> String {
        unsafe { BnString::into_string(BNTransformContextGetTransformName(self.handle)) }
    }

    /// Override the [`Transform`] used to process this context.
    ///
    /// This is used when automatically selecting a transform is not possible (e.g. no magic bytes)
    /// or when there is multiple conflicting transforms.
    ///
    /// After setting the transform name, process the context with [`TransformSession::process_from`].
    pub fn set_transform_name(&self, transform_name: &str) {
        let raw_transform_name = transform_name.to_cstr();
        unsafe { BNTransformContextSetTransformName(self.handle, raw_transform_name.as_ptr()) }
    }

    pub fn set_transform_params(&self, params: &TransformInputParameters) {
        let mut param_list: Vec<BNTransformParameter> = params
            .iter()
            .map(|(name, value)| BNTransformParameter {
                name: BnString::into_raw(BnString::new(name)),
                value: value.as_raw(),
            })
            .collect();
        unsafe {
            BNTransformContextSetTransformParameters(
                self.handle,
                param_list.as_mut_ptr(),
                param_list.len(),
            )
        };
        for param in param_list {
            unsafe { BnString::from_raw(param.name as *mut c_char) };
        }
    }

    pub fn set_transform_param(&self, name: &str, value: &DataBuffer) {
        let raw_name = name.to_cstr();
        unsafe {
            BNTransformContextSetTransformParameter(self.handle, raw_name.as_ptr(), value.as_raw())
        }
    }

    pub fn has_transform_param(&self, name: &str) -> bool {
        let raw_name = name.to_cstr();
        unsafe { BNTransformContextHasTransformParameter(self.handle, raw_name.as_ptr()) }
    }

    pub fn clear_transform_params(&self, name: &str) {
        let raw_name = name.to_cstr();
        unsafe { BNTransformContextClearTransformParameter(self.handle, raw_name.as_ptr()) }
    }

    /// The message associated with the extraction operation performed by the parent.
    ///
    /// Originates from a call to [`TransformContext::create_child`].
    pub fn extraction_message(&self) -> String {
        unsafe { BnString::into_string(BNTransformContextGetExtractionMessage(self.handle)) }
    }

    /// The result associated with the extraction operation performed by the parent.
    ///
    /// Originates from a call to [`TransformContext::create_child`].
    pub fn extraction_result(&self) -> TransformResult {
        unsafe { BNTransformContextGetExtractionResult(self.handle) }
    }

    /// The result of applying the transform to the current input.
    ///
    /// Can be set with [`TransformContext::set_transform_result`].
    pub fn transform_result(&self) -> TransformResult {
        unsafe { BNTransformContextGetTransformResult(self.handle) }
    }

    /// Set the result of the applied transform on the current input.
    pub fn set_transform_result(&self, result: TransformResult) {
        unsafe { BNTransformContextSetTransformResult(self.handle, result) }
    }

    /// Metadata associated with this context.
    ///
    /// Can be accessed by transforms to store format-specific information.
    pub fn metadata(&self) -> Ref<Metadata> {
        // SAFETY: The metadata field in the core is always initialized to a key value data type.
        unsafe { Metadata::ref_from_raw(BNTransformContextGetMetadata(self.handle)) }
    }

    /// The parent context will be `None` if the context is the root context.
    pub fn parent(&self) -> Option<Ref<TransformContext>> {
        let parent_handle = unsafe { BNTransformContextGetParent(self.handle) };
        if parent_handle.is_null() {
            None
        } else {
            Some(unsafe { TransformContext::ref_from_raw(parent_handle) })
        }
    }

    pub fn children(&self) -> Array<TransformContext> {
        let mut count = 0;
        let raw = unsafe { BNTransformContextGetChildren(self.handle, &mut count) };
        unsafe { Array::new(raw, count, ()) }
    }

    pub fn child_by_name(&self, name: &str) -> Option<Ref<TransformContext>> {
        let name = name.to_cstr();
        let child_handle = unsafe { BNTransformContextGetChild(self.handle, name.as_ptr()) };
        if child_handle.is_null() {
            None
        } else {
            Some(unsafe { TransformContext::ref_from_raw(child_handle) })
        }
    }

    /// Create a new child context with the given data.
    ///
    /// The child context will be added as a child of this context.
    ///
    /// - `data`: The contents of the child context.
    /// - `extraction_result`: The result of the extraction operation.
    /// - `extraction_message`: The message associated with the extraction operation.
    /// - `is_descriptor`: Indicates whether the child context represents a descriptor, if so, the name
    ///   of the child context when shown will show both the parent name and then the child name ('parent.child').
    pub fn create_child(
        &self,
        name: &str,
        data: &DataBuffer,
        extraction_result: TransformResult,
        extraction_message: &str,
        is_descriptor: bool,
    ) -> Ref<TransformContext> {
        let name = name.to_cstr();
        let message = extraction_message.to_cstr();
        let child_handle = unsafe {
            BNTransformContextSetChild(
                self.handle,
                data.as_raw(),
                name.as_ptr(),
                extraction_result,
                message.as_ptr(),
                is_descriptor,
            )
        };
        assert!(
            !child_handle.is_null(),
            "Core always constructs a valid child context handle"
        );
        unsafe { TransformContext::ref_from_raw(child_handle) }
    }

    /// This context has no children.
    pub fn is_leaf(&self) -> bool {
        unsafe { BNTransformContextIsLeaf(self.handle) }
    }

    /// This context is the root of the transform session, it has no parent.
    pub fn is_root(&self) -> bool {
        unsafe { BNTransformContextIsRoot(self.handle) }
    }

    /// The list of available files for extraction.
    pub fn available_files(&self) -> Array<BnString> {
        let mut count = 0;
        let file_list = unsafe { BNTransformContextGetAvailableFiles(self.handle, &mut count) };
        assert!(
            !file_list.is_null(),
            "Core always returns a valid file list"
        );
        unsafe { Array::new(file_list, count, ()) }
    }

    /// Set the list of available files available for extraction.
    ///
    /// A [`Transform`] will call this to set the files that are possible to extract, but this won't
    /// actually mark the files for extraction by the [`TransformSession`]. To mark files for extraction,
    /// call [`TransformContext::set_requested_files`] _after_ calling this function.
    pub fn set_available_files(&self, files: &[&str]) {
        let file_list = strings_to_string_list(files);
        unsafe { BNTransformContextSetAvailableFiles(self.handle, file_list as _, files.len()) };
        unsafe { BNFreeStringList(file_list as _, files.len()) };
    }

    /// The files with which to extract from this context.
    ///
    /// This is used in [`TransformSession::process_from`] to actually perform the extraction of the
    /// child contexts.
    pub fn requested_files(&self) -> Array<BnString> {
        let mut count = 0;
        let file_list = unsafe { BNTransformContextGetRequestedFiles(self.handle, &mut count) };
        assert!(
            !file_list.is_null(),
            "Core always returns a valid file list"
        );
        unsafe { Array::new(file_list, count, ()) }
    }

    /// Specify which files to extract from this context. The associated [`TransformSession`] will then
    /// extract the specified files with [`TransformSession::process_from`].
    ///
    /// To get the list of possible files, use [`TransformContext::available_files`].
    pub fn set_requested_files(&self, files: &[&str]) {
        let file_list = strings_to_string_list(files);
        unsafe { BNTransformContextSetRequestedFiles(self.handle, file_list as _, files.len()) };
        unsafe { BNFreeStringList(file_list as _, files.len()) };
    }

    /// If the contents of this context represent a database file (BNDB).
    pub fn is_database(&self) -> bool {
        unsafe { BNTransformContextIsDatabase(self.handle) }
    }

    /// If this context is being used interactively.
    ///
    /// Transforms can use this to adjust their behavior. For example, filtering children in non-interactive
    /// mode while showing all children in interactive mode.
    pub fn is_interactive(&self) -> bool {
        unsafe { BNTransformContextIsInteractive(self.handle) }
    }

    pub fn settings(&self) -> Ref<Settings> {
        unsafe { Settings::ref_from_raw(BNTransformContextGetSettings(self.handle)) }
    }
}

impl ToOwned for TransformContext {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for TransformContext {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewTransformContextReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeTransformContext(handle.handle);
    }
}

impl CoreArrayProvider for TransformContext {
    type Raw = *mut BNTransformContext;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for TransformContext {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        unsafe { BNFreeTransformContextList(raw, count) };
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::from_raw(*raw)
    }
}

/// A [`TransformSession`] manages the lifetime of a set of [`TransformContext`]s, performing transformations
/// on said contexts, and extracting the results.
///
/// Sessions automatically apply appropriate transforms to navigate through nested containers, maintaining
/// a tree of [`TransformContext`] objects representing each extraction stage.
///
/// NOTE: All sessions have a [`TransformSessionMode`] that configures the session for one of the below:
///
/// - [`TransformSessionMode::TransformSessionModeDisabled`] The session will immediately end processing
///   and return the root context data as-is.
/// - [`TransformSessionMode::TransformSessionModeInteractive`] The session will process a context then
///   require another round of processing to traverse to the next level of contexts, used to progressively
///   transform the inputs rather than transforming all at once.
/// - [`TransformSessionMode::TransformSessionModeFull`] The session will exhaust all processable
///   contexts, or in other words, processing all at once.
pub struct TransformSession {
    handle: *mut BNTransformSession,
}

impl TransformSession {
    pub(crate) unsafe fn from_raw(handle: *mut BNTransformSession) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: *mut BNTransformSession) -> Ref<Self> {
        unsafe { Ref::new(Self::from_raw(handle)) }
    }

    /// Creates the new transform session for the given `file_path` on disk.
    ///
    /// NOTE: The [`TransformSessionMode`] will be set to the default specified by the `files.container.mode`
    /// setting in the Binary Ninja global settings (_not_ the settings passed into this function). To
    /// specify the mode, use [`TransformSession::new_with_mode`] instead.
    pub fn new(file_path: &Path, settings: &Settings) -> Ref<TransformSession> {
        let file_path = file_path.to_cstr();
        let settings = settings.serialize_schema().to_cstr();
        let session = unsafe { BNCreateTransformSession(file_path.as_ptr(), settings.as_ptr()) };
        assert!(
            !session.is_null(),
            "Transform session should always be valid"
        );
        unsafe { Self::ref_from_raw(session) }
    }

    /// Creates the new transform session for the given `file_path` on disk, with the specified `mode`.
    pub fn new_with_mode(
        file_path: &Path,
        settings: &Settings,
        mode: TransformSessionMode,
    ) -> Ref<TransformSession> {
        let file_path = file_path.to_cstr();
        let settings = settings.serialize_schema().to_cstr();
        let session = unsafe {
            BNCreateTransformSessionWithMode(file_path.as_ptr(), mode, settings.as_ptr())
        };
        assert!(
            !session.is_null(),
            "Transform session should always be valid"
        );
        unsafe { Self::ref_from_raw(session) }
    }

    /// Creates the new transform session for the given `view`.
    pub fn from_view(view: &BinaryView, settings: &Settings) -> Ref<TransformSession> {
        let settings = settings.serialize_schema().to_cstr();
        let session =
            unsafe { BNCreateTransformSessionFromBinaryView(view.handle, settings.as_ptr()) };
        assert!(
            !session.is_null(),
            "Transform session should always be valid"
        );
        unsafe { Self::ref_from_raw(session) }
    }

    /// Creates the new transform session for the given `view`.
    pub fn from_view_with_mode(
        view: &BinaryView,
        settings: &Settings,
        mode: TransformSessionMode,
    ) -> Ref<TransformSession> {
        let settings = settings.serialize_schema().to_cstr();
        let session = unsafe {
            BNCreateTransformSessionFromBinaryViewWithMode(view.handle, mode, settings.as_ptr())
        };
        assert!(
            !session.is_null(),
            "Transform session should always be valid"
        );
        unsafe { Self::ref_from_raw(session) }
    }

    /// Creates the new transform session for the given `context`.
    pub fn from_context(
        context: &TransformContext,
        settings: &Settings,
        mode: TransformSessionMode,
    ) -> Ref<TransformSession> {
        let settings = settings.serialize_schema().to_cstr();
        let session = unsafe {
            BNCreateTransformSessionFromTransformContextWithMode(
                context.handle,
                mode,
                settings.as_ptr(),
            )
        };
        assert!(
            !session.is_null(),
            "Transform session should always be valid"
        );
        unsafe { Self::ref_from_raw(session) }
    }

    pub fn root_context(&self) -> Option<Ref<TransformContext>> {
        let handle = unsafe { BNTransformSessionGetRootContext(self.handle) };
        if handle.is_null() {
            None
        } else {
            Some(unsafe { TransformContext::ref_from_raw(handle) })
        }
    }

    pub fn current_context(&self) -> Option<Ref<TransformContext>> {
        let handle = unsafe { BNTransformSessionGetCurrentContext(self.handle) };
        if handle.is_null() {
            None
        } else {
            Some(unsafe { TransformContext::ref_from_raw(handle) })
        }
    }

    /// Process starting at the [`TransformSession::root_context`].
    ///
    /// See [`TransformSession`] for more information on how the different [`TransformSessionMode`]s affect processing.
    pub fn process(&self) -> ProcessResult {
        match unsafe { BNTransformSessionProcess(self.handle) } {
            false => ProcessResult::Incomplete,
            true => ProcessResult::Complete,
        }
    }

    /// Process starting at the given `context`.
    ///
    /// See [`TransformSession`] for more information on how the different [`TransformSessionMode`]s affect processing.
    pub fn process_from(&self, context: &TransformContext) -> ProcessResult {
        match unsafe { BNTransformSessionProcessFrom(self.handle, context.handle) } {
            false => ProcessResult::Incomplete,
            true => ProcessResult::Complete,
        }
    }

    /// Is there anything in the session to process?
    ///
    /// Checks the root context to see if it has any possible transforms, if it does not, then that
    /// means the session will have nothing to process.
    pub fn has_any_stages(&self) -> bool {
        unsafe { BNTransformSessionHasAnyStages(self.handle) }
    }

    /// If the tree has a single linear path, meaning that there is only one possible sequence of contexts to process.
    pub fn has_single_path(&self) -> bool {
        unsafe { BNTransformSessionHasSinglePath(self.handle) }
    }

    /// Selected contexts are the contexts that will be loaded for analysis.
    ///
    /// Use [`TransformSession::set_selected_contexts`] to specify the contexts which to keep for further analysis.
    pub fn selected_contexts(&self) -> Array<TransformContext> {
        let mut count = 0;
        let handle = unsafe { BNTransformSessionGetSelectedContexts(self.handle, &mut count) };
        unsafe { Array::new(handle, count, ()) }
    }

    /// Specifies the contexts which will be loaded for analysis, anything not in this list will be
    /// considered temporary and will be discarded.
    pub fn set_selected_contexts(&self, contexts: &[Ref<TransformContext>]) {
        let mut contexts: Vec<*mut BNTransformContext> =
            contexts.iter().map(|c| c.handle).collect();
        unsafe {
            BNTransformSessionSetSelectedContexts(
                self.handle,
                contexts.as_mut_ptr(),
                contexts.len(),
            )
        }
    }
}

impl ToOwned for TransformSession {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { RefCountable::inc_ref(self) }
    }
}

unsafe impl RefCountable for TransformSession {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewTransformSessionReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeTransformSession(handle.handle);
    }
}

#[derive(Clone, PartialEq, Eq, Debug, Hash, PartialOrd, Ord)]
pub struct TransformParameterInfo {
    pub name: Cow<'static, str>,
    pub long_name: Cow<'static, str>,
    pub length: Option<usize>,
}

impl TransformParameterInfo {
    pub fn new(name: &'static str, length: Option<usize>) -> Self {
        Self {
            name: Cow::Borrowed(name),
            long_name: Cow::Borrowed(name),
            length,
        }
    }

    pub fn new_with_long(
        name: &'static str,
        long_name: &'static str,
        length: Option<usize>,
    ) -> Self {
        Self {
            name: Cow::Borrowed(name),
            long_name: Cow::Borrowed(long_name),
            length,
        }
    }

    pub fn from_raw(value: BNTransformParameterInfo) -> Self {
        Self {
            name: Cow::Owned(raw_to_string(value.name).unwrap_or_default()),
            long_name: Cow::Owned(raw_to_string(value.longName).unwrap_or_default()),
            length: Some(value.fixedLength),
        }
    }

    pub fn into_raw(self) -> BNTransformParameterInfo {
        BNTransformParameterInfo {
            name: BnString::into_raw(BnString::new(self.name)),
            longName: BnString::into_raw(BnString::new(self.long_name)),
            fixedLength: self.length.unwrap_or(0),
        }
    }

    pub fn free_raw(value: BNTransformParameterInfo) {
        unsafe {
            BnString::free_raw(value.name);
            BnString::free_raw(value.longName);
        }
    }
}

impl CoreArrayProvider for TransformParameterInfo {
    type Raw = BNTransformParameterInfo;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for TransformParameterInfo {
    unsafe fn free(raw: *mut Self::Raw, count: usize, _context: &Self::Context) {
        unsafe { BNFreeTransformParameterList(raw, count) };
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::from_raw(*raw)
    }
}

unsafe extern "C" fn cb_get_params<C: CustomTransform>(
    _ctxt: *mut c_void,
    count: *mut usize,
) -> *mut BNTransformParameterInfo {
    let boxed_params: Box<[_]> = C::PARAMETERS
        .iter()
        .cloned()
        .map(TransformParameterInfo::into_raw)
        .collect();
    let leaked_params = Box::leak(boxed_params);
    *count = leaked_params.len();
    leaked_params as *mut _ as *mut BNTransformParameterInfo
}

unsafe extern "C" fn cb_free_params(params: *mut BNTransformParameterInfo, count: usize) {
    let params = Box::from_raw(std::ptr::slice_from_raw_parts_mut(params, count));
    for param in params {
        TransformParameterInfo::free_raw(param);
    }
}

unsafe extern "C" fn cb_decode<C: CustomTransform>(
    ctxt: *mut c_void,
    input: *mut BNDataBuffer,
    output: *mut BNDataBuffer,
    params: *mut BNTransformParameter,
    param_count: usize,
) -> bool {
    let ctxt = ctxt as *mut C;
    let raw_params = core::slice::from_raw_parts(params, param_count);
    let params: TransformInputParameters = raw_params
        .iter()
        .map(|p| {
            let name = CStr::from_ptr(p.name).to_string_lossy();
            // We do not own the buffer, clone it and then make sure not to drop the original.
            let buffer = DataBuffer::from_raw(p.value);
            let owned_buffer = buffer.clone();
            std::mem::forget(buffer);
            (name.to_string(), owned_buffer)
        })
        .collect();
    let input = ManuallyDrop::new(DataBuffer::from_raw(input));
    let mut output = ManuallyDrop::new(DataBuffer::from_raw(output));
    match (*ctxt).decode(input.as_ref(), &params) {
        Some(buffer) => {
            output.set_data(buffer.as_ref());
            true
        }
        None => false,
    }
}

unsafe extern "C" fn cb_encode<C: CustomTransform>(
    ctxt: *mut c_void,
    input: *mut BNDataBuffer,
    output: *mut BNDataBuffer,
    params: *mut BNTransformParameter,
    param_count: usize,
) -> bool {
    let ctxt = ctxt as *mut C;
    let raw_params = core::slice::from_raw_parts(params, param_count);
    let params: TransformInputParameters = raw_params
        .iter()
        .map(|p| {
            let name = CStr::from_ptr(p.name).to_string_lossy();
            // We do not own the buffer, clone it and then make sure not to drop the original.
            let buffer = DataBuffer::from_raw(p.value);
            let owned_buffer = buffer.clone();
            std::mem::forget(buffer);
            (name.to_string(), owned_buffer)
        })
        .collect();
    let input = ManuallyDrop::new(DataBuffer::from_raw(input));
    let mut output = ManuallyDrop::new(DataBuffer::from_raw(output));
    match (*ctxt).encode(input.as_ref(), &params) {
        Some(buffer) => {
            output.set_data(buffer.as_ref());
            true
        }
        None => false,
    }
}

unsafe extern "C" fn cb_decode_with_context<C: CustomTransform + ContextTransform>(
    ctxt: *mut c_void,
    input: *mut BNTransformContext,
    params: *mut BNTransformParameter,
    param_count: usize,
) -> bool {
    let ctxt = ctxt as *mut C;
    let raw_params = core::slice::from_raw_parts(params, param_count);
    let params: TransformInputParameters = raw_params
        .iter()
        .map(|p| {
            let name = CStr::from_ptr(p.name).to_string_lossy();
            // We do not own the buffer, clone it and then make sure not to drop the original.
            let buffer = DataBuffer::from_raw(p.value);
            let owned_buffer = buffer.clone();
            std::mem::forget(buffer);
            (name.to_string(), owned_buffer)
        })
        .collect();
    let input = TransformContext::from_raw(input);
    (*ctxt).decode_within_context(&input, &params)
}

unsafe extern "C" fn cb_can_decode<C: CustomTransform + DetectionTransform>(
    ctxt: *mut c_void,
    input: *mut BNBinaryView,
) -> bool {
    let ctxt = ctxt as *mut C;
    let input = BinaryView::from_raw(input);
    let mut reader = BinaryReader::new(&input);
    (*ctxt).can_decode(&mut reader)
}
