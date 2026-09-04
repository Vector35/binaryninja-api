//! Interface for registering and using scripting providers.

use std::ffi::{c_char, c_void, CStr};
use std::mem::MaybeUninit;
use std::path::Path;
use std::pin::Pin;

use binaryninjacore_sys::*;

use crate::basic_block::BasicBlock;
use crate::binary_view::BinaryView;
use crate::function::{Function, NativeBlock};
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner, Ref, RefCountable};
use crate::string::{strings_to_string_list, BnString, IntoCStr};

pub type ScriptingProviderExecuteResult = BNScriptingProviderExecuteResult;
pub type ScriptingProviderInputReadyState = BNScriptingProviderInputReadyState;

/// Register a new scripting provider.
pub fn register_scripting_provider<S>(provider: S) -> (&'static S, ScriptingProvider)
where
    S: CustomScriptingProvider,
{
    let name = S::NAME.to_cstr();
    let api_name = S::API_NAME.to_cstr();
    let leaked_provider = Box::leak(Box::new(provider));
    let result = unsafe {
        BNRegisterScriptingProvider(
            name.as_ptr(),
            api_name.as_ptr(),
            &mut BNScriptingProviderCallbacks {
                context: leaked_provider as *mut _ as *mut c_void,
                createInstance: Some(cb_create_instance::<S>),
                loadModule: Some(cb_load_module::<S>),
                installModules: Some(cb_install_modules::<S>),
            },
        )
    };
    assert!(
        !result.is_null(),
        "Should always be able to register a provider"
    );
    let provider_core = unsafe { ScriptingProvider::from_raw(result) };
    (leaked_provider, provider_core)
}

pub trait CustomScriptingProvider {
    type Instance: CustomScriptingInstance;

    const NAME: &'static str;
    const API_NAME: &'static str;

    fn load_module(&self, repo_path: &str, plugin_path: &str, force: bool) -> bool;

    fn install_modules(&self, modules: &str) -> bool;

    fn create_instance(&self) -> Self::Instance;
}

pub trait CustomScriptingInstance {
    fn execute_script_input(
        &self,
        instance: &ScriptingInstance,
        input: &str,
    ) -> ScriptingProviderExecuteResult;

    fn execute_script_input_from_file(
        &self,
        instance: &ScriptingInstance,
        file_path: &Path,
    ) -> ScriptingProviderExecuteResult;

    /// Called when the user requests that the current executing input be canceled.
    fn cancel_script_input(&self) {}

    /// Called when the binary view is no longer available.
    ///
    /// This function should release any resources associated with the binary view.
    fn release_binary_view(&self, _view: &BinaryView) {}

    /// Called when the current binary view is changed.
    ///
    /// The `view` will be `None` if there is no current binary view.
    fn set_current_binary_view(&self, _view: Option<&BinaryView>) {}

    /// Called when the current function is changed.
    ///
    /// The `func` will be `None` if there is no current function.
    fn set_current_function(&self, _func: Option<&Function>) {}

    /// Called when the current basic block is changed.
    ///
    /// The `block` will be `None` if there is no current basic block.
    fn set_current_basic_block(&self, _block: Option<&BasicBlock<NativeBlock>>) {}

    /// Called when the current selected address range is changed.
    fn set_current_selection(&self, _begin: u64, _end: u64) {}

    fn complete_input(&self, _text: &str, _state: u64) -> String {
        "".to_string()
    }

    // TODO: What is the point of this? There is not difference I can ascertain from just impl Drop on the instance type.
    /// Perform cleanup of resources, this is called before the instance destructor is called.
    fn stop(&self) {}
}

pub trait ScriptingOutputListener: Sync + Send {
    fn output(&self, text: &str);
    fn warning(&self, text: &str);
    fn error(&self, text: &str);
    fn input_ready_state_changed(&self, state: ScriptingProviderInputReadyState);
}

#[derive(Clone, Copy, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct ScriptingProvider {
    handle: *mut BNScriptingProvider,
}

impl ScriptingProvider {
    pub(crate) unsafe fn from_raw(handle: *mut BNScriptingProvider) -> Self {
        Self { handle }
    }

    pub fn all() -> Array<Self> {
        let mut count = 0;
        let result = unsafe { BNGetScriptingProviderList(&mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    pub fn by_name(name: &str) -> Option<ScriptingProvider> {
        let name = name.to_cstr();
        let result = unsafe { BNGetScriptingProviderByName(name.as_ptr()) };
        if result.is_null() {
            None
        } else {
            unsafe { Some(Self::from_raw(result)) }
        }
    }

    pub fn by_api_name(name: &str) -> Option<ScriptingProvider> {
        let name = name.to_cstr();
        let result = unsafe { BNGetScriptingProviderByAPIName(name.as_ptr()) };
        if result.is_null() {
            None
        } else {
            unsafe { Some(Self::from_raw(result)) }
        }
    }

    pub fn name(&self) -> String {
        let result = unsafe { BNGetScriptingProviderName(self.handle) };
        assert!(!result.is_null());
        unsafe { BnString::into_string(result) }
    }

    pub fn api_name(&self) -> String {
        let result = unsafe { BNGetScriptingProviderAPIName(self.handle) };
        assert!(!result.is_null());
        unsafe { BnString::into_string(result) }
    }

    pub fn load_module(&self, repository: &str, module: &str, force: bool) -> bool {
        let repository = repository.to_cstr();
        let module = module.to_cstr();
        unsafe {
            BNLoadScriptingProviderModule(self.handle, repository.as_ptr(), module.as_ptr(), force)
        }
    }

    pub fn install_modules(&self, modules: &[&str]) -> bool {
        let modules_raw = strings_to_string_list(modules);
        let result =
            unsafe { BNInstallScriptingProviderModules(self.handle, modules_raw as *const _) };
        unsafe { BNFreeStringList(modules_raw, modules.len()) };
        result
    }

    pub fn create_instance(&self) -> Ref<ScriptingInstance> {
        let instance = unsafe { BNCreateScriptingProviderInstance(self.handle) };
        unsafe { ScriptingInstance::ref_from_raw(instance) }
    }
}

unsafe impl Sync for ScriptingProvider {}
unsafe impl Send for ScriptingProvider {}

impl CoreArrayProvider for ScriptingProvider {
    type Raw = *mut BNScriptingProvider;
    type Context = ();
    type Wrapped<'a> = Self;
}

unsafe impl CoreArrayProviderInner for ScriptingProvider {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeScriptingProviderList(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::from_raw(*raw)
    }
}

#[repr(transparent)]
pub struct ScriptingInstance {
    handle: *mut BNScriptingInstance,
}

impl ScriptingInstance {
    pub(crate) unsafe fn ref_from_raw(handle: *mut BNScriptingInstance) -> Ref<Self> {
        Ref::new(Self { handle })
    }

    /// Create a core instance of the [`CustomScriptingInstance`].
    pub fn from_custom<C: CustomScriptingInstance>(
        provider: &ScriptingProvider,
        instance: C,
    ) -> Ref<Self> {
        // Leaked to be freed by `cb_destroy_instance`.
        let context = CustomScriptingInstanceContext {
            core_instance: MaybeUninit::uninit(),
            instance,
        };
        let leaked_context = Box::leak(Box::new(context));
        let mut callbacks = BNScriptingInstanceCallbacks {
            context: leaked_context as *mut _ as *mut c_void,
            destroyInstance: Some(cb_destroy_instance::<C>),
            externalRefTaken: None,
            externalRefReleased: None,
            executeScriptInput: Some(cb_execute_script_input::<C>),
            executeScriptInputFromFilename: Some(cb_execute_script_input_from_filename::<C>),
            cancelScriptInput: Some(cb_cancel_script_input::<C>),
            releaseBinaryView: Some(cb_release_binary_view::<C>),
            setCurrentBinaryView: Some(cb_set_current_binary_view::<C>),
            setCurrentFunction: Some(cb_set_current_function::<C>),
            setCurrentBasicBlock: Some(cb_set_current_basic_block::<C>),
            setCurrentAddress: Some(cb_set_current_address::<C>),
            setCurrentSelection: Some(cb_set_current_selection::<C>),
            completeInput: Some(cb_complete_input::<C>),
            stop: Some(cb_stop::<C>),
        };
        let handle = unsafe { BNInitScriptingInstance(provider.handle, &mut callbacks) };
        assert!(!handle.is_null(), "Handle should always be valid");
        leaked_context.core_instance = MaybeUninit::new(Self { handle });
        unsafe { ScriptingInstance::ref_from_raw(handle) }
    }

    /// Notifies the active scripting instance listeners of output, typically called in [`ScriptingInstance::execute_script_input`].
    pub fn notify_output(&self, text: &str) {
        let text = text.to_cstr();
        unsafe { BNNotifyOutputForScriptingInstance(self.handle, text.as_ptr()) }
    }

    /// Notifies the active scripting instance listeners of a warning, typically called in [`ScriptingInstance::execute_script_input`].
    pub fn notify_warning(&self, text: &str) {
        let text = text.to_cstr();
        unsafe { BNNotifyWarningForScriptingInstance(self.handle, text.as_ptr()) }
    }

    /// Notifies the active scripting instance listeners of an error, typically called in [`ScriptingInstance::execute_script_input`].
    pub fn notify_error(&self, text: &str) {
        let text = text.to_cstr();
        unsafe { BNNotifyErrorForScriptingInstance(self.handle, text.as_ptr()) }
    }

    /// Notify the scripting instance that the input state has changed.
    ///
    /// When constructing an instance, the default state is [`ScriptingProviderInputReadyState::NotReadyForInput`]
    /// which prevents the scripting instance from accepting input until explicitly notified otherwise.
    pub fn notify_input_ready_state(&self, state: ScriptingProviderInputReadyState) {
        unsafe { BNNotifyInputReadyStateForScriptingInstance(self.handle, state) }
    }

    /// Listen for output from this scripting instance.
    pub fn register_output_listener<L: ScriptingOutputListener>(
        &self,
        listener: L,
    ) -> ScriptingInstanceWithListener<'_, L> {
        let mut listener = Box::pin(listener);
        let mut callbacks = BNScriptingOutputListener {
            context: unsafe { listener.as_mut().get_unchecked_mut() } as *mut _ as *mut c_void,
            output: Some(cb_output::<L>),
            warning: Some(cb_warning::<L>),
            error: Some(cb_error::<L>),
            inputReadyStateChanged: Some(cb_input_ready_state_changed::<L>),
        };
        unsafe { BNRegisterScriptingInstanceOutputListener(self.handle, &mut callbacks) }

        ScriptingInstanceWithListener {
            instance: self,
            listener,
        }
    }

    pub fn delimiters(&self) -> String {
        let result = unsafe { BNGetScriptingInstanceDelimiters(self.handle) };
        assert!(!result.is_null());
        unsafe { BnString::into_string(result) }
    }

    pub fn set_delimiters(&self, delimiters: &str) {
        let delimiters = delimiters.to_cstr();
        unsafe { BNSetScriptingInstanceDelimiters(self.handle, delimiters.as_ptr()) }
    }

    /// The current input ready state of the scripting instance.
    ///
    /// If this is set to [`ScriptingProviderInputReadyState::NotReadyForInput`], the scripting instance will not accept input.
    ///
    /// To interact with the scripting instance, ensure it is in the correct state using [`ScriptingInstance::notify_input_ready_state`].
    pub fn input_ready_state(&self) -> ScriptingProviderInputReadyState {
        unsafe { BNGetScriptingInstanceInputReadyState(self.handle) }
    }

    /// Execute the input within this instance.
    ///
    /// Before calling this, make sure the scripting instance is ready for input with [`ScriptingInstance::input_ready_state`].
    pub fn execute_script_input(&self, input: &str) -> ScriptingProviderExecuteResult {
        let input = input.to_cstr();
        unsafe { BNExecuteScriptInput(self.handle, input.as_ptr()) }
    }

    pub fn execute_script_input_from_filename(
        &self,
        filename: &str,
    ) -> ScriptingProviderExecuteResult {
        let filename = filename.to_cstr();
        unsafe { BNExecuteScriptInputFromFilename(self.handle, filename.as_ptr()) }
    }

    /// Request that the current executing input be canceled.
    pub fn cancel_script_input(&self) {
        unsafe { BNCancelScriptInput(self.handle) }
    }

    pub fn release_binary_view(&self, view: &BinaryView) {
        unsafe { BNScriptingInstanceReleaseBinaryView(self.handle, view.handle) }
    }

    pub fn set_current_binary_view(&self, view: &BinaryView) {
        unsafe { BNSetScriptingInstanceCurrentBinaryView(self.handle, view.handle) }
    }

    pub fn set_current_function(&self, view: &Function) {
        unsafe { BNSetScriptingInstanceCurrentFunction(self.handle, view.handle) }
    }

    pub fn set_current_basic_block(&self, view: &BasicBlock<NativeBlock>) {
        unsafe { BNSetScriptingInstanceCurrentBasicBlock(self.handle, view.handle) }
    }

    pub fn set_current_address(&self, address: u64) {
        unsafe { BNSetScriptingInstanceCurrentAddress(self.handle, address) }
    }

    pub fn set_current_selection(&self, begin: u64, end: u64) {
        unsafe { BNSetScriptingInstanceCurrentSelection(self.handle, begin, end) }
    }

    pub fn complete_input(&self, text: &str, state: u64) -> String {
        let text = text.to_cstr();
        let result = unsafe { BNScriptingInstanceCompleteInput(self.handle, text.as_ptr(), state) };
        assert!(!result.is_null());
        unsafe { BnString::into_string(result) }
    }

    pub fn stop(&self) {
        unsafe { BNStopScriptingInstance(self.handle) }
    }
}

unsafe impl Sync for ScriptingInstance {}
unsafe impl Send for ScriptingInstance {}

impl ToOwned for ScriptingInstance {
    type Owned = Ref<Self>;

    fn to_owned(&self) -> Self::Owned {
        unsafe { Self::inc_ref(self) }
    }
}

unsafe impl RefCountable for ScriptingInstance {
    unsafe fn inc_ref(handle: &Self) -> Ref<Self> {
        Ref::new(Self {
            handle: BNNewScriptingInstanceReference(handle.handle),
        })
    }

    unsafe fn dec_ref(handle: &Self) {
        BNFreeScriptingInstance(handle.handle);
    }
}

/// Wrapper around `C` when being passed to the custom instance constructor so that we have the core
/// instance available to [`CustomScriptingInstance`] functions.
struct CustomScriptingInstanceContext<C: CustomScriptingInstance> {
    // This is not ref-counted because we do not want to impact the lifetime of the core view, the lifetime
    // of which is already bound to the lifetime of the custom view (to be freed when the custom view is freed).
    core_instance: MaybeUninit<ScriptingInstance>,
    instance: C,
}

pub struct ScriptingInstanceWithListener<'a, L: ScriptingOutputListener> {
    instance: &'a ScriptingInstance,
    listener: Pin<Box<L>>,
}

impl<L: ScriptingOutputListener> AsRef<L> for ScriptingInstanceWithListener<'_, L> {
    fn as_ref(&self) -> &L {
        &self.listener
    }
}

impl<L: ScriptingOutputListener> core::ops::Deref for ScriptingInstanceWithListener<'_, L> {
    type Target = L;
    fn deref(&self) -> &Self::Target {
        &self.listener
    }
}

impl<L: ScriptingOutputListener> ScriptingInstanceWithListener<'_, L> {
    pub fn unregister(mut self) {
        let mut callbacks = BNScriptingOutputListener {
            context: unsafe { self.listener.as_mut().get_unchecked_mut() } as *mut _ as *mut c_void,
            output: Some(cb_output::<L>),
            warning: Some(cb_warning::<L>),
            error: Some(cb_error::<L>),
            inputReadyStateChanged: Some(cb_input_ready_state_changed::<L>),
        };
        unsafe {
            BNUnregisterScriptingInstanceOutputListener(self.instance.handle, &mut callbacks)
        };
    }
}

unsafe extern "C" fn cb_create_instance<S: CustomScriptingProvider>(
    ctxt: *mut c_void,
) -> *mut BNScriptingInstance {
    let ctxt = &mut *(ctxt as *mut S);
    let instance = ctxt.create_instance();
    // TODO: Bit of a hack, but we need the core provider handle here.
    let provider = ScriptingProvider::by_name(S::NAME).expect("Provider should always exist");
    let core_instance = ScriptingInstance::from_custom(&provider, instance);
    Ref::into_raw(core_instance).handle
}

unsafe extern "C" fn cb_load_module<S: CustomScriptingProvider>(
    ctxt: *mut c_void,
    repo_path: *const c_char,
    plugin_path: *const c_char,
    force: bool,
) -> bool {
    let ctxt = &mut *(ctxt as *mut S);
    let repo_path = CStr::from_ptr(repo_path);
    let plugin_path = CStr::from_ptr(plugin_path);
    ctxt.load_module(
        &repo_path.to_string_lossy(),
        &plugin_path.to_string_lossy(),
        force,
    )
}

unsafe extern "C" fn cb_install_modules<S: CustomScriptingProvider>(
    ctxt: *mut c_void,
    modules: *const c_char,
) -> bool {
    let ctxt = &mut *(ctxt as *mut S);
    let modules = CStr::from_ptr(modules);
    ctxt.install_modules(&modules.to_string_lossy())
}

unsafe extern "C" fn cb_destroy_instance<S: CustomScriptingInstance>(ctxt: *mut c_void) {
    let _ = Box::from_raw(ctxt as *mut CustomScriptingInstanceContext<S>);
}

unsafe extern "C" fn cb_execute_script_input<S: CustomScriptingInstance>(
    ctxt: *mut c_void,
    input: *const c_char,
) -> BNScriptingProviderExecuteResult {
    let input = CStr::from_ptr(input);
    let ctxt = &mut *(ctxt as *mut CustomScriptingInstanceContext<S>);
    let result = ctxt.instance.execute_script_input(
        ctxt.core_instance.assume_init_ref(),
        &input.to_string_lossy(),
    );
    result
}

unsafe extern "C" fn cb_execute_script_input_from_filename<S: CustomScriptingInstance>(
    ctxt: *mut c_void,
    input: *const c_char,
) -> BNScriptingProviderExecuteResult {
    let input = CStr::from_ptr(input);
    let ctxt = &mut *(ctxt as *mut CustomScriptingInstanceContext<S>);
    ctxt.instance.execute_script_input(
        ctxt.core_instance.assume_init_ref(),
        &input.to_string_lossy(),
    )
}

unsafe extern "C" fn cb_cancel_script_input<S: CustomScriptingInstance>(ctxt: *mut c_void) {
    let ctxt = &mut *(ctxt as *mut CustomScriptingInstanceContext<S>);
    ctxt.instance.cancel_script_input()
}

unsafe extern "C" fn cb_release_binary_view<S: CustomScriptingInstance>(
    ctxt: *mut c_void,
    view: *mut BNBinaryView,
) {
    let view = BinaryView::from_raw(view);
    let ctxt = &mut *(ctxt as *mut CustomScriptingInstanceContext<S>);
    ctxt.instance.release_binary_view(&view)
}

unsafe extern "C" fn cb_set_current_binary_view<S: CustomScriptingInstance>(
    ctxt: *mut c_void,
    view: *mut BNBinaryView,
) {
    let ctxt = &mut *(ctxt as *mut CustomScriptingInstanceContext<S>);
    match view.is_null() {
        true => ctxt.instance.set_current_binary_view(None),
        false => {
            let view = BinaryView::from_raw(view);
            ctxt.instance.set_current_binary_view(Some(&view))
        }
    }
}

unsafe extern "C" fn cb_set_current_function<S: CustomScriptingInstance>(
    ctxt: *mut c_void,
    func: *mut BNFunction,
) {
    let ctxt = &mut *(ctxt as *mut CustomScriptingInstanceContext<S>);
    match func.is_null() {
        true => ctxt.instance.set_current_function(None),
        false => {
            let func = Function::from_raw(func);
            ctxt.instance.set_current_function(Some(&func))
        }
    }
}

unsafe extern "C" fn cb_set_current_basic_block<S: CustomScriptingInstance>(
    ctxt: *mut c_void,
    block: *mut BNBasicBlock,
) {
    let ctxt = &mut *(ctxt as *mut CustomScriptingInstanceContext<S>);
    match block.is_null() {
        true => ctxt.instance.set_current_basic_block(None),
        false => {
            let block = BasicBlock::from_raw(block, NativeBlock::new());
            ctxt.instance.set_current_basic_block(Some(&block))
        }
    }
}

unsafe extern "C" fn cb_set_current_address<S: CustomScriptingInstance>(
    ctxt: *mut c_void,
    addr: u64,
) {
    let ctxt = &mut *(ctxt as *mut CustomScriptingInstanceContext<S>);
    ctxt.instance.set_current_selection(addr, addr)
}

unsafe extern "C" fn cb_set_current_selection<S: CustomScriptingInstance>(
    ctxt: *mut c_void,
    begin: u64,
    end: u64,
) {
    let ctxt = &mut *(ctxt as *mut CustomScriptingInstanceContext<S>);
    ctxt.instance.set_current_selection(begin, end)
}

unsafe extern "C" fn cb_complete_input<S: CustomScriptingInstance>(
    ctxt: *mut c_void,
    text: *const c_char,
    state: u64,
) -> *mut c_char {
    let ctxt = &mut *(ctxt as *mut CustomScriptingInstanceContext<S>);
    let text = CStr::from_ptr(text);
    let result = ctxt.instance.complete_input(&text.to_string_lossy(), state);
    BnString::into_raw(BnString::new(result))
}

unsafe extern "C" fn cb_stop<S: CustomScriptingInstance>(ctxt: *mut c_void) {
    let ctxt = &mut *(ctxt as *mut CustomScriptingInstanceContext<S>);
    ctxt.instance.stop()
}

unsafe extern "C" fn cb_output<S: ScriptingOutputListener>(ctxt: *mut c_void, text: *const c_char) {
    let ctxt = &mut *(ctxt as *mut S);
    let text = CStr::from_ptr(text);
    ctxt.output(&text.to_string_lossy())
}

unsafe extern "C" fn cb_warning<S: ScriptingOutputListener>(
    ctxt: *mut c_void,
    text: *const c_char,
) {
    let ctxt = &mut *(ctxt as *mut S);
    let text = CStr::from_ptr(text);
    ctxt.warning(&text.to_string_lossy())
}

unsafe extern "C" fn cb_error<S: ScriptingOutputListener>(ctxt: *mut c_void, text: *const c_char) {
    let ctxt = &mut *(ctxt as *mut S);
    let text = CStr::from_ptr(text);
    ctxt.error(&text.to_string_lossy())
}

unsafe extern "C" fn cb_input_ready_state_changed<S: ScriptingOutputListener>(
    ctxt: *mut c_void,
    state: BNScriptingProviderInputReadyState,
) {
    let ctxt = &mut *(ctxt as *mut S);
    ctxt.input_ready_state_changed(state)
}
