use core::{ffi, mem, ptr};
use std::pin::Pin;

use binaryninjacore_sys::*;

use crate::basicblock::BasicBlock;
use crate::binaryview::BinaryView;
use crate::function::{Function, NativeBlock};
use crate::rc::{Array, CoreArrayProvider, CoreArrayProviderInner};
use crate::string::{BnStrCompatible, BnString};

pub type ScriptingProviderExecuteResult = BNScriptingProviderExecuteResult;
pub type ScriptingProviderInputReadyState = BNScriptingProviderInputReadyState;

#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct ScriptingProvider {
    handle: ptr::NonNull<BNScriptingProvider>,
}

impl ScriptingProvider {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNScriptingProvider>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn ref_from_raw(handle: &*mut BNScriptingProvider) -> &Self {
        assert!(!handle.is_null());
        mem::transmute(handle)
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNScriptingProvider {
        &mut *self.handle.as_ptr()
    }

    pub fn all() -> Array<Self> {
        let mut count = 0;
        let result = unsafe { BNGetScriptingProviderList(&mut count) };
        assert!(!result.is_null());
        unsafe { Array::new(result, count, ()) }
    }

    pub fn by_name<S: BnStrCompatible>(name: S) -> Option<ScriptingProvider> {
        let name = name.into_bytes_with_nul();
        let result =
            unsafe { BNGetScriptingProviderByName(name.as_ref().as_ptr() as *const ffi::c_char) };
        ptr::NonNull::new(result).map(|h| unsafe { Self::from_raw(h) })
    }

    pub fn by_api_name<S: BnStrCompatible>(name: S) -> Option<ScriptingProvider> {
        let name = name.into_bytes_with_nul();
        let result = unsafe {
            BNGetScriptingProviderByAPIName(name.as_ref().as_ptr() as *const ffi::c_char)
        };
        ptr::NonNull::new(result).map(|h| unsafe { Self::from_raw(h) })
    }

    pub fn name(&self) -> BnString {
        let result = unsafe { BNGetScriptingProviderName(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    pub fn api_name(&self) -> BnString {
        let result = unsafe { BNGetScriptingProviderAPIName(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    pub fn load_module<R: BnStrCompatible, M: BnStrCompatible>(
        &self,
        repository: R,
        module: M,
        force: bool,
    ) -> bool {
        let repository = repository.into_bytes_with_nul();
        let module = module.into_bytes_with_nul();
        unsafe {
            BNLoadScriptingProviderModule(
                self.as_raw(),
                repository.as_ref().as_ptr() as *const ffi::c_char,
                module.as_ref().as_ptr() as *const ffi::c_char,
                force,
            )
        }
    }

    pub fn install_modules<M: BnStrCompatible>(&self, modules: M) -> bool {
        let modules = modules.into_bytes_with_nul();
        unsafe {
            BNInstallScriptingProviderModules(
                self.as_raw(),
                modules.as_ref().as_ptr() as *const ffi::c_char,
            )
        }
    }

    pub fn new_instance<S: ScriptingInstanceCallbacks>(&self) -> ScriptingInstance {
        // SAFETY freed by cb_destroy_instance
        let uninit = Box::leak(Box::new(mem::MaybeUninit::zeroed()));
        let mut callbacks = BNScriptingInstanceCallbacks {
            context: unsafe { uninit.assume_init_mut() as *mut S as *mut ffi::c_void },
            destroyInstance: Some(cb_destroy_instance::<S>),
            externalRefTaken: Some(cb_external_ref_taken::<S>),
            externalRefReleased: Some(cb_external_ref_released::<S>),
            executeScriptInput: Some(cb_execute_script_input::<S>),
            executeScriptInputFromFilename: Some(cb_execute_script_input_from_filename::<S>),
            cancelScriptInput: Some(cb_cancel_script_input::<S>),
            releaseBinaryView: Some(cb_release_binary_view::<S>),
            setCurrentBinaryView: Some(cb_set_current_binary_view::<S>),
            setCurrentFunction: Some(cb_set_current_function::<S>),
            setCurrentBasicBlock: Some(cb_set_current_basic_block::<S>),
            setCurrentAddress: Some(cb_set_current_address::<S>),
            setCurrentSelection: Some(cb_set_current_selection::<S>),
            completeInput: Some(cb_complete_input::<S>),
            stop: Some(cb_stop::<S>),
        };
        let result = unsafe { BNInitScriptingInstance(self.as_raw(), &mut callbacks) };
        let instance = unsafe { ScriptingInstance::from_raw(ptr::NonNull::new(result).unwrap()) };
        uninit.write(S::new(*self, &instance));
        instance
    }
}

impl CoreArrayProvider for ScriptingProvider {
    type Raw = *mut BNScriptingProvider;
    type Context = ();
    type Wrapped<'a> = &'a Self;
}

unsafe impl CoreArrayProviderInner for ScriptingProvider {
    unsafe fn free(raw: *mut Self::Raw, _count: usize, _context: &Self::Context) {
        BNFreeScriptingProviderList(raw)
    }

    unsafe fn wrap_raw<'a>(raw: &'a Self::Raw, _context: &'a Self::Context) -> Self::Wrapped<'a> {
        Self::ref_from_raw(raw)
    }
}

#[repr(transparent)]
pub struct ScriptingInstance {
    handle: ptr::NonNull<BNScriptingInstance>,
}

impl Clone for ScriptingInstance {
    fn clone(&self) -> Self {
        let result = unsafe { BNNewScriptingInstanceReference(self.as_raw()) };
        unsafe { Self::from_raw(ptr::NonNull::new(result).unwrap()) }
    }
}

impl Drop for ScriptingInstance {
    fn drop(&mut self) {
        unsafe { BNFreeScriptingInstance(self.as_raw()) }
    }
}

impl ScriptingInstance {
    pub(crate) unsafe fn from_raw(handle: ptr::NonNull<BNScriptingInstance>) -> Self {
        Self { handle }
    }

    pub(crate) unsafe fn into_raw(self) -> *mut BNScriptingInstance {
        mem::ManuallyDrop::new(self).handle.as_ptr()
    }

    #[allow(clippy::mut_from_ref)]
    pub(crate) unsafe fn as_raw(&self) -> &mut BNScriptingInstance {
        &mut *self.handle.as_ptr()
    }

    pub fn notify_output<S: BnStrCompatible>(&self, text: S) {
        let text = text.into_bytes_with_nul();
        unsafe {
            BNNotifyOutputForScriptingInstance(
                self.as_raw(),
                text.as_ref().as_ptr() as *const ffi::c_char,
            )
        }
    }

    pub fn notify_warning<S: BnStrCompatible>(&self, text: S) {
        let text = text.into_bytes_with_nul();
        unsafe {
            BNNotifyOutputForScriptingInstance(
                self.as_raw(),
                text.as_ref().as_ptr() as *const ffi::c_char,
            )
        }
    }

    pub fn notify_error<S: BnStrCompatible>(&self, text: S) {
        let text = text.into_bytes_with_nul();
        unsafe {
            BNNotifyOutputForScriptingInstance(
                self.as_raw(),
                text.as_ref().as_ptr() as *const ffi::c_char,
            )
        }
    }

    pub fn notify_input_ready_state(&self, state: ScriptingProviderInputReadyState) {
        unsafe { BNNotifyInputReadyStateForScriptingInstance(self.as_raw(), state) }
    }

    pub fn register_output_listener<L: ScriptingOutputListener>(
        self,
        listener: L,
    ) -> ScriptingInstanceWithListener<L> {
        let mut listener = Box::pin(listener);
        let mut callbacks = BNScriptingOutputListener {
            context: unsafe { listener.as_mut().get_unchecked_mut() } as *mut _ as *mut ffi::c_void,
            output: Some(cb_output::<L>),
            warning: Some(cb_warning::<L>),
            error: Some(cb_error::<L>),
            inputReadyStateChanged: Some(cb_input_ready_state_changed::<L>),
        };
        unsafe { BNRegisterScriptingInstanceOutputListener(self.as_raw(), &mut callbacks) }

        ScriptingInstanceWithListener {
            handle: self,
            listener,
        }
    }

    pub fn delimiters(&self) -> BnString {
        let result = unsafe { BNGetScriptingInstanceDelimiters(self.as_raw()) };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result as *mut ffi::c_char) }
    }

    pub fn set_delimiters<S: BnStrCompatible>(&self, delimiters: S) {
        let delimiters = delimiters.into_bytes_with_nul();
        unsafe {
            BNSetScriptingInstanceDelimiters(
                self.as_raw(),
                delimiters.as_ref().as_ptr() as *const ffi::c_char,
            )
        }
    }

    pub fn input_ready_state(&self) -> ScriptingProviderInputReadyState {
        unsafe { BNGetScriptingInstanceInputReadyState(self.as_raw()) }
    }

    pub fn execute_script_input<S: BnStrCompatible>(
        &self,
        input: S,
    ) -> ScriptingProviderExecuteResult {
        let input = input.into_bytes_with_nul();
        unsafe {
            BNExecuteScriptInput(self.as_raw(), input.as_ref().as_ptr() as *const ffi::c_char)
        }
    }

    pub fn execute_script_input_from_filename<S: BnStrCompatible>(
        &self,
        filename: S,
    ) -> ScriptingProviderExecuteResult {
        let filename = filename.into_bytes_with_nul();
        unsafe {
            BNExecuteScriptInputFromFilename(
                self.as_raw(),
                filename.as_ref().as_ptr() as *const ffi::c_char,
            )
        }
    }

    pub fn cancel_script_input(&self) {
        unsafe { BNCancelScriptInput(self.as_raw()) }
    }

    pub fn release_binary_view(&self, view: &BinaryView) {
        unsafe { BNScriptingInstanceReleaseBinaryView(self.as_raw(), view.handle) }
    }

    pub fn set_current_binary_view(&self, view: &BinaryView) {
        unsafe { BNSetScriptingInstanceCurrentBinaryView(self.as_raw(), view.handle) }
    }

    pub fn set_current_function(&self, view: &Function) {
        unsafe { BNSetScriptingInstanceCurrentFunction(self.as_raw(), view.handle) }
    }

    pub fn set_current_basic_block(&self, view: &BasicBlock<NativeBlock>) {
        unsafe { BNSetScriptingInstanceCurrentBasicBlock(self.as_raw(), view.handle) }
    }

    pub fn set_current_address(&self, address: u64) {
        unsafe { BNSetScriptingInstanceCurrentAddress(self.as_raw(), address) }
    }

    pub fn set_current_selection(&self, begin: u64, end: u64) {
        unsafe { BNSetScriptingInstanceCurrentSelection(self.as_raw(), begin, end) }
    }

    pub fn complete_input<S: BnStrCompatible>(&self, text: S, state: u64) -> BnString {
        let text = text.into_bytes_with_nul();
        let result = unsafe {
            BNScriptingInstanceCompleteInput(
                self.as_raw(),
                text.as_ref().as_ptr() as *const ffi::c_char,
                state,
            )
        };
        assert!(!result.is_null());
        unsafe { BnString::from_raw(result) }
    }

    pub fn stop(&self) {
        unsafe { BNStopScriptingInstance(self.as_raw()) }
    }
}

pub struct ScriptingInstanceWithListener<L: ScriptingOutputListener> {
    handle: ScriptingInstance,
    listener: Pin<Box<L>>,
}

impl<L: ScriptingOutputListener> AsRef<ScriptingInstance> for ScriptingInstanceWithListener<L> {
    fn as_ref(&self) -> &ScriptingInstance {
        &self.handle
    }
}

impl<L: ScriptingOutputListener> core::ops::Deref for ScriptingInstanceWithListener<L> {
    type Target = ScriptingInstance;
    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl<L: ScriptingOutputListener> ScriptingInstanceWithListener<L> {
    pub fn unregister(mut self) -> ScriptingInstance {
        let mut callbacks = BNScriptingOutputListener {
            context: unsafe { self.listener.as_mut().get_unchecked_mut() } as *mut _
                as *mut ffi::c_void,
            output: Some(cb_output::<L>),
            warning: Some(cb_warning::<L>),
            error: Some(cb_error::<L>),
            inputReadyStateChanged: Some(cb_input_ready_state_changed::<L>),
        };
        unsafe {
            BNUnregisterScriptingInstanceOutputListener(self.handle.as_raw(), &mut callbacks)
        };
        // drop the listener
        let Self {
            handle: instance,
            listener: _,
        } = self;
        // return the inner instance
        instance
    }
}

pub trait ScriptingCustomProvider: Sync + Send {
    fn new(core: ScriptingProvider) -> Self;
    fn create_instance(&self) -> ScriptingInstance;
    fn load_module(&self, repo_path: &str, plugin_path: &str, force: bool) -> bool;
    fn install_modules(&self, modules: &str) -> bool;
}

pub trait ScriptingInstanceCallbacks: Sync + Send {
    fn new(provider: ScriptingProvider, handle: &ScriptingInstance) -> Self;
    fn destroy_instance(&self);
    fn external_ref_taken(&self);
    fn external_ref_released(&self);
    fn execute_script_input(&self, input: &str) -> ScriptingProviderExecuteResult;
    fn execute_script_input_from_filename(&self, input: &str) -> ScriptingProviderExecuteResult;
    fn cancel_script_input(&self);
    fn release_binary_view(&self, view: &BinaryView);
    fn set_current_binary_view(&self, view: &BinaryView);
    fn set_current_function(&self, func: &Function);
    fn set_current_basic_block(&self, block: &BasicBlock<NativeBlock>);
    fn set_current_address(&self, addr: u64);
    fn set_current_selection(&self, begin: u64, end: u64);
    fn complete_input(&self, text: &str, state: u64) -> String;
    fn stop(&self);
}

pub trait ScriptingOutputListener: Sync + Send {
    fn output(&self, text: &str);
    fn warning(&self, text: &str);
    fn error(&self, text: &str);
    fn input_ready_state_changed(&self, state: ScriptingProviderInputReadyState);
}

pub fn register_scripting_provider<N, A, S>(name: N, api_name: A) -> (&'static S, ScriptingProvider)
where
    N: BnStrCompatible,
    A: BnStrCompatible,
    S: ScriptingCustomProvider + 'static,
{
    let name = name.into_bytes_with_nul();
    let api_name = api_name.into_bytes_with_nul();
    // SAFETY: Websocket provider is never freed
    let provider_uinit = Box::leak(Box::new(mem::MaybeUninit::zeroed()));
    let result = unsafe {
        BNRegisterScriptingProvider(
            name.as_ref().as_ptr() as *const ffi::c_char,
            api_name.as_ref().as_ptr() as *const ffi::c_char,
            &mut BNScriptingProviderCallbacks {
                context: provider_uinit as *mut _ as *mut ffi::c_void,
                createInstance: Some(cb_create_instance::<S>),
                loadModule: Some(cb_load_module::<S>),
                installModules: Some(cb_install_modules::<S>),
            },
        )
    };
    let provider_core = unsafe { ScriptingProvider::from_raw(ptr::NonNull::new(result).unwrap()) };
    provider_uinit.write(S::new(provider_core));
    (unsafe { provider_uinit.assume_init_ref() }, provider_core)
}

unsafe extern "C" fn cb_create_instance<S: ScriptingCustomProvider>(
    ctxt: *mut ffi::c_void,
) -> *mut BNScriptingInstance {
    let ctxt = &mut *(ctxt as *mut S);
    ctxt.create_instance().into_raw()
}

unsafe extern "C" fn cb_load_module<S: ScriptingCustomProvider>(
    ctxt: *mut ffi::c_void,
    repo_path: *const ffi::c_char,
    plugin_path: *const ffi::c_char,
    force: bool,
) -> bool {
    let ctxt = &mut *(ctxt as *mut S);
    let repo_path = ffi::CStr::from_ptr(repo_path);
    let plugin_path = ffi::CStr::from_ptr(plugin_path);
    ctxt.load_module(
        &repo_path.to_string_lossy(),
        &plugin_path.to_string_lossy(),
        force,
    )
}

unsafe extern "C" fn cb_install_modules<S: ScriptingCustomProvider>(
    ctxt: *mut ffi::c_void,
    modules: *const ffi::c_char,
) -> bool {
    let ctxt = &mut *(ctxt as *mut S);
    let modules = ffi::CStr::from_ptr(modules);
    ctxt.install_modules(&modules.to_string_lossy())
}

unsafe extern "C" fn cb_destroy_instance<S: ScriptingInstanceCallbacks>(ctxt: *mut ffi::c_void) {
    drop(Box::from_raw(ctxt as *mut S))
}

unsafe extern "C" fn cb_external_ref_taken<S: ScriptingInstanceCallbacks>(ctxt: *mut ffi::c_void) {
    let ctxt = &mut *(ctxt as *mut S);
    ctxt.external_ref_taken()
}

unsafe extern "C" fn cb_external_ref_released<S: ScriptingInstanceCallbacks>(
    ctxt: *mut ffi::c_void,
) {
    let ctxt = &mut *(ctxt as *mut S);
    ctxt.external_ref_released()
}

unsafe extern "C" fn cb_execute_script_input<S: ScriptingInstanceCallbacks>(
    ctxt: *mut ffi::c_void,
    input: *const ffi::c_char,
) -> BNScriptingProviderExecuteResult {
    let input = ffi::CStr::from_ptr(input);
    let ctxt = &mut *(ctxt as *mut S);
    ctxt.execute_script_input(&input.to_string_lossy())
}

unsafe extern "C" fn cb_execute_script_input_from_filename<S: ScriptingInstanceCallbacks>(
    ctxt: *mut ffi::c_void,
    input: *const ffi::c_char,
) -> BNScriptingProviderExecuteResult {
    let input = ffi::CStr::from_ptr(input);
    let ctxt = &mut *(ctxt as *mut S);
    ctxt.execute_script_input(&input.to_string_lossy())
}

unsafe extern "C" fn cb_cancel_script_input<S: ScriptingInstanceCallbacks>(ctxt: *mut ffi::c_void) {
    let ctxt = &mut *(ctxt as *mut S);
    ctxt.cancel_script_input()
}

unsafe extern "C" fn cb_release_binary_view<S: ScriptingInstanceCallbacks>(
    ctxt: *mut ffi::c_void,
    view: *mut BNBinaryView,
) {
    let view = BinaryView { handle: view };
    let ctxt = &mut *(ctxt as *mut S);
    ctxt.release_binary_view(&view)
}

unsafe extern "C" fn cb_set_current_binary_view<S: ScriptingInstanceCallbacks>(
    ctxt: *mut ffi::c_void,
    view: *mut BNBinaryView,
) {
    let view = BinaryView { handle: view };
    let ctxt = &mut *(ctxt as *mut S);
    ctxt.set_current_binary_view(&view)
}

unsafe extern "C" fn cb_set_current_function<S: ScriptingInstanceCallbacks>(
    ctxt: *mut ffi::c_void,
    func: *mut BNFunction,
) {
    let func = Function { handle: func };
    let ctxt = &mut *(ctxt as *mut S);
    ctxt.set_current_function(&func)
}

unsafe extern "C" fn cb_set_current_basic_block<S: ScriptingInstanceCallbacks>(
    ctxt: *mut ffi::c_void,
    block: *mut BNBasicBlock,
) {
    let block = BasicBlock::from_raw(block, NativeBlock::new());
    let ctxt = &mut *(ctxt as *mut S);
    ctxt.set_current_basic_block(&block)
}

unsafe extern "C" fn cb_set_current_address<S: ScriptingInstanceCallbacks>(
    ctxt: *mut ffi::c_void,
    addr: u64,
) {
    let ctxt = &mut *(ctxt as *mut S);
    ctxt.set_current_address(addr)
}

unsafe extern "C" fn cb_set_current_selection<S: ScriptingInstanceCallbacks>(
    ctxt: *mut ffi::c_void,
    begin: u64,
    end: u64,
) {
    let ctxt = &mut *(ctxt as *mut S);
    ctxt.set_current_selection(begin, end)
}

unsafe extern "C" fn cb_complete_input<S: ScriptingInstanceCallbacks>(
    ctxt: *mut ffi::c_void,
    text: *const ffi::c_char,
    state: u64,
) -> *mut ffi::c_char {
    let ctxt = &mut *(ctxt as *mut S);
    let text = ffi::CStr::from_ptr(text);
    let result = ctxt.complete_input(&text.to_string_lossy(), state);
    BnString::new(result).into_raw()
}

unsafe extern "C" fn cb_stop<S: ScriptingInstanceCallbacks>(ctxt: *mut ffi::c_void) {
    let ctxt = &mut *(ctxt as *mut S);
    ctxt.stop()
}

unsafe extern "C" fn cb_output<S: ScriptingOutputListener>(
    ctxt: *mut ffi::c_void,
    text: *const ffi::c_char,
) {
    let ctxt = &mut *(ctxt as *mut S);
    let text = ffi::CStr::from_ptr(text);
    ctxt.output(&text.to_string_lossy())
}

unsafe extern "C" fn cb_warning<S: ScriptingOutputListener>(
    ctxt: *mut ffi::c_void,
    text: *const ffi::c_char,
) {
    let ctxt = &mut *(ctxt as *mut S);
    let text = ffi::CStr::from_ptr(text);
    ctxt.warning(&text.to_string_lossy())
}

unsafe extern "C" fn cb_error<S: ScriptingOutputListener>(
    ctxt: *mut ffi::c_void,
    text: *const ffi::c_char,
) {
    let ctxt = &mut *(ctxt as *mut S);
    let text = ffi::CStr::from_ptr(text);
    ctxt.error(&text.to_string_lossy())
}

unsafe extern "C" fn cb_input_ready_state_changed<S: ScriptingOutputListener>(
    ctxt: *mut ffi::c_void,
    state: BNScriptingProviderInputReadyState,
) {
    let ctxt = &mut *(ctxt as *mut S);
    ctxt.input_ready_state_changed(state)
}
