use std::path::Path;
use std::sync::Mutex;

use binaryninja::scripting_provider::{
    register_scripting_provider, CustomScriptingInstance, CustomScriptingProvider,
    ScriptingInstance, ScriptingOutputListener, ScriptingProviderExecuteResult,
    ScriptingProviderInputReadyState,
};

struct MyScriptingProvider;

impl CustomScriptingProvider for MyScriptingProvider {
    type Instance = MyScriptingProviderInstance;
    const NAME: &'static str = "MyScriptingProvider";
    const API_NAME: &'static str = "MyScriptingProviderAPI";

    fn load_module(&self, repo_path: &str, plugin_path: &str, force: bool) -> bool {
        panic!(
            "load_module not implemented: {} {} {}",
            repo_path, plugin_path, force
        );
    }

    fn install_modules(&self, modules: &str) -> bool {
        panic!("install_modules not implemented: {}", modules);
    }

    fn create_instance(&self) -> Self::Instance {
        MyScriptingProviderInstance
    }
}

#[derive(Clone)]
struct MyScriptingProviderInstance;

impl CustomScriptingInstance for MyScriptingProviderInstance {
    fn execute_script_input(
        &self,
        instance: &ScriptingInstance,
        input: &str,
    ) -> ScriptingProviderExecuteResult {
        instance.notify_output(&format!("execute_script_input({})", input));
        ScriptingProviderExecuteResult::SuccessfulScriptExecution
    }

    fn execute_script_input_from_file(
        &self,
        instance: &ScriptingInstance,
        file_path: &Path,
    ) -> ScriptingProviderExecuteResult {
        instance.notify_output(&format!(
            "execute_script_input_from_filename({})",
            file_path.to_string_lossy()
        ));
        ScriptingProviderExecuteResult::SuccessfulScriptExecution
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputType {
    Output,
    Warning,
    Error,
}

#[derive(Debug, Default)]
struct MyListener {
    output: Mutex<Vec<(OutputType, String)>>,
}

impl ScriptingOutputListener for MyListener {
    fn output(&self, text: &str) {
        let mut output = self.output.lock().unwrap();
        output.push((OutputType::Output, text.to_string()))
    }

    fn warning(&self, text: &str) {
        let mut output = self.output.lock().unwrap();
        output.push((OutputType::Warning, text.to_string()))
    }

    fn error(&self, text: &str) {
        let mut output = self.output.lock().unwrap();
        output.push((OutputType::Error, text.to_string()))
    }

    fn input_ready_state_changed(&self, _state: ScriptingProviderInputReadyState) {}
}

#[test]
fn listen_script_provider() {
    let _session = binaryninja::headless::Session::new().expect("Failed to initialize session");
    let (rust_provider, core_provider) = register_scripting_provider(MyScriptingProvider);
    let rust_instance = rust_provider.create_instance();
    let core_instance = ScriptingInstance::from_custom(&core_provider, rust_instance.clone());

    let listener1 = core_instance.register_output_listener(MyListener::default());
    assert_eq!(
        rust_instance.execute_script_input(&core_instance, "test"),
        ScriptingProviderExecuteResult::SuccessfulScriptExecution
    );

    let output1 = listener1.output.lock().unwrap();
    assert_eq!(
        &*output1,
        &[(OutputType::Output, "execute_script_input(test)".to_string()),]
    );

    let other_core_instance = core_provider.create_instance();
    let listener3 = other_core_instance.register_output_listener(MyListener::default());
    assert_eq!(
        other_core_instance.input_ready_state(),
        ScriptingProviderInputReadyState::NotReadyForInput,
        "Scripting instance should not be ready for input yet"
    );
    assert_eq!(
        other_core_instance.execute_script_input("test3"),
        ScriptingProviderExecuteResult::InvalidScriptInput,
        "Should not be able to execute script input until the input state is ready"
    );

    // Set the input state to ready.
    other_core_instance
        .notify_input_ready_state(ScriptingProviderInputReadyState::ReadyForScriptProgramInput);
    assert_eq!(
        other_core_instance.execute_script_input("test3"),
        ScriptingProviderExecuteResult::SuccessfulScriptExecution,
        "Should be able to execute script input now that the input state is ready"
    );

    let output3 = listener3.output.lock().unwrap();
    assert_eq!(
        &*output3,
        &[(
            OutputType::Output,
            "execute_script_input(test3)".to_string()
        ),]
    );
}
