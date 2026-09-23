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

struct ArgumentCompletionProvider;

impl CustomScriptingProvider for ArgumentCompletionProvider {
    type Instance = ArgumentCompletionInstance;

    const NAME: &'static str = "ArgumentCompletionProvider";
    const API_NAME: &'static str = "ArgumentCompletionProviderAPI";

    fn load_module(&self, _repo_path: &str, _plugin_path: &str, _force: bool) -> bool {
        false
    }

    fn install_modules(&self, _modules: &str) -> bool {
        false
    }

    fn create_instance(&self) -> Self::Instance {
        ArgumentCompletionInstance {
            prefix: "open(\"/usr".to_string(),
            completion: "open(\"/usr/bin/\")".to_string(),
            argument_start: 6,
        }
    }
}

struct ArgumentCompletionInstance {
    prefix: String,
    completion: String,
    argument_start: u64,
}

impl CustomScriptingInstance for ArgumentCompletionInstance {
    fn execute_script_input(
        &self,
        _instance: &ScriptingInstance,
        _input: &str,
    ) -> ScriptingProviderExecuteResult {
        ScriptingProviderExecuteResult::SuccessfulScriptExecution
    }

    fn execute_script_input_from_file(
        &self,
        _instance: &ScriptingInstance,
        _file_path: &Path,
    ) -> ScriptingProviderExecuteResult {
        ScriptingProviderExecuteResult::SuccessfulScriptExecution
    }

    fn can_complete_arguments(&self, text: &str) -> bool {
        text.starts_with(&self.prefix)
    }

    fn complete_arguments(&self, _text: &str) -> (String, u64) {
        (self.completion.clone(), self.argument_start)
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

#[test]
fn complete_script_provider_arguments() {
    let _session = binaryninja::headless::Session::new().expect("Failed to initialize session");
    let (_, provider) = register_scripting_provider(ArgumentCompletionProvider);
    let instance = provider.create_instance();

    assert!(instance.can_complete_arguments("open(\"/usr"));
    assert!(!instance.can_complete_arguments("print(\"hello\")"));
    assert_eq!(
        instance.complete_arguments("open(\"/usr"),
        ("open(\"/usr/bin/\")".to_string(), 6)
    );
}
