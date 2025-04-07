use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use binaryninja::binary_view::BinaryView;
use binaryninja::headless::Session;
use binaryninja::plugin_command::{CustomDefaultPluginCommand, PluginCommand, PluginCommandAll};

#[test]
fn test_custom_plugin_command() {
    let _session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");
    let counter = Arc::new(Mutex::new(0));
    struct MyCommand {
        counter: Arc<Mutex<usize>>,
    }
    impl CustomDefaultPluginCommand for MyCommand {
        fn is_valid(&mut self, _view: &BinaryView) -> bool {
            true
        }

        fn run(&mut self, _view: &BinaryView) {
            let mut counter = self.counter.lock().unwrap();
            *counter += 1;
        }
    }
    const PLUGIN_NAME: &str = "MyTestCommand1";
    MyCommand {
        counter: Arc::clone(&counter),
    }
    .register(
        PLUGIN_NAME,
        "Test for the plugin command custom implementation",
    );

    let all_plugins = PluginCommand::<PluginCommandAll>::valid_plugin_commands();
    let my_core_plugin = all_plugins
        .iter()
        .find(|plugin| plugin.name() == PLUGIN_NAME)
        .unwrap();
    match my_core_plugin.execution() {
        PluginCommandAll::DefaultPluginCommand(mut exe) => {
            assert!(exe.is_valid(&view));
            exe.run(&view);
        }
        _ => unreachable!(),
    }

    let counter = *counter.lock().unwrap();
    assert_eq!(counter, 1);
}
