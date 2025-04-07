use binaryninja::binary_view::BinaryView;
use binaryninja::headless::Session;
use binaryninja::plugin_command::{
    CustomDefaultPluginCommand, DefaultPluginCommand, PluginCommand, PluginCommandAll,
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[test]
fn test_custom_plugin_command() {
    let _session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");
    let counter = Arc::new(AtomicUsize::new(0));

    struct MyCommand {
        counter: Arc<AtomicUsize>,
    }

    impl CustomDefaultPluginCommand for MyCommand {
        fn is_valid(&mut self, _view: &BinaryView) -> bool {
            true
        }

        fn run(&mut self, _view: &BinaryView) {
            self.counter.fetch_add(1, Ordering::SeqCst);
        }
    }

    // Register the plugin command.
    const PLUGIN_NAME: &str = "MyTestCommand1";
    let test_command = MyCommand {
        counter: counter.clone(),
    };
    test_command.register(
        PLUGIN_NAME,
        "Test for the plugin command custom implementation",
    );

    // Execute the plugin command to verify that it's callable.
    let all_plugins = PluginCommand::<PluginCommandAll>::valid_plugin_commands();
    let my_core_plugin = all_plugins
        .iter()
        .find(|plugin| plugin.name() == PLUGIN_NAME)
        .unwrap();
    match my_core_plugin.execution() {
        PluginCommandAll::DefaultPluginCommand(mut cmd) => {
            assert!(cmd.is_valid(&view));
            cmd.run(&view);
        }
        _ => unreachable!(),
    }

    // Get the plugin through the specific command type.
    let view_default_plugins = PluginCommand::<DefaultPluginCommand>::valid_plugin_commands(&view);
    let my_core_plugin_1 = view_default_plugins
        .iter()
        .find(|plugin| plugin.name() == PLUGIN_NAME)
        .unwrap();
    let mut my_core_plugin_cmd = my_core_plugin_1.execution();
    assert!(my_core_plugin_cmd.is_valid(&view));
    my_core_plugin_cmd.run(&view);

    assert_eq!(counter.load(Ordering::SeqCst), 2);
}
