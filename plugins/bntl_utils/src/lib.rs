mod command;
pub mod diff;
pub mod dump;
pub mod helper;
mod merge;
pub mod process;
pub mod schema;
pub mod tbd;
pub mod url;
pub mod validate;
mod winmd;

#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginInit() -> bool {
    if plugin_init().is_err() {
        tracing::error!("Failed to initialize BNTL Utils plug-in");
        return false;
    }
    true
}

fn plugin_init() -> Result<(), ()> {
    binaryninja::tracing_init!("BNTL Utils");

    binaryninja::command::register_command(
        "BNTL\\Create\\From Current View",
        "Create .bntl files from the current view",
        command::create::CreateFromCurrentView {},
    );

    binaryninja::command::register_command_for_project(
        "BNTL\\Create\\From Project",
        "Create .bntl files from the given project",
        command::create::CreateFromProject {},
    );

    binaryninja::command::register_global_command(
        "BNTL\\Create\\From Directory",
        "Create .bntl files from the given directory",
        command::create::CreateFromDirectory {},
    );

    binaryninja::command::register_global_command(
        "BNTL\\Diff",
        "Diff two .bntl files and output the difference to a file",
        command::diff::Diff {},
    );

    binaryninja::command::register_global_command(
        "BNTL\\Dump To Header",
        "Dump a .bntl file to a header file",
        command::dump::Dump {},
    );

    binaryninja::command::register_global_command(
        "BNTL\\Validate",
        "Validate a .bntl file and report the issues",
        command::validate::Validate {},
    );

    Ok(())
}
