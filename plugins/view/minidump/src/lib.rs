use binaryninja::binary_view::BinaryView;
use binaryninja::command::{register_command, Command};
use binaryninja::custom_binary_view::register_view_type;
use binaryninja::logger::Logger;
use log::{debug, LevelFilter};

mod command;
mod view;

struct PrintMemoryInformationCommand;

impl Command for PrintMemoryInformationCommand {
    fn action(&self, binary_view: &BinaryView) {
        command::print_memory_information(binary_view);
    }

    fn valid(&self, _binary_view: &BinaryView) -> bool {
        true // TODO: Of course, the command will not always be valid!
    }
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginInit() -> bool {
    Logger::new("Minidump")
        .with_level(LevelFilter::Trace)
        .init();

    debug!("Registering minidump binary view type");
    register_view_type("Minidump", "Minidump", view::MinidumpBinaryViewType::new);

    debug!("Registering minidump plugin commands");
    register_command(
        "Minidump\\[DEBUG] Print Minidump Memory Information",
        "Print a human-readable description of the contents of the MinidumpMemoryInfoList stream in the loaded minidump",
        PrintMemoryInformationCommand {},
    );

    true
}
