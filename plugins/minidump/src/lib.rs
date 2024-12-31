use binaryninja::binaryview::BinaryView;
use binaryninja::command::{register, Command};
use binaryninja::custombinaryview::register_view_type;
use log::{debug, LevelFilter};
use binaryninja::logger::Logger;

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
    Logger::new("Minidump").with_level(LevelFilter::Trace).init();

    debug!("Registering minidump binary view type");
    register_view_type("Minidump", "Minidump", view::MinidumpBinaryViewType::new);

    debug!("Registering minidump plugin commands");
    register(
        "Minidump\\[DEBUG] Print Minidump Memory Information",
        "Print a human-readable description of the contents of the MinidumpMemoryInfoList stream in the loaded minidump",
        PrintMemoryInformationCommand {},
    );

    true
}
