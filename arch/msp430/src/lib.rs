extern crate binaryninja;
extern crate log;
extern crate msp430_asm;

use binaryninja::{
    add_optional_plugin_dependency,
    architecture::ArchitectureExt,
    calling_convention,
    custom_binary_view::{BinaryViewType, BinaryViewTypeExt},
    Endianness,
};
use log::LevelFilter;

mod architecture;
mod flag;
mod lift;
mod register;

use architecture::Msp430;
use binaryninja::logger::Logger;

#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginInit() -> bool {
    Logger::new("MSP430").with_level(LevelFilter::Info).init();
    let arch =
        binaryninja::architecture::register_architecture("msp430", |custom_handle, handle| {
            Msp430::new(handle, custom_handle)
        });

    // we may need to introduce additional calling conventions here to
    // support additional ABIs. MSPGCC's calling convention (what
    // microcorruption seems to use) has some differences between the EABI
    // calling convention though GCC has since added support for the EABI
    // calling convention according to
    // https://www.ti.com/lit/an/slaa664/slaa664.pdf?ts=1613210655081. MSPGCC
    // appears to be a legacy calling convention while EABI is the newer
    // standardized one that is compatible with TI's compiler
    let default = calling_convention::ConventionBuilder::new(arch)
        .is_eligible_for_heuristics(true)
        .int_arg_registers(&["r15", "r14", "r13", "r12"])
        .return_int_reg("r15")
        .return_hi_int_reg("r14")
        .register("default");
    calling_convention::ConventionBuilder::new(arch)
        .is_eligible_for_heuristics(true)
        .return_int_reg("r15")
        .return_hi_int_reg("r14")
        .register("stack");

    arch.set_default_calling_convention(&default);

    if let Ok(bvt) = BinaryViewType::by_name("ELF") {
        bvt.register_arch(105, Endianness::LittleEndian, arch);
    }

    true
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginDependencies() {
    add_optional_plugin_dependency("view_elf");
}
