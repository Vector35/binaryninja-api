use binaryninja::architecture::CoreArchitecture;
use binaryninja::binaryview::{BinaryView, BinaryViewBase, BinaryViewExt};
use binaryninja::llil::VisitorAction;
use binaryninja::mlil::{ExprInfo, Finalized, NonSSA, RegularNonSSA};

fn main() {
    binaryninja::headless::init();

    let bv = binaryninja::open_view("/Users/admin/projects/testc/complicated-gcc").unwrap();
    for func in &bv.functions() {
        if func.symbol().full_name().as_str() != "_main" {
            continue;
        }

        println!("FUNCTION:: {}", func.symbol().full_name());
        let mlil = func.medium_level_il().unwrap();
        for bb in &mlil.basic_blocks() {
            bb.iter().for_each(|x| {
                println!("{:#x?}", x.operation());
            });
        }
    }

    binaryninja::headless::shutdown();
}
