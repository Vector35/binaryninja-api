use binaryninja::binaryninjacore_sys::BNMediumLevelILOperation::*;
use binaryninja::binaryview::BinaryViewExt;
use binaryninja::mlil::MediumLevelILOperation;

fn main() {
    binaryninja::headless::init();

    let bv = binaryninja::open_view("/Users/admin/projects/testc/complicated-gcc").unwrap();
    for func in &bv.functions() {
        if func.symbol().full_name().as_str() != "_main" {
            continue;
        }

        println!("FUNCTION:: {}", func.symbol().full_name());
        func.mlil()
            .unwrap()
            .basic_blocks()
            .unwrap()
            .iter()
            .for_each(|bb| {
                bb.iter().for_each(|instr| match instr.info() {
                    MediumLevelILOperation::Call { output, ..  } => {
                        output.iter().for_each(|var| println!("{:?}", var.t));
                    }
                    _ => {}
                });
            });
    }

    binaryninja::headless::shutdown();
}
