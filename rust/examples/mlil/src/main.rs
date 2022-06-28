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
        let mlil = func.mlil().unwrap();
        mlil.basic_blocks().unwrap().iter().for_each(|bb| {
            bb.iter().for_each(|instr| match instr.info() {
                MediumLevelILOperation::Unimplemented => {
                    println!("Unimplemented: {:#x?}", instr.operation);
                }
                MediumLevelILOperation::SetVar { src, dest } => match src.info() {
                    MediumLevelILOperation::Unimplemented => {
                        println!("Unimplemented: {:#x?}", src.operation);
                    }
                    MediumLevelILOperation::Var { src } => {
                        println!(
                            "{} set to {}",
                            mlil.variable_name(&dest),
                            mlil.variable_name(&src)
                        );
                    }
                    _ => {}
                },
                _ => {}
            });
        });
    }

    binaryninja::headless::shutdown();
}
