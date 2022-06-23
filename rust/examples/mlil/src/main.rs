use binaryninja::binaryview::BinaryViewExt;

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
                bb.iter().for_each(|instr| {
                    println!("{:#x?}", instr);
                });
            });
    }

    binaryninja::headless::shutdown();
}
