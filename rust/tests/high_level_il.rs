use binaryninja::binary_view::BinaryViewBase;
use binaryninja::headless::Session;
use binaryninja::high_level_il::{
    HighLevelExpressionIndex, HighLevelILInstructionKind, HighLevelInstructionIndex,
};
use std::path::PathBuf;

#[test]
fn test_hlil_info() {
    let _session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");
    let image_base = view.original_image_base();

    let entry_function = view.entry_point_function().unwrap();
    let hlil_function = entry_function.high_level_il(false).unwrap();
    let hlil_basic_blocks = hlil_function.basic_blocks();
    let mut hlil_basic_block_iter = hlil_basic_blocks.iter();
    let first_basic_block = hlil_basic_block_iter.next().unwrap();
    let mut hlil_instr_iter = first_basic_block.iter();

    // NOTE: I guess this is right?
    // 00025f10        (HLIL_BLOCK
    // 00025f22            (HLIL_RET return (
    // 00025f22                HLIL_CALL (HLIL_CONST_PTR.d __crt_interlocked_read_32)((HLIL_VAR.d arg1))))
    // 00025f10        )
    let instr_0 = hlil_instr_iter.next().unwrap();
    assert_eq!(instr_0.instr_index, HighLevelInstructionIndex(0));
    assert_eq!(instr_0.expr_index, HighLevelExpressionIndex(5));
    assert_eq!(instr_0.address, image_base + 0x00025f22);
    println!("{:?}", instr_0.kind);
    match instr_0.kind {
        HighLevelILInstructionKind::Ret(op) => {
            assert_eq!(op.first_src, 4);
            assert_eq!(op.num_srcs, 1);
        }
        _ => panic!("Expected Ret"),
    }
}

#[test]
fn test_hlil_var_info() {
    let _session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");

    let function = view
        .function_at(&view.default_platform().unwrap(), view.start() + 0x28600)
        .unwrap();
    let hlil_function = function.high_level_il(false).unwrap();

    for v in hlil_function.variables().iter() {
        let defs = hlil_function.variable_definitions(v).to_vec();
        if v.index != 0 {
            // Make sure non-param vars have a def site
            assert!(defs.len() > 0)
        }
        let _ = hlil_function.variable_uses(v).to_vec();
        for ssa_var in hlil_function.ssa_variables(&v).iter() {
            let _ = hlil_function.ssa_variable_uses(ssa_var).to_vec();
        }
    }
}
