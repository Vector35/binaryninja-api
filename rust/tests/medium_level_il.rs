use binaryninja::binary_view::BinaryViewExt;
use binaryninja::headless::Session;
use binaryninja::medium_level_il::{MediumLevelILInstructionKind, MediumLevelInstructionIndex};
use rstest::*;
use std::path::PathBuf;

#[fixture]
#[once]
fn session() -> Session {
    Session::new().expect("Failed to initialize session")
}

#[rstest]
fn test_mlil_info(_session: &Session) {
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");
    let image_base = view.original_image_base();

    let entry_function = view.entry_point_function().unwrap();
    let mlil_function = entry_function.medium_level_il().unwrap();
    let mlil_basic_blocks = mlil_function.basic_blocks();
    let mut mlil_basic_block_iter = mlil_basic_blocks.iter();
    let first_basic_block = mlil_basic_block_iter.next().unwrap();
    let mut mlil_instr_iter = first_basic_block.iter();

    // 0 @ 00025f10  (MLIL_SET_VAR.d edi_1 = (MLIL_VAR.d edi))
    let instr_0 = mlil_instr_iter.next().unwrap();
    assert_eq!(instr_0.expr_index, MediumLevelInstructionIndex(1));
    assert_eq!(instr_0.address, image_base + 0x00025f10);
    println!("{:?}", instr_0.kind);
    match instr_0.kind {
        MediumLevelILInstructionKind::SetVar(op) => {
            assert_eq!(op.dest.index, 524288);
            assert_eq!(op.src, 0);
        }
        _ => panic!("Expected SetVar"),
    }
    // 1 @ 00025f15  (MLIL_SET_VAR.d eax = (MLIL_VAR.d arg1))
    let instr_1 = mlil_instr_iter.next().unwrap();
    assert_eq!(instr_1.expr_index, MediumLevelInstructionIndex(3));
    assert_eq!(instr_1.address, image_base + 0x00025f15);
    println!("{:?}", instr_1.kind);
    match instr_1.kind {
        MediumLevelILInstructionKind::SetVar(op) => {
            assert_eq!(op.dest.index, 5);
            assert_eq!(op.src, 2);
        }
        _ => panic!("Expected SetVar"),
    }
    // 2 @ 00025f18  (MLIL_SET_VAR.d var_8 = (MLIL_VAR.d eax))
    let instr_2 = mlil_instr_iter.next().unwrap();
    assert_eq!(instr_2.expr_index, MediumLevelInstructionIndex(5));
    assert_eq!(instr_2.address, image_base + 0x00025f18);
    println!("{:?}", instr_2.kind);
    match instr_2.kind {
        MediumLevelILInstructionKind::SetVar(op) => {
            assert_eq!(op.dest.index, 8);
            assert_eq!(op.src, 4);
        }
        _ => panic!("Expected SetVar"),
    }
    // 3 @ 00025f19  (MLIL_CALL eax_1 = (MLIL_CONST_PTR.d __crt_interlocked_read_32)((MLIL_VAR.d var_8)))
    let instr_3 = mlil_instr_iter.next().unwrap();
    assert_eq!(instr_3.expr_index, MediumLevelInstructionIndex(10));
    assert_eq!(instr_3.address, image_base + 0x00025f19);
    println!("{:?}", instr_3.kind);
    match instr_3.kind {
        MediumLevelILInstructionKind::Call(op) => {
            assert_eq!(op.first_output, 8);
            assert_eq!(op.num_outputs, 1);
            assert_eq!(op.dest, 7);
            assert_eq!(op.first_param, 9);
            assert_eq!(op.num_params, 1);
        }
        _ => panic!("Expected Call"),
    }
    // 4 @ 00025f22  (MLIL_RET return (MLIL_VAR.d eax_1))
    let instr_4 = mlil_instr_iter.next().unwrap();
    assert_eq!(instr_4.expr_index, MediumLevelInstructionIndex(13));
    assert_eq!(instr_4.address, image_base + 0x00025f22);
    println!("{:?}", instr_4.kind);
    match instr_4.kind {
        MediumLevelILInstructionKind::Ret(op) => {
            assert_eq!(op.first_operand, 12);
            assert_eq!(op.num_operands, 1);
        }
        _ => panic!("Expected Ret"),
    }
}
