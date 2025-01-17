use binaryninja::architecture::Register;
use binaryninja::binaryview::{BinaryView, BinaryViewExt};
use binaryninja::headless::Session;
use binaryninja::lowlevelil::expression::LowLevelILExpressionIndex;
use binaryninja::lowlevelil::instruction::{
    InstructionHandler, LowLevelILInstructionKind, LowLevelInstructionIndex,
};
use binaryninja::lowlevelil::LowLevelILRegister;
use binaryninja::rc::Ref;
use rstest::*;
use std::path::PathBuf;

#[fixture]
#[once]
fn session() -> Session {
    Session::new().expect("Failed to initialize session")
}

#[fixture]
#[once]
fn view() -> Ref<BinaryView> {
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view")
}

#[rstest]
fn test_llil_info(_session: &Session, view: &BinaryView) {
    let entry_function = view.entry_point_function().unwrap();
    let llil_function = entry_function.low_level_il().unwrap();
    let llil_basic_blocks = llil_function.basic_blocks();
    let mut llil_basic_block_iter = llil_basic_blocks.iter();
    let first_basic_block = llil_basic_block_iter.next().unwrap();
    let mut llil_instr_iter = first_basic_block.iter();

    // 0 @ 00025f10  (LLIL_SET_REG.d edi = (LLIL_REG.d edi))
    let instr_0 = llil_instr_iter.next().unwrap();
    assert_eq!(instr_0.index, LowLevelInstructionIndex(0));
    assert_eq!(instr_0.address(), 0x00025f10);
    println!("{:?}", instr_0.kind());
    match instr_0.kind() {
        LowLevelILInstructionKind::SetReg(op) => {
            assert_eq!(op.size(), 4);
            match op.dest_reg() {
                LowLevelILRegister::ArchReg(reg) => assert_eq!(reg.name(), "edi"),
                _ => panic!("Expected Register::ArchReg"),
            }
            assert_eq!(op.source_expr().index, LowLevelILExpressionIndex(0));
        }
        _ => panic!("Expected SetReg"),
    }
    // 1 @ 00025f12  (LLIL_PUSH.d push((LLIL_REG.d ebp)))
    let instr_1 = llil_instr_iter.next().unwrap();
    assert_eq!(instr_1.index, LowLevelInstructionIndex(1));
    assert_eq!(instr_1.address(), 0x00025f12);
    println!("{:?}", instr_1.kind());
    match instr_1.kind() {
        LowLevelILInstructionKind::Push(op) => {
            assert_eq!(op.size(), 4);
            assert_eq!(op.operand().index, LowLevelILExpressionIndex(2));
        }
        _ => panic!("Expected Push"),
    }
    // 2 @ 00025f13  (LLIL_SET_REG.d ebp = (LLIL_REG.d esp) {__saved_ebp})
    let instr_2 = llil_instr_iter.next().unwrap();
    assert_eq!(instr_2.index, LowLevelInstructionIndex(2));
    assert_eq!(instr_2.address(), 0x00025f13);
    println!("{:?}", instr_2.kind());
    match instr_2.kind() {
        LowLevelILInstructionKind::SetReg(op) => {
            assert_eq!(op.size(), 4);
            match op.dest_reg() {
                LowLevelILRegister::ArchReg(reg) => assert_eq!(reg.name(), "ebp"),
                _ => panic!("Expected Register::ArchReg"),
            }
            assert_eq!(op.source_expr().index, LowLevelILExpressionIndex(4));
        }
        _ => panic!("Expected SetReg"),
    }
    // 3 @ 00025f15  (LLIL_SET_REG.d eax = (LLIL_LOAD.d [(LLIL_ADD.d (LLIL_REG.d ebp) + (LLIL_CONST.d 8)) {arg1}].d))
    let instr_3 = llil_instr_iter.next().unwrap();
    assert_eq!(instr_3.index, LowLevelInstructionIndex(3));
    assert_eq!(instr_3.address(), 0x00025f15);
    println!("{:?}", instr_3.kind());
    match instr_3.kind() {
        LowLevelILInstructionKind::SetReg(op) => {
            assert_eq!(op.size(), 4);
            match op.dest_reg() {
                LowLevelILRegister::ArchReg(reg) => assert_eq!(reg.name(), "eax"),
                _ => panic!("Expected Register::ArchReg"),
            }
            assert_eq!(op.source_expr().index, LowLevelILExpressionIndex(9));
        }
        _ => panic!("Expected SetReg"),
    }
    // 4 @ 00025f18  (LLIL_PUSH.d push((LLIL_REG.d eax)))
    let instr_4 = llil_instr_iter.next().unwrap();
    assert_eq!(instr_4.index, LowLevelInstructionIndex(4));
    assert_eq!(instr_4.address(), 0x00025f18);
    println!("{:?}", instr_4.kind());
    match instr_4.kind() {
        LowLevelILInstructionKind::Push(op) => {
            assert_eq!(op.size(), 4);
            assert_eq!(op.operand().index, LowLevelILExpressionIndex(11));
        }
        _ => panic!("Expected Push"),
    }
    // 5 @ 00025f19  (LLIL_CALL call((LLIL_CONST_PTR.d __crt_interlocked_read_32)))
    let instr_5 = llil_instr_iter.next().unwrap();
    assert_eq!(instr_5.index, LowLevelInstructionIndex(5));
    assert_eq!(instr_5.address(), 0x00025f19);
    println!("{:?}", instr_5.kind());
    match instr_5.kind() {
        LowLevelILInstructionKind::Call(op) => {
            assert_eq!(op.target().index, LowLevelILExpressionIndex(13));
        }
        _ => panic!("Expected Call"),
    }
    // 6 @ 00025f1e  (LLIL_SET_REG.d esp = (LLIL_ADD.d (LLIL_REG.d esp) + (LLIL_CONST.d 4)))
    let instr_6 = llil_instr_iter.next().unwrap();
    assert_eq!(instr_6.index, LowLevelInstructionIndex(6));
    assert_eq!(instr_6.address(), 0x00025f1e);
    println!("{:?}", instr_6.kind());
    match instr_6.kind() {
        LowLevelILInstructionKind::SetReg(op) => {
            assert_eq!(op.size(), 4);
            match op.dest_reg() {
                LowLevelILRegister::ArchReg(reg) => assert_eq!(reg.name(), "esp"),
                _ => panic!("Expected Register::ArchReg"),
            }
            assert_eq!(op.source_expr().index, LowLevelILExpressionIndex(17));
        }
        _ => panic!("Expected SetReg"),
    }
    // 7 @ 00025f21  (LLIL_SET_REG.d ebp = (LLIL_POP.d pop))
    let instr_7 = llil_instr_iter.next().unwrap();
    assert_eq!(instr_7.index, LowLevelInstructionIndex(7));
    assert_eq!(instr_7.address(), 0x00025f21);
    println!("{:?}", instr_7.kind());
    match instr_7.kind() {
        LowLevelILInstructionKind::SetReg(op) => {
            assert_eq!(op.size(), 4);
            match op.dest_reg() {
                LowLevelILRegister::ArchReg(reg) => assert_eq!(reg.name(), "ebp"),
                _ => panic!("Expected Register::ArchReg"),
            }
            assert_eq!(op.source_expr().index, LowLevelILExpressionIndex(19));
        }
        _ => panic!("Expected SetReg"),
    }
    // 8 @ 00025f22  (LLIL_RET <return> jump((LLIL_POP.d pop)))
    let instr_8 = llil_instr_iter.next().unwrap();
    assert_eq!(instr_8.index, LowLevelInstructionIndex(8));
    assert_eq!(instr_8.address(), 0x00025f22);
    println!("{:?}", instr_8.kind());
    match instr_8.kind() {
        LowLevelILInstructionKind::Ret(op) => {
            assert_eq!(op.target().index, LowLevelILExpressionIndex(21));
        }
        _ => panic!("Expected Ret"),
    }
}
