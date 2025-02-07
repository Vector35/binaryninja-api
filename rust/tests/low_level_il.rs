use binaryninja::architecture::Register;
use binaryninja::binary_view::BinaryViewExt;
use binaryninja::headless::Session;
use binaryninja::low_level_il::expression::{
    ExpressionHandler, LowLevelExpressionIndex, LowLevelILExpressionKind,
};
use binaryninja::low_level_il::instruction::{
    InstructionHandler, LowLevelILInstructionKind, LowLevelInstructionIndex,
};
use binaryninja::low_level_il::{LowLevelILRegister, VisitorAction};
use rstest::*;
use std::path::PathBuf;

#[fixture]
#[once]
fn session() -> Session {
    Session::new().expect("Failed to initialize session")
}

#[rstest]
fn test_llil_info(_session: &Session) {
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");
    let image_base = view.original_image_base();

    let entry_function = view.entry_point_function().unwrap();
    let llil_function = entry_function.low_level_il().unwrap();
    let llil_basic_blocks = llil_function.basic_blocks();
    let mut llil_basic_block_iter = llil_basic_blocks.iter();
    let first_basic_block = llil_basic_block_iter.next().unwrap();
    let mut llil_instr_iter = first_basic_block.iter();

    // 0 @ 00025f10  (LLIL_SET_REG.d edi = (LLIL_REG.d edi))
    let instr_0 = llil_instr_iter.next().unwrap();
    assert_eq!(instr_0.index, LowLevelInstructionIndex(0));
    assert_eq!(instr_0.address(), image_base + 0x00025f10);
    println!("{:?}", instr_0);
    println!("{:?}", instr_0.kind());
    match instr_0.kind() {
        LowLevelILInstructionKind::SetReg(op) => {
            assert_eq!(op.size(), 4);
            match op.dest_reg() {
                LowLevelILRegister::ArchReg(reg) => assert_eq!(reg.name(), "edi"),
                _ => panic!("Expected Register::ArchReg"),
            }
            assert_eq!(op.source_expr().index, LowLevelExpressionIndex(0));
        }
        _ => panic!("Expected SetReg"),
    }
    // 1 @ 00025f12  (LLIL_PUSH.d push((LLIL_REG.d ebp)))
    let instr_1 = llil_instr_iter.next().unwrap();
    assert_eq!(instr_1.index, LowLevelInstructionIndex(1));
    assert_eq!(instr_1.address(), image_base + 0x00025f12);
    println!("{:?}", instr_1.kind());
    match instr_1.kind() {
        LowLevelILInstructionKind::Push(op) => {
            assert_eq!(op.size(), 4);
            assert_eq!(op.operand().index, LowLevelExpressionIndex(2));
            println!("{:?}", op.operand().kind());
            match op.operand().kind() {
                LowLevelILExpressionKind::Reg(op) => {
                    assert_eq!(op.size(), 4);
                    match op.source_reg() {
                        LowLevelILRegister::ArchReg(reg) => assert_eq!(reg.name(), "ebp"),
                        _ => panic!("Expected Register::ArchReg"),
                    }
                }
                _ => panic!("Expected Reg"),
            }
        }
        _ => panic!("Expected Push"),
    }
    // 2 @ 00025f13  (LLIL_SET_REG.d ebp = (LLIL_REG.d esp) {__saved_ebp})
    let instr_2 = llil_instr_iter.next().unwrap();
    assert_eq!(instr_2.index, LowLevelInstructionIndex(2));
    assert_eq!(instr_2.address(), image_base + 0x00025f13);
    println!("{:?}", instr_2.kind());
    match instr_2.kind() {
        LowLevelILInstructionKind::SetReg(op) => {
            assert_eq!(op.size(), 4);
            match op.dest_reg() {
                LowLevelILRegister::ArchReg(reg) => assert_eq!(reg.name(), "ebp"),
                _ => panic!("Expected Register::ArchReg"),
            }
            assert_eq!(op.source_expr().index, LowLevelExpressionIndex(4));
        }
        _ => panic!("Expected SetReg"),
    }
    // 3 @ 00025f15  (LLIL_SET_REG.d eax = (LLIL_LOAD.d [(LLIL_ADD.d (LLIL_REG.d ebp) + (LLIL_CONST.d 8)) {arg1}].d))
    let instr_3 = llil_instr_iter.next().unwrap();
    assert_eq!(instr_3.index, LowLevelInstructionIndex(3));
    assert_eq!(instr_3.address(), image_base + 0x00025f15);
    println!("{:?}", instr_3.kind());
    match instr_3.kind() {
        LowLevelILInstructionKind::SetReg(op) => {
            assert_eq!(op.size(), 4);
            match op.dest_reg() {
                LowLevelILRegister::ArchReg(reg) => assert_eq!(reg.name(), "eax"),
                _ => panic!("Expected Register::ArchReg"),
            }
            assert_eq!(op.source_expr().index, LowLevelExpressionIndex(9));
        }
        _ => panic!("Expected SetReg"),
    }
    // 4 @ 00025f18  (LLIL_PUSH.d push((LLIL_REG.d eax)))
    let instr_4 = llil_instr_iter.next().unwrap();
    assert_eq!(instr_4.index, LowLevelInstructionIndex(4));
    assert_eq!(instr_4.address(), image_base + 0x00025f18);
    println!("{:?}", instr_4.kind());
    match instr_4.kind() {
        LowLevelILInstructionKind::Push(op) => {
            assert_eq!(op.size(), 4);
            assert_eq!(op.operand().index, LowLevelExpressionIndex(11));
        }
        _ => panic!("Expected Push"),
    }
    // 5 @ 00025f19  (LLIL_CALL call((LLIL_CONST_PTR.d __crt_interlocked_read_32)))
    let instr_5 = llil_instr_iter.next().unwrap();
    assert_eq!(instr_5.index, LowLevelInstructionIndex(5));
    assert_eq!(instr_5.address(), image_base + 0x00025f19);
    println!("{:?}", instr_5.kind());
    match instr_5.kind() {
        LowLevelILInstructionKind::Call(op) => {
            assert_eq!(op.target().index, LowLevelExpressionIndex(13));
        }
        _ => panic!("Expected Call"),
    }
    // 6 @ 00025f1e  (LLIL_SET_REG.d esp = (LLIL_ADD.d (LLIL_REG.d esp) + (LLIL_CONST.d 4)))
    let instr_6 = llil_instr_iter.next().unwrap();
    assert_eq!(instr_6.index, LowLevelInstructionIndex(6));
    assert_eq!(instr_6.address(), image_base + 0x00025f1e);
    println!("{:?}", instr_6.kind());
    match instr_6.kind() {
        LowLevelILInstructionKind::SetReg(op) => {
            assert_eq!(op.size(), 4);
            match op.dest_reg() {
                LowLevelILRegister::ArchReg(reg) => assert_eq!(reg.name(), "esp"),
                _ => panic!("Expected Register::ArchReg"),
            }
            assert_eq!(op.source_expr().index, LowLevelExpressionIndex(17));
        }
        _ => panic!("Expected SetReg"),
    }
    // 7 @ 00025f21  (LLIL_SET_REG.d ebp = (LLIL_POP.d pop))
    let instr_7 = llil_instr_iter.next().unwrap();
    assert_eq!(instr_7.index, LowLevelInstructionIndex(7));
    assert_eq!(instr_7.address(), image_base + 0x00025f21);
    println!("{:?}", instr_7.kind());
    match instr_7.kind() {
        LowLevelILInstructionKind::SetReg(op) => {
            assert_eq!(op.size(), 4);
            match op.dest_reg() {
                LowLevelILRegister::ArchReg(reg) => assert_eq!(reg.name(), "ebp"),
                _ => panic!("Expected Register::ArchReg"),
            }
            assert_eq!(op.source_expr().index, LowLevelExpressionIndex(19));
        }
        _ => panic!("Expected SetReg"),
    }
    // 8 @ 00025f22  (LLIL_RET <return> jump((LLIL_POP.d pop)))
    let instr_8 = llil_instr_iter.next().unwrap();
    assert_eq!(instr_8.index, LowLevelInstructionIndex(8));
    assert_eq!(instr_8.address(), image_base + 0x00025f22);
    println!("{:?}", instr_8.kind());
    match instr_8.kind() {
        LowLevelILInstructionKind::Ret(op) => {
            assert_eq!(op.target().index, LowLevelExpressionIndex(21));
        }
        _ => panic!("Expected Ret"),
    }
}

#[rstest]
fn test_llil_visitor(_session: &Session) {
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");
    let image_base = view.original_image_base();
    let platform = view.default_platform().unwrap();

    // Sample function: __crt_strtox::c_string_character_source<char>::validate
    let sample_function = view.function_at(&platform, image_base + 0x2bd80).unwrap();
    let llil_function = sample_function.low_level_il().unwrap();
    let llil_basic_blocks = llil_function.basic_blocks();
    let llil_basic_block_iter = llil_basic_blocks.iter();

    let mut basic_blocks_visited = 0;
    let mut instructions_visited: Vec<LowLevelInstructionIndex> = vec![];
    let mut expressions_visited: Vec<LowLevelExpressionIndex> = vec![];
    for basic_block in llil_basic_block_iter {
        basic_blocks_visited += 1;
        for instr in basic_block.iter() {
            instructions_visited.push(instr.index);
            expressions_visited.push(instr.expr_idx());
            instr.visit_tree(&mut |expr| {
                expressions_visited.push(expr.index);
                VisitorAction::Descend
            });
        }
    }

    assert_eq!(basic_blocks_visited, 10);
    // This is a flag instruction removed in LLIL.
    instructions_visited.push(LowLevelInstructionIndex(38));
    for instr_idx in 0..41 {
        if instructions_visited
            .iter()
            .find(|x| x.0 == instr_idx)
            .is_none()
        {
            panic!("Instruction with index {:?} not visited", instr_idx);
        };
    }
    // These are NOP's
    expressions_visited.push(LowLevelExpressionIndex(24));
    expressions_visited.push(LowLevelExpressionIndex(54));
    expressions_visited.push(LowLevelExpressionIndex(62));
    expressions_visited.push(LowLevelExpressionIndex(87));
    // These are some flag things
    expressions_visited.push(LowLevelExpressionIndex(114));
    expressions_visited.push(LowLevelExpressionIndex(115));
    expressions_visited.push(LowLevelExpressionIndex(116));
    expressions_visited.push(LowLevelExpressionIndex(121));
    for expr_idx in 0..127 {
        if expressions_visited
            .iter()
            .find(|x| x.0 == expr_idx)
            .is_none()
        {
            panic!("Expression with index {:?} not visited", expr_idx);
        };
    }
}
