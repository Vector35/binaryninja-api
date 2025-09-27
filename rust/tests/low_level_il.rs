use binaryninja::architecture::{ArchitectureExt, Intrinsic, Register};
use binaryninja::binary_view::BinaryViewExt;
use binaryninja::headless::Session;
use binaryninja::low_level_il::expression::{
    ExpressionHandler, LowLevelExpressionIndex, LowLevelILExpressionKind,
};
use binaryninja::low_level_il::instruction::{
    InstructionHandler, LowLevelILInstructionKind, LowLevelInstructionIndex,
};
use binaryninja::low_level_il::operation::IntrinsicOutput;
use binaryninja::low_level_il::{LowLevelILRegisterKind, LowLevelILSSARegisterKind, VisitorAction};
use std::path::PathBuf;

#[test]
fn test_llil_info() {
    let _session = Session::new().expect("Failed to initialize session");
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
                LowLevelILRegisterKind::Arch(reg) => assert_eq!(reg.name(), "edi"),
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
                        LowLevelILRegisterKind::Arch(reg) => assert_eq!(reg.name(), "ebp"),
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
                LowLevelILRegisterKind::Arch(reg) => assert_eq!(reg.name(), "ebp"),
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
                LowLevelILRegisterKind::Arch(reg) => assert_eq!(reg.name(), "eax"),
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
                LowLevelILRegisterKind::Arch(reg) => assert_eq!(reg.name(), "esp"),
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
                LowLevelILRegisterKind::Arch(reg) => assert_eq!(reg.name(), "ebp"),
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

#[test]
fn test_llil_visitor() {
    let _session = Session::new().expect("Failed to initialize session");
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

#[test]
fn test_llil_ssa() {
    let _session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let view = binaryninja::load(out_dir.join("atox.obj")).expect("Failed to create view");
    let image_base = view.original_image_base();
    let platform = view.default_platform().unwrap();

    // Sample function: __crt_strtox::c_string_character_source<char>::validate
    let sample_function = view.function_at(&platform, image_base + 0x2bd80).unwrap();
    let llil_function = sample_function.low_level_il().unwrap();
    let llil_ssa_function = llil_function.ssa_form().expect("Valid SSA form");

    let llil_ssa_basic_blocks = llil_ssa_function.basic_blocks();
    let mut llil_ssa_basic_block_iter = llil_ssa_basic_blocks.iter();
    let first_basic_block = llil_ssa_basic_block_iter.next().unwrap();
    let mut llil_instr_iter = first_basic_block.iter();

    // 0 @ 0002bd80  (LLIL_SET_REG_SSA.d edi#1 = (LLIL_REG_SSA.d edi#0))
    let ssa_instr_0 = llil_instr_iter.next().unwrap();
    assert_eq!(ssa_instr_0.index, LowLevelInstructionIndex(0));
    assert_eq!(ssa_instr_0.address(), image_base + 0x0002bd80);
    println!("{:?}", ssa_instr_0);
    println!("{:?}", ssa_instr_0.kind());
    match ssa_instr_0.kind() {
        LowLevelILInstructionKind::SetRegSsa(op) => {
            assert_eq!(op.size(), 4);
            match op.dest_reg() {
                LowLevelILSSARegisterKind::Full { kind, version } => {
                    assert_eq!(kind.name(), "edi");
                    assert_eq!(version, 1);
                }
                _ => panic!("Expected LowLevelILSSARegisterKind::Full"),
            }
            assert_eq!(op.source_expr().index, LowLevelExpressionIndex(0));
        }
        _ => panic!("Expected SetRegSsa"),
    }

    // 1 @ 0002bd82  (LLIL_STORE_SSA.d [(LLIL_SUB.d (LLIL_REG_SSA.d esp#0) - (LLIL_CONST.d 4)) {__saved_ebp}].d = (LLIL_REG_SSA.d ebp#0) @ mem#0 -> mem#1)
    let ssa_instr_1 = llil_instr_iter.next().unwrap();
    assert_eq!(ssa_instr_1.index, LowLevelInstructionIndex(1));
    assert_eq!(ssa_instr_1.address(), image_base + 0x0002bd82);
    println!("{:?}", ssa_instr_1);
    println!("{:?}", ssa_instr_1.kind());
    match ssa_instr_1.kind() {
        LowLevelILInstructionKind::StoreSsa(op) => {
            assert_eq!(op.size(), 4);
            let source_expr = op.source_expr();
            let source_memory_version = op.source_memory_version();
            assert_eq!(source_memory_version, 0);
            assert_eq!(source_expr.index, LowLevelExpressionIndex(5));
            let dest_expr = op.dest_expr();
            let dest_memory_version = op.dest_memory_version();
            assert_eq!(dest_memory_version, 1);
            assert_eq!(dest_expr.index, LowLevelExpressionIndex(4));
        }
        _ => panic!("Expected StoreSsa"),
    }

    // 34 @ 0002bdc7  (LLIL_CALL_SSA eax#8, edx#5, ecx#6, mem#23 = call((LLIL_EXTERN_PTR.d __CrtDbgReportW), stack = esp#18 @ mem#22))
    let ssa_instr_34 = llil_ssa_function
        .instruction_from_index(LowLevelInstructionIndex(34))
        .expect("Valid instruction");
    assert_eq!(ssa_instr_34.index, LowLevelInstructionIndex(34));
    assert_eq!(ssa_instr_34.address(), image_base + 0x0002bdc7);
    println!("{:?}", ssa_instr_34);
    println!("{:?}", ssa_instr_34.kind());
    match ssa_instr_34.kind() {
        LowLevelILInstructionKind::CallSsa(op) => match op.target().kind() {
            LowLevelILExpressionKind::ExternPtr(extern_ptr) => {
                assert_eq!(extern_ptr.size(), 4);
                let extern_sym = view
                    .symbol_by_address(extern_ptr.value())
                    .expect("Valid symbol");
                assert_eq!(extern_sym.short_name(), "__CrtDbgReportW".into())
            }
            _ => panic!("Expected ExternPtr"),
        },
        _ => panic!("Expected CallSsa"),
    }
}

#[test]
fn test_llil_intrinsic() {
    let _session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let view = binaryninja::load(out_dir.join("atof.obj")).expect("Failed to create view");
    let image_base = view.original_image_base();
    let platform = view.default_platform().unwrap();
    let arch = platform.arch();

    // Sample function: __crt_strtox::bit_scan_reverse
    let sample_function = view
        .function_at(&platform, image_base + 0x00037310)
        .unwrap();
    let llil_function = sample_function.low_level_il().unwrap();

    // 5 @ 0004731d  (LLIL_INTRINSIC eax, eflags = __bsr_gprv_memv((LLIL_LOAD.d [(LLIL_ADD.d (LLIL_REG.d ebp) + (LLIL_CONST.d 8)) {arg1}].d)))
    let instr_5 = llil_function
        .instruction_from_index(LowLevelInstructionIndex(5))
        .expect("Valid instruction");
    assert_eq!(instr_5.address(), image_base + 0x0003731d);
    println!("{:?}", instr_5);
    println!("{:#?}", instr_5.kind());
    match instr_5.kind() {
        LowLevelILInstructionKind::Intrinsic(op) => {
            assert_eq!(op.intrinsic().unwrap().name(), "__bsr_gprv_memv");
            assert_eq!(op.outputs().len(), 2);
            let reg_out_0 = arch.register_by_name("eax").unwrap();
            let reg_out_1 = arch.register_by_name("eflags").unwrap();
            assert_eq!(
                op.outputs(),
                vec![
                    IntrinsicOutput::Reg(reg_out_0),
                    IntrinsicOutput::Reg(reg_out_1),
                ]
            );
        }
        _ => panic!("Expected Intrinsic"),
    }
}
