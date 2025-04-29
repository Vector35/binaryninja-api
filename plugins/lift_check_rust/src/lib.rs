use binaryninja::architecture::{CoreArchitecture, Register, RegisterInfo};
use binaryninja::logger::Logger;
use binaryninja::low_level_il::expression::{ExpressionHandler, LowLevelILExpression, ValueExpr};
use binaryninja::low_level_il::expression::LowLevelILExpressionKind::*;
use binaryninja::low_level_il::function::{Finalized, LowLevelILFunction, Mutable, NonSSA};
use binaryninja::low_level_il::instruction::LowLevelILInstructionKind::*;
use log::{error, info, LevelFilter};
use binaryninja::low_level_il::instruction::{InstructionHandler, LowLevelILInstruction};
use binaryninja::low_level_il::{LowLevelILRegisterKind};
use binaryninja::workflow::{Activity, AnalysisContext, Workflow};

pub const LIFT_CHECK_ACTIVITY_NAME: &str = "analysis.liftCheck";
const LIFT_CHECK_ACTIVITY_CONFIG: &str = r#"{
    "name": "analysis.liftCheck",
    "title" : "Lift Check",
    "description": "This analysis step checks all IL instructions in the function",
    "eligibility": {
        "auto": {}
    }
}"#;

fn check_expression(expr: &LowLevelILExpression<Mutable, NonSSA, ValueExpr>,
                    required_size: Option<usize>)
{
    match expr.kind() {
        Reg(ref op) => {
            let size = op.size();

            if let Some(required_size) = required_size {
                if required_size != size {
                    error!("LLIL_REG op gives a {} byte value where {} bytes are expected! (addr: {:x} {:?})",
                           size, required_size, op.address(), expr);
                }
            }

            if let LowLevelILRegisterKind::Arch(r) = op.source_reg() {
                let reg_size = r.info().size();

                if reg_size != size {
                    error!("LLIL_REG attempting to load {} bytes out of a {} byte register! (addr: {:x} {:?})",
                           size, reg_size, op.address(), expr);
                }
            }
        }

        Flag(ref op) => {
            if let Some(required_size) = required_size {
                if required_size != 0 {
                    error!("LLIL_FLAG op gives a boolean value where {} bytes are expected! (addr: {:x} {:?})",
                           required_size, op.address(), expr);
                }
            }
        }

        FlagBit(ref op) => {
            // TODO
        }

        Load(ref op) => {
            if let Some(required_size) = required_size {
                if required_size != op.size() {
                    error!("LLIL_LOAD op gives a {} byte value where {} bytes are expected! (addr: {:x} {:?})",
                           op.size(), required_size, op.address(), expr);
                }
            }
        }

        Pop(ref op) => {
            if let Some(required_size) = required_size {
                if required_size != op.size() {
                    error!("LLIL_POP op gives a {} byte value where {} bytes are expected! (addr: {:x} {:?})",
                           op.size(), required_size, op.address(), expr);
                }
            }
        }

        Const(ref op) | ConstPtr(ref op) => {
            if let Some(required_size) = required_size {
                if required_size != op.size() {
                    error!("LLIL_CONST op gives a {} byte value where {} bytes are expected! (addr: {:x} {:?})",
                           op.size(), required_size, op.address(), expr);
                }
            }
        }

        FlagCond(ref op) => {
            if let Some(required_size) = required_size {
                if required_size != 0 {
                    error!("LLIL_FLAG_COND op gives boolean value where {} bytes are expected! (addr: {:x} {:?})",
                           required_size, op.address(), expr);
                }
            }
        }

        CmpE(ref op)   | CmpNe(ref op) |
        CmpSlt(ref op) | CmpUlt(ref op) |
        CmpSle(ref op) | CmpUle(ref op) |
        CmpSge(ref op) | CmpUge(ref op) |
        CmpSgt(ref op) | CmpUgt(ref op) => {
            if let Some(required_size) = required_size {
                if required_size != 0 {
                    error!("LLIL_CMP ops produce a boolean value, and a {} byte value is expected here! (addr: {:x} {:?})",
                           required_size, op.address(), expr);
                }
            }

            let cmp_size = op.size();
            if cmp_size == 0 {
                error!("compare of zero width detected! {:?}", expr);
            }

            check_expression(&op.left(), Some(cmp_size));
            check_expression(&op.right(), Some(cmp_size));
        }

        Adc(ref op) |
        Sbb(ref op) => {
            let op_size = op.size();

            if let Some(required_size) = required_size {
                if required_size != op_size {
                    error!("LLIL_ADC/SBB producing {} byte value {} byte value is expected! (addr: {:x} {:?})",
                           op_size, required_size, op.address(), expr);
                }
            }

            check_expression(&op.left(), Some(op_size));
            check_expression(&op.right(), Some(op_size));
            check_expression(&op.carry(), Some(0));
        }

        Rlc(ref op) |
        Rrc(ref op) => {
            let op_size = op.size();

            if let Some(required_size) = required_size {
                if required_size != op_size {
                    error!("LLIL_RLC/RRC producing {} byte value {} byte value is expected! (addr: {:x} {:?})",
                           op_size, required_size, op.address(), expr);
                }
            }

            // rotate amounts just need to be >= 1 byte
            if let Some(0) = op.right().kind().size() {
                error!("LLIL_RLC/RRC can't rotate by a 0 byte expression! (addr: {:x} {:?})",
                       op.address(), expr);
            }

            check_expression(&op.left(), Some(op_size));
            check_expression(&op.right(), None);
            check_expression(&op.carry(), Some(0));
        }

        Add(ref op) |
        Sub(ref op) |
        And(ref op) |
        Or (ref op) |
        Xor(ref op) |
        Mul(ref op) |
        Divu(ref op) |
        Divs(ref op) |
        Modu(ref op) |
        Mods(ref op) => {
            let op_size = op.size();

            if let Some(required_size) = required_size {
                if required_size != op_size {
                    error!("LLIL binary op producing {} byte value where {} byte value is expected! (addr: {:x} {:?})",
                           op_size, required_size, op.address(), expr);
                }
            }

            check_expression(&op.left(), Some(op_size));
            check_expression(&op.right(), Some(op_size));
        }

        Lsl(ref op) |
        Lsr(ref op) |
        Asr(ref op) |
        Rol(ref op) |
        Ror(ref op) => {
            let op_size = op.size();

            if let Some(required_size) = required_size {
                if required_size != op_size {
                    error!("LLIL rotate/shift binary op producing {} byte value where {} byte value is expected! (addr: {:x} {:?})",
                           op_size, required_size, op.address(), expr);
                }
            }

            // rotate amounts just need to be >= 1 byte
            if let Some(0) = op.right().kind().size() {
                error!("LLIL shift/rotate ops can't rotate by a 0 byte expression! (addr: {:x} {:?})",
                       op.address(), expr);
            }

            check_expression(&op.left(), Some(op_size));
            check_expression(&op.right(), None);
        }

        MulsDp(ref op) |
        MuluDp(ref op) => {
            let op_size = op.size();

            if let Some(required_size) = required_size {
                if required_size != op_size * 2 {
                    error!("LLIL double precision mul op producing {} byte value where {} byte value is expected! (addr: {:x} {:?})",
                           op_size, required_size, op.address(), expr);
                }
            }

            check_expression(&op.left(), Some(op_size));
            check_expression(&op.right(), Some(op_size));
        }

        DivuDp(ref op) |
        DivsDp(ref op) |
        ModuDp(ref op) |
        ModsDp(ref op) => {
            let op_size = op.size();

            if let Some(required_size) = required_size {
                if required_size != op_size {
                    error!("LLIL double precision div op producing {} byte value where {} byte value is expected! (addr: {:x} {:?})",
                           op_size, required_size, op.address(), expr);
                }
            }

            // TODO what's the actual right size here?
            check_expression(&op.high(), Some(op_size));
            check_expression(&op.low(), Some(op_size));
            check_expression(&op.right(), Some(op_size));
        }

        Neg(ref op) |
        Not(ref op) => {
            let op_size = op.size();

            if let Some(required_size) = required_size {
                if required_size != op_size {
                    error!("LLIL unary op producing {} byte value where {} byte value is expected! (addr: {:x} {:?})",
                           op_size, required_size, op.address(), expr);
                }
            }

            check_expression(&op.operand(), Some(op_size));
        }

        Sx(ref op) |
        Zx(ref op) => {
            let op_size = op.size();

            if let Some(required_size) = required_size {
                if required_size != op_size {
                    error!("LLIL extending op producing {} byte value where {} byte value is expected! (addr: {:x} {:?})",
                           op_size, required_size, op.address(), expr);
                }
            }

            let operand = op.operand();

            if let Some(actual_size) = operand.kind().size() {
                if actual_size >= op_size {
                    error!("LLIL extending op to {} bytes is invalid; source is already {} bytes (addr: {:x} {:?})",
                           op_size, actual_size, op.address(), expr);
                }
            }

            check_expression(&operand, None);
        }

        LowPart(ref op) => {
            let op_size = op.size();

            if let Some(required_size) = required_size {
                if required_size != op_size {
                    error!("LLIL_LOW_PART truncating to {} byte value where {} byte value is expected! (addr: {:x} {:?})",
                           op_size, required_size, op.address(), expr);
                }
            }

            let operand = op.operand();

            if let Some(actual_size) = operand.kind().size() {
                if actual_size <= op_size {
                    error!("LLIL truncating op to {} bytes is invalid; source is already {} bytes (addr: {:x} {:?})",
                           op_size, actual_size, op.address(), expr);
                }
            }

            check_expression(&operand, None);
        }

        BoolToInt(ref op) => {
            let op_size = op.size();

            if let Some(required_size) = required_size {
                if required_size != op_size {
                    error!("LLIL_BOOL_TO_INT extending to {} byte value where {} byte value is expected! (addr: {:x} {:?})",
                           op_size, required_size, op.address(), expr);
                }
            }

            check_expression(&op.operand(), Some(0));
        }

        UnimplMem(ref op) => {
            let op_size = op.size();

            if let Some(required_size) = required_size {
                if required_size != op_size {
                    error!("LLIL_UNIMPL_MEM producing {} byte value where {} byte value is expected! (addr: {:x} {:?})",
                           op_size, required_size, op.address(), expr);
                }
            }

            check_expression(&op.mem_expr(), None);
        }

        Unimpl(_) => {}

        op => {
            info!("   unhandled expr @ {:x} ... {:?}", op.address(), expr);
        }
    }
}

fn check_instruction(inst: &LowLevelILInstruction<Mutable, NonSSA>) {
    match inst.kind() {
        SetReg(op) => {
            let required_expr_size = op.size();

            // TODO how to do sanity checking for temp registers?
            if let LowLevelILRegisterKind::Arch(r) = op.dest_reg() {
                let reg_size = r.info().size();

                if reg_size != required_expr_size {
                    error!("LLIL_SET_REG can't set {} byte register to {} byte value! (addr: {:x})",
                           reg_size, required_expr_size, op.address());
                }
            }

            check_expression(&op.source_expr(), Some(required_expr_size));
        }
        SetRegSplit(op) => {
            let required_reg_size = op.size();

            if let LowLevelILRegisterKind::Arch(hi) = op.dest_reg_high() {
                if hi.info().size() != required_reg_size {
                    error!("LLIL_SET_REG_SPLIT received a register with wrong size (wanted {} bytes)! (addr: {:x})",
                           required_reg_size, op.address());
                }
            }

            if let LowLevelILRegisterKind::Arch(lo) = op.dest_reg_low() {
                if lo.info().size() != required_reg_size {
                    error!("LLIL_SET_REG_SPLIT received a register with wrong size (wanted {} bytes)! (addr: {:x})",
                           required_reg_size, op.address());
                }
            }

            check_expression(&op.source_expr(), Some(required_reg_size * 2));
        }
        SetFlag(op) => {
            check_expression(&op.source_expr(), Some(0));
        }
        Store(op) => {
            let required_expr_size = op.size();

            if required_expr_size == 0 {
                error!("LLIL_STORE storing a 0 byte value! non-sensical! (addr {:x})", op.address());
            }

            // TODO make sure size matches arch default addr len?
            check_expression(&op.dest_expr(), None);
            check_expression(&op.source_expr(), Some(required_expr_size));
        }
        Push(op) => {
            let required_expr_size = op.size();

            if required_expr_size == 0 {
                error!("LLIL_PUSH pushing a 0 byte value! non-sensical! (addr {:x})", op.address());
            }

            check_expression(&op.operand(), Some(required_expr_size));
        }
        Jump(op) => {
            check_expression(&op.target(), None);
        }
        JumpTo(op) => {
            check_expression(&op.target(), None);
        }
        Call(op) => {
            check_expression(&op.target(), None);
        }
        Ret(op) => {
            check_expression(&op.target(), None);
        }
        If(op) => {
            check_expression(&op.condition(), Some(0));
        }
        Value(e) => {
            check_expression(&e, None);
        }
        _ => {},
    }
}

fn insert_workflow() {
    let check_activity_fn = |ctx: &AnalysisContext| {
        if let Some(il) = unsafe { ctx.llil_function() } {
            for block in &il.basic_blocks() {
                for instr in &*block {
                    check_instruction(&instr);
                }
            }
        }
    };

    let old_function_meta_workflow = Workflow::instance("core.function.metaAnalysis");
    let function_meta_workflow = old_function_meta_workflow.clone_to("core.function.metaAnalysis");
    let check_activity = Activity::new_with_action(LIFT_CHECK_ACTIVITY_CONFIG, check_activity_fn);
    function_meta_workflow
        .register_activity(&check_activity)
        .unwrap();
    function_meta_workflow.insert("core.function.generateMediumLevelIL", [LIFT_CHECK_ACTIVITY_NAME]);
    function_meta_workflow.register().unwrap();
}


#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginInit() -> bool {
    Logger::new("LiftCheck").with_level(LevelFilter::Debug).init();

    insert_workflow();

    true
}
