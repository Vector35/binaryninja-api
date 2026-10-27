use binaryninja::architecture::*;
use binaryninja::disassembly::InstructionTextToken;
use binaryninja::headless::Session;
use binaryninja::low_level_il::expression::{
    ExpressionHandler, LowLevelILExpressionKind, ValueExpr,
};
use binaryninja::low_level_il::lifting::LowLevelILFlagWriteOp;
use binaryninja::low_level_il::{LowLevelILMutableExpression, LowLevelILMutableFunction};
use binaryninja::Endianness;
use binaryninjacore_sys::*;
use std::sync::Mutex;

#[derive(Debug, PartialEq)]
struct CapturedOperation {
    operation: BNLowLevelILOperation,
    size: usize,
    operands: Vec<(bool, u32, u64)>,
}

impl CapturedOperation {
    fn new(
        operation: BNLowLevelILOperation,
        size: usize,
        operands: &[BNRegisterOrConstant],
    ) -> Self {
        Self {
            operation,
            size,
            operands: operands
                .iter()
                .map(|op| (op.constant, op.reg, op.value))
                .collect(),
        }
    }

    fn decode(op: LowLevelILFlagWriteOp<CoreRegister>) -> (bool, Option<Self>) {
        macro_rules! capture {
            ($($variant:ident => $operation:ident ($($operand:ident),*);)*) => {
                match op {
                    $(LowLevelILFlagWriteOp::$variant(size, $($operand),*) => (true, Some(Self::new(
                        BNLowLevelILOperation::$operation,
                        size,
                        &[$($operand.into()),*],
                    ))),)*
                    LowLevelILFlagWriteOp::Raw { operation, size, operands } => {
                        (false, Some(Self::new(operation, size, &operands)))
                    }
                    _ => (false, None),
                }
            };
        }
        capture! {
            Pop => LLIL_POP();
            Fsqrt => LLIL_FSQRT(value);
            Fneg => LLIL_FNEG(value);
            Fabs => LLIL_FABS(value);
            FloatToInt => LLIL_FLOAT_TO_INT(value);
            IntToFloat => LLIL_INT_TO_FLOAT(value);
            FloatConv => LLIL_FLOAT_CONV(value);
            RoundToInt => LLIL_ROUND_TO_INT(value);
            Floor => LLIL_FLOOR(value);
            Ceil => LLIL_CEIL(value);
            Ftrunc => LLIL_FTRUNC(value);
            Fadd => LLIL_FADD(left, right);
            Fsub => LLIL_FSUB(left, right);
            Fmul => LLIL_FMUL(left, right);
            Fdiv => LLIL_FDIV(left, right);
            CmpE => LLIL_CMP_E(left, right);
            CmpNe => LLIL_CMP_NE(left, right);
            CmpSlt => LLIL_CMP_SLT(left, right);
            CmpUlt => LLIL_CMP_ULT(left, right);
            CmpSle => LLIL_CMP_SLE(left, right);
            CmpUle => LLIL_CMP_ULE(left, right);
            CmpSge => LLIL_CMP_SGE(left, right);
            CmpUge => LLIL_CMP_UGE(left, right);
            CmpSgt => LLIL_CMP_SGT(left, right);
            CmpUgt => LLIL_CMP_UGT(left, right);
            FcmpE => LLIL_FCMP_E(left, right);
            FcmpNe => LLIL_FCMP_NE(left, right);
            FcmpLt => LLIL_FCMP_LT(left, right);
            FcmpLe => LLIL_FCMP_LE(left, right);
            FcmpGe => LLIL_FCMP_GE(left, right);
            FcmpGt => LLIL_FCMP_GT(left, right);
            FcmpO => LLIL_FCMP_O(left, right);
            FcmpUo => LLIL_FCMP_UO(left, right);
            Add => LLIL_ADD(left, right);
            Sub => LLIL_SUB(left, right);
            MuluDp => LLIL_MULU_DP(left, right);
            DivsDp => LLIL_DIVS_DP(left, right);
            Adc => LLIL_ADC(left, right, carry);
            Sbb => LLIL_SBB(left, right, carry);
            Rlc => LLIL_RLC(left, right, carry);
            Rrc => LLIL_RRC(left, right, carry);
        }
    }
}

struct FlagArchitecture {
    handle: CustomArchitectureHandle<Self>,
    core: CoreArchitecture,
    base: CoreArchitecture,
    registers: Vec<CoreRegister>,
    calls: Mutex<Vec<(bool, Option<CapturedOperation>)>>,
}

impl AsRef<CoreArchitecture> for FlagArchitecture {
    fn as_ref(&self) -> &CoreArchitecture {
        &self.core
    }
}

impl Architecture for FlagArchitecture {
    type Handle = CustomArchitectureHandle<Self>;
    type RegisterInfo = CoreRegisterInfo;
    type Register = CoreRegister;
    type RegisterStackInfo = UnusedRegisterStack<CoreRegister>;
    type RegisterStack = UnusedRegisterStack<CoreRegister>;
    type Flag = CoreFlag;
    type FlagWrite = CoreFlagWrite;
    type FlagClass = CoreFlagClass;
    type FlagGroup = CoreFlagGroup;
    type Intrinsic = UnusedIntrinsic;

    fn endianness(&self) -> Endianness {
        Endianness::LittleEndian
    }
    fn address_size(&self) -> usize {
        8
    }
    fn default_integer_size(&self) -> usize {
        8
    }
    fn instruction_alignment(&self) -> usize {
        1
    }
    fn max_instr_len(&self) -> usize {
        1
    }
    fn handle(&self) -> Self::Handle {
        self.handle
    }

    fn instruction_info(&self, _data: &[u8], _addr: u64) -> Option<InstructionInfo> {
        None
    }
    fn instruction_text(
        &self,
        _data: &[u8],
        _addr: u64,
    ) -> Option<(usize, Vec<InstructionTextToken>)> {
        None
    }
    fn instruction_llil(
        &self,
        _data: &[u8],
        _addr: u64,
        _il: &LowLevelILMutableFunction,
    ) -> Option<(usize, bool)> {
        None
    }
    fn registers_all(&self) -> Vec<CoreRegister> {
        self.registers.clone()
    }
    fn registers_full_width(&self) -> Vec<CoreRegister> {
        self.base.registers_full_width()
    }
    fn register_from_id(&self, id: RegisterId) -> Option<CoreRegister> {
        self.registers.iter().copied().find(|reg| reg.id() == id)
    }
    fn stack_pointer_reg(&self) -> Option<CoreRegister> {
        None
    }

    fn flags(&self) -> Vec<CoreFlag> {
        self.base.flags()
    }
    fn flag_from_id(&self, id: FlagId) -> Option<CoreFlag> {
        self.base.flag_from_id(id)
    }
    fn flag_write_types(&self) -> Vec<CoreFlagWrite> {
        self.base.flag_write_types()
    }
    fn flag_write_from_id(&self, id: FlagWriteId) -> Option<CoreFlagWrite> {
        self.base.flag_write_from_id(id)
    }

    fn flag_write_llil<'a>(
        &self,
        _flag: CoreFlag,
        _write: CoreFlagWrite,
        op: LowLevelILFlagWriteOp<CoreRegister>,
        il: &'a LowLevelILMutableFunction,
    ) -> Option<LowLevelILMutableExpression<'a, ValueExpr>> {
        self.calls
            .lock()
            .unwrap()
            .push(CapturedOperation::decode(op));
        Some(il.const_int(0, 1))
    }
}

struct PassThroughHook;
impl ArchitectureHook for PassThroughHook {}

#[derive(Default)]
struct OverrideHook {
    calls: Mutex<Vec<(bool, Option<CapturedOperation>)>>,
}

impl ArchitectureHook for OverrideHook {
    fn flag_write_llil<'a>(
        &self,
        _base: &CoreArchitecture,
        _flag: CoreFlag,
        _write: CoreFlagWrite,
        op: LowLevelILFlagWriteOp<CoreRegister>,
        il: &'a LowLevelILMutableFunction,
    ) -> Option<LowLevelILMutableExpression<'a, ValueExpr>> {
        self.calls
            .lock()
            .unwrap()
            .push(CapturedOperation::decode(op));
        Some(il.const_int(0, 0))
    }
}

fn invoke_flag_write(
    arch: CoreArchitecture,
    write: CoreFlagWrite,
    flag: CoreFlag,
    operation: BNLowLevelILOperation,
    size: usize,
    operands: &[BNRegisterOrConstant],
) -> u64 {
    let il = LowLevelILMutableFunction::new(arch, None);
    let result = arch
        .flag_write_llil(
            flag,
            write,
            LowLevelILFlagWriteOp::Raw {
                operation,
                size,
                operands: operands.to_vec(),
            },
            &il,
        )
        .unwrap();
    match result.kind() {
        LowLevelILExpressionKind::Const(value) => value.value(),
        other => panic!("Expected a constant flag value, got {other:?}"),
    }
}

fn check_flag_write_op_round_trip(arch: &FlagArchitecture, write: CoreFlagWrite, flag: CoreFlag) {
    use BNLowLevelILOperation::*;
    let reg = arch
        .base
        .registers_all()
        .into_iter()
        .find(|r| r.name() == "rax")
        .unwrap();
    let operands = [
        BNRegisterOrConstant {
            constant: true,
            reg: 0,
            value: 0x7ff8_0000_0000_1234,
        },
        BNRegisterOrConstant {
            constant: false,
            reg: reg.id().0,
            value: 0,
        },
        BNRegisterOrConstant {
            constant: false,
            reg: 0x8000_0007,
            value: 0,
        },
    ];
    let unary = [
        LLIL_FSQRT,
        LLIL_FNEG,
        LLIL_FABS,
        LLIL_FLOAT_TO_INT,
        LLIL_INT_TO_FLOAT,
        LLIL_FLOAT_CONV,
        LLIL_ROUND_TO_INT,
        LLIL_FLOOR,
        LLIL_CEIL,
        LLIL_FTRUNC,
    ];
    let binary = [
        LLIL_FADD,
        LLIL_FSUB,
        LLIL_FMUL,
        LLIL_FDIV,
        LLIL_CMP_E,
        LLIL_CMP_NE,
        LLIL_CMP_SLT,
        LLIL_CMP_ULT,
        LLIL_CMP_SLE,
        LLIL_CMP_ULE,
        LLIL_CMP_SGE,
        LLIL_CMP_UGE,
        LLIL_CMP_SGT,
        LLIL_CMP_UGT,
        LLIL_FCMP_E,
        LLIL_FCMP_NE,
        LLIL_FCMP_LT,
        LLIL_FCMP_LE,
        LLIL_FCMP_GE,
        LLIL_FCMP_GT,
        LLIL_FCMP_O,
        LLIL_FCMP_UO,
        LLIL_ADD,
        LLIL_SUB,
        LLIL_MULU_DP,
        LLIL_DIVS_DP,
    ];
    let ternary = [LLIL_ADC, LLIL_SBB, LLIL_RLC, LLIL_RRC];

    for (count, operations) in [
        (0, &[LLIL_POP][..]),
        (1, &unary),
        (2, &binary),
        (3, &ternary),
    ] {
        for &operation in operations {
            for size in [1, 4, 8, 16] {
                // Rotate through constants, architecture registers, and temporary registers.
                for offset in 0..operands.len() {
                    let input: Vec<_> = operands
                        .iter()
                        .copied()
                        .cycle()
                        .skip(offset)
                        .take(count)
                        .collect();
                    assert_eq!(
                        invoke_flag_write(arch.core, write, flag, operation, size, &input),
                        1
                    );
                    let (typed, captured) = arch.calls.lock().unwrap().pop().unwrap();
                    assert!(typed, "{operation:?}");
                    assert_eq!(
                        captured,
                        Some(CapturedOperation::new(operation, size, &input)),
                        "{operation:?}"
                    );
                }
            }
        }
    }

    // Intrinsics have a variable number of arguments; unexpected shapes must also survive.
    let input: Vec<_> = operands.iter().copied().cycle().take(9).collect();
    for (operation, input) in [(LLIL_INTRINSIC, input.as_slice()), (LLIL_FSUB, &input[..1])] {
        assert_eq!(
            invoke_flag_write(arch.core, write, flag, operation, 8, input),
            1
        );
        let (typed, captured) = arch.calls.lock().unwrap().pop().unwrap();
        assert!(!typed, "{operation:?}");
        assert_eq!(captured, Some(CapturedOperation::new(operation, 8, input)));
    }
}

#[test]
fn test_flag_write_dispatch_and_forwarding() {
    use BNLowLevelILOperation::*;
    let _session = Session::new().expect("Failed to initialize session");
    let base = CoreArchitecture::by_name("x86_64").unwrap();
    let arch = register_architecture("rust_flag_write_operations", |handle, core| {
        FlagArchitecture {
            handle,
            core,
            base,
            registers: base.registers_all(),
            calls: Mutex::new(Vec::new()),
        }
    });
    let write = base
        .flag_write_types()
        .into_iter()
        .find(|w| w.name() == "vcomi")
        .unwrap();
    let flag = base.flags().into_iter().find(|f| f.name() == "s").unwrap();
    let constant = BNRegisterOrConstant {
        constant: true,
        reg: 0,
        value: 1.25f64.to_bits(),
    };
    let temporary = BNRegisterOrConstant {
        constant: false,
        reg: 0x8000_0007,
        value: 0,
    };
    let cases = [
        (LLIL_FSUB, 8, vec![constant, temporary]),
        // Intrinsic flag writes start with the intrinsic ID and can have more than five operands.
        (LLIL_INTRINSIC, 0, vec![constant; 9]),
        (LLIL_POP, 4, vec![]),
        // An unexpected operand count and an unresolved register are exposed through Raw.
        (LLIL_FSUB, 8, vec![constant]),
        (
            LLIL_FSUB,
            8,
            vec![
                constant,
                BNRegisterOrConstant {
                    constant: false,
                    reg: 12345,
                    value: 0,
                },
            ],
        ),
    ];

    // Ordinary architectures and stacked hooks must receive the same argument values.
    for hooked in [false, true] {
        if hooked {
            register_architecture_hook(arch.core, PassThroughHook);
            register_architecture_hook(arch.core, PassThroughHook);
        }
        check_flag_write_op_round_trip(arch, write, flag);
        for (operation, size, operands) in &cases {
            assert_eq!(
                invoke_flag_write(arch.core, write, flag, *operation, *size, operands),
                1
            );
            let (_, captured) = arch.calls.lock().unwrap().pop().unwrap();
            assert_eq!(
                captured,
                Some(CapturedOperation::new(*operation, *size, operands))
            );
        }
    }

    let hook = register_architecture_hook(arch.core, OverrideHook::default());
    // Another default hook must preserve the override as well as all arguments.
    register_architecture_hook(arch.core, PassThroughHook);
    for (operation, size, operands) in &cases {
        assert_eq!(
            invoke_flag_write(arch.core, write, flag, *operation, *size, operands),
            0
        );
        let (_, captured) = hook.calls.lock().unwrap().pop().unwrap();
        assert_eq!(
            captured,
            Some(CapturedOperation::new(*operation, *size, operands))
        );
        assert!(arch.calls.lock().unwrap().is_empty());
    }
}
