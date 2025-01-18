use crate::flag::{Flag, FlagClass, FlagGroup, FlagWrite};
use crate::lift::lift_instruction;
use crate::register::Register;

use binaryninja::{
    architecture::{
        Architecture, CoreArchitecture, CustomArchitectureHandle, FlagCondition, InstructionInfo,
        UnusedIntrinsic, UnusedRegisterStack, UnusedRegisterStackInfo,
    },
    disassembly::{InstructionTextToken, InstructionTextTokenKind},
    Endianness,
};

use msp430_asm::{
    emulate::Emulated, instruction::Instruction, jxx::Jxx, operand::Operand,
    single_operand::SingleOperand, two_operand::TwoOperand,
};

use binaryninja::architecture::{
    BranchKind, FlagClassId, FlagGroupId, FlagId, FlagWriteId, RegisterId,
};
use binaryninja::low_level_il::expression::ValueExpr;
use binaryninja::low_level_il::{MutableLiftedILExpr, MutableLiftedILFunction};
use log::error;

const MIN_MNEMONIC: usize = 9;

pub struct Msp430 {
    handle: CoreArchitecture,
    custom_handle: CustomArchitectureHandle<Msp430>,
}

impl Msp430 {
    pub fn new(handle: CoreArchitecture, custom_handle: CustomArchitectureHandle<Msp430>) -> Self {
        Msp430 {
            handle,
            custom_handle,
        }
    }
}

impl Architecture for Msp430 {
    type Handle = CustomArchitectureHandle<Self>;
    type RegisterStackInfo = UnusedRegisterStackInfo<Self::Register>;
    type RegisterStack = UnusedRegisterStack<Self::Register>;
    type Register = Register;
    type RegisterInfo = Register;
    type Flag = Flag;
    type FlagWrite = FlagWrite;
    type FlagClass = FlagClass;
    type FlagGroup = FlagGroup;
    type Intrinsic = UnusedIntrinsic;

    fn endianness(&self) -> Endianness {
        Endianness::LittleEndian
    }

    fn address_size(&self) -> usize {
        2 // 16 bit
    }

    fn default_integer_size(&self) -> usize {
        2 // 16 bit integers
    }

    fn instruction_alignment(&self) -> usize {
        2
    }

    fn max_instr_len(&self) -> usize {
        6
    }

    fn opcode_display_len(&self) -> usize {
        self.max_instr_len()
    }

    fn associated_arch_by_addr(&self, _addr: u64) -> CoreArchitecture {
        self.handle
    }

    fn instruction_info(&self, data: &[u8], addr: u64) -> Option<InstructionInfo> {
        match msp430_asm::decode(data) {
            Ok(inst) => {
                let mut info = InstructionInfo::new(inst.size(), 0);

                match inst {
                    Instruction::Jnz(inst) => {
                        info.add_branch(BranchKind::True(offset_to_absolute(addr, inst.offset())));
                        info.add_branch(BranchKind::False(addr + inst.size() as u64));
                    }
                    Instruction::Jz(inst) => {
                        info.add_branch(BranchKind::True(offset_to_absolute(addr, inst.offset())));
                        info.add_branch(BranchKind::False(addr + inst.size() as u64));
                    }
                    Instruction::Jlo(inst) => {
                        info.add_branch(BranchKind::True(offset_to_absolute(addr, inst.offset())));
                        info.add_branch(BranchKind::False(addr + inst.size() as u64));
                    }
                    Instruction::Jc(inst) => {
                        info.add_branch(BranchKind::True(offset_to_absolute(addr, inst.offset())));
                        info.add_branch(BranchKind::False(addr + inst.size() as u64));
                    }
                    Instruction::Jn(inst) => {
                        info.add_branch(BranchKind::True(offset_to_absolute(addr, inst.offset())));
                        info.add_branch(BranchKind::False(addr + inst.size() as u64));
                    }
                    Instruction::Jge(inst) => {
                        info.add_branch(BranchKind::True(offset_to_absolute(addr, inst.offset())));
                        info.add_branch(BranchKind::False(addr + inst.size() as u64));
                    }
                    Instruction::Jl(inst) => {
                        info.add_branch(BranchKind::True(offset_to_absolute(addr, inst.offset())));
                        info.add_branch(BranchKind::False(addr + inst.size() as u64));
                    }
                    Instruction::Jmp(inst) => {
                        info.add_branch(BranchKind::Unconditional(offset_to_absolute(
                            addr,
                            inst.offset(),
                        )));
                    }
                    Instruction::Br(inst) => match inst.destination() {
                        Some(Operand::RegisterDirect(_)) => info.add_branch(BranchKind::Indirect),
                        Some(Operand::Indexed(_)) => info.add_branch(BranchKind::Indirect),
                        Some(Operand::Absolute(value)) => {
                            info.add_branch(BranchKind::Unconditional(*value as u64))
                        }
                        Some(Operand::Symbolic(offset)) => info.add_branch(
                            BranchKind::Unconditional((addr as i64 + *offset as i64) as u64),
                        ),
                        Some(Operand::Immediate(addr)) => {
                            info.add_branch(BranchKind::Unconditional(*addr as u64))
                        }
                        Some(Operand::Constant(_)) => {
                            info.add_branch(BranchKind::Unconditional(addr))
                        }
                        Some(Operand::RegisterIndirect(_))
                        | Some(Operand::RegisterIndirectAutoIncrement(_)) => {
                            info.add_branch(BranchKind::Indirect)
                        }
                        None => {}
                    },
                    Instruction::Call(inst) => match inst.source() {
                        Operand::RegisterDirect(_) => info.add_branch(BranchKind::Indirect),
                        Operand::Indexed(_) => info.add_branch(BranchKind::Indirect),
                        Operand::Absolute(value) => {
                            info.add_branch(BranchKind::Call(*value as u64))
                        }
                        Operand::Symbolic(offset) => {
                            info.add_branch(BranchKind::Call((addr as i64 + *offset as i64) as u64))
                        }
                        Operand::Immediate(addr) => info.add_branch(BranchKind::Call(*addr as u64)),
                        Operand::Constant(_) => info.add_branch(BranchKind::Call(addr)),
                        Operand::RegisterIndirect(_)
                        | Operand::RegisterIndirectAutoIncrement(_) => {
                            info.add_branch(BranchKind::Indirect)
                        }
                    },
                    Instruction::Reti(_) => {
                        info.add_branch(BranchKind::FunctionReturn);
                    }
                    Instruction::Ret(_) => {
                        info.add_branch(BranchKind::FunctionReturn);
                    }
                    _ => {}
                }

                Some(info)
            }
            Err(_) => None,
        }
    }

    fn instruction_text(
        &self,
        data: &[u8],
        addr: u64,
    ) -> Option<(usize, Vec<InstructionTextToken>)> {
        match msp430_asm::decode(data) {
            Ok(inst) => {
                let tokens = generate_tokens(&inst, addr);
                if tokens.is_empty() {
                    None
                } else {
                    Some((inst.size(), tokens))
                }
            }
            Err(_) => None,
        }
    }

    fn instruction_llil(
        &self,
        data: &[u8],
        addr: u64,
        il: &mut MutableLiftedILFunction<Self>,
    ) -> Option<(usize, bool)> {
        match msp430_asm::decode(data) {
            Ok(inst) => {
                lift_instruction(&inst, addr, il);
                Some((inst.size(), true))
            }
            Err(_) => None,
        }
    }

    fn flags_required_for_flag_condition(
        &self,
        condition: FlagCondition,
        _class: Option<Self::FlagClass>,
    ) -> Vec<Self::Flag> {
        match condition {
            FlagCondition::LLFC_UGE => vec![Flag::C],
            FlagCondition::LLFC_ULT => vec![Flag::C],
            FlagCondition::LLFC_SGE => vec![Flag::N, Flag::V],
            FlagCondition::LLFC_SLT => vec![Flag::N, Flag::V],
            FlagCondition::LLFC_E => vec![Flag::Z],
            FlagCondition::LLFC_NE => vec![Flag::Z],
            FlagCondition::LLFC_NEG => vec![Flag::N],
            FlagCondition::LLFC_POS => vec![Flag::N],
            _ => vec![],
        }
    }

    fn flag_group_llil<'a>(
        &self,
        _group: Self::FlagGroup,
        _il: &'a mut MutableLiftedILFunction<Self>,
    ) -> Option<MutableLiftedILExpr<'a, Self, ValueExpr>> {
        None
    }

    fn registers_all(&self) -> Vec<Self::Register> {
        vec![
            Register::Pc,
            Register::Sp,
            Register::Sr,
            Register::Cg,
            Register::R4,
            Register::R5,
            Register::R6,
            Register::R7,
            Register::R8,
            Register::R9,
            Register::R10,
            Register::R11,
            Register::R12,
            Register::R13,
            Register::R14,
            Register::R15,
        ]
    }

    fn registers_full_width(&self) -> Vec<Self::Register> {
        vec![
            Register::Pc,
            Register::Sp,
            Register::Sr,
            Register::Cg,
            Register::R4,
            Register::R5,
            Register::R6,
            Register::R7,
            Register::R8,
            Register::R9,
            Register::R10,
            Register::R11,
            Register::R12,
            Register::R13,
            Register::R14,
            Register::R15,
        ]
    }

    fn registers_global(&self) -> Vec<Self::Register> {
        Vec::new()
    }

    fn registers_system(&self) -> Vec<Self::Register> {
        Vec::new()
    }

    fn flags(&self) -> Vec<Self::Flag> {
        vec![Flag::C, Flag::Z, Flag::N, Flag::V]
    }

    fn flag_write_types(&self) -> Vec<Self::FlagWrite> {
        vec![
            FlagWrite::All,
            FlagWrite::Nz,
            FlagWrite::Nvz,
            FlagWrite::Cnz,
        ]
    }

    fn flag_classes(&self) -> Vec<Self::FlagClass> {
        Vec::new()
    }

    fn flag_groups(&self) -> Vec<Self::FlagGroup> {
        Vec::new()
    }

    fn stack_pointer_reg(&self) -> Option<Self::Register> {
        Some(Register::Sp)
    }

    fn link_reg(&self) -> Option<Self::Register> {
        None
    }

    fn register_from_id(&self, id: RegisterId) -> Option<Self::Register> {
        match id.try_into() {
            Ok(register) => Some(register),
            Err(_) => None,
        }
    }

    fn flag_from_id(&self, id: FlagId) -> Option<Self::Flag> {
        match id.try_into() {
            Ok(flag) => Some(flag),
            Err(_) => {
                error!("invalid flag id {}", id);
                None
            }
        }
    }

    fn flag_write_from_id(&self, id: FlagWriteId) -> Option<Self::FlagWrite> {
        match id.try_into() {
            Ok(flag_write) => Some(flag_write),
            Err(_) => {
                error!("invalid flag write id {}", id);
                None
            }
        }
    }

    fn flag_class_from_id(&self, _: FlagClassId) -> Option<Self::FlagClass> {
        None
    }

    fn flag_group_from_id(&self, _: FlagGroupId) -> Option<Self::FlagGroup> {
        None
    }

    fn handle(&self) -> Self::Handle {
        self.custom_handle
    }
}

impl AsRef<CoreArchitecture> for Msp430 {
    fn as_ref(&self) -> &CoreArchitecture {
        &self.handle
    }
}

fn generate_tokens(inst: &Instruction, addr: u64) -> Vec<InstructionTextToken> {
    match inst {
        Instruction::Rrc(inst) => generate_single_operand_tokens(inst, addr, false),
        Instruction::Swpb(inst) => generate_single_operand_tokens(inst, addr, false),
        Instruction::Rra(inst) => generate_single_operand_tokens(inst, addr, false),
        Instruction::Sxt(inst) => generate_single_operand_tokens(inst, addr, false),
        Instruction::Push(inst) => generate_single_operand_tokens(inst, addr, false),
        Instruction::Call(inst) => generate_single_operand_tokens(inst, addr, true),
        Instruction::Reti(_) => vec![InstructionTextToken::new(
            "reti",
            InstructionTextTokenKind::Instruction,
        )],

        // Jxx instructions
        Instruction::Jnz(inst) => generate_jxx_tokens(inst, addr),
        Instruction::Jz(inst) => generate_jxx_tokens(inst, addr),
        Instruction::Jlo(inst) => generate_jxx_tokens(inst, addr),
        Instruction::Jc(inst) => generate_jxx_tokens(inst, addr),
        Instruction::Jn(inst) => generate_jxx_tokens(inst, addr),
        Instruction::Jge(inst) => generate_jxx_tokens(inst, addr),
        Instruction::Jl(inst) => generate_jxx_tokens(inst, addr),
        Instruction::Jmp(inst) => generate_jxx_tokens(inst, addr),

        // two operand instructions
        Instruction::Mov(inst) => generate_two_operand_tokens(inst, addr),
        Instruction::Add(inst) => generate_two_operand_tokens(inst, addr),
        Instruction::Addc(inst) => generate_two_operand_tokens(inst, addr),
        Instruction::Subc(inst) => generate_two_operand_tokens(inst, addr),
        Instruction::Sub(inst) => generate_two_operand_tokens(inst, addr),
        Instruction::Cmp(inst) => generate_two_operand_tokens(inst, addr),
        Instruction::Dadd(inst) => generate_two_operand_tokens(inst, addr),
        Instruction::Bit(inst) => generate_two_operand_tokens(inst, addr),
        Instruction::Bic(inst) => generate_two_operand_tokens(inst, addr),
        Instruction::Bis(inst) => generate_two_operand_tokens(inst, addr),
        Instruction::Xor(inst) => generate_two_operand_tokens(inst, addr),
        Instruction::And(inst) => generate_two_operand_tokens(inst, addr),

        // emulated
        Instruction::Adc(inst) => generate_emulated_tokens(inst, addr, false),
        Instruction::Br(inst) => generate_emulated_tokens(inst, addr, true),
        Instruction::Clr(inst) => generate_emulated_tokens(inst, addr, false),
        Instruction::Clrc(inst) => generate_emulated_tokens(inst, addr, false),
        Instruction::Clrn(inst) => generate_emulated_tokens(inst, addr, false),
        Instruction::Clrz(inst) => generate_emulated_tokens(inst, addr, false),
        Instruction::Dadc(inst) => generate_emulated_tokens(inst, addr, false),
        Instruction::Dec(inst) => generate_emulated_tokens(inst, addr, false),
        Instruction::Decd(inst) => generate_emulated_tokens(inst, addr, false),
        Instruction::Dint(inst) => generate_emulated_tokens(inst, addr, false),
        Instruction::Eint(inst) => generate_emulated_tokens(inst, addr, false),
        Instruction::Inc(inst) => generate_emulated_tokens(inst, addr, false),
        Instruction::Incd(inst) => generate_emulated_tokens(inst, addr, false),
        Instruction::Inv(inst) => generate_emulated_tokens(inst, addr, false),
        Instruction::Nop(inst) => generate_emulated_tokens(inst, addr, false),
        Instruction::Pop(inst) => generate_emulated_tokens(inst, addr, false),
        Instruction::Ret(inst) => generate_emulated_tokens(inst, addr, false),
        Instruction::Rla(inst) => generate_emulated_tokens(inst, addr, false),
        Instruction::Rlc(inst) => generate_emulated_tokens(inst, addr, false),
        Instruction::Sbc(inst) => generate_emulated_tokens(inst, addr, false),
        Instruction::Setc(inst) => generate_emulated_tokens(inst, addr, false),
        Instruction::Setn(inst) => generate_emulated_tokens(inst, addr, false),
        Instruction::Setz(inst) => generate_emulated_tokens(inst, addr, false),
        Instruction::Tst(inst) => generate_emulated_tokens(inst, addr, false),
    }
}

fn generate_single_operand_tokens(
    inst: &impl SingleOperand,
    addr: u64,
    call: bool,
) -> Vec<InstructionTextToken> {
    let mut res = vec![InstructionTextToken::new(
        inst.mnemonic(),
        InstructionTextTokenKind::Instruction,
    )];

    if inst.mnemonic().len() < MIN_MNEMONIC {
        let padding = " ".repeat(MIN_MNEMONIC - inst.mnemonic().len());
        res.push(InstructionTextToken::new(
            padding,
            InstructionTextTokenKind::Text,
        ))
    }

    res.extend_from_slice(&generate_operand_tokens(inst.source(), addr, call));

    res
}

fn generate_jxx_tokens(inst: &impl Jxx, addr: u64) -> Vec<InstructionTextToken> {
    let fixed_addr = offset_to_absolute(addr, inst.offset());

    let mut res = vec![InstructionTextToken::new(
        inst.mnemonic(),
        InstructionTextTokenKind::Instruction,
    )];

    if inst.mnemonic().len() < MIN_MNEMONIC {
        let padding = " ".repeat(MIN_MNEMONIC - inst.mnemonic().len());
        res.push(InstructionTextToken::new(
            padding,
            InstructionTextTokenKind::Text,
        ))
    }

    res.push(InstructionTextToken::new(
        format!("0x{fixed_addr:4x}"),
        InstructionTextTokenKind::CodeRelativeAddress {
            value: fixed_addr,
            size: None,
        },
    ));

    res
}

fn generate_two_operand_tokens(inst: &impl TwoOperand, addr: u64) -> Vec<InstructionTextToken> {
    let mut res = vec![InstructionTextToken::new(
        inst.mnemonic(),
        InstructionTextTokenKind::Instruction,
    )];

    if inst.mnemonic().len() < MIN_MNEMONIC {
        let padding = " ".repeat(MIN_MNEMONIC - inst.mnemonic().len());
        res.push(InstructionTextToken::new(
            padding,
            InstructionTextTokenKind::Text,
        ))
    }

    res.extend_from_slice(&generate_operand_tokens(inst.source(), addr, false));
    res.push(InstructionTextToken::new(
        ", ",
        InstructionTextTokenKind::OperandSeparator,
    ));
    res.extend_from_slice(&generate_operand_tokens(inst.destination(), addr, false));

    res
}

fn generate_emulated_tokens(
    inst: &impl Emulated,
    addr: u64,
    call: bool,
) -> Vec<InstructionTextToken> {
    let mut res = vec![InstructionTextToken::new(
        inst.mnemonic(),
        InstructionTextTokenKind::Instruction,
    )];

    if inst.mnemonic().len() < MIN_MNEMONIC {
        let padding = " ".repeat(MIN_MNEMONIC - inst.mnemonic().len());
        res.push(InstructionTextToken::new(
            &padding,
            InstructionTextTokenKind::Text,
        ))
    }

    if inst.destination().is_some() {
        res.extend_from_slice(&generate_operand_tokens(
            &inst.destination().unwrap(),
            addr,
            call,
        ))
    }

    res
}

fn generate_operand_tokens(source: &Operand, addr: u64, call: bool) -> Vec<InstructionTextToken> {
    match source {
        Operand::RegisterDirect(r) => match r {
            0 => vec![InstructionTextToken::new(
                "pc",
                InstructionTextTokenKind::Register,
            )],
            1 => vec![InstructionTextToken::new(
                "sp",
                InstructionTextTokenKind::Register,
            )],
            2 => vec![InstructionTextToken::new(
                "sr",
                InstructionTextTokenKind::Register,
            )],
            3 => vec![InstructionTextToken::new(
                "cg",
                InstructionTextTokenKind::Register,
            )],
            _ => vec![InstructionTextToken::new(
                format!("r{r}"),
                InstructionTextTokenKind::Register,
            )],
        },
        Operand::Indexed((r, i)) => match r {
            0 => {
                let num_text = if *i >= 0 {
                    format!("{i:#x}")
                } else {
                    format!("-{:#x}", -i)
                };
                vec![
                    InstructionTextToken::new(
                        &num_text,
                        InstructionTextTokenKind::Integer {
                            value: *i as u64,
                            size: None,
                        },
                    ),
                    InstructionTextToken::new("(", InstructionTextTokenKind::Text),
                    InstructionTextToken::new("pc", InstructionTextTokenKind::Register),
                    InstructionTextToken::new(")", InstructionTextTokenKind::Text),
                ]
            }
            1 => {
                let num_text = if *i >= 0 {
                    format!("{i:#x}")
                } else {
                    format!("-{:#x}", -i)
                };
                vec![
                    InstructionTextToken::new(
                        &num_text,
                        InstructionTextTokenKind::Integer {
                            value: *i as u64,
                            size: None,
                        },
                    ),
                    InstructionTextToken::new("(", InstructionTextTokenKind::Text),
                    InstructionTextToken::new("sp", InstructionTextTokenKind::Register),
                    InstructionTextToken::new(")", InstructionTextTokenKind::Text),
                ]
            }
            2 => {
                let num_text = if *i >= 0 {
                    format!("{i:#x}")
                } else {
                    format!("-{:#x}", -i)
                };
                vec![
                    InstructionTextToken::new(
                        &num_text,
                        InstructionTextTokenKind::Integer {
                            value: *i as u64,
                            size: None,
                        },
                    ),
                    InstructionTextToken::new("(", InstructionTextTokenKind::Text),
                    InstructionTextToken::new("sr", InstructionTextTokenKind::Register),
                    InstructionTextToken::new(")", InstructionTextTokenKind::Text),
                ]
            }
            3 => {
                let num_text = if *i >= 0 {
                    format!("{i:#x}")
                } else {
                    format!("-{:#x}", -i)
                };
                vec![
                    InstructionTextToken::new(
                        &num_text,
                        InstructionTextTokenKind::Integer {
                            value: *i as u64,
                            size: None,
                        },
                    ),
                    InstructionTextToken::new("(", InstructionTextTokenKind::Text),
                    InstructionTextToken::new("cg", InstructionTextTokenKind::Register),
                    InstructionTextToken::new(")", InstructionTextTokenKind::Text),
                ]
            }
            _ => {
                let num_text = if *i >= 0 {
                    format!("{i:#x}")
                } else {
                    format!("-{:#x}", -i)
                };
                vec![
                    InstructionTextToken::new(
                        &num_text,
                        InstructionTextTokenKind::Integer {
                            value: *i as u64,
                            size: None,
                        },
                    ),
                    InstructionTextToken::new("(", InstructionTextTokenKind::Text),
                    InstructionTextToken::new(format!("r{r}"), InstructionTextTokenKind::Register),
                    InstructionTextToken::new(")", InstructionTextTokenKind::Text),
                ]
            }
        },
        Operand::RegisterIndirect(r) => {
            let r_text = if *r == 1 {
                "sp".into()
            } else {
                format!("r{r}")
            };

            vec![
                InstructionTextToken::new("@", InstructionTextTokenKind::Text),
                InstructionTextToken::new(r_text, InstructionTextTokenKind::Register),
            ]
        }
        Operand::RegisterIndirectAutoIncrement(r) => {
            let r_text = if *r == 1 {
                "sp".into()
            } else {
                format!("r{r}")
            };

            vec![
                InstructionTextToken::new("@", InstructionTextTokenKind::Text),
                InstructionTextToken::new(r_text, InstructionTextTokenKind::Register),
                InstructionTextToken::new("+", InstructionTextTokenKind::Text),
            ]
        }
        Operand::Symbolic(i) => {
            let value = (addr as i64 + *i as i64) as u64;
            vec![InstructionTextToken::new(
                format!("{value:#x}"),
                InstructionTextTokenKind::CodeRelativeAddress { value, size: None },
            )]
        }
        Operand::Immediate(i) => {
            if call {
                vec![InstructionTextToken::new(
                    format!("{i:#x}"),
                    InstructionTextTokenKind::CodeRelativeAddress {
                        value: *i as u64,
                        size: None,
                    },
                )]
            } else {
                vec![InstructionTextToken::new(
                    format!("{i:#x}"),
                    InstructionTextTokenKind::PossibleAddress {
                        value: *i as u64,
                        size: None,
                    },
                )]
            }
        }
        Operand::Absolute(a) => {
            if call {
                vec![InstructionTextToken::new(
                    format!("{a:#x}"),
                    InstructionTextTokenKind::CodeRelativeAddress {
                        value: *a as u64,
                        size: None,
                    },
                )]
            } else {
                vec![InstructionTextToken::new(
                    format!("{a:#x}"),
                    InstructionTextTokenKind::PossibleAddress {
                        value: *a as u64,
                        size: None,
                    },
                )]
            }
        }
        Operand::Constant(i) => {
            let num_text = if *i >= 0 {
                format!("{i:#x}")
            } else {
                format!("-{:#x}", -i)
            };

            vec![
                InstructionTextToken::new("#", InstructionTextTokenKind::Text),
                InstructionTextToken::new(
                    num_text,
                    InstructionTextTokenKind::Integer {
                        value: *i as u64,
                        size: None,
                    },
                ),
            ]
        }
    }
}

pub(crate) fn offset_to_absolute(addr: u64, offset: i16) -> u64 {
    // add + 2 to addr to get past the jxx instruction which is always 2 bytes
    ((addr + 2) as i64 + ((offset * 2) as i64)) as u64
}
