use crate::architecture::offset_to_absolute;
use crate::flag::{Flag, FlagWrite};
use crate::register::Register;
use crate::Msp430;

use binaryninja::{architecture::FlagCondition, low_level_il::lifting::LowLevelILLabel};

use msp430_asm::emulate::Emulated;
use msp430_asm::instruction::Instruction;
use msp430_asm::jxx::Jxx;
use msp430_asm::operand::{Operand, OperandWidth};
use msp430_asm::single_operand::SingleOperand;
use msp430_asm::two_operand::TwoOperand;

use binaryninja::low_level_il::expression::ValueExpr;
use binaryninja::low_level_il::{MutableLiftedILExpr, MutableLiftedILFunction};
use log::info;

macro_rules! auto_increment {
    ($src:expr, $il:ident) => {
        if let Operand::RegisterIndirectAutoIncrement(r) = $src {
            $il.set_reg(
                2,
                Register::try_from(*r as u32).unwrap(),
                $il.add(
                    2,
                    $il.reg(2, Register::try_from(*r as u32).unwrap()),
                    $il.const_int(2, 2),
                ),
            )
            .append();
        }
    };
}

macro_rules! one_operand {
    ($source:expr, $il:ident, $op:ident) => {
        match $source {
            Operand::RegisterDirect(r) => $il
                .set_reg(2, Register::try_from(*r as u32).unwrap(), $op)
                .append(),
            Operand::Indexed((r, offset)) => $il
                .store(
                    2,
                    $il.add(
                        2,
                        $il.reg(2, Register::try_from(*r as u32).unwrap()),
                        $il.const_int(2, *offset as u64),
                    ),
                    $op,
                )
                .append(),
            Operand::Symbolic(offset) => $il
                .store(2, $il.add(2, $il.reg(2, Register::Pc), *offset as u64), $op)
                .append(),
            Operand::Absolute(val) => $il.store(2, $il.const_ptr(*val as u64), $op).append(),
            Operand::Immediate(_) => $op.append(),
            Operand::RegisterIndirect(r) => $il
                .store(2, $il.reg(2, Register::try_from(*r as u32).unwrap()), $op)
                .append(),
            Operand::RegisterIndirectAutoIncrement(r) => {
                $il.store(2, $il.reg(2, Register::try_from(*r as u32).unwrap()), $op)
                    .append();
                $il.set_reg(
                    2,
                    Register::try_from(*r as u32).unwrap(),
                    $il.add(
                        2,
                        $il.reg(2, Register::try_from(*r as u32).unwrap()),
                        $il.const_int(2, 2),
                    ),
                )
                .append()
            }
            Operand::Constant(val) => $il.store(2, $il.const_int(2, *val as u64), $op).append(),
        };
    };
}

macro_rules! two_operand {
    ($destination:expr, $il:ident, $op:ident) => {
        match $destination {
            Operand::RegisterDirect(r) => $il
                .set_reg(2, Register::try_from(*r as u32).unwrap(), $op)
                .append(),
            Operand::Indexed((r, offset)) => $il
                .store(
                    2,
                    $il.add(
                        2,
                        $il.reg(2, Register::try_from(*r as u32).unwrap()),
                        $il.const_int(2, *offset as u64),
                    ),
                    $op,
                )
                .append(),
            Operand::Symbolic(offset) => $il
                .store(2, $il.add(2, $il.reg(2, Register::Pc), *offset as u64), $op)
                .append(),
            Operand::Absolute(val) => $il.store(2, $il.const_ptr(*val as u64), $op).append(),
            _ => {
                unreachable!()
            }
        };
    };
}

macro_rules! emulated {
    ($inst:ident, $il:ident, $op:ident) => {
        match $inst.destination() {
            Some(Operand::RegisterDirect(r)) => $il
                .set_reg(2, Register::try_from(*r as u32).unwrap(), $op)
                .append(),
            Some(Operand::Indexed((r, offset))) => $il
                .store(
                    2,
                    $il.add(
                        2,
                        $il.reg(2, Register::try_from(*r as u32).unwrap()),
                        $il.const_int(2, *offset as u64),
                    ),
                    $op,
                )
                .append(),
            Some(Operand::Symbolic(offset)) => $il
                .store(2, $il.add(2, $il.reg(2, Register::Pc), *offset as u64), $op)
                .append(),
            Some(Operand::Absolute(val)) => $il.store(2, $il.const_ptr(*val as u64), $op).append(),
            _ => {
                unreachable!()
            }
        };
    };
}

macro_rules! conditional_jump {
    ($addr:ident, $inst:ident, $cond:ident, $il:ident) => {
        let true_addr = offset_to_absolute($addr, $inst.offset());
        let false_addr = $addr + $inst.size() as u64;
        let mut new_true = true;
        let mut new_false = false;

        let mut true_label = $il.label_for_address(true_addr).unwrap_or_else(|| {
            new_true = true;
            LowLevelILLabel::new()
        });

        let mut false_label = $il.label_for_address(false_addr).unwrap_or_else(|| {
            new_false = true;
            LowLevelILLabel::new()
        });

        $il.if_expr($cond, &mut true_label, &mut false_label)
            .append();

        if new_true {
            $il.mark_label(&mut true_label);
            $il.jump($il.const_ptr(true_addr)).append();
        }

        if new_false {
            $il.mark_label(&mut false_label);
        }
    };
}

pub(crate) fn lift_instruction(
    inst: &Instruction,
    addr: u64,
    il: &MutableLiftedILFunction<Msp430>,
) {
    match inst {
        Instruction::Rrc(inst) => {
            let size = match inst.operand_width() {
                Some(width) => width_to_size(width),
                None => 2,
            };
            let src = il.const_int(size, 1);
            let dest = lift_source_operand(inst.source(), size, il);
            let op = match inst.operand_width() {
                Some(OperandWidth::Byte) => {
                    il.sx(2, il.rrc(size, dest, src).with_flag_write(FlagWrite::All))
                }
                Some(OperandWidth::Word) | None => {
                    il.rrc(size, dest, src).with_flag_write(FlagWrite::All)
                }
            };
            one_operand!(inst.source(), il, op);
        }
        Instruction::Swpb(inst) => {
            let src = lift_source_operand(inst.source(), 2, il);
            let op = il.rol(2, src, il.const_int(2, 8));
            one_operand!(inst.source(), il, op);
        }
        Instruction::Rra(inst) => {
            let size = match inst.operand_width() {
                Some(width) => width_to_size(width),
                None => 2,
            };
            let src = il.const_int(size, 1);
            let dest = lift_source_operand(inst.source(), size, il);
            let op = match inst.operand_width() {
                Some(OperandWidth::Byte) => {
                    il.sx(2, il.ror(size, dest, src).with_flag_write(FlagWrite::Cnz))
                }
                Some(OperandWidth::Word) | None => {
                    il.ror(size, dest, src).with_flag_write(FlagWrite::Cnz)
                }
            };
            one_operand!(inst.source(), il, op);
            il.set_flag(Flag::V, il.const_int(0, 0)).append();
        }
        Instruction::Sxt(inst) => {
            // source is always 1 byte and instruction is always 2 bytes for sxt because we're sign
            // extending the low byte into the high and the result is always 2 bytes
            let src = lift_source_operand(inst.source(), 1, il);
            let op = il.sx(2, src).with_flag_write(FlagWrite::Nz);
            one_operand!(inst.source(), il, op);
            il.set_flag(Flag::V, il.const_int(0, 0)).append();
            il.set_flag(Flag::C, il.not(0, il.flag(Flag::Z))).append();
        }
        Instruction::Push(inst) => {
            let size = match inst.operand_width() {
                Some(width) => width_to_size(width),
                None => 2,
            };
            let src = lift_source_operand(inst.source(), size, il);
            il.push(size, src).append();
            auto_increment!(inst.source(), il);
        }
        Instruction::Call(inst) => {
            // TODO: verify the special autoincrement behavior Josh implemented?
            let src = if let Operand::Immediate(src) = inst.source() {
                il.const_ptr(*src as u64)
            } else {
                let size = match inst.operand_width() {
                    Some(width) => width_to_size(width),
                    None => 2,
                };

                lift_source_operand(inst.source(), size, il)
            };
            il.call(src).append();
            auto_increment!(inst.source(), il);
        }
        Instruction::Reti(_) => {
            il.set_reg(2, Register::Sr, il.pop(2))
                .with_flag_write(FlagWrite::All)
                .append();
            il.ret(il.pop(2)).append();
        }

        // Jxx instructions
        Instruction::Jnz(inst) => {
            let cond = il.flag_cond(FlagCondition::LLFC_NE);
            conditional_jump!(addr, inst, cond, il);
        }
        Instruction::Jz(inst) => {
            let cond = il.flag_cond(FlagCondition::LLFC_E);
            conditional_jump!(addr, inst, cond, il);
        }
        Instruction::Jlo(inst) => {
            let cond = il.flag_cond(FlagCondition::LLFC_ULT);
            conditional_jump!(addr, inst, cond, il);
        }
        Instruction::Jc(inst) => {
            let cond = il.flag_cond(FlagCondition::LLFC_UGE);
            conditional_jump!(addr, inst, cond, il);
        }
        Instruction::Jn(inst) => {
            let cond = il.flag_cond(FlagCondition::LLFC_NEG);
            conditional_jump!(addr, inst, cond, il);
        }
        Instruction::Jge(inst) => {
            let cond = il.flag_cond(FlagCondition::LLFC_SGE);
            conditional_jump!(addr, inst, cond, il);
        }
        Instruction::Jl(inst) => {
            let cond = il.flag_cond(FlagCondition::LLFC_SLT);
            conditional_jump!(addr, inst, cond, il);
        }
        Instruction::Jmp(inst) => {
            let fixed_addr = offset_to_absolute(addr, inst.offset());
            let label = il.label_for_address(fixed_addr);
            match label {
                Some(mut label) => {
                    il.goto(&mut label).append();
                }
                None => {
                    il.jump(il.const_ptr(fixed_addr)).append();
                }
            }
        }

        // two operand instructions
        Instruction::Mov(inst) => {
            let size = width_to_size(inst.operand_width());
            let src = match inst.operand_width() {
                OperandWidth::Byte => il
                    .sx(2, lift_source_operand(inst.source(), size, il))
                    .build(),
                OperandWidth::Word => lift_source_operand(inst.source(), size, il),
            };
            two_operand!(inst.destination(), il, src);
            auto_increment!(inst.source(), il);
        }
        Instruction::Add(inst) => {
            let size = width_to_size(inst.operand_width());
            let src = lift_source_operand(inst.source(), size, il);
            let dest = lift_source_operand(inst.destination(), size, il);
            let op = match inst.operand_width() {
                OperandWidth::Byte => {
                    il.sx(2, il.add(size, src, dest).with_flag_write(FlagWrite::All))
                }
                OperandWidth::Word => il.add(size, src, dest).with_flag_write(FlagWrite::All),
            };
            two_operand!(inst.destination(), il, op);
            auto_increment!(inst.source(), il);
        }
        Instruction::Addc(_) => {
            il.unimplemented().append();
        }
        Instruction::Subc(_) => {
            il.unimplemented().append();
        }
        Instruction::Sub(inst) => {
            let size = width_to_size(inst.operand_width());
            let src = lift_source_operand(inst.source(), size, il);
            let dest = lift_source_operand(inst.destination(), size, il);
            let op = match inst.operand_width() {
                OperandWidth::Byte => {
                    il.sx(2, il.sub(size, src, dest).with_flag_write(FlagWrite::All))
                }
                OperandWidth::Word => il.sub(size, src, dest).with_flag_write(FlagWrite::All),
            };
            two_operand!(inst.destination(), il, op);
            auto_increment!(inst.source(), il);
        }
        Instruction::Cmp(inst) => {
            let size = width_to_size(inst.operand_width());
            let src = lift_source_operand(inst.source(), size, il);
            let dest = lift_source_operand(inst.destination(), size, il);
            il.sub(size, dest, src)
                .with_flag_write(FlagWrite::All)
                .append();
            auto_increment!(inst.source(), il);
        }
        Instruction::Dadd(_) => {
            il.unimplemented().append();
        }
        Instruction::Bit(inst) => {
            let size = width_to_size(inst.operand_width());
            let src = lift_source_operand(inst.source(), size, il);
            let dest = lift_source_operand(inst.destination(), size, il);
            il.and(size, src, dest)
                .with_flag_write(FlagWrite::Nz)
                .append();
            il.set_flag(Flag::V, il.const_int(0, 0)).append();
            il.set_flag(Flag::C, il.not(0, il.flag(Flag::Z))).append();
            auto_increment!(inst.source(), il);
        }
        Instruction::Bic(inst) => {
            let size = width_to_size(inst.operand_width());
            let src = lift_source_operand(inst.source(), size, il);
            let dest = lift_source_operand(inst.destination(), size, il);
            let op = match inst.operand_width() {
                OperandWidth::Byte => il.sx(2, il.and(size, il.not(size, src), dest)),
                OperandWidth::Word => il.and(size, il.not(size, src), dest),
            };
            two_operand!(inst.destination(), il, op);
            auto_increment!(inst.source(), il);
        }
        Instruction::Bis(inst) => {
            let size = width_to_size(inst.operand_width());
            let src = lift_source_operand(inst.source(), size, il);
            let dest = lift_source_operand(inst.destination(), size, il);
            let op = match inst.operand_width() {
                OperandWidth::Byte => il.sx(2, il.or(size, src, dest)),
                OperandWidth::Word => il.or(size, src, dest),
            };
            two_operand!(inst.destination(), il, op);
            auto_increment!(inst.source(), il);
        }
        Instruction::Xor(inst) => {
            let size = width_to_size(inst.operand_width());
            let src = lift_source_operand(inst.source(), size, il);
            let dest = lift_source_operand(inst.destination(), size, il);
            let op = match inst.operand_width() {
                OperandWidth::Byte => {
                    il.sx(2, il.xor(size, src, dest).with_flag_write(FlagWrite::Nvz))
                }
                OperandWidth::Word => il.xor(size, src, dest).with_flag_write(FlagWrite::Nvz),
            };
            two_operand!(inst.destination(), il, op);
            il.set_flag(Flag::C, il.not(0, il.flag(Flag::Z))).append();
            auto_increment!(inst.source(), il);
        }
        Instruction::And(inst) => {
            let size = width_to_size(inst.operand_width());
            let src = lift_source_operand(inst.source(), size, il);
            let dest = lift_source_operand(inst.destination(), size, il);
            let op = match inst.operand_width() {
                OperandWidth::Byte => {
                    il.sx(2, il.and(size, src, dest).with_flag_write(FlagWrite::Nz))
                }
                OperandWidth::Word => il.and(size, src, dest).with_flag_write(FlagWrite::Nz),
            };
            two_operand!(inst.destination(), il, op);
            il.set_flag(Flag::V, il.const_int(0, 0)).append();
            il.set_flag(Flag::C, il.not(0, il.flag(Flag::Z))).append();
            auto_increment!(inst.source(), il);
        }

        // emulated
        Instruction::Adc(_) => {
            il.unimplemented().append();
        }
        Instruction::Br(inst) => {
            let dest = if let Some(Operand::Immediate(dest)) = inst.destination() {
                if let Some(mut label) = il.label_for_address(*dest as u64) {
                    il.goto(&mut label).append();
                    return;
                } else {
                    il.const_ptr(*dest as u64)
                }
            } else {
                lift_source_operand(&inst.destination().unwrap(), 2, il)
            };

            il.jump(dest).append();
        }
        Instruction::Clr(inst) => {
            let op = il.const_int(2, 0);
            emulated!(inst, il, op);
        }
        Instruction::Clrc(_) => {
            // TODO: should we lift clearing the C bit in the SR register as well?
            il.set_flag(Flag::C, il.const_int(0, 0)).append();
        }
        Instruction::Clrn(_) => {
            // TODO: should we lift clearing the N bit in the SR register as well?
            il.set_flag(Flag::N, il.const_int(0, 0)).append();
        }
        Instruction::Clrz(_) => {
            // TODO: should we lift clearing the Z bit in the SR register as well?
            il.set_flag(Flag::Z, il.const_int(0, 0)).append();
        }
        Instruction::Dadc(_) => {
            il.unimplemented().append();
        }
        Instruction::Dec(inst) => {
            let size = match inst.operand_width() {
                Some(width) => width_to_size(width),
                None => 2,
            };
            let dest = lift_source_operand(&inst.destination().unwrap(), size, il);
            let op = match inst.operand_width() {
                Some(OperandWidth::Byte) => il.sx(
                    2,
                    il.sub(size, dest, il.const_int(size, 1))
                        .with_flag_write(FlagWrite::All),
                ),
                Some(OperandWidth::Word) | None => il
                    .sub(size, dest, il.const_int(size, 1))
                    .with_flag_write(FlagWrite::All),
            };
            emulated!(inst, il, op);
        }
        Instruction::Decd(inst) => {
            let size = match inst.operand_width() {
                Some(width) => width_to_size(width),
                None => 2,
            };
            let dest = lift_source_operand(&inst.destination().unwrap(), size, il);
            let op = match inst.operand_width() {
                Some(OperandWidth::Byte) => il.sx(
                    2,
                    il.sub(size, dest, il.const_int(size, 2))
                        .with_flag_write(FlagWrite::All),
                ),
                Some(OperandWidth::Word) | None => il
                    .sub(size, dest, il.const_int(size, 2))
                    .with_flag_write(FlagWrite::All),
            };
            emulated!(inst, il, op);
        }
        Instruction::Dint(_) => {
            // If GIE flag is ever exposed this should clear it
        }
        Instruction::Eint(_) => {
            // If GIE flag is ever exposed this should set it
        }
        Instruction::Inc(inst) => {
            let size = match inst.operand_width() {
                Some(width) => width_to_size(width),
                None => 2,
            };
            let dest = lift_source_operand(&inst.destination().unwrap(), size, il);
            let op = match inst.operand_width() {
                Some(OperandWidth::Byte) => il.sx(
                    2,
                    il.add(size, dest, il.const_int(size, 1))
                        .with_flag_write(FlagWrite::All),
                ),
                Some(OperandWidth::Word) | None => il
                    .add(size, dest, il.const_int(size, 1))
                    .with_flag_write(FlagWrite::All),
            };
            emulated!(inst, il, op);
        }
        Instruction::Incd(inst) => {
            let size = match inst.operand_width() {
                Some(width) => width_to_size(width),
                None => 2,
            };
            let dest = lift_source_operand(&inst.destination().unwrap(), size, il);
            let op = match inst.operand_width() {
                Some(OperandWidth::Byte) => il.sx(
                    2,
                    il.add(size, dest, il.const_int(size, 2))
                        .with_flag_write(FlagWrite::All),
                ),
                Some(OperandWidth::Word) | None => il
                    .add(size, dest, il.const_int(size, 2))
                    .with_flag_write(FlagWrite::All),
            };
            emulated!(inst, il, op);
        }
        Instruction::Inv(inst) => {
            let size = match inst.operand_width() {
                Some(width) => width_to_size(width),
                None => 2,
            };
            let dest = lift_source_operand(&inst.destination().unwrap(), size, il);
            let op = match inst.operand_width() {
                Some(OperandWidth::Byte) => {
                    il.sx(2, il.not(size, dest).with_flag_write(FlagWrite::Nvz))
                }
                Some(OperandWidth::Word) | None => {
                    il.not(size, dest).with_flag_write(FlagWrite::Nvz)
                }
            };
            emulated!(inst, il, op);
            il.set_flag(Flag::C, il.not(0, il.flag(Flag::Z))).append();
        }
        Instruction::Nop(_) => {
            il.nop().append();
        }
        Instruction::Pop(inst) => {
            if let Some(Operand::RegisterDirect(r)) = inst.destination() {
                let size = match inst.operand_width() {
                    Some(width) => width_to_size(width),
                    None => 2,
                };
                il.set_reg(size, Register::try_from(*r as u32).unwrap(), il.pop(2))
                    .append();
            } else {
                info!("pop: invalid destination operand");
            }
        }
        Instruction::Ret(_) => {
            il.ret(il.pop(2)).append();
        }
        Instruction::Rla(inst) => {
            let size = match inst.operand_width() {
                Some(width) => width_to_size(width),
                None => 2,
            };
            let src = il.const_int(size, 1);
            let dest = lift_source_operand(&inst.destination().unwrap(), size, il);
            let op = match inst.operand_width() {
                Some(OperandWidth::Byte) => {
                    il.sx(2, il.rol(size, dest, src).with_flag_write(FlagWrite::All))
                }
                Some(OperandWidth::Word) | None => {
                    il.rol(size, dest, src).with_flag_write(FlagWrite::All)
                }
            };
            emulated!(inst, il, op);
        }
        Instruction::Rlc(inst) => {
            let size = match inst.operand_width() {
                Some(width) => width_to_size(width),
                None => 2,
            };
            let src = il.const_int(size, 1);
            let dest = lift_source_operand(&inst.destination().unwrap(), size, il);
            let op = match inst.operand_width() {
                Some(OperandWidth::Byte) => {
                    il.sx(2, il.rlc(size, dest, src).with_flag_write(FlagWrite::All))
                }
                Some(OperandWidth::Word) | None => {
                    il.rlc(size, dest, src).with_flag_write(FlagWrite::All)
                }
            };
            emulated!(inst, il, op);
        }
        Instruction::Sbc(_) => {
            il.unimplemented().append();
        }
        Instruction::Setc(_) => {
            // TODO: should we lift setting the C bit in the SR register as well?
            il.set_flag(Flag::C, il.const_int(0, 1)).append();
        }
        Instruction::Setn(_) => {
            // TODO: should we lift setting the N bit in the SR register as well?
            il.set_flag(Flag::N, il.const_int(0, 1)).append();
        }
        Instruction::Setz(_) => {
            // TODO: should we lift setting the Z bit in the SR register as well?
            il.set_flag(Flag::Z, il.const_int(0, 1)).append();
        }
        Instruction::Tst(inst) => {
            let size = match inst.operand_width() {
                Some(width) => width_to_size(width),
                None => 2,
            };
            let dest = lift_source_operand(&inst.destination().unwrap(), size, il);
            il.sub(size, dest, il.const_int(size, 0))
                .with_flag_write(FlagWrite::Nz)
                .append();
            il.set_flag(Flag::V, il.const_int(0, 0)).append();
            il.set_flag(Flag::C, il.const_int(0, 1)).append();
        }
    }
}

fn lift_source_operand<'a>(
    operand: &Operand,
    size: usize,
    il: &'a MutableLiftedILFunction<Msp430>,
) -> MutableLiftedILExpr<'a, Msp430, ValueExpr> {
    match operand {
        Operand::RegisterDirect(r) => il.reg(size, Register::try_from(*r as u32).unwrap()),
        Operand::Indexed((r, offset)) => il
            .load(
                size,
                il.add(
                    2,
                    il.reg(2, Register::try_from(*r as u32).unwrap()),
                    il.const_int(2, *offset as u64),
                ),
            )
            .build(),
        // should we add offset to addr here rather than lifting to the register since we know where PC is?
        Operand::Symbolic(offset) => il
            .load(
                size,
                il.add(2, il.reg(2, Register::Pc), il.const_int(2, *offset as u64)),
            )
            .build(),
        Operand::Absolute(addr) => il.load(size, il.const_ptr(*addr as u64)).build(),
        // these are the same, we need to autoincrement in a separate il instruction
        Operand::RegisterIndirect(r) | Operand::RegisterIndirectAutoIncrement(r) => il
            .load(size, il.reg(2, Register::try_from(*r as u32).unwrap()))
            .build(),
        Operand::Immediate(val) => il.const_int(size, *val as u64),
        Operand::Constant(val) => il.const_int(size, *val as u64),
    }
}

fn width_to_size(width: &OperandWidth) -> usize {
    match width {
        OperandWidth::Byte => 1,
        OperandWidth::Word => 2,
    }
}
