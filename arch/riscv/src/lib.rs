#![allow(clippy::unusual_byte_groupings)]
// Option -> Result
// rework operands/instruction text
// helper func for reading/writing to registers
// do the amo max/min instructions
// Platform api

use binaryninja::relocation::{Relocation, RelocationHandlerExt};
use binaryninja::{
    add_optional_plugin_dependency, architecture,
    architecture::{
        llvm_assemble, Architecture, ArchitectureExt, CoreArchitecture, CustomArchitectureHandle,
        ImplicitRegisterExtend, InstructionInfo, LlvmServicesCodeModel, LlvmServicesDialect,
        LlvmServicesRelocMode, Register as Reg, RegisterInfo, UnusedFlag, UnusedRegisterStack,
        UnusedRegisterStackInfo,
    },
    binary_view::{BinaryView, BinaryViewExt},
    calling_convention::{register_calling_convention, CallingConvention, ConventionBuilder},
    custom_binary_view::{BinaryViewType, BinaryViewTypeExt},
    disassembly::{InstructionTextToken, InstructionTextTokenKind},
    function::Function,
    function_recognizer::FunctionRecognizer,
    rc::Ref,
    relocation::{
        CoreRelocationHandler, CustomRelocationHandlerHandle, RelocationHandler, RelocationInfo,
        RelocationType,
    },
    symbol::{Symbol, SymbolType},
    types::{NameAndType, Type},
};
use log::LevelFilter;
use std::borrow::Cow;
use std::fmt;
use std::hash::Hash;
use std::marker::PhantomData;

use binaryninja::architecture::{BranchKind, IntrinsicId, RegisterId};
use binaryninja::confidence::{Conf, MAX_CONFIDENCE, MIN_CONFIDENCE};
use binaryninja::logger::Logger;
use binaryninja::low_level_il::expression::{LowLevelILExpressionKind, ValueExpr};
use binaryninja::low_level_il::instruction::LowLevelILInstructionKind;
use binaryninja::low_level_il::lifting::{
    LiftableLowLevelIL, LiftableLowLevelILWithSize, LowLevelILLabel,
};
use binaryninja::low_level_il::{
    expression::ExpressionHandler, instruction::InstructionHandler, LowLevelILRegister,
    MutableLiftedILExpr, MutableLiftedILFunction, RegularLowLevelILFunction,
};
use riscv_dis::{
    FloatReg, FloatRegType, Instr, IntRegType, Op, RegFile, Register as RiscVRegister,
    RiscVDisassembler, RoundMode,
};

enum RegType {
    Integer(u32),
    Float(u32),
}

#[repr(u32)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Intrinsic {
    Uret,
    Sret,
    Mret,
    Wfi,
    Csrrw,
    Csrwr,
    Csrrd,
    Csrrs,
    Csrrc,
    Fadd(u8, RoundMode),
    Fsub(u8, RoundMode),
    Fmul(u8, RoundMode),
    Fdiv(u8, RoundMode),
    Fsqrt(u8, RoundMode),
    Fsgnj(u8),
    Fsgnjn(u8),
    Fsgnjx(u8),
    Fmin(u8),
    Fmax(u8),
    Fclass(u8),
    FcvtFToF(u8, u8, RoundMode),
    FcvtIToF(u8, u8, RoundMode),
    FcvtFToI(u8, u8, RoundMode),
    FcvtUToF(u8, u8, RoundMode),
    FcvtFToU(u8, u8, RoundMode),
    Fence,
}

#[derive(Copy, Clone)]
struct Register<D: 'static + RiscVDisassembler> {
    id: RegisterId,
    _dis: PhantomData<D>,
}

#[derive(Debug, Copy, Clone)]
struct RiscVIntrinsic<D: 'static + RiscVDisassembler> {
    id: Intrinsic,
    _dis: PhantomData<D>,
}

impl<D: 'static + RiscVDisassembler> Register<D> {
    fn new(id: RegisterId) -> Self {
        Self {
            id,
            _dis: PhantomData,
        }
    }

    fn reg_type(&self) -> RegType {
        let int_reg_count = <D::RegFile as RegFile>::int_reg_count();

        if self.id.0 < int_reg_count {
            RegType::Integer(self.id.0)
        } else {
            RegType::Float(self.id.0 - int_reg_count)
        }
    }
}

impl<D: 'static + RiscVDisassembler> From<riscv_dis::IntReg<D>> for Register<D> {
    fn from(reg: riscv_dis::IntReg<D>) -> Self {
        Self {
            id: RegisterId(reg.id()),
            _dis: PhantomData,
        }
    }
}

impl<D: 'static + RiscVDisassembler> From<FloatReg<D>> for Register<D> {
    fn from(reg: FloatReg<D>) -> Self {
        let int_reg_count = <D::RegFile as RegFile>::int_reg_count();

        Self {
            id: RegisterId(reg.id() + int_reg_count),
            _dis: PhantomData,
        }
    }
}

impl<D: 'static + RiscVDisassembler> From<Register<D>> for LowLevelILRegister<Register<D>> {
    fn from(reg: Register<D>) -> Self {
        LowLevelILRegister::ArchReg(reg)
    }
}

impl<D: 'static + RiscVDisassembler> RegisterInfo for Register<D> {
    type RegType = Self;

    fn parent(&self) -> Option<Self> {
        None
    }

    fn size(&self) -> usize {
        match self.reg_type() {
            RegType::Integer(_) => <D::RegFile as RegFile>::Int::width(),
            RegType::Float(_) => <D::RegFile as RegFile>::Float::width(),
        }
    }

    fn offset(&self) -> usize {
        0
    }
    fn implicit_extend(&self) -> ImplicitRegisterExtend {
        ImplicitRegisterExtend::NoExtend
    }
}

impl<D: 'static + RiscVDisassembler> architecture::Register for Register<D> {
    type InfoType = Self;

    fn name(&self) -> Cow<str> {
        match self.reg_type() {
            RegType::Integer(id) => match id {
                0 => "zero".into(),
                1 => "ra".into(),
                2 => "sp".into(),
                3 => "gp".into(),
                4 => "tp".into(),
                r @ 5..=7 => format!("t{}", r - 5).into(),
                r @ 8..=9 => format!("s{}", r - 8).into(),
                r @ 10..=17 => format!("a{}", r - 10).into(),
                r @ 18..=27 => format!("s{}", r - 16).into(),
                r @ 28..=31 => format!("t{}", r - 25).into(),
                _ => unreachable!(),
            },
            RegType::Float(id) => match id {
                r @ 0..=7 => format!("ft{}", r).into(),
                r @ 8..=9 => format!("fs{}", r - 8).into(),
                r @ 10..=17 => format!("fa{}", r - 10).into(),
                r @ 18..=27 => format!("fs{}", r - 16).into(),
                r @ 28..=31 => format!("ft{}", r - 20).into(),
                _ => unreachable!(),
            },
        }
    }

    fn info(&self) -> Self {
        *self
    }

    fn id(&self) -> RegisterId {
        self.id
    }
}

impl<'a, D: 'static + RiscVDisassembler + Send + Sync> LiftableLowLevelIL<'a, RiscVArch<D>>
    for Register<D>
{
    type Result = ValueExpr;

    fn lift(
        il: &'a MutableLiftedILFunction<RiscVArch<D>>,
        reg: Self,
    ) -> MutableLiftedILExpr<'a, RiscVArch<D>, Self::Result> {
        match reg.reg_type() {
            RegType::Integer(0) => il.const_int(reg.size(), 0),
            RegType::Integer(_) => il.reg(reg.size(), reg),
            _ => il.unimplemented(),
        }
    }
}

impl<'a, D: 'static + RiscVDisassembler + Send + Sync> LiftableLowLevelILWithSize<'a, RiscVArch<D>>
    for Register<D>
{
    fn lift_with_size(
        il: &'a MutableLiftedILFunction<RiscVArch<D>>,
        reg: Self,
        size: usize,
    ) -> MutableLiftedILExpr<'a, RiscVArch<D>, ValueExpr> {
        #[cfg(debug_assertions)]
        {
            if reg.size() < size {
                log::warn!(
                    "il @ {:x} attempted to lift {} byte register as {} byte expr",
                    il.current_address(),
                    reg.size(),
                    size
                );
            }
        }

        match reg.reg_type() {
            RegType::Integer(0) => il.const_int(size, 0),
            RegType::Integer(_) => {
                let expr = il.reg(reg.size(), reg);

                if size < reg.size() {
                    il.low_part(size, expr).build()
                } else {
                    expr
                }
            }
            _ => il.unimplemented(),
        }
    }
}

impl<D: 'static + RiscVDisassembler> Hash for Register<D> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}

impl<D: 'static + RiscVDisassembler> PartialEq for Register<D> {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl<D: 'static + RiscVDisassembler> Eq for Register<D> {}

impl<D: 'static + RiscVDisassembler> fmt::Debug for Register<D> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.name().as_ref())
    }
}

impl<D: RiscVDisassembler> RiscVIntrinsic<D> {
    fn id_from_parts(
        id: u32,
        sz1: Option<u8>,
        sz2: Option<u8>,
        rm: Option<RoundMode>,
    ) -> IntrinsicId {
        let sz1 = sz1.unwrap_or(0);
        let sz2 = sz2.unwrap_or(0);
        let rm = match rm {
            None | Some(RoundMode::Dynamic) => 0,
            Some(RoundMode::RoundNearestEven) => 1,
            Some(RoundMode::RoundTowardZero) => 2,
            Some(RoundMode::RoundDown) => 3,
            Some(RoundMode::RoundUp) => 4,
            Some(RoundMode::RoundMaxMagnitude) => 5,
        };

        let mut id = id << 20;
        id |= sz1 as u32;
        id |= (sz2 as u32) << 8;
        id |= (rm as u32) << 16;
        IntrinsicId(id)
    }

    fn parts_from_id(id: IntrinsicId) -> Option<(u32, u8, u8, RoundMode)> {
        let id = id.0;
        let sz1 = (id & 0xff) as u8;
        let sz2 = ((id >> 8) & 0xff) as u8;
        let rm = match (id >> 16) & 0xf {
            0 => RoundMode::Dynamic,
            1 => RoundMode::RoundNearestEven,
            2 => RoundMode::RoundTowardZero,
            3 => RoundMode::RoundDown,
            4 => RoundMode::RoundUp,
            5 => RoundMode::RoundMaxMagnitude,
            _ => return None,
        };
        Some(((id >> 20) & 0xfff, sz1, sz2, rm))
    }

    fn from_id(id: IntrinsicId) -> Option<RiscVIntrinsic<D>> {
        match Self::parts_from_id(id) {
            Some((0, _, _, _)) => Some(Intrinsic::Uret.into()),
            Some((1, _, _, _)) => Some(Intrinsic::Sret.into()),
            Some((2, _, _, _)) => Some(Intrinsic::Mret.into()),
            Some((3, _, _, _)) => Some(Intrinsic::Wfi.into()),
            Some((4, _, _, _)) => Some(Intrinsic::Csrrw.into()),
            Some((5, _, _, _)) => Some(Intrinsic::Csrwr.into()),
            Some((6, _, _, _)) => Some(Intrinsic::Csrrd.into()),
            Some((7, _, _, _)) => Some(Intrinsic::Csrrs.into()),
            Some((8, _, _, _)) => Some(Intrinsic::Csrrc.into()),
            Some((9, size, _, rm)) => Some(Intrinsic::Fadd(size, rm).into()),
            Some((10, size, _, rm)) => Some(Intrinsic::Fsub(size, rm).into()),
            Some((11, size, _, rm)) => Some(Intrinsic::Fmul(size, rm).into()),
            Some((12, size, _, rm)) => Some(Intrinsic::Fdiv(size, rm).into()),
            Some((13, size, _, rm)) => Some(Intrinsic::Fsqrt(size, rm).into()),
            Some((14, size, _, _)) => Some(Intrinsic::Fsgnj(size).into()),
            Some((15, size, _, _)) => Some(Intrinsic::Fsgnjn(size).into()),
            Some((16, size, _, _)) => Some(Intrinsic::Fsgnjx(size).into()),
            Some((17, size, _, _)) => Some(Intrinsic::Fmin(size).into()),
            Some((18, size, _, _)) => Some(Intrinsic::Fmax(size).into()),
            Some((19, size, _, _)) => Some(Intrinsic::Fclass(size).into()),
            Some((20, ssize, dsize, rm)) => Some(Intrinsic::FcvtFToF(ssize, dsize, rm).into()),
            Some((21, isize, fsize, rm)) => Some(Intrinsic::FcvtIToF(isize, fsize, rm).into()),
            Some((22, fsize, isize, rm)) => Some(Intrinsic::FcvtFToI(fsize, isize, rm).into()),
            Some((23, usize, fsize, rm)) => Some(Intrinsic::FcvtUToF(usize, fsize, rm).into()),
            Some((24, fsize, usize, rm)) => Some(Intrinsic::FcvtFToU(fsize, usize, rm).into()),
            Some((25, _, _, _)) => Some(Intrinsic::Fence.into()),
            _ => None,
        }
    }

    fn int_size_suffix(size: u8) -> &'static str {
        match size {
            4 => "_i32",
            8 => "_i64",
            _ => unreachable!(),
        }
    }

    fn uint_size_suffix(size: u8) -> &'static str {
        match size {
            4 => "_u32",
            8 => "_u64",
            _ => unreachable!(),
        }
    }

    fn float_size_suffix(size: u8) -> &'static str {
        match size {
            4 => "_s",
            8 => "_d",
            16 => "_q",
            _ => unreachable!(),
        }
    }

    fn round_mode_suffix(rm: RoundMode) -> &'static str {
        match rm {
            RoundMode::RoundNearestEven => "_rne",
            RoundMode::RoundTowardZero => "_rtz",
            RoundMode::RoundDown => "_rdn",
            RoundMode::RoundUp => "_rup",
            RoundMode::RoundMaxMagnitude => "_rmm",
            RoundMode::Dynamic => "",
        }
    }
}

impl<D: RiscVDisassembler> From<Intrinsic> for RiscVIntrinsic<D> {
    fn from(id: Intrinsic) -> Self {
        Self {
            id,
            _dis: PhantomData,
        }
    }
}

impl<D: RiscVDisassembler> architecture::Intrinsic for RiscVIntrinsic<D> {
    fn name(&self) -> Cow<str> {
        match self.id {
            Intrinsic::Uret => "_uret".into(),
            Intrinsic::Sret => "_sret".into(),
            Intrinsic::Mret => "_mret".into(),
            Intrinsic::Wfi => "_wfi".into(),
            Intrinsic::Csrrw => "_csrrw".into(),
            Intrinsic::Csrwr => "_csrwr".into(),
            Intrinsic::Csrrd => "_csrrd".into(),
            Intrinsic::Csrrs => "_csrrs".into(),
            Intrinsic::Csrrc => "_csrrc".into(),
            Intrinsic::Fadd(size, rm) => format!(
                "_fadd{}{}",
                Self::float_size_suffix(size),
                Self::round_mode_suffix(rm)
            )
            .into(),
            Intrinsic::Fsub(size, rm) => format!(
                "_fsub{}{}",
                Self::float_size_suffix(size),
                Self::round_mode_suffix(rm)
            )
            .into(),
            Intrinsic::Fmul(size, rm) => format!(
                "_fmul{}{}",
                Self::float_size_suffix(size),
                Self::round_mode_suffix(rm)
            )
            .into(),
            Intrinsic::Fdiv(size, rm) => format!(
                "_fdiv{}{}",
                Self::float_size_suffix(size),
                Self::round_mode_suffix(rm)
            )
            .into(),
            Intrinsic::Fsqrt(size, rm) => format!(
                "_fsqrt{}{}",
                Self::float_size_suffix(size),
                Self::round_mode_suffix(rm)
            )
            .into(),
            Intrinsic::Fsgnj(size) => format!("_fsgnj{}", Self::float_size_suffix(size)).into(),
            Intrinsic::Fsgnjn(size) => format!("_fsgnjn{}", Self::float_size_suffix(size)).into(),
            Intrinsic::Fsgnjx(size) => format!("_fsgnjx{}", Self::float_size_suffix(size)).into(),
            Intrinsic::Fmin(size) => format!("_fmin{}", Self::float_size_suffix(size)).into(),
            Intrinsic::Fmax(size) => format!("_fmax{}", Self::float_size_suffix(size)).into(),
            Intrinsic::Fclass(size) => format!("_fclass{}", Self::float_size_suffix(size)).into(),
            Intrinsic::FcvtFToF(usize, fsize, rm) => format!(
                "_fcvt{}_to{}{}",
                Self::float_size_suffix(usize),
                Self::float_size_suffix(fsize),
                Self::round_mode_suffix(rm)
            )
            .into(),
            Intrinsic::FcvtIToF(isize, fsize, rm) => format!(
                "_fcvt{}_to{}{}",
                Self::int_size_suffix(isize),
                Self::float_size_suffix(fsize),
                Self::round_mode_suffix(rm)
            )
            .into(),
            Intrinsic::FcvtFToI(fsize, isize, rm) => format!(
                "_fcvt{}_to{}{}",
                Self::float_size_suffix(fsize),
                Self::int_size_suffix(isize),
                Self::round_mode_suffix(rm)
            )
            .into(),
            Intrinsic::FcvtUToF(usize, fsize, rm) => format!(
                "_fcvt{}_to{}{}",
                Self::uint_size_suffix(usize),
                Self::float_size_suffix(fsize),
                Self::round_mode_suffix(rm)
            )
            .into(),
            Intrinsic::FcvtFToU(fsize, usize, rm) => format!(
                "_fcvt{}_to{}{}",
                Self::float_size_suffix(fsize),
                Self::uint_size_suffix(usize),
                Self::round_mode_suffix(rm)
            )
            .into(),
            Intrinsic::Fence => "_fence".into(),
        }
    }

    fn id(&self) -> IntrinsicId {
        match self.id {
            Intrinsic::Uret => Self::id_from_parts(0, None, None, None),
            Intrinsic::Sret => Self::id_from_parts(1, None, None, None),
            Intrinsic::Mret => Self::id_from_parts(2, None, None, None),
            Intrinsic::Wfi => Self::id_from_parts(3, None, None, None),
            Intrinsic::Csrrw => Self::id_from_parts(4, None, None, None),
            Intrinsic::Csrwr => Self::id_from_parts(5, None, None, None),
            Intrinsic::Csrrd => Self::id_from_parts(6, None, None, None),
            Intrinsic::Csrrs => Self::id_from_parts(7, None, None, None),
            Intrinsic::Csrrc => Self::id_from_parts(8, None, None, None),
            Intrinsic::Fadd(size, rm) => Self::id_from_parts(9, Some(size), None, Some(rm)),
            Intrinsic::Fsub(size, rm) => Self::id_from_parts(10, Some(size), None, Some(rm)),
            Intrinsic::Fmul(size, rm) => Self::id_from_parts(11, Some(size), None, Some(rm)),
            Intrinsic::Fdiv(size, rm) => Self::id_from_parts(12, Some(size), None, Some(rm)),
            Intrinsic::Fsqrt(size, rm) => Self::id_from_parts(13, Some(size), None, Some(rm)),
            Intrinsic::Fsgnj(size) => Self::id_from_parts(14, Some(size), None, None),
            Intrinsic::Fsgnjn(size) => Self::id_from_parts(15, Some(size), None, None),
            Intrinsic::Fsgnjx(size) => Self::id_from_parts(16, Some(size), None, None),
            Intrinsic::Fmin(size) => Self::id_from_parts(17, Some(size), None, None),
            Intrinsic::Fmax(size) => Self::id_from_parts(18, Some(size), None, None),
            Intrinsic::Fclass(size) => Self::id_from_parts(19, Some(size), None, None),
            Intrinsic::FcvtFToF(ssize, dsize, rm) => {
                Self::id_from_parts(20, Some(ssize), Some(dsize), Some(rm))
            }
            Intrinsic::FcvtIToF(isize, fsize, rm) => {
                Self::id_from_parts(21, Some(isize), Some(fsize), Some(rm))
            }
            Intrinsic::FcvtFToI(fsize, isize, rm) => {
                Self::id_from_parts(22, Some(isize), Some(fsize), Some(rm))
            }
            Intrinsic::FcvtUToF(usize, fsize, rm) => {
                Self::id_from_parts(23, Some(usize), Some(fsize), Some(rm))
            }
            Intrinsic::FcvtFToU(fsize, usize, rm) => {
                Self::id_from_parts(24, Some(usize), Some(fsize), Some(rm))
            }
            Intrinsic::Fence => Self::id_from_parts(25, None, None, None),
        }
    }

    fn inputs(&self) -> Vec<NameAndType> {
        match self.id {
            Intrinsic::Uret | Intrinsic::Sret | Intrinsic::Mret | Intrinsic::Wfi => {
                vec![]
            }
            Intrinsic::Csrrd => {
                vec![NameAndType::new(
                    "csr",
                    Conf::new(Type::int(4, false), MAX_CONFIDENCE),
                )]
            }
            Intrinsic::Csrrw | Intrinsic::Csrwr | Intrinsic::Csrrs | Intrinsic::Csrrc => {
                vec![
                    NameAndType::new("csr", Conf::new(Type::int(4, false), MAX_CONFIDENCE)),
                    NameAndType::new(
                        "value",
                        Conf::new(
                            Type::int(<D::RegFile as RegFile>::Int::width(), false),
                            MIN_CONFIDENCE,
                        ),
                    ),
                ]
            }
            Intrinsic::Fadd(size, _)
            | Intrinsic::Fsub(size, _)
            | Intrinsic::Fmul(size, _)
            | Intrinsic::Fdiv(size, _)
            | Intrinsic::Fsgnj(size)
            | Intrinsic::Fsgnjn(size)
            | Intrinsic::Fsgnjx(size)
            | Intrinsic::Fmin(size)
            | Intrinsic::Fmax(size) => {
                vec![
                    NameAndType::new("", Conf::new(Type::float(size as usize), MAX_CONFIDENCE)),
                    NameAndType::new("", Conf::new(Type::float(size as usize), MAX_CONFIDENCE)),
                ]
            }
            Intrinsic::Fsqrt(size, _)
            | Intrinsic::Fclass(size)
            | Intrinsic::FcvtFToF(size, _, _)
            | Intrinsic::FcvtFToI(size, _, _)
            | Intrinsic::FcvtFToU(size, _, _) => {
                vec![NameAndType::new(
                    "",
                    Conf::new(Type::float(size as usize), MAX_CONFIDENCE),
                )]
            }
            Intrinsic::FcvtIToF(size, _, _) => {
                vec![NameAndType::new(
                    "",
                    Conf::new(Type::int(size as usize, true), MAX_CONFIDENCE),
                )]
            }
            Intrinsic::FcvtUToF(size, _, _) => {
                vec![NameAndType::new(
                    "",
                    Conf::new(Type::int(size as usize, false), MAX_CONFIDENCE),
                )]
            }
            Intrinsic::Fence => {
                vec![NameAndType::new(
                    "",
                    Conf::new(Type::int(4, false), MIN_CONFIDENCE),
                )]
            }
        }
    }

    fn outputs(&self) -> Vec<Conf<Ref<Type>>> {
        match self.id {
            Intrinsic::Uret
            | Intrinsic::Sret
            | Intrinsic::Mret
            | Intrinsic::Wfi
            | Intrinsic::Csrwr
            | Intrinsic::Fence => {
                vec![]
            }
            Intrinsic::Csrrw | Intrinsic::Csrrd | Intrinsic::Csrrs | Intrinsic::Csrrc => {
                vec![Conf::new(
                    Type::int(<D::RegFile as RegFile>::Int::width(), false),
                    MIN_CONFIDENCE,
                )]
            }
            Intrinsic::Fadd(size, _)
            | Intrinsic::Fsub(size, _)
            | Intrinsic::Fmul(size, _)
            | Intrinsic::Fdiv(size, _)
            | Intrinsic::Fsqrt(size, _)
            | Intrinsic::Fsgnj(size)
            | Intrinsic::Fsgnjn(size)
            | Intrinsic::Fsgnjx(size)
            | Intrinsic::Fmin(size)
            | Intrinsic::Fmax(size)
            | Intrinsic::FcvtFToF(_, size, _)
            | Intrinsic::FcvtIToF(_, size, _)
            | Intrinsic::FcvtUToF(_, size, _) => {
                vec![Conf::new(Type::float(size as usize), MAX_CONFIDENCE)]
            }
            Intrinsic::Fclass(_) => {
                vec![Conf::new(Type::int(4, false), MIN_CONFIDENCE)]
            }
            Intrinsic::FcvtFToI(_, size, _) => {
                vec![Conf::new(Type::int(size as usize, true), MAX_CONFIDENCE)]
            }
            Intrinsic::FcvtFToU(_, size, _) => {
                vec![Conf::new(Type::int(size as usize, false), MAX_CONFIDENCE)]
            }
        }
    }
}

struct RiscVArch<D: 'static + RiscVDisassembler + Send + Sync> {
    handle: CoreArchitecture,
    custom_handle: CustomArchitectureHandle<RiscVArch<D>>,
    _dis: PhantomData<D>,
}

impl<D: 'static + RiscVDisassembler + Send + Sync> architecture::Architecture for RiscVArch<D> {
    type Handle = CustomArchitectureHandle<Self>;

    type RegisterInfo = Register<D>;
    type Register = Register<D>;
    type RegisterStackInfo = UnusedRegisterStackInfo<Self::Register>;
    type RegisterStack = UnusedRegisterStack<Self::Register>;

    type Flag = UnusedFlag;
    type FlagWrite = UnusedFlag;
    type FlagClass = UnusedFlag;
    type FlagGroup = UnusedFlag;

    type Intrinsic = RiscVIntrinsic<D>;

    fn endianness(&self) -> binaryninja::Endianness {
        binaryninja::Endianness::LittleEndian
    }

    fn address_size(&self) -> usize {
        <D::RegFile as RegFile>::Int::width()
    }

    fn default_integer_size(&self) -> usize {
        <D::RegFile as RegFile>::Int::width()
    }

    fn instruction_alignment(&self) -> usize {
        use riscv_dis::StandardExtension;

        if D::CompressedExtension::supported() {
            2
        } else {
            4
        }
    }

    fn max_instr_len(&self) -> usize {
        4
    }

    fn opcode_display_len(&self) -> usize {
        self.max_instr_len()
    }

    fn associated_arch_by_addr(&self, _addr: u64) -> CoreArchitecture {
        self.handle
    }

    fn instruction_info(&self, data: &[u8], addr: u64) -> Option<InstructionInfo> {
        let (inst_len, op) = match D::decode(addr, data) {
            Ok(Instr::Rv16(op)) => (2, op),
            Ok(Instr::Rv32(op)) => (4, op),
            _ => return None,
        };

        let mut res = InstructionInfo::new(inst_len, 0);

        match op {
            Op::Jal(ref j) => {
                let target = addr.wrapping_add(j.imm() as i64 as u64);

                let branch = if j.rd().id() == 0 {
                    BranchKind::Unconditional(target)
                } else {
                    BranchKind::Call(target)
                };

                res.add_branch(branch);
            }
            Op::Jalr(ref i) => {
                // TODO handle the calls with rs1 == 0?
                if i.rd().id() == 0 {
                    let branch_type = if i.rs1().id() == 1 {
                        BranchKind::FunctionReturn
                    } else {
                        BranchKind::Unresolved
                    };

                    res.add_branch(branch_type);
                }
            }
            Op::Beq(ref b)
            | Op::Bne(ref b)
            | Op::Blt(ref b)
            | Op::Bge(ref b)
            | Op::BltU(ref b)
            | Op::BgeU(ref b) => {
                res.add_branch(BranchKind::False(addr.wrapping_add(inst_len as u64)));
                res.add_branch(BranchKind::True(addr.wrapping_add(b.imm() as i64 as u64)));
            }
            Op::Ecall => {
                res.add_branch(BranchKind::SystemCall);
            }
            Op::Ebreak => {
                // TODO is this valid, or should lifting handle this?
                res.add_branch(BranchKind::Unresolved);
            }
            Op::Uret | Op::Sret | Op::Mret => {
                res.add_branch(BranchKind::FunctionReturn);
            }
            _ => {}
        }

        Some(res)
    }

    fn instruction_text(
        &self,
        data: &[u8],
        addr: u64,
    ) -> Option<(usize, Vec<InstructionTextToken>)> {
        use riscv_dis::Operand;
        use InstructionTextTokenKind::*;

        let inst = match D::decode(addr, data) {
            Ok(i) => i,
            _ => return None,
        };

        let (inst_len, op) = match inst {
            Instr::Rv16(op) => (2, op),
            Instr::Rv32(op) => (4, op),
        };

        let mut res = Vec::new();
        let mut mnem = format!("{}", inst.mnem());
        let mut pad_len = 8usize.saturating_sub(mnem.len());
        let mut operands = inst.operands();

        // Handle pseudo-instructions. Only single instruction pseudo-instructions are handled.
        match op {
            Op::AddI(i) => {
                // addi zero, zero, 0 => nop
                if i.rd().id() == 0 && i.rs1().id() == 0 && i.imm() == 0 {
                    mnem = "nop".into();
                    pad_len = 8usize.saturating_sub(mnem.len());
                    operands.clear();
                }
                // addi rd, zero, imm => li rd, imm
                else if i.rs1().id() == 0 {
                    mnem = "li".into();
                    pad_len = 8usize.saturating_sub(mnem.len());
                    operands.remove(1);
                }
                // addi rd, rs, 0 => mv rd, rs
                else if i.imm() == 0 {
                    mnem = "mv".into();
                    pad_len = 8usize.saturating_sub(mnem.len());
                    operands.remove(2);
                }
            }
            Op::AddIW(i) => {
                // addiw rd, rs, 0 => sext.w rd, rs
                if i.imm() == 0 {
                    mnem = "sext.w".into();
                    pad_len = 8usize.saturating_sub(mnem.len());
                    operands.remove(2);
                }
            }
            Op::Beq(i) => {
                // beq rs, zero, offset => beqz rs, offset
                if i.rs2().id() == 0 {
                    mnem = "beqz".into();
                    pad_len = 8usize.saturating_sub(mnem.len());
                    operands.remove(1);
                }
            }
            Op::Bne(i) => {
                // bne rs, zero, offset => bnez rs, offset
                if i.rs2().id() == 0 {
                    mnem = "bnez".into();
                    pad_len = 8usize.saturating_sub(mnem.len());
                    operands.remove(1);
                }
            }
            Op::Bge(i) => {
                // bge zero, rs, offset => blez rs, offset
                if i.rs1().id() == 0 {
                    mnem = "blez".into();
                    pad_len = 8usize.saturating_sub(mnem.len());
                    operands.remove(0);
                }
                // bge rs, zero, offset => bgez rs, offset
                else if i.rs2().id() == 0 {
                    mnem = "bgez".into();
                    pad_len = 8usize.saturating_sub(mnem.len());
                    operands.remove(1);
                }
            }
            Op::Blt(i) => {
                // blt zero, rs, offset => bgtz rs, offset
                if i.rs1().id() == 0 {
                    mnem = "bgtz".into();
                    pad_len = 8usize.saturating_sub(mnem.len());
                    operands.remove(0);
                }
                // blt rs, zero, offset => bltz rs, offset
                else if i.rs2().id() == 0 {
                    mnem = "bltz".into();
                    pad_len = 8usize.saturating_sub(mnem.len());
                    operands.remove(1);
                }
            }
            Op::Jal(i) => {
                // jal zero, offset => j offset
                if i.rd().id() == 0 {
                    mnem = "j".into();
                    pad_len = 8usize.saturating_sub(mnem.len());
                    operands.remove(0);
                }
                // jal ra, offset => jal offset
                else if i.rd().id() == 0 {
                    operands.remove(0);
                }
            }
            Op::Jalr(i) => {
                // jalr zero, ra, 0 => ret
                if i.rd().id() == 0 && i.rs1().id() == 1 && i.imm() == 0 {
                    mnem = "ret".into();
                    pad_len = 8usize.saturating_sub(mnem.len());
                    operands.clear();
                }
                // jalr zero, rs, 0 => jr rs
                else if i.rd().id() == 0 && i.imm() == 0 {
                    mnem = "jr".into();
                    pad_len = 8usize.saturating_sub(mnem.len());
                    operands.remove(2);
                    operands.remove(0);
                }
                // jalr ra, rs, 0 => jalr rs
                else if i.rd().id() == 1 && i.imm() == 0 {
                    mnem = "jalr".into();
                    pad_len = 8usize.saturating_sub(mnem.len());
                    operands.remove(2);
                    operands.remove(0);
                }
            }
            Op::Slt(i) => {
                // slt rd, rs, zero => sltz rd, rs
                if i.rs2().id() == 0 {
                    mnem = "sltz".into();
                    pad_len = 8usize.saturating_sub(mnem.len());
                    operands.remove(2);
                }
                // slt rd, zero, rs => sgtz rd, rs
                else if i.rs1().id() == 0 {
                    mnem = "sgtz".into();
                    pad_len = 8usize.saturating_sub(mnem.len());
                    operands.remove(1);
                }
            }
            Op::SltU(i) => {
                // sltu rd, zero, rs => snez rd, rs
                if i.rs1().id() == 0 {
                    mnem = "snez".into();
                    pad_len = 8usize.saturating_sub(mnem.len());
                    operands.remove(1);
                }
            }
            Op::SltIU(i) => {
                // sltiu rd, rs, 1 => seqz rd, rs
                if i.imm() == 1 {
                    mnem = "seqz".into();
                    pad_len = 8usize.saturating_sub(mnem.len());
                    operands.remove(2);
                }
            }
            Op::Sub(i) => {
                // sub rd, zero, rs => neg rd, rs
                if i.rs1().id() == 0 {
                    mnem = "neg".into();
                    pad_len = 8usize.saturating_sub(mnem.len());
                    operands.remove(1);
                }
            }
            Op::SubW(i) => {
                // subw rd, zero, rs => negw rd, rs
                if i.rs1().id() == 0 {
                    mnem = "negw".into();
                    pad_len = 8usize.saturating_sub(mnem.len());
                    operands.remove(1);
                }
            }
            Op::XorI(i) => {
                // xori rd, rs, -1 => not rd, rs
                if i.imm() == -1 {
                    mnem = "not".into();
                    pad_len = 8usize.saturating_sub(mnem.len());
                    operands.remove(2);
                }
            }
            Op::Fsgnj(i) => {
                // fsgnj rd, rs, rs => fmv rd, rs
                if i.rs1().id() == i.rs2().id() {
                    mnem = match i.width() {
                        4 => "fmv.s".into(),
                        8 => "fmv.d".into(),
                        16 => "fmv.q".into(),
                        _ => unreachable!(),
                    };
                    pad_len = 8usize.saturating_sub(mnem.len());
                    operands.remove(2);
                }
            }
            Op::Fsgnjn(i) => {
                // fsgnjn rd, rs, rs => fneg rd, rs
                if i.rs1().id() == i.rs2().id() {
                    mnem = match i.width() {
                        4 => "fneg.s".into(),
                        8 => "fneg.d".into(),
                        16 => "fneg.q".into(),
                        _ => unreachable!(),
                    };
                    pad_len = 8usize.saturating_sub(mnem.len());
                    operands.remove(2);
                }
            }
            Op::Fsgnjx(i) => {
                // fsgnjx rd, rs, rs => fabs rd, rs
                if i.rs1().id() == i.rs2().id() {
                    mnem = match i.width() {
                        4 => "fabs.s".into(),
                        8 => "fabs.d".into(),
                        16 => "fabs.q".into(),
                        _ => unreachable!(),
                    };
                    pad_len = 8usize.saturating_sub(mnem.len());
                    operands.remove(2);
                }
            }
            _ => (),
        }

        res.push(InstructionTextToken::new(&mnem, Instruction));

        for (i, oper) in operands.iter().enumerate() {
            if i == 0 {
                res.push(InstructionTextToken::new(
                    &format!("{:1$}", " ", pad_len),
                    Text,
                ));
            } else {
                res.push(InstructionTextToken::new(",", OperandSeparator));
                res.push(InstructionTextToken::new(" ", Text));
            }

            match *oper {
                Operand::R(r) => {
                    let reg = self::Register::from(r);

                    res.push(InstructionTextToken::new(reg.name(), Register));
                }
                Operand::F(r) => {
                    let reg = self::Register::from(r);

                    res.push(InstructionTextToken::new(reg.name(), Register));
                }
                Operand::I(i) => {
                    match op {
                        Op::Beq(..)
                        | Op::Bne(..)
                        | Op::Blt(..)
                        | Op::Bge(..)
                        | Op::BltU(..)
                        | Op::BgeU(..)
                        | Op::Jal(..) => {
                            // BRANCH or JAL
                            let target = addr.wrapping_add(i as i64 as u64);

                            res.push(InstructionTextToken::new(
                                format!("0x{:x}", target),
                                CodeRelativeAddress {
                                    value: target,
                                    size: Some(self.address_size()),
                                },
                            ));
                        }
                        _ => {
                            res.push(InstructionTextToken::new(
                                &match i {
                                    -0x8_0000..=-1 => format!("-0x{:x}", -i),
                                    _ => format!("0x{:x}", i),
                                },
                                Integer {
                                    value: i as u64,
                                    size: None,
                                },
                            ));
                        }
                    }
                }
                Operand::M(i, b) => {
                    let reg = self::Register::from(b);

                    res.push(InstructionTextToken::new("", BeginMemoryOperand));
                    res.push(InstructionTextToken::new(
                        &if i < 0 {
                            format!("-0x{:x}", -i)
                        } else {
                            format!("0x{:x}", i)
                        },
                        Integer {
                            value: i as u64,
                            size: None,
                        },
                    ));

                    res.push(InstructionTextToken::new("(", Brace { hash: None }));
                    res.push(InstructionTextToken::new(reg.name(), Register));
                    res.push(InstructionTextToken::new(")", Brace { hash: None }));
                    res.push(InstructionTextToken::new("", EndMemoryOperand));
                }
                Operand::RM(r) => {
                    res.push(InstructionTextToken::new(r.name(), Register));
                }
            }
        }

        Some((inst_len, res))
    }

    fn instruction_llil(
        &self,
        data: &[u8],
        addr: u64,
        il: &mut MutableLiftedILFunction<Self>,
    ) -> Option<(usize, bool)> {
        let max_width = self.default_integer_size();

        let (inst_len, op) = match D::decode(addr, data) {
            Ok(Instr::Rv16(op)) => (2, op),
            Ok(Instr::Rv32(op)) => (4, op),
            _ => return None,
        };

        macro_rules! set_reg_or_append_fallback {
            ($op:ident, $t:expr, $f:expr) => {{
                let rd = Register::from($op.rd());
                match rd.id.0 {
                    0 => $f.append(),
                    _ => il.set_reg(rd.size(), rd, $t).append(),
                }
            }};
        }

        macro_rules! simple_op {
            ($op:ident, no_discard $f:expr) => {{
                let expr = $f;
                set_reg_or_append_fallback!($op, expr, expr)
            }};
            ($op:ident, $f:expr) => {
                set_reg_or_append_fallback!($op, $f, il.nop())
            };
        }

        macro_rules! simple_i {
            ($i:ident, $f:expr ) => {{
                let rs1 = Register::from($i.rs1());
                simple_op!($i, $f(rs1, $i.imm()))
            }};
        }

        macro_rules! simple_r {
            ($r:ident, $f:expr ) => {{
                let rs1 = Register::from($r.rs1());
                let rs2 = Register::from($r.rs2());
                simple_op!($r, $f(rs1, rs2))
            }};
        }

        match op {
            Op::Load(l) => simple_op!(l, no_discard {
                let size = l.width();
                let rs1 = Register::from(l.rs1());

                let src_expr = il.add(max_width, rs1, l.imm());
                let load_expr = il.load(size, src_expr)
                                  .with_source_operand(1);

                match (size < max_width, l.zx()) {
                    (false,    _) => load_expr,
                    (true,  true) => il.zx(max_width, load_expr).build(),
                    (true, false) => il.sx(max_width, load_expr).build(),
                }
            }),
            Op::Store(s) => {
                let size = s.width();
                let dest = il.add(max_width, Register::from(s.rs1()), s.imm());
                let mut src = il
                    .expression(Register::from(s.rs2()))
                    .with_source_operand(0);

                if size < max_width {
                    src = il.low_part(size, src).build();
                }

                il.store(size, dest, src).with_source_operand(1).append();
            }

            Op::AddI(i) => simple_i!(i, |rs1, imm| il.add(max_width, rs1, imm)),
            Op::SltI(i) => simple_i!(i, |rs1, imm| il
                .bool_to_int(max_width, il.cmp_slt(max_width, rs1, imm))),
            Op::SltIU(i) => simple_i!(i, |rs1, imm| il
                .bool_to_int(max_width, il.cmp_ult(max_width, rs1, imm))),
            Op::XorI(i) => simple_i!(i, |rs1, imm| il.xor(max_width, rs1, imm)),
            Op::OrI(i) => simple_i!(i, |rs1, imm| il.or(max_width, rs1, imm)),
            Op::AndI(i) => simple_i!(i, |rs1, imm| il.and(max_width, rs1, imm)),
            Op::SllI(i) => simple_i!(i, |rs1, imm| il.lsl(max_width, rs1, imm)),
            Op::SrlI(i) => simple_i!(i, |rs1, imm| il.lsr(max_width, rs1, imm)),
            Op::SraI(i) => simple_i!(i, |rs1, imm| il.asr(max_width, rs1, imm)),

            // r-type
            Op::Add(r) => simple_r!(r, |rs1, rs2| il.add(max_width, rs1, rs2)),
            Op::Sll(r) => simple_r!(r, |rs1, rs2| il.lsl(max_width, rs1, rs2)),
            Op::Slt(r) => simple_r!(r, |rs1, rs2| il
                .bool_to_int(max_width, il.cmp_slt(max_width, rs1, rs2))),
            Op::SltU(r) => simple_r!(r, |rs1, rs2| il
                .bool_to_int(max_width, il.cmp_ult(max_width, rs1, rs2))),
            Op::Xor(r) => simple_r!(r, |rs1, rs2| il.xor(max_width, rs1, rs2)),
            Op::Srl(r) => simple_r!(r, |rs1, rs2| il.lsr(max_width, rs1, rs2)),
            Op::Or(r) => simple_r!(r, |rs1, rs2| il.or(max_width, rs1, rs2)),
            Op::And(r) => simple_r!(r, |rs1, rs2| il.and(max_width, rs1, rs2)),
            Op::Sub(r) => simple_r!(r, |rs1, rs2| il.sub(max_width, rs1, rs2)),
            Op::Sra(r) => simple_r!(r, |rs1, rs2| il.asr(max_width, rs1, rs2)),

            // i-type 32-bit
            Op::AddIW(i) => simple_i!(i, |rs1, imm| il.sx(max_width, il.add(4, rs1, imm))),
            Op::SllIW(i) => simple_i!(i, |rs1, imm| il.sx(max_width, il.lsl(4, rs1, imm))),
            Op::SrlIW(i) => simple_i!(i, |rs1, imm| il.sx(max_width, il.lsr(4, rs1, imm))),
            Op::SraIW(i) => simple_i!(i, |rs1, imm| il.sx(max_width, il.asr(4, rs1, imm))),

            // r-type 32-bit
            Op::AddW(r) => simple_r!(r, |rs1, rs2| il.sx(max_width, il.add(4, rs1, rs2))),
            Op::SllW(r) => simple_r!(r, |rs1, rs2| il.sx(max_width, il.lsl(4, rs1, rs2))),
            Op::SrlW(r) => simple_r!(r, |rs1, rs2| il.sx(max_width, il.lsr(4, rs1, rs2))),
            Op::SubW(r) => simple_r!(r, |rs1, rs2| il.sx(max_width, il.sub(4, rs1, rs2))),
            Op::SraW(r) => simple_r!(r, |rs1, rs2| il.sx(max_width, il.asr(4, rs1, rs2))),

            Op::Mul(r) => simple_r!(r, |rs1, rs2| il.mul(max_width, rs1, rs2)),
            Op::MulH(r) => simple_r!(r, |rs1, rs2| {
                let extended_width = max_width * 2;
                let extended_rs1 = il.sx(extended_width, rs1);
                let extended_rs2 = il.sx(extended_width, rs2);
                let mul_expr = il.mul(extended_width, extended_rs1, extended_rs2);
                il.asr(max_width, mul_expr, il.const_int(1, 8 * (max_width as u64)))
            }),
            Op::MulHU(r) => simple_r!(r, |rs1, rs2| {
                let extended_width = max_width * 2;
                let extended_rs1 = il.zx(extended_width, rs1);
                let extended_rs2 = il.zx(extended_width, rs2);
                let mul_expr = il.mul(extended_width, extended_rs1, extended_rs2);
                il.lsr(max_width, mul_expr, il.const_int(1, 8 * (max_width as u64)))
            }),
            Op::MulHSU(r) => simple_r!(r, |rs1, rs2| {
                let extended_width = max_width * 2;
                let extended_rs1 = il.sx(extended_width, rs1);
                let extended_rs2 = il.zx(extended_width, rs2);
                let mul_expr = il.mul(extended_width, extended_rs1, extended_rs2);
                il.asr(max_width, mul_expr, il.const_int(1, 8 * (max_width as u64)))
            }),

            Op::Div(r) => simple_r!(r, |rs1, rs2| il.divs(max_width, rs1, rs2)),
            Op::DivU(r) => simple_r!(r, |rs1, rs2| il.divu(max_width, rs1, rs2)),
            Op::Rem(r) => simple_r!(r, |rs1, rs2| il.mods(max_width, rs1, rs2)),
            Op::RemU(r) => simple_r!(r, |rs1, rs2| il.modu(max_width, rs1, rs2)),

            Op::MulW(r) => simple_r!(r, |rs1, rs2| il.sx(max_width, il.mul(4, rs1, rs2))),
            Op::DivW(r) => simple_r!(r, |rs1, rs2| il.sx(max_width, il.divs(4, rs1, rs2))),
            Op::DivUW(r) => simple_r!(r, |rs1, rs2| il.sx(max_width, il.divu(4, rs1, rs2))),
            Op::RemW(r) => simple_r!(r, |rs1, rs2| il.sx(max_width, il.mods(4, rs1, rs2))),
            Op::RemUW(r) => simple_r!(r, |rs1, rs2| il.sx(max_width, il.modu(4, rs1, rs2))),

            Op::Lui(u) => simple_op!(u, il.const_int(max_width, u.imm() as i64 as u64)),
            Op::Auipc(u) => simple_op!(u, il.const_ptr(addr.wrapping_add(u.imm() as i64 as u64))),

            Op::Jal(j) => {
                let target = addr.wrapping_add(j.imm() as i64 as u64);

                match (j.rd().id(), il.label_for_address(target)) {
                    (0, Some(mut l)) => il.goto(&mut l),
                    (0, None) => il.jump(il.const_ptr(target)),
                    (_, _) => il.call(il.const_ptr(target)),
                }
                .append();
            }
            Op::Jalr(i) => {
                let rd = i.rd();
                let rs1 = i.rs1();
                let imm = i.imm();

                let target = il.add(max_width, Register::from(rs1), imm).build();

                match (rd.id(), rs1.id(), imm) {
                    (0, 1, 0) => il.ret(target).append(),  // jalr zero, ra, 0
                    (1, _, _) => il.call(target).append(), // indirect call
                    (0, _, _) => il.jump(target).append(), // indirect jump
                    (rd_id, rs1_id, _) if rd_id == rs1_id => {
                        // store the target in a temporary register so we don't clobber it when rd == rs1
                        let tmp_reg: LowLevelILRegister<Register<D>> = LowLevelILRegister::Temp(0);
                        il.set_reg(max_width, tmp_reg, target).append();
                        // indirect jump with storage of next address to non-`ra` register
                        il.set_reg(
                            max_width,
                            Register::from(rd),
                            il.const_ptr(addr.wrapping_add(inst_len)),
                        )
                        .append();
                        il.jump(tmp_reg).append();
                    }
                    (_, _, _) => {
                        // indirect jump with storage of next address to non-`ra` register
                        il.set_reg(
                            max_width,
                            Register::from(rd),
                            il.const_ptr(addr.wrapping_add(inst_len)),
                        )
                        .append();
                        il.jump(target).append();
                    }
                }
            }

            Op::Beq(b) | Op::Bne(b) | Op::Blt(b) | Op::Bge(b) | Op::BltU(b) | Op::BgeU(b) => {
                let left = Register::from(b.rs1());
                let right = Register::from(b.rs2());

                let cond_expr = match op {
                    Op::Beq(..) => il.cmp_e(max_width, left, right),
                    Op::Bne(..) => il.cmp_ne(max_width, left, right),
                    Op::Blt(..) => il.cmp_slt(max_width, left, right),
                    Op::Bge(..) => il.cmp_sge(max_width, left, right),
                    Op::BltU(..) => il.cmp_ult(max_width, left, right),
                    Op::BgeU(..) => il.cmp_uge(max_width, left, right),
                    _ => unreachable!(),
                };

                let mut new_false = false;
                let mut new_true = false;

                let ft = addr.wrapping_add(inst_len);
                let tt = addr.wrapping_add(b.imm() as i64 as u64);

                let mut f = il.label_for_address(ft).unwrap_or_else(|| {
                    new_false = true;
                    LowLevelILLabel::new()
                });

                let mut t = il.label_for_address(tt).unwrap_or_else(|| {
                    new_true = true;
                    LowLevelILLabel::new()
                });

                il.if_expr(cond_expr, &mut t, &mut f).append();

                if new_true {
                    il.mark_label(&mut t);
                    il.jump(il.const_ptr(tt)).append();
                }

                if new_false {
                    il.mark_label(&mut f);
                }
            }

            Op::Ecall => il.syscall().append(),
            Op::Ebreak => il.bp().append(),
            Op::Uret => {
                il.intrinsic(
                    MutableLiftedILFunction::<Self>::NO_OUTPUTS,
                    Intrinsic::Uret,
                    MutableLiftedILFunction::<Self>::NO_INPUTS,
                )
                .append();
                il.no_ret().append();
            }
            Op::Sret => {
                il.intrinsic(
                    MutableLiftedILFunction::<Self>::NO_OUTPUTS,
                    Intrinsic::Sret,
                    MutableLiftedILFunction::<Self>::NO_INPUTS,
                )
                .append();
                il.no_ret().append();
            }
            Op::Mret => {
                il.intrinsic(
                    MutableLiftedILFunction::<Self>::NO_OUTPUTS,
                    Intrinsic::Mret,
                    MutableLiftedILFunction::<Self>::NO_INPUTS,
                )
                .append();
                il.no_ret().append();
            }
            Op::Wfi => il
                .intrinsic(
                    MutableLiftedILFunction::<Self>::NO_OUTPUTS,
                    Intrinsic::Wfi,
                    MutableLiftedILFunction::<Self>::NO_INPUTS,
                )
                .append(),
            Op::Fence(i) => il
                .intrinsic(
                    MutableLiftedILFunction::<Self>::NO_OUTPUTS,
                    Intrinsic::Fence,
                    [il.const_int(4, i.imm() as u32 as u64)],
                )
                .append(),

            Op::Csrrw(i) => {
                let rd = Register::from(i.rd());
                let rs1 = LiftableLowLevelIL::lift(il, Register::from(i.rs1()));
                let csr = il.const_int(4, i.csr() as u64);

                if i.rd().id() == 0 {
                    il.intrinsic(
                        MutableLiftedILFunction::<Self>::NO_OUTPUTS,
                        Intrinsic::Csrwr,
                        [csr, rs1],
                    )
                    .append();
                } else {
                    il.intrinsic([rd], Intrinsic::Csrrw, [rs1]).append();
                }
            }
            Op::Csrrs(i) => {
                let rd = Register::from(i.rd());
                let rs1 = LiftableLowLevelIL::lift(il, Register::from(i.rs1()));
                let csr = il.const_int(4, i.csr() as u64);

                if i.rs1().id() == 0 {
                    il.intrinsic([rd], Intrinsic::Csrrd, [csr]).append();
                } else {
                    il.intrinsic([rd], Intrinsic::Csrrs, [csr, rs1]).append();
                }
            }
            Op::Csrrc(i) => {
                let rd = Register::from(i.rd());
                let rs1 = LiftableLowLevelIL::lift(il, Register::from(i.rs1()));
                let csr = il.const_int(4, i.csr() as u64);

                if i.rs1().id() == 0 {
                    il.intrinsic([rd], Intrinsic::Csrrd, [csr]).append();
                } else {
                    il.intrinsic([rd], Intrinsic::Csrrc, [csr, rs1]).append();
                }
            }
            Op::CsrrwI(i) => {
                let rd = Register::from(i.rd());
                let csr = il.const_int(4, i.csr() as u64);
                let imm = il.const_int(max_width, i.imm() as u64);

                if i.rd().id() == 0 {
                    il.intrinsic(
                        MutableLiftedILFunction::<Self>::NO_OUTPUTS,
                        Intrinsic::Csrwr,
                        [csr, imm],
                    )
                    .append();
                } else {
                    il.intrinsic([rd], Intrinsic::Csrrw, [csr, imm]).append();
                }
            }
            Op::CsrrsI(i) => {
                let rd = Register::from(i.rd());
                let csr = il.const_int(4, i.csr() as u64);
                let imm = il.const_int(max_width, i.imm() as u64);

                if i.imm() == 0 {
                    il.intrinsic([rd], Intrinsic::Csrrd, [csr]).append();
                } else {
                    il.intrinsic([rd], Intrinsic::Csrrs, [csr, imm]).append();
                }
            }
            Op::CsrrcI(i) => {
                let rd = Register::from(i.rd());
                let csr = il.const_int(4, i.csr() as u64);
                let imm = il.const_int(max_width, i.imm() as u64);

                if i.imm() == 0 {
                    il.intrinsic([rd], Intrinsic::Csrrd, [csr]).append();
                } else {
                    il.intrinsic([rd], Intrinsic::Csrrc, [csr, imm]).append();
                }
            }

            Op::Lr(a) => simple_op!(a, no_discard {
                let size = a.width();
                let load_expr = il.load(size, Register::from(a.rs1()))
                                  .with_source_operand(1);

                match size == max_width {
                    true  => load_expr,
                    false => il.sx(max_width, load_expr).build(),
                }
            }),
            Op::Sc(a) => {
                let size = a.width();
                let rd = a.rd();

                let dest_reg = match rd.id() {
                    0 => LowLevelILRegister::Temp(0),
                    _ => Register::from(rd).into(),
                };

                // set rd (or a temp register) to an indeterminate value,
                // which signals to the application whether the conditional
                // store was successful. by clobbering first, we can then
                // emit conditionals based on its value to lift the conditional
                // nature of the store -- dataflow will give up
                il.set_reg(max_width, dest_reg, il.unimplemented()).append();

                let mut new_false = false;
                let mut t = LowLevelILLabel::new();

                let cond_expr = il.cmp_e(max_width, dest_reg, 0u64);

                let ft = addr.wrapping_add(inst_len);
                let mut f = il.label_for_address(ft).unwrap_or_else(|| {
                    new_false = true;
                    LowLevelILLabel::new()
                });

                il.if_expr(cond_expr, &mut t, &mut f).append();

                il.mark_label(&mut t);
                il.store(size, Register::from(a.rs1()), Register::from(a.rs2()))
                    .with_source_operand(2)
                    .append();

                if new_false {
                    il.mark_label(&mut f);
                }
            }
            Op::AmoSwap(a)
            | Op::AmoAdd(a)
            | Op::AmoXor(a)
            | Op::AmoAnd(a)
            | Op::AmoOr(a)
            | Op::AmoMin(a)
            | Op::AmoMax(a)
            | Op::AmoMinU(a)
            | Op::AmoMaxU(a) => {
                let size = a.width();
                let rd = a.rd();
                let rs1 = a.rs1();
                let rs2 = a.rs2();

                let dest_reg = match rd.id() {
                    0 => LowLevelILRegister::Temp(0),
                    _ => Register::from(rd).into(),
                };

                let mut next_temp_reg = 1;
                let mut alloc_reg = |rs: riscv_dis::IntReg<D>| match (rs.id(), rd.id()) {
                    (id, r) if id != 0 && id == r => {
                        let reg = LowLevelILRegister::Temp(next_temp_reg);
                        next_temp_reg += 1;

                        il.set_reg(max_width, reg, Register::from(rs)).append();

                        reg
                    }
                    _ => Register::from(rs).into(),
                };

                let reg_with_address = alloc_reg(rs1);
                let reg_with_val = alloc_reg(rs2);

                let mut load_expr = il.load(size, Register::from(rs1)).with_source_operand(2);

                if size < max_width {
                    load_expr = il.sx(max_width, load_expr).build();
                }

                il.set_reg(max_width, dest_reg, load_expr).append();

                let val_expr = LiftableLowLevelILWithSize::lift_with_size(il, reg_with_val, size);
                let dest_reg_val = LiftableLowLevelILWithSize::lift_with_size(il, dest_reg, size);

                let val_to_store = match op {
                    Op::AmoSwap(..) => val_expr,
                    Op::AmoAdd(..) => il.add(size, dest_reg_val, val_expr).build(),
                    Op::AmoXor(..) => il.xor(size, dest_reg_val, val_expr).build(),
                    Op::AmoAnd(..) => il.and(size, dest_reg_val, val_expr).build(),
                    Op::AmoOr(..) => il.or(size, dest_reg_val, val_expr).build(),
                    Op::AmoMin(..) | Op::AmoMax(..) | Op::AmoMinU(..) | Op::AmoMaxU(..) => {
                        il.unimplemented()
                    }
                    _ => unreachable!(),
                };

                il.store(size, reg_with_address, val_to_store).append()
            }

            Op::LoadFp(m) => {
                let rd = Register::from(m.fr());
                let rs1 = Register::from(m.rs1());

                let load_expr = il
                    .load(m.width(), il.add(max_width, rs1, m.imm()))
                    .with_source_operand(1);

                il.set_reg(m.width(), rd, load_expr).append();
            }
            Op::StoreFp(m) => {
                let rs1 = Register::from(m.rs1());
                let rs2 = Register::from(m.fr());

                let dest_expr = il.add(max_width, rs1, m.imm());

                il.store(m.width(), dest_expr, il.reg(m.width(), rs2))
                    .with_source_operand(1)
                    .append();
            }
            Op::Fmadd(f) | Op::Fmsub(f) | Op::Fnmadd(f) | Op::Fnmsub(f) => {
                let rd = Register::from(f.rd());
                let rs1 = Register::from(f.rs1());
                let rs2 = Register::from(f.rs2());
                let rs3 = Register::from(f.rs2());
                let width = f.width() as usize;
                if f.rm() == RoundMode::Dynamic {
                    let product = il.fmul(width, il.reg(width, rs1), il.reg(width, rs2));
                    let result = match op {
                        Op::Fmadd(..) => il.fadd(width, product, il.reg(width, rs3)),
                        Op::Fmsub(..) => il.fsub(width, product, il.reg(width, rs3)),
                        Op::Fnmadd(..) => {
                            il.fsub(width, il.fneg(width, product), il.reg(width, rs3))
                        }
                        Op::Fnmsub(..) => {
                            il.fadd(width, il.fneg(width, product), il.reg(width, rs3))
                        }
                        _ => unreachable!(),
                    };
                    il.set_reg(width, rd, result).append();
                } else {
                    let product = LowLevelILRegister::Temp(0);
                    il.intrinsic(
                        [product],
                        Intrinsic::Fmul(f.width(), f.rm()),
                        [il.reg(width, rs1), il.reg(width, rs2)],
                    )
                    .append();
                    match op {
                        Op::Fmadd(..) => il
                            .intrinsic(
                                [rd],
                                Intrinsic::Fmul(f.width(), f.rm()),
                                [il.reg(width, product), il.reg(width, rs3)],
                            )
                            .append(),
                        Op::Fmsub(..) => il
                            .intrinsic(
                                [rd],
                                Intrinsic::Fsub(f.width(), f.rm()),
                                [il.reg(width, product), il.reg(width, rs3)],
                            )
                            .append(),
                        Op::Fnmadd(..) => il
                            .intrinsic(
                                [rd],
                                Intrinsic::Fsub(f.width(), f.rm()),
                                [
                                    il.fneg(width, il.reg(width, product)).build(),
                                    il.reg(width, rs3),
                                ],
                            )
                            .append(),
                        Op::Fnmsub(..) => il
                            .intrinsic(
                                [rd],
                                Intrinsic::Fadd(f.width(), f.rm()),
                                [
                                    il.fneg(width, il.reg(width, product)).build(),
                                    il.reg(width, rs3),
                                ],
                            )
                            .append(),
                        _ => unreachable!(),
                    };
                }
            }
            Op::Fadd(f) | Op::Fsub(f) | Op::Fmul(f) | Op::Fdiv(f) => {
                let rd = Register::from(f.rd());
                let rs1 = Register::from(f.rs1());
                let rs2 = Register::from(f.rs2());
                let width = f.width() as usize;
                if f.rm() == RoundMode::Dynamic {
                    let result = match op {
                        Op::Fadd(..) => il.fadd(width, il.reg(width, rs1), il.reg(width, rs2)),
                        Op::Fsub(..) => il.fsub(width, il.reg(width, rs1), il.reg(width, rs2)),
                        Op::Fmul(..) => il.fmul(width, il.reg(width, rs1), il.reg(width, rs2)),
                        Op::Fdiv(..) => il.fdiv(width, il.reg(width, rs1), il.reg(width, rs2)),
                        _ => unreachable!(),
                    };
                    il.set_reg(width, rd, result).append();
                } else {
                    let intrinsic = match op {
                        Op::Fadd(..) => Intrinsic::Fadd(f.width(), f.rm()),
                        Op::Fsub(..) => Intrinsic::Fsub(f.width(), f.rm()),
                        Op::Fmul(..) => Intrinsic::Fmul(f.width(), f.rm()),
                        Op::Fdiv(..) => Intrinsic::Fdiv(f.width(), f.rm()),
                        _ => unreachable!(),
                    };
                    il.intrinsic([rd], intrinsic, [il.reg(width, rs1), il.reg(width, rs2)])
                        .append();
                }
            }
            Op::Fsgnj(f) => {
                let rd = Register::from(f.rd());
                let rs1 = Register::from(f.rs1());
                let rs2 = Register::from(f.rs2());
                let width = f.width() as usize;
                if f.rs1().id() == f.rs2().id() {
                    il.set_reg(width, rd, il.reg(width, rs1)).append();
                } else {
                    il.intrinsic(
                        [rd],
                        Intrinsic::Fsgnj(f.width()),
                        [il.reg(width, rs1), il.reg(width, rs2)],
                    )
                    .append();
                }
            }
            Op::Fsgnjn(f) => {
                let rd = Register::from(f.rd());
                let rs1 = Register::from(f.rs1());
                let rs2 = Register::from(f.rs2());
                let width = f.width() as usize;
                if f.rs1().id() == f.rs2().id() {
                    il.set_reg(width, rd, il.fneg(width, il.reg(width, rs1)))
                        .append();
                } else {
                    il.intrinsic(
                        [rd],
                        Intrinsic::Fsgnjn(f.width()),
                        [il.reg(width, rs1), il.reg(width, rs2)],
                    )
                    .append();
                }
            }
            Op::Fsgnjx(f) => {
                let rd = Register::from(f.rd());
                let rs1 = Register::from(f.rs1());
                let rs2 = Register::from(f.rs2());
                let width = f.width() as usize;
                if f.rs1().id() == f.rs2().id() {
                    il.set_reg(width, rd, il.fabs(width, il.reg(width, rs1)))
                        .append();
                } else {
                    il.intrinsic(
                        [rd],
                        Intrinsic::Fsgnjx(f.width()),
                        [il.reg(width, rs1), il.reg(width, rs2)],
                    )
                    .append();
                }
            }
            Op::Fsqrt(f) => {
                let rd = Register::from(f.rd());
                let rs1 = Register::from(f.rs1());
                let width = f.width() as usize;
                let result = il.fsqrt(width, il.reg(width, rs1));
                il.set_reg(width, rd, result).append();
            }
            Op::Fmin(f) => {
                let rd = Register::from(f.rd());
                let rs1 = Register::from(f.rs1());
                let rs2 = Register::from(f.rs2());
                let width = f.width() as usize;
                il.intrinsic(
                    [rd],
                    Intrinsic::Fmin(f.width()),
                    [il.reg(width, rs1), il.reg(width, rs2)],
                )
                .append();
            }
            Op::Fmax(f) => {
                let rd = Register::from(f.rd());
                let rs1 = Register::from(f.rs1());
                let rs2 = Register::from(f.rs2());
                let width = f.width() as usize;
                il.intrinsic(
                    [rd],
                    Intrinsic::Fmax(f.width()),
                    [il.reg(width, rs1), il.reg(width, rs2)],
                )
                .append();
            }
            Op::Fle(f) | Op::Flt(f) | Op::Feq(f) => {
                let rd = match f.rd().id() {
                    0 => LowLevelILRegister::Temp(0),
                    _ => Register::from(f.rd()).into(),
                };
                let left = Register::from(f.rs1());
                let right = Register::from(f.rs2());
                let width = f.width() as usize;
                let cond_expr = match op {
                    Op::Fle(..) => il.fcmp_le(width, il.reg(width, left), il.reg(width, right)),
                    Op::Flt(..) => il.fcmp_lt(width, il.reg(width, left), il.reg(width, right)),
                    Op::Feq(..) => il.fcmp_e(width, il.reg(width, left), il.reg(width, right)),
                    _ => unreachable!(),
                };
                let result = il.bool_to_int(max_width, cond_expr);
                il.set_reg(max_width, rd, result).append();
            }
            Op::Fcvt(f) => {
                let rd = Register::from(f.rd());
                let rs1 = Register::from(f.rs1());
                let rd_width = f.rd_width() as usize;
                let rs1_width = f.rs1_width() as usize;
                if f.rm() == RoundMode::Dynamic {
                    let src = il.float_conv(rd_width, il.reg(rs1_width, rs1));
                    il.set_reg(rd_width, rd, src).append();
                } else {
                    il.intrinsic(
                        [rd],
                        Intrinsic::FcvtFToF(f.rs1_width(), f.rd_width(), f.rm()),
                        [il.reg(rs1_width, rs1)],
                    )
                    .append();
                }
            }
            Op::FcvtToInt(f) => {
                let rd = match f.rd().id() {
                    0 => LowLevelILRegister::Temp(0),
                    _ => Register::from(f.rd()).into(),
                };
                let rs1 = Register::from(f.rs1());
                let rd_width = f.rd_width() as usize;
                let rs1_width = f.rs1_width() as usize;
                if f.zx() {
                    il.intrinsic(
                        [rd],
                        Intrinsic::FcvtFToU(f.rs1_width(), f.rd_width(), f.rm()),
                        [il.reg(rs1_width, rs1)],
                    )
                    .append();
                } else if f.rm() != RoundMode::Dynamic {
                    il.intrinsic(
                        [rd],
                        Intrinsic::FcvtFToI(f.rs1_width(), f.rd_width(), f.rm()),
                        [il.reg(rs1_width, rs1)],
                    )
                    .append();
                } else {
                    let conv = il.float_to_int(rd_width, il.reg(rs1_width, rs1));
                    let src = if rd_width < max_width {
                        il.sx(max_width, conv)
                    } else {
                        conv
                    };
                    il.set_reg(max_width, rd, src).append();
                }
            }
            Op::FcvtFromInt(f) => {
                let rd = Register::from(f.rd());
                let rs1 = Register::from(f.rs1());
                let rd_width = f.rd_width() as usize;
                let rs1_width = f.rs1_width() as usize;
                let rs1 = LiftableLowLevelILWithSize::lift_with_size(il, rs1, rs1_width);
                if f.zx() {
                    il.intrinsic(
                        [rd],
                        Intrinsic::FcvtUToF(f.rs1_width(), f.rd_width(), f.rm()),
                        [rs1],
                    )
                    .append();
                } else if f.rm() != RoundMode::Dynamic {
                    il.intrinsic(
                        [rd],
                        Intrinsic::FcvtIToF(f.rs1_width(), f.rd_width(), f.rm()),
                        [rs1],
                    )
                    .append();
                } else {
                    il.set_reg(rd_width, rd, il.int_to_float(rd_width, rs1))
                        .append();
                }
            }
            Op::FmvToInt(f) => {
                let rd = match f.rd().id() {
                    0 => LowLevelILRegister::Temp(0),
                    _ => Register::from(f.rd()).into(),
                };
                let rs1 = Register::from(f.rs1());
                let width = f.width() as usize;
                let src = if width < max_width {
                    il.sx(max_width, il.reg(width, rs1)).build()
                } else {
                    il.reg(width, rs1)
                };
                il.set_reg(max_width, rd, src).append();
            }
            Op::FmvFromInt(f) => {
                let rd = Register::from(f.rd());
                let rs1 = Register::from(f.rs1());
                let width = f.width() as usize;
                let rs1 = LiftableLowLevelILWithSize::lift_with_size(il, rs1, width);
                il.set_reg(width, rd, rs1).append();
            }
            Op::Fclass(f) => {
                let rd = Register::from(f.rd());
                let rs1 = Register::from(f.rs1());
                let width = f.width() as usize;
                il.intrinsic([rd], Intrinsic::Fclass(f.width()), [il.reg(width, rs1)])
                    .append();
            }

            _ => il.unimplemented().append(),
        };

        Some((inst_len as usize, true))
    }

    fn registers_all(&self) -> Vec<Self::Register> {
        let mut reg_count = <D::RegFile as RegFile>::int_reg_count();

        if <D::RegFile as RegFile>::Float::present() {
            reg_count += 32;
        }

        let mut res = Vec::with_capacity(reg_count as usize);

        for i in 0..reg_count {
            res.push(Register::new(RegisterId(i)));
        }

        res
    }

    fn registers_full_width(&self) -> Vec<Self::Register> {
        self.registers_all()
    }

    fn registers_global(&self) -> Vec<Self::Register> {
        let mut regs = Vec::with_capacity(2);

        for i in &[3, 4] {
            regs.push(Register::new(RegisterId(*i)));
        }

        regs
    }

    fn stack_pointer_reg(&self) -> Option<Self::Register> {
        Some(Register::new(RegisterId(2)))
    }

    fn link_reg(&self) -> Option<Self::Register> {
        Some(Register::new(RegisterId(1)))
    }

    fn register_from_id(&self, id: RegisterId) -> Option<Self::Register> {
        let mut reg_count = <D::RegFile as RegFile>::int_reg_count();

        if <D::RegFile as RegFile>::Float::present() {
            reg_count += 32;
        }

        if id.0 > reg_count {
            None
        } else {
            Some(Register::new(id))
        }
    }

    fn intrinsics(&self) -> Vec<Self::Intrinsic> {
        let mut res = Vec::new();

        res.extend_from_slice(&[
            Intrinsic::Uret,
            Intrinsic::Sret,
            Intrinsic::Mret,
            Intrinsic::Wfi,
            Intrinsic::Csrrw,
            Intrinsic::Csrwr,
            Intrinsic::Csrrd,
            Intrinsic::Csrrs,
            Intrinsic::Csrrc,
        ]);

        if <D::RegFile as RegFile>::Float::present() {
            let mut float_sizes = vec![4];
            if <D::RegFile as RegFile>::Float::width() >= 8 {
                float_sizes.push(8);
            }
            if <D::RegFile as RegFile>::Float::width() >= 16 {
                float_sizes.push(16);
            }
            let mut int_sizes = vec![4];
            if <D::RegFile as RegFile>::Int::width() >= 8 {
                int_sizes.push(8);
            }

            for fsize in &float_sizes {
                res.extend_from_slice(&[
                    Intrinsic::Fsgnj(*fsize),
                    Intrinsic::Fsgnjn(*fsize),
                    Intrinsic::Fsgnjx(*fsize),
                    Intrinsic::Fmin(*fsize),
                    Intrinsic::Fmax(*fsize),
                    Intrinsic::Fclass(*fsize),
                ]);
                for rm in RoundMode::all() {
                    if *rm != RoundMode::Dynamic {
                        res.extend_from_slice(&[
                            Intrinsic::Fadd(*fsize, *rm),
                            Intrinsic::Fsub(*fsize, *rm),
                            Intrinsic::Fmul(*fsize, *rm),
                            Intrinsic::Fdiv(*fsize, *rm),
                            Intrinsic::Fsqrt(*fsize, *rm),
                        ]);
                    }
                }
                for dsize in &float_sizes {
                    if fsize != dsize {
                        for rm in RoundMode::all() {
                            if *rm != RoundMode::Dynamic {
                                res.push(Intrinsic::FcvtFToF(*fsize, *dsize, *rm));
                            }
                        }
                    }
                }
                for isize in &int_sizes {
                    for rm in RoundMode::all() {
                        res.push(Intrinsic::FcvtFToU(*fsize, *isize, *rm));
                        res.push(Intrinsic::FcvtUToF(*isize, *fsize, *rm));
                        if *rm != RoundMode::Dynamic {
                            res.push(Intrinsic::FcvtFToI(*fsize, *isize, *rm));
                            res.push(Intrinsic::FcvtIToF(*isize, *fsize, *rm));
                        }
                    }
                }
            }
        }

        res.iter().map(|i| (*i).into()).collect()
    }

    fn intrinsic_from_id(&self, id: IntrinsicId) -> Option<Self::Intrinsic> {
        RiscVIntrinsic::from_id(id)
    }

    fn can_assemble(&self) -> bool {
        true
    }

    fn assemble(&self, code: &str, _addr: u64) -> Result<Vec<u8>, String> {
        // FIXME: This does not support any instructions outside the very basic RV32I/RV64I instruction set.
        // It is completely undocumented how to tell LLVM to accept the additional extensions, and may
        // require core changes to enable.
        let arch_triple = if <D::RegFile as RegFile>::Int::width() == 4 {
            "riscv32-none-none"
        } else {
            "riscv64-none-none"
        };

        llvm_assemble(
            code,
            LlvmServicesDialect::Unspecified,
            arch_triple,
            LlvmServicesCodeModel::Default,
            LlvmServicesRelocMode::Static,
        )
    }

    fn is_never_branch_patch_available(&self, data: &[u8], addr: u64) -> bool {
        let op = match D::decode(addr, data) {
            Ok(Instr::Rv16(op)) => op,
            Ok(Instr::Rv32(op)) => op,
            _ => return false,
        };

        match op {
            Op::Beq(_) | Op::Bne(_) | Op::Blt(_) | Op::Bge(_) | Op::BltU(_) | Op::BgeU(_) => true,
            _ => false,
        }
    }

    fn is_always_branch_patch_available(&self, data: &[u8], addr: u64) -> bool {
        self.is_never_branch_patch_available(data, addr)
    }

    fn is_invert_branch_patch_available(&self, data: &[u8], addr: u64) -> bool {
        self.is_never_branch_patch_available(data, addr)
    }

    fn is_skip_and_return_zero_patch_available(&self, data: &[u8], addr: u64) -> bool {
        let op = match D::decode(addr, data) {
            Ok(Instr::Rv16(op)) => op,
            Ok(Instr::Rv32(op)) => op,
            _ => return false,
        };

        match op {
            Op::Jal(ref j) if j.rd().id() != 0 => true,
            Op::Jalr(ref j) if j.rd().id() != 0 => true,
            _ => false,
        }
    }

    fn is_skip_and_return_value_patch_available(&self, data: &[u8], addr: u64) -> bool {
        self.is_skip_and_return_zero_patch_available(data, addr)
    }

    fn convert_to_nop(&self, mut data: &mut [u8], _addr: u64) -> bool {
        if data.len() & 1 != 0 {
            // If not aligned on 16 bit boundary, can't convert to nop
            return false;
        }

        while data.len() > 0 {
            if data.len() >= 4 {
                // If more than 4 bytes left, use uncompressed nop
                data[0..4].copy_from_slice(&[0x13, 0x00, 0x00, 0x00]);
                data = data[4..].as_mut();
            } else {
                // If only 2 bytes left, use compressed nop
                data[0..2].copy_from_slice(&[0x01, 0x00]);
                data = data[2..].as_mut();
            }
        }

        true
    }

    fn always_branch(&self, data: &mut [u8], addr: u64) -> bool {
        let op = match D::decode(addr, data) {
            Ok(Instr::Rv16(_)) => return false,
            Ok(Instr::Rv32(op)) => op,
            _ => return false,
        };

        if data.len() < 4 {
            return false;
        }

        match op {
            Op::Beq(ref b)
            | Op::Bne(ref b)
            | Op::Blt(ref b)
            | Op::Bge(ref b)
            | Op::BltU(ref b)
            | Op::BgeU(ref b) => {
                let offset = b.imm() as u32;
                let opcode = ((offset >> 20) & 1) << 31
                    | ((offset >> 1) & 0x3ff) << 21
                    | ((offset >> 11) & 1) << 20
                    | ((offset >> 12) & 0xff) << 12
                    | 0b1101111;
                data[0..4].copy_from_slice(&opcode.to_le_bytes());
                true
            }
            _ => false,
        }
    }

    fn invert_branch(&self, data: &mut [u8], addr: u64) -> bool {
        let op = match D::decode(addr, data) {
            Ok(Instr::Rv16(_)) => return false,
            Ok(Instr::Rv32(op)) => op,
            _ => return false,
        };

        if data.len() < 4 {
            return false;
        }

        match op {
            Op::Beq(_) | Op::Bne(_) | Op::Blt(_) | Op::Bge(_) | Op::BltU(_) | Op::BgeU(_) => {
                data[1] ^= 0x10;
                true
            }
            _ => false,
        }
    }

    fn skip_and_return_value(&self, data: &mut [u8], addr: u64, value: u64) -> bool {
        let (instr_len, op) = match D::decode(addr, data) {
            Ok(Instr::Rv16(op)) => (2, op),
            Ok(Instr::Rv32(op)) => (4, op),
            _ => return false,
        };

        if data.len() < instr_len {
            return false;
        }

        let valid = match op {
            Op::Jal(ref j) if j.rd().id() != 0 => true,
            Op::Jalr(ref j) if j.rd().id() != 0 => true,
            _ => false,
        };
        if !valid {
            return false;
        }

        let signed_value = if <D::RegFile as RegFile>::Int::width() == 4 {
            value as i32 as i64
        } else {
            value as i64
        };

        match instr_len {
            2 => {
                if signed_value < -0x20 || signed_value > 0x1f {
                    return false;
                }
                let opcode = (0b010 << 13)
                    | (signed_value as u16 & 0x10) << 7
                    | (0b01010 << 7)
                    | (signed_value as u16 & 0xf) << 2
                    | 0b01;
                data[0..2].copy_from_slice(&opcode.to_le_bytes());
            }
            4 => {
                if signed_value < -0x800 || signed_value > 0x7ff {
                    return false;
                }
                let opcode = (signed_value as u32 & 0xfff) << 20 | 0b00000_000_01010_0010011;
                data[0..4].copy_from_slice(&opcode.to_le_bytes());
            }
            _ => unreachable!(),
        }

        true
    }

    fn handle(&self) -> CustomArchitectureHandle<Self> {
        self.custom_handle
    }
}

impl<D: 'static + RiscVDisassembler + Send + Sync> AsRef<CoreArchitecture> for RiscVArch<D> {
    fn as_ref(&self) -> &CoreArchitecture {
        &self.handle
    }
}

struct RiscVELFRelocationHandler<D: 'static + RiscVDisassembler + Send + Sync> {
    handle: CoreRelocationHandler,
    custom_handle: CustomRelocationHandlerHandle<Self>,
    _dis: PhantomData<D>,
}

impl<D: 'static + RiscVDisassembler + Send + Sync> RiscVELFRelocationHandler<D> {
    const R_RISCV_NONE: u64 = 0;
    const R_RISCV_32: u64 = 1;
    const R_RISCV_64: u64 = 2;
    const R_RISCV_RELATIVE: u64 = 3;
    const R_RISCV_COPY: u64 = 4;
    const R_RISCV_JUMP_SLOT: u64 = 5;
    const R_RISCV_TLS_TPREL32: u64 = 10;
    const R_RISCV_TLS_TPREL64: u64 = 11;
    const R_RISCV_BRANCH: u64 = 16;
    const R_RISCV_JAL: u64 = 17;
    const R_RISCV_CALL: u64 = 18;
    const R_RISCV_CALL_PLT: u64 = 19;
    const R_RISCV_PCREL_HI20: u64 = 23;
    const R_RISCV_PCREL_LO12_I: u64 = 24;
    const R_RISCV_PCREL_LO12_S: u64 = 25;
    const R_RISCV_HI20: u64 = 26;
    const R_RISCV_LO12_I: u64 = 27;
    const R_RISCV_LO12_S: u64 = 28;
    const R_RISCV_ADD8: u64 = 33;
    const R_RISCV_ADD16: u64 = 34;
    const R_RISCV_ADD32: u64 = 35;
    const R_RISCV_ADD64: u64 = 36;
    const R_RISCV_SUB8: u64 = 37;
    const R_RISCV_SUB16: u64 = 38;
    const R_RISCV_SUB32: u64 = 39;
    const R_RISCV_SUB64: u64 = 40;
    const R_RISCV_RVC_BRANCH: u64 = 44;
    const R_RISCV_RVC_JUMP: u64 = 45;

    fn replace_b_imm(opcode: u32, imm: u32) -> u32 {
        (opcode & 0x01fff07f)
            | (((imm >> 1) & 0xf) << 8)
            | (((imm >> 5) & 0x3f) << 25)
            | (((imm >> 11) & 1) << 7)
            | (((imm >> 12) & 1) << 31)
    }

    fn replace_j_imm(opcode: u32, imm: u32) -> u32 {
        (opcode & 0x00000fff)
            | (((imm >> 1) & 0x3ff) << 21)
            | (((imm >> 11) & 1) << 20)
            | (((imm >> 12) & 0xff) << 12)
            | (((imm >> 20) & 1) << 31)
    }

    fn replace_u_imm(opcode: u32, imm: u32) -> u32 {
        (opcode & 0x00000fff) | (imm << 12)
    }

    fn replace_i_imm(opcode: u32, imm: u32) -> u32 {
        (opcode & 0x000fffff) | (imm << 20)
    }

    fn replace_s_imm(opcode: u32, imm: u32) -> u32 {
        (opcode & 0x01fff07f) | ((imm & 0x1f) << 7) | (((imm >> 5) & 0x7f) << 25)
    }

    fn replace_cb_imm(opcode: u16, imm: u16) -> u16 {
        (opcode & 0xe383)
            | (((imm >> 1) & 3) << 3)
            | (((imm >> 3) & 3) << 10)
            | (((imm >> 5) & 1) << 2)
            | (((imm >> 6) & 3) << 5)
            | (((imm >> 8) & 1) << 12)
    }

    fn replace_cj_imm(opcode: u16, imm: u16) -> u16 {
        (opcode & 0xe003)
            | (((imm >> 1) & 7) << 3)
            | (((imm >> 4) & 1) << 11)
            | (((imm >> 5) & 1) << 2)
            | (((imm >> 6) & 1) << 7)
            | (((imm >> 7) & 1) << 6)
            | (((imm >> 8) & 3) << 9)
            | (((imm >> 10) & 1) << 8)
            | (((imm >> 11) & 1) << 12)
    }
}

impl<D: 'static + RiscVDisassembler + Send + Sync> RelocationHandler
    for RiscVELFRelocationHandler<D>
{
    type Handle = CustomRelocationHandlerHandle<Self>;

    fn get_relocation_info(
        &self,
        _bv: &BinaryView,
        _arch: &CoreArchitecture,
        info: &mut [RelocationInfo],
    ) -> bool {
        for reloc in info.iter_mut() {
            reloc.type_ = RelocationType::StandardRelocationType;
            match reloc.native_type {
                Self::R_RISCV_NONE => reloc.type_ = RelocationType::IgnoredRelocation,
                Self::R_RISCV_32 => {
                    reloc.pc_relative = false;
                    reloc.base_relative = false;
                    reloc.has_sign = false;
                    reloc.size = 4;
                    reloc.truncate_size = 4;
                }
                Self::R_RISCV_64 => {
                    reloc.pc_relative = false;
                    reloc.base_relative = false;
                    reloc.has_sign = false;
                    reloc.size = 8;
                    reloc.truncate_size = 8;
                }
                Self::R_RISCV_RELATIVE => {
                    reloc.pc_relative = false;
                    reloc.base_relative = true;
                    reloc.has_sign = false;
                    reloc.size = <D::RegFile as RegFile>::Int::width();
                    reloc.truncate_size = <D::RegFile as RegFile>::Int::width();
                }
                Self::R_RISCV_COPY => {
                    reloc.type_ = RelocationType::ELFCopyRelocationType;
                    reloc.size = <D::RegFile as RegFile>::Int::width();
                }
                Self::R_RISCV_JUMP_SLOT => {
                    reloc.type_ = RelocationType::ELFJumpSlotRelocationType;
                    reloc.size = <D::RegFile as RegFile>::Int::width();
                }
                Self::R_RISCV_BRANCH
                | Self::R_RISCV_JAL
                | Self::R_RISCV_PCREL_HI20
                | Self::R_RISCV_PCREL_LO12_I
                | Self::R_RISCV_PCREL_LO12_S
                | Self::R_RISCV_HI20
                | Self::R_RISCV_LO12_I
                | Self::R_RISCV_LO12_S => {
                    reloc.pc_relative = true;
                    reloc.base_relative = false;
                    reloc.has_sign = false;
                    reloc.size = 4;
                    reloc.truncate_size = 4;
                }
                Self::R_RISCV_CALL | Self::R_RISCV_CALL_PLT => {
                    reloc.pc_relative = true;
                    reloc.base_relative = false;
                    reloc.has_sign = false;
                    reloc.size = 8;
                    reloc.truncate_size = 8;
                }
                Self::R_RISCV_ADD8 | Self::R_RISCV_SUB8 => {
                    reloc.pc_relative = false;
                    reloc.base_relative = false;
                    reloc.has_sign = reloc.native_type == Self::R_RISCV_SUB8;
                    reloc.size = 1;
                    reloc.truncate_size = 1;
                }
                Self::R_RISCV_ADD16 | Self::R_RISCV_SUB16 => {
                    reloc.pc_relative = false;
                    reloc.base_relative = false;
                    reloc.has_sign = reloc.native_type == Self::R_RISCV_SUB16;
                    reloc.size = 2;
                    reloc.truncate_size = 2;
                }
                Self::R_RISCV_ADD32 | Self::R_RISCV_SUB32 => {
                    reloc.pc_relative = false;
                    reloc.base_relative = false;
                    reloc.has_sign = reloc.native_type == Self::R_RISCV_SUB32;
                    reloc.size = 4;
                    reloc.truncate_size = 4;
                }
                Self::R_RISCV_ADD64 | Self::R_RISCV_SUB64 => {
                    reloc.pc_relative = false;
                    reloc.base_relative = false;
                    reloc.has_sign = reloc.native_type == Self::R_RISCV_SUB64;
                    reloc.size = 8;
                    reloc.truncate_size = 8;
                }
                Self::R_RISCV_RVC_BRANCH | Self::R_RISCV_RVC_JUMP => {
                    reloc.pc_relative = true;
                    reloc.base_relative = false;
                    reloc.has_sign = false;
                    reloc.size = 2;
                    reloc.truncate_size = 2;
                }
                Self::R_RISCV_TLS_TPREL32 => {
                    reloc.type_ = RelocationType::UnhandledRelocation;
                    log::warn!(
                        "Unhandled relocation type {:?} (R_RISCV_TLS_TPREL32) at {:x?}",
                        reloc.native_type,
                        reloc.address
                    )
                }
                Self::R_RISCV_TLS_TPREL64 => {
                    reloc.type_ = RelocationType::UnhandledRelocation;
                    log::warn!(
                        "Unhandled relocation type {:?} (R_RISCV_TLS_TPREL64) at {:x?}",
                        reloc.native_type,
                        reloc.address
                    )
                }
                _ => {
                    reloc.type_ = RelocationType::UnhandledRelocation;
                    log::warn!(
                        "Unknown relocation type {:?} at {:x?}",
                        reloc.native_type,
                        reloc.address
                    )
                }
            }
        }
        true
    }

    fn apply_relocation(
        &self,
        bv: &BinaryView,
        arch: &CoreArchitecture,
        reloc: &Relocation,
        dest: &mut [u8],
    ) -> bool {
        let info = reloc.info();
        match info.native_type {
            Self::R_RISCV_BRANCH => {
                let opcode = u32::from_le_bytes(match dest[0..4].try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => return false,
                });
                let offset = reloc
                    .target()
                    .wrapping_add(info.addend as u64)
                    .wrapping_sub(info.address) as u32;
                let opcode = Self::replace_b_imm(opcode, offset);
                dest[0..4].copy_from_slice(&opcode.to_le_bytes());
                true
            }
            Self::R_RISCV_JAL => {
                let opcode = u32::from_le_bytes(match dest[0..4].try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => return false,
                });
                let offset = reloc
                    .target()
                    .wrapping_add(info.addend as u64)
                    .wrapping_sub(info.address) as u32;
                let opcode = Self::replace_j_imm(opcode, offset);
                dest[0..4].copy_from_slice(&opcode.to_le_bytes());
                true
            }
            Self::R_RISCV_CALL | Self::R_RISCV_CALL_PLT => {
                let u_opcode = u32::from_le_bytes(match dest[0..4].try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => return false,
                });
                let i_opcode = u32::from_le_bytes(match dest[4..8].try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => return false,
                });
                let offset = reloc
                    .target()
                    .wrapping_add(info.addend as u64)
                    .wrapping_sub(info.address) as u32;
                let high_offset = (offset.wrapping_add(0x800)) >> 12;
                let low_offset = offset & 0xfff;
                let u_opcode = Self::replace_u_imm(u_opcode, high_offset);
                let i_opcode = Self::replace_i_imm(i_opcode, low_offset);
                dest[0..4].copy_from_slice(&u_opcode.to_le_bytes());
                dest[4..8].copy_from_slice(&i_opcode.to_le_bytes());
                true
            }
            Self::R_RISCV_PCREL_HI20 => {
                let opcode = u32::from_le_bytes(match dest[0..4].try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => return false,
                });
                let offset = reloc
                    .target()
                    .wrapping_add(info.addend as u64)
                    .wrapping_sub(info.address) as u32;
                let high_offset = (offset.wrapping_add(0x800)) >> 12;
                let opcode = Self::replace_u_imm(opcode, high_offset);
                dest[0..4].copy_from_slice(&opcode.to_le_bytes());
                true
            }
            Self::R_RISCV_PCREL_LO12_I | Self::R_RISCV_PCREL_LO12_S => {
                let opcode = u32::from_le_bytes(match dest[0..4].try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => return false,
                });

                // Actual target symbol is on the associated R_RISCV_PCREL_HI20 relocation, which
                // is pointed to by `reloc.target()`.
                let target = match bv
                    .relocations_at(reloc.target())
                    .iter()
                    .find(|r| r.info().native_type == Self::R_RISCV_PCREL_HI20)
                {
                    Some(target) => target.target().wrapping_add(target.info().addend as u64),
                    None => return false,
                };

                let offset = target.wrapping_sub(reloc.target()) as u32;
                let low_offset = offset & 0xfff;

                let opcode = match info.native_type {
                    Self::R_RISCV_PCREL_LO12_I => Self::replace_i_imm(opcode, low_offset),
                    Self::R_RISCV_PCREL_LO12_S => Self::replace_s_imm(opcode, low_offset),
                    _ => return false,
                };

                dest[0..4].copy_from_slice(&opcode.to_le_bytes());
                true
            }
            Self::R_RISCV_HI20 => {
                let opcode = u32::from_le_bytes(match dest[0..4].try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => return false,
                });
                let addr = reloc.target().wrapping_add(info.addend as u64) as u32;
                let high_addr = (addr.wrapping_add(0x800)) >> 12;
                let opcode = Self::replace_u_imm(opcode, high_addr);
                dest[0..4].copy_from_slice(&opcode.to_le_bytes());
                true
            }
            Self::R_RISCV_LO12_I => {
                let opcode = u32::from_le_bytes(match dest[0..4].try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => return false,
                });
                let addr = reloc.target().wrapping_add(info.addend as u64) as u32;
                let low_addr = addr & 0xfff;
                let opcode = Self::replace_i_imm(opcode, low_addr);
                dest[0..4].copy_from_slice(&opcode.to_le_bytes());
                true
            }
            Self::R_RISCV_LO12_S => {
                let opcode = u32::from_le_bytes(match dest[0..4].try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => return false,
                });
                let addr = reloc.target().wrapping_add(info.addend as u64) as u32;
                let low_addr = addr & 0xfff;
                let opcode = Self::replace_s_imm(opcode, low_addr);
                dest[0..4].copy_from_slice(&opcode.to_le_bytes());
                true
            }
            Self::R_RISCV_ADD8 => {
                let value = u8::from_le_bytes(match dest[0..1].try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => return false,
                });
                let value = value
                    .wrapping_add(reloc.target() as u8)
                    .wrapping_add(info.addend as u8);
                dest[0..1].copy_from_slice(&value.to_le_bytes());
                true
            }
            Self::R_RISCV_ADD16 => {
                let value = u16::from_le_bytes(match dest[0..2].try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => return false,
                });
                let value = value
                    .wrapping_add(reloc.target() as u16)
                    .wrapping_add(info.addend as u16);
                dest[0..2].copy_from_slice(&value.to_le_bytes());
                true
            }
            Self::R_RISCV_ADD32 => {
                let value = u32::from_le_bytes(match dest[0..4].try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => return false,
                });
                let value = value
                    .wrapping_add(reloc.target() as u32)
                    .wrapping_add(info.addend as u32);
                dest[0..4].copy_from_slice(&value.to_le_bytes());
                true
            }
            Self::R_RISCV_ADD64 => {
                let value = u64::from_le_bytes(match dest[0..8].try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => return false,
                });
                let value = value
                    .wrapping_add(reloc.target())
                    .wrapping_add(info.addend as u64);
                dest[0..8].copy_from_slice(&value.to_le_bytes());
                true
            }
            Self::R_RISCV_SUB8 => {
                let value = u8::from_le_bytes(match dest[0..1].try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => return false,
                });
                let value = value
                    .wrapping_sub(reloc.target() as u8)
                    .wrapping_sub(info.addend as u8);
                dest[0..1].copy_from_slice(&value.to_le_bytes());
                true
            }
            Self::R_RISCV_SUB16 => {
                let value = u16::from_le_bytes(match dest[0..2].try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => return false,
                });
                let value = value
                    .wrapping_sub(reloc.target() as u16)
                    .wrapping_sub(info.addend as u16);
                dest[0..2].copy_from_slice(&value.to_le_bytes());
                true
            }
            Self::R_RISCV_SUB32 => {
                let value = u32::from_le_bytes(match dest[0..4].try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => return false,
                });
                let value = value
                    .wrapping_sub(reloc.target() as u32)
                    .wrapping_sub(info.addend as u32);
                dest[0..4].copy_from_slice(&value.to_le_bytes());
                true
            }
            Self::R_RISCV_SUB64 => {
                let value = u64::from_le_bytes(match dest[0..8].try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => return false,
                });
                let value = value
                    .wrapping_sub(reloc.target())
                    .wrapping_sub(info.addend as u64);
                dest[0..8].copy_from_slice(&value.to_le_bytes());
                true
            }
            Self::R_RISCV_RVC_BRANCH => {
                let opcode = u16::from_le_bytes(match dest[0..2].try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => return false,
                });
                let offset = reloc
                    .target()
                    .wrapping_add(info.addend as u64)
                    .wrapping_sub(info.address) as u16;
                let opcode = Self::replace_cb_imm(opcode, offset);
                dest[0..2].copy_from_slice(&opcode.to_le_bytes());
                true
            }
            Self::R_RISCV_RVC_JUMP => {
                let opcode = u16::from_le_bytes(match dest[0..2].try_into() {
                    Ok(bytes) => bytes,
                    Err(_) => return false,
                });
                let offset = reloc
                    .target()
                    .wrapping_add(info.addend as u64)
                    .wrapping_sub(info.address) as u16;
                let opcode = Self::replace_cj_imm(opcode, offset);
                dest[0..2].copy_from_slice(&opcode.to_le_bytes());
                true
            }
            _ => self.default_apply_relocation(bv, arch, reloc, dest),
        }
    }

    fn handle(&self) -> Self::Handle {
        self.custom_handle
    }
}

impl<D: 'static + RiscVDisassembler + Send + Sync> AsRef<CoreRelocationHandler>
    for RiscVELFRelocationHandler<D>
{
    fn as_ref(&self) -> &CoreRelocationHandler {
        &self.handle
    }
}

struct RiscVCC<D: 'static + RiscVDisassembler + Send + Sync> {
    _dis: PhantomData<D>,
}

impl<D: 'static + RiscVDisassembler + Send + Sync> RiscVCC<D> {
    fn new() -> Self {
        RiscVCC { _dis: PhantomData }
    }
}

impl<D: 'static + RiscVDisassembler + Send + Sync> CallingConvention for RiscVCC<D> {
    fn caller_saved_registers(&self) -> Vec<RegisterId> {
        let mut regs = Vec::with_capacity(36);
        let int_reg_count = <D::RegFile as RegFile>::int_reg_count();

        for i in &[
            1u32, 5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17, 28, 29, 30, 31,
        ] {
            if i < &int_reg_count {
                regs.push(RegisterId(*i));
            }
        }

        if <D::RegFile as RegFile>::Float::present() {
            for i in &[
                0u32, 1, 2, 3, 4, 5, 6, 7, 10, 11, 12, 13, 14, 15, 16, 17, 28, 29, 30, 31,
            ] {
                regs.push(RegisterId(*i + int_reg_count));
            }
        }

        regs
    }

    fn callee_saved_registers(&self) -> Vec<RegisterId> {
        let mut regs = Vec::with_capacity(24);
        let int_reg_count = <D::RegFile as RegFile>::int_reg_count();

        for i in &[8u32, 9, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27] {
            if i < &int_reg_count {
                regs.push(RegisterId(*i));
            }
        }

        if <D::RegFile as RegFile>::Float::present() {
            for i in &[8u32, 9, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27] {
                regs.push(RegisterId(*i + int_reg_count));
            }
        }

        regs
    }

    fn int_arg_registers(&self) -> Vec<RegisterId> {
        let mut regs = Vec::with_capacity(8);
        let int_reg_count = <D::RegFile as RegFile>::int_reg_count();

        for i in &[10, 11, 12, 13, 14, 15, 16, 17] {
            if i < &int_reg_count {
                regs.push(RegisterId(*i));
            }
        }

        regs
    }

    fn float_arg_registers(&self) -> Vec<RegisterId> {
        let mut regs = Vec::with_capacity(8);

        if <D::RegFile as RegFile>::Float::present() {
            let int_reg_count = <D::RegFile as RegFile>::int_reg_count();
            for i in &[10, 11, 12, 13, 14, 15, 16, 17] {
                regs.push(RegisterId(*i + int_reg_count));
            }
        }

        regs
    }

    fn arg_registers_shared_index(&self) -> bool {
        false
    }

    fn reserved_stack_space_for_arg_registers(&self) -> bool {
        false
    }
    fn stack_adjusted_on_return(&self) -> bool {
        false
    }

    fn is_eligible_for_heuristics(&self) -> bool {
        true
    }

    // a0 == x10
    fn return_int_reg(&self) -> Option<RegisterId> {
        Some(RegisterId(10))
    }
    // a1 == x11
    fn return_hi_int_reg(&self) -> Option<RegisterId> {
        Some(RegisterId(11))
    }

    fn return_float_reg(&self) -> Option<RegisterId> {
        if <D::RegFile as RegFile>::Float::present() {
            let int_reg_count = <D::RegFile as RegFile>::int_reg_count();
            Some(RegisterId(10 + int_reg_count))
        } else {
            None
        }
    }

    // gp == x3
    fn global_pointer_reg(&self) -> Option<RegisterId> {
        Some(RegisterId(3))
    }

    fn implicitly_defined_registers(&self) -> Vec<RegisterId> {
        Vec::new()
    }
    fn are_argument_registers_used_for_var_args(&self) -> bool {
        true
    }
}

struct RiscVELFPLTRecognizer;

impl FunctionRecognizer for RiscVELFPLTRecognizer {
    fn recognize_low_level_il(
        &self,
        bv: &BinaryView,
        func: &Function,
        llil: &RegularLowLevelILFunction<CoreArchitecture>,
    ) -> bool {
        // Look for the following code pattern:
        // t3 = plt
        // t3 = [t3 + pltoffset] || t3 = [t3]
        // temp0 = t3 (optional)
        // t1 = next instruction
        // jump(t3 || temp0)

        if llil.instruction_count() < 4 {
            return false;
        }

        let mut next_llil_instr = llil.basic_blocks().iter().next().unwrap().iter();

        // Match instruction that fetches PC-relative PLT address range
        let auipc = next_llil_instr.next().unwrap().kind();
        let (auipc_dest, plt_base) = match auipc {
            LowLevelILInstructionKind::SetReg(r) => {
                let value = match r.source_expr().kind() {
                    LowLevelILExpressionKind::Const(v) | LowLevelILExpressionKind::ConstPtr(v) => {
                        v.value()
                    }
                    _ => return false,
                };
                (r.dest_reg(), value)
            }
            _ => return false,
        };

        // Match load instruction that loads the imported address
        let load = next_llil_instr.next().unwrap().kind();
        let (mut entry, mut target_reg) = match load {
            LowLevelILInstructionKind::SetReg(r) => match r.source_expr().kind() {
                LowLevelILExpressionKind::Load(l) => {
                    let target_reg = r.dest_reg();
                    let entry = match l.source_mem_expr().kind() {
                        LowLevelILExpressionKind::Reg(lr) if lr.source_reg() == auipc_dest => {
                            plt_base
                        }
                        LowLevelILExpressionKind::Add(a) => {
                            match (a.left().kind(), a.right().kind()) {
                                (
                                    LowLevelILExpressionKind::Reg(a),
                                    LowLevelILExpressionKind::Const(b)
                                    | LowLevelILExpressionKind::ConstPtr(b),
                                ) if a.source_reg() == auipc_dest => {
                                    plt_base.wrapping_add(b.value())
                                }
                                (
                                    LowLevelILExpressionKind::Const(b)
                                    | LowLevelILExpressionKind::ConstPtr(b),
                                    LowLevelILExpressionKind::Reg(a),
                                ) if a.source_reg() == auipc_dest => {
                                    plt_base.wrapping_add(b.value())
                                }
                                _ => return false,
                            }
                        }
                        LowLevelILExpressionKind::Sub(a) => {
                            match (a.left().kind(), a.right().kind()) {
                                (
                                    LowLevelILExpressionKind::Reg(a),
                                    LowLevelILExpressionKind::Const(b)
                                    | LowLevelILExpressionKind::ConstPtr(b),
                                ) if a.source_reg() == auipc_dest => {
                                    plt_base.wrapping_sub(b.value())
                                }
                                _ => return false,
                            }
                        }
                        _ => return false,
                    };
                    (entry, target_reg)
                }
                _ => return false,
            },
            _ => return false,
        };
        if func.arch().address_size() == 4 {
            entry = entry as u32 as u64;
        }

        // Ensure that load is pointing at an import address
        let sym = match bv.symbol_by_address(entry) {
            Some(sym) => sym,
            None => return false,
        };
        if sym.sym_type() != SymbolType::ImportAddress {
            return false;
        }

        // (OPTIONAL) Check if we are storing in temp0, adjust target reg if so
        let mut temp_reg_inst = next_llil_instr.next().unwrap().kind();
        match &temp_reg_inst {
            LowLevelILInstructionKind::SetReg(r) if llil.instruction_count() >= 5 => {
                match r.source_expr().kind() {
                    LowLevelILExpressionKind::Reg(op) if target_reg == op.source_reg() => {
                        // Update the target_reg to the temp reg.
                        target_reg = r.dest_reg();
                        temp_reg_inst = next_llil_instr.next().unwrap().kind()
                    }
                    _ => {}
                }
            }
            _ => {}
        };

        // Match instruction that stores the next instruction address into a register
        let next_pc_inst = temp_reg_inst;
        let (next_pc_dest, next_pc, cur_pc) = match next_pc_inst {
            LowLevelILInstructionKind::SetReg(r) => {
                let value = match r.source_expr().kind() {
                    LowLevelILExpressionKind::Const(v) | LowLevelILExpressionKind::ConstPtr(v) => {
                        v.value()
                    }
                    _ => return false,
                };
                (r.dest_reg(), value, r.address())
            }
            _ => return false,
        };
        if next_pc != cur_pc + 4 || next_pc_dest == target_reg {
            return false;
        }

        // Match tail call at the end and make sure it is going to the import
        let jump = next_llil_instr.next().unwrap().kind();
        match jump {
            LowLevelILInstructionKind::TailCall(j) => {
                match j.target().kind() {
                    LowLevelILExpressionKind::Reg(r) if r.source_reg() == target_reg => (),
                    _ => return false,
                };
            }
            LowLevelILInstructionKind::Jump(j) => {
                match j.target().kind() {
                    LowLevelILExpressionKind::Reg(r) if r.source_reg() == target_reg => (),
                    _ => return false,
                };
            }
            _ => return false,
        }

        let func_sym =
            Symbol::imported_function_from_import_address_symbol(sym.as_ref(), func.start());

        bv.define_auto_symbol(func_sym.as_ref());
        for ext_sym in &bv.symbols_by_name(func_sym.raw_name()) {
            if ext_sym.sym_type() == SymbolType::External {
                if let Some(var) = bv.data_variable_at_address(ext_sym.address()) {
                    func.apply_imported_types(func_sym.as_ref(), Some(&var.ty.contents));
                    return true;
                }
            }
        }
        false
    }
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginInit() -> bool {
    Logger::new("RISCV").with_level(LevelFilter::Trace).init();

    use riscv_dis::{RiscVIMACDisassembler, Rv32GRegs, Rv64GRegs};
    let arch32 =
        architecture::register_architecture("rv32gc", |custom_handle, core_arch| RiscVArch::<
            RiscVIMACDisassembler<Rv32GRegs>,
        > {
            handle: core_arch,
            custom_handle,
            _dis: PhantomData,
        });
    let arch64 =
        architecture::register_architecture("rv64gc", |custom_handle, core_arch| RiscVArch::<
            RiscVIMACDisassembler<Rv64GRegs>,
        > {
            handle: core_arch,
            custom_handle,
            _dis: PhantomData,
        });

    arch32.register_relocation_handler("ELF", |custom_handle, core_handler| {
        RiscVELFRelocationHandler::<RiscVIMACDisassembler<Rv32GRegs>> {
            handle: core_handler,
            custom_handle,
            _dis: PhantomData,
        }
    });
    arch64.register_relocation_handler("ELF", |custom_handle, core_handler| {
        RiscVELFRelocationHandler::<RiscVIMACDisassembler<Rv64GRegs>> {
            handle: core_handler,
            custom_handle,
            _dis: PhantomData,
        }
    });

    arch32.register_function_recognizer(RiscVELFPLTRecognizer);
    arch64.register_function_recognizer(RiscVELFPLTRecognizer);

    let cc32 = register_calling_convention(
        arch32,
        "default",
        RiscVCC::<RiscVIMACDisassembler<Rv32GRegs>>::new(),
    );
    arch32.set_default_calling_convention(&cc32);
    let cc64 = register_calling_convention(
        arch64,
        "default",
        RiscVCC::<RiscVIMACDisassembler<Rv64GRegs>>::new(),
    );
    arch64.set_default_calling_convention(&cc64);

    if let Ok(bvt) = BinaryViewType::by_name("ELF") {
        bvt.register_arch(
            (1 << 16) | 243,
            binaryninja::Endianness::LittleEndian,
            arch32,
        );
        bvt.register_arch(
            (2 << 16) | 243,
            binaryninja::Endianness::LittleEndian,
            arch64,
        );
    }

    let plat32 = arch32.standalone_platform().unwrap();
    let plat64 = arch64.standalone_platform().unwrap();

    let syscall_cc32 = ConventionBuilder::new(arch32)
        .caller_saved_registers(&[
            "ra", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "a0", "a1", "a2", "a3", "a4", "a5",
            "a6", "a7",
        ])
        .int_arg_registers(&["a7", "a0", "a1", "a2", "a3", "a4", "a5", "a6"])
        .return_int_reg("a0")
        .return_hi_int_reg("a1")
        .global_pointer_reg("gp")
        .implicitly_defined_registers(&["gp", "tp"])
        .register("syscall");
    let syscall_cc64 = ConventionBuilder::new(arch64)
        .caller_saved_registers(&[
            "ra", "t0", "t1", "t2", "t3", "t4", "t5", "t6", "a0", "a1", "a2", "a3", "a4", "a5",
            "a6", "a7",
        ])
        .int_arg_registers(&["a7", "a0", "a1", "a2", "a3", "a4", "a5", "a6"])
        .return_int_reg("a0")
        .return_hi_int_reg("a1")
        .global_pointer_reg("gp")
        .implicitly_defined_registers(&["gp", "tp"])
        .register("syscall");

    plat32.set_syscall_convention(&syscall_cc32);
    plat64.set_syscall_convention(&syscall_cc64);

    true
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "C" fn CorePluginDependencies() {
    add_optional_plugin_dependency("view_elf");
}
