// TODO list
// op-imm shift amounts
// clean up the compressed stuff (esp MISC-ALU)
// finish transition to from_instr32 from 'new'
// make the various component structs smaller (8 bit IntReg/FloatReg etc.)

use std::borrow::Cow;
use std::fmt;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::mem;

use byteorder::{ByteOrder, LittleEndian};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    TooShort,
    UnhandledLength,
    Unaligned,
    InvalidOpcode,
    InvalidSubop,
    BadRegister,
}

pub type DisResult<T> = Result<T, Error>;

#[derive(Copy, Clone, Debug)]
pub enum Op<D: RiscVDisassembler> {
    //
    // RV32I
    //

    // LOAD
    Load(LoadTypeInst<D>),

    // MISC-MEM
    Fence(ITypeIntInst<D>),
    FenceI(ITypeIntInst<D>),

    // OP-IMM
    AddI(ITypeIntInst<D>),
    SltI(ITypeIntInst<D>),
    SltIU(ITypeIntInst<D>),
    XorI(ITypeIntInst<D>),
    OrI(ITypeIntInst<D>),
    AndI(ITypeIntInst<D>),
    SllI(ITypeIntInst<D>),
    SrlI(ITypeIntInst<D>),
    SraI(ITypeIntInst<D>),

    // AUIPC
    Auipc(UTypeInst<D>),

    // STORE
    Store(StoreTypeInst<D>),

    // OP
    Add(RTypeIntInst<D>),
    Sll(RTypeIntInst<D>),
    Slt(RTypeIntInst<D>),
    SltU(RTypeIntInst<D>),
    Xor(RTypeIntInst<D>),
    Srl(RTypeIntInst<D>),
    Or(RTypeIntInst<D>),
    And(RTypeIntInst<D>),
    Sub(RTypeIntInst<D>),
    Sra(RTypeIntInst<D>),

    // LUI
    Lui(UTypeInst<D>),

    // BRANCH
    Beq(BTypeInst<D>),
    Bne(BTypeInst<D>),
    Blt(BTypeInst<D>),
    Bge(BTypeInst<D>),
    BltU(BTypeInst<D>),
    BgeU(BTypeInst<D>),

    // JALR
    Jalr(ITypeIntInst<D>),

    // JAL
    Jal(JTypeInst<D>),

    // SYSTEM
    Ecall,
    Ebreak,
    Csrrw(CsrTypeInst<D>),
    Csrrs(CsrTypeInst<D>),
    Csrrc(CsrTypeInst<D>),
    CsrrwI(CsrITypeInst<D>),
    CsrrsI(CsrITypeInst<D>),
    CsrrcI(CsrITypeInst<D>),

    Uret,
    Sret,
    Mret,
    Wfi,
    SfenceVm(RTypeIntInst<D>),
    SfenceVma(RTypeIntInst<D>),

    //
    // RV64I
    //

    // OP-IMM-32
    AddIW(ITypeIntInst<D>),
    SllIW(ITypeIntInst<D>),
    SrlIW(ITypeIntInst<D>),
    SraIW(ITypeIntInst<D>),

    // OP-32
    AddW(RTypeIntInst<D>),
    SllW(RTypeIntInst<D>),
    SrlW(RTypeIntInst<D>),
    SubW(RTypeIntInst<D>),
    SraW(RTypeIntInst<D>),

    //
    // RV32M
    //

    // OP
    Mul(RTypeIntInst<D>),
    MulH(RTypeIntInst<D>),
    MulHSU(RTypeIntInst<D>),
    MulHU(RTypeIntInst<D>),
    Div(RTypeIntInst<D>),
    DivU(RTypeIntInst<D>),
    Rem(RTypeIntInst<D>),
    RemU(RTypeIntInst<D>),

    //
    // RV64M
    //

    // OP-32
    MulW(RTypeIntInst<D>),
    DivW(RTypeIntInst<D>),
    DivUW(RTypeIntInst<D>),
    RemW(RTypeIntInst<D>),
    RemUW(RTypeIntInst<D>),

    //
    // RV32A
    //

    // AMO
    Lr(AtomicInst<D>),
    Sc(AtomicInst<D>),
    AmoSwap(AtomicInst<D>),
    AmoAdd(AtomicInst<D>),
    AmoXor(AtomicInst<D>),
    AmoAnd(AtomicInst<D>),
    AmoOr(AtomicInst<D>),
    AmoMin(AtomicInst<D>),
    AmoMax(AtomicInst<D>),
    AmoMinU(AtomicInst<D>),
    AmoMaxU(AtomicInst<D>),

    //
    // RV32F
    //
    LoadFp(FpMemInst<D>),
    StoreFp(FpMemInst<D>),
    Fmadd(FpMAddInst<D>),
    Fmsub(FpMAddInst<D>),
    Fnmsub(FpMAddInst<D>),
    Fnmadd(FpMAddInst<D>),
    Fadd(RTypeFloatRoundInst<D>),
    Fsub(RTypeFloatRoundInst<D>),
    Fmul(RTypeFloatRoundInst<D>),
    Fdiv(RTypeFloatRoundInst<D>),
    Fsqrt(RTypeFloatRoundInst<D>),
    Fsgnj(RTypeFloatInst<D>),
    Fsgnjn(RTypeFloatInst<D>),
    Fsgnjx(RTypeFloatInst<D>),
    Fmin(RTypeFloatInst<D>),
    Fmax(RTypeFloatInst<D>),
    Fle(RTypeFloatCmpInst<D>),
    Flt(RTypeFloatCmpInst<D>),
    Feq(RTypeFloatCmpInst<D>),
    Fcvt(FpCvtInst<D>),
    FcvtToInt(FpCvtToIntInst<D>),
    FcvtFromInt(FpCvtFromIntInst<D>),
    FmvToInt(FpMvToIntInst<D>),
    FmvFromInt(FpMvFromIntInst<D>),
    Fclass(FpClassInst<D>),
}

pub trait Register {
    fn new(id: u32) -> Self;

    fn id(&self) -> u32;
    fn valid(&self) -> bool;
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RoundMode {
    RoundNearestEven,
    RoundTowardZero,
    RoundDown,
    RoundUp,
    RoundMaxMagnitude,
    Dynamic,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct IntReg<D: RiscVDisassembler> {
    reg_id: u8,
    _dis: PhantomData<D>,
}

impl<D: RiscVDisassembler> Register for IntReg<D> {
    #[inline(always)]
    fn new(id: u32) -> Self {
        let ret = Self {
            reg_id: id as u8,
            _dis: PhantomData,
        };

        debug_assert!(ret.valid());

        ret
    }

    #[inline(always)]
    fn id(&self) -> u32 {
        self.reg_id as u32
    }

    #[inline(always)]
    fn valid(&self) -> bool {
        (self.reg_id as u32) < <D::RegFile as RegFile>::int_reg_count()
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct FloatReg<D: RiscVDisassembler> {
    reg_id: u8,
    _dis: PhantomData<D>,
}

impl<D: RiscVDisassembler> Register for FloatReg<D> {
    #[inline(always)]
    fn new(id: u32) -> Self {
        let ret = Self {
            reg_id: id as u8,
            _dis: PhantomData,
        };

        debug_assert!(ret.valid());

        ret
    }

    #[inline(always)]
    fn id(&self) -> u32 {
        self.reg_id as u32
    }

    #[inline(always)]
    fn valid(&self) -> bool {
        (self.reg_id as u32) < <D::RegFile as RegFile>::int_reg_count()
    }
}

pub trait IntRegType: Sized {
    #[inline(always)]
    fn width() -> usize {
        mem::size_of::<Self>()
    }
}

pub trait FloatRegType: Sized {
    #[inline(always)]
    fn width() -> usize {
        mem::size_of::<Self>()
    }

    #[inline(always)]
    fn present() -> bool {
        mem::size_of::<Self>() != 0
    }
}

impl IntRegType for u32 {}
impl IntRegType for u64 {}
impl FloatRegType for () {}
impl FloatRegType for f32 {}
impl FloatRegType for f64 {}

pub trait RegFile: Debug + Sized + Copy + Clone {
    type Int: IntRegType;
    type Float: FloatRegType;

    #[inline(always)]
    fn int_reg_count() -> u32 {
        32
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Rv32IRegs;
impl RegFile for Rv32IRegs {
    type Int = u32;
    type Float = ();
}

#[derive(Copy, Clone, Debug)]
pub struct Rv32ERegs;
impl RegFile for Rv32ERegs {
    type Int = u32;
    type Float = ();

    #[inline(always)]
    fn int_reg_count() -> u32 {
        16
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Rv32GRegs;
impl RegFile for Rv32GRegs {
    type Int = u32;
    type Float = f64;
}

#[derive(Copy, Clone, Debug)]
pub struct Rv64GRegs;
impl RegFile for Rv64GRegs {
    type Int = u64;
    type Float = f64;
}

pub enum Operand<D: RiscVDisassembler> {
    R(IntReg<D>),
    F(FloatReg<D>),
    I(i32),
    M(i32, IntReg<D>), // reg + displacement
    RM(RoundMode),
}

impl<D: RiscVDisassembler> fmt::Display for Operand<D> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Operand::R(r) => write!(f, "x{}", r.id()),
            Operand::F(r) => write!(f, "f{}", r.id()),
            Operand::I(i) => match i {
                -0x80000..=-1 => write!(f, "-{:x}", -i),
                _ => write!(f, "{:x}", i),
            },
            Operand::M(i, r) => {
                if i < 0 {
                    write!(f, "-{:x}(x{})", -i, r.id())
                } else {
                    write!(f, "{:x}(x{})", i, r.id())
                }
            }
            Operand::RM(r) => write!(f, "{}", r.name()),
        }
    }
}

#[derive(Copy, Clone, Debug)]
struct Instr32(u32);
impl Instr32 {
    #[inline(always)]
    fn extract_bits(self, start_bit: u32, width: u32) -> u32 {
        self.0.wrapping_shr(start_bit) & 1u32.wrapping_shl(width).wrapping_sub(1)
    }

    #[inline(always)]
    fn opcode(self) -> u32 {
        self.extract_bits(0, 7)
    }

    #[inline(always)]
    fn rd(self) -> u32 {
        self.extract_bits(7, 5)
    }

    #[inline(always)]
    fn rs1(self) -> u32 {
        self.extract_bits(15, 5)
    }

    #[inline(always)]
    fn rs2(self) -> u32 {
        self.extract_bits(20, 5)
    }

    #[inline(always)]
    fn rs3(self) -> u32 {
        self.extract_bits(27, 5)
    }

    #[inline(always)]
    fn funct3(self) -> u32 {
        self.extract_bits(12, 3)
    }

    #[inline(always)]
    fn funct7(self) -> u32 {
        self.extract_bits(25, 7)
    }

    #[inline(always)]
    fn rm(self) -> u32 {
        self.extract_bits(12, 3)
    }

    #[inline(always)]
    fn fsize(self) -> u32 {
        self.extract_bits(25, 2)
    }

    #[inline(always)]
    fn fop(self) -> u32 {
        self.extract_bits(27, 5)
    }

    #[inline(always)]
    fn i_imm(self) -> i32 {
        (self.0 as i32) >> 20
    }

    #[inline(always)]
    fn s_imm(self) -> i32 {
        (((self.0 as i32) >> 20) & !0x1f) | self.extract_bits(7, 5) as i32
    }

    #[inline(always)]
    fn b_imm(self) -> i32 {
        let b_imm = self.s_imm();
        (b_imm & !0x801) | ((b_imm & 1) << 11)
    }

    #[inline(always)]
    fn u_imm(self) -> i32 {
        (self.0 & !0xfff) as i32
    }

    #[inline(always)]
    fn j_imm(self) -> i32 {
        let mut j_imm = (((self.0 as i32) >> 11) as u32) & 0xfff00000;
        j_imm |= 0x000ff000 & self.0;
        j_imm |= self.extract_bits(20, 11);
        ((j_imm & !0x801) | ((j_imm & 1) << 11)) as i32
    }
}

impl RoundMode {
    fn from_bits(bits: u32) -> DisResult<RoundMode> {
        match bits {
            0b000 => Ok(RoundMode::RoundNearestEven),
            0b001 => Ok(RoundMode::RoundTowardZero),
            0b010 => Ok(RoundMode::RoundDown),
            0b011 => Ok(RoundMode::RoundUp),
            0b100 => Ok(RoundMode::RoundMaxMagnitude),
            0b111 => Ok(RoundMode::Dynamic),
            _ => Err(Error::InvalidSubop),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            RoundMode::RoundNearestEven => "rne",
            RoundMode::RoundTowardZero => "rtz",
            RoundMode::RoundDown => "rdn",
            RoundMode::RoundUp => "rup",
            RoundMode::RoundMaxMagnitude => "rmm",
            RoundMode::Dynamic => "dyn",
        }
    }

    pub fn all() -> &'static [RoundMode] {
        &[
            RoundMode::RoundNearestEven,
            RoundMode::RoundTowardZero,
            RoundMode::RoundDown,
            RoundMode::RoundUp,
            RoundMode::RoundMaxMagnitude,
            RoundMode::Dynamic,
        ]
    }
}

#[derive(Copy, Clone, Debug)]
pub struct LoadTypeInst<D: RiscVDisassembler> {
    width: u8,
    zx: bool,
    rd: IntReg<D>,
    rs1: IntReg<D>,
    imm: i16,
    _dis: PhantomData<D>,
}

impl<D: RiscVDisassembler> LoadTypeInst<D> {
    #[inline(always)]
    fn new(width: usize, zx: bool, rd: IntReg<D>, rs1: IntReg<D>, imm: i32) -> DisResult<Self> {
        if width + zx as usize > <D::RegFile as RegFile>::Int::width() {
            return Err(Error::InvalidSubop);
        } else if !rd.valid() || !rs1.valid() {
            return Err(Error::BadRegister);
        }

        Ok(Self {
            width: width as u8,
            zx,
            rd,
            rs1,
            imm: imm as i16,
            _dis: PhantomData,
        })
    }

    #[inline(always)]
    fn from_instr32(inst: Instr32) -> DisResult<Self> {
        let width = 1u32.wrapping_shl(inst.extract_bits(12, 2)) as u8;
        let zx = inst.extract_bits(14, 1) == 1;
        let rd = IntReg::new(inst.rd());
        let rs1 = IntReg::new(inst.rs1());

        if width as usize + zx as usize > <D::RegFile as RegFile>::Int::width() {
            return Err(Error::InvalidSubop);
        } else if !rd.valid() || !rs1.valid() {
            return Err(Error::BadRegister);
        }

        Ok(Self {
            width,
            zx,
            rd,
            rs1,
            imm: inst.i_imm() as i16,
            _dis: PhantomData,
        })
    }

    #[inline(always)]
    pub fn width(&self) -> usize {
        self.width as usize
    }

    #[inline(always)]
    pub fn zx(&self) -> bool {
        self.zx
    }

    #[inline(always)]
    pub fn rd(&self) -> IntReg<D> {
        self.rd
    }

    #[inline(always)]
    pub fn rs1(&self) -> IntReg<D> {
        self.rs1
    }

    #[inline(always)]
    pub fn imm(&self) -> i32 {
        self.imm as i32
    }
}

#[derive(Copy, Clone, Debug)]
pub struct StoreTypeInst<D: RiscVDisassembler> {
    width: u8,
    rs1: IntReg<D>,
    rs2: IntReg<D>,
    imm: i16,
    _dis: PhantomData<D>,
}

impl<D: RiscVDisassembler> StoreTypeInst<D> {
    #[inline(always)]
    fn new(width: usize, rs2: IntReg<D>, rs1: IntReg<D>, imm: i32) -> DisResult<Self> {
        if width > <D::RegFile as RegFile>::Int::width() {
            return Err(Error::InvalidSubop);
        } else if !rs1.valid() || !rs2.valid() {
            return Err(Error::BadRegister);
        }

        Ok(Self {
            width: width as u8,
            rs1,
            rs2,
            imm: imm as i16,
            _dis: PhantomData,
        })
    }

    #[inline(always)]
    fn from_instr32(inst: Instr32) -> DisResult<Self> {
        let width = 1u32.wrapping_shl(inst.extract_bits(12, 3)) as u8;
        let rs1 = IntReg::new(inst.rs1());
        let rs2 = IntReg::new(inst.rs2());

        if width as usize > <D::RegFile as RegFile>::Int::width() {
            return Err(Error::InvalidSubop);
        } else if !rs1.valid() || !rs2.valid() {
            return Err(Error::BadRegister);
        }

        Ok(Self {
            width,
            rs1,
            rs2,
            imm: inst.s_imm() as i16,
            _dis: PhantomData,
        })
    }

    #[inline(always)]
    pub fn width(&self) -> usize {
        self.width as usize
    }

    #[inline(always)]
    pub fn rs1(&self) -> IntReg<D> {
        self.rs1
    }

    #[inline(always)]
    pub fn rs2(&self) -> IntReg<D> {
        self.rs2
    }

    #[inline(always)]
    pub fn imm(&self) -> i32 {
        self.imm as i32
    }
}

#[derive(Copy, Clone, Debug)]
pub struct ITypeInst<Rd, Rs1>
where
    Rd: Register,
    Rs1: Register,
{
    inst: Instr32,
    _rd: PhantomData<Rd>,
    _rs1: PhantomData<Rs1>,
}

pub type ITypeIntInst<D> = ITypeInst<IntReg<D>, IntReg<D>>;

impl<Rd, Rs1> ITypeInst<Rd, Rs1>
where
    Rd: Register,
    Rs1: Register,
{
    #[inline(always)]
    fn new(inst: Instr32) -> DisResult<Self> {
        let ret = Self {
            inst,
            _rd: PhantomData,
            _rs1: PhantomData,
        };

        if !ret.rd().valid() || !ret.rs1().valid() {
            return Err(Error::BadRegister);
        }

        Ok(ret)
    }

    #[inline(always)]
    fn from_ops(rd: Rd, rs1: Rs1, imm: i32) -> Self {
        let imm = imm as u32;
        let raw: u32 = (imm << 20) | (rd.id() << 7) | (rs1.id() << 15);

        Self {
            inst: Instr32(raw),
            _rd: PhantomData,
            _rs1: PhantomData,
        }
    }

    #[inline(always)]
    pub fn rd(&self) -> Rd {
        Rd::new(self.inst.rd())
    }

    #[inline(always)]
    pub fn rs1(&self) -> Rs1 {
        Rs1::new(self.inst.rs1())
    }

    #[inline(always)]
    pub fn imm(&self) -> i32 {
        self.inst.i_imm()
    }
}

#[derive(Copy, Clone, Debug)]
pub struct CsrITypeInst<D: RiscVDisassembler> {
    inst: Instr32,
    _dis: PhantomData<D>,
}

impl<D: RiscVDisassembler> CsrITypeInst<D> {
    #[inline(always)]
    fn new(inst: Instr32) -> DisResult<Self> {
        let ret = Self {
            inst,
            _dis: PhantomData,
        };

        if !ret.rd().valid() {
            return Err(Error::BadRegister);
        }

        Ok(ret)
    }

    #[inline(always)]
    pub fn rd(&self) -> IntReg<D> {
        IntReg::new(self.inst.rd())
    }

    #[inline(always)]
    pub fn imm(&self) -> u32 {
        self.inst.rs1()
    }

    #[inline(always)]
    pub fn csr(&self) -> u32 {
        self.inst.i_imm() as u32 & 0xfff
    }
}

#[derive(Copy, Clone, Debug)]
pub struct CsrTypeInst<D: RiscVDisassembler> {
    inst: Instr32,
    _dis: PhantomData<D>,
    _rs1: PhantomData<IntReg<D>>,
}

impl<D: RiscVDisassembler> CsrTypeInst<D> {
    #[inline(always)]
    fn new(inst: Instr32) -> DisResult<Self> {
        let ret = Self {
            inst,
            _dis: PhantomData,
            _rs1: PhantomData,
        };

        if !ret.rd().valid() || !ret.rs1().valid() {
            return Err(Error::BadRegister);
        }

        Ok(ret)
    }

    #[inline(always)]
    pub fn rd(&self) -> IntReg<D> {
        IntReg::new(self.inst.rd())
    }

    #[inline(always)]
    pub fn rs1(&self) -> IntReg<D> {
        IntReg::new(self.inst.rs1())
    }

    #[inline(always)]
    pub fn csr(&self) -> u32 {
        self.inst.i_imm() as u32 & 0xfff
    }
}

#[derive(Copy, Clone, Debug)]
pub struct RTypeInst<Rd, Rs1, Rs2>
where
    Rd: Register,
    Rs1: Register,
    Rs2: Register,
{
    inst: Instr32,
    _rd: PhantomData<Rd>,
    _rs1: PhantomData<Rs1>,
    _rs2: PhantomData<Rs2>,
}

pub type RTypeIntInst<D> = RTypeInst<IntReg<D>, IntReg<D>, IntReg<D>>;

impl<Rd, Rs1, Rs2> RTypeInst<Rd, Rs1, Rs2>
where
    Rd: Register,
    Rs1: Register,
    Rs2: Register,
{
    #[inline(always)]
    fn new(inst: Instr32) -> DisResult<Self> {
        let ret = Self {
            inst,
            _rd: PhantomData,
            _rs1: PhantomData,
            _rs2: PhantomData,
        };

        if !ret.rd().valid() || !ret.rs1().valid() || !ret.rs2().valid() {
            return Err(Error::BadRegister);
        }

        Ok(ret)
    }

    #[inline(always)]
    fn from_ops(rd: Rd, rs1: Rs1, rs2: Rs2) -> Self {
        let raw: u32 = (rd.id() << 7) | (rs1.id() << 15) | (rs2.id() << 20);

        Self {
            inst: Instr32(raw),
            _rd: PhantomData,
            _rs1: PhantomData,
            _rs2: PhantomData,
        }
    }

    #[inline(always)]
    pub fn rd(&self) -> Rd {
        Rd::new(self.inst.rd())
    }

    #[inline(always)]
    pub fn rs1(&self) -> Rs1 {
        Rs1::new(self.inst.rs1())
    }

    #[inline(always)]
    pub fn rs2(&self) -> Rs2 {
        Rs2::new(self.inst.rs2())
    }
}

#[derive(Copy, Clone, Debug)]
pub struct RTypeFloatInst<D: RiscVDisassembler> {
    width: u8,
    rd: FloatReg<D>,
    rs1: FloatReg<D>,
    rs2: FloatReg<D>,
}

impl<D: RiscVDisassembler> RTypeFloatInst<D> {
    #[inline(always)]
    fn from_instr32(inst: Instr32) -> DisResult<Self> {
        let width = match inst.fsize() {
            0b00 => 4,
            0b01 => 8,
            0b11 => 16,
            _ => return Err(Error::InvalidSubop),
        };

        if width > <D::RegFile as RegFile>::Float::width() {
            return Err(Error::InvalidSubop);
        }

        let rd = FloatReg::new(inst.rd());
        let rs1 = FloatReg::new(inst.rs1());
        let rs2 = FloatReg::new(inst.rs2());

        if !rd.valid() || !rs1.valid() || !rs2.valid() {
            return Err(Error::BadRegister);
        }

        Ok(Self {
            width: width as u8,
            rd,
            rs1,
            rs2,
        })
    }

    #[inline(always)]
    pub fn width(&self) -> u8 {
        self.width
    }

    #[inline(always)]
    pub fn rd(&self) -> FloatReg<D> {
        self.rd
    }

    #[inline(always)]
    pub fn rs1(&self) -> FloatReg<D> {
        self.rs1
    }

    #[inline(always)]
    pub fn rs2(&self) -> FloatReg<D> {
        self.rs2
    }
}

#[derive(Copy, Clone, Debug)]
pub struct RTypeFloatCmpInst<D: RiscVDisassembler> {
    width: u8,
    rd: IntReg<D>,
    rs1: FloatReg<D>,
    rs2: FloatReg<D>,
}

impl<D: RiscVDisassembler> RTypeFloatCmpInst<D> {
    #[inline(always)]
    fn from_instr32(inst: Instr32) -> DisResult<Self> {
        let width = match inst.fsize() {
            0b00 => 4,
            0b01 => 8,
            0b11 => 16,
            _ => return Err(Error::InvalidSubop),
        };

        if width > <D::RegFile as RegFile>::Float::width() {
            return Err(Error::InvalidSubop);
        }

        let rd = IntReg::new(inst.rd());
        let rs1 = FloatReg::new(inst.rs1());
        let rs2 = FloatReg::new(inst.rs2());

        if !rd.valid() || !rs1.valid() || !rs2.valid() {
            return Err(Error::BadRegister);
        }

        Ok(Self {
            width: width as u8,
            rd,
            rs1,
            rs2,
        })
    }

    #[inline(always)]
    pub fn width(&self) -> u8 {
        self.width
    }

    #[inline(always)]
    pub fn rd(&self) -> IntReg<D> {
        self.rd
    }

    #[inline(always)]
    pub fn rs1(&self) -> FloatReg<D> {
        self.rs1
    }

    #[inline(always)]
    pub fn rs2(&self) -> FloatReg<D> {
        self.rs2
    }
}

#[derive(Copy, Clone, Debug)]
pub struct RTypeFloatRoundInst<D: RiscVDisassembler> {
    width: u8,
    rd: FloatReg<D>,
    rs1: FloatReg<D>,
    rs2: FloatReg<D>,
    rm: RoundMode,
}

impl<D: RiscVDisassembler> RTypeFloatRoundInst<D> {
    #[inline(always)]
    fn from_instr32(inst: Instr32) -> DisResult<Self> {
        let width = match inst.fsize() {
            0b00 => 4,
            0b01 => 8,
            0b11 => 16,
            _ => return Err(Error::InvalidSubop),
        };

        if width > <D::RegFile as RegFile>::Float::width() {
            return Err(Error::InvalidSubop);
        }

        let rd = FloatReg::new(inst.rd());
        let rs1 = FloatReg::new(inst.rs1());
        let rs2 = FloatReg::new(inst.rs2());
        let rm = RoundMode::from_bits(inst.rm())?;

        if !rd.valid() || !rs1.valid() || !rs2.valid() {
            return Err(Error::BadRegister);
        }

        Ok(Self {
            width: width as u8,
            rd,
            rs1,
            rs2,
            rm,
        })
    }

    #[inline(always)]
    pub fn width(&self) -> u8 {
        self.width
    }

    #[inline(always)]
    pub fn rd(&self) -> FloatReg<D> {
        self.rd
    }

    #[inline(always)]
    pub fn rs1(&self) -> FloatReg<D> {
        self.rs1
    }

    #[inline(always)]
    pub fn rs2(&self) -> FloatReg<D> {
        self.rs2
    }

    #[inline(always)]
    pub fn rm(&self) -> RoundMode {
        self.rm
    }
}

#[derive(Copy, Clone, Debug)]
pub struct BTypeInst<D: RiscVDisassembler> {
    rs1: IntReg<D>,
    rs2: IntReg<D>,
    imm: i16,
    _dis: PhantomData<D>,
}

impl<D: RiscVDisassembler> BTypeInst<D> {
    #[inline(always)]
    fn new(rs1: IntReg<D>, rs2: IntReg<D>, imm: i32) -> DisResult<Self> {
        if !rs1.valid() || !rs2.valid() {
            return Err(Error::BadRegister);
        }

        Ok(Self {
            rs1,
            rs2,
            imm: imm as i16,
            _dis: PhantomData,
        })
    }

    #[inline(always)]
    fn from_instr32(inst: Instr32) -> DisResult<Self> {
        let rs1 = IntReg::new(inst.rs1());
        let rs2 = IntReg::new(inst.rs2());

        if !rs1.valid() || !rs2.valid() {
            return Err(Error::BadRegister);
        }

        Ok(Self {
            rs1,
            rs2,
            imm: inst.b_imm() as i16,
            _dis: PhantomData,
        })
    }

    #[inline(always)]
    pub fn rs1(&self) -> IntReg<D> {
        self.rs1
    }

    #[inline(always)]
    pub fn rs2(&self) -> IntReg<D> {
        self.rs2
    }

    #[inline(always)]
    pub fn imm(&self) -> i32 {
        self.imm as i32
    }
}

#[derive(Copy, Clone, Debug)]
pub struct UTypeInst<D: RiscVDisassembler> {
    rd: IntReg<D>,
    imm: i32,
    _dis: PhantomData<D>,
}

impl<D: RiscVDisassembler> UTypeInst<D> {
    #[inline(always)]
    fn new(rd: IntReg<D>, imm: i32) -> DisResult<Self> {
        if !rd.valid() {
            return Err(Error::BadRegister);
        }

        Ok(Self {
            rd,
            imm,
            _dis: PhantomData,
        })
    }

    #[inline(always)]
    fn from_instr32(inst: Instr32) -> DisResult<Self> {
        let rd = IntReg::new(inst.rd());

        if !rd.valid() {
            return Err(Error::BadRegister);
        }

        Ok(Self {
            rd,
            imm: inst.u_imm(),
            _dis: PhantomData,
        })
    }

    #[inline(always)]
    pub fn rd(&self) -> IntReg<D> {
        self.rd
    }

    #[inline(always)]
    pub fn imm(&self) -> i32 {
        self.imm
    }
}

#[derive(Copy, Clone, Debug)]
pub struct JTypeInst<D: RiscVDisassembler> {
    rd: IntReg<D>,
    imm: i32,
    _dis: PhantomData<D>,
}

impl<D: RiscVDisassembler> JTypeInst<D> {
    #[inline(always)]
    fn new(rd: IntReg<D>, imm: i32) -> DisResult<Self> {
        if !rd.valid() {
            return Err(Error::BadRegister);
        }

        Ok(Self {
            rd,
            imm,
            _dis: PhantomData,
        })
    }

    #[inline(always)]
    fn from_instr32(inst: Instr32) -> DisResult<Self> {
        let rd = IntReg::new(inst.rd());

        if !rd.valid() {
            return Err(Error::BadRegister);
        }

        Ok(Self {
            rd,
            imm: inst.j_imm(),
            _dis: PhantomData,
        })
    }

    #[inline(always)]
    pub fn rd(&self) -> IntReg<D> {
        self.rd
    }

    #[inline(always)]
    pub fn imm(&self) -> i32 {
        self.imm
    }
}

#[derive(Copy, Clone, Debug)]
pub struct AtomicInst<D: RiscVDisassembler> {
    inst: Instr32,
    _dis: PhantomData<D>,
}

impl<D: RiscVDisassembler> AtomicInst<D> {
    #[inline(always)]
    fn new(inst: Instr32) -> DisResult<Self> {
        let ret = Self {
            inst,
            _dis: PhantomData,
        };

        let width = ret.width();

        if width < 4 || width > <D::RegFile as RegFile>::Int::width() {
            return Err(Error::InvalidSubop);
        } else if !ret.rd().valid() || !ret.rs1().valid() || !ret.rs2().valid() {
            return Err(Error::BadRegister);
        }

        Ok(ret)
    }

    #[inline(always)]
    pub fn rd(&self) -> IntReg<D> {
        IntReg::new(self.inst.rd())
    }

    #[inline(always)]
    pub fn rs1(&self) -> IntReg<D> {
        IntReg::new(self.inst.rs1())
    }

    #[inline(always)]
    pub fn rs2(&self) -> IntReg<D> {
        IntReg::new(self.inst.rs2())
    }

    #[inline(always)]
    pub fn width(&self) -> usize {
        1usize.wrapping_shl(self.inst.funct3())
    }

    #[inline(always)]
    pub fn aq(&self) -> bool {
        self.inst.extract_bits(26, 1) != 0
    }

    #[inline(always)]
    pub fn rl(&self) -> bool {
        self.inst.extract_bits(25, 1) != 0
    }
}

#[derive(Copy, Clone, Debug)]
pub struct FpMemInst<D: RiscVDisassembler> {
    width: u8,
    fr: FloatReg<D>,
    rs1: IntReg<D>,
    imm: i16,
    _dis: PhantomData<D>,
}

impl<D: RiscVDisassembler> FpMemInst<D> {
    #[inline(always)]
    fn new(width: usize, fr: FloatReg<D>, rs1: IntReg<D>, imm: i32) -> DisResult<Self> {
        if width > <D::RegFile as RegFile>::Float::width() {
            return Err(Error::InvalidSubop);
        } else if !fr.valid() || !rs1.valid() {
            return Err(Error::BadRegister);
        }

        Ok(Self {
            width: width as u8,
            fr,
            rs1,
            imm: imm as i16,
            _dis: PhantomData,
        })
    }

    #[inline(always)]
    pub fn width(&self) -> usize {
        self.width as usize
    }

    #[inline(always)]
    pub fn fr(&self) -> FloatReg<D> {
        self.fr
    }

    #[inline(always)]
    pub fn rs1(&self) -> IntReg<D> {
        self.rs1
    }

    #[inline(always)]
    pub fn imm(&self) -> i32 {
        self.imm as i32
    }
}

#[derive(Copy, Clone, Debug)]
pub struct FpMAddInst<D: RiscVDisassembler> {
    width: u8,
    rd: FloatReg<D>,
    rs1: FloatReg<D>,
    rs2: FloatReg<D>,
    rs3: FloatReg<D>,
    rm: RoundMode,
    _dis: PhantomData<D>,
}

impl<D: RiscVDisassembler> FpMAddInst<D> {
    #[inline(always)]
    fn from_instr32(inst: Instr32) -> DisResult<Self> {
        let width = match inst.fsize() {
            0b00 => 4,
            0b01 => 8,
            0b11 => 16,
            _ => return Err(Error::InvalidSubop),
        };

        if width > <D::RegFile as RegFile>::Float::width() {
            return Err(Error::InvalidSubop);
        }

        let rd = FloatReg::new(inst.rd());
        let rs1 = FloatReg::new(inst.rs1());
        let rs2 = FloatReg::new(inst.rs2());
        let rs3 = FloatReg::new(inst.rs3());
        let rm = RoundMode::from_bits(inst.rm())?;

        if !rd.valid() || !rs1.valid() || !rs2.valid() || !rs3.valid() {
            return Err(Error::BadRegister);
        }

        Ok(Self {
            width: width as u8,
            rd,
            rs1,
            rs2,
            rs3,
            rm,
            _dis: PhantomData,
        })
    }

    #[inline(always)]
    pub fn width(&self) -> u8 {
        self.width
    }

    #[inline(always)]
    pub fn rd(&self) -> FloatReg<D> {
        self.rd
    }

    #[inline(always)]
    pub fn rs1(&self) -> FloatReg<D> {
        self.rs1
    }

    #[inline(always)]
    pub fn rs2(&self) -> FloatReg<D> {
        self.rs2
    }

    #[inline(always)]
    pub fn rs3(&self) -> FloatReg<D> {
        self.rs3
    }

    #[inline(always)]
    pub fn rm(&self) -> RoundMode {
        self.rm
    }
}

#[derive(Copy, Clone, Debug)]
pub struct FpCvtInst<D: RiscVDisassembler> {
    rd_width: u8,
    rs1_width: u8,
    rd: FloatReg<D>,
    rs1: FloatReg<D>,
    rm: RoundMode,
    _dis: PhantomData<D>,
}

impl<D: RiscVDisassembler> FpCvtInst<D> {
    #[inline(always)]
    fn new(
        rd: FloatReg<D>,
        rd_width: u8,
        rs1: FloatReg<D>,
        rs1_width: u8,
        rm: RoundMode,
    ) -> DisResult<Self> {
        Ok(Self {
            rd_width,
            rs1_width,
            rd,
            rs1,
            rm,
            _dis: PhantomData,
        })
    }

    #[inline(always)]
    pub fn rd_width(&self) -> u8 {
        self.rd_width
    }

    #[inline(always)]
    pub fn rs1_width(&self) -> u8 {
        self.rs1_width
    }

    #[inline(always)]
    pub fn rd(&self) -> FloatReg<D> {
        self.rd
    }

    #[inline(always)]
    pub fn rs1(&self) -> FloatReg<D> {
        self.rs1
    }

    #[inline(always)]
    pub fn rm(&self) -> RoundMode {
        self.rm
    }
}

#[derive(Copy, Clone, Debug)]
pub struct FpCvtToIntInst<D: RiscVDisassembler> {
    rd_width: u8,
    rs1_width: u8,
    zx: bool,
    rd: IntReg<D>,
    rs1: FloatReg<D>,
    rm: RoundMode,
    _dis: PhantomData<D>,
}

impl<D: RiscVDisassembler> FpCvtToIntInst<D> {
    #[inline(always)]
    fn new(
        rd: IntReg<D>,
        rd_width: u8,
        zx: bool,
        rs1: FloatReg<D>,
        rs1_width: u8,
        rm: RoundMode,
    ) -> DisResult<Self> {
        Ok(Self {
            rd_width,
            rs1_width,
            zx,
            rd,
            rs1,
            rm,
            _dis: PhantomData,
        })
    }

    #[inline(always)]
    pub fn rd_width(&self) -> u8 {
        self.rd_width
    }

    #[inline(always)]
    pub fn rs1_width(&self) -> u8 {
        self.rs1_width
    }

    #[inline(always)]
    pub fn zx(&self) -> bool {
        self.zx
    }

    #[inline(always)]
    pub fn rd(&self) -> IntReg<D> {
        self.rd
    }

    #[inline(always)]
    pub fn rs1(&self) -> FloatReg<D> {
        self.rs1
    }

    #[inline(always)]
    pub fn rm(&self) -> RoundMode {
        self.rm
    }
}

#[derive(Copy, Clone, Debug)]
pub struct FpCvtFromIntInst<D: RiscVDisassembler> {
    rd_width: u8,
    rs1_width: u8,
    zx: bool,
    rd: FloatReg<D>,
    rs1: IntReg<D>,
    rm: RoundMode,
    _dis: PhantomData<D>,
}

impl<D: RiscVDisassembler> FpCvtFromIntInst<D> {
    #[inline(always)]
    fn new(
        rd: FloatReg<D>,
        rd_width: u8,
        rs1: IntReg<D>,
        rs1_width: u8,
        zx: bool,
        rm: RoundMode,
    ) -> DisResult<Self> {
        Ok(Self {
            rd_width,
            rs1_width,
            zx,
            rd,
            rs1,
            rm,
            _dis: PhantomData,
        })
    }

    #[inline(always)]
    pub fn rd_width(&self) -> u8 {
        self.rd_width
    }

    #[inline(always)]
    pub fn rs1_width(&self) -> u8 {
        self.rs1_width
    }

    #[inline(always)]
    pub fn zx(&self) -> bool {
        self.zx
    }

    #[inline(always)]
    pub fn rd(&self) -> FloatReg<D> {
        self.rd
    }

    #[inline(always)]
    pub fn rs1(&self) -> IntReg<D> {
        self.rs1
    }

    #[inline(always)]
    pub fn rm(&self) -> RoundMode {
        self.rm
    }
}

#[derive(Copy, Clone, Debug)]
pub struct FpMvToIntInst<D: RiscVDisassembler> {
    width: u8,
    rd: IntReg<D>,
    rs1: FloatReg<D>,
    _dis: PhantomData<D>,
}

impl<D: RiscVDisassembler> FpMvToIntInst<D> {
    #[inline(always)]
    fn from_instr32(inst: Instr32) -> DisResult<Self> {
        let width = match inst.fsize() {
            0b00 => 4,
            0b01 => 8,
            0b11 => 16,
            _ => return Err(Error::InvalidSubop),
        };

        if width > <D::RegFile as RegFile>::Float::width()
            || width > <D::RegFile as RegFile>::Int::width()
        {
            return Err(Error::InvalidSubop);
        }

        let rd = IntReg::new(inst.rd());
        let rs1 = FloatReg::new(inst.rs1());

        if !rd.valid() || !rs1.valid() {
            return Err(Error::BadRegister);
        }

        Ok(Self {
            width: width as u8,
            rd,
            rs1,
            _dis: PhantomData,
        })
    }

    #[inline(always)]
    pub fn width(&self) -> u8 {
        self.width
    }

    #[inline(always)]
    pub fn rd(&self) -> IntReg<D> {
        self.rd
    }

    #[inline(always)]
    pub fn rs1(&self) -> FloatReg<D> {
        self.rs1
    }
}

#[derive(Copy, Clone, Debug)]
pub struct FpMvFromIntInst<D: RiscVDisassembler> {
    width: u8,
    rd: FloatReg<D>,
    rs1: IntReg<D>,
    _dis: PhantomData<D>,
}

impl<D: RiscVDisassembler> FpMvFromIntInst<D> {
    #[inline(always)]
    fn from_instr32(inst: Instr32) -> DisResult<Self> {
        let width = match inst.fsize() {
            0b00 => 4,
            0b01 => 8,
            0b11 => 16,
            _ => return Err(Error::InvalidSubop),
        };

        if width > <D::RegFile as RegFile>::Float::width()
            || width > <D::RegFile as RegFile>::Int::width()
        {
            return Err(Error::InvalidSubop);
        }

        let rd = FloatReg::new(inst.rd());
        let rs1 = IntReg::new(inst.rs1());

        if !rd.valid() || !rs1.valid() {
            return Err(Error::BadRegister);
        }

        Ok(Self {
            width: width as u8,
            rd,
            rs1,
            _dis: PhantomData,
        })
    }

    #[inline(always)]
    pub fn width(&self) -> u8 {
        self.width
    }

    #[inline(always)]
    pub fn rd(&self) -> FloatReg<D> {
        self.rd
    }

    #[inline(always)]
    pub fn rs1(&self) -> IntReg<D> {
        self.rs1
    }
}

#[derive(Copy, Clone, Debug)]
pub struct FpClassInst<D: RiscVDisassembler> {
    width: u8,
    rd: IntReg<D>,
    rs1: FloatReg<D>,
    _dis: PhantomData<D>,
}

impl<D: RiscVDisassembler> FpClassInst<D> {
    #[inline(always)]
    fn from_instr32(inst: Instr32) -> DisResult<Self> {
        let width = match inst.fsize() {
            0b00 => 4,
            0b01 => 8,
            0b11 => 16,
            _ => return Err(Error::InvalidSubop),
        };

        if width > <D::RegFile as RegFile>::Float::width() {
            return Err(Error::InvalidSubop);
        }

        let rd = IntReg::new(inst.rd());
        let rs1 = FloatReg::new(inst.rs1());

        if !rd.valid() || !rs1.valid() {
            return Err(Error::BadRegister);
        }

        Ok(Self {
            width: width as u8,
            rd,
            rs1,
            _dis: PhantomData,
        })
    }

    #[inline(always)]
    pub fn width(&self) -> u8 {
        self.width
    }

    #[inline(always)]
    pub fn rd(&self) -> IntReg<D> {
        self.rd
    }

    #[inline(always)]
    pub fn rs1(&self) -> FloatReg<D> {
        self.rs1
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Instr16(u16);
impl Instr16 {
    #[inline(always)]
    fn extract_bits(self, start_bit: u32, width: u32) -> u16 {
        self.0.wrapping_shr(start_bit) & 1u16.wrapping_shl(width).wrapping_sub(1)
    }

    #[inline(always)]
    fn sp_load_imm(self, size: usize) -> i32 {
        let size = size as u32 >> 3;
        let start = 4 + size;

        let res = (self.extract_bits(start, 3 - size) << (2 + size))
            | (self.extract_bits(2, 2 + size) << 6);

        (res | (self.extract_bits(12, 1) << 5)) as i32
    }

    #[inline(always)]
    fn mem_imm(self, size: usize) -> i32 {
        let upper = self.extract_bits(10, 3) << 3;

        let res = match size {
            4 => upper | self.extract_bits(6, 1) << 2 | self.extract_bits(5, 1) << 6,
            8 => upper | self.extract_bits(5, 2) << 6,
            _ => unimplemented!(),
        };

        res as i32
    }

    #[inline(always)]
    fn sp_store_imm(self, size: usize) -> i32 {
        let size = size as u32 >> 3;
        let start = 9 + size;

        ((self.extract_bits(start, 4 - size) << (2 + size)) | (self.extract_bits(7, 2 + size) << 6))
            as i32
    }

    #[inline(always)]
    fn cb_imm(self) -> i32 {
        let mut imm = self.extract_bits(2, 1) << 5;
        imm |= self.extract_bits(3, 2) << 1;
        imm |= self.extract_bits(5, 2) << 6;
        imm |= self.extract_bits(10, 2) << 3;

        if self.extract_bits(12, 1) != 0 {
            imm |= !0xff;
        }

        imm as i16 as i32
    }

    #[inline(always)]
    fn cj_imm(self) -> i32 {
        let mut imm = self.extract_bits(2, 1) << 5;
        imm |= self.extract_bits(3, 3) << 1;
        imm |= self.extract_bits(6, 1) << 7;
        imm |= self.extract_bits(7, 1) << 6;
        imm |= self.extract_bits(8, 1) << 10;
        imm |= self.extract_bits(9, 2) << 8;
        imm |= self.extract_bits(11, 1) << 4;

        if self.extract_bits(12, 1) != 0 {
            imm |= !0x7ff;
        }

        imm as i16 as i32
    }
}

pub enum Instr<D: RiscVDisassembler> {
    Rv16(Op<D>),
    Rv32(Op<D>),
}

impl<D: RiscVDisassembler> Instr<D> {
    pub fn mnem(&self) -> Mnem<D> {
        Mnem(self)
    }

    pub fn operands(&self) -> Vec<Operand<D>> {
        let mut ops = Vec::new();

        match *self {
            //Instr::Rv16(..) => {}
            Instr::Rv32(ref op) | Instr::Rv16(ref op) => match *op {
                Op::Load(ref l) => {
                    ops.push(Operand::R(l.rd()));
                    ops.push(Operand::M(l.imm(), l.rs1()));
                }
                Op::Store(ref s) => {
                    ops.push(Operand::R(s.rs2()));
                    ops.push(Operand::M(s.imm(), s.rs1()));
                }
                Op::Fence(ref i)
                | Op::FenceI(ref i)
                | Op::AddI(ref i)
                | Op::SltI(ref i)
                | Op::SltIU(ref i)
                | Op::XorI(ref i)
                | Op::OrI(ref i)
                | Op::AndI(ref i)
                | Op::SllI(ref i)
                | Op::SrlI(ref i)
                | Op::SraI(ref i)
                | Op::AddIW(ref i)
                | Op::SllIW(ref i)
                | Op::SrlIW(ref i)
                | Op::SraIW(ref i) => {
                    ops.push(Operand::R(i.rd()));
                    ops.push(Operand::R(i.rs1()));
                    ops.push(Operand::I(i.imm()));
                }
                Op::Auipc(ref u) | Op::Lui(ref u) => {
                    ops.push(Operand::R(u.rd()));
                    ops.push(Operand::I(u.imm()));
                }
                Op::Add(ref r)
                | Op::Sll(ref r)
                | Op::Slt(ref r)
                | Op::SltU(ref r)
                | Op::Xor(ref r)
                | Op::Srl(ref r)
                | Op::Or(ref r)
                | Op::And(ref r)
                | Op::Sub(ref r)
                | Op::Sra(ref r)
                | Op::AddW(ref r)
                | Op::SllW(ref r)
                | Op::SrlW(ref r)
                | Op::SubW(ref r)
                | Op::SraW(ref r)
                | Op::Mul(ref r)
                | Op::MulH(ref r)
                | Op::MulHSU(ref r)
                | Op::MulHU(ref r)
                | Op::Div(ref r)
                | Op::DivU(ref r)
                | Op::Rem(ref r)
                | Op::RemU(ref r)
                | Op::MulW(ref r)
                | Op::DivW(ref r)
                | Op::DivUW(ref r)
                | Op::RemW(ref r)
                | Op::RemUW(ref r) => {
                    ops.push(Operand::R(r.rd()));
                    ops.push(Operand::R(r.rs1()));
                    ops.push(Operand::R(r.rs2()));
                }
                Op::Beq(ref b)
                | Op::Bne(ref b)
                | Op::Blt(ref b)
                | Op::Bge(ref b)
                | Op::BltU(ref b)
                | Op::BgeU(ref b) => {
                    ops.push(Operand::R(b.rs1()));
                    ops.push(Operand::R(b.rs2()));
                    ops.push(Operand::I(b.imm()));
                }
                Op::Jalr(ref i) => {
                    ops.push(Operand::R(i.rd()));
                    ops.push(Operand::R(i.rs1()));
                    ops.push(Operand::I(i.imm()));
                }
                Op::Jal(ref j) => {
                    ops.push(Operand::R(j.rd()));
                    ops.push(Operand::I(j.imm()));
                }
                Op::SfenceVm(ref _r) => {}
                Op::SfenceVma(ref r) => {
                    ops.push(Operand::R(r.rs1()));
                    ops.push(Operand::R(r.rs2()));
                }
                Op::Csrrw(ref i) | Op::Csrrs(ref i) | Op::Csrrc(ref i) => {
                    ops.push(Operand::R(i.rd()));
                    ops.push(Operand::I(i.csr() as i32));
                    ops.push(Operand::R(i.rs1()));
                }
                Op::CsrrwI(ref i) | Op::CsrrsI(ref i) | Op::CsrrcI(ref i) => {
                    ops.push(Operand::R(i.rd()));
                    ops.push(Operand::I(i.csr() as i32));
                    ops.push(Operand::I(i.imm() as i32));
                }
                Op::Ecall | Op::Ebreak | Op::Uret | Op::Sret | Op::Mret | Op::Wfi => {}
                Op::Lr(ref a)
                | Op::Sc(ref a)
                | Op::AmoSwap(ref a)
                | Op::AmoAdd(ref a)
                | Op::AmoXor(ref a)
                | Op::AmoAnd(ref a)
                | Op::AmoOr(ref a)
                | Op::AmoMin(ref a)
                | Op::AmoMax(ref a)
                | Op::AmoMinU(ref a)
                | Op::AmoMaxU(ref a) => {
                    ops.push(Operand::R(a.rd()));

                    if let Op::Lr(..) = *op {
                    } else {
                        ops.push(Operand::R(a.rs2()));
                    }

                    ops.push(Operand::M(0, a.rs1()));
                }
                Op::LoadFp(ref m) | Op::StoreFp(ref m) => {
                    ops.push(Operand::F(m.fr()));
                    ops.push(Operand::M(m.imm(), m.rs1()));
                }
                Op::Fmadd(ref f) | Op::Fmsub(ref f) | Op::Fnmadd(ref f) | Op::Fnmsub(ref f) => {
                    ops.push(Operand::F(f.rd()));
                    ops.push(Operand::F(f.rs1()));
                    ops.push(Operand::F(f.rs2()));
                    ops.push(Operand::F(f.rs3()));
                    if f.rm() != RoundMode::Dynamic {
                        ops.push(Operand::RM(f.rm()));
                    }
                }
                Op::Fadd(ref f) | Op::Fsub(ref f) | Op::Fmul(ref f) | Op::Fdiv(ref f) => {
                    ops.push(Operand::F(f.rd()));
                    ops.push(Operand::F(f.rs1()));
                    ops.push(Operand::F(f.rs2()));
                    if f.rm() != RoundMode::Dynamic {
                        ops.push(Operand::RM(f.rm()));
                    }
                }
                Op::Fsqrt(ref f) => {
                    ops.push(Operand::F(f.rd()));
                    ops.push(Operand::F(f.rs1()));
                    if f.rm() != RoundMode::Dynamic {
                        ops.push(Operand::RM(f.rm()));
                    }
                }
                Op::Fsgnj(ref f)
                | Op::Fsgnjn(ref f)
                | Op::Fsgnjx(ref f)
                | Op::Fmin(ref f)
                | Op::Fmax(ref f) => {
                    ops.push(Operand::F(f.rd()));
                    ops.push(Operand::F(f.rs1()));
                    ops.push(Operand::F(f.rs2()));
                }
                Op::Fle(ref f) | Op::Flt(ref f) | Op::Feq(ref f) => {
                    ops.push(Operand::R(f.rd()));
                    ops.push(Operand::F(f.rs1()));
                    ops.push(Operand::F(f.rs2()));
                }
                Op::Fcvt(ref f) => {
                    ops.push(Operand::F(f.rd()));
                    ops.push(Operand::F(f.rs1()));
                    if f.rm() != RoundMode::Dynamic {
                        ops.push(Operand::RM(f.rm()));
                    }
                }
                Op::FcvtToInt(ref f) => {
                    ops.push(Operand::R(f.rd()));
                    ops.push(Operand::F(f.rs1()));
                    if f.rm() != RoundMode::Dynamic {
                        ops.push(Operand::RM(f.rm()));
                    }
                }
                Op::FcvtFromInt(ref f) => {
                    ops.push(Operand::F(f.rd()));
                    ops.push(Operand::R(f.rs1()));
                    if f.rm() != RoundMode::Dynamic {
                        ops.push(Operand::RM(f.rm()));
                    }
                }
                Op::FmvToInt(ref f) => {
                    ops.push(Operand::R(f.rd()));
                    ops.push(Operand::F(f.rs1()));
                }
                Op::FmvFromInt(ref f) => {
                    ops.push(Operand::F(f.rd()));
                    ops.push(Operand::R(f.rs1()));
                }
                Op::Fclass(ref f) => {
                    ops.push(Operand::R(f.rd()));
                    ops.push(Operand::F(f.rs1()));
                }
            },
        }

        ops
    }
}

pub struct Mnem<'a, D: RiscVDisassembler + 'a>(&'a Instr<D>);
impl<'a, D: RiscVDisassembler + 'a> Mnem<'a, D> {
    fn mnem(&self) -> &str {
        match self.0 {
            &Instr::Rv32(ref op) | &Instr::Rv16(ref op) => match *op {
                Op::Load(..) => "l",
                Op::Fence(..) => "fence",
                Op::FenceI(..) => "fence.i",

                Op::AddI(..) => "addi",
                Op::SltI(..) => "slti",
                Op::SltIU(..) => "sltiu",
                Op::XorI(..) => "xori",
                Op::OrI(..) => "ori",
                Op::AndI(..) => "andi",
                Op::SllI(..) => "slli",
                Op::SrlI(..) => "srli",
                Op::SraI(..) => "srai",

                Op::Auipc(..) => "auipc",

                Op::AddIW(..) => "addiw",
                Op::SllIW(..) => "slliw",
                Op::SrlIW(..) => "srliw",
                Op::SraIW(..) => "sraiw",

                Op::Store(..) => "s",

                Op::Lr(..) => "lr",
                Op::Sc(..) => "sc",
                Op::AmoSwap(..) => "amoswap",
                Op::AmoAdd(..) => "amoadd",
                Op::AmoXor(..) => "amoxor",
                Op::AmoAnd(..) => "amoand",
                Op::AmoOr(..) => "amoor",
                Op::AmoMin(..) => "amoamin",
                Op::AmoMax(..) => "amoamax",
                Op::AmoMinU(..) => "amoaminu",
                Op::AmoMaxU(..) => "amoamaxu",

                Op::Add(..) => "add",
                Op::Sll(..) => "sll",
                Op::Slt(..) => "slt",
                Op::SltU(..) => "sltu",
                Op::Xor(..) => "xor",
                Op::Srl(..) => "srl",
                Op::Or(..) => "or",
                Op::And(..) => "and",
                Op::Sub(..) => "sub",
                Op::Sra(..) => "sra",

                Op::Mul(..) => "mul",
                Op::MulH(..) => "mulh",
                Op::MulHSU(..) => "mulhsu",
                Op::MulHU(..) => "mulhu",
                Op::Div(..) => "div",
                Op::DivU(..) => "divu",
                Op::Rem(..) => "rem",
                Op::RemU(..) => "remu",

                Op::Lui(..) => "lui",

                Op::AddW(..) => "addw",
                Op::SllW(..) => "sllw",
                Op::SrlW(..) => "srlw",
                Op::SubW(..) => "subw",
                Op::SraW(..) => "sraw",

                Op::MulW(..) => "mulw",
                Op::DivW(..) => "divw",
                Op::DivUW(..) => "divuw",
                Op::RemW(..) => "remw",
                Op::RemUW(..) => "remuw",

                Op::Beq(..) => "beq",
                Op::Bne(..) => "bne",
                Op::Blt(..) => "blt",
                Op::Bge(..) => "bge",
                Op::BltU(..) => "bltu",
                Op::BgeU(..) => "bgeu",

                Op::Jalr(..) => "jalr",
                Op::Jal(..) => "jal",

                Op::Ecall => "ecall",
                Op::Ebreak => "ebreak",

                Op::Uret => "uret",
                Op::Sret => "sret",
                Op::Mret => "mret",

                Op::Wfi => "wfi",

                Op::SfenceVm(..) => "sfence.vm",
                Op::SfenceVma(..) => "sfence.vma",

                Op::Csrrw(..) => "csrrw",
                Op::Csrrs(..) => "csrrs",
                Op::Csrrc(..) => "csrrc",

                Op::CsrrwI(..) => "csrrwi",
                Op::CsrrsI(..) => "csrrsi",
                Op::CsrrcI(..) => "csrrci",

                Op::LoadFp(..) => "fl",
                Op::StoreFp(..) => "fs",

                Op::Fmadd(..) => "fmadd",
                Op::Fmsub(..) => "fmsub",
                Op::Fnmadd(..) => "fnmadd",
                Op::Fnmsub(..) => "fnmsub",
                Op::Fadd(..) => "fadd",
                Op::Fsub(..) => "fsub",
                Op::Fmul(..) => "fmul",
                Op::Fdiv(..) => "fdiv",
                Op::Fsqrt(..) => "fsqrt",
                Op::Fsgnj(..) => "fsgnj",
                Op::Fsgnjn(..) => "fsgnjn",
                Op::Fsgnjx(..) => "fsgnjx",
                Op::Fmin(..) => "fmin",
                Op::Fmax(..) => "fmax",
                Op::Fle(..) => "fle",
                Op::Flt(..) => "flt",
                Op::Feq(..) => "feq",
                Op::Fcvt(..) | Op::FcvtToInt(..) | Op::FcvtFromInt(..) => "fcvt",
                Op::FmvToInt(..) | Op::FmvFromInt(..) => "fmv",
                Op::Fclass(..) => "fclass",
            },
        }
    }

    fn suffix(&self) -> Option<Cow<str>> {
        match self.0 {
            // &Instr::Rv16(_) => None,
            &Instr::Rv32(ref op) | &Instr::Rv16(ref op) => match *op {
                Op::Load(ref l) => {
                    let zx = if l.zx() { "u" } else { "" };
                    let width = match l.width() {
                        1 => "b",
                        2 => "h",
                        4 => "w",
                        8 => "d",
                        _ => unreachable!(),
                    };

                    Some(format!("{}{}", width, zx).into())
                }
                Op::Store(ref s) => Some(
                    match s.width() {
                        1 => "b",
                        2 => "h",
                        4 => "w",
                        8 => "d",
                        _ => unreachable!(),
                    }
                    .into(),
                ),
                Op::Lr(ref a)
                | Op::Sc(ref a)
                | Op::AmoSwap(ref a)
                | Op::AmoAdd(ref a)
                | Op::AmoXor(ref a)
                | Op::AmoAnd(ref a)
                | Op::AmoOr(ref a)
                | Op::AmoMin(ref a)
                | Op::AmoMax(ref a)
                | Op::AmoMinU(ref a)
                | Op::AmoMaxU(ref a) => {
                    let width = match a.width() {
                        4 => ".w",
                        8 => ".d",
                        _ => unreachable!(),
                    };
                    let aq = if a.aq() { ".aq" } else { "" };
                    let rl = if a.rl() { ".rl" } else { "" };

                    Some(format!("{}{}{}", width, aq, rl).into())
                }
                Op::LoadFp(ref m) | Op::StoreFp(ref m) => {
                    let suf = match m.width() {
                        4 => "w",
                        8 => "d",
                        16 => "q",
                        _ => unreachable!(),
                    };

                    Some(suf.into())
                }
                Op::Fmadd(ref f) | Op::Fmsub(ref f) | Op::Fnmadd(ref f) | Op::Fnmsub(ref f) => {
                    let suf = match f.width() {
                        4 => ".s",
                        8 => ".d",
                        16 => ".q",
                        _ => unreachable!(),
                    };

                    Some(suf.into())
                }
                Op::Fadd(ref f) | Op::Fsub(ref f) | Op::Fmul(ref f) | Op::Fdiv(ref f) => {
                    let suf = match f.width() {
                        4 => ".s",
                        8 => ".d",
                        16 => ".q",
                        _ => unreachable!(),
                    };

                    Some(suf.into())
                }
                Op::Fsgnj(ref f)
                | Op::Fsgnjn(ref f)
                | Op::Fsgnjx(ref f)
                | Op::Fmin(ref f)
                | Op::Fmax(ref f) => {
                    let suf = match f.width() {
                        4 => ".s",
                        8 => ".d",
                        16 => ".q",
                        _ => unreachable!(),
                    };

                    Some(suf.into())
                }
                Op::Fle(ref f) | Op::Flt(ref f) | Op::Feq(ref f) => {
                    let suf = match f.width() {
                        4 => ".s",
                        8 => ".d",
                        16 => ".q",
                        _ => unreachable!(),
                    };

                    Some(suf.into())
                }
                Op::Fcvt(ref f) => {
                    let rd_suf = match f.rd_width() {
                        4 => ".s",
                        8 => ".d",
                        16 => ".q",
                        _ => unreachable!(),
                    };
                    let rs1_suf = match f.rs1_width() {
                        4 => ".s",
                        8 => ".d",
                        16 => ".q",
                        _ => unreachable!(),
                    };

                    Some(format!("{}{}", rd_suf, rs1_suf).into())
                }
                Op::FcvtToInt(ref f) => {
                    let rd_suf = match f.rd_width() {
                        4 => ".w",
                        8 => ".l",
                        _ => unreachable!(),
                    };
                    let zx_suf = if f.zx() { "u" } else { "" };
                    let rs1_suf = match f.rs1_width() {
                        4 => ".s",
                        8 => ".d",
                        16 => ".q",
                        _ => unreachable!(),
                    };

                    Some(format!("{}{}{}", rd_suf, zx_suf, rs1_suf).into())
                }
                Op::FcvtFromInt(ref f) => {
                    let rd_suf = match f.rs1_width() {
                        4 => ".s",
                        8 => ".d",
                        16 => ".q",
                        _ => unreachable!(),
                    };
                    let rs1_suf = match f.rd_width() {
                        4 => ".w",
                        8 => ".l",
                        _ => unreachable!(),
                    };
                    let zx_suf = if f.zx() { "u" } else { "" };

                    Some(format!("{}{}{}", rd_suf, rs1_suf, zx_suf).into())
                }
                Op::FmvToInt(ref f) => {
                    let suf = match f.width() {
                        4 => ".x.w",
                        8 => ".x.d",
                        _ => unreachable!(),
                    };

                    Some(suf.into())
                }
                Op::FmvFromInt(ref f) => {
                    let suf = match f.width() {
                        4 => ".w.x",
                        8 => ".d.x",
                        _ => unreachable!(),
                    };

                    Some(suf.into())
                }
                Op::Fclass(ref f) => {
                    let suf = match f.width() {
                        4 => ".s",
                        8 => ".d",
                        16 => ".q",
                        _ => unreachable!(),
                    };

                    Some(suf.into())
                }
                _ => None,
            },
        }
    }
}

impl<D: RiscVDisassembler> fmt::Display for Mnem<'_, D> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match (self.mnem(), self.suffix()) {
            (m, None) => f.pad(m),
            (m, Some(s)) => {
                let s = format!("{}{}", m, s);
                f.pad(&s)
            }
        }
    }
}

pub trait StandardExtension {
    fn supported() -> bool;
}

pub struct ExtensionNotImplemented;
impl StandardExtension for ExtensionNotImplemented {
    #[inline(always)]
    fn supported() -> bool {
        false
    }
}

pub struct ExtensionSupported;
impl StandardExtension for ExtensionSupported {
    #[inline(always)]
    fn supported() -> bool {
        true
    }
}

pub trait RiscVDisassembler: Debug + Sized + Copy + Clone {
    type RegFile: RegFile;
    type MulDivExtension: StandardExtension;
    type AtomicExtension: StandardExtension;
    type CompressedExtension: StandardExtension;

    fn decode(addr: u64, bytes: &[u8]) -> DisResult<Instr<Self>> {
        use Error::*;

        let required_alignment: u64 = if Self::CompressedExtension::supported() {
            2
        } else {
            4
        };

        if addr & required_alignment.wrapping_sub(1) != 0
            || bytes.len() < required_alignment as usize
        {
            return Err(Unaligned);
        }

        let parcel = LittleEndian::read_u16(bytes);

        let inst_len = match parcel {
            p if (p & 0b11) != 0b11 => 2,
            p if (p & 0b11111) != 0b11111 => 4,
            _ => {
                return Err(UnhandledLength);
            }
        };

        match inst_len {
            2 if bytes.len() >= 2 && Self::CompressedExtension::supported() => {
                let inst = Instr16(parcel);

                // top 3 bits and bottom 2 bits make up
                // the bulk of the opcode map
                // see: Table 12.3 RVC Opcode Map RISCV spec 2.2
                let opcode = (parcel >> 11 & !3) | (parcel & 3);
                let int_width = <Self::RegFile as RegFile>::Int::width();
                let float_width = <Self::RegFile as RegFile>::Float::width();

                let decoded = match opcode {
                    0b000_00 if parcel != 0 => {
                        // ADDI4SPN
                        let rd = 8 + inst.extract_bits(2, 3) as u32;
                        let mut imm = inst.extract_bits(5, 1) << 3;
                        imm |= inst.extract_bits(6, 1) << 2;
                        imm |= inst.extract_bits(7, 4) << 6;
                        imm |= inst.extract_bits(11, 2) << 4;

                        if imm == 0 {
                            return Err(InvalidSubop);
                        }

                        Op::AddI(ITypeInst::from_ops(
                            IntReg::new(rd),
                            IntReg::new(2),
                            imm as i32,
                        ))
                    }
                    0b000_01 => {
                        // ADDI
                        let rd = inst.extract_bits(7, 5) as u32;
                        let mut imm = inst.extract_bits(2, 5) as u32;

                        // sign extend the 6 bit immediate value
                        if inst.extract_bits(12, 1) == 1 {
                            imm |= !0x1f;
                        }

                        Op::AddI(ITypeInst::from_ops(
                            IntReg::new(rd),
                            IntReg::new(rd),
                            imm as i32,
                        ))
                    }
                    // shift amounts >= 32 are prohibited for Rv32 (reserved for NSE)
                    0b000_10 if int_width >= 8 || inst.extract_bits(12, 1) == 0 => {
                        // SLLI
                        // TODO merge shamt extraction
                        let shamt =
                            (inst.extract_bits(12, 1) << 5 | inst.extract_bits(2, 5)) as u32;
                        let rd = inst.extract_bits(7, 5) as u32;

                        // TODO Rv128 shamt of 0 == 64

                        Op::SllI(ITypeInst::from_ops(
                            IntReg::new(rd),
                            IntReg::new(rd),
                            shamt as i32,
                        ))
                    }

                    //0b001_00 if int_width == 16 => unimplemented!("LQ"),
                    0b001_00 if float_width >= 8 => {
                        // FLD
                        let rd = FloatReg::new(8 + inst.extract_bits(2, 3) as u32);
                        let rs1 = IntReg::new(8 + inst.extract_bits(7, 3) as u32);

                        let imm = inst.mem_imm(8);
                        Op::LoadFp(FpMemInst::new(8, rd, rs1, imm)?)
                    }
                    0b001_01 if int_width == 4 => {
                        // JAL
                        Op::Jal(JTypeInst::new(IntReg::new(1), inst.cj_imm())?)
                    }
                    0b001_01 => {
                        // ADDIW
                        let rd = inst.extract_bits(7, 5) as u32;
                        let mut imm = inst.extract_bits(2, 5) as u32;

                        // TODO rd == zero valid?
                        // sign extend the 6 bit immediate value
                        if inst.extract_bits(12, 1) == 1 {
                            imm |= !0x1f;
                        }

                        Op::AddIW(ITypeInst::from_ops(
                            IntReg::new(rd),
                            IntReg::new(rd),
                            imm as i32,
                        ))
                    }
                    //0b001_10 if int_width == 16 => unimplemented!("LQSP"),
                    0b001_10 if float_width >= 8 => {
                        // FLDSP
                        let rd = FloatReg::new(inst.extract_bits(7, 5) as u32);
                        let imm = inst.sp_load_imm(8);

                        Op::LoadFp(FpMemInst::new(8, rd, IntReg::new(2), imm)?)
                    }

                    0b010_00 => {
                        // LW
                        let rd = IntReg::new(8 + inst.extract_bits(2, 3) as u32);
                        let rs1 = IntReg::new(8 + inst.extract_bits(7, 3) as u32);

                        let imm = inst.mem_imm(4);
                        Op::Load(LoadTypeInst::new(4, false, rd, rs1, imm)?)
                    }
                    0b010_01 => {
                        // LI
                        let rd = inst.extract_bits(7, 5) as u32;

                        // TODO rd == 0 behavior
                        if rd == 0 {
                            return Err(InvalidSubop);
                        }

                        // sign extend the 6 bit immediate value
                        let mut imm = inst.extract_bits(2, 5) as u32;
                        if inst.extract_bits(12, 1) == 1 {
                            imm |= !0x1f;
                        }

                        Op::AddI(ITypeInst::from_ops(
                            IntReg::new(rd),
                            IntReg::new(0),
                            imm as i32,
                        ))
                    }
                    0b010_10 => {
                        // LWSP
                        let rd = IntReg::new(inst.extract_bits(7, 5) as u32);
                        let imm = inst.sp_load_imm(4);

                        if rd.id() == 0 {
                            return Err(InvalidOpcode);
                        }

                        Op::Load(LoadTypeInst::new(4, false, rd, IntReg::new(2), imm)?)
                    }

                    0b011_00 if int_width >= 8 => {
                        // LD
                        let rd = IntReg::new(8 + inst.extract_bits(2, 3) as u32);
                        let rs1 = IntReg::new(8 + inst.extract_bits(7, 3) as u32);

                        let imm = inst.mem_imm(8);
                        Op::Load(LoadTypeInst::new(8, false, rd, rs1, imm)?)
                    }
                    0b011_00 if float_width >= 4 => {
                        // FLW
                        let rd = FloatReg::new(8 + inst.extract_bits(2, 3) as u32);
                        let rs1 = IntReg::new(8 + inst.extract_bits(7, 3) as u32);

                        let imm = inst.mem_imm(4);
                        Op::LoadFp(FpMemInst::new(4, rd, rs1, imm)?)
                    }
                    0b011_01 => {
                        // LUI/ADDI16SP
                        let rd = inst.extract_bits(7, 5) as u32;

                        match rd {
                            0 => return Err(InvalidSubop),
                            2 => {
                                // ADDI16SP
                                let mut imm = inst.extract_bits(2, 1) << 5;
                                imm |= inst.extract_bits(3, 2) << 7;
                                imm |= inst.extract_bits(5, 1) << 6;
                                imm |= inst.extract_bits(6, 1) << 4;

                                if inst.extract_bits(12, 1) == 1 {
                                    imm |= !0x1ff;
                                }

                                if imm == 0 {
                                    return Err(InvalidSubop);
                                }

                                Op::AddI(ITypeInst::from_ops(
                                    IntReg::new(2),
                                    IntReg::new(2),
                                    imm as i16 as i32,
                                ))
                            }
                            _ => {
                                // sign extend the 6 bit immediate value
                                let mut imm = inst.extract_bits(2, 5) as u32;
                                if inst.extract_bits(12, 1) == 1 {
                                    imm |= !0x1f;
                                }

                                let imm = (imm as i32) << 12;
                                Op::Lui(UTypeInst::new(IntReg::new(rd), imm)?)
                            }
                        }
                    }
                    0b011_10 if int_width >= 8 => {
                        // LDSP
                        let rd = IntReg::new(inst.extract_bits(7, 5) as u32);
                        let imm = inst.sp_load_imm(8);

                        if rd.id() == 0 {
                            return Err(InvalidOpcode);
                        }

                        Op::Load(LoadTypeInst::new(8, false, rd, IntReg::new(2), imm)?)
                    }
                    0b011_10 if float_width >= 4 => {
                        // FLWSP
                        let rd = FloatReg::new(inst.extract_bits(7, 5) as u32);
                        let imm = inst.sp_load_imm(4);

                        Op::LoadFp(FpMemInst::new(4, rd, IntReg::new(2), imm)?)
                    }

                    // 0b100_00 RESERVED
                    0b100_01 => {
                        // MISC-ALU
                        let rd = 8 + inst.extract_bits(7, 3) as u32;

                        // TODO merge shamt extraction
                        let shamt =
                            (inst.extract_bits(12, 1) << 5 | inst.extract_bits(2, 5)) as u32;

                        let mut mask = inst.extract_bits(2, 5) as u32;
                        if inst.extract_bits(12, 1) == 1 {
                            mask |= !0x1f;
                        }

                        // TODO is shamt 0 actually prohibited?
                        // TODO should not always check this...
                        //if shamt == 0 || (int_width == 4 && shamt >= 32) {
                        //    return Err(InvalidSubop);
                        //}

                        match inst.extract_bits(10, 2) {
                            0 => Op::SrlI(ITypeInst::from_ops(
                                IntReg::new(rd),
                                IntReg::new(rd),
                                shamt as i32,
                            )), // SRLI
                            1 => Op::SraI(ITypeInst::from_ops(
                                IntReg::new(rd),
                                IntReg::new(rd),
                                shamt as i32,
                            )), // SRAI
                            2 => Op::AndI(ITypeInst::from_ops(
                                IntReg::new(rd),
                                IntReg::new(rd),
                                mask as i32,
                            )), // ANDI
                            3 => {
                                let op = inst.extract_bits(5, 2) | (inst.extract_bits(12, 1) << 2);
                                let rs2 = 8 + inst.extract_bits(2, 3) as u32;
                                let rtype = RTypeInst::from_ops(
                                    IntReg::new(rd),
                                    IntReg::new(rd),
                                    IntReg::new(rs2),
                                );

                                match op {
                                    0 => Op::Sub(rtype),                    // SUB
                                    1 => Op::Xor(rtype),                    // XOR
                                    2 => Op::Or(rtype),                     // OR
                                    3 => Op::And(rtype),                    // AND
                                    4 if int_width >= 8 => Op::SubW(rtype), // SUBW
                                    5 if int_width >= 8 => Op::AddW(rtype), // ADDW
                                    _ => return Err(InvalidSubop),
                                }
                            }
                            _ => unreachable!(),
                        }
                    }
                    0b100_10 => {
                        // JALR/MV/ADD
                        let reg1 = inst.extract_bits(7, 5) as u32;
                        let reg2 = inst.extract_bits(2, 5) as u32;
                        let bit = inst.extract_bits(12, 1) as u32;

                        match (bit, reg1, reg2) {
                            (link, rs1, 0) if rs1 != 0 => {
                                // JR, JALR
                                Op::Jalr(ITypeInst::from_ops(
                                    IntReg::new(link),
                                    IntReg::new(rs1),
                                    0,
                                ))
                            }
                            (0, rd, rs2) if rd != 0 && rs2 != 0 => {
                                // MV
                                Op::AddI(ITypeInst::from_ops(IntReg::new(rd), IntReg::new(rs2), 0))
                            }
                            (1, 0, 0) => Op::Ebreak,
                            (1, rd, rs2) if rs2 != 0 => {
                                // ADD
                                Op::Add(RTypeInst::from_ops(
                                    IntReg::new(rd),
                                    IntReg::new(rd),
                                    IntReg::new(rs2),
                                ))
                            }
                            _ => return Err(InvalidSubop),
                        }
                    }

                    //0b101_00 if int_width == 16 => unimplemented!("SQ"),
                    0b101_00 if float_width >= 8 => {
                        // FSD
                        let rd = FloatReg::new(8 + inst.extract_bits(2, 3) as u32);
                        let rs1 = IntReg::new(8 + inst.extract_bits(7, 3) as u32);

                        let imm = inst.mem_imm(8);
                        Op::StoreFp(FpMemInst::new(8, rd, rs1, imm)?)
                    }
                    0b101_01 => {
                        // J
                        Op::Jal(JTypeInst::new(IntReg::new(0), inst.cj_imm())?)
                    }
                    //0b101_10 if int_width == 16 => unimplemented!("SQSP"),
                    0b101_10 if float_width >= 8 => {
                        // FSDSP
                        let rd = FloatReg::new(inst.extract_bits(7, 5) as u32);
                        let imm = inst.sp_load_imm(8);

                        Op::StoreFp(FpMemInst::new(8, rd, IntReg::new(2), imm)?)
                    }

                    0b110_00 => {
                        // SW
                        let rs2 = IntReg::new(8 + inst.extract_bits(2, 3) as u32);
                        let rs1 = IntReg::new(8 + inst.extract_bits(7, 3) as u32);

                        let imm = inst.mem_imm(4);
                        Op::Store(StoreTypeInst::new(4, rs2, rs1, imm)?)
                    }
                    0b110_01 => {
                        // BEQZ
                        let rs1 = IntReg::new(8 + inst.extract_bits(7, 3) as u32);
                        Op::Beq(BTypeInst::new(rs1, IntReg::new(0), inst.cb_imm())?)
                    }
                    0b110_10 => {
                        // SWSP
                        let rs2 = IntReg::new(inst.extract_bits(2, 5) as u32);
                        let imm = inst.sp_store_imm(4);

                        Op::Store(StoreTypeInst::new(4, rs2, IntReg::new(2), imm)?)
                    }

                    0b111_00 if int_width >= 8 => {
                        // SD
                        let rs2 = IntReg::new(8 + inst.extract_bits(2, 3) as u32);
                        let rs1 = IntReg::new(8 + inst.extract_bits(7, 3) as u32);

                        let imm = inst.mem_imm(8);
                        Op::Store(StoreTypeInst::new(8, rs2, rs1, imm)?)
                    }
                    0b111_00 if float_width >= 4 => {
                        // FSW
                        let rd = FloatReg::new(8 + inst.extract_bits(2, 3) as u32);
                        let rs1 = IntReg::new(8 + inst.extract_bits(7, 3) as u32);

                        let imm = inst.mem_imm(4);
                        Op::StoreFp(FpMemInst::new(4, rd, rs1, imm)?)
                    }
                    0b111_01 => {
                        // BNEZ
                        let rs1 = IntReg::new(8 + inst.extract_bits(7, 3) as u32);
                        Op::Bne(BTypeInst::new(rs1, IntReg::new(0), inst.cb_imm())?)
                    }
                    0b111_10 if int_width >= 8 => {
                        // SDSP
                        let rs2 = IntReg::new(inst.extract_bits(2, 5) as u32);
                        let imm = inst.sp_store_imm(8);

                        Op::Store(StoreTypeInst::new(8, rs2, IntReg::new(2), imm)?)
                    }
                    0b111_10 if float_width >= 4 => {
                        // FSWSP
                        let rd = FloatReg::new(inst.extract_bits(7, 5) as u32);
                        let imm = inst.sp_load_imm(4);

                        Op::StoreFp(FpMemInst::new(4, rd, IntReg::new(2), imm)?)
                    }

                    _ => return Err(InvalidOpcode),
                };

                Ok(Instr::Rv16(decoded))
            }
            4 if bytes.len() >= 4 => {
                let inst = LittleEndian::read_u32(bytes);
                let inst = Instr32(inst);

                let int_width = <Self::RegFile as RegFile>::Int::width();
                let float_width = <Self::RegFile as RegFile>::Float::width();

                let decoded = match inst.opcode() >> 2 {
                    0b00000 => Op::Load(LoadTypeInst::from_instr32(inst)?), // LOAD
                    0b00001 if float_width > 0 => {
                        // LOAD-FP
                        let width = 1usize.wrapping_shl(inst.funct3());
                        let fr = FloatReg::new(inst.rd());
                        let rs1 = IntReg::new(inst.rs1());
                        let imm = inst.i_imm();

                        if width < 4 || width > float_width {
                            return Err(InvalidSubop);
                        }

                        Op::LoadFp(FpMemInst::new(width, fr, rs1, imm)?)
                    }
                    // TODO CUSTOM_0
                    0b00011 => {
                        // MISC-MEM
                        let itype = ITypeInst::new(inst)?;

                        match inst.funct3() {
                            0b000 => Op::Fence(itype),
                            0b001 => Op::FenceI(itype),
                            _ => return Err(InvalidSubop),
                        }
                    }
                    0b00100 => {
                        // OP-IMM
                        let mut itype = ITypeInst::new(inst)?;
                        match inst.funct3() {
                            0b000 => Op::AddI(itype),
                            0b010 => Op::SltI(itype),
                            0b011 => Op::SltIU(itype),
                            0b100 => Op::XorI(itype),
                            0b110 => Op::OrI(itype),
                            0b111 => Op::AndI(itype),
                            0b001 => Op::SllI(itype), // TODO shamt
                            0b101 => {
                                if inst.0 & 0x40000000 == 0 {
                                    Op::SrlI(itype)
                                } else {
                                    // pretty terrible hack, whatever
                                    itype.inst.0 &= !0x40000000;
                                    Op::SraI(itype)
                                }
                            }
                            _ => unreachable!(),
                        }
                    }

                    0b00101 => Op::Auipc(UTypeInst::from_instr32(inst)?), // AUIPC

                    0b00110 if int_width > 4 => {
                        // OP-IMM-32
                        let mut itype = ITypeInst::new(inst)?;
                        match inst.funct3() {
                            0b000 => Op::AddIW(itype),
                            0b001 => Op::SllIW(itype), // TODO shamt
                            0b101 => {
                                if inst.0 & 0x40000000 == 0 {
                                    Op::SrlIW(itype)
                                } else {
                                    // pretty terrible hack, whatever
                                    itype.inst.0 &= !0x40000000;
                                    Op::SraIW(itype)
                                }
                            }
                            _ => return Err(InvalidSubop),
                        }
                    }

                    0b01000 => Op::Store(StoreTypeInst::from_instr32(inst)?), // STORE
                    0b01001 if float_width > 0 => {
                        // STORE-FP
                        let width = 1usize.wrapping_shl(inst.funct3());
                        let fr = FloatReg::new(inst.rs2());
                        let rs1 = IntReg::new(inst.rs1());
                        let imm = inst.s_imm();

                        if width < 4 || width > float_width {
                            return Err(InvalidSubop);
                        }

                        Op::StoreFp(FpMemInst::new(width, fr, rs1, imm)?)
                    }
                    // TODO CUSTOM_1
                    0b01011 if Self::AtomicExtension::supported() => {
                        // AMO
                        let atomic = AtomicInst::new(inst)?;

                        // lower two bits represent aq/rl
                        match inst.funct7() >> 2 {
                            0b00010 if inst.rs2() == 0 => Op::Lr(atomic),
                            0b00011 => Op::Sc(atomic),
                            0b00001 => Op::AmoSwap(atomic),
                            0b00000 => Op::AmoAdd(atomic),
                            0b00100 => Op::AmoXor(atomic),
                            0b01100 => Op::AmoAnd(atomic),
                            0b01000 => Op::AmoOr(atomic),
                            0b10000 => Op::AmoMin(atomic),
                            0b10100 => Op::AmoMax(atomic),
                            0b11000 => Op::AmoMinU(atomic),
                            0b11100 => Op::AmoMaxU(atomic),
                            _ => return Err(InvalidSubop),
                        }
                    }
                    0b01100 => {
                        // OP
                        let rtype = RTypeIntInst::new(inst)?;
                        match inst.funct7() {
                            0b0000000 => match inst.funct3() {
                                0b000 => Op::Add(rtype),
                                0b001 => Op::Sll(rtype),
                                0b010 => Op::Slt(rtype),
                                0b011 => Op::SltU(rtype),
                                0b100 => Op::Xor(rtype),
                                0b101 => Op::Srl(rtype),
                                0b110 => Op::Or(rtype),
                                0b111 => Op::And(rtype),
                                _ => unreachable!(),
                            },
                            0b0100000 => match inst.funct3() {
                                0b000 => Op::Sub(rtype),
                                0b101 => Op::Sra(rtype),
                                _ => return Err(InvalidSubop),
                            },
                            0b0000001 if Self::MulDivExtension::supported() => {
                                match inst.funct3() {
                                    0b000 => Op::Mul(rtype),
                                    0b001 => Op::MulH(rtype),
                                    0b010 => Op::MulHSU(rtype),
                                    0b011 => Op::MulHU(rtype),
                                    0b100 => Op::Div(rtype),
                                    0b101 => Op::DivU(rtype),
                                    0b110 => Op::Rem(rtype),
                                    0b111 => Op::RemU(rtype),
                                    _ => unreachable!(),
                                }
                            }
                            _ => return Err(InvalidSubop),
                        }
                    }
                    0b01101 => Op::Lui(UTypeInst::from_instr32(inst)?), // LUI
                    0b01110 if int_width > 4 => {
                        // OP-32
                        let rtype = RTypeIntInst::new(inst)?;
                        match inst.funct7() {
                            0b0000000 => match inst.funct3() {
                                0b000 => Op::AddW(rtype),
                                0b001 => Op::SllW(rtype),
                                0b101 => Op::SrlW(rtype),
                                _ => return Err(InvalidSubop),
                            },
                            0b0100000 => match inst.funct3() {
                                0b000 => Op::SubW(rtype),
                                0b101 => Op::SraW(rtype),
                                _ => return Err(InvalidSubop),
                            },
                            0b0000001 if Self::MulDivExtension::supported() => {
                                match inst.funct3() {
                                    0b000 => Op::MulW(rtype),
                                    0b100 => Op::DivW(rtype),
                                    0b101 => Op::DivUW(rtype),
                                    0b110 => Op::RemW(rtype),
                                    0b111 => Op::RemUW(rtype),
                                    _ => return Err(InvalidSubop),
                                }
                            }
                            _ => return Err(InvalidSubop),
                        }
                    }
                    0b10000 if float_width > 0 => Op::Fmadd(FpMAddInst::from_instr32(inst)?), // MADD
                    0b10001 if float_width > 0 => Op::Fmsub(FpMAddInst::from_instr32(inst)?), // MSUB
                    0b10010 if float_width > 0 => Op::Fnmsub(FpMAddInst::from_instr32(inst)?), // NMSUB
                    0b10011 if float_width > 0 => Op::Fnmadd(FpMAddInst::from_instr32(inst)?), // NMADD
                    0b10100 if float_width > 0 => {
                        // OP-FP
                        match inst.fop() {
                            0b00000 => Op::Fadd(RTypeFloatRoundInst::from_instr32(inst)?),
                            0b00001 => Op::Fsub(RTypeFloatRoundInst::from_instr32(inst)?),
                            0b00010 => Op::Fmul(RTypeFloatRoundInst::from_instr32(inst)?),
                            0b00011 => Op::Fdiv(RTypeFloatRoundInst::from_instr32(inst)?),
                            0b00100 => match inst.funct3() {
                                0b000 => Op::Fsgnj(RTypeFloatInst::from_instr32(inst)?),
                                0b001 => Op::Fsgnjn(RTypeFloatInst::from_instr32(inst)?),
                                0b010 => Op::Fsgnjx(RTypeFloatInst::from_instr32(inst)?),
                                _ => return Err(InvalidSubop),
                            },
                            0b00101 => match inst.funct3() {
                                0b000 => Op::Fmin(RTypeFloatInst::from_instr32(inst)?),
                                0b001 => Op::Fmax(RTypeFloatInst::from_instr32(inst)?),
                                _ => return Err(InvalidSubop),
                            },
                            0b01000 => {
                                let rd_width = match inst.fsize() {
                                    0b00 => 4,
                                    0b01 => 8,
                                    0b11 => 16,
                                    _ => return Err(InvalidSubop),
                                };
                                let rs1_width = match inst.rs2() {
                                    0b00000 => 4,
                                    0b00001 => 8,
                                    0b00011 => 16,
                                    _ => return Err(InvalidSubop),
                                };

                                if rd_width > float_width
                                    || rs1_width > float_width
                                    || rd_width == rs1_width
                                {
                                    return Err(InvalidSubop);
                                }

                                let rd = FloatReg::new(inst.rd());
                                let rs1 = FloatReg::new(inst.rs1());
                                let rm = RoundMode::from_bits(inst.rm())?;

                                Op::Fcvt(FpCvtInst::new(
                                    rd,
                                    rd_width as u8,
                                    rs1,
                                    rs1_width as u8,
                                    rm,
                                )?)
                            }
                            0b10100 => match inst.funct3() {
                                0b000 => Op::Fle(RTypeFloatCmpInst::from_instr32(inst)?),
                                0b001 => Op::Flt(RTypeFloatCmpInst::from_instr32(inst)?),
                                0b010 => Op::Feq(RTypeFloatCmpInst::from_instr32(inst)?),
                                _ => return Err(InvalidSubop),
                            },
                            0b01011 if inst.rs2() == 0 => {
                                Op::Fsqrt(RTypeFloatRoundInst::from_instr32(inst)?)
                            }
                            0b11000 => {
                                let rs1_width = match inst.fsize() {
                                    0b00 => 4,
                                    0b01 => 8,
                                    0b11 => 16,
                                    _ => return Err(InvalidSubop),
                                };

                                if rs1_width > float_width {
                                    return Err(InvalidSubop);
                                }

                                let rd = IntReg::new(inst.rd());
                                let rs1 = FloatReg::new(inst.rs1());
                                let rm = RoundMode::from_bits(inst.rm())?;

                                match inst.rs2() {
                                    0b00000 => Op::FcvtToInt(FpCvtToIntInst::new(
                                        rd,
                                        4,
                                        false,
                                        rs1,
                                        rs1_width as u8,
                                        rm,
                                    )?),
                                    0b00001 => Op::FcvtToInt(FpCvtToIntInst::new(
                                        rd,
                                        4,
                                        true,
                                        rs1,
                                        rs1_width as u8,
                                        rm,
                                    )?),
                                    0b00010 if int_width >= 8 => {
                                        Op::FcvtToInt(FpCvtToIntInst::new(
                                            rd,
                                            8,
                                            false,
                                            rs1,
                                            rs1_width as u8,
                                            rm,
                                        )?)
                                    }
                                    0b00011 if int_width >= 8 => Op::FcvtToInt(
                                        FpCvtToIntInst::new(rd, 8, true, rs1, rs1_width as u8, rm)?,
                                    ),
                                    _ => return Err(InvalidSubop),
                                }
                            }
                            0b11010 => {
                                let rd_width = match inst.fsize() {
                                    0b00 => 4,
                                    0b01 => 8,
                                    0b11 => 16,
                                    _ => return Err(InvalidSubop),
                                };

                                if rd_width > float_width {
                                    return Err(InvalidSubop);
                                }

                                let rd = FloatReg::new(inst.rd());
                                let rs1 = IntReg::new(inst.rs1());
                                let rm = RoundMode::from_bits(inst.rm())?;

                                match inst.rs2() {
                                    0b00000 => Op::FcvtFromInt(FpCvtFromIntInst::new(
                                        rd,
                                        rd_width as u8,
                                        rs1,
                                        4,
                                        false,
                                        rm,
                                    )?),
                                    0b00001 => Op::FcvtFromInt(FpCvtFromIntInst::new(
                                        rd,
                                        rd_width as u8,
                                        rs1,
                                        4,
                                        true,
                                        rm,
                                    )?),
                                    0b00010 if int_width >= 8 => {
                                        Op::FcvtFromInt(FpCvtFromIntInst::new(
                                            rd,
                                            rd_width as u8,
                                            rs1,
                                            8,
                                            false,
                                            rm,
                                        )?)
                                    }
                                    0b00011 if int_width >= 8 => {
                                        Op::FcvtFromInt(FpCvtFromIntInst::new(
                                            rd,
                                            rd_width as u8,
                                            rs1,
                                            8,
                                            true,
                                            rm,
                                        )?)
                                    }
                                    _ => return Err(InvalidSubop),
                                }
                            }
                            0b11100 if inst.rs2() == 0 => match inst.funct3() {
                                0b000 => Op::FmvToInt(FpMvToIntInst::from_instr32(inst)?),
                                0b001 => Op::Fclass(FpClassInst::from_instr32(inst)?),
                                _ => return Err(InvalidSubop),
                            },
                            0b11110 if inst.rs2() == 0 && inst.funct3() == 0 => {
                                Op::FmvFromInt(FpMvFromIntInst::from_instr32(inst)?)
                            }
                            _ => return Err(InvalidSubop),
                        }
                    }
                    // TODO CUSTOM_2
                    0b11000 => {
                        // BRANCH
                        let btype = BTypeInst::from_instr32(inst)?;
                        match inst.funct3() {
                            0b000 => Op::Beq(btype),
                            0b001 => Op::Bne(btype),
                            0b100 => Op::Blt(btype),
                            0b101 => Op::Bge(btype),
                            0b110 => Op::BltU(btype),
                            0b111 => Op::BgeU(btype),
                            _ => return Err(InvalidSubop),
                        }
                    }
                    0b11001 if inst.funct3() == 0b000 => Op::Jalr(ITypeIntInst::new(inst)?), // JALR
                    0b11011 => Op::Jal(JTypeInst::from_instr32(inst)?),                      // JAL
                    0b11100 => {
                        // SYSTEM
                        match inst.funct3() {
                            0b000 => {
                                let funct12 = inst.0 >> 20;

                                match funct12 {
                                    // Uses the low 5 bits to hold a register,
                                    // everything else treats this as an immediate
                                    // or ignores it
                                    f if (f & 0xfe0) == 0x120 => {
                                        Op::SfenceVma(RTypeIntInst::new(inst)?)
                                    }
                                    0x104 => Op::SfenceVm(RTypeIntInst::new(inst)?),

                                    0x000 => Op::Ecall,
                                    0x001 => Op::Ebreak,

                                    0x002 => Op::Uret,
                                    0x102 => Op::Sret,
                                    0x302 => Op::Mret,

                                    0x105 => Op::Wfi,
                                    _ => return Err(InvalidSubop),
                                }
                            }
                            0b001 => Op::Csrrw(CsrTypeInst::new(inst)?),
                            0b010 => Op::Csrrs(CsrTypeInst::new(inst)?),
                            0b011 => Op::Csrrc(CsrTypeInst::new(inst)?),
                            0b101 => Op::CsrrwI(CsrITypeInst::new(inst)?),
                            0b110 => Op::CsrrsI(CsrITypeInst::new(inst)?),
                            0b111 => Op::CsrrcI(CsrITypeInst::new(inst)?),
                            _ => return Err(InvalidSubop),
                        }
                    }

                    _ => return Err(InvalidOpcode),
                };

                Ok(Instr::Rv32(decoded))
            }
            _ => Err(TooShort),
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct RiscVIMACDisassembler<RF: RegFile>(PhantomData<RF>);
impl<RF: RegFile> RiscVDisassembler for RiscVIMACDisassembler<RF> {
    type RegFile = RF;
    type MulDivExtension = ExtensionSupported;
    type AtomicExtension = ExtensionSupported;
    type CompressedExtension = ExtensionSupported;
}
