#define _CRT_SECURE_NO_WARNINGS
#include "armv7.h"

#ifdef __cplusplus
using namespace armv7;
#endif

uint32_t armv7_64_bit_transfers(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv7_branch_and_block_data_transfer(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv7_coprocessor_instruction_and_supervisor_call(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv7_data_processing_and_misc(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv7_data_processing_imm(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv7_data_processing_reg_shifted_reg(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv7_data_processing_reg(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv7_decompose(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address, uint32_t bigEndian);
uint32_t armv7_extension_register_load_store(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv7_extra_load_store(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv7_extra_load_store_unprivilaged(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv7_floating_point_data_processing(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv7_halfword_multiply_and_accumulate(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv7_load_store_word_and_unsigned_byte(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv7_media_instructions(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv7_memory_hints_simd_and_misc(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv7_miscellaneous(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv7_msr_imm_and_hints(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv7_multiply_and_accumulate(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv7_one_register_and_modified_imm(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv7_parallel_add_sub_reversal(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv7_parallel_add_sub_signed(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv7_parallel_add_sub_udiv(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv7_parallel_add_sub_unsigned(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv7_saturating_add_sub(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv7_simd_data_processing(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv7_simd_load_store(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv7_synchronization_primitives(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv7_three_register_different(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv7_three_register_same(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv7_transfers(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv7_two_register_and_shift(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv7_two_register_misc(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv7_two_register_scalar(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
uint32_t armv7_unconditional(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);
typedef uint32_t (*armv7_decompose_instruction)(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address);

static Register regMap[2] = {REG_D0, REG_Q0};


#define SET_REGISTER(x) (1<<((x)))
#define DECODE_DT(s,u) (enum DataType)(1+((((u&1))<<2) | ((s)&3)))

static const char* operationString[] = {
	"UNDEFINED",
	"UNPREDICTABLE",
	"adc",
	"adcs",
	"add",
	"adds",
	"addw",
	"adr",
	"and",
	"ands",
	"asr",
	"asrs",
	"b",
	"bfc",
	"bfi",
	"bic",
	"bics",
	"bkpt",
	"bl",
	"blx",
	"bx",
	"bxj",
	"cbnz",
	"cbz",
	"cdp",
	"cdp2",
	"clrex",
	"clz",
	"cmn",
	"cmp",
	"cps",
	"cpsid",
	"cpsie",
	"dbg",
	"dmb",
	"dsb",
	"enterx",
	"eor",
	"eors",
	"eret",
	"fldmdbx",
	"fldmiax",
	"fstmdbx",
	"fstmiax",
	"fstmx",
	"hint",
	"hvc",
	"isb",
	"it",
	"lda",
	"ldab",
	"ldah",
	"ldaex", // A32
	"ldaexb", // A32
	"ldaexh", // A32
	"ldaexd", // A32
	"ldc",
	"ldc2",
	"ldc2l",
	"ldcl",
	"ldm",
	"ldmda",
	"ldmdb",
	"ldmia",
	"ldmib",
	"ldr",
	"ldrb",
	"ldrbt",
	"ldrd",
	"ldrex",
	"ldrexb",
	"ldrexd",
	"ldrexh",
	"ldrh",
	"ldrht",
	"ldrsb",
	"ldrsbt",
	"ldrsh",
	"ldrsht",
	"ldrt",
	"leavex",
	"lsl",
	"lsls",
	"lsr",
	"lsrs",
	"mcr",
	"mcr2",
	"mcrr",
	"mcrr2",
	"mla",
	"mls",
	"mov",
	"movs",
	"movt",
	"movw",
	"mrc",
	"mrc2",
	"mrrc",
	"mrrc2",
	"mrs",
	"msr",
	"mul",
	"muls",
	"mvn",
	"mvns",
	"nop",
	"orn",
	"orr",
	"orrs",
	"pkhbt",
	"pkhtb",
	"pld",
	"pldw",
	"pli",
	"pop",
	"push",
	"qadd",
	"qadd16",
	"qadd8",
	"qasx",
	"qdadd",
	"qdsub",
	"qsax",
	"qsub",
	"qsub16",
	"qsub8",
	"rbit",
	"rev",
	"rev16",
	"revsh",
	"rfe",
	"rfeda",
	"rfedb",
	"rfeia",
	"rfeib",
	"ror",
	"rors",
	"rrx",
	"rsb",
	"rsbs",
	"rsc",
	"sadd16",
	"sadd8",
	"sasx",
	"sbc",
	"sbcs",
	"sbfx",
	"sdiv",
	"sel",
	"setend",
	"sev",
	"shadd16",
	"shadd8",
	"shasx",
	"shsax",
	"shsub16",
	"shsub8",
	"smc",
	"smlabb",
	"smlabt",
	"smlad",
	"smladx",
	"smlal",
	"smlalbb",
	"smlalbt",
	"smlald",
	"smlaldx",
	"smlaltb",
	"smlaltt",
	"smlatb",
	"smlatt",
	"smlawb",
	"smlawt",
	"smlsd",
	"smlsdx",
	"smlsld",
	"smlsldx",
	"smmla",
	"smmlar",
	"smmls",
	"smmlsr",
	"smmul",
	"smmulr",
	"smuad",
	"smuadx",
	"smulbb",
	"smulbt",
	"smull",
	"smultb",
	"smultt",
	"smulwb",
	"smulwt",
	"smusd",
	"smusdt",
	"smusdx",
	"srs",
	"srsda",
	"srsdb",
	"srsia",
	"srsib",
	"ssat",
	"ssat16",
	"ssax",
	"ssub16",
	"ssub8",
	"stc",
	"stc2",
	"stc2l",
	"stcl",
	"stl", // A32
	"stlb",
	"stlh",
	"stlex", // A32
	"stlexb", // A32
	"stlexh", // A32
	"stlexd", // A32
	"stm",
	"stmbd",
	"stmda",
	"stmdb",
	"stmia",
	"stmib",
	"str",
	"strb",
	"strbt",
	"strd",
	"strex",
	"strexb",
	"strexd",
	"strexh",
	"strh",
	"strht",
	"strt",
	"sub",
	"subs",
	"subw",
	"svc",
	"swp",
	"swpb",
	"sxtab",
	"sxtab16",
	"sxtah",
	"sxtb",
	"sxtb16",
	"sxth",
	"tbb",
	"tbh",
	"teq",
	"trap",
	"trt",
	"tst",
	"uadd16",
	"uadd8",
	"uasx",
	"ubfx",
	"udf",
	"udiv",
	"uhadd16",
	"uhadd8",
	"uhasx",
	"uhsax",
	"uhsub16",
	"uhsub8",
	"umaal",
	"umlal",
	"umull",
	"uqadd16",
	"uqadd8",
	"uqasx",
	"uqsax",
	"uqsub16",
	"uqsub8",
	"usad8",
	"usada8",
	"usat",
	"usat16",
	"usax",
	"usub16",
	"usub8",
	"uxtab",
	"uxtab16",
	"uxtah",
	"uxtb",
	"uxtb16",
	"uxth",
	"vaba",
	"vabal",
	"vabd",
	"vabdl",
	"vabs",
	"vacge",
	"vacgt",
	"vadd",
	"vaddhn",
	"vaddl",
	"vaddw",
	"vand",
	"vbic",
	"vbif",
	"vbit",
	"vbsl",
	"vceq",
	"vcge",
	"vcgt",
	"vcle",
	"vcls",
	"vclt",
	"vclz",
	"vcmp",
	"vcmpe",
	"vcnt",
	"vcvt",
	"vcvta",
	"vcvtb",
	"vcvtm",
	"vcvtn",
	"vcvtp",
	"vcvtr",
	"vcvtt",
	"vdiv",
	"vdup",
	"veor",
	"vext",
	"vfma",
	"vfms",
	"vfnma",
	"vfnms",
	"vhadd",
	"vhsub",
	"vld1",
	"vld2",
	"vld3",
	"vld4",
	"vldm",
	"vldmdb",
	"vldmia",
	"vldr",
	"vmax",
	"vmaxnm",
	"vmin",
	"vminm",
	"vmla",
	"vmlal",
	"vmls",
	"vmlsl",
	"vmov",
	"vmovl",
	"vmovn",
	"vmrs",
	"vmsr",
	"vmul",
	"vmull",
	"vmvn",
	"vneg",
	"vnmla",
	"vnmls",
	"vnmul",
	"vorn",
	"vorr",
	"vpadal",
	"vpadd",
	"vpaddl",
	"vpmax",
	"vpmin",
	"vpop",
	"vpush",
	"vqabs",
	"vqadd",
	"vqdmlal",
	"vqdmlsl",
	"vqdmulh",
	"vqdmull",
	"vqmovn",
	"vqmovun",
	"vqneg",
	"vqrdmulh",
	"vqrshl",
	"vqrshrn",
	"vqrshrun",
	"vqshl",
	"vqshlu",
	"vqshrn",
	"vqshrun",
	"vqsub",
	"vraddhn",
	"vrecpe",
	"vrecps",
	"vrev16",
	"vrev32",
	"vrev64",
	"vrhadd",
	"vrhsub",
	"vrinta",
	"vrintm",
	"vrintn",
	"vrintp",
	"vrintr",
	"vrintx",
	"vrintz",
	"vrshl",
	"vrshr",
	"vrshrn",
	"vrsqrte",
	"vrsqrts",
	"vrsra",
	"vrsubhn",
	"vsel",
	"vshl",
	"vshll",
	"vshr",
	"vshrn",
	"vsli",
	"vsqrt",
	"vsra",
	"vsri",
	"vst1",
	"vst2",
	"vst3",
	"vst4",
	"vstm",
	"vstmdb",
	"vstmia",
	"vstr",
	"vsub",
	"vsubhn",
	"vsubl",
	"vsubw",
	"vswp",
	"vtbl",
	"vtbx",
	"vtrn",
	"vtst",
	"vuzp",
	"vzip",
	"wfe",
	"wfi",
	"yield"
};

static const char* registerString[] = {
	"r0",
	"r1",
	"r2",
	"r3",
	"r4",
	"r5",
	"r6",
	"r7",
	"r8",
	"r9",
	"r10",
	"r11",
	"r12",
	// "sb",
	// "sl",
	// "fp",
	// "ip",
	"sp",
	"lr",
	"pc",
	"s0",
	"s1",
	"s2",
	"s3",
	"s4",
	"s5",
	"s6",
	"s7",
	"s8",
	"s9",
	"s10",
	"s11",
	"s12",
	"s13",
	"s14",
	"s15",
	"s16",
	"s17",
	"s18",
	"s19",
	"s20",
	"s21",
	"s22",
	"s23",
	"s24",
	"s25",
	"s26",
	"s27",
	"s28",
	"s29",
	"s30",
	"s31",
	"d0",
	"d1",
	"d2",
	"d3",
	"d4",
	"d5",
	"d6",
	"d7",
	"d8",
	"d9",
	"d10",
	"d11",
	"d12",
	"d13",
	"d14",
	"d15",
	"d16",
	"d17",
	"d18",
	"d19",
	"d20",
	"d21",
	"d22",
	"d23",
	"d24",
	"d25",
	"d26",
	"d27",
	"d28",
	"d29",
	"d30",
	"d31",
	"q0",
	"q1",
	"q2",
	"q3",
	"q4",
	"q5",
	"q6",
	"q7",
	"q8",
	"q9",
	"q10",
	"q11",
	"q12",
	"q13",
	"q14",
	"q15",

	/* banked regs */
	"elr_hyp",
	"lr_abt",
	"lr_fiq",
	"lr_irq",
	"lr_mon",
	"lr_svc",
	"lr_und",
	"lr_usr",
	"r10_fiq",
	"r10_usr",
	"r11_fiq",
	"r11_usr",
	"r12_fiq",
	"r12_usr",
	"r8_fiq",
	"r8_usr",
	"r9_fiq",
	"r9_usr",
	"spsr_abt",
	"spsr_fiq",
	"spsr_hyp",
	"spsr_irq",
	"spsr_mon",
	"spsr_svc",
	"spsr_und",
	"sp_abt",
	"sp_fiq",
	"sp_hyp",
	"sp_irq",
	"sp_mon",
	"sp_svc",
	"sp_und",
	"sp_usr",

	/* special regs */
	"apsr",
	"apsr_g",
	"apsr_nzcvq",
	"apsr_nzcvqg",
	"cpsr",
	"cpsr_c",
	"cpsr_x",
	"cpsr_xc",
	"cpsr_s",
	"cpsr_sc",
	"cpsr_sx",
	"cpsr_sxc",
	"cpsr_f",
	"cpsr_fc",
	"cpsr_fx",
	"cpsr_fxc",
	"cpsr_fs",
	"cpsr_fsc",
	"cpsr_fsx",
	"cpsr_fsxc",
	"spsr",
	"spsr_c",
	"spsr_x",
	"spsr_xc",
	"spsr_s",
	"spsr_sc",
	"spsr_sx",
	"spsr_sxc",
	"spsr_f",
	"spsr_fc",
	"spsr_fx",
	"spsr_fxc",
	"spsr_fs",
	"spsr_fsc",
	"spsr_fsx",
	"spsr_fsxc",
	"apsr_nzcv",
	"fpsid", // 0
	"fpscr", // 1
	"mvfr2", // 5
	"mvfr1", // 6
	"mvfr0", // 7
	"fpexc", // 8
	"fpinst", // 9
	"fpinst2", //10
	"msp",
	"psp",
	"primask",
	"basepri",
	"faultmask",
	"control",

	/* invalid */
	""
};

static const char* coprocRegisterCString[] = {
	"c0",
	"c1",
	"c2",
	"c3",
	"c4",
	"c5",
	"c6",
	"c7",
	"c8",
	"c9",
	"c10",
	"c11",
	"c12",
	"c13",
	"c14",
	"c15",
};

static const char* coprocRegisterString[] = {
	"p0",
	"p1",
	"p2",
	"p3",
	"p4",
	"p5",
	"p6",
	"p7",
	"p8",
	"p9",
	"p10",
	"p11",
	"p12",
	"p13",
	"p14",
	"p15",
};

static const char* condString[] = {
	"eq",
	"ne",
	"hs",
	"lo",
	"mi",
	"pl",
	"vs",
	"vc",
	"hi",
	"ls",
	"ge",
	"lt",
	"gt",
	"le",
	"", //COND_NONE
	"", //COND_NONE2
};

static const char* iflagStrings[] = {
	"none",
	"f",
	"i",
	"if",
	"a",
	"af",
	"ai",
	"aif"
};

static const char* endianSpecStrings[] = {
	"le", "be"
};

static const char* dsbOptionStrings[] = {
	"",
	"oshld", // 1
	"oshst", // 2
	"osh",   // 3
	"",
	"nshld", // 5
	"nshst", // 6
	"nsh",   // 7
	"",
	"ishld", // 9
	"ishst", // 10
	"ish",   // 11
	"",
	"ld",    // 13
	"st",    // 14
	"sy",    // 15
};

static const char* shiftString[] = {
	"", //SHIFT_NONE
	"lsl",
	"lsr",
	"asr",
	"ror",
	"rrx"
};

static const char* dataTypeString[] = {
	"",
	".s8",
	".s16",
	".s32",
	".s64",
	".u8",
	".u16",
	".u32",
	".u64",
	".i8",
	".i16",
	".i32",
	".i64",
	".f16",
	".f32",
	".f64",
	".p8",
	".p16",
	".p32",
	".p64",
	".8",
	".16",
	".32",
	".64"
};

uint32_t simdExpandImm(uint32_t op, uint32_t cmode, uint64_t imm8, uint64_t* result, DataType* dt, OperandClass* cls)
{
	uint32_t testImm = 0;
	imm8 &= 0xff;
	static uint8_t repBit[2] = {0x00,0xff};
	*cls = IMM;
	switch ((cmode >> 1) & 7)
	{
		case 0:
			testImm = 0;
			*result = (imm8 << 32) | imm8;
			*dt = DT_I32;
			break;
		case 1:
			 testImm = 1;
			 *result = (imm8 << 40) | (imm8 << 8);
			 *dt = DT_I32;
			 break;
		case 2:
			 testImm = 1;
			 *result = (imm8 << 48) | (imm8 << 16);
			 *dt = DT_I32;
			 break;
		case 3:
			 testImm = 1;
			 *result = (imm8 << 56) | (imm8 << 24);
			 *dt = DT_I32;
			 break;
		case 4:
			 testImm = 0;
			 *result = (imm8 << 48) | (imm8 << 32) | (imm8 << 16) | imm8;
			 *dt = DT_I16;
			 break;
		case 5:
			 testImm = 1;
			 *result = (imm8 << 56) | (imm8 << 40) | (imm8 << 24) | (imm8 << 8);
			 *dt = DT_I16;
			 break;
		case 6:
			testImm = 1;
			*dt = DT_I32;
			if ((cmode & 1) == 0)
				*result = (((imm8 << 8) | 0xff) << 32) | ((imm8 << 8) | 0xff);
			else
				*result = (((imm8 << 16) | 0xffff) << 32) | ((imm8 << 16) | 0xffff);
			break;
		case 7:
			testImm = 0;
			if ((cmode & 1) == 0)
			{
				if (op == 0)
				{
					*dt = DT_I8;
					*result = (imm8 << 56) | (imm8 << 48) | (imm8 << 40) | (imm8 << 32) |
						(imm8 << 24) | (imm8 << 16) | (imm8 << 8) | imm8;
				}
				else
				{
					*dt = DT_I64;
					*cls = IMM64;
					*result = ((uint64_t) repBit[imm8 & 1]) |
						(((uint64_t)repBit[(imm8 >> 1) & 1]) << 8) |
						(((uint64_t)repBit[(imm8 >> 2) & 1]) << 16) |
						(((uint64_t)repBit[(imm8 >> 3) & 1]) << 24) |
						(((uint64_t)repBit[(imm8 >> 4) & 1]) << 32) |
						(((uint64_t)repBit[(imm8 >> 5) & 1]) << 40) |
						(((uint64_t)repBit[(imm8 >> 6) & 1]) << 48) |
						(((uint64_t)repBit[(imm8 >> 7) & 1]) << 56);
				}
			}
			else
			{
				if (op == 0)
				{
					*dt = DT_F32;
					//imm32 = imm8<7>:NOT(imm8<6>):Replicate(imm8<6>,5):imm8<5:0>:Zeros(19);
					//imm64 = Replicate(imm32, 2);
					*result = ((imm8 & 0x3f) << 19) |             //19 + 6 bits
						((repBit[(imm8 >> 6) & 1] & 0x1f) << 25)| //5 bits
						(~((imm8 >> 6) & 1) << 30) |			  //1 bit
						(((imm8 >> 7) & 1) << 31);                //1 bit
					*result = (*result << 32) | *result;
				}
				else
				{
					return 0;
				}
			}
	}
	if (testImm == 1 && imm8 == 0)
		return 0;
	return 1;
}

uint64_t VFPExpandImm64(uint64_t imm8)
{
	ieee754_double t;
	uint64_t bit6 = (imm8>>6) & 1;
	uint64_t bit54 = (imm8>>4) & 3;
	uint64_t x = bit6?0xff:0;

	t.sign = imm8>>7;
	t.exponent = (~bit6) << 10 | x << 2 | bit54;
	t.fraction = (imm8 & 0xf) << 48;
	return t.value;
}

uint32_t VFPExpandImm32(uint32_t imm8)
{
	ieee754 t;
	uint32_t bit6 = (imm8>>6) & 1;
	uint32_t bit54 = (imm8>>4) & 3;
	uint32_t x = bit6?0x1f:0;

	t.sign = imm8>>7;
	t.exponent = (~bit6) << 7 | x << 2 | bit54;
	t.fraction = (imm8 & 0xf) << 19;
	return t.value;
}

Shift DecodeRegisterShift(uint32_t type)
{
	return (Shift)((type&3)+1);
}
uint32_t DecodeImmShift(uint32_t type, uint32_t imm, Shift* shift)
{
	/*
	 * (SRType, integer) DecodeImmShift(bits(2) type, bits(5) imm5)
	 * case type of
	 * 		when ‘00’
	 *			shift_t = SRType_LSL;
	 * 			shift_n = UInt(imm5);
	 * 		when ‘01’
	 *			shift_t = SRType_LSR;
	 * 			shift_n = if imm5 == ‘00000’ then 32 else UInt(imm5);
	 * 		when ‘10’
	 * 			shift_t = SRType_ASR;
	 * 			shift_n = if imm5 == ‘00000’ then 32 else UInt(imm5);
	 *		when ‘11’
	 * 			if imm5 == ‘00000’ then
	 * 				shift_t = SRType_RRX; shift_n = 1;
	 * 			else
	 * 				shift_t = SRType_ROR; shift_n = UInt(imm5);
	 * return (shift_t, shift_n);
	 *
	 */

	switch (type & 3)
	{
		case 0:
			*shift = imm==0?SHIFT_NONE:SHIFT_LSL;
			return imm;
		case 1:
			*shift = SHIFT_LSR;
			return imm == 0 ? 32 : imm;
		case 2:
			*shift = SHIFT_ASR;
			return imm == 0 ? 32 : imm;
		case 3:
			if (imm == 0)
			{
				*shift = SHIFT_RRX;
				return 1;
			}
			else
			{
				*shift = SHIFT_ROR;
				return imm;
			}
	}
	return 0;
}


uint32_t ExpandImm(uint32_t imm)
{
	uint32_t base = imm & 0xff;
	uint32_t rot = 2 * (imm >> 8);
	return (base >> rot) | (base << (32-rot));
}


uint32_t bswap32(uint32_t x)
{
	return	((x << 24) & 0xff000000 ) |
		((x <<  8) & 0x00ff0000 ) |
		((x >>  8) & 0x0000ff00 ) |
		((x >> 24) & 0x000000ff );
}


uint32_t armv7_decompose(uint32_t instructionValue,
                         Instruction* restrict instruction,
                         uint32_t address,
                         uint32_t bigEndian)
{
	/* A5.1 ARM instruction set encoding */
	union {
		struct {
			uint32_t group2:4;
			uint32_t op:1;
			uint32_t group1:20;
			uint32_t op1:3;
			uint32_t cond:4;
		};
		uint32_t value;
	} decode;

	if (bigEndian)
		decode.value = bswap32(instructionValue);
	else
		decode.value = instructionValue;

	//Decompose the instructionValue into its various groups
	static armv7_decompose_instruction group[2][8][2] = {
		{
			{armv7_data_processing_and_misc, armv7_data_processing_and_misc},
			{armv7_data_processing_and_misc, armv7_data_processing_and_misc},
			{armv7_load_store_word_and_unsigned_byte, armv7_load_store_word_and_unsigned_byte},
			{armv7_load_store_word_and_unsigned_byte, armv7_media_instructions},
			{armv7_branch_and_block_data_transfer, armv7_branch_and_block_data_transfer},
			{armv7_branch_and_block_data_transfer, armv7_branch_and_block_data_transfer},
			{armv7_coprocessor_instruction_and_supervisor_call, armv7_coprocessor_instruction_and_supervisor_call},
			{armv7_coprocessor_instruction_and_supervisor_call, armv7_coprocessor_instruction_and_supervisor_call}
		},{
			{armv7_unconditional, armv7_unconditional},
			{armv7_unconditional, armv7_unconditional},
			{armv7_unconditional, armv7_unconditional},
			{armv7_unconditional, armv7_unconditional},
			{armv7_unconditional, armv7_unconditional},
			{armv7_unconditional, armv7_unconditional},
			{armv7_unconditional, armv7_unconditional},
			{armv7_unconditional, armv7_unconditional},
		}
	};
	return group[decode.cond == 15][decode.op1][decode.op](decode.value, instruction, address);
}

uint32_t armv7_data_processing_and_misc(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
	/* A5.2 Data-processing and miscellaneous instructions */
	(void)address;
	union {
		uint32_t value;
		struct {
			uint32_t group1:4;
			uint32_t op2:4;
			uint32_t group2:12;
			uint32_t op1:5;
			uint32_t op:1;
			uint32_t id:2;
			uint32_t cond:4;
		};
	} decode;

	decode.value = instructionValue;
	if (decode.op == 0)
	{
		if ((decode.op1 & 0x19) == 0x10) //10xx0
		{
			if ((decode.op2 & 8) == 0)
				return armv7_miscellaneous(instructionValue, instruction, address);
			else if ((decode.op2 & 9) == 8)
				return armv7_halfword_multiply_and_accumulate(instructionValue, instruction, address);
		}
		else // !10xx0
		{
			if ((decode.op2 & 1) == 0)
			{
				return armv7_data_processing_reg(instructionValue, instruction, address);
			}
			else if ((decode.op2 & 9) == 1)
			{
				return armv7_data_processing_reg_shifted_reg(instructionValue, instruction, address);
			}
		}

		if ((decode.op1 & 0x10) == 0 && decode.op2 == 9) //0xxxx
			return armv7_multiply_and_accumulate(instructionValue, instruction, address);
		else if ((decode.op1 & 0x10) == 0x10 && decode.op2 == 9) //1xxxx
			return armv7_synchronization_primitives(instructionValue, instruction, address);

		if ((decode.op1 & 0x12) == 2) //0xx1x
		{
			if (decode.op2 == 11)
				return armv7_extra_load_store_unprivilaged(instructionValue, instruction, address);
		}
		else //!0xx1x
		{
			if (decode.op2 == 11 || (decode.op2 & 13) == 13)
				return armv7_extra_load_store(instructionValue, instruction, address);
		}

		if ((decode.op1 & 0x13) == 2 && (decode.op2 & 13) == 13) //0xx10
		{
			return armv7_extra_load_store(instructionValue, instruction, address);
		}

		if ((decode.op1 & 0x13) == 3 && (decode.op2 & 13) == 13) //0xx11
		{
			return armv7_extra_load_store_unprivilaged(instructionValue, instruction, address);
		}
		return 1;
	}
	else if (decode.op == 1)
	{
		if ((decode.op1 & 0x19) != 0x10)
		{
			return armv7_data_processing_imm(instructionValue, instruction, address);
		}
		else
		{
			switch (decode.op1)
			{
				case 0x10:
					{
					//MOV instruction
					union {
						uint32_t value;
						struct {
							uint32_t imm12:12;
							uint32_t rd:4;
							uint32_t imm4:4;
							uint32_t s:1;
							uint32_t group2:7;
							uint32_t cond:4;
						};
					} decode2;
					decode2.value = instructionValue;
					instruction->operation = ARMV7_MOVW;
					instruction->cond = (enum Condition)decode2.cond;
					instruction->setsFlags = 0; //decode2.s;
					instruction->operands[0].cls = REG;
					instruction->operands[0].reg = (enum Register)decode2.rd;
					instruction->operands[1].cls = IMM;
					instruction->operands[1].imm = decode2.imm4 << 12 | decode2.imm12;
					return 0;
					}
				case 0x14:
					{
					//MOVT instruction
					union {
						uint32_t value;
						struct {
							uint32_t imm12:12;
							uint32_t rd:4;
							uint32_t imm4:4;
							uint32_t group2:8;
							uint32_t cond:4;
						};
					} decode2;
					decode2.value = instructionValue;
					instruction->operation = ARMV7_MOVT;
					instruction->cond = (enum Condition)decode2.cond;
					instruction->operands[0].cls = REG;
					instruction->operands[0].reg = (enum Register)decode2.rd;
					instruction->operands[1].cls = IMM;
					instruction->operands[1].imm = (decode2.imm4 << 12) | decode2.imm12;
					return 0;
					}
				case 0x12:
				case 0x16:
					return armv7_msr_imm_and_hints(instructionValue, instruction, address);
				default:
					return armv7_data_processing_imm(instructionValue, instruction, address);
			}
		}
	}
	return 1;
}

uint32_t armv7_data_processing_reg(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
	/* A5.2.1 Data-processing (register) */
	(void)address;
	union {
		uint32_t value;
		struct {
			uint32_t rm:4;
			uint32_t zero:1;
			uint32_t type:2;
			uint32_t imm5:5;
			uint32_t rd:4;
			uint32_t rn:4;
			uint32_t s:1;
			uint32_t op:4;
			uint32_t group3:3;
			uint32_t cond:4;
		};
	} decode;

	struct opInfo {
		Operation op;
		uint32_t type;
	};
	static struct opInfo operation[] = {
		{ARMV7_AND, 0},
		{ARMV7_EOR, 0},
		{ARMV7_SUB, 0},
		{ARMV7_RSB, 0},
		{ARMV7_ADD, 0},
		{ARMV7_ADC, 0},
		{ARMV7_SBC, 0},
		{ARMV7_RSC, 0},
		{ARMV7_TST, 1},
		{ARMV7_TEQ, 1},
		{ARMV7_CMP, 1},
		{ARMV7_CMN, 1},
		{ARMV7_ORR, 0},
		{ARMV7_MOV, 2},
		{ARMV7_BIC, 0},
		{ARMV7_MVN, 3}
	};

	/* AND{S}<c> <Rd>, <Rn>, <Rm>{, <shift>}
	 * EOR{S}<c> <Rd>, <Rn>, <Rm>{, <shift>}
	 * SUB{S}<c> <Rd>, <Rn>, <Rm>{, <shift>}
	 * RSB{S}<c> <Rd>, <Rn>, <Rm>{, <shift>}
	 * ADD{S}<c> <Rd>, <Rn>, <Rm>{, <shift>}
	 * ADC{S}<c> <Rd>, <Rn>, <Rm>{, <shift>}
	 * SBC{S}<c> <Rd>, <Rn>, <Rm>{, <shift>}
	 * RSC{S}<c> <Rd>, <Rn>, <Rm>{, <shift>}
	 * BIC{S}<c> <Rd>, <Rn>, <Rm>{, <shift>}
	 * ORR{S}<c> <Rd>, <Rn>, <Rm>{, <shift>}
	 * TST<c>          <Rn>, <Rm>{, <shift>}
	 * TEQ<c>          <Rn>, <Rm>{, <shift>}
	 * CMP<c>          <Rn>, <Rm>{, <shift>}
	 * CMN<c>          <Rn>, <Rm>{, <shift>}
	 * LSL{S}<c> <Rd>, <Rm>, #<imm5>
	 * LSR{S}<c> <Rd>, <Rm>, #<imm>
	 * ASR{S}<c> <Rd>, <Rm>, #<imm>
	 * ROR{S}<c> <Rd>, <Rm>, #<imm>
	 * RRX{S}<c> <Rd>, <Rm>
	 * MOV{S}<c> <Rd>, <Rm>
	 * MVN{S}<c> <Rd>, <Rm>{, <shift>}
	 */
	decode.value = instructionValue;
	struct opInfo* info = &operation[decode.op];
	enum Shift dummy;
	instruction->operation = info->op;
	instruction->cond = (enum Condition)decode.cond;
	instruction->setsFlags = decode.s;

	if (instruction->operation == ARMV7_MOV)
	{
		/*COMPILER-BUG!!!!!
			The following table if not declared static will be allocated and assigned on the stack
			in the current stack frame.  Gcc sometimes depending on surrounding code will
			fail to initialize the opInfo.type field. Thus giving us an uninitialized value for
			info->type, and causing all kinds of bad behavior.

			The fix for now is to just declare the lookup table static causing gcc to allocate
			it in the data segment rather than the stack.
		*/
		static struct opInfo operation2[4][2] = {
			{{ARMV7_MOV, 2}, {ARMV7_LSL, 4}},
			{{ARMV7_LSR, 4}, {ARMV7_LSR, 4}},
			{{ARMV7_ASR, 4}, {ARMV7_ASR, 4}},
			{{ARMV7_RRX, 2}, {ARMV7_ROR, 4}}
		};
		info =  &operation2[decode.type][decode.imm5 != 0];
		instruction->operation = info->op;
	}

	switch (info->type)
	{
		case 0:
			instruction->operands[0].cls = REG;
			instruction->operands[0].reg = (enum Register)decode.rd;
			instruction->operands[1].cls = REG;
			instruction->operands[1].reg = (enum Register)decode.rn;
			instruction->operands[2].cls = REG;
			instruction->operands[2].reg = (enum Register)decode.rm;
			instruction->operands[2].imm = DecodeImmShift(decode.type, decode.imm5,
				&instruction->operands[2].shift);
			break;
		case 1:
			instruction->setsFlags = 0;
			instruction->operands[0].cls = REG;
			instruction->operands[0].reg = (enum Register)decode.rn;
			instruction->operands[1].cls = REG;
			instruction->operands[1].reg = (enum Register)decode.rm;
			instruction->operands[1].imm = DecodeImmShift(decode.type, decode.imm5,
				&instruction->operands[1].shift);
			break;
		case 2:
			instruction->operands[0].cls = REG;
			instruction->operands[0].reg = (enum Register)decode.rd;
			instruction->operands[1].cls = REG;
			instruction->operands[1].reg = (enum Register)decode.rm;
			break;
		case 3:
			instruction->operands[0].cls = REG;
			instruction->operands[0].reg = (enum Register)decode.rd;
			instruction->operands[1].cls = REG;
			instruction->operands[1].reg = (enum Register)decode.rm;
			instruction->operands[1].imm = DecodeImmShift(decode.type, decode.imm5,
				&instruction->operands[1].shift);
			break;
		case 4:
			instruction->operands[0].cls = REG;
			instruction->operands[0].reg = (enum Register)decode.rd;
			instruction->operands[1].cls = REG;
			instruction->operands[1].reg = (enum Register)decode.rm;
			instruction->operands[2].cls = IMM;
			instruction->operands[2].imm = DecodeImmShift(decode.type, decode.imm5, &dummy);
			break;
	}
	return 0;
}

uint32_t armv7_data_processing_reg_shifted_reg(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
	/* A5.2.2 Data-processing (register-shifted register)*/
	(void)address;
	union {
		uint32_t value;
		struct {
			uint32_t rm:4;
			uint32_t group1:1;
			uint32_t type:2;
			uint32_t group2:1;
			uint32_t rs:4;
			uint32_t rd:4;
			uint32_t rn:4;
			uint32_t s:1;
			uint32_t op:4;
			uint32_t group3:3;
			uint32_t cond:4;
		} com;
		struct {
			uint32_t rn:4;
			uint32_t group1:4;
			uint32_t rm:4;
			uint32_t rd:4;
			uint32_t group2:4;
			uint32_t s:1;
			uint32_t group3:7;
			uint32_t cond:4;
		}ror;
	} decode;


	struct opInfo {
		Operation op;
		uint32_t type;
	};
	static struct opInfo operation[] = {
		{ARMV7_AND, 0},
		{ARMV7_EOR, 0},
		{ARMV7_SUB, 0},
		{ARMV7_RSB, 0},
		{ARMV7_ADD, 0},
		{ARMV7_ADC, 0},
		{ARMV7_SBC, 0},
		{ARMV7_RSC, 0},
		{ARMV7_TST, 1},
		{ARMV7_TEQ, 1},
		{ARMV7_CMP, 1},
		{ARMV7_CMN, 1},
		{ARMV7_ORR, 0},
		{ARMV7_LSL, 2},
		{ARMV7_BIC, 0},
		{ARMV7_MVN, 3}
	};

	/* 0 AND{S}<c> <Rd>, <Rn>, <Rm>, <type> <Rs>
	 * 0 EOR{S}<c> <Rd>, <Rn>, <Rm>, <type> <Rs>
	 * 0 SUB{S}<c> <Rd>, <Rn>, <Rm>, <type> <Rs>
	 * 0 RSB{S}<c> <Rd>, <Rn>, <Rm>, <type> <Rs>
	 * 0 ADD{S}<c> <Rd>, <Rn>, <Rm>, <type> <Rs>
	 * 0 SBC{S}<c> <Rd>, <Rn>, <Rm>, <type> <Rs>
	 * 0 RSC{S}<c> <Rd>, <Rn>, <Rm>, <type> <Rs>
	 * 1 TST<c>          <Rn>, <Rm>, <type> <Rs>
	 * 1 TEQ<c>          <Rn>, <Rm>, <type> <Rs>
	 * 1 CMP<c>          <Rn>, <Rm>, <type> <Rs>
	 * 1 CMN<c>          <Rn>, <Rm>, <type> <Rs>
	 * 0 ORR{S}<c> <Rd>, <Rn>, <Rm>, <type> <Rs>
	 * 2 LSL{S}<c> <Rd>, <Rn>, <Rm>
	 * 2 LSR{S}<c> <Rd>, <Rn>, <Rm>
	 * 2 ASR{S}<c> <Rd>, <Rn>, <Rm>
	 * 2 ROR{S}<c> <Rd>, <Rn>, <Rm>
	 * 0 BIC{S}<c> <Rd>, <Rn>, <Rm>, <type> <Rs>
	 * 3 MVN{S}<c> <Rd>,       <Rm>, <type> <Rs>
	 */

	decode.value = instructionValue;
	struct opInfo* op = &operation[decode.com.op];
	instruction->operation = op->op;
	instruction->cond = (enum Condition)decode.com.cond;
	instruction->setsFlags = decode.com.s;

	if (instruction->operation == ARMV7_LSL)
	{
			static struct opInfo operation2[4] = {
				{ARMV7_LSL, 2},
				{ARMV7_LSR, 2},
				{ARMV7_ASR, 2},
				{ARMV7_ROR, 2}
			};
			op = &operation2[decode.com.type];
			instruction->operation = op->op;
			if (decode.ror.rd == 15 || decode.ror.rn == 15 ||
				decode.ror.rm == 15 || decode.ror.group2 != 0)
				instruction->unpredictable = 1;
	}

	switch (op->type)
	{
		case 0:
			instruction->operands[0].cls = REG;
			instruction->operands[0].reg = (enum Register)decode.com.rd;
			instruction->operands[1].cls = REG;
			instruction->operands[1].reg = (enum Register)decode.com.rn;
			instruction->operands[2].cls = REG;
			instruction->operands[2].reg = (enum Register)decode.com.rm;
			instruction->operands[2].shift = DecodeRegisterShift(decode.com.type);
			instruction->operands[2].offset = (enum Register)decode.com.rs;
			instruction->operands[2].flags.offsetRegUsed = 1;
			break;
		case 1:
			instruction->setsFlags = 0;
			instruction->operands[0].cls = REG;
			instruction->operands[0].reg = (enum Register)decode.com.rn;
			instruction->operands[1].cls = REG;
			instruction->operands[1].reg = (enum Register)decode.com.rm;
			instruction->operands[1].shift = DecodeRegisterShift(decode.com.type);
			instruction->operands[1].offset = (enum Register)decode.com.rs;
			instruction->operands[1].flags.offsetRegUsed = 1;
			break;
		case 2:
			instruction->operands[0].cls = REG;
			instruction->operands[0].reg = (enum Register)decode.ror.rd;
			instruction->operands[1].cls = REG;
			instruction->operands[1].reg = (enum Register)decode.ror.rn;
			instruction->operands[2].cls = REG;
			instruction->operands[2].reg = (enum Register)decode.ror.rm;
			break;
		case 3:
			instruction->operands[0].cls = REG;
			instruction->operands[0].reg = (enum Register)decode.com.rd;
			instruction->operands[1].cls = REG;
			instruction->operands[1].reg = (enum Register)decode.com.rm;
			instruction->operands[1].shift = DecodeRegisterShift(decode.com.type);
			instruction->operands[1].offset = (enum Register)decode.com.rs;
			instruction->operands[1].flags.offsetRegUsed = 1;
			break;
	}
	return 0;
}

uint32_t armv7_data_processing_imm(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
	/* A5.2.3 Data-processing (immediate) */
	(void)address;
	union {
		uint32_t value;
		struct {
			uint32_t imm:12;
			uint32_t rd:4;
			uint32_t rn:4;
			uint32_t s:1;
			uint32_t op:4;
			uint32_t group1:3;
			uint32_t cond:4;
		};
	} decode;

	static Operation operation[] = {
		ARMV7_AND,
		ARMV7_EOR,
		ARMV7_SUB,
		ARMV7_RSB,
		ARMV7_ADD,
		ARMV7_ADC,
		ARMV7_SBC,
		ARMV7_RSC,
		ARMV7_TST,
		ARMV7_TEQ,
		ARMV7_CMP,
		ARMV7_CMN,
		ARMV7_ORR,
		ARMV7_MOV,
		ARMV7_BIC,
		ARMV7_MVN,
	};

	decode.value = instructionValue;
	instruction->operation = operation[decode.op];
	instruction->cond = (enum Condition)decode.cond;
	instruction->setsFlags = decode.s;
	if ((instruction->operation == ARMV7_SUB ||
		instruction->operation == ARMV7_ADD) &&
		decode.rn == REG_PC)
	{
		instruction->operands[0].cls = REG;
		instruction->operands[0].reg = (Register)decode.rd;
		instruction->operands[1].cls = LABEL;
		instruction->operands[1].imm = address + 8;
		if (instruction->operation == ARMV7_ADD) {
			instruction->operands[1].imm += ExpandImm(decode.imm);
		}
		else {
			instruction->operands[1].imm -= ExpandImm(decode.imm);
		}
		instruction->operation = ARMV7_ADR;
		return 0;
	}
	uint32_t i = 0;
	if (instruction->operation == ARMV7_CMP ||
		instruction->operation == ARMV7_CMN ||
		instruction->operation == ARMV7_TST ||
		instruction->operation == ARMV7_TEQ)
	{
		//instruction->cond = (Condition)COND_NONE;
		instruction->setsFlags = 0;
	}
	else
	{
		instruction->operands[i].cls = REG;
		instruction->operands[i++].reg = (Register)decode.rd;
	}
	if (instruction->operation != ARMV7_MOV &&
		instruction->operation != ARMV7_MVN )
	{
		instruction->operands[i].cls = REG;
		instruction->operands[i++].reg = (Register)decode.rn;
	}
	instruction->operands[i].cls = IMM;
	instruction->operands[i].imm = ExpandImm(decode.imm);
	return 0;
}

uint32_t armv7_multiply_and_accumulate(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
	/* A5.2.5 Multiply and multiply accumulate */
	(void)address;
	union {
		uint32_t value;
		struct {
			uint32_t rn:4;
			uint32_t group1:4;
			uint32_t rm:4;
			uint32_t group2:4;
			uint32_t rd:4;
			uint32_t op:4;
			uint32_t group3:4;
			uint32_t cond:4;
		};
		struct {
			uint32_t rn:4;
			uint32_t group1:4;
			uint32_t rm:4;
			uint32_t rdlo:4;
			uint32_t rdhi:4;
			uint32_t group2:8;
			uint32_t cond:4;
		} maal;
	} decode;

	static Operation operation[] = {
		ARMV7_MUL,
		ARMV7_MUL,
		ARMV7_MLA,
		ARMV7_MLA,
		ARMV7_UMAAL,
		ARMV7_UNDEFINED,
		ARMV7_MLS,
		ARMV7_UNDEFINED,
		ARMV7_UMULL,
		ARMV7_UMULL,
		ARMV7_UMLAL,
		ARMV7_UMLAL,
		ARMV7_SMULL,
		ARMV7_SMULL,
		ARMV7_SMLAL,
		ARMV7_SMLAL
	};
	decode.value = instructionValue;
	instruction->operation = operation[decode.op];
	instruction->setsFlags = decode.op & 1;
	instruction->cond = (Condition)decode.cond;
	instruction->unpredictable = decode.rd == 15 || decode.rn == 15 || decode.rm == 15;

	uint32_t i = 0;
	if (instruction->operation == ARMV7_MLS ||
		instruction->operation == ARMV7_MLA)
	{
		instruction->operands[i].cls = REG;
		instruction->operands[i++].reg = (Register)(Register)decode.maal.rdhi;
		instruction->operands[i].cls = REG;
		instruction->operands[i++].reg = (Register)decode.rn;
		instruction->operands[i].cls = REG;
		instruction->operands[i++].reg = (Register)decode.rm;
		instruction->operands[i].cls = REG;
		instruction->operands[i].reg = (Register)(Register)decode.maal.rdlo;
	}
	else
	{
		if (instruction->operation != ARMV7_MUL)
		{
			instruction->operands[i].cls = REG;
			instruction->operands[i++].reg = (Register)(Register)decode.maal.rdlo;
		}
		instruction->operands[i].cls = REG;
		instruction->operands[i++].reg = (Register)(Register)decode.maal.rdhi;
		instruction->operands[i].cls = REG;
		instruction->operands[i++].reg = (Register)decode.rn;
		instruction->operands[i].cls = REG;
		instruction->operands[i].reg = (Register)decode.rm;
	}
	return instruction->operation == ARMV7_UNDEFINED;
}

uint32_t armv7_saturating_add_sub(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
	/* A5.2.6 Saturating addition and subtraction */
	(void)address;
	union {
		uint32_t value;
		struct {
			uint32_t rm:4;
			uint32_t group1:8;
			uint32_t rd:4;
			uint32_t rn:4;
			uint32_t op:4;
			uint32_t group3:4;
			uint32_t cond:4;
		};
	} decode;

	static Operation operation[] = {
		ARMV7_QADD,
		ARMV7_QSUB,
		ARMV7_QDADD,
		ARMV7_QDSUB
	};

	decode.value = instructionValue;
	instruction->operation = operation[(decode.op >> 1) & 3];
	instruction->setsFlags = decode.op & 1;
	instruction->cond = (Condition)decode.cond;
	instruction->unpredictable = decode.rd == 15 || decode.rn == 15 || decode.rm == 15;
	instruction->operands[0].cls = REG;
	instruction->operands[0].reg = (Register)decode.rd;
	instruction->operands[1].cls = REG;
	instruction->operands[1].reg = (Register)decode.rm;
	instruction->operands[2].cls = REG;
	instruction->operands[2].reg = (Register)decode.rn;
	return instruction->operation == ARMV7_UNDEFINED;
}

uint32_t armv7_halfword_multiply_and_accumulate(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
	/* A5.2.7 Halfword multiply and multiply accumulate */
	(void)address;
	union {
		uint32_t value;
		struct {
			uint32_t group1:5;
			uint32_t op:1;
			uint32_t group2:15;
			uint32_t op1:2;
			uint32_t group3:5;
			uint32_t cond:4;
		};
		struct {
			uint32_t rn:4;
			uint32_t group1:1;
			uint32_t n:1;
			uint32_t m:1;
			uint32_t group2:1;
			uint32_t rm:4;
			uint32_t ra:4;
			uint32_t rd:4;
			uint32_t group3:8;
			uint32_t cond:4;
		} smla;
		struct {
			uint32_t rn:4;
			uint32_t group1:2;
			uint32_t m:1;
			uint32_t group2:1;
			uint32_t rm:4;
			uint32_t ra:4;
			uint32_t rd:4;
			uint32_t group3:8;
			uint32_t cond:4;
		} smlaw;
		struct {
			uint32_t rn:4;
			uint32_t group1:2;
			uint32_t m:1;
			uint32_t group2:1;
			uint32_t rm:4;
			uint32_t group3:4;
			uint32_t rd:4;
			uint32_t group4:8;
			uint32_t cond:4;
		} smulw;
		struct {
			uint32_t rn:4;
			uint32_t group1:1;
			uint32_t n:1;
			uint32_t m:1;
			uint32_t group2:1;
			uint32_t rm:4;
			uint32_t rdlo:4;
			uint32_t rdhi:4;
			uint32_t group3:8;
			uint32_t cond:4;
		} smlal;
		struct {
			uint32_t rn:4;
			uint32_t group1:1;
			uint32_t n:1;
			uint32_t m:1;
			uint32_t group2:1;
			uint32_t rm:4;
			uint32_t group3:4;
			uint32_t rd:4;
			uint32_t group4:8;
			uint32_t cond:4;
		} smul;
	} decode;

	static Operation operation[4][4] = {
		{ARMV7_SMLABB,  ARMV7_SMLATB,  ARMV7_SMLABT,  ARMV7_SMLATT},
		{ARMV7_SMLAWT,  ARMV7_SMLAWB,  ARMV7_SMULWT,  ARMV7_SMULWB},
		{ARMV7_SMLALBB, ARMV7_SMLALTB, ARMV7_SMLALBT, ARMV7_SMLALTT},
		{ARMV7_SMULBB,  ARMV7_SMULTB,  ARMV7_SMULBT,  ARMV7_SMULTT},
	};
	decode.value = instructionValue;
	instruction->operation = operation[decode.op1][decode.op];
	instruction->cond = (Condition)decode.cond;

	switch (decode.op1)
	{
		case 0:
			{
			static Operation operation2[] = {ARMV7_SMLABB,  ARMV7_SMLATB,  ARMV7_SMLABT,  ARMV7_SMLATT};
			instruction->operation = operation2[(decode.smla.m << 1) | decode.smla.n];
			instruction->operands[0].cls = REG;
			instruction->operands[0].reg = (Register)decode.smla.rd;
			instruction->operands[1].cls = REG;
			instruction->operands[1].reg = (Register)decode.smla.rn;
			instruction->operands[2].cls = REG;
			instruction->operands[2].reg = (Register)decode.smla.rm;
			instruction->operands[3].cls = REG;
			instruction->operands[3].reg = (Register)decode.smla.ra;
			}
			break;
		case 1:
			{
			if (decode.op == 0)
			{
				if (decode.smlaw.m == 1)
					instruction->operation = ARMV7_SMLAWT;
				else
					instruction->operation = ARMV7_SMLAWB;

				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)decode.smlaw.rd;
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)decode.smlaw.rn;
				instruction->operands[2].cls = REG;
				instruction->operands[2].reg = (Register)decode.smlaw.rm;
				instruction->operands[3].cls = REG;
				instruction->operands[3].reg = (Register)decode.smlaw.ra;
			}
			else
			{
				if (decode.smulw.m == 1)
					instruction->operation = ARMV7_SMULWT;
				else
					instruction->operation = ARMV7_SMULWB;
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)decode.smulw.rd;
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)decode.smulw.rn;
				instruction->operands[2].cls = REG;
				instruction->operands[2].reg = (Register)decode.smulw.rm;
			}
			}
			break;
		case 2:
			{
			static Operation operation2[] = {ARMV7_SMLALBB, ARMV7_SMLALTB, ARMV7_SMLALBT, ARMV7_SMLALTT};
			instruction->operation = operation2[(decode.smlal.m << 1) | decode.smlal.n];
			instruction->operands[0].cls = REG;
			instruction->operands[0].reg = (Register)decode.smlal.rdlo;
			instruction->operands[1].cls = REG;
			instruction->operands[1].reg = (Register)decode.smlal.rdhi;
			instruction->operands[2].cls = REG;
			instruction->operands[2].reg = (Register)decode.smlal.rn;
			instruction->operands[3].cls = REG;
			instruction->operands[3].reg = (Register)decode.smlal.rm;
			}
			break;
		case 3:
			{
			static Operation operation2[] = {ARMV7_SMULBB,  ARMV7_SMULTB,  ARMV7_SMULBT,  ARMV7_SMULTT};
			instruction->operation = operation2[(decode.smul.m << 1) | decode.smul.n];
			instruction->operands[0].cls = REG;
			instruction->operands[0].reg = (Register)decode.smul.rd;
			instruction->operands[1].cls = REG;
			instruction->operands[1].reg = (Register)decode.smul.rn;
			instruction->operands[2].cls = REG;
			instruction->operands[2].reg = (Register)decode.smul.rm;
			}
			break;
	}
	return instruction->operation == ARMV7_UNDEFINED;
}

uint32_t armv7_extra_load_store(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
	/* A5.2.8 Extra load/store instructions */
	(void)address;
	union {
		uint32_t value;
		struct {
			uint32_t group1:5;
			uint32_t op2:2;
			uint32_t group2:13;
			uint32_t op1:5;
			uint32_t group3:3;
			uint32_t cond:4;
		};
		struct {
			uint32_t rm:4;
			uint32_t group4:4;
			uint32_t immH:4;
			uint32_t rt:4;
			uint32_t rn:4;
			uint32_t group5:1;
			uint32_t w:1;
			uint32_t group6:1;
			uint32_t u:1;
			uint32_t p:1;
			uint32_t op:3;
			uint32_t group7:7;
		};
	} decode;

	struct opInfo {
		Operation op;
		uint32_t type;
	};

	//1 => register, 2 => immediate, 3 => literal
	static struct opInfo operation[4][4] = {
		{{ARMV7_UNDEFINED, 0},  {ARMV7_UNDEFINED, 0}, {ARMV7_UNDEFINED, 0},  {ARMV7_UNDEFINED, 0}},
		{{ARMV7_STRH     , 1},  {ARMV7_LDRH     , 1}, {ARMV7_STRH     , 2},  {ARMV7_LDRH     , 2}},
		{{ARMV7_LDRD     , 1},  {ARMV7_LDRSB    , 1}, {ARMV7_LDRD     , 2},  {ARMV7_LDRSB    , 2}},
		{{ARMV7_STRD     , 1},  {ARMV7_LDRSH    , 1}, {ARMV7_STRD     , 2},  {ARMV7_LDRSH    , 2}},
	};


	decode.value = instructionValue;
	struct opInfo *opinfo = &operation[decode.op2][((decode.op1 >> 1) & 2)|(decode.op1 & 1)];

	instruction->operation = opinfo->op;
	instruction->cond = (Condition)decode.cond;
	uint32_t type = opinfo->type;
	uint32_t i = 0;
	uint32_t wback = decode.p == 0 || decode.w == 1;
	uint32_t index = decode.p;

	instruction->operands[i].cls = REG;
	instruction->operands[i++].reg = (Register)decode.rt;
	if (instruction->operation == ARMV7_STRD || instruction->operation == ARMV7_LDRD)
	{
		instruction->operands[i].cls = REG;
		instruction->operands[i++].reg = (Register)(Register)((decode.rt + 1) % 16);
	}

	//type += (decode.rn == 15 && (
	//		instruction->operation == ARMV7_LDRH ||
	//		instruction->operation == ARMV7_LDRD ||
	//		instruction->operation == ARMV7_LDRSB ||
	//		instruction->operation == ARMV7_LDRSH
	//		));

	switch (type)
	{
		case 1://Register
			{
			static OperandClass memDecode[2][2] = {
				{NONE, MEM_POST_IDX},
				{MEM_IMM,  MEM_PRE_IDX}
			};
			instruction->operands[i].cls = memDecode[index][wback];
			instruction->operands[i].reg = (Register)decode.rn;
			instruction->operands[i].flags.add = decode.u;
			instruction->operands[i].offset = (Register)decode.rm;
			instruction->operands[i].flags.offsetRegUsed = 1;
			break;
			}
		case 2://Immediate
			{
			static OperandClass memDecode[2][2] = {
				{NONE, MEM_POST_IDX},
				{MEM_IMM,  MEM_PRE_IDX}
			};
			instruction->operands[i].cls = memDecode[index][wback];
			instruction->operands[i].reg = (Register)decode.rn;
			instruction->operands[i].flags.add = decode.u;
			instruction->operands[i].imm = decode.immH << 4 | decode.rm;
			break;
			}
		case 3://Literal
			instruction->operands[i].cls = LABEL;
			if (decode.u == 1)
				instruction->operands[i].imm = address + (decode.immH << 4 | decode.rm);
			else
				instruction->operands[i].imm = address - (decode.immH << 4 | decode.rm);
			break;
		default:
			return 1;
	}
	return instruction->operation == ARMV7_UNDEFINED;
}

uint32_t armv7_extra_load_store_unprivilaged(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
	/* A5.2.9 Extra load/store instructions, unprivileged */
	(void)address;
	union {
		uint32_t value;
		struct {
			uint32_t group1:5;
			uint32_t op2:2;
			uint32_t group2:13;
			uint32_t op:1;
			uint32_t group3:1;
			uint32_t i:1;
			uint32_t group4:5;
			uint32_t cond:4;
		};
		struct {
			uint32_t rm:4;
			uint32_t group4:8;
			uint32_t rt:4;
			uint32_t rn:4;
			uint32_t group5:2;
			uint32_t i:1;
			uint32_t u:1;
			uint32_t group6:8;
		}reg;
		struct {
			uint32_t immL:4;
			uint32_t group1:4;
			uint32_t immH:4;
			uint32_t rt:4;
			uint32_t rn:4;
			uint32_t group2:2;
			uint32_t i:1;
			uint32_t u:1;
			uint32_t group3:4;
			uint32_t cond:4;
		}imm;
	} decode;

	static Operation operation[4][2] = {
		{ARMV7_UNDEFINED, ARMV7_UNDEFINED},
		{ARMV7_STRHT,     ARMV7_LDRHT},
		{ARMV7_UNDEFINED, ARMV7_LDRSBT},
		{ARMV7_UNDEFINED, ARMV7_LDRSHT}
	};

	static OperandClass memType[2] = {MEM_POST_IDX, MEM_POST_IDX};
	decode.value = instructionValue;
	instruction->operation = operation[decode.op2][decode.op];
	instruction->cond = (Condition)decode.cond;
	instruction->operands[0].cls = REG;
	instruction->operands[0].reg = (Register)decode.reg.rt;
	instruction->operands[1].cls = memType[decode.i];
	instruction->operands[1].reg = (Register)decode.reg.rn;
	instruction->operands[1].flags.add = decode.reg.u;

	if (decode.i == 0)
	{
		instruction->operands[1].offset = (Register)decode.reg.rm;
		instruction->operands[1].flags.offsetRegUsed = 1;
	}
	else
	{
		instruction->operands[1].imm = decode.imm.immH << 4 | decode.imm.immL;
	}

	return instruction->operation == ARMV7_UNDEFINED;
}

uint32_t armv7_synchronization_primitives(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
	/* A5.2.10 Synchronization primitives */
	(void)address;
	union {
		uint32_t value;
		struct {
			uint32_t rm:4;
			uint32_t group1:8;
			uint32_t rt:4;
			uint32_t rn:4;
			uint32_t op:4;
			uint32_t group4:4;
			uint32_t cond:4;
		};
		struct {
			uint32_t rt2:4;
			uint32_t group1:4;
			uint32_t group2:4;
			uint32_t rt:4;
			uint32_t rn:4;
			uint32_t group3:2;
			uint32_t b:1;
			uint32_t group4:5;
			uint32_t cond:4;
		} swp;
		struct {
			uint32_t group1:4;
			uint32_t group2:4;
			uint32_t group3:4;
			uint32_t rt:4;
			uint32_t rn:4;
			uint32_t group5:4;
			uint32_t cond:4;
		} ldrex;
		struct {
			uint32_t rt:4;
			uint32_t group1:4;
			uint32_t group2:4;
			uint32_t rd:4;
			uint32_t rn:4;
			uint32_t group3:4;
			uint32_t cond:4;
		} strexd;
	} decode;

	struct opInfo {
		Operation op;
		uint32_t type;
	};
	static struct opInfo operation[] = {
		{ARMV7_SWP,      0},
		{ARMV7_UNDEFINED,0},
		{ARMV7_UNDEFINED,0},
		{ARMV7_UNDEFINED,0},
		{ARMV7_SWPB,     0},
		{ARMV7_UNDEFINED,0},
		{ARMV7_UNDEFINED,0},
		{ARMV7_UNDEFINED,0},
		{ARMV7_STREX,    0},
		{ARMV7_LDREX,    1},
		{ARMV7_STREXD,   2},
		{ARMV7_LDREXD,   3},
		{ARMV7_STREXB,   4},
		{ARMV7_LDREXB,   1},
		{ARMV7_STREXH,   4},
		{ARMV7_LDREXH,   1}
	};

	decode.value = instructionValue;
	struct opInfo *op = &operation[decode.op];
	instruction->operation = op->op;
	instruction->cond = (Condition)decode.cond;

	switch (op->type)
	{
		case 0:
			//instruction->cond = (Condition)COND_NONE;
			instruction->operands[0].cls = REG;
			instruction->operands[0].reg = (Register)decode.swp.rt;
			instruction->operands[1].cls = REG;
			instruction->operands[1].reg = (Register)decode.swp.rt2;
			instruction->operands[2].cls = MEM_IMM;
			instruction->operands[2].flags.add = 1;
			instruction->operands[2].reg = (Register)decode.swp.rn;
			break;
		case 1:
			instruction->operands[0].cls = REG;
			instruction->operands[0].reg = (Register)decode.ldrex.rt;
			instruction->operands[1].cls = MEM_IMM;
			instruction->operands[1].flags.add = 1;
			instruction->operands[1].reg = (Register)decode.ldrex.rn;
			break;
		case 2:
			instruction->operands[0].cls = REG;
			instruction->operands[0].reg = (Register)decode.strexd.rd;
			instruction->operands[1].cls = REG;
			instruction->operands[1].reg = (Register)decode.strexd.rt;
			instruction->operands[2].cls = REG;
			instruction->operands[2].reg = (Register)(Register)((decode.strexd.rt + 1) % 16);
			instruction->operands[3].cls = MEM_IMM;
			instruction->operands[3].flags.add = 1;
			instruction->operands[3].reg = (Register)decode.strexd.rn;
			break;
		case 3:
			instruction->operands[0].cls = REG;
			instruction->operands[0].reg = (Register)decode.ldrex.rt;
			instruction->operands[1].cls = REG;
			instruction->operands[1].reg = (Register)(Register)((decode.ldrex.rt + 1) % 16);
			instruction->operands[2].cls = MEM_IMM;
			instruction->operands[2].flags.add = 1;
			instruction->operands[2].reg = (Register)decode.ldrex.rn;
			break;
		case 4:
			instruction->operands[0].cls = REG;
			instruction->operands[0].reg = (Register)decode.swp.rt;
			instruction->operands[1].cls = REG;
			instruction->operands[1].reg = (Register)decode.swp.rt2;
			instruction->operands[2].cls = MEM_IMM;
			instruction->operands[2].flags.add = 1;
			instruction->operands[2].reg = (Register)decode.swp.rn;
			break;
	}

	// A32 extends the ARMv7 encodings by specializing on the b11..b8 == (1)(1)(1)(1) field
	uint32_t b11_b8 = (instructionValue & 0xF00) >> 8;
	if(b11_b8 == 0xE) {
		switch(instruction->operation) {
			case ARMV7_LDREX: instruction->operation = ARMV7_LDAEX; break; // A32
			case ARMV7_LDREXB: instruction->operation = ARMV7_LDAEXB; break; // A32
			case ARMV7_LDREXH: instruction->operation = ARMV7_LDAEXH; break; // A32
			case ARMV7_LDREXD: instruction->operation = ARMV7_LDAEXD; break; // A32
			case ARMV7_STREX: instruction->operation = ARMV7_STLEX; break; // A32
			case ARMV7_STREXB: instruction->operation = ARMV7_STLEXB; break; // A32
			case ARMV7_STREXH: instruction->operation = ARMV7_STLEXH; break; // A32
			case ARMV7_STREXD: instruction->operation = ARMV7_STLEXD; break; // A32
			default: break;
		}
	}
	else
	if(b11_b8 == 0xC) {
		switch(instruction->operation) {
			case ARMV7_STREX:
				instruction->operation = ARMV7_STL; // A32
				instruction->operands[0] = instruction->operands[1];
				instruction->operands[1] = instruction->operands[2];
				instruction->operands[2].cls = NONE;
				break;
			default: break;
		}
	}

	return instruction->operation == ARMV7_UNDEFINED;
}

uint32_t armv7_msr_imm_and_hints(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
	/* A5.2.11 MSR (immediate), and hints */
	(void)address;
	union {
		uint32_t value;
		struct {
			uint32_t op2:8;
			uint32_t rt:4;
			uint32_t rm:4;
			uint32_t op1:4;
			uint32_t group1:2;
			uint32_t op:1;
			uint32_t group3:5;
			uint32_t cond:4;
		};
		struct {
			uint32_t imm12:12;
			uint32_t group1:6;
			uint32_t mask:2;
			uint32_t group2:8;
			uint32_t cond:4;
		}msr;
		struct {
			uint32_t imm12:12;
			uint32_t group1:4;
			uint32_t mask:4;
			uint32_t group2:2;
			uint32_t r:1;
			uint32_t group3:5;
			uint32_t cond:4;
		}msr2;
	} decode;

	decode.value = instructionValue;
	instruction->cond = (Condition)decode.cond;
	if (decode.op == 0 && decode.op1 == 0)
	{
		if (decode.op2 < 5)
		{
			static Operation operation[] = {
				ARMV7_NOP,
				ARMV7_YIELD,
				ARMV7_WFE,
				ARMV7_WFI,
				ARMV7_SEV
			};
			instruction->operation = operation[decode.op2];
			instruction->cond = (Condition)decode.cond;
		}
		else if (decode.op2 >= 240)
		{
			instruction->operation = ARMV7_DBG;
			instruction->operands[0].cls = IMM;
			instruction->operands[0].imm = decode.op2 & 15;
		}
		else
		{
			instruction->operation = ARMV7_HINT;
			instruction->operands[0].cls = IMM;
			instruction->operands[0].imm = decode.op2;
		}
	}
	else if (decode.op == 0 && (decode.op1 == 4 || (decode.op1 & 11) == 8))
	{
		instruction->operation = ARMV7_MSR;
		instruction->operands[0].cls = REG_SPEC;
		instruction->operands[0].reg = (Register)(Register)(REGS_APSR + decode.msr.mask);
		instruction->operands[1].cls = IMM;
		instruction->operands[1].imm = ExpandImm(decode.msr.imm12);
	}
	else if (decode.op == 1 ||
			(decode.op == 0 && ((decode.op1 & 3) == 1 || (decode.op1 & 2) == 2)))
	{
		instruction->operation = ARMV7_MSR;
		instruction->operands[0].cls = REG_SPEC;
		if (decode.msr2.r == 1)
			instruction->operands[0].reg = (Register)(Register)(REGS_SPSR + decode.msr2.mask);
		else
			instruction->operands[0].reg = (Register)(Register)(REGS_CPSR + decode.msr2.mask);
		instruction->operands[1].cls = IMM;
		instruction->operands[1].imm = ExpandImm(decode.msr.imm12);
	}
	return instruction->operation == ARMV7_UNDEFINED;
}

uint32_t armv7_miscellaneous(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
	/* A5.2.12 Miscellaneous instructions */
	(void)address;
	union {
		uint32_t value;
		struct {
			uint32_t group1:4;
			uint32_t op2:3;
			uint32_t group2:2;
			uint32_t b:1;
			uint32_t group3:6;
			uint32_t op1:4;
			uint32_t group4:1;
			uint32_t op:2;
			uint32_t group5:5;
			uint32_t cond:4;
		};
		struct {
			uint32_t imm4:4;
			uint32_t group1:4;
			uint32_t imm12:12;
			uint32_t group2:12;
		} set1;
		struct {
			uint32_t rm:4;
			uint32_t group1:8;
			uint32_t rd:4;
			uint32_t group2:12;
			uint32_t cond:4;
		} clz;
		struct {
			uint32_t rn:4;
			uint32_t group1:4;
			uint32_t m:1;
			uint32_t group2:3;
			uint32_t rd:4;
			uint32_t m1:4;
			uint32_t group3:2;
			uint32_t r:1;
			uint32_t group4:5;
			uint32_t cond:4;
		} msr;
	} decode;

	decode.value = instructionValue;
	switch (decode.op2)
	{
		case 0:
			if (decode.b)
			{
				uint32_t sysm = decode.msr.m << 4 | decode.msr.m1;
				static Register banked[2][32] = {
				{
					REGB_R8_USR,    REGB_R9_USR,   REGB_R10_USR,   REGB_R11_USR,
					REGB_R12_USR,   REGB_SP_USR,   REGB_LR_USR,    REG_INVALID,
					REGB_R8_FIQ,    REGB_R9_FIQ,   REGB_R10_FIQ,   REGB_R11_FIQ,
					REGB_R12_FIQ,   REGB_SP_FIQ,   REGB_LR_FIQ,    REG_INVALID,
					REGB_LR_IRQ,    REGB_SP_IRQ,   REGB_LR_SVC,    REGB_SP_SVC,
					REGB_LR_ABT,    REGB_SP_ABT,   REGB_LR_UND,    REGB_SP_UND,
					REG_INVALID,    REG_INVALID,   REG_INVALID,    REG_INVALID,
					REGB_LR_MON,    REGB_SP_MON,   REGB_ELR_HYP,   REGB_SP_HYP
				},{
					REG_INVALID,    REG_INVALID,   REG_INVALID,    REG_INVALID,
					REG_INVALID,    REG_INVALID,   REG_INVALID,    REG_INVALID,
					REG_INVALID,    REG_INVALID,   REG_INVALID,    REG_INVALID,
					REG_INVALID,    REG_INVALID,   REGB_SPSR_FIQ,  REG_INVALID,
					REGB_SPSR_IRQ,  REG_INVALID,   REGB_SPSR_SVC,  REG_INVALID,
					REGB_SPSR_ABT,  REG_INVALID,   REGB_SPSR_UND,  REG_INVALID,
					REG_INVALID,    REG_INVALID,   REG_INVALID,    REG_INVALID,
					REGB_SPSR_MON,  REG_INVALID,   REGB_SPSR_HYP,  REG_INVALID
				}
				};
				if ((decode.op & 1) == 0)
				{
					instruction->operation = ARMV7_MRS;
					instruction->cond = (Condition)decode.cond;
					instruction->operands[0].cls = REG;
					instruction->operands[0].reg = (Register)decode.msr.rd;
					instruction->operands[1].cls = REG_BANKED;
					instruction->operands[1].regb = banked[decode.msr.r][sysm];
					return instruction->operands[1].regb == REG_INVALID;
				}
				else
				{
					instruction->operation = ARMV7_MSR;
					instruction->cond = (Condition)decode.cond;
					instruction->operands[0].cls = REG_BANKED;
					instruction->operands[0].regb = banked[decode.msr.r][sysm];
					instruction->operands[1].cls = REG;
					instruction->operands[1].reg = (Register)decode.msr.rn;
					return instruction->operands[0].regb == REG_INVALID;
				}
			}
			else
			{
				switch (decode.op)
				{
					case 0:
					case 2:
						instruction->operation = ARMV7_MRS;
						instruction->cond = (Condition)decode.cond;
						instruction->operands[0].cls = REG;
						instruction->operands[0].reg = (Register)decode.msr.rd;
						instruction->operands[1].cls = REG_SPEC;
						if (decode.msr.r == 1)
							instruction->operands[1].regs = REGS_SPSR;
						else
							instruction->operands[1].regs = REGS_APSR;
						break;
					case 1:
						instruction->operation = ARMV7_MSR;
						instruction->cond = (Condition)decode.cond;
						instruction->operands[0].cls = REG_SPEC;
						if ((decode.op1 & 3) == 0)
							instruction->operands[0].regs = (Register)(REGS_APSR + (decode.msr.m1 >> 2));
						else
						{
							if (decode.msr.r == 1)
								instruction->operands[0].regs = (Register)(REGS_SPSR + decode.msr.m1);
							else
								instruction->operands[0].regs = (Register)(REGS_CPSR + decode.msr.m1);
						}
						instruction->operands[1].cls = REG;
						instruction->operands[1].reg = (Register)decode.msr.rn;
						break;
					case 3:
						instruction->operation = ARMV7_MSR;
						instruction->cond = (Condition)decode.cond;
						instruction->operands[0].cls = REG_SPEC;
						if (decode.msr.m1 == 8 || decode.msr.m1 == 4 || decode.msr.m1 == 12)
							instruction->operands[0].regs = (Register)(REGS_APSR + (decode.msr.m1 & 3));
						else
						{
							if (decode.msr.r == 1)
								instruction->operands[0].regs = (Register)(REGS_SPSR + decode.msr.m1);
							else
								instruction->operands[0].regs = (Register)(REGS_CPSR + decode.msr.m1);
						}
						instruction->operands[1].cls = REG;
						instruction->operands[1].reg = (Register)decode.msr.rn;
						break;
				}
			}
			break;
		case 1:
			if (decode.op == 1)
			{
				instruction->operation = ARMV7_BX;
				instruction->cond = (Condition)decode.cond;
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)decode.clz.rm;
			}
			else if (decode.op == 3)
			{
				instruction->operation = ARMV7_CLZ;
				instruction->cond = (Condition)decode.cond;
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)decode.clz.rd;
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)decode.clz.rm;
			}
			break;
		case 2:
			instruction->operation = ARMV7_BXJ;
			instruction->cond = (Condition)decode.cond;
			instruction->operands[0].cls = REG;
			instruction->operands[0].reg = (Register)decode.clz.rm;
			break;
		case 3:
			instruction->operation = ARMV7_BLX;
			instruction->cond = (Condition)decode.cond;
			instruction->operands[0].cls = REG;
			instruction->operands[0].reg = (Register)decode.clz.rm;
			break;
		case 5:
			return armv7_saturating_add_sub(instructionValue, instruction, address);
		case 6:
			{
			instruction->operation = ARMV7_ERET;
			instruction->cond = (Condition)decode.cond;
			break;
			}
		case 7:
			{
			static Operation operation[] = {ARMV7_UNDEFINED, ARMV7_BKPT, ARMV7_HVC, ARMV7_SMC};
			instruction->operation = operation[decode.op];
			instruction->cond = (Condition)decode.cond;
			instruction->operands[0].cls = IMM;
			if (instruction->operation == ARMV7_SMC)
				instruction->operands[0].imm = decode.set1.imm4;
			else
				instruction->operands[0].imm = decode.set1.imm12 << 4 | decode.set1.imm4;
			break;
			}
		default:
			return 1;
	}
	return instruction->operation == ARMV7_UNDEFINED;
}

uint32_t armv7_load_store_word_and_unsigned_byte(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
	/* A5.3 Load/store word and unsigned byte */
	(void)address;
	union {
		uint32_t value;
		struct {
			uint32_t group1:4;
			uint32_t b:1;
			uint32_t group2:11;
			uint32_t rn:4;
			uint32_t op1:5;
			uint32_t a:1;
			uint32_t group3:2;
			uint32_t cond:4;
		};
		struct {
			uint32_t imm12:12;
			uint32_t rt:4;
			uint32_t rn:4;
			uint32_t group1:1;
			uint32_t w:1;
			uint32_t group2:1;
			uint32_t u:1;
			uint32_t p:1;
			uint32_t group3:3;
			uint32_t cond:4;
		}stri;
		struct {
			uint32_t rm:4;
			uint32_t group1:1;
			uint32_t type:2;
			uint32_t imm5:5;
			uint32_t rt:4;
			uint32_t rn:4;
			uint32_t group2:1;
			uint32_t w:1;
			uint32_t group3:1;
			uint32_t u:1;
			uint32_t p:1;
			uint32_t group4:3;
			uint32_t cond:4;
		}strr;
	} decode;

	static Operation operation[32] =
	{
		/* 0*/ARMV7_STR,  ARMV7_LDR,  ARMV7_STRT,  ARMV7_LDRT,
		/* 4*/ARMV7_STRB, ARMV7_LDRB, ARMV7_STRBT, ARMV7_LDRBT,
		/* 8*/ARMV7_STR,  ARMV7_LDR,  ARMV7_STRT,  ARMV7_LDRT,
		/*12*/ARMV7_STRB, ARMV7_LDRB, ARMV7_STRBT, ARMV7_LDRBT,
		/*16*/ARMV7_STR,  ARMV7_LDR,  ARMV7_STR,   ARMV7_LDR,
		/*20*/ARMV7_STRB, ARMV7_LDRB, ARMV7_STRB,  ARMV7_LDRB,
		/*24*/ARMV7_STR,  ARMV7_LDR,  ARMV7_STR,   ARMV7_LDR,
		/*28*/ARMV7_STRB, ARMV7_LDRB, ARMV7_STRB,  ARMV7_LDRB
	};
	decode.value = instructionValue;
	instruction->operation = operation[decode.op1];
	instruction->cond = (Condition)decode.cond;

	static OperandClass memDecode[4] = { MEM_IMM, MEM_POST_IDX, MEM_IMM, MEM_PRE_IDX};
	uint32_t memtype = decode.stri.p << 1 | (decode.stri.p == 0 || decode.stri.w == 1);
	instruction->operands[0].cls = REG;
	instruction->operands[0].reg = (Register)decode.stri.rt;
	instruction->operands[1].reg = (Register)decode.stri.rn;
	instruction->operands[1].flags.add = decode.stri.u;

	if (decode.a == 0)
	{
		if (decode.stri.rn == REG_PC)
		{
			instruction->operands[1].cls = LABEL;
			if (decode.stri.u == 1)
				instruction->operands[1].imm = ((address + 3) & ~3) + decode.stri.imm12 + 8;
			else
				instruction->operands[1].imm = ((address + 3) & ~3) - decode.stri.imm12 + 8;
		}
		else
		{
			instruction->operands[1].cls = memDecode[memtype];
			instruction->operands[1].imm = decode.stri.imm12;
		}
	}
	else
	{
		instruction->operands[1].cls = memDecode[memtype];
		instruction->operands[1].offset = (Register)decode.strr.rm;
		instruction->operands[1].flags.offsetRegUsed = 1;
		instruction->operands[1].imm = DecodeImmShift(decode.strr.type, decode.strr.imm5,
				&instruction->operands[1].shift);
	}
	return 0;
}

uint32_t armv7_parallel_add_sub_signed(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
	//A5.4.1 Parallel addition and subtraction, signed
	(void)address;
	union {
		uint32_t value;
		struct {
			uint32_t rm:4;
			uint32_t group1:1;
			uint32_t op2:3;
			uint32_t group2:4;
			uint32_t rd:4;
			uint32_t rn:4;
			uint32_t op1:2;
			uint32_t group3:6;
			uint32_t cond:4;
		};
	}decode;
	decode.value = instructionValue;

	/* SADD16<c> <Rd>, <Rn>, <Rm>
	 * SASX<c>   <Rd>, <Rn>, <Rm>
	 * SSAX<c>   <Rd>, <Rn>, <Rm>
	 * SSUB16<c> <Rd>, <Rn>, <Rm>
	 * SADD8<c>  <Rd>, <Rn>, <Rm>
	 * SSUB8<c>  <Rd>, <Rn>, <Rm>
	 *
	 * QADD16<c> <Rd>, <Rn>, <Rm>
	 * QASX<c>   <Rd>, <Rn>, <Rm>
	 * QSAX<c>   <Rd>, <Rn>, <Rm>
	 * QSUB16<c> <Rd>, <Rn>, <Rm>
	 * QADD8<c>  <Rd>, <Rn>, <Rm>
	 * QSUB8<c>  <Rd>, <Rn>, <Rm>
	 *
	 * SHADD16<c> <Rd>, <Rn>, <Rm>
	 * SHASX<c>   <Rd>, <Rn>, <Rm>
	 * SHSAX<c>   <Rd>, <Rn>, <Rm>
	 * SHSUB16<c> <Rd>, <Rn>, <Rm>
	 * SHADD8<c>  <Rd>, <Rn>, <Rm>
	 * SHSUB8<c>  <Rd>, <Rn>, <Rm>
	 */

	static Operation operation[4][8] = {
		{
			ARMV7_UNDEFINED, ARMV7_UNDEFINED, ARMV7_UNDEFINED, ARMV7_UNDEFINED,
			ARMV7_UNDEFINED, ARMV7_UNDEFINED, ARMV7_UNDEFINED, ARMV7_UNDEFINED
		},{
			ARMV7_SADD16,  ARMV7_SASX,       ARMV7_SSAX,       ARMV7_SSUB16,
			ARMV7_SADD8,   ARMV7_UNDEFINED,  ARMV7_UNDEFINED,  ARMV7_SSUB8
		},{
			ARMV7_QADD16,  ARMV7_QASX,       ARMV7_QSAX,       ARMV7_QSUB16,
			ARMV7_QADD8,   ARMV7_UNDEFINED,  ARMV7_UNDEFINED,  ARMV7_QSUB8
		},{
			ARMV7_SHADD16,  ARMV7_SHASX,      ARMV7_SHSAX,      ARMV7_SHSUB16,
			ARMV7_SHADD8,   ARMV7_UNDEFINED,  ARMV7_UNDEFINED,  ARMV7_SHSUB8
		}
	};

	instruction->operation = operation[decode.op1][decode.op2];
	instruction->cond = (Condition)decode.cond;
	instruction->operands[0].cls = REG;
	instruction->operands[0].reg = (Register)decode.rd;
	instruction->operands[1].cls = REG;
	instruction->operands[1].reg = (Register)decode.rn;
	instruction->operands[2].cls = REG;
	instruction->operands[2].reg = (Register)decode.rm;
	return instruction->operation == ARMV7_UNDEFINED;
}
uint32_t armv7_parallel_add_sub_unsigned(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
	//A5.4.2 Parallel addition and subtraction, unsigned
	(void)address;
	union {
		uint32_t value;
		struct {
			uint32_t rm:4;
			uint32_t group1:1;
			uint32_t op2:3;
			uint32_t group2:4;
			uint32_t rd:4;
			uint32_t rn:4;
			uint32_t op1:2;
			uint32_t group3:6;
			uint32_t cond:4;
		};
	}decode;
	decode.value = instructionValue;

	/* UADD16<c> <Rd>, <Rn>, <Rm>
	 * UASX<c>   <Rd>, <Rn>, <Rm>
	 * USAX<c>   <Rd>, <Rn>, <Rm>
	 * USUB16<c> <Rd>, <Rn>, <Rm>
	 * UADD8<c>  <Rd>, <Rn>, <Rm>
	 * USUB8<c>  <Rd>, <Rn>, <Rm>
	 *
	 * UQADD16<c> <Rd>, <Rn>, <Rm>
	 * UQASX<c>   <Rd>, <Rn>, <Rm>
	 * UQSAX<c>   <Rd>, <Rn>, <Rm>
	 * UQSUB16<c> <Rd>, <Rn>, <Rm>
	 * UQADD8<c>  <Rd>, <Rn>, <Rm>
	 * UQSUB8<c>  <Rd>, <Rn>, <Rm>
	 *
	 * UHADD16<c> <Rd>, <Rn>, <Rm>
	 * UHASX<c>   <Rd>, <Rn>, <Rm>
	 * UHSAX<c>   <Rd>, <Rn>, <Rm>
	 * UHSUB16<c> <Rd>, <Rn>, <Rm>
	 * UHADD8<c>  <Rd>, <Rn>, <Rm>
	 * UHSUB8<c>  <Rd>, <Rn>, <Rm>
	 */

	static Operation operation[4][8] = {
		{
			ARMV7_UNDEFINED, ARMV7_UNDEFINED, ARMV7_UNDEFINED, ARMV7_UNDEFINED,
			ARMV7_UNDEFINED, ARMV7_UNDEFINED, ARMV7_UNDEFINED, ARMV7_UNDEFINED
		},{
			ARMV7_UADD16,  ARMV7_UASX,       ARMV7_USAX,       ARMV7_USUB16,
			ARMV7_UADD8,   ARMV7_UNDEFINED,  ARMV7_UNDEFINED,  ARMV7_USUB8
		},{
			ARMV7_UQADD16,  ARMV7_UQASX,      ARMV7_UQSAX,      ARMV7_UQSUB16,
			ARMV7_UQADD8,   ARMV7_UNDEFINED,  ARMV7_UNDEFINED,  ARMV7_UQSUB8
		},{
			ARMV7_UHADD16,  ARMV7_UHASX,      ARMV7_UHSAX,      ARMV7_UHSUB16,
			ARMV7_UHADD8,   ARMV7_UNDEFINED,  ARMV7_UNDEFINED,  ARMV7_UHSUB8
		}
	};

	instruction->operation = operation[decode.op1][decode.op2];
	instruction->cond = (Condition)decode.cond;
	instruction->operands[0].cls = REG;
	instruction->operands[0].reg = (Register)decode.rd;
	instruction->operands[1].cls = REG;
	instruction->operands[1].reg = (Register)decode.rn;
	instruction->operands[2].cls = REG;
	instruction->operands[2].reg = (Register)decode.rm;
	return instruction->operation == ARMV7_UNDEFINED;
}
uint32_t armv7_parallel_add_sub_reversal(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
	//A5.4.3 Packing, unpacking, saturation, and reversal
	(void)address;
	union {
		uint32_t value;
		struct {
			uint32_t group1:5;
			uint32_t op2:3;
			uint32_t group2:8;
			uint32_t a:4;
			uint32_t op1:3;
			uint32_t group3:5;
			uint32_t cond:4;
		}com;
		struct {
			uint32_t rm:4;
			uint32_t group1:2;
			uint32_t tb:1;
			uint32_t imm5:5;
			uint32_t rd:4;
			uint32_t rn:4;
			uint32_t group2:8;
			uint32_t cond:4;
		}pkh;
		struct {
			uint32_t rm:4;
			uint32_t group1:6;
			uint32_t rot:2;
			uint32_t rd:4;
			uint32_t rn:4;
			uint32_t group2:8;
			uint32_t cond:4;
		} sxtab;
		struct {
			uint32_t rn:4;
			uint32_t group1:2;
			uint32_t sh:1;
			uint32_t imm5:5;
			uint32_t rd:4;
			uint32_t sat_imm:5;
			uint32_t group2:7;
			uint32_t cond:4;
		}ssat;
	} decode;
	decode.value = instructionValue;

	/*
	 * PKHBT<c>   <Rd>, <Rn>, <Rm>{, LSL #<imm>}
	 * PKHTB<c>   <Rd>, <Rn>, <Rm>{, ASR #<imm>}
	 * SXTAB16<c> <Rd>, <Rn>, <Rm>{, <rotation>}
	 * SXTAB<c>   <Rd>, <Rn>, <Rm>{, <rotation>}
	 * SXTAH<c>   <Rd>, <Rn>, <Rm>{, <rotation>}
	 * UXTAB16<c> <Rd>, <Rn>, <Rm>{, <rotation>}
	 * UXTAB<c>   <Rd>, <Rn>, <Rm>{, <rotation>}
	 * UXTAH<c>   <Rd>, <Rn>, <Rm>{, <rotation>}
	 * UXTH<c>    <Rd>,       <Rm>{, <rotation>}
	 * UXTB<c>    <Rd>,       <Rm>{, <rotation>}
	 * UXTB16<c>  <Rd>,       <Rm>{, <rotation>}
	 * SXTH<c>    <Rd>,       <Rm>{, <rotation>}
	 * SXTB16<c>  <Rd>,       <Rm>{, <rotation>}
	 * SXTB<c>    <Rd>,       <Rm>{, <rotation>}
	 * SEL<c>     <Rd>, <Rn>, <Rm>
	 * SSAT<c>    <Rd>, #<imm>, <Rn>{, <shift>}
	 * USAT<c>    <Rd>, #<imm5>, <Rn>{, <shift>}
	 * SSAT16<c>  <Rd>, #<imm>, <Rn>
	 * USAT16<c>  <Rd>, #<imm4>, <Rn>
	 * REV<c>     <Rd>, <Rm>
	 * REV16<c>   <Rd>, <Rm>
	 * RBIT<c>    <Rd>, <Rm>
	 * REVSH<c>   <Rd>, <Rm>
	 */

	instruction->cond = (Condition)decode.com.cond;
	switch (decode.com.op1)
	{
		case 0:
			switch (decode.com.op2)
			{
				case 0:
				case 2:
				case 4:
				case 6:
					instruction->operands[0].cls = REG;
					instruction->operands[0].reg = (Register)decode.pkh.rd;
					instruction->operands[1].cls = REG;
					instruction->operands[1].reg = (Register)decode.pkh.rn;
					instruction->operands[2].cls = REG;
					instruction->operands[2].reg = (Register)decode.pkh.rm;
					instruction->operands[2].imm = DecodeImmShift(
							decode.pkh.tb << 1,
							decode.pkh.imm5,
							&instruction->operands[2].shift);
					if (decode.pkh.tb == 0)
						instruction->operation = ARMV7_PKHBT;
					else
						instruction->operation = ARMV7_PKHTB;
					break;
				case 3:
					{
					static Operation operation2[] = {ARMV7_SXTAB16, ARMV7_SXTB16};
					uint32_t i = 0;
					instruction->operation = operation2[decode.com.a == 15];
					instruction->operands[i].cls = REG;
					instruction->operands[i++].reg = (Register)decode.sxtab.rd;
					if (decode.com.a != 15)
					{
						instruction->operands[i].cls = REG;
						instruction->operands[i++].reg = (Register)decode.sxtab.rn;
					}
					instruction->operands[i].cls = REG;
					instruction->operands[i].reg = (Register)decode.sxtab.rm;
					instruction->operands[i].shift = SHIFT_ROR;
					instruction->operands[i].imm = decode.sxtab.rot << 3;
					break;
					}
				case 5:
					instruction->operation = ARMV7_SEL;
					instruction->operands[0].cls = REG;
					instruction->operands[0].reg = (Register)decode.pkh.rd;
					instruction->operands[1].cls = REG;
					instruction->operands[1].reg = (Register)decode.pkh.rn;
					instruction->operands[2].cls = REG;
					instruction->operands[2].reg = (Register)decode.pkh.rm;
					break;
				default:
					return 1;
			}
			break;
		case 2:
			switch (decode.com.op2)
			{
				case 0:
				case 2:
				case 4:
				case 6:
					instruction->operation = ARMV7_SSAT;
					instruction->operands[0].cls = REG;
					instruction->operands[0].reg = (Register)decode.ssat.rd;
					instruction->operands[1].cls = IMM;
					instruction->operands[1].imm = decode.ssat.sat_imm+1;
					instruction->operands[2].cls = REG;
					instruction->operands[2].reg = (Register)decode.ssat.rn;
					instruction->operands[2].imm = DecodeImmShift(
							decode.ssat.sh << 1,
							decode.ssat.imm5,
							&instruction->operands[2].shift);
					break;
				case 1:
					instruction->operation = ARMV7_SSAT16;
					instruction->operands[0].cls = REG;
					instruction->operands[0].reg = (Register)decode.ssat.rd;
					instruction->operands[1].cls = IMM;
					instruction->operands[1].imm = decode.ssat.sat_imm+1;
					instruction->operands[2].cls = REG;
					instruction->operands[2].reg = (Register)decode.ssat.rn;
					break;
				case 3:
					{
					static Operation operation2[] = {ARMV7_SXTAB, ARMV7_SXTB};
					instruction->operation = operation2[decode.com.a == 15];
					uint32_t i = 0;
					instruction->operands[i].cls = REG;
					instruction->operands[i++].reg = (Register)decode.pkh.rd;
					if (decode.com.a != 15)
					{
						instruction->operands[i].cls = REG;
						instruction->operands[i++].reg = (Register)decode.pkh.rn;
					}
					instruction->operands[i].cls = REG;
					instruction->operands[i].shift = SHIFT_ROR;
					instruction->operands[i].reg = (Register)decode.pkh.rm;
					instruction->operands[i].imm = decode.sxtab.rot << 3;
					break;
					}
				default:
					return 1;
			}
			break;
		case 3:
			switch (decode.com.op2)
			{
				case 0:
				case 2:
				case 4:
				case 6:
					instruction->operation = ARMV7_SSAT;
					instruction->operands[0].cls = REG;
					instruction->operands[0].reg = (Register)decode.ssat.rd;
					instruction->operands[1].cls = IMM;
					instruction->operands[1].imm = decode.ssat.sat_imm+1;
					instruction->operands[2].cls = REG;
					instruction->operands[2].reg = (Register)decode.ssat.rn;
					instruction->operands[2].imm = DecodeImmShift(
							decode.ssat.sh << 1,
							decode.ssat.imm5,
							&instruction->operands[2].shift);
					break;
				case 1:
					instruction->operation = ARMV7_REV;
					instruction->operands[0].cls = REG;
					instruction->operands[0].reg = (Register)decode.pkh.rd;
					instruction->operands[1].cls = REG;
					instruction->operands[1].reg = (Register)decode.pkh.rm;
					break;
				case 3:
					{
						static Operation operation2[2] = {ARMV7_SXTAH, ARMV7_SXTH};
						instruction->operation = operation2[decode.com.a == 15];
						uint32_t i = 0;
						instruction->operands[i].cls = REG;
						instruction->operands[i++].reg = (Register)decode.sxtab.rd;
						if (decode.com.a != 15)
						{
							instruction->operands[i].cls = REG;
							instruction->operands[i++].reg = (Register)decode.sxtab.rn;
						}
						instruction->operands[i].cls = REG;
						instruction->operands[i].shift = SHIFT_ROR;
						instruction->operands[i].reg = (Register)decode.sxtab.rm;
						instruction->operands[i].imm = decode.sxtab.rot << 3;
					}
					break;
				case 5:
					instruction->operation = ARMV7_REV16;
					instruction->operands[0].cls = REG;
					instruction->operands[0].reg = (Register)decode.pkh.rd;
					instruction->operands[1].cls = REG;
					instruction->operands[1].reg = (Register)decode.pkh.rm;
					break;
				default:
					return 1;
			}
			break;
		case 4:
			if (decode.com.op2 == 3)
			{
			static Operation operation2[] = {ARMV7_UXTAB16, ARMV7_UXTB16};
			instruction->operation = operation2[decode.com.a == 15];
			uint32_t i = 0;
			instruction->operands[i].cls = REG;
			instruction->operands[i++].reg = (Register)decode.pkh.rd;
			if (decode.com.a != 15)
			{
				instruction->operands[i].cls = REG;
				instruction->operands[i++].reg = (Register)decode.pkh.rn;
			}
			instruction->operands[i].cls = REG;
			instruction->operands[i].shift = SHIFT_ROR;
			instruction->operands[i].reg = (Register)decode.pkh.rm;
			instruction->operands[i].imm = decode.sxtab.rot << 3;
			}
			break;
		case 6:
		case 7:
			switch (decode.com.op2)
			{
				case 0:
				case 2:
				case 4:
				case 6:
					instruction->operation = ARMV7_USAT;
					instruction->operands[0].cls = REG;
					instruction->operands[0].reg = (Register)decode.ssat.rd;
					instruction->operands[1].cls = IMM;
					instruction->operands[1].imm = decode.ssat.sat_imm;
					instruction->operands[2].cls = REG;
					instruction->operands[2].reg = (Register)decode.ssat.rn;
					instruction->operands[2].imm = DecodeImmShift(
							decode.ssat.sh << 1,
							decode.ssat.imm5,
							&instruction->operands[2].shift);
					break;
				case 1:
					if (decode.com.op1 == 6)
					{
						instruction->operation = ARMV7_USAT16;
						instruction->operands[0].cls = REG;
						instruction->operands[0].reg = (Register)decode.ssat.rd;
						instruction->operands[1].cls = IMM;
						instruction->operands[1].imm = decode.ssat.sat_imm;
						instruction->operands[2].cls = REG;
						instruction->operands[2].reg = (Register)decode.ssat.rn;
					}
					else //decode.com.op1 == 7
					{
						instruction->operation = ARMV7_RBIT;
						instruction->operands[0].cls = REG;
						instruction->operands[0].reg = (Register)decode.pkh.rd;
						instruction->operands[1].cls = REG;
						instruction->operands[1].reg = (Register)decode.pkh.rm;
					}
					break;
				case 3:
					{
					if (decode.com.op1 == 6)
					{
						static Operation operation2[] = {ARMV7_UXTAB, ARMV7_UXTB};
						instruction->operation = operation2[decode.com.a == 15];
					}
					else //decode.com.op1 == 7
					{
						static Operation operation2[] = {ARMV7_UXTAH, ARMV7_UXTH};
						instruction->operation = operation2[decode.com.a == 15];
					}
					uint32_t i = 0;
					instruction->operands[i].cls = REG;
					instruction->operands[i++].reg = (Register)decode.pkh.rd;
					if (decode.com.a != 15)
					{
						instruction->operands[i].cls = REG;
						instruction->operands[i++].reg = (Register)decode.pkh.rn;
					}
					instruction->operands[i].cls = REG;
					instruction->operands[i].shift = SHIFT_ROR;
					instruction->operands[i].reg = (Register)decode.pkh.rm;
					instruction->operands[i].imm = decode.sxtab.rot << 3;
					}
					break;
				case 5:
					instruction->operation = ARMV7_REVSH;
					instruction->operands[0].cls = REG;
					instruction->operands[0].reg = (Register)decode.pkh.rd;
					instruction->operands[1].cls = REG;
					instruction->operands[1].reg = (Register)decode.pkh.rm;
					break;
				default:
					return 1;
			}
			break;
		default:
			return 1;
	}
	return instruction->operation == ARMV7_UNDEFINED;
}
uint32_t armv7_parallel_add_sub_udiv(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
	/*A5.4.4 Signed multiply, signed and unsigned divide*/
	(void)address;
	union {
		uint32_t value;
		struct {
			uint32_t group1:4;
			uint32_t group2:1;
			uint32_t op2:3;
			uint32_t group3:4;
			uint32_t a:4;
			uint32_t group4:4;
			uint32_t op1:3;
			uint32_t group5:5;
			uint32_t cond:4;
		}com;
		struct {
			uint32_t rn:4;
			uint32_t group1:1;
			uint32_t m:1;
			uint32_t group2:2;
			uint32_t rm:4;
			uint32_t ra:4;
			uint32_t rd:4;
			uint32_t group3:8;
			uint32_t cond:4;
		} smlad;
	} decode;
	decode.value = instructionValue;
	instruction->cond = (Condition)decode.com.cond;
	/*
	 * SMLAD{X}<c>  <Rd>, <Rn>, <Rm>, <Ra>
	 * SMUAD{X}<c>  <Rd>, <Rn>, <Rm>
	 * SMLSD{X}<c>  <Rd>, <Rn>, <Rm>, <Ra>
	 * SMUSD{X}<c>  <Rd>, <Rn>, <Rm>
	 * SDIV<c>      <Rd>, <Rn>, <Rm>
	 * UDIV<c>      <Rd>, <Rn>, <Rm>
	 * SMLALD{X}<c> <RdLo>, <RdHi>, <Rn>, <Rm>
	 * SMLSLD{X}<c> <RdLo>, <RdHi>, <Rn>, <Rm>
	 * SMMLA{R}<c>  <Rd>, <Rn>, <Rm>, <Ra>
	 * SMMUL{R}<c>  <Rd>, <Rn>, <Rm>
	 * SMMLS{R}<c>  <Rd>, <Rn>, <Rm>, <Ra>
	 */
	switch (decode.com.op1)
	{
		case 0:
			{
				static Operation operation[2][2][2] = {
					{
					{ARMV7_SMLAD, ARMV7_SMUAD},
					{ARMV7_SMLSD, ARMV7_SMUSD}
					},{
					{ARMV7_SMLADX, ARMV7_SMUADX},
					{ARMV7_SMLSDX, ARMV7_SMUSDX}
					}
				};
				if (decode.com.op2 > 3)
					break;
				instruction->operation = operation[decode.smlad.m][decode.com.op2 >> 1][decode.com.a == 15];
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)decode.smlad.rd;
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)decode.smlad.rn;
				instruction->operands[2].cls = REG;
				instruction->operands[2].reg = (Register)decode.smlad.rm;
				if (decode.com.a != 15)
				{
					instruction->operands[3].cls = REG;
					instruction->operands[3].reg = (Register)decode.smlad.ra;
				}
			}
			break;
		case 1:
			if (decode.com.op2 == 0)
			{
				instruction->operation = ARMV7_SDIV;
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)decode.smlad.rd;
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)decode.smlad.rn;
				instruction->operands[2].cls = REG;
				instruction->operands[2].reg = (Register)decode.smlad.rm;
			}
			break;
		case 3:
			if (decode.com.op2 == 0)
			{
				instruction->operation = ARMV7_UDIV;
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)decode.smlad.rd;
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)decode.smlad.rn;
				instruction->operands[2].cls = REG;
				instruction->operands[2].reg = (Register)decode.smlad.rm;
			}
			break;
		case 4:
			{
				if (decode.com.op2 > 3)
					break;

				static Operation operation[2][2] = {
					{ARMV7_SMLALD, ARMV7_SMLSLD},
					{ARMV7_SMLALDX, ARMV7_SMLSLDX}
				};
				instruction->operation = operation[decode.smlad.m][decode.com.op2 >> 1];
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)decode.smlad.ra;
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)decode.smlad.rd;
				instruction->operands[2].cls = REG;
				instruction->operands[2].reg = (Register)decode.smlad.rn;
				instruction->operands[3].cls = REG;
				instruction->operands[3].reg = (Register)decode.smlad.rm;
			}
			break;
		case 5:
			{
				if (decode.com.op2 < 2)
				{
					static Operation operation[2][2] = {
						{ARMV7_SMMLA, ARMV7_SMMUL},
						{ARMV7_SMMLAR, ARMV7_SMMULR}
					};
					instruction->operation = operation[decode.smlad.m][decode.com.a == 15];
					instruction->operands[0].cls = REG;
					instruction->operands[0].reg = (Register)decode.smlad.rd;
					instruction->operands[1].cls = REG;
					instruction->operands[1].reg = (Register)decode.smlad.rn;
					instruction->operands[2].cls = REG;
					instruction->operands[2].reg = (Register)decode.smlad.rm;
					if (decode.com.a != 15)
					{
						instruction->operands[3].cls = REG;
						instruction->operands[3].reg = (Register)decode.smlad.ra;
					}
				}
				else if (decode.com.op2 > 5)
				{
					static Operation operation[2] = {ARMV7_SMMLS, ARMV7_SMMLSR};
					instruction->operation = operation[decode.smlad.m];
					instruction->operands[0].cls = REG;
					instruction->operands[0].reg = (Register)decode.smlad.rd;
					instruction->operands[1].cls = REG;
					instruction->operands[1].reg = (Register)decode.smlad.rn;
					instruction->operands[2].cls = REG;
					instruction->operands[2].reg = (Register)decode.smlad.rm;
					instruction->operands[3].cls = REG;
					instruction->operands[3].reg = (Register)decode.smlad.ra;
				}
			}
			break;
	}
	return instruction->operation == ARMV7_UNDEFINED;
}
uint32_t armv7_media_instructions(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
	/* A5.4 Media instructions */
	union {
		uint32_t value;
		struct {
			uint32_t rn:4;
			uint32_t group1:1;
			uint32_t op2:3;
			uint32_t rm:4;
			uint32_t rd:4;
			uint32_t rx:4;
			uint32_t op1l:3;
			uint32_t op1h:2;
			uint32_t group4:3;
			uint32_t cond:4;
		}com;
		struct {
			uint32_t rn:4;
			uint32_t group1:3;
			uint32_t lsb:5;
			uint32_t rd:4;
			uint32_t widthm1:5;
			uint32_t group2:7;
			uint32_t cond:4;
		}sbfx;
		struct {
			uint32_t rn:4;
			uint32_t group1:3;
			uint32_t lsb:5;
			uint32_t rd:4;
			uint32_t msb:5;
			uint32_t group2:7;
			uint32_t cond:4;
		}bfc;
		struct {
			uint32_t imm4:4;
			uint32_t group1:4;
			uint32_t imm12:12;
			uint32_t group2:12;
		}udf;
	}decode;
	decode.value = instructionValue;

	switch (decode.com.op1h)
	{
		case 0:
			if (decode.com.op1l < 4)
				return armv7_parallel_add_sub_signed(instructionValue, instruction, address);
			return armv7_parallel_add_sub_unsigned(instructionValue, instruction, address);
		case 1:
			return armv7_parallel_add_sub_reversal(instructionValue, instruction, address);
		case 2:
			return armv7_parallel_add_sub_udiv(instructionValue, instruction, address);
	}
	/* USAD8<c>  <Rd>, <Rn>, <Rm>
	 * USADA8<c> <Rd>, <Rn>, <Rm>, <Ra>
	 * SBFX<c>   <Rd>, <Rn>, #<lsb>, #<width>
	 * BFC<c>    <Rd>, #<lsb>, #<width>
	 * BFI<c>    <Rd>, <Rn>, #<lsb>, #<width>
	 * UBFX<c>   <Rd>, <Rn>, #<lsb>, #<width>
	 * UDF<c>    #<imm16>
	 */
	instruction->operation = ARMV7_UNDEFINED;
	instruction->cond = (Condition)decode.com.cond;
	switch (decode.com.op1l)
	{
		case 0:
			if (decode.com.op2 == 0)
			{
				if (decode.com.rd == 15)
				{
					instruction->operation = ARMV7_USAD8;
					instruction->operands[0].cls = REG;
					instruction->operands[0].reg = (Register)decode.com.rx;
					instruction->operands[1].cls = REG;
					instruction->operands[1].reg = (Register)decode.com.rn;
					instruction->operands[2].cls = REG;
					instruction->operands[2].reg = (Register)decode.com.rm;
				}
				else
				{
					instruction->operation = ARMV7_USADA8;
					instruction->operands[0].cls = REG;
					instruction->operands[0].reg = (Register)decode.com.rx;
					instruction->operands[1].cls = REG;
					instruction->operands[1].reg = (Register)decode.com.rn;
					instruction->operands[2].cls = REG;
					instruction->operands[2].reg = (Register)decode.com.rm;
					instruction->operands[3].cls = REG;
					instruction->operands[3].reg = (Register)decode.com.rd;
				}
			}
			break;
		case 2:
		case 3:
			if ((decode.com.op2 & 3) == 2)
			{
				instruction->operation = ARMV7_SBFX;
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)decode.sbfx.rd;
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)decode.sbfx.rn;
				instruction->operands[2].cls = IMM;
				instruction->operands[2].imm = decode.sbfx.lsb;
				instruction->operands[3].cls = IMM;
				instruction->operands[3].imm = decode.sbfx.widthm1+1;
			}
			break;
		case 4:
		case 5:
			if ((decode.com.op2 & 3) == 0)
			{
				if (decode.com.rn == 15)
				{
					instruction->operation = ARMV7_BFC;
					if (decode.bfc.lsb > decode.bfc.msb)
						decode.bfc.lsb = decode.bfc.msb;
					instruction->operands[0].cls = REG;
					instruction->operands[0].reg = (Register)decode.bfc.rd;
					instruction->operands[1].cls = IMM;
					instruction->operands[1].imm = decode.bfc.lsb;
					instruction->operands[2].cls = IMM;
					instruction->operands[2].imm = decode.bfc.msb + 1 - decode.bfc.lsb;
				}
				else
				{
					instruction->operation = ARMV7_BFI;
					instruction->unpredictable = decode.bfc.lsb > decode.bfc.msb;
					if (decode.bfc.lsb > decode.bfc.msb)
						decode.bfc.lsb = decode.bfc.msb;
					instruction->operands[0].cls = REG;
					instruction->operands[0].reg = (Register)decode.bfc.rd;
					instruction->operands[1].cls = REG;
					instruction->operands[1].reg = (Register)decode.bfc.rn;
					instruction->operands[2].cls = IMM;
					instruction->operands[2].imm = decode.bfc.lsb;
					instruction->operands[3].cls = IMM;
					instruction->operands[3].imm = decode.bfc.msb + 1 - decode.bfc.lsb;
				}
			}
			break;
		case 6:
		case 7:
			if ((decode.com.op2 & 3) == 2)
			{
				instruction->operation = ARMV7_UBFX;
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)decode.bfc.rd;
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)decode.bfc.rn;
				instruction->operands[2].cls = IMM;
				instruction->operands[2].imm = decode.bfc.lsb;
				instruction->operands[3].cls = IMM;
				instruction->operands[3].imm = decode.bfc.msb + 1;
			}
			else if ((decode.com.op2 & 3) == 3)
			{
				instruction->cond = (Condition)COND_NONE;
				instruction->operation = ARMV7_UDF;
				instruction->operands[0].cls = IMM;
				instruction->operands[0].imm = (decode.udf.imm12 << 4) | decode.udf.imm4;
			}
			break;
	}
	return instruction->operation == ARMV7_UNDEFINED;
}
uint32_t armv7_branch_and_block_data_transfer(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
	/* A5.5 Branch, branch with link, and block data transfer */
	(void)address;
	union {
		uint32_t value;
		struct {
			uint32_t group1:15;
			uint32_t r:1;
			uint32_t rn:4;
			uint32_t op:6;
			uint32_t group2:2;
			uint32_t cond:4;
		}com;
		struct {
			uint32_t registerList:16;
			uint32_t rn:4;
			uint32_t group1:1;
			uint32_t w:1;
			uint32_t group2:6;
			uint32_t cond:4;
		}stmda;
		struct {
			uint32_t registerList:16;
			uint32_t rn:4;
			uint32_t group2:1;
			uint32_t w:1;
			uint32_t group3:1;
			uint32_t u:1;
			uint32_t p:1;
			uint32_t group4:7;
		}ldm;
		struct {
			int32_t imm:24;
			uint32_t group1:4;
			uint32_t cond:4;
		}b;
		struct {
			int32_t imm:24;
			uint32_t h:1;
			uint32_t group1:3;
			uint32_t cond:4;
		}blx;
	} decode;
	decode.value = instructionValue;

	/* STMDA<c>        <Rn>{!}, <registers>
	 * LDMDA<c>        <Rn>{!}, <registers>
	 * STM<c>          <Rn>{!}, <registers>
	 * LDM<c>          <Rn>{!}, <registers>
	 * POP<c>          <registers>; <registers> contains one register, <Rt>
	 * STMDB<c>        <Rn>{!}, <registers>
	 * STMDB<c>        <Rn>{!}, <registers>
	 * PUSH<c>         <registers>; <registers> contains more than one register
	 * PUSH<c>         <registers>; <registers> contains one register, <Rt>
	 * LDMDB<c>        <Rn>{!}, <registers>
	 * STMIB<c>        <Rn>{!}, <registers>
	 * LDMIB<c>        <Rn>{!}, <registers>
	 * STM{<amode>}<c> <Rn>, <registers>
	 * LDM{<amode>}<c> <Rn>, <registers_without_pc>
	 * LDM{<amode>}<c> <Rn>{!}, <registers_with_pc>
	 * B<c>  <label>
	 * BL<c> <label>
	 * BLX   <label>
	 */
	instruction->cond = (Condition)decode.com.cond;
	uint32_t type = 0;
	switch (decode.com.op)
	{
		case 0:
		case 2:
			instruction->operation = ARMV7_STMDA;
			break;
		case 1:
		case 3:
			instruction->operation = ARMV7_LDMDA;
			break;
		case 8:
		case 10:
			instruction->operation = ARMV7_STM;
			break;
		case 9:
			instruction->operation = ARMV7_LDM;
			break;
		case 11:
			if (decode.com.rn == REG_SP)
			{
				instruction->operation = ARMV7_POP;
				type = 1;
			}
			else
			{
				instruction->operation = ARMV7_LDM;
			}
			break;
		case 16:
			instruction->operation = ARMV7_STMDB;
			break;
		case 18:
			if (decode.com.rn == REG_SP)
			{
				instruction->operation = ARMV7_PUSH;
				type = 1;
			}
			else
			{
				instruction->operation = ARMV7_STMDB;
			}
			break;
		case 17:
		case 19:
			instruction->operation = ARMV7_LDMDB;
			break;
		case 24:
		case 26:
			instruction->operation = ARMV7_STMIB;
			break;
		case 25:
		case 27:
			instruction->operation = ARMV7_LDMIB;
			break;
		case 4: case 6: case 12: case 14: case 20: case 22: case 28: case 30:
			{
				uint32_t value = decode.ldm.p << 1 | decode.ldm.u;
				switch (value)
				{
					case 0: instruction->operation = ARMV7_STMDA; break;
					case 1: instruction->operation = ARMV7_STM; break;
					case 2: instruction->operation = ARMV7_STMDB; break;
					case 3: instruction->operation = ARMV7_STMIB; break;
				}
				type = 5;
				break;
			}
		case 5: case 7: case 13: case 15: case 21: case 23: case 29: case 31:
			{
				uint32_t value = decode.ldm.p << 1 | decode.ldm.u;
				switch (value)
				{
					case 0: instruction->operation = ARMV7_LDMDA; break;
					case 1: instruction->operation = ARMV7_LDM; break;
					case 2: instruction->operation = ARMV7_LDMDB; break;
					case 3: instruction->operation = ARMV7_LDMIB; break;
				}
				type = 5;
			break;
			}
		case 32: case 33: case 34: case 35: case 36: case 37: case 38: case 39:
		case 40: case 41: case 42: case 43: case 44: case 45: case 46: case 47:
			instruction->operation = ARMV7_B;
			type = 3;
			break;
		case 48: case 49: case 50: case 51: case 52: case 53: case 54: case 55:
		case 56: case 57: case 58: case 59: case 60: case 61: case 62: case 63:
			if (decode.com.cond == 15)
			{
				instruction->operation = ARMV7_BLX;
				type = 4;
			}
			else
			{
				instruction->operation = ARMV7_BL;
				type = 3;
			}
			break;
		default:
			return 1;
	}
	switch (type)
	{
		case 0:
			instruction->operands[0].cls = REG;
			instruction->operands[0].reg = (Register)decode.stmda.rn;
			instruction->operands[0].flags.wb = decode.stmda.w;
			instruction->operands[1].cls = REG_LIST;
			instruction->operands[1].flags.hasElements = 0;
			instruction->operands[1].reg = (Register)(Register)decode.stmda.registerList;
			break;
		case 1:
			instruction->operands[0].cls = REG_LIST;
			instruction->operands[0].flags.hasElements = 0;
			instruction->operands[0].reg = (Register)(Register)decode.stmda.registerList;
			break;
		case 2: //w/o PC
			instruction->operands[0].cls = REG;
			instruction->operands[0].reg = (Register)decode.stmda.rn;
			instruction->operands[0].flags.wb = decode.stmda.w;
			instruction->operands[1].cls = REG_LIST;
			instruction->operands[1].flags.hasElements = 0;
			instruction->operands[1].reg = (Register)(Register)(decode.stmda.registerList & 0x7fff);
			break;
		case 3:
			instruction->operands[0].cls = LABEL;
			instruction->operands[0].imm = 8 + (decode.b.imm << 2)+ address;
			break;
		case 4:
			instruction->operands[0].cls = LABEL;
			//sign extend if the high bit of blx.imm is 1
			instruction->operands[0].imm = address + 8 +
				((int32_t)((decode.blx.imm << 2 | decode.blx.h << 1) << 6) >> 6);
			break;
		case 5:
			instruction->operands[0].cls = REG;
			instruction->operands[0].reg = (Register)decode.ldm.rn;
			instruction->operands[0].flags.wb = decode.ldm.w;
			instruction->operands[1].cls = REG_LIST;
			instruction->operands[1].reg = (Register)(Register)decode.ldm.registerList;
			instruction->operands[1].flags.hasElements = 0;
			instruction->operands[1].flags.wb = 1;
			break;
		case 6:
			instruction->operands[0].cls = REG;
			instruction->operands[0].reg = (Register)decode.stmda.rn;
			instruction->operands[0].flags.wb = decode.stmda.w;
			instruction->operands[1].cls = REG_LIST;
			instruction->operands[1].reg = (Register)(Register)decode.stmda.registerList;
			instruction->operands[1].flags.hasElements = 0;
			instruction->operands[1].flags.wb = (decode.stmda.registerList >> 15) & 1;
			break;
	}
	return instruction->operation == ARMV7_UNDEFINED;
}

uint32_t armv7_coprocessor_instruction_and_supervisor_call(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
	/* A5.6 Coprocessor instructions, and Supervisor Call */
	union {
		uint32_t value;
		struct {
			uint32_t group1:4;
			uint32_t op:1;
			uint32_t group2:3;
			uint32_t coproc:4;
			uint32_t group3:4;
			uint32_t rn:4;
			uint32_t op1:6;
			uint32_t group4:2;
			uint32_t cond:4;
		}com;
		struct {
			uint32_t imm:24;
			uint32_t group1:4;
			uint32_t cond:4;
		}svc;
		struct {
			uint32_t imm8:8;
			uint32_t coproc:4;
			uint32_t crd:4;
			uint32_t rn:4;
			uint32_t group1:1;
			uint32_t w:1;
			uint32_t d:1;
			uint32_t u:1;
			uint32_t p:1;
			uint32_t group2:3;
			uint32_t cond:4;
		}stc;
		struct {
			uint32_t crm:4;
			uint32_t opc1:4;
			uint32_t coproc:4;
			uint32_t rt:4;
			uint32_t rt2:4;
			uint32_t group1:8;
			uint32_t cond:4;
		} mrrc;
		struct {
			uint32_t crm:4;
			uint32_t group1:1;
			uint32_t opc2:3;
			uint32_t coproc:4;
			uint32_t crd:4;
			uint32_t crn:4;
			uint32_t group2:1;
			uint32_t opc1:3;
			uint32_t group3:4;
			uint32_t cond:4;
		} mcr;
		struct {
			uint32_t crm:4;
			uint32_t group1:1;
			uint32_t opc2:3;
			uint32_t coproc:4;
			uint32_t crd:4;
			uint32_t crn:4;
			uint32_t opc1:4;
			uint32_t group2:4;
			uint32_t cond:4;
		} cdp;
	}decode;

	/* 0 SVC<c> #<imm24>
	 * 1 STC{2}{L}{<c>}{<q>} <coproc>, <CRd>, [<Rn>{, #+/-<imm>}]
	 * 1 STC{2}{L}{<c>}{<q>} <coproc>, <CRd>, [<Rn>, #+/-<imm>]!
	 * 1 STC{2}{L}{<c>}{<q>} <coproc>, <CRd>, [<Rn>], #+/-<imm>
	 * 1 STC{2}{L}{<c>}{<q>} <coproc>, <CRd>, [<Rn>], <option>
	 * 1 LDC{2}{L}{<c>}{<q>} <coproc>, <CRd>, [<Rn>{, #+/-<imm>}]
	 * 1 LDC{2}{L}{<c>}{<q>} <coproc>, <CRd>, [<Rn>, #+/-<imm>]!
	 * 1 LDC{2}{L}{<c>}{<q>} <coproc>, <CRd>, [<Rn>], #+/-<imm>
	 * 1 LDC{2}{L}{<c>}{<q>} <coproc>, <CRd>, [<Rn>], <option>
	 * 2 MCRR{2}<c>    <coproc>, <opc1>, <Rt>, <Rt2>, <CRm>
	 * 3 CDP{2}<c>     <coproc>, <opc1>, <CRd>, <CRn>, <CRm>, <opc2>
	 * 4 MCR{2}<c>     <coproc>, <opc1>, <Rt>, <CRn>, <CRm>{, <opc2>}
	 */
	(void)address;
	decode.value = instructionValue;
	instruction->cond = (Condition)decode.com.cond;
	uint32_t type = 0;
	if (decode.com.op1 >> 1 == 0)
	{
		instruction->operation = ARMV7_UNDEFINED;
	}
	else if (decode.com.op1 >> 4 == 3)
	{
		instruction->operation = ARMV7_SVC;
	}
	else if (decode.com.coproc >> 1 != 5)
	{
		switch (decode.com.op1)
		{
			case  2: case  6: case  8: case 10: case 12: case 14: case 16: case 18:
			case 20: case 22: case 24: case 26: case 28: case 30:
				{
					static Operation operation2[2][2] = {
						{ARMV7_STC, ARMV7_STCL},
						{ARMV7_STC2, ARMV7_STC2L}
					};
					instruction->operation = operation2[decode.stc.cond == 15][decode.stc.d];
					type = 1;
					break;
				}
			case  3: case  7: case  9: case 11: case 13: case 15: case 17: case 19:
			case 21: case 23: case 25: case 27: case 29: case 31:
				{
					static Operation operation2[2][2] = {
						{ARMV7_LDC, ARMV7_LDCL},
						{ARMV7_LDC2, ARMV7_LDC2L}
					};
					instruction->operation = operation2[decode.stc.cond == 15][decode.stc.d];
					type = 1;
					break;
				}
			case 4:
				{
				static Operation operation[2] = {ARMV7_MCRR, ARMV7_MCRR2};
				instruction->operation = operation[decode.com.cond == 15];
				type = 2;
				}
				break;
			case 5:
				{
				static Operation operation[2] = {ARMV7_MRRC, ARMV7_MRRC2};
				instruction->operation = operation[decode.com.cond == 15];
				type = 2;
				}
				break;
			case 32: case 34: case 36: case 38: case 40: case 42: case 44: case 46:
				if (decode.com.op == 0)
				{
					instruction->operation = ARMV7_CDP;
					type = 3;
				}
				else
				{
					static Operation operation[2] = {ARMV7_MCR, ARMV7_MCR2};
					instruction->operation = operation[decode.com.cond == 15];
					type = 4;
				}
				break;
			case 33: case 35: case 37: case 39: case 41: case 43: case 45: case 47:
				if (decode.com.op == 0)
				{
					instruction->operation = ARMV7_CDP;
					type = 3;
				}
				else
				{
					static Operation operation[2] = {ARMV7_MRC, ARMV7_MRC2};
					instruction->operation = operation[decode.com.cond == 15];
					type = 5;
				}
				break;
			default:
				return 1;
		}
	}
	else
	{
		switch (decode.com.op1)
		{
			case  2: case  6: case  8: case 10: case 12: case 14: case 16:
			case  3: case  7: case  9: case 11: case 13: case 15: case 17:
			case 18: case 20: case 22: case 24: case 26: case 28: case 30:
			case 19: case 21: case 23: case 25: case 27: case 29: case 31:
				return armv7_extension_register_load_store(
						instructionValue, instruction, address);
			case 4: case 5:
				return armv7_64_bit_transfers(
						instructionValue, instruction, address);
			case 32: case 34: case 36: case 38: case 40: case 42: case 44: case 46:
			case 33: case 35: case 37: case 39: case 41: case 43: case 45: case 47:
				if (decode.com.op == 0)
					return armv7_floating_point_data_processing(
							instructionValue, instruction, address);
				else
					return armv7_transfers(
							instructionValue, instruction, address);
			default:
				return 1;
		}
	}

	static OperandClass memDecode[2][2] = {
		{MEM_OPTION, MEM_POST_IDX},
		{MEM_IMM,    MEM_PRE_IDX}
	};
	instruction->operands[2].flags.add = 0;
	switch (type)
	{
		case 0:
			instruction->operands[0].cls = IMM;
			instruction->operands[0].imm = decode.svc.imm;
			break;
		case 1:
			instruction->operands[0].cls = REG_COPROCP;
			instruction->operands[0].reg = (Register)decode.stc.coproc;
			instruction->operands[1].cls = REG_COPROCC;
			instruction->operands[1].reg = (Register)decode.stc.crd;
			instruction->operands[2].cls = memDecode[decode.stc.p][decode.stc.w];
			instruction->operands[2].reg = (Register)decode.stc.rn;
			instruction->operands[2].flags.add = decode.stc.u;
			if (instruction->operands[2].cls == MEM_OPTION)
				instruction->operands[2].imm = decode.stc.imm8;
			else
				instruction->operands[2].imm = decode.stc.imm8 << 2;

			break;
		case 2:
			instruction->operands[0].cls = REG_COPROCP;
			instruction->operands[0].reg = (Register)decode.mrrc.coproc;
			instruction->operands[1].cls = IMM;
			instruction->operands[1].imm = decode.mrrc.opc1;
			instruction->operands[2].cls = REG;
			instruction->operands[2].reg = (Register)decode.mrrc.rt;
			instruction->operands[3].cls = REG;
			instruction->operands[3].reg = (Register)decode.mrrc.rt2;
			instruction->operands[4].cls = REG_COPROCC;
			instruction->operands[4].reg = (Register)decode.mrrc.crm;
			break;
		case 3:
			instruction->operands[0].cls = REG_COPROCP;
			instruction->operands[0].reg = (Register)decode.cdp.coproc;
			instruction->operands[1].cls = IMM;
			instruction->operands[1].imm = decode.cdp.opc1;
			instruction->operands[2].cls = REG_COPROCC;
			instruction->operands[2].reg = (Register)decode.cdp.crd;
			instruction->operands[3].cls = REG_COPROCC;
			instruction->operands[3].reg = (Register)decode.cdp.crn;
			instruction->operands[4].cls = REG_COPROCC;
			instruction->operands[4].reg = (Register)decode.cdp.crm;
			instruction->operands[5].cls = IMM;
			instruction->operands[5].imm = decode.cdp.opc2;
			break;
		case 4:
			instruction->operands[0].cls = REG_COPROCP;
			instruction->operands[0].reg = (Register)decode.mcr.coproc;
			instruction->operands[1].cls = IMM;
			instruction->operands[1].imm = decode.mcr.opc1;
			instruction->operands[2].cls = REG;
			instruction->operands[2].reg = (Register)decode.mcr.crd;
			instruction->operands[3].cls = REG_COPROCC;
			instruction->operands[3].reg = (Register)decode.mcr.crn;
			instruction->operands[4].cls = REG_COPROCC;
			instruction->operands[4].reg = (Register)decode.mcr.crm;
			if (decode.mcr.opc2 != 0)
			{
				instruction->operands[5].cls = IMM;
				instruction->operands[5].imm = decode.mcr.opc2;
			}
			break;
		case 5:
			instruction->operands[0].cls = REG_COPROCP;
			instruction->operands[0].reg = (Register)decode.mcr.coproc;
			instruction->operands[1].cls = IMM;
			instruction->operands[1].imm = decode.mcr.opc1;
			if (decode.mcr.crd == 15)
			{
				instruction->operands[2].cls = REG_SPEC;
				instruction->operands[2].regs = REGS_APSR_NZCV;
			}
			else
			{
				instruction->operands[2].cls = REG;
				instruction->operands[2].reg = (Register)decode.mcr.crd;
			}
			instruction->operands[3].cls = REG_COPROCC;
			instruction->operands[3].reg = (Register)decode.mcr.crn;
			instruction->operands[4].cls = REG_COPROCC;
			instruction->operands[4].reg = (Register)decode.mcr.crm;
			if (decode.mcr.opc2 != 0)
			{
				instruction->operands[5].cls = IMM;
				instruction->operands[5].imm = decode.mcr.opc2;
			}
			break;
	}
	return instruction->operation == ARMV7_UNDEFINED;
}

uint32_t armv7_unconditional(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
	/* A5.7 Unconditional instructions */
	union {
		uint32_t value;
		struct {
			uint32_t group1:4;
			uint32_t op:1;
			uint32_t group2:11;
			uint32_t rn:4;
			uint32_t op1:8;
			uint32_t cond:4;
		} com;
		struct {
			uint32_t mode:5;
			uint32_t group1:16;
			uint32_t w:1;
			uint32_t group2:1;
			uint32_t u:1;
			uint32_t p:1;
			uint32_t group3:7;
		} srs;
		struct {
			uint32_t group1:16;
			uint32_t rn:4;
			uint32_t group2:1;
			uint32_t w:1;
			uint32_t group3:1;
			uint32_t u:1;
			uint32_t p:1;
			uint32_t group4:7;
		} rfe;
		struct {
			uint32_t imm24:24;
			uint32_t h:1;
			uint32_t group1:7;
		} blx;
		struct {
			uint32_t imm:8;
			uint32_t coproc:4;
			uint32_t crd:4;
			uint32_t rn:4;
			uint32_t group1:1;
			uint32_t w:1;
			uint32_t d:1;
			uint32_t u:1;
			uint32_t p:1;
			uint32_t group2:3;
			uint32_t cond:4;
		} stc;
		struct {
			uint32_t crm:4;
			uint32_t group1:1;
			uint32_t opc2:3;
			uint32_t coproc:4;
			uint32_t crd:4;
			uint32_t crn:4;
			uint32_t opc1:4;
			uint32_t group2:4;
			uint32_t cond:4;
		} cdp;
		struct {
			uint32_t crm:4;
			uint32_t opc1:4;
			uint32_t coproc:4;
			uint32_t rt:4;
			uint32_t rt2:4;
			uint32_t group2:12;
		} mcrr;
		struct {
			uint32_t crm:4;
			uint32_t group1:1;
			uint32_t opc2:3;
			uint32_t coproc:4;
			uint32_t rt:4;
			uint32_t crn:4;
			uint32_t group2:1;
			uint32_t opc1:3;
			uint32_t group3:4;
			uint32_t cond:4;
		} mrc;
	} decode;

	/* SRS{<amode>} SP{!}, #<mode>
	 * RFE{<amode>}{<c>}{<q>} <Rn>{!}
	 * BL<c> <label>
	 * BLX   <label>
	 * STC{2}{L}{<c>}{<q>} <coproc>, <CRd>, [<Rn>{, #+/-<imm>}]
	 * STC{2}{L}{<c>}{<q>} <coproc>, <CRd>, [<Rn>, #+/-<imm>]!
	 * STC{2}{L}{<c>}{<q>} <coproc>, <CRd>, [<Rn>], #+/-<imm>
	 * STC{2}{L}{<c>}{<q>} <coproc>, <CRd>, [<Rn>], <option>
	 * LDC{2}{L}<c>        <coproc>, <CRd>, [<Rn>, #+/-<imm>]{!}
	 * LDC{2}{L}<c>        <coproc>, <CRd>, [<Rn>], #+/-<imm>
	 * LDC{2}{L}<c>        <coproc>, <CRd>, [<Rn>], <option>
	 * LDC{2}{L}{<c>}{<q>} <coproc>, <CRd>, <label>
	 * LDC{2}{L}{<c>}{<q>} <coproc>, <CRd>, [PC, #+/-<imm>]
	 * LDC{2}{L}{<c>}{<q>} <coproc>, <CRd>, [PC], <option>
	 * CDP{2}{<c>}{<q>}        <coproc>, {#}<opc1>, <CRd>, <CRn>, <CRm> {, {#}<opc2>}
	 * M{CRR|RRC}{2}{<c>}{<q>} <coproc>, {#}<opc1>, <Rt>, <Rt2>, <CRm>
	 * M{CR|RC}{2}{<c>}{<q>}   <coproc>, {#}<opc1>, <Rt>, <CRn>, <CRm>{, {#}<opc2>}
	 */
	decode.value = instructionValue;
	if (decode.com.op1 >> 7 == 0)
		return armv7_memory_hints_simd_and_misc(instructionValue, instruction, address);
	else
	{
		instruction->cond = (Condition)decode.com.cond;
		uint32_t tmp = ((decode.com.op1 >> 3) & ~3) |
			((decode.com.op1 >> 1) & 2) | (decode.com.op1 & 1);
		if (tmp == 18)
		{
			static Operation operation[2][2] = {
				{ARMV7_SRSDA, ARMV7_SRSIA},
				{ARMV7_SRSDB, ARMV7_SRSIB}
			};
			instruction->operation = operation[decode.srs.p][decode.srs.u];
			instruction->operands[0].cls = REG;
			instruction->operands[0].reg = (Register)REG_SP;
			instruction->operands[0].flags.wb = decode.srs.w;
			instruction->operands[1].cls = IMM;
			instruction->operands[1].imm = decode.srs.mode;
		}
		else if (tmp == 17)
		{
			static Operation operation[2][2] = {
				{ARMV7_RFEDA, ARMV7_RFEIA},
				{ARMV7_RFEDB, ARMV7_RFEIB}
			};
			instruction->operation = operation[decode.rfe.p][decode.rfe.u];
			instruction->operands[0].cls = REG;
			instruction->operands[0].reg = (Register)decode.rfe.rn;
			instruction->operands[0].flags.wb = decode.srs.w;
		}
		else if (decode.com.op1 >> 5 == 5)
		{
			instruction->operation = ARMV7_BLX;
			instruction->operands[0].cls = LABEL;
			//sign extend if the high bit of blx.imm is 1
			instruction->operands[0].imm = address + 8 +
				((int32_t)((decode.blx.imm24 << 2 | decode.blx.h << 1) << 6) >> 6);
		}
		else if (decode.com.op1 >> 4 == 14)
		{
			if (decode.com.op == 0)
			{
				static Operation operation[2] = {ARMV7_CDP, ARMV7_CDP2};
				instruction->operation = operation[decode.cdp.cond == 15];
				instruction->operands[0].cls = REG_COPROCP;
				instruction->operands[0].reg = (Register)decode.cdp.coproc;
				instruction->operands[1].cls = IMM;
				instruction->operands[1].imm = decode.cdp.opc1;
				instruction->operands[2].cls = REG_COPROCC;
				instruction->operands[2].reg = (Register)decode.cdp.crd;
				instruction->operands[3].cls = REG_COPROCC;
				instruction->operands[3].reg = (Register)decode.cdp.crn;
				instruction->operands[4].cls = REG_COPROCC;
				instruction->operands[4].reg = (Register)decode.cdp.crm;
				if (decode.cdp.opc2 != 0)
				{
					instruction->operands[5].cls = IMM;
					instruction->operands[5].imm = decode.cdp.opc2;
				}
			}
			else
			{
				static Operation operation[2][2] = {
					{ARMV7_MCR, ARMV7_MCR2},
					{ARMV7_MRC, ARMV7_MRC2}
				};
				instruction->operation = operation[decode.com.op1 & 1][decode.com.cond == 15];
				instruction->operands[0].cls = REG_COPROCP;
				instruction->operands[0].reg = (Register)decode.mrc.coproc;
				instruction->operands[1].cls = IMM;
				instruction->operands[1].imm = decode.mrc.opc1;
				if ((decode.com.op1 & 1) == 1 && decode.mrc.rt == 15)
				{
					instruction->operands[2].cls = REG_SPEC;
					instruction->operands[2].regs = REGS_APSR_NZCV;
				}
				else
				{
					instruction->operands[2].cls = REG;
					instruction->operands[2].reg = (Register)decode.mrc.rt;
				}
				instruction->operands[3].cls = REG_COPROCC;
				instruction->operands[3].reg = (Register)decode.mrc.crn;
				instruction->operands[4].cls = REG_COPROCC;
				instruction->operands[4].reg = (Register)decode.mrc.crm;
				if (decode.mrc.opc2 != 0)
				{
					instruction->operands[5].cls = IMM;
					instruction->operands[5].imm = decode.mrc.opc2;
				}
			}
		}
		else if (decode.com.op1 == 196)
		{
			static Operation operation[2] = {ARMV7_MCRR, ARMV7_MCRR2};
			instruction->operation = operation[decode.com.cond == 15];
			instruction->operands[0].cls = REG_COPROCP;
			instruction->operands[0].reg = (Register)decode.mcrr.coproc;
			instruction->operands[1].cls = IMM;
			instruction->operands[1].imm = decode.mcrr.opc1;
			instruction->operands[2].cls = REG;
			instruction->operands[2].reg = (Register)decode.mcrr.rt;
			instruction->operands[3].cls = REG;
			instruction->operands[3].reg = (Register)decode.mcrr.rt2;
			instruction->operands[4].cls = REG_COPROCC;
			instruction->operands[4].reg = (Register)decode.mcrr.crm;
		}
		else if (decode.com.op1 == 197)
		{
			static Operation operation[2] = {ARMV7_MRRC, ARMV7_MRRC2};
			instruction->operation = operation[decode.com.cond == 15];
			instruction->operands[0].cls = REG_COPROCP;
			instruction->operands[0].reg = (Register)decode.mcrr.coproc;
			instruction->operands[1].cls = IMM;
			instruction->operands[1].imm = decode.mcrr.opc1;
			instruction->operands[2].cls = REG;
			instruction->operands[2].reg = (Register)decode.mcrr.rt;
			instruction->operands[3].cls = REG;
			instruction->operands[3].reg = (Register)decode.mcrr.rt2;
			instruction->operands[4].cls = REG_COPROCC;
			instruction->operands[4].reg = (Register)decode.mcrr.crm;
		}
		else if ((decode.com.op1 & 1) == 0)
		{
			static Operation operation[2][2] = {
				{ARMV7_STC, ARMV7_STC2},
				{ARMV7_STCL, ARMV7_STC2L}
			};
			static OperandClass memDecode[2][2] = {
				{MEM_OPTION, MEM_POST_IDX},
				{MEM_IMM, MEM_PRE_IDX}
			};
			instruction->operation = operation[decode.stc.d][decode.stc.cond == 15];
			instruction->operands[0].cls = REG_COPROCP;
			instruction->operands[0].reg = (Register)decode.stc.coproc;
			instruction->operands[1].cls = REG_COPROCC;
			instruction->operands[1].reg = (Register)decode.stc.crd;
			instruction->operands[2].cls = memDecode[decode.stc.p][decode.stc.w];
			instruction->operands[2].reg = (Register)decode.stc.rn;
			if (instruction->operands[2].cls == MEM_OPTION)
				instruction->operands[2].imm = decode.stc.imm;
			else
				instruction->operands[2].imm = decode.stc.imm << 2;
			instruction->operands[2].flags.add = decode.stc.u;
		}
		else if ((((decode.com.op1 >> 4) & 14) | (decode.com.op1 & 1)) == 13)
		{
			static Operation operation[2][2] = {
				{ARMV7_LDC, ARMV7_LDC2},
				{ARMV7_LDCL, ARMV7_LDC2L}
			};
			static OperandClass memDecode[2][2] = {
				{MEM_OPTION, MEM_POST_IDX},
				{MEM_IMM, MEM_PRE_IDX}
			};
			instruction->operation = operation[decode.stc.d][decode.stc.cond == 15];
			instruction->operands[0].cls = REG_COPROCP;
			instruction->operands[0].reg = (Register)decode.stc.coproc;
			instruction->operands[1].cls = REG_COPROCC;
			instruction->operands[1].reg = (Register)decode.stc.crd;
			instruction->operands[2].cls = memDecode[decode.stc.p][decode.stc.w];
			if (instruction->operands[2].cls != MEM_OPTION && decode.com.rn == REG_PC)
			{
				//immediate
				instruction->operands[2].cls = LABEL;
				if (decode.stc.u == 1)
					instruction->operands[2].imm = 8 + (address & ~3) + (decode.stc.imm << 2);
				else
					instruction->operands[2].imm = 8 + (address & ~3) - (decode.stc.imm << 2);
			}
			else
			{
				//literal
				instruction->operands[2].reg = (Register)decode.stc.rn;
				if (instruction->operands[2].cls == MEM_OPTION)
					instruction->operands[2].imm = decode.stc.imm;
				else
					instruction->operands[2].imm = decode.stc.imm << 2;
				instruction->operands[2].flags.add = decode.stc.u;
			}
		}
	}
	return instruction->operation == ARMV7_UNDEFINED;
}

uint32_t armv7_memory_hints_simd_and_misc(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
	/*A5.7.1 Memory hints, Advanced SIMD instructions, and miscellaneous instructions*/
	(void)address;
	union {
		uint32_t value;
		struct {
			uint32_t group1:4;
			uint32_t op2:4;
			uint32_t group2:8;
			uint32_t rn:4;
			uint32_t op1:7;
			uint32_t group3:5;
		} com;
		struct {
			uint32_t mode:5;
			uint32_t group1:1;
			uint32_t aif:3;
			uint32_t group3:8;
			uint32_t m:1;
			uint32_t imod:2;
			uint32_t group4:12;
		} cps;
		struct {
			uint32_t imm12:12;
			uint32_t group1:4;
			uint32_t rn:4;
			uint32_t group2:2;
			uint32_t r:1;
			uint32_t u:1;
			uint32_t group3:8;
		} pli;
		struct {
			uint32_t rm:4;
			uint32_t group1:1;
			uint32_t type:2;
			uint32_t imm5:5;
			uint32_t group2:4;
			uint32_t rn:4;
			uint32_t group3:1;
			uint32_t w:1;
			uint32_t group4:1;
			uint32_t u:1;
			uint32_t group5:8;
		} plir;
	}decode;
	decode.value = instructionValue;
	instruction->cond = (Condition)COND_NONE;
	if ((decode.com.op1 >> 5) == 1)
	{
		return armv7_simd_data_processing(instructionValue, instruction, address);
	}
	else if ((decode.com.op1 & 0x71) == 64)
	{
		return armv7_simd_load_store(instructionValue, instruction, address);
	}
	else
	{
		switch (decode.com.op1)
		{
			case 16:
				if ((decode.com.rn & 1) == 0)
				{
					static Operation operation[4] = {ARMV7_CPS, ARMV7_CPS, ARMV7_CPSIE, ARMV7_CPSID};
					instruction->operation = operation[decode.cps.imod];
					uint32_t i = 0;
					if ((decode.cps.m == 1 && decode.cps.aif != 0) || decode.cps.m == 0)
					{
					instruction->operands[i].cls = IFLAGS;
					instruction->operands[i++].iflag = (Iflags)decode.cps.aif;
					}
					if ((decode.cps.m == 0 &&decode.cps.mode != 0) || decode.cps.m == 1)
					{
					instruction->operands[i].cls = IMM;
					instruction->operands[i].imm = decode.cps.mode;
					}
				}
				else
				{
					instruction->operation = ARMV7_SETEND;
					instruction->operands[0].cls = ENDIAN_SPEC;
					instruction->operands[0].endian = (EndianSpec)((instructionValue >> 9) & 1);
				}
				break;
			case 65:
			case 73:
				instruction->operation = ARMV7_NOP;
				break;
			case 69:
			case 77:
				instruction->operation = ARMV7_PLI;
				instruction->operands[0].cls = MEM_IMM;
				instruction->operands[0].reg = (Register)decode.pli.rn;
				instruction->operands[0].imm = decode.pli.imm12;
				instruction->operands[0].flags.add = decode.pli.u;
				break;
			case 81:
			case 89:
				{
					static Operation operation[2] = {ARMV7_PLDW, ARMV7_PLD};
					instruction->operation = operation[decode.pli.r];
					instruction->operands[0].cls = MEM_IMM;
					instruction->operands[0].reg = (Register)decode.pli.rn;
					instruction->operands[0].imm = decode.pli.imm12;
					instruction->operands[0].flags.add = decode.pli.u;
				}
				break;
			case 85:
			case 93:
				//if (decode.pli.rn == 15)
				{
					static Operation operation[2] = {ARMV7_PLDW, ARMV7_PLD};
					instruction->operation = operation[decode.pli.r];
					instruction->operands[0].cls = MEM_IMM;
					instruction->operands[0].reg = (Register)decode.pli.rn;
					instruction->operands[0].imm = decode.pli.imm12;
					instruction->operands[0].flags.add = decode.pli.u;
				}
				//else
				//{
				//	instruction->operation = ARMV7_PLD;
				//	instruction->operands[0].cls = LABEL;
				//	if (decode.pli.u == 1)
				//		instruction->operands[0].imm = decode.pli.imm12 + address;
				//	else
				//		instruction->operands[0].imm = address - decode.pli.imm12;
				//}
				break;
			case 87:
				switch (decode.com.op2)
				{
					case 1:
						instruction->operation = ARMV7_CLREX;
						break;
					case 4:
						instruction->operation = ARMV7_DSB;
						instruction->operands[0].cls = DSB_OPTION;
						instruction->operands[0].dsbOpt = (DsbOption)(instructionValue & 15);
						break;
					case 5:
						instruction->operation = ARMV7_DMB;
						instruction->operands[0].cls = DSB_OPTION;
						instruction->operands[0].dsbOpt = (DsbOption)(instructionValue & 15);
						break;
					case 6:
						instruction->operation = ARMV7_ISB;
						instruction->operands[0].cls = DSB_OPTION;
						instruction->operands[0].dsbOpt = (DsbOption)(instructionValue & 15);
						break;
					default:
						break;
				}
				break;
			case 97:
			case 105:
				instruction->operation = ARMV7_NOP;
				break;
			case 101:
			case 109:
				{
				instruction->operation = ARMV7_PLI;
				instruction->operands[0].cls = MEM_IMM;
				instruction->operands[0].reg = (Register)decode.plir.rn;
				instruction->operands[0].flags.add = decode.plir.u;
				instruction->operands[0].offset = (Register)decode.plir.rm;
				instruction->operands[0].flags.offsetRegUsed = 1;
				instruction->operands[0].imm = DecodeImmShift(
						decode.plir.type,
						decode.plir.imm5,
						&instruction->operands[0].shift);
				}
				break;
			case 113:
			case 121:
				{
				static Operation operation[2] = {ARMV7_PLDW, ARMV7_PLD};
				instruction->operation = operation[decode.pli.r];
				instruction->operands[0].cls = MEM_IMM;
				instruction->operands[0].reg = (Register)decode.plir.rn;
				instruction->operands[0].flags.add = decode.plir.u;
				instruction->operands[0].offset = (Register)decode.plir.rm;
				instruction->operands[0].flags.offsetRegUsed = 1;
				instruction->operands[0].imm = DecodeImmShift(
						decode.plir.type,
						decode.plir.imm5,
						&instruction->operands[0].shift);
				}
				break;
			case 117:
			case 125:
				{
				static Operation operation[2] = {ARMV7_PLDW, ARMV7_PLD};
				instruction->operation = operation[decode.pli.r];
				instruction->operands[0].cls = MEM_IMM;
				instruction->operands[0].reg = (Register)decode.plir.rn;
				instruction->operands[0].flags.add = decode.plir.u;
				instruction->operands[0].offset = (Register)decode.plir.rm;
				instruction->operands[0].flags.offsetRegUsed = 1;
				instruction->operands[0].imm = DecodeImmShift(
						decode.plir.type,
						decode.plir.imm5,
						&instruction->operands[0].shift);
				}
				break;
		}
	}
	return instruction->operation == ARMV7_UNDEFINED;
}


uint32_t armv7_simd_data_processing(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
	/*A7.4 Advanced SIMD data-processing instructions*/
	union {
		uint32_t value;
		struct {
			uint32_t group1:4;
			uint32_t c:4;
			uint32_t b:4;
			uint32_t group2:7;
			uint32_t a:5;
			uint32_t u:1;
			uint32_t group3:7;
		} com;
		struct {
			uint32_t vm:4;
			uint32_t group1:1;
			uint32_t m:1;
			uint32_t op:1;
			uint32_t n:1;
			uint32_t len:2;
			uint32_t group2:2;
			uint32_t vd:4;
			uint32_t vn:4;
			uint32_t group3:2;
			uint32_t d:1;
			uint32_t group4:9;
		} vtbl;
		struct {
			uint32_t vm:4;
			uint32_t group1:1;
			uint32_t m:1;
			uint32_t q:1;
			uint32_t n:1;
			uint32_t imm4:4;
			uint32_t vd:4;
			uint32_t vn:4;
			uint32_t group3:2;
			uint32_t d:1;
			uint32_t group4:9;
		} vext;
		struct {
			uint32_t vm:4;
			uint32_t group1:1;
			uint32_t m:1;
			uint32_t q:1;
			uint32_t group2:5;
			uint32_t vd:4;
			uint32_t imm4:4;
			uint32_t group3:2;
			uint32_t d:1;
			uint32_t group4:9;
		} vdup;
	} decode;
	decode.value = instructionValue;
	if (decode.com.a >> 4 == 0)
		return armv7_three_register_same(instructionValue, instruction, address);

	uint32_t a = decode.com.a & 7;
	if ((decode.com.c & 9) == 1 && a == 0)
		return armv7_one_register_and_modified_imm(instructionValue, instruction, address);

	if ((decode.com.c & 9) == 9 || (a > 0 && (decode.com.c & 1) == 1))
		return armv7_two_register_and_shift(instructionValue, instruction, address);

	if (a <= 5)
	{
		if ((decode.com.c & 5) == 0)
			return armv7_three_register_different(instructionValue, instruction, address);
		if ((decode.com.c & 5) == 4)
			return armv7_two_register_scalar(instructionValue, instruction, address);
	}

	if (decode.com.u == 0)
	{
		if ((decode.com.c & 1) != 0)
			return 1;
		instruction->operation = ARMV7_VEXT;
		instruction->dataType = DT_8;
		instruction->cond = (Condition)COND_NONE;
		instruction->operands[0].cls = REG;
		instruction->operands[0].reg = (Register)(regMap[decode.vext.q] + ((decode.vext.d << 4 | decode.vext.vd) >> decode.vext.q));
		instruction->operands[1].cls = REG;
		instruction->operands[1].reg = (Register)(regMap[decode.vext.q] + ((decode.vext.n << 4 | decode.vext.vn) >> decode.vext.q));
		instruction->operands[2].cls = REG;
		instruction->operands[2].reg = (Register)(regMap[decode.vext.q] + ((decode.vext.m << 4 | decode.vext.vm) >> decode.vext.q));
		instruction->operands[3].cls = IMM;
		instruction->operands[3].imm = decode.vext.imm4 * 8;
		if (decode.vext.q)
			instruction->operands[3].imm <<= 1;
	}
	else if (decode.com.b <= 7)
	{
		if ((decode.com.c & 1) != 0)
			return 1;
		return armv7_two_register_misc(instructionValue, instruction, address);
	}
	else if (decode.com.b <= 11)
	{
		if ((decode.com.c & 1) != 0)
			return 1;
		//VTBL, VTBX
		static Operation operation[2] = {ARMV7_VTBL, ARMV7_VTBX};
		instruction->operation = operation[decode.vtbl.op];
		instruction->dataType = DT_8;
		instruction->cond = (Condition)COND_NONE;
		static uint8_t sizeMap[4] = {1,3,7,15};
		uint32_t n = (decode.vtbl.n << 4) | decode.vtbl.vn;
		instruction->unpredictable = (n + decode.vtbl.len + 1) > 32;
		instruction->operands[0].cls = REG;
		instruction->operands[0].reg = (Register)(REG_D0 + ((decode.vtbl.d << 4) | decode.vtbl.vd));
		instruction->operands[1].cls = REG_LIST_DOUBLE;
		instruction->operands[1].flags.hasElements = 0;
		instruction->operands[1].reg = (Register)(sizeMap[decode.vtbl.len] << (n));
		instruction->operands[2].cls = REG;
		instruction->operands[2].reg = (Register)(REG_D0 + ((decode.vtbl.m << 4) | decode.vtbl.vm));
	}
	else if (decode.com.b == 12)
	{
		if ((decode.com.c & 9) != 0)
			return 1;
		instruction->operation = ARMV7_VDUP;
		instruction->cond = (Condition)COND_NONE;
		instruction->operands[0].cls = REG;
		instruction->operands[0].reg = (Register)(regMap[decode.vdup.q] + ((decode.vdup.d << 4 | decode.vdup.vd) >> decode.vdup.q));
		instruction->operands[1].cls = REG;
		instruction->operands[1].reg = (Register)(REG_D0 + (decode.vdup.m << 4 | decode.vdup.vm));
		instruction->operands[1].flags.hasElements = 1;

		if ((decode.vdup.imm4 & 1) == 1)
		{
			instruction->dataType = DT_8;
			instruction->operands[1].imm = (decode.vdup.imm4 >> 1) & 7;
		}
		else if ((decode.vdup.imm4 & 3) == 2)
		{
			instruction->dataType = DT_16;
			instruction->operands[1].imm = (decode.vdup.imm4 >> 2) & 3;
		}
		else if ((decode.vdup.imm4 & 7) == 4)
		{
			instruction->dataType = DT_32;
			instruction->operands[1].imm = (decode.vdup.imm4 >> 3) & 1;
		}
	}
	return instruction->operation == ARMV7_UNDEFINED;
}

uint32_t armv7_three_register_same(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
	/*A7.4.1 Three registers of the same length*/
	(void)address;
	union {
		uint32_t value;
		struct {
			uint32_t group1:4;
			uint32_t b:1;
			uint32_t group2:3;
			uint32_t a:4;
			uint32_t group3:8;
			uint32_t c:2;
			uint32_t group4:2;
			uint32_t u:1;
			uint32_t group5:7;
		} com;
		struct {
			uint32_t vm:4;
			uint32_t b:1;
			uint32_t m:1;
			uint32_t q:1;
			uint32_t n:1;
			uint32_t sz:1;
			uint32_t op:1;
			uint32_t group1:2;
			uint32_t vd:4;
			uint32_t vn:4;
			uint32_t size:2;
			uint32_t d:1;
			uint32_t group2:1;
			uint32_t u:1;
			uint32_t group3:7;
		} vh;
	} decode;
	decode.value = instructionValue;
	instruction->cond = (Condition)COND_NONE;
	instruction->operation = ARMV7_UNDEFINED;
	instruction->dataType = DECODE_DT(decode.vh.size, decode.vh.u);
	int /* checkV0 = 0, */ src1 = 1, src2 = 2;
	switch (decode.com.a)
	{
		case 0:
			{
				if (decode.com.b == 1)
					instruction->operation = ARMV7_VQADD;
				else
				{
					static Operation operation[2] = {ARMV7_VHADD, ARMV7_VHSUB};
					instruction->operation = operation[decode.vh.op];
				}
				break;
			}
		case 1:
			{
				if (decode.com.b == 0)
				{
					instruction->operation = ARMV7_VRHADD;
				}
				else
				{
					if (decode.com.u == 0)
					{
						static Operation operation[4] = {ARMV7_VAND, ARMV7_VBIC, ARMV7_VORR, ARMV7_VORN};
						instruction->operation = operation[decode.com.c];
						if (decode.com.c == 2 && decode.vh.vn == decode.vh.vm)
							instruction->operation = ARMV7_VORR;
					}
					else
					{
						static Operation operation[4] = {ARMV7_VEOR, ARMV7_VBSL, ARMV7_VBIT, ARMV7_VBIF};
						instruction->operation = operation[decode.com.c];
					}
					instruction->dataType = DT_NONE;
				}
				break;
			}
		case 2:
			{
				if (decode.com.b == 0)
				{
					static Operation operation[2]= {ARMV7_VHADD, ARMV7_VHSUB};
					instruction->operation = operation[decode.vh.op];
				}
				else
				{
					instruction->operation = ARMV7_VQSUB;
				}
				break;
			}
		case 3:
			{
				static Operation operation[2] = {ARMV7_VCGT, ARMV7_VCGE};
				instruction->operation = operation[decode.com.b];
				break;
			}
		case 4:
			{
				static Operation operation[2] = {ARMV7_VSHL, ARMV7_VQSHL};
				instruction->operation = operation[decode.com.b];
				src1 = 2;
				src2 = 1;
				break;
			}
		case 5:
			{
				static Operation operation[2] = {ARMV7_VRSHL, ARMV7_VQRSHL};
				instruction->operation = operation[decode.com.b];
				src1 = 2;
				src2 = 1;
				break;
			}
		case 6:
			{
				static Operation operation[2] = {ARMV7_VMAX, ARMV7_VMIN};
				instruction->operation = operation[decode.vh.b];
				break;
			}
		case 7:
			{
				static Operation operation[2] = {ARMV7_VABD, ARMV7_VABA};
				instruction->operation = operation[decode.com.b];
				break;
			}
		case 8:
			{
				static Operation operation[2][2] = {
					{ARMV7_VADD, ARMV7_VSUB},
					{ARMV7_VTST, ARMV7_VCEQ}
				};
				instruction->operation = operation[decode.com.b][decode.com.u];
				if (instruction->operation == ARMV7_VTST)
				{
					instruction->dataType = (DataType)(DT_8 + decode.vh.size);
					// checkV0 = decode.vh.q;
				}
				else
				{
					instruction->dataType = (DataType)(DT_I8 + decode.vh.size);
					// checkV0 = decode.vh.q;
				}
				break;
			}
		case 9:
			{
				if (decode.vh.b == 0)
				{
					static Operation operation[2] = {ARMV7_VMLA, ARMV7_VMLS};
					instruction->operation = operation[decode.com.u];
					instruction->dataType = (DataType)(DT_I8 + decode.vh.size);
				}
				else
				{
					instruction->operation = ARMV7_VMUL;
					if (decode.com.u == 1)
						instruction->dataType = (DataType)(DT_P8);
					else
					{
						instruction->dataType = (DataType)(DT_I8 + decode.vh.size);
					}
				}
				break;
			}
		case 10:
			{
				static Operation operation[2] = {ARMV7_VPMAX, ARMV7_VPMIN};
				instruction->operation = operation[decode.vh.b];
				break;
			}
		case 11:
			{
				static Operation operation[2][2] = {
					{ARMV7_VQDMULH, ARMV7_VQRDMULH},
					{ARMV7_VPADD, ARMV7_UNDEFINED}
				};
				instruction->operation = operation[decode.com.b][decode.com.u];
				if (instruction->operation == ARMV7_VPADD)
					instruction->dataType = (DataType)(DT_I8 + decode.vh.size);
				else
					instruction->dataType = (DataType)(DT_S8 + decode.vh.size);
				break;
			}
		case 12:
			{
				if (decode.com.b == 1 && decode.com.u == 0)
				{
					Operation operation[2] = {ARMV7_VFMA, ARMV7_VFMS};
					instruction->operation = operation[decode.vh.size >> 1];
					instruction->dataType = DT_F32;
				}
				break;
			}
		case 13:
			{
				if (decode.com.b == 0)
				{
					static Operation operation[2][2] = {
						{ARMV7_VADD, ARMV7_VSUB},
						{ARMV7_VPADD, ARMV7_VABD}
					};
					instruction->operation = operation[decode.com.u][decode.com.c >> 1];
					instruction->operation = (Operation)((instruction->operation == ARMV7_VMLA && decode.vh.op) + instruction->operation);
				}
				else
				{
					static Operation operation[2][2] = {
						{ARMV7_VMLA, ARMV7_VMLS},
						{ARMV7_VMUL, ARMV7_VMUL}
					};
					instruction->operation = operation[decode.com.u][decode.com.c >> 1];
				}
				instruction->dataType = DT_F32;
				break;
			}
		case 14:
			{
				if (decode.com.b == 0)
				{
					static Operation operation[2][2] = {
						{ARMV7_VCEQ, ARMV7_VCEQ},
						{ARMV7_VCGE, ARMV7_VCGT}
					};
					instruction->operation = operation[decode.com.u][decode.com.c >> 1];
				}
				else
				{
					static Operation operation[2] = {ARMV7_VACGE, ARMV7_VACGT};
					instruction->operation = operation[decode.com.c >> 1];
				}
				instruction->dataType = DT_F32;
				break;
			}
		case 15:
			{
				if (decode.com.b == 0)
				{
					static Operation operation[2][2] = {
						{ARMV7_VMAX, ARMV7_VMIN},
						{ARMV7_VPMAX, ARMV7_VPMIN}
					};
					instruction->operation = operation[decode.com.u][decode.com.c >> 1];
				}
				else
				{
					static Operation operation[2][2] = {
						{ARMV7_VRECPS, ARMV7_VRSQRTS},
						{ARMV7_UNDEFINED, ARMV7_UNDEFINED}
					};
					instruction->operation = operation[decode.com.u][decode.com.c >> 1];
				}
				instruction->dataType = DT_F32;
				break;
			}
	}

	instruction->operands[0].cls = REG;
	instruction->operands[0].reg = (Register)(regMap[decode.vh.q] + ((decode.vh.d << 4 | decode.vh.vd) >> decode.vh.q));
	instruction->operands[src1].cls = REG;
	instruction->operands[src1].reg = (Register)(regMap[decode.vh.q] + ((decode.vh.n << 4 | decode.vh.vn) >> decode.vh.q));
	instruction->operands[src2].cls = REG;
	instruction->operands[src2].reg = (Register)(regMap[decode.vh.q] + ((decode.vh.m << 4 | decode.vh.vm) >> decode.vh.q));
	return instruction->operation == ARMV7_UNDEFINED;
}

uint32_t armv7_three_register_different(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
	/*A7.4.2 Three registers of different lengths*/
	(void)address;
	union {
		uint32_t value;
		struct {
			uint32_t group1:8;
			uint32_t a:4;
			uint32_t group2:8;
			uint32_t b:2;
			uint32_t group3:2;
			uint32_t u:1;
			uint32_t group4:7;
		} com;
		struct {
			uint32_t vm:4;
			uint32_t group1:1;
			uint32_t m:1;
			uint32_t group2:1;
			uint32_t n:1;
			uint32_t op:1;
			uint32_t op2:1;
			uint32_t group3:2;
			uint32_t vd:4;
			uint32_t vn:4;
			uint32_t size:2;
			uint32_t d:1;
			uint32_t diff:1;
			uint32_t u:1;
			uint32_t group5:7;
		} vcom;
	} decode;
	decode.value = instructionValue;
	instruction->cond = (Condition)COND_NONE;

	/* VADDL<c>.<dt> <Qd>, <Dn>, <Dm>
	 * VADDW<c>.<dt> <Qd>, <Qn>, <Dm>
	 * UBL<c>.<dt> <Qd>, <Dn>, <Dm>
	 * VSUBW<c>.<dt> <Qd>, <Qn>, <Dm>
	 * VADDHN<c>.<dt> <Dd>, <Qn>, <Qm>
	 * VRADDHN<c>.<dt> <Dd>, <Qn>, <Qm>
	 * VABAL<c>.<dt> <Qd>, <Dn>, <Dm>  //A2
	 * VSUBHN<c>.<dt> <Dd>, <Qn>, <Qm>
	 * VRSUBHN<c>.<dt> <Dd>, <Qn>, <Qm>
	 * VABD<c>.<dt> <Qd>, <Qn>, <Qm>
	 * VABD<c>.<dt> <Dd>, <Dn>, <Dm>
	 * VABDL<c>.<dt> <Qd>, <Dn>, <Dm>
	 * V<op>L<c>.<dt> <Qd>, <Dn>, <Dm>
	 * VQD<op><c>.<dt> <Qd>, <Dn>, <Dm> //A1
	 * VMULL<c>.<dt> <Qd>, <Dn>, <Dm> //A2
	 * VQDMULL<c>.<dt> <Qd>, <Dn>, <Dm> //A1
	 * VMULL<c>.<dt> <Qd>, <Dn>, <Dm> //A2 op=1
	 */
	switch (decode.com.a)
	{
		case 0:
		case 1:
			{
				static Operation operation[2] = {ARMV7_VADDL, ARMV7_VADDW};
				static DataType dataType[2][4] = {
					{DT_S8, DT_S16, DT_S32, DT_NONE},
					{DT_U8, DT_U16, DT_U32, DT_NONE}
				};
				instruction->operation = operation[decode.vcom.op];
				instruction->dataType = dataType[decode.vcom.u][decode.vcom.size];
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)(REG_Q0 + (((decode.vcom.d << 4) | decode.vcom.vd) >> 1));
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)(regMap[decode.vcom.op] + (((decode.vcom.n << 4) | decode.vcom.vn) >> decode.vcom.op));
				instruction->operands[2].cls = REG;
				instruction->operands[2].reg = (Register)(REG_D0 + ((decode.vcom.m << 4) | decode.vcom.vm));
				if ((decode.vcom.vd & 1) == 1 ||
					(decode.vcom.op == 1 && (decode.vcom.vn & 1) == 1))
					return 1;
			}
			break;
		case 2:
		case 3:
			{
				static Operation operation[2] = {ARMV7_VSUBL, ARMV7_VSUBW};
				static DataType dataType[2][4] = {
					{DT_S8, DT_S16, DT_S32, DT_NONE},
					{DT_U8, DT_U16, DT_U32, DT_NONE}
				};
				instruction->operation = operation[decode.vcom.op];
				instruction->dataType = dataType[decode.vcom.u][decode.vcom.size];
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)(REG_Q0 + (((decode.vcom.d << 4) | decode.vcom.vd) >> 1));
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)(regMap[decode.vcom.op] + (((decode.vcom.n << 4) | decode.vcom.vn) >> decode.vcom.op));
				instruction->operands[2].cls = REG;
				instruction->operands[2].reg = (Register)(REG_D0 + ((decode.vcom.m << 4) | decode.vcom.vm));
				if ((decode.vcom.vd & 1) == 1 ||
					(decode.vcom.op == 1 && (decode.vcom.vn & 1) == 1))
					return 1;
			}

			break;
		case 4:
			{
				static DataType dataType[4] = {DT_I16, DT_I32, DT_I64, DT_NONE};
				static Operation operation[2] = {ARMV7_VADDHN, ARMV7_VRADDHN};
				instruction->operation = operation[decode.com.u];
				instruction->dataType = dataType[decode.vcom.size];
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)(REG_D0 + ((decode.vcom.d << 4) | decode.vcom.vd));
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)(REG_Q0 + (((decode.vcom.n << 4) | decode.vcom.vn) >> 1));
				instruction->operands[2].cls = REG;
				instruction->operands[2].reg = (Register)(REG_Q0 + (((decode.vcom.m << 4) | decode.vcom.vm) >> 1));
			}
			break;
		case 5:
			{
				static DataType dataType[2][4] = {
					{DT_S8, DT_S16, DT_S32, DT_NONE},
					{DT_U8, DT_U16, DT_U32, DT_NONE}
				};
				instruction->operation = ARMV7_VABAL;
				instruction->dataType = dataType[decode.vcom.u][decode.vcom.size];
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)(REG_Q0 + (((decode.vcom.d << 4) | decode.vcom.vd) >> 1));
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)(REG_D0 + ((decode.vcom.n << 4) | decode.vcom.vn));
				instruction->operands[2].cls = REG;
				instruction->operands[2].reg = (Register)(REG_D0 + ((decode.vcom.m << 4) | decode.vcom.vm));
			}
			break;
		case 6:
			{
				static DataType dataType[4] = {DT_I16, DT_I32, DT_I64, DT_NONE};
				static Operation operation[2] = {ARMV7_VSUBHN, ARMV7_VRSUBHN};
				instruction->operation = operation[decode.com.u];
				instruction->dataType = dataType[decode.vcom.size];
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)(REG_D0 + ((decode.vcom.d << 4) | decode.vcom.vd));
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)(REG_Q0 + (((decode.vcom.n << 4) | decode.vcom.vn) >> 1));
				instruction->operands[2].cls = REG;
				instruction->operands[2].reg = (Register)(REG_Q0 + (((decode.vcom.m << 4) | decode.vcom.vm) >> 1));
			}
			break;
		case 7:
			{
				static Operation operation[2] = {ARMV7_VABD, ARMV7_VABDL};
				static DataType dataType[2][4] = {
					{DT_S8, DT_S16, DT_S32, DT_NONE},
					{DT_U8, DT_U16, DT_U32, DT_NONE}
				};
				instruction->operation = operation[decode.vcom.diff];
				instruction->dataType = dataType[decode.vcom.u][decode.vcom.size];
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)(REG_Q0 + (((decode.vcom.d << 4) | decode.vcom.vd) >> 1));
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)(REG_D0 + ((decode.vcom.n << 4) | decode.vcom.vn));
				instruction->operands[2].cls = REG;
				instruction->operands[2].reg = (Register)(REG_D0 + ((decode.vcom.m << 4) | decode.vcom.vm));
			}
			break;
		case 8:
		case 10:
			{
				static Operation operation[2] = {ARMV7_VMLAL, ARMV7_VMLSL};
				static DataType dataType[2][4] = {
					{DT_S8, DT_S16, DT_S32, DT_NONE},
					{DT_U8, DT_U16, DT_U32, DT_NONE}
				};
				instruction->operation = operation[decode.vcom.op2];
				instruction->dataType = dataType[decode.vcom.u][decode.vcom.size];
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)(REG_Q0 + (((decode.vcom.d << 4) | decode.vcom.vd) >> 1));
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)(REG_D0 + ((decode.vcom.n << 4) | decode.vcom.vn));
				instruction->operands[2].cls = REG;
				instruction->operands[2].reg = (Register)(REG_D0 + ((decode.vcom.m << 4) | decode.vcom.vm));
			}
			break;
		case 9:
		case 11:
			if (decode.com.u == 0)
			{
				static Operation operation[2] = {ARMV7_VQDMLAL, ARMV7_VQDMLSL};
				static DataType dataType[4] = {DT_S8, DT_S16, DT_S32, DT_NONE};
				instruction->operation = operation[decode.vcom.op2];
				instruction->dataType = dataType[decode.vcom.size];
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)(REG_Q0 + (((decode.vcom.d << 4) | decode.vcom.vd) >> 1));
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)(REG_D0 + ((decode.vcom.n << 4) | decode.vcom.vn));
				instruction->operands[2].cls = REG;
				instruction->operands[2].reg = (Register)(REG_D0 + ((decode.vcom.m << 4) | decode.vcom.vm));
			}
			break;
		case 12: //op = 0
			{
				static DataType dataType[2][4] = {
					{DT_S8, DT_S16, DT_S32, DT_NONE},
					{DT_U8, DT_U16, DT_U32, DT_NONE}
				};
				instruction->operation = ARMV7_VMULL;
				instruction->dataType = dataType[decode.vcom.u][decode.vcom.size];
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)(REG_Q0 + (((decode.vcom.d << 4) | decode.vcom.vd) >> 1));
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)(REG_D0 + ((decode.vcom.n << 4) | decode.vcom.vn));
				instruction->operands[2].cls = REG;
				instruction->operands[2].reg = (Register)(REG_D0 + ((decode.vcom.m << 4) | decode.vcom.vm));
			}
			break;
		case 13:
			if (decode.com.u == 0)
			{
				static DataType dataType[4] = {DT_S8, DT_S16, DT_S32, DT_NONE};
				instruction->operation = ARMV7_VQDMULL;
				instruction->dataType = dataType[decode.vcom.size];
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)(REG_Q0 + (((decode.vcom.d << 4) | decode.vcom.vd) >> 1));
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)(REG_D0 + ((decode.vcom.n << 4) | decode.vcom.vn));
				instruction->operands[2].cls = REG;
				instruction->operands[2].reg = (Register)(REG_D0 + ((decode.vcom.m << 4) | decode.vcom.vm));
			}
			break;
		case 14: //op = 1
			{
				static DataType dataType[4] = {DT_P8, DT_P16, DT_P32, DT_NONE};
				instruction->operation = ARMV7_VMULL;
				instruction->dataType = dataType[decode.vcom.size];
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)(REG_Q0 + (((decode.vcom.d << 4) | decode.vcom.vd) >> 1));
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)(REG_D0 + ((decode.vcom.n << 4) | decode.vcom.vn));
				instruction->operands[2].cls = REG;
				instruction->operands[2].reg = (Register)(REG_D0 + ((decode.vcom.m << 4) | decode.vcom.vm));
			}
			break;
	}

	return instruction->operation == ARMV7_UNDEFINED;
}
uint32_t armv7_two_register_scalar(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
	/*A7.4.3 Two registers and a scalar*/
	(void)address;
	union {
		uint32_t value;
		struct {
			uint32_t group1:8;
			uint32_t a:4;
			uint32_t group2:8;
			uint32_t b:2;
			uint32_t group3:2;
			uint32_t u:1;
			uint32_t group4:7;
		}com;
		struct {
			uint32_t vm:4;
			uint32_t group1:1;
			uint32_t m:1;
			uint32_t group2:1;
			uint32_t n:1;
			uint32_t f:1;
			uint32_t l:1;
			uint32_t op:1;
			uint32_t diff:1;
			uint32_t vd:4;
			uint32_t vn:4;
			uint32_t size:2;
			uint32_t d:1;
			uint32_t group5:1;
			uint32_t q:1;
			uint32_t group6:7;
		}vcom;
	} decode;
	decode.value = instructionValue;
	instruction->cond = (Condition)COND_NONE;
	switch (decode.com.a)
	{
		case 0:
		case 1:
		case 2:
		case 4:
		case 5:
		case 6:
			{
				static Operation operation[2][2] = {
					{ARMV7_VMLA, ARMV7_VMLS},
					{ARMV7_VMLAL, ARMV7_VMLSL}
				};
				static DataType dtMap[2][4][2] = {
					{{DT_NONE, DT_NONE}, {DT_I16, DT_F16}, {DT_I32, DT_F32}, {DT_NONE, DT_NONE}},
					{{DT_NONE, DT_NONE}, {DT_S16, DT_U16}, {DT_S32, DT_U32}, {DT_NONE, DT_NONE}}
				};
				instruction->operation = operation[decode.vcom.l][decode.vcom.op];
				if (decode.vcom.l == 0)
					instruction->dataType = dtMap[0][decode.vcom.size][decode.vcom.f];
				else
					instruction->dataType = dtMap[1][decode.vcom.size][decode.vcom.q];

				instruction->operands[0].cls = REG;
				if (decode.vcom.l == 0)
					instruction->operands[0].reg = (Register)(regMap[decode.vcom.q] + (((decode.vcom.d << 4) | decode.vcom.vd) >> decode.vcom.q));
				else
					instruction->operands[0].reg = (Register)(REG_Q0 + (((decode.vcom.d << 4) | decode.vcom.vd) >> 1));
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)(regMap[decode.vcom.q] + (((decode.vcom.n << 4) | decode.vcom.vn) >> decode.vcom.q));
				instruction->operands[2].cls = REG;
				instruction->operands[2].flags.hasElements = 1;
				if (decode.vcom.size == 0 || (decode.vcom.f == 1 && decode.vcom.size == 1))
				{
					return 1;
				}
				else if (decode.vcom.size == 1)
				{
					instruction->operands[2].reg = (Register)(REG_D0 + (decode.vcom.vm & 7));
					instruction->operands[2].imm = (decode.vcom.m << 1) |(decode.vcom.vm >> 3);
				}
				else if (decode.vcom.size == 2)
				{
					instruction->operands[2].reg = (Register)(REG_D0 + (decode.vcom.vm));
					instruction->operands[2].imm = decode.vcom.m;
				}
				else
					return 1;
			}
			break;
		case 3:
		case 7:
			if (decode.com.u == 0)
			{

				static Operation operation[2] = {ARMV7_VQDMLAL, ARMV7_VQDMLSL};
				static DataType dtMap[4] = {DT_NONE, DT_S16, DT_S32, DT_NONE};
				instruction->dataType = dtMap[decode.vcom.size];
				if ((decode.vcom.vd & 1) == 1)
					return 1;
				if (decode.vcom.diff == 1)
				{
					//Encoding T1/A1
					instruction->operation = operation[decode.vcom.l];
					instruction->operands[0].cls = REG;
					instruction->operands[0].reg = (Register)(REG_Q0 + (((decode.vcom.d << 4) | decode.vcom.vd) >> 1));
					instruction->operands[1].cls = REG;
					instruction->operands[1].reg = (Register)(REG_D0 + ((decode.vcom.n << 4) | decode.vcom.vn));
					instruction->operands[2].cls = REG;
					instruction->operands[2].reg = (Register)(REG_D0 + ((decode.vcom.m << 4) | decode.vcom.vm));
				}
				else
				{
					//Encoding T2/A2
					instruction->operation = operation[decode.vcom.op];
					instruction->operands[0].cls = REG;
					instruction->operands[0].reg = (Register)(REG_Q0 + (((decode.vcom.d << 4) | decode.vcom.vd) >> 1));
					instruction->operands[1].cls = REG;
					instruction->operands[1].reg = (Register)(REG_D0 + ((decode.vcom.n << 4) | decode.vcom.vn));
					instruction->operands[2].cls = REG;
					instruction->operands[2].reg = (Register)(REG_D0 + (decode.vcom.vm & 7));
					if (decode.vcom.size == 1)
						instruction->operands[2].imm = (decode.vcom.m << 1) | (decode.vcom.vm >> 3);
					else
						instruction->operands[2].imm = decode.vcom.m;

					instruction->operands[2].flags.hasElements = 1;
				}
			}
			break;
		case 8:
		case 9:
			{
				static DataType dtMap[2][4] = {
					{DT_NONE, DT_I16,  DT_I32, DT_NONE},
					{DT_NONE, DT_NONE, DT_F32, DT_NONE}
				};
				instruction->operation = ARMV7_VMUL;
				instruction->dataType = dtMap[decode.vcom.f][decode.vcom.size];
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)(regMap[decode.vcom.q] + (((decode.vcom.d << 4) | decode.vcom.vd) >> decode.vcom.q));
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)(regMap[decode.vcom.q] + (((decode.vcom.n << 4) | decode.vcom.vn) >> decode.vcom.q));
				instruction->operands[2].cls = REG;
				instruction->operands[2].flags.hasElements = 1;
				if (decode.vcom.size == 1)
				{
					instruction->operands[2].reg = (Register)(REG_D0 + (decode.vcom.vm & 7));
					instruction->operands[2].imm = (decode.vcom.m << 1) | (decode.vcom.vm >> 3);
				}
				else if (decode.vcom.size == 2)
				{
					instruction->operands[2].reg = (Register)(REG_D0 + (decode.vcom.vm));
					instruction->operands[2].imm = decode.vcom.m;
				}
				else
					return 1;
			}
			break;
		case 10:
			{
				static DataType dtMap[4] = {DT_NONE, DT_S16, DT_S32, DT_NONE};
				instruction->operation = ARMV7_VMULL;
				instruction->dataType = dtMap[decode.vcom.size];
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)(REG_Q0 + (((decode.vcom.d << 4) | decode.vcom.vd) >> 1));
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)(REG_D0 + (((decode.vcom.n << 4) | decode.vcom.vn) >> decode.vcom.q));
				instruction->operands[2].cls = REG;
				instruction->operands[2].flags.hasElements = 1;
				if (decode.vcom.size == 1)
				{
					instruction->operands[2].reg = (Register)(REG_D0 + (decode.vcom.vm & 7));
					instruction->operands[2].imm = (decode.vcom.m << 1) | (decode.vcom.vm >> 3);
				}
				else if (decode.vcom.size == 2)
				{
					instruction->operands[2].reg = (Register)(REG_D0 + (decode.vcom.vm));
					instruction->operands[2].imm = decode.vcom.m;
				}
				else
					return 1;
			}
			break;
		case 11:
			if (decode.com.u == 0)
			{
				static DataType dtMap[4] = {DT_NONE, DT_S16, DT_S32, DT_NONE};
				instruction->operation = ARMV7_VQDMULL;
				instruction->dataType = dtMap[decode.vcom.size];
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)(REG_Q0 + (((decode.vcom.d << 4) | decode.vcom.vd) >> 1));
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)(REG_D0 + ((decode.vcom.n << 4) | decode.vcom.vn));
				instruction->operands[2].cls = REG;
				instruction->operands[2].reg = (Register)(REG_D0 + (decode.vcom.vm & 7));
				instruction->operands[2].imm = (decode.vcom.m << 1) | (decode.vcom.vm >> 3);
				instruction->operands[2].flags.hasElements = 1;

			}
			break;
		 case 12:
			{
				//Encoding T2/A2
				static DataType dtMap[4] = {DT_NONE, DT_S16, DT_S32, DT_NONE};
				instruction->operation = ARMV7_VQDMULH;
				instruction->dataType = dtMap[decode.vcom.size];
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)(regMap[decode.vcom.q] + (decode.vcom.vd));
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)(regMap[decode.vcom.q] + (decode.vcom.vn));
				instruction->operands[2].cls = REG;
				instruction->operands[2].reg = (Register)(REG_D0 + (decode.vcom.vm & 7));
				instruction->operands[2].imm = (decode.vcom.m << 1) | (decode.vcom.vm >> 3);
				instruction->operands[2].flags.hasElements = 1;
			}
			break;
		case 13:
			{
				//Encoding T2/A2
				static DataType dtMap[4] = {DT_NONE, DT_S16, DT_S32, DT_NONE};
				instruction->operation = ARMV7_VQRDMULH;
				instruction->dataType = dtMap[decode.vcom.size];
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)(((regMap[decode.vcom.q] + (((decode.vcom.d << 4) | decode.vcom.vd))) >> decode.vcom.q));
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)(((regMap[decode.vcom.q] + (((decode.vcom.n << 4) | decode.vcom.vn))) >> decode.vcom.q));
				instruction->operands[2].cls = REG;
				instruction->operands[2].reg = (Register)(REG_D0 + (decode.vcom.vm & 7));
				instruction->operands[2].imm = (decode.vcom.m << 1) | (decode.vcom.vm >> 3);
				instruction->operands[2].flags.hasElements = 1;
			}
			break;
	}
	return instruction->operation == ARMV7_UNDEFINED;
}
uint32_t armv7_two_register_and_shift(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
	/*A7.4.4 Two registers and a shift amount*/
	(void)address;
	union {
		uint32_t value;
		struct {
			uint32_t group1:6;
			uint32_t b:1;
			uint32_t l:1;
			uint32_t a:4;
			uint32_t group2:7;
			uint32_t imm3:3;
			uint32_t group3:2;
			uint32_t u:1;
			uint32_t group4:7;
		} com;
		struct {
			uint32_t vm:4;
			uint32_t group1:1;
			uint32_t m:1;
			uint32_t q:1;
			uint32_t l:1;
			uint32_t op:1;
			uint32_t group2:3;
			uint32_t vd:4;
			uint32_t imm6:6;
			uint32_t d:1;
			uint32_t group3:1;
			uint32_t u:1;
			uint32_t group4:7;
		} vshr;
	} decode;
	/*
	 * VSHR<c>.<type><size> <Qd>, <Qm>, #<imm>
	 * VSHR<c>.<type><size> <Dd>, <Dm>, #<imm>
	 * VSRA<c>.<type><size> <Qd>, <Qm>, #<imm>
	 * VSRA<c>.<type><size> <Dd>, <Dm>, #<imm>
	 * VRSHR<c>.<type><size> <Qd>, <Qm>, #<imm>
	 * VRSHR<c>.<type><size> <Dd>, <Dm>, #<imm>
	 * VRSRA<c>.<type><size> <Qd>, <Qm>, #<imm>
	 * VRSRA<c>.<type><size> <Dd>, <Dm>, #<imm>
	 * VSRI<c>.<size> <Qd>, <Qm>, #<imm>
	 * VSRI<c>.<size> <Dd>, <Dm>, #<imm>
	 * VSHL<c>.I<size> <Qd>, <Qm>, #<imm>
	 * VSHL<c>.I<size> <Dd>, <Dm>, #<imm>
	 * VSLI<c>.<size> <Qd>, <Qm>, #<imm>
	 * VSLI<c>.<size> <Dd>, <Dm>, #<imm>
	 * VQSHL{U}<c>.<type><size> <Qd>, <Qm>, #<imm>
	 * VQSHL{U}<c>.<type><size> <Dd>, <Dm>, #<imm>
	 * VSHRN<c>.I<size> <Dd>, <Qm>, #<imm>
	 * VQSHR{U}N<c>.<type><size> <Dd>, <Qm>, #<imm>
	 * VQRSHR{U}N<c>.<type><size> <Dd>, <Qm>, #<imm>
	 * VQSHR{U}N<c>.<type><size> <Dd>, <Qm>, #<imm>
	 * VQRSHR{U}N<c>.<type><size> <Dd>, <Qm>, #<imm>
	 * VSHLL<c>.<type><size> <Qd>, <Dm>, #<imm> //A1
	 * VMOVL<c>.<dt> <Qd>, <Dm>
	 * VCVT<c>.<Td>.<Tm> <Qd>, <Qm>, #<fbits>
	 * VCVT<c>.<Td>.<Tm> <Dd>, <Dm>, #<fbits>
	 */
	decode.value = instructionValue;
	instruction->cond = (Condition)COND_NONE;
	switch (decode.com.a)
	{
		case 0:
		case 1:
		case 2:
		case 3:
			{
				static Operation operation[4] = {
					ARMV7_VSHR, ARMV7_VSRA, ARMV7_VRSHR, ARMV7_VRSRA};
				instruction->operation = operation[decode.com.a];

				static DataType dtMap[2][4] = {
					{DT_S8, DT_S16, DT_S32, DT_S64},
					{DT_U8, DT_U16, DT_U32, DT_U64}
				};
				uint32_t imm = (decode.vshr.l << 6) | decode.vshr.imm6;
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)
					(regMap[decode.vshr.q] + (((decode.vshr.d << 4) | decode.vshr.vd) >> decode.vshr.q));
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)
					(regMap[decode.vshr.q] + (((decode.vshr.m << 4) | decode.vshr.vm) >> decode.vshr.q));
				instruction->operands[2].cls = IMM;
				if (imm < 16)
				{
					instruction->operands[2].imm = 16 - decode.vshr.imm6;
					instruction->dataType = dtMap[decode.vshr.u][0];
				}
				else if (imm < 32)
				{
					instruction->operands[2].imm = 32 - decode.vshr.imm6;
					instruction->dataType = dtMap[decode.vshr.u][1];
				}
				else if (imm < 64)
				{
					instruction->operands[2].imm = 64 - decode.vshr.imm6;
					instruction->dataType = dtMap[decode.vshr.u][2];
				}
				else if (imm < 128)
				{
					instruction->operands[2].imm = 64 - decode.vshr.imm6;
					instruction->dataType = dtMap[decode.vshr.u][3];
				}
			}
			break;
		case 4:
			if (decode.com.u == 1)
			{
				instruction->operation = ARMV7_VSRI;
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)
					(regMap[decode.vshr.q] + (((decode.vshr.d << 4) | decode.vshr.vd) >> decode.vshr.q));
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)
					(regMap[decode.vshr.q] + (((decode.vshr.m << 4) | decode.vshr.vm) >> decode.vshr.q));
				instruction->operands[2].cls = IMM;
				uint32_t imm = (decode.vshr.l << 6) | decode.vshr.imm6;
				if (imm < 16)
				{
					instruction->operands[2].imm = 16 - decode.vshr.imm6;
					instruction->dataType = DT_8;
				}
				else if (imm < 32)
				{
					instruction->operands[2].imm = 32 - decode.vshr.imm6;
					instruction->dataType = DT_16;
				}
				else if (imm < 64)
				{
					instruction->operands[2].imm = 64 - decode.vshr.imm6;
					instruction->dataType = DT_32;
				}
				else if (imm < 128)
				{
					instruction->operands[2].imm = 64 - decode.vshr.imm6;
					instruction->dataType = DT_64;
				}
			}
			break;
		case 5:
			if (decode.com.u == 0)
			{
				instruction->operation = ARMV7_VSHL;
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)
					(regMap[decode.vshr.q] + (((decode.vshr.d << 4) | decode.vshr.vd) >> decode.vshr.q));
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)
					(regMap[decode.vshr.q] + (((decode.vshr.m << 4) | decode.vshr.vm) >> decode.vshr.q));
				instruction->operands[2].cls = IMM;
				uint32_t imm = (decode.vshr.l << 6) | decode.vshr.imm6;
				if (imm < 16)
				{
					instruction->operands[2].imm = decode.vshr.imm6 - 8;
					instruction->dataType = DT_I8;
				}
				else if (imm < 32)
				{
					instruction->operands[2].imm = decode.vshr.imm6 - 16;
					instruction->dataType = DT_I16;
				}
				else if (imm < 64)
				{
					instruction->operands[2].imm = decode.vshr.imm6 - 32;
					instruction->dataType = DT_I32;
				}
				else if (imm < 128)
				{
					instruction->operands[2].imm = decode.vshr.imm6;
					instruction->dataType = DT_I64;
				}
			}
			else
			{
				instruction->operation = ARMV7_VSLI;
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)(regMap[decode.vshr.q] + (((decode.vshr.d << 4) | decode.vshr.vd) >> decode.vshr.q));
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)(regMap[decode.vshr.q] + (((decode.vshr.m << 4) | decode.vshr.vm) >> decode.vshr.q));
				instruction->operands[2].cls = IMM;
				uint32_t imm = (decode.vshr.l << 6) | decode.vshr.imm6;
				if (imm < 16)
				{
					instruction->operands[2].imm = decode.vshr.imm6 - 8;
					instruction->dataType = DT_8;
				}
				else if (imm < 32)
				{
					instruction->operands[2].imm = decode.vshr.imm6 - 16;
					instruction->dataType = DT_16;
				}
				else if (imm < 64)
				{
					instruction->operands[2].imm = decode.vshr.imm6 - 32;
					instruction->dataType = DT_32;
				}
				else if (imm < 128)
				{
					instruction->operands[2].imm = decode.vshr.imm6;
					instruction->dataType = DT_64;
				}
			}
			break;
		case 6:
		case 7:
			{
				if (decode.vshr.op == 0)
				{
					if (decode.vshr.u == 0)
						return 1;
					instruction->operation = ARMV7_VQSHLU;
				}
				else
				{
					instruction->operation = ARMV7_VQSHL;
					decode.com.u = !decode.com.u;
				}
				static DataType dtMap[2][4] = {
					{DT_U8, DT_U16, DT_U32, DT_U64},
					{DT_S8, DT_S16, DT_S32, DT_S64}
				};
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)(regMap[decode.vshr.q] + (((decode.vshr.d << 4) | decode.vshr.vd) >> decode.vshr.q));
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)(regMap[decode.vshr.q] + (((decode.vshr.m << 4) | decode.vshr.vm) >> decode.vshr.q));
				instruction->operands[2].cls = IMM;
				uint32_t imm = (decode.vshr.l << 6) | decode.vshr.imm6;
				if (imm < 16)
				{
					instruction->operands[2].imm = decode.vshr.imm6 - 8;
					instruction->dataType = dtMap[decode.vshr.u][0];
				}
				else if (imm < 32)
				{
					instruction->operands[2].imm = decode.vshr.imm6 - 16;
					instruction->dataType = dtMap[decode.vshr.u][1];
				}
				else if (imm < 64)
				{
					instruction->operands[2].imm = decode.vshr.imm6 - 32;
					instruction->dataType = dtMap[decode.vshr.u][2];
				}
				else if (imm < 128)
				{
					instruction->operands[2].imm = decode.vshr.imm6;
					instruction->dataType = dtMap[decode.vshr.u][3];
				}
			}
			break;
		case 8:
			if (decode.com.l == 0)
			{
				if (decode.com.u == 0)
				{
					static Operation operation[2] = {ARMV7_VSHRN, ARMV7_VRSHRN};
					instruction->operation = operation[decode.com.b];
					instruction->operands[0].cls = REG;
					instruction->operands[0].reg = (Register)(REG_D0 + ((decode.vshr.d << 4) | decode.vshr.vd));
					instruction->operands[1].cls = REG;
					instruction->operands[1].reg = (Register)(REG_Q0 + (((decode.vshr.m << 4) | decode.vshr.vm) >> 1));
					instruction->operands[2].cls = IMM;
					uint32_t imm = decode.vshr.imm6;
					if (imm < 16)
					{
						instruction->operands[2].imm = 16 - decode.vshr.imm6;
						instruction->dataType = DT_I16;
					}
					else if (imm < 32)
					{
						instruction->operands[2].imm = 32 - decode.vshr.imm6;
						instruction->dataType = DT_I32;
					}
					else if (imm < 64)
					{
						instruction->operands[2].imm = 64 - decode.vshr.imm6;
						instruction->dataType = DT_I64;
					}
				}
				else
				{
					static Operation operation[2] = {ARMV7_VQSHRUN, ARMV7_VQRSHRUN};
					instruction->operation = operation[decode.com.b];
					DataType dtMap[2][4] = {
						{DT_U8, DT_U16, DT_U32, DT_U64},
						{DT_S8, DT_S16, DT_S32, DT_S64}
					};
					instruction->operands[0].cls = REG;
					instruction->operands[0].reg = (Register)(REG_D0 + ((decode.vshr.d << 4) | decode.vshr.vd));
					instruction->operands[1].cls = REG;
					instruction->operands[1].reg = (Register)(REG_Q0 + (((decode.vshr.m << 4) | decode.vshr.vm) >> 1));
					instruction->operands[2].cls = IMM;
					uint32_t imm = decode.vshr.imm6;
					if (imm < 16)
					{
						instruction->operands[2].imm = 16 - decode.vshr.imm6;
						instruction->dataType = dtMap[decode.vshr.u][1];
					}
					else if (imm < 32)
					{
						instruction->operands[2].imm = 32 - decode.vshr.imm6;
						instruction->dataType = dtMap[decode.vshr.u][2];
					}
					else if (imm < 64)
					{
						instruction->operands[2].imm = 64 - decode.vshr.imm6;
						instruction->dataType = dtMap[decode.vshr.u][3];
					}
				}
			}
			break;
		case 9:
			if (decode.com.l == 0)
			{
				static Operation operation[2] = {ARMV7_VQSHRN, ARMV7_VQRSHRN};
				instruction->operation = operation[decode.com.b];
				static DataType dtMap[2][4] = {
					{DT_S8, DT_S16, DT_S32, DT_S64},
					{DT_U8, DT_U16, DT_U32, DT_U64}
				};
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)(REG_D0 + ((decode.vshr.d << 4) | decode.vshr.vd));
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)(REG_Q0 + (((decode.vshr.m << 4) | decode.vshr.vm) >> 1));
				instruction->operands[2].cls = IMM;
				uint32_t imm = decode.vshr.imm6;
				if (imm < 16)
				{
					instruction->operands[2].imm = 16 - decode.vshr.imm6;
					instruction->dataType = dtMap[decode.vshr.u][1];
				}
				else if (imm < 32)
				{
					instruction->operands[2].imm = 32 - decode.vshr.imm6;
					instruction->dataType = dtMap[decode.vshr.u][2];
				}
				else if (imm < 64)
				{
					instruction->operands[2].imm = 64 - decode.vshr.imm6;
					instruction->dataType = dtMap[decode.vshr.u][3];
				}
			}
			break;
		case 10:
			if (decode.com.b == 0 && decode.com.l == 0)
			{
				instruction->operation = ARMV7_VSHLL;
				static DataType dtMap[2][4] = {
					{DT_S8, DT_S16, DT_S32, DT_S64},
					{DT_U8, DT_U16, DT_U32, DT_U64}
				};
				uint32_t imm = decode.vshr.imm6;
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)(REG_Q0 + (((decode.vshr.d << 4) | decode.vshr.vd) >> 1));
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)(REG_D0 + ((decode.vshr.m << 4) | decode.vshr.vm));
				instruction->operands[2].cls = IMM;
				if (imm < 16)
				{
					instruction->operands[2].imm = decode.vshr.imm6 - 8;
					instruction->dataType = dtMap[decode.vshr.u][0];
				}
				else if (imm < 32)
				{
					instruction->operands[2].imm = decode.vshr.imm6 - 16;
					instruction->dataType = dtMap[decode.vshr.u][1];
				}
				else if (imm < 64)
				{
					instruction->operands[2].imm = decode.vshr.imm6 - 32;
					instruction->dataType = dtMap[decode.vshr.u][2];
				}
				if (instruction->operands[2].imm == 0)
				{
					instruction->operation = ARMV7_VMOVL;
					instruction->operands[2].cls = NONE;
				}
			}
			break;
		case 14:
		case 15:
			instruction->operation = ARMV7_VCVT;
			static DataType dtMap[2] = {DT_S32, DT_U32};
			instruction->operands[0].cls = REG;
			instruction->operands[0].reg = (Register)
				(regMap[decode.vshr.q] + (((decode.vshr.d << 4) | decode.vshr.vd) >> decode.vshr.q));
			instruction->operands[1].cls = REG;
			instruction->operands[1].reg = (Register)
				(regMap[decode.vshr.q] + (((decode.vshr.m << 4) | decode.vshr.vm) >> decode.vshr.q));
			instruction->operands[2].cls = IMM;
			instruction->operands[2].imm = 64 - decode.vshr.imm6;
			if (decode.vshr.op == 1)
			{
				instruction->dataType = dtMap[decode.vshr.u];
				instruction->dataType2 = DT_F32;
			}
			else
			{
				instruction->dataType = DT_F32;
				instruction->dataType2 = dtMap[decode.vshr.u];
			}
			break;
	}
	return instruction->operation == ARMV7_UNDEFINED;
}

uint32_t armv7_two_register_misc(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
	/*A7.4.5 Two registers, miscellaneous*/
	(void)address;
	union {
		uint32_t value;
		struct {
			uint32_t group1:6;
			uint32_t b:5;
			uint32_t group2:5;
			uint32_t a:2;
			uint32_t group3:14;
		} com;
		struct {
			uint32_t vm:4;
			uint32_t group1:1;
			uint32_t m:1;
			uint32_t q:1;
			uint32_t op:2;
			uint32_t group2:3;
			uint32_t vd:4;
			uint32_t group3:2;
			uint32_t size:2;
			uint32_t group4:2;
			uint32_t d:1;
			uint32_t group5:9;
		} vrev;
		struct {
			uint32_t vm:4;
			uint32_t group1:1;
			uint32_t m:1;
			uint32_t q:1;
			uint32_t group2:3;
			uint32_t f:1;
			uint32_t group3:1;
			uint32_t vd:4;
			uint32_t group4:2;
			uint32_t size:2;
			uint32_t group5:2;
			uint32_t d:1;
			uint32_t group6:9;
		} vcgt;
		struct {
			uint32_t vm:4;
			uint32_t group1:1;
			uint32_t m:1;
			uint32_t op:2;
			uint32_t group2:4;
			uint32_t vd:4;
			uint32_t group4:2;
			uint32_t size:2;
			uint32_t group5:2;
			uint32_t d:1;
			uint32_t group6:9;
		} vqmov;
		struct {
			uint32_t vm:4;
			uint32_t group1:1;
			uint32_t m:1;
			uint32_t q:1;
			uint32_t group2:1;
			uint32_t f:1;
			uint32_t vd:4;
			uint32_t group4:2;
			uint32_t size:2;
			uint32_t group5:2;
			uint32_t d:1;
			uint32_t group6:9;
		} vrsqrte;
		struct {
			uint32_t vm:4;
			uint32_t group1:1;
			uint32_t m:1;
			uint32_t group2:2;
			uint32_t op:1;
			uint32_t group3:3;
			uint32_t vd:4;
			uint32_t group4:2;
			uint32_t size:2;
			uint32_t group5:2;
			uint32_t d:1;
			uint32_t group6:9;
		} vcvt;
		struct {
			uint32_t vm:4;
			uint32_t group1:1;
			uint32_t m:1;
			uint32_t q:1;
			uint32_t op:2;
			uint32_t group3:3;
			uint32_t vd:4;
			uint32_t group4:2;
			uint32_t size:2;
			uint32_t group5:2;
			uint32_t d:1;
			uint32_t group6:9;
		} vcvt2;
	} decode;
	decode.value = instructionValue;
	instruction->cond = (Condition)COND_NONE;

	switch (decode.com.a)
	{
		case 0:
			{
				static DataType dtMap[5][4] = {
					{DT_S8, DT_S16, DT_S32, DT_S64},
					{DT_U8, DT_U16, DT_U32, DT_U64},
					{DT_I8, DT_I16, DT_I32, DT_I64},
					{DT_8, DT_16, DT_32, DT_64},
					{DT_NONE, DT_NONE, DT_NONE, DT_NONE}
				};
				switch (decode.com.b)
				{
					case 0:
					case 1:
						if (decode.vrev.op + decode.vrev.size >= 3)
							return 1;
						instruction->operation = ARMV7_VREV64;
						instruction->dataType = dtMap[3][decode.vrev.size];
						break;
					case 2:
					case 3:
						if (decode.vrev.op + decode.vrev.size >= 3)
							return 1;
						instruction->operation = ARMV7_VREV32;
						instruction->dataType = dtMap[3][decode.vrev.size];
						break;
					case 4:
					case 5:
						if (decode.vrev.op + decode.vrev.size >= 3)
							return 1;
						instruction->operation = ARMV7_VREV16;
						instruction->dataType = dtMap[3][decode.vrev.size];
						break;
					case 8:
					case 9:
					case 10:
					case 11:
						if (decode.vrev.size == 3)
							return 1;
						//op is guaranteed to be < 2
						instruction->operation = ARMV7_VPADDL;
						instruction->dataType = dtMap[decode.vrev.op][decode.vrev.size];
						break;
					case 16:
					case 17:
						if (decode.vrev.size == 3)
							return 1;
						instruction->operation = ARMV7_VCLS;
						instruction->dataType = dtMap[0][decode.vrev.size];
						break;
					case 18:
					case 19:
						if (decode.vrev.size == 3)
							return 1;
						instruction->operation = ARMV7_VCLZ;
						instruction->dataType = dtMap[2][decode.vrev.size];
						break;
					case 20:
					case 21:
						if (decode.vrev.size != 0)
							return 1;
						instruction->operation = ARMV7_VCNT;
						instruction->dataType = DT_8;
						break;
					case 22:
					case 23:
						if (decode.vrev.size != 0)
							return 1;
						instruction->operation = ARMV7_VMVN;
						instruction->dataType = dtMap[4][decode.vrev.size];
						break;
					case 24:
					case 25:
					case 26:
					case 27:
						if (decode.vrev.size == 3)
							return 1;
						instruction->operation = ARMV7_VPADAL;
						instruction->dataType = dtMap[decode.vrev.op][decode.vrev.size];
						break;
					case 28:
					case 29:
						if (decode.vrev.size == 3)
							return 1;
						instruction->operation = ARMV7_VQABS;
						instruction->dataType = dtMap[0][decode.vrev.size];
						break;
					case 30:
					case 31:
						if (decode.vrev.size == 3)
							return 1;
						instruction->operation = ARMV7_VQNEG;
						instruction->dataType = dtMap[0][decode.vrev.size];
						break;
				}
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)(regMap[decode.vrev.q] + (((decode.vrev.d << 4) | decode.vrev.vd) >> decode.vrev.q));
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)(regMap[decode.vrev.q] + (((decode.vrev.m << 4) | decode.vrev.vm) >> decode.vrev.q));
			}
			break;
		case 1:
			{
				static DataType dtMap[4][4] = {
					{DT_S8,   DT_S16,  DT_S32, DT_NONE},
					{DT_NONE, DT_NONE, DT_F32, DT_NONE},
					{DT_I8,   DT_I16,  DT_I32, DT_NONE},
					{DT_NONE, DT_NONE, DT_F32, DT_NONE}
				};
				uint32_t type = 0;
				switch (decode.com.b)
				{
					case 0:
					case 1:
					case 16:
					case 17:
						if (decode.vcgt.size == 3 ||
							(decode.vcgt.f == 1 && decode.vcgt.size != 2))
							return 1;
						instruction->operation = ARMV7_VCGT;
						instruction->dataType = dtMap[decode.vcgt.f][decode.vcgt.size];
						break;
					case 2:
					case 3:
					case 18:
					case 19:
						if (decode.vcgt.size == 3 ||
							(decode.vcgt.f == 1 && decode.vcgt.size != 2))
							return 1;
						instruction->operation = ARMV7_VCGE;
						instruction->dataType = dtMap[decode.vcgt.f][decode.vcgt.size];
						break;
					case 4:
					case 5:
					case 20:
					case 21:
						if (decode.vcgt.size == 3 ||
							(decode.vcgt.f == 1 && decode.vcgt.size != 2))
							return 1;
						instruction->operation = ARMV7_VCEQ;
						instruction->dataType = dtMap[2 + decode.vcgt.f][decode.vcgt.size];
						break;
					case 6:
					case 7:
					case 22:
					case 23:
						if (decode.vcgt.size == 3 ||
							(decode.vcgt.f == 1 && decode.vcgt.size != 2))
							return 1;
						instruction->operation = ARMV7_VCLE;
						instruction->dataType = dtMap[decode.vcgt.f][decode.vcgt.size];
						break;
					case 8:
					case 9:
					case 24:
					case 25:
						if (decode.vcgt.size == 3 ||
							(decode.vcgt.f == 1 && decode.vcgt.size != 2))
							return 1;
						instruction->operation = ARMV7_VCLT;
						instruction->dataType = dtMap[decode.vcgt.f][decode.vcgt.size];
						break;
					case 12:
					case 13:
					case 28:
					case 29:
						if (decode.vcgt.size == 3 ||
							(decode.vcgt.f == 1 && decode.vcgt.size != 2))
							return 1;
						instruction->operation = ARMV7_VABS;
						instruction->dataType = dtMap[decode.vcgt.f][decode.vcgt.size];
						type = 1;
						break;
					case 14:
					case 15:
					case 30:
					case 31:
						if (decode.vcgt.size == 3 ||
							(decode.vcgt.f == 1 && decode.vcgt.size != 2))
							return 1;
						instruction->operation = ARMV7_VNEG;
						instruction->dataType = dtMap[decode.vcgt.f][decode.vcgt.size];
						type = 1;
						break;
				}

				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)(regMap[decode.vcgt.q] + (((decode.vrev.d << 4) | decode.vcgt.vd) >> decode.vcgt.q));
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)(regMap[decode.vcgt.q] + (((decode.vcgt.m << 4) | decode.vcgt.vm) >> decode.vcgt.q));
				if (type == 0)
				{
					instruction->operands[2].cls = IMM;
					instruction->operands[2].imm = 0;
				}
			}
			break;
		case 2:
			{
				static DataType dtMap[4][4] = {
					{DT_8,  DT_16,  DT_32,  DT_64},
					{DT_I8, DT_I16, DT_I32, DT_I64},
					{DT_S8, DT_S16, DT_S32, DT_S64},
					{DT_U8, DT_U16, DT_U32, DT_U64}
				};
				uint32_t type = 0;
				switch (decode.com.b)
				{
					case 0:
					case 1:
						if (decode.vcgt.size == 3 ||
							(decode.vcgt.q == 0 && decode.vcgt.size == 2))
							return 1;
						instruction->operation = ARMV7_VSWP;
						break;
					case 2:
					case 3:
						if (decode.vcgt.size == 3 ||
							(decode.vcgt.q == 1 &&
							((decode.vcgt.vd & 1) == 1 || (decode.vcgt.vm & 1) == 1)))
							return 1;
						instruction->operation = ARMV7_VTRN;
						instruction->dataType = dtMap[0][decode.vcgt.size];
						break;
					case 4:
					case 5:
						if (decode.vcgt.size == 3 ||
							(decode.vcgt.q == 1 &&
							((decode.vcgt.vd & 1) == 1 || (decode.vcgt.vm & 1) == 1)))
							return 1;
						instruction->operation = ARMV7_VUZP;
						instruction->dataType = dtMap[0][decode.vcgt.size];
						break;
					case 6:
					case 7:
						if (decode.vcgt.size == 3 ||
							(decode.vcgt.q == 1 &&
							((decode.vcgt.vd & 1) == 1 || (decode.vcgt.vm & 1) == 1)))
							return 1;
						instruction->operation = ARMV7_VZIP;
						instruction->dataType = dtMap[0][decode.vcgt.size];
						break;
					case 8:
						if (decode.vcgt.size == 3 || (decode.vcgt.vm & 1) == 1)
							return 1;
						type = 2;
						instruction->operation = ARMV7_VMOVN;
						instruction->dataType = dtMap[1][decode.vcgt.size+1];
						break;
					case 9:
					case 10:
					case 11:
						{
							if (decode.vcgt.size == 3 || (decode.vcgt.vm & 1) == 1)
								return 1;
							Operation operation[4] = {
								ARMV7_UNDEFINED, ARMV7_VQMOVUN, ARMV7_VQMOVN, ARMV7_VQMOVN};
							type = 2;
							instruction->operation = operation[decode.vqmov.op];
							if (instruction->operation == ARMV7_VQMOVUN)
								instruction->dataType = dtMap[2][decode.vcgt.size+1];
							else
							{
								if (decode.vqmov.op == 2)
									instruction->dataType = dtMap[2][decode.vcgt.size+1];
								else if (decode.vqmov.op == 3)
									instruction->dataType = dtMap[3][decode.vcgt.size+1];
							}
						}
						break;
					case 12:
						instruction->operation = ARMV7_VSHLL;
						instruction->operands[2].cls = IMM;
						instruction->operands[2].imm = 8 << decode.vqmov.size;
						instruction->dataType = dtMap[1][decode.vqmov.size];
						type = 1;
						break;
					case 24:
					case 28:
						{
							DataType dtMap2[2] = {DT_F16, DT_F32};
							instruction->operation = ARMV7_VCVT;
							instruction->dataType = dtMap2[decode.vcvt.op];
							instruction->dataType2 = dtMap2[!decode.vcvt.op];
							type = 3;
						}
						break;
				}

				if (type == 0)
				{
					instruction->operands[0].cls = REG;
					instruction->operands[0].reg = (Register)(regMap[decode.vcgt.q] + (((decode.vrev.d << 4) | decode.vcgt.vd) >> decode.vcgt.q));
					instruction->operands[1].cls = REG;
					instruction->operands[1].reg = (Register)(regMap[decode.vcgt.q] + (((decode.vcgt.m << 4) | decode.vcgt.vm) >> decode.vcgt.q));
				}
				else if (type == 1)
				{
					instruction->operands[0].cls = REG;
					instruction->operands[0].reg = (Register)(REG_Q0 + (((decode.vrev.d << 4) | decode.vcgt.vd) >> 1));
					instruction->operands[1].cls = REG;
					instruction->operands[1].reg = (Register)(REG_D0 + ((decode.vcgt.m << 4) | decode.vcgt.vm));
				}
				else if (type == 2)
				{
					instruction->operands[0].cls = REG;
					instruction->operands[0].reg = (Register)(REG_D0 + ((decode.vrev.d << 4) | decode.vcgt.vd));
					instruction->operands[1].cls = REG;
					instruction->operands[1].reg = (Register)(REG_Q0 + (((decode.vcgt.m << 4) | decode.vcgt.vm) >> 1));
				}
				else
				{
					instruction->operands[0].cls = REG;
					instruction->operands[0].reg = (Register)(regMap[decode.vcvt.op] + (((decode.vrev.d << 4) | decode.vcgt.vd) >> decode.vcvt.op));
					instruction->operands[1].cls = REG;
					instruction->operands[1].reg = (Register)(regMap[!decode.vcvt.op] + (((decode.vcgt.m << 4) | decode.vcgt.vm) >> !decode.vcvt.op));
				}

			}
			break;
		case 3:
			{
				static DataType dtMap[2][4] = {
					{DT_U8, DT_U16, DT_U32, DT_U64},
					{DT_NONE, DT_F16, DT_F32, DT_F64}
				};
				switch (decode.com.b)
				{
					case 16:
					case 17:
					case 20:
					case 21:
						instruction->operation = ARMV7_VRECPE;
						instruction->dataType = dtMap[decode.vrsqrte.f][decode.vcgt.size];
						break;
					case 18:
					case 19:
					case 22:
					case 23:
						instruction->operation = ARMV7_VRSQRTE;
						instruction->dataType = dtMap[decode.vrsqrte.f][decode.vcgt.size];
						break;
					case 24:
					case 25:
					case 26:
					case 27:
					case 28:
					case 29:
					case 30:
					case 31:
						instruction->operation = ARMV7_VCVT;
						if (decode.vcvt2.op < 2)
						{
							instruction->dataType = DT_F32;
							if ((decode.vcvt2.op & 1) == 1)
								instruction->dataType2 = DT_U32;
							else
								instruction->dataType2 = DT_S32;
						}
						else
						{
							instruction->dataType2 = DT_F32;
							if ((decode.vcvt2.op & 1) == 1)
								instruction->dataType = DT_U32;
							else
								instruction->dataType = DT_S32;
						}
						break;
				}
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)(regMap[decode.vcgt.q] + (((decode.vcgt.d << 4) | decode.vcgt.vd) >> decode.vcgt.q));
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)(regMap[decode.vcgt.q] + (((decode.vcgt.m << 4) | decode.vcgt.vm) >> decode.vcgt.q));
			}
			break;
	}
	return instruction->operation == ARMV7_UNDEFINED;
}
uint32_t armv7_one_register_and_modified_imm(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
	/*A7.4.6 One register and a modified immediate value*/
	(void)address;
	union {
		uint32_t value;
		struct {
			uint32_t group1:5;
			uint32_t op:1;
			uint32_t group2:2;
			uint32_t cmode:4;
			uint32_t group3:20;
		} com;
		struct {
			uint32_t imm4:4;
			uint32_t group1:1;
			uint32_t op:1;
			uint32_t q:1;
			uint32_t group2:1;
			uint32_t cmode:4;
			uint32_t vd:4;
			uint32_t imm3:3;
			uint32_t group3:3;
			uint32_t d:1;
			uint32_t group4:1;
			uint32_t i:1;
			uint32_t group5:7;
		} vmov;
	} decode;
	decode.value = instructionValue;
	instruction->cond = (Condition)COND_NONE;
	if (decode.com.op == 0)
	{
		switch (decode.com.cmode)
		{
			case 0:
			case 2:
			case 4:
			case 6:
				instruction->operation = ARMV7_VMOV;
				break;
			case 1:
			case 3:
			case 5:
			case 7:
				instruction->operation = ARMV7_VORR;
				break;
			case 8:
			case 10:
				instruction->operation = ARMV7_VMOV;
				break;
			case 9:
			case 11:
				instruction->operation = ARMV7_VORR;
				break;
			case 12:
			case 13:
			case 14:
			case 15:
				instruction->operation = ARMV7_VMOV;
				break;
		}

	}
	else
	{
		switch (decode.com.cmode)
		{
			case 0:
			case 2:
			case 4:
			case 6:
				instruction->operation = ARMV7_VMVN;
				break;
			case 1:
			case 3:
			case 5:
			case 7:
				instruction->operation = ARMV7_VBIC;
				break;
			case 8:
			case 10:
				instruction->operation = ARMV7_VMVN;
				break;
			case 9:
			case 11:
				instruction->operation = ARMV7_VBIC;
				break;
			case 12:
			case 13:
				instruction->operation = ARMV7_VMVN;
				break;
			case 14:
				instruction->operation = ARMV7_VMOV;
				break;
		}
	}
	instruction->operands[0].cls = REG;
	instruction->operands[0].reg = (Register)(regMap[decode.vmov.q] + (((decode.vmov.d << 4) | decode.vmov.vd) >> decode.vmov.q));
	instruction->operands[1].cls = IMM;
	if (simdExpandImm(
			decode.vmov.op,
			decode.vmov.cmode,
			(decode.vmov.i << 7) | (decode.vmov.imm3 << 4) | decode.vmov.imm4,
			&instruction->operands[1].imm64,
			&instruction->dataType,
			&instruction->operands[1].cls) == 0)
		return 1;
	return instruction->operation == ARMV7_UNDEFINED;
}
uint32_t armv7_floating_point_data_processing(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
	/*A7.5 Floating-point data-processing instructions*/
	(void)address;
	union{
		uint32_t value;
		struct{
			uint32_t opc4:4;
			uint32_t group1:2;
			uint32_t opc3:2;
			uint32_t sz:1;
			uint32_t group2:7;
			uint32_t opc2:4;
			uint32_t opc1:4;
			uint32_t group3:4;
			uint32_t cond:4;
		}com;
		struct{
			uint32_t vm:4;
			uint32_t group1:1;
			uint32_t m:1;
			uint32_t op:1;
			uint32_t n:1;
			uint32_t sz:1;
			uint32_t group2:3;
			uint32_t vd:4;
			uint32_t vn:4;
			uint32_t group3:2;
			uint32_t d:1;
			uint32_t group4:4;
			uint32_t t:1;
			uint32_t group5:4;
		}vmla;
		struct{
			uint32_t imm4l:4;
			uint32_t group1:4;
			uint32_t sz:1;
			uint32_t group2:3;
			uint32_t vd:4;
			uint32_t imm4h:4;
			uint32_t group3:2;
			uint32_t d:1;
			uint32_t group4:9;
		}vmov;
		struct{
			uint32_t imm4:4;
			uint32_t group1:1;
			uint32_t i:1;
			uint32_t group2:1;
			uint32_t sx:1;
			uint32_t sf:1;
			uint32_t group3:3;
			uint32_t vd:4;
			uint32_t u:1;
			uint32_t group4:1;
			uint32_t op:1;
			uint32_t group5:3;
			uint32_t d:1;
			uint32_t group6:9;
		}vcvt;
		struct{
			uint32_t vm:4;
			uint32_t group1:1;
			uint32_t m:1;
			uint32_t group2:1;
			uint32_t op:1;
			uint32_t sz:1;
			uint32_t group3:3;
			uint32_t vd:4;
			uint32_t rm:2;
			uint32_t group4:4;
			uint32_t d:1;
			uint32_t group5:9;
		}vcvt2;
		struct{
			uint32_t vm:4;
			uint32_t group1:1;
			uint32_t m:1;
			uint32_t group2:1;
			uint32_t t:1;
			uint32_t sz:1;
			uint32_t group3:3;
			uint32_t vd:4;
			uint32_t op:1;
			uint32_t group4:5;
			uint32_t d:1;
			uint32_t group5:9;
		}vcvtt;
		struct{
			uint32_t vm:4;
			uint32_t group1:1;
			uint32_t m:1;
			uint32_t group2:1;
			uint32_t op:1;
			uint32_t sz:1;
			uint32_t group3:3;
			uint32_t vd:4;
			uint32_t group4:6;
			uint32_t d:1;
			uint32_t group5:9;
		}vrint;
		struct {
			uint32_t vm:4;
			uint32_t group1:1;
			uint32_t m:1;
			uint32_t group2:1;
			uint32_t op:1;
			uint32_t sz:1;
			uint32_t group3:3;
			uint32_t vd:4;
			uint32_t rm:2;
			uint32_t group4:4;
			uint32_t d:1;
			uint32_t group5:9;
		}vcvta;
		struct {
			uint32_t vm:4;
			uint32_t group1:1;
			uint32_t m:1;
			uint32_t group2:1;
			uint32_t op:1;
			uint32_t sz:1;
			uint32_t group3:3;
			uint32_t vd:4;
			uint32_t rm:2;
			uint32_t group4:4;
			uint32_t d:1;
			uint32_t group5:9;
		} vcvtr;
		struct {
			uint32_t vm:4;
			uint32_t group1:1;
			uint32_t m:1;
			uint32_t group2:1;
			uint32_t n:1;
			uint32_t sz:1;
			uint32_t group3:3;
			uint32_t vd:4;
			uint32_t vn:4;
			uint32_t cc:2;
			uint32_t d:1;
			uint32_t group4:9;
		} vsel;
		struct {
			uint32_t vm:4;
			uint32_t group1:1;
			uint32_t m:1;
			uint32_t op:1;
			uint32_t n:1;
			uint32_t sz:1;
			uint32_t group3:3;
			uint32_t vd:4;
			uint32_t vn:4;
			uint32_t group4:2;
			uint32_t d:1;
			uint32_t group5:9;
		} vmax;
		struct {
			uint32_t vm:4;
			uint32_t group1:1;
			uint32_t m:1;
			uint32_t group2:2;
			uint32_t sz:1;
			uint32_t group3:3;
			uint32_t vd:4;
			uint32_t rm:2;
			uint32_t group4:4;
			uint32_t d:1;
			uint32_t group5:9;
		} vrint2;
	} decode;
	decode.value = instructionValue;
	instruction->cond = (Condition)decode.com.cond;
	instruction->dataType = (DataType)(DT_F32 + decode.vmla.sz);
	uint32_t type = 0;
	/*
	 * VNMLA<c>.F64 <Dd>, <Dn>, <Dm>
	 * VNMLA<c>.F32 <Sd>, <Sn>, <Sm>
	 * VNMLS<c>.F64 <Dd>, <Dn>, <Dm>
	 * VNMLS<c>.F32 <Sd>, <Sn>, <Sm>
	 * VNMUL<c>.F64 <Dd>, <Dn>, <Dm>
	 * VNMUL<c>.F32 <Sd>, <Sn>, <Sm>
	 */
	switch (decode.com.opc1)
	{
		case 0:
		case 4:
			{
				static Operation operation[2] = {ARMV7_VMLA, ARMV7_VMLS};
				instruction->operation = operation[decode.vmla.op];
				type = 1;
			}
			break;
		case 1:
		case 5:
			{
				static Operation operation[2] = {ARMV7_VNMLS, ARMV7_VNMLA};
				instruction->operation = operation[decode.vmla.op];
				type = 1;
			}
			break;
		case 2:
		case 6:
			{
				static Operation operation[2] = {ARMV7_VMUL, ARMV7_VNMUL};
				instruction->operation = operation[decode.com.opc3 & 1];
				type = 1;
			}
			break;
		case 3:
		case 7:
			{
				static Operation operation[2] = {ARMV7_VADD, ARMV7_VSUB};
				instruction->operation = operation[decode.com.opc3 & 1];
				type = 1;
			}
			break;
		case 8:
		case 12:
			{
				static Operation operation[4] = {ARMV7_VDIV, ARMV7_UNDEFINED, ARMV7_VDIV, ARMV7_UNDEFINED};
				instruction->operation = operation[decode.com.opc3];
				type = 1;
			}
			break;
		case 9:
		case 13:
			{
				static Operation operation[2] = {ARMV7_VFNMS, ARMV7_VFNMA};
				instruction->operation = operation[decode.vmla.op];
				type = 1;
			}
			break;
		case 10:
		case 14:
			{
				static Operation operation[2] = {ARMV7_VFMA, ARMV7_VFMS};
				instruction->operation = operation[decode.vmla.op];
				type = 1;
			}
			break;
		case 11:
		case 15:
			/*
			* VMOV<c>.F64        <Dd>, #<imm>
			* VMOV<c>.F32        <Sd>, #<imm>
			* VMOV<c>.F64        <Dd>, <Dm>
			* VMOV<c>.F32        <Sd>, <Sm>
			* VABS<c>.F64        <Dd>, <Dm>
			* VABS<c>.F32        <Sd>, <Sm>
			* VNEG<c>.F64        <Dd>, <Dm>
			* VNEG<c>.F32        <Sd>, <Sm>
			* VSQRT<c>.F64       <Dd>, <Dm>
			* VSQRT<c>.F32       <Sd>, <Sm>
			* VCVT<y><c>.F32.F16 <Sd>, <Sm>
			* VCVT<y><c>.F16.F32 <Sd>, <Sm>
			* VCMP{E}<c>.F64     <Dd>, <Dm>
			* VCMP{E}<c>.F32     <Sd>, <Sm>
			* VCMP{E}<c>.F64     <Dd>, #0.0
			* VCMP{E}<c>.F32     <Sd>, #0.0
			* VCVT<c>.F64.F32    <Dd>, <Sm>
			* VCVT<c>.F32.F64    <Sd>, <Dm>
			* VCVT{R}<c>.S32.F64 <Sd>, <Dm>
			* VCVT{R}<c>.S32.F32 <Sd>, <Sm>
			* VCVT{R}<c>.U32.F64 <Sd>, <Dm>
			* VCVT{R}<c>.U32.F32 <Sd>, <Sm>
			* VCVT<c>.F64.<Tm>   <Dd>, <Sm>
			* VCVT<c>.F32.<Tm>   <Sd>, <Sm>
			* VCVT<c>.<Td>.F64   <Dd>, <Dd>, #<fbits>
			* VCVT<c>.<Td>.F32   <Sd>, <Sd>, #<fbits>
			* VCVT<c>.F64.<Td>   <Dd>, <Dd>, #<fbits>
			* VCVT<c>.F32.<Td>   <Sd>, <Sd>, #<fbits>
			*/
			type = 1;
			static uint32_t fregMap[2] = {REG_S0, REG_D0};
			if ((decode.com.opc3 & 1) == 0)
			{
				instruction->operation = ARMV7_VMOV;
				if (decode.vmla.sz == 0)
				{
					instruction->operands[0].cls = REG;
					instruction->operands[0].reg = (Register)(REG_S0 + ((decode.vmov.vd << 1) | decode.vmov.d));
					instruction->operands[1].cls = FIMM32;
					instruction->operands[1].imm =
						VFPExpandImm32(decode.vmov.imm4h << 4 | decode.vmov.imm4l);
				}
				else
				{
					instruction->operands[0].cls = REG;
					instruction->operands[0].reg = (Register)(REG_D0 + ((decode.vmov.d << 4) | decode.vmov.vd));
					instruction->operands[1].cls = FIMM64;
					instruction->operands[1].imm64 =
						VFPExpandImm64(decode.vmov.imm4h << 4 | decode.vmov.imm4l);
				}
			}
			else
			{
				switch (decode.com.opc2)
				{
					case 0:
						{
							static OperandClass immMap[2] = {FIMM32, FIMM64};
							instruction->operands[0].cls = REG;
							if (decode.com.opc3 == 1)
							{
								instruction->operation = ARMV7_VMOV;
								if (decode.vmla.sz == 0)
								{
									instruction->operands[0].reg = (Register)(REG_D0 + ((decode.vmla.vd << 1) | decode.vmla.d));
									instruction->operands[1].cls = immMap[decode.vmla.sz];
									instruction->operands[1].imm =
										VFPExpandImm32(decode.vmla.vn << 4 | decode.vmla.vm);
								}
								else
								{
									instruction->operands[0].reg = (Register)(REG_Q0 + (((decode.vmla.d << 4) | decode.vmla.vd) >> 1));
									instruction->operands[1].cls = immMap[decode.vmla.sz];
									instruction->operands[1].imm64 =
										VFPExpandImm64(decode.vmla.vn << 4 | decode.vmla.vm);
								}
							}
							else
							{
								instruction->operation = ARMV7_VABS;
								if (decode.vmla.sz == 0)
								{
									instruction->operands[0].cls = REG;
									instruction->operands[0].reg = (Register)(REG_S0 + ((decode.vmla.vd << 1) | decode.vmla.d));
									instruction->operands[1].cls = REG;
									instruction->operands[1].reg = (Register)(REG_S0 + ((decode.vmla.vm << 1) | decode.vmla.m));
								}
								else
								{
									instruction->operands[0].cls = REG;
									instruction->operands[0].reg = (Register)(REG_D0 + ((decode.vmla.d << 4) | decode.vmla.vd));
									instruction->operands[1].cls = REG;
									instruction->operands[1].reg = (Register)(REG_D0 + ((decode.vmla.m << 4) | decode.vmla.vm));
								}
							}
						}
						break;
					case 1:
						{
							static Operation operation[4] = {
								ARMV7_UNDEFINED, ARMV7_VNEG,
								ARMV7_UNDEFINED, ARMV7_VSQRT,
							};
							instruction->operation = operation[decode.com.opc3];
							if (decode.vmla.sz == 0)
							{
								instruction->operands[0].cls = REG;
								instruction->operands[0].reg = (Register)(REG_S0 + ((decode.vmla.vd << 1) | decode.vmla.d));
								instruction->operands[1].cls = REG;
								instruction->operands[1].reg = (Register)(REG_S0 + ((decode.vmla.vm << 1) | decode.vmla.m));
							}
							else
							{
								instruction->operands[0].cls = REG;
								instruction->operands[0].reg = (Register)(REG_D0 + ((decode.vmla.d << 4) | decode.vmla.vd));
								instruction->operands[1].cls = REG;
								instruction->operands[1].reg = (Register)(REG_D0 + ((decode.vmla.m << 4) | decode.vmla.vm));
							}
						}
						break;
					case 2:
					case 3:
						{
							static Operation operation[2] = {ARMV7_VCVTB, ARMV7_VCVTT};
							instruction->operation = operation[decode.vcvtt.t];
							static DataType dtMap[2][2] = {
								{DT_F16, DT_F32},
								{DT_F16, DT_F64}
							};
							instruction->dataType  = dtMap[decode.vcvtt.sz][!decode.vcvtt.op];
							instruction->dataType2 = dtMap[decode.vcvtt.sz][decode.vcvtt.op];
							if (decode.vcvtt.sz == 0)
							{
								instruction->operands[0].cls = REG;
								instruction->operands[0].reg = (Register)(REG_S0 + ((decode.vcvtt.vd << 1) | decode.vcvtt.d));
								instruction->operands[1].cls = REG;
								instruction->operands[1].reg = (Register)(REG_S0 + ((decode.vcvtt.vm << 1) | decode.vcvtt.m));

							}
							else
							{
								if (decode.vcvtt.op == 0)
								{
									instruction->operands[0].cls = REG;
									instruction->operands[0].reg = (Register)(REG_D0 + ((decode.vcvtt.d << 4) | decode.vcvtt.vd));
									instruction->operands[1].cls = REG;
									instruction->operands[1].reg = (Register)(REG_S0 + ((decode.vcvtt.vm << 1) | decode.vcvtt.m));
								}
								else
								{
									instruction->operands[0].cls = REG;
									instruction->operands[0].reg = (Register)(REG_S0 + ((decode.vcvtt.vd << 1) | decode.vcvtt.d));
									instruction->operands[1].cls = REG;
									instruction->operands[1].reg = (Register)(REG_D0 + ((decode.vcvtt.m << 4) | decode.vcvtt.vm));
								}
							}
						}
						break;
					case 4:
						{
							static Operation operation[2] = {ARMV7_VCMP, ARMV7_VCMPE};
							instruction->operation = operation[decode.vmla.n];
							if (decode.vmla.sz == 0)
							{
								instruction->operands[0].cls = REG;
								instruction->operands[0].reg = (Register)(REG_S0 + ((decode.vmla.vd << 1) | decode.vmla.d));
								instruction->operands[1].cls = REG;
								instruction->operands[1].reg = (Register)(REG_S0 + ((decode.vmla.vm << 1) | decode.vmla.m));
							}
							else
							{
								instruction->operands[0].cls = REG;
								instruction->operands[0].reg = (Register)(REG_D0 + ((decode.vmla.d << 4) | decode.vmla.vd));
								instruction->operands[1].cls = REG;
								instruction->operands[1].reg = (Register)(REG_D0 + ((decode.vmla.m << 4) | decode.vmla.vm));
							}
						}
						break;
					case 5:
						{
							static Operation operation[2] = {ARMV7_VCMP, ARMV7_VCMPE};
							instruction->operation = operation[decode.vmla.n];
							if (decode.vmla.sz == 0)
							{
								instruction->operands[0].cls = REG;
								instruction->operands[0].reg = (Register)(REG_S0 + ((decode.vmla.vd << 1) | decode.vmla.d));
							}
							else
							{
								instruction->operands[0].cls = REG;
								instruction->operands[0].reg = (Register)(REG_D0 + ((decode.vmla.d << 4) | decode.vmla.vd));
							}
							instruction->operands[1].cls = FIMM32;
						}
						break;
					case 6:
						{
							static Operation operation[2] = {ARMV7_VRINTR, ARMV7_VRINTZ};
							instruction->operation = operation[decode.vrint.op];
							if (decode.vrint.sz == 0)
							{
								instruction->operands[0].cls = REG;
								instruction->operands[0].reg = (Register)(REG_S0 + ((decode.vrint.vd << 1) | decode.vrint.d));
								instruction->operands[1].cls = REG;
								instruction->operands[1].reg = (Register)(REG_S0 + ((decode.vrint.vm << 1) | decode.vrint.m));
							}
							else
							{
								instruction->operands[0].cls = REG;
								instruction->operands[0].reg = (Register)(REG_D0 + ((decode.vrint.d << 4) | decode.vrint.vd));
								instruction->operands[1].cls = REG;
								instruction->operands[1].reg = (Register)(REG_D0 + ((decode.vrint.m << 4) | decode.vrint.vm));
							}
						}
						break;
					case 7:
						{
							static DataType dtMap[2] = {DT_F32, DT_F64};
							if (decode.com.opc3 == 3)
							{
								instruction->operation = ARMV7_VCVT;
								instruction->dataType = dtMap[!decode.vmla.sz];
								instruction->dataType2 = dtMap[decode.vmla.sz];
								if (decode.vmla.sz == 1)
								{
									instruction->operands[0].cls = REG;
									instruction->operands[0].reg = (Register)(REG_S0 + ((decode.vmla.vd << 1) | decode.vmla.d));
									instruction->operands[1].cls = REG;
									instruction->operands[1].reg = (Register)(REG_D0 + ((decode.vmla.m << 4) | decode.vmla.vm));
								}
								else
								{
									instruction->operands[0].cls = REG;
									instruction->operands[0].reg = (Register)(REG_D0 + ((decode.vmla.d << 4) | decode.vmla.vd));
									instruction->operands[1].cls = REG;
									instruction->operands[1].reg = (Register)(REG_S0 + ((decode.vmla.vm << 1) | decode.vmla.m));
								}

							}
							else
							{
								instruction->operation = ARMV7_VRINTX;
								instruction->dataType  = dtMap[decode.vmla.sz];
								if (decode.vmla.sz == 0)
								{
									instruction->operands[0].cls = REG;
									instruction->operands[0].reg = (Register)(REG_S0 + ((decode.vmla.vd << 1) | decode.vmla.d));
									instruction->operands[1].cls = REG;
									instruction->operands[1].reg = (Register)(REG_S0 + ((decode.vmla.vm << 1) | decode.vmla.m));
								}
								else
								{
									instruction->operands[0].cls = REG;
									instruction->operands[0].reg = (Register)(REG_D0 + ((decode.vmla.d << 4) | decode.vmla.vd));
									instruction->operands[1].cls = REG;
									instruction->operands[1].reg = (Register)(REG_D0 + ((decode.vmla.m << 4) | decode.vmla.vm));
								}
							}
						}
						break;
					case 8:
						{
							instruction->operation = ARMV7_VCVT;
							static DataType dtMap1[2] = {DT_F32, DT_F64};
							static DataType dtMap2[2] = {DT_U32, DT_S32};
							instruction->dataType = dtMap1[decode.vcvtr.sz];
							instruction->dataType2 = dtMap2[decode.vcvtr.op];
							instruction->operands[1].cls = REG;
							instruction->operands[1].reg = (Register)(REG_S0 + ((decode.vmla.vm << 1) | decode.vmla.m));
							if (decode.vmla.sz == 0)
							{
								instruction->operands[0].cls = REG;
								instruction->operands[0].reg = (Register)(REG_S0 + ((decode.vmla.vd << 1) | decode.vmla.d));
							}
							else
							{
								instruction->operands[0].cls = REG;
								instruction->operands[0].reg = (Register)(REG_D0 + ((decode.vmla.d << 4) | decode.vmla.vd));
							}

						}
						break;
					case 12:
						{
							/*
							* VCVT{R}<c>.S32.F64 <Sd>, <Dm>
							* VCVT{R}<c>.S32.F32 <Sd>, <Sm>
							* VCVT{R}<c>.U32.F64 <Sd>, <Dm>
							* VCVT{R}<c>.U32.F32 <Sd>, <Sm>
							* VCVT<c>.F64.<Tm> <Dd>, <Sm>
							* VCVT<c>.F32.<Tm> <Sd>, <Sm>
							*/
							if (decode.vmla.t == 0)
							{
								static Operation operation[2] = {ARMV7_VCVT, ARMV7_VCVTR};
								instruction->operation = operation[decode.vmla.op];
								static DataType dtMap[2] = {DT_F32, DT_F64};
								instruction->dataType  = dtMap[!decode.vcvt.u];
								instruction->dataType2 = dtMap[decode.vcvt.u];
								if (decode.vmla.sz == 0)
								{
									instruction->operands[0].cls = REG;
									instruction->operands[0].reg = (Register)(REG_D0 + ((decode.vmla.vd << 1) | decode.vmla.d));
									instruction->operands[1].cls = REG;
									instruction->operands[1].reg = (Register)(REG_S0 + ((decode.vmla.vm << 1) | decode.vmla.m));
								}
								else
								{
									instruction->operands[0].cls = REG;
									instruction->operands[0].reg = (Register)(REG_S0 + ((decode.vmla.d << 4) | decode.vmla.vd));
									instruction->operands[1].cls = REG;
									instruction->operands[1].reg = (Register)(REG_D0 + ((decode.vmla.m << 4) | decode.vmla.vm));
								}
							}
							else
							{
								Operation operation[2] = {ARMV7_VCVT, ARMV7_VCVTR};
								instruction->operation = operation[!decode.vcvtr.op];
								DataType dtMap2[2] = {DT_F32, DT_F64};
								instruction->dataType = DT_U32;
								instruction->dataType2 = dtMap2[decode.vcvta.sz];
								instruction->operands[0].cls = REG;
								instruction->operands[0].reg = (Register)(REG_S0 + ((decode.vcvta.vd << 1) | decode.vcvta.d));
								instruction->operands[1].cls = REG;
								if (decode.vcvta.sz == 1)
									instruction->operands[1].reg = (Register)(fregMap[decode.vcvta.sz] +
										((decode.vcvta.m << 4) | decode.vcvta.vm));
								else
									instruction->operands[1].reg = (Register)(fregMap[decode.vcvta.sz] +
										((decode.vcvta.vm << 1) | decode.vcvta.m));
							}
						}
						break;
					case 13:
						{
							static Operation operation[2] = {ARMV7_VCVTR, ARMV7_VCVT};
							instruction->operation = operation[decode.vcvt.sx];
							static DataType dtMap2[2] = {DT_F32, DT_F64};
							instruction->dataType = DT_S32;
							instruction->dataType2 = dtMap2[decode.vcvta.sz];
							instruction->operands[0].cls = REG;
							instruction->operands[0].reg = (Register)(REG_S0 + ((decode.vcvta.vd << 1) | decode.vcvta.d));
							instruction->operands[1].cls = REG;
							if (decode.vcvta.sz == 1)
								instruction->operands[1].reg = (Register)(fregMap[decode.vcvta.sz] +
									((decode.vcvta.m << 4) | decode.vcvta.vm));
							else
								instruction->operands[1].reg = (Register)(fregMap[decode.vcvta.sz] +
									((decode.vcvta.vm << 1) | decode.vcvta.m));
						}
						break;
					case 10:
					case 11:
						{
							static DataType dt[2][2] = {
								{DT_S16, DT_U16},
								{DT_S32, DT_U32}
							};
							static DataType fdt[2] = {DT_F32, DT_F64};
							instruction->operation = ARMV7_VCVT;
							if (decode.vmla.op == 0)
							{
								instruction->dataType = dt[decode.vcvt.sx][decode.vcvt.u];
								instruction->dataType2 = fdt[decode.vcvt.sf];
							}
							else
							{
								instruction->dataType = fdt[decode.vcvt.sf];
								instruction->dataType2 = dt[decode.vcvt.sx][decode.vcvt.u];
							}
							uint32_t reg;
							if (decode.vcvt.sf == 1)
							{
								reg = fregMap[decode.vcvt.sf] + ((decode.vcvt.d << 4) | decode.vcvt.vd);
							}
							else
							{
								reg = fregMap[decode.vcvt.sf] + ((decode.vcvt.vd << 1) | decode.vcvt.d);
							}
							instruction->operands[0].cls = REG;
							instruction->operands[0].reg = (Register)reg;
							instruction->operands[1].cls = REG;
							instruction->operands[1].reg = (Register)reg;
							instruction->operands[2].cls = IMM;
							instruction->operands[2].imm = (16 << decode.vcvt.sx) - ((decode.vcvt.imm4 << 1) | decode.vcvt.i);

						}
						break;
					case 14:
					case 15:
						{
							/*
							* VCVT<c>.<Td>.F64 <Dd>, <Dd>, #<fbits>
							* VCVT<c>.<Td>.F32 <Sd>, <Sd>, #<fbits>
							* VCVT<c>.F64.<Td> <Dd>, <Dd>, #<fbits>
							* VCVT<c>.F32.<Td> <Sd>, <Sd>, #<fbits>
							*/
							static DataType dt[2][2] = {
								{DT_S16, DT_U16},
								{DT_S32, DT_U32}
							};
							static DataType fdt[2] = {DT_F32, DT_F64};
							instruction->operation = ARMV7_VCVT;
							if (decode.vmla.op == 1)
							{
								instruction->dataType = dt[decode.vcvt.sx][decode.vcvt.u];
								instruction->dataType2 = fdt[decode.vcvt.sf];
							}
							else
							{
								instruction->dataType = fdt[decode.vcvt.sf];
								instruction->dataType2 = dt[decode.vcvt.sx][decode.vcvt.u];
							}
							uint32_t reg;
							if (decode.vcvt.sf == 1)
							{
								reg = fregMap[decode.vcvt.sf] + ((decode.vcvt.d << 4) | decode.vcvt.vd);
							}
							else
							{
								reg = fregMap[decode.vcvt.sf] + ((decode.vcvt.vd << 1) | decode.vcvt.d);
							}
							instruction->operands[0].cls = REG;
							instruction->operands[0].reg = (Register)reg;
							instruction->operands[1].cls = REG;
							instruction->operands[1].reg = (Register)reg;
							instruction->operands[2].cls = IMM;
							instruction->operands[2].imm = (16 << decode.vcvt.sx) - ((decode.vcvt.imm4 << 1) | decode.vcvt.i);
						}
						break;
				}
			}
			return instruction->operation == ARMV7_UNDEFINED;
	}
//	}
//	else
//	{
//		uint32_t fregMap[2] = {REG_SINGLE, REG_DOUBLE};
//		DataType dtMap[2] = {DT_F32, DT_F64};
//		printf("opc1: %d\n", decode.com.opc1);
//		switch (decode.com.opc1)
//		{
//			case 0: case 1: case 2: case 3: case 4: case 5: case 6: case 7:
//				instruction->operation = ARMV7_VSEL;
//				instruction->cond = (Condition)decode.com.cond;
//				instruction->dataType = dtMap[decode.vsel.sz];
//				instruction->operands[0].cls = fregMap[decode.vsel.sz];
//				instruction->operands[0].reg = (Register)decode.vsel.vd;
//				instruction->operands[1].cls = fregMap[decode.vsel.sz];
//				instruction->operands[1].reg = (Register)decode.vsel.vn;
//				instruction->operands[2].cls = fregMap[decode.vsel.sz];
//				instruction->operands[2].reg = (Register)decode.vsel.vm;
//				break;
//			case 8: case 12:
//				{
//					Operation operation[2] = {ARMV7_VMAXNM, ARMV7_VMINM};
//					instruction->operation = operation[decode.vmax.op];
//					instruction->dataType = dtMap[decode.vmax.sz];
//					instruction->operands[0].cls = fregMap[decode.vmax.sz];
//					instruction->operands[0].reg = (Register)decode.vmax.vd;
//					instruction->operands[1].cls = fregMap[decode.vmax.sz];
//					instruction->operands[1].reg = (Register)decode.vmax.vn;
//					instruction->operands[2].cls = fregMap[decode.vmax.sz];
//					instruction->operands[2].reg = (Register)decode.vmax.vm;
//				}
//				break;
//			case 11: case 15:
//				if ((decode.com.opc2 >> 2) == 2 )
//				{
//					if (decode.com.opc3 == 1)
//					{
//						Operation operation[4] = {ARMV7_VRINTA, ARMV7_VRINTN, ARMV7_VRINTP, ARMV7_VRINTM};
//						instruction->operation = operation[decode.vrint2.rm];
//						instruction->dataType = dtMap[decode.vrint2.sz];
//						instruction->operands[0].cls = fregMap[decode.vrint2.sz];
//						instruction->operands[0].reg = (Register)decode.vrint2.vd;
//						instruction->operands[1].cls = fregMap[decode.vrint2.sz];
//						instruction->operands[1].reg = (Register)decode.vrint2.vm;
//					}
//				}
//				else if ((decode.com.opc2 >> 2) == 3)
//				{
//					if ((decode.com.opc3 & 2) == 1)
//					{
//						DataType dtMap2[2] = {DT_U32, DT_S32};
//						Operation operation[4] = {ARMV7_VCVTA, ARMV7_VCVTN, ARMV7_VCVTP, ARMV7_VCVTM};
//						instruction->operation = operation[decode.vcvt2.rm];
//						instruction->dataType = dtMap2[decode.vcvt2.op];
//						instruction->dataType2 = dtMap[decode.vcvt2.sz];
//						instruction->operands[0].cls = fregMap[decode.vcvt2.sz];
//						instruction->operands[0].reg = (Register)decode.vcvt2.vd;
//						instruction->operands[1].cls = fregMap[decode.vcvt2.sz];
//						instruction->operands[1].reg = (Register)decode.vcvt2.vm;
//					}
//				}
//				else
//				{
//					printf("opc2: %d opc3: %d\n", decode.com.opc2, decode.com.opc3);
//				}
//				break;
//			default:
//				printf("opc1: %d\n", decode.com.opc1);
//				break;
//		}
//		return instruction->operation == ARMV7_UNDEFINED;
//	}

	uint32_t i = 0;
	if (decode.vmla.sz == 1)
	{
		instruction->operands[i].cls = REG;
		instruction->operands[i++].reg = (Register)(REG_D0 + (decode.vmla.vd | (decode.vmla.d << 4)));
		instruction->operands[i].cls = REG;
		instruction->operands[i].reg = (Register)(REG_D0 + (decode.vmla.vn | (decode.vmla.n << 4)));
		i += type;
		instruction->operands[i].cls  = REG;
		instruction->operands[i].reg = (Register)(REG_D0 + (decode.vmla.vm | (decode.vmla.m << 4)));
	}
	else
	{
		instruction->operands[i].cls = REG;
		instruction->operands[i++].reg = (Register)(REG_S0 + ((decode.vmla.vd << 1) | decode.vmla.d));
		instruction->operands[i].cls = REG;
		instruction->operands[i].reg = (Register)(REG_S0 + ((decode.vmla.vn << 1) | decode.vmla.n));
		i += type;
		instruction->operands[i].cls = REG;
		instruction->operands[i].reg = (Register)(REG_S0 + ((decode.vmla.vm << 1) | decode.vmla.m));
	}
	return instruction->operation == ARMV7_UNDEFINED;
}
#define ROTL32(x, n) ((x << (n)) | (x >> (32-(n))))
static uint32_t reg_start_and_size_to_list(uint32_t start, uint32_t size)
{
	if (size > 32)
		size = 32 - start;
	return ((1 << size) - 1) << start;
	//return ROTL32((((uint32_t)-1) >> (32-size)), start);
}

uint32_t armv7_extension_register_load_store(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
	/*A7.6 Extension register load/store instructions*/
	union {
		uint32_t value;
		struct {
			uint32_t group1:16;
			uint32_t rn:4;
			uint32_t opcode:5;
			uint32_t group2:3;
			uint32_t cond:4;
		}com;
		struct {
			uint32_t vm:4;
			uint32_t op:4;
			uint32_t c:1;
			uint32_t group2:19;
			uint32_t cond:4;
		}vmov;
		struct {
			uint32_t vm:4;
			uint32_t group1:1;
			uint32_t m:1;
			uint32_t group2:6;
			uint32_t rt:4;
			uint32_t rt2:2;
			uint32_t op:1;
			uint32_t group3:7;
			uint32_t cond:4;
		}vmov1;
		struct {
			uint32_t imm8:8;
			uint32_t size:1;
			uint32_t group1:3;
			uint32_t vd:4;
			uint32_t rn:4;
			uint32_t group2:1;
			uint32_t w:1;
			uint32_t d:1;
			uint32_t u:1;
			uint32_t p:1;
			uint32_t group3:3;
			uint32_t cond:4;
		}vstm;
	}decode;
	(void)address;

	decode.value = instructionValue;
	instruction->cond = (Condition)decode.com.cond;
	switch (decode.com.opcode)
	{
		case 4:
		case 5:
			{
				instruction->operation = ARMV7_VMOV;
				uint32_t fregMap[2] = {REG_S0, REG_R0};
				uint32_t m = (decode.vmov1.vm << 1) | decode.vmov1.m;

				if (decode.vmov.c == 0)
				{
					if (decode.vmov1.op == 1)
					{
						instruction->operands[0].cls = REG;
						instruction->operands[0].reg = (Register)(fregMap[decode.vmov.op] + (m));
						instruction->operands[1].cls = REG;
						instruction->operands[1].reg = (Register)(fregMap[decode.vmov.op] + (m+1));
						instruction->operands[2].cls = REG;
						instruction->operands[2].reg = (Register)(fregMap[!decode.vmov.op] + (decode.vmov.vm));
						instruction->operands[3].cls = REG;
						instruction->operands[3].reg = (Register)(fregMap[!decode.vmov.op] + (decode.vmov.vm + 1));
					}
					else
					{
						instruction->operands[0].cls = REG;
						instruction->operands[0].reg = (Register)(fregMap[!decode.vmov.op] + (decode.vmov.vm));
						instruction->operands[1].cls = REG;
						instruction->operands[1].reg = (Register)(fregMap[!decode.vmov.op] + (decode.vmov.vm + 1));
						instruction->operands[2].cls = REG;
						instruction->operands[2].reg = (Register)(fregMap[decode.vmov.op] + (m));
						instruction->operands[3].cls = REG;
						instruction->operands[3].reg = (Register)(fregMap[decode.vmov.op] + (m+1));
					}
				}
				else
				{
					if (decode.vmov1.op == 1)
					{
						instruction->operands[0].cls = REG;
						instruction->operands[0].reg = (Register)m;
						instruction->operands[1].cls = REG;
						instruction->operands[1].reg = (Register)decode.vmov1.rt;
						instruction->operands[2].cls = REG;
						instruction->operands[2].reg = (Register)decode.vmov1.rt2;
					}
					else
					{
						instruction->operands[0].cls = REG;
						instruction->operands[0].reg = (Register)decode.vmov1.rt;
						instruction->operands[1].cls = REG;
						instruction->operands[1].reg = (Register)decode.vmov1.rt2;
						instruction->operands[2].cls = REG;
						instruction->operands[2].reg = (Register)m;
					}
				}
			}
			break;
		case 18:
		case 22:
		case 8:
		case 10:
		case 12:
		case 14:
			{
				static OperandClass regListType[2] = {REG_LIST_SINGLE, REG_LIST_DOUBLE};
				if ((decode.vstm.p == 0 && decode.vstm.u == 0 && decode.vstm.w == 0) ||
					((decode.vstm.imm8 & 1) == 1 && decode.vstm.size == 1))
				{
					static Operation operation[2][2] = {
						{ARMV7_UNDEFINED, ARMV7_FSTMIAX},
						{ARMV7_FSTMDBX, ARMV7_UNDEFINED}
					};
					instruction->operation = operation[decode.vstm.p][decode.vstm.u];
				}
				else if (decode.vstm.p == 1 && decode.vstm.u == 0 &&
						decode.vstm.w == 1 && decode.vstm.rn == 13)
				{
					instruction->operation = ARMV7_VPUSH;
				}
				else
				{
					static Operation operation[2][2] = {
						{ARMV7_UNDEFINED, ARMV7_VSTMIA},
						{ARMV7_VSTMDB, ARMV7_UNDEFINED}
					};
					instruction->operation = operation[decode.vstm.p][decode.vstm.u];
				}
				uint32_t i = 0;
				if (instruction->operation != ARMV7_VPUSH)
				{
					instruction->operands[i].cls = REG;
					instruction->operands[i].flags.wb = decode.vstm.w;
					instruction->operands[i++].reg = (Register)decode.vstm.rn;
				}
				instruction->operands[i].cls = regListType[decode.vstm.size];
				instruction->operands[i].flags.hasElements = 0;
				uint32_t d = 0;
				if (decode.vstm.size == 0)
					d = (decode.vstm.vd << 1) | decode.vstm.d;
				else
					d = (decode.vstm.d << 4) | decode.vstm.vd;

				instruction->operands[i].reg = (Register)reg_start_and_size_to_list(d, decode.vstm.imm8 >> decode.vstm.size);
			}
			break;
		case 16:
		case 20:
		case 24:
		case 28:
			instruction->operation = ARMV7_VSTR;
			if (decode.vstm.size == 0)
			{
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)(REG_S0 + ((decode.vstm.vd << 1) | decode.vstm.d));
			}
			else
			{
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)(REG_D0 + ((decode.vstm.d << 4) | decode.vstm.vd));
			}
			instruction->operands[1].cls = MEM_IMM;
			instruction->operands[1].reg = (Register)decode.vstm.rn;
			instruction->operands[1].imm = decode.vstm.imm8 << 2;
			instruction->operands[1].flags.add = decode.vstm.u;
			break;
		case 9:
		case 11:
		case 13:
		case 15:
		case 19:
		case 23:
			{
				static OperandClass regListType[2] = {REG_LIST_SINGLE, REG_LIST_DOUBLE};
				if ((decode.vstm.p == 0 && decode.vstm.u == 0 && decode.vstm.w == 0) ||
					((decode.vstm.imm8 & 1) == 1 && decode.vstm.size == 1))
				{
					static Operation operation[2][2] = {
						{ARMV7_UNDEFINED, ARMV7_FLDMIAX},
						{ARMV7_FLDMDBX, ARMV7_UNDEFINED}
					};
					instruction->operation = operation[decode.vstm.p][decode.vstm.u];
				}
				else if (decode.vstm.p == 0 && decode.vstm.u == 1 &&
						decode.vstm.w == 1 && decode.vstm.rn == 13)
				{
					instruction->operation = ARMV7_VPOP;
				}
				else if (decode.vstm.p == 1 && decode.vstm.w == 0)
				{
					instruction->operation = ARMV7_VLDR;
				}
				else
				{
					static Operation operation[2][2] = {
						{ARMV7_UNDEFINED, ARMV7_VLDMIA},
						{ARMV7_VLDMDB, ARMV7_UNDEFINED}
					};
					instruction->operation = operation[decode.vstm.p][decode.vstm.u];
				}
				uint32_t i = 0;
				if (instruction->operation != ARMV7_VPOP)
				{
					instruction->operands[i].cls = REG;
					instruction->operands[i].flags.wb = decode.vstm.w;
					instruction->operands[i++].reg = (Register)decode.vstm.rn;
				}
				instruction->operands[i].cls = regListType[decode.vstm.size];
				instruction->operands[i].flags.hasElements = 0;
				uint32_t d = 0;
				if (decode.vstm.size == 0)
					d = (decode.vstm.vd << 1) | decode.vstm.d;
				else
					d = (decode.vstm.d << 4) | decode.vstm.vd;

				instruction->operands[i].reg = (Register)reg_start_and_size_to_list(d, decode.vstm.imm8 >> decode.vstm.size);
			}
			break;
		case 17:
		case 21:
		case 25:
		case 29:
			instruction->operation = ARMV7_VLDR;
			if (decode.vstm.size == 0)
			{
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)(REG_S0 + ((decode.vstm.vd << 1) | decode.vstm.d));
			}
			else
			{
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)(REG_D0 + ((decode.vstm.d << 4) | decode.vstm.vd));
			}
			instruction->operands[1].cls = MEM_IMM;
			instruction->operands[1].reg = (Register)decode.vstm.rn;
			instruction->operands[1].imm = decode.vstm.imm8 << 2;
			instruction->operands[1].flags.add = decode.vstm.u;
			break;
	}
	return instruction->operation == ARMV7_UNDEFINED;
}

uint32_t armv7_simd_load_store(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
	/*A7.7 Advanced SIMD element or structure load/store instructions*/
	(void)address;
	union {
		uint32_t value;
		struct {
			uint32_t group1:8;
			uint32_t b:4;
			uint32_t group2:9;
			uint32_t l:1;
			uint32_t group3:1;
			uint32_t a:1;
			uint32_t group4:8;
		} com;
		struct {
			uint32_t rm:4;
			uint32_t align:2;
			uint32_t size:2;
			uint32_t type:4;
			uint32_t vd:4;
			uint32_t rn:4;
			uint32_t group1:2;
			uint32_t d:1;
			uint32_t group2:9;
		} vst;
		struct {
			uint32_t rm:4;
			uint32_t index_align:4;
			uint32_t group1:2;
			uint32_t size:2;
			uint32_t vd:4;
			uint32_t rn:4;
			uint32_t group2:2;
			uint32_t d:1;
			uint32_t group3:9;
		} v2;
		struct {
			uint32_t rm:4;
			uint32_t a:1;
			uint32_t t:1;
			uint32_t size:2;
			uint32_t group1:4;
			uint32_t vd:4;
			uint32_t rn:4;
			uint32_t group2:2;
			uint32_t d:1;
			uint32_t group3:9;
		} v3;
	} decode;
	decode.value = instructionValue;
	instruction->cond = (Condition)COND_NONE;
	static DataType dtMap[4] = {DT_8, DT_16, DT_32, DT_64};
	uint32_t type = -1;
	uint32_t regs = 1;
	if (decode.com.l == 0)
	{
		if (decode.com.a == 0)
		{
			switch (decode.com.b)
			{
				case 2:
				case 6:
				case 7:
				case 10:
					instruction->operation = ARMV7_VST1;
					type = 0;
					break;
				case 3:
				case 8:
				case 9:
					instruction->operation = ARMV7_VST2;
					type = 1;
					break;
				case 4:
				case 5:
					instruction->operation = ARMV7_VST3;
					type = 2;
					break;
				case 0:
				case 1:
					instruction->operation = ARMV7_VST4;
					type = 3;
					break;
			}
		}
		else
		{
			switch (decode.com.b)
			{
				case 0:
				case 4:
				case 8:
					instruction->operation = ARMV7_VST1;
					type = 4;
					break;
				case 1:
				case 5:
				case 9:
					instruction->operation = ARMV7_VST2;
					type = 5;
					break;
				case 2:
				case 6:
				case 10:
					instruction->operation = ARMV7_VST3;
					type = 6;
					break;
				case 3:
				case 7:
				case 11:
					instruction->operation = ARMV7_VST4;
					type = 7;
					break;
			}
		}
	}
	else
	{
		if (decode.com.a == 0)
		{
			switch (decode.com.b)
			{
				case 2:
				case 6:
				case 7:
				case 10:
					instruction->operation = ARMV7_VLD1;
					type = 0;
					break;
				case 3:
				case 8:
				case 9:
					instruction->operation = ARMV7_VLD2;
					type = 1;
					break;
				case 4:
				case 5:
					instruction->operation = ARMV7_VLD3;
					type = 2;
					break;
				case 0:
				case 1:
					instruction->operation = ARMV7_VLD4;
					type = 3;
					break;
			}
		}
		else
		{
			switch (decode.com.b)
			{
				case 0:
				case 4:
				case 8:
					instruction->operation = ARMV7_VLD1;
					type = 4;
					break;
				case 12:
					instruction->operation = ARMV7_VLD1;
					type = 8;
					break;
				case 1:
				case 5:
				case 9:
					instruction->operation = ARMV7_VLD2;
					type = 5;
					break;
				case 13:
					instruction->operation = ARMV7_VLD2;
					type = 9;
					break;
				case 2:
				case 6:
				case 10:
					instruction->operation = ARMV7_VLD3;
					type = 6;
					break;
				case 14:
					instruction->operation = ARMV7_VLD3;
					type = 10;
					break;
				case 3:
				case 7:
				case 11:
					instruction->operation = ARMV7_VLD4;
					type = 7;
					break;
				case 15:
					instruction->operation = ARMV7_VLD4;
					type = 11;
					break;
			}
		}
	}

	switch (type)
	{
		case 0:
			{
			instruction->dataType = dtMap[decode.vst.size];
			instruction->operands[0].cls = REG_LIST_DOUBLE;
			instruction->operands[0].flags.hasElements = 0;
			uint32_t d = (decode.vst.d << 4) | decode.vst.vd;
			if (decode.vst.type == 7)
			{
				instruction->operands[0].reg = (Register)(1 << d);
				if (((decode.vst.align >> 1) & 1) == 1)
					return 1;
			}
			else if (decode.vst.type == 10)
			{
				instruction->operands[0].reg = (Register)(3 << d);
				if ((decode.vst.align & 3) == 3)
					return 1;
			}
			else if (decode.vst.type == 6)
			{
				instruction->operands[0].reg = (Register)(7 << d);
			}
			else if (decode.vst.type == 2)
			{
				instruction->operands[0].reg = (Register)(15 << d);
			}
			instruction->operands[1].cls = MEM_ALIGNED;
			instruction->operands[1].reg = (Register)decode.vst.rn;
			instruction->operands[1].flags.wb = decode.vst.rm == 13;
			if (decode.vst.align == 0)
				instruction->operands[1].imm = 0;
			else
				instruction->operands[1].imm = 32 << decode.vst.align;
			if (decode.vst.rm != 15 && decode.vst.rm != 13)
			{
				instruction->operands[2].cls = REG;
				instruction->operands[2].reg = (Register)decode.vst.rm;
			}
			}
			break;
		case 1:
			{
			switch (decode.vst.type)
			{
				case 8:
					if (decode.vst.align == 3)
						return 1;
					regs = 3 << ((decode.vst.d << 4) | decode.vst.vd);
					break;
				case 9:
					if (decode.vst.align == 3)
						return 1;
					regs = 5 << ((decode.vst.d << 4) | decode.vst.vd);
					break;
				case 3:
					regs = 15 << ((decode.vst.d << 4) | decode.vst.vd);
					break;
			}

			instruction->dataType = dtMap[decode.vst.size];
			instruction->operands[0].cls = REG_LIST_DOUBLE;
			instruction->operands[0].flags.hasElements = 0;
			instruction->operands[0].reg = (Register)regs;
			instruction->operands[1].cls = MEM_ALIGNED;
			instruction->operands[1].reg = (Register)decode.vst.rn;
			instruction->operands[1].flags.wb = decode.vst.rm == 13;
			if (decode.vst.align == 0)
				instruction->operands[1].imm = 0;
			else
				instruction->operands[1].imm = 32 << decode.vst.align;
			if (decode.vst.rm != 15 && decode.vst.rm != 13)
			{
				instruction->operands[2].cls = REG;
				instruction->operands[2].reg = (Register)decode.vst.rm;
			}
			}
			break;
		case 2:
			if (decode.vst.type == 4)
				regs = 7 << ((decode.vst.d << 4) | decode.vst.vd);
			else if (decode.vst.type == 5)
				regs = 21 << ((decode.vst.d << 4) | decode.vst.vd);

			instruction->dataType = dtMap[decode.vst.size];
			instruction->operands[0].cls = REG_LIST_DOUBLE;
			instruction->operands[0].flags.hasElements = 0;
			instruction->operands[0].reg = (Register)regs;
			instruction->operands[1].cls = MEM_ALIGNED;
			instruction->operands[1].reg = (Register)decode.vst.rn;
			instruction->operands[1].flags.wb = decode.vst.rm == 13;
			if (decode.vst.align == 0)
				instruction->operands[1].imm = 0;
			else
				instruction->operands[1].imm = 32 << decode.vst.align;
			if (decode.vst.rm != 15 && decode.vst.rm != 13)
			{
				instruction->operands[2].cls = REG;
				instruction->operands[2].reg = (Register)decode.vst.rm;
			}
			break;
		case 3:
			if (decode.vst.type == 0)
				regs = ROTL32(0xf, ((decode.vst.d << 4) | decode.vst.vd));
			else if (decode.vst.type == 1)
				regs = ROTL32(0x55, ((decode.vst.d << 4) | decode.vst.vd));

			instruction->dataType = dtMap[decode.vst.size];
			instruction->operands[0].cls = REG_LIST_DOUBLE;
			instruction->operands[0].flags.hasElements = 0;
			instruction->operands[0].reg = (Register)regs;
			instruction->operands[1].cls = MEM_ALIGNED;
			instruction->operands[1].reg = (Register)decode.vst.rn;
			instruction->operands[1].flags.wb = decode.vst.rm == 13;
			if (decode.vst.align == 0)
				instruction->operands[1].imm = 0;
			else
				instruction->operands[1].imm = 32 << decode.vst.align;
			if (decode.vst.rm != 15 && decode.vst.rm != 13)
			{
				instruction->operands[2].cls = REG;
				instruction->operands[2].reg = (Register)decode.vst.rm;
			}
			break;
		case 4:
			switch (decode.v2.size)
			{
				case 0:
					if ((decode.v2.index_align & 1) != 0)
						return 1;
					regs = 1 << ((decode.v2.d << 4) | decode.v2.vd);
					instruction->operands[0].imm = (decode.v2.index_align >> 1) & 7;
					break;
				case 1:
					if ((decode.v2.index_align & 2) != 0)
						return 1;
					if ((decode.v2.index_align & 3) == 1)
						instruction->operands[1].imm = 16;

					regs = 1 << ((decode.v2.d << 4) | decode.v2.vd);
					instruction->operands[0].imm = (decode.v2.index_align >> 2) & 3;
					break;
				case 2:
					if ((decode.v2.index_align & 4) != 0)
						return 1;
					if ((decode.v2.index_align & 7) == 3)
						instruction->operands[1].imm = 32;
					regs = 1 << ((decode.v2.d << 4) | decode.v2.vd);
					instruction->operands[0].imm = (decode.v2.index_align >> 3) & 1;
					break;
				case 3:
					return 1;
			}
			instruction->dataType = dtMap[decode.v2.size];
			instruction->operands[0].cls = REG_LIST_DOUBLE;
			instruction->operands[0].reg = (Register)regs;
			instruction->operands[0].flags.hasElements = 1;
			instruction->operands[1].cls = MEM_ALIGNED;
			instruction->operands[1].reg = (Register)decode.v2.rn;
			instruction->operands[1].flags.wb = decode.v2.rm == 13;
			if (decode.v2.rm != 15 && decode.v2.rm != 13)
			{
				instruction->operands[2].cls = REG;
				instruction->operands[2].reg = (Register)decode.v2.rm;
			}
			break;
		case 5:
			switch (decode.v2.size)
			{
				case 0:
					if ((decode.v2.index_align & 1) == 1)
						instruction->operands[1].imm = 16;

					regs = 3 << ((decode.v2.d << 4) | decode.v2.vd);
					instruction->operands[0].imm = (decode.v2.index_align >> 1) & 7;
					break;
				case 1:
					if ((decode.v2.index_align & 1) == 1)
						instruction->operands[1].imm = 32;

					if (((decode.v2.index_align >> 1) & 1) == 1)
						regs = 5 << ((decode.v2.d << 4) | decode.v2.vd);
					else
						regs = 3 << ((decode.v2.d << 4) | decode.v2.vd);
					instruction->operands[0].imm = (decode.v2.index_align >> 2) & 3;
					break;
				case 2:
					if ((decode.v2.index_align & 3) == 1)
						instruction->operands[1].imm = 64;

					if (((decode.v2.index_align >> 2) & 1) == 1)
						regs = 5 << ((decode.v2.d << 4) | decode.v2.vd);
					else
						regs = 3 << ((decode.v2.d << 4) | decode.v2.vd);
					instruction->operands[0].imm = (decode.v2.index_align >> 3) & 1;
					break;
				case 3:
					return 1;
			}
			instruction->dataType = dtMap[decode.v2.size];
			instruction->operands[0].cls = REG_LIST_DOUBLE;
			instruction->operands[0].reg = (Register)regs;
			instruction->operands[0].flags.hasElements = 1;
			instruction->operands[1].cls = MEM_ALIGNED;
			instruction->operands[1].reg = (Register)decode.v2.rn;
			instruction->operands[1].flags.wb = decode.v2.rm == 13;
			if (decode.v2.rm != 15 && decode.v2.rm != 13)
			{
				instruction->operands[2].cls = REG;
				instruction->operands[2].reg = (Register)decode.v2.rm;
			}
			break;
		case 6:
			switch (decode.v2.size)
			{
				case 0:
					if ((decode.v2.index_align & 1) == 1)
						instruction->operands[1].imm = 16;

					regs = 7 << ((decode.v2.d << 4) | decode.v2.vd);
					instruction->operands[0].imm = (decode.v2.index_align >> 1) & 7;
					break;
				case 1:
					if ((decode.v2.index_align & 1) == 1)
						instruction->operands[1].imm = 32;

					if (((decode.v2.index_align >> 1) & 1) == 1)
						regs = 21 << ((decode.v2.d << 4) | decode.v2.vd);
					else
						regs = 7 << ((decode.v2.d << 4) | decode.v2.vd);
					instruction->operands[0].imm = (decode.v2.index_align >> 2) & 3;
					break;
				case 2:
					if ((decode.v2.index_align & 3) == 1)
						instruction->operands[1].imm = 64;

					if (((decode.v2.index_align >> 2) & 1) == 1)
						regs = 21 << ((decode.v2.d << 4) | decode.v2.vd);
					else
						regs = 7 << ((decode.v2.d << 4) | decode.v2.vd);
					instruction->operands[0].imm = (decode.v2.index_align >> 3) & 1;
					break;
				case 3:
					return 1;
			}
			instruction->dataType = dtMap[decode.v2.size];
			instruction->operands[0].cls = REG_LIST_DOUBLE;
			instruction->operands[0].reg = (Register)regs;
			instruction->operands[0].flags.hasElements = 1;
			instruction->operands[1].cls = MEM_ALIGNED;
			instruction->operands[1].reg = (Register)decode.v2.rn;
			instruction->operands[1].flags.wb = decode.v2.rm == 13;
			if (decode.v2.rm != 15 && decode.v2.rm != 13)
			{
				instruction->operands[2].cls = REG;
				instruction->operands[2].reg = (Register)decode.v2.rm;
			}
			break;
		case 7:
			switch (decode.v2.size)
			{
				case 0:
					if ((decode.v2.index_align & 1) == 1)
						instruction->operands[1].imm = 32;

					regs = 15 << ((decode.v2.d << 4) | decode.v2.vd);
					instruction->operands[0].imm = (decode.v2.index_align >> 1) & 7;
					break;
				case 1:
					if ((decode.v2.index_align & 1) == 1)
						instruction->operands[1].imm = 64;

					if (((decode.v2.index_align >> 1) & 1) == 1)
						regs = 85 << ((decode.v2.d << 4) | decode.v2.vd);
					else
						regs = 15 << ((decode.v2.d << 4) | decode.v2.vd);
					instruction->operands[0].imm = (decode.v2.index_align >> 2) & 3;
					break;
				case 2:
					if ((decode.v2.index_align & 3) == 1)
						instruction->operands[1].imm = 64;
					else if ((decode.v2.index_align & 3) == 2)
						instruction->operands[1].imm = 128;

					if (((decode.v2.index_align >> 2) & 1) == 1)
						regs = 85 << ((decode.v2.d << 4) | decode.v2.vd);
					else
						regs = 15 << ((decode.v2.d << 4) | decode.v2.vd);
					instruction->operands[0].imm = (decode.v2.index_align >> 3) & 1;
					break;
				case 3:
					return 1;
			}
			instruction->dataType = dtMap[decode.v2.size];
			instruction->operands[0].cls = REG_LIST_DOUBLE;
			instruction->operands[0].reg = (Register)regs;
			instruction->operands[0].flags.hasElements = 1;
			instruction->operands[1].cls = MEM_ALIGNED;
			instruction->operands[1].reg = (Register)decode.v2.rn;
			instruction->operands[1].flags.wb = decode.v2.rm == 13;
			if (decode.v2.rm != 15 && decode.v2.rm != 13)
			{
				instruction->operands[2].cls = REG;
				instruction->operands[2].reg = (Register)decode.v2.rm;
			}
			break;
		case 8:
			{
			static uint32_t regNumMap[2] = {1,3};
			instruction->dataType = dtMap[decode.v3.size];
			instruction->operands[0].cls = REG_LIST_DOUBLE;
			instruction->operands[0].reg = (Register)(regNumMap[decode.v3.t] << ((decode.v3.d << 4) | decode.v3.vd));
			instruction->operands[0].flags.hasElements = 1;
			instruction->operands[0].flags.emptyElement = 1;
			instruction->operands[1].cls = MEM_ALIGNED;
			instruction->operands[1].reg = (Register)decode.v3.rn;
			instruction->operands[1].flags.wb = decode.v3.rm == 13;
			if (decode.v3.rm != 15 && decode.v3.rm != 13)
			{
				instruction->operands[2].cls = REG;
				instruction->operands[2].reg = (Register)decode.v3.rm;
			}
			}
			break;
		case 9:
			{
			static uint32_t regNumMap[2] = {3,5};
			instruction->dataType = dtMap[decode.v3.size];
			instruction->operands[0].cls = REG_LIST_DOUBLE;
			instruction->operands[0].reg = (Register)(regNumMap[decode.v3.t] << ((decode.v3.d << 4) | decode.v3.vd));
			instruction->operands[0].flags.hasElements = 1;
			instruction->operands[0].flags.emptyElement = 1;
			instruction->operands[1].cls = MEM_ALIGNED;
			instruction->operands[1].reg = (Register)decode.v3.rn;
			instruction->operands[1].flags.wb = decode.v3.rm == 13;
			if (decode.v3.rm != 15 && decode.v3.rm != 13)
			{
				instruction->operands[2].cls = REG;
				instruction->operands[2].reg = (Register)decode.v3.rm;
			}
			if ((decode.vst.align & 1) == 1)
				instruction->operands[1].imm = 16 << decode.vst.size;
			}
			break;
		case 10:
			{
			static uint32_t regNumMap[2] = {7,21};
			instruction->dataType = dtMap[decode.v3.size];
			instruction->operands[0].cls = REG_LIST_DOUBLE;
			instruction->operands[0].reg = (Register)(regNumMap[decode.v3.t] << ((decode.v3.d << 4) | decode.v3.vd));
			instruction->operands[0].flags.hasElements = 1;
			instruction->operands[0].flags.emptyElement = 1;
			instruction->operands[1].cls = MEM_ALIGNED;
			instruction->operands[1].reg = (Register)decode.v3.rn;
			instruction->operands[1].flags.wb = decode.v3.rm == 13;
			if (decode.v3.rm != 15 && decode.v3.rm != 13)
			{
				instruction->operands[2].cls = REG;
				instruction->operands[2].reg = (Register)decode.v3.rm;
			}
			}
			break;
		case 11:
			{
			static uint32_t regNumMap[2] = {15,85};
			instruction->dataType = dtMap[decode.v3.size];
			instruction->operands[0].cls = REG_LIST_DOUBLE;
			instruction->operands[0].reg = (Register)(regNumMap[decode.v3.t] << ((decode.v3.d << 4) | decode.v3.vd));
			instruction->operands[0].flags.hasElements = 1;
			instruction->operands[0].flags.emptyElement = 1;
			instruction->operands[1].cls = MEM_ALIGNED;
			instruction->operands[1].reg = (Register)decode.v3.rn;
			instruction->operands[1].flags.wb = decode.v3.rm == 13;
			if (decode.v3.rm != 15 && decode.v3.rm != 13)
			{
				instruction->operands[2].cls = REG;
				instruction->operands[2].reg = (Register)decode.v3.rm;
			}
			if ((decode.vst.align & 1) == 1)
			{
				if (decode.vst.size == 0)
					instruction->operands[1].imm = 32;
				else if (decode.vst.size < 3)
					instruction->operands[1].imm = 64;
				else
					instruction->operands[0].imm = 128;
			}
			}
			break;
		default:
			return 1;
	}
	return instruction->operation == ARMV7_UNDEFINED;
}

uint32_t armv7_transfers(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
	/*A7.8 - 8, 16, and 32-bit transfer between ARM core and extension registers*/
	(void)address;
	union {
		uint32_t value;
		struct {
			uint32_t group1:5;
			uint32_t b:2;
			uint32_t group2:1;
			uint32_t c:1;
			uint32_t group3:11;
			uint32_t l:1;
			uint32_t a:3;
			uint32_t group4:4;
			uint32_t cond:4;
		} com;
		struct {
			uint32_t group1:12;
			uint32_t rt:4;
			uint32_t reg:4;
			uint32_t group2:12;
		} vmsr;
		struct {
			uint32_t group1:7;
			uint32_t n:1;
			uint32_t group2:4;
			uint32_t rt:4;
			uint32_t vn:4;
			uint32_t op:1;
			uint32_t group3:11;
		} vmov;
		struct {
			uint32_t group1:5;
			uint32_t opc2:2;
			uint32_t d:1;
			uint32_t group2:4;
			uint32_t rt:4;
			uint32_t vd:4;
			uint32_t group3:1;
			uint32_t opc1:2;
			uint32_t u:1;
			uint32_t group4:8;
		} vmov2;
		struct {
			uint32_t group1:5;
			uint32_t e:1;
			uint32_t group2:1;
			uint32_t d:1;
			uint32_t group3:4;
			uint32_t rt:4;
			uint32_t vd:4;
			uint32_t group4:1;
			uint32_t q:1;
			uint32_t b:1;
			uint32_t group5:9;
		} vdup;
	} decode;

	decode.value = instructionValue;
	instruction->cond = (Condition)decode.com.cond;
	if (decode.com.c == 0)
	{
		if (decode.com.a == 0)
		{
			instruction->operation = ARMV7_VMOV;
			instruction->operands[decode.vmov.op].cls = REG;
			instruction->operands[decode.vmov.op].reg = (Register)(REG_S0 + (((decode.vmov.vn << 1) | decode.vmov.n)));
			instruction->operands[!decode.vmov.op].cls = REG;
			instruction->operands[!decode.vmov.op].reg = (Register)decode.vmov.rt;
		}
		else if (decode.com.a == 7)
		{
			static Register regs[16] = {
				REGS_FPSID, // 0
				REGS_FPSCR, // 1
				REG_INVALID,
				REG_INVALID,
				REG_INVALID,
				REGS_MVFR2,
				REGS_MVFR1, // 6
				REGS_MVFR0, // 7
				REGS_FPEXC, // 8
				REGS_FPINST, // 9
				REGS_FPINST2, //10
				REG_INVALID,
				REG_INVALID,
				REG_INVALID,
				REG_INVALID,
				REG_INVALID,
			};
			static Operation operation[2] = {ARMV7_VMSR, ARMV7_VMRS};
			instruction->operation = operation[decode.com.l];
			instruction->operands[decode.com.l].cls = REG_SPEC;
			instruction->operands[decode.com.l].regs = regs[decode.vmsr.reg];
			if (instruction->operands[decode.com.l].regs == REG_INVALID)

				return 1;
			if (instruction->operands[decode.com.l].regs == REGS_FPSCR && decode.vmsr.rt == 15)
			{
				instruction->operands[!decode.com.l].cls = REG_SPEC;
				instruction->operands[!decode.com.l].regs = REGS_APSR_NZCV;
			}
			else
			{
				instruction->operands[!decode.com.l].cls = REG;
				instruction->operands[!decode.com.l].reg = (Register)decode.vmsr.rt;
			}
		}
	}
	else
	{
		if (decode.com.a < 4 || decode.com.l == 1)
		{
			instruction->operation = ARMV7_VMOV;
			instruction->operands[decode.com.l].cls = REG;
			instruction->operands[decode.com.l].reg = (Register)(REG_D0 + (((decode.vmov2.d << 4) | decode.vmov2.vd)));
			instruction->operands[decode.com.l].flags.hasElements = 1;
			if (decode.com.l == 0)
			{
				switch ((decode.vmov2.opc1 << 2) | decode.vmov2.opc2)
				{
					case 8:  case 9:  case 10: case 11:
					case 12: case 13: case 14: case 15:
						instruction->operands[decode.com.l].imm = ((decode.vmov2.opc1 & 1) << 2) | decode.vmov2.opc2;
						instruction->dataType = DT_8;
						break;
					case 1: case 3: case 5: case 7:
						instruction->operands[decode.com.l].imm =
							((decode.vmov2.opc1 & 1) << 1) | ((decode.vmov2.opc2 >> 1) & 1);
						instruction->dataType = DT_16;
						break;
					case 0: case 4:
						instruction->operands[decode.com.l].imm = decode.vmov2.opc1 & 1;
						instruction->dataType = DT_32;
						break;
					case 2: case 6:
						return 1;
				}
			}
			else
			{
				uint32_t opc1_1 = (decode.vmov2.opc1 >> 1) & 1;
				uint32_t opc2_0 = decode.vmov2.opc2 & 1;
				uint32_t u = decode.vmov2.u;
				if (u == 0)
				{
					if (u == 0 && opc1_1 == 1)
					{
						instruction->dataType = DT_S8;
						instruction->operands[decode.com.l].imm =
							((decode.vmov2.opc1 & 1) << 2) | decode.vmov2.opc2;
					}
					else if (u == 0 && opc1_1 == 0 && opc2_0 == 1)
					{
						instruction->dataType = DT_S16;
						instruction->operands[decode.com.l].imm =
							((decode.vmov2.opc1 & 1) << 1) | ((decode.vmov2.opc2 >> 1) & 1);
					}
					else if (u == 0 && opc1_1 == 0 && decode.vmov2.opc2 == 0)
					{
						instruction->dataType = DT_32;
						instruction->operands[decode.com.l].imm = decode.vmov2.opc1 & 1;
					}
				}
				else
				{
					if (opc1_1 == 1)
					{
						instruction->dataType = DT_U8;
						instruction->operands[decode.com.l].imm =
							((decode.vmov2.opc1 & 1) << 2) | decode.vmov2.opc2;
					}
					else if (opc1_1 == 0 && opc2_0 == 1)
					{
						instruction->dataType = DT_U16;
						instruction->operands[decode.com.l].imm =
							((decode.vmov2.opc1 & 1) << 1) | ((decode.vmov2.opc2 >> 1) & 1);
					}
				}
			}
			instruction->operands[!decode.com.l].cls = REG;
			instruction->operands[!decode.com.l].reg = (Register)decode.vmov2.rt;
		}
		else
		{
			if (decode.com.b < 2)
			{
				instruction->operation = ARMV7_VDUP;
				instruction->dataType = (DataType)(DT_32 - ((decode.vdup.b << 1) | decode.vdup.e));
				instruction->operands[0].cls = REG;
				instruction->operands[0].reg = (Register)(regMap[decode.vdup.q] + (((decode.vdup.d << 4) | decode.vdup.vd) >> decode.vdup.q));
				instruction->operands[1].cls = REG;
				instruction->operands[1].reg = (Register)decode.vdup.rt;
			}
		}
	}
	return instruction->operation == ARMV7_UNDEFINED;
}

uint32_t armv7_64_bit_transfers(uint32_t instructionValue, Instruction* restrict instruction, uint32_t address)
{
	/*A7.9 64-bit transfers between ARM core and extension registers*/
	(void)address;
	union {
		uint32_t value;
		struct {
			uint32_t group1:4;
			uint32_t one:1;
			uint32_t op:1;
			uint32_t zero:2;
			uint32_t c:1;
			uint32_t group2:17;
			uint32_t cond:4;
		} com;
		struct {
			uint32_t vm:4;
			uint32_t group1:1;
			uint32_t m:1;
			uint32_t group2:6;
			uint32_t rt:4;
			uint32_t rt2:4;
			uint32_t op:1;
			uint32_t group3:7;
			uint32_t cond:4;
		} vmov1;
	} decode;
	decode.value = instructionValue;
	if (decode.com.zero != 0 || decode.com.one != 1)
		return 1;

	instruction->operation = ARMV7_VMOV;
	if (decode.com.c == 0)
	{
		// VMOV<c> <Sm>, <Sm1>, <Rt>, <Rt2>
		// VMOV<c> <Rt>, <Rt2>, <Sm>, <Sm1>
		static uint8_t entries[2][4] = {{0,1,2,3}, {2,3,0,1}};
		instruction->operands[entries[decode.vmov1.op][0]].cls = REG;
		instruction->operands[entries[decode.vmov1.op][0]].reg = (Register)(REG_S0 + ((decode.vmov1.vm << 1) | decode.vmov1.m));
		instruction->operands[entries[decode.vmov1.op][1]].cls = REG;
		instruction->operands[entries[decode.vmov1.op][1]].reg = (Register)(REG_S0 + (((decode.vmov1.vm << 1) | decode.vmov1.m) + 1));
		instruction->operands[entries[decode.vmov1.op][2]].cls = REG;
		instruction->operands[entries[decode.vmov1.op][2]].reg = (Register)decode.vmov1.rt;
		instruction->operands[entries[decode.vmov1.op][3]].cls = REG;
		instruction->operands[entries[decode.vmov1.op][3]].reg = (Register)decode.vmov1.rt2;
	}
	else
	{
		// VMOV<c> <Dm>, <Rt>, <Rt2>
		// VMOV<c> <Rt>, <Rt2>, <Dm>
		static uint8_t entries[2][3] = {{0,1,2}, {2,0,1}};
		instruction->operands[entries[decode.vmov1.op][0]].cls = REG;
		instruction->operands[entries[decode.vmov1.op][0]].reg = (Register)(REG_D0 + ((decode.vmov1.m << 4) | decode.vmov1.vm));
		instruction->operands[entries[decode.vmov1.op][1]].cls = REG;
		instruction->operands[entries[decode.vmov1.op][1]].reg = (Register)decode.vmov1.rt;
		instruction->operands[entries[decode.vmov1.op][2]].cls = REG;
		instruction->operands[entries[decode.vmov1.op][2]].reg = (Register)decode.vmov1.rt2;
	}
	return instruction->operation == ARMV7_UNDEFINED;
}

const char* get_operation(Operation operation)
{
	if (operation > ARMV7_UNDEFINED && operation < ARMV7_END_INSTRUCTION)
		return operationString[operation];
	return "";
}

const char* get_vector_data_type(DataType dataType)
{
	if (dataType >= DT_NONE && dataType < DT_END)
		return dataTypeString[dataType];
	return "";
}

const char* get_register_name(Register reg)
{
	if (reg >= REG_R0 && reg < REG_INVALID)
		return registerString[reg];
	return NULL;
}

const char* get_banked_register_name(Register regb)
{
	if (regb >= REGB_ELR_HYP && regb <= REGB_SP_USR)
		return registerString[regb];
	return NULL;
}

const char* get_spec_register_name(Register regs)
{
	if (regs >= REGS_APSR && regs <= REGS_CONTROL)
		return registerString[regs];
	return NULL;
}

const char* get_coproc_register_c_name(CoprocRegisterC regc)
{
	if (regc >= REG_C0 && regc < REG_CEND)
		return coprocRegisterCString[regc - REG_C0];
	return NULL;
}

const char* get_coproc_register_p_name(CoprocRegisterP regp)
{
	if (regp >= REG_P0 && regp < REG_PEND)
		return coprocRegisterString[regp - REG_P0];
	return NULL;
}

const char* get_iflag(Iflags iflag)
{
	if (iflag >= IFL_NONE && iflag < IFL_END)
		return iflagStrings[iflag];
	return NULL;
}

const char* get_endian(EndianSpec spec)
{
	return endianSpecStrings[spec == 1];
}

const char* get_dsb_option(DsbOption opt)
{
	if (opt >= DSB_NONE0 && opt < DSB_END)
		return dsbOptionStrings[opt];
	return NULL;
}

const char* get_shift(Shift shift)
{
	if (shift >= SHIFT_NONE  && shift < SHIFT_END)
		return shiftString[shift];
	return NULL;
}

const char* get_condition(Condition cond)
{
	if (cond >= COND_EQ && cond < COND_END)
		return condString[cond];
	return "";
}

uint32_t get_register_names(Register reg, const char** regNames, OperandClass cls)
{
	uint32_t base = REG_R0;
	if (cls == REG_LIST_SINGLE)
		base = REG_S0;
	else if (cls == REG_LIST_DOUBLE)
		base = REG_D0;
	for (int32_t i = 31; i >= 0; i--)
	{
		if (((reg>>i)&1) == 1)
			regNames[i] = get_register_name((Register)(i + base));
		else
			regNames[i] = 0;
	}
	return 0;
}

uint32_t get_register_list(InstructionOperand* op, char* out, size_t outLength, OperandClass cls)
{
	const char* regbuf[32] = {0};
	get_register_names(op->reg, regbuf, cls);
	uint32_t first = 1;
	if (out == NULL)
		return 1;

	char* end = out + outLength;
	out[0] = '\0';
	for (uint32_t i = 0; i < 32 && out < end; i++)
	{
		if (regbuf[i] != 0)
		{
			if (first == 0)
				out += snprintf(out, end - out, ", ");

			first = 0;
			out += snprintf(out, end - out, "%s", regbuf[i]);
			if (op->flags.hasElements == 1)
			{
				if (op->flags.emptyElement == 1)
					out += snprintf(out, end - out, "[]");
				else
					out += snprintf(out, end - out, "[%d]", op->imm);
			}
		}
	}
	return 0;
}

uint32_t get_register_size(Register reg)
{
	if (reg <= REG_S31)
		return 4;
	else if (reg <= REG_D31)
		return 8;
	else if (reg <= REG_Q15)
		return 16;
	return 0;
}

char* get_full_operation(char* outBuffer, size_t outBufferSize, Instruction* restrict instruction)
{
	static const char* setsFlags[2] = {"", ".s"};

	snprintf(outBuffer, outBufferSize, "%s%s%s%s%s",
			get_operation(instruction->operation),
			setsFlags[instruction->setsFlags],
			get_condition(instruction->cond),
			get_vector_data_type(instruction->dataType),
			get_vector_data_type(instruction->dataType2));

	return outBuffer;
}

uint32_t armv7_disassemble(
		Instruction* restrict instruction,
		char* outBuffer,
		uint32_t outBufferSize)
{
	char operands[512];
	char tmpOperand[1024];
	static const char* neg[2] = {"-", ""};
	static const char* wb[2] = {"", "!"};
	static const char* crt[2] = {"", " ^"};
	memset(operands, 0, sizeof(operands));

	char* start = (char*)&operands;
	char* end = start + sizeof(operands);

	for (uint32_t i = 0; i < MAX_OPERANDS && instruction->operands[i].cls != NONE && start < end; i++)
	{
		InstructionOperand* op = &instruction->operands[i];
		if (i != 0)
			start += snprintf(start, end - start, ", ");
		switch (op->cls)
		{
		case REG:
				//reg
				//reg[imm]
				//reg <shift> imm
				//reg <shfit> offset
				if (op->flags.hasElements == 1)
				{
					if (op->flags.emptyElement == 1)
						start += snprintf(start, end - start, "%s[]", get_register_name(op->reg));
					else
						start += snprintf(start, end - start, "%s[%d]", get_register_name(op->reg), op->imm);
				}
				else if (op->shift == SHIFT_NONE)
				{
					start += snprintf(start, end - start, "%s%s", get_register_name(op->reg), wb[op->flags.wb]);
				}
				else if (op->flags.offsetRegUsed == 1)
				{   //shifted by register
					start += snprintf(start, end - start, "%s, %s %s",
								get_register_name(op->reg),
								get_shift(op->shift),
								get_register_name(op->offset));
				}
				else
				{   //shifted by immediate
					if (op->shift == SHIFT_RRX)
						start += snprintf(start, end - start, "%s, %s",
									get_register_name(op->reg),
									get_shift(op->shift));
					else if (op->imm != 0)
						start += snprintf(start, end - start, "%s, %s #%#x",
									get_register_name(op->reg),
									get_shift(op->shift),
									op->imm);
					else
						start += snprintf(start, end - start, "%s", get_register_name(op->reg));
				}
				break;
			case REG_LIST:
			case REG_LIST_SINGLE:
			case REG_LIST_DOUBLE:
				get_register_list(op, tmpOperand, sizeof(tmpOperand), op->cls);
				start += snprintf(start, end - start, "{%s}%s", tmpOperand, crt[op->flags.wb]);
				break;
			case REG_SPEC:
				start += snprintf(start, end - start, "%s", get_spec_register_name(op->regs));
				break;
			case REG_BANKED:
				start += snprintf(start, end - start, "%s", get_banked_register_name(op->regb));
				break;
			case REG_COPROCP:
				start += snprintf(start, end - start, "%s", get_coproc_register_p_name(op->regp));
				break;
			case REG_COPROCC:
				start += snprintf(start, end - start, "%s", get_coproc_register_c_name(op->regc));
				break;
			case IFLAGS:
				start += snprintf(start, end - start, "%s", get_iflag(op->iflag));
				break;
			case ENDIAN_SPEC:
				start += snprintf(start, end - start, "%s", get_endian(op->endian));
				break;
			case DSB_OPTION:
				start += snprintf(start, end - start, "%s", get_dsb_option(op->dsbOpt));
				break;
			case IMM:
				start += snprintf(start, end - start, "#%#x", op->imm);
				break;
			case LABEL:
				start += snprintf(start, end - start, "%#x", op->imm);
				break;
			case IMM64:
				start += snprintf(start, end - start, "#%#" PRIx64, op->imm64);
				break;
			case FIMM32:
				start += snprintf(start, end - start, "#%f", op->immf);
				break;
			case FIMM64:
				start += snprintf(start, end - start, "#%e", op->immd);
				break;
			case MEM_ALIGNED:
				if (op->imm != 0)
					snprintf(tmpOperand, sizeof(tmpOperand), ":%#x", op->imm);
				else
					tmpOperand[0] = 0;
				start += snprintf(start, end - start, "[%s%s]%s",
						get_register_name(op->reg),
						tmpOperand,
						wb[op->flags.wb]);
				break;
			case MEM_OPTION:
				start += snprintf(start, end - start, "[%s], {%#x}",
						get_register_name(op->reg),
						op->imm);
				break;
			case MEM_PRE_IDX:
				if (op->flags.offsetRegUsed == 1)
				{
					if (op->imm == 0)
						snprintf(tmpOperand, sizeof(tmpOperand), "%s", get_register_name(op->offset));
					else if (op->shift == SHIFT_RRX)
						snprintf(tmpOperand, sizeof(tmpOperand), "%s, %s",
							get_register_name(op->offset),
							get_shift(op->shift));
					else
						snprintf(tmpOperand, sizeof(tmpOperand), "%s, %s #%#x",
							get_register_name(op->offset),
							get_shift(op->shift),
							op->imm);

					start += snprintf(start, end - start, "[%s, %s%s]!",
							get_register_name(op->reg),
							neg[op->flags.add == 1],
							tmpOperand);
				}
				else
				{
					start += snprintf(start, end - start, "[%s, #%s%#x]!",
							get_register_name(op->reg),
							neg[op->flags.add == 1],
							op->imm);
				}
				break;
			case MEM_POST_IDX:
				if (op->flags.offsetRegUsed == 1)
				{
					if (op->imm == 0)
						snprintf(tmpOperand, sizeof(tmpOperand), "%s", get_register_name(op->offset));
					else
						if (op->shift == SHIFT_RRX)
							snprintf(tmpOperand, sizeof(tmpOperand), "%s, %s", get_register_name(op->offset), get_shift(op->shift));
						else
							snprintf(tmpOperand, sizeof(tmpOperand), "%s, %s #%#x", get_register_name(op->offset), get_shift(op->shift), op->imm);

					start += snprintf(start, end - start, "[%s], %s%s",
							get_register_name(op->reg),
							neg[op->flags.add == 1],
							tmpOperand);
				}
				else
				{
					start += snprintf(start, end - start, "[%s], #%s%#x",
							get_register_name(op->reg),
							neg[op->flags.add == 1],
							op->imm);
				}
				break;
			case MEM_IMM:
				if (op->shift == SHIFT_NONE)
				{
					if (op->flags.offsetRegUsed == 1)
					{
						start += snprintf(start, end - start, "[%s, %s%s]",
								get_register_name(op->reg),
								neg[op->flags.add == 1],
								get_register_name(op->offset));
					}
					else
					{
						if (op->imm != 0)
							start += snprintf(start, end - start, "[%s, #%s%#x]",
									get_register_name(op->reg),
									neg[op->flags.add == 1],
									op->imm);
						else
							start += snprintf(start, end - start, "[%s]", get_register_name(op->reg));
					}
				}
				else if (op->shift == SHIFT_RRX)
					start += snprintf(start, end - start, "[%s, %s%s, %s]",
							get_register_name(op->reg),
							neg[op->flags.add == 1],
							get_register_name(op->offset),
							get_shift(op->shift));
				else
					start += snprintf(start, end - start, "[%s, %s%s, %s #%#x]",
							get_register_name(op->reg),
							neg[op->flags.add == 1],
							get_register_name(op->offset),
							get_shift(op->shift),
							op->imm);
				break;
			default:
				return 4;
		}
	}
	snprintf(outBuffer, outBufferSize, "%s\t%s",
		get_full_operation(tmpOperand, sizeof(tmpOperand), instruction),
		operands);
	return 0;
}
