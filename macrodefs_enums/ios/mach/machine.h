// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/machine.h

enum macro_cpu_state_max {
/*line: 74*/    CPU_STATE_MAX = 0x4,  // 4
};

enum macro_cpu_states {
/*line: 76*/    CPU_STATE_USER = 0x0,  // 0
/*line: 77*/    CPU_STATE_SYSTEM = 0x1,  // 1
/*line: 78*/    CPU_STATE_IDLE = 0x2,  // 2
/*line: 79*/    CPU_STATE_NICE = 0x3,  // 3
/*
 * Capability bits used in the definition of cpu_type.
 */
/*line: 86*/    CPU_ARCH_MASK = 0xff000000, /* mask for architecture bits */ // 0xff000000
/*line: 87*/    CPU_ARCH_ABI64 = 0x1000000, /* 64 bit ABI */ // 0x01000000
/*line: 88*/    CPU_ARCH_ABI64_32 = 0x2000000, /* ABI for 64-bit hardware with 32-bit types; LP32 */ // 0x02000000
};

// Depends on identifiers
enum macro_cpu_types {
/*
 *	Machine types known by all.
 */
/*line: 94*/    CPU_TYPE_ANY = -0x1,  // ((cpu_type_t)-1)
/*line: 96*/    CPU_TYPE_VAX = 0x1,  // ((cpu_type_t)1)
/* skip				((cpu_type_t) 5)	*/
/*line: 101*/   CPU_TYPE_MC680x0 = 0x6,  // ((cpu_type_t)6)
/*line: 102*/   CPU_TYPE_X86 = 0x7,  // ((cpu_type_t)7)
/*line: 103*/   CPU_TYPE_I386 = 0x7, /* compatibility */ // CPU_TYPE_X86
/*line: 104*/   CPU_TYPE_X86_64 = 0x1000007,  // (CPU_TYPE_X86|CPU_ARCH_ABI64)
};

// Depends on identifiers
enum macro_cpu_type {
/* skip                         ((cpu_type_t) 9)	*/
/*line: 108*/   CPU_TYPE_MC98000 = 0xa,  // ((cpu_type_t)10)
/*line: 109*/   CPU_TYPE_HPPA = 0xb,  // ((cpu_type_t)11)
/*line: 110*/   CPU_TYPE_ARM = 0xc,  // ((cpu_type_t)12)
/*line: 111*/   CPU_TYPE_ARM64 = 0x100000c,  // (CPU_TYPE_ARM|CPU_ARCH_ABI64)
/*line: 112*/   CPU_TYPE_ARM64_32 = 0x200000c,  // (CPU_TYPE_ARM|CPU_ARCH_ABI64_32)
/*line: 113*/   CPU_TYPE_MC88000 = 0xd,  // ((cpu_type_t)13)
/*line: 114*/   CPU_TYPE_SPARC = 0xe,  // ((cpu_type_t)14)
/*line: 115*/   CPU_TYPE_I860 = 0xf,  // ((cpu_type_t)15)
/* skip				((cpu_type_t) 17)	*/
/*line: 118*/   CPU_TYPE_POWERPC = 0x12,  // ((cpu_type_t)18)
/*line: 119*/   CPU_TYPE_POWERPC64 = 0x1000012,  // (CPU_TYPE_POWERPC|CPU_ARCH_ABI64)
};

enum macro_cpu_subtype {
/*
 * Capability bits used in the definition of cpu_subtype.
 */
/*line: 136*/   CPU_SUBTYPE_MASK = 0xff000000, /* mask for feature flags */ // 0xff000000
/*line: 137*/   CPU_SUBTYPE_LIB64 = 0x80000000, /* 64 bit libraries */ // 0x80000000
/*line: 138*/   CPU_SUBTYPE_PTRAUTH_ABI = 0x80000000, /* pointer authentication with versioned ABI */ // 0x80000000
/*
 *      When selecting a slice, ANY will pick the slice with the best
 *      grading for the selected cpu_type_t, unlike the "ALL" subtypes,
 *      which are the slices that can run on any hardware for that cpu type.
 */
/*line: 145*/   CPU_SUBTYPE_ANY = -0x1,  // ((cpu_subtype_t)-1)
/*
 *	Object files that are hand-crafted to run on any
 *	implementation of an architecture are tagged with
 *	CPU_SUBTYPE_MULTIPLE.  This functions essentially the same as
 *	the "ALL" subtype of an architecture except that it allows us
 *	to easily find object files that may need to be modified
 *	whenever a new implementation of an architecture comes out.
 *
 *	It is the responsibility of the implementor to make sure the
 *	software handles unsupported implementations elegantly.
 */
/*line: 158*/   CPU_SUBTYPE_MULTIPLE = -0x1,  // ((cpu_subtype_t)-1)
/*line: 159*/   CPU_SUBTYPE_LITTLE_ENDIAN = 0x0,  // ((cpu_subtype_t)0)
/*line: 160*/   CPU_SUBTYPE_BIG_ENDIAN = 0x1,  // ((cpu_subtype_t)1)
};

// Depends on identifiers
enum macro_cpu_threadtype {
/*
 *     Machine threadtypes.
 *     This is none - not defined - for most machine types/subtypes.
 */
/*line: 166*/   CPU_THREADTYPE_NONE = 0x0,  // ((cpu_threadtype_t)0)
/*line: 253*/   CPU_THREADTYPE_INTEL_HTT = 0x1,  // ((cpu_threadtype_t)1)
};

// Depends on identifiers
enum macro_vax_subtype {
/*
 *	VAX subtypes (these do *not* necessary conform to the actual cpu
 *	ID assigned by DEC available via the SID register).
 */
/*line: 173*/   CPU_SUBTYPE_VAX_ALL = 0x0,  // ((cpu_subtype_t)0)
/*line: 174*/   CPU_SUBTYPE_VAX780 = 0x1,  // ((cpu_subtype_t)1)
/*line: 175*/   CPU_SUBTYPE_VAX785 = 0x2,  // ((cpu_subtype_t)2)
/*line: 176*/   CPU_SUBTYPE_VAX750 = 0x3,  // ((cpu_subtype_t)3)
/*line: 177*/   CPU_SUBTYPE_VAX730 = 0x4,  // ((cpu_subtype_t)4)
/*line: 178*/   CPU_SUBTYPE_UVAXI = 0x5,  // ((cpu_subtype_t)5)
/*line: 179*/   CPU_SUBTYPE_UVAXII = 0x6,  // ((cpu_subtype_t)6)
/*line: 180*/   CPU_SUBTYPE_VAX8200 = 0x7,  // ((cpu_subtype_t)7)
/*line: 181*/   CPU_SUBTYPE_VAX8500 = 0x8,  // ((cpu_subtype_t)8)
/*line: 182*/   CPU_SUBTYPE_VAX8600 = 0x9,  // ((cpu_subtype_t)9)
/*line: 183*/   CPU_SUBTYPE_VAX8650 = 0xa,  // ((cpu_subtype_t)10)
/*line: 184*/   CPU_SUBTYPE_VAX8800 = 0xb,  // ((cpu_subtype_t)11)
/*line: 185*/   CPU_SUBTYPE_UVAXIII = 0xc,  // ((cpu_subtype_t)12)
};

// Depends on identifiers
enum macro_cpu_680x0_subtype {
/*
 *      680x0 subtypes
 *
 * The subtype definitions here are unusual for historical reasons.
 * NeXT used to consider 68030 code as generic 68000 code.  For
 * backwards compatability:
 *
 *	CPU_SUBTYPE_MC68030 symbol has been preserved for source code
 *	compatability.
 *
 *	CPU_SUBTYPE_MC680x0_ALL has been defined to be the same
 *	subtype as CPU_SUBTYPE_MC68030 for binary comatability.
 *
 *	CPU_SUBTYPE_MC68030_ONLY has been added to allow new object
 *	files to be tagged as containing 68030-specific instructions.
 */
/*line: 204*/   CPU_SUBTYPE_MC680x0_ALL = 0x1,  // ((cpu_subtype_t)1)
/*line: 205*/   CPU_SUBTYPE_MC68030 = 0x1, /* compat */ // ((cpu_subtype_t)1)
/*line: 206*/   CPU_SUBTYPE_MC68040 = 0x2,  // ((cpu_subtype_t)2)
/*line: 207*/   CPU_SUBTYPE_MC68030_ONLY = 0x3,  // ((cpu_subtype_t)3)
};

enum macro_intel_family_max {
/*line: 238*/   CPU_SUBTYPE_INTEL_FAMILY_MAX = 0xf,  // 15
};

// Depends on identifiers
enum macro_cpu_x86_subtype {
/*line: 241*/   CPU_SUBTYPE_INTEL_MODEL_ALL = 0x0,  // 0
/*
 *	X86 subtypes.
 */
/*line: 247*/   CPU_SUBTYPE_X86_ALL = 0x3,  // ((cpu_subtype_t)3)
/*line: 248*/   CPU_SUBTYPE_X86_64_ALL = 0x3,  // ((cpu_subtype_t)3)
/*line: 249*/   CPU_SUBTYPE_X86_ARCH1 = 0x4,  // ((cpu_subtype_t)4)
/*line: 250*/   CPU_SUBTYPE_X86_64_H = 0x8, /* Haswell feature subset */ // ((cpu_subtype_t)8)
};

// Depends on identifiers
enum macro_cpu_mips_subtype {
/*
 *	Mips subtypes.
 */
/*line: 259*/   CPU_SUBTYPE_MIPS_ALL = 0x0,  // ((cpu_subtype_t)0)
/*line: 260*/   CPU_SUBTYPE_MIPS_R2300 = 0x1,  // ((cpu_subtype_t)1)
/*line: 261*/   CPU_SUBTYPE_MIPS_R2600 = 0x2,  // ((cpu_subtype_t)2)
/*line: 262*/   CPU_SUBTYPE_MIPS_R2800 = 0x3,  // ((cpu_subtype_t)3)
/*line: 263*/   CPU_SUBTYPE_MIPS_R2000a = 0x4, /* pmax */ // ((cpu_subtype_t)4)
/*line: 264*/   CPU_SUBTYPE_MIPS_R2000 = 0x5,  // ((cpu_subtype_t)5)
/*line: 265*/   CPU_SUBTYPE_MIPS_R3000a = 0x6, /* 3max */ // ((cpu_subtype_t)6)
/*line: 266*/   CPU_SUBTYPE_MIPS_R3000 = 0x7,  // ((cpu_subtype_t)7)
};

// Depends on identifiers
enum macro_cpu_mc98000_subtype {
/*
 *	MC98000 (PowerPC) subtypes
 */
/*line: 271*/   CPU_SUBTYPE_MC98000_ALL = 0x0,  // ((cpu_subtype_t)0)
/*line: 272*/   CPU_SUBTYPE_MC98601 = 0x1,  // ((cpu_subtype_t)1)
};

// Depends on identifiers
enum macro_cpu_hppa_subtype {
/*
 *	HPPA subtypes for Hewlett-Packard HP-PA family of
 *	risc processors. Port by NeXT to 700 series.
 */
/*line: 279*/   CPU_SUBTYPE_HPPA_ALL = 0x0,  // ((cpu_subtype_t)0)
/*line: 280*/   CPU_SUBTYPE_HPPA_7100 = 0x0, /* compat */ // ((cpu_subtype_t)0)
/*line: 281*/   CPU_SUBTYPE_HPPA_7100LC = 0x1,  // ((cpu_subtype_t)1)
};

// Depends on identifiers
enum macro_cpu_mc88000_subtype {
/*
 *	MC88000 subtypes.
 */
/*line: 286*/   CPU_SUBTYPE_MC88000_ALL = 0x0,  // ((cpu_subtype_t)0)
/*line: 287*/   CPU_SUBTYPE_MC88100 = 0x1,  // ((cpu_subtype_t)1)
/*line: 288*/   CPU_SUBTYPE_MC88110 = 0x2,  // ((cpu_subtype_t)2)
};

// Depends on identifiers
enum macro_cpu_sparc_subtype {
/*
 *	SPARC subtypes
 */
/*line: 293*/   CPU_SUBTYPE_SPARC_ALL = 0x0,  // ((cpu_subtype_t)0)
};

// Depends on identifiers
enum macro_cpu_i860_subtype {
/*
 *	I860 subtypes
 */
/*line: 298*/   CPU_SUBTYPE_I860_ALL = 0x0,  // ((cpu_subtype_t)0)
/*line: 299*/   CPU_SUBTYPE_I860_860 = 0x1,  // ((cpu_subtype_t)1)
};

// Depends on identifiers
enum macro_cpu_powerpc_subtype {
/*
 *	PowerPC subtypes
 */
/*line: 304*/   CPU_SUBTYPE_POWERPC_ALL = 0x0,  // ((cpu_subtype_t)0)
/*line: 305*/   CPU_SUBTYPE_POWERPC_601 = 0x1,  // ((cpu_subtype_t)1)
/*line: 306*/   CPU_SUBTYPE_POWERPC_602 = 0x2,  // ((cpu_subtype_t)2)
/*line: 307*/   CPU_SUBTYPE_POWERPC_603 = 0x3,  // ((cpu_subtype_t)3)
/*line: 308*/   CPU_SUBTYPE_POWERPC_603e = 0x4,  // ((cpu_subtype_t)4)
/*line: 309*/   CPU_SUBTYPE_POWERPC_603ev = 0x5,  // ((cpu_subtype_t)5)
/*line: 310*/   CPU_SUBTYPE_POWERPC_604 = 0x6,  // ((cpu_subtype_t)6)
/*line: 311*/   CPU_SUBTYPE_POWERPC_604e = 0x7,  // ((cpu_subtype_t)7)
/*line: 312*/   CPU_SUBTYPE_POWERPC_620 = 0x8,  // ((cpu_subtype_t)8)
/*line: 313*/   CPU_SUBTYPE_POWERPC_750 = 0x9,  // ((cpu_subtype_t)9)
/*line: 314*/   CPU_SUBTYPE_POWERPC_7400 = 0xa,  // ((cpu_subtype_t)10)
/*line: 315*/   CPU_SUBTYPE_POWERPC_7450 = 0xb,  // ((cpu_subtype_t)11)
/*line: 316*/   CPU_SUBTYPE_POWERPC_970 = 0x64,  // ((cpu_subtype_t)100)
};

// Depends on identifiers
enum macro_arm_subtype {
/*
 *	ARM subtypes
 */
/*line: 321*/   CPU_SUBTYPE_ARM_ALL = 0x0,  // ((cpu_subtype_t)0)
/*line: 322*/   CPU_SUBTYPE_ARM_V4T = 0x5,  // ((cpu_subtype_t)5)
/*line: 323*/   CPU_SUBTYPE_ARM_V6 = 0x6,  // ((cpu_subtype_t)6)
/*line: 324*/   CPU_SUBTYPE_ARM_V5TEJ = 0x7,  // ((cpu_subtype_t)7)
/*line: 325*/   CPU_SUBTYPE_ARM_XSCALE = 0x8,  // ((cpu_subtype_t)8)
/*line: 326*/   CPU_SUBTYPE_ARM_V7 = 0x9, /* ARMv7-A and ARMv7-R */ // ((cpu_subtype_t)9)
/*line: 327*/   CPU_SUBTYPE_ARM_V7F = 0xa, /* Cortex A9 */ // ((cpu_subtype_t)10)
/*line: 328*/   CPU_SUBTYPE_ARM_V7S = 0xb, /* Swift */ // ((cpu_subtype_t)11)
/*line: 329*/   CPU_SUBTYPE_ARM_V7K = 0xc,  // ((cpu_subtype_t)12)
/*line: 330*/   CPU_SUBTYPE_ARM_V8 = 0xd,  // ((cpu_subtype_t)13)
/*line: 331*/   CPU_SUBTYPE_ARM_V6M = 0xe, /* Not meant to be run under xnu */ // ((cpu_subtype_t)14)
/*line: 332*/   CPU_SUBTYPE_ARM_V7M = 0xf, /* Not meant to be run under xnu */ // ((cpu_subtype_t)15)
/*line: 333*/   CPU_SUBTYPE_ARM_V7EM = 0x10, /* Not meant to be run under xnu */ // ((cpu_subtype_t)16)
/*line: 334*/   CPU_SUBTYPE_ARM_V8M = 0x11, /* Not meant to be run under xnu */ // ((cpu_subtype_t)17)
};

// Depends on identifiers
enum macro_arm64_subtype {
/*
 *  ARM64 subtypes
 */
/*line: 339*/   CPU_SUBTYPE_ARM64_ALL = 0x0,  // ((cpu_subtype_t)0)
/*line: 340*/   CPU_SUBTYPE_ARM64_V8 = 0x1,  // ((cpu_subtype_t)1)
/*line: 341*/   CPU_SUBTYPE_ARM64E = 0x2,  // ((cpu_subtype_t)2)
};

enum macro_cpu_ptrauth_mask {
/* CPU subtype feature flags for ptrauth on arm64e platforms */
/*line: 344*/   CPU_SUBTYPE_ARM64_PTR_AUTH_MASK = 0xf000000,  // 0x0f000000
};

// Depends on identifiers
enum macro_arm64_32_subtype {
/*
 *  ARM64_32 subtypes
 */
/*line: 350*/   CPU_SUBTYPE_ARM64_32_ALL = 0x0,  // ((cpu_subtype_t)0)
/*line: 351*/   CPU_SUBTYPE_ARM64_32_V8 = 0x1,  // ((cpu_subtype_t)1)
};

enum macro_cpu_family {
/*
 *	CPU families (sysctl hw.cpufamily)
 *
 * These are meant to identify the CPU's marketing name - an
 * application can map these to (possibly) localized strings.
 * NB: the encodings of the CPU families are intentionally arbitrary.
 * There is no ordering, and you should never try to deduce whether
 * or not some feature is available based on the family.
 * Use feature flags (eg, hw.optional.altivec) to test for optional
 * functionality.
 */
/*line: 367*/   CPUFAMILY_UNKNOWN = 0x0,  // 0
/*line: 368*/   CPUFAMILY_POWERPC_G3 = 0xcee41549,  // 0xcee41549
/*line: 369*/   CPUFAMILY_POWERPC_G4 = 0x77c184ae,  // 0x77c184ae
/*line: 370*/   CPUFAMILY_POWERPC_G5 = 0xed76d8aa,  // 0xed76d8aa
/*line: 371*/   CPUFAMILY_INTEL_6_13 = 0xaa33392b,  // 0xaa33392b
/*line: 372*/   CPUFAMILY_INTEL_PENRYN = 0x78ea4fbc,  // 0x78ea4fbc
/*line: 373*/   CPUFAMILY_INTEL_NEHALEM = 0x6b5a4cd2,  // 0x6b5a4cd2
/*line: 374*/   CPUFAMILY_INTEL_WESTMERE = 0x573b5eec,  // 0x573b5eec
/*line: 375*/   CPUFAMILY_INTEL_SANDYBRIDGE = 0x5490b78c,  // 0x5490b78c
/*line: 376*/   CPUFAMILY_INTEL_IVYBRIDGE = 0x1f65e835,  // 0x1f65e835
/*line: 377*/   CPUFAMILY_INTEL_HASWELL = 0x10b282dc,  // 0x10b282dc
/*line: 378*/   CPUFAMILY_INTEL_BROADWELL = 0x582ed09c,  // 0x582ed09c
/*line: 379*/   CPUFAMILY_INTEL_SKYLAKE = 0x37fc219f,  // 0x37fc219f
/*line: 380*/   CPUFAMILY_INTEL_KABYLAKE = 0xf817246,  // 0x0f817246
/*line: 381*/   CPUFAMILY_INTEL_ICELAKE = 0x38435547,  // 0x38435547
/*line: 382*/   CPUFAMILY_INTEL_COMETLAKE = 0x1cf8a03e,  // 0x1cf8a03e
/*line: 383*/   CPUFAMILY_ARM_9 = 0xe73283ae,  // 0xe73283ae
/*line: 384*/   CPUFAMILY_ARM_11 = 0x8ff620d8,  // 0x8ff620d8
/*line: 385*/   CPUFAMILY_ARM_XSCALE = 0x53b005f5,  // 0x53b005f5
/*line: 386*/   CPUFAMILY_ARM_12 = 0xbd1b0ae9,  // 0xbd1b0ae9
/*line: 387*/   CPUFAMILY_ARM_13 = 0xcc90e64,  // 0x0cc90e64
/*line: 388*/   CPUFAMILY_ARM_14 = 0x96077ef1,  // 0x96077ef1
/*line: 389*/   CPUFAMILY_ARM_15 = 0xa8511bca,  // 0xa8511bca
/*line: 390*/   CPUFAMILY_ARM_SWIFT = 0x1e2d6381,  // 0x1e2d6381
/*line: 391*/   CPUFAMILY_ARM_CYCLONE = 0x37a09642,  // 0x37a09642
/*line: 392*/   CPUFAMILY_ARM_TYPHOON = 0x2c91a47e,  // 0x2c91a47e
/*line: 393*/   CPUFAMILY_ARM_TWISTER = 0x92fb37c8,  // 0x92fb37c8
/*line: 394*/   CPUFAMILY_ARM_HURRICANE = 0x67ceee93,  // 0x67ceee93
/*line: 395*/   CPUFAMILY_ARM_MONSOON_MISTRAL = 0xe81e7ef6,  // 0xe81e7ef6
/*line: 396*/   CPUFAMILY_ARM_VORTEX_TEMPEST = 0x7d34b9f,  // 0x07d34b9f
/*line: 397*/   CPUFAMILY_ARM_LIGHTNING_THUNDER = 0x462504d2,  // 0x462504d2
/*line: 398*/   CPUFAMILY_ARM_FIRESTORM_ICESTORM = 0x1b588bb3,  // 0x1b588bb3
/*line: 399*/   CPUFAMILY_ARM_BLIZZARD_AVALANCHE = 0xda33d83d,  // 0xda33d83d
/*line: 400*/   CPUFAMILY_ARM_EVEREST_SAWTOOTH = 0x8765edea,  // 0x8765edea
/*line: 401*/   CPUFAMILY_ARM_IBIZA = 0xfa33415e,  // 0xfa33415e
/*line: 402*/   CPUFAMILY_ARM_PALMA = 0x72015832,  // 0x72015832
/*line: 403*/   CPUFAMILY_ARM_COLL = 0x2876f5b5,  // 0x2876f5b5
/*line: 404*/   CPUFAMILY_ARM_LOBOS = 0x5f4dea93,  // 0x5f4dea93
/*line: 405*/   CPUFAMILY_ARM_DONAN = 0x6f5129ac,  // 0x6f5129ac
/*line: 406*/   CPUFAMILY_ARM_BRAVA = 0x17d5b93a,  // 0x17d5b93a
/*line: 407*/   CPUFAMILY_ARM_TAHITI = 0x75d4acb9,  // 0x75d4acb9
/*line: 408*/   CPUFAMILY_ARM_TUPAI = 0x204526d0,  // 0x204526d0
/* The following synonyms are deprecated: */
/*line: 420*/   CPUFAMILY_INTEL_6_23 = 0x78ea4fbc,  // CPUFAMILY_INTEL_PENRYN
/*line: 421*/   CPUFAMILY_INTEL_6_26 = 0x6b5a4cd2,  // CPUFAMILY_INTEL_NEHALEM
};

enum macro_cpu_subfamily {
/* Described in rdar://64125549 */
/*line: 411*/   CPUSUBFAMILY_UNKNOWN = 0x0,  // 0
/*line: 412*/   CPUSUBFAMILY_ARM_HP = 0x1,  // 1
/*line: 413*/   CPUSUBFAMILY_ARM_HG = 0x2,  // 2
/*line: 414*/   CPUSUBFAMILY_ARM_M = 0x3,  // 3
/*line: 415*/   CPUSUBFAMILY_ARM_HS = 0x4,  // 4
/*line: 416*/   CPUSUBFAMILY_ARM_HC_HD = 0x5,  // 5
/*line: 417*/   CPUSUBFAMILY_ARM_HA = 0x6,  // 6
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 215
// #define CPU_SUBTYPE_I386_ALL CPU_SUBTYPE_INTEL(3, 0)

// Line: 216
// #define CPU_SUBTYPE_386 CPU_SUBTYPE_INTEL(3, 0)

// Line: 217
// #define CPU_SUBTYPE_486 CPU_SUBTYPE_INTEL(4, 0)

// Line: 218
// #define CPU_SUBTYPE_486SX CPU_SUBTYPE_INTEL(4, 8)

// Line: 219
// #define CPU_SUBTYPE_586 CPU_SUBTYPE_INTEL(5, 0)

// Line: 220
// #define CPU_SUBTYPE_PENT CPU_SUBTYPE_INTEL(5, 0)

// Line: 221
// #define CPU_SUBTYPE_PENTPRO CPU_SUBTYPE_INTEL(6, 1)

// Line: 222
// #define CPU_SUBTYPE_PENTII_M3 CPU_SUBTYPE_INTEL(6, 3)

// Line: 223
// #define CPU_SUBTYPE_PENTII_M5 CPU_SUBTYPE_INTEL(6, 5)

// Line: 224
// #define CPU_SUBTYPE_CELERON CPU_SUBTYPE_INTEL(7, 6)

// Line: 225
// #define CPU_SUBTYPE_CELERON_MOBILE CPU_SUBTYPE_INTEL(7, 7)

// Line: 226
// #define CPU_SUBTYPE_PENTIUM_3 CPU_SUBTYPE_INTEL(8, 0)

// Line: 227
// #define CPU_SUBTYPE_PENTIUM_3_M CPU_SUBTYPE_INTEL(8, 1)

// Line: 228
// #define CPU_SUBTYPE_PENTIUM_3_XEON CPU_SUBTYPE_INTEL(8, 2)

// Line: 229
// #define CPU_SUBTYPE_PENTIUM_M CPU_SUBTYPE_INTEL(9, 0)

// Line: 230
// #define CPU_SUBTYPE_PENTIUM_4 CPU_SUBTYPE_INTEL(10, 0)

// Line: 231
// #define CPU_SUBTYPE_PENTIUM_4_M CPU_SUBTYPE_INTEL(10, 1)

// Line: 232
// #define CPU_SUBTYPE_ITANIUM CPU_SUBTYPE_INTEL(11, 0)

// Line: 233
// #define CPU_SUBTYPE_ITANIUM_2 CPU_SUBTYPE_INTEL(11, 1)

// Line: 234
// #define CPU_SUBTYPE_XEON CPU_SUBTYPE_INTEL(12, 0)

// Line: 235
// #define CPU_SUBTYPE_XEON_MP CPU_SUBTYPE_INTEL(12, 1)

