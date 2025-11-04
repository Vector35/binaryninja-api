// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach-o/loader.h

enum macro_mach_magic {
/* Constant for the magic field of the mach_header (32-bit architectures) */
/*line: 73*/    MH_MAGIC = 0xfeedface, /* the mach magic number */ // 0xfeedface
/*line: 74*/    MH_CIGAM = 0xcefaedfe, /* NXSwapInt(MH_MAGIC) */ // 0xcefaedfe
/* Constant for the magic field of the mach_header_64 (64-bit architectures) */
/*line: 92*/    MH_MAGIC_64 = 0xfeedfacf, /* the 64-bit mach magic number */ // 0xfeedfacf
/*line: 93*/    MH_CIGAM_64 = 0xcffaedfe, /* NXSwapInt(MH_MAGIC_64) */ // 0xcffaedfe
};

enum macro_mach_filetype {
/*
 * The layout of the file depends on the filetype.  For all but the MH_OBJECT
 * file type the segments are padded out and aligned on a segment alignment
 * boundary for efficient demand pageing.  The MH_EXECUTE, MH_FVMLIB, MH_DYLIB,
 * MH_DYLINKER and MH_BUNDLE file types also have the headers included as part
 * of their first segment.
 * 
 * The file type MH_OBJECT is a compact format intended as output of the
 * assembler and input (and possibly output) of the link editor (the .o
 * format).  All sections are in one unnamed segment with no segment padding. 
 * This format is used as an executable format when the file is so small the
 * segment padding greatly increases its size.
 *
 * The file type MH_PRELOAD is an executable format intended for things that
 * are not executed under the kernel (proms, stand alones, kernels, etc).  The
 * format can be executed under the kernel but may demand paged it and not
 * preload it before execution.
 *
 * A core file is in MH_CORE format and can be any in an arbritray legal
 * Mach-O file.
 *
 * Constants for the filetype field of the mach_header
 */
/*line: 118*/   MH_OBJECT = 0x1, /* relocatable object file */ // 0x1
/*line: 119*/   MH_EXECUTE = 0x2, /* demand paged executable file */ // 0x2
/*line: 120*/   MH_FVMLIB = 0x3, /* fixed VM shared library file */ // 0x3
/*line: 121*/   MH_CORE = 0x4, /* core file */ // 0x4
/*line: 122*/   MH_PRELOAD = 0x5, /* preloaded executable file */ // 0x5
/*line: 123*/   MH_DYLIB = 0x6, /* dynamically bound shared library */ // 0x6
/*line: 124*/   MH_DYLINKER = 0x7, /* dynamic link editor */ // 0x7
/*line: 125*/   MH_BUNDLE = 0x8, /* dynamically bound bundle file */ // 0x8
/*line: 126*/   MH_DYLIB_STUB = 0x9, /* shared library stub for static
					   linking only, no section contents */ // 0x9
/*line: 128*/   MH_DSYM = 0xa, /* companion file with only debug
					   sections */ // 0xa
/*line: 130*/   MH_KEXT_BUNDLE = 0xb, /* x86_64 kexts */ // 0xb
/*line: 131*/   MH_FILESET = 0xc, /* a file composed of other Mach-Os to
					   be run in the same userspace sharing
					   a single linkedit. */ // 0xc
/*line: 134*/   MH_GPU_EXECUTE = 0xd, /* gpu program */ // 0xd
/*line: 135*/   MH_GPU_DYLIB = 0xe, /* gpu support functions */ // 0xe
};

enum macro_mach_header_flags {
/* Constants for the flags field of the mach_header */
/*line: 139*/   MH_NOUNDEFS = 0x1, /* the object file has no undefined
					   references */ // 0x1
/*line: 141*/   MH_INCRLINK = 0x2, /* the object file is the output of an
					   incremental link against a base file
					   and can't be link edited again */ // 0x2
/*line: 144*/   MH_DYLDLINK = 0x4, /* the object file is input for the
					   dynamic linker and can't be staticly
					   link edited again */ // 0x4
/*line: 147*/   MH_BINDATLOAD = 0x8, /* the object file's undefined
					   references are bound by the dynamic
					   linker when loaded. */ // 0x8
/*line: 150*/   MH_PREBOUND = 0x10, /* the file has its dynamic undefined
					   references prebound. */ // 0x10
/*line: 152*/   MH_SPLIT_SEGS = 0x20, /* the file has its read-only and
					   read-write segments split */ // 0x20
/*line: 154*/   MH_LAZY_INIT = 0x40, /* the shared library init routine is
					   to be run lazily via catching memory
					   faults to its writeable segments
					   (obsolete) */ // 0x40
/*line: 158*/   MH_TWOLEVEL = 0x80, /* the image is using two-level name
					   space bindings */ // 0x80
/*line: 160*/   MH_FORCE_FLAT = 0x100, /* the executable is forcing all images
					   to use flat name space bindings */ // 0x100
/*line: 162*/   MH_NOMULTIDEFS = 0x200, /* this umbrella guarantees no multiple
					   defintions of symbols in its
					   sub-images so the two-level namespace
					   hints can always be used. */ // 0x200
/*line: 166*/   MH_NOFIXPREBINDING = 0x400, /* do not have dyld notify the
					   prebinding agent about this
					   executable */ // 0x400
/*line: 169*/   MH_PREBINDABLE = 0x800, /* the binary is not prebound but can
					   have its prebinding redone. only used
                                           when MH_PREBOUND is not set. */ // 0x800
/*line: 172*/   MH_ALLMODSBOUND = 0x1000, /* indicates that this binary binds to
                                           all two-level namespace modules of
					   its dependent libraries. only used
					   when MH_PREBINDABLE and MH_TWOLEVEL
					   are both set. */ // 0x1000
/*line: 177*/   MH_SUBSECTIONS_VIA_SYMBOLS = 0x2000,  // 0x2000
/*line: 180*/   MH_CANONICAL = 0x4000, /* the binary has been canonicalized
					   via the unprebind operation */ // 0x4000
/*line: 182*/   MH_WEAK_DEFINES = 0x8000, /* the final linked image contains
					   external weak symbols */ // 0x8000
/*line: 184*/   MH_BINDS_TO_WEAK = 0x10000, /* the final linked image uses
					   weak symbols */ // 0x10000
/*line: 187*/   MH_ALLOW_STACK_EXECUTION = 0x20000,  // 0x20000
/*line: 191*/   MH_ROOT_SAFE = 0x40000, /* When this bit is set, the binary 
					  declares it is safe for use in
					  processes with uid zero */ // 0x40000
/*line: 195*/   MH_SETUID_SAFE = 0x80000, /* When this bit is set, the binary 
					  declares it is safe for use in
					  processes when issetugid() is true */ // 0x80000
/*line: 199*/   MH_NO_REEXPORTED_DYLIBS = 0x100000, /* When this bit is set on a dylib, 
					  the static linker does not need to
					  examine dependent dylibs to see
					  if any are re-exported */ // 0x100000
/*line: 203*/   MH_PIE = 0x200000, /* When this bit is set, the OS will
					   load the main executable at a
					   random address.  Only used in
					   MH_EXECUTE filetypes. */ // 0x200000
/*line: 207*/   MH_DEAD_STRIPPABLE_DYLIB = 0x400000, /* Only for use on dylibs.  When
					     linking against a dylib that
					     has this bit set, the static linker
					     will automatically not create a
					     LC_LOAD_DYLIB load command to the
					     dylib if no symbols are being
					     referenced from the dylib. */ // 0x400000
/*line: 214*/   MH_HAS_TLV_DESCRIPTORS = 0x800000, /* Contains a section of type 
					    S_THREAD_LOCAL_VARIABLES */ // 0x800000
/*line: 217*/   MH_NO_HEAP_EXECUTION = 0x1000000, /* When this bit is set, the OS will
					   run the main executable with
					   a non-executable heap even on
					   platforms (e.g. i386) that don't
					   require it. Only used in MH_EXECUTE
					   filetypes. */ // 0x1000000
/*line: 224*/   MH_APP_EXTENSION_SAFE = 0x2000000, /* The code was linked for use in an
					    application extension. */ // 0x02000000
/*line: 227*/   MH_NLIST_OUTOFSYNC_WITH_DYLDINFO = 0x4000000, /* The external symbols
					   listed in the nlist symbol table do
					   not include all the symbols listed in
					   the dyld info. */ // 0x04000000
/*line: 232*/   MH_SIM_SUPPORT = 0x8000000, /* Allow LC_MIN_VERSION_MACOS and
					   LC_BUILD_VERSION load commands with
					   the platforms macOS, macCatalyst,
					   iOSSimulator, tvOSSimulator and
					   watchOSSimulator. */ // 0x08000000
/*line: 238*/   MH_IMPLICIT_PAGEZERO = 0x10000000, /* main executable has no __PAGEZERO
					   segment.  Instead, loader (xnu)
					   will load program high and block
					   out all memory below it. */ // 0x10000000
/*line: 243*/   MH_DYLIB_IN_CACHE = 0x80000000, /* Only for use on dylibs. When this bit
					   is set, the dylib is part of the dyld
					   shared cache, rather than loose in
					   the filesystem. */ // 0x80000000
};

enum macro_required_dyld {
/*
 * After MacOS X 10.1 when a new load command is added that is required to be
 * understood by the dynamic linker for the image to execute properly the
 * LC_REQ_DYLD bit will be or'ed into the load command constant.  If the dynamic
 * linker sees such a load command it it does not understand will issue a
 * "unknown load command required for execution" error and refuse to use the
 * image.  Other load commands without this bit that are not understood will
 * simply be ignored.
 */
/*line: 279*/   LC_REQ_DYLD = 0x80000000,  // 0x80000000
};

enum macro_load_command {
/* Constants for the cmd field of all load commands, the type */
/*line: 282*/   LC_SEGMENT = 0x1, /* segment of this file to be mapped */ // 0x1
/*line: 283*/   LC_SYMTAB = 0x2, /* link-edit stab symbol table info */ // 0x2
/*line: 284*/   LC_SYMSEG = 0x3, /* link-edit gdb symbol table info (obsolete) */ // 0x3
/*line: 285*/   LC_THREAD = 0x4, /* thread */ // 0x4
/*line: 286*/   LC_UNIXTHREAD = 0x5, /* unix thread (includes a stack) */ // 0x5
/*line: 287*/   LC_LOADFVMLIB = 0x6, /* load a specified fixed VM shared library */ // 0x6
/*line: 288*/   LC_IDFVMLIB = 0x7, /* fixed VM shared library identification */ // 0x7
/*line: 289*/   LC_IDENT = 0x8, /* object identification info (obsolete) */ // 0x8
/*line: 290*/   LC_FVMFILE = 0x9, /* fixed VM file inclusion (internal use) */ // 0x9
/*line: 291*/   LC_PREPAGE = 0xa, /* prepage command (internal use) */ // 0xa
/*line: 292*/   LC_DYSYMTAB = 0xb, /* dynamic link-edit symbol table info */ // 0xb
/*line: 293*/   LC_LOAD_DYLIB = 0xc, /* load a dynamically linked shared library */ // 0xc
/*line: 294*/   LC_ID_DYLIB = 0xd, /* dynamically linked shared lib ident */ // 0xd
/*line: 295*/   LC_LOAD_DYLINKER = 0xe, /* load a dynamic linker */ // 0xe
/*line: 296*/   LC_ID_DYLINKER = 0xf, /* dynamic linker identification */ // 0xf
/*line: 297*/   LC_PREBOUND_DYLIB = 0x10, /* modules prebound for a dynamically */ // 0x10
/*  linked shared library */
/*line: 299*/   LC_ROUTINES = 0x11, /* image routines */ // 0x11
/*line: 300*/   LC_SUB_FRAMEWORK = 0x12, /* sub framework */ // 0x12
/*line: 301*/   LC_SUB_UMBRELLA = 0x13, /* sub umbrella */ // 0x13
/*line: 302*/   LC_SUB_CLIENT = 0x14, /* sub client */ // 0x14
/*line: 303*/   LC_SUB_LIBRARY = 0x15, /* sub library */ // 0x15
/*line: 304*/   LC_TWOLEVEL_HINTS = 0x16, /* two-level namespace lookup hints */ // 0x16
/*line: 305*/   LC_PREBIND_CKSUM = 0x17, /* prebind checksum */ // 0x17
};

// Depends on identifiers
enum macro_load_weak_dylib {
/*
 * load a dynamically linked shared library that is allowed to be missing
 * (all symbols are weak imported).
 */
/*line: 311*/   LC_LOAD_WEAK_DYLIB = 0x80000018,  // (0x18|LC_REQ_DYLD)
};

// Depends on identifiers
enum macro_load_commands {
/*line: 313*/   LC_SEGMENT_64 = 0x19, /* 64-bit segment of this file to be
				   mapped */ // 0x19
/*line: 315*/   LC_ROUTINES_64 = 0x1a, /* 64-bit image routines */ // 0x1a
/*line: 316*/   LC_UUID = 0x1b, /* the uuid */ // 0x1b
/*line: 317*/   LC_RPATH = 0x8000001c, /* runpath additions */ // (0x1c|LC_REQ_DYLD)
/*line: 318*/   LC_CODE_SIGNATURE = 0x1d, /* local of code signature */ // 0x1d
/*line: 319*/   LC_SEGMENT_SPLIT_INFO = 0x1e, /* local of info to split segments */ // 0x1e
/*line: 320*/   LC_REEXPORT_DYLIB = 0x8000001f, /* load and re-export dylib */ // (0x1f|LC_REQ_DYLD)
/*line: 321*/   LC_LAZY_LOAD_DYLIB = 0x20, /* delay load of dylib until first use */ // 0x20
/*line: 322*/   LC_ENCRYPTION_INFO = 0x21, /* encrypted segment information */ // 0x21
/*line: 323*/   LC_DYLD_INFO = 0x22, /* compressed dyld information */ // 0x22
/*line: 324*/   LC_DYLD_INFO_ONLY = 0x80000022, /* compressed dyld information only */ // (0x22|LC_REQ_DYLD)
/*line: 325*/   LC_LOAD_UPWARD_DYLIB = 0x80000023, /* load upward dylib */ // (0x23|LC_REQ_DYLD)
/*line: 326*/   LC_VERSION_MIN_MACOSX = 0x24, /* build for MacOSX min OS version */ // 0x24
/*line: 327*/   LC_VERSION_MIN_IPHONEOS = 0x25, /* build for iPhoneOS min OS version */ // 0x25
/*line: 328*/   LC_FUNCTION_STARTS = 0x26, /* compressed table of function start addresses */ // 0x26
/*line: 329*/   LC_DYLD_ENVIRONMENT = 0x27, /* string for dyld to treat
				    like environment variable */ // 0x27
/*line: 331*/   LC_MAIN = 0x80000028, /* replacement for LC_UNIXTHREAD */ // (0x28|LC_REQ_DYLD)
/*line: 332*/   LC_DATA_IN_CODE = 0x29, /* table of non-instructions in __text */ // 0x29
/*line: 333*/   LC_SOURCE_VERSION = 0x2a, /* source version used to build binary */ // 0x2A
/*line: 334*/   LC_DYLIB_CODE_SIGN_DRS = 0x2b, /* Code signing DRs copied from linked dylibs */ // 0x2B
/*line: 335*/   LC_ENCRYPTION_INFO_64 = 0x2c, /* 64-bit encrypted segment information */ // 0x2C
/*line: 336*/   LC_LINKER_OPTION = 0x2d, /* linker options in MH_OBJECT files */ // 0x2D
/*line: 337*/   LC_LINKER_OPTIMIZATION_HINT = 0x2e, /* optimization hints in MH_OBJECT files */ // 0x2E
/*line: 338*/   LC_VERSION_MIN_TVOS = 0x2f, /* build for AppleTV min OS version */ // 0x2F
/*line: 339*/   LC_VERSION_MIN_WATCHOS = 0x30, /* build for Watch min OS version */ // 0x30
/*line: 340*/   LC_NOTE = 0x31, /* arbitrary data included within a Mach-O file */ // 0x31
/*line: 341*/   LC_BUILD_VERSION = 0x32, /* build for platform min OS version */ // 0x32
/*line: 342*/   LC_DYLD_EXPORTS_TRIE = 0x80000033, /* used with linkedit_data_command, payload is trie */ // (0x33|LC_REQ_DYLD)
/*line: 343*/   LC_DYLD_CHAINED_FIXUPS = 0x80000034, /* used with linkedit_data_command */ // (0x34|LC_REQ_DYLD)
/*line: 344*/   LC_FILESET_ENTRY = 0x80000035, /* used with fileset_entry_command */ // (0x35|LC_REQ_DYLD)
/*line: 345*/   LC_ATOM_INFO = 0x36, /* used with linkedit_data_command */ // 0x36
/*line: 346*/   LC_FUNCTION_VARIANTS = 0x37, /* used with linkedit_data_command */ // 0x37
/*line: 347*/   LC_FUNCTION_VARIANT_FIXUPS = 0x38, /* used with linkedit_data_command */ // 0x38
/*line: 348*/   LC_TARGET_TRIPLE = 0x39, /* target triple used to compile */ // 0x39
};

enum macro_segment_flags {
/* Constants for the flags field of the segment_command */
/*line: 414*/   SG_HIGHVM = 0x1, /* the file contents for this segment is for
				   the high part of the VM space, the low part
				   is zero filled (for stacks in core files) */ // 0x1
/*line: 417*/   SG_FVMLIB = 0x2, /* this segment is the VM that is allocated by
				   a fixed VM library, for overlap checking in
				   the link editor */ // 0x2
/*line: 420*/   SG_NORELOC = 0x4, /* this segment has nothing that was relocated
				   in it and nothing relocated to it, that is
				   it maybe safely replaced without relocation*/ // 0x4
/*line: 423*/   SG_PROTECTED_VERSION_1 = 0x8, /* This segment is protected.  If the
				       segment starts at file offset 0, the
				       first page of the segment is not
				       protected.  All other pages of the
				       segment are protected. */ // 0x8
/*line: 428*/   SG_READ_ONLY = 0x10, /* This segment is made read-only after fixups */ // 0x10
};

enum macro_section_flags {
/*
 * The flags field of a section structure is separated into two parts a section
 * type and section attributes.  The section types are mutually exclusive (it
 * can only have one type) but the section attributes are not (it may have more
 * than one attribute).
 */
/*line: 494*/   SECTION_TYPE = 0xff, /* 256 section types */ // 0x000000ff
/*line: 495*/   SECTION_ATTRIBUTES = 0xffffff00, /*  24 section attributes */ // 0xffffff00
};

enum macro_section_types {
/* Constants for the type of a section */
/*line: 498*/   S_REGULAR = 0x0, /* regular section */ // 0x0
/*line: 499*/   S_ZEROFILL = 0x1, /* zero fill on demand section */ // 0x1
/*line: 500*/   S_CSTRING_LITERALS = 0x2, /* section with only literal C strings*/ // 0x2
/*line: 501*/   S_4BYTE_LITERALS = 0x3, /* section with only 4 byte literals */ // 0x3
/*line: 502*/   S_8BYTE_LITERALS = 0x4, /* section with only 8 byte literals */ // 0x4
/*line: 503*/   S_LITERAL_POINTERS = 0x5, /* section with only pointers to */ // 0x5
/*
 * For the two types of symbol pointers sections and the symbol stubs section
 * they have indirect symbol table entries.  For each of the entries in the
 * section the indirect symbol table entries, in corresponding order in the
 * indirect symbol table, start at the index stored in the reserved1 field
 * of the section structure.  Since the indirect symbol table entries
 * correspond to the entries in the section the number of indirect symbol table
 * entries is inferred from the size of the section divided by the size of the
 * entries in the section.  For symbol pointers sections the size of the entries
 * in the section is 4 bytes and for symbol stubs sections the byte size of the
 * stubs is stored in the reserved2 field of the section structure.
 */
/*line: 517*/   S_NON_LAZY_SYMBOL_POINTERS = 0x6, /* section with only non-lazy
						   symbol pointers */ // 0x6
/*line: 519*/   S_LAZY_SYMBOL_POINTERS = 0x7, /* section with only lazy symbol
						   pointers */ // 0x7
/*line: 521*/   S_SYMBOL_STUBS = 0x8, /* section with only symbol
						   stubs, byte size of stub in
						   the reserved2 field */ // 0x8
/*line: 524*/   S_MOD_INIT_FUNC_POINTERS = 0x9, /* section with only function
						   pointers for initialization*/ // 0x9
/*line: 526*/   S_MOD_TERM_FUNC_POINTERS = 0xa, /* section with only function
						   pointers for termination */ // 0xa
/*line: 528*/   S_COALESCED = 0xb, /* section contains symbols that
						   are to be coalesced */ // 0xb
/*line: 530*/   S_GB_ZEROFILL = 0xc, /* zero fill on demand section
						   (that can be larger than 4
						   gigabytes) */ // 0xc
/*line: 533*/   S_INTERPOSING = 0xd, /* section with only pairs of
						   function pointers for
						   interposing */ // 0xd
/*line: 536*/   S_16BYTE_LITERALS = 0xe, /* section with only 16 byte
						   literals */ // 0xe
/*line: 538*/   S_DTRACE_DOF = 0xf, /* section contains 
						   DTrace Object Format */ // 0xf
/*line: 540*/   S_LAZY_DYLIB_SYMBOL_POINTERS = 0x10, /* section with only lazy
						   symbol pointers to lazy
						   loaded dylibs */ // 0x10
/*
 * Section types to support thread local variables
 */
/*line: 546*/   S_THREAD_LOCAL_REGULAR = 0x11, /* template of initial 
							  values for TLVs */ // 0x11
/*line: 548*/   S_THREAD_LOCAL_ZEROFILL = 0x12, /* template of initial 
							  values for TLVs */ // 0x12
/*line: 550*/   S_THREAD_LOCAL_VARIABLES = 0x13, /* TLV descriptors */ // 0x13
/*line: 551*/   S_THREAD_LOCAL_VARIABLE_POINTERS = 0x14, /* pointers to TLV 
                                                          descriptors */ // 0x14
/*line: 553*/   S_THREAD_LOCAL_INIT_FUNCTION_POINTERS = 0x15, /* functions to call
							  to initialize TLV
							  values */ // 0x15
/*line: 556*/   S_INIT_FUNC_OFFSETS = 0x16, /* 32-bit offsets to
							  initializers */ // 0x16
/*
 * Constants for the section attributes part of the flags field of a section
 * structure.
 */
/*line: 563*/   SECTION_ATTRIBUTES_USR = 0xff000000, /* User setable attributes */ // 0xff000000
/*line: 564*/   S_ATTR_PURE_INSTRUCTIONS = 0x80000000, /* section contains only true
						   machine instructions */ // 0x80000000
/*line: 566*/   S_ATTR_NO_TOC = 0x40000000, /* section contains coalesced
						   symbols that are not to be
						   in a ranlib table of
						   contents */ // 0x40000000
/*line: 570*/   S_ATTR_STRIP_STATIC_SYMS = 0x20000000, /* ok to strip static symbols
						   in this section in files
						   with the MH_DYLDLINK flag */ // 0x20000000
/*line: 573*/   S_ATTR_NO_DEAD_STRIP = 0x10000000, /* no dead stripping */ // 0x10000000
/*line: 574*/   S_ATTR_LIVE_SUPPORT = 0x8000000, /* blocks are live if they
						   reference live blocks */ // 0x08000000
/*line: 576*/   S_ATTR_SELF_MODIFYING_CODE = 0x4000000, /* Used with i386 code stubs
						   written on by dyld */ // 0x04000000
/*
 * If a segment contains any sections marked with S_ATTR_DEBUG then all
 * sections in that segment must have this attribute.  No section other than
 * a section marked with this attribute may reference the contents of this
 * section.  A section with this attribute may contain no symbols and must have
 * a section type S_REGULAR.  The static linker will not copy section contents
 * from sections with this attribute into its output file.  These sections
 * generally contain DWARF debugging info.
 */
/*line: 587*/   S_ATTR_DEBUG = 0x2000000, /* a debug section */ // 0x02000000
/*line: 588*/   SECTION_ATTRIBUTES_SYS = 0xffff00, /* system setable attributes */ // 0x00ffff00
/*line: 589*/   S_ATTR_SOME_INSTRUCTIONS = 0x400, /* section contains some
						   machine instructions */ // 0x00000400
/*line: 591*/   S_ATTR_EXT_RELOC = 0x200, /* section has external
						   relocation entries */ // 0x00000200
/*line: 593*/   S_ATTR_LOC_RELOC = 0x100, /* section has local
						   relocation entries */ // 0x00000100
};

enum macro_dylib_flags {
/*line: 727*/   DYLIB_USE_WEAK_LINK = 0x1,  // 0x01
/*line: 728*/   DYLIB_USE_REEXPORT = 0x2,  // 0x02
/*line: 729*/   DYLIB_USE_UPWARD = 0x4,  // 0x04
/*line: 730*/   DYLIB_USE_DELAYED_INIT = 0x8,  // 0x08
};

enum macro_dylib_use_marker {
/*line: 732*/   DYLIB_USE_MARKER = 0x1a741800,  // 0x1a741800
};

enum macro_indirect_symbol_flags {
/*
 * An indirect symbol table entry is simply a 32bit index into the symbol table 
 * to the symbol that the pointer or stub is refering to.  Unless it is for a
 * non-lazy symbol pointer section for a defined symbol which strip(1) as 
 * removed.  In which case it has the value INDIRECT_SYMBOL_LOCAL.  If the
 * symbol was also absolute INDIRECT_SYMBOL_ABS is or'ed with that.
 */
/*line: 1085*/  INDIRECT_SYMBOL_LOCAL = 0x80000000,  // 0x80000000
/*line: 1086*/  INDIRECT_SYMBOL_ABS = 0x40000000,  // 0x40000000
};

enum macro_platform_type {
/* Known values for the platform field above. */
/*line: 1323*/  PLATFORM_UNKNOWN = 0x0,  // 0
/*line: 1324*/  PLATFORM_ANY = 0xffffffff,  // 0xFFFFFFFF
/*line: 1325*/  PLATFORM_MACOS = 0x1,  // 1
/*line: 1326*/  PLATFORM_IOS = 0x2,  // 2
/*line: 1327*/  PLATFORM_TVOS = 0x3,  // 3
/*line: 1328*/  PLATFORM_WATCHOS = 0x4,  // 4
/*line: 1329*/  PLATFORM_BRIDGEOS = 0x5,  // 5
/*line: 1330*/  PLATFORM_MACCATALYST = 0x6,  // 6
/*line: 1331*/  PLATFORM_IOSSIMULATOR = 0x7,  // 7
/*line: 1332*/  PLATFORM_TVOSSIMULATOR = 0x8,  // 8
/*line: 1333*/  PLATFORM_WATCHOSSIMULATOR = 0x9,  // 9
/*line: 1334*/  PLATFORM_DRIVERKIT = 0xa,  // 10
/*line: 1335*/  PLATFORM_VISIONOS = 0xb,  // 11
/*line: 1336*/  PLATFORM_VISIONOSSIMULATOR = 0xc,  // 12
/*line: 1338*/  PLATFORM_FIRMWARE = 0xd,  // 13
/*line: 1339*/  PLATFORM_SEPOS = 0xe,  // 14
/*line: 1341*/  PLATFORM_MACOS_EXCLAVECORE = 0xf,  // 15
/*line: 1342*/  PLATFORM_MACOS_EXCLAVEKIT = 0x10,  // 16
/*line: 1343*/  PLATFORM_IOS_EXCLAVECORE = 0x11,  // 17
/*line: 1344*/  PLATFORM_IOS_EXCLAVEKIT = 0x12,  // 18
/*line: 1345*/  PLATFORM_TVOS_EXCLAVECORE = 0x13,  // 19
/*line: 1346*/  PLATFORM_TVOS_EXCLAVEKIT = 0x14,  // 20
/*line: 1347*/  PLATFORM_WATCHOS_EXCLAVECORE = 0x15,  // 21
/*line: 1348*/  PLATFORM_WATCHOS_EXCLAVEKIT = 0x16,  // 22
/*line: 1349*/  PLATFORM_VISIONOS_EXCLAVECORE = 0x17,  // 23
/*line: 1350*/  PLATFORM_VISIONOS_EXCLAVEKIT = 0x18,  // 24
};

enum macro_tool_type {
/* Known values for the tool field above. */
/*line: 1362*/  TOOL_CLANG = 0x1,  // 1
/*line: 1363*/  TOOL_SWIFT = 0x2,  // 2
/*line: 1364*/  TOOL_LD = 0x3,  // 3
/*line: 1365*/  TOOL_LLD = 0x4,  // 4
/* values for gpu tools (1024 to 1048) */
/*line: 1368*/  TOOL_METAL = 0x400,  // 1024
/*line: 1369*/  TOOL_AIRLLD = 0x401,  // 1025
/*line: 1370*/  TOOL_AIRNT = 0x402,  // 1026
/*line: 1371*/  TOOL_AIRNT_PLUGIN = 0x403,  // 1027
/*line: 1372*/  TOOL_AIRPACK = 0x404,  // 1028
/*line: 1373*/  TOOL_GPUARCHIVER = 0x407,  // 1031
/*line: 1374*/  TOOL_METAL_FRAMEWORK = 0x408,  // 1032
};

enum macro_rebase_info {
/*
 * The following are used to encode rebasing information
 */
/*line: 1491*/  REBASE_TYPE_POINTER = 0x1,  // 1
/*line: 1492*/  REBASE_TYPE_TEXT_ABSOLUTE32 = 0x2,  // 2
/*line: 1493*/  REBASE_TYPE_TEXT_PCREL32 = 0x3,  // 3
/*line: 1495*/  REBASE_OPCODE_MASK = 0xf0,  // 0xF0
/*line: 1496*/  REBASE_IMMEDIATE_MASK = 0xf,  // 0x0F
/*line: 1497*/  REBASE_OPCODE_DONE = 0x0,  // 0x00
/*line: 1498*/  REBASE_OPCODE_SET_TYPE_IMM = 0x10,  // 0x10
/*line: 1499*/  REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 0x20,  // 0x20
/*line: 1500*/  REBASE_OPCODE_ADD_ADDR_ULEB = 0x30,  // 0x30
/*line: 1501*/  REBASE_OPCODE_ADD_ADDR_IMM_SCALED = 0x40,  // 0x40
/*line: 1502*/  REBASE_OPCODE_DO_REBASE_IMM_TIMES = 0x50,  // 0x50
/*line: 1503*/  REBASE_OPCODE_DO_REBASE_ULEB_TIMES = 0x60,  // 0x60
/*line: 1504*/  REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB = 0x70,  // 0x70
/*line: 1505*/  REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB = 0x80,  // 0x80
};

enum macro_bind_type {
/*
 * The following are used to encode binding information
 */
/*line: 1511*/  BIND_TYPE_POINTER = 0x1,  // 1
/*line: 1512*/  BIND_TYPE_TEXT_ABSOLUTE32 = 0x2,  // 2
/*line: 1513*/  BIND_TYPE_TEXT_PCREL32 = 0x3,  // 3
};

enum macro_bind_opcodes {
/*line: 1515*/  BIND_SPECIAL_DYLIB_SELF = 0x0,  // 0
/*line: 1516*/  BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE = -0x1,  // -1
/*line: 1517*/  BIND_SPECIAL_DYLIB_FLAT_LOOKUP = -0x2,  // -2
/*line: 1518*/  BIND_SPECIAL_DYLIB_WEAK_LOOKUP = -0x3,  // -3
/*line: 1520*/  BIND_SYMBOL_FLAGS_WEAK_IMPORT = 0x1,  // 0x1
/*line: 1521*/  BIND_SYMBOL_FLAGS_NON_WEAK_DEFINITION = 0x8,  // 0x8
/*line: 1523*/  BIND_OPCODE_MASK = 0xf0,  // 0xF0
/*line: 1524*/  BIND_IMMEDIATE_MASK = 0xf,  // 0x0F
/*line: 1525*/  BIND_OPCODE_DONE = 0x0,  // 0x00
/*line: 1526*/  BIND_OPCODE_SET_DYLIB_ORDINAL_IMM = 0x10,  // 0x10
/*line: 1527*/  BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB = 0x20,  // 0x20
/*line: 1528*/  BIND_OPCODE_SET_DYLIB_SPECIAL_IMM = 0x30,  // 0x30
/*line: 1529*/  BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM = 0x40,  // 0x40
/*line: 1530*/  BIND_OPCODE_SET_TYPE_IMM = 0x50,  // 0x50
/*line: 1531*/  BIND_OPCODE_SET_ADDEND_SLEB = 0x60,  // 0x60
/*line: 1532*/  BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB = 0x70,  // 0x70
/*line: 1533*/  BIND_OPCODE_ADD_ADDR_ULEB = 0x80,  // 0x80
/*line: 1534*/  BIND_OPCODE_DO_BIND = 0x90,  // 0x90
/*line: 1535*/  BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB = 0xa0,  // 0xA0
/*line: 1536*/  BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED = 0xb0,  // 0xB0
/*line: 1537*/  BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB = 0xc0,  // 0xC0
/*line: 1538*/  BIND_OPCODE_THREADED = 0xd0,  // 0xD0
/*line: 1539*/  BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB = 0x0,  // 0x00
/*line: 1540*/  BIND_SUBOPCODE_THREADED_APPLY = 0x1,  // 0x01
};

enum macro_export_symbol_flags {
/*
 * The following are used on the flags byte of a terminal node
 * in the export information.
 */
/*line: 1547*/  EXPORT_SYMBOL_FLAGS_KIND_MASK = 0x3,  // 0x03
/*line: 1548*/  EXPORT_SYMBOL_FLAGS_KIND_REGULAR = 0x0,  // 0x00
/*line: 1549*/  EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL = 0x1,  // 0x01
/*line: 1550*/  EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE = 0x2,  // 0x02
/*line: 1551*/  EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION = 0x4,  // 0x04
/*line: 1552*/  EXPORT_SYMBOL_FLAGS_REEXPORT = 0x8,  // 0x08
/*line: 1553*/  EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER = 0x10,  // 0x10
/*line: 1554*/  EXPORT_SYMBOL_FLAGS_STATIC_RESOLVER = 0x20,  // 0x20
};

enum macro_dice_kind {
/*line: 1644*/  DICE_KIND_DATA = 0x1,  // 0x0001
/*line: 1645*/  DICE_KIND_JUMP_TABLE8 = 0x2,  // 0x0002
/*line: 1646*/  DICE_KIND_JUMP_TABLE16 = 0x3,  // 0x0003
/*line: 1647*/  DICE_KIND_JUMP_TABLE32 = 0x4,  // 0x0004
/*line: 1648*/  DICE_KIND_ABS_JUMP_TABLE32 = 0x5,  // 0x0005
};

