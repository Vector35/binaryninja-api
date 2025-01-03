#pragma once

#include <exception>
#include <vector>
#include <string.h>

#include "binaryninjaapi.h"
#include "objc.h"

//These are laready defined in one of the osx headers we want to override
#undef CPU_SUBTYPE_INTEL
#undef CPU_SUBTYPE_I386_ALL
#undef CPU_SUBTYPE_POWERPC_ALL
#undef LC_MAIN
#undef LC_SOURCE_VERSION
#undef LC_DYLIB_CODE_SIGN_DRS
#undef LC_DYLD_INFO_ONLY

#define MH_MAGIC     0xfeedface
#define MH_MAGIC_64  0xfeedfacf
#define MH_CIGAM     0xcefaedfe
#define MH_CIGAM_64  0xcffaedfe
#define FAT_MAGIC    0xcafebabe
#define FAT_MAGIC_64 0xcafebabf

typedef int32_t cpu_type_t;
typedef int32_t cpu_subtype_t;
typedef int vm_prot_t;

//Cpu types
#define MACHO_CPU_ARCH_ABI64           0x01000000
#define MACHO_CPU_ARCH_ABI64_32        0x02000000

#define MACHO_CPU_TYPE_ANY       ((cpu_type_t) -1)
#define MACHO_CPU_TYPE_VAX       ((cpu_type_t) 1)
#define MACHO_CPU_TYPE_MC680x0	((cpu_type_t) 6)
#define MACHO_CPU_TYPE_X86       ((cpu_type_t) 7)
#define MACHO_CPU_TYPE_X86_64    (MACHO_CPU_TYPE_X86 | MACHO_CPU_ARCH_ABI64)
#define MACHO_CPU_TYPE_MIPS      ((cpu_type_t) 8)
#define MACHO_CPU_TYPE_MC98000	((cpu_type_t) 10)
#define MACHO_CPU_TYPE_HPPA      ((cpu_type_t) 11)
#define MACHO_CPU_TYPE_ARM       ((cpu_type_t) 12)
#define MACHO_CPU_TYPE_ARM64     (MACHO_CPU_TYPE_ARM | MACHO_CPU_ARCH_ABI64)
#define MACHO_CPU_TYPE_ARM64_32  (MACHO_CPU_TYPE_ARM | MACHO_CPU_ARCH_ABI64_32)
#define MACHO_CPU_TYPE_MC88000   ((cpu_type_t) 13)
#define MACHO_CPU_TYPE_SPARC     ((cpu_type_t) 14)
#define MACHO_CPU_TYPE_I860      ((cpu_type_t) 15)
#define MACHO_CPU_TYPE_ALPHA     ((cpu_type_t) 16)
#define MACHO_CPU_TYPE_POWERPC   ((cpu_type_t) 18)
#define MACHO_CPU_TYPE_POWERPC64 (MACHO_CPU_TYPE_POWERPC | MACHO_CPU_ARCH_ABI64)

//Cpu subtype capability bits
#define MACHO_CPU_SUBTYPE_MASK         ((cpu_subtype_t)0xff000000)
#define MACHO_CPU_SUBTYPE_LIB64        ((cpu_subtype_t)0x80000000)

//Cpu subtypes
#define MACHO_CPU_SUBTYPE_INTEL(f,m)   ((cpu_subtype_t) (f)+((m)<<4))
#define MACHO_CPU_SUBTYPE_I386_ALL     MACHO_CPU_SUBTYPE_INTEL(3,0)
#define MACHO_CPU_SUBTYPE_X86_ALL      ((cpu_subtype_t) 3)
#define MACHO_CPU_SUBTYPE_X86_ARCH1    ((cpu_subtype_t) 4)
#define MACHO_CPU_SUBTYPE_X86_64_ALL   ((cpu_subtype_t) 3)
#define MACHO_CPU_SUBTYPE_X86_64_H     ((cpu_subtype_t) 8)

#define MACHO_CPU_SUBTYPE_ARM_ALL      ((cpu_subtype_t) 0)
#define MACHO_CPU_SUBTYPE_ARM_V4T      ((cpu_subtype_t) 5)
#define MACHO_CPU_SUBTYPE_ARM_V6       ((cpu_subtype_t) 6)
#define MACHO_CPU_SUBTYPE_ARM_V5TEJ    ((cpu_subtype_t) 7)
#define MACHO_CPU_SUBTYPE_ARM_XSCALE   ((cpu_subtype_t) 8)
#define MACHO_CPU_SUBTYPE_ARM_V7       ((cpu_subtype_t) 9)
#define MACHO_CPU_SUBTYPE_ARM_V7F      ((cpu_subtype_t) 10)
#define MACHO_CPU_SUBTYPE_ARM_V7S      ((cpu_subtype_t) 11)
#define MACHO_CPU_SUBTYPE_ARM_V7K      ((cpu_subtype_t) 12)
#define MACHO_CPU_SUBTYPE_ARM_V8       ((cpu_subtype_t) 13)
#define MACHO_CPU_SUBTYPE_ARM_V6M      ((cpu_subtype_t) 14)
#define MACHO_CPU_SUBTYPE_ARM_V7M      ((cpu_subtype_t) 15)
#define MACHO_CPU_SUBTYPE_ARM_V7EM     ((cpu_subtype_t) 16)

#define MACHO_CPU_SUBTYPE_ARM64_ALL    ((cpu_subtype_t) 0)
#define MACHO_CPU_SUBTYPE_ARM64_V8     ((cpu_subtype_t) 1)
#define MACHO_CPU_SUBTYPE_ARM64E       ((cpu_subtype_t) 2)

#define MACHO_CPU_SUBTYPE_ARM64_32_ALL ((cpu_subtype_t) 0)
#define MACHO_CPU_SUBTYPE_ARM64_32_V8  ((cpu_subtype_t) 1)

#define MACHO_CPU_SUBTYPE_POWERPC_ALL   ((cpu_subtype_t) 0)
#define MACHO_CPU_SUBTYPE_POWERPC_601   ((cpu_subtype_t) 1)
#define MACHO_CPU_SUBTYPE_POWERPC_602   ((cpu_subtype_t) 2)
#define MACHO_CPU_SUBTYPE_POWERPC_603   ((cpu_subtype_t) 3)
#define MACHO_CPU_SUBTYPE_POWERPC_603e  ((cpu_subtype_t) 4)
#define MACHO_CPU_SUBTYPE_POWERPC_603ev ((cpu_subtype_t) 5)
#define MACHO_CPU_SUBTYPE_POWERPC_604   ((cpu_subtype_t) 6)
#define MACHO_CPU_SUBTYPE_POWERPC_604e  ((cpu_subtype_t) 7)
#define MACHO_CPU_SUBTYPE_POWERPC_620   ((cpu_subtype_t) 8)
#define MACHO_CPU_SUBTYPE_POWERPC_750   ((cpu_subtype_t) 9)
#define MACHO_CPU_SUBTYPE_POWERPC_7400  ((cpu_subtype_t) 10)
#define MACHO_CPU_SUBTYPE_POWERPC_7450  ((cpu_subtype_t) 11)
#define MACHO_CPU_SUBTYPE_POWERPC_970   ((cpu_subtype_t) 100)

//Page protections
#define MACHO_VM_PROT_NONE             ((vm_prot_t) 0x00)
#define MACHO_VM_PROT_READ             ((vm_prot_t) 0x01)
#define MACHO_VM_PROT_WRITE            ((vm_prot_t) 0x02)
#define MACHO_VM_PROT_EXECUTE          ((vm_prot_t) 0x04)
#define MACHO_VM_PROT_DEFAULT          (VM_PROT_READ|VM_PROT_WRITE)
#define MACHO_VM_PROT_ALL              (VM_PROT_READ|VM_PROT_WRITE|VM_PROT_EXECUTE)
#define MACHO_VM_PROT_NO_CHANGE        ((vm_prot_t) 0x08)
#define MACHO_VM_PROT_COPY             ((vm_prot_t) 0x10)
#define MACHO_VM_PROT_WANTS_COPY       ((vm_prot_t) 0x10)

//Segment flags
#define SG_HIGHVM 0x1
#define SG_FVMLIB 0x2
#define SG_NORELOC 0x4
#define SG_PROTECTED_VERSION_1 0x8

//Section flags
#define S_ATTR_SOME_INSTRUCTIONS              0x00000400
#define S_ATTR_PURE_INSTRUCTIONS              0x80000000 // section contains only true machine instructions
#define S_ATTR_NO_TOC                         0x40000000 // section contains coalesced symbols that are not to be in a ranlib table of contents
#define S_ATTR_STRIP_STATIC_SYMS              0x20000000 // ok to strip static symbols in this section in files with the MH_DYLDLINK flag
#define S_ATTR_NO_DEAD_STRIP                  0x10000000 // no dead stripping
#define S_ATTR_LIVE_SUPPORT                   0x08000000 // blocks are live if they reference live blocks
#define S_ATTR_SELF_MODIFYING_CODE            0x04000000 // Used with i386 code stubs written on by dyld

#define S_REGULAR                             0x0
#define S_ZEROFILL                            0x1
#define S_CSTRING_LITERALS                    0x2
#define S_4BYTE_LITERALS                      0x3
#define S_8BYTE_LITERALS                      0x4
#define S_LITERAL_POINTERS                    0x5
#define S_NON_LAZY_SYMBOL_POINTERS            0x6
#define S_LAZY_SYMBOL_POINTERS                0x7
#define S_SYMBOL_STUBS                        0x8
#define S_MOD_INIT_FUNC_POINTERS              0x9
#define S_MOD_TERM_FUNC_POINTERS              0xa
#define S_COALESCED                           0xb
#define S_GB_ZEROFILL                         0xc
#define S_INTERPOSING                         0xd
#define S_16BYTE_LITERALS                     0xe
#define S_DTRACE_DOF                          0xf
#define S_LAZY_DYLIB_SYMBOL_POINTERS          0x10
#define S_THREAD_LOCAL_REGULAR                0x11
#define S_THREAD_LOCAL_ZEROFILL               0x12
#define S_THREAD_LOCAL_VARIABLES              0x13
#define S_THREAD_LOCAL_VARIABLE_POINTERS      0x14
#define S_THREAD_LOCAL_INIT_FUNCTION_POINTERS 0x15

//Mach-O Commands
#define LC_REQ_DYLD              0x80000000
#define LC_SEGMENT               0x1
#define LC_SYMTAB                0x2
#define LC_SYMSEG                0x3
#define LC_THREAD                0x4
#define LC_UNIXTHREAD            0x5
#define LC_LOADFVMLIB            0x6
#define LC_IDFVMLIB              0x7
#define LC_IDENT                 0x8
#define LC_FVMFILE               0x9
#define LC_PREPAGE               0xa
#define LC_DYSYMTAB              0xb
#define LC_LOAD_DYLIB            0xc
#define LC_ID_DYLIB              0xd
#define LC_LOAD_DYLINKER         0xe
#define LC_ID_DYLINKER           0xf
#define LC_PREBOUND_DYLIB        0x10
#define LC_ROUTINES              0x11
#define LC_SUB_FRAMEWORK         0x12
#define LC_SUB_UMBRELLA          0x13
#define LC_SUB_CLIENT            0x14
#define LC_SUB_LIBRARY           0x15
#define LC_TWOLEVEL_HINTS        0x16
#define LC_PREBIND_CKSUM         0x17
#define LC_LOAD_WEAK_DYLIB       (0x18 | LC_REQ_DYLD)
#define LC_SEGMENT_64            0x19
#define LC_ROUTINES_64           0x1a
#define LC_UUID                  0x1b
#define LC_RPATH                 (0x1c | LC_REQ_DYLD)
#define LC_CODE_SIGNATURE        0x1d
#define LC_SEGMENT_SPLIT_INFO    0x1e
#define LC_REEXPORT_DYLIB        (0x1f | LC_REQ_DYLD)
#define LC_LAZY_LOAD_DYLIB       0x20
#define LC_ENCRYPTION_INFO       0x21
#define LC_DYLD_INFO             0x22
#define LC_DYLD_INFO_ONLY        (0x22 | LC_REQ_DYLD)
#define LC_LOAD_UPWARD_DYLIB     (0x23 | LC_REQ_DYLD)
#define LC_VERSION_MIN_MACOSX    0x24
#define LC_VERSION_MIN_IPHONEOS  0x25
#define LC_FUNCTION_STARTS       0x26
#define LC_DYLD_ENVIRONMENT      0x27
#define LC_MAIN                  (0x28 | LC_REQ_DYLD)
#define LC_DATA_IN_CODE          0x29
#define LC_SOURCE_VERSION        0x2a
#define LC_DYLIB_CODE_SIGN_DRS   0x2b
#define _LC_ENCRYPTION_INFO_64    0x2c /* FIXME: warning defined in .../SDKs/MacOSX10.15.sdk/usr/include/mach-o/loader.h */
#define _LC_LINKER_OPTION         0x2d /* FIXME: warning defined in .../SDKs/MacOSX10.15.sdk/usr/include/mach-o/loader.h */
#define _LC_LINKER_OPTIMIZATION_HINT 0x2e /* FIXME: warning defined in .../SDKs/MacOSX10.15.sdk/usr/include/mach-o/loader.h */
#define _LC_VERSION_MIN_TVOS      0x2f /* FIXME: warning defined in .../SDKs/MacOSX10.15.sdk/usr/include/mach-o/loader.h */
#define LC_VERSION_MIN_WATCHOS   0x30
#define LC_NOTE                  0x31
#define LC_BUILD_VERSION         0x32
#define LC_DYLD_EXPORTS_TRIE     (0x33 | LC_REQ_DYLD)
#define LC_DYLD_CHAINED_FIXUPS   (0x34 | LC_REQ_DYLD)
#define LC_FILESET_ENTRY         (0x35 | LC_REQ_DYLD)

//Mach-O File types
#define  MH_OBJECT                   0x1
#define  MH_EXECUTE                  0x2
#define  MH_FVMLIB                   0x3
#define  MH_CORE                     0x4
#define  MH_PRELOAD                  0x5
#define  MH_DYLIB                    0x6
#define  MH_DYLINKER                 0x7
#define  MH_BUNDLE                   0x8
#define  MH_DYLIB_STUB               0x9
#define  MH_DSYM                     0xa
#define  MH_KEXT_BUNDLE              0xb
#define  MH_FILESET                  0xc

#define  MH_NOUNDEFS                 0x1
#define  MH_INCRLINK                 0x2
#define  MH_DYLDLINK                 0x4
#define  MH_BINDATLOAD               0x8
#define  MH_PREBOUND                 0x10
#define  MH_SPLIT_SEGS               0x20
#define  MH_LAZY_INIT                0x40
#define  MH_TWOLEVEL                 0x80
#define  MH_FORCE_FLAT               0x100
#define  MH_NOMULTIDEFS              0x200
#define  MH_NOFIXPREBINDING          0x400
#define  MH_PREBINDABLE              0x800
#define  MH_ALLMODSBOUND             0x1000
#define  MH_SUBSECTIONS_VIA_SYMBOLS  0x2000
#define  MH_CANONICAL                0x4000
#define  MH_WEAK_DEFINES             0x8000
#define  MH_BINDS_TO_WEAK            0x10000
#define  MH_ALLOW_STACK_EXECUTION    0x20000
#define  MH_ROOT_SAFE                0x40000
#define  MH_SETUID_SAFE              0x80000
#define  MH_NO_REEXPORTED_DYLIBS     0x100000
#define  MH_PIE                      0x200000
#define  MH_DEAD_STRIPPABLE_DYLIB    0x400000
#define  MH_HAS_TLV_DESCRIPTORS      0x800000
#define  MH_NO_HEAP_EXECUTION        0x1000000
#define  _MH_APP_EXTENSION_SAFE       0x2000000 /* FIXME: warning defined in .../SDKs/MacOSX10.15.sdk/usr/include/mach-o/loader.h */
#define  _MH_NLIST_OUTOFSYNC_WITH_DYLDINFO 0x04000000u
#define  _MH_SIM_SUPPORT                   0x08000000u
#define  _MH_DYLIB_IN_CACHE                0x80000000u

//Segment Names
#define  SEG_PAGEZERO       "__PAGEZERO"
#define  SEG_TEXT           "__TEXT"
#define  SECT_TEXT          "__text"
#define  SECT_FVMLIB_INIT0  "__fvmlib_init0"
#define  SECT_FVMLIB_INIT1  "__fvmlib_init1"
#define  SEG_DATA           "__DATA"
#define  SECT_DATA          "__data"
#define  SECT_BSS           "__bss"
#define  SECT_COMMON        "__common"
#define  SEG_OBJC           "__OBJC"
#define  SECT_OBJC_SYMBOLS  "__symbol_table"
#define  SECT_OBJC_MODULES  "__module_info"
#define  SECT_OBJC_STRINGS  "__selector_strs"
#define  SECT_OBJC_REFS     "__selector_refs"
#define  SEG_ICON           "__ICON"
#define  SECT_ICON_HEADER   "__header"
#define  SECT_ICON_TIFF     "__tiff"
#define  SEG_LINKEDIT       "__LINKEDIT"
#define  SEG_UNIXSTACK      "__UNIXSTACK"
#define  SEG_IMPORT         "__IMPORT"

/*
 * Symbols with a index into the string table of zero (n_un.n_strx == 0) are
 * defined to have a null, "", name.  Therefore all string indexes to non null
 * names must not have a zero string index.  This is bit historical information
 * that has never been well documented.
 */

/*
 * The n_type field really contains four fields:
 *	unsigned char N_STAB:3,
 *		      N_PEXT:1,
 *		      N_TYPE:3,
 *		      N_EXT:1;
 * which are used via the following masks.
 */
#define	N_STAB	0xe0  /* if any of these bits set, a symbolic debugging entry */
#define	N_PEXT	0x10  /* private external symbol bit */
#define	N_TYPE	0x0e  /* mask for the type bits */
#define	N_EXT	0x01  /* external symbol bit, set for external symbols */

/*
 * Only symbolic debugging entries have some of the N_STAB bits set and if any
 * of these bits are set then it is a symbolic debugging entry (a stab).  In
 * which case then the values of the n_type field (the entire field) are given
 * in <mach-o/stab.h>
 */

/*
 * Values for N_TYPE bits of the n_type field.
 */
#define	N_UNDF	0x0		/* undefined, n_sect == NO_SECT */
#define	N_ABS	0x2		/* absolute, n_sect == NO_SECT */
#define	N_SECT	0xe		/* defined in section number n_sect */
#define	N_PBUD	0xc		/* prebound undefined (defined in a dylib) */
#define N_INDR	0xa		/* indirect */

/* 
 * If the type is N_INDR then the symbol is defined to be the same as another
 * symbol.  In this case the n_value field is an index into the string table
 * of the other symbol's name.  When the other symbol is defined then they both
 * take on the defined type and value.
 */

/*
 * If the type is N_SECT then the n_sect field contains an ordinal of the
 * section the symbol is defined in.  The sections are numbered from 1 and 
 * refer to sections in order they appear in the load commands for the file
 * they are in.  This means the same ordinal may very well refer to different
 * sections in different files.
 *
 * The n_value field for all symbol table entries (including N_STAB's) gets
 * updated by the link editor based on the value of it's n_sect field and where
 * the section n_sect references gets relocated.  If the value of the n_sect 
 * field is NO_SECT then it's n_value field is not changed by the link editor.
 */
#define	NO_SECT		0	/* symbol is not in any section */
#define MAX_SECT	255	/* 1 thru 255 inclusive */

/*
 * The bit 0x0020 of the n_desc field is used for two non-overlapping purposes
 * and has two different symbolic names, N_NO_DEAD_STRIP and N_DESC_DISCARDED.
 */

/*
 * The N_NO_DEAD_STRIP bit of the n_desc field only ever appears in a 
 * relocatable .o file (MH_OBJECT filetype). And is used to indicate to the
 * static link editor it is never to dead strip the symbol.
 */
#define N_NO_DEAD_STRIP 0x0020 /* symbol is not to be dead stripped */

/*
 * The N_DESC_DISCARDED bit of the n_desc field never appears in linked image.
 * But is used in very rare cases by the dynamic link editor to mark an in
 * memory symbol as discared and longer used for linking.
 */
#define N_DESC_DISCARDED 0x0020	/* symbol is discarded */

/*
 * The N_WEAK_REF bit of the n_desc field indicates to the dynamic linker that
 * the undefined symbol is allowed to be missing and is to have the address of
 * zero when missing.
 */
#define N_WEAK_REF	0x0040 /* symbol is weak referenced */

/*
 * The N_WEAK_DEF bit of the n_desc field indicates to the static and dynamic
 * linkers that the symbol definition is weak, allowing a non-weak symbol to
 * also be used which causes the weak definition to be discared.  Currently this
 * is only supported for symbols in coalesed sections.
 */
#define N_WEAK_DEF	0x0080 /* coalesed symbol is a weak definition */

/*
 * The N_REF_TO_WEAK bit of the n_desc field indicates to the dynamic linker
 * that the undefined symbol should be resolved using flat namespace searching.
 */
#define	N_REF_TO_WEAK	0x0080 /* reference to a weak symbol */

/*
 * The N_ARM_THUMB_DEF bit of the n_desc field indicates that the symbol is
 * a defintion of a Thumb function.
 */
#define N_ARM_THUMB_DEF	0x0008 /* symbol is a Thumb function (ARM) */

/*
 * The N_SYMBOL_RESOLVER bit of the n_desc field indicates that the
 * that the function is actually a resolver function and should
 * be called to get the address of the real function to use.
 * This bit is only available in .o files (MH_OBJECT filetype)
 */
#define N_SYMBOL_RESOLVER  0x0100 

/*
 * The N_ALT_ENTRY bit of the n_desc field indicates that the
 * symbol is pinned to the previous content.
 */
#define N_ALT_ENTRY 0x0200

/*
 * The N_COLD_FUNC bit of the n_desc field indicates that the symbol is used
 * infrequently and the linker should order it towards the end of the section.
 */
#define N_COLD_FUNC 0x0400

/*
 * An indirect symbol table entry is simply a 32bit index into the symbol table
 * to the symbol that the pointer or stub is referring to.  Unless it is for a
 * non-lazy symbol pointer section for a defined symbol which strip(1) as
 * removed.  In which case it has the value INDIRECT_SYMBOL_LOCAL.  If the
 * symbol was also absolute INDIRECT_SYMBOL_ABS is or'ed with that.
 */
#define INDIRECT_SYMBOL_ABS   0x40000000
#define INDIRECT_SYMBOL_LOCAL 0x80000000

#define SECTION_TYPE		 0x000000ff	/* 256 section types */
#define SECTION_ATTRIBUTES	 0xffffff00	/*  24 section attributes */

#define BINARYNINJA_MANUAL_RELOCATION ((uint64_t)-2)

enum MachoRelocationType
{
	GENERIC_RELOC_VANILLA = 0,
	GENERIC_RELOC_PAIR = 1,
	GENERIC_RELOC_SECTDIFF = 2,
	GENERIC_RELOC_PB_LA_PTR = 3,
	GENERIC_RELOC_LOCAL_SECTDIFF = 4,
	GENERIC_RELOC_TLV = 5
};


namespace BinaryNinja
{
	class MachoFormatException: public std::exception
	{
		std::string m_message;

	public:
		MachoFormatException(const std::string& msg = "invalid format"): m_message(msg) {}
		virtual const char* what() const NOEXCEPT { return m_message.c_str(); }
	};

	struct FatHeader {
		uint32_t magic;
		uint32_t nfat_arch;
	};

	struct FatArch32 {
		cpu_type_t cputype;
		cpu_subtype_t cpusubtype;
		uint32_t offset;
		uint32_t size;
		uint32_t align;
	};

	struct FatArch64 {
		cpu_type_t cputype;
		cpu_subtype_t cpusubtype;
		uint64_t offset;
		uint64_t size;
		uint32_t align;
		uint32_t reserved;
	};

	struct mach_header {
		uint32_t	magic;
		cpu_type_t	cputype;
		cpu_subtype_t	cpusubtype;
		uint32_t	filetype;
		uint32_t	ncmds;
		uint32_t	sizeofcmds;
		uint32_t	flags;
	};

	struct mach_header_64 {
		uint32_t	magic;
		cpu_type_t	cputype;
		cpu_subtype_t	cpusubtype;
		uint32_t	filetype;
		uint32_t	ncmds;
		uint32_t	sizeofcmds;
		uint32_t	flags;
		uint32_t	reserved;
	};

	struct load_command {
		uint32_t	cmd;
		uint32_t	cmdsize;
	};

	struct segment_command {
		uint32_t	cmd;
		uint32_t	cmdsize;
		char		segname[16];
		uint32_t	vmaddr;
		uint32_t	vmsize;
		uint32_t	fileoff;
		uint32_t	filesize;
		vm_prot_t	maxprot;
		vm_prot_t	initprot;
		uint32_t	nsects;
		uint32_t	flags;
	};

	struct section { 				// for 32-bit architectures
		char		sectname[16];	// name of this section
		char		segname[16];	// segment this section goes in
		uint32_t	addr;			// memory address of this section
		uint32_t	size;			// size in bytes of this section
		uint32_t	offset;			// file offset of this section
		uint32_t	align;			// section alignment (power of 2)
		uint32_t	reloff;			// file offset of relocation entries
		uint32_t	nreloc;			// number of relocation entries
		uint32_t	flags;			// flags (section type and attributes)
		uint32_t	reserved1;		// reserved (for offset or index)
		uint32_t	reserved2;		// reserved (for count or sizeof)
	};

	struct section_64 { 			// for 64-bit architectures
		char		sectname[16];	// name of this section
		char		segname[16];	// segment this section goes in
		uint64_t	addr;			// memory address of this section
		uint64_t	size;			// size in bytes of this section
		uint32_t	offset;			// file offset of this section
		uint32_t	align;			// section alignment (power of 2)
		uint32_t	reloff;			// file offset of relocation entries
		uint32_t	nreloc;			// number of relocation entries
		uint32_t	flags;			// flags (section type and attributes)
		uint32_t	reserved1;		// reserved (for offset or index)
		uint32_t	reserved2;		// reserved (for count or sizeof)
		uint32_t	reserved3;		// reserved
	};

	struct segment_command_64 {
		uint32_t	cmd;
		uint32_t	cmdsize;
		char		segname[16];
		uint64_t	vmaddr;
		uint64_t	vmsize;
		uint64_t	fileoff;
		uint64_t	filesize;
		vm_prot_t	maxprot;
		vm_prot_t	initprot;
		uint32_t	nsects;
		uint32_t	flags;
	};

	struct uuid_command {
		uint32_t	cmd;
		uint32_t	cmdsize;
		char		uuid[16];
	};

	struct fvmlib_command {
		uint32_t	cmd;
		uint32_t	cmdsize;
		char		segname[16];
		uint32_t	minor_version;
		uint32_t	header_addr;
	};

	struct dylib {
		uint32_t	name;
		uint32_t	timestamp;
		uint32_t	current_version;
		uint32_t	compatibility_version;
	};

	struct dylib_command {
		uint32_t		cmd;
		uint32_t		cmdsize;
		struct dylib	dylib;
	};

	struct sub_framework_command {
		uint32_t	cmd;		// LC_SUB_FRAMEWORK
		uint32_t	cmdsize;	// includes umbrella string
		uint32_t	umbrella;	// the umbrella framework name
	};

	struct sub_client_command {
		uint32_t	cmd;		// LC_SUB_CLIENT
		uint32_t	cmdsize;	// includes client string
		uint32_t	client;		// offset to the string
	};

	struct sub_umbrella_command {
		uint32_t	cmd;		// LC_SUB_UMBRELLA
		uint32_t	cmdsize;	// includes sub_umbrella string
		uint32_t	sub_umbrella;	// the sub_umbrella framework name
	};

	struct sub_library_command {
		uint32_t	cmd;		// LC_SUB_LIBRARY
		uint32_t	cmdsize;	// includes sub_library string
		uint32_t	sub_library;	// the sub_library name
	};

	struct prebound_dylib_command {
		uint32_t	cmd;			// LC_PREBOUND_DYLIB
		uint32_t	cmdsize;		// includes strings
		uint32_t	name;			// library's path name
		uint32_t	nmodules;		// number of modules in library
		uint32_t	linked_modules;	// bit vector of linked modules
	};

	struct dylinker_command {
		uint32_t	cmd;		// LC_ID_DYLINKER or LC_LOAD_DYLINKER
		uint32_t	cmdsize;	// includes pathname string
		uint32_t	name;		// dynamic linker's path name
	};

	struct x86_thread_state64 {
		uint64_t	rax;
		uint64_t	rbx;
		uint64_t	rcx;
		uint64_t	rdx;
		uint64_t	rdi;
		uint64_t	rsi;
		uint64_t	rbp;
		uint64_t	rsp;
		uint64_t	r8;
		uint64_t	r9;
		uint64_t	r10;
		uint64_t	r11;
		uint64_t	r12;
		uint64_t	r13;
		uint64_t	r14;
		uint64_t	r15;
		uint64_t	rip;
		uint64_t	rflags;
		uint64_t	cs;
		uint64_t	fs;
		uint64_t	gs;
	};

	struct x86_thread_state32 {
		uint32_t	eax;
		uint32_t	ebx;
		uint32_t	ecx;
		uint32_t	edx;
		uint32_t	edi;
		uint32_t	esi;
		uint32_t	ebp;
		uint32_t	esp;
		uint32_t	ss;
		uint32_t	eflags;
		uint32_t	eip;
		uint32_t	cs;
		uint32_t	ds;
		uint32_t	es;
		uint32_t	fs;
		uint32_t	gs;
	};

	struct armv7_thread_state {
		uint32_t	r0;
		uint32_t	r1;
		uint32_t	r2;
		uint32_t	r3;
		uint32_t	r4;
		uint32_t	r5;
		uint32_t	r6;
		uint32_t	r7;
		uint32_t	r8;
		uint32_t	r9;
		uint32_t	r10;
		uint32_t	r11;
		uint32_t	r12;
		uint32_t	r13;
		uint32_t	r14; //SP
		uint32_t	r15; //PC
	};

	struct arm_thread_state64 {
		uint64_t	x[29];		// GPR x0-x28
		uint64_t	fp;			// x29
		uint64_t	lr;			// x30
		uint64_t	sp;			// x31
		uint64_t	pc;			// Program Counter
		uint32_t	cpsr;		// Current program status register
	};

	struct ppc_thread_state {
		uint32_t	srr0; //Machine state register (PC)
		uint32_t	srr1;
		uint32_t	r0;
		uint32_t	r1; //Stack pointer
		uint32_t	r2;
		uint32_t	r3;
		uint32_t	r4;
		uint32_t	r5;
		uint32_t	r6;
		uint32_t	r7;
		uint32_t	r8;
		uint32_t	r9;
		uint32_t	r10;
		uint32_t	r11;
		uint32_t	r12;
		uint32_t	r13;
		uint32_t	r14;
		uint32_t	r15;
		uint32_t	r16;
		uint32_t	r17;
		uint32_t	r18;
		uint32_t	r19;
		uint32_t	r20;
		uint32_t	r21;
		uint32_t	r22;
		uint32_t	r23;
		uint32_t	r24;
		uint32_t	r25;
		uint32_t	r26;
		uint32_t	r27;
		uint32_t	r28;
		uint32_t	r29;
		uint32_t	r30;
		uint32_t	r31;
		uint32_t	cr;
		uint32_t	xer;
		uint32_t	lr;
		uint32_t	ctr;
		uint32_t	mq;
		uint32_t	vrsave;
	};

	#pragma pack(push, 4)
	struct ppc_thread_state64 {
		uint64_t	srr0;  //Machine state register (PC)
		uint64_t	srr1;
		uint64_t	r0; //Stack pointer
		uint64_t	r1;
		uint64_t	r2;
		uint64_t	r3;
		uint64_t	r4;
		uint64_t	r5;
		uint64_t	r6;
		uint64_t	r7;
		uint64_t	r8;
		uint64_t	r9;
		uint64_t	r10;
		uint64_t	r11;
		uint64_t	r12;
		uint64_t	r13;
		uint64_t	r14;
		uint64_t	r15;
		uint64_t	r16;
		uint64_t	r17;
		uint64_t	r18;
		uint64_t	r19;
		uint64_t	r20;
		uint64_t	r21;
		uint64_t	r22;
		uint64_t	r23;
		uint64_t	r24;
		uint64_t	r25;
		uint64_t	r26;
		uint64_t	r27;
		uint64_t	r28;
		uint64_t	r29;
		uint64_t	r30;
		uint64_t	r31;
		uint32_t	cr;     // Condition register
		uint64_t	xer;    // User's integer exception register
		uint64_t	lr;     // Link register
		uint64_t	ctr;    // Count register
		uint32_t	vrsave; // Vector Save Register
	};
	#pragma pack(pop)

	struct thread_command {
		uint32_t	cmd;		// LC_THREAD or  LC_UNIXTHREAD
		uint32_t	cmdsize;	// total size of this command
		uint32_t	flavor;	// flavor of thread state
		uint32_t	count;		//count of longs in thread state
		union {
			x86_thread_state64 statex64;
			x86_thread_state32 statex86;
			armv7_thread_state statearmv7;
			arm_thread_state64 stateaarch64;
			ppc_thread_state   stateppc;
			ppc_thread_state64 stateppc64;
		};
	};

	struct linkedit_data_command {
		uint32_t cmd;
		uint32_t cmdsize;
		uint32_t dataoff;
		uint32_t datasize;
	};


	enum MachOArchitecture {
		MachOABIMask	= 0xff000000,
		MachOABI64	= 0x01000000, // 64 bit ABI
		MachOABI6432	= 0x02000000, // "ABI for 64-bit hardware with 32-bit types; LP32"

		// Constants for the cputype field.
		MachOx86	= 7,
		MachOx64	= MachOx86 | MachOABI64,
		MachOArm	= 0xc,
		MachOAarch64	= MachOABI64 | MachOArm,
		MachOAarch6432	= MachOABI6432 | MachOArm,
		MachOSPARC	= 0xe,
		MachOPPC	= 0x12,
		MachOPPC64	= MachOABI64 | MachOPPC,
	};

	enum RebaseType {
		RebaseTypeInvalid = 0,
		RebaseTypePointer = 1,
		RebaseTypeTextAbsolute32 = 2,
		RebaseTypeTextPCRel32 = 3
	};

	enum RebaseOpcode {
		RebaseOpcodeMask                            = 0xF0u, // REBASE_OPCODE_MASK
		RebaseImmediateMask                         = 0x0Fu, // REBASE_IMMEDIATE_MASK
		RebaseOpcodeDone                            = 0x00u, // REBASE_OPCODE_DONE
		RebaseOpcodeSetTypeImmediate                = 0x10u, // REBASE_OPCODE_SET_TYPE_IMM
		RebaseOpcodeSetSegmentAndOffsetUleb         = 0x20u, // REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB
		RebaseOpcodeAddAddressUleb                  = 0x30u, // REBASE_OPCODE_ADD_ADDR_ULEB
		RebaseOpcodeAddAddressImmediateScaled       = 0x40u, // REBASE_OPCODE_ADD_ADDR_IMM_SCALED
		RebaseOpcodeDoRebaseImmediateTimes          = 0x50u, // REBASE_OPCODE_DO_REBASE_IMM_TIMES
		RebaseOpcodeDoRebaseUlebTimes               = 0x60u, // REBASE_OPCODE_DO_REBASE_ULEB_TIMES
		RebaseOpcodeDoRebaseAddAddressUleb          = 0x70u, // REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB
		RebaseOpcodeDoRebaseUlebTimesSkippingUleb   = 0x80u, // REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB
	};

	enum BindOpcode {
		BindOpcodeMask                            = 0xF0u, // BIND_OPCODE_MASK
		BindImmediateMask                         = 0x0Fu, // BIND_IMMEDIATE_MASK
		BindOpcodeDone                            = 0x00u, // BIND_OPCODE_DONE
		BindOpcodeSetDylibOrdinalImmediate        = 0x10u, // BIND_OPCODE_SET_DYLIB_ORDINAL_IMM
		BindOpcodeSetDylibOrdinalULEB             = 0x20u, // BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB
		BindOpcodeSetDylibSpecialImmediate        = 0x30u, // BIND_OPCODE_SET_DYLIB_SPECIAL_IMM
		BindOpcodeSetSymbolTrailingFlagsImmediate = 0x40u, // BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM
		BindOpcodeSetTypeImmediate                = 0x50u, // BIND_OPCODE_SET_TYPE_IMM
		BindOpcodeSetAddendSLEB                   = 0x60u, // BIND_OPCODE_SET_ADDEND_SLEB
		BindOpcodeSetSegmentAndOffsetULEB         = 0x70u, // BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB
		BindOpcodeAddAddressULEB                  = 0x80u, // BIND_OPCODE_ADD_ADDR_ULEB
		BindOpcodeDoBind                          = 0x90u, // BIND_OPCODE_DO_BIND
		BindOpcodeDoBindAddAddressULEB            = 0xA0u, // BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB
		BindOpcodeDoBindAddAddressImmediateScaled = 0xB0u, // BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED
		BindOpcodeDoBindULEBTimesSkippingULEB     = 0xC0u, // BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB
	};

	enum X86ThreadFlavor {
		X86_THREAD_STATE32      = 0x1,
		X86_FLOAT_STATE32       = 0x2,
		X86_EXCEPTION_STATE32   = 0x3,
		X86_THREAD_STATE64      = 0x4,
		X86_FLOAT_STATE64       = 0x5,
		X86_EXCEPTION_STATE64   = 0x6,
		X86_THREAD_STATE        = 0x7,
		X86_FLOAT_STATE         = 0x8,
		X86_EXCEPTION_STATE     = 0x9,
		X86_DEBUG_STATE32       = 0xA,
		X86_DEBUG_STATE64       = 0xB,
		X86_DEBUG_STATE         = 0xC,
		_THREAD_STATE_NONE      = 0xD
	};

	enum PPCThreadFlavor {
		PPC_THREAD_STATE        = 0x1,
		PPC_FLOAT_STATE         = 0x2,
		PPC_EXCEPTION_STATE     = 0x3,
		PPC_VECTOR_STATE        = 0x4,
		PPC_THREAD_STATE64      = 0x5,
		PPC_EXCEPTION_STATE64   = 0x6
	};

	enum ARMThreadFlavor
	{
		_ARM_THREAD_STATE      = 1,
		_ARM_VFP_STATE         = 2,
		_ARM_EXCEPTION_STATE   = 3,
		_ARM_DEBUG_STATE       = 4, /* pre-armv8 */
		_ARM_THREAD_STATE64    = 6,
		_ARM_EXCEPTION_STATE64 = 7
	};

	struct routines_command { // for 32-bit architectures
		uint32_t	cmd;			// LC_ROUTINES
		uint32_t	cmdsize;		// total size of this command
		uint32_t	init_address;	// address of initialization routine
		uint32_t	init_module;	// index into the module table that the init routine is defined in
		uint32_t	reserved1;
		uint32_t	reserved2;
		uint32_t	reserved3;
		uint32_t	reserved4;
		uint32_t	reserved5;
		uint32_t	reserved6;
	};

	struct routines_command_64 { 	// for 64-bit architectures
		uint32_t	cmd;			// LC_ROUTINES_64
		uint32_t	cmdsize;		// total size of this command
		uint64_t	init_address;	// address of initialization routine
		uint64_t	init_module;	// index into the module table that the init routine is defined in
		uint64_t	reserved1;
		uint64_t	reserved2;
		uint64_t	reserved3;
		uint64_t	reserved4;
		uint64_t	reserved5;
		uint64_t	reserved6;
	};

	struct symtab_command {
		uint32_t	cmd;		// LC_SYMTAB
		uint32_t	cmdsize;	// sizeof(struct symtab_command)
		uint32_t	symoff;		// symbol table offset
		uint32_t	nsyms;		// number of symbol table entries
		uint32_t	stroff;		// string table offset
		uint32_t	strsize;	// string table size in bytes
	};

	// Lots of good information on how to use dysymtab for relocations
	// https://opensource.apple.com/source/cctools/cctools-795/include/mach-o/loader.h
	struct dysymtab_command {
		uint32_t cmd;			// LC_DYSYMTAB
		uint32_t cmdsize;		// sizeof(struct dysymtab_command)
		uint32_t ilocalsym;		// index to local symbols
		uint32_t nlocalsym;		// number of local symbols
		uint32_t iextdefsym;	// index to externally defined symbols
		uint32_t nextdefsym;	// number of externally defined symbols
		uint32_t iundefsym;		// index to undefined symbols
		uint32_t nundefsym;		// number of undefined symbols
		uint32_t tocoff;		// file offset to table of contents
		uint32_t ntoc;			// number of entries in table of contents
		uint32_t modtaboff;		// file offset to module table
		uint32_t nmodtab;		// number of module table entries
		uint32_t extrefsymoff;	// offset to referenced symbol table
		uint32_t nextrefsyms;	// number of referenced symbol table entries
		uint32_t indirectsymoff; // file offset to the indirect symbol table
		uint32_t nindirectsyms;  // number of indirect symbol table entries
		uint32_t extreloff;		// offset to external relocation entries
		uint32_t nextrel;		// number of external relocation entries
		uint32_t locreloff;		// offset to local relocation entries
		uint32_t nlocrel;		// number of local relocation entries
	};

	struct twolevel_hints_command {
		uint32_t cmd;		// LC_TWOLEVEL_HINTS
		uint32_t cmdsize;	// sizeof(struct twolevel_hints_command)
		uint32_t offset;	// offset to the hint table
		uint32_t nhints;	// number of hints in the hint table
	};

	struct dyld_info_command {
		uint32_t   cmd;				// LC_DYLD_INFO or LC_DYLD_INFO_ONLY
		uint32_t   cmdsize;			// sizeof(struct dyld_info_command)
		uint32_t   rebase_off;		// file offset to rebase info
		uint32_t   rebase_size;		// size of rebase info
		uint32_t   bind_off;		// file offset to binding info
		uint32_t   bind_size;		// size of binding info
		uint32_t   weak_bind_off;	// file offset to weak binding info
		uint32_t   weak_bind_size;  // size of weak binding info
		uint32_t   lazy_bind_off;	// file offset to lazy binding info
		uint32_t   lazy_bind_size;  // size of lazy binding infs
		uint32_t   export_off;		// file offset to lazy binding info
		uint32_t   export_size;		// size of lazy binding infs
	};

	struct function_starts_command {
		uint32_t cmd;		//LC_FUNCTION_STARTS
		uint32_t cmdsize;   //sizeof(struct function_starts_command)
		uint32_t funcoff;   //offset to function starts list
		uint32_t funcsize;  //sizeof function starts list
	};

	enum MachoPlatform {
		MACHO_PLATFORM_MACOS    = 1,
		MACHO_PLATFORM_IOS      = 2,
		MACHO_PLATFORM_TVOS     = 3,
		MACHO_PLATFORM_WATCHOS  = 4,
		MACHO_PLATFORM_BRIDGEOS = 5
	};

	enum MachoBuildTool {
		MACHO_TOOL_CLANG  = 1,
		MACHO_TOOL_SWIFT  = 2,
		MACHO_TOOL_LD     = 3
	};

	struct build_tool_version {
		uint32_t tool;
		uint32_t version;
	};

	struct build_version_command {
		uint32_t cmd;       // LC_BUILD_VERSION
		uint32_t cmdsize;   // sizeof(build_version_command) + (ntools * sizeof(build_tool_version)
		uint32_t platform;  // MachoPlatform
		uint32_t minos;     // X.Y.Z is encoded in nibbles xxxx.yy.zz
		uint32_t sdk;       // X.Y.Z is encoded in nibbles xxxx.yy.zz
		uint32_t ntools;    // number build_tool_version entries
	};

#pragma pack(push, 1)
	struct nlist {
		int32_t n_strx;
		uint8_t n_type;
		uint8_t n_sect;
		int16_t n_desc;
		uint32_t n_value;
	};

	struct nlist_64 {
		uint32_t n_strx;
		uint8_t n_type;
		uint8_t n_sect;
		uint16_t n_desc;
		uint64_t n_value;
	};
#pragma pack(pop)

#define	R_ABS 0
	struct relocation_info
	{
		int32_t r_address;
		uint32_t r_symbolnum:24;
		uint32_t r_pcrel:1;
		uint32_t r_length:2;
		uint32_t r_extern:1;
		uint32_t r_type:4;
	};
#define R_SCATTERED 0x80000000
	struct scattered_relocation_info_be_64 {
		uint32_t r_scattered:1; // 1=scattered, 0=non-scattered (see above)
		uint32_t r_pcrel:1;     // was relocated pc relative already
		uint32_t r_length:2;    // 0=byte, 1=word, 2=long
		uint32_t r_type:4;      // if not 0, machine specific relocation type
		uint32_t r_address:24;  // offset in the section to what is being relocated
		int64_t r_value;        // the value the item to be relocated is refering to (without any offset added)
	};
	struct scattered_relocation_info_le_64 {
		uint32_t r_address:24;  // offset in the section to what is being relocated
		uint32_t r_type:4;      // if not 0, machine specific relocation type
		uint32_t r_length:2;    // 0=byte, 1=word, 2=long
		uint32_t r_pcrel:1;     // was relocated pc relative already
		uint32_t r_scattered:1; // 1=scattered, 0=non-scattered (see above)
		int64_t r_value;        // the value the item to be relocated is refering to (without any offset added)
	};
	struct scattered_relocation_info_be {
		uint32_t r_scattered:1; // 1=scattered, 0=non-scattered (see above)
		uint32_t r_pcrel:1;     // was relocated pc relative already
		uint32_t r_length:2;    // 0=byte, 1=word, 2=long
		uint32_t r_type:4;      // if not 0, machine specific relocation type
		uint32_t r_address:24;  // offset in the section to what is being relocated
		int32_t r_value;        // the value the item to be relocated is refering to (without any offset added)
	};
	struct scattered_relocation_info_le {
		uint32_t r_address:24;  // offset in the section to what is being relocated
		uint32_t r_type:4;      // if not 0, machine specific relocation type
		uint32_t r_length:2;    // 0=byte, 1=word, 2=long
		uint32_t r_pcrel:1;     // was relocated pc relative already
		uint32_t r_scattered:1; // 1=scattered, 0=non-scattered (see above)
		int32_t r_value;        // the value the item to be relocated is refering to (without any offset added)
	};

	enum reloc_type_generic
	{
		GENERIC_RELOC_VANILLA,   // generic relocation as discribed above
		GENERIC_RELOC_PAIR,      // Only follows a GENRIC_RELOC_SECTDIFF
		GENERIC_RELOC_SECTDIFF,
		GENERIC_RELOC_PB_LA_PTR  // prebound lazy pointer
	};

	struct dyld_chained_fixups_header
	{
		uint32_t    fixups_version;    // 0
		uint32_t    starts_offset;     // offset of dyld_chained_starts_in_image in chain_data
		uint32_t    imports_offset;    // offset of imports table in chain_data
		uint32_t    symbols_offset;    // offset of symbol strings in chain_data
		uint32_t    imports_count;     // number of imported symbol names
		uint32_t    imports_format;    // DYLD_CHAINED_IMPORT*
		uint32_t    symbols_format;    // 0 => uncompressed, 1 => zlib compressed
	};

	// This struct is embedded in LC_DYLD_CHAINED_FIXUPS payload
	struct dyld_chained_starts_in_image
	{
		uint32_t    seg_count;
		uint32_t    seg_info_offset[1];  // each entry is offset into this struct for that segment
		// followed by pool of dyld_chain_starts_in_segment data
	};

	// This struct is embedded in dyld_chain_starts_in_image
	// and passed down to the kernel for page-in linking
	struct dyld_chained_starts_in_segment
	{
		uint32_t    size;               // size of this (amount kernel needs to copy)
		uint16_t    page_size;          // 0x1000 or 0x4000
		uint16_t    pointer_format;     // DYLD_CHAINED_PTR_*
		uint64_t    segment_offset;     // offset in memory to start of segment
		uint32_t    max_valid_pointer;  // for 32-bit OS, any value beyond this is not a pointer
		uint16_t    page_count;         // how many pages are in array
		uint16_t    page_start[1];      // each entry is offset in each page of first element in chain
										// or DYLD_CHAINED_PTR_START_NONE if no fixups on page

		// uint16_t    chain_starts[1];  // some 32-bit formats may require multiple starts per page.
										 // for those, if high bit is set in page_starts[], then it
										 // is index into chain_starts[] which is a list of starts
										 // the last of which has the high bit set
	};

	enum {
		DYLD_CHAINED_PTR_START_NONE   = 0xFFFF, // used in page_start[] to denote a page with no fixups
		DYLD_CHAINED_PTR_START_MULTI  = 0x8000, // used in page_start[] to denote a page which has multiple starts
		DYLD_CHAINED_PTR_START_LAST   = 0x8000, // used in chain_starts[] to denote last start in list for page
	};

	// This struct is embedded in __TEXT,__chain_starts section in firmware
	struct dyld_chained_starts_offsets
	{
		uint32_t    pointer_format;     // DYLD_CHAINED_PTR_32_FIRMWARE
		uint32_t    starts_count;       // number of starts in array
		uint32_t    chain_starts[1];    // array chain start offsets
	};

	// values for dyld_chained_starts_in_segment.pointer_format
	enum {
		DYLD_CHAINED_PTR_ARM64E                 =  1,    // stride 8, unauth target is vmaddr
		DYLD_CHAINED_PTR_64                     =  2,    // target is vmaddr
		DYLD_CHAINED_PTR_32                     =  3,
		DYLD_CHAINED_PTR_32_CACHE               =  4,
		DYLD_CHAINED_PTR_32_FIRMWARE            =  5,
		DYLD_CHAINED_PTR_64_OFFSET              =  6,    // target is vm offset
		DYLD_CHAINED_PTR_ARM64E_OFFSET          =  7,    // old name
		DYLD_CHAINED_PTR_ARM64E_KERNEL          =  7,    // stride 4, unauth target is vm offset
		DYLD_CHAINED_PTR_64_KERNEL_CACHE        =  8,
		DYLD_CHAINED_PTR_ARM64E_USERLAND        =  9,    // stride 8, unauth target is vm offset
		DYLD_CHAINED_PTR_ARM64E_FIRMWARE        = 10,    // stride 4, unauth target is vmaddr
		DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE    = 11,    // stride 1, x86_64 kernel caches
		DYLD_CHAINED_PTR_ARM64E_USERLAND24      = 12,    // stride 8, unauth target is vm offset, 24-bit bind
	};

	// DYLD_CHAINED_PTR_ARM64E
	struct dyld_chained_ptr_arm64e_rebase
	{
		uint64_t    target   : 43,
			high8    :  8,
			next     : 11,    // 4 or 8-byte stide
			bind     :  1,    // == 0
			auth     :  1;    // == 0
	};

	// DYLD_CHAINED_PTR_ARM64E
	struct dyld_chained_ptr_arm64e_bind
	{
		uint64_t    ordinal   : 16,
			zero      : 16,
			addend    : 19,    // +/-256K
			next      : 11,    // 4 or 8-byte stide
			bind      :  1,    // == 1
			auth      :  1;    // == 0
	};

	// DYLD_CHAINED_PTR_ARM64E
	struct dyld_chained_ptr_arm64e_auth_rebase
	{
		uint64_t    target    : 32,   // runtimeOffset
			diversity : 16,
			addrDiv   :  1,
			key       :  2,
			next      : 11,    // 4 or 8-byte stide
			bind      :  1,    // == 0
			auth      :  1;    // == 1
	};

	// DYLD_CHAINED_PTR_ARM64E
	struct dyld_chained_ptr_arm64e_auth_bind
	{
		uint64_t    ordinal   : 16,
			zero      : 16,
			diversity : 16,
			addrDiv   :  1,
			key       :  2,
			next      : 11,    // 4 or 8-byte stide
			bind      :  1,    // == 1
			auth      :  1;    // == 1
	};

	// DYLD_CHAINED_PTR_64/DYLD_CHAINED_PTR_64_OFFSET
	struct dyld_chained_ptr_64_rebase
	{
		uint64_t    target    : 36,    // 64GB max image size (DYLD_CHAINED_PTR_64 => vmAddr, DYLD_CHAINED_PTR_64_OFFSET => runtimeOffset)
			high8     :  8,    // top 8 bits set to this (DYLD_CHAINED_PTR_64 => after slide added, DYLD_CHAINED_PTR_64_OFFSET => before slide added)
			reserved  :  7,    // all zeros
			next      : 12,    // 4-byte stride
			bind      :  1;    // == 0
	};


	// DYLD_CHAINED_PTR_ARM64E_USERLAND24
	struct dyld_chained_ptr_arm64e_bind24
	{
		uint64_t    ordinal   : 24,
			zero      :  8,
			addend    : 19,    // +/-256K
			next      : 11,    // 8-byte stide
			bind      :  1,    // == 1
			auth      :  1;    // == 0
	};

	// DYLD_CHAINED_PTR_ARM64E_USERLAND24
	struct dyld_chained_ptr_arm64e_auth_bind24
	{
		uint64_t    ordinal   : 24,
			zero      :  8,
			diversity : 16,
			addrDiv   :  1,
			key       :  2,
			next      : 11,    // 8-byte stide
			bind      :  1,    // == 1
			auth      :  1;    // == 1
	};


	// DYLD_CHAINED_PTR_64
	struct dyld_chained_ptr_64_bind
	{
		uint64_t    ordinal   : 24,
			addend    :  8,   // 0 thru 255
			reserved  : 19,   // all zeros
			next      : 12,   // 4-byte stride
			bind      :  1;   // == 1
	};

	// DYLD_CHAINED_PTR_64_KERNEL_CACHE, DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE
	struct dyld_chained_ptr_64_kernel_cache_rebase
	{
		uint64_t    target     : 30,   // basePointers[cacheLevel] + target
			cacheLevel :  2,   // what level of cache to bind to (indexes a mach_header array)
			diversity  : 16,
			addrDiv    :  1,
			key        :  2,
			next       : 12,    // 1 or 4-byte stide
			isAuth     :  1;    // 0 -> not authenticated.  1 -> authenticated
	};

	// DYLD_CHAINED_PTR_32
	// Note: for DYLD_CHAINED_PTR_32 some non-pointer values are co-opted into the chain
	// as out of range rebases.  If an entry in the chain is > max_valid_pointer, then it
	// is not a pointer.  To restore the value, subtract off the bias, which is
	// (64MB+max_valid_pointer)/2.
	struct dyld_chained_ptr_32_rebase
	{
		uint32_t    target    : 26,   // vmaddr, 64MB max image size
			next      :  5,   // 4-byte stride
			bind      :  1;   // == 0
	};

	// DYLD_CHAINED_PTR_32
	struct dyld_chained_ptr_32_bind
	{
		uint32_t    ordinal   : 20,
			addend    :  6,   // 0 thru 63
			next      :  5,   // 4-byte stride
			bind      :  1;   // == 1
	};

	// DYLD_CHAINED_PTR_32_CACHE
	struct dyld_chained_ptr_32_cache_rebase
	{
		uint32_t    target    : 30,   // 1GB max dyld cache TEXT and DATA
			next      :  2;   // 4-byte stride
	};


	// DYLD_CHAINED_PTR_32_FIRMWARE
	struct dyld_chained_ptr_32_firmware_rebase
	{
		uint32_t    target   : 26,   // 64MB max firmware TEXT and DATA
			next     :  6;   // 4-byte stride
	};

	enum ChainedFixupPointerGeneric {
		GenericArm64eFixupFormat,
		Generic64FixupFormat,
		Generic32FixupFormat,
		Firmware32FixupFormat
	};

	union Arm64e {
		dyld_chained_ptr_arm64e_auth_rebase authRebase;
		dyld_chained_ptr_arm64e_auth_bind   authBind;
		dyld_chained_ptr_arm64e_rebase      rebase;
		dyld_chained_ptr_arm64e_bind        bind;
		dyld_chained_ptr_arm64e_bind24      bind24;
		dyld_chained_ptr_arm64e_auth_bind24 authBind24;
	};

	union Generic64 {
		dyld_chained_ptr_64_rebase rebase;
		dyld_chained_ptr_64_bind   bind;
	};

	union Generic32 {
		dyld_chained_ptr_32_rebase rebase;
		dyld_chained_ptr_32_bind   bind;
	};

	union ChainedFixupPointer
	{
		dyld_chained_ptr_64_kernel_cache_rebase kernel64;
		dyld_chained_ptr_32_firmware_rebase firmware32;

		uint64_t            raw64;
		Arm64e              arm64e;
		Generic64           generic64;

		uint32_t            raw32;
		Generic32           generic32;
		dyld_chained_ptr_32_cache_rebase             cache32;
	};

	// values for dyld_chained_fixups_header.imports_format
	enum {
		DYLD_CHAINED_IMPORT          = 1,
		DYLD_CHAINED_IMPORT_ADDEND   = 2,
		DYLD_CHAINED_IMPORT_ADDEND64 = 3,
	};

	// DYLD_CHAINED_IMPORT
	struct dyld_chained_import
	{
		uint32_t    lib_ordinal :  8,
			weak_import :  1,
			name_offset : 23;
	};

	// DYLD_CHAINED_IMPORT_ADDEND
	struct dyld_chained_import_addend
	{
		uint32_t    lib_ordinal :  8,
			weak_import :  1,
			name_offset : 23;
		int32_t     addend;
	};

	// DYLD_CHAINED_IMPORT_ADDEND64
	struct dyld_chained_import_addend64
	{
		uint64_t    lib_ordinal : 16,
			weak_import :  1,
			reserved    : 15,
			name_offset : 32;
		uint64_t    addend;
	};

	// When we preload the table, we store them in this format.
	struct import_entry
	{
		uint64_t lib_ordinal;
		uint64_t addend;
		bool weak;
		std::string name;
	};

#ifndef EXPORT_SYMBOL_FLAGS_KIND_MASK
	enum EXPORT_SYMBOL_FLAGS {
		EXPORT_SYMBOL_FLAGS_KIND_MASK           = 0x03u, ///< Mask to access to EXPORT_SYMBOL_KINDS
		EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION     = 0x04u,
		EXPORT_SYMBOL_FLAGS_REEXPORT            = 0x08u,
		EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER   = 0x10u
	};

	enum EXPORT_SYMBOL_KINDS {
		EXPORT_SYMBOL_FLAGS_KIND_REGULAR        = 0x00u,
		EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL   = 0x01u,
		EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE       = 0x02u
	};
#endif

	struct MachOHeader {
		bool isMainHeader = false;

		uint64_t textBase = 0;
		uint64_t loadCommandOffset = 0;
		mach_header_64 ident;
		std::string identifierPrefix;

		std::vector<std::pair<uint64_t, bool>> entryPoints;
		std::vector<uint64_t> m_entryPoints; //list of entrypoints

		std::vector<std::pair<BNRelocationInfo, std::string>> externalRelocations;
		std::vector<BNRelocationInfo> rebaseRelocations;

		symtab_command symtab;
		dysymtab_command dysymtab;
		dyld_info_command dyldInfo;
		routines_command_64 routines64;
		function_starts_command functionStarts;
		std::vector<section_64> moduleInitSections;
		linkedit_data_command exportTrie;
		linkedit_data_command chainedFixups {};
		section_64 chainStarts {};

		DataBuffer* stringList;
		size_t stringListSize = 0;

		uint64_t relocationBase = 0;
		// Section and program headers, internally use 64-bit form as it is a superset of 32-bit
		std::vector<segment_command_64> segments; //only three types of sections __TEXT, __DATA, __IMPORT
		std::vector<section_64> sections;
		std::vector<std::string> sectionNames;

		std::vector<section_64> symbolStubSections;
		std::vector<section_64> symbolPointerSections;

		std::vector<std::pair<std::string, std::string>> dylibs;

		build_version_command buildVersion;
		std::vector<build_tool_version> buildToolVersions;

		bool dysymPresent = false;
		bool dyldInfoPresent = false;
		bool exportTriePresent = false;
		bool chainedFixupsPresent = false;
		bool chainStartsPresent = false;
		bool routinesPresent = false;
		bool functionStartsPresent = false;
		bool relocatable = false;
	};

	class MachoView: public BinaryView
	{
		MachOHeader m_header;
		std::map<uint64_t, MachOHeader> m_subHeaders; // Used for MH_FILESET entries.

		struct HeaderQualifiedNames {
			QualifiedName cpuTypeEnumQualName;
			QualifiedName fileTypeEnumQualName;
			QualifiedName flagsTypeEnumQualName;
			QualifiedName headerQualName;
			QualifiedName cmdTypeEnumQualName;
			QualifiedName loadCommandQualName;
			QualifiedName protTypeEnumQualName;
			QualifiedName segFlagsTypeEnumQualName;
			QualifiedName loadSegmentCommandQualName;
			QualifiedName loadSegment64CommandQualName;
			QualifiedName sectionQualName;
			QualifiedName section64QualName;
			QualifiedName symtabQualName;
			QualifiedName dynsymtabQualName;
			QualifiedName uuidQualName;
			QualifiedName linkeditDataQualName;
			QualifiedName encryptionInfoQualName;
			QualifiedName versionMinQualName;
			QualifiedName dyldInfoQualName;
			QualifiedName dylibQualName;
			QualifiedName dylibCommandQualName;
			QualifiedName filesetEntryCommandQualName;
		} m_typeNames;

		MachoObjCProcessor* m_objcProcessor = nullptr;

		uint64_t m_universalImageOffset;
		bool m_parseOnly, m_backedByDatabase;
		int64_t m_imageBaseAdjustment;
		size_t m_addressSize;	 //Address size in bytes 4/8
		BNEndianness m_endian;
		uint32_t m_archId;
		Ref<Architecture> m_arch;
		Ref<Platform> m_plat = nullptr;
		bool m_dylibFile;
		bool m_objectFile;
		std::vector<std::string> m_symbols;

		bool m_relocatable = false;

		bool m_extractMangledTypes;
		bool m_simplifyTemplates;

		SymbolQueue* m_symbolQueue = nullptr;
		Ref<Logger> m_logger;

		std::vector<segment_command_64> m_allSegments; //only three types of sections __TEXT, __DATA, __IMPORT
		std::vector<section_64> m_allSections;

		MachOHeader HeaderForAddress(BinaryView* data, uint64_t address, bool isMainHeader, std::string identifierPrefix = "");
		bool InitializeHeader(MachOHeader& header, bool isMainHeader, uint64_t preferredImageBase, std::string preferredImageBaseDesc);

		void RebaseThreadStarts(BinaryReader& virtualReader, std::vector<uint32_t>& threadStarts, uint64_t stepMultiplier);
		Ref<Symbol> DefineMachoSymbol(
			BNSymbolType type, const std::string& name, uint64_t addr, BNSymbolBinding binding, bool deferred);
		void ParseSymbolTable(BinaryReader& reader, MachOHeader& header, const symtab_command& symtab, const std::vector<uint32_t>& symbolStubsList);
		bool IsValidFunctionStart(uint64_t addr);
		void ParseFunctionStarts(Platform* platform, uint64_t textBase, function_starts_command functionStarts);
		bool ParseRelocationEntry(const relocation_info& info, uint64_t start, BNRelocationInfo& result);

		void ParseExportTrie(BinaryReader& reader, linkedit_data_command exportTrie);
		void ReadExportNode(uint64_t viewStart, DataBuffer& buffer, const std::string& currentText,
			size_t cursor, uint32_t endGuard);

		void ParseRebaseTable(BinaryReader& reader, MachOHeader& header, uint32_t tableOffset, uint32_t tableSize);
		void ParseDynamicTable(BinaryReader& reader, MachOHeader& header, BNSymbolType type, uint32_t tableOffset, uint32_t tableSize,
			BNSymbolBinding binding);
		bool GetSectionPermissions(MachOHeader& header, uint64_t address, uint32_t &flags);
		bool GetSegmentPermissions(MachOHeader& header, uint64_t address, uint32_t &flags);
		void ParseChainedFixups(MachOHeader& header, linkedit_data_command chainedFixups);
		void ParseChainedStarts(MachOHeader& header, section_64 chainedStarts);

		virtual uint64_t PerformGetEntryPoint() const override;

		virtual bool PerformIsExecutable() const override { return true; }
		virtual BNEndianness PerformGetDefaultEndianness() const override;
		virtual bool PerformIsRelocatable() const override;
		virtual size_t PerformGetAddressSize() const override;
	public:
		MachoView(const std::string& typeName, BinaryView* data, bool parseOnly = false);

		virtual bool Init() override;
	};

	class MachoViewType: public BinaryViewType
	{
		Ref<Logger> m_logger;
	public:
		MachoViewType();
		virtual Ref<BinaryView> Create(BinaryView* data) override;
		virtual Ref<BinaryView> Parse(BinaryView* data) override;
		virtual bool IsTypeValidForData(BinaryView* data) override;
		virtual uint64_t ParseHeaders(BinaryView* data, uint64_t imageOffset, mach_header_64& ident, Ref<Architecture>* arch, Ref<Platform>* platform, std::string& errorMsg);
		virtual Ref<Settings> GetLoadSettingsForData(BinaryView* data) override;
	};

	void InitMachoViewType();
}
