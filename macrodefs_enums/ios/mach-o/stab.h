// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach-o/stab.h

enum macro_stab_symbols {
/*
 * Symbolic debugger symbols.  The comments give the conventional use for
 * 
 * 	.stabs "n_name", n_type, n_sect, n_desc, n_value
 *
 * where n_type is the defined constant and not listed in the comment.  Other
 * fields not listed are zero. n_sect is the section ordinal the entry is
 * refering to.
 */
/*line: 87*/    N_GSYM = 0x20, /* global symbol: name,,NO_SECT,type,0 */ // 0x20
/*line: 88*/    N_FNAME = 0x22, /* procedure name (f77 kludge): name,,NO_SECT,0,0 */ // 0x22
/*line: 89*/    N_FUN = 0x24, /* procedure: name,,n_sect,linenumber,address */ // 0x24
/*line: 90*/    N_STSYM = 0x26, /* static symbol: name,,n_sect,type,address */ // 0x26
/*line: 91*/    N_LCSYM = 0x28, /* .lcomm symbol: name,,n_sect,type,address */ // 0x28
/*line: 92*/    N_BNSYM = 0x2e, /* begin nsect sym: 0,,n_sect,0,address */ // 0x2e
/*line: 93*/    N_AST = 0x32, /* AST file path: name,,NO_SECT,0,0 */ // 0x32
/*line: 94*/    N_OPT = 0x3c, /* emitted with gcc2_compiled and in gcc source */ // 0x3c
/*line: 95*/    N_RSYM = 0x40, /* register sym: name,,NO_SECT,type,register */ // 0x40
/*line: 96*/    N_SLINE = 0x44, /* src line: 0,,n_sect,linenumber,address */ // 0x44
/*line: 97*/    N_ENSYM = 0x4e, /* end nsect sym: 0,,n_sect,0,address */ // 0x4e
/*line: 98*/    N_SSYM = 0x60, /* structure elt: name,,NO_SECT,type,struct_offset */ // 0x60
/*line: 99*/    N_SO = 0x64, /* source file name: name,,n_sect,0,address */ // 0x64
/*line: 100*/   N_OSO = 0x66, /* object file name: name,,(see below),1,st_mtime */ // 0x66
/*   historically N_OSO set n_sect to 0. The N_OSO
			 *   n_sect may instead hold the low byte of the
			 *   cpusubtype value from the Mach-O header. */
/*line: 104*/   N_LIB = 0x68, /* dynamic library file name: name,,NO_SECT,0,0 */ // 0x68
/*line: 105*/   N_LSYM = 0x80, /* local sym: name,,NO_SECT,type,offset */ // 0x80
/*line: 106*/   N_BINCL = 0x82, /* include file beginning: name,,NO_SECT,0,sum */ // 0x82
/*line: 107*/   N_SOL = 0x84, /* #included file name: name,,n_sect,0,address */ // 0x84
/*line: 108*/   N_PARAMS = 0x86, /* compiler parameters: name,,NO_SECT,0,0 */ // 0x86
/*line: 109*/   N_VERSION = 0x88, /* compiler version: name,,NO_SECT,0,0 */ // 0x88
/*line: 110*/   N_OLEVEL = 0x8a, /* compiler -O level: name,,NO_SECT,0,0 */ // 0x8A
/*line: 111*/   N_PSYM = 0xa0, /* parameter: name,,NO_SECT,type,offset */ // 0xa0
/*line: 112*/   N_EINCL = 0xa2, /* include file end: name,,NO_SECT,0,0 */ // 0xa2
/*line: 113*/   N_ENTRY = 0xa4, /* alternate entry: name,,n_sect,linenumber,address */ // 0xa4
/*line: 114*/   N_LBRAC = 0xc0, /* left bracket: 0,,NO_SECT,nesting level,address */ // 0xc0
/*line: 115*/   N_EXCL = 0xc2, /* deleted include file: name,,NO_SECT,0,sum */ // 0xc2
/*line: 116*/   N_RBRAC = 0xe0, /* right bracket: 0,,NO_SECT,nesting level,address */ // 0xe0
/*line: 117*/   N_BCOMM = 0xe2, /* begin common: name,,NO_SECT,0,0 */ // 0xe2
/*line: 118*/   N_ECOMM = 0xe4, /* end common: name,,n_sect,0,0 */ // 0xe4
/*line: 119*/   N_ECOML = 0xe8, /* end common (local name): 0,,n_sect,0,address */ // 0xe8
/*line: 120*/   N_LENG = 0xfe, /* second stab entry with length information */ // 0xfe
};

enum macro_n_pc {
/*
 * for the berkeley pascal compiler, pc(1):
 */
/*line: 125*/   N_PC = 0x30, /* global pascal symbol: name,,NO_SECT,subtype,line */ // 0x30
};

