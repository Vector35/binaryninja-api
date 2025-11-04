// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach-o/nlist.h

enum macro_nlist_type_bit_mask {
/*
 * The n_type field really contains four fields:
 *	unsigned char N_STAB:3,
 *		      N_PEXT:1,
 *		      N_TYPE:3,
 *		      N_EXT:1;
 * which are used via the following masks.
 */
/*line: 117*/   N_STAB = 0xe0, /* if any of these bits set, a symbolic debugging entry */ // 0xe0
/*line: 118*/   N_PEXT = 0x10, /* private external symbol bit */ // 0x10
/*line: 119*/   N_TYPE = 0xe, /* mask for the type bits */ // 0x0e
/*line: 120*/   N_EXT = 0x1, /* external symbol bit, set for external symbols */ // 0x01
};

enum macro_nlist_type {
/*
 * Values for N_TYPE bits of the n_type field.
 */
/*line: 132*/   N_UNDF = 0x0, /* undefined, n_sect == NO_SECT */ // 0x0
/*line: 133*/   N_ABS = 0x2, /* absolute, n_sect == NO_SECT */ // 0x2
/*line: 134*/   N_SECT = 0xe, /* defined in section number n_sect */ // 0xe
/*line: 135*/   N_PBUD = 0xc, /* prebound undefined (defined in a dylib) */ // 0xc
/*line: 136*/   N_INDR = 0xa, /* indirect */ // 0xa
};

enum macro_section_ordinal {
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
/*line: 157*/   NO_SECT = 0x0, /* symbol is not in any section */ // 0
/*line: 158*/   MAX_SECT = 0xff, /* 1 thru 255 inclusive */ // 255
};

enum macro_reference_flags {
/* Reference type bits of the n_desc field of undefined symbols */
/*line: 193*/   REFERENCE_TYPE = 0x7,  // 0x7
/* types of references */
/*line: 195*/   REFERENCE_FLAG_UNDEFINED_NON_LAZY = 0x0,  // 0
/*line: 196*/   REFERENCE_FLAG_UNDEFINED_LAZY = 0x1,  // 1
/*line: 197*/   REFERENCE_FLAG_DEFINED = 0x2,  // 2
/*line: 198*/   REFERENCE_FLAG_PRIVATE_DEFINED = 0x3,  // 3
/*line: 199*/   REFERENCE_FLAG_PRIVATE_UNDEFINED_NON_LAZY = 0x4,  // 4
/*line: 200*/   REFERENCE_FLAG_PRIVATE_UNDEFINED_LAZY = 0x5,  // 5
/*
 * To simplify stripping of objects that use are used with the dynamic link
 * editor, the static link editor marks the symbols defined an object that are
 * referenced by a dynamically bound object (dynamic shared libraries, bundles).
 * With this marking strip knows not to strip these symbols.
 */
/*line: 208*/   REFERENCED_DYNAMICALLY = 0x10,  // 0x0010
};

enum macro_library_ordinal {
/*line: 240*/   SELF_LIBRARY_ORDINAL = 0x0,  // 0x0
/*line: 241*/   MAX_LIBRARY_ORDINAL = 0xfd,  // 0xfd
/*line: 242*/   DYNAMIC_LOOKUP_ORDINAL = 0xfe,  // 0xfe
/*line: 243*/   EXECUTABLE_ORDINAL = 0xff,  // 0xff
};

enum macro_description_bits {
/*
 * The N_NO_DEAD_STRIP bit of the n_desc field only ever appears in a 
 * relocatable .o file (MH_OBJECT filetype). And is used to indicate to the
 * static link editor it is never to dead strip the symbol.
 */
/*line: 255*/   N_NO_DEAD_STRIP = 0x20, /* symbol is not to be dead stripped */ // 0x0020
/*
 * The N_DESC_DISCARDED bit of the n_desc field never appears in linked image.
 * But is used in very rare cases by the dynamic link editor to mark an in
 * memory symbol as discared and longer used for linking.
 */
/*line: 262*/   N_DESC_DISCARDED = 0x20, /* symbol is discarded */ // 0x0020
/*
 * The N_WEAK_REF bit of the n_desc field indicates to the dynamic linker that
 * the undefined symbol is allowed to be missing and is to have the address of
 * zero when missing.
 */
/*line: 269*/   N_WEAK_REF = 0x40, /* symbol is weak referenced */ // 0x0040
/*
 * The N_WEAK_DEF bit of the n_desc field indicates to the static and dynamic
 * linkers that the symbol definition is weak, allowing a non-weak symbol to
 * also be used which causes the weak definition to be discared.  Currently this
 * is only supported for symbols in coalesed sections.
 */
/*line: 277*/   N_WEAK_DEF = 0x80, /* coalesed symbol is a weak definition */ // 0x0080
/*
 * The N_REF_TO_WEAK bit of the n_desc field indicates to the dynamic linker
 * that the undefined symbol should be resolved using flat namespace searching.
 */
/*line: 283*/   N_REF_TO_WEAK = 0x80, /* reference to a weak symbol */ // 0x0080
/*
 * The N_ARM_THUMB_DEF bit of the n_desc field indicates that the symbol is
 * a defintion of a Thumb function.
 */
/*line: 289*/   N_ARM_THUMB_DEF = 0x8, /* symbol is a Thumb function (ARM) */ // 0x0008
/*
 * The N_SYMBOL_RESOLVER bit of the n_desc field indicates that the
 * that the function is actually a resolver function and should
 * be called to get the address of the real function to use.
 * This bit is only available in .o files (MH_OBJECT filetype)
 */
/*line: 297*/   N_SYMBOL_RESOLVER = 0x100,  // 0x0100
/*
 * The N_ALT_ENTRY bit of the n_desc field indicates that the
 * symbol is pinned to the previous content.
 */
/*line: 303*/   N_ALT_ENTRY = 0x200,  // 0x0200
/*
 * The N_COLD_FUNC bit of the n_desc field indicates that the symbol is used
 * infrequently and the linker should order it towards the end of the section.
 */
/*line: 309*/   N_COLD_FUNC = 0x400,  // 0x0400
};

