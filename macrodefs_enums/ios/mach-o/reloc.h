// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach-o/reloc.h

enum macro_relocation_type {
/*line: 74*/    R_ABS = 0x0, /* absolute relocation type for Mach-O files */ // 0
};

enum macro_scattered_relocation {
/*line: 147*/   R_SCATTERED = 0x80000000, /* mask to be applied to the r_address field 
				   of a relocation_info structure to tell that
				   is is really a scattered_relocation_info
				   stucture */ // 0x80000000
};

