// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/error.h

// Depends on identifiers
enum macro_mach_error {
/*
 *	error number layout as follows:
 *
 *	hi		                       lo
 *	| system(6) | subsystem(12) | code(14) |
 */
/*line: 78*/    err_none = 0x0,  // (mach_error_t)0
/*line: 79*/    ERR_SUCCESS = 0x0,  // (mach_error_t)0
/*line: 80*/    ERR_ROUTINE_NIL = 0x0,  // (mach_error_fn_t)0
};

// Depends on identifiers
enum macro_error_masks {
/*line: 90*/    system_emask = 0x3f,  // (err_system(0x3f))
/*line: 91*/    sub_emask = 0xfff,  // (err_sub(0xfff))
/*line: 92*/    code_emask = 0x3fff,  // (0x3fff)
};

// Depends on identifiers
enum macro_error_system {
/*	major error systems	*/
/*line: 96*/    err_kern = 0x0, /* kernel */ // err_system(0x0)
/*line: 97*/    err_us = 0x1, /* user space library */ // err_system(0x1)
/*line: 98*/    err_server = 0x2, /* user space servers */ // err_system(0x2)
/*line: 99*/    err_ipc = 0x3, /* old ipc errors */ // err_system(0x3)
/*line: 100*/   err_mach_ipc = 0x4, /* mach-ipc errors */ // err_system(0x4)
/*line: 101*/   err_dipc = 0x7, /* distributed ipc */ // err_system(0x7)
/*line: 102*/   err_vm = 0x8, /* virtual memory */ // err_system(0x8)
/*                              err_system(0x38)           iokit */
/*line: 105*/   err_local = 0x3e, /* user defined errors */ // err_system(0x3e)
/*line: 106*/   err_ipc_compat = 0x3f, /* (compatibility) mach-ipc errors */ // err_system(0x3f)
};

enum macro_err_max_system {
/*line: 108*/   err_max_system = 0x3f,  // 0x3f
};

