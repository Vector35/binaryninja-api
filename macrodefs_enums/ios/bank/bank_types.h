// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/bank/bank_types.h

// Depends on identifiers
enum macro_voucher_attr_bank {
/*line: 36*/    MACH_VOUCHER_ATTR_BANK_NULL = 0x259,  // ((mach_voucher_attr_recipe_command_t)601)
/*line: 37*/    MACH_VOUCHER_ATTR_BANK_CREATE = 0x262,  // ((mach_voucher_attr_recipe_command_t)610)
/*line: 38*/    MACH_VOUCHER_ATTR_BANK_MODIFY_PERSONA = 0x263,  // ((mach_voucher_attr_recipe_command_t)611)
};

enum macro_voucher_size {
/*line: 40*/    MACH_VOUCHER_BANK_CONTENT_SIZE = 0x1f4,  // (500)
};

enum macro_bank_persona_type {
/*line: 43*/    BANK_ORIGINATOR_PID = 0x1,  // 0x1
/*line: 44*/    BANK_PERSONA_TOKEN = 0x2,  // 0x2
/*line: 45*/    BANK_PERSONA_ID = 0x3,  // 0x3
/*line: 46*/    BANK_PERSONA_ADOPT_ANY = 0x4,  // 0x4
/*line: 47*/    BANK_ORIGINATOR_PROXIMATE_PID = 0x5,  // 0x5
};

enum macro_adoption_allowed {
/*line: 50*/    PROC_PERSONA_INFO_FLAG_ADOPTION_ALLOWED = 0x1,  // 0x1
};

