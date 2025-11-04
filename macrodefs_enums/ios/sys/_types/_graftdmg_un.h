// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/_types/_graftdmg_un.h

enum macro_graftdmg_args {
/*line: 35*/    GRAFTDMG_SECURE_BOOT_CRYPTEX_ARGS_VERSION = 0x1,  // 1
/*line: 36*/    MAX_GRAFT_ARGS_SIZE = 0x200,  // 512
};

enum macro_secure_boot_flags {
/* Flag values for secure_boot_cryptex_args.sbc_flags */
/*line: 39*/    SBC_PRESERVE_MOUNT = 0x1, /* Preserve underlying mount until shutdown */ // 0x0001
/*line: 40*/    SBC_ALTERNATE_SHARED_REGION = 0x2, /* Binaries within should use alternate shared region */ // 0x0002
/*line: 41*/    SBC_SYSTEM_CONTENT = 0x4, /* Cryptex contains system content */ // 0x0004
/*line: 42*/    SBC_PANIC_ON_AUTHFAIL = 0x8, /* On failure to authenticate, panic */ // 0x0008
/*line: 43*/    SBC_STRICT_AUTH = 0x10, /* Strict authentication mode */ // 0x0010
/*line: 44*/    SBC_PRESERVE_GRAFT = 0x20, /* Preserve graft itself until unmount */ // 0x0020
};

