// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach_debug/mach_debug_types.h

enum macro_mach_core_file_header_constants {
/*line: 72*/    MACH_CORE_FILEHEADER_SIGNATURE = 0x63614d20646152,  // 0x0063614d20646152ULL
/*line: 73*/    MACH_CORE_FILEHEADER_V2_SIGNATURE = 0x63614d2073736f42,  // 0x63614d2073736f42ULL
/*line: 74*/    MACH_CORE_FILEHEADER_MAXFILES = 0x10,  // 16
/*line: 75*/    MACH_CORE_FILEHEADER_NAMELEN = 0x10,  // 16
};

enum macro_mach_core_fileheader_v2_constants {
/* The following are defined for mach_core_fileheader_v2 */
/*line: 78*/    MACH_CORE_FILEHEADER_V2_FLAG_LOG_ENCRYPTED_AEA = 0x1, /* The log is encrypted using AEA */ // (1ULL<<0)
/*line: 79*/    MACH_CORE_FILEHEADER_V2_FLAG_EXISTING_COREFILE_KEY_FORMAT_NIST_P256 = 0x100, /* The public key is an NIST-P256 ECC key */ // (1ULL<<8)
/*line: 80*/    MACH_CORE_FILEHEADER_V2_FLAG_NEXT_COREFILE_KEY_FORMAT_NIST_P256 = 0x10000, /* The next public key is an NIST-P256 ECC key */ // (1ULL<<16)
/*line: 82*/    MACH_CORE_FILEHEADER_V2_FLAGS_EXISTING_COREFILE_KEY_FORMAT_MASK = 0x100, /* A bit-mask for all supported key formats */ // (0x1ULL<<8)
/*line: 83*/    MACH_CORE_FILEHEADER_V2_FLAGS_NEXT_COREFILE_KEY_FORMAT_MASK = 0x10000, /* A bit-mask for all supported next key formats */ // (0x1ULL<<16)
};

enum macro_core_details_flags {
/* The following are defined for mach_core_details_v2 */
/*line: 88*/    MACH_CORE_DETAILS_V2_FLAG_ENCRYPTED_AEA = 0x1, /* This core is encrypted using AEA */ // (1ULL<<0)
/*line: 89*/    MACH_CORE_DETAILS_V2_FLAG_COMPRESSED_ZLIB = 0x100, /* This core is compressed using ZLib */ // (1ULL<<8)
/*line: 90*/    MACH_CORE_DETAILS_V2_FLAG_COMPRESSED_LZ4 = 0x200, /* This core is compressed using LZ4 */ // (1ULL<<9)
};

enum macro_object_description_length {
/*line: 197*/   KOBJECT_DESCRIPTION_LENGTH = 0x200,  // 512
};

