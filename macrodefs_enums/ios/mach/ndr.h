// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/ndr.h

// enum macro_ndr_protocol {
// /*
//  * MIG supported protocols for Network Data Representation
//  */
// /*line: 54*/    NDR_PROTOCOL_2_0 = 0x0,  // 0
// };

enum macro_ndr_format {
/*
 * NDR 2.0 format flag type definition and values.
 */
/*line: 59*/    NDR_INT_BIG_ENDIAN = 0x0,  // 0
/*line: 60*/    NDR_INT_LITTLE_ENDIAN = 0x1,  // 1
/*line: 61*/    NDR_FLOAT_IEEE = 0x0,  // 0
/*line: 62*/    NDR_FLOAT_VAX = 0x1,  // 1
/*line: 63*/    NDR_FLOAT_CRAY = 0x2,  // 2
/*line: 64*/    NDR_FLOAT_IBM = 0x3,  // 3
/*line: 65*/    NDR_CHAR_ASCII = 0x0,  // 0
/*line: 66*/    NDR_CHAR_EBCDIC = 0x1,  // 1
};

// enum macro_ndr_convert {
// /*line: 73*/    __NDR_convert__ = 0x0,  // 0
// };

// // Depends on identifiers
// enum macro_ndr_convert {
// /*line: 77*/    __NDR_convert__int_rep__ = 0x0,  // __NDR_convert__
// };

// enum macro_ndr_convert {
// /*line: 81*/    __NDR_convert__char_rep__ = 0x0,  // 0
// };

// enum macro_ndr_float_rep {
// /*line: 85*/    __NDR_convert__float_rep__ = 0x0,  // 0
// };

