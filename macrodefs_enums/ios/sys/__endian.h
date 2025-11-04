// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/__endian.h

enum macro_byte_order {
/*
 * Definitions for byte order, according to byte significance from low
 * address to high.
 */
/*line: 97*/    __DARWIN_LITTLE_ENDIAN = 0x4d2, /* LSB first: i386, vax */ // 1234
/*line: 98*/    __DARWIN_BIG_ENDIAN = 0x10e1, /* MSB first: 68000, ibm, net */ // 4321
/*line: 99*/    __DARWIN_PDP_ENDIAN = 0xd54, /* LSB first in word, MSW first in long */ // 3412
};

// Depends on identifiers
enum macro_endianness {
/*line: 103*/   LITTLE_ENDIAN = 0x4d2,  // __DARWIN_LITTLE_ENDIAN
/*line: 104*/   BIG_ENDIAN = 0x10e1,  // __DARWIN_BIG_ENDIAN
/*line: 105*/   PDP_ENDIAN = 0xd54,  // __DARWIN_PDP_ENDIAN
};

