// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/libDER/libDER_config.h

enum macro_der_encode_enable {
/* enable general DER encode */
/*line: 98*/    DER_ENCODE_ENABLE = 0x1,  // 1
};

enum macro_der_decode_enable {
/* enable general DER decode */
/*line: 101*/   DER_DECODE_ENABLE = 0x1,  // 1
};

enum macro_der_config {
/* enable multibyte tag support. */
/*line: 105*/   DER_MULTIBYTE_TAGS = 0x1,  // 1
/* Iff DER_MULTIBYTE_TAGS is 1 this is the sizeof(DERTag) in bytes. Note that
   tags are still encoded and decoded from a minimally encoded DER
   represantation.  This value maintains compatibility with libImg4Decode/Encode.  */
/*line: 112*/   DER_TAG_SIZE = 0x8,  // 8
};

