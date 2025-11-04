// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/dns_util.h

enum macro_dns_status {
/*
 * Status returned in a dns_reply_t
 */
/*line: 40*/    DNS_STATUS_OK = 0x0,  // 0
/*line: 41*/    DNS_STATUS_BAD_HANDLE = 0x1,  // 1
/*line: 42*/    DNS_STATUS_MALFORMED_QUERY = 0x2,  // 2
/*line: 43*/    DNS_STATUS_TIMEOUT = 0x3,  // 3
/*line: 44*/    DNS_STATUS_SEND_FAILED = 0x4,  // 4
/*line: 45*/    DNS_STATUS_RECEIVE_FAILED = 0x5,  // 5
/*line: 46*/    DNS_STATUS_CONNECTION_FAILED = 0x6,  // 6
/*line: 47*/    DNS_STATUS_WRONG_SERVER = 0x7,  // 7
/*line: 48*/    DNS_STATUS_WRONG_XID = 0x8,  // 8
/*line: 49*/    DNS_STATUS_WRONG_QUESTION = 0x9,  // 9
};

enum macro_dns_print_flags {
/*
 * dns_print_reply mask
 */
/*line: 54*/    DNS_PRINT_XID = 0x1,  // 0x0001
/*line: 55*/    DNS_PRINT_QR = 0x2,  // 0x0002
/*line: 56*/    DNS_PRINT_OPCODE = 0x4,  // 0x0004
/*line: 57*/    DNS_PRINT_AA = 0x8,  // 0x0008
/*line: 58*/    DNS_PRINT_TC = 0x10,  // 0x0010
/*line: 59*/    DNS_PRINT_RD = 0x20,  // 0x0020
/*line: 60*/    DNS_PRINT_RA = 0x40,  // 0x0040
/*line: 61*/    DNS_PRINT_PR = 0x80,  // 0x0080
/*line: 62*/    DNS_PRINT_RCODE = 0x100,  // 0x0100
/*line: 63*/    DNS_PRINT_QUESTION = 0x200,  // 0x0200
/*line: 64*/    DNS_PRINT_ANSWER = 0x400,  // 0x0400
/*line: 65*/    DNS_PRINT_AUTHORITY = 0x800,  // 0x0800
/*line: 66*/    DNS_PRINT_ADDITIONAL = 0x1000,  // 0x1000
/*line: 67*/    DNS_PRINT_SERVER = 0x2000,  // 0x2000
};

