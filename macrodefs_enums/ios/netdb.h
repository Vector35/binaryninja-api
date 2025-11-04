// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/netdb.h

// Depends on identifiers
enum macro_netdb_errors {
/*line: 171*/   NETDB_INTERNAL = -0x1, /* see errno */ // -1
/*line: 172*/   NETDB_SUCCESS = 0x0, /* no problem */ // 0
/*line: 174*/   HOST_NOT_FOUND = 0x1, /* Authoritative Answer Host not found */ // 1
/*line: 175*/   TRY_AGAIN = 0x2, /* Non-Authoritative Host not found, or SERVERFAIL */ // 2
/*line: 176*/   NO_RECOVERY = 0x3, /* Non recoverable errors, FORMERR, REFUSED, NOTIMP */ // 3
/*line: 177*/   NO_DATA = 0x4, /* Valid name, no data record of requested type */ // 4
/*line: 179*/   NO_ADDRESS = 0x4, /* no address, look for MX record */ // NO_DATA
/*line: 185*/   EAI_ADDRFAMILY = 0x1, /* address family for hostname not supported */ // 1
/*line: 187*/   EAI_AGAIN = 0x2, /* temporary failure in name resolution */ // 2
/*line: 188*/   EAI_BADFLAGS = 0x3, /* invalid value for ai_flags */ // 3
/*line: 189*/   EAI_FAIL = 0x4, /* non-recoverable failure in name resolution */ // 4
/*line: 190*/   EAI_FAMILY = 0x5, /* ai_family not supported */ // 5
/*line: 191*/   EAI_MEMORY = 0x6, /* memory allocation failure */ // 6
/*line: 193*/   EAI_NODATA = 0x7, /* no address associated with hostname */ // 7
/*line: 195*/   EAI_NONAME = 0x8, /* hostname nor servname provided, or not known */ // 8
/*line: 196*/   EAI_SERVICE = 0x9, /* servname not supported for ai_socktype */ // 9
/*line: 197*/   EAI_SOCKTYPE = 0xa, /* ai_socktype not supported */ // 10
/*line: 198*/   EAI_SYSTEM = 0xb, /* system error returned in errno */ // 11
/*line: 200*/   EAI_BADHINTS = 0xc, /* invalid value for hints */ // 12
/*line: 201*/   EAI_PROTOCOL = 0xd, /* resolved protocol is unknown */ // 13
/*line: 203*/   EAI_OVERFLOW = 0xe, /* argument buffer overflow */ // 14
/*line: 205*/   EAI_MAX = 0xf,  // 15
};

// Depends on identifiers
enum macro_getaddrinfo_flags {
/*
 * Flag values for getaddrinfo()
 */
/*line: 211*/   AI_PASSIVE = 0x1, /* get address to use bind() */ // 0x00000001
/*line: 212*/   AI_CANONNAME = 0x2, /* fill ai_canonname */ // 0x00000002
/*line: 213*/   AI_NUMERICHOST = 0x4, /* prevent host name resolution */ // 0x00000004
/*line: 214*/   AI_NUMERICSERV = 0x1000, /* prevent service name resolution */ // 0x00001000
/*line: 217*/   AI_MASK = 0x1407,  // (AI_PASSIVE|AI_CANONNAME|AI_NUMERICHOST|AI_NUMERICSERV|AI_ADDRCONFIG)
/*line: 222*/   AI_ALL = 0x100, /* IPv6 and IPv4-mapped (with AI_V4MAPPED) */ // 0x00000100
/*line: 224*/   AI_V4MAPPED_CFG = 0x200, /* accept IPv4-mapped if kernel supports */ // 0x00000200
/*line: 226*/   AI_ADDRCONFIG = 0x400, /* only if any address is assigned */ // 0x00000400
/*line: 227*/   AI_V4MAPPED = 0x800, /* accept IPv4-mapped IPv6 address */ // 0x00000800
/*line: 230*/   AI_DEFAULT = 0x600,  // (AI_V4MAPPED_CFG|AI_ADDRCONFIG)
/* If the hints pointer is null or ai_flags is zero, getaddrinfo() automatically defaults to the AI_DEFAULT behavior.
 * To override this default behavior, thereby causing unusable addresses to be included in the results, pass any nonzero
 * value for ai_flags, by setting any desired flag values, or by setting AI_UNUSABLE if no other flags are desired. */
/*line: 234*/   AI_UNUSABLE = 0x10000000, /* return addresses even if unusable (i.e. opposite of AI_DEFAULT) */ // 0x10000000
};

enum macro_nameinfo_limits {
/*line: 241*/   NI_MAXHOST = 0x401,  // 1025
/*line: 242*/   NI_MAXSERV = 0x20,  // 32
};

enum macro_getnameinfo_flags {
/*
 * Flag values for getnameinfo()
 */
/*line: 247*/   NI_NOFQDN = 0x1,  // 0x00000001
/*line: 248*/   NI_NUMERICHOST = 0x2,  // 0x00000002
/*line: 249*/   NI_NAMEREQD = 0x4,  // 0x00000004
/*line: 250*/   NI_NUMERICSERV = 0x8,  // 0x00000008
/*line: 251*/   NI_NUMERICSCOPE = 0x100,  // 0x00000100
/*line: 252*/   NI_DGRAM = 0x10,  // 0x00000010
/*line: 254*/   NI_WITHSCOPEID = 0x20,  // 0x00000020
};

enum macro_scope_delimiter {
/*
 * Scope delimit character
 */
/*line: 259*/   SCOPE_DELIMITER = 0x25,  // '%'
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 119
// #define h_addr h_addr_list[0]

