// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/netinet6/ipsec.h

enum macro_ipsec_options {
/* according to IANA assignment, port 0x0000 and proto 0xff are reserved. */
/*line: 46*/    IPSEC_PORT_ANY = 0x0,  // 0
/*line: 47*/    IPSEC_ULPROTO_ANY = 0xff,  // 255
/*line: 48*/    IPSEC_PROTO_ANY = 0xff,  // 255
};

enum macro_ipsec_mode {
/* NOTE: DON'T use IPSEC_MODE_ANY at SPD.  It's only use in SAD */
/*line: 52*/    IPSEC_MODE_ANY = 0x0, /* i.e. wildcard. */ // 0
/*line: 53*/    IPSEC_MODE_TRANSPORT = 0x1,  // 1
/*line: 54*/    IPSEC_MODE_TUNNEL = 0x2,  // 2
};

enum macro_ipsec_direction {
/*
 * Direction of security policy.
 * NOTE: Since INVALID is used just as flag.
 * The other are used for loop counter too.
 */
/*line: 61*/    IPSEC_DIR_ANY = 0x0,  // 0
/*line: 62*/    IPSEC_DIR_INBOUND = 0x1,  // 1
/*line: 63*/    IPSEC_DIR_OUTBOUND = 0x2,  // 2
/*line: 64*/    IPSEC_DIR_MAX = 0x3,  // 3
/*line: 65*/    IPSEC_DIR_INVALID = 0x4,  // 4
};

enum macro_ipsec_policy {
/*
 * IPSEC, ENTRUST and BYPASS are allowed for setsockopt() in PCB,
 * DISCARD, IPSEC and NONE are allowed for setkey() in SPD.
 * DISCARD and NONE are allowed for system default.
 */
/*line: 73*/    IPSEC_POLICY_DISCARD = 0x0, /* discarding packet */ // 0
/*line: 74*/    IPSEC_POLICY_NONE = 0x1, /* through IPsec engine */ // 1
/*line: 75*/    IPSEC_POLICY_IPSEC = 0x2, /* do IPsec */ // 2
/*line: 76*/    IPSEC_POLICY_ENTRUST = 0x3, /* consulting SPD if present. */ // 3
/*line: 77*/    IPSEC_POLICY_BYPASS = 0x4, /* only for privileged socket. */ // 4
/*line: 78*/    IPSEC_POLICY_GENERATE = 0x5, /* same as discard - IKE daemon can override with generated policy */ // 5
};

enum macro_security_level {
/* Security protocol level */
/*line: 81*/    IPSEC_LEVEL_DEFAULT = 0x0, /* reference to system default */ // 0
/*line: 82*/    IPSEC_LEVEL_USE = 0x1, /* use SA if present. */ // 1
/*line: 83*/    IPSEC_LEVEL_REQUIRE = 0x2, /* require SA. */ // 2
/*line: 84*/    IPSEC_LEVEL_UNIQUE = 0x3, /* unique SA. */ // 3
/*line: 86*/    IPSEC_MANUAL_REQID_MAX = 0x3fff,  // 0x3fff
/*
 * if security policy level == unique, this id
 * indicate to a relative SA for use, else is
 * zero.
 * 1 - 0x3fff are reserved for manual keying.
 * 0 are reserved for above reason.  Others is
 * for kernel use.
 * Note that this id doesn't identify SA
 * by only itself.
 */
/*line: 97*/    IPSEC_REPLAYWSIZE = 0x20,  // 32
};

enum macro_key_max_bytes {
/*
 * Maximum key sizes in bytes expected to be passed from userspace.
 *
 * These values are based on the NULL algorithms for AH and ESP,
 * which both specify a keymax of 2048 bits.
 */
/*line: 105*/   IPSEC_KEY_AUTH_MAX_BYTES = 0x100,  // 256
/*line: 106*/   IPSEC_KEY_ENCRYPT_MAX_BYTES = 0x100,  // 256
};

enum macro_max_wake_pkt_len {
/*line: 138*/   IPSEC_MAX_WAKE_PKT_LEN = 0x64,  // 100
};

