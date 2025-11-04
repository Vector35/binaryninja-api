// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/notify.h

enum macro_notify_status {
/*! @defineblock Status Codes
 * Status codes returned by the API. See notify(3) for detailed description.
 */
/*line: 81*/    NOTIFY_STATUS_OK = 0x0,  // 0
/*line: 82*/    NOTIFY_STATUS_INVALID_NAME = 0x1,  // 1
/*line: 83*/    NOTIFY_STATUS_INVALID_TOKEN = 0x2,  // 2
/*line: 84*/    NOTIFY_STATUS_INVALID_PORT = 0x3,  // 3
/*line: 85*/    NOTIFY_STATUS_INVALID_FILE = 0x4,  // 4
/*line: 86*/    NOTIFY_STATUS_INVALID_SIGNAL = 0x5,  // 5
/*line: 87*/    NOTIFY_STATUS_INVALID_REQUEST = 0x6,  // 6
/*line: 88*/    NOTIFY_STATUS_NOT_AUTHORIZED = 0x7,  // 7
/*line: 89*/    NOTIFY_STATUS_OPT_DISABLE = 0x8,  // 8
/*line: 90*/    NOTIFY_STATUS_SERVER_NOT_FOUND = 0x9,  // 9
/*line: 91*/    NOTIFY_STATUS_NULL_INPUT = 0xa,  // 10
/*line: 93*/    NOTIFY_STATUS_FAILED = 0xf4240,  // 1000000
};

enum macro_reuse_flag {
/*!
 * Flag bits used for registration.
 */
/*line: 100*/   NOTIFY_REUSE = 0x1,  // 0x00000001
};

enum macro_notify_token {
/*!
 * Token values are zero or positive integers.
 * NOTIFY_TOKEN_INVALID is useful as an initial value for
 * a token value passed as an in/out parameter to one of
 * the registration routines below.
 */
/*line: 109*/   NOTIFY_TOKEN_INVALID = -0x1,  // -1
};

