// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/mach/mig_errors.h

enum macro_mig_errors {
/*
 *	These error codes should be specified as system 4, subsytem 2.
 *	But alas backwards compatibility makes that impossible.
 *	The problem is old clients of new servers (eg, the kernel)
 *	which get strange large error codes when there is a Mig problem
 *	in the server.  Unfortunately, the IPC system doesn't have
 *	the knowledge to convert the codes in this situation.
 */
/*line: 82*/    MIG_TYPE_ERROR = -0x12c, /* client type check failure */ // -300
/*line: 83*/    MIG_REPLY_MISMATCH = -0x12d, /* wrong reply message ID */ // -301
/*line: 84*/    MIG_REMOTE_ERROR = -0x12e, /* server detected error */ // -302
/*line: 85*/    MIG_BAD_ID = -0x12f, /* bad request message ID */ // -303
/*line: 86*/    MIG_BAD_ARGUMENTS = -0x130, /* server type check failure */ // -304
/*line: 87*/    MIG_NO_REPLY = -0x131, /* no reply should be send */ // -305
/*line: 88*/    MIG_EXCEPTION = -0x132, /* server raised exception */ // -306
/*line: 89*/    MIG_ARRAY_TOO_LARGE = -0x133, /* array not large enough */ // -307
/*line: 90*/    MIG_SERVER_DIED = -0x134, /* server died */ // -308
/*line: 91*/    MIG_TRAILER_ERROR = -0x135, /* trailer has an unknown format */ // -309
};

