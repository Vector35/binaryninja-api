// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/sys/errno.h

// Depends on identifiers
enum macro_errno_codes {
/*
 * Error codes
 */
/*line: 88*/    EPERM = 0x1, /* Operation not permitted */ // 1
/*line: 89*/    ENOENT = 0x2, /* No such file or directory */ // 2
/*line: 90*/    ESRCH = 0x3, /* No such process */ // 3
/*line: 91*/    EINTR = 0x4, /* Interrupted system call */ // 4
/*line: 92*/    EIO = 0x5, /* Input/output error */ // 5
/*line: 93*/    ENXIO = 0x6, /* Device not configured */ // 6
/*line: 94*/    E2BIG = 0x7, /* Argument list too long */ // 7
/*line: 95*/    ENOEXEC = 0x8, /* Exec format error */ // 8
/*line: 96*/    EBADF = 0x9, /* Bad file descriptor */ // 9
/*line: 97*/    ECHILD = 0xa, /* No child processes */ // 10
/*line: 98*/    EDEADLK = 0xb, /* Resource deadlock avoided */ // 11
/* 11 was EAGAIN */
/*line: 100*/   ENOMEM = 0xc, /* Cannot allocate memory */ // 12
/*line: 101*/   EACCES = 0xd, /* Permission denied */ // 13
/*line: 102*/   EFAULT = 0xe, /* Bad address */ // 14
/*line: 104*/   ENOTBLK = 0xf, /* Block device required */ // 15
/*line: 106*/   EBUSY = 0x10, /* Device / Resource busy */ // 16
/*line: 107*/   EEXIST = 0x11, /* File exists */ // 17
/*line: 108*/   EXDEV = 0x12, /* Cross-device link */ // 18
/*line: 109*/   ENODEV = 0x13, /* Operation not supported by device */ // 19
/*line: 110*/   ENOTDIR = 0x14, /* Not a directory */ // 20
/*line: 111*/   EISDIR = 0x15, /* Is a directory */ // 21
/*line: 112*/   EINVAL = 0x16, /* Invalid argument */ // 22
/*line: 113*/   ENFILE = 0x17, /* Too many open files in system */ // 23
/*line: 114*/   EMFILE = 0x18, /* Too many open files */ // 24
/*line: 115*/   ENOTTY = 0x19, /* Inappropriate ioctl for device */ // 25
/*line: 116*/   ETXTBSY = 0x1a, /* Text file busy */ // 26
/*line: 117*/   EFBIG = 0x1b, /* File too large */ // 27
/*line: 118*/   ENOSPC = 0x1c, /* No space left on device */ // 28
/*line: 119*/   ESPIPE = 0x1d, /* Illegal seek */ // 29
/*line: 120*/   EROFS = 0x1e, /* Read-only file system */ // 30
/*line: 121*/   EMLINK = 0x1f, /* Too many links */ // 31
/*line: 122*/   EPIPE = 0x20, /* Broken pipe */ // 32
/* math software */
/*line: 125*/   EDOM = 0x21, /* Numerical argument out of domain */ // 33
/*line: 126*/   ERANGE = 0x22, /* Result too large */ // 34
/* non-blocking and interrupt i/o */
/*line: 129*/   EAGAIN = 0x23, /* Resource temporarily unavailable */ // 35
/*line: 130*/   EWOULDBLOCK = 0x23, /* Operation would block */ // EAGAIN
/*line: 131*/   EINPROGRESS = 0x24, /* Operation now in progress */ // 36
/*line: 132*/   EALREADY = 0x25, /* Operation already in progress */ // 37
/* ipc/network software -- argument errors */
/*line: 135*/   ENOTSOCK = 0x26, /* Socket operation on non-socket */ // 38
/*line: 136*/   EDESTADDRREQ = 0x27, /* Destination address required */ // 39
/*line: 137*/   EMSGSIZE = 0x28, /* Message too long */ // 40
/*line: 138*/   EPROTOTYPE = 0x29, /* Protocol wrong type for socket */ // 41
/*line: 139*/   ENOPROTOOPT = 0x2a, /* Protocol not available */ // 42
/*line: 140*/   EPROTONOSUPPORT = 0x2b, /* Protocol not supported */ // 43
/*line: 142*/   ESOCKTNOSUPPORT = 0x2c, /* Socket type not supported */ // 44
/*line: 144*/   ENOTSUP = 0x2d, /* Operation not supported */ // 45
/*line: 158*/   EPFNOSUPPORT = 0x2e, /* Protocol family not supported */ // 46
/*line: 160*/   EAFNOSUPPORT = 0x2f, /* Address family not supported by protocol family */ // 47
/*line: 161*/   EADDRINUSE = 0x30, /* Address already in use */ // 48
/*line: 162*/   EADDRNOTAVAIL = 0x31, /* Can't assign requested address */ // 49
/* ipc/network software -- operational errors */
/*line: 165*/   ENETDOWN = 0x32, /* Network is down */ // 50
/*line: 166*/   ENETUNREACH = 0x33, /* Network is unreachable */ // 51
/*line: 167*/   ENETRESET = 0x34, /* Network dropped connection on reset */ // 52
/*line: 168*/   ECONNABORTED = 0x35, /* Software caused connection abort */ // 53
/*line: 169*/   ECONNRESET = 0x36, /* Connection reset by peer */ // 54
/*line: 170*/   ENOBUFS = 0x37, /* No buffer space available */ // 55
/*line: 171*/   EISCONN = 0x38, /* Socket is already connected */ // 56
/*line: 172*/   ENOTCONN = 0x39, /* Socket is not connected */ // 57
/*line: 174*/   ESHUTDOWN = 0x3a, /* Can't send after socket shutdown */ // 58
/*line: 175*/   ETOOMANYREFS = 0x3b, /* Too many references: can't splice */ // 59
/*line: 177*/   ETIMEDOUT = 0x3c, /* Operation timed out */ // 60
/*line: 178*/   ECONNREFUSED = 0x3d, /* Connection refused */ // 61
/*line: 180*/   ELOOP = 0x3e, /* Too many levels of symbolic links */ // 62
/*line: 181*/   ENAMETOOLONG = 0x3f, /* File name too long */ // 63
/*line: 185*/   EHOSTDOWN = 0x40, /* Host is down */ // 64
/*line: 187*/   EHOSTUNREACH = 0x41, /* No route to host */ // 65
/*line: 188*/   ENOTEMPTY = 0x42, /* Directory not empty */ // 66
/*line: 192*/   EPROCLIM = 0x43, /* Too many processes */ // 67
/*line: 193*/   EUSERS = 0x44, /* Too many users */ // 68
/*line: 195*/   EDQUOT = 0x45, /* Disc quota exceeded */ // 69
/* Network File System */
/*line: 198*/   ESTALE = 0x46, /* Stale NFS file handle */ // 70
/*line: 200*/   EREMOTE = 0x47, /* Too many levels of remote in path */ // 71
/*line: 201*/   EBADRPC = 0x48, /* RPC struct is bad */ // 72
/*line: 202*/   ERPCMISMATCH = 0x49, /* RPC version wrong */ // 73
/*line: 203*/   EPROGUNAVAIL = 0x4a, /* RPC prog. not avail */ // 74
/*line: 204*/   EPROGMISMATCH = 0x4b, /* Program version wrong */ // 75
/*line: 205*/   EPROCUNAVAIL = 0x4c, /* Bad procedure for program */ // 76
/*line: 208*/   ENOLCK = 0x4d, /* No locks available */ // 77
/*line: 209*/   ENOSYS = 0x4e, /* Function not implemented */ // 78
/*line: 212*/   EFTYPE = 0x4f, /* Inappropriate file type or format */ // 79
/*line: 213*/   EAUTH = 0x50, /* Authentication error */ // 80
/*line: 214*/   ENEEDAUTH = 0x51, /* Need authenticator */ // 81
/* Intelligent device errors */
/*line: 217*/   EPWROFF = 0x52, /* Device power is off */ // 82
/*line: 218*/   EDEVERR = 0x53, /* Device error, e.g. paper out */ // 83
/*line: 221*/   EOVERFLOW = 0x54, /* Value too large to be stored in data type */ // 84
/*line: 225*/   EBADEXEC = 0x55, /* Bad executable */ // 85
/*line: 226*/   EBADARCH = 0x56, /* Bad CPU type in executable */ // 86
/*line: 227*/   ESHLIBVERS = 0x57, /* Shared library version mismatch */ // 87
/*line: 228*/   EBADMACHO = 0x58, /* Malformed Macho file */ // 88
/*line: 231*/   ECANCELED = 0x59, /* Operation canceled */ // 89
/*line: 233*/   EIDRM = 0x5a, /* Identifier removed */ // 90
/*line: 234*/   ENOMSG = 0x5b, /* No message of desired type */ // 91
/*line: 235*/   EILSEQ = 0x5c, /* Illegal byte sequence */ // 92
/*line: 237*/   ENOATTR = 0x5d, /* Attribute not found */ // 93
/*line: 240*/   EBADMSG = 0x5e, /* Bad message */ // 94
/*line: 241*/   EMULTIHOP = 0x5f, /* Reserved */ // 95
/*line: 242*/   ENODATA = 0x60, /* No message available on STREAM */ // 96
/*line: 243*/   ENOLINK = 0x61, /* Reserved */ // 97
/*line: 244*/   ENOSR = 0x62, /* No STREAM resources */ // 98
/*line: 245*/   ENOSTR = 0x63, /* Not a STREAM */ // 99
/*line: 246*/   EPROTO = 0x64, /* Protocol error */ // 100
/*line: 247*/   ETIME = 0x65, /* STREAM ioctl timeout */ // 101
/* This value is only discrete when compiling __DARWIN_UNIX03, or KERNEL */
/*line: 251*/   EOPNOTSUPP = 0x66, /* Operation not supported on socket */ // 102
/*line: 254*/   ENOPOLICY = 0x67, /* No such policy registered */ // 103
/*line: 257*/   ENOTRECOVERABLE = 0x68, /* State not recoverable */ // 104
/*line: 258*/   EOWNERDEAD = 0x69, /* Previous owner died */ // 105
/*line: 262*/   EQFULL = 0x6a, /* Interface output queue is full */ // 106
/*line: 263*/   ELAST = 0x6a, /* Must be equal largest errno */ // 106
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 81
// #define errno (*__error())

