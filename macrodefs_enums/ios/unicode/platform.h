// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/unicode/platform.h

enum macro_platform_id {
/** Unknown platform. @internal */
/*line: 89*/    U_PF_UNKNOWN = 0x0,  // 0
/** Windows @internal */
/*line: 91*/    U_PF_WINDOWS = 0x3e8,  // 1000
/** MinGW. Windows, calls to Win32 API, but using GNU gcc and binutils. @internal */
/*line: 93*/    U_PF_MINGW = 0x708,  // 1800
/**
 * Cygwin. Windows, calls to cygwin1.dll for Posix functions,
 * using MSVC or GNU gcc and binutils.
 * @internal
 */
/*line: 99*/    U_PF_CYGWIN = 0x76c,  // 1900
/** HP-UX is based on UNIX System V. @internal */
/*line: 102*/   U_PF_HPUX = 0x834,  // 2100
/** Solaris is a Unix operating system based on SVR4. @internal */
/*line: 104*/   U_PF_SOLARIS = 0xa28,  // 2600
/** BSD is a UNIX operating system derivative. @internal */
/*line: 106*/   U_PF_BSD = 0xbb8,  // 3000
/** AIX is based on UNIX System V Releases and 4.3 BSD. @internal */
/*line: 108*/   U_PF_AIX = 0xc1c,  // 3100
/** IRIX is based on UNIX System V with BSD extensions. @internal */
/*line: 110*/   U_PF_IRIX = 0xc80,  // 3200
/**
 * Darwin is a POSIX-compliant operating system, composed of code developed by Apple,
 * as well as code derived from NeXTSTEP, BSD, and other projects,
 * built around the Mach kernel.
 * Darwin forms the core set of components upon which Mac OS X, Apple TV, and iOS are based.
 * (Original description modified from WikiPedia.)
 * @internal
 */
/*line: 119*/   U_PF_DARWIN = 0xdac,  // 3500
/** iPhone OS (iOS) is a derivative of Mac OS X. @internal */
/*line: 121*/   U_PF_IPHONE = 0xdde,  // 3550
/** QNX is a commercial Unix-like real-time operating system related to BSD. @internal */
/*line: 123*/   U_PF_QNX = 0xe74,  // 3700
/** Linux is a Unix-like operating system. @internal */
/*line: 125*/   U_PF_LINUX = 0xfa0,  // 4000
/**
 * Native Client is pretty close to Linux.
 * See https://developer.chrome.com/native-client and
 *  http://www.chromium.org/nativeclient
 *  @internal
 */
/*line: 132*/   U_PF_BROWSER_NATIVE_CLIENT = 0xfb4,  // 4020
/** Android is based on Linux. @internal */
/*line: 134*/   U_PF_ANDROID = 0xfd2,  // 4050
/** Haiku is a POSIX-ish platform. @internal */
/*line: 136*/   U_PF_HAIKU = 0xff0,  // 4080
/** Fuchsia is a POSIX-ish platform. @internal */
/*line: 138*/   U_PF_FUCHSIA = 0x1004,  // 4100
/**
 * Emscripten is a C++ transpiler for the Web that can target asm.js or
 * WebAssembly. It provides some POSIX-compatible wrappers and stubs and
 * some Linux-like functionality, but is not fully compatible with
 * either.
 * @internal
 */
/*line: 147*/   U_PF_EMSCRIPTEN = 0x1392,  // 5010
/** z/OS is the successor to OS/390 which was the successor to MVS. @internal */
/*line: 149*/   U_PF_OS390 = 0x2328,  // 9000
/** "IBM i" is the current name of what used to be i5/OS and earlier OS/400. @internal */
/*line: 151*/   U_PF_OS400 = 0x24b8,  // 9400
};

// Depends on identifiers
enum macro_u_platform {
/*line: 176*/   U_PLATFORM = 0xdde,  // U_PF_IPHONE
};

enum macro_uses_win32_api {
/* Cygwin implements POSIX. */
/*line: 253*/   U_PLATFORM_USES_ONLY_WIN32_API = 0x0,  // 0
};

enum macro_has_win32_api {
/*line: 267*/   U_PLATFORM_HAS_WIN32_API = 0x0,  // 0
};

enum macro_u_platform_has_winuwp_api {
/*line: 279*/   U_PLATFORM_HAS_WINUWP_API = 0x0,  // 0
};

enum macro_posix_implementation {
/*line: 293*/   U_PLATFORM_IMPLEMENTS_POSIX = 0x1,  // 1
};

// Depends on identifiers
enum macro_platform_flags {
/*line: 306*/   U_PLATFORM_IS_LINUX_BASED = 0x0,  // 0
/*line: 317*/   U_PLATFORM_IS_DARWIN_BASED = 0x1,  // 1
/*line: 337*/   U_GCC_MAJOR_MINOR = 0x192,  // (__GNUC__*100+__GNUC_MINOR__)
};

enum macro_has_placement_new {
/*line: 381*/   U_HAVE_PLACEMENT_NEW = 0x1,  // 1
};

enum macro_debug_location_new {
/*line: 395*/   U_HAVE_DEBUG_LOCATION_NEW = 0x0,  // 0
};

enum macro_cpp_version {
/*line: 481*/   U_CPLUSPLUS_VERSION = 0x0,  // 0
};

enum macro_u_charset_family {
/**
 * U_CHARSET_FAMILY is equal to this value when the platform is an ASCII based platform.
 * @stable ICU 2.0
 */
/*line: 529*/   U_ASCII_FAMILY = 0x0,  // 0
};

enum macro_ebcdic_family {
/**
 * U_CHARSET_FAMILY is equal to this value when the platform is an EBCDIC based platform.
 * @stable ICU 2.0
 */
/*line: 535*/   U_EBCDIC_FAMILY = 0x1,  // 1
};

// Depends on identifiers
enum macro_charset_family {
/*line: 586*/   U_CHARSET_FAMILY = 0x0,  // U_ASCII_FAMILY
};

enum macro_is_utf8 {
/*line: 613*/   U_CHARSET_IS_UTF8 = 0x1,  // 1
};

enum macro_unicode_wchar_h {
/*line: 640*/   U_HAVE_WCHAR_H = 0x1,  // 1
};

enum macro_wchar_size {
/*line: 708*/   U_SIZEOF_WCHAR_T = 0x4,  // 4
};

// Depends on identifiers
enum macro_unicode_wcs_cpy {
/*line: 712*/   U_HAVE_WCSCPY = 0x1,  // U_HAVE_WCHAR_H
};

enum macro_have_char16_t {
/*line: 737*/   U_HAVE_CHAR16_T = 0x0,  // 0
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 353
// #define U_IS_BIG_ENDIAN (__BYTE_ORDER__===___ORDER_BIG_ENDIAN__)

// Line: 448
// #define U_MALLOC_ATTR __attribute__(((__malloc__))

// Line: 846
// #define U_CALLCONV U_EXPORT2

