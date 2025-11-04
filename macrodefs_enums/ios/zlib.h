// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/zlib.h

enum macro_zlib_version {
/*line: 47*/    ZLIB_VERNUM = 0x12c0,  // 0x12c0
/*line: 48*/    ZLIB_VER_MAJOR = 0x1,  // 1
/*line: 49*/    ZLIB_VER_MINOR = 0x2,  // 2
/*line: 50*/    ZLIB_VER_REVISION = 0xc,  // 12
/*line: 51*/    ZLIB_VER_SUBREVISION = 0x0,  // 0
};

enum macro_zlib_flush {
/* constants */
/*line: 174*/   Z_NO_FLUSH = 0x0,  // 0
/*line: 175*/   Z_PARTIAL_FLUSH = 0x1,  // 1
/*line: 176*/   Z_SYNC_FLUSH = 0x2,  // 2
/*line: 177*/   Z_FULL_FLUSH = 0x3,  // 3
/*line: 178*/   Z_FINISH = 0x4,  // 4
/*line: 179*/   Z_BLOCK = 0x5,  // 5
/*line: 180*/   Z_TREES = 0x6,  // 6
};

// Depends on identifiers
enum macro_zlib_return_codes {
/* Allowed flush values; see deflate() and inflate() below for details */
/*line: 183*/   Z_OK = 0x0,  // 0
/*line: 184*/   Z_STREAM_END = 0x1,  // 1
/*line: 185*/   Z_NEED_DICT = 0x2,  // 2
/*line: 186*/   Z_ERRNO = -0x1,  // (-1)
/*line: 187*/   Z_STREAM_ERROR = -0x2,  // (-2)
/*line: 188*/   Z_DATA_ERROR = -0x3,  // (-3)
/*line: 189*/   Z_MEM_ERROR = -0x4,  // (-4)
/*line: 190*/   Z_BUF_ERROR = -0x5,  // (-5)
/*line: 191*/   Z_VERSION_ERROR = -0x6,  // (-6)
/* Return codes for the compression/decompression functions. Negative values
 * are errors, positive values are used for special but normal events.
 */
/*line: 196*/   Z_NO_COMPRESSION = 0x0,  // 0
/*line: 197*/   Z_BEST_SPEED = 0x1,  // 1
/*line: 198*/   Z_BEST_COMPRESSION = 0x9,  // 9
/*line: 199*/   Z_DEFAULT_COMPRESSION = -0x1,  // (-1)
/* compression levels */
/*line: 202*/   Z_FILTERED = 0x1,  // 1
/*line: 203*/   Z_HUFFMAN_ONLY = 0x2,  // 2
/*line: 204*/   Z_RLE = 0x3,  // 3
/*line: 205*/   Z_FIXED = 0x4,  // 4
/*line: 206*/   Z_DEFAULT_STRATEGY = 0x0,  // 0
/* compression strategy; see deflateInit2() below for details */
/*line: 209*/   Z_BINARY = 0x0,  // 0
/*line: 210*/   Z_TEXT = 0x1,  // 1
/*line: 211*/   Z_ASCII = 0x1, /* for compatibility with 1.2.2 and earlier */ // Z_TEXT
/*line: 212*/   Z_UNKNOWN = 0x2,  // 2
};

enum macro_data_type {
/* Possible values of the data_type field for deflate() */
/*line: 215*/   Z_DEFLATED = 0x8,  // 8
};

enum macro_zlib_null {
/* The deflate compression method (the only one supported in this version) */
/*line: 218*/   Z_NULL = 0x0, /* for initializing zalloc, zfree, opaque */ // 0
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 220
// #define zlib_version zlibVersion()

