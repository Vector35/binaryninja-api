// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/asl.h

enum macro_asl_api_version {
/* Version number encodes the date YYYYMMDD */
/*line: 34*/    ASL_API_VERSION = 0x13377d1,  // 20150225
};

enum macro_log_level {
/*! @defineblock Log Message Priority Levels
 * Log levels of the message.
 */
/*line: 73*/    ASL_LEVEL_EMERG = 0x0,  // 0
/*line: 74*/    ASL_LEVEL_ALERT = 0x1,  // 1
/*line: 75*/    ASL_LEVEL_CRIT = 0x2,  // 2
/*line: 76*/    ASL_LEVEL_ERR = 0x3,  // 3
/*line: 77*/    ASL_LEVEL_WARNING = 0x4,  // 4
/*line: 78*/    ASL_LEVEL_NOTICE = 0x5,  // 5
/*line: 79*/    ASL_LEVEL_INFO = 0x6,  // 6
/*line: 80*/    ASL_LEVEL_DEBUG = 0x7,  // 7
};

enum macro_query_operations {
/*! @defineblock Attribute Matching
 * Attribute value comparison operations.
 */
/*line: 103*/   ASL_QUERY_OP_CASEFOLD = 0x10,  // 0x0010
/*line: 104*/   ASL_QUERY_OP_PREFIX = 0x20,  // 0x0020
/*line: 105*/   ASL_QUERY_OP_SUFFIX = 0x40,  // 0x0040
/*line: 106*/   ASL_QUERY_OP_SUBSTRING = 0x60,  // 0x0060
/*line: 107*/   ASL_QUERY_OP_NUMERIC = 0x80,  // 0x0080
/*line: 108*/   ASL_QUERY_OP_REGEX = 0x100,  // 0x0100
};

enum macro_query_operation {
/*line: 110*/   ASL_QUERY_OP_EQUAL = 0x1,  // 0x0001
/*line: 111*/   ASL_QUERY_OP_GREATER = 0x2,  // 0x0002
/*line: 112*/   ASL_QUERY_OP_GREATER_EQUAL = 0x3,  // 0x0003
/*line: 113*/   ASL_QUERY_OP_LESS = 0x4,  // 0x0004
/*line: 114*/   ASL_QUERY_OP_LESS_EQUAL = 0x5,  // 0x0005
/*line: 115*/   ASL_QUERY_OP_NOT_EQUAL = 0x6,  // 0x0006
/*line: 116*/   ASL_QUERY_OP_TRUE = 0x7,  // 0x0007
};

enum macro_asl_object_type {
/*! @defineblock ASL Object Types
 * The library uses only one opaque type - asl_object_t.
 * Many of the routines can operate on several different types.
 * For example, asl_search() can be used to search a list of messages,
 * an ASL database directory or data file, or the main ASL database.
 * It can even be used to check a single message against a query
 * message, or against another message to check for exact match.
 *
 * The first three types are container objects - messages, queries,
 * and lists of messages or queries.  The following types are
 * abstractions for ASL data files and ASL data stores (directories
 * containing data files).
 *
 * ASL_TYPE_CLIENT is a high-level object that abstracts ASL
 * interactions.  It may access ASL stores or files directly,
 * and it may communicate with ASL daemons.
 * 
 */
/*line: 175*/   ASL_TYPE_UNDEF = 0xffffffff,  // 0xffffffff
/*line: 176*/   ASL_TYPE_MSG = 0x0,  // 0
/*line: 177*/   ASL_TYPE_QUERY = 0x1,  // 1
/*line: 178*/   ASL_TYPE_LIST = 0x2,  // 2
/*line: 179*/   ASL_TYPE_FILE = 0x3,  // 3
/*line: 180*/   ASL_TYPE_STORE = 0x4,  // 4
/*line: 181*/   ASL_TYPE_CLIENT = 0x5,  // 5
};

enum macro_match_direction {
/*! @defineblock search directions
 * Used for asl_store_match(), asl_file_match(), and asl_match().
 */
/*line: 189*/   ASL_MATCH_DIRECTION_FORWARD = 0x1,  // 1
/*line: 190*/   ASL_MATCH_DIRECTION_REVERSE = -0x1,  // -1
};

enum macro_asl_filter_mask {
/*! @defineblock Filter Masks
 * Used in client-side filtering, which determines which
 * messages are sent by the client to the syslogd server.
 */
/*line: 199*/   ASL_FILTER_MASK_EMERG = 0x1,  // 0x01
/*line: 200*/   ASL_FILTER_MASK_ALERT = 0x2,  // 0x02
/*line: 201*/   ASL_FILTER_MASK_CRIT = 0x4,  // 0x04
/*line: 202*/   ASL_FILTER_MASK_ERR = 0x8,  // 0x08
/*line: 203*/   ASL_FILTER_MASK_WARNING = 0x10,  // 0x10
/*line: 204*/   ASL_FILTER_MASK_NOTICE = 0x20,  // 0x20
/*line: 205*/   ASL_FILTER_MASK_INFO = 0x40,  // 0x40
/*line: 206*/   ASL_FILTER_MASK_DEBUG = 0x80,  // 0x80
};

enum macro_asl_options {
/*! @defineblock Client Creation Options
 * Options for asl_open().
 * Note that ASL_OPT_NO_DELAY no longer has any effect.
 */
/*line: 224*/   ASL_OPT_STDERR = 0x1,  // 0x00000001
/*line: 225*/   ASL_OPT_NO_DELAY = 0x2,  // 0x00000002
/*line: 226*/   ASL_OPT_NO_REMOTE = 0x4,  // 0x00000004
};

enum macro_file_store_options {
/*! @defineblock File and Store Open Options
 * Options for asl_open_path().
 */
/*line: 234*/   ASL_OPT_OPEN_WRITE = 0x1,  // 0x00000001
/*line: 235*/   ASL_OPT_CREATE_STORE = 0x2,  // 0x00000002
};

enum macro_log_descriptor_type {
/*! @defineblock File Descriptor Types
 * Instructions on how to treat the file descriptor in asl_log_descriptor().
 */
/*line: 243*/   ASL_LOG_DESCRIPTOR_READ = 0x1,  // 1
/*line: 244*/   ASL_LOG_DESCRIPTOR_WRITE = 0x2,  // 2
};

enum macro_asl_encoding {
/*! @defineblock Text Encoding Types
 * These are used by the library when formatting messages to be written 
 * to file descriptors associated with an ASL client handle with 
 * asl_add_output_file().  The syslog(1) manual page describes text encoding
 * in detail.  ASL_ENCODE_ASL corresponds to the "vis" encoding option
 * described in the syslog(1) manual.  ASL_ENCODE_XML should be used in
 * combination with ASL_MSG_FMT_XML to ensure that special XML characters
 * are correctly encoded.
 */
/*line: 275*/   ASL_ENCODE_NONE = 0x0,  // 0
/*line: 276*/   ASL_ENCODE_SAFE = 0x1,  // 1
/*line: 277*/   ASL_ENCODE_ASL = 0x2,  // 2
/*line: 278*/   ASL_ENCODE_XML = 0x3,  // 3
};

