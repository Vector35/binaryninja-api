// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/unicode/utf_old.h

enum macro_utf_size {
/*line: 161*/   U_HIDE_OBSOLETE_UTF_OLD_H = 0x0,  // 0
/** Number of bits in a Unicode string code unit - ICU uses 16-bit Unicode. @deprecated ICU 2.4. Obsolete, see utf_old.h. */
/*line: 180*/   UTF_SIZE = 0x10,  // 16
};

enum macro_utf8_errors {
/**
 * UTF8_ERROR_VALUE_1 and UTF8_ERROR_VALUE_2 are special error values for UTF-8,
 * which need 1 or 2 bytes in UTF-8:
 * \code
 * U+0015 = NAK = Negative Acknowledge, C0 control character
 * U+009f = highest C1 control character
 * \endcode
 *
 * These are used by UTF8_..._SAFE macros so that they can return an error value
 * that needs the same number of code units (bytes) as were seen by
 * a macro. They should be tested with UTF_IS_ERROR() or UTF_IS_VALID().
 *
 * @deprecated ICU 2.4. Obsolete, see utf_old.h.
 */
/*line: 208*/   UTF8_ERROR_VALUE_1 = 0x15,  // 0x15
/**
 * See documentation on UTF8_ERROR_VALUE_1 for details.
 *
 * @deprecated ICU 2.4. Obsolete, see utf_old.h.
 */
/*line: 215*/   UTF8_ERROR_VALUE_2 = 0x9f,  // 0x9f
/**
 * Error value for all UTFs. This code point value will be set by macros with error
 * checking if an error is detected.
 *
 * @deprecated ICU 2.4. Obsolete, see utf_old.h.
 */
/*line: 223*/   UTF_ERROR_VALUE = 0xffff,  // 0xffff
};

enum macro_utf8_max_length {
/** The maximum number of bytes per code point. @deprecated ICU 2.4. Renamed to U8_MAX_LENGTH, see utf_old.h. */
/*line: 362*/   UTF8_MAX_CHAR_LENGTH = 0x4,  // 4
};

enum macro_utf16_surrogate_offset {
/** Helper constant for UTF16_GET_PAIR_VALUE. @deprecated ICU 2.4. Renamed to U16_SURROGATE_OFFSET, see utf_old.h. */
/*line: 546*/   UTF_SURROGATE_OFFSET = 0x35fdc00,  // ((0xd800<<10UL)+0xdc00-0x10000)
};

enum macro_utf_length {
/** @deprecated ICU 2.4. Renamed to U16_MAX_LENGTH, see utf_old.h. */
/*line: 580*/   UTF16_MAX_CHAR_LENGTH = 0x2,  // 2
/** @deprecated ICU 2.4. Obsolete, see utf_old.h. */
/*line: 828*/   UTF32_MAX_CHAR_LENGTH = 0x1,  // 1
};

// Depends on identifiers
enum macro_utf_max_char_length {
/**
 * How many code units are used at most for any Unicode code point (2)?
 * Same as UTF16_MAX_CHAR_LENGTH.
 * @deprecated ICU 2.4. Renamed to U16_MAX_LENGTH, see utf_old.h.
 */
/*line: 1073*/  UTF_MAX_CHAR_LENGTH = 0x2,  // U16_MAX_LENGTH
};

