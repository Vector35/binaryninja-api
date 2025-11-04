// Correctnes: bad
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/unicode/stringoptions.h

enum macro_unicode_options {
/**
 * Option value for case folding: Use default mappings defined in CaseFolding.txt.
 *
 * @stable ICU 2.0
 */
/*line: 22*/    U_FOLD_CASE_DEFAULT = 0x0,  // 0
/**
 * Option value for case folding:
 *
 * Use the modified set of mappings provided in CaseFolding.txt to handle dotted I
 * and dotless i appropriately for Turkic languages (tr, az).
 *
 * Before Unicode 3.2, CaseFolding.txt contains mappings marked with 'I' that
 * are to be included for default mappings and
 * excluded for the Turkic-specific mappings.
 *
 * Unicode 3.2 CaseFolding.txt instead contains mappings marked with 'T' that
 * are to be excluded for default mappings and
 * included for the Turkic-specific mappings.
 *
 * @stable ICU 2.0
 */
/*line: 40*/    U_FOLD_CASE_EXCLUDE_SPECIAL_I = 0x1,  // 1
/**
 * Titlecase the string as a whole rather than each word.
 * (Titlecase only the character at index 0, possibly adjusted.)
 * Option bits value for titlecasing APIs that take an options bit set.
 *
 * It is an error to specify multiple titlecasing iterator options together,
 * including both an options bit and an explicit BreakIterator.
 *
 * @see U_TITLECASE_ADJUST_TO_CASED
 * @stable ICU 60
 */
/*line: 53*/    U_TITLECASE_WHOLE_STRING = 0x20,  // 0x20
/**
 * Titlecase sentences rather than words.
 * (Titlecase only the first character of each sentence, possibly adjusted.)
 * Option bits value for titlecasing APIs that take an options bit set.
 *
 * It is an error to specify multiple titlecasing iterator options together,
 * including both an options bit and an explicit BreakIterator.
 *
 * @see U_TITLECASE_ADJUST_TO_CASED
 * @stable ICU 60
 */
/*line: 66*/    U_TITLECASE_SENTENCES = 0x40,  // 0x40
/**
 * Do not lowercase non-initial parts of words when titlecasing.
 * Option bit for titlecasing APIs that take an options bit set.
 *
 * By default, titlecasing will titlecase the character at each
 * (possibly adjusted) BreakIterator index and
 * lowercase all other characters up to the next iterator index.
 * With this option, the other characters will not be modified.
 *
 * @see U_TITLECASE_ADJUST_TO_CASED
 * @see UnicodeString::toTitle
 * @see CaseMap::toTitle
 * @see ucasemap_setOptions
 * @see ucasemap_toTitle
 * @see ucasemap_utf8ToTitle
 * @stable ICU 3.8
 */
/*line: 85*/    U_TITLECASE_NO_LOWERCASE = 0x100,  // 0x100
/**
 * Do not adjust the titlecasing BreakIterator indexes;
 * titlecase exactly the characters at breaks from the iterator.
 * Option bit for titlecasing APIs that take an options bit set.
 *
 * By default, titlecasing will take each break iterator index,
 * adjust it to the next relevant character (see U_TITLECASE_ADJUST_TO_CASED),
 * and titlecase that one.
 *
 * Other characters are lowercased.
 *
 * It is an error to specify multiple titlecasing adjustment options together.
 *
 * @see U_TITLECASE_ADJUST_TO_CASED
 * @see U_TITLECASE_NO_LOWERCASE
 * @see UnicodeString::toTitle
 * @see CaseMap::toTitle
 * @see ucasemap_setOptions
 * @see ucasemap_toTitle
 * @see ucasemap_utf8ToTitle
 * @stable ICU 3.8
 */
/*line: 109*/   U_TITLECASE_NO_BREAK_ADJUSTMENT = 0x200,  // 0x200
/**
 * Adjust each titlecasing BreakIterator index to the next cased character.
 * (See the Unicode Standard, chapter 3, Default Case Conversion, R3 toTitlecase(X).)
 * Option bit for titlecasing APIs that take an options bit set.
 *
 * This used to be the default index adjustment in ICU.
 * Since ICU 60, the default index adjustment is to the next character that is
 * a letter, number, symbol, or private use code point.
 * (Uncased modifier letters are skipped.)
 * The difference in behavior is small for word titlecasing,
 * but the new adjustment is much better for whole-string and sentence titlecasing:
 * It yields "49ers" and "«丰(abc)»" instead of "49Ers" and "«丰(Abc)»".
 *
 * It is an error to specify multiple titlecasing adjustment options together.
 *
 * @see U_TITLECASE_NO_BREAK_ADJUSTMENT
 * @stable ICU 60
 */
/*line: 129*/   U_TITLECASE_ADJUST_TO_CASED = 0x400,  // 0x400
/**
 * Option for string transformation functions to not first reset the Edits object.
 * Used for example in some case-mapping and normalization functions.
 *
 * @see CaseMap
 * @see Edits
 * @see Normalizer2
 * @stable ICU 60
 */
/*line: 140*/   U_EDITS_NO_RESET = 0x2000,  // 0x2000
/**
 * Omit unchanged text when recording how source substrings
 * relate to changed and unchanged result substrings.
 * Used for example in some case-mapping and normalization functions.
 *
 * @see CaseMap
 * @see Edits
 * @see Normalizer2
 * @stable ICU 60
 */
/*line: 152*/   U_OMIT_UNCHANGED_TEXT = 0x4000,  // 0x4000
/**
 * Option bit for u_strCaseCompare, u_strcasecmp, unorm_compare, etc:
 * Compare strings in code point order instead of code unit order.
 * @stable ICU 2.2
 */
/*line: 159*/   U_COMPARE_CODE_POINT_ORDER = 0x8000,  // 0x8000
/**
 * Option bit for unorm_compare:
 * Perform case-insensitive comparison.
 * @stable ICU 2.2
 */
/*line: 166*/   U_COMPARE_IGNORE_CASE = 0x10000,  // 0x10000
};

enum macro_unorm_input_is_fcd {
/**
 * Option bit for unorm_compare:
 * Both input strings are assumed to fulfill FCD conditions.
 * @stable ICU 2.2
 */
/*line: 173*/   UNORM_INPUT_IS_FCD = 0x20000,  // 0x20000
};

