// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/libxml/parserInternals.h

enum macro_max_text_length {
/**
 * XML_MAX_TEXT_LENGTH:
 *
 * Maximum size allowed for a single text node when building a tree.
 * This is not a limitation of the parser but a safety boundary feature,
 * use XML_PARSE_HUGE option to override it.
 * Introduced in 2.9.0
 */
/*line: 41*/    XML_MAX_TEXT_LENGTH = 0x989680,  // 10000000
};

enum macro_max_name_length {
/**
 * XML_MAX_NAME_LENGTH:
 *
 * Maximum size allowed for a markup identifier.
 * This is not a limitation of the parser but a safety boundary feature,
 * use XML_PARSE_HUGE option to override it.
 * Note that with the use of parsing dictionaries overriding the limit
 * may result in more runtime memory usage in face of "unfriendly' content
 * Introduced in 2.9.0
 */
/*line: 53*/    XML_MAX_NAME_LENGTH = 0xc350,  // 50000
};

enum macro_max_dictionary_limit {
/**
 * XML_MAX_DICTIONARY_LIMIT:
 *
 * Maximum size allowed by the parser for a dictionary by default
 * This is not a limitation of the parser but a safety boundary feature,
 * use XML_PARSE_HUGE option to override it.
 * Introduced in 2.9.0
 */
/*line: 63*/    XML_MAX_DICTIONARY_LIMIT = 0x989680,  // 10000000
};

enum macro_max_lookup_limit {
/**
 * XML_MAX_LOOKUP_LIMIT:
 *
 * Maximum size allowed by the parser for ahead lookup
 * This is an upper boundary enforced by the parser to avoid bad
 * behaviour on "unfriendly' content
 * Introduced in 2.9.0
 */
/*line: 73*/    XML_MAX_LOOKUP_LIMIT = 0x989680,  // 10000000
};

enum macro_max_namelen {
/**
 * XML_MAX_NAMELEN:
 *
 * Identifiers can be longer, but this will be more costly
 * at runtime.
 */
/*line: 81*/    XML_MAX_NAMELEN = 0x64,  // 100
};

enum macro_input_chunk {
/**
 * INPUT_CHUNK:
 *
 * The parser tries to always have that amount of input ready.
 * One of the point is providing context when reporting errors.
 */
/*line: 89*/    INPUT_CHUNK = 0xfa,  // 250
};

enum macro_entity_substitution {
/**
 * XML_SUBSTITUTE_NONE:
 *
 * If no entities need to be substituted.
 */
/*line: 501*/   XML_SUBSTITUTE_NONE = 0x0,  // 0
/**
 * XML_SUBSTITUTE_REF:
 *
 * Whether general entities need to be substituted.
 */
/*line: 507*/   XML_SUBSTITUTE_REF = 0x1,  // 1
/**
 * XML_SUBSTITUTE_PEREF:
 *
 * Whether parameter entities need to be substituted.
 */
/*line: 513*/   XML_SUBSTITUTE_PEREF = 0x2,  // 2
/**
 * XML_SUBSTITUTE_BOTH:
 *
 * Both general and parameter entities need to be substituted.
 */
/*line: 519*/   XML_SUBSTITUTE_BOTH = 0x3,  // 3
};

