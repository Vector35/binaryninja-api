// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/unicode/uchar.h

enum macro_unicode_range {
/** The lowest Unicode code point value. Code points are non-negative. @stable ICU 2.0 */
/*line: 158*/   UCHAR_MIN_VALUE = 0x0,  // 0
/**
 * The highest Unicode code point value (scalar value) according to
 * The Unicode Standard. This is a 21-bit value (20.1 bits, rounded up).
 * For a single character, UChar32 is a simple type that can hold any code point value.
 *
 * @see UChar32
 * @stable ICU 2.0
 */
/*line: 168*/   UCHAR_MAX_VALUE = 0x10ffff,  // 0x10ffff
};

/* ======== UNRESOLVED MACROS SECTION ======== */
// Line: 927
// #define U_GC_CN_MASK U_MASK(U_GENERAL_OTHER_TYPES)

// Line: 930
// #define U_GC_LU_MASK U_MASK(U_UPPERCASE_LETTER)

// Line: 932
// #define U_GC_LL_MASK U_MASK(U_LOWERCASE_LETTER)

// Line: 934
// #define U_GC_LT_MASK U_MASK(U_TITLECASE_LETTER)

// Line: 936
// #define U_GC_LM_MASK U_MASK(U_MODIFIER_LETTER)

// Line: 938
// #define U_GC_LO_MASK U_MASK(U_OTHER_LETTER)

// Line: 941
// #define U_GC_MN_MASK U_MASK(U_NON_SPACING_MARK)

// Line: 943
// #define U_GC_ME_MASK U_MASK(U_ENCLOSING_MARK)

// Line: 945
// #define U_GC_MC_MASK U_MASK(U_COMBINING_SPACING_MARK)

// Line: 948
// #define U_GC_ND_MASK U_MASK(U_DECIMAL_DIGIT_NUMBER)

// Line: 950
// #define U_GC_NL_MASK U_MASK(U_LETTER_NUMBER)

// Line: 952
// #define U_GC_NO_MASK U_MASK(U_OTHER_NUMBER)

// Line: 955
// #define U_GC_ZS_MASK U_MASK(U_SPACE_SEPARATOR)

// Line: 957
// #define U_GC_ZL_MASK U_MASK(U_LINE_SEPARATOR)

// Line: 959
// #define U_GC_ZP_MASK U_MASK(U_PARAGRAPH_SEPARATOR)

// Line: 962
// #define U_GC_CC_MASK U_MASK(U_CONTROL_CHAR)

// Line: 964
// #define U_GC_CF_MASK U_MASK(U_FORMAT_CHAR)

// Line: 966
// #define U_GC_CO_MASK U_MASK(U_PRIVATE_USE_CHAR)

// Line: 968
// #define U_GC_CS_MASK U_MASK(U_SURROGATE)

// Line: 971
// #define U_GC_PD_MASK U_MASK(U_DASH_PUNCTUATION)

// Line: 973
// #define U_GC_PS_MASK U_MASK(U_START_PUNCTUATION)

// Line: 975
// #define U_GC_PE_MASK U_MASK(U_END_PUNCTUATION)

// Line: 977
// #define U_GC_PC_MASK U_MASK(U_CONNECTOR_PUNCTUATION)

// Line: 979
// #define U_GC_PO_MASK U_MASK(U_OTHER_PUNCTUATION)

// Line: 982
// #define U_GC_SM_MASK U_MASK(U_MATH_SYMBOL)

// Line: 984
// #define U_GC_SC_MASK U_MASK(U_CURRENCY_SYMBOL)

// Line: 986
// #define U_GC_SK_MASK U_MASK(U_MODIFIER_SYMBOL)

// Line: 988
// #define U_GC_SO_MASK U_MASK(U_OTHER_SYMBOL)

// Line: 991
// #define U_GC_PI_MASK U_MASK(U_INITIAL_PUNCTUATION)

// Line: 993
// #define U_GC_PF_MASK U_MASK(U_FINAL_PUNCTUATION)

// Line: 997
// #define U_GC_L_MASK (U_GC_LU_MASK|U_GC_LL_MASK|U_GC_LT_MASK|U_GC_LM_MASK|U_GC_LO_MASK)

// Line: 1001
// #define U_GC_LC_MASK (U_GC_LU_MASK|U_GC_LL_MASK|U_GC_LT_MASK)

// Line: 1005
// #define U_GC_M_MASK (U_GC_MN_MASK|U_GC_ME_MASK|U_GC_MC_MASK)

// Line: 1008
// #define U_GC_N_MASK (U_GC_ND_MASK|U_GC_NL_MASK|U_GC_NO_MASK)

// Line: 1011
// #define U_GC_Z_MASK (U_GC_ZS_MASK|U_GC_ZL_MASK|U_GC_ZP_MASK)

// Line: 1014
// #define U_GC_C_MASK (U_GC_CN_MASK|U_GC_CC_MASK|U_GC_CF_MASK|U_GC_CO_MASK|U_GC_CS_MASK)

// Line: 1018
// #define U_GC_P_MASK (U_GC_PD_MASK|U_GC_PS_MASK|U_GC_PE_MASK|U_GC_PC_MASK|U_GC_PO_MASK|\
//              UU_GC_PI_MASK|U_GC_PF_MASK)

// Line: 1023
// #define U_GC_S_MASK (U_GC_SM_MASK|U_GC_SC_MASK|U_GC_SK_MASK|U_GC_SO_MASK)

// Line: 3138
// #define U_NO_NUMERIC_VALUE ((double)-123456789.)

