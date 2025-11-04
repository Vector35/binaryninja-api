// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/_regex.h

enum macro_regex_compile_flags {
/*line: 129*/   REG_BASIC = 0x0, /* Basic regular expressions (synonym for 0) */ // 0000
/*line: 132*/   REG_EXTENDED = 0x1, /* Extended regular expressions */ // 0001
/*line: 133*/   REG_ICASE = 0x2, /* Compile ignoring upper/lower case */ // 0002
/*line: 134*/   REG_NOSUB = 0x4, /* Compile only reporting success/failure */ // 0004
/*line: 135*/   REG_NEWLINE = 0x8, /* Compile for newline-sensitive matching */ // 0010
/*line: 138*/   REG_NOSPEC = 0x10, /* Compile turning off all special characters */ // 0020
/*line: 143*/   REG_LITERAL = 0x10,  // REG_NOSPEC
/*line: 146*/   REG_PEND = 0x20, /* Use re_endp as end pointer */ // 0040
/*line: 151*/   REG_MINIMAL = 0x40, /* Compile using minimal repetition */ // 0100
/*line: 152*/   REG_UNGREEDY = 0x40,  // REG_MINIMAL
/*line: 155*/   REG_DUMP = 0x80, /* Unused */ // 0200
/*line: 160*/   REG_ENHANCED = 0x100, /* Additional (non-POSIX) features */ // 0400
};

enum macro_regex_error {
/********************/
/*line: 167*/   REG_ENOSYS = -0x1, /* Reserved */ // (-1)
/*line: 168*/   REG_NOMATCH = 0x1, /* regexec() function failed to match */ // 1
/*line: 169*/   REG_BADPAT = 0x2, /* invalid regular expression */ // 2
/*line: 170*/   REG_ECOLLATE = 0x3, /* invalid collating element */ // 3
/*line: 171*/   REG_ECTYPE = 0x4, /* invalid character class */ // 4
/*line: 172*/   REG_EESCAPE = 0x5, /* trailing backslash (\) */ // 5
/*line: 173*/   REG_ESUBREG = 0x6, /* invalid backreference number */ // 6
/*line: 174*/   REG_EBRACK = 0x7, /* brackets ([ ]) not balanced */ // 7
/*line: 175*/   REG_EPAREN = 0x8, /* parentheses not balanced */ // 8
/*line: 176*/   REG_EBRACE = 0x9, /* braces not balanced */ // 9
/*line: 177*/   REG_BADBR = 0xa, /* invalid repetition count(s) */ // 10
/*line: 178*/   REG_ERANGE = 0xb, /* invalid character range */ // 11
/*line: 179*/   REG_ESPACE = 0xc, /* out of memory */ // 12
/*line: 180*/   REG_BADRPT = 0xd, /* repetition-operator operand invalid */ // 13
/*line: 183*/   REG_EMPTY = 0xe, /* Unused */ // 14
/*line: 184*/   REG_ASSERT = 0xf, /* Unused */ // 15
/*line: 185*/   REG_INVARG = 0x10, /* invalid argument to regex routine */ // 16
/*line: 186*/   REG_ILLSEQ = 0x11, /* illegal byte sequence */ // 17
/*line: 188*/   REG_ATOI = 0xff, /* convert name to number (!) */ // 255
/*line: 189*/   REG_ITOA = 0x100, /* convert number to name (!) */ // 0400
};

enum macro_regex_exec_flags {
/*******************/
/*line: 195*/   REG_NOTBOL = 0x1, /* First character not at beginning of line */ // 00001
/*line: 196*/   REG_NOTEOL = 0x2, /* Last character not at end of line */ // 00002
/*line: 199*/   REG_STARTEND = 0x4, /* String start/end in pmatch[0] */ // 00004
/*line: 200*/   REG_TRACE = 0x100, /* Unused */ // 00400
/*line: 201*/   REG_LARGE = 0x200, /* Unused */ // 01000
/*line: 202*/   REG_BACKR = 0x400, /* force use of backref code */ // 02000
};

// Depends on identifiers
enum macro_reg_backtracking_matcher {
/*line: 207*/   REG_BACKTRACKING_MATCHER = 0x400,  // REG_BACKR
};

