// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/readpassphrase.h

enum macro_readpassphrase_flags {
/*line: 24*/    RPP_ECHO_OFF = 0x0, /* Turn off echo (default). */ // 0x00
/*line: 25*/    RPP_ECHO_ON = 0x1, /* Leave echo on. */ // 0x01
/*line: 26*/    RPP_REQUIRE_TTY = 0x2, /* Fail if there is no tty. */ // 0x02
/*line: 27*/    RPP_FORCELOWER = 0x4, /* Force input to lower case. */ // 0x04
/*line: 28*/    RPP_FORCEUPPER = 0x8, /* Force input to upper case. */ // 0x08
/*line: 29*/    RPP_SEVENBIT = 0x10, /* Strip the high bit from input. */ // 0x10
/*line: 30*/    RPP_STDIN = 0x20, /* Read from stdin, not /dev/tty */ // 0x20
};

