// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/setjmp.h

enum macro_jmp_buf_len {
/*
 * _JBLEN is the number of ints required to save the following:
 * r21-r29, sp, fp, lr == 12 registers, 8 bytes each. d8-d15
 * are another 8 registers, each 8 bytes long. (aapcs64 specifies
 * that only 64-bit versions of FP registers need to be saved).
 * Finally, two 8-byte fields for signal handling purposes.
 */
/*line: 77*/    _JBLEN = 0x30,  // ((14+8+2)*2)
};

