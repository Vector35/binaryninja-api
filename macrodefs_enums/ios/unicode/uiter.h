// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/unicode/uiter.h

// Depends on identifiers
enum macro_uiter_no_state {
/**
 * Constant for UCharIterator getState() indicating an error or
 * an unknown state.
 * Returned by uiter_getState()/UCharIteratorGetState
 * when an error occurs.
 * Also, some UCharIterator implementations may not be able to return
 * a valid state for each position. This will be clearly documented
 * for each such iterator (none of the public ones here).
 *
 * @stable ICU 2.6
 */
/*line: 86*/    UITER_NO_STATE = 0xffffffff,  // ((uint32_t)0xffffffff)
};

