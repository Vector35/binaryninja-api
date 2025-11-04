// Correctnes: ok
// /Users/mstanchin/share/git-reps/binaryninja/contributing/origin/iPhoneOS18.6.sdk/usr/include/xattr_flags.h

enum macro_xattr_operation_intent {
/*
 * xattr_operation_intent_t is used to declare what the intent of the copy is.
 * Not a bit-field (for now, at least).
 *
 * XATTR_OPERATION_INTENT_COPY indicates that the EA is attached to an object
 * that is simply being copied.  E.g., cp src dst
 *
 * XATTR_OPERATION_INTENT_SAVE indicates that the EA is attached to an object
 * being saved; as in a "safe save," the destination is being replaced by
 * the source, so the question is whether the EA should be applied to the
 * destination, or generated anew.
 *
 * XATTR_OPERATION_INTENT_SHARE  indicates that the EA is attached to an object that
 * is being given out to other people.  For example, saving to a public folder,
 * or attaching to an email message.
 *
 * XATTR_OPERATION_INTENT_SYNC  indicates that the EA is attached to an object that
 * is being synced to other storages for the same user.  For example synced to
 * iCloud.
 *
 * XATTR_OPERATION_INTENT_BACKUP indicates that the EA is attached to an object
 * that is being backed-up.  For example, being backed-up to Time Machine.
 */
/*line: 60*/    XATTR_OPERATION_INTENT_COPY = 0x1,  // 1
/*line: 61*/    XATTR_OPERATION_INTENT_SAVE = 0x2,  // 2
/*line: 62*/    XATTR_OPERATION_INTENT_SHARE = 0x3,  // 3
/*line: 63*/    XATTR_OPERATION_INTENT_SYNC = 0x4,  // 4
/*line: 64*/    XATTR_OPERATION_INTENT_BACKUP = 0x5,  // 5
};

// Depends on identifiers
enum macro_xattr_flags {
/*
 * XATTR_FLAG_NO_EXPORT
 * Declare that the extended property should not be exported; this is
 * deliberately a bit vague, but this is used by XATTR_OPERATION_INTENT_SHARE
 * to indicate not to preserve the xattr.
 */
/*line: 81*/    XATTR_FLAG_NO_EXPORT = 0x1,  // ((xattr_flags_t)0x0001)
/*
 * XATTR_FLAG_CONTENT_DEPENDENT
 * Declares the extended attribute to be tied to the contents of the file (or
 * vice versa), such that it should be re-created when the contents of the
 * file change.  Examples might include cryptographic keys, checksums, saved
 * position or search information, and text encoding.
 *
 * This property causes the EA to be preserved for copy and share, but not for
 * safe save.  (In a safe save, the EA exists on the original, and will not
 * be copied to the new version.)
 */
/*line: 94*/    XATTR_FLAG_CONTENT_DEPENDENT = 0x2,  // ((xattr_flags_t)0x0002)
/*
 * XATTR_FLAG_NEVER_PRESERVE
 * Declares that the extended attribute is never to be copied, for any
 * intention type.
 */
/*line: 101*/   XATTR_FLAG_NEVER_PRESERVE = 0x4,  // ((xattr_flags_t)0x0004)
/*
 * XATTR_FLAG_SYNCABLE
 * Declares that the extended attribute is to be synced, used by the
 * XATTR_OPERATION_ITENT_SYNC intention.  Syncing tends to want to minimize the
 * amount of metadata synced around, hence the default behavior is for the EA
 * NOT to be synced, even if it would else be preserved for the
 * XATTR_OPERATION_ITENT_COPY intention.
 */
/*line: 111*/   XATTR_FLAG_SYNCABLE = 0x8,  // ((xattr_flags_t)0x0008)
/*
 * XATTR_FLAG_ONLY_BACKUP
 * Declares that the extended attribute should only be copied if the intention
 * is XATTR_OPERATION_INTENT_BACKUP. That intention is distinct from the
 * XATTR_OPERATION_INTENT_SYNC intention in that there is no desire to minimize the
 * amount of metadata being moved.
 */
/*line: 120*/   XATTR_FLAG_ONLY_BACKUP = 0x10,  // ((xattr_flags_t)0x0010)
/*
 * XATTR_FLAG_ONLY_SAVING
 * Declares that the extended attribute should only be copied if the intention
 * is XATTR_OPERATION_INTENT_SAVE or XATTR_OPERATION_INTENT_BACKUP.
 */
/*line: 127*/   XATTR_FLAG_ONLY_SAVING = 0x20,  // ((xattr_flags_t)0x0020)
};

