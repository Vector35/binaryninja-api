# Platform Types

Binary Ninja pulls type information from a variety of sources. The highest-level source are the platform types loaded for the given platform (which includes operating system and architecture). There are two sources of platform types. The first are shipped with the product in a [binary path](../index.md#directories). The second location is in your [user folder](../index.md#user-folder) and is intended for you to put custom platform types.

???+ Danger "Warning"
    Do NOT make changes to platform types in the binary path as they will be overwritten any time Binary Ninja updates. 

Platform types are used to define types that should be available to all programs available on that particular platform. They are only for global common types. Consider, for example, that you might want to add the following on windows:

```
typedef uint8_t u8;
```

You could write this type into:

```
/home/user/.binaryninja/types/platform/windows-x86.c
```

And any time you opened a 32bit windows binary, that type would be available to use. However, please note that these are not substitutes for [Type Libraries](../../dev/annotation.md#type-libraries).  Type Libraries are used to provide a collection of types for a given library such as a libc, or common DLL. 

???+ Warning "Tip"
    If you don't know the specific platform (and thus filename) you need to create for a given file, just enter `bv.platform` in the scripting console.

## Common Types

You may wish to provide types that are common across multiple architectures or platforms. The easiest way to do this is to use a `#include "filename.c"` line in the specific platform so that any common types will be loaded.

The base path for these files is in your [user folder](../index.md#user-folder) inside of a "types/platform" subfolder.

For example, something like:

```
$ pwd
/home/user/.binaryninja/types/platform
$ cat windows-x86.c
#include "windows.c"
$ cat windows-x86_64.c
#include "windows.c"
$ cat windows.c
typedef uint8_t u8;
```
