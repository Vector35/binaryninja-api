# Working with Types, Structures, and Symbols

There's so many things to learn about working with Types in Binary Ninja that we've organized it into several sections!

- Introduction (this introduction)
- [Basic Types](basictypes.md): Brief overview of the basics of types in Binary Ninja
- [Working with Types](type.md): Interacting with types and symbols from the UI and using the keyboard
- [Platform Types](platformtypes.md): Types that automatically apply to a platform
- [Type Archives](typearchives.md): How you can use type archives to share types between analysis databases
- [Importing/Exporting Types](typeimportexport.md): How to import or export types

Additionally, make sure to see the [applying annotations](../dev/annotation.md) section of the developer guide for information about using the API with types and covering the creation of many of the items described below.

## Type Libraries

[Type Libraries](../dev/annotation.md#type-libraries) are collection of type information, usually for libraries that are imported into a binary so that, for example, common calls like libc functions can have appropriately named and typed parameters. If all goes well, you shouldn't have to do anything and default type libraries will be applied to files you open, but you can also make your own in the [applying annotations](../dev/annotation.md#type-libraries) documentation.

## Signature Libraries

Signtuare libraries don't actually contain any types themselves but they're often closely associated with types. A [signature library](https://dev-docs.binary.ninja/dev/annotation.html#signature-library) is used to match a fingerprint for a statically compiled function with its name, and _when paired with a Type Library_ will provide matching type information. 

## Type Archives

[Type Archives](typearchives.md) are a collection of types that are shared between analysis databases.

## Platform Types

[Platform types](platformtypes.md) are simple c style types provided for common platforms and may be useful when you wish to make a base type to a platform.
