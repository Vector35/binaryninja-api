# Working with Types, Structures, and Symbols

There's so many things to learn about working with Types in Binary Ninja that we've organized it into several sections!

- [Basic Type Editing](basictypes.md): Brief overview of the basics
- [Working with Types](type.md): Interacting with types in disassembly and decompilation
- [Importing/Exporting Types](typeimportexport.md): How to import or export types from header files, archives, or other BNDBs
- [Attributes and Annotations](attributes.md): Annotations you can apply to types to influence analysis and presentation

Additionally, several types of containers for type information are documented here:

- [Debug Info](debuginfo.md): Debug Info can provide additional type information (examples include DWARF and PDB files)
- [Type Libraries](typelibraries.md): Type Libraries contain types from commonly-used dynamic libraries 
- [Platform Types](platformtypes.md): Types that automatically apply to a platform
- [Type Archives](typearchives.md): How you can use type archives to share types between analysis databases
- [Signature Libraries](../../dev/annotation.md#signature-libraries): Signature libraries are used to match names of functions with signatures for code that is statically compiled

Additionally, make sure to see the [applying annotations](../../dev/annotation.md) section of the developer guide for information about using the API with types and covering the creation of many of the items described below.
