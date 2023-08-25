# Debug Info

Debug Info is a mechanism for importing types, function signatures, and data variables from either the original binary (eg. an ELF compiled with DWARF) or a supplemental file (eg. a PDB).

Currently debug info plugins are limited to types, function signatures, and data variables, but in the future will include line number information, comments, local variables, and possibly more.

## Supported DEBUG Info

Out of the box, Binary Ninja supports PDBs and DWARF.

For PDBs, Binary Ninja will automatically try to source from specified local folders and Microsoft's symbol server ([see the PDB settings for more information](settings.md#all-settings)).

For DWARF, this includes DWARF information compiled in to ELF binaries, DWARF information in external ELF files (`.dwo`, `.debug`, etc), DWARF information compiled in to Mach-O's, and DWARF information in external `.dSYM` files as well. Support for DWARF information in PEs is [planned](https://github.com/Vector35/binaryninja-api/issues/1555).

## Applying debug info

### PDB Notes

PDBs will make a best effort to find relevant debug info and apply it when you open a binary. Some PDBs can be very large and take a significant amount of time to parse. When you open a large PDB, you'll see a progress indicator in the status bar at the bottom of the application.

### DWARF Notes

DWARF information will be imported by default if the file contains DWARF sections. Currently, Binary Ninja will not search local or remote locations to attempt to find the associated DWARF information for you. If you have separate DWARF info, you'll need to import that from an external file.

### Importing from External Files

Whether the Binary Ninja chooses the wrong PDB to import debug information from, or you have an external DWARF file you with to import the debug information from, you'll need to explicitly import debug info from that external file. You can either do this on-load by populating the "External Debug Info File" setting field (`analysis.debugInfo.external`), or by using the toolbar menu `Analysis` -> `Import Debug Info from External File`.

#### Special Note for `.dSYM` Files

`.dSYM` packages are often provided as application bundles. Binary Ninja currently does not support extracting the actual `.dSYM` file out of the package for parsing, so you may need to provide a full path for Binary Ninja to correctly parse.

For example, you could have the file `hello.macho` that you would like to import debug info for. Thankfully, you also have `hello.dSYM`. So you open `hello.macho` with options, find the "External Debug Info File" and provide the `hello.dSYM` file. When the file opens, you notice that no information was imported and the log reads "No available/valid parsers for file." This is because `hello.dSYM` is a bundle. The actual path you needed to provide for the "External Debug Info File" setting would look something like `hello.dSYM/Contents/Resources/DWARF/hello`.

## Not applying debug info

If you wish not to import debug information for a file, you'll need to change the setting "Import Debug Information" (or `analysis.debugInfo.internal`). If you want to import debug information later, you can use the toolbar menu `Analysis` -> `Import Debug Info`, this will parse the current file and try to apply the recovered debug information.
