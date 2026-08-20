# Debug Info

Debug Info is a mechanism for importing types, function signatures, data variables, and more from either the original binary (e.g. an ELF compiled with debug info) or a supplemental file (e.g. a PDB or .debug file).

Currently, debug info plugins are limited to applying types, function signatures, data variables, and local stack variables, but in the future will include line number information, comments, and possibly more.

## Supported Formats

We currently support [PDBs](https://github.com/Vector35/binaryninja-api/tree/dev/plugins/pdb-ng) and [DWARF](https://github.com/Vector35/binaryninja-api/tree/dev/plugins/dwarf/dwarf_import) (which are both open source), though you can also [register your own debug info parser through the API](https://api.binary.ninja/binaryninja.debuginfo-module.html#binaryninja.debuginfo.DebugInfoParser).

Binary Ninja will automatically try to access relevant PDBs from specified local folders and Microsoft's symbol server (see the [PDB settings](../settings.md#settings-reference) for more information).

Binary Ninja's DWARF loader supports loading information compiled into binaries, information from external files (`.dwo`, `.debug`, etc.), and information from external `.dSYM` files as well.

## Applying Debug Info

Debug Info is automatically applied by default if available.

![Import Debug Info >](../../img/import-debug-info.png "Import Debug Info"){ width="300" }

However, for some file formats, you may wish to specify an external source of Debug Info using the `Analysis/Import Debug Info from External File` menu option.

## Blocking Debug Info

You can control if debug information is imported for a file by changing the setting [`analysis.debugInfo.internal`](https://docs.binary.ninja/guide/settings.html#analysis.debugInfo.internal). You can import debug information at any point later by using the menu action `Analysis/Import Debug Info`.

## PDB Notes

Binary Ninja will make a best effort to find relevant PDBs and apply debug info from them when you open a binary. Some PDBs can be very large and take a significant amount of time to process. When you open a file with a large PDB, you'll see a progress indicator in the status bar at the bottom of the application.

## DWARF Notes

DWARF information is imported from files that contain DWARF sections. Binary Ninja can automatically locate and load separate DWARF information through several methods:

- **Debuginfod servers**: If [`network.enableDebuginfod`](https://docs.binary.ninja/guide/settings.html#network.enableDebuginfod) is enabled, Binary Ninja will query the [debuginfod](https://developers.redhat.com/blog/2019/10/14/introducing-debuginfod-the-elfutils-debuginfo-server) servers configured in [`network.debuginfodServers`](https://docs.binary.ninja/guide/settings.html#network.debuginfodServers)
- **Sibling debug files**: If [`analysis.debugInfo.loadSiblingDebugFiles`](https://docs.binary.ninja/guide/settings.html#analysis.debugInfo.loadSiblingDebugFiles) is enabled, Binary Ninja will look for files of the form `<filename>.debug` and `<filename>.dSYM` in the same directory as the binary
- **Debug directories**: Binary Ninja will search the directories specified in [`analysis.debugInfo.debugDirectories`](https://docs.binary.ninja/guide/settings.html#analysis.debugInfo.debugDirectories) for debug files stored by the binary's build ID

If automatic loading does not succeed, you can still manually import debug info from an external file using the `Analysis/Import Debug Info from External File` menu option.

### DWARF Import Limitations

[DWARF version 5](https://dwarfstd.org/dwarf5std.html) is mostly backwards compatible with DWARF version 4, which we originally targeted with our DWARF import plugin, with the caveats described in [this issue](https://github.com/Vector35/binaryninja-api/issues/5423).

Components are supported by the API, but not in the parser. The [same issue](https://github.com/Vector35/binaryninja-api/issues/5423) as above would also allow us to support components more easily as well.

### DWARF Export Limitations

Our [DWARF Export plugin](https://github.com/Vector35/binaryninja-api/tree/dev/plugins/dwarf/dwarf_export) is also open source and uses a different system from our debug information import plugins. It also does not support function-local variable names or types. The export plugin currently will export the global variables, function prototypes, and all the types in your binary view except for ones that are `FunctionTypeClass` or `VarArgsTypeClass`.

### Special Note for `.dSYM` Files

Binary Ninja will automatically load `.dSYM` files given the following:

- The `.dSYM` file is adjacent on the filesystem to the binary being analyzed
- The `.dSYM` file is named `X.dSYM`, where `X` is the name of the binary being analyzed
- `analysis.debugInfo.loadSiblingDebugFiles` is enabled

When a `.dSYM` file is not automatically loaded, you will need to manually import the debug info contained in the `.dSYM`.
For example, you could have the file `hello.macho` that you would like to import debug info for. Thankfully, you also have `hello.dSYM`. So you open `hello.macho` with options, find the "External Debug Info File" and provide the `hello.dSYM` file. When the file opens, you notice that no information was imported and the log reads "No available/valid parsers for file." This is because `hello.dSYM` is a bundle. The actual path you needed to provide for the "External Debug Info File" setting would look something like `hello.dSYM/Contents/Resources/DWARF/hello`.
