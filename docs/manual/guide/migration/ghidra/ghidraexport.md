# Ghidra Export

Currently, the following categories of analysis information can be exported to Ghidra:

- Bookmarks
- Comments
- Data variables
- Functions
- Symbols
- Types

## Exporting data

`Plugins > Ghidra > Export View...` allows exporting an existing Binary View to a packed Ghidra database (.gzf). This can then be imported into an existing Ghidra project just like any other file.

## Importing into Ghidra

Use the [File Import](https://htmlpreview.github.io/?https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Base/src/main/help/help/topics/ImporterPlugin/importer.htm) functionality built into ghidra to add the exported .gzf.
