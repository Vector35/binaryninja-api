# Ghidra Import

Currently, the following categories of analysis information can be imported from Ghidra files:

- Bookmarks
- Comments
- Data variables
- Functions
- Memory map
- Types

## Importing data

### Import to a new file
`Plugins > Ghidra > Open Database...` allows you to select a Ghidra file to open as a binary view in Binary Ninja. You are able to select a single `.gbf`/`.gzf` file or project file from a `.gpr`.

### Import to an existing file
`Plugins > Ghidra > Import Database...` allows you to apply analysis information from a Ghidra file to an already open binary view in Binary Ninja. You are able to select a single `.gbf`/`.gzf` file or project file from a `.gpr`. You can choose to import all or only some categories of analysis information to apply to the binary view.

### Import to an existing project
!!! note
    Binary Ninja projects are only available in Commercial and Ultimate editions

`Plugins > Ghidra > Import Project...` allows you to import files from a Ghidra project (`.gpr`) to an open Binary Ninja project. All available analysis information will be imported for all selected files.
