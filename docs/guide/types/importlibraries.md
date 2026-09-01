# Import Libraries

Import Libraries are collections of type information (structs, enums, function types, etc.), corresponding to specific dynamic libraries that are imported into your analysis. You can browse and import them in the [Types View](./basictypes.md#the-type-list).

<!--
__image of Type List showing a couple import libraries, with one expanded showing its types__
-->

## Usage

Most of your usage of Import Libraries will be performed automatically by Binary Ninja when you analyze a binary. They are automatically imported based on the libraries that your binary uses. Any library functions or global variables your binary references will have their type signature imported, and any structures those functions and variables reference are imported as well.

<!-- 
__image of linear view showing a bunch of imported functions from an import library__
-->

Compared to [Platform Types](./platformtypes.md), only Import Libraries needed by your binary will be imported into your analysis. If you want to manually import additional Import Libraries (e.g. if your binary dynamically loads a library), you can use the **Add Import Library** action in [Types View](./basictypes.md#the-type-list). Just pick an Import Library from the list shown, and it will be added to the list where you can import types from it. 

If you want to use types from an Import Library that have not yet been imported, you can select them in the [Types View](./basictypes.md#the-type-list) and use the **Import Type** action. They will be copied into your analysis's System Types and you can use them in your own structure and function annotations.

## Design and Purpose

Import Libraries contain details about a specific library that is imported by binaries. They contain information about the types used in the library:

* Types
    * Structures, Classes, Unions
    * Enumerations
    * Typedefs
* Objects
    * Function Signatures
    * Global Variables

Import Libraries are named after the source library they are providing types for. When a binary is opened, Binary Ninja finds all of its linked library dependencies, and looks up Import Libraries for them. Those with a File Name or Alternative Name matching the exact text of a library used by the binary will be imported into the analysis. You can see this process in the Log:

```text
elf: searching for 'libc.so.6' in import libraries
Import library 'libc.so.6' imported
```

The [Developer Guide](../../dev/importlibraries.md) contains more details about the implementation details of the Import Library format.

## Creating and Modifying

Import Libraries are read-only by design, so while you cannot modify the ones built into Binary Ninja, you can create your own and use them as replacements. While there is no User Interface for doing this, there are plenty of APIs available. Check the [Developer Guide](../../dev/importlibraries.md) for details on how to create an Import Library.
