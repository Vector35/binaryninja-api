# Type Libraries

Type Libraries are collections of type information (structs, enums, function types, etc.), corresponding to specific dynamic libraries that are imported into your analysis. You can browse and import them in the [Types View](./basictypes.md#the-type-list).

<!--
__image of Type List showing a couple imported type libraries, with one expanded showing its types__
-->

## Usage

Most of your usage of Type Libraries will be performed automatically by Binary Ninja when you analyze a binary. They are automatically imported based on the libraries that your binary uses. Any library functions or global variables your binary references will have their type signature imported, and any structures those functions and variables reference are imported as well.

<!-- 
__image of linear view showing a bunch of imported functions from a type library__
-->

Compared to [Platform Types](./platformtypes.md), only Type Libraries needed by your binary will be imported into your analysis. If you want to manually import additional Type Libraries (e.g. if your binary dynamically loads a library), you can use the **Import Type Library** action in [Types View](./basictypes.md#the-type-list). Just pick a Type Library from the list shown, and it will be added to the list where you can import types from it. 

If you want to use types from a Type Library that have not yet been imported, you can select them in the [Types View](./basictypes.md#the-type-list) and use the **Add Type Library** action. They will be copied into your analysis's System Types and you can use them in your own structure and function annotations.

## Design and Purpose

Type Libraries contain details about a specific library that is imported by binaries. They contain information about the types used in the library:

* Types
    * Structures, Classes, Unions
    * Enumerations
    * Typedefs
* Objects
    * Function Signatures
    * Global Variables

Type Libraries are named after the source library they are providing types for. When a binary is opened, Binary Ninja finds all of its linked library dependencies, and looks up Type Libraries for them. Those with a File Name or Alternative Name matching the exact text of a library used by the binary will be imported into the analysis. You can see this process in the Log:

    elf: searching for 'libc.so.6' in type libraries
    Type library 'libc.so.6' imported

The [Developer Guide](../../dev/typelibraries.md) contains more details about the implementation details of the Type Library format.

## Creating and Modifying

Type Libraries are read-only by design, so while you cannot modify the ones built into Binary Ninja, you can create your own and use them as replacements. While there is no User Interface for doing this, there are plenty of APIs available. Check the [Developer Guide](../../dev/typelibraries.md) for details on how to create a Type Library.
