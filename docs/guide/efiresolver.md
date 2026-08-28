# EFI Resolver

EFI Resolver is a Binary Ninja workflow that automates the resolution of type information for EFI (Extensible Firmware
Interface) protocol usage in UEFI binaries. It supports Terse Executable (TE) and Portable Executable (PE) formatted
EFI binaries such as PEI, DXE, and SMM modules.

![EFI Resolver](../img/efi-resolver.png "EFI Resolver")

## Key Features

* **Automatic Type Propagation** – propagates EFI types from the module entry point to callee functions and global data
  variables
* **EFI Protocol Interface Detection** – identifies EFI DXE, SMM, and PPI protocol interfaces by analyzing calls to EFI
  services methods (`InstallProtocolInterface`, `LocateProtocol`, etc.), queries known EFI types by GUID, and applies
  types to interface pointers
* **PEI Services Table Recovery** – identifies architecture-specific code patterns (described in the
  [UEFI PI Specification](https://uefi.org/specs/PI/1.8/V1_PEI_Foundation.html#pei-services-table-retrieval)) for
  resolving the address of the PEI services table
* **User-defined / Proprietary EFI Protocol Support** – allows users to create custom EFI types and associate them with
  an EFI GUID to be included during automated analysis

## Re-running the Workflow

EFI Resolver registers a plugin command that allows for re-running the EFI Resolver workflow after the binary view has
been finalized. This can be valuable when manually applying new types or when creating new types for proprietary EFI
protocol interfaces. To re-run EFI Resolver, click `Plugins -> Run EFI Resolver`.

## User-defined EFI Protocol GUIDs and Types

Binary Ninja bundles EFI platform type definitions for the majority of the types in the UEFI specification. However,
many UEFI firmware vendors implement proprietary interfaces. EFI Resolver allows users to extend its capabilities by
supplying custom GUIDs and associated type definitions for proprietary protocols. This can be achieved in the following
steps:

1. Create a JSON file named `efi-guids.json` in the `types` directory of your [user folder](index.md#user-folder)
    * macOS: `~/Library/Application Support/Binary Ninja/types/efi-guids.json`
    * Linux: `~/.binaryninja/types/efi-guids.json`
    * Windows: `%APPDATA%\Binary Ninja\types`

    !!! Important "GUID Database"
        An excellent source of proprietary EFI GUIDs is Binarly's
        [GUID DB](https://github.com/REhints/guiddb/blob/main/guids.json). This file is in the expected format for
        EFI Resolver's `efi-guids.json`, and can be copied directly to your user folder as a starting point.

2. Define a GUID in the following format:

    ```json
    {
        "EFI_EXAMPLE_CUSTOM_PROTOCOL_GUID": [
            19088743, 35243, 52719,
            1, 35, 69, 103, 137, 171, 205, 239
        ]
    }
    ```

3. Create a type named `EFI_EXAMPLE_CUSTOM_PROTOCOL` using the types widget

    !!! Important "Unassociated EFI Types"
        If there is not a type for a GUID defined in `efi-guids.json`, EFI Resolver will still use the GUID name to name
        the protocol interface and GUID data variables.

4. Re-run the workflow

In this example, the workflow will apply the `EFI_EXAMPLE_CUSTOM_PROTOCOL` type to identified protocol interfaces that
were queried in the binary via the `EFI_EXAMPLE_CUSTOM_PROTOCOL_GUID` EFI GUID.

!!! Important "Platform Types"
	To make a custom EFI protocol type accessible when loading future EFI binaries, it is recommended to add the type to
	[platform types](types/platformtypes.md)
