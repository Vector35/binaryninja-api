[![slack](https://slack.binary.ninja/badge.svg)](https://slack.binary.ninja/)

# Binary Ninja API

This repository contains documentation and source code for the [Binary Ninja](https://binary.ninja/) reverse engineering platform API.

## Branches

Please note that the [dev](/Vector35/binaryninja-api/tree/dev/) branch tracks changes on the `dev` build of binary ninja and is generally the place where all pull requests should be submitted to. However, the [master](/Vector35/binaryninja-api/tree/master/) branch tracks the `stable` build of Binary Ninja which is the default version run after installation. Online [documentation](https://api.binary.ninja/) tracks the stable branch. 

## Contributing

Public contributions are welcome to this repository. All the API and documentation in this repository is licensed under an MIT license, however, the API interfaces with a closed-source commercial application, [Binary Ninja](https://binary.ninja).

If you're interested in contributing when you submit your first PR, you'll receive a notice from [CLA Assistant](https://cla-assistant.io/) that allows you to sign our [Contribution License Agreement](https://binary.ninja/cla.pdf) online. 

## Issues

The issue tracker for this repository tracks not only issues with the source code contained here but also the broader Binary Ninja product.

## Building

Starting July 10th, C++ portion of this API can be built into a static library (.a, .lib) that binary plugins can link against using [cmake](https://cmake.org/).

The compiled API contains names and functions you can use from your plugins, but most of the implementation is missing until you link up against libbinaryninjacore.dylib or libbinaryninjacore.dll (via import file libbinaryninjacore.lib). See the ./examples.

Since BinaryNinja is a 64-bit only product, ensure that you are using a 64-bit compiling and linking environment. Errors on windows like LNK1107 might indicate that your bits don't match.

## Examples

There are many examples available. The [Python examples folder ](https://github.com/Vector35/binaryninja-api/tree/dev/python/examples) demonstrates many different applications of the Python API, while native examples include:

* [bin-info](https://github.com/Vector35/binaryninja-api/tree/dev/examples/bin-info) is a standalone executable that prints some information about a given binary to stdout (only usable with licenses that support headless API access)
* [breakpoint](https://github.com/Vector35/binaryninja-api/tree/dev/examples/breakpoint) is a plugin that allows you to select a region within an x86 binary and use the context menu to fill it with breakpoint bytes
* [command-line disassm](https://github.com/Vector35/binaryninja-api/tree/dev/examples/cmdline_disasm) demonstrates how to dump disassembly to the command-line (only usable with licenses that support headless API access)
* [llil-parser](https://github.com/Vector35/binaryninja-api/tree/dev/examples/llil_parser) parses Low-Level IL, demonstrating how to match types and use a visitor class (only usable with licenses that support headless API access)
* [mlil-parser](https://github.com/Vector35/binaryninja-api/tree/dev/examples/mlil_parser) parses Medium-Level IL, demonstrating how to match types and use a visitor class (only usable with licenses that support headless API access)
* [print_syscalls](https://github.com/Vector35/binaryninja-api/tree/dev/examples/print_syscalls) is a standalone executable that prints the syscalls used in a given binary (only usable with licenses that support headless API access)
* [triage](https://github.com/Vector35/binaryninja-api/tree/dev/examples/triage) is a fully featured plugin that is shipped and enabled by default, demonstrating how to do a wide variety of tasks including extending the UI through QT
* [x86 extension](https://github.com/Vector35/binaryninja-api/tree/dev/examples/x86_extension) creates an architecture extension which shows how to modify the behavior of the build-in architectures without creating a complete replacement
