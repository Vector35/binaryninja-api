[![slack](https://binaryninja-slack-hwwdinrdce.now.sh/badge.svg)](https://binaryninja-slack-hwwdinrdce.now.sh/)

# Binary Ninja API

This repository contains documentation and source code for the [Binary Ninja](https://binary.ninja/) reverse engineering platform API.

## Branches

Please note that the [dev](/Vector35/binaryninja-api/tree/dev/) branch tracks changes on the `dev` build of binary ninja and is generally the place where all pull requests should be submitted to. However, the [master](/Vector35/binaryninja-api/tree/master/) branch tracks the `stable` build of Binary Ninja which is the default version run after installation. Online [documentation](https://api.binary.ninja/) tracks the stable branch. 

## Contributing

Public contributions are welcome to this repository. All the API and documentation in this repository is licensed under an MIT license, however, the API interfaces with a closed-source commercial application, [Binary Ninja](https://binary.ninja).

If interested in contributing, first please read and sign the [Contribution License Agreement](https://binary.ninja/cla.pdf). Next, email a your signed copy of the license to info@binary.ninja along with your github username. Once that email is confirmed, any pending pull requests will be evaluated for inclusion.

## Issues

The issue tracker for this repository tracks not only issues with the source code contained here but also the broader Binary Ninja product.

## Building

Starting mid March 2017, the C++ portion of this API can be built into a static library (.a, .lib) that binary plugins can link against. Use Makefile on MacOS, Linux, and Windows mingw environments, and Makefile.win (nmake file) for Windows Visual Studio environment (nmake -f).

The compiled API contains names and functions you can use from your plugins, but most of the implementation is missing until you link up against libbinaryninjacore.dylib or libbinaryninjacore.dll (via import file libbinaryninjacore.lib). See the ./examples.

Since BinaryNinja is a 64-bit only product, ensure that you are using a 64-bit compiling and linking environment. Errors on windows like LNK1107 might indicate that your bits don't match.

## Examples

* bin-info is a standalone executable that prints some information about a given binary to stdout
* breakpoint is a plugin that allows you to select a region within an x86 binary and use the context menu to fill it with breakpoint bytes
* print_syscalls is a standalone executable that prints the syscalls used in a given binary 
