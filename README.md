[![slack](https://img.shields.io/badge/slack-binaryninja-red.svg?logo=slack)](https://slack.binary.ninja/)


# Binary Ninja API

This repository contains documentation and source code of the C++, Python, and Rust APIs for the [Binary Ninja](https://binary.ninja/) reverse engineering platform.

## Documentation

Online documentation is available for the following APIs:

- [C++ API, Stable Branch](https://api.binary.ninja/cpp/)
- [Python API, Stable Branch](https://api.binary.ninja/)
- [Python API, Dev Branch](https://dev-api.binary.ninja/)
- [Rust API, Stable Branch](https://rust.binary.ninja/)
- [Rust API, Dev Branch](https://dev-rust.binary.ninja/)

## Usage and Build Instructions

**In order to build the Binary Ninja API, you will need to use the specific revision that matches the hash from the file `api_REVISION.txt`.** This file should be located in the root install folder for Linux and Windows or the `Contents/Resources` sub-folder of the app on macOS. The easiest way to do this is by cloning this repository (or adding it as a submodule) and doing something like `git checkout $(cat api_REVISION.txt | awk -F/ '{print $NF}')`. Documentation for how to set this up with something like `cmake` can be found [here](https://docs.binary.ninja/dev/plugins.html?h=api_#cmake-setup).

To write Binary Ninja plugins using C++, you'll need to build the C++ API. Building the API library is done similarly to most CMake-based projects; the basic steps are outlined as follows:

```Bash
# Get the source
git clone https://github.com/Vector35/binaryninja-api.git
cd binaryninja-api
git submodule update --init --recursive

# Configure an out-of-source build setup
cmake -S . -B build # (additional arguments go here if needed)

# Compile
cmake --build build -j8
```

In addition to the default build setup, you may want to:

- **Build examples.** To build the [API examples](#examples), pass `-DBN_API_BUILD_EXAMPLES=ON` to CMake when configuring the build. After the build succeeds, you can install the built plugins by running the `install` target. When using the "Unix Makefiles" build generator, this looks like: `make install`.
- **Build UI plugins.** You will need Qt 6.8.2 installed to build UI plugins. We use a slightly modified [build configuration](https://github.com/Vector35/qt-build) internally that has some ABI-compatible fixes and changes to defaults, but a stock build can also work. Note that it is not recommended to use pre-built configurations from Homebrew. Either using the official installer or building from our repo is recommended.
- **Build headlessly.** If you are using a headless Binary Ninja distribution or you do not wish to build UI plugins, pass `-DHEADLESS=ON` to CMake when configuring the build.

### Troubleshooting

- If Binary Ninja is installed at a different location than the platform default (defined in CMakeLists.txt), you will likely get an error stating "Binary Ninja Core Not Found." Specify the path to your Binary Ninja installation with by passing `-DBN_INSTALL_DIR=/path/to/binaryninja` to CMake when configuring the build setup.
- Since Binary Ninja is a 64-bit only product, ensure that you are using a 64-bit compiling and linking environment. Errors on Windows like `LNK1107` might indicate that your bits don't match.

## Examples

There are many examples available. The [Python examples folder](https://github.com/Vector35/binaryninja-api/tree/dev/python/examples) demonstrates many different applications of the Python API, while C++ examples include:

- [background_task](https://github.com/Vector35/binaryninja-api/tree/dev/examples/background_task) is a plugin that demonstrates managing a background task.\*
- [bin-info](https://github.com/Vector35/binaryninja-api/tree/dev/examples/bin-info) is a standalone executable that prints some information about a given binary to the terminal.\*
- [breakpoint](https://github.com/Vector35/binaryninja-api/tree/dev/examples/breakpoint) is a plugin that allows you to select a region within an x86 binary and use the context menu to fill it with breakpoint bytes.
- [command-line disassm](https://github.com/Vector35/binaryninja-api/tree/dev/examples/cmdline_disasm) demonstrates how to dump disassembly to the command line.\*
- [llil-parser](https://github.com/Vector35/binaryninja-api/tree/dev/examples/llil_parser) parses Low-Level IL, demonstrating how to match types and use a visitor class.\*
- [mlil-parser](https://github.com/Vector35/binaryninja-api/tree/dev/examples/mlil_parser) parses Medium-Level IL, demonstrating how to match types and use a visitor class.\*
- [print_syscalls](https://github.com/Vector35/binaryninja-api/tree/dev/examples/print_syscalls) is a standalone executable that prints the syscalls used in a given binary.\*
- [triage](https://github.com/Vector35/binaryninja-api/tree/dev/examples/triage) is a fully featured plugin that is shipped and enabled by default, demonstrating how to do a wide variety of tasks including extending the UI through QT.
- [workflows](https://github.com/Vector35/binaryninja-api/tree/dev/examples/workflows) is a collection of plugins that demonstrate using Workflows to extend the analysis pipeline.
- [x86 extension](https://github.com/Vector35/binaryninja-api/tree/dev/examples/x86_extension) creates an architecture extension which shows how to modify the behavior of the build-in architectures without creating a complete replacement.

\* Requires license supporting headless API access.

## Issues

The issue tracker for this repository tracks not only issues with the source code contained here but also the broader Binary Ninja product.

## Branches

This repository has two primary branches [`dev`](/Vector35/binaryninja-api/tree/dev/) and [`master`](/Vector35/binaryninja-api/tree/master/).

The `dev` branch has the latest updates and tracks the latest development build of Binary Ninja; pull requests should be made against this branch. The `master` branch tracks the stable build of Binary Ninja. If you have just installed Binary Ninja for the first time, you are likely on the stable release channel.

## Contributing

Public contributions are welcome to this repository. Most of the API and documentation in this repository is licensed under an MIT license, however, the API interfaces with a closed-source commercial application, [Binary Ninja](https://binary.ninja). Additionally, the [Rust API](https://github.com/Vector35/binaryninja-api/tree/dev/rust) is [licensed](https://github.com/Vector35/binaryninja-api/tree/dev/rust/LICENSE) under a Apache 2.0 license.

If you're interested in contributing when you submit your first PR, you'll receive a notice from [CLA Assistant](https://cla-assistant.io/) that allows you to sign our [Contribution License Agreement](https://binary.ninja/cla.pdf) online.

## Platforms

This repository contains all of our Platform plugins available here:

* [Windows](https://github.com/Vector35/binaryninja-api/tree/dev/platform/windows)
* [Linux](https://github.com/Vector35/binaryninja-api/tree/dev/platform/linux)
* [macOS](https://github.com/Vector35/binaryninja-api/tree/dev/platform/mac)
* [FreeBSD](https://github.com/Vector35/binaryninja-api/tree/dev/platform/freebsd)
* [Decree](https://github.com/Vector35/binaryninja-api/tree/dev/platform/decree)
* [EFI](https://github.com/Vector35/binaryninja-api/tree/dev/platform/efi)


## Architectures

This repository contains all of the Architecture plugins available in Personal and Commercial editions of Binary Ninja. You can find each architecture here:

* [x86/x86_64](https://github.com/Vector35/binaryninja-api/tree/dev/arch/x86)
* [ARM64](https://github.com/Vector35/binaryninja-api/tree/dev/arch/arm64)
* [ARMv7](https://github.com/Vector35/binaryninja-api/tree/dev/arch/armv7)
* [PPC](https://github.com/Vector35/binaryninja-api/tree/dev/arch/powerpc)
* [MIPS](https://github.com/Vector35/binaryninja-api/tree/dev/arch/mips)
* [RISC-V](https://github.com/Vector35/binaryninja-api/tree/dev/arch/riscv)
* [MSP430](https://github.com/Vector35/binaryninja-api/tree/dev/arch/msp430)


## BinaryViewTypes

This repository contains all of our Binary View Type plugins available here:

* [Mach-O](https://github.com/Vector35/binaryninja-api/tree/dev/view/macho)
* [ELF](https://github.com/Vector35/binaryninja-api/tree/dev/view/elf)
* [PE/COFF/TE](https://github.com/Vector35/binaryninja-api/tree/dev/view/pe)
* [MD1Rom](https://github.com/Vector35/binaryninja-api/tree/dev/view/md1rom)


## DebugInfo

* [DWARF Import](https://github.com/Vector35/binaryninja-api/tree/dev/plugins/dwarf/dwarf_import)
* [PDB Import](https://github.com/Vector35/binaryninja-api/tree/dev/plugins/pdb-ng)
* [IDB Import](https://github.com/Vector35/binaryninja-api/tree/dev/plugins/idb_import)


## Related Repositories

In addition to this main API repository being open source Vector35 also has open sourced the Debugger and the Objective-C plugins open source as well:

* [Debugger](https://github.com/Vector35/debugger)
* [workflow_objc](https://github.com/Vector35/workflow_objc)

## Licensing

Some components may be released under compatible but slightly different open source licenses and will have their own LICENSE file as appropriate.

Remaining components are released under an [MIT](https://github.com/Vector35/binaryninja-api/blob/dev/LICENSE.txt) license.

Note that `.lib` files are included the native binary builds of Binary Ninja for windows. Those lib files are also released under the same license as this repository and may be distributed accordingly.
