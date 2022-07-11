[![slack](https://slack.binary.ninja/badge.svg)](https://slack.binary.ninja/)

# Binary Ninja API

This repository contains documentation and source code of the C++, Python, and Rust APIs for the [Binary Ninja](https://binary.ninja/) reverse engineering platform.

## Documentation

Online documentation is available for the following APIs:

- [C++ API, Stable Branch](https://api.binary.ninja/cpp/)
- [Python API, Stable Branch](https://api.binary.ninja/)
- [Python API, Dev Branch](https://dev-api.binary.ninja/)

## Branches

This repository has two primary branches [`dev`](/Vector35/binaryninja-api/tree/dev/) and [`master`](/Vector35/binaryninja-api/tree/master/).

The `dev` branch has the latest updates and tracks the latest development build of Binary Ninja; pull requests should be made against this branch. The `master` branch tracks the stable build of Binary Ninja. If you have just installed Binary Ninja for the first time, you are likely on the stable release channel.

## Usage and Build Instructions

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
- **Build UI plugins.** You will need Qt 6.3.1 (as of writing) installed to build UI plugins.
- **Build headlessly.** If you are using a headless Binary Ninja distribution or you do not wish to build UI plugins, pass `-DHEADLESS=ON` to CMake when configuring the build.

### Troubleshooting

- If Binary Ninja is installed at a different location than the platform default (defined in CMakeLists.txt), you will likely get an error stating "Binary Ninja Core Not Found." Specify the path to your Binary Ninja installation with by passing `-DBN_INSTALL_DIR=/path/to/binaryninja` to CMake when configuring the build setup.
- Since Binary Ninja is a 64-bit only product, ensure that you are using a 64-bit compiling and linking environment. Errors on Windows like `LNK1107` might indicate that your bits don't match.

## Examples

There are many examples available. The [Python examples folder ](https://github.com/Vector35/binaryninja-api/tree/dev/python/examples) demonstrates many different applications of the Python API, while C++ examples include:

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

## Contributing

Public contributions are welcome to this repository. All the API and documentation in this repository is licensed under an MIT license, however, the API interfaces with a closed-source commercial application, [Binary Ninja](https://binary.ninja).

If you're interested in contributing when you submit your first PR, you'll receive a notice from [CLA Assistant](https://cla-assistant.io/) that allows you to sign our [Contribution License Agreement](https://binary.ninja/cla.pdf) online.

## Licensing

Some components may be released under compatible but slightly different open source licenses and will have their own LICENSE file as appropriate.
