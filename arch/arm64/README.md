# arch-arm64

This is the Aarch64 plugin that ships with Binary Ninja.

## What's What

- [arch_arm64.cpp](./arch_arm64.cpp) implements the Architecture class
- [il.cpp](./il.cpp) contains the lifter, the translator from disassembly to intermediate language
- [disassembler/*](./disassembler/) is the disassembler

## Testing

There are three tests:

- [./disassembler/test.py](./disassembler/test.py) test of disassembler module, isolated from the architecture module or Binary Ninja
- [./test_disasm.py](./test_disasm.py) test of disassembler, using the architecture module through the binaryninja API
- [./arm64test.py](./arm64test.py) runs a very basic "lift to string and compare" test

Personal Binary Ninja users can test via the built in console:

```
>>> sys.path.append('C:/users/x/documents/binja/arch-arm64') # Path directory containing arm64test.py
>>> from importlib import reload
>>> import arm64test
success!
>>> # Add or fix any testcases
>>> reload(arm64test)
success!
```

And, of course, you can open a test binary in Binary Ninja with this architecture built and activated to see if results are as expected.

## Requirements for Pull Requesters

1. **TEST!** If you're making an architecture or lifter change, add a test case to [arm64test.py](./arm64test.py) that fails before your change and succeeds after your change.

2. **TEST!** If you're making a disassembler change, add a test case to [disassembler/test.py](./disassembler/test.py) that fails before your change and succeeds after your change.
3. Compile with warnings enabled. Do this cmake invocation: `ARM64_WARNINGS=1 cmake .`

Please follow whatever formatting conventions are present in the file you edit. Pay attention to curly brackets, spacing, tabs vs. spaces, etc.

When you submit your first PR to one of Vector 35's repositories, you'll receive a notice from [CLA Assistant](https://cla-assistant.io/) that allows you to sign our [Contribution License Agreement](https://binary.ninja/cla.pdf) online.


## Building

Building the architecture plugin requires `cmake` 3.9 or above. You will also need the
[Binary Ninja API source](https://github.com/Vector35/binaryninja-api).

Run `cmake`. This can be done either from a separate build directory or from the source
directory. Once that is complete, run `make` in the build directory to compile the plugin.

The plugin can be found in the root of the build directory as `libarch_arm64.so`,
`libarch_arm64.dylib` or `arch_arm64.dll` depending on your platform.

To install the plugin, first launch Binary Ninja and uncheck the "Aarch64 architecture plugin"
option in the "Core Plugins" section. This will cause Binary Ninja to stop loading the
bundled plugin so that its replacement can be loaded. Once this is complete, you can copy
the plugin into the user plugins directory (you can locate this by using the "Open Plugin Folder"
option in the Binary Ninja UI).

**Do not replace the architecture plugin in the Binary Ninja install directory. This will
be overwritten every time there is a Binary Ninja update. Use the above process to ensure that
updates do not automatically uninstall your custom build.**

## Build Example

### acquire repositories

```
mkdir ~/repos/vector35
cd ~/repos/vector35
git clone git@github.com:Vector35/binaryninja-api.git
git clone git@github.com:Vector35/arch-arm64.git
```

### environment variables

`export BN_API_PATH=~/repos/vector35/binaryninja-api`

### cmake, make

```
cd arch-arm64
cmake -DBN_INSTALL_DIR=/Applications/Binary\ Ninja\ DEV.app/ .
make
```

## Build Troubleshooting

### example

    CMake Error at CMakeLists.txt:8 (message):
      Provide path to Binary Ninja API source in BN_API_PATH
    resolution:
    ensure BN_API_PATH is in your environment

### example

    CMake Error at /Users/andrewl/repos/vector35/binaryninja-api/CMakeLists.txt:53 (message):
      Binary Ninja Core Not Found
    resolution:
    ensure BN_INSTALL_DIR is supplied at command line invocation of cmake
    ensure some bad directory is not cached in CMakeCache.txt

### example

    cmake seems to ignore your setting of BN_INSTALL_DIR and other cmake variables
    resolution:
    rm CMakeCache.txt

### example

    undefined symbols at link time, like:
    Undefined symbols for architecture x86_64:
      "_BNClearUserVariableValue", referenced from:
      BinaryNinja::Function::ClearUserVariableValue(BinaryNinja::Variable const&, unsigned long long) in libbinaryninjaapi.a(function.cpp.o)
    resolution:
    ensure that your api repo is on the same channel and at the same commit as the libbinaryninjacore you're linking against
    eg: binaryninja is on dev update channel and is up-to-date and binaryninja-api repo is on branch dev with latest pulled
