# ppc-capstone
This is a PowerPC architecture plugin for Binary Ninja.

## This Repo Demonstrates

* use of an existing disassembler (capstone) in making an architecture
* use of the genetic algorithm for assembling (oracle: capstone)
* proper lifting

Note that assembler.cpp and test_asm.cpp are isolated, in that they do not include any binja headers or link against any binja libs. This allows quick command line compilation, debugging, and testing. See the comments atop `test_disasm.cpp` and `test_asm.cpp` for compilation instructions.

## Building

Building the architecture plugin requires `cmake` 3.13 or above. You will also need the
[Binary Ninja API source](https://github.com/Vector35/binaryninja-api).

Steps:

2. Run `git submodule update --init --recursive` to download the capstone source code fixed at a particular commit.

3. Generate makefiles with `cmake`. This can be done either from a separate build directory or from the source directory, eg:

  ```
  $ mkdir build_debug
  $ cmake -S . -B build_debug -DCMAKE_BUILD_TYPE=Debug
  $ cmake --build ./build
  ```

4. Run `make` to compile the plugin.

The plugin can be found in the root of the build directory as `libarch_ppc.so`,
`libarch_ppc.dylib` or `arch_ppc.dll` depending on your platform.

To install the plugin, first launch Binary Ninja and uncheck the "PowerPC architecture plugin"
option in the "Core Plugins" section. This will cause Binary Ninja to stop loading the
bundled plugin so that its replacement can be loaded. Once this is complete, you can copy
the plugin into the user plugins directory (you can locate this by using the "Open Plugin Folder"
option in the Binary Ninja UI).

**Do not replace the architecture plugin in the Binary Ninja install directory. This will
be overwritten every time there is a Binary Ninja update. Use the above process to ensure that
updates do not automatically uninstall your custom build.**

## Testing

- [./test_lifting.py](./test_lifting.py) runs a very basic "lift to string and compare" test

Personal Binary Ninja users can test via the built in console:

```
>>> sys.path.append('C:/users/x/documents/binja/ppc-capstone') # Path directory containing test_lifting.py
>>> from importlib import reload
>>> import test_lifting
success!
>>> # Add or fix any testcases
>>> reload(test_lifting)
success!
```

And, of course, you can open a test binary in Binary Ninja with this architecture built and activated to see if results are as expected.

## Requirements for Pull Requesters

1. **TEST!** If you're making an architecture or lifter change, add a test case to [test_lifting.py](./test_lifting.p) that fails before your change and succeeds after your change.

Please follow whatever formatting conventions are present in the file you edit. Pay attention to curly brackets, spacing, tabs vs. spaces, etc.

When you submit your first PR to one of Vector 35's repositories, you'll receive a notice from [CLA Assistant](https://cla-assistant.io/) that allows you to sign our [Contribution License Agreement](https://binary.ninja/cla.pdf) online.

## License

This code MIT licensed, see [LICENSE.txt](./license.txt).

It links against the [Capstone disassembly framework](https://github.com/aquynh/capstone) which is BSD licensed.
