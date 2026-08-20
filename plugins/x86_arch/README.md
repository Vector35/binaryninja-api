# arch-x86
This is the x86/x64 plugin that ships with Binary Ninja.

## Contributing

If you're interested in contributing when you submit your first PR, you'll receive a notice from [CLA Assistant](https://cla-assistant.io/) that allows you to sign our [Contribution License Agreement](https://binary.ninja/cla.pdf) online. 

## Building

Building the architecture plugin requires `cmake` 3.13 or above. You will also need the
[Binary Ninja API source](https://github.com/Vector35/binaryninja-api).

Run `cmake`. This can be done either from a separate build directory or from the source
directory. Once that is complete, run `make` in the build directory to compile the plugin.

The plugin can be found in the root of the build directory as `libarch_x86.so`,
`libarch_x86.dylib` or `arch_x86.dll` depending on your platform.

To install the plugin, first launch Binary Ninja and uncheck the "x86 architecture plugin"
option in the "Core Plugins" section. This will cause Binary Ninja to stop loading the
bundled plugin so that its replacement can be loaded. Once this is complete, you can copy
the plugin into the user plugins directory (you can locate this by using the "Open Plugin Folder"
option in the Binary Ninja UI).

**Do not replace the architecture plugin in the Binary Ninja install directory. This will
be overwritten every time there is a Binary Ninja update. Use the above process to ensure that
updates do not automatically uninstall your custom build.**

## XED

XED is submoduled into the `xed` sub-directory at the specific commit we build with.

As of January 16, 2026, we do not maintain a patchset on top of this upstream dependency.

## License

This repository itself is released under an [Apache 2.0](./license) license. Note that it relies on the following additional libraries each available under their respective licenses:

- [Intel XED](https://intelxed.github.io/): [Apache 2.0](https://github.com/intelxed/xed/blob/master/LICENSE)
- [YASM](https://yasm.tortall.net/): ["new" BSD License](http://github.com/yasm/yasm/blob/master/BSD.txt) (inside of [./yasm/](yasm/))
