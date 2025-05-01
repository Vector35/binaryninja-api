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

XED is at commit afbb851b5f2f2ac6cdb6e6d9bebbaf2d4e77286d (April 15 2020)

To update XED, first run `make download` to download the latest source and make necessary patches to it. Then run `make <platform>` to build xed for the selected platform. If everything works out, run `make clean_repo` to remove the downloaded mbuild and xed source.

Update July 2020:

Commit 9bdeca6d77065e5f1b23891655a26e510ffae74a changes the order of segement registers in the generated xed-reg-enum.h. If left unattended, this will cause database descrepency. Currently, we revert the commit 9bdeca6d77065e5f1b23891655a26e510ffae74a before building xed. This does not affect the xed's own functionality since the xed tests still pass without any issue.

## License

This repository itself is released under an [Apache 2.0](./license) license. Note that it relies on the following additional libraries each available under their respective licenses:

- [Intel XED](https://intelxed.github.io/): [Apache 2.0](https://github.com/intelxed/xed/blob/master/LICENSE)
- [YASM](https://yasm.tortall.net/): ["new" BSD License](http://github.com/yasm/yasm/blob/master/BSD.txt) (inside of [./yasm/](yasm/))
