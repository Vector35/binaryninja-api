# view-elf
This is the ELF view plugin that ships with Binary Ninja.

## Issues

Issues for this repository have been disabled. Please file an issue for this repository at https://github.com/Vector35/binaryninja-api/issues. All previously existing issues for this repository have been transferred there as well.

## Building

Building the architecture plugin requires `cmake` 3.9 or above. You will also need the
[Binary Ninja API source](https://github.com/Vector35/binaryninja-api).

Run `cmake`. This can be done either from a separate build directory or from the source
directory. Once that is complete, run `make` in the build directory to compile the plugin.

The plugin can be found in the root of the build directory as `libview_elf.so`,
`libview_elf.dylib` or `view_elf.dll` depending on your platform.

To install the plugin, first launch Binary Ninja and uncheck the "ELF view plugin"
option in the "Core Plugins" section. This will cause Binary Ninja to stop loading the
bundled plugin so that its replacement can be loaded. Once this is complete, you can copy
the plugin into the user plugins directory (you can locate this by using the "Open Plugin Folder"
option in the Binary Ninja UI).

**Do not replace the view plugin in the Binary Ninja install directory. This will be overwritten
every time there is a Binary Ninja update. Use the above process to ensure that updates do not
automatically uninstall your custom build.**
