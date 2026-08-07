# platform-linux
This is the Linux platform plugin that ships with Binary Ninja.

## Building

Building the architecture plugin requires `cmake` 3.9 or above. You will also need the
[Binary Ninja API source](https://github.com/Vector35/binaryninja-api).

Run `cmake`. This can be done either from a separate build directory or from the source
directory. Once that is complete, run `make` in the build directory to compile the plugin.

The plugin can be found in the root of the build directory as `libplatform_linux.so`,
`libplatform_linux.dylib` or `platform_linux.dll` depending on your platform.

To install the plugin, copy it into the user plugins directory (you can locate this by using
the "Open Plugin Folder" option in the Binary Ninja UI). This local plugin takes precedence
over the bundled Linux platform plugin. Restart Binary Ninja to load the local version.

**Do not replace the architecture plugin in the Binary Ninja install directory. This will
be overwritten every time there is a Binary Ninja update. Use the above process to ensure that
updates do not automatically uninstall your custom build.**
