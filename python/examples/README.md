# Binary Ninja Python API Examples

The following examples demonstrate some of the Binary Ninja API. They include both stand-alone examples that directly call into the core without a GUI, as well as examples meant to be loaded as plugins available from the UI.

## Stand-alone

* bin-info.py - general binary information
* arm-syscall.py - extract syscall numbers from IL for arm Mach-O files
* version-switcher.py - uses the update API to see raw version notes and manually downgrade or upgrade

To use the stand-alone Python examples, make sure your `PYTHON_PATH` includes the API, like:

```
PYTHONPATH=$PYTHONPATH:/Applications/Binary\ Ninja.app/Contents/Resources/python
```

## GUI Plugins

* nes.py - 6502 CPU architecture including LLIL lifting and `.NES` file format parser
* breakpoint.py - small example showing how to modify a file and register a GUI menu item
* jump-table.py - stop-gap jump table plugin triggered via right-click menu at an indirect jump

Plugins are meant to be loaded into a running Binary Ninja GUI and should either be copied or symlinked into the appropriate plugin folder. You'll need to then re-start Binary Ninja.

### OSX

```
~/Library/Application Support/Binary Ninja/plugins
```

### Windows

```
%APPDATA%\Binary Ninja\plugins
```

### Linux

```
~/.binaryninja/plugins
```
