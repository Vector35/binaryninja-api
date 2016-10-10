# Binary Ninja Python API Examples

The following examples demonstrate some of the Binary Ninja API. They include both stand-alone examples that directly call into the core without a GUI, as well as examples meant to be loaded as plugins available from the UI.

## Stand-alone

These plugins only operate when run directly outside of the UI

* bin_info.py - general binary information
* print_syscalls.py - extract syscall numbers from IL on specified file. Can be run both headless and in Binary Ninja
* version_switcher.py - uses the update API to see raw version notes and manually downgrade or upgrade
* instruction_iterator.py - very simple plugin that iterates through functions, blocks, and instructions

To use the stand-alone Python examples, make sure your `PYTHON_PATH` includes the API, as shown below. Please note, this is a feature that requires the "GUI-less processing" capability not available in the personal edition. In the personal edition, all scripts must by run from the integrated python console (follow the directions below under "Loading Plugins" section)

```
PYTHONPATH=$PYTHONPATH:/Applications/Binary\ Ninja.app/Contents/Resources/python
```

## GUI Plugins

These plugins require the UI to be running

* breakpoint.py - small example showing how to modify a file and register a GUI menu item
* jump_table.py - heuristic based jump table detection for when the data-flow based computation fails, triggered by right-clicking on the location where the jump value is computed
* angr_plugin.py - a plugin to demonstrate both background threads,  the simplified plugin UI elements, and highlighting
* export_svg.py - exports the graph view of a function to an SVG file for including in reports

## Both

These plugins are able to operate in either the GUI or as stand-alone plugins

* nes.py - 6502 CPU architecture including LLIL lifting and `.NES` file format parser


## Loading Plugins

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
