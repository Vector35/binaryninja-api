# Binary Ninja Python API Examples

The following examples demonstrate some of the Binary Ninja API. They include both stand-alone examples that directly call into the core without a GUI, as well as examples meant to be loaded as plugins available from the UI.

## Stand-alone

These plugins only operate when run directly outside of the UI and require a commercial license

* bin_info.py - general binary information
* cli_dis.py - Command line disassembly utility
* cli_lift.py - Command line IL dumping utility
* feature_map.py - command line generation of the feature map
* instruction_iterator.py - very simple plugin that iterates through functions, blocks, and instructions
* print_syscalls.py - extract syscall numbers from IL on specified file. Can be run both headless and in Binary Ninja
* pe_stat.py - reimplementation of Z0MBIE's PE_STAT utility
* version_switcher.py - uses the update API to see raw version notes and manually downgrade or upgrade

To use the stand-alone Python examples, make sure your `PYTHON_PATH` includes the API, as shown below. Please note, this is a feature that requires the "GUI-less processing" capability not available in the personal edition. In the personal edition, all scripts must by run from the integrated python console (follow the directions below under "Loading Plugins" section)

```
PYTHONPATH=$PYTHONPATH:/Applications/Binary\ Ninja.app/Contents/Resources/python
```

## GUI Plugins

These plugins require the UI to be running

* angr_plugin.py - a plugin to demonstrate both background threads, simplified plugin UI elements, and highlighting
* asm_to_llil_view.py - demonstration of a custom [Flow Graph](https://api.binary.ninja/binaryninja.flowgraph-module.html) view showing both disassembly and llil in one graph
* breakpoint.py - simple plugin to demonstrate overwriting an offset with a breakpoint in a cross-platform manner
* breakpoint.py - small example showing how to modify a file and register a GUI menu item
* export_svg.py - exports the graph view of a function to an SVG file 
* helloglobarea.py - example [Global Area](https://api.binary.ninja/cpp/group__globalarea.html#class_global_area) UI element (like Log or Scripting Console)
* hellopane.py - example [Pane](https://api.binary.ninja/cpp/group__pane.html#class_pane) UI element (like the main views)
* hellosidebar.py - example [Sidebar](https://api.binary.ninja/cpp/group__sidebar.html) UI element (like the Symbol list)
* jump_table.py - heuristic based jump table detection for when the data-flow based computation fails, triggered by right-clicking on the location where the jump value is computed
* linear_mlil.py - deprecated (now supported internally, left purely as a code example) plugin generating a custom linear MLIL view
* make_code.py - plugin to render hex as disassembly without creating a function using a [DataRenderer](https://api.binary.ninja/binaryninja.datarender-module.html#binaryninja.datarender.DataRenderer)
* mapped_view.py - example view showing how to map regions in memory in a custom [BinaryView](https://api.binary.ninja/binaryninja.binaryview-module.html#binaryninja.binaryview.BinaryView)
* ui_notification_callbacks.py - example showing multiple UI notification callbacks
* [Snippets](https://github.com/Vector35/snippets) - powerful code-editing plugin for writing and managing python code-snippets with syntax highlightingd, hotkey binding and other features
* [Kaitai](https://github.com/Vector35/kaitai) - allows you to browse a hex dump within Binary Ninja with a tree view informed by [Kaitai Struct](https://kaitai.io).

## Both

These plugins are able to operate in either the GUI or as stand-alone plugins

* arch_hook.py - a plugin to demonstrate an architecture hook that allows modifying the behavior of a built in architecture without having to modify/rebuild the [open source architectures](https://github.com/vector35/?q=arch-&type=all&language=&sort=)
* debug_info.py - a custom debug info implementation that can be used to load additional debug information at initial file load time (used internally for DWARF and PDB support for example, but may be used for other custom formats)
* nds.py - File format loader for NDS rom files creating multiple views
* nes.py - 6502 CPU architecture including LLIL lifting and `.NES` file format parser
* nfs.py - nsf file format loader (music files extracted from NES roms)
* notification_callbacks.py - example plugin showing notification callbacks that can be used in the UI or headless
* typelib_create.py - Example script from the [Type Library documentation](https://docs.binary.ninja/dev/annotation.html#type-libraries)
* typelib_dump.py - Example script from the [Type Library documentation](https://docs.binary.ninja/dev/annotation.html#type-libraries)


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
