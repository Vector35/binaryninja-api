# Getting Started

Welcome to Binary Ninja. This introduction document is meant to quickly guide you over some of the most common uses of Binary Ninja.

![license popup](/images/license-popup.png "License Popup")

## License

When you first run Binary Ninja, it will prompt you for your license key. You should have received your license key via email after your purchase. If not, please contact [support].

Once the license key is installed, you can change it, back it up, or otherwise inspect it simply by looking in:

- OS X: `~/Library/Application Support/Binary Ninja`
- Linux: `~/.binaryninja`
- Windows: `%APPDATA%\Binary Ninja`

## Loading Files

You can load files in many ways:

1. Drag-and-drop a file onto the Binary Ninja window
2. Use the `File/Open` menu or `Open` button on the start screen
3. Clicking an item in the recent files list
4. Running Binary Ninja with an optional command-line parameter
5. Opening a file from a URL via the `⌘-l` or `⌃-l` hotkey
6. Opening a file using the binaryninja: url handler. For security reasons, the url handler requires you to confirm a warning before opening a file via the url handler. The url handler can open remote URLs like: `binaryninja:https://captf.com/2015/plaidctf/pwnable/datastore_7e64104f876f0aa3f8330a409d9b9924.elf`, or even local files like `binarynina://bin/ls` in cases where you wish to script up Binary Ninja from a local webapp.

![recent files](/images/recent.png "Recent Files")


## Analysis

![auto analysis](/images/analysis.png "Auto Analysis")

As soon as you open a file, Binary Ninja begins its auto-analysis.

Even while Binary Ninja is analyzing a binary, the UI should be responsive. Not only that, but because the analysis prioritizes user-requested analysis, you can start navigating a binary immediately and any functions you select will be added to the top of the analysis queue. The current progress through a binary is shown in the status bar, but note that the total number of items left to analyze will go up as well as the binary is processed and more items are discovered that require analysis.

Errors or warnings during the load of the binary are also shown in the status bar, along with an icon (in the case of the image above, a large number of warnings were shown). The most common warnings are from incomplete lifting and can be safely ignored. If the warnings include a message like `Data flow for function at 0x41414141 did not terminate`, then please report the binary to the [bug database][issues].

## Interacting

### Hotkeys

 - "h" : Switch to hex view
 - "p" : Create a function
 - &lt;ESC&gt; : Navigate backward
 - &lt;SPACE&gt; : Toggle between linear view and graph view
 - "g" : Go To Address dialog
 - "n" : Name a symbol
 - "u" : Undefine a symbol
 - "e" : Edits an instruction (by modifying the original binary -- currently only enabled for x86, and x64)
 - "x" : Focuses the cross-reference pane
 - ";" : Adds a comment
 - "l" : Switches between disassembly and low-level il in graph view
 - "y" : Change type
 - [1248] : Change type directly to a data variable of the indicated widths
 - "d" : Switches between data variables of various widths
 - "r" : Change the data type to single ASCII character
 - "o" : Create a pointer data type

### Graph View

![graph view](/images/graphview.png "Graph View")

The default view in Binary Ninja when opening a binary is a graph view that groups the basic blocks of disassembly into visually distinct blocks with edges showing control flow between them.

![graph view context](/images/graphcontext.png "Graph View Contet Menu")

Features of the graph view include:

- Ability to double click edges to quickly jump between locations
- Zoom (CTRL-mouse wheel)
- Vertical Scrolling (Side scroll bar as well as mouse wheel)
- Horizontal Scrolling (Bottom scroll bar as well as SHIFT-mouse wheel)
- Individual highlighting of arguments, addresses, immediate values
- Edge colors indicate whether the path is the true or false case of a conditional jump (a color-blind option in the preferences is useful for those with red-green color blindness)
- Context menu that can trigger some function-wide actions as well as some specific to the highlighted instruction (such as inverting branch logic or replacing a specific function with a NOP)

### View Options

![options](/images/options.png "options")

Each of the views (Hex, Graph, Linear) have a variety of options configurable in the bottom-right of the UI.

Current options include:

- Hex
    - Background highlight
        - None
        - Column
        - Byte value
    - Color highlight
        - None
        - ASCII and printable
        - Modification
    - Contrast
        - Normal
        - Medium
        - Highlight
- Graph
    - Show address
    - Show opcode bytes
    - Assembly
    - Lifted IL
        - Show IL flag usage (if showing Lifted IL)
    - Low Level IL
        - Show basic block register state (if showing Low Level IL)
- Linear
    - Show address
    - Show opcode bytes

### Hex View

![hex](/images/hex.png "hex view")

The hexadecimal view is useful for view raw binary files that may or may not even be executable binaries. The hex view is particularly good for transforming data in various ways via the `Copy as`, `Transform`, and `Paste from` menus. Note that `Transform` menu options will transform the data in-place, and that these options will only work when the Hex View is in the `Raw` mode as opposd to any of the binary views (such as "ELF", "Mach-O", or "PE").

Note that any changes made in the Hex view will take effect immediately in any other views open into the same file (new views can be created via the `Split to new tab`, or `Split to new window` options under `View`.). This can, however, cause large amounts of re-analysis so be warned before making large edits or transformations in a large binary file.

### Xrefs View

![xrefs](/images/xrefs.png "xrefs")

The xrefs view in the lower-left shows all cross-references to a given location or reference. Note that the cross-references pane will change depending on whether an entire line is selected (all cross-references to that address are shown), or whether a specific token within the line is selected.

One fun trick that the xrefs view has up its sleeve: when in [Hex View](#hexview), a large range of memory addresses can be selected and the xrefs pane will show all xrefs to any location within that range of data.

### Linear View

![linear](/images/linear.png "linear view")

Linear view is a hybrid view between a graph-based disassembly window and the raw hex view. It lists the entire binary's memory in a linear fashion and is especially useful when trying to find sections of a binary that were not properly identified as code or even just examining data.

Linear view is most commonly used for identifying and adding type information for unknown data. To this end,


### Function List

![function list](/images/functionlist.png "Function List")

The function list in Binary Ninja shows the list of functions currently identified. As large binaries are analyzed, the list may grow during analysis. The function list starts with known functions such as the entry point, exports, or using other features of the binary file format and explores from there to identify other functions.

The function list also highlights imports, and functions identified with symbols in different colors to make them easier to identify.

!!! Tip "Tip"
    To search in the function list, just click to make sure it's focused and start typing!

### Script (Python) Console

![console](/images/console.png "Console")

The integrated script console is useful for small scripts that aren't worth writing as full plugins.

To trigger the console, either use `<CTRL>-<BACKTICK>` (markdown can't handle the \` character inside of an escaped block), or use the `View`/`Script console` menu.

Once loaded, the script console can be docked in different locations or popped out into a stand-alone window. Note that [at this time](https://github.com/Vector35/binaryninja-api/issues/226) window locations are not saved on restart.

Multi-line input is possible just by doing what you'd normally do in python. If you leave a trailing `:` at the end of a line, the box will automatically turn into a multi-line edit box, complete with a command-history. To submit that multi-line input, use `<CTRL>-<ENTER>`

By default the interactive python prompt has a number of convenient helper functions and variables built in:

- `here` / `current_address`: address of the current selection
- `bv` / `current_view` / : the current [BinaryView](https://api.binary.ninja/binaryninja.BinaryView.html)
- `current_function`: the current [Function](https://api.binary.ninja/binaryninja.Function.html)
- `current_basic_block`: the current [BasicBlock](https://api.binary.ninja/binaryninja.BasicBlock.html)
- `current_selection`: a tuple of the start and end addresses of the current selection
- `write_at_cursor(data)`: function that writes data to the start of the current selection
- `get_selected_data()`: function that returns the data in the current selection

Note
!!! Tip "Note"
    The current script console only supports Python at the moment, but it's fully extensible for other programming languages for advanced users who with to implement their own bindings.

## Preferences/Updates

![preferences](/images/preferences.png "Preferences")

Binary Ninja automatically updates itself by default. This functionality can be disabled in the preferences by turning off the `Update to latest version automatically` option. Updates are silently downloaded in the background and when complete an option to restart is displayed in the status bar. Whenever Binary Ninja restarts next, it will replace itself with the new version as it launches.

On windows, this is achieved through a separate launcher that loads first and replaces the installation before launching the new version. On OS X and Linux, the original installation is overwritten after the update occurs as these operating systems allow files to be replaced while running. The update on restart is thus immediate.

Most preferences are fairly intuitive. There is no advanced preference system at this time, but it is [expected](https://github.com/Vector35/binaryninja-api/issues/126) to be added soon.

## Getting Support

Vector 35 offers a number of ways to get Binary Ninja [support].

[support]: https://binary.ninja/support.html
