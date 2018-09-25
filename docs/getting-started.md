# Getting Started

Welcome to Binary Ninja. This introduction document is meant to quickly guide you over some of the most common uses of Binary Ninja.

## Directories

Binary Ninja uses two main locations. The first is the install path of the binary itself and the second is the user folders for user-installed content.

### Binary Path

Binaries are installed in the following locations by default:

- OS X: `/Applications/Binary Ninja.app`
- Windows: `C:\Program Files\Vector35\BinaryNinja`
- Linux: Wherever you extract it! (No standard location)

!!! Warning "Warning"
    Do not put any user content in the install-path of Binary Ninja. The auto-update process of Binary Ninja may replace any files included in these folders.

### User Folder

The base locations of user folders are:

- OS X: `~/Library/Application Support/Binary Ninja`
- Linux: `~/.binaryninja`
- Windows: `%APPDATA%\Binary Ninja`

Contents of the user folder includes:

- `lastrun`: A text file containing the directory of the last BinaryNinja binary path -- very useful for plugins to resolve the install locations in non-default settings or on linux.
- `license.dat`: License file
- `plugins/`: Folder containing all manually installed user plugins
- `repositories/`: Folder containing files and plugins managed by the [Plugin Manager API](https://api.binary.ninja/binaryninja.pluginmanager-module.html)
- `settings.json`: Advanced settings (see [settings](#settings))

![license popup >](/img/license-popup.png "License Popup")

## License

When you first run Binary Ninja, it will prompt you for your license key. You should have received your license key via email after your purchase. If not, please contact [support](https://binary.ninja/support).

Once the license key is installed, you can change it, back it up, or otherwise inspect it simply by looking inside the base of the user folder for `license.dat`.


## Linux Setup

Because linux install locations can vary widely, we do not assume a Binary Ninja has been installed in any particular folder on linux. Rather, you can simply run `binaryninja/scripts/linux-setup.sh` after extracting the zip and various file associations, icons, and other settings will be set up. Run it with `-h` to see the customization options.

## Loading Files

You can load files in many ways:

1. Drag-and-drop a file onto the Binary Ninja window
2. Use the `File/Open` menu or `Open` button on the start screen
3. Clicking an item in the recent files list
4. Running Binary Ninja with an optional command-line parameter
5. Opening a file from a URL via the `⌘-l` or `⌃-l` hotkey
6. Opening a file using the binaryninja: url handler. For security reasons, the url handler requires you to confirm a warning before opening a file via the url handler. The url handler can open remote URLs like: `binaryninja:https://captf2.captf.com/2015/plaidctf/pwnable/datastore_7e64104f876f0aa3f8330a409d9b9924.elf`, or even local files like `binarynina://bin/ls` in cases where you wish to script up Binary Ninja from a local webapp.

![recent files](/img/recent.png "Recent Files")


## Analysis

![auto analysis ><](/img/analysis.png "Auto Analysis")

As soon as you open a file, Binary Ninja begins its auto-analysis.

Even while Binary Ninja is analyzing a binary, the UI should be responsive. Not only that, but because the analysis prioritizes user-requested analysis, you can start navigating a binary immediately and any functions you select will be added to the top of the analysis queue. The current progress through a binary is shown in the status bar, but note that the total number of items left to analyze will go up as well as the binary is processed and more items are discovered that require analysis.

Errors or warnings during the load of the binary are also shown in the status bar, along with an icon (in the case of the image above, a large number of warnings were shown). The most common warnings are from incomplete lifting and can be safely ignored. If the warnings include a message like `Data flow for function at 0x41414141 did not terminate`, then please report the binary to the [bug database][issues].

## Interacting

### Navigating

Navigating code in Binary Ninja is usually a case of just double-clicking where you want to go. Addresses, references, functions, jmp edges, etc, can all be double-clicked to navigate. Additionally, The `g` hotkey can navigate to a specific address in the current view.

![graph view](/img/view-choices.png "Different Views")

Switching views happens multiple ways. In some instances, it's automatic (clicking a data reference from graph view will navigate to linear view as data is not shown in the graph view), and there are multiple ways to manually change views as well. While navigating, you can use the view hotkeys (see below) to switch to a specific view at the same location as the current selection. Alternatively, the view menu in the bottom-right can be used to change views without navigating to any given location.

### Hotkeys

 - `h` : Switch to hex view
 - `p` : Create a function
 - `[ESC]` : Navigate backward
 - `[CMD] [` (OS X) : Navigate backward
 - `[CMD] ]` (OS X) : Navigate forward
 - `[CTRL] [` (Windows/Linux) : Navigate backward
 - `[CTRL] ]` (Windows/Linux) : Navigate forward
 - `[SPACE]` : Toggle between linear view and graph view
 - `g` : Go To Address dialog
 - `n` : Name a symbol
 - `u` : Undefine a symbol
 - `e` : Edits an instruction (by modifying the original binary -- currently only enabled for x86, and x64)
 - `x` : Focuses the cross-reference pane
 - `;` : Adds a comment
 - `i` : Cycles between disassembly, low-level il, and medium-level il in graph view
 - `y` : Change type
 - `a` : Change the data type to an ASCII string
 - [1248] : Change type directly to a data variable of the indicated widths
 - `a` : Change the data type to an ASCII string
 - `d` : Switches between data variables of various widths
 - `r` : Change the data type to single ASCII character
 - `o` : Create a pointer data type
 - `[CMD-SHIFT] +` (OS X) : Graph view zoom in
 - `[CMD-SHIFT] -` (OS X) : Graph view zoom out
 - `[CTRL-SHIFT] +` (Windows/Linux) : Graph view zoom in
 - `[CTRL-SHIFT] -` (Windows/Linux) : Graph view zoom out

### Graph View

![graph view](/img/graphview.png "Graph View")

The default view in Binary Ninja when opening a binary is a graph view that groups the basic blocks of disassembly into visually distinct blocks with edges showing control flow between them.

![graph view context >](/img/graphcontext.png "Graph View Contet Menu")

Features of the graph view include:

- Ability to double click edges to quickly jump between locations
- Zoom (CTRL-mouse wheel)
- Vertical Scrolling (Side scroll bar as well as mouse wheel)
- Horizontal Scrolling (Bottom scroll bar as well as SHIFT-mouse wheel)
- Individual highlighting of arguments, addresses, immediate values
- Edge colors indicate whether the path is the true or false case of a conditional jump (a color-blind option in the preferences is useful for those with red-green color blindness)
- Context menu that can trigger some function-wide actions as well as some specific to the highlighted instruction (such as inverting branch logic or replacing a specific function with a NOP)

### View Options

![options ><](/img/options.png "options")

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

![hex >](/img/hex.png "hex view")

The hexadecimal view is useful for view raw binary files that may or may not even be executable binaries. The hex view is particularly good for transforming data in various ways via the `Copy as`, `Transform`, and `Paste from` menus. Note that `Transform` menu options will transform the data in-place, and that these options will only work when the Hex View is in the `Raw` mode as opposd to any of the binary views (such as "ELF", "Mach-O", or "PE").

Note that any changes made in the Hex view will take effect immediately in any other views open into the same file (new views can be created via the `Split to new tab`, or `Split to new window` options under `View`.). This can, however, cause large amounts of re-analysis so be warned before making large edits or transformations in a large binary file.

### Xrefs View

![xrefs >](/img/xrefs.png "xrefs")

The xrefs view in the lower-left shows all cross-references to a given location or reference. Note that the cross-references pane will change depending on whether an entire line is selected (all cross-references to that address are shown), or whether a specific token within the line is selected.

One fun trick that the xrefs view has up its sleeve: when in [Hex View](#hex-view), a large range of memory addresses can be selected and the xrefs pane will show all xrefs to any location within that range of data.

### Linear View

![linear](/img/linear.png "linear view")

Linear view is a hybrid view between a graph-based disassembly window and the raw hex view. It lists the entire binary's memory in a linear fashion and is especially useful when trying to find sections of a binary that were not properly identified as code or even just examining data.

Linear view is most commonly used for identifying and adding type information for unknown data. To this end,


### Function List

![function list >](/img/functionlist.png "Function List")

The function list in Binary Ninja shows the list of functions currently identified. As large binaries are analyzed, the list may grow during analysis. The function list starts with known functions such as the entry point, exports, or using other features of the binary file format and explores from there to identify other functions.

The function list also highlights imports, and functions identified with symbols in different colors to make them easier to identify.

!!! Tip "Tip"
    To search in the function list, just click to make sure it's focused and start typing!

### Script (Python) Console

![console >](/img/console.png "Console")

The integrated script console is useful for small scripts that aren't worth writing as full plugins.

To trigger the console, either use `<CTRL>-<BACKTICK>`, or use the `View`/`Script console` menu.

Once loaded, the script console can be docked in different locations or popped out into a stand-alone window. Note that [at this time](https://github.com/Vector35/binaryninja-api/issues/226) window locations are not saved on restart.

Multi-line input is possible just by doing what you'd normally do in python. If you leave a trailing `:` at the end of a line, the box will automatically turn into a multi-line edit box, complete with a command-history. To submit that multi-line input, use `<CTRL>-<ENTER>`

By default the interactive python prompt has a number of convenient helper functions and variables built in:

- `here` / `current_address`: address of the current selection
- `bv` / `current_view` / : the current [BinaryView](https://api.binary.ninja/binaryninja.BinaryView.html)
- `current_function`: the current [Function](https://api.binary.ninja/binaryninja.Function.html)
- `current_basic_block`: the current [BasicBlock](https://api.binary.ninja/binaryninja.BasicBlock.html)
- `current_llil`: the current [LowLevelILFunction](https://api.binary.ninja/binaryninja.lowlevelil.LowLevelILFunction.html)
- `current_mlil`: the current [MediumLevelILFunction](https://api.binary.ninja/binaryninja.mediumlevelil.MediumLevelILFunction.html)
- `current_selection`: a tuple of the start and end addresses of the current selection
- `write_at_cursor(data)`: function that writes data to the start of the current selection
- `get_selected_data()`: function that returns the data in the current selection

Note
!!! Tip "Note"
    The current script console only supports Python at the moment, but it's fully extensible for other programming languages for advanced users who wish to implement their own bindings.

## Using Plugins

Plugins can be installed by one of two methods. First, they can be manually installed by adding the plugin (either a `.py` file or a folder implementing a python module with a `__init__.py` file) to the appropriate path:

- OS X: `~/Library/Application Support/Binary Ninja/plugins/`
- Linux: `~/.binaryninja/plugins/`
- Windows: `%APPDATA%\Binary Ninja\plugins`

Alternatively, plugins can be installed with the new [pluginmanager](https://api.binary.ninja/binaryninja.pluginmanager-module.html) API.

For more detailed information, see the [plugin guide](/guide/plugins).

## PDB Plugin

Binary Ninja supports loading PDB files through the built in PDB plugin. When selected from the plugin menu it attempts to find where the corresponding PDB file is located using the following search order:

1. Look for in the same directory as the opened file/bndb (e.g. If you ahve `c:\foo.exe` or `c:\foo.bndb` open the pdb plugin looks for `c:\foo.pdb`)
2. Look in the local symbol store. This is the directory specified by the settings: `local-store-relative` or `local-store-absolute`. The format of this directory is `foo.pdb\<guid>\foo.pdb`.
3. Attempt to connect and download the PDB from the list of symbol servers specified in setting `symbol-server-list`.
4. Prompt the user for the pdb.

## Preferences/Updates

![preferences >](/img/preferences.png "Preferences")

Binary Ninja automatically updates itself by default. This functionality can be disabled in the preferences by turning off the `Update to latest version automatically` option. Updates are silently downloaded in the background and when complete an option to restart is displayed in the status bar. Whenever Binary Ninja restarts next, it will replace itself with the new version as it launches.

On windows, this is achieved through a separate launcher that loads first and replaces the installation before launching the new version. On OS X and Linux, the original installation is overwritten after the update occurs as these operating systems allow files to be replaced while running. The update on restart is thus immediate.

## Settings

Settings are stored in the _user_ directory in the file `settings.json`. Each top level object in this file is represents a different plugin.  As of build 860 the following settings are available:

|Plugin     | Setting                  | Type         | Default                                            | Description                                                                                         |
|----------:|-------------------------:|-------------:|---------------------------------------------------:|:----------------------------------------------------------------------------------------------------|
| analysis  | autorunLinearSweep       | boolean      | True                                               | Automatically run linear sweep when opening a binary for analysis                                   |
| analysis  | enabledUnicodeBlocks     | list(string) | []                                                 | Defines which Unicode blocks to consider when searching for strings                                 |
| analysis  | enableUTF8               | boolean      | True                                               | Whether or not to consider UTF-8 code points when searching for strings                             |
| analysis  | enableUTF16              | boolean      | True                                               | Whether or not to consider UTF-16 code points when searching for strings                            |
| analysis  | enableUTF32              | boolean      | True                                               | Whether or not to consider UTF-32 code points when searching for strings                            |
| analysis  | max-function-size        | integer      | 65536                                              | Any functions over this size will not be automatically analyzed and require manual override         |
| core      | linux\_ca\_bundle        | string       | ""                                                 | Certificate authority (.pem or .crt) file to be used for secure downloads                           |
| core      | linux\_ca\_dir           | string       | ""                                                 | Certificate authority directory (for distributions without a CA bundle)                             |
| ui        | activeContent            | boolean      | True                                               | Allow Binary Ninja to connect to the web to check for updates                                       |
| ui        | colorblind               | boolean      | True                                               | Choose colors that are visible to those with red/green colorblind                                   |
| ui        | debug                    | boolean      | False                                              | Enable developer debugging features (Additional views: Lifted IL, and SSA forms)                    |
| ui        | recent-file-limit        | integer      | 10                                                 | Specify limit for number of recent files                                                            |
| ui        | scriptingProvider        | string       | "Python"                                           | Specify the registered ScriptingProvider that controls the 'Console' in the UI                      |
| pdb       | local-store-absolute     | string       | ""                                                 | Absolute path specifying where the pdb symbol store exists on this machine, overrides relative path |
| pdb       | local-store-relative     | string       | "symbols"                                          | Path *relative* to the binaryninja _user_ directory, sepcifying the pdb symbol store                |
| pdb       | auto-download-pdb        | boolean      | True                                               | Automatically download pdb files from specified symbol servers                                      |
| pdb       | symbol-server-list       | list(string) | ["http://msdl.microsoft.com/download/symbols"]     | List of servers to query for pdb symbols.                                                           |
| python    | interpreter              | string       | "{/path/,C:\\\\Path\\\\}python27.{dylib,dll,so.1}" | Python interpreter to load if one is not already present when plugins are loaded                    |
| arch      | x86.disassemblyFlavor    | string       | "BN_INTEL"                                         | "BN_INTEL", "INTEL", or "AT&T"                                                                      |
| arch      | x86.disassemblySeperator | string       | ", "                                               | What to put between operands in disassembly tokens                                                  |
| arch      | x86.disassemblyLowercase | bool         | True                                               | Lowercase opcodes, operands, and registers (False for uppercase)                                    |

Below is an example `settings.json` setting various options:
```
{
    "ui" :
    {
        "activeContent" : false,
        "colorblind" : false,
        "debug" : true,
        "recent-file-limit" : 10
    }
    "pdb" :
    {
        "local-store-absolute" : "C:\\Symbols",
        "local-store-relative" : "",
        "symbol-server-list" : ["http://mysymbolserver.company.lan"]
    },
	"python":
	{
		"interpreter": "C:\\Users\\Binja\\AppData\\Local\\Programs\\Python\\Python37\\python37.dll"
	}
}
```

## Unicode Support

Currently, Unicode support for Big Endian strings is very limited. Also, UTF-16 only supports Basic Latin code points.

## Getting Support

Vector 35 offers a number of ways to get Binary Ninja [support](https://binary.ninja/support/).
