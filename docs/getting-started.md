# Getting Started

Welcome to Binary Ninja. This introduction document is meant to quickly guide you over some of the most common uses of Binary Ninja.

## Directories

Binary Ninja uses two main locations. The first is the install path of the binary itself and the second is the user folders for user-installed content.

### Binary Path

Binaries are installed in the following locations by default:

- MacOS: `/Applications/Binary Ninja.app`
- Windows (global install): `C:\Program Files\Vector35\BinaryNinja`
- Windows (user install): `%LOCALAPPDATA%\Vector35\BinaryNinja`
- Linux: Wherever you extract it! (No standard location)

!!! Warning "Warning"
    Do not put any user content in the install-path of Binary Ninja. The auto-update process of Binary Ninja may replace any files included in these folders.

### User Folder

The base locations of user folders are:

- MacOS: `~/Library/Application Support/Binary Ninja`
- Linux: `~/.binaryninja`
- Windows: `%APPDATA%\Binary Ninja`

Contents of the user folder includes:

- `lastrun`: A text file containing the directory of the last BinaryNinja binary path -- very useful for plugins to resolve the install locations in non-default settings or on Linux.
- `license.dat`: License file
- `plugins/`: Folder containing all manually installed user plugins
- `repositories/`: Folder containing files and plugins managed by the [Plugin Manager API](https://api.binary.ninja/binaryninja.pluginmanager-module.html)
- `settings.json`: User settings file (see [settings](#settings))
- `keybindings.json`: Custom key bindings (see [key bindings](#custom-keybindings))

![license pop-up >](img/license-popup.png "License Popup")

## License

When you first run Binary Ninja, it will prompt you for your license key. You should have received your license key via email after your purchase. If not, please contact [support](https://binary.ninja/support).

Once the license key is installed, you can change it, back it up, or otherwise inspect it simply by looking inside the base of the user folder for `license.dat`.


## Linux Setup

Because Linux install locations can vary widely, we do not assume a Binary Ninja has been installed in any particular folder on Linux. Rather, you can simply run `binaryninja/scripts/linux-setup.sh` after extracting the zip and various file associations, icons, and other settings will be set up. Run it with `-h` to see the customization options.

## Loading Files

You can load files in many ways:

![open with options >](img/open-with-options.png "Open with Options")

1. Drag-and-drop a file onto the Binary Ninja window
2. Use the `File/Open` menu or `Open` button on the start screen (`CMD-o` or `CTL-o`)
3. Use the `File/Open with Options` menu which allows you to customize the analysis options (`CMD-SHIFT-o` or `CTL-SHIFT-o`)
4. Open a file from the Triage picker (`File/Open for Triage`) which enables several minimal analysis options and shows a summary view first
5. Clicking an item in the recent files list (hold `CMD`/`CTL` and `SHIFT` while clicking to use the `Open with Options` workflow)
6. Running Binary Ninja with an optional command-line parameter
7. Opening a file from a URL via the `CMD-l` or `CTRL-l` hot key
8. Opening a file using the binaryninja: URL handler. For security reasons, the URL handler requires you to confirm a warning before opening a file via the URL handler. The URL handler can open remote URLs like: `binaryninja:https://captf2.captf.com/2015/plaidctf/pwnable/datastore_7e64104f876f0aa3f8330a409d9b9924.elf`, or even local files like `binarynina://bin/ls` in cases where you wish to script up Binary Ninja from a local web application.

## Analysis

![auto analysis >](img/analysis.png "Auto Analysis")

As soon as you open a file, Binary Ninja begins its auto-analysis which is fairly similar to decompiling the entire binary.

Even while Binary Ninja is analyzing a binary, the UI should be responsive. Not only that, but because the analysis prioritizes user-requested analysis, you can start navigating a binary immediately and wherever you are viewing will be prioritized for analysis. The current progress through a binary is shown in the status bar (more details are available via `bv.analysis_info` in the Python console), but note that the total number of items left to analyze will go up as well as the binary is processed and more items are discovered that require analysis.

Errors or warnings during the load of the binary are also shown in the status bar, along with an icon (in the case of the image above, a large number of warnings were shown). The most common warnings are from incomplete lifting and can be safely ignored. If the warnings include a message like `Data flow for function at 0x41414141 did not terminate`, then please report the binary to the [bug database](https://github.com/Vector35/binaryninja-api/issues).

### Analysis Speed

If you wish to speed up analysis, you have several options. The first is to use the `File/Open for Triage` menu which activates the Triage file picker. By default, [Triage mode](https://binary.ninja/2019/04/01/hackathon-2019-summary.html#triage-mode-rusty) will enable a faster set of default analysis options that doesn't provide as much in-depth analysis but is significantly faster.

Additionally, using the [open with options](#loading-files) feature allows for customization of a number of analysis options on a per-binary basis. See [all settings](#all-settings) under the `analysis` category for more details.

## Interacting

### Navigating

Navigating code in Binary Ninja is usually a case of just double-clicking where you want to go. Addresses, references, functions, jmp edges, etc, can all be double-clicked to navigate. Additionally, The `g` hot key can navigate to a specific address in the current view.

![graph view](img/view-choices.png "Different Views")

Switching views happens multiple ways. In some instances, it is automatic (clicking a data reference from graph view will navigate to linear view as data is not shown in the graph view), and there are multiple ways to manually change views as well. While navigating, you can use the view hot keys (see below) to switch to a specific view at the same location as the current selection. Alternatively, the view menu in the bottom-right can be used to change views without navigating to any given location.

### Command-Palette

![command palette](img/command-palette.png "Command Palette")

One great feature for quickly navigating through a variety of options and actions is the `command palette`. Inspired by similar features in [Sublime](http://docs.sublimetext.info/en/latest/reference/command_palette.html), and [VS Code](https://code.visualstudio.com/docs/getstarted/userinterface#_command-palette), the command-palette is a front end into an application-wide, context-sensitve action system that all actions, plugins, and hotekys in the system are routed through.

To trigger it, simply use the `CMD-p` or `CTRL-p` hot key. Note that the command-palette is context-sensitive and therefore some actions (for example, `Display as - Binary`) may only be available depending on your current view or selection. This is also available to plugins. For example, a plugin may use [PluginCommand.register](https://api.binary.ninja/binaryninja.plugin-module.html#binaryninja.plugin.PluginCommand.register) with the optional `is_valid` callback to determine whether the action should be available.

### Custom Hotkeys

![keybindings](img/keybindings.png "Keybindings")

Any action in the [action system](#command-palette) can have a custom hot key mapped to it. To access the keybindings menu, use the `CMD-SHIFT-p` or `CTRL-SHIFT-p` hot key, via the `Edit / Keybindings...` menu, or the `Keybindings` [command palette](#commnad-palette) entry.

Note
!!! Tip "Note"
    On MacOS, `Ctrl` refers to the Command key, while `Meta` refers to the Control key. This is a remapping performed by Qt to make cross-platform keybindings easier to define.

!!! Tip "Tip"
    To search in the keybindings list, just click to make sure it's focused and start typing!

### Default Hotkeys

 - `h` : Switch to hex view
 - `p` : Create a function
 - `[ESC]` : Navigate backward
 - `[CMD] [` (MacOS) : Navigate backward
 - `[CMD] ]` (MacOS) : Navigate forward
 - `[CTRL] [` (Windows/Linux) : Navigate backward
 - `[CTRL] ]` (Windows/Linux) : Navigate forward
 - `[SPACE]` : Toggle between linear view and graph view
 - `g` : Go To Address dialog
 - `n` : Name a symbol
 - `u` : Undefine an existing symbol (only for removing new user-defined names)
 - `e` : Edits an instruction (by modifying the original binary -- currently only enabled for x86, and x64)
 - `x` : Focuses the cross-reference pane
 - `;` : Adds a comment
 - `i` : Cycles between disassembly, low-level il, and medium-level il in graph view
 - `t` : Switch to type view
 - `y` : Change type
 - `a` : Change the data type to an ASCII string
 - [1248] : Change type directly to a data variable of the indicated widths
 - `d` : Switches between data variables of various widths
 - `r` : Change the data type to single ASCII character
 - `o` : Create a pointer data type
 - `[CMD-SHIFT] +` (MacOS) : Graph view zoom in
 - `[CMD-SHIFT] -` (MacOS) : Graph view zoom out
 - `[CTRL-SHIFT] +` (Windows/Linux) : Graph view zoom in
 - `[CTRL-SHIFT] -` (Windows/Linux) : Graph view zoom out

### Graph View

![graph view](img/graphview.png "Graph View")

The default view in Binary Ninja when opening a binary is a graph view that groups the basic blocks of disassembly into visually distinct blocks with edges showing control flow between them.

![graph view context >](img/graphcontext.png "Graph View Contet Menu")

Features of the graph view include:

- Ability to double click edges to quickly jump between locations
- Zoom (CTRL-mouse wheel)
- Vertical Scrolling (Side scroll bar as well as mouse wheel)
- Horizontal Scrolling (Bottom scroll bar as well as SHIFT-mouse wheel)
- Individual highlighting of arguments, addresses, immediate values
- Edge colors indicate whether the path is the true or false case of a conditional jump (a color-blind option in the preferences is useful for those with red-green color blindness)
- Context menu that can trigger some function-wide actions as well as some specific to the highlighted instruction (such as inverting branch logic or replacing a specific function with a NOP)

### View Options

![options ><](img/options.png "options")

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

![hex >](img/hex.png "hex view")

### Hex View

The hexadecimal view is useful for view raw binary files that may or may not even be executable binaries. The hex view is particularly good for transforming data in various ways via the `Copy as`, `Transform`, and `Paste from` menus. Note that `Transform` menu options will transform the data in-place, and that these options will only work when the Hex View is in the `Raw` mode as opposed to any of the binary views (such as "ELF", "Mach-O", or "PE").

!!! Tip "Tip"
    Any changes made in the Hex view will take effect immediately in any other views open into the same file (new views can be created via the `Split to new tab`, or `Split to new window` options under `View`.). This can, however, cause large amounts of re-analysis so be warned before making large edits or transformations in a large binary file.

### Xrefs View

![xrefs <](img/xrefs.png "xrefs")

The xrefs view in the lower-left shows all cross-references to a given location or reference. Note that the cross-references pane will change depending on whether an entire line is selected (all cross-references to that address are shown), or whether a specific token within the line is selected.

One fun trick that the xrefs view has up its sleeve: when in [Hex View](#hex-view), a large range of memory addresses can be selected and the xrefs pane will show all xrefs to any location within that range of data.

### Linear View

![linear](img/linear.png "linear view")

Linear view is a hybrid view between a graph-based disassembly window and the raw hex view. It lists the entire binary's memory in a linear fashion and is especially useful when trying to find sections of a binary that were not properly identified as code or even just examining data.

Linear view is most commonly used for identifying and adding type information for unknown data. To this end,

### Function List

![function list >](img/functionlist.png "Function List")

The function list in Binary Ninja shows the list of functions currently identified. As large binaries are analyzed, the list may grow during analysis. The function list starts with known functions such as the entry point, exports, or using other features of the binary file format and explores from there to identify other functions.

The function list also highlights imports, and functions identified with symbols in different colors to make them easier to identify.

!!! Tip "Tip"
    To search in the function list, just click to make sure it's focused and start typing!

![console >](img/console.png "Console")

### Script (Python) Console

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

- MacOS: `~/Library/Application Support/Binary Ninja/plugins/`
- Linux: `~/.binaryninja/plugins/`
- Windows: `%APPDATA%\Binary Ninja\plugins`

Alternatively, plugins can be installed with the new [pluginmanager](https://api.binary.ninja/binaryninja.pluginmanager-module.html) API.

For more detailed information on plugins, see the [plugin guide](/guide/plugins).

## PDB Plugin

Binary Ninja supports loading PDB files through a built in PDB loader. When selected from the plugin menu it attempts to find the corresponding PDB file using the following search order:

1. Look for in the same directory as the opened file/bndb (e.g. If you have `c:\foo.exe` or `c:\foo.bndb` open the PDB plugin looks for `c:\foo.pdb`)
2. Look in the local symbol store. This is the directory specified by the settings: `local-store-relative` or `local-store-absolute`. The format of this directory is `foo.pdb\<guid>\foo.pdb`.
3. Attempt to connect and download the PDB from the list of symbol servers specified in setting `symbol-server-list`.
4. Prompt the user for the PDB.

![settings >](img/settings.png "Settings")

## Settings

Settings are available via the `CMD-,` or `CTRL-,` hot key and allow a wide variety of customization.

All settings are saved in the [_user_ directory](#user-folder) in the file `settings.json`. Each top level object in this file is represents a different plugin or logical group.  

Enabling the `identifiers` check box will show the raw identifiers used to set settings in the json file which may be useful for [programmatically](https://api.binary.ninja/binaryninja.settings-module.html) interacting with settings.

Note
!!! Tip "Note"
    Changing a setting to a non-default value and then changing it back to a default value will result in explicitly specifying that default value which will not change if the default ever does. This can be avoided by right-clicking and choosing `Clear Setting` which will remove the user-setting.

### All Settings

Here's a list of all settings currently available from the UI:

|Category|Setting|Description|Type|Default|
|---|---|---|---|---|
|analysis|Disallow Branch to String|Enable the ability to halt analysis of branch targets that fall within a string reference. This setting is experimental and may be useful for malformed binaries.|`boolean`|`False`|
|analysis|Always Analyze Indirect Branches|When using faster analysis modes, perform full analysis of functions containing indirect branches.|`boolean`|`True`|
|analysis|Advanced Analysis Cache Size|Controls the number of functions for which the most recent generated advanced analysis is cached. Large values are may result in very high memory utilization.|`number`|`64`|
|analysis|Max Function Analysis Time|Any functions that exceed this analysis time are deferred. Default value of 0 disables this feature. Time is specified in milliseconds.|`number`|`0`|
|analysis|Max Function Size|Any functions over this size will not be automatically analyzed. A value of 0 disables analysis of functions and suppresses the related log warning. To override see FunctionAnalysisSkipOverride. Size is specified in bytes.|`number`|`65535`|
|analysis|Max Function Update Count|Any functions that exceed this incremental update count are deferred. A value of 0 disables this feature.|`number`|`100`|
|analysis|Minimum String Length|The minimum length for strings created during auto-analysis|`number`|`4`|
|analysis|Worker Thread Count|The number of worker threads available for concurrent analysis activities.|`number`|`11`|
|analysis|Autorun Linear Sweep|Automatically run linear sweep when opening a binary for analysis.|`boolean`|`True`|
|analysis|Control Flow Graph Analysis|Enable the control flow graph analysis (Analysis Phase 3) portion of linear sweep.|`boolean`|`True`|
|analysis|Detailed Linear Sweep Log Information|Linear sweep generates additional log information at the InfoLog level.|`boolean`|`False`|
|analysis|Entropy Heuristics for Linear Sweep|Enable the application of entropy based heuristics to the function search space for linear sweep.|`boolean`|`True`|
|analysis|Max Linear Sweep Work Queues|The number of binary regions under concurrent analysis.|`number`|`64`|
|analysis|Analysis Mode|Controls the amount of analysis performed on functions.|`string`|`full`|
|analysis|Tail Call Heuristics|Attempts to recover function starts that may be obscured by tail call optimization (TCO). Specifically, branch targets within a function are analyzed as potential function starts.|`boolean`|`True`|
|analysis|Tail Call Translation|Performs tail call translation for jump instructions where the target is an existing function start.|`boolean`|`True`|
|analysis|Unicode Blocks|Defines which unicode blocks to consider when searching for strings.|`array`|`[]`|
|analysis|UTF-16 Encoding|Whether or not to consider UTF-16 code points when searching for strings.|`boolean`|`True`|
|analysis|UTF-32 Encoding|Whether or not to consider UTF-32 code points when searching for strings.|`boolean`|`True`|
|analysis|UTF-8 Encoding|Whether or not to consider UTF-8 code points when searching for strings.|`boolean`|`True`|
|arch|x86 Disassembly Case|Specify the case for opcodes, operands, and registers.|`boolean`|`True`|
<<<<<<< HEAD
|arch|x86 Disassembly Seperator|Specify the token seperator between operands.|`string`|`, `|
=======
|arch|x86 Disassembly Separator|Specify the token separator between operands.|`string`|`, `|
>>>>>>> lots of documentation updates: updated preferences/settings, spelling fixes, new screenshots for open with options and settings, standardize on MacOS
|arch|x86 Disassembly Syntax|Specify disassembly syntax for the x86/x86_64 architectures.|`string`|`BN_INTEL`|
|bnil-graph|Show Common ILs|Show common forms (non-SSA, non-mapped) in the output.|`boolean`|`True`|
|bnil-graph|Include MMLIL|Show the MappedMediumLevelIL form in the output.|`boolean`|`False`|
|bnil-graph|Include SSA|Include SSA forms in the output.|`boolean`|`True`|
|downloadClient|HTTPS Proxy|Override default HTTPS proxy settings. By default, HTTPS Proxy settings are detected and used automatically via environment variables (e.g., https_proxy). Alternatively, proxy settings are obtained from the Internet Settings section of the Windows registry, or the Mac OS X System Configuration Framework.|`string`||
|downloadClient|Download Provider|Specify the registered DownloadProvider which enables resource fetching over HTTPS.|`string`|`PythonDownloadProvider`|
|pdb|Auto Download PDBs|Automatically download pdb files from specified symbol servers.|`boolean`|`True`|
|pdb|Absolute PDB Symbol Store Path|Absolute path specifying where the PDB symbol store exists on this machine, overrides relative path.|`string`||
<<<<<<< HEAD
|pdb|Relative PDB Symbol Store Path|Path *relative* to the binaryninja _user_ directory, sepcifying the pdb symbol store.|`string`|`symbols`|
=======
|pdb|Relative PDB Symbol Store Path|Path *relative* to the binaryninja _user_ directory, specifying the pdb symbol store.|`string`|`symbols`|
>>>>>>> lots of documentation updates: updated preferences/settings, spelling fixes, new screenshots for open with options and settings, standardize on MacOS
|pdb|Symbol Server List|List of servers to query for pdb symbols.|`array`|`['https://msdl.microsoft.com/download/symbols']`|
|pluginManager|Community Plugin Manager Update Channel|Specify which community update channel the Plugin Manager should update plugins from.|`string`|`master`|
|pluginManager|Official Plugin Manager Update Channel|Specify which official update channel the Plugin Manager should update plugins from.|`string`|`master`|
|python|Python Interpreter|Python interpreter library(dylib/dll/so.1) to load if one is not already present when plugins are loaded.|`string`|`libpython2.7.dylib`|
|triage|Triage Analysis Mode|Controls the amount of analysis performed on functions when opening for triage.|`string`|`basic`|
|triage|Triage Shows Hidden Files|Whether the Triage file picker shows hidden files.|`boolean`|`False`|
|triage|Triage Linear Sweep Mode|Controls the level of linear sweep performed when opening for triage.|`string`|`partial`|
|triage|Always Prefer Triage Summary View|Always prefer opening binaries in Triage Summary view, even when performing full analysis.|`boolean`|`False`|
|triage|Prefer Triage Summary View for Raw Files|Prefer opening raw files in Triage Summary view.|`boolean`|`False`|
|ui|Color Blind|Choose colors that are visible to those with red/green color blindness.|`boolean`|`False`|
|ui|Debug Mode|Enable developer debugging features (Additional views: Lifted IL, and IL SSA forms).|`boolean`|`False`|
|ui|Feature Map|Enable the feature map which displays a visual overview of the BinaryView.|`boolean`|`True`|
|ui|Feature Map File-Backed Only Mode|Exclude mapped regions that are not backed by a load file.|`boolean`|`False`|
|ui|Antialiasing|Select font antialiasing style.|`string`|`subpixel`|
|ui|Bold Fonts|Allow bold fonts.|`boolean`|`True`|
|ui|Font Name|Font family selection.|`string`|`Source Code Pro`|
|ui|Font Size|Font point size selection.|`number`|`12`|
|ui|Line Spacing|Specify an additional distance between adjacent baselines.|`number`|`1`|
|ui|Graph Carousel|Graphs and order of graphs to display for 'i' keystroke|`array`|`['Disassembly', 'LowLevelIL', 'MediumLevelIL']`|
|ui|Default Disassembly Graph|Default disassembly graph to display on startup.|`string`|`Disassembly`|
|ui|Number of history entries to store.|Controls the number of history entries to store for input dialogs.|`number`|`50`|
|ui|Minimum UI Log Level|Set the minimum log level for the UI log.|`string`|`InfoLog`|
|ui|Manual Tooltip|Enable to prevent tooltips from showing without &lt;ctrl&gt; being held.|`boolean`|`False`|
|ui|Recent File Limit|Specify a limit for the recent file history.|`number`|`10`|
|ui|Scripting Provider|Specify the registered ScriptingProvider for the default scripting console in the UI|`string`|`Python`|
|ui|Display Settings Identifiers|Display setting identifiers in the UI settings view.|`boolean`|`False`|
|ui|Theme|Customize the appearance and style of Binary Ninja.|`string`|`Dark`|
|ui|TypeView Line Numbers|Controls the display of line numbers in the types view.|`boolean`|`True`|
|updates|Active Content|Allow Binary Ninja to connect to the update server to check for updates and release notes.|`boolean`|`True`|
|updates|Update Channel Preferences|Select update channel and version.|`string`|`None`|
|updates|Show All Versions|Show all versions that are available for the current update channel in the UI.|`boolean`|`False`|


## Updates

Binary Ninja automatically updates itself by default. This functionality can be disabled in the `Update Channel` dialog (`CMD-p`/`CTL-p`, `Update Channel`, or under the `Preferences` sub menu available under `Edit` on Linux and Windows, and the Application menu on MacOS) preferences by turning off the `Update to latest version automatically` option. 

Updates are silently downloaded in the background and when complete an option to restart is displayed in the status bar. Whenever Binary Ninja restarts next, it will replace itself with the new version as it launches.

On windows, this is achieved through a separate launcher that loads first and replaces the installation before launching the new version which you'll notice as a separate window. On MacOS and Linux, the original installation is overwritten after the update occurs as these operating systems allow files to be replaced while running. The update on restart is thus immediate.

Note
!!! Tip "Note"
    If you have any trouble with the self-updater, you can always [request](https://binary.ninja/recover/) a fresh set of download links as long as you are under active support.


## Unicode Support

Currently, Unicode support for Big Endian strings is very limited. Also, UTF-16 only supports Basic Latin code points.

## Getting Support

Vector 35 offers a number of ways to get Binary Ninja [support](https://binary.ninja/support/).
