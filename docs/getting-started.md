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

1. Drag-and-drop a file onto the Binary Ninja window (hold `[CMD/CTRL-SHIFT]` while dropping to use the `Open with Options` workflow)
2. Use the `File/Open` menu or `Open` button on the start screen (`[CMD/CTRL] o`)
3. Use the `File/Open with Options` menu which allows you to customize the analysis options (`[CMD/CTRL-SHIFT] o`)
4. Open a file from the Triage picker (`File/Open for Triage`) which enables several minimal analysis options and shows a summary view first
5. Click an item in the recent files list (hold `[CMD/CTRL-SHIFT]` while clicking to use the `Open with Options` workflow)
6. Run Binary Ninja with an optional command-line parameter
7. Open a file from a URL via the `[CMD/CTRL] l` hotkey
8. Open a file using the `binaryninja:` URL handler. For security reasons, the URL handler requires you to confirm a warning before opening a file via the URL handler. URLs additionally support deep linking using the `expr` query parameter where expression value is a valid parsable expression such as those possible in the [navigation dialog](#navigating), and fully documented in the [`parse_expression`](https://api.binary.ninja/binaryninja.binaryview-module.html?highlight=parse_expression#binaryninja.binaryview.BinaryView.parse_expression) API. Below a few examples are provided:
    * URLs For referencing files on the local file system.
        * `binaryninja:///bin/ls?expr=sub_2830` - open the given file and navigate to the function: `sub_2830`
        * `binaryninja:///bin/ls?expr=.text` - open the given file and navigate to the start address of the `.text` section
        * `binaryninja:///bin/ls?expr=.text+6b` - open the given file and navigate to the hexadecimal offset `6b` from the `.text` section.
    * URLs For referencing remote file files either the url should be prefixed with `binaryninja:` and optionally suffixed with the `expr` query parameter
        * `binaryninja:file://<remote_path>?expr=[.data + 400]` - Download the remote file and navigate to the address at `.data` plus `0x400`

## Status Bar

![status bar >](img/status-bar.png "Status Bar")

The status bar provides current information about the open file as well as some interactive controls. Summary features are listed below:

* Update Notification - perform updates, download status, and restart notification
* Analysis progress - ongoing analysis progress of current active file
* Cursor offset or selection
* BinaryView Switcher
* View Layer Selection - present a layer of analysis information from the BinaryView (e.g. hex, graph, linear, strings, types, etc.)
* File Contents Lock - interactive control to prevent accidental changes to the underlying file

## Analysis



As soon as you open a file, Binary Ninja begins its auto-analysis which is fairly similar to decompiling the entire binary.

Even while Binary Ninja is analyzing a binary, the UI should be responsive. Not only that, but because the analysis prioritizes user-requested analysis, you can start navigating a binary immediately and wherever you are viewing will be prioritized for analysis. The current progress through a binary is shown in the status bar (more details are available via `bv.analysis_info` in the Python console), but note that the total number of items left to analyze will go up as well as the binary is processed and more items are discovered that require analysis.

Analysis proceeds through several phases summarized below:

* Phase 1 - Initial Recursive Descent
* Phase 2 - Call Target Analysis (Part of Linear Sweep)
* Phase 3.x - Control Flow Graph Analysis (Part of Linear Sweep)

Errors or warnings during the load of the binary are also shown in the status bar, along with an icon (in the case of the image above, a large number of warnings were shown). The most common warnings are from incomplete lifting and can be safely ignored. If the warnings include a message like `Data flow for function at 0x41414141 did not terminate`, then please report the binary to the [bug database](https://github.com/Vector35/binaryninja-api/issues).

### Analysis Speed

If you wish to speed up analysis, you have several options. The first is to use the `File/Open for Triage` menu which activates the Triage file picker. By default, [Triage mode](https://binary.ninja/2019/04/01/hackathon-2019-summary.html#triage-mode-rusty) will enable a faster set of default analysis options that doesn't provide as much in-depth analysis but is significantly faster.

Additionally, using the [open with options](#loading-files) feature allows for customization of a number of analysis options on a per-binary basis. See [all settings](#all-settings) under the `analysis` category for more details.

## Interacting

### Navigating

![navigation >](img/navigation.png "Navigation")
Navigating code in Binary Ninja is usually a case of just double-clicking where you want to go. Addresses, references, functions, jump edges, etc, can all be double-clicked to navigate. Additionally, the `g` hotkey can navigate to a specific address in the current view. Syntax for this field is very flexible. Full expressions can be entered including basic arithmetic, dereferencing, and name resolution (function names, data variable names, segment names, etc). Numerics default to hexadecimal but that can be controlled as well. Full documentation on the syntax of this field can be found [here](https://api.binary.ninja/binaryninja.binaryview-module.html?highlight=parse_expression#binaryninja.binaryview.BinaryView.parse_expression).

### Switching Views
![graph view >](img/view-choices.png "Different Views")

Switching views happens multiple ways. In some instances, it is automatic (clicking a data reference from graph view will navigate to linear view as data is not shown in the graph view), and there are multiple ways to manually change views as well. While navigating, you can use the view hotkeys (see below) to switch to a specific view at the same location as the current selection. Alternatively, the view menu in the bottom-right can be used to change views without navigating to any given location.

### Command-Palette

![command palette](img/command-palette.png "Command Palette")

One great feature for quickly navigating through a variety of options and actions is the `command palette`. Inspired by similar features in [Sublime](http://docs.sublimetext.info/en/latest/reference/command_palette.html), and [VS Code](https://code.visualstudio.com/docs/getstarted/userinterface#_command-palette), the command-palette is a front end into an application-wide, context-sensitive action system that all actions, plugins, and hotkeys in the system are routed through.

To trigger it, simply use the `[CMD/CTRL] p` hotkey. Note that the command-palette is context-sensitive and therefore some actions (for example, `Display as - Binary`) may only be available depending on your current view or selection. This is also available to plugins. For example, a plugin may use [PluginCommand.register](https://api.binary.ninja/binaryninja.plugin-module.html#binaryninja.plugin.PluginCommand.register) with the optional `is_valid` callback to determine when the action should be available.

### Custom Hotkeys

![keybindings](img/keybindings.png "Keybindings")

Any action in the [action system](#command-palette) can have a custom hotkey mapped to it. To access the keybindings menu, use the `[CMD/CTRL-SHIFT] b` hotkey, via the `Edit / Keybindings...` menu, or the `Keybindings` [command palette](#command-palette) entry.

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
 - `i` : Cycles between disassembly, LLIL, MLIL and HLIL in graph view
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

![graph view context >](img/graphcontext.png "Graph View Context Menu")

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
    - Medium Level IL
        - Show basic block register state (if showing Medium IL)
    - High Level IL
        - Show basic block register state (if showing High IL)
- Linear
    - Show address
    - Show call parameter names
    - Show opcode bytes
    - Show register set highlighting
    - Show variable types
        - List default register types

![hex >](img/hex.png "hex view")

### Hex View

The hexadecimal view is useful for view raw binary files that may or may not even be executable binaries. The hex view is particularly good for transforming data in various ways via the `Copy as`, `Transform`, and `Paste from` menus. Note that `Transform` menu options will transform the data in-place, and that these options will only work when the Hex View is in the `Raw` mode as opposed to any of the binary views (such as "ELF", "Mach-O", or "PE").

!!! Tip "Tip"
    Any changes made in the Hex view will take effect immediately in any other views open into the same file (new views can be created via the `Split to new tab`, or `Split to new window` options under `View`.). This can, however, cause large amounts of re-analysis so be warned before making large edits or transformations in a large binary file.

### Cross References Pane

![Cross Reference Tree <](img/cross-reference-tree.png "xrefs tree")

The Cross References view in the lower-left shows all cross-references to the currently selected address or address range. Additionally this pane will change depending on whether an entire line is selected (all cross-references to that address are shown), or whether a specific token within the line is selected. For instance if you click on the symbol `memmove` in `call memmove` it will display all known cross-references to `memmove`, whereas if you click on the line the `call` instruction is on, you will only get cross-references to the address of the call instruction. Cross-references can be either incoming or outgoing, and they can be either data or code. To be explicit:

* Incoming-Data References - The reference is a data variable pointing to this location.
* Incoming-Code References - The reference is a pointer in code pointing to this location.
* Outgoing-Data References - The currently selected item is a data variable pointer to the reference which itself is either data or code.
* Outgoing-Code References - The currently selected item is code pointing to the reference which itself is either data or code.

#### Tree-based Layout
The cross-references pane comes in two different layouts: tree-based (default and shown above) and table-based (this can be toggled through the context menu or the command palette). The tree-based layout provides the most condensed view, allowing users to quickly see (for instance) how many references are present to the current selection overall and by function. It also allows collapsing to quickly hide uninteresting results.

#### Table-based Layout

![xrefs >](img/cross-reference-table.png "xrefs table")

The table-based layout provides field-based sorting and multi-select. Clicking the `Filter` text expands the filter pane, showing options for filtering the current results.

#### Template Simplifier

The `analysis.types.TemplateSimplifier` setting can be helpful when working with C++ symbols.

![Before Template Simplification <](img/before-template-simplification.png "Before Template Simplification")
![After Template Simplification >](img/after-template-simplification.png "After Template Simplification")

#### Cross-Reference Filtering

![xrefs <](img/cross-reference-filter.png "xrefs filter")

The first of the two drop down boxes allows the selection of incoming, outgoing, or both incoming and outgoing (default). The second allows selection of code, data, or code and data (default). The text box allows regular expression matching of results. When a filter is selected the `Filter` display changes from `Filter (<total-count>)` to `Filter (<total-filtered>/<total-count>)`

#### Cross-Reference Pinning

By default Binary Ninja's cross-reference pane is dynamic, allowing quick navigation to relevant references. Sometimes you might rather have the current references stick around so they can be used as a sort of work-list. This workflow is supported in three different ways. First and most obviously by clicking the `Pin` checkbox (which is only visible if the `Filter` drop-down is open). This prevents the list of cross-references from being updated even after the current selection is changed. Alternatively, `SHIFT+X` (or selecting `Focus Pinned Cross References` in the context menu or command palette) pops up a `Pinned Cross References` pane. This pane has a static address range which can only be updated through the `Pinned Cross References` action. The third way would be to select (or multi-select in table view) a set of cross-references then right-click `Tag Selected Rows`. The tag pane can then be used to navigate those references. Tags allow for persistent lists to be saved to analysis database whereas the other options only last for the current session.


#### Cross-Reference Hotkeys

* `x` - Focus the cross-references pane
* `[SHIFT] x` Focus the pinned cross-references pane
* `[OPTION/ALT] x` - Navigate to the next cross-reference
* `[OPTION/ALT-SHIFT] x` - Navigate to the previous cross-reference

The following are only available when the cross-references pane is in focus:

* `[CMD/CTRL] f` - Open the filter dialog
* `[ESC]` - Clear the search dialog
* `[CMD/CTRL] a` - Select all cross-references
* `[ARROW UP/DOWN]` - Select (but don't navigate) next/previous cross-reference
* `[ENTER]` - Navigate to the selected reference


### Linear View

![linear](img/linear.png "linear view")

Linear view is a hybrid view between a graph-based disassembly window and the raw hex view. It lists the entire binary's memory in a linear fashion and is especially useful when trying to find sections of a binary that were not properly identified as code or even just examining data.

Linear view is most commonly used for identifying and adding type information for unknown data. To this end, as you scroll, you'll see data and code interspersed. Much like the graph view, you can turn on and off addresses via the command palette `Show Address` or the `Options` menu in the lower right. Many other [option](#view-options) are also available.

### Function List

![function list >](img/functionlist.png "Function List")

The function list in Binary Ninja shows the list of functions currently identified. As large binaries are analyzed, the list may grow during analysis. The function list starts with known functions such as the entry point, exports, or using other features of the binary file format and explores from there to identify other functions.

The function list also highlights imports, and functions identified with symbols in different colors to make them easier to identify.

!!! Tip "Tip"
    To search in the function list, just click to make sure it's focused and start typing!

![console >](img/console.png "Console")

### Reflection View

- View BNILs and assembly for the same file side-by-side

![Reflection View >](img/reflection_view.png "Reflection View")

- Settings to control the synchronization behavior

![Reflection Settings >](img/reflection_settings.png "Reflection Settings")

- Right Click the Function Header for quick access to synchronization mode changes

![Reflection Controls >](img/reflection_controls.png "Reflection Controls")

- Reflection currently presents in graph view only

- When main view is linear, Mini Graph renders the Reflection View

### Script (Python) Console

The integrated script console is useful for small scripts that aren't worth writing as full plugins.

To trigger the console, either use `<CTRL>-<BACKTICK>`, or use the `View`/`Native Docks`/`Show Python Console` menu.

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

For more detailed information on plugins, see the [plugin guide](guide/plugins.md).

## PDB Plugin

Binary Ninja supports loading PDB files through a built in PDB loader. When selected from the plugin menu it attempts to find the corresponding PDB file using the following search order:

1. Look for in the same directory as the opened file/bndb (e.g. If you have `c:\foo.exe` or `c:\foo.bndb` open the PDB plugin looks for `c:\foo.pdb`)
2. Look in the local symbol store. This is the directory specified by the settings: `local-store-relative` or `local-store-absolute`. The format of this directory is `foo.pdb\<guid>\foo.pdb`.
3. Attempt to connect and download the PDB from the list of symbol servers specified in setting `symbol-server-list`.
4. Prompt the user for the PDB.

![settings >](img/settings.png "Settings")

## Settings

Binary Ninja provides various settings which are available via the `[CMD/CTRL] ,` hotkey. These settings allow a wide variety of customization of the user interface and functional aspects of the analysis environment.

There are several scopes available for settings:
* **User Settings** - Settings that apply globally and override the defaults. These settings are stored in `settings.json` within the [User Folder](#user-folder).
* **Project Settings** - Settings which only apply if a project is opened. These settings are stored in `.binaryninja/settings.json` within a Project Folder. Project Folders can exist anywhere except within the User Folder. These settings apply to all files contained in the Project Folder and override the default and user settings.
* **Resource Settings** - Settings which only apply to a specific BinaryView object within a file. These settings persist in a Binary Ninja Database (.bndb) database or ephemerally in a BinaryView object if a database does not yet exist for a file.

All settings are uniquely identified with an identifier string. Identifiers are available in the UI via the context menu and are useful for [programmatically](https://api.binary.ninja/binaryninja.settings-module.html) interacting with settings.

**Note**: In order to facilitate reproducible analysis results, when opening a file for the first time, all of the analysis settings are automatically serialized into the _Resource Setting_ scope. This prevents subsequent _User_ and _Project_ setting modifications from unintentionally changing existing analysis results.

### All Settings

Here's a list of all settings currently available from the UI:

|Category|Setting|Description|Type|Default|Key|
|---|---|---|---|---|---|
|analysis|Disallow Branch to String|Enable the ability to halt analysis of branch targets that fall within a string reference. This setting may be useful for malformed binaries.|`boolean`|`False`|<a id='analysis.conservative.disallowBranchToString'>analysis.conservative.disallowBranchToString</a>|
|analysis|Never Save Undo Data|Never save previous user actions to the database.|`boolean`|`False`|<a id='analysis.database.neverSaveUndoData'>analysis.database.neverSaveUndoData</a>|
|analysis|Suppress Reanalysis|Disable function reanalysis on database load when the product version or analysis settings change.|`boolean`|`False`|<a id='analysis.database.suppressReanalysis'>analysis.database.suppressReanalysis</a>|
|analysis|Alternate Type Propagation|Enable an alternate approach for function type propagation. This setting is experimental and may be useful for some binaries.|`boolean`|`False`|<a id='analysis.experimental.alternateTypePropagation'>analysis.experimental.alternateTypePropagation</a>|
|analysis|Correlated Memory Value Propagation|Attempt to propagate the value of an expression from a memory definition to a usage. Currently this feature is simplistic and the scope is a single basic block. This setting is experimental and may be useful for some binaries.|`boolean`|`True`|<a id='analysis.experimental.correlatedMemoryValuePropagation'>analysis.experimental.correlatedMemoryValuePropagation</a>|
|analysis|Heuristic Value Range Clamping|Use DataVariable state inferencing to help determine the possible size of a lookup table.|`boolean`|`True`|<a id='analysis.experimental.heuristicRangeClamp'>analysis.experimental.heuristicRangeClamp</a>|
|analysis|Always Analyze Indirect Branches|When using faster analysis modes, perform full analysis of functions containing indirect branches.|`boolean`|`True`|<a id='analysis.forceIndirectBranches'>analysis.forceIndirectBranches</a>|
|analysis|Advanced Analysis Cache Size|Controls the number of functions for which the most recent generated advanced analysis is cached. Large values may result in very high memory utilization.|`number`|`64`|<a id='analysis.limits.cacheSize'>analysis.limits.cacheSize</a>|
|analysis|Max Function Analysis Time|Any functions that exceed this analysis time are deferred. A value of 0 disables this feature. The default value is 20 seconds. Time is specified in milliseconds.|`number`|`20000`|<a id='analysis.limits.maxFunctionAnalysisTime'>analysis.limits.maxFunctionAnalysisTime</a>|
|analysis|Max Function Size|Any functions over this size will not be automatically analyzed. A value of 0 disables analysis of functions and suppresses the related log warning. To override see FunctionAnalysisSkipOverride. Size is specified in bytes.|`number`|`65536`|<a id='analysis.limits.maxFunctionSize'>analysis.limits.maxFunctionSize</a>|
|analysis|Max Function Update Count|Any functions that exceed this incremental update count are deferred. A value of 0 disables this feature.|`number`|`100`|<a id='analysis.limits.maxFunctionUpdateCount'>analysis.limits.maxFunctionUpdateCount</a>|
|analysis|Max Lookup Table Size|Limits the maximum number of entries for a lookup table.|`number`|`4095`|<a id='analysis.limits.maxLookupTableSize'>analysis.limits.maxLookupTableSize</a>|
|analysis|Maximum String Annotation Length|The maximum substring length that will be shown in string annotations.|`number`|`32`|<a id='analysis.limits.maxStringAnnotationLength'>analysis.limits.maxStringAnnotationLength</a>|
|analysis|Minimum String Length|The minimum length for strings created during auto-analysis|`number`|`4`|<a id='analysis.limits.minStringLength'>analysis.limits.minStringLength</a>|
|analysis|Worker Thread Count|The number of worker threads available for concurrent analysis activities.|`number`|`15`|<a id='analysis.limits.workerThreadCount'>analysis.limits.workerThreadCount</a>|
|analysis|Autorun Linear Sweep|Automatically run linear sweep when opening a binary for analysis.|`boolean`|`True`|<a id='analysis.linearSweep.autorun'>analysis.linearSweep.autorun</a>|
|analysis|Control Flow Graph Analysis|Enable the control flow graph analysis (Analysis Phase 3) portion of linear sweep.|`boolean`|`True`|<a id='analysis.linearSweep.controlFlowGraph'>analysis.linearSweep.controlFlowGraph</a>|
|analysis|Detailed Linear Sweep Log Information|Linear sweep generates additional log information at the InfoLog level.|`boolean`|`False`|<a id='analysis.linearSweep.detailedLogInfo'>analysis.linearSweep.detailedLogInfo</a>|
|analysis|Entropy Heuristics for Linear Sweep|Enable the application of entropy based heuristics to the function search space for linear sweep.|`boolean`|`True`|<a id='analysis.linearSweep.entropyHeuristics'>analysis.linearSweep.entropyHeuristics</a>|
|analysis|Max Linear Sweep Work Queues|The number of binary regions under concurrent analysis.|`number`|`64`|<a id='analysis.linearSweep.maxWorkQueues'>analysis.linearSweep.maxWorkQueues</a>|
|analysis|Analysis Mode|Controls the amount of analysis performed on functions.|`string`|`full`|<a id='analysis.mode'>analysis.mode</a>|
| | |  enum: Only perform control flow analysis on the binary. Cross references are valid only for direct function calls. [Disassembly Only]|`enum`|`controlFlow`| |
| | |  enum: Perform fast initial analysis of the binary. This mode does not analyze types or data flow through stack variables. [LLIL and Equivalents]|`enum`|`basic`| |
| | |  enum: Perform analysis which includes type propagation and data flow. [MLIL and Equivalents]|`enum`|`intermediate`| |
| | |  enum: Perform full analysis of the binary.|`enum`|`full`| |
|analysis|Autorun Function Signature Matcher|Automatically run the function signature matcher when opening a binary for analysis.|`boolean`|`True`|<a id='analysis.signatureMatcher.autorun'>analysis.signatureMatcher.autorun</a>|
|analysis|Auto Function Analysis Suppression|Enable suppressing analysis of automatically discovered functions.|`boolean`|`False`|<a id='analysis.suppressNewAutoFunctionAnalysis'>analysis.suppressNewAutoFunctionAnalysis</a>|
|analysis|Tail Call Heuristics|Attempts to recover function starts that may be obscured by tail call optimization (TCO). Specifically, branch targets within a function are analyzed as potential function starts.|`boolean`|`True`|<a id='analysis.tailCallHeuristics'>analysis.tailCallHeuristics</a>|
|analysis|Tail Call Translation|Performs tail call translation for jump instructions where the target is an existing function start.|`boolean`|`True`|<a id='analysis.tailCallTranslation'>analysis.tailCallTranslation</a>|
|analysis|Simplify Templates|Simplify common C++ templates that are expanded with default arguments at compile time (eg. `std::__cxx11::basic_string<wchar, std::char_traits<wchar>, std::allocator<wchar> >` to `std::wstring`).|`boolean`|`False`|<a id='analysis.types.TemplateSimplifier'>analysis.types.TemplateSimplifier</a>|
|analysis|Unicode Blocks|Defines which unicode blocks to consider when searching for strings.|`array`|[]|<a id='analysis.unicode.blocks'>analysis.unicode.blocks</a>|
|analysis|UTF-16 Encoding|Whether or not to consider UTF-16 code points when searching for strings.|`boolean`|`True`|<a id='analysis.unicode.utf16'>analysis.unicode.utf16</a>|
|analysis|UTF-32 Encoding|Whether or not to consider UTF-32 code points when searching for strings.|`boolean`|`True`|<a id='analysis.unicode.utf32'>analysis.unicode.utf32</a>|
|analysis|UTF-8 Encoding|Whether or not to consider UTF-8 code points when searching for strings.|`boolean`|`True`|<a id='analysis.unicode.utf8'>analysis.unicode.utf8</a>|
|arch|x86 Disassembly Case|Specify the case for opcodes, operands, and registers.|`boolean`|`True`|<a id='arch.x86.disassembly.lowercase'>arch.x86.disassembly.lowercase</a>|
|arch|x86 Disassembly Separator|Specify the token separator between operands.|`string`|`, `|<a id='arch.x86.disassembly.separator'>arch.x86.disassembly.separator</a>|
|arch|x86 Disassembly Syntax|Specify disassembly syntax for the x86/x86_64 architectures.|`string`|`BN_INTEL`|<a id='arch.x86.disassembly.syntax'>arch.x86.disassembly.syntax</a>|
| | |  enum: Sets the disassembly syntax to a simplified Intel format. (TBD) |`enum`|`BN_INTEL`| |
| | |  enum: Sets the disassembly syntax to Intel format. (Destination on the left) |`enum`|`INTEL`| |
| | |  enum: Sets the disassembly syntax to AT&T format. (Destination on the right) |`enum`|`AT&T`| |
|corePlugins|Aarch64 Architecture|Enable the built-in Aarch64 architecture module.|`boolean`|`True`|<a id='corePlugins.architectures.aarch64'>corePlugins.architectures.aarch64</a>|
|corePlugins|ARMv7 Architecture|Enable the built-in ARMv7 architecture module.|`boolean`|`True`|<a id='corePlugins.architectures.armv7'>corePlugins.architectures.armv7</a>|
|corePlugins|MIPS Architecture|Enable the built-in MIPS architecture module.|`boolean`|`True`|<a id='corePlugins.architectures.mips'>corePlugins.architectures.mips</a>|
|corePlugins|PowerPC Architecture|Enable the built-in PowerPC architecture module.|`boolean`|`True`|<a id='corePlugins.architectures.powerpc'>corePlugins.architectures.powerpc</a>|
|corePlugins|x86/x86_64 Architecture|Enable the built-in x86/x86_64 architecture module.|`boolean`|`True`|<a id='corePlugins.architectures.x86'>corePlugins.architectures.x86</a>|
|corePlugins|Crypto Plugin|Enable the built-in crypto plugin.|`boolean`|`True`|<a id='corePlugins.crypto'>corePlugins.crypto</a>|
|corePlugins|PDB Loader|Enable the built-in PDB loader plugin.|`boolean`|`True`|<a id='corePlugins.pdb'>corePlugins.pdb</a>|
|corePlugins|DECREE Platform|Enable the built-in DECREE platform module.|`boolean`|`True`|<a id='corePlugins.platforms.decree'>corePlugins.platforms.decree</a>|
|corePlugins|FreeBSD Platform|Enable the built-in FreeBSD platform module.|`boolean`|`True`|<a id='corePlugins.platforms.freebsd'>corePlugins.platforms.freebsd</a>|
|corePlugins|Linux Platform|Enable the built-in Linux platform module.|`boolean`|`True`|<a id='corePlugins.platforms.linux'>corePlugins.platforms.linux</a>|
|corePlugins|macOS Platform|Enable the built-in macOS platform module.|`boolean`|`True`|<a id='corePlugins.platforms.mac'>corePlugins.platforms.mac</a>|
|corePlugins|Windows Platform|Enable the built-in Windows platform module.|`boolean`|`True`|<a id='corePlugins.platforms.windows'>corePlugins.platforms.windows</a>|
|corePlugins|Triage Plugin|Enable the built-in triage plugin.|`boolean`|`True`|<a id='corePlugins.triage'>corePlugins.triage</a>|
|downloadClient|HTTPS Proxy|Override default HTTPS proxy settings. By default, HTTPS Proxy settings are detected and used automatically via environment variables (e.g., https_proxy). Alternatively, proxy settings are obtained from the Internet Settings section of the Windows registry, or the Mac OS X System Configuration Framework.|`string`| |<a id='downloadClient.httpsProxy'>downloadClient.httpsProxy</a>|
|downloadClient|Download Provider|Specify the registered DownloadProvider which enables resource fetching over HTTPS.|`string`|`CoreDownloadProvider`|<a id='downloadClient.providerName'>downloadClient.providerName</a>|
| | | |`enum`|`QtDownloadProvider`| |
| | | |`enum`|`CoreDownloadProvider`| |
| | | |`enum`|`PythonDownloadProvider`| |
|files|Auto Rebase Load File|When opening a file with options, automatically rebase an image which has a default load address of zero to 4MB for 64-bit binaries, or 64KB for 32-bit binaries.|`boolean`|`False`|<a id='files.pic.autoRebase'>files.pic.autoRebase</a>|
|files|Universal Mach-O Architecture Preference|Specify an architecture preference for automatic loading of a Mach-O file from a Universal archive. By default, the first object file in the listing is loaded.|`array`|[]|<a id='files.universal.architecturePreference'>files.universal.architecturePreference</a>|
| | | |`enum`|`alpha`| |
| | | |`enum`|`arm`| |
| | | |`enum`|`arm64`| |
| | | |`enum`|`arm64_32`| |
| | | |`enum`|`hppa`| |
| | | |`enum`|`i860`| |
| | | |`enum`|`mc680x0`| |
| | | |`enum`|`mc88000`| |
| | | |`enum`|`mc98000`| |
| | | |`enum`|`mips`| |
| | | |`enum`|`ppc`| |
| | | |`enum`|`ppc64`| |
| | | |`enum`|`sparc`| |
| | | |`enum`|`vax`| |
| | | |`enum`|`x86`| |
| | | |`enum`|`x86_64`| |
|pdb|Auto Download PDBs|Automatically download pdb files from specified symbol servers.|`boolean`|`True`|<a id='pdb.autoDownload'>pdb.autoDownload</a>|
|pdb|Absolute PDB Symbol Store Path|Absolute path specifying where the PDB symbol store exists on this machine, overrides relative path.|`string`| |<a id='pdb.localStoreAbsolute'>pdb.localStoreAbsolute</a>|
|pdb|Relative PDB Symbol Store Path|Path *relative* to the binaryninja _user_ directory, specifying the pdb symbol store.|`string`|`symbols`|<a id='pdb.localStoreRelative'>pdb.localStoreRelative</a>|
|pdb|Symbol Server List|List of servers to query for pdb symbols.|`array`|[`https://msdl.microsoft.com/download/symbols`]|<a id='pdb.symbolServerList'>pdb.symbolServerList</a>|
|pluginManager|Community Plugin Manager Update Channel|Specify which community update channel the Plugin Manager should update plugins from.|`string`|`master`|<a id='pluginManager.communityUpdateChannel'>pluginManager.communityUpdateChannel</a>|
| | |  enum: The default channel. This setting should be used unless you are testing the Plugin Manager.|`enum`|`master`| |
| | |  enum: Plugin Manager test channel.|`enum`|`test`| |
|pluginManager|Official Plugin Manager Update Channel|Specify which official update channel the Plugin Manager should update plugins from.|`string`|`master`|<a id='pluginManager.officialUpdateChannel'>pluginManager.officialUpdateChannel</a>|
| | |  enum: The default channel. This setting should be used unless you are testing the Plugin Manager.|`enum`|`master`| |
| | |  enum: Plugin Manager test channel.|`enum`|`test`| |
|python|Python Interpreter|Python interpreter library(dylib/dll/so.1) to load if one is not already present when plugins are loaded.|`string`| |<a id='python.interpreter'>python.interpreter</a>|
|python|Minimum Python Log Level|Set the minimum Python log level which applies in headless operation only. The log is connected to stderr. Additionally, stderr must be associated with a terminal device.|`string`|`WarningLog`|<a id='python.log.minLevel'>python.log.minLevel</a>|
| | |  enum: Print Debug, Info, Warning, Error, and Alert messages to stderr on the terminal device.|`enum`|`DebugLog`| |
| | |  enum: Print Info, Warning, Error, and Alert messages to stderr on the terminal device.|`enum`|`InfoLog`| |
| | |  enum: Print Warning, Error, and Alert messages to stderr on the terminal device.|`enum`|`WarningLog`| |
| | |  enum: Print Error and Alert messages to stderr on the terminal device.|`enum`|`ErrorLog`| |
| | |  enum: Print Alert messages to stderr on the terminal device.|`enum`|`AlertLog`| |
| | |  enum: Disable all logging in headless operation.|`enum`|`Disabled`| |
|triage|Triage Analysis Mode|Controls the amount of analysis performed on functions when opening for triage.|`string`|`basic`|<a id='triage.analysisMode'>triage.analysisMode</a>|
| | |  enum: Only perform control flow analysis on the binary. Cross references are valid only for direct function calls.|`enum`|`controlFlow`| |
| | |  enum: Perform fast initial analysis of the binary. This mode does not analyze types or data flow through stack variables.|`enum`|`basic`| |
| | |  enum: Perform full analysis of the binary.|`enum`|`full`| |
|triage|Triage Shows Hidden Files|Whether the Triage file picker shows hidden files.|`boolean`|`False`|<a id='triage.hiddenFiles'>triage.hiddenFiles</a>|
|triage|Triage Linear Sweep Mode|Controls the level of linear sweep performed when opening for triage.|`string`|`partial`|<a id='triage.linearSweep'>triage.linearSweep</a>|
| | |  enum: Do not perform linear sweep of the binary.|`enum`|`none`| |
| | |  enum: Perform linear sweep on the binary, but skip the control flow graph analysis phase.|`enum`|`partial`| |
| | |  enum: Perform full linear sweep on the binary.|`enum`|`full`| |
|triage|Always Prefer Triage Summary View|Always prefer opening binaries in Triage Summary view, even when performing full analysis.|`boolean`|`False`|<a id='triage.preferSummaryView'>triage.preferSummaryView</a>|
|triage|Prefer Triage Summary View for Raw Files|Prefer opening raw files in Triage Summary view.|`boolean`|`False`|<a id='triage.preferSummaryViewForRaw'>triage.preferSummaryViewForRaw</a>|
|ui|Color Blind|Choose colors that are visible to those with red/green color blindness.|`boolean`|`False`|<a id='ui.colorBlind'>ui.colorBlind</a>|
|ui|Debug Mode|Enable developer debugging features (Additional views: Lifted IL, and IL SSA forms).|`boolean`|`False`|<a id='ui.debugMode'>ui.debugMode</a>|
|ui|Dock Window Title Bars|Enable to display title bars for dockable windows attached to a main window.|`boolean`|`True`|<a id='ui.docks.titleBars'>ui.docks.titleBars</a>|
|ui|Feature Map Auto-Rotate|Automatically rotate the feature map orientation based on the current layout and dimensions.|`boolean`|`True`|<a id='ui.featureMap.autoRotate'>ui.featureMap.autoRotate</a>|
|ui|Feature Map|Enable the feature map which displays a visual overview of the BinaryView.|`boolean`|`True`|<a id='ui.featureMap.enable'>ui.featureMap.enable</a>|
|ui|Feature Map File-Backed Only Mode|Exclude mapped regions that are not backed by a load file.|`boolean`|`False`|<a id='ui.featureMap.fileBackedOnly'>ui.featureMap.fileBackedOnly</a>|
|ui|File Contents Lock|Lock the file contents to prevent accidental edits from the UI. File modification via API and menu based patching is explicitly allowed while the lock is enabled.|`boolean`|`True`|<a id='ui.fileContentsLock'>ui.fileContentsLock</a>|
|ui|Auto Open with Options|Specify the file types which automatically open with the options dialog.|`array`|[`Mapped`, `Universal`]|<a id='ui.files.openWithOptions'>ui.files.openWithOptions</a>|
| | | |`enum`|`Mapped`| |
| | | |`enum`|`ELF`| |
| | | |`enum`|`Mach-O`| |
| | | |`enum`|`PE`| |
| | | |`enum`|`Universal`| |
|ui|Antialiasing|Select font antialiasing style.|`string`|`subpixel`|<a id='ui.font.antialiasing'>ui.font.antialiasing</a>|
| | |  enum: Perform subpixel antialiasing on fonts.|`enum`|`subpixel`| |
| | |  enum: Avoid subpixel antialiasing on fonts if possible.|`enum`|`grayscale`| |
| | |  enum: No subpixel antialiasing at High DPI.|`enum`|`hidpi`| |
| | |  enum: No font antialiasing.|`enum`|`none`| |
|ui|Bold Fonts|Allow bold fonts.|`boolean`|`True`|<a id='ui.font.bold'>ui.font.bold</a>|
|ui|Font Name|Font family selection.|`string`|`Source Code Pro`|<a id='ui.font.name'>ui.font.name</a>|
|ui|Font Size|Font point size selection.|`number`|`12`|<a id='ui.font.size'>ui.font.size</a>|
|ui|Line Spacing|Specify an additional distance between adjacent baselines.|`number`|`1`|<a id='ui.font.spacing'>ui.font.spacing</a>|
|ui|Font Style|Font Style selection.|`string`| |<a id='ui.font.style'>ui.font.style</a>|
|ui|Number of history entries to store.|Controls the number of history entries to store for input dialogs.|`number`|`50`|<a id='ui.inputHistoryCount'>ui.inputHistoryCount</a>|
|ui|Maximum UI Log Size|Set the maximum number of lines for the UI log.|`number`|`10000`|<a id='ui.log.maxSize'>ui.log.maxSize</a>|
|ui|Minimum UI Log Level|Set the minimum log level for the UI log.|`string`|`InfoLog`|<a id='ui.log.minLevel'>ui.log.minLevel</a>|
| | |  enum: Display Debug, Info, Warning, Error, and Alert messages to log console.|`enum`|`DebugLog`| |
| | |  enum: Display Info, Warning, Error, and Alert messages to log console.|`enum`|`InfoLog`| |
| | |  enum: Display Warning, Error, and Alert messages to log console.|`enum`|`WarningLog`| |
| | |  enum: Display Error and Alert messages to log console.|`enum`|`ErrorLog`| |
| | |  enum: Display Alert messages to log console.|`enum`|`AlertLog`| |
|ui|Manual Tooltip|Enable to prevent tooltips from showing without &lt;ctrl&gt; being held.|`boolean`|`False`|<a id='ui.manualTooltip'>ui.manualTooltip</a>|
|ui|Recent Command Limit|Specify a limit for the recent command palette history.|`number`|`5`|<a id='ui.recentCommandLimit'>ui.recentCommandLimit</a>|
|ui|Recent File Limit|Specify a limit for the recent file history in the new tab window.|`number`|`10`|<a id='ui.recentFileLimit'>ui.recentFileLimit</a>|
|ui|Show Indentation Guides|Show indentation markers in linear high-level IL|`boolean`|`True`|<a id='ui.renderIndentGuides'>ui.renderIndentGuides</a>|
|ui|Default Scripting Provider|Specify the registered ScriptingProvider for the default scripting console in the UI.|`string`|`Python`|<a id='ui.scripting.defaultProvider'>ui.scripting.defaultProvider</a>|
| | | |`enum`|`Python`| |
|ui|Scripting Provider History Size|Specify the maximum number of lines contained in the scripting history.|`number`|`1000`|<a id='ui.scripting.historySize'>ui.scripting.historySize</a>|
|ui|Display Settings Identifiers|Display setting identifiers in the UI settings view.|`boolean`|`False`|<a id='ui.settings.displayIdentifiers'>ui.settings.displayIdentifiers</a>|
|ui|HLIL Scoping Style|Controls the display of new scopes in HLIL.|`string`|`default`|<a id='ui.style.hlil.scoping'>ui.style.hlil.scoping</a>|
| | |  enum: Default BNIL scoping style.|`enum`|`default`| |
| | |  enum: Braces around scopes, same line.|`enum`|`braces`| |
| | |  enum: Braces around scopes, new line.|`enum`|`bracesNewLine`| |
|ui|Show Exported Data Variables|Show exported data variables in the symbol list.|`boolean`|`False`|<a id='ui.symbolList.showExportedDataVars'>ui.symbolList.showExportedDataVars</a>|
|ui|Show Exported Functions|Show exported functions in the symbol list.|`boolean`|`True`|<a id='ui.symbolList.showExportedFunctions'>ui.symbolList.showExportedFunctions</a>|
|ui|Show Imports|Show imports in the symbol list.|`boolean`|`True`|<a id='ui.symbolList.showImports'>ui.symbolList.showImports</a>|
|ui|Show Local Data Variables|Show local data variables in the symbol list.|`boolean`|`False`|<a id='ui.symbolList.showLocalDataVars'>ui.symbolList.showLocalDataVars</a>|
|ui|Show Local Functions|Show local functions in the symbol list.|`boolean`|`True`|<a id='ui.symbolList.showLocalFunctions'>ui.symbolList.showLocalFunctions</a>|
|ui|Theme|Customize the appearance and style of Binary Ninja.|`string`|`Dark`|<a id='ui.theme'>ui.theme</a>|
|ui|Graph View IL Carousel|Specify the IL view types and order for use with the 'Cycle IL' actions in Graph view.|`array`|[`Disassembly`, `LowLevelIL`, `MediumLevelIL`, `HighLevelIL`]|<a id='ui.view.graph.carousel'>ui.view.graph.carousel</a>|
| | | |`enum`|`Disassembly`| |
| | | |`enum`|`LowLevelIL`| |
| | | |`enum`|`LiftedIL`| |
| | | |`enum`|`LowLevelILSSAForm`| |
| | | |`enum`|`MediumLevelIL`| |
| | | |`enum`|`MediumLevelILSSAForm`| |
| | | |`enum`|`MappedMediumLevelIL`| |
| | | |`enum`|`MappedMediumLevelILSSAForm`| |
| | | |`enum`|`HighLevelIL`| |
| | | |`enum`|`HighLevelILSSAForm`| |
|ui|Default IL for Graph View|Default IL for graph view on startup.|`string`|`Disassembly`|<a id='ui.view.graph.il'>ui.view.graph.il</a>|
| | | |`enum`|`Disassembly`| |
| | | |`enum`|`LowLevelIL`| |
| | | |`enum`|`LiftedIL`| |
| | | |`enum`|`LowLevelILSSAForm`| |
| | | |`enum`|`MediumLevelIL`| |
| | | |`enum`|`MediumLevelILSSAForm`| |
| | | |`enum`|`MappedMediumLevelIL`| |
| | | |`enum`|`MappedMediumLevelILSSAForm`| |
| | | |`enum`|`HighLevelIL`| |
| | | |`enum`|`HighLevelILSSAForm`| |
|ui|Prefer Disassembly Graph|Prefer graph view over linear view on startup.|`boolean`|`False`|<a id='ui.view.graph.preferred'>ui.view.graph.preferred</a>|
|ui|Linear View IL Carousel|Specify the IL view types and order for use with the 'Cycle IL' actions in Linear view.|`array`|[`Disassembly`, `LowLevelIL`, `MediumLevelIL`, `HighLevelIL`]|<a id='ui.view.linear.carousel'>ui.view.linear.carousel</a>|
| | | |`enum`|`Disassembly`| |
| | | |`enum`|`LowLevelIL`| |
| | | |`enum`|`LiftedIL`| |
| | | |`enum`|`LowLevelILSSAForm`| |
| | | |`enum`|`MediumLevelIL`| |
| | | |`enum`|`MediumLevelILSSAForm`| |
| | | |`enum`|`MappedMediumLevelIL`| |
| | | |`enum`|`MappedMediumLevelILSSAForm`| |
| | | |`enum`|`HighLevelIL`| |
| | | |`enum`|`HighLevelILSSAForm`| |
|ui|Linear View Gutter Width|Linear view gutter and tags width, in characters.|`number`|`5`|<a id='ui.view.linear.gutterWidth'>ui.view.linear.gutterWidth</a>|
|ui|Default IL for Linear View|Default linear view type to display on startup.|`string`|`HighLevelIL`|<a id='ui.view.linear.il'>ui.view.linear.il</a>|
| | | |`enum`|`Disassembly`| |
| | | |`enum`|`LowLevelIL`| |
| | | |`enum`|`LiftedIL`| |
| | | |`enum`|`LowLevelILSSAForm`| |
| | | |`enum`|`MediumLevelIL`| |
| | | |`enum`|`MediumLevelILSSAForm`| |
| | | |`enum`|`MappedMediumLevelIL`| |
| | | |`enum`|`MappedMediumLevelILSSAForm`| |
| | | |`enum`|`HighLevelIL`| |
| | | |`enum`|`HighLevelILSSAForm`| |
|ui|Default IL for Reflection View|Default IL for reflection view on startup.|`string`|`Disassembly`|<a id='ui.view.reflection.il'>ui.view.reflection.il</a>|
| | | |`enum`|`Disassembly`| |
| | | |`enum`|`LowLevelIL`| |
| | | |`enum`|`LiftedIL`| |
| | | |`enum`|`LowLevelILSSAForm`| |
| | | |`enum`|`MediumLevelIL`| |
| | | |`enum`|`MediumLevelILSSAForm`| |
| | | |`enum`|`MappedMediumLevelIL`| |
| | | |`enum`|`MappedMediumLevelILSSAForm`| |
| | | |`enum`|`HighLevelIL`| |
| | | |`enum`|`HighLevelILSSAForm`| |
|ui|Reflection View IL Map|Specify the IL view to display based on a given source IL view. The source IL view is encoded as the index of this array and corresponds to the values defined in BNFunctionGraphType.|`array`|[`LowLevelIL`, `Disassembly`, `Disassembly`, `Disassembly`, `LowLevelIL`, `LowLevelILSSAForm`, `LowLevelIL`, `LowLevelILSSAForm`, `MediumLevelIL`, `MediumLevelILSSAForm`]|<a id='ui.view.reflection.ilMap'>ui.view.reflection.ilMap</a>|
| | | |`enum`|`Disassembly`| |
| | | |`enum`|`LowLevelIL`| |
| | | |`enum`|`LiftedIL`| |
| | | |`enum`|`LowLevelILSSAForm`| |
| | | |`enum`|`MediumLevelIL`| |
| | | |`enum`|`MediumLevelILSSAForm`| |
| | | |`enum`|`MappedMediumLevelIL`| |
| | | |`enum`|`MappedMediumLevelILSSAForm`| |
| | | |`enum`|`HighLevelIL`| |
| | | |`enum`|`HighLevelILSSAForm`| |
|ui|Reflection View IL Synchronization|Reflection view follows main view IL changes according to the Reflection View IL Map.|`boolean`|`True`|<a id='ui.view.reflection.ilSync'>ui.view.reflection.ilSync</a>|
|ui|Reflection View Location Synchronization|Reflection view follows navigation actions in the main view.|`boolean`|`True`|<a id='ui.view.reflection.locationSync'>ui.view.reflection.locationSync</a>|
|ui|TypeView Line Numbers|Controls the display of line numbers in the types view.|`boolean`|`True`|<a id='ui.view.types.lineNumbers'>ui.view.types.lineNumbers</a>|
|ui|File Path in Window Title|Controls whether the window title includes the full file path for the current file.|`boolean`|`False`|<a id='ui.window.title.showPath'>ui.window.title.showPath</a>|
|updates|Active Content|Allow Binary Ninja to connect to the update server to check for updates and release notes.|`boolean`|`True`|<a id='updates.activeContent'>updates.activeContent</a>|
|updates|Update Channel Preferences|Select update channel and version.|`string`|`None`|<a id='updates.channelPreferences'>updates.channelPreferences</a>|
|updates|Show All Versions|Show all versions that are available for the current update channel in the UI.|`boolean`|`False`|<a id='updates.showAllVersions'>updates.showAllVersions</a>|

## Updates

Binary Ninja automatically updates itself by default. This functionality can be disabled in the `Update Channel` dialog (`[CMD/CTRL] p`, `Update Channel`, or under the `Preferences` sub menu available under `Edit` on Linux and Windows, and the Application menu on MacOS) preferences by turning off the `Update to latest version automatically` option.

Updates are silently downloaded in the background and when complete an option to restart is displayed in the status bar. Whenever Binary Ninja restarts next, it will replace itself with the new version as it launches.

On windows, this is achieved through a separate launcher that loads first and replaces the installation before launching the new version which you'll notice as a separate window. On MacOS and Linux, the original installation is overwritten after the update occurs as these operating systems allow files to be replaced while running. The update on restart is thus immediate.

Note
!!! Tip "Note"
    If you have any trouble with the self-updater, you can always [request](https://binary.ninja/recover/) a fresh set of download links as long as you are under active support.

### Development Branch

Binary Ninja [stable builds](https://binary.ninja/changelog) releases happen on semi-regular intervals throughout the year. However, we also make development builds available to customers with active support. Simply use the update dialog, and select one of the "Development" channels in the `Update Channel` field.

## Unicode Support

Currently, Unicode support for Big Endian strings is very limited. Also, UTF-16 only supports Basic Latin code points.

## Getting Support

Vector 35 offers a number of ways to receive [support](https://binary.ninja/support/).
