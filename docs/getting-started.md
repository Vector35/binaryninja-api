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

![recent files](/images/recent.png "Recent Files")


## Analysis

![auto analysis](/images/analysis.png "Auto Analysis")

As soon as you open a file, Binary Ninja begins its auto-analysis.

Even while Binary Ninja is analyzing a binary, the UI should be responsive. Not only that, but because the analysis prioritizes user-requested analysis, you can start navigating a binary immediately and any functions you select will be added to the top of the analysis queue. The current progress through a binary is shown in the status bar, but note that the total number of items left to analyze will go up as well as the binary is processed and more items are discovered that require analysis.

Errors or warnings during the load of the binary are also shown in the status bar, along with an icon (in the case of the image above, a large number of warnings were shown). The most common warnings are from incomplete lifting and can be safely ignored. If the warnings include a message like `Data flow for function at 0x41414141 did not terminate`, then please report the binary to the [bug database][issues].

## Interacting

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
    - Raw
        - Raw: Raw hex view with addresses based on file offsets
        - ELF: 
    - Highlight
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

### Hex View

### Xrefs View

![xrefs](/images/xrefs.png "xrefs")

The xrefs view in the lower-left shows all cross-references to a given location or reference. Note that the cross-references pane will change depending on whether an entire line is selected (all cross-references to that address are shown), or whether a specific token within the line is selected.

One fun trick that the xrefs view has up its sleeve: when in [Hex View](#hexview)

### Linear View



### Function List

![function list](/images/functionlist.png "Function List")

The function list in Binary Ninja shows the list of functions currently identified. As large binaries are analyzed, the list may grow during analysis. The function list starts with known functions such as the entry point, exports, or using other features of the binary file format and explores from there to identify other functions.

The function list also highlights imports, and functions identified with symbols in different colors to make them easier to identify.

!!! Tip "Tip"
    To search in the function list, just click to make sure it's focused and start typing!

## Updates


## Preferences


## Troubleshooting

### Common problems

- If you are having problems finding your license or the installers, you can always [recover] either with a self-service email mechanism.
- If experiencing problems with Windows UAC permissions, the easiest fix is to
- Always check both closed and open [issues](https://github.com/Vector35/binaryninja-api/issues) on the github issues search.


### Getting Support

Vector 35 offers a number of ways to get Binary Ninja [support].

[recover]: https://binary.ninja/recover.html
[support]: https://binary.ninja/support.html
[issues]: https://github.com/Vector35/binaryninja-api/issues
