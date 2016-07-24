# Getting Started

Welcome to Binary Ninja. This introduction document is meant to quickly guide you over some of the most common uses of Binary Ninja.

## License

When you first run Binary Ninja, it will prompt you for your license key. You should have received your license key via email after your purchase. If not, please contact [support].

![license popup](/images/license-popup.png "License Popup")

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

As soon as you open a file, Binary Ninja begins its auto-analysis.

Even while Binary Ninja is analyzing a binary, the UI should be responsive. Not only that, but because the analysis prioritizes user-requested analysis, you can start navigating a binary immediately and any functions you select will be added to the top of the analysis queue. The current progress through a binary is shown in the status bar, but note that the total number of items left to analyze will go up as well as the binary is processed and more items are discovered that require analysis.

![auto analysis](/images/analysis.png "Auto Analysis")

Errors or warnings during the load of the binary are also shown in the status bar, along with an icon (in the case of the image above, a large number of warnings were shown). The most common warnings are from incomplete lifting and can be safely ignored. If the warnings include a message like `Data flow for function at 0x41414141 did not terminate`, then please report the binary to the [bug database][issues].

## Interacting

- TBD

## Troubleshooting

- TBD

### Common problems

- TBD

### Getting Support

Vector 35 offers a number of ways to get Binary Ninja [support].

[support]: https://binary.ninja/support.html
[issues]: https://github.com/Vector35/binaryninja-api/issues
