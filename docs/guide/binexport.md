# BinExport / BinDiff

Binary Ninja includes a native similarity provider based on Google's
[BinDiff](https://github.com/google/bindiff) project. The same plugin can export
[BinExport](https://github.com/google/binexport) files for use with the standalone BinDiff tools.

## Exporting from the UI

Run **Plugins > BinExport**, or select **BinExport** in the
[command palette](./index.md#command-palette). Choose the destination for the `.BinExport` file in the save dialog.
Export failures are reported in the log and in the UI.

After exporting the binaries to compare, run BinDiff on the two files using its command-line or graphical interface:

```sh
bindiff baseline.BinExport modified.BinExport
```

## Exporting headlessly

The same command works headlessly. It writes a `.BinExport` file next to the source binary using the source filename:

```python
from binaryninja import PluginCommand, PluginCommandContext

context = PluginCommandContext(bv)
PluginCommand.get_valid_list(context)["BinExport"].execute(context)
```

The source view must have a filename when the command is run headlessly.

## Built-in similarity

The **Google BinDiff** provider can also compare binaries directly in a
[similarity session](./similarity.md), without first creating intermediate BinExport files.

## Disabling

Disable `corePlugins.bindiffSimilarity` to prevent the bundled plugin from loading. This disables both the Google
BinDiff similarity provider and the BinExport command.

BinExport and BinDiff are Google projects distributed under the Apache 2.0 license. See
[Open Source Components](../about/open-source.md) for attribution.
