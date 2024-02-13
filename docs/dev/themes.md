User themes are loaded from JSON files (with the `.bntheme` extension) found in the `themes` or `community-themes` subdirectories of your [user folder](../guide/index.md#user-folder). The default, full path to these folders is the following on each supported platform:

- macOS: `~/Library/Application Support/Binary Ninja/{themes,community-themes}`
- Windows: `%APPDATA%\Binary Ninja\{themes,community-themes}`
- Linux: `~/.binaryninja/{themes,community-themes}`

To get started, create a new `.bntheme` file in the themes folder for your platform. You may want to copy one of the [example themes](https://github.com/Vector35/binaryninja-api/tree/dev/themes) to start with to avoid lots of "missing required color" errors.

## Theme File Structure

Theme files have the following top-level structure:

```json
{
  "name": "Example Theme",
  "style": "Fusion",
  "styleSheet": "...",
  "colors": { ... },
  "palette": { ... },
  "disabledPalette": { ... },
  "theme-colors": { ... }
}
```

### Name
The `name` key controls the theme's display name in the UI. This key *must* be unique. There cannot be multiple themes with the same name.

### Style
The `style` key specifies which [Qt style](https://doc.qt.io/qt-6/qstyle.html#details) to use for the UI controls. This key should almost always be set to `"Fusion"`.

### Stylesheet
The `styleSheet` key can be used to customize the Qt style above with a [stylesheet in Qt CSS syntax](https://doc.qt.io/qt-6/stylesheet-reference.html), like so:

```json
{
  "styleSheet": "QWidget { border-radius: 0; }"
}
```

If you need to determine what a specific control's class is in order to style it, you can use the `ui.uiDeveloperTools` setting to enable the Widget Inspector.

### Colors
The `colors` key allows you (the theme author) to define color aliases to be used throughout the rest of the theme file. For example, the following sets up two color aliases, `red` and `blue`:

```json
{
  "colors": {
    "red": "#ff0000",
    "blue": [0, 0, 255]
  }
}
```

Colors can be specified as hex strings or as an `[R, G, B]` array.

#### Blending Functions
In addition to color aliases, the theming engine provides the ability to blend colors by passing an array of blending functions and arguments in [prefix notation](https://en.wikipedia.org/wiki/Polish_notation) in place of a color. We provide two blending functions: **average** (`"+"`) and **mix** (`"~"`), as seen in the example below:

```json
{
  "colors": {
    "red": "#ff0000",
    "blue": [0, 0, 255],
    "purple": ["+", "red", "blue"],
    "yellow": "#ffff00",
    "white": [255, 255, 255],
    "slightPink": ["~", "white", "red", 20],
    "quitePink":  ["~", "white", "red", 200],
    "slightlyPinkYellow": ["+", "~", "white", "red", 20, "yellow"]
  }
}
```

In this example, `red` and `blue` are *averaged* (`+`) to create `purple`. Colors can also be *mixed* (`~`), in a weighted manner, like the `slightPink` and `quitePink` colors (which mix `red` into `white` using two different weights, specified by the integers at the end of the array). These blending functions can also be chained together, like in the `slightlyPinkYellow` color, which mixes some `red` into `white` and then averages the result with `yellow`.

### Palette
The `palette` key is the primary interface for theming Qt UI elements and enables customization of the main [`QPalette` color roles](https://doc.qt.io/qt-6/qpalette.html). The following sub-keys are required for all themes:

```json
{
  "palette": {
    "Window": "...",
    "WindowText": "...",
    "Base": "...",
    "AlternateBase": "...",
    "ToolTipBase": "...",
    "ToolTipText": "...",
    "Text": "...",
    "Button": "...",
    "ButtonText": "...",
    "BrightText": "...",
    "Link": "...",
    "LinkVisited": "...",
    "Highlight": "...",
    "HighlightedText": "...",
    "Light": "..."
  }
}
```

The `PlaceholderText` sub-key is currently not themeable and will be automatically set to the "disabled" `Text` value specified below.

### Disabled Palette
The `disabledPalette` key matches the `palette` key above, but specifies colors to use for disabled controls instead. While not required, providing entries for the `Button`, `ButtonText`, `Text`, `WindowText`, and `ToolTipText` roles is highly recommended.

### Theme Colors
The `theme-colors` key contains the rest of a theme's settings. These colors are typically used for custom controls or contexts specific to Binary Ninja itself (which is why they are separate from the Qt colors controlled via the `palette` and `disabledPalette` keys above).

Colors marked "*required*" must be specified. Unmarked colors will hold default values based upon other colors you have chosen, but will be overridden if specified.

#### Tokens

![Tokens Diagram](../img/themedocs-tokens.png)

1. `addressColor` (*required*) - Used to color memory addresses, e.g. `0x100003c5b`
2. `modifiedColor` (*required*)
3. `insertedColor` (*required*)
4. `notPresentColor` (*required*)
5. `selectionColor` (*required*)
6. `outlineColor` (*required*)
7. `registerColor` (*required*) - Used to color register names in code views, e.g. `rax`
8. `numberColor` (*required*) - Used to color number literals in code view, e.g. `0xf0`
9. `codeSymbolColor` (*required*) - Used to color local function names in code views, e.g. `sub_100003c50`
10. `dataSymbolColor` (*required*) - Used to color data symbols in code views, e.g. `data_100003e2c`
11. `stackVariableColor` (*required*) - Used to color stack variables in code views, e.g `var_8`
12. `importColor` (*required*) - Used to color imported function names in code views, e.g. `printf`
13. `instructionHighlightColor` (*required*)
14. `relatedInstructionHighlightColor`
15. `tokenHighlightColor` (*required*)
16. `annotationColor` (*required*) - Used to color annotations, such as hints
17. `commentColor` - Used to color comments
18. `opcodeColor` (*required*) - Used to color instruction opcodes in code views
19. `stringColor` (*required*) - Used to color string literals in code views, e.g. `"Hello, world!"`
20. `typeNameColor` (*required*) - Used to color user-defined type names in code views, e.g. `my_struct`
21. `fieldNameColor` (*required*) - Used to color structure member names in code views
22. `keywordColor` (*required*) - Used to color keywords in code views, e.g. `for` in HLIL
23. `uncertainColor` (*required*) - Used to color uncertain data in code views, such as variable types with low confidence
24. `exportColor`
25. `nameSpaceColor`
26. `nameSpaceSeparatorColor`
27. `operationColor`
28. `gotoLabelColor`
29. `tokenSelectionColor`

The following colors are used for the Rainbow Braces setting (`ui.rainbowBraces`):

1. `braceOption1Color` - Defaults to `blueStandardHighlightColor`
2. `braceOption2Color` - Defaults to `orangeStandardHighlightColor`
3. `braceOption3Color` - Defaults to `greenStandardHighlightColor`
4. `braceOption4Color` - Defaults to `redStandardHighlightColor`
5. `braceOption5Color` - Defaults to `yellowStandardHighlightColor`
6. `braceOption6Color` - Defaults to `magentaStandardHighlightColor`

#### Hex View

![Hex View Diagram](../img/themedocs-hexview.png)

Each byte in hex view is given a background color based on its value. Values between `0x00` and `0xFF` will use a color interpolated between the `Dark` and `Light` colors specified below.

1. `backgroundHighlightDarkColor` - Used as the background color for bytes of value `0x00`
2. `backgroundHighlightLightColor` - Used as the background color for bytes of value `0xFF`
3. `boldBackgroundHighlightDarkColor` (*required*)
4. `boldBackgroundHighlightLightColor` (*required*)
5. `alphanumericHighlightColor` (*required*) - Used to color alphanumeric characters in hex views, takes precedence over printableHighlightColor
6. `printableHighlightColor` (*required*) - Used to color printable characters in hex views

#### Linear View

![Linear View Diagram](../img/themedocs-linearview.png)

1. `linearDisassemblyFunctionHeaderColor` (*required*) - Used as the background for function
  headers in linear view
2. `linearDisassemblyBlockColor` (*required*) - Used as the background for function bodies in
  linear view
3. `linearDisassemblyNoteColor` (*required*) - Used as the background color for note blocks in
  linear view, such as the info block found at the start of linear view
4. `linearDisassemblySeparatorColor` (*required*) - Used as the separator/border color between
  major elements in linear view

#### Graph View

![Graph View Diagram](../img/themedocs-graphview.png)

Both the graph background and individual graph nodes are actually painted as a gradient. To get a flat background instead, set the `Dark` and `Light` colors to the same color value.

1. `graphBackgroundDarkColor` (*required*) - Used as the bottom-right gradient stop in the graph view background
2. `graphBackgroundLightColor` (*required*) - Used as the upper-left gradient stop in the graph view background
3. `graphNodeDarkColor` (*required*) - Used as the bottom gradient stop in graph node backgrounds
4. `graphNodeLightColor` (*required*) - Used as the upper gradient stop in graph node backgrounds
5. `graphNodeOutlineColor` (*required*) - Used to color the border of graph nodes with no indicator
6. `graphNodeShadowColor`
7. `graphEntryNodeIndicatorColor`
8. `graphExitNodeIndicatorColor`
9. `graphExitNoreturnNodeIndicatorColor`
10. `trueBranchColor` (*required*) - Used to color branches taken when a comparison is true
11. `falseBranchColor` (*required*) - Used to color branches taken when a comparison is false
12. `unconditionalBranchColor` (*required*) - Used to color branches that are always taken
13. `altTrueBranchColor` (*required*) - Used instead of `trueBranchColor` when color-blind mode is enabled
14. `altFalseBranchColor` (*required*) - Used instead of `falseBranchColor` when color-blind mode is enabled
15. `altUnconditionalBranchColor` (*required*) - Used instead of `unconditionalBranchColor` when color-blind mode is enabled

#### Highlighting

![Highlighting Diagram](../img/themedocs-highlighting.png)

1. `blackStandardHighlightColor` (*required*)
2. `blueStandardHighlightColor` (*required*)
3. `cyanStandardHighlightColor` (*required*)
4. `greenStandardHighlightColor` (*required*)
5. `magentaStandardHighlightColor` (*required*)
6. `orangeStandardHighlightColor` (*required*)
7. `redStandardHighlightColor` (*required*)
8. `whiteStandardHighlightColor` (*required*)
9. `yellowStandardHighlightColor` (*required*)

#### Tab Bar

1. `tabBarTabActiveColor`
2. `tabBarTabHoverColor`
3. `tabBarTabInactiveColor`
4. `tabBarTabBorderColor`
5. `tabBarTabGlowColor`

#### Feature Map

1. `featureMapBaseColor`
2. `featureMapNavLineColor`
3. `featureMapNavHighlightColor`
4. `featureMapDataVariableColor`
5. `featureMapAsciiStringColor`
6. `featureMapUnicodeStringColor`
7. `featureMapFunctionColor`
8. `featureMapImportColor`
9. `featureMapExternColor`
10. `featureMapLibraryColor`

#### Side Bar

1. `sidebarBackgroundColor`
2. `sidebarInactiveIconColor`
3. `sidebarActiveIconColor`
4. `sidebarHeaderBackgroundColor`
5. `sidebarHeaderTextColor`
6. `sidebarWidgetBackgroundColor`

#### Mini-Graph

1. `miniGraphOverlayColor`

#### Script Console

![Hex View Diagram](../img/themedocs-console.png)

1. `scriptConsoleOutputColor` - Used to color normal output in the console
2. `scriptConsoleWarningColor` - Used to color warnings in the console
3. `scriptConsoleErrorColor` - Used to color errors in the console
4. `scriptConsoleEchoColor` - Used to color user input in the console

#### Panes

1. `activePaneBackgroundColor`
2. `inactivePaneBackgroundColor`

#### Status Bar

1. `statusBarServerConnectedColor`
2. `statusBarServerDisconnectedColor`
3. `statusBarServerWarningColor`
4. `statusBarProjectColor`
