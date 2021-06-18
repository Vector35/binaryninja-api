## Creating Themes

User themes are loaded from JSON files (with the `.bntheme` extension) found in
the `themes` or `community-themes` subdirectories of your [user
folder](/getting-started.html#user-folder). The full path to these folders
effectively being the following:

- macOS: `~/Library/Application Support/Binary Ninja/{themes,community-themes}`
- Windows: `%APPDATA%\Binary Ninja\{themes,community-themes}`
- Linux: `~/.binaryninja/{themes,community-themes}`



To get started, create a new `.bntheme` file in the themes folder for your
platform. You may want to copy one of the [example
themes](https://github.com/Vector35/binaryninja-api/tree/dev/themes) to start
with to avoid lots of "missing required color" errors.

### Theme File Structure

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

A description of each of these keys is as follows.

#### Name

The `name` key controls the theme's display name in the UI. Be sure that this is
unique, as there cannot be multiple themes with the same name.

#### Style

The `style` key specifies which [Qt
style](https://doc.qt.io/qt-6/qstyle.html#details) to use for the UI
controls. This key should almost always be set to `"Fusion"`.

#### Stylesheet

Additional styling can be done by provinding a
[stylesheet](https://doc.qt.io/qt-6/stylesheet-reference.html) in Qt CSS syntax
via the `styleSheet` key, like so:

```json
{
  "styleSheet": "QWidget { border-radius: 0; }"
}
```

#### Colors

The `colors` keys allows you (the theme author) to define color aliases to be
used throughout the rest of the theme file as a shorthand for specific
colors. For example, the following sets up two color aliases, `red` and `blue`:

```json
{
  "colors": {
    "red": "#ff0000",
    "blue": [0, 0, 255]
  }
}
```

Notice that colors can be specified as hex strings or as a `[R, G, B]` array.

#### Palette

The `palette` key is the primary interface for theming Qt UI elements and
enables customization of the main `QPalette` color roles.

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
    "Highlight": "...",
    "HighlightedText": "...",
    "Light": "..."
  }
}
```

See [Qt's documentation](https://doc.qt.io/qt-5/qpalette.html#ColorRole-enum)
for more info about which each color role does.

#### Disabled Palette

The `disabledPalette` key is similar to the `palette` key, except it allow
configuration of the same colors for use in disabled controls. While not
required, providing entries for the `Button`, `ButtonText`, `Text`, and
`WindowText` roles is highly recommended.

### Theme Colors

The rest of a theme's settings are in the `theme-colors` key, where colors for
different disassembly tokens, custom UI elements, etc. are defined. See the next
section for a list of all the customizable options.

### Blending Functions

In addition to [color aliases](#colors), the theming engine provides the ability
to blend colors by passing an array of blending functions and arguments in
[prefix notation](https://en.wikipedia.org/wiki/Polish_notation) in place of a
color:

```json
{
  "colors": {
    "red": "#ff0000",
	"blue": [0, 0, 255],
	"purple": ["+", "red", "blue"]
    "slightPink": ["~", "white", "red", 20],
    "quitePink":  ["~", "white", "red", 200],
  }
}
```

In the example above, the **average function** (`+`) is used to create a
`purple` color that is the avarge of `red` and `blue`. Colors can also be mixed
in a weighted manner, using the **mix function** (`~`), which is used above to
create the `slightPink` and `quitePink` colors by mixing `red` into `white`.
These functions can also be chained together like in the example below, which
mixes some `red` into `white` then averages the result with `yellow`:

```json
{
  "colors": {
    "red": "#ff0000",
	"white": [255, 255, 255],
	"yellow": "#ffff00",
	"slightPinkYellow": ["+", "~", "white", "red", 20, "yellow"],
  }
}
```

### Theme Colors

All of the custom colors that can be adjusted by themes (and how they are used)
are described below.

#### Tokens

The following colors are used to highlight tokens in code views:

- `addressColor` - Used to highlight memory addresses, e.g. `0x100003c5b`
- `registerColor` - Used to highlight register names in code views, e.g. `rax`
- `numberColor` - Used to highlight number literals in code view, e.g. `0xf0`
- `codeSymbolColor` - Used to highlight local function names in code views, e.g. `sub_100003c50`
- `dataSymbolColor` - Used to highlight data symbols in code views, e.g. `data_100003e2c`
- `stackVariableColor` - Used to highlight stack variables in code views, e.g `var_8`
- `importColor` - Used to highlight imported function names in code views, e.g. `printf`
- `stringColor` - Used to highlight string literals in code views, e.g. `"Hello, world!"`
- `typeNameColor` - Used to highlight user-defined type names in code views, e.g. `my_struct`
- `fieldNameColor` - Used to highlight structure member names in code views
- `keywordColor` - Used to highlight keywords in code views, e.g. `for` in HLIL
- `uncertainColor` - Used to highlight uncertain data in code views, such as variable types with low confidence
- `annotationColor` - Used to highlight annotations, such as hints and comments
- `opcodeColor` - Used to highlight instruction opcodes in code views

#### Graph View

##### Background

The graph view background is controlled by the following two colors:

- `graphBackgroundDarkColor` - Used as the bottom-right gradient stop in the
  graph view background
- `graphBackgroundLightColor` - Used as the upper-left gradient stop in the
  graph view background

For a flat background, set both colors to the same value. For a diagonal
gradient, assign a unique color to each.

##### Nodes

Node appearance can be configured with the following colors:

- `graphNodeDarkColor` - Used as the bottom gradient stop in graph node backgrounds
- `graphNodeLightColor` - Used as the upper gradient stop in graph node backgrounds
- `graphNodeOutlineColor` - Used to color the border of graph nodes

Similar to the graph background, a gradient appearance can be achieved by using
unique colors for both background colors

##### Branches

The color of branches between nodes can be adjusted with the following colors:

- `trueBranchColor` - Used to color branches taken when a comparison is true
- `falseBranchColor` - Used to color branches taken when a comparison is false
- `unconditionalBranchColor` - Used to color branches that are always taken
- `altTrueBranchColor` - Same as `trueBranchColor`, but used when color blind
  mode is enabled
- `altFalseBranchColor` - Same as `falseBranchColor`, but used when color blind
  mode is enabled
- `altUnconditionalBranchColor` - Same as `unconditionalBranchColor`, but used
  when color blind mode is enabled

Don't forget about the alternate colors for users with color blind mode enabled!

#### Linear View

The appearance of linear view can be tweaked via the following colors:

- `linearDisassemblyFunctionHeaderColor` - Used as the background for function
  headers in linear view
- `linearDisassemblyBlockColor` - Used as the background for function bodies in
  linear view
- `linearDisassemblyNoteColor` - Used as the background color for note blocks in
  linear view, such as the info block found at the start of linear view
- `linearDisassemblySeparatorColor` - Used as the separator/border color between
  major elements in linear view

#### Hex View

##### Foreground

Byte values corresponding to alphanumeric and printable ASCII values are given
special highlighting controlled by the folowing colors:

- `alphanumericHighlightColor` - Used to highlight alphanumeric characters in
  hex views, takes precedence over printableHighlightColor
- `printableHighlightColor` - Used to highlight printable characters in hex views

##### Background

Each byte in hex view is given a background color based on its value. The
following two colors control the color of each extreme:

- `backgroundHighlightDarkColor` - Used as the background color for bytes of
  value `0x00`
- `backgroundHighlightLightColor` - Used as the background color for bytes of
  value `0xFF`

Values in between `0x00` and `0xFF` will use a color interpolated between the
two colors above.

#### Script Console

Different types of text inside the scripting console can be themed via the
following colors:

- `scriptConsoleOutputColor` - Used to color normal output in the console
- `scriptConsoleWarningColor` - Used to color warnings in the console
- `scriptConsoleErrorColor` - Used to color errors in the console
- `scriptConsoleEchoColor` - Used to color user input in the console

#### Highlighting

The following colors are used when the user wishes to highlight an instruction
or graph node:

- `blueStandardHighlightColor`
- `greenStandardHighlightColor`
- `cyanStandardHighlightColor`
- `redStandardHighlightColor`
- `magentaStandardHighlightColor`
- `yellowStandardHighlightColor`
- `orangeStandardHighlightColor`
- `whiteStandardHighlightColor`
- `blackStandardHighlightColor`
