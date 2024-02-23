# Migrating from Ghidra

## Starting Binary Ninja

Binary Ninja starts with the [New Tab Page](../index.md#new-tab) open. From here, you can optionally [start a project](../projects.md#creating-a-project) to work with multiple files, navigate your offline docs from the help menu, or just [open existing files](../index.md#loading-files) (including drag-and-drop!).

## Decompiler Settings

Binary Ninja likes to stay out of your way as much as possible, but sometimes you need to dig into the settings and change how a file is analyzed. If you have a file that can be opened with default settings, you won't get prompted for any additional input. Binary Ninja will automatically analyze the entire file — including running [linear sweep](https://binary.ninja/2017/11/06/architecture-agnostic-function-detection-in-binaries.html) — and provide you with linear decompilation for the whole file (like Ghidra's linear disassembly, but as decomp by default).

If you're opening a [Universal Mach-O](https://en.wikipedia.org/wiki/Universal_binary), the Open with Options dialogue will appear so that you can choose which architecture to open (in the top right). If you have a default architecture you want to open whenever you open a universal binary, you can set your preference in a setting called [Universal Mach-O Architecture Preference](../settings.md#all-settings). You'll also see the Open with Options dialogue when Binary Ninja is unable to recognize the file type or otherwise needs user input to analyze the file (can't find the entry point, needs you to provide some memory mappings, etc).

It's worth digging into Binary Ninja's [settings](../settings.md) and seeing what's available to tune, but if you ever want to change a setting for a single binary, you can Open (it) with Options. Go to File -> Open with Options, and any settings you change will apply to only that file.

<!-- TODO : Can you analyze a file while Ghidra is running its analysis?
## Analyzing While Analyzing -->

## Keybindings

Binary Ninja's keybindings are very different from Ghidra. Thankfully, [Binary Ninja's action system](https://binary.ninja/2024/02/15/command-palette.html) allows you to easily find actions and view the keybindings extremely easily. It'll also save you from digging through unfamiliar right-click menus while helping you learn any new keybindings. All actions can have their keybinding set, changed, or removed in the [keybindings menu](../index.md#default-hotkeys).

Some of the most useful default keybindings are as follows:

Analysis Keybindings:

| Action               | Keybinding         |
|----------------------|--------------------|
| Rename               | `N`                |
| Set Type             | `Y`                |
| Go to                | `G`                |
| Toggle Disasm/Decomp | `[TAB]`            |
| Toggle Graph/Linear  | `[SPACE]`          |
| Toggle Hex View      | `H`                |
| Insert Comment       | `;`                |
| Manage Plugins       | `[CTRL/⌘-SHIFT-B]` |
| Open Command Palette | `[CTRL/⌘-P]`       |
| Open Python Console  | `\``               |

Types Keybindings:

| Action               | Keybinding |
|----------------------|------------|
| Set Type             | Y          |
| Make C String        | A          |
| Make Magic Struct    | S          |
| Open Types Menu      | T          |
| Make 1-byte elements | 1          |
| Make 2-byte elements | 2          |
| Make 4-byte elements | 4          |
| Make 8-byte elements | 8          |
| Make array           | *          |

Common System Keybindings:

| Action            | Keybinding         |
|-------------------|--------------------|
| Open File         | `[CTRL/⌘-O]`       |
| Open with Options | `[CTRL/⌘-SHIFT-O]` |
| Save              | `[CTRL/⌘-S]`       |
| Undo              | `[CTRL/⌘-Z]`       |
| Redo              | `[CTRL/⌘-SHIFT-Z]` |
| Find              | `[CTRL/⌘-F]`       |
| Open Settings     | `[CTRL/⌘-,]`       |
| Open Keybindings  | `[CTRL/⌘-SHIFT-B]` |

## Layout

Binary Ninja's layout is also a bit different from what you're used to in Ghidra, but thankfully Binary Ninja's UI is flexible enough to allow us to build something that will feel familiar.

### Theme

This doesn't exactly have to do with your layout, but it go a long way towards making the interface feel a bit more familiar. We have an expansive list of [community themes](https://github.com/Vector35/community-themes), and [a guide](../../dev/themes.md) and a [blog post](https://binary.ninja/2021/07/08/creating-great-themes.html) on how to make your own. The built-in "Classic" theme should feel nostalgic, but if you're looking for a light theme that's slightly easier on the eyes, try out Summer or Solarized Light.

### Feature Map

Binary Ninja's [feature map](../index.md#feature-map) lives on the right side of your main view area. If you'd rather not see it, you can right-click it and select "Hide Feature Map."

### Sidebars

Our sidebars have a whole host of customization options, so make sure to check out [their dedicated docs](../index.md#the-sidebar) to maximize your workflow.

That said, I'll walk you through how to set up your sidebars to get it looking very similar to what you're used to in Ghidra.

#### Program Tree

But first, there are a couple caveats. Binary Ninja does not have an exact 1-to-1 widget for everything in Ghidra. The Program Tree is one of those elements; it's a little bit like our memory map, but it's also kinda not. Our new Binary Ninja layout assumes you've closed the program tree in Ghidra. Now Binary Ninja and Ghidra's sidebars are starting to match by having the symbols view on the top (which we start as a flat listing for you to organize into file yourself), and a different sidebar panel below it. Be sure to check out the options in the Symbols list's hamburger menu (the three lines in the top right).

#### Cross References and Types Manager

We show cross references by default, but you can toggle that just by clicking it off on the left side under the divider line. If you want to match how Ghidra has it's types showing on the bottom, you can simply drag the types widget to beneath the divider line on the left side. Whenever you open your sidebar, both areas will open together. The Types sidebar also shows you the full type definition when you select a type.

#### Main Area

Time for the main event!

Ghidra shows you a linear view on the left, and single-function-at-a-time decompilation on the right. We already gave you linear decompilation of the whole Binary here by default, so there are three last things to do:

1. Create a new pane by pressing the icon in the top right that looks like a rectangle with a line through it. The two panes are now synced by address, as you’d expect.
2. In the left pane, find the drop down that says "High Level IL", and switch down to disassembly. You should now have linear disassembly on the left, and linear decompilation on the right.
3. The final touch is to go back to the decompilation pane on the right and find the hamburger menu for that pane in the top right, and then select “Single Function View.”

Now the UI should be looking extremely familiar. Read our last couple of tips below, don't forget to use the command palette to find what you want to do, and you'll be off analyzing binaries in no time!

#### Saving Layouts

Now that you've done all this hard work to make the perfect layout, it would be a shame to lose it! Thankfully, we make it easy. Go to the `Window` → `Layout` → `Save Current Layout...` and give it a name, or select `Save Current Layout as Default`. Named layouts let you quickly swap between different kinds of work.

## What You'll Love

...about switching to Binary Ninja! We know leaving your old tool behind can be hard, and there will be things you miss, but we think there are a lot of features packed into Binary Ninja that you'll love. Here are a couple we think you'll appreciate:

 - [Updates every day](../index.md#updates) on the dev branch (nearly) - accepted PRs can be in everyone's hands within hours.
 - [Our awesome native Python API](../../dev/cookbook.md) (and [C++](https://api.binary.ninja/cpp/), and [Rust](https://dev-rust.binary.ninja/))
 - [The speed](https://binary.ninja/2022/05/31/3.1-the-performance-release.html)
 - ...not needing to manage Java installations

---

Don't forget to check out our [additional resources](index.md#additional-resources)!
