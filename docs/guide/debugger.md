# Debugger (Beta)

Binary Ninja Debugger is a plugin that can debug executables on Windows, Linux, and macOS.

The debugger plugin is shipped with Binary Ninja. However, it is currently in Beta, so it needs to be manually turned on. The relevant setting is in "Settings" -> "corePlugins" -> "Debugger Plugin (Beta)".

Alternatively, one can set the environment variable BN_EXPERIMENTAL_DEBUGGER (to anything), which also enables the debugger.

After enabling the debugger plugin, restart Binary Ninja to use it.

The debugger is open-source at https://github.com/Vector35/debugger with Apache License 2.0. Bug reports and pull requests are welcome!


## UI

<img src="../img/debugger/ui.png" width="1000"/>

The debugger UI mainly consists of five parts:

- debugger sidebar
- global area panels
- debugger status widget
- debugger context menu
- stack variable annotations

The current UI should accommodate common operations within the debugger. And it is set to receive huge improvements over this summer.

### Debugger Sidebar

The debugger sidebar locates inside the sidebar, which is on the left side of the main window. It can be enabled by clicking the button that looks like a bug.

The debugger sidebar contains four widgets, the control buttons, the register widget, the breakpoint widget, and the module widget.

#### Control Buttons

![](../img/debugger/controlbuttons.png)

There is a row of buttons at the top of the debugger Sidebar. They control the execution of the target. The behavior of the button is hopefully sensible from its icon. One can also hover over the button to get the name of the icon.

Buttons that do not work for the current target status are disabled. For example, before launching the target, the `Step Into` button is disabled.

A typical scenario is to click the left-most button to launch the target, and then use the buttons on the right to resume the target, step into/over/return. The `Pause` button can be used to break into the target while it is running.

There is a Settings button on the right of the buttons. Clicking it will pop up a Debug Adapter Settings dialog, which allows the selection of a DebugAdapter, as well as the configuration of useful things like command-line arguments or the working directory.

For `Step Into` and `Step Over`, if the current view is viewing an IL function, then the operation appears to be performed on that IL, offering a source-code debugging-like experience. However, the underlying operation is still performed at the disassembly level because that is the only thing the backend understands. The high-level operations are simulated, i.e., the debugger may decide to step the target multiple times before finally yielding the control. These are transparent to the users.

![](../img/debugger/adaptersettings.png)


#### Register Widget

![](../img/debugger/registerwidget.png)

Register widget lists registers and their values. A hint column presents anything interesting pointed to by the register. Currently, only strings and pointers to strings are considered. In the future, we would also annotate variables.

Double-clicking a value enters editing mode, and the user can type in new values for the register. The new value is parsed as hex.

The Register widget tracks the last seen value of registers and provides visual feedback. Unchanged values are colored white, changed values are colored blue. User-edited values are colored orange.

An experimental feature is added to shorten the list: registers with a value of zero are not shown in the list. We will evaluate how well it works, and probably going to offer it as a configurable option.


#### Breakpoint Widget

![](../img/debugger/breakpointwidget.png)

The breakpoint widget lists breakpoints in the target. There are two columns in it, the left one shows the address in the format of `module + offset`, and the right column shows the absolute address.

The context menu of the widget offers to delete a breakpoint or to jump to the address of a breakpoint.

#### Module Widget

![](../img/debugger/modulewidget.png)

The module widget shows the address, size, name, and path information of the target's modules.

Note: the bizarrely huge size is caused by dyld_shared_cache on macOS, which will be addressed in the future. The size of the main executable is still calculated correctly.



### Global Area Panels

The debugger adds three new global area widgets, i.e., target terminal, debugger console, and stack trace.

#### Target Terminal

![](../img/debugger/targetterminal.png)

The target terminal simulates a terminal for the target. If the process writes to stdout, the content will be printed here. There is a line input at the bottom, and all input to it will be sent to the target's stdin.

Due to a backend limitation, this feature only works on macOS and Linux. On Windows, the target always runs in its terminal, and all input/output happens there.

On macOS and Linux, the default setting redirects the stdin/stdout here. However, if the user configures the target to run in its terminal (by calling `dbg.request_terminal_emulator = True`), then the stdin/stdout will not be redirected, and need to be accessed in the target's terminal.

#### Debugger Console

![](../img/debugger/debuggerconsole.png)

The debugger console allows the user to execute a backend command and get the result.

On Linux and macOS, the backend is based on LLDB and the syntax follows LLDB command syntax.

On Windows, the backend is based on Windows Debugger Engine, which supports Windbg command syntax.

Note, however, one should NOT execute any command that changes the execution status of the target, E.g., resume/step the target, or launch/quit the target. It will cause the UI to de-synchronize with the backend, or even hang. We have given a high priority to fixing this issue.

#### Stack Trace

![](../img/debugger/stacktracewidget.png)

The stack trace widget lists all the threads along with the stack frames of the active thread.

The dropdown menu is a thread selector, which can be used to switch between threads. The selected thread will become the active thread, and its stack frames will be shown below.

Double-clicking an item in the stack frames list navigates to the return address of the frame.




### Debugger Status Widget

![](../img/debugger/statuswidget.png)

![](../img/debugger/statuswidget2.png)

A debugger status widget is added to the main window's status bar. It indicates the current status of the target.

For example, when the target stops, it will include the reason for the stop. When the target exists, the exit code is reported. When an error occurs during certain operations, an error message will also be displayed here.

The widget always shows the status of the debugger for the current binary view. If you switch to a tab that views a different binary, it will show the status of the debugger for that binary, which might be inactive.


### Context menu

![](../img/debugger/contextmenu.png)

The debugger registers a series of useful actions, along with keyboard shortcuts. These shortcuts can be customized using Binary Ninja's keybindings support.

Among these actions, target control actions, e.g., `Run`/`Step Into` have the same effect as the control buttons in the sidebar.

`Toggle Breakpoint` adds a breakpoint at the current location if there is no breakpoint; otherwise, the existing breakpoint is removed.

`Run To Here` lets the target execute until the current line is hit.

`Make Code` is an experimental feature that displays the selected region as code. If the region is indeed code, the user can then hit `P` to create a function there.

### Stack variable annotation

![](../img/debugger/stackvariable.png)

When the target breaks and a stack trace is available, the debugger annotates the stack variables in the linear view as data variables.

The above image shows the annotated stack with three stack frames. The start and end of each stack frame are marked, and stack variables are defined according to the stack variables in the functions.

To view the stack variable annotations, switch to the linear view of the Debugger binary view, and then navigate to the stack pointer address.

A useful setup is a split view that shows the code on the left, and the stack on the right. If the user adopts this layout, remember to put the linear view that shows the stack region on a different sync group, so executing the target would not lead to navigation of the linear view. This way, we can observe how variables on the stack change.

In the future, we will offer a way to set up this side-by-side view in one click.

Only the stack frames and variables of the current (active) thread are annotated to avoid confusion. If you wish to view stack variables from a different thread, first switch to that thread in the `Stack Trace` global area panel.

The annotation is done only when there are at least two frames in the stack trace. This is a known limitation, and we will address it later.


### Other UI elements

On every line that has a breakpoint, there are two visual indicators:

- the line is highlighted in red
- a red breakpoint tag is added to the left

On the line where the program counter is at, there are two visual indicators:

- the line is highlighted in blue
- a program counter tag is added to the left


## Design

### Debug Adapters

The goal of the Binary Ninja debugger is to provide a unified way of debugging programs on different platforms (e.g., Windows, Linux, macOS, etc). However, this is not an easy task, because each platform has its way of supporting debugging and it varies considerably.

To deal with this, we abstract the core functionalities of a debugger into a class `DebugAdapter`. Each debug adapter is a subclass of the `DebugAdapter` with the platform-dependent implementation of each method.

The debugger then **drives** the various adapters, creating a unified debugging experience, both in GUI and API.

Right now, the debugger comes with two debug adapters. The `LLDBAdapter` uses [LLDB](https://lldb.llvm.org/) as its backend and debugs programs on macOS and Linux. The `DbgEngAdapter` uses [Windows debugger engine](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/introduction), and debugs programs on Windows.

New debug adapters can be created by subclassing `DebugAdapter` to support other targets.

Remote debugging is a planned feature. Specifically, the capacity to connect to a target via [RSP protocol](https://sourceware.org/gdb/current/onlinedocs/gdb/Remote-Protocol.html) is already baked into the LLDBAdapter, though not tested.


### The Debugger BinaryView

To represent the memory space of the target, the debugger creates a specialized `BinaryView` called `DebugProcessView`. Throughout this document, it is also called the `Debugger` BinaryView.

[//]: # (On the other hand, there is a `base` BinaryView that is the BinaryView used to create the debugger. The base binaryView gets rebased to the correct location when the target launches. )

The Debugger BinaryView reads and writes its memory from the connected `DebugAdapter`. To save on data transfer, the debugger caches all read operations from the adapter. Whenever the debugger executes instructions or writes data, the cached data is cleared.

When the target is launched, the debugger automatically switches the view to the Debugger BinaryView.

![](../img/debugger/debuggerview.png)

The debugger automatically applies all analysis data to the Debugger BinaryView, including functions and types, etc. This means the user can conveniently use types that are present in the static analysis.

The Debugger BinaryView can be accessed by `dbg.live_view`, which should not be None once the target is launched. One can read/write to it in the normal way. Writing to it will also cause the target's memory to change.

Right now, the Debugger BinaryView is discarded once the target exits. It cannot be easily reused due to ASLR, which makes the base of the program different in each run. As a result, any changes the user made to the Debugger BinaryView is also gone after the target exits. In the future, we will provide a way to let the user to selectively commit the changes made to the original view.

## API

The debugger exposes its functionality in both Python and C++ API. The Python documentation can be accessed [online](https://api.binary.ninja/binaryninja.debugger.debuggercontroller-module.html).

The API is centered around the [`DebuggerController`](https://api.binary.ninja/binaryninja.debugger.debuggercontroller-module.html#binaryninja.debugger.debuggercontroller.DebuggerController) class, which provides all functionalities of the debugger. There is no need to directly access the `DebugAdapter` classes.

When the debugger is used within the UI, the `dbg` variable is injected into the Python interpreter. It always represents the debugger for the currently active Binary View. One can think of it as being created by

```Python
dbg = DebuggerController(bv)
```

where `bv` is another magic variable that always represents the current BinaryView.

One can simply run `dbg.launch()` in the Python console to launch the target.



## How-to Guide

Here is an incomplete guide on how to get started with the debugger. It covers the most basics operations in the debugger.

### Launch and Control the Target

There are several ways to launch the target:

- Use the control buttons at the top of the debugger sidebar
- Use the debugger context menu or its keybindings
- run `dbg.run()`, `dbg.step_into()`, etc. in the Python console.

Note, one should never issue any command that changes the execution status of the target in the `Debugger Console`, which causes the UI to go out of sync with the backend.


### Configure Launch Parameters

- Click the Settings button which is on the right side of the control buttons widget, and edit parameters in the dialog
- directly set the value of `dbg.cmd_line`, `dbg.working_directory`, `dbg.working_dir`, etc


### Add/Remove Breakpoints

- Select the line, use the `Toggle Breakpoint` context menu
- Right-click a line in the Breakpoint widget in the sidebar, and select `Remove Breakpoint`
- run `dbg.add_breakpoint(address)` or `dbg.delete_breakpoint(address)` in the Python console.


### Modify Register Values

- Double-click a value item in the Register widget, type in the new value, and hit enter
- run `dbg.set_reg_value(reg_name, value)` in the Python console.


### View/Edit Memory

- Switch to Linear or hex view of the Debugger BinaryView, and view/edit in the normal way
- get the Debugger BinaryView by `dbg.live_view`, and read/write it in the normal way


## Open-Source

Vector 35 is grateful for the following open source packages that are used in Binary Ninja debugger:

- [fmt](https://github.com/fmtlib/fmt) ([fmt license](https://github.com/fmtlib/fmt/blob/master/LICENSE.rst) - MIT)
- [pugixml](https://pugixml.org/) ([pugixml license](https://pugixml.org/license.html) - MIT)
- [gdb](https://www.gnu.org/software/gdb) ([GPLv3](https://www.gnu.org/licenses/gpl-3.0.html))
- [lldb](https://lldb.llvm.org/) ([Apache 2.0 License with LLVM exceptions](https://llvm.org/docs/DeveloperPolicy.html#new-llvm-project-license-framework))
