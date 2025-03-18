# Writing Plugins


## Writing Python Plugins

### Creating the Plugin

First, take a look at some of the [example](https://github.com/Vector35/binaryninja-api/tree/dev/python/examples) plugins, or some of the [community](https://github.com/Vector35/community-plugins) plugins to get a feel for different APIs you might be interested in. Of course, the full [API](https://api.binary.ninja/) docs are online and available offline via the `Help`/`Open Python API Reference...`.

To start, we suggest you download the [sample plugin](https://github.com/Vector35/sample_plugin) as a template since it contains all of the elements you're likely to need.

- Begin by editing the `plugin.json` file
- Next, update the `LICENSE`
- For small scripts, you can include all the code inside of `__init__.py`, though we recommend for most larger scripts that init just act as an initializer and call into functions organized appropriately in other files.
- If you have python dependencies, create a [requirements.txt](https://pip.pypa.io/en/latest/cli/pip_freeze/) listing any python dependencies.

### Submitting to the Plugin Manager

If your plugin was created as described above, there's only two steps to get it submitted to the plugin manager!

1. First, create a release either [manually](https://binary.ninja/2019/07/04/plugin-manager-2.0.html#5-create-a-release) or using our [release helper](https://github.com/Vector35/release_helper).
1. Next, just [file an issue](https://github.com/Vector35/community-plugins/issues/new/choose) letting us know about your plugin.

For future releases all you need to do is increment the version and create a new release.

### Using Your Own Plugin Repository

The simplest way to run your own plugin repository is to duplicate the structure of [https://github.com/vector35/community-plugins](https://github.com/vector35/community-plugins). Specifically, the [plugins.json](https://github.com/Vector35/community-plugins/blob/master/plugins.json), as [listing.json](https://github.com/Vector35/community-plugins/blob/master/listing.json) is used along with [generate_index.py](https://github.com/Vector35/community-plugins/blob/master/generate_index.py) to create that file.

Once you've created your test repository, use the `pluginManager.unofficialName` and `pluginManager.unofficialUrl` settings to add your third-party repository.

The [`add_repository`](https://api.binary.ninja/binaryninja.pluginmanager-module.html#binaryninja.pluginmanager.RepositoryManager.add_repository) API can also be used to add the repository, though it [may require manual creation of the repository folder](https://github.com/Vector35/binaryninja-api/issues/2987).

### Testing

It's useful to be able to reload your plugin during testing. On the Commercial or Ultimate editions of Binary Ninja, this is easily accomplished with a stand-alone headless install using `import binaryninja` after [installing the API](https://github.com/Vector35/binaryninja-api/blob/dev/scripts/install_api.py).  (install_api.py is included in each platforms respective [installation folder](../guide/index.md#binary-path))

Additionally, some plugin types like Architectures or BinaryViews are only loaded at launch and cannot be reloaded during a running session.

For other plugins, we recommend the following workflow from the scripting console which enables easy iteration and testing:

```python
import pluginname
import importlib
importlib.reload(pluginname);pluginname.callbackmethod(bv)
```

Then just `[UP] [ENTER]` to trigger the reload when the plugin has changed.

## Writing plugins using other IDEs (tab completion)

Even though non-commercial licenses don't have headless automation, the [install API](https://github.com/Vector35/binaryninja-api/blob/dev/scripts/install_api.py) script (which is included in the installation directory) allows you to add the binaryninja module to your python environment. Once you do that, you should get automatic completion in any editor that supports it even on non-commercial! Of course, on Commercial and Ultimate installations, the script is even more useful, allowing for headless scripts with your existing python interpreter.

## Debugging using other IDEs

If you wish to debug your python scripts, there are a few methods specific to different IDEs:

### Remote debugging with VSCode:

1. Run `pip install --user debugpy` in the Python interpreter you have selected in Binary Ninja Settings.
1. In VSCode, open the Run and Debug sidebar.
1. Create a `launch.json` file if one does not already exist, or open `launch.json` if one does.
1. In `launch.json`, select Add Configuration > Python > Remote Attach
1. Enter a host of `localhost` and any port
1. Set the path mapping to be from `/` to `/` (Windows: `C:\\` to `C:\\`)
1. Open Binary Ninja
1. Use `connect_vscode_debugger(port=12345)` in the Python Console, using whichever port you selected in `launch.json`.
1. In VSCode, start debugging. You should see the bottom toolbar change color, and the debugger should be attached.

### Remote debugging with IntelliJ PyCharm

**WARNING**: Does not work on PyCharm Community, requires PyCharm Professional

1. In PyCharm, add a Run Configuration for Python Debug Server. Give it a name and choose a port and host.
1. Run the `pip install` script displayed in the Run Configuration using whichever python interpreter you have selected for Binary Ninja.
1. In PyCharm, start debugging. You should see "Waiting for process connection..." in the Debugger panel.
1. Open Binary Ninja
1. Use `connect_pycharm_debugger(port=12345)` in the Python Console, using whichever port you selected in the Run Configuration. You should now see "Connected" in the PyCharm Debugger panel.

## UI Plugins

Binary Ninja UI plugins should always `import binaryninjaui` before an `import PySide6`. Not only does this make sure the correct PySide6 is loaded (running the wrong version of PySide6 can result in crashing), but this [prevents plugins](https://github.com/Vector35/binaryninja-api/commit/55cb3e76f536bc8d4a6533bd7ea5202d464c5f81) from running headlessly.

UI plugins can take many forms. Some, like [Snippets](https://github.com/vector35/snippets) create their own UI elements and interact via UIActions. Others extend the UI via existing UI elements such as [Triage](https://github.com/Vector35/binaryninja-api/tree/dev/python/examples/triage), [Kaitai](https://github.com/Vector35/kaitai), [hellosidebar](https://github.com/Vector35/binaryninja-api/blob/dev/python/examples/hellosidebar.py), or [helloglobalarea](https://github.com/Vector35/binaryninja-api/blob/dev/python/examples/helloglobalarea.py).

Many other [third-party](https://github.com/vector35/community-plugins/) plugins also implement UI based examples, such as [BNIL Graph](https://github.com/withzombies/bnil-graph) using the FlowGraph APIs. 

Unfortunately, due to a PySide documentation generation issue, the best and most reliable documentation on the UI system is not in the regular [python](https://api.binary.ninja/) API docs, but in the [C++ documentation](https://api.binary.ninja/cpp/) which translates fairly cleanly to their python equivalent.


## Writing Native Plugins

Writing native plugins allows for higher performance code and lower level access to the Binary Ninja API, but comes with a couple more hurdles than Python. 
Notably, native plugins are built against a specific version of the API, cannot be hot-reloaded, and require more sophisticated build setups.

### Supported Toolchains

When building native plugins for Binary Ninja, the following toolchains and dependencies are required, based on host OS.
Older versions may work but are not supported.

- macOS: Xcode 13+
- Windows: VS 2019 Professional with C/C++ Native Tools package
- Linux: GCC 9.4+

Additionally, Binary Ninja uses C++17 features, and requires a C++17 compatible compiler.

### CMake Setup

Binary Ninja uses the [CMake](https://cmake.org/) build system generator to compile native code, and provides
convenient helper scripts for those making plugins. As of writing, CMake 3.13 or greater is required,
although it is recommended to use the latest version.

### Project Setup

The first things to specify in your CMake file are a couple boilerplate options for building C++:  

    # Pick whatever version you have
    cmake_minimum_required(VERSION 3.24)

    # Name your plugin
    project(TestPlugin CXX)
    
    set(CMAKE_CXX_STANDARD 17)
    
    # Unless you are writing a plugin that needs Qt's UI, specify this
    set(HEADLESS 1)

Then you want to get the matching API repository for the version of Binary Ninja you have.
This information is contained in a file named `api_REVISION.txt` that exists in the root install folder for Linux,
the `Contents/Resources` sub-folder on macOS, and the root installation folder on Windows.

Once you know which revision to use, you can clone a copy of the binaryninja-api repository
and reference it directly in your plugin. If you're using git, this can be accomplished easily using a submodule:

    git submodule add https://github.com/Vector35/binaryninja-api.git binaryninjaapi
    cd binaryninjaapi
    # Pick the revision from api_REVISION.txt
    git checkout 6466fba3341b2ea7dbfceeeebbc6c0322a5d8514 

If you're not using git, you can clone the repository elsewhere:

    git clone https://github.com/Vector35/binaryninja-api.git binaryninjaapi
    cd binaryninjaapi 
    # Pick the revision from api_REVISION.txt
    git checkout 6466fba3341b2ea7dbfceeeebbc6c0322a5d8514 

Now that you have the correct copy of the api, you need to point CMake at it and include it for use.
Include something like the following in your CMake script and either add the path of your clone
to the HINTS list or set the BN_API_PATH environment variable to the location of your clone

    find_path(
        BN_API_PATH
        NAMES binaryninjaapi.h
        # List of paths to search for the clone of the api
        HINTS ../.. binaryninjaapi $ENV{BN_API_PATH}
        REQUIRED
    )
    add_subdirectory(${BN_API_PATH} api)

Be sure to create a shared library and link against the Binary Ninja api. Also, you can use the
`bn_install_plugin` helper to automatically set up your plugin to install to the Binary Ninja plugins directory
when you use `cmake install`.

    # Use whichever sources and plugin name you want
    add_library(TestPlugin SHARED TestPlugin.cpp) 
    
    # Link with Binary Ninja
    target_link_libraries(TestPlugin PUBLIC binaryninjaapi)
    
    # Tell `cmake --install` to copy your plugin to the plugins directory
    bn_install_plugin(TestPlugin)

From there you can write the rest of your plugin's CMake configuration, including any other dependencies or
options that you want. When you want to run your plugin, you can use `cmake --build` and `cmake --install`
to compile and copy your plugin to your Binary Ninja plugins directory, or set up an IDE to do that for you.
You could also copy the plugin manually if you are using a different plugins directory location. 

In the source code of your plugin, you will need to export some functions that Binary Ninja uses to load your plugin
at runtime:

    #include "binaryninjaapi.h"
    extern "C" {
        // Tells Binary Ninja which version of the API you compiled against
        BN_DECLARE_CORE_ABI_VERSION
        
        // Function run on plugin startup, do simple initialization here (Settings, BinaryViewTypes, etc)
        BINARYNINJAPLUGIN bool CorePluginInit()
        {
            return true;
        }

        // (Optional) Function to add other plugin dependencies in case your plugin requires them
        BINARYNINJAPLUGIN void CorePluginDependencies()
        {
            // For example, if you require the x86 to be loaded before your plugin
            AddRequiredPluginDependency("arch_x86");
        }
    }

From there, you can implement your plugin functionality as you desire. I highly recommend looking at other plugins for
API usage since the C++ API is less well-documented than the Python API. Usually the functions and classes are named
identically, but you may find some outliers. Also, C++ has a way more difficult task of managing memory, since there is
no garbage collector to handle it for you. Generally speaking, most API objects are reference-counted via the `Ref<T>`
class, and you should only ever handle Refs or bare pointers. When in doubt, feel free to ask on
[our Slack](https://binaryninja.slack.com/) and both our team and helpful community can assist.

### Automated GitHub CI

Managing build infrastructure to build cross-platform native plugins can be a headache even for stables, let alone 
trying to track all dev releases. To help with that, we've published an [example plugin](https://github.com/Vector35/sample_plugin_cpp) that includes GitHub
actions to build on MacOS, Linux, and Windows. Combining this with something like a [plugin loader](https://github.com/rikodot/binja_native_sigscan_loader) can simplify
both publishing and using native plugins.

### UI Plugins

If you want to include UI in your plugin, you can integrate with Binary Ninja's Qt-based UI by linking with Qt and `binaryninjaui`.
You will need to use the same version of Qt as Binary Ninja. We provide steps for building it [here](../about/open-source.md#building-qt),
or you can attempt to use a system-provided copy if you use Linux and like to live dangerously.
Building it is a bit of a process, but should provide you with a working installation. Once you have a Qt build,
you can amend your CMake file to make a UI plugin. You will need the following CMake:

    # Remove this or set to 0
    # set(HEADLESS 1)

    # If you are using Qt MOC (i.e. use Q_OBJECT/Q_SIGNALS/Q_SLOTS)
    set(CMAKE_AUTOMOC ON)
    set(CMAKE_AUTORCC ON)
    
    # Locate Qt installation for linking
    find_package(Qt6 COMPONENTS Core Gui Widgets REQUIRED)
    
    # Add MOCS to your build
    add_library(TestPlugin SHARED library.cpp ${MOCS})

    # Link against both binaryninjaapi/binaryninjaui and Qt6
    target_link_libraries(TestPlugin PUBLIC binaryninjaapi binaryninjaui Qt6::Core Qt6::Gui Qt6::Widgets)

Then, in your plugin code, instead of using the exported functions for a core plugin, use the ones for a UI plugin:

    #include "binaryninjaapi.h"
    #include "uitypes.h"
    #include "uicontext.h"
    
    extern "C" {
        // Tells Binary Ninja which version of the API you compiled against
        BN_DECLARE_UI_ABI_VERSION
    
        // Function run on plugin startup, do simple initialization here (ViewTypes, SidebarWidgetTypes, etc)
        BINARYNINJAPLUGIN bool UIPluginInit()
        {
            return true;
        }

        // (Optional) Function to add other plugin dependencies in case your plugin requires them
        // Historically, these have never actually been used 
        BINARYNINJAPLUGIN void UIPluginDependencies()
        {
            // For example, if you require triage view to be loaded before your plugin
            AddRequiredUIPluginDependency("triage");
        }
    }

From there, you can implement whatever wacky Qt user interfaces you dream up. Be warned that the Binary Ninja UI API is
rather poorly documented and often missing helper functions for use by plugins. Feel free to ask for assistance and
suggestions, but know that it's very easy to run into memory bugs when working with Qt. I would recommend looking at
the source to [the debugger](https://github.com/vector35/debugger), as an example of the largest, best-maintained UI
plugin for Binary Ninja.

### Python Integration

If you want your C++ plugin to also support a Python API, you will have a lot of work to do. Generally speaking, there
are no cookie-cutter solutions to this problem, but there is a general strategy:

1. Expose a C API from your plugin
2. Provide a set of Python bindings to that C API
3. Load those Python bindings as a Python plugin in Binary Ninja

Again, I'm going to point out [the debugger](https://github.com/vector35/debugger) as a fantastic example of how to
implement this. Generally speaking, you will either need to write both sides of the FFI in a similar way, or you may
be able to find a library that does that for you. Possibly [libffi](https://sourceware.org/libffi/), although there 
aren't any examples of using it for Binary Ninja specifically. If you manage to get something working, let us know!
We would love to see more complex plugins with extensible behavior! 

## IDE Setup

### CLion

CLion is generally pretty good at handling CMake projects. Given the above CMake configuration, it can
automatically detect the plugin target and will compile and install correctly. Here are a a few steps to finish
setup for building and live debugging your plugin:

1. If you installed Binary Ninja somewhere other than the default, add an environment variable in your CMake Profile pointing at the installation, e.g.: `BN_INSTALL_DIR=/Applications/Binary Ninja.app`
2. If you are writing a UI plugin, you will need to include the directory containing `qmake` to the `PATH` Environment Variable in your CMake Profile, e.g.: `PATH=/usr/bin:/bin:/usr/sbin:/sbin:/Users/user/Qt/6.8.2/clang_64/bin`
3. In your Run Configuration's Before Launch steps, add an Install step. This will copy the updated version of your plugin before starting, so you don't have to run Install manually.
4. Set the Executable of your Run Configuration to point to the Binary Ninja executable. This allows you to compile your plugin and start Binary Ninja automatically.
   i. On macOS, you will need the full path to /Applications/Binary Ninja.app/Contents/MacOS/binaryninja
5. (Optionally) Add the `-e` flag to the Program Arguments to get error logs printed to your console 
6. (Optionally) Add the `-e -d` flags to the Program Arguments to get debug logs printed to your console. This may slow down Binary Ninja (and CLion) due to the large volume of logs produced.
7. (Optionally) Add the `-l /tmp/bn_out.txt` flags to the Program Arguments so your logs also get printed to a text file when you inevitably fill up the Console buffer in CLion and want to see what happened.
8. (Optionally on macOS) Add the Environment Variables `MallocScribble=1` and `MallocPreScribble=1` to make memory errors easier to spot.

### Visual Studio Code

VSCode takes a bit of configuration to set up, but can build and debug plugins efficiently once ready.
You can install the C/C++ extension, the CMake extension, and the CMake Tools extension.
You need to set up a task in `.vscode/tasks.json` to build and install your plugin. Something like this:

    // tasks.json
    {
        "version": "2.0.0",
        "tasks": [
            {
                "type": "cmake",
                "label": "CMake: install",
                "command": "install",
                "problemMatcher": [],
                "detail": "CMake template install task",
                "options": {
                    "environment": {
                        // You will need this if your Binary Ninja installation is not in the default location   
                        "BN_INSTALL_DIR": "C:\\Users\\User\\AppData\\Local\\Vector35\\BinaryNinja",
                        // You will need this if you are writing a UI plugin
                        "PATH": "C:\\Users\\User\\Qt\\6.8.2\\msvc2019_64\\bin"
                    }
                }
            }
        ]
    }

You will also want to set up a launch task in `.vscode/launch.json` to launch Binary Ninja in a debugger,
so you can debug your plugin.
Be sure to set `"preLaunchTask"` to use the `CMake: install` task created above, so your code updates will be
built and installed automatically before you start debugging.

    // launch.json
    {
        "version": "0.2.0",
        "configurations": [
            {
                "name": "(Windows) Launch",
                "type": "cppvsdbg",
                "request": "launch",
                "program": "C:\\Users\\User\\AppData\\Local\\Vector35\\BinaryNinja\\binaryninja.exe",
                "args": [],
                "stopAtEntry": false,
                "cwd": "C:\\Users\\User\\AppData\\Local\\Vector35\\BinaryNinja",
                "environment": [],
                "console": "externalTerminal",
                "preLaunchTask": "CMake: install"
            }
        ]
    }

There are a few other options you can use to assist in debugging:

1. (Optionally) Add the `"-e"` flag to the launch configuration's `args` to get error logs printed to your console
2. (Optionally) Add the `"-e", "-d"` flags to the launch configuration's `args` to get debug logs printed to your console. This may slow down Binary Ninja (and VSCode) due to the large volume of logs produced.
3. (Optionally) Add the `"-l", "/tmp/bn_out.txt"` flags to the launch configuration's `args` so your logs also get printed to a text file when you inevitably fill up the Console buffer and want to see what happened.
4. (Optionally on macOS) Add the environment variables `{ "name": "MallocScribble", "value": "1" }` and `{ "name": "MallocPreScribble", "value": "1" }` to make memory errors easier to spot.

As a footnote, it should be noted that most of the team at Vector 35 use VSCode as a bare text editor
and use command-line lldb or gdb to debug their code. Shout-outs to people trying to get this working in Vim.

## Submitting to the plugin manager

While native plugins are not supported in the plugin manager at this time, it's possible to work around this limitation by pre-building a native plugin for all three platforms and using a python plugin that acts as a loader for the native plugin. There aren't any good examples of automated workflows for this, but [binexport](https://github.com/google/binexport) has supposedly got it working. But given that the people you're distributing your plugin to may have a different version of the API, you will likely want to just distribute the source code and build setup, and have them build against whatever version of Binary Ninja they have installed.

## Examples

Several native plugin examples exist:

 - [Triage](https://github.com/Vector35/binaryninja-api/tree/dev/examples/triage)
 - [Debugger](https://github.com/Vector35/debugger)
 - [ObjectiveNinja](https://github.com/jonpalmisc/ObjectiveNinja)
 - [BinExport](https://github.com/google/binexport#binary-ninja) (Used with BinDiff)
 - [Binliner](https://github.com/holmesmr/binliner)

## Contributing to Official Plugins

There are many many official plugins released as open source. Python ones are included in the [official plugin repository](https://github.com/vector35/official-plugins), [native architectures](https://github.com/vector35/?q=arch-&type=all&language=&sort=) are available on GitHub along with several others that are included with the default product such as the [debugger](https://github.com/Vector35/debugger), the [views](https://github.com/vector35/?q=view-&type=public&language=&sort=), [platforms](https://github.com/vector35/?q=platform&type=public&language=&sort=), and some [rust plugins](https://github.com/Vector35/binaryninja-api/tree/dev/rust/examples).

The first time you contribute, you'll be asked to sign a [CLA](https://gist.github.com/psifertex/a207c2e070f4e342554dc011e920b341) automatically by [cla-assistant](https://cla-assistant.io/). Further commits after the first should not require any changes.
