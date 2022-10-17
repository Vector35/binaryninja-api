# Using Plugins

The most common Binary Ninja plugins are Python which we are covering here. That said, there are some C++ plugins which must be built for the appropriate native architecture and will usually include build instructions for each platform. Several [C++ examples](https://github.com/Vector35/binaryninja-api/tree/dev/examples) are included in the API repository, and the [binexport](https://github.com/google/binexport) utility (used with [bindiff](https://www.zynamics.com/bindiff.html)) is also a native plugin that must be built and installed manually.

Plugins are loaded from the user's plugin folder:

- macOS: `~/Library/Application Support/Binary Ninja/plugins/`
- Linux: `~/.binaryninja/plugins/`
- Windows: `%APPDATA%\Binary Ninja\plugins`

Note that plugins installed via the [PluginManager API](https://api.binary.ninja/binaryninja.pluginmanager-module.html) are installed in the `repositories` folder in the same path as the previous `plugin` folder listed above.  You should not need to manually adjust anything in that folder, but should access them via the API instead.

## Plugin Manager

![Plugin Manager >](../img/plugin-manager.png "Plugin Manager")

Plugins can now be installed directly via the GUI from Binary Ninja. You can launch the plugin manager via any of the following methods:

 - (Linux/Windows) `[CTRL-SHIFT-M]`
 - (macOS) `[CMD-SHIFT-M]`

 Or:

 - (Linux/Windows) `Edit` / `Preferences` / `Manage Plugins`
 - (macOS) `Binary Ninja` / `Preferences` / `Manage Plugins`

 Or:

 - (Linux/Windows) `[CTRL-P]` / `Plugin Manager` / `[ENTER]`
 - (macOS) `[CMD-P]` / `Plugin Manager` / `[ENTER]`

Note that some plugins may show `Force Install` instead of the normal `Install` button. If that's the case, it means the plugin does not specifically advertise support for your platform or version of python. Often times the plugin will still work, but you must override a warning to confirm installation and be aware that the plugin may not be compatible.

### Plugin Manager Searching

The plugin manager also supports a number of helpful search keywords to filter through the list of plugins as it continues to grow:

 - `@installed` to only show installed plugins
 - `@enabled` to only show enabled plugins
 - `@disabled` to show plugins that are installed but not enabled)

The following plugin categories are also searchable:

 - `@core`
 - `@ui`
 - `@architecture`
 - `@binaryview`
 - `@helper`

## Manual installation

You can manually install a plugin either by adding a folder which contains it (the plugin folder must contain an `__init__.py` at the top of the folder, or a python file can be included directly in the plugin folder--though this is not recommended).

Note, if manually cloning the [api repository](https://github.com/Vector35/binaryninja-api), make sure to:

``` text
git submodule update --init --recursive
```

after cloning or else the submodules will not actually be downloaded.

### Installing via the API

Binary Ninja now offers a [PluginManager API](https://api.binary.ninja/binaryninja.pluginmanager-module.html) which can simplify the process of finding and installing plugins. From the console:

``` text
>>> mgr = RepositoryManager()
>>> dir(mgr)
['__class__', '__delattr__', '__dict__', '__dir__', '__doc__', '__eq__', '__format__', '__ge__', '__getattribute__', '__getitem__', '__gt__', '__hash__', '__init__', '__init_subclass__', '__le__', '__lt__', '__module__', '__ne__', '__new__', '__reduce__', '__reduce_ex__', '__repr__', '__setattr__', '__sizeof__', '__str__', '__subclasshook__', '__weakref__', 'add_repository', 'check_for_updates', 'default_repository', 'handle', 'plugins', 'repositories']
>>> mgr.plugins
{'community': [<joshwatson_binaryninjamsp430 not-installed/disabled>, <Alex3434_BinjaSigMaker not-installed/disabled>, <toolCHAINZ_structor not-installed/disabled>, <Vascojofra_jumptablebrancheditor not-installed/disabled>, <zznop_bnida not-installed/disabled>, <zznop_bngenesis not-installed/disabled>, <zznop_bnkallsyms not-installed/disabled>, <zznop_binjago not-installed/disabled>, <zznop_bnrecursion not-installed/disabled>, <bkerler_annotate installed/enabled>, <verylazyguy_binaryninjavmndh not-installed/disabled>, <0x1F9F1_binjamsvc not-installed/disabled>, <fluxchief_binaryninja_avr not-installed/disabled>, <withzombies_bnilgraph installed/enabled>, <mechanicalnull_sourcery_pane not-installed/disabled>, <chame1eon_binaryninjafrida not-installed/disabled>, <Vascojofra_formatstringfinderbinja installed/enabled>, <shareef12_driveranalyzer not-installed/disabled>, <carstein_Syscaller not-installed/disabled>, <404d_peutils not-installed/disabled>, <ForAllSecure_bncov not-installed/disabled>, <ehntoo_binaryninjasvd not-installed/disabled>, <whitequark_binja_function_abi not-installed/disabled>, <bowline90_BinRida not-installed/disabled>, <wrigjl_binaryninjam68k not-installed/disabled>], 'official': [<Vector35_OpaquePredicatePatcher not-installed/disabled>, <Vector35_sample_plugin not-installed/disabled>]}
>>> mgr.plugins['community'][0].installed
False
>>> mgr.plugins['community'][0].installed = True
>>> mgr.plugins['community'][0].installed
True
>>> mgr.plugins['community'][0].enabled
False
>>> mgr.plugins['community'][0].enabled = True
>>> mgr.plugins['community'][0].enabled
>>> mgr.plugins['community'][0].enabled
True
```

Then just restart and your plugin will be loaded.

### Installing Prerequisites

Binary Ninja can now automatically install pip requirements for python plugins when the plugin was installed using the plugin manager. If the plugin author has included a `requirements.txt` file, the plugin manager will automatically install those dependencies.

Because Windows and macOS ship with an embedded version of Python, if you want to install plugins inside that Python, we recommend instead installing an official [python.org](https://www.python.org/downloads/windows/) (NOTE: ensure you do not accidentally install a 32-bit build) version, or a [homebrew](https://docs.brew.sh/Homebrew-and-Python) Python 3.x build.

Then you can adjust your [python.interpreter setting](settings.md#python.interpreter) to point to the appropriate install location. Note that the file being pointed to should be a `.dll` or `.dylib` though homebrew will often install libraries without any extension. For example:

```
$ file /usr/local/Cellar/python@3.8/3.8.5/Frameworks/Python.framework/Versions/3.8/Python
/usr/local/Cellar/python@3.8/3.8.5/Frameworks/Python.framework/Versions/3.8/Python: Mach-O 64-bit dynamically linked shared library x86_64
```

### Troubleshooting

Troubleshooting many Binary Ninja problems is enhanced by enabling debug logs and logging the output to a file. Just launch Binary Ninja with:

``` text
/Applications/Binary\ Ninja.app/Contents/macOS/binaryninja -d -l /tmp/bnlog.txt
```

And check `/tmp/bnlog.txt` when you're done.

Additionally, running a python plugin with an environment variable of `BN_DISABLE_USER_PLUGINS` will prevent the API from initializing user-plugins which is helpful for identifying when a plugin is causing problems. Furthermore, by setting `BN_USER_DIRECTORY` you can override your 'user' directory where all your settings and plugins are loaded.

## Writing Plugins

See the [developer documentation](../dev/) for documentation on creating plugins.
