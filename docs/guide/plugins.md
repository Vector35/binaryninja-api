# Plugins

Plugins really show off the power of Binary Ninja. This guide should help give you an overview of both using and writing plugins.

The most common Binary Ninja plugins are Python which we are covering here. That said, there are some C++ plugins which must be built for the appropriate native architecture and will usually include build instructions for each platform. Several [C++ examples] are included in the API repository. 

## Using Plugins

Plugins are loaded from the user's plugin folder: 

- OS X: `~/Library/Application Support/Binary Ninja/plugins/`
- Linux: `~/.binaryninja/plugins/`
- Windows: `%APPDATA%\Binary Ninja\plugins`

Note that plugins installed via the [PluginManager API] are installed in the `repositories` folder in the same path as the previous `plugin` folder listed above.  You should not need to manually touch anything in that folder, but should access them via the API instead. 

### Plugin Manager

![Plugin Manager >](../img/plugin-manager.png "Plugin Manager")

Plugins can now be installed directly via the GUI from Binary Ninja. You can launch the plugin manager via any of the following methods:

 - (Linux/Windows) `[CTRL-SHIFT-M]`
 - (MacOS) `[CMD-SHIFT-M]`

 Or:

 - (Linux/Windows) `Edit` / `Preferences` / `Manage Plugins`
 - (MacOS) `Binary Ninja` / `Preferences` / `Manage Plugins`

 Or:

 - (Linux/Windows) `[CTRL-P]` / `Plugin Manager` / `[ENTER]`
 - (MacOS) `[CMD-P]` / `Plugin Manager` / `[ENTER]`

Note that some plugins may show `Force Install` instead of the normal `Install` button. If that's the case, it means the plugin does not specifically advertise support for your platform or version of python. Often times the plugin will still work, but you must override a warning to confirm installation and be aware that the plugin may not be compatible. 

### Manual installation

You can manually install a plugin either by adding a folder which contains it (the plugin folder must contain an `__init__.py` at the top of the folder, or a python file can be included directly in the plugin folder though this is not recommended).

Note, if manually cloning the [api repository](https://github.com/Vector35/binaryninja-api), make sure to:

```
git submodule update --init --recursive
```

after cloning or else the submodules will not actually be downloaded. 

### Installing via the API

Binary Ninja now offers a [PluginManager API] which can simplify the process of finding and installing plugins. From the console:

```
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

Then just restart, and your plugin will be loaded.

### Installing Prerequisites

Because Windows ships with an embedded version of Python, if you want to install plugins inside that Python, you'll need to either adjust your `sys.path` to include the locations for the other libraries (making sure they're compatible with the built-in version), or else install them directly in the environment via:

```
import pip
pip.main(['install', '--quiet', 'packagename'])
```

_--quiet is required to minimize some of the normal output of pip that doesn't work within the context of our scripting console_

Binary Ninja can also switch to a different installed version of Python using the [python.interpreter setting].

### Troubleshooting

Troubleshooting many Binary Ninja problems is helped by enabling debug logs and logging the output to a file. Just launch Binary Ninja with 

```
/Applications/Binary\ Ninja.app/Contents/MacOS/binaryninja -d -l /tmp/bnlog.txt
```

And check `/tmp/bnlog.txt` when you're done. 

Additionally, running a python plugin with an environment variable of `BN_DISABLE_USER_PLUGINS` will prevent the API from initializing user-plugins which is helpful for root cause analysis.

## Writing Plugins

First, take a look at some of the [example] plugins, or some of the [community] plugins to get a feel for different APIs you might be interested in. Of course, the full [API] docs are online and available offline via the `Help`/`Open API Reference...`.

To start, we suggest you download the [sample plugin] as a template since it contains all of the elements you're likely to need.

- Begin by editing the `plugin.json` file 
- Next, update the `LICENSE`
- For small scripts, you can include all the code inside of `__init__.py`, though we recommend for most larger scripts that init just act as an initializer and call into functions organized appropriately in other files.

### Plugin Debugging Mode

Available via [settings], enabling plugin debugging mode will enable additional IL types via the UI.

### UI Elements

While it is possible to use Qt to directly create [UI enhancements] to Binary Ninja, we don't recommend it. First, there's a chance that we'll change UI platforms in the future (in particular because Qt's QWidget performance is actually getting worse with newer versions and they're trying to move everyone to QTQuick which might as well be Electron). Secondly, it is much more difficult for other users to install your plugin given the much more complicated dependencies and cross-platform headache of setup.

The officially supported mechanism (until the 1.2 release which will include much more featureful UI API enhancements) are available from the [interaction API] and shown off in the [angr] and [nampa] plugins.

### Testing

It's useful to be able to reload your plugin during testing. On the Commercial edition of Binary Ninja, this is easily accomplished with a stand-alone headless install using `import binaryninja` after [installing the API].  (install_api.py is included in every install in the installation folder)

For the Personal edition, we recommend simply commenting out the `register_` function normally used to register the plugin via whatever mechanism it uses and instead simply using the built-in Python console along with the python `reload` function to load new changes and test them by directly calling functions in the module. This work-around unfortunately is not supported for Binary View or Architecture plugins which unfortunately do require a restart to test if not running on Commercial. 

[PluginManager API]: https://api.binary.ninja/binaryninja.pluginmanager-module.html
[example]: https://github.com/Vector35/binaryninja-api/tree/dev/python/examples
[community]: https://github.com/Vector35/community-plugins
[C++ examples]: https://github.com/Vector35/binaryninja-api/tree/dev/examples
[API]: https://api.binary.ninja/
[sample plugin]: https://github.com/Vector35/sample_plugin
[UI enhancements]: https://github.com/NOPDev/BinjaDock
[interaction API]: https://api.binary.ninja/binaryninja.interaction-module.html
[angr]: https://github.com/Vector35/binaryninja-api/blob/dev/python/examples/angr_plugin.py
[nampa]: https://github.com/kenoph/nampa
[installing the API]: https://github.com/Vector35/binaryninja-api/blob/dev/scripts/install_api.py
[settings]: ../getting-started.html#ui.debugMode
[python.interpreter setting]: ../getting-started.html#python.interpreter
