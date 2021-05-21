## Writing Plugins

First, take a look at some of the [example](https://github.com/Vector35/binaryninja-api/tree/dev/python/examples) plugins, or some of the [community](https://github.com/Vector35/community-plugins) plugins to get a feel for different APIs you might be interested in. Of course, the full [API](https://api.binary.ninja/) docs are online and available offline via the `Help`/`Open Python API Reference...`.

To start, we suggest you download the [sample plugin](https://github.com/Vector35/sample_plugin) as a template since it contains all of the elements you're likely to need.

- Begin by editing the `plugin.json` file
- Next, update the `LICENSE`
- For small scripts, you can include all the code inside of `__init__.py`, though we recommend for most larger scripts that init just act as an initializer and call into functions organized appropriately in other files.

## Plugin Debugging Mode

Available via [settings](../getting-started.md#ui.debugMode), enabling plugin debugging mode will enable additional IL types via the UI.

## UI Elements

There are several ways to create UI elements in Binary Ninja. The first is to use the simplified [interaction](https://api.binary.ninja/binaryninja.interaction-module.html) API which lets you make simple UI elements for use in GUI plugins in Binary Ninja. As an added bonus, they all have fallbacks that will work in headless console-based applications as well. Plugins that use these API include the [angr](https://github.com/Vector35/binaryninja-api/blob/dev/python/examples/angr_plugin.py) and [nampa](https://github.com/kenoph/nampa) plugins.

The second and more powerful (but more complicated) mechanism is to leverage the _binaryninjaui_ module. Additional documentation is forthcoming, but there are several examples ([1](https://github.com/Vector35/binaryninja-api/tree/dev/python/examples/kaitai), [2](https://github.com/Vector35/binaryninja-api/tree/dev/python/examples/snippets), [3](https://github.com/Vector35/binaryninja-api/tree/dev/python/examples/triage)), and most of the APIs are backed by the [documented C++ headers](https://api.binary.ninja/cpp). Additionally, the generated _binaryninjaui_ module is shipped with each build of binaryninja and the usual python `dir()` instructions are helpful for exploring its capabilities.

## Testing

It's useful to be able to reload your plugin during testing. On the Commercial edition of Binary Ninja, this is easily accomplished with a stand-alone headless install using `import binaryninja` after [installing the API](https://github.com/Vector35/binaryninja-api/blob/dev/scripts/install_api.py).  (install_api.py is included in each platforms respective [installation folder](../getting-started.md#binary-path))

For other plugins, we recommend the following workflow from the scripting console which enables easy iteration and testing:

```python
import pluginname
import importlib
importlib.reload(pluginname);pluginname.callbackmethod(bv)
```

Then just `[UP] [ENTER]` to trigger the reload when the plugin has changed.