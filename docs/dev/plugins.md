# Writing Python Plugins

## Creating the Plugin

First, take a look at some of the [example](https://github.com/Vector35/binaryninja-api/tree/dev/python/examples) plugins, or some of the [community](https://github.com/Vector35/community-plugins) plugins to get a feel for different APIs you might be interested in. Of course, the full [API](https://api.binary.ninja/) docs are online and available offline via the `Help`/`Open Python API Reference...`.

To start, we suggest you download the [sample plugin](https://github.com/Vector35/sample_plugin) as a template since it contains all of the elements you're likely to need.

- Begin by editing the `plugin.json` file
- Next, update the `LICENSE`
- For small scripts, you can include all the code inside of `__init__.py`, though we recommend for most larger scripts that init just act as an initializer and call into functions organized appropriately in other files.
- If you have python dependencies, create a [requirements.txt](https://pip.pypa.io/en/latest/cli/pip_freeze/) listing any python dependencies.

## Submitting to the Plugin Manager

If your plugin was created as described above, there's only two steps to get it submitted to the plugin manager!

1. First, create a release either [manually](https://binary.ninja/2019/07/04/plugin-manager-2.0.html#5-create-a-release) or using our [release helper](https://github.com/Vector35/release_helper).
1. Next, just [file an issue](https://github.com/Vector35/community-plugins/issues/new/choose) letting us know about your plugin.

For future releases all you need to do is increment the version and create a new release.

## Using Your Own Plugin Repository

The simplest way to run your own plugin repository is to duplicate the structure of [https://github.com/vector35/community-plugins](https://github.com/vector35/community-plugins). Specifically, the [plugins.json](https://github.com/Vector35/community-plugins/blob/master/plugins.json), as [listing.json](https://github.com/Vector35/community-plugins/blob/master/listing.json) is used along with [generate_index.py](https://github.com/Vector35/community-plugins/blob/master/generate_index.py) to create that file.

Once you've created your test repository, use the `pluginManager.unofficialName` and `pluginManager.unofficialUrl` settings to add your third-party repository.

The [`add_repository`](https://api.binary.ninja/binaryninja.pluginmanager-module.html#binaryninja.pluginmanager.RepositoryManager.add_repository) API can also be used to add the repository, though it [may require manual creation of the repository folder](https://github.com/Vector35/binaryninja-api/issues/2987).
## Testing

It's useful to be able to reload your plugin during testing. On the Commercial edition of Binary Ninja, this is easily accomplished with a stand-alone headless install using `import binaryninja` after [installing the API](https://github.com/Vector35/binaryninja-api/blob/dev/scripts/install_api.py).  (install_api.py is included in each platforms respective [installation folder](../getting-started.md#binary-path))

For other plugins, we recommend the following workflow from the scripting console which enables easy iteration and testing:

```python
import pluginname
import importlib
importlib.reload(pluginname);pluginname.callbackmethod(bv)
```

Then just `[UP] [ENTER]` to trigger the reload when the plugin has changed.

## Debugging Python

If you wish to debug your python scripts, there are a few methods:

### Remote debugging with VSCode:

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
