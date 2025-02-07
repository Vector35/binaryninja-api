# Batch Processing and Other Automation Tips

An often asked question of Binary Ninja is "How do I enable batch-processing mode?". The answer is that we don't have one--but the good news is because it doesn't need it! We have an even better solution. BN is simply a library that is trivial to include in your own scripts for batch analysis. As long as you have a Commercial or Ultimate license (or a [headless](https://binary.ninja/purchase/#container:~:text=This%20works%20especially%20well%20with%20our,that%20are%20designed%20for%20headless%2Donly%20installs.) license), it's possible to invoke the core analysis library with all of its APIs without even launching the UI.

This document describes some general tips and tricks for effective batch processing. In particular, because Binary Ninja is multi-threaded, some methods for faster processing like [multiprocessing](https://docs.python.org/3/library/multiprocessing.html) can have dangerous consequences.

## Dedicated Python

While MacOS, Linux, and Windows all ship with python interpreters, those are only tested and intended for use within the scripting console. For headless automation, first install a dedicated python and using the steps in the next section to add the Binary Ninja libraries to the paths of that environment.

???+ Danger "Warning"
    Do NOT use the Python available in the Windows App Store as its sandbox protections prevent it from working with other libraries.

## Install the API

First, make sure to run the [install_api.py](https://github.com/Vector35/binaryninja-api/tree/dev/scripts) script. Note that the script is shipped with Binary Ninja already, just look in your [binary path](../guide/index.md#binary-path) inside of the `scripts` subfolder. Run it like:

```
python3 ~/binaryninja/scripts/install_api.py
```

Note
???+ Info "Tip"
    If you have multiple python copies installed, you'll want to make sure to specify the full path to the correct python when running as shown above.

This script adds appropriate `.pth` files so that your Python can find the Binary Ninja libraries.

## Our First Script

Let's try a simple example script (note that this script will work identically on macOS and Linux, but Windows users will want to adjust paths accordingly):

```python
#!/usr/bin/env python3
import binaryninja
with binaryninja.load("/bin/ls") as bv:
	print(f"Opening {bv.file.filename} which has {len(list(bv.functions))} functions")
```

If we run it, we'll see:

```
$ ./first.py
Opening /bin/ls which has 128 functions
```

Note that we used the `load` method which lets you temporarily create a `bv` with the appropriate scope. If you don't use the `with` syntax, you **MUST** close the BinaryView yourself when you are done with it. To do so, just:

```python
bv.file.close() #close the file handle or else leak memory
```

### Multiple files

Looks good! But what if we just want to parse basic headers or stop any major analysis from happening and scan multiple files quickly? We can use the `update_analysis` named parameter to prevent the usual linear sweep and recursive descent analysis from event occurring:

```python
#!/usr/bin/env python3
from binaryninja import load
from glob import glob
for bin in glob("/bin/*"):
	with load(bin, update_analysis=False) as bv:
		print(f"Opening {bv.file.filename} which has {len(list(bv.functions))} functions")
```

Now let's run it and notice it's fast enough to parse all of `/bin/*` in just a few seconds:

```
 $ ./glob.py
Opening /bin/cat which has 11 functions
Opening /bin/echo which has 2 functions
Opening /bin/launchctl which has 131 functions
...
Opening /bin/ls which has 50 functions
...
```

Notice that we have far fewer functions in `/bin/ls` this time. By shortcutting the analysis we've prevented further function identification but we've done so much more quickly.

### Single Function Analysis

A common workflow is to analyze a single (or small number) of functions in a particular binaries. This can be done using the analysis hold feature:

```python
from binaryninja import load
with load("/bin/ls", options={'analysis.initialAnalysisHold': True}) as bv:
    fn = bv.entry_function
    # Alternatively, use add_user_function at a particular address to first
    # create the function
    if fn:
        if fn.hlil_if_available:
            print("This will not fire because analysis hold has analyzed nothing so no HLIL exists.")
        if fn.hlil:
            print("This will work because HLIL is explicitly being requested via the API and will override the hold.")
```

### Running Plugins

Want to trigger another plugin via headless? As long as the other plugin is registered via a [PluginCommand](https://api.binary.ninja/binaryninja.plugin-module.html#binaryninja.plugin.PluginCommand), you can use something like:

```py
import binaryninja
bv = binaryninja.load("testfile")
ctx = binaryninja.PluginCommandContext(bv);
PluginCommand.get_valid_list(ctx)["BinExport"].execute(ctx)
# Creates a .BinExport file in the same folder as testfile
```

### Logging and Exceptions

By default, logging will follow whatever the setting is for [minimum log level](../guide/settings.md#python.log.minLevel) (`WarningLog` if not changed). However, for batch-process, it's often convenient to use the [`disable_default_log`](https://api.binary.ninja/index.html#binaryninja.disable_default_log) API to shut off logging entirely. Note that you may still need to handle python exceptions with a "try/except" pattern in the event of malformed files that do not process as expected.

### Further Customization

We can customize our analysis a lot more granularly than that though. In [`load`](https://api.binary.ninja/binaryninja.binaryview-module.html#binaryninja.load), notice the named `options` parameter, and the example code. Any setting you can set in the Binary Ninja "Open with Options" UI you can set through that parameter.

### On-Disk License

If manually installing a named license on Commercial, Ultimate, or Headless, make sure that your license file is copied to the [appropriate location](https://docs.binary.ninja/guide/index.html#user-folder) (`~/.binaryninja/license.dat` on Linux), or see the next section for an alternative.

If using a floating license, you can use the [example code](https://api.binary.ninja/binaryninja.enterprise-module.html#binaryninja.enterprise.LicenseCheckout) to check out a license on the fly.

### In-Memory License

For many applications it might be helpful to avoid having a license file on disk. Whether because the environment will be used to analyze malware, or because a docker image might be saved somewhere that the license file needs to be kept secret. (Note: this does not obfuscate the serial number as it can be extracted from memory or even via the API -- an informed attacker can still leak it and network isolation is recommended for analzying malicious applications)

To use this API, copy the contents of your license file into a string and pass it as an argument to [`core_set_license`](https://api.binary.ninja/#binaryninja.core_set_license)

## Parallelization

Of course, one of the main reasons you might want to build some automation so to spin up a number of threads to process multiple files. Be aware though, that Binary Ninja itself is multithreaded. In fact, if the bottle neck for your analysis script is BN itself, you're almost certainly better off not using any parallelization because the multithreading BN does on its own will provide more benefit than you'd gain by extra parallelization.

That said, there are certainly several good use cases where splitting your analysis makes sense. When processing many files for example, you might want to use multiple processes so that a single big slow file doesn't slow down the rest of the analysis as much. Or if you're working with potentially malformed files that may trigger bugs or crashes and you're worried about a single script failing.

### GNU Parallel

Another option is to use a tool like GNU parallel to simply launch multiple separate copies of the process itself.

### Multiprocessing

As mentioned above, Python's [Multiprocessing](https://docs.python.org/3/library/multiprocessing.html) library is NOT safe for use with multithreaded libraries. That said, you can use it with the following conditions:

- Make sure [to enable](https://docs.python.org/3/library/multiprocessing.html#contexts-and-start-methods) `spawn` or `forkserver` mode as the default `fork` method **WILL CRASH OR HANG**.
- Make sure to [set the thread-count](https://api.binary.ninja/binaryninja.mainthread-module.html#binaryninja.mainthread.set_worker_thread_count) appropriately. If you're going to spin up multiple processes, you don't want each process also spinning up CORE_COUNT - 1 threads (which is the default BN behavior). We recommend using a value of at least two.

Here's a short example showing how that might work:

```python
#!/usr/bin/env python3
import binaryninja
import glob
from multiprocessing import Pool, cpu_count, set_start_method

def spawn(filename):
    binaryninja.set_worker_thread_count(2)
    with binaryninja.load(filename, update_analysis=False) as bv:
        print(f"Binary {bv.file.filename} has {len(list(bv.functions))} functions.")

if __name__ == '__main__':
    set_start_method("spawn")
    processes = cpu_count()-1 if cpu_count() > 1 else 1
    pool = Pool(processes=processes)
    results = []
    for filename in glob.glob("/bin/*"):
        results.append(pool.apply_async(spawn, (filename,)))
    output = [result.get() for result in results]
```

Of course, if you do any timing tests you'll quickly notice that this script is actually much slower than the previous, simpler example!  Again, you probably only want to use some parallelization like this if the additional analysis you're doing on top of Binary Ninja is the bigger bottleneck in your analysis and thus you really want to split your analysis up across multiple processes.

## Disabling Plugins and Settings

Because the headless APIs will be using the same settings as the UI, you may wish to write batch-processing scripts that do NOT follow the same settings that you are using for interactive analysis. Likewise with wanting to not load additional plugins. You can disable loading of both of those by setting environment variables _before_ importing binaryninja like:

```python
import os
os.environ["BN_DISABLE_USER_SETTINGS"] = "True"
os.environ["BN_DISABLE_USER_PLUGINS"] = "True"
os.environ["BN_DISABLE_REPOSITORY_PLUGINS"] = "True"
import binaryninja
```

Other alternative solutions include setting the environment variable before running your script, or manually moving your settings file from your [user folder](../guide/index.md#user-folder) before running your automation.

