# Batch Processing and Other Automation Tips

An often asked question of Binary Ninja is "How do I enable batch-processing mode?". The answer is that we don't have one--but the good news is because it doesn't need it! We have an even better solution. BN is simply a library that is trivial to include in your own scripts for batch analysis. As long as you have a Commercial license (or a [headless](https://binary.ninja/purchase/#container:~:text=This%20works%20especially%20well%20with%20our,that%20are%20designed%20for%20headless%2Donly%20installs.) license), it's possible to invoke the core analysis library with all of its APIs without even launching the UI. 

This document describes some general tips and tricks for effective batch processing. In particular, because Binary Ninja is multi-threaded, some methods for faster processing like [multiprocessing](https://docs.python.org/3/library/multiprocessing.html) can have dangerous consequences.

## Install the API

First, make sure to run the [install_api.py](https://github.com/Vector35/binaryninja-api/tree/dev/scripts) script. Note that the script is shipped with Binary Ninja already, just look in your [binary path](../getting-started.md#binary-path) inside of the `scripts` subfolder. Run it like:

```
python3 ~/binaryninja/scripts/install_api.py
```

This script adds appropriate `.pth` files so that your Python can find the Binary Ninja libraries. 

## Our First Script

Let's try a simple example script (note that this script will work identically on MacOS and Linux, but Windows users will want to adjust paths accordingly):

```python
#!/usr/bin/env python3
import binaryninja
with binaryninja.open_view("/bin/ls") as bv:
	print(f"Opening {bv.file.filename} which has {len(bv.functions)} functions")
```

If we run it, we'll see:

```
$ ./first.py
Opening /bin/ls which has 128 functions
```

Note that we used the `open_view` method which lets you temporarily create a `bv` with the appropriate scope. The traditional way to do that was with `BinaryViewType.get_view_of_file` which returns a [BinaryView](https://api.binary.ninja/binaryninja.binaryview.BinaryView.html#binaryninja.binaryview.BinaryView) directly. Note however, that if you use that method you **MUST** close the BinaryView yourself when you are done with it. To do so, just:

```python
bv.file.close() #close the file handle or else leak memory
```

### Multiple files 

Looks good! But what if we just want to parse basic headers or stop any major analysis from happening and scan multiple files quickly? We can use the `update_analysis` named parameter to prevent the usual linear sweep and recursive descent analysis from event occurring:

```python
#!/usr/bin/env python3
from binaryninja import open_view
from glob import glob
for bin in glob("/bin/*"):
	with open_view(bin, update_analysis=False) as bv:
		print(f"Opening {bv.file.filename} which has {len(bv.functions)} functions")
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

### Further Customization

We can customize our analysis a lot more granularly than that though. `open_view` is actually a wrapper around [`get_view_of_file_with_options`](https://api.binary.ninja/binaryninja.binaryview-module.html#binaryninja.binaryview.BinaryViewType.get_view_of_file_with_options). Notice the named `options` parameter, and the example code. Any setting you can set in the Binary Ninja "Open with Options" UI you can set through that parameter.

## Parallelization

Of course, one of the main reasons you might want to build some automation so to spin up a number of threads to process multiple files. Be aware though, that Binary Ninja itself is multithreaded. In fact, if the bottle neck for your analysis script is BN itself, you're almost certainly better off not using any parallelization because the multithreading BN does on its own will provide more benefit than you'd gain by extra parallelization. 

That said, there are certainly several good use cases where splitting your analysis makes sense. When processing many files for example, you might want to use multiple processes so that a single big slow file doesn't slow down the rest of the analysis as much. Or if you're working with potentially malformed files that may trigger bugs or crashes and you're worried about a single script failing.

### GNU Parallel

TODO

### Multiprocessing

As mentioned above, Python's [Multiprocessing](https://docs.python.org/3/library/multiprocessing.html) library is NOT safe for use with multithreaded libraries. That said, you can use it with the following conditions:

- Make sure [to enable](https://docs.python.org/3/library/multiprocessing.html#contexts-and-start-methods) `spawn` or `forkserver` mode as the default `fork` method **WILL CRASH OR HANG**.
- Make sure to [set the thread-count](https://api.binary.ninja/binaryninja.mainthread-module.html#binaryninja.mainthread.set_worker_thread_count) appropriately. If you're going to spin up multiple processes, you don't want each process also spinning up CORE_COUNT - 1 threads (which is the default BN behavior)

Here's a short example showing how that might work:

```python
#!/usr/bin/env python3
import binaryninja
import glob
from multiprocessing import Pool, cpu_count, set_start_method

def spawn(filename):
    binaryninja.set_worker_thread_count(1)
    with binaryninja.open_view(filename, update_analysis=False) as bv:
        print(f"Binary {bv.file.filename} has {len(bv.functions)} functions.")

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
import binaryninja
```

Other alternative solutions include setting the environment variable before running your script, or manually moving your settings file from your [user folder](../getting-started.md#user-folder) before running your automation.

## Other Languages

TODO

First, make sure to run the [install_api.py](https://github.com/Vector35/binaryninja-api/tree/dev/scripts) script. Note that the script is shipped with Binary Ninja already, just look in your [binary path](../getting-started.md#binary-path) inside of the `scripts` subfolder. Run it like: