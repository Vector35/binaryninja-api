# Cookbook

One of the best ways to learn a complicated API is to simply find the right example! First, here's a huge number of other sources of larger programs if you don't find what you're looking for in the below simple examples:

 - [Official Plugins](https://github.com/vector35/official-plugins): Official Plugins written and maintained by Vector 35
 - [Community Plugins](https://github.com/vector35/community-plugins): Over 100 plugins contributed by the Binary Ninja community
 - [Gist Collection](https://gist.github.com/psifertex/6fbc7532f536775194edd26290892ef7): Jordan's collection of python examples usually created for (or contributed by) customers
 - [Offline examples](https://github.com/Vector35/binaryninja-api/tree/dev/python/examples): These examples are especially useful because they're included in your offline install as well, just look in the examples/python subfolder wherever Binary Ninja installed

 That said, most of those examples tend to be more complex and so the following recipes are meant to be simple but useful building-blocks with which to learn useful techniques:

## Recipes

### Accessing cross references

This recipe is useful for iterating over all of the HLIL cross-references of a given interesting function:

```python
for ref in current_function.caller_sites:
	print(ref.hlil)
```

But what if you don't have that function yet?

### Getting a function by name

```python
bv.get_functions_by_name('_start')
```

### Finding the function with the most bytes

```python
max(bv.functions, key=lambda x: x.total_bytes)
```

### Finding the most "connected" function

As defined by having the highest sum of incoming and outgoing calls. Adjust accordingly.

```python
max(bv.functions, key=lambda x: len(x.callers + x.callees))
```

### Querying possible values of a function parameter

Is that memcpy length a bit too big?

```python
for ref in current_function.caller_sites:
	if isinstance(ref.hlil, Call) and len(ref.hlil.params) >= 3:
		print(ref.hlil.params[2])
		# For bonus points, query the range analysis using .possible_values
```

### Search for a good nop-slide?

```python
bv.find_next_data(0, b"\x90" * 10)
```

### Change a function's type signature

Make sure to check out the much more in-depth [applying annotations](annotation.md) as well.

```python
current_function.type = Type.function(Type.void(), [])
```

### Find a variable's definition and all uses using SSA

```python
>>> print(current_il_instruction)
x0_2 = 0x100007750(x0_1)
>>> findMe = current_il_instruction.params[0]
>>> findMe.ssa_form.function.get_ssa_var_definition(findMe.ssa_form.src)
<mlil: x0_1#5 = ϕ(x0_1#1, x0_1#2, x0_1#4)>
>>> findMe.ssa_form.function.get_ssa_var_uses(findMe.ssa_form.src)
[<mlil: x0_2#6, mem#3 = 0x100007750(x0_1#5) @ mem#2>]
```

If the result is a PHI, you'll want to either recursively search each version as well, or (more likely) use a queue to process all parameters until you find the source which could be an argument, global variable, immediate, or some other transformed data (which would require handling more types of IL instructions such as math operations, etc):

```python
>>> findMe.ssa_form.function.get_ssa_var_definition(findMe.ssa_form.src).src
[<ssa x0_1 version 1>, <ssa x0_1 version 2>, <ssa x0_1 version 4>]
>>> findMe2 = findMe.ssa_form.function.get_ssa_var_definition(findMe.ssa_form.src).src[0]
>>> current_il_function.get_ssa_var_definition(findMe2)
<mlil: x0_1#1 = "%*lld ">
```

Note, don't forget the difference between an MLIL Variable Instruction and the actual variable itself (use .src to get the later from the former)

```python
>>> findMe.ssa_form
<mlil: x0#3>
>>> findMe.ssa_form.src
<ssa x0 version 3>
>>> type(findMe.ssa_form.src)
<class 'binaryninja.mediumlevelil.SSAVariable'>
>>> type(findMe.ssa_form)
<class 'binaryninja.mediumlevelil.MediumLevelILVarSsa'>
```

### Apply a hotkey to a register_ plugin

There are basically two plugin systems in Binary Ninja. The first and simplest is the [PluginCommand](https://api.binary.ninja/binaryninja.plugin-module.html#binaryninja.plugin.PluginCommand) type. These plugins are very easy to register and are fairly separate from the QT code that powers the UI. Conversely, UIActions can have much more power over the interface. Unfortunately, not only are they not documented in the Python API (instead you have to poke into the [C++ docs](https://api.binary.ninja/cpp/group__action.html#struct_u_i_action)), but they also require a bit more work to get up and running. Here's a simple example showing how to convert a simple `register_for_range` plugin that just logs the selected address and size to one that is triggered via hotkey as a UIAction:

```python
from binaryninja import log_info, PluginCommand, mainthread
from binaryninjaui import UIAction, UIActionHandler, Menu
from PySide6.QtGui import QKeySequence

def old_range_action(bv, start, length):
    log_info(f"{bv} {start} {length}")

PluginCommand.register_for_range("Old Range Action", "Old Range Action", old_range_action)

def new_range_action_with_hotkey(ctx):
    bv = ctx.binaryView
    start = ctx.address
    length = ctx.length
    log_info(f"{bv} {start} {length}")

UIAction.registerAction("Trigger Range", QKeySequence("F3"))
UIActionHandler.globalActions().bindAction("Trigger Range", UIAction(new_range_action_with_hotkey))

# Unlike the PluginCommand above, you must manually add a UIAction to menus including the right-click menu and plugin menu:

Menu.mainMenu("Plugins").addAction("Trigger Range", "Plugins")
```
