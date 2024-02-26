# Cookbook

One of the best ways to learn a complicated API is to simply find the right example! First, here's a huge number of other sources of larger programs if you don't find what you're looking for in the below simple examples:

 - [Official Plugins](https://github.com/vector35/official-plugins): Official Plugins written and maintained by Vector 35
 - [Community Plugins](https://github.com/vector35/community-plugins): Over 100 plugins contributed by the Binary Ninja community
 - [Gist Collection](https://gist.github.com/psifertex/6fbc7532f536775194edd26290892ef7): Jordan's collection of python examples usually created for (or contributed by) customers
 - [Offline examples](https://github.com/Vector35/binaryninja-api/tree/dev/python/examples): These examples are especially useful because they're included in your offline install as well, just look in the examples/python subfolder wherever Binary Ninja installed

 That said, most of those examples tend to be more complex and so the following recipes are meant to be simple but useful building-blocks with which to learn useful techniques. Many of them also make use of the built-in Python console's [magic variables](../guide/index.md#magic-console-variables):

## Recipes

### Getting all functions in a binary

```python
for func in bv.functions:
  print(func.name)
  print(func.start)
  print(func.parameter_vars)
  print(func.function_type)
```

### Getting a specific function

```python
func = bv.get_functions_by_name(here)[0]  # Multiple functions can share the same name!
func = bv.get_function_at(here)      # Shortcut for the next one
func = bv.get_functions_at(here)[0]  # Binary Ninja support functions that overlap!
func = bv.get_function_containing(here)  # Functions that contain the given address
# Just a note that using address to work with functions is fine
# But when working with ILs, addresses are approximate and can change for any given instruction
```

### All forms of a function

```python
for func in bv.functions:
  low_level_il        = func.llil
  low_level_il_ssa    = func.llil.ssa_form

  medium_level_il     = func.mlil
  medium_level_il_ssa = func.mlil.ssa_form

  # Decompilation:
  high_level_il       = func.hlil
  high_level_il_ssa   = func.hlil.ssa_form

  base_function       = <any>_level_il.source_function # Some helpers are only on the base function object!
```

### All decompiled instructions in a binary

```python
for func in bv.functions:
  for inst in func.hlil.instructions:
    print(f"{inst.address} : {inst}")
```

or

```python
for func in bv.functions:
  for bb in func.hlil:
    for inst in bb:
      print(f"{inst.address} : {inst}")
```

or

```python
for inst in bv.hlil_instructions:
  print(f"{inst.address} : {inst}")
```

### Getting the decompiled instruction at an address

```python
func = bv.get_functions_containing(here)[0]  # You should probably be more robust than this
llil_inst = func.get_llil_at(here)  # LLIL have the "closest" mapping to actual addresses, but you should still consider this volatile/fuzzy
hlil_inst = llil_inst.hlil          # This is also very approximate

# What's "more correct" walking down instead:
hlil_inst.mlil   # Approximate "direct" mapping down
hlil_inst.mlils  # All mlil instructions that contributed to this hlil instruction - most correct!
hlil_inst.llil   # Approximate "direct" mapping down
hlil_inst.llils  # All llil instructions that contributed to this hlil instruction - most correct!
# Be careful when working with address and mappings! We try to make them work as well as possible
# (and in most cases using the direct mapping is _fine_)
# But you should always be aware that they are approximate and can change!
```


### All callers of a function

```python
current_function.callers
```

### All locations where a function is called

```python
for site in current_function.caller_sites:
  addr = site.address
  inst = site.hlil
```

### All calls and call instructions in a function:

```python
for site in current_function.call_sites:
  addr = site.address
  inst = site.hlil
```

### Finding the most "connected" function

As defined by having the highest sum of incoming and outgoing calls. Adjust accordingly.

```python
max(bv.functions, key=lambda x: len(x.callers + x.callees))
```

### Finding the largest function (by most bytes)

```python
max(bv.functions, key=lambda x: x.total_bytes)
```

### Querying possible values of a function parameter

Is that memcpy length a bit too big?

```python
for ref in current_function.caller_sites:
	if isinstance(ref.hlil, Call) and len(ref.hlil.params) >= 3:
		print(ref.hlil.params[2])
		# For bonus points, query the range analysis using .possible_values
```

### Search for a good nop-slide

```python
bv.find_next_data(0, b"\x90" * 10)
```

### Change a function's type signature

Make sure to check out the much more in-depth [applying annotations](annotation.md) as well.

```python
current_function.type = Type.function(Type.void(), [])
```

### Accessing cross references

This recipe is useful for iterating over all of the HLIL cross-references of a given interesting function:

```python
for ref in current_function.caller_sites:
	print(ref.hlil)
```

### Common variable APIs

```python
for func in bv.functions:
  all_vars          = func.vars               # This isn't the most meaningful thing to do, because....
  hlil_vars         = func.hlil.vars          # ...you probably only want the variables used in the IL you're looking at
  hlil_aliased_vars = func.hlil.aliased_vars  # ...but don't forget about aliased variables!
  parameter_vars    = func.parameter_vars     # ...or parameter variables!

  var = hlil_vars[0]
  if var.source_type == StackVariableSourceType:
    print(var.storage)  # var.storage is the variables stack offset, but ONLY IF the source type is `StackVariableSourceType`

    # There are many ways to *estimate* the size of a variable on the stack
    print(var.offset_to_next_variable)  # Distance to the next variable that Binary Ninja has identified on the stack
    print(abs(var.storage))  # Absolute maximum size the variable can be until it overwrites the saved return pointer!
    print(abs(var.type.width))  # If Binary Ninja gave the variable a type, or you manually applied a type, then you can get the size from that type

  # SSA
  hlil_ssa_vars = func.hlil.ssa_vars                                           # You can also get ssa variables
  def_inst      = func.hlil.ssa_form.get_ssa_variable_definition(ssa_vars[0])  # But if you want definitions, you need to use the ssa form
  use_insts     = func.hlil.ssa_form.get_ssa_variable_uses(ssa_vars[0])        # There's only ever one ssa definition, but potentially many uses
```

### Working with Tags

```python
# Data tags
bv.add_tag(here, "Crashes", "Description")

# Function tags
current_function.add_tag("Important", "Look at this later!")

# Function address tags
current_function.add_tag("Bug", "I think there's an overflow here?", here)
```

### Logging

```python
log.log_debug("Debug logs are hidden by default")
log.log_info("Info logs are displayed in the console")
log.log_warn("Warning logs will print in yellow text")
log.log_error("Errors are red!")
log.log_alert("This pops up a dialogue box!")

log.log_error("You can add your own filter group easily to any of these APIs", "My Log Group")
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
