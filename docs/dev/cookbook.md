# Cookbook

One of the best ways to learn a complicated API is to simply find the right example! First, here's a huge number of other sources of larger programs if you don't find what you're looking for in the below simple examples:

 - [Official Plugins](https://github.com/vector35/official-plugins): Official Plugins written and maintained by Vector 35
 - [Community Plugins](https://github.com/vector35/community-plugins): Over 100 plugins contributed by the Binary Ninja community
 - [Gist Collection](https://gist.github.com/psifertex/6fbc7532f536775194edd26290892ef7): Jordan's collection of python examples usually created for (or contributed by) customers
 - [Offline examples](https://github.com/Vector35/binaryninja-api/tree/dev/python/examples): These examples are especially useful because they're included in your offline install as well, just look in the examples/python subfolder wherever Binary Ninja installed

 That said, most of those examples tend to be more complex and so the following recipes are meant to be simple but useful building-blocks with which to learn useful techniques:

## Recipies

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
		# For bonus points, query the range analysis
```

### Search for a good nop-slide?

```python
bv.find_next_data(0, b"\x90" * 10)
```

### Change a function's type signature

Make sure to check out the much more in-depth [type guide](../guide/type.md#using-the-api) as well.

```python
current_function.function_type = Type.function(Type.void(), [])
```
