# Using the Binary Ninja API

## Language Specific Bindings

The Binary Ninja API is available through a [Core API](#core-api), through the [C++ API](#c-api), through a [Python API](#python-api), and a [Rust API](#rust-api).


### Core API

The Core API is designed to only be used as a shim from other languages and is not currently intended to be used to build C plugins directly.

 - [Header](https://github.com/Vector35/binaryninja-api/blob/dev/binaryninjacore.h) (used by all other bindings)

### C++ API

The C++ API is what the Binary Ninja UI itself is built using so it's a robust and fully feature-complete interface to the core, however, it does not have the same level of detail in the documentation.

 - [C++ Header](https://github.com/Vector35/binaryninja-api/blob/dev/binaryninjaapi.h) (along with the rest of the [repository](https://github.com/Vector35/binaryninja-api))
 - [Build Instructions](https://github.com/Vector35/binaryninja-api#building)
 - [C++ / UI API Documentation](https://api.binary.ninja/cpp/)


### Python API

The most heavily documented of all of the APIs, the Python API serves as a useful documentation for the other APIs. Here's a list of the most important Python API documentation resources:

 - [Writing Python Plugins](plugins.md)
 - [Python API](https://api.binary.ninja/)
 - [API Source](https://github.com/Vector35/binaryninja-api/tree/dev/python)

### Rust API

The Rust API is still experimental and lacks complete coverage for all core APIs. Instructions on using are available in:

 - [Rust API](https://github.com/Vector35/binaryninja-api/tree/dev/rust)


## UI Elements

There are several ways to create UI elements in Binary Ninja. The first is to use the simplified [interaction](https://api.binary.ninja/binaryninja.interaction-module.html) API which lets you make simple UI elements for use in GUI plugins in Binary Ninja. As an added bonus, they all have fallbacks that will work in headless console-based applications as well. Plugins that use these API include the [angr](https://github.com/Vector35/binaryninja-api/blob/dev/python/examples/angr_plugin.py) and [nampa](https://github.com/kenoph/nampa) plugins.

The second and more powerful (but more complicated) mechanism is to leverage the _binaryninjaui_ module. Additional documentation is forthcoming, but there are several examples ([1](https://github.com/Vector35/binaryninja-api/tree/dev/python/examples/kaitai), [2](https://github.com/Vector35/binaryninja-api/tree/dev/python/examples/snippets), [3](https://github.com/Vector35/binaryninja-api/tree/dev/python/examples/triage)), and most of the APIs are backed by the [documented C++ headers](https://api.binary.ninja/cpp). Additionally, the generated _binaryninjaui_ module is shipped with each build of binaryninja and the usual python `dir()` instructions are helpful for exploring its capabilities.
