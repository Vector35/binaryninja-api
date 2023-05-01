# Using the Binary Ninja API

Welcome to the Binary Ninja API documentation. Much like the [User Manual](../guide/index.md), some larger sections have been split off into their own sections on the left, while the table of contents for this documentation is on the right.

## Language Specific Bindings

The Binary Ninja API is available through a [Core API](#core-api), through the [C++ API](#c-api), through a [Python API](#python-api), and a [Rust API](#rust-api).

### Python API

The Python API is the most common third-party API and is used in many [public plugins](https://github.com/vector35/community-plugins). Here's a list of the most important Python API documentation resources:

 - [Writing Python Plugins](plugins.md)
 - [Applying Annotations](annotation.md)
 - [Script Cookbook](cookbook.md) with common examples and concepts explained
 - [Python API Reference](https://api.binary.ninja/) (available offline via the Help menu)
 - [API Source](https://github.com/Vector35/binaryninja-api/tree/dev/python)

### Core API

The Core API is designed to only be used as a shim from other languages and is not currently intended to be used to build C plugins directly.

 - [Header](https://github.com/Vector35/binaryninja-api/blob/dev/binaryninjacore.h) (used by all other bindings)

### C++ API

The C++ API is what the Binary Ninja UI itself is built using so it's a robust and fully feature-complete interface to the core, however, it does not have the same level of detail in the documentation.

 - [C++ Header](https://github.com/Vector35/binaryninja-api/blob/dev/binaryninjaapi.h) (along with the rest of the [repository](https://github.com/Vector35/binaryninja-api))
 - [Build Instructions](https://github.com/Vector35/binaryninja-api#building)
 - [C++ / UI API Documentation](https://api.binary.ninja/cpp/)

### Rust API

The Rust API is still experimental and lacks complete coverage for all core APIs. Documentation is available at:

 - [Rust API](https://github.com/Vector35/binaryninja-api/tree/dev/rust)

