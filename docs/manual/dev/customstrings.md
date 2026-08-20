# Custom Strings and Constants

A [StringRecognizer](https://api.binary.ninja/binaryninja.stringrecognizer-module.html#binaryninja.stringrecognizer.StringRecognizer) decodes strings from HLIL expressions and returns them as a [DerivedString](https://api.binary.ninja/binaryninja.binaryview-module.html#binaryninja.binaryview.DerivedString). The decoded value need not exist in the binary. Derived strings render inline in decompilation, appear in the strings list, and support cross references. Use this for obfuscated strings, length-prefixed or fat-pointer string types, and stack strings.

A [ConstantRenderer](https://api.binary.ninja/binaryninja.constantrenderer-module.html#binaryninja.constantrenderer.ConstantRenderer) does the same for non-string constants, emitting tokens directly instead of returning a value.

Both receive the type of the expression, so [custom type attributes](../guide/types/attributes.md#custom-attributes) can select which expressions they apply to and carry parameters such as a decoding key.

!!! Tip "Tip"
    For strings stored literally but in a non-ASCII encoding (cp932, GBK, EUC-KR), enable the appropriate code pages instead. See [Unicode Support](concepts.md#unicode-support).

## Custom String Types

A [CustomStringType](https://api.binary.ninja/binaryninja.stringrecognizer-module.html#binaryninja.stringrecognizer.CustomStringType) is the registered name for a kind of string, along with the prefix and postfix used to render it. The name appears in the strings list type column.

```python
from binaryninja import CustomStringType

rust_str_type = CustomStringType.register("Rust &str", string_prefix="rs")  # rs"hello"
encoded_string_type = CustomStringType.register("Encoded", "", "_enc")      # "hello"_enc
```

## Derived Strings

A [DerivedString](https://api.binary.ninja/binaryninja.binaryview-module.html#binaryninja.binaryview.DerivedString) holds:

* `value` — the decoded bytes
* `location` — optional [DerivedStringLocation](https://api.binary.ninja/binaryninja.binaryview-module.html#binaryninja.binaryview.DerivedStringLocation), either `DataBackedStringLocation` (a range in the binary) or `CodeStringLocation` (assembled by code). Required for cross references.
* `custom_type` — the `CustomStringType` used to render it

```python
loc = DerivedStringLocation(DerivedStringLocationType.DataBackedStringLocation, addr, length)
DerivedString(b"decoded text", loc, encoded_string_type)
```

All derived strings in a view are available through `bv.derived_strings`, and their uses through `bv.get_derived_string_code_refs(str)`.

## String Recognizers

Subclass [StringRecognizer](https://api.binary.ninja/binaryninja.stringrecognizer-module.html#binaryninja.stringrecognizer.StringRecognizer), set `recognizer_name`, override the callbacks you need, and call `register()` on an instance. Each returns a `DerivedString`, or `None` to pass.

| Method | Called for |
| --- | --- |
| `recognize_constant` | A constant that is not a pointer |
| `recognize_constant_pointer` | A constant pointer |
| `recognize_extern_pointer` | An external symbol, with an offset into it |
| `recognize_import` | An imported symbol |
| `recognize_constant_data` | `HLIL_CONST_DATA`, produced by [outlining](outlining.md) from scattered stores |
| `recognize_struct_init` | `HLIL_STRUCT_INIT`, a run of constant field assignments folded into one initializer |

`is_valid_for_type` is an optional filter. Override it to skip the recognizer for types that cannot match; the callbacks otherwise run on every constant in every function.

!!! Warning "Warning"
    Python string recognizers can be slow. The callbacks run on every constant in every function, and each call crosses the FFI boundary, builds wrapper objects, and takes the GIL, serializing analysis threads. Always override `is_valid_for_type` to reject types you don't handle — it is the cheapest way to stay off the hot path. For large binaries or recognizers that must inspect many expressions, write it in [C++](#c-api) instead.

String recognizers only run on code. To render matching data variables, register a [DataRenderer](https://api.binary.ninja/binaryninja.datarender-module.html#binaryninja.datarender.DataRenderer) alongside the recognizer. [rust_string.py](https://github.com/Vector35/binaryninja-api/blob/dev/python/examples/rust_string.py) does this for Rust `&str` slices, recovering them from both struct initializers and data variables.

### Example: Attribute-Driven Deobfuscation

[encoded_strings.py](https://github.com/Vector35/binaryninja-api/blob/dev/python/examples/encoded_strings.py) reads both the decoder and its key out of a type attribute:

```python
class EncodedStringRecognizer(StringRecognizer):
    recognizer_name = "encoded_strings"
    decoders = {
        "xor_encoded": lambda encoded, key: encoded ^ key,
        "sub_encoded": lambda encoded, key: (encoded - key) & 0xff,
        "add_encoded": lambda encoded, key: (encoded + key) & 0xff
    }

    def is_valid_for_type(self, func, type):
        if not isinstance(type, PointerType):
            return False
        return any(name in type.target.attributes for name in self.__class__.decoders)

    def recognize_constant_pointer(self, instr, type, val):
        ...  # decode using the hex key in the attribute
        loc = DerivedStringLocation(DerivedStringLocationType.DataBackedStringLocation, val, i)
        return DerivedString(result, loc, encoded_string_type)


EncodedStringRecognizer().register()
```

Declare a type carrying the key and apply it to the decoding routine's parameter. Type propagation carries it to every call site:

```C
typedef char __attr("sub_encoded", "31656537366531313932396130373434")* deobfuscate;
```

The [5.2 release notes](https://binary.ninja/2025/11/13/binary-ninja-5.2-io.html#custom-strings--constants) work through this on an Amadey sample.

!!! Warning "Warning"
    This example in particular can seriously slow down analysis: it reads the binary one byte at a time from Python for each string it decodes. It is written for clarity, not speed.

## Constant Renderers

Subclass [ConstantRenderer](https://api.binary.ninja/binaryninja.constantrenderer-module.html#binaryninja.constantrenderer.ConstantRenderer), set `renderer_name`, and call `register()`. Callbacks emit to the `tokens` emitter and return `True` if they handled the constant.

| Method | Called for |
| --- | --- |
| `render_constant` | A constant that is not a pointer |
| `render_constant_pointer` | A constant pointer |
| `is_valid_for_type` | Optional filter, as with string recognizers |

The same performance warning applies: constant renderers run while rendering every constant, so filter aggressively in `is_valid_for_type` and use [C++](#c-api) for anything expensive.

[bid64_constant.py](https://github.com/Vector35/binaryninja-api/blob/dev/python/examples/bid64_constant.py) renders BID64 decimal floating point constants, keying off the `BID_UINT64` typedef name:

```python
class Bid64ConstantRenderer(ConstantRenderer):
    renderer_name = "bid64_constant"

    def render_constant(self, instr, type, val, tokens, settings, precedence):
        if not isinstance(type, IntegerType) or type.width != 8:
            return False
        if type.registered_name is None or type.registered_name.name != 'BID_UINT64':
            return False
        ...  # decode into `value`
        tokens.append(InstructionTextToken(InstructionTextTokenType.FloatingPointToken, str(value) + "_bid"))
        return True


Bid64ConstantRenderer().register()
```

This also covers constants that stand in for strings absent from the binary, such as precomputed API hashes.

## C++ API

`BinaryNinja::StringRecognizer`, `BinaryNinja::ConstantRenderer`, `BinaryNinja::CustomStringType::Register`, and the `DerivedString` / `DerivedStringLocation` structures mirror the Python API. Recognizer callbacks return `std::optional<DerivedString>`. This avoids the per-expression FFI and GIL costs entirely, and is the recommended approach for anything running over a large binary.

## Examples

* [encoded_strings.py](https://github.com/Vector35/binaryninja-api/blob/dev/python/examples/encoded_strings.py) — attribute-driven XOR/add/sub string deobfuscation
* [rust_string.py](https://github.com/Vector35/binaryninja-api/blob/dev/python/examples/rust_string.py) — Rust `&str` recognizer plus a matching data renderer
* [bid64_constant.py](https://github.com/Vector35/binaryninja-api/blob/dev/python/examples/bid64_constant.py) — BID64 constant renderer
* [cpp/examples/encoded_strings](https://github.com/Vector35/binaryninja-api/tree/dev/cpp/examples/encoded_strings) — C++ port of `encoded_strings.py`
* [cpp/examples/bid64_constant](https://github.com/Vector35/binaryninja-api/tree/dev/cpp/examples/bid64_constant) — C++ port of `bid64_constant.py`, with a sample binary
