"""
Deobfuscates XOR/add/sub encoded strings, reading the decoder and its key from a type attribute.

WARNING: This example can seriously slow down analysis. `recognize_constant_pointer` reads the
binary a byte at a time from Python, and the recognizer callbacks run on every constant in every
function. `is_valid_for_type` keeps it off the hot path for types without one of our attributes,
but expect a noticeable slowdown on large binaries. If that matters, port it to C++; see the version
in `examples/encoded_strings`.

See https://docs.binary.ninja/dev/customstrings.html for details.
"""

from binaryninja import (StringRecognizer, CustomStringType, DataBuffer, DerivedString, DerivedStringLocation,
                         DerivedStringLocationType, PointerType, InstructionTextToken, InstructionTextTokenType)

encoded_string_type = CustomStringType.register("Encoded", "", "_enc")


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
        for name in self.__class__.decoders.keys():
            if name in type.target.attributes:
                return True
        return False

    def recognize_constant_pointer(self, instr, type, val):
        if not isinstance(type, PointerType):
            return None

        values = None
        decoder = None
        for name in self.__class__.decoders.keys():
            if name in type.target.attributes:
                try:
                    values = bytes.fromhex(type.target.attributes[name])
                    decoder = self.__class__.decoders[name]
                except Exception:
                    return None
        if values is None or decoder is None:
            return None

        encoded_null = "encoded_null" in type.target.attributes

        result = b""
        i = 0
        while True:
            byte = instr.function.view.read(val + i, 1)
            if len(byte) != 1:
                return False
            if not encoded_null and byte[0] == 0:
                break
            byte = decoder(byte[0], values[i % len(values)])
            if byte == 0:
                break
            result += bytes([byte])
            i += 1

        loc = DerivedStringLocation(DerivedStringLocationType.DataBackedStringLocation, val, i)
        return DerivedString(result, loc, encoded_string_type)


EncodedStringRecognizer().register()
