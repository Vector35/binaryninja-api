# This plugin renders 64-bit binary integer decimal floating point constants directly in the
# decompilation. See the sample binary at `cpp/examples/bid64_constant/sample_binary` for an
# example of a binary that uses this unusual format.

from binaryninja import (ConstantRenderer, InstructionTextToken, InstructionTextTokenType, IntegerType)
from decimal import Decimal


class Bid64ConstantRenderer(ConstantRenderer):
    renderer_name = "bid64_constant"

    def render_constant(self, instr, type, val, tokens, settings, precedence):
        # Typedefs have the final type, so make sure it is a 64 bit integer. The registered name
        # should be the typedef "BID_UINT64".
        if not isinstance(type, IntegerType):
            return False
        if type.width != 8:
            return False
        if type.registered_name is None or type.registered_name.name != 'BID_UINT64':
            return False

        sign = (val & (1 << 63)) != 0
        raw_exponent = (val >> 53) & 0x3ff
        if raw_exponent >= 0x300:
            # Don't try and render NaN or infinity
            return False

        bias = 398
        exponent = raw_exponent - bias
        magnitude = val & ((1 << 53) - 1)

        if magnitude == 0:
            exponent = 0

        value = Decimal(magnitude) * Decimal(10.0) ** Decimal(exponent)
        if sign:
            value = -value
        tokens.append(InstructionTextToken(InstructionTextTokenType.FloatingPointToken, str(value) + "_bid"))
        return True


Bid64ConstantRenderer().register()
