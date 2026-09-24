# Pseudo C representation transfers

`BIT_CAST(type, value)` copies an expression's representation into an equally
sized type. Pseudo C uses it when a 32- or 64-bit floating value and an integer
exchange bits, such as `FMOV` or a source-level `memcpy`. Numeric conversions
continue to use ordinary casts.

```c
#include <stdint.h>
#include "pseudoc_helpers.h"

uint64_t double_bits(double value)
{
    return BIT_CAST(uint64_t, value);
}
```

The helper supports GCC and Clang C. It evaluates `value` once, checks that the
sizes match, and uses `memcpy` without violating aliasing rules. The copy
preserves signed zero and NaN payloads. A caller can supply its own `BIT_CAST`
definition before including the header.
