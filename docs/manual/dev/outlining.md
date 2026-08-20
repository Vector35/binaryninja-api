# Outlining

## Overview

Outlining improves decompilation quality by recognizing patterns of low-level memory operations and transforming them into semantically equivalent high-level function calls. This feature automatically converts sequences of individual memory operations into cleaner, more readable calls to standard library functions like `memcpy`, `memset`, and `strcpy`.

## How It Works

Outlining operates during the translation from Medium Level IL (MLIL) to High Level IL (HLIL). The system identifies patterns of related memory operations and replaces them with appropriate builtin function calls.

**Pattern Recognition**: Binary Ninja analyzes sequences of memory operations, tracking data flow and identifying common algorithms even when operations appear out of order or are interleaved with unrelated code.

**Transformation**: Recognized patterns are replaced with calls to synthetic builtin functions that provide cleaner, more semantic representations of the original operations.

## Enabling Outlining

### Settings

- **`analysis.outlining.builtins`**: Enable outlining of constant expression compiler emitted builtins (default: true)

### Controlling Outlining

The `analysis.outlining.builtins` setting controls outlining behavior and can be configured at multiple scopes:

- **User/Project Scope**: Apply outlining preferences globally across all files or within a project
- **Resource Scope (BinaryView)**: Configure outlining for an entire binary
- **Resource Scope (Function)**: Control outlining for individual functions

**Per-Function Control**: Use the Quick Settings menu (right-click in any function view → Quick Settings) to quickly toggle outlining for specific functions. Add `analysis.outlining.builtins` to Quick Settings via the Settings UI for easy access.

For programmatic control, use the [Settings API](https://api.binary.ninja/binaryninja.settings-module.html). For more information on settings scopes and configuration, see the [Settings documentation](../guide/settings.md).

## Supported Builtin Functions

Binary Ninja currently supports outlining for the following memory and string operations:

| Builtin Function | Category | Status | Description |
|------------------|----------|--------|-------------|
| `__builtin_memcpy` | Memory | ✓ Supported | Standard memory copy operations |
| `__builtin_memmove` | Memory | ✓ Supported | Copy operations with overlap handling |
| `__builtin_memset` | Memory | ✓ Supported | Fill memory with a specific byte value |
| `__builtin_strcpy` | String | ✓ Supported | Null-terminated string copy |
| `__builtin_strncpy` | String | ✓ Supported | Length-limited string copy |
| `__builtin_wcscpy` | Wide Char | ✓ Supported | Wide character string copy (null-terminated) |
| `__builtin_wcsncpy` | Wide Char | ✓ Supported | Length-limited wide character copy |
| `__builtin_wmemcpy` | Wide Char | ✓ Supported | Wide character memory copy (with trailing data) |
| `__builtin_strcat` | String | ⚠ Future | String concatenation (in development) |
| `__builtin_strncat` | String | ⚠ Future | Length-limited string concatenation |
| `__builtin_strlen` | String | ⚠ Future | String length calculation |
| `__builtin_memcmp` | Memory | ⚠ Future | Memory comparison |
| _Others..._ | — | 💡 Request | Have a function you'd like to see? [Let us know!](https://github.com/Vector35/binaryninja-api/issues) |

**Note**: Functions marked as "Future" are planned or in development but not yet available in production releases.

### Architecture-Specific Intrinsics

Binary Ninja architecture plugins can map specialized instructions directly to well-known intrinsic names that the outliner recognizes. This enables automatic outlining of architecture-specific memory operations.

#### How It Works

Architecture plugins implement instruction lifting to IL using intrinsics. The outliner then recognizes these intrinsic names and transforms them into builtin function calls. Here's the flow:

1. **Architecture Lifting**: Specialized instructions are lifted to IL intrinsics with standardized names
2. **Intrinsic Recognition**: The outliner detects recognized intrinsic names (`__memcpy`, `__memfill`, etc.)
3. **Builtin Transformation**: The intrinsic is replaced with an appropriate builtin function call
4. **Parameter Adjustment**: Count parameters are adjusted based on element width

#### Example: x86 REP Instructions

The x86 architecture plugin (`api/plugins/x86_arch/arch_x86_intrinsics.cpp`) maps REP-prefixed string instructions to intrinsics:

```cpp
// In GetIntrinsicName():
case INTRINSIC_XED_IFORM_REP_MOVSB:
    return "__memcpy_u8";
case INTRINSIC_XED_IFORM_REP_MOVSW:
    return "__memcpy_u16";
case INTRINSIC_XED_IFORM_REP_MOVSD:
    return "__memcpy_u32";
case INTRINSIC_XED_IFORM_REP_MOVSQ:
    return "__memcpy_u64";

case INTRINSIC_XED_IFORM_REP_STOSB:
    return "__memfill_u8";
case INTRINSIC_XED_IFORM_REP_STOSW:
    return "__memfill_u16";
case INTRINSIC_XED_IFORM_REP_STOSD:
    return "__memfill_u32";
case INTRINSIC_XED_IFORM_REP_STOSQ:
    return "__memfill_u64";
```

During IL generation (`api/plugins/x86_arch/il.cpp`), these instructions are lifted as intrinsics:

```cpp
il.AddInstruction(il.Intrinsic(
    vector<RegisterOrFlag> {
        RegisterOrFlag::Register(dstReg),
        RegisterOrFlag::Register(srcReg),
        RegisterOrFlag::Register(GetCountRegister(addrSize))
    },
    intrinsic,
    vector<ExprId> { dstExpr, srcExpr, countExpr }
));
```

The outliner then recognizes the intrinsic name and transforms it into the appropriate builtin call.

#### Recognized Intrinsic Names

**Memory Copy Intrinsics**:

- `__memcpy` → `memcpy`, `strcpy`, or `strncpy` (based on data classification)
- `__memcpy_u8` → `memcpy` (byte-wise, count unchanged)
- `__memcpy_u16` → `memcpy` (16-bit elements, count × 2)
- `__memcpy_u32` → `memcpy` (32-bit elements, count × 4)
- `__memcpy_u64` → `memcpy` (64-bit elements, count × 8)

**Memory Fill Intrinsics**:

- `__memfill` → `memset`
- `__memfill_u8` → `memset` (byte-wise, count unchanged)
- `__memfill_u16` → `memset` (16-bit elements, count × 2)
- `__memfill_u32` → `memset` (32-bit elements, count × 4)
- `__memfill_u64` → `memset` (64-bit elements, count × 8)

**Width-Specific Parameter Adjustment**: For width-specific intrinsics (u16, u32, u64), the count parameter is automatically adjusted by left-shifting (1, 2, or 3 bits) to convert element counts to byte counts.

## Example Transformations

### Before and After

Binary Ninja's outlining transforms code at multiple levels of abstraction. What starts as a series of individual memory operations becomes a clear, semantic function call:

**Assembly View (Before):**

The raw assembly shows a sequence of individual memory operations that must be mentally reconstructed into a higher-level pattern.

![Assembly code before outlining](../img/outlining-before-asm.png)

**Pseudo-C View (Before):**

Even in pseudo-C, without outlining, the operations remain as individual memory accesses that obscure the programmer's intent.

![HLIL code before outlining](../img/outlining-before-c.png)

**Pseudo-C View (After):**

After outlining, Binary Ninja transforms these operations into a single `strncpy` call with appropriate parameters, instantly revealing the code's purpose.

![Decompiled code after outlining](../img/outlining-after.png)

This transformation dramatically reduces cognitive load during analysis, letting you focus on understanding program logic rather than reconstructing common operations.

## Synthetic Builtins Section

Binary Ninja creates a special `.synthetic_builtins` section containing properly typed function symbols for all outlined operations.

![Synthetic builtins section](../img/outlining-synthetic-builtins.png)

This provides:

- **Proper function signatures** for all builtin operations
- **Enhanced cross-references** showing semantic function calls
- **Type information** for better analysis and navigation
- **Coherent call graph** connecting outlined operations

**Enhanced Cross-References:**

Memory operations that were previously disconnected now show up as cross-references to semantic function calls, creating a coherent call graph.

![Cross-references to outlined functions](../img/outlining-xrefs.png)

## Type System Integration

### Type-Guided Outlining

Type information significantly improves outlining quality:

- **Pointer types** determine whether operations are treated as string, wide character, or general memory operations
- **Character types** (`char`, `wchar_t`) suggest string operations over memory operations
  - `char*` → `strcpy` or `strncpy`
  - `wchar_t*` → `wcscpy` (for null-terminated strings) or `wmemcpy` (for buffers)
- **Array element types** affect size calculations and operation selection
- **Structure types** help identify field-wise initialization patterns
- **Platform context** affects wide character width (Windows=2 bytes, Unix-like=4 bytes)

### Improving Outlining Results

Provide accurate type information to enhance outlining:

```python
# Set variable types to guide outlining decisions
var.type = types.Type.array(types.Type.char(), 16)

# Define structures for better field initialization recognition
struct_type = types.Type.structure([
    types.StructureMember(types.Type.char(), "name", 0),
    types.StructureMember(types.Type.int(4), "value", 16)
])
```

## Data Stream Classification

The outliner classifies memory operations based on data patterns:

| Stream Type | Description | Typical Result |
|-------------|-------------|----------------|
| **DataStreamZeros** | Stream of zero bytes | `memset(ptr, 0, size)` |
| **DataStreamOnes** | Stream of 0xFF bytes | `memset(ptr, 0xFF, size)` |
| **DataStreamFill** | Stream of identical bytes (not 0x00/0xFF) | `memset(ptr, value, size)` |
| **DataStreamAscii** | ASCII text patterns | `strcpy` or string operations |
| **DataStreamUtf8** | UTF-8 encoded text | `strcpy` or `memcpy` |
| **DataStreamUtf16** | UTF-16 null-terminated text | `wcscpy` (platform-dependent) |
| **DataStreamUtf32** | UTF-32 null-terminated text | `wcscpy` (platform-dependent) |
| **DataStreamUtf16Buffer** | UTF-16 with trailing data | `wmemcpy` |
| **DataStreamUtf32Buffer** | UTF-32 with trailing data | `wmemcpy` |
| **DataStreamStrcpy** | Null-terminated strings | `strcpy` variants |
| **DataStreamStrncpy** | Fixed-length string operations | `strncpy` |

**Note on Wide Characters**: The choice between `wcscpy` and `memcpy` for UTF-16/UTF-32 depends on the platform's wide character width. On Windows (2 bytes), UTF-16 maps to `wcscpy`. On Unix-like systems (4 bytes), UTF-32 maps to `wcscpy`. Mismatched widths fall back to `memcpy`.

## Key Use Cases

Outlining is valuable across many analysis domains including reverse engineering, malware analysis, and firmware analysis:

- **Cleaner decompilation** - Transforms low-level operations into readable function calls
- **Pattern recognition** - Identifies common algorithms obscured by compiler optimizations
- **String extraction** - Reveals string initialization patterns, even in obfuscated code
- **Data structure analysis** - Shows initialization of complex data structures
- **Cross-reference analysis** - Creates semantic connections between related operations
- **Memory operation identification** - Recognizes standard library patterns in bootloaders, drivers, and protocols
- **Algorithm recognition** - Identifies standard algorithms despite optimization or obfuscation

## Troubleshooting

### Common Issues

**Patterns not being outlined**:

- Check if `analysis.outlining.builtins` is enabled
- Verify type information supports the expected operation
- Ensure patterns meet minimum size thresholds (see below)

**Incorrect function selection**:

- Provide more precise type information
- Check data stream classification
- Verify pattern clarity and confidence

### Size Thresholds and Filtering

Binary Ninja applies size-based filtering to avoid outlining trivial operations. Understanding these thresholds can help explain why certain patterns aren't outlined:

**Without Type Information** (no user-provided types with full confidence):

- General memory operations: Must be >16 bytes
- String operations: Must be ≥4 bytes
- ASCII patterns: Must be ≥4 bytes
- Fill patterns (memset): Must be ≥16 bytes

**With Type Information** (user-provided types with full confidence):

- Size thresholds are relaxed
- Type compatibility checks take priority
- Operations matching type boundaries are more likely to be outlined

**String-Specific Requirements**:

- String must have at least 4 printable characters before null terminator
- Very short strings (1-3 bytes) are often demoted to general memory operations

**Examples**:
```c
// Likely NOT outlined (too small, no type info)
buffer[0] = 'A';
buffer[1] = 'B';
buffer[2] = 0;

// Likely outlined (meets 4-byte minimum)
buffer[0] = 'H';
buffer[1] = 'e';
buffer[2] = 'l';
buffer[3] = 'l';
buffer[4] = 'o';
buffer[5] = 0;  // strcpy(buffer, "Hello")
```

**Tip**: To outline smaller operations, provide explicit type information with full confidence (user-specified types).
