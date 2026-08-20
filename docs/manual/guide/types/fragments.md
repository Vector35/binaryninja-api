# Type Fragments

A `FragmentType` describes a bitwise slice of a larger source type while that slice is carried
in integer-like storage. Fragments are generally intermediate, in-flight types used by
analysis. They are not new structures or memory layouts, and they are not inherently tied to
a particular load instruction. The live fragment's current size and placement within its
container are tracked in bits.

Fragments let Binary Ninja preserve type information when only part of a typed object moves
through the program. Common examples include:

- a calling convention that passes pieces of a structure in registers;
- an optimized inline `memcpy` that copies a typed object in register-sized chunks, often from
  the data segment; and
- a partial move or extraction from a larger aggregate.

Without a fragment, a register holding one 64-bit part of a larger structure would usually
have only a generic integer type. The relationship between those bits and the source object
would be lost. A fragment carries that relationship through partial moves and compatible bit
operations so later analysis can still recover the relevant source or member types.

## Live Bit Slice and Its Storage

A fragment has bit-granular live state plus byte-granular metadata for its original source
window and storage container. The live fragment's current size and container placement are
`fragment_width_bits` and `fragment_start_bit`; the plain `width` and `offset` properties are
storage and original-source metadata, not the fragment's bit size and placement.

The live state is measured in bits:

| State | Python property | Meaning |
|---|---|---|
| Container bit offset | `fragment_start_bit` | Bit position at which the live fragment begins, where the container's least-significant bit is zero |
| Fragment bit size | `fragment_width_bits` | Number of valid fragment bits still represented |
| Original logical fragment offset | `fragment_truncated_start_bits` | Number of original low-order logical fragment bits no longer represented |
| Saved wrap boundary | `fragment_wrap_bit` | Historical container bit boundary retained for a rotated, extended fragment; zero means no boundary is saved, so the current container width is used |

The remaining properties record byte-granular source and container metadata:

| State | Python property | Meaning | Unit |
|---|---|---|---|
| Source type | `target` | Larger type from which the slice originates | type |
| Original source offset | `offset` | Byte offset of the original source window within `target` | bytes |
| Original source window | `fragment_original_width_bytes` | Width of the byte-aligned window from which the live bits originate | bytes |
| Mapping order | `fragment_endianness` | Byte order used to map the source window into integer-like storage | endianness |
| Container storage | `width` | Width of the current integer-like storage | bytes |

For a fresh fragment, `fragment_start_bit` is zero and the fragment bit size is the original
source-window width in bytes multiplied by eight. The container and source window initially use
the same byte width, and the truncation and wrap fields are zero. Analysis updates the container
width and/or bit-level fields as the value is shifted, rotated, extended, or truncated; the
source type and original byte window remain the reference point.

## Example: A Structure Slice in Flight

Consider this 16-byte structure:

``` C
struct Record
{
    uint32_t prefix;  /* Offset: 0x0 */
    uint32_t kind;    /* Offset: 0x4 */
    uint32_t flags;   /* Offset: 0x8 */
    uint32_t suffix;  /* Offset: 0xc */
};
```

Suppose a calling convention or optimized inline copy moves a fragment with a live size of 64
bits through a register, derived from source bytes 4 through 11. Its original source byte
offset is `0x4`:

``` C
struct Record __frag(0x8, 0x4, 0x8)
```

The live fragment starts at container bit zero and has a bit size of 64. Those values are
implicit in this fresh form. The three written arguments describe an eight-byte container, a
source byte offset of `0x4`, and an eight-byte original source window. As the register is copied,
the fragment preserves the relationship to `kind` and `flags` rather than becoming an unrelated
`uint64_t`.

Fragments can propagate through supported constant `AND` masks, constant shifts and rotations,
extensions, and low-part operations. A supported mask is either all ones or a single
contiguous, possibly wrapping run of ones. If an operation isolates exactly `flags`, analysis
can recover its declared `uint32_t` type. If an operation cannot preserve the mapping, the
result falls back to an ordinary integer type.

## Fragment Syntax

The text form records how the live bit slice maps into the current container and byte-aligned
source window. Little-endian mappings use `__frag`, while big-endian mappings use `__frag_be`.
A fresh fragment has three arguments:

``` C
source_type __frag(container_width_bytes, original_offset_bytes, original_width_bytes)
source_type __frag_be(container_width_bytes, original_offset_bytes, original_width_bytes)
```

These three arguments encode the storage width and original byte window, not the live
fragment's bit size and container placement. The latter are initially implied: the fragment
begins at container bit zero and its bit size is `original_width_bytes * 8`. The container width
can differ from the original source-window width after an extension or truncation.

Analysis may append bit-level live state when a fragment has been transformed:

``` C
source_type __frag(container_width_bytes, original_offset_bytes, original_width_bytes,
    fragment_start_bit, fragment_width_bits, fragment_truncated_start_bits)
source_type __frag(container_width_bytes, original_offset_bytes, original_width_bytes,
    fragment_start_bit, fragment_width_bits, fragment_truncated_start_bits, fragment_wrap_bit)
```

`fragment_start_bit` and `fragment_wrap_bit` are positions in the current container, whose
least-significant bit is zero independent of the source-to-container byte order.
`fragment_width_bits` is the live bit count, and `fragment_truncated_start_bits` counts missing
low-order bits in the original logical fragment. When only a saved wrap boundary is needed,
`fragment_wrap_bit` can also appear as the sole fourth argument.

These advanced fields are primarily analysis bookkeeping for slices already in flight. When
constructing a fresh fragment manually, prefer the simple constructors unless you specifically
need to reproduce an analysis-generated state. See [Fragment Types](../../dev/annotation.md#fragment-types)
for Python examples.
