# Legacy COFF debug fixture

`legacy_coff_debug.exe` is a minimal synthetic PE32 image for
[binaryninja-api#4308](https://github.com/Vector35/binaryninja-api/issues/4308).
It contains a raw-only `IMAGE_DEBUG_TYPE_COFF` entry and an
`IMAGE_COFF_SYMBOLS_HEADER` whose symbol table matches the PE file header.

The `legacy` function is physically located at RVA `0x1010`, and its COFF
symbol value is also `0x1010`. The separate PE entry point is at RVA `0x1020`,
so Binary Ninja's automatic `_start` symbol does not obscure `legacy` in the
UI. Treating the record as an ordinary section-relative symbol incorrectly
adds the `.text` RVA of `0x1000` and places the symbol at RVA `0x2010`.

Regenerate the fixture with:

```sh
python3 generate_legacy_coff_debug.py legacy_coff_debug.exe
```

Expected SHA-256:
`7d3d2b3a45405e542d4c5644712cd11b27d5c08b968f7020e2960ecffb8dcba7`.
