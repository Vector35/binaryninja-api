# Legacy COFF debug fixture

`legacy_coff_debug.exe` is a minimal synthetic PE32 image for
[binaryninja-api#4308](https://github.com/Vector35/binaryninja-api/issues/4308).
It contains a raw-only `IMAGE_DEBUG_TYPE_COFF` entry and an
`IMAGE_COFF_SYMBOLS_HEADER` whose symbol table matches the PE file header.

The `legacy` function is physically located at RVA `0x1010`, and its COFF
symbol value is also `0x1010`. Treating the record as an ordinary
section-relative symbol incorrectly adds the `.text` RVA of `0x1000` and
places the symbol at RVA `0x2010`.

Regenerate the fixture with:

```sh
python3 generate_legacy_coff_debug.py legacy_coff_debug.exe
```

The expected SHA-256 is
`457b7fdf56f480477e8fe80d1e937adaafc06ab3bc8c3f9a6ad389b8b4a067d8`.
