# x86 per-iclass lifting coverage

Generates **one instruction per XED iclass, per machine mode** so that changes
in x86 lifting (particularly intrinsic lifting) can be tracked. See
Vector35/binaryninja#1668.

An iclass valid in both long and legacy modes appears in both manifests,
because its lifting can legitimately differ between them (stack width, flag
handling, operand size, etc.).

The regression test that consumes these files lives in the main Binary Ninja
repository at `tests/python/test_x86_iclass_lifting.py`; it lifts every
instruction here and diffs the result against a stored oracle, so a lifting
change shows up as a diff naming the exact instruction that changed.

## Files

| File | Purpose |
| --- | --- |
| `generate.c` | Generator: encodes one instruction per iclass with XED and writes the manifests. |
| `x86_64.manifest`, `x86.manifest` | `<iclass> <iform> <hexbytes>` per instruction (long mode / legacy 32-bit). The bytes are inline; length is recovered from the hex string. |

## Coverage

All 1858 iclasses appear in the long-mode manifest; the ~1700 of them that are
also valid in legacy 32-bit mode appear in `x86.manifest` as well. The gap is
the 64-bit-only iclasses (REX/APX forms, `PUSHFQ`, `MOVSXD`, ...).

Most instructions are produced by XED's encoder. `BND*` and `NOP2`..`NOP9` are
recorded as forced known-good bytes: this XED build (and Binary Ninja) has MPX
disabled and decodes every multi-byte NOP as the plain `NOP` iclass, so those
bytes lift as `NOP` -- keeping the iclass in the dataset flags any future change
(e.g. if MPX decoding is enabled). A handful of iclasses that XED's *encoder*
cannot emit (the `XSAVE` family, `JMPABS`, `JCXZ`, and the legacy
`LDS`/`LES`/`BOUND`) are supplied as known-good bytes and classified by XED's
*decoder*, so a wrong guess can never be mislabeled.

## Regenerating

The generator needs a standalone XED built **with the encoder** (the copy built
for `arch_x86` is decoder-only, `--no-encoder`):

```sh
# Build XED with the encoder (macOS: point --ar at a real archiver).
cd ../xed
python3 mfile.py --ar=/usr/bin/ar --build-dir=/tmp/xedbuild install \
    --install-dir=/tmp/xedbuild/kit

# Build and run the generator.
cd ../iclass_coverage
cc -std=c11 -O2 -I/tmp/xedbuild/kit/include generate.c \
    /tmp/xedbuild/kit/lib/libxed.a -o generate
./generate .          # writes *.manifest
```

After regenerating, refresh the test oracle in the main repo:
`pytest python/test_x86_iclass_lifting.py --overwrite`.

`generate.c --diag <ICLASS>` dumps the operand templates and encode result for
every iform of an iclass — useful when extending operand synthesis.
