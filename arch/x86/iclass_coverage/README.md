# x86 per-iclass lifting coverage

Generates a test binary containing **one instruction per XED iclass** so that
changes in x86 lifting (particularly intrinsic lifting) can be tracked. See
Vector35/binaryninja#1668.

The regression test that consumes these files lives in the main Binary Ninja
repository at `tests/python/test_x86_iclass_lifting.py`; it lifts every
instruction here and diffs the result against a stored oracle, so a lifting
change shows up as a diff naming the exact instruction that changed.

## Files

| File | Purpose |
| --- | --- |
| `generate.c` | Generator: encodes one instruction per iclass with XED and writes the manifests and coverage report. |
| `x86_64.manifest`, `x86.manifest` | `<iclass> <iform> <hexbytes>` per instruction (long mode / legacy 32-bit). The bytes are inline; length is recovered from the hex string. |
| `coverage.txt` | Covered / uncovered iclass summary. |

## Coverage

1843 / 1858 iclasses. The 15 that are not covered are unreachable in Binary
Ninja's XED build and so cannot appear in any test binary (details in
`coverage.txt`):

* `BND*` — MPX decoding is disabled, so the MPX opcodes decode as `NOP`.
* `NOP2`..`NOP9` — every multi-byte NOP decodes to the plain `NOP` iclass.

Most instructions are produced by XED's encoder. A handful of iclasses that
XED's *encoder* cannot emit (the `XSAVE` family, `JMPABS`, `JCXZ`, and the
legacy `LDS`/`LES`/`BOUND`) are supplied as known-good bytes and classified by
XED's *decoder*, so a wrong guess can never be mislabeled.

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
./generate .          # writes *.manifest, coverage.txt
```

After regenerating, refresh the test oracle in the main repo:
`pytest python/test_x86_iclass_lifting.py --overwrite`.

`generate.c --diag <ICLASS>` dumps the operand templates and encode result for
every iform of an iclass — useful when extending operand synthesis.
