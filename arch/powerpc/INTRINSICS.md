# PowerPC intrinsic semantics

Intrinsic IDs are persistent database identities. Existing IDs (including the
legacy count-leading-zero intrinsic and string-copy intrinsic) are retained;
new IDs are appended after them, not inserted before them.

## Reservations

`__set_reservation(address, size)` establishes a reservation for the load just
performed at `address`, with `size` in bytes. `__check_reservation(address, size)`
returns a boolean indicating whether the corresponding conditional store can
succeed and **consumes the reservation regardless of its result**. Reservation
operations are memory intrinsics to carry memory/hidden state through SSA.
The lifter snapshots effective addresses before load destinations are written.
The conditional store occurs only on success and reports CR0 EQ and XER SO.
This abstracts reservation loss and atomicity; it is not an executable memory
model for multithreaded emulation.

## Scalar floating point

The unary `__fsqrt`, `__fsqrts`, `__frin`, `__friz`, `__frip`, `__frim`,
`__fctiw`, `__fctiwz`, `__fctiwu`, `__fctiwuz`, `__fctid`, `__fctidz`,
`__fctidu`, `__fctiduz`, `__fcfid`, `__fcfidu`, `__fcfids`, and `__fcfidus`
intrinsics implement their namesake Power ISA instructions. Each takes the
source FPR's **64-bit bit pattern** and the 64-bit FPSCR, and returns the
destination FPR's **64-bit bit pattern** and updated FPSCR.

- Sources are binary64 except for `fcfid*`, which interpret integer bit patterns.
- Unsigned variants interpret unsigned integers, not signed approximations.
- `fcti*z` always rounds toward zero; other `fcti*` forms use FPSCR RN.
- `fcfid*` and `fsqrt*` use FPSCR rounding. Single forms round to binary32 and
  represent that result as binary64 in the destination FPR, without first
  truncating the source FPR to 32 bits.
- `frin` uses nearest with ties away from zero; `friz`, `frip`, and `frim` use
  toward-zero, toward-positive-infinity, and toward-negative-infinity respectively.
- Integer-word conversions retain the architecturally specified destination
  packaging and undefined upper word; they are not treated as sign/zero-extended
  integers. NaNs, out-of-range values, enabled exceptions, FPSCR result/status
  updates, and architectural undefined results follow the ISA for each form.

These are semantic intrinsics, not implementations of an FP emulator. Native IL
conversions cannot describe all these distinctions. Explicit FPSCR input/output
prevents folding a conversion as if it had fixed signedness or rounding.
Record forms copy FPSCR bits 0:3 (FX/FEX/VX/OX) into CR1, never CR0.
`fsel` and `fcpsgn` use pure IL and preserve FPSCR, including on record forms.
Existing FP arithmetic outside this group still has incomplete status modeling;
its FPSCR output is conservatively invalidated rather than left falsely unchanged.

The FPSCR state is 64 bits so that `mtfsf`'s W selector can address its extended
word as well as its traditional low word. The traditional summary bits copied
to CR1 are still bits 31:28 of that low word (in ordinary LSB numbering).
`__mffs(fpscr)` returns the architectural FPR bit pattern.
`__mtfsf(fpscr, mask, value, l, w)` returns updated FPSCR, including recomputed
summary bits. `__mtfsb0(fpscr, bit)` and `__mtfsb1(fpscr, bit)` similarly return
updated state. Their record forms copy the resulting summaries to CR1.

## System and cache operations

`__mtmsr(msr, value, l)` and `__mtmsrd(msr, value, l)` return the new MSR after
the instruction-specific selective update. `mfmsr` reads this state directly.
Both writes are memory intrinsics because address translation and execution
mode changes may invalidate memory facts. The L bit and word/doubleword variant
are never discarded. Generic `__mfspr(spr)` / `__mtspr(spr, value)` retain the
SPR number; the latter conservatively participates in memory SSA. Time-base
reads use distinct low/full and upper-word intrinsics.

Barriers and cache maintenance are memory intrinsics. This conservatively
invalidates memory facts across operations affecting visibility, ordering,
translation, or cache contents. Prefetch-only hints are no-ops.
`__dcbz(address)` and `__dcbzl(address)` keep their different block-zeroing
semantics distinct without assuming a cache-line size. `__dcbf(address, l)`
preserves its L field, and `__mbar(mo)` preserves its ordering selector.

The existing `xer` register backs the bits not individually modeled as flags.
`mfxer` overlays SO/OV/CA from their authoritative flags; `mtxer` updates both
the backing register and those flags. The new OE arithmetic also updates OV32
while preserving byte count and CA32. Older arithmetic still has incomplete
XER status modeling; these changes do not attempt an architecture-wide rewrite.
The SVR4 calling convention conservatively treats FPSCR and the XER backing
register as caller-saved. Some FPSCR control bits are nonvolatile, but preserving
the entire register would incorrectly preserve volatile status across calls.

## Floating-point memory packing

`lfs*` and `stfs*` implement the ISA's non-arithmetic DOUBLE and SINGLE bit
conversions using integer IL. They preserve signaling NaNs/payloads, signed
zero and subnormal encodings without updating FPSCR. These are not generic
rounded FP arithmetic conversions. Doubleword FP memory forms transfer bits
directly. Out-of-range SINGLE inputs with architecturally undefined results
may produce signed zero rather than introducing arithmetic rounding semantics.
