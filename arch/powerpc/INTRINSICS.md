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
source FPR's **64-bit bit pattern** and the 32-bit FPSCR, and returns the
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
