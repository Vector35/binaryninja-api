#!/bin/sh
# Rebuild the known-answer-test objects consumed by emulator_kat_test.py.
#
# The checked-in objects under prebuilt/ are what the tests actually load, so that the
# suite is hermetic and does not depend on a cross-compiler being installed. Run
# this only when kat.c changes, and commit the regenerated objects.
#
# The flags are part of the test contract, not incidental:
#   -ffreestanding -nostdlib  no libc is linked or assumed
#   -fno-builtin              the compiler may not turn loops into memcpy/memset
#   -fno-tree-vectorize
#   -fno-slp-vectorize        no SIMD, which would reach the emulator as an
#                             LLIL_INTRINSIC and stop it without a hook
#   -O1                       optimized enough to be interesting, not so much
#                             that it reaches for vector or ISA extensions
set -eu

cd "$(dirname "$0")"
mkdir -p prebuilt

CFLAGS="-ffreestanding -nostdlib -fno-builtin -fno-tree-vectorize -fno-slp-vectorize -O1 -g0"

for target in x86_64-unknown-none-elf aarch64-unknown-none-elf; do
	arch="${target%%-*}"
	clang -target "$target" $CFLAGS -c kat.c -o "prebuilt/kat-$arch.o"
	echo "built prebuilt/kat-$arch.o"
done
