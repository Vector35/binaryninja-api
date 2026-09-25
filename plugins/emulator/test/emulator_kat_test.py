#!/usr/bin/env python3
#
# Known-answer tests for the BNIL emulator.
#
# emulator_test.py and emulator_il_test.py both test in the small: a handful of
# instructions, one assertion each. These tests instead emulate whole compiled
# algorithms -- base64 and MD5 -- against published test vectors.
#
# That matters because the two styles fail differently. A per-instruction test
# only catches a bug you already thought to write a case for; MD5's 64 rounds of
# rotate-and-wrapping-add catch carry, rotate, masking and truncation errors
# unconditionally, because a single wrong bit anywhere changes the digest
# completely.
#
# The kernels are built freestanding (see kat/build.sh) with no libc and no
# syscalls, so each entry point is a pure function over caller-supplied buffers
# and the emulator core is what is under test, not the libc stub layer. The same
# C is compiled for every architecture below, so one set of vectors validates
# each lifter/emulator pair.
#
# Run headless with, e.g.:
#
#     PYTHONPATH=<bn>/python python3 -m pytest emulator_kat_test.py
#
# Requires the `emulator` core plugin to be present in the Binary Ninja install.

import hashlib
import os
import unittest

import binaryninja

try:
    from emulator import LLILEmulator, ILEmulatorStopReason
except ImportError:
    from binaryninja.emulator import LLILEmulator, ILEmulatorStopReason


KAT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'kat', 'prebuilt')

# Emulator address space. The loaded object's own sections sit at 0x400000; these
# regions are placed well clear of it.
STACK_BASE = 0x7000_0000
STACK_SIZE = 0x10000
IN_BUF = 0x1000_0000
OUT_BUF = 0x2000_0000
BUF_SIZE = 0x1000

MAX_INSTRUCTIONS = 20_000_000


class KATBase:
    """Emulates the freestanding KAT kernels for one architecture."""

    obj_name = None  # set by subclasses

    @classmethod
    def setUpClass(cls):
        path = os.path.join(KAT_DIR, cls.obj_name)
        if not os.path.exists(path):
            raise unittest.SkipTest(f'missing KAT object {path}; run kat/build.sh')
        cls.bv = binaryninja.load(path)
        cls.bv.update_analysis_and_wait()

    def emulator_at(self, symbol):
        """Build an emulator positioned at ``symbol`` with a stack and buffers mapped."""
        funcs = self.bv.get_functions_by_name(symbol)
        self.assertTrue(funcs, f'{symbol} not found in {self.obj_name}')

        emu = LLILEmulator(self.bv)

        # The emulator has its own address space and does not read the view, so the
        # object's sections (crucially .rodata, holding the base64 alphabet and the
        # MD5 constants) must be copied in explicitly.
        for section in self.bv.sections.values():
            data = self.bv.read(section.start, section.length)
            if data:
                emu.map_memory(section.start, data, section.name)

        emu.map_memory(STACK_BASE, STACK_SIZE, 'stack')
        emu.map_memory(IN_BUF, BUF_SIZE, 'input')
        emu.map_memory(OUT_BUF, BUF_SIZE, 'output')

        self.assertTrue(emu.set_entry_point(funcs[0].start))
        emu.set_max_instructions(MAX_INSTRUCTIONS)
        # Leave headroom on both sides so a push or a red zone stays mapped.
        emu.set_register(self.bv.arch.stack_pointer, STACK_BASE + STACK_SIZE // 2)
        return emu

    def run_to_halt(self, emu, what):
        emu.run()
        self.assertEqual(
            emu.stop_reason, ILEmulatorStopReason.ILEmulatorHalt,
            f'{what} did not run to completion on {self.obj_name}: '
            f'stop_reason={emu.stop_reason} msg={emu.stop_message!r} '
            f'at {emu.current_address:#x}')

    # -- kernels ------------------------------------------------------------

    def b64_encode(self, data: bytes) -> bytes:
        emu = self.emulator_at('b64_encode')
        emu.write_memory(IN_BUF, data)
        emu.set_arguments([IN_BUF, len(data), OUT_BUF])
        self.run_to_halt(emu, 'b64_encode')
        out = emu.read_memory(OUT_BUF, BUF_SIZE)
        return out[:out.index(b'\x00')]

    def md5(self, data: bytes) -> bytes:
        emu = self.emulator_at('md5')
        emu.write_memory(IN_BUF, data)
        emu.set_arguments([IN_BUF, len(data), OUT_BUF])
        self.run_to_halt(emu, 'md5')
        return emu.read_memory(OUT_BUF, 16)

    # -- tests --------------------------------------------------------------

    # RFC 4648 section 10.
    B64_VECTORS = [
        (b'', b''),
        (b'f', b'Zg=='),
        (b'fo', b'Zm8='),
        (b'foo', b'Zm9v'),
        (b'foob', b'Zm9vYg=='),
        (b'fooba', b'Zm9vYmE='),
        (b'foobar', b'Zm9vYmFy'),
    ]

    def test_base64_rfc4648_vectors(self):
        for data, expected in self.B64_VECTORS:
            with self.subTest(input=data):
                self.assertEqual(self.b64_encode(data), expected)

    def test_base64_matches_reference(self):
        import base64
        # Every residue of the 3-byte group, plus a payload spanning many groups.
        for n in (1, 2, 3, 4, 5, 16, 17, 18, 61):
            data = bytes((i * 7 + 11) & 0xff for i in range(n))
            with self.subTest(length=n):
                self.assertEqual(self.b64_encode(data), base64.b64encode(data))

    # RFC 1321 appendix A.5.
    MD5_VECTORS = [
        (b'', 'd41d8cd98f00b204e9800998ecf8427e'),
        (b'a', '0cc175b9c0f1b6a831c399e269772661'),
        (b'abc', '900150983cd24fb0d6963f7d28e17f72'),
        (b'message digest', 'f96b697d7cb7938d525a2f31aaf161d0'),
        (b'abcdefghijklmnopqrstuvwxyz', 'c3fcd3d76192e4007dfb496cca67e13b'),
        (b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
         'd174ab98d277d9f5a5611c2c9f419d9f'),
        (b'1234567890' * 8, '57edf4a22be3c955ac49da2e2107b67a'),
    ]

    def test_md5_rfc1321_vectors(self):
        for data, expected in self.MD5_VECTORS:
            with self.subTest(input=data[:24]):
                self.assertEqual(self.md5(data).hex(), expected)

    def test_md5_block_boundaries(self):
        # 55/56 and 63/64 are where MD5's padding spills into an extra block --
        # the cases most likely to expose a length or carry bug.
        for n in (54, 55, 56, 57, 63, 64, 65, 119, 120):
            data = bytes((i * 31 + 7) & 0xff for i in range(n))
            with self.subTest(length=n):
                self.assertEqual(self.md5(data).hex(), hashlib.md5(data).hexdigest())


class X86_64KATTests(KATBase, unittest.TestCase):
    obj_name = 'kat-x86_64.o'


class AArch64KATTests(KATBase, unittest.TestCase):
    obj_name = 'kat-aarch64.o'

    # These fail on a known emulator/lifter disagreement about shift counts, not on
    # anything wrong with the vectors -- base64 passes here, and both algorithms pass
    # on x86-64.
    #
    # When the rotate amount comes from a table, the aarch64 lifter emits
    #
    #     w9 = neg.d(w8)      ; -7 -> 0xfffffff9
    #     w8 = w0 << w8
    #     w9 = w0 u>> w9      ; relies on the ISA masking the count to 5 bits
    #     w0 = w9 | w8
    #
    # relying on ARM64 masking a register shift amount to the operand width. The
    # emulator shifts literally (see the LLIL_LSR/LLIL_LSL comment in
    # llilemulator.cpp), so the second shift yields 0 and every rotate collapses to
    # `x << c`. MD5 is 64 such rotates, so the digest is wrong for every input.
    #
    # Masking by operand width in the emulator would fix aarch64 but break 8/16-bit
    # x86 shifts, whose counts the x86 lifter has already masked to 5 bits and which
    # must yield 0 rather than wrapping -- so the resolution belongs in the aarch64
    # lifter, which is out of tree. These expectations flip to unexpected successes
    # once that is settled.
    # Defined as wrappers rather than
    #     test_x = unittest.expectedFailure(KATBase.test_x)
    # because expectedFailure marks the function object itself, which the base class
    # shares with the x86-64 subclass.
    @unittest.expectedFailure
    def test_md5_rfc1321_vectors(self):
        KATBase.test_md5_rfc1321_vectors(self)

    @unittest.expectedFailure
    def test_md5_block_boundaries(self):
        KATBase.test_md5_block_boundaries(self)


if __name__ == '__main__':
    unittest.main()
