#!/usr/bin/env python3
#
# command-line BinaryNinja disassembler
#
# Copyright (c) 2020-2026 Vector 35 Inc
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

import argparse

import binaryninja

GREEN = '\x1B[32m'
NORMAL = '\x1B[0m'

def main() -> int:
	parser = argparse.ArgumentParser(description="Disassemble one instruction with a Binary Ninja architecture")
	parser.add_argument("architecture", help="registered architecture name, such as x86 or aarch64")
	parser.add_argument("bytes", nargs="+", metavar="BYTE", help="instruction bytes in hexadecimal")
	args = parser.parse_args()

	try:
		data = bytes(int(value, 16) for value in args.bytes)
	except ValueError as error:
		parser.error(f"invalid hexadecimal byte: {error}")

	try:
		arch = binaryninja.Architecture[args.architecture]
	except KeyError:
		parser.error(
			f"unknown architecture {args.architecture!r}; available architectures: "
			+ ", ".join(arch.name for arch in binaryninja.Architecture)
		)

	result = arch.get_instruction_text(data, 0)
	if not result or result[1] == 0:
		print("disassembly failed")
		return 1

	print(GREEN, "".join(token.text for token in result[0]), NORMAL)
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
