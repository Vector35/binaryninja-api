#!/usr/bin/env python
#
# command-line BinaryNinja lifter
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
from binaryninja import binaryview
from binaryninja import lowlevelil

RED = '\x1B[31m'
NORMAL = '\x1B[0m'


def traverse_IL(il, indent):
	if isinstance(il, lowlevelil.LowLevelILInstruction):
		print('\t'*indent + il.operation.name)

		for o in il.operands:
			traverse_IL(o, indent + 1)

	else:
		print('\t'*indent + str(il))


def main() -> int:
	parser = argparse.ArgumentParser(description="Lift instruction bytes to Binary Ninja Low Level IL")
	parser.add_argument("platform", help="registered platform name, such as linux-x86")
	parser.add_argument("bytes", nargs="+", metavar="BYTE", help="instruction bytes in hexadecimal")
	args = parser.parse_args()

	try:
		data = bytes(int(value, 16) for value in args.bytes)
	except ValueError as error:
		parser.error(f"invalid hexadecimal byte: {error}")

	try:
		platform = binaryninja.Platform[args.platform]
	except KeyError:
		parser.error(
			f"unknown platform {args.platform!r}; available platforms: "
			+ ", ".join(str(platform) for platform in binaryninja.Platform)
		)

	with binaryview.BinaryView.new(data) as view:
		view.platform = platform
		view.add_function(0, plat=platform)

		print(RED)
		for function in view.functions:
			for block in function.low_level_il:
				for instruction in block:
					traverse_IL(instruction, 0)
		print(NORMAL)
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
