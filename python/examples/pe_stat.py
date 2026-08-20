#!/usr/bin/env python3
#
# BinaryNinja multiplatform version of Z0MBIE's PE_STAT for opcode frequency
# statistics http://z0mbie.dreamhosters.com/opcodes.html
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
from collections import defaultdict

import binaryninja


def main() -> int:
	parser = argparse.ArgumentParser(description="Report opcode frequencies for a binary")
	parser.add_argument("path", help="binary to analyze")
	args = parser.parse_args()

	opcode_counts = defaultdict(int)
	print(f"opening {args.path}")
	with binaryninja.load(args.path) as view:
		print("analyzing")
		view.update_analysis_and_wait()
		print("looping over functions")
		for function in view.functions:
			print(f"disassembling {function.symbol.full_name}()")
			for block in function:
				for tokens, _length in block:
					if tokens:
						opcode_counts[tokens[0].text] += 1

	total = sum(opcode_counts.values())
	print("op       frequency        %")
	print("--       ---------        -")
	for opcode in sorted(opcode_counts, key=opcode_counts.get, reverse=True):
		percentage = 100.0 * opcode_counts[opcode] / total if total else 0.0
		print(opcode.ljust(8), str(opcode_counts[opcode]).ljust(16), f"{percentage:.1f}%")
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
