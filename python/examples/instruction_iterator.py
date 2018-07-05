#!/usr/bin/env python
# Copyright (c) 2015-2017 Vector 35 LLC
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

import sys
import binaryninja as binja

if len(sys.argv) > 1:
	target = sys.argv[1]

bv = binja.BinaryViewType.get_view_of_file(target)
binja.log_to_stdout(True)
binja.log_info("-------- %s --------" % target)
binja.log_info("START: 0x%x" % bv.start)
binja.log_info("ENTRY: 0x%x" % bv.entry_point)
binja.log_info("ARCH: %s" % bv.arch.name)
binja.log_info("\n-------- Function List --------")

""" print all the functions, their basic blocks, and their il instructions """
for func in bv.functions:
	binja.log_info(repr(func))
	for block in func.low_level_il:
		binja.log_info("\t{0}".format(block))

		for insn in block:
			binja.log_info("\t\t{0}".format(insn))


""" print all the functions, their basic blocks, and their mc instructions """
for func in bv.functions:
	binja.log_info(repr(func))
	for block in func:
		binja.log_info("\t{0}".format(block))

		for insn in block:
			binja.log_info("\t\t{0}".format(insn))
