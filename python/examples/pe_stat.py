#!/usr/bin/env python3
#
# BinaryNinja multiplatform version of Z0MBIE's PE_STAT for opcode frequency
# statistics http://z0mbie.dreamhosters.com/opcodes.html
#
# Copyright (c) 2020-2022 Vector 35 Inc
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
import binaryninja
from collections import defaultdict

opc2count = defaultdict(lambda:0)
target = sys.argv[1]

print('opening %s' % target)
bv = binaryninja.BinaryViewType.get_view_of_file(target)
print('analyzing')
bv.update_analysis_and_wait()

print('looping over functions')
for func in bv.functions:
	print('disassembling %s()' % func.symbol.full_name)
	for block in func:
		for (toks, length) in block:
			opc = toks[0].text
			opc2count[opc] += 1
			#print('incremented %s, is now: %d' % (opc, opc2count[opc]))

total = sum([x[1] for x in opc2count.items()])

print('op       frequency        %')
print('--       ---------        -')
for opc in sorted(opc2count.keys(), key=lambda x:opc2count[x], reverse=True):
	print(opc.ljust(8), str(opc2count[opc]).ljust(16), '%.1f%%'%(100.0*opc2count[opc]/total))

