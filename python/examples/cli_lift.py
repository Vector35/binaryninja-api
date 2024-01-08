#!/usr/bin/env python
#
# command-line BinaryNinja lifter
#
# Copyright (c) 2020-2024 Vector 35 Inc
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
from binaryninja import core
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


if __name__ == '__main__':

	if not sys.argv[2:]:
		print('usage: %s <platform> <bytes>' % sys.argv[0])
		print('')
		print('examples:')
		print('   eg: %s linux-armv7 14 d0 4d e2 01 20 a0 e1 00 30 a0 e1 00 c0 a0 e3' % sys.argv[0])
		print('')
		print('platforms:')
		print('\t' + '\n\t'.join(map(str, list(binaryninja.Platform))))

		sys.exit(-1)

	# divide arguments
	platName = sys.argv[1]
	archName = platName.split('-')[1]
	bytesList = sys.argv[2:]

	# parse byte arguments
	data = b''.join(list(map(lambda x: int(x, 16).to_bytes(1, 'big'), bytesList)))

	plat = binaryninja.Platform[platName]
	bv = binaryview.BinaryView.new(data)
	bv.platform = plat

	bv.add_function(0, plat=plat)

	#	print('print all the functions, their basic blocks, and their mc instructions')
	#	for func in bv.functions:
	#		print(repr(func))
	#		for block in func:
	#			print("\t{0}".format(block))
	#			for insn in block:
	#				print("\t\t{0}".format(insn))

	print(RED)
	for func in bv.functions:
		#print(repr(func))
		for block in func.low_level_il:
			#print("\t{0}".format(block))
			for insn in block:
				traverse_IL(insn, 0)
	print(NORMAL)
