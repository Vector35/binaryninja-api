#!/usr/bin/env python3
#
# command-line BinaryNinja disassembler
#
# BinaryNinja multiplatform version of Z0MBIE's PE_STAT for opcode frequency
# statistics http://z0mbie.dreamhosters.com/opcodes.html
#
# Copyright (c) 2020-2021 Vector 35 Inc
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

GREEN = '\x1B[32m'
NORMAL = '\x1B[0m'

if not sys.argv[2:]:
	print('usage: %s <arch> <bytes>' % sys.argv[0])
	print('examples:')
	print('   eg: %s aarch64  ff 43 00 d1' % sys.argv[0])
	print('   eg: %s armv7    14 d0 4d e2' % sys.argv[0])
	print('   eg: %s armv7eb  14 d0 4d e2' % sys.argv[0])
	print('   eg: %s mips32   27 bd ff f0' % sys.argv[0])
	print('   eg: %s mipsel32 f0 ff bd 27' % sys.argv[0])
	print('   eg: %s ppc      93 e1 ff fc' % sys.argv[0])
	print('   eg: %s ppc_le   fc ff e1 93' % sys.argv[0])
	print('   eg: %s thumb2   85 b0' % sys.argv[0])
	print('   eg: %s thumb2eb b0 85' % sys.argv[0])
	print('   eg: %s x86      55' % sys.argv[0])
	print('   eg: %s x86_64   55' % sys.argv[0])
	print('')
	print('architectures:')
	print('\t' + '\n\t'.join(map(lambda x: x.name, list(binaryninja.Architecture))))
	sys.exit(-1)

# divide arguments
archName = sys.argv[1]
bytesList = sys.argv[2:]

# parse byte arguments
data = b''.join(list(map(lambda x: int(x,16).to_bytes(1,'big'), bytesList)))

# disassemble
arch = binaryninja.Architecture[archName]
context = binaryninja.function.InstructionContext(bv=None)
toksAndLen = arch.get_instruction_text(data, 0, context)
if not toksAndLen or toksAndLen[1]==0:
	print('disassembly failed')
	sys.exit(-1)

# report
toks = toksAndLen[0]
strs = map(lambda x: x.text, toks)
print(GREEN, ''.join(strs), NORMAL)

