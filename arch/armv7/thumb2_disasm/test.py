#!/usr/bin/env python

# (bytes, expected_disassembly, options)
test_cases = (
	(b'\x00\xbf', 'nop', {}),
	(b'\xef\xf3\x09\x80', 'mrs r0, psp', {}),
	(b'\x80\xf3\x09\x88', 'msr psp, r0', {}),
	(b'\xef\xf3\x08\x80', 'mrs r0, msp', {}),
	(b'\x80\xf3\x08\x88', 'msr msp, r0', {}),
	(b'\xef\xf3\x00\x80', 'mrs r0, apsr', {}),
	(b'\xef\xf3\x10\x80', 'mrs r0, primask', {}),
	(b'\xef\xf3\x11\x80', 'mrs r0, basepri', {}),
	(b'\xef\xf3\x13\x80', 'mrs r0, faultmask', {}),
	(b'\xef\xf3\x14\x80', 'mrs r0, control', {}),
	(b'\x80\xf3\x00\x88', 'msr apsr_nzcvq, r0', {}),
	(b'\x80\xf3\x10\x88', 'msr primask, r0', {}),
	(b'\x80\xf3\x11\x88', 'msr basepri, r0', {}),
	(b'\x80\xf3\x13\x88', 'msr faultmask, r0', {}),
	(b'\x80\xf3\x14\x88', 'msr control, r0', {}),
)

import sys, re
import binaryninja

arch = None
def disassemble_binja(data, addr):
	global arch
	if not arch:
		arch = binaryninja.Architecture['thumb2']
	(tokens, length) = arch.get_instruction_text(data, addr)
	if not tokens or length==0:
		return 'disassembly failed'
	strs = map(lambda x: x.text, tokens)
	instxt = ''.join(strs)
	instxt = re.sub(r'\s+', ' ', instxt)
	return instxt

if __name__ == '__main__':
	for (test_i, (data, expected, options)) in enumerate(test_cases):
		addr = options.get('addr', 0)
		actual = disassemble_binja(data, addr)
		if actual != expected:
			print('MISMATCH AT TEST %d!' % test_i)
			print('\t    data: %s' % repr(data))
			print('\t address: %08X' % addr)
			print('\tinsvalue: 0x%08X' % insvalue)
			print('\texpected: %s' % expected)
			print('\t  actual: %s' % actual)
			sys.exit(-1)

	print('success!')
	sys.exit(0)

