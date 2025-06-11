#!/usr/bin/env python

# (bytes, expected_disassembly, options)
test_cases = (
	(b'\x00\xbf', 'nop', {}),
	(b'\xef\xf3\x00\x80', 'mrs r0, apsr', {}),
	(b'\xef\xf3\x01\x80', 'mrs r0, iapsr', {}),
	(b'\xef\xf3\x02\x80', 'mrs r0, eapsr', {}),
	(b'\xef\xf3\x03\x80', 'mrs r0, xpsr', {}),
	(b'\xef\xf3\x05\x80', 'mrs r0, ipsr', {}),
	(b'\xef\xf3\x06\x80', 'mrs r0, epsr', {}),
	(b'\xef\xf3\x07\x80', 'mrs r0, iepsr', {}),

	(b'\xef\xf3\x09\x80', 'mrs r0, psp', {}),
	(b'\xef\xf3\x08\x80', 'mrs r0, msp', {}),

	(b'\xef\xf3\x10\x80', 'mrs r0, primask', {}),
	(b'\xef\xf3\x11\x80', 'mrs r0, basepri', {}),
	(b'\xef\xf3\x12\x80', 'mrs r0, basepri', {}),
	(b'\xef\xf3\x13\x80', 'mrs r0, faultmask', {}),
	(b'\xef\xf3\x14\x80', 'mrs r0, control', {}),

	(b'\x80\xf3\x00\x84', 'msr apsr_g, r0', {}),
	(b'\x80\xf3\x00\x88', 'msr apsr_nzcvq, r0', {}),
	(b'\x80\xf3\x00\x8c', 'msr apsr_nzcvqg, r0', {}),
	(b'\x80\xf3\x01\x84', 'msr iapsr_g, r0', {}),
	(b'\x80\xf3\x01\x88', 'msr iapsr_nzcvq, r0', {}),
	(b'\x80\xf3\x01\x8c', 'msr iapsr_nzcvqg, r0', {}),
	(b'\x80\xf3\x02\x84', 'msr eapsr_g, r0', {}),
	(b'\x80\xf3\x02\x88', 'msr eapsr_nzcvq, r0', {}),
	(b'\x80\xf3\x02\x8c', 'msr eapsr_nzcvqg, r0', {}),
	(b'\x80\xf3\x03\x84', 'msr xpsr_g, r0', {}),
	(b'\x80\xf3\x03\x88', 'msr xpsr_nzcvq, r0', {}),
	(b'\x80\xf3\x03\x8c', 'msr xpsr_nzcvqg, r0', {}),

	(b'\x80\xf3\x09\x88', 'msr psp, r0', {}),
	(b'\x80\xf3\x08\x88', 'msr msp, r0', {}),

	(b'\x80\xf3\x10\x88', 'msr primask, r0', {}),
	(b'\x80\xf3\x11\x88', 'msr basepri, r0', {}),
	(b'\x80\xf3\x12\x88', 'msr basepri_max, r0', {}),
	(b'\x80\xf3\x13\x88', 'msr faultmask, r0', {}),
	(b'\x80\xf3\x14\x88', 'msr control, r0', {}),
)

'''
msr r0, apsr
mrs apsr, r0
msr r0, apsr_g
mrs apsr_g, r0
msr r0, apsr_nzcvq
mrs apsr_nzcvq, r0
msr r0, apsr_nzcvqg
mrs apsr_nzcvqg, r0
'''

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

