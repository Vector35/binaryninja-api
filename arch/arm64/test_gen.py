#!/usr/bin/env python

# utility to generate tests

import re, sys, codecs

N_SAMPLES = 8 # number of samples for each encoding

from arm64test import instr_to_il, il2str
if not sys.argv[1:]:
	sys.exit(-1)

arch = None
def disassemble(addr, data):
	global arch
	if not arch:
		arch = binaryninja.Architecture['aarch64']
	(tokens, length) = arch.get_instruction_text(data, addr)
	if not tokens or length==0:
		return None
	return disasm_test.normalize(''.join([x.text for x in tokens]))

def print_case(data, comment=''):
	ilstr = instr_to_il(data)
	il_lines = ilstr.split(';')
	print("\t(b'%s', " % (''.join(['\\x%02X'%b for b in data])), end='')
	for (i,line) in enumerate(il_lines):
		if i!=0:
			print('\t\t\t\t\t\t ', end='')
		print('\'%s' % line, end='')
		if i!=len(il_lines)-1:
			print(';\' + \\')
	comment = ' # '+comment if comment else ''
	print('\'),%s' % comment)

def gather_samples(mnems, encodings):
	encodings = [x.upper() for x in encodings]

	global N_SAMPLES
	fpath = './disassembler/test_cases.txt'
	with open(fpath) as fp:
		lines = fp.readlines()

	samples = 0
	current_encoding = None
	for line in lines:
		if line.startswith('// NOTE:'): continue
		if line.startswith('// SYNTAX:'): continue

		if re.match(r'^// .*? .*', line):
			m = re.match(r'^// (.*?) .*', line)

			# example:
			# // BFCVT_Z_P_Z_S2BF 01100101|opc=10|0010|opc2=10|101|Pg=xxx|Zn=xxxxx|Zd=xxxxx
			current_encoding = m.group(1)
			samples = 0
			continue

		m = re.match(r'^(..)(..)(..)(..) (.*)$', line)
		if m:
			# example:
			# 658AB9BB bfcvt z27.h, p6/m, z13.s
			if samples >= N_SAMPLES:
				continue
			(b0, b1, b2, b3, instxt) = m.group(1,2,3,4,5)
			data = codecs.decode(b3+b2+b1+b0, 'hex_codec')
			#if not (instxt==mnem or instxt.startswith(mnem+' ')):

			mnemonic_match = [x for x in mnems if instxt.startswith(x)]
			encoding_match = current_encoding.upper() in encodings
			if not (mnemonic_match or encoding_match):
				continue

			#if samples == 0:
			#	print('\t# %s' % encoding)
			print('\t# %s %s' % (instxt.ljust(64), current_encoding))
			print_case(data)

			samples += 1
			continue

		print('unable to parse line: %s' % line)
		sys.exit(-1)

# generate lifting tests for a given mnemonic
# example:
# ./test_gen mnemonic ld1
if sys.argv[1] == 'mnemonic':
	mnem = sys.argv[2]
	print('searching for mnemonic -%s-' % mnem)
	gather_samples([mnem], [])

elif sys.argv[1] == 'encoding':
	encname = sys.argv[2]
	print('searching for encoding -%s-' % encname)
	gather_samples([], [encname])

elif sys.argv[1] == 'mte':
	mnems = ['addg', 'cmpp', 'gmi', 'irg', 'ldg', 'dgv', 'ldgm', 'st2g', 'stg',
			'stgm', 'stgp', 'stgv', 'stz2g', 'stzg', 'stzgm', 'subg', 'subp',
			'subps']
	gather_samples(mnems, [])

elif sys.argv[1] == 'recompute_arm64test':
	with open('arm64test.py') as fp:
		lines = [x.rstrip() for x in fp.readlines()]

	i = 0
	while i < len(lines):
		m = re.match(r'^\t\(b\'\\x(..)\\x(..)\\x(..)\\x(..)\'.*$', lines[i])
		if not m:
			print(lines[i])
			i += 1
			continue

		(b0, b1, b2, b3) = m.group(1,2,3,4)

		comment = None
		m = re.search(r'# (.*)$', lines[i])
		if m:
			comment = m.group(1)

		data = codecs.decode(b0+b1+b2+b3, 'hex_codec')
		print_case(data, comment)

		i += 1
		while lines[i].startswith('\t\t\t\t\t\t'):
			i += 1




