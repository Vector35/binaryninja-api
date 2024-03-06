#!/usr/bin/env python
# read neon_intrins.c and generate code for the architecture

import re
import sys

from collections import OrderedDict

# SMMLA Vd.4S,Vn.16B,Vm.16B -> Vd.4S
def get_destination_reg(asig):
	try:
		(mnem, regs) = re.match(r'^(\w+) (.*)', asig).group(1,2)
	except AttributeError:
		print('couldn\'t get destination register from -%s-' % asig)
		sys.exit(-1)
	return regs.split(',')[0]

def get_reg_size(reg):
	if reg in ['Qd', 'Qt']: return 16
	if reg in ['Dd', 'Dm']: return 8
	if reg=='Sd': return 4
	if reg=='Hd': return 2
	if reg=='Bd': return 1

	if reg in ['Wd', 'Wn', 'Wm']: return 4

	reg = reg.lower()
	if '.1q' in reg: return 16
	if '.2d' in reg: return 16
	if '.4s' in reg: return 16
	if '.8h' in reg: return 16
	if '.16b' in reg: return 16
	if '.d' in reg: return 8
	if '.1d' in reg: return 8
	if '.2s' in reg: return 8
	if '.4h' in reg: return 8
	if '.8b' in reg: return 8
	if '.s' in reg: return 4
	if '.2h' in reg: return 4
	if '.4b' in reg: return 4
	if '.h' in reg: return 2
	if '.b' in reg: return 1

	print('couldn\'t get size of register -%s-' % reg)
	sys.exit(-1)

def get_write_size(asig):
	(mnem, regs) = re.match(r'^(\w+) (.*)', asig).group(1,2)
	regs = regs.split(',')
	reg0 = regs[0]

	if reg0=='Rd':
		# eg: UMOV Rd,Vn.B[lane] means Rd is 1 byte
		assert len(regs)==2
		return get_reg_size(regs[1])

	if reg0.startswith('{') and reg0.endswith('}') and ' - ' in reg0:
		# eg: ST2 {Vt.16B - Vt2.16B},[Xn]
		m = re.match('^.* - (Vt(\d)\..*)}', reg0)
		(reg0, num) = m.group(1,2)
		return (int(num)+1) * get_reg_size(reg0)

	return get_reg_size(reg0)

def type_to_binja_types(ntype):
	# remove pointer
	if ntype.endswith(' const *'):
		ntype = ntype[0:-8]
	if ntype.endswith(' *'):
		ntype = ntype[0:-2]

	binja_type = 'Float' if 'float' in ntype else 'Int'

	# int (for lane or immediate)
	if ntype == 'int':
		return ['Type::IntegerType(4)']

	# multiple packed, eg: "uint8x8x2_t"
	m = re.match(r'^(\w+?)(\d+)x(\d+)x(\d+)_t$', ntype)
	if m:
		(base, bit_width, npacked, nregs) = m.group(1,2,3, 4)
		return ['Type::%sType(%d)' % (binja_type, int(bit_width)*int(npacked)/8)]*int(nregs)

	# packed in registers, eg: "int8x8_t"
	m = re.match(r'^(\w+?)(\d+)x(\d+)_t$', ntype)
	if m:
		(base, bit_width, npacked) = m.group(1,2,3)
		return ['Type::%sType(%d)' % (binja_type, int(bit_width)*int(npacked)/8)]

	# simple, eg: "int8_t"
	m = re.match(r'^(\w+?)(\d+)_t$', ntype)
	if m:
		(base, bit_width) = m.group(1,2)
		return ['Type::%sType(%d)' % (binja_type, int(bit_width)/8)]

	print('cannot convert neon type %s into binja type' % ntype)
	sys.exit(-1)

# given an intrinsic's name, argument types, and return type, compute
# the binja intrinsic input types
def resolve_input_types(name, arg_types, return_type):
	result = []

	for at in arg_types:
		if at.endswith(' *'):
			# eg: int32x4x2_t vld2q_s32(int32_t const * ptr);
			assert ('ld' in name) or ('st' in name)
			result.extend(neon_type_to_binja_types(return_type))
		else:
			result.extend(neon_type_to_binja_types(at))

	return result

if __name__ == '__main__':
	# parse neon_intrins.c into a "database"
	with open('neon_intrins.c') as fp:
		lines = [l.strip() for l in fp.readlines()]

	db = OrderedDict()

	for l in lines:
		if 'reinterpret' in l: continue
		if 'RESULT[' in l: continue
		(fsig, asig) = l.split('; // ')

		# function name
		m = re.match(r'^(\w+) (\w+)\((.*)\)$', fsig)
		fname = m.group(2)
		if fname in db: continue
		if asig.startswith('RESULT['): continue

		# function arguments
		fargs = [m.group(1)] + m.group(3).split(', ')
		fargs = [x.replace('const ', '') for x in fargs]

		(operation, operands) = re.match(r'^(\w+?) (.*)$', asig).group(1, 2)
		operands = operands.split(',')

		db[fname] = OrderedDict({
			          'fsig': fsig,
		              'asig': asig,
		              'define': 'ARM64_INTRIN_%s' % fname.upper(),
		              'operation': 'ARM64_' + operation,
		              'fargs': fargs,
		              'operands': operands,
		           })

	cmd = sys.argv[1]

	if cmd in ['dump']:
		import pprint
		pp = pprint.PrettyPrinter()
		pp.pprint(db)

	elif cmd in ['enum', 'enumeration']:
		# for enum NeonIntrinsic : uint32_t ...
		first = True
		for fname in db:
			extra = '=ARM64_INTRIN_NORMAL_END' if first else ''
			print('\t%s%s,' % (db[fname]['define'], extra))
			first = False

	elif cmd in ['name', 'names']:
		# for GetIntrinsicName(uint32_t intrinsic)
		for fname in db:
			print('\t\tcase %s: return "%s";' % (db[fname]['define'], fname))

	elif cmd in ['all', 'define', 'defines']:
		# for GetAllIntrinsics()
		collection = [db[fname]['define'] for fname in db]
		i = 0
		while i<len(collection):
			print('\t\t' + ', '.join(collection[i:i+3]) + ',')
			i += 3

	elif cmd in ['input', 'inputs']:
		# for GetIntrinsicInputs()

		# collect all unique write types
		rtstrs = set(str(db[x]['binja_input_types']) for x in db)

		# for each write type
		for rtstr in sorted(rtstrs):
			fnames = [x for x in db if str(db[x]['binja_input_types']) == rtstr]

			# print cases in the db that have the same type
			for fname in fnames:
				print('\t\tcase %s:' % (db[fname]['define']))

			print('\t\t\treturn {%s};' % (', '.join(db[fnames[0]]['binja_input_types'])))

	elif cmd in ['output', 'outputs']:
		# for GetIntrinsicOutputs()

		# collect all unique write types
		wtstrs = set(str(db[x]['binja_output_types']) for x in db)

		# for each write type
		for wtstr in sorted(wtstrs):
			fnames = [x for x in db if str(db[x]['binja_output_types']) == wtstr]

			# print cases in the db that have the same type
			for fname in fnames:
				print('\t\tcase %s:' % (db[fname]['define']))

			print('\t\t\treturn {%s};' % (', '.join(db[fnames[0]]['binja_output_types'])))

	elif cmd in ['implementation', 'code']:
		# expects:
		# std::vector<RegisterOrFlag> outputs
		# std::vector<ExprId> inputs
		for fname in db:
			entry = db[fname]

			print('\t\tcase %s:' % entry['operation'])
			print('\t\t{')
			print('\t\t\t// fsig: %s' % entry['fsig'])
			print('\t\t\t// asig: %s' % entry['asig'])
			print('\t\t\t// operands_n: %d' % entry['operands_n'])
			print('\t\t\tadd_output(outputs, oper0, inst, INTRIN_TYPE_HINT_%s);' % (' '.join(entry['binja_output_types']).upper()))
			for i in range(0, len(entry['binja_input_types'])):
				print('\t\t\tadd_input(inputs, oper%d, inst, INTRIN_TYPE_HINT_%s);' % (i+1, entry['binja_input_types'][i].upper()))
			print('\t\t\til.AddInstruction(il.Intrinsic(outputs, %s, inputs));' % entry['define'])
			print('\t\t}')
			print('\t\tbreak;')

	elif cmd in ['test']:
		for fname in db:
			entry = db[fname]
			fargs = entry['fargs']
			operands = entry['operands']

			print(entry['operation'])
			print('fsig: %s' % entry['fsig'])
			print('asig: %s' % entry['asig'])
			print('fargs: %s' % fargs)
			print('operands: %s' % operands)

			# convert OPERATION X,Y,Z[lane] ->
			#         OPERATION X,Y,Z,Z[lane]
#			tmp = []
#			for o in operands:
#				m = re.match(r'^(.*)\[lane\d*\]$', o)
#				if m:
#					tmp.append(m.group(1))
#					tmp.append('lane(%s)' % m.group(1))
#				else:
#					tmp.append(o)
#			operands = tmp
			# convert OPERATION X,Y,#0 ->
			#         OPERATION X,Y
			if re.match(r'^#\d+$', operands[-1]):
				operands = operands[:-1]
			#
			if len(fargs) == len(operands)+1:
				operands = [operands[0]] + operands

			if len(operands) != len(fargs):
				print('cant reconcile fargs and operands')
				if not 'vcopy' in entry['fsig']:
					sys.exit(-1)
