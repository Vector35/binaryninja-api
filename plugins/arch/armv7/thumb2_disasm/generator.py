#!/usr/bin/env python

# see the Makefile for how to invoke me

import os
import re
import sys
import string
import binascii

sys.path.append('./arm_pcode_parser')
import codegencpp

# globals
g_code = ''
g_lineNum = 0
g_lines = []
g_indentLevel = 0
g_DEBUG_GEN = 0
g_DEBUG_DECOMP = 0

header = '''
#include <stdint.h>

#include <map>
#include <string>
#include <vector>

#include "spec.h" /* FIELD_imm8, FIELD_MAX, etc. */
#include "disassembler.h" /* decomp_request, decomp_result */

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunused-variable"
#pragma clang diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wunused-function"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wunused-function"
#endif
'''

support = '''
// see A8.4.3
int DecodeImmShift_shift_t(uint8_t enc_bits, uint8_t imm5)
{
	if(enc_bits == 0)
		return SRType_LSL;
	else if(enc_bits == 1)
		return SRType_LSR;
	else if(enc_bits == 2)
		return SRType_ASR;
	else if(enc_bits == 3) {
		if(imm5 == 0)
			return SRType_RRX;
		else
			return SRType_ROR;
	}
	return SRType_ERROR;
}

int DecodeImmShift_shift_n(uint8_t enc_bits, uint8_t imm5)
{
	if(enc_bits == 0)
		return imm5;
	else if(enc_bits == 1)
		return imm5 ? imm5 : 32;
	else if(enc_bits == 2)
		return imm5 ? imm5 : 32;
	else if(enc_bits == 3) {
		if(imm5 == 0)
			return 1;
		else
			return imm5;
	}
	return -1;
}

int BadReg(uint8_t reg)
{
	return (reg==13) || (reg==15);
}

uint64_t Replicate(uint32_t rep, uint32_t before, char before_char, uint32_t after, char after_char, uint8_t times) {
    uint64_t imm64 = 0;
    uint32_t i, time;
    for (time = 0; time < times; time++) {
        if (time > 0) {
            for (i = 0; i < before+8; i++) {
                imm64 <<= 1;
                imm64 |= before_char;
            }
        }
        imm64 |= rep;
        for (i = 0; i < after; i++) {
            imm64 <<= 1;
            imm64 |= after_char;
        }
    }
    return imm64;
}

uint32_t VFPExpandImm(uint32_t imm, uint32_t N, uint32_t lowbits) {

    uint32_t E = 0;
    if (N == 32) {
        E = 8;
    }
    else {
        E = 11;
    }
    uint32_t F = (N - E) - 1;
    uint32_t sign = (imm >> 7) & 1;
    uint32_t exp = ((imm >> 6) & 1) ^ 1;
    for (uint32_t i = 0; i < E-3; i++) {
        exp <<= 1;
        exp |= (imm >> 6) & 1;
    }
    exp <<= 2;
    exp |= (imm >> 4) & 3;
    uint32_t frac = (imm & 15);
    frac <<= F-4;
    uint32_t out = (sign << 31) | (exp << 23) | (frac);

    return out;
}

uint32_t AdvSIMDExpandImm(uint32_t op, uint32_t cmode, uint32_t imm8, uint32_t lowbits) {

    uint32_t testimm8;
    uint64_t imm64 = 0;
    uint32_t imm32 = 0;
    uint32_t i = 0;
    imm8 = imm8 & 0xff;
    switch(cmode >> 1) {
        case 0:
            testimm8 = 0;
            imm64 = Replicate(imm8, 24, 0, 0, 0, 2);
            if (lowbits) return imm64 & 0xffffffff;
            return 0;
            break;
        case 1:
            testimm8 = 1;
            imm64 = Replicate(imm8, 16, 0, 8, 0, 2);
            if (lowbits) return imm64 & 0xffffffff;
            return 0;
            break;
        case 2:
            testimm8 = 1;
            imm64 = Replicate(imm8, 8, 0, 16, 0, 2);
            if (lowbits) return imm64 & 0xffffffff;
            return 0;
            break;
        case 3:
            testimm8 = 1;
            imm64 = Replicate(imm8, 0, 0, 24, 0, 2);
            if (lowbits) return imm64 & 0xffffffff;
            return 0;
            break;
        case 4:
            testimm8 = 0;
            imm64 = Replicate(imm8, 8, 0, 0, 0, 4);
            if (lowbits) return imm64 & 0xff;
            return 0;
            break;
        case 5:
            testimm8 = 1;
            imm64 = Replicate(imm8, 0, 0, 8, 0, 4);
            if (lowbits) return imm64 & 0xffff;
            return 0;
            break;
        case 6:
            testimm8 = 1;
            if ((cmode & 1) == 0) {
                imm64 = Replicate(imm8, 16, 0, 8, 1, 2);
            }
            else {
                imm64 = Replicate(imm8, 8, 0, 16, 1, 2);
            }
            if (lowbits) return imm64 & 0xffffffff;
            return 0;
            break;
        case 7:
            testimm8 = 0;
            if ((cmode & 1) == 0 && (op & 1) == 0) {
                imm64 = Replicate(imm8, 0, 0, 0, 0, 8);
                if (lowbits) return imm8;
                return 0;
            }

            else if ((cmode & 1) == 0 && (op & 1) == 1) {
                int i, j;
                for (i = 0; i < 8; i++) {
                    for (j = 0; j < 8; j++) {
                        imm64 |= ((imm8 >> (7-i)) & 1);
                        if (i != 7 || j != 7) imm64 <<= 1;
                    }
                }
            }
            else if ((cmode & 1) == 1 && (op & 1) == 0) {
                imm32 = ((imm8 >> 7) & 1);
                imm32 <<= 1;
                imm32 |= ((imm8 >> 6) & 1) ? 0 : 1;
                for (i = 0; i < 5; i++) {
                    imm32 <<= 1;
                    imm32 |= (imm8 >> 6) & 1;
                }
                imm32 <<= 6;
                imm32 |= (imm8 & 63);
                imm32 <<= 19;
                imm64 = imm32;
            }
            else if ((cmode & 1) == 1 && (op & 1) == 1) {
                //return undefined()
            }
            break;
    }

    if (testimm8 && imm8 == 0) {
        //return undefined()
    }

    if (lowbits) return imm64 & 0xffffffff;
    return imm64 >> 32;
}

uint32_t ROR_C(uint32_t input, int shamt)
{
	shamt %= 32;
	uint32_t left = input << (32-shamt);
	uint32_t right = input >> shamt;
	return left | right;
}

uint32_t ROR_C_cout(uint32_t input, int shamt)
{
	return ROR_C(input, shamt) >> 31;
}

int ThumbExpandImm_C_imm32(uint32_t imm12, uint32_t carry_in)
{
	(void)carry_in;

	if(0 == (imm12 & 0xC00)) {
		uint32_t idx = (imm12 & 0x300)>>8;
		uint32_t tmp = imm12 & 0xFF;
		if(idx==0) {
			return tmp;
		}
		else if(idx==1) {
			return (tmp << 16) | tmp;
		}
		else if(idx==2) {
			return (tmp << 24) | (tmp << 8);
		}
		else {
			return (tmp << 24) | (tmp << 16) | (tmp << 8) | tmp;
		}
	}
	else {
		uint32_t value = 0x80 | (imm12 & 0x7F);
		uint32_t rotamt = (imm12 & 0xF80) >> 7;
		return ROR_C(value, rotamt);
	}
}

int ThumbExpandImm_C_cout(uint32_t imm12, uint32_t carry_in)
{
	if(0 == (imm12 & 0xC00)) {
		return carry_in;
	}
	else {
		uint32_t unrot_value = 0x80 | (imm12 & 0x7F);
		return ROR_C_cout(unrot_value, (imm12 & 0xF80) >> 7);
	}
}

// TODO: replace with optimized implementation
int BitCount(int x)
{
	int answer = 0;
	while(x) {
		if(x&1) answer += 1;
		x>>=1;
	}
	return answer;
}

uint32_t SignExtend(uint32_t val, int inWidth)
{
	int doExtend = val & (1 << (inWidth-1));

	if(doExtend) {
		uint32_t mask = (uint32_t)-1 ^ ((1<<inWidth)-1);
		val = mask | val;
	}

	return val;
}

void printBits(uint32_t val, int bit_width, int str_width)
{
	int left_pad = (str_width > bit_width) ? str_width - bit_width : 0;
	for(int i=0; i<left_pad; ++i) printf(" ");

	if(bit_width > 32) bit_width = 32;
	for(int i=bit_width-1; i>=0; --i)
		printf("%c", (val & (1<<i)) ? '1' : '0');
}

#if defined(__APPLE__) || defined(__MACH__)
int __attribute__((optnone)) success(void) {
	/* debugger script can break here to see path taken */
	return 0;
}
#else
int success(void) {
	return 0;
}
#endif
'''

footer = '''
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
'''

#------------------------------------------------------------------------------
# bitmask functions
#------------------------------------------------------------------------------

# convert an extended bitmask (having 0,1,x)
# example: '01xx01x' generates '(var & 0x66) == 0x22'
def bitMaskGenCheckMatch(maskEx, varName):
	#print("//bitMaskGenCheckMatch(\"%s\", \"%s\")" % (varName, maskEx))

	# if entire spec is "xx..x" then return 1 (always matches)
	if re.match(r'^x+$', maskEx): return '1'

	comparator = '=='

	mask = 0
	reqVal = 0

	for c in maskEx:
		if c == '0':
			mask = (mask << 1) | 1
			reqVal = reqVal << 1
		elif c == '1':
			mask = (mask << 1) | 1
			reqVal = (reqVal << 1) | 1
		elif c == 'x':
			mask = (mask << 1)
			reqVal = reqVal << 1
		else:
			parseError("invalid character in bitmask check \"%s\"" % maskEx)

	# fully enclosed so it can be bang inverted
	return '((%s & 0x%X)%s0x%X)' % (varName, mask, comparator, reqVal)

def measureBitmask(mask):
	if not re.match(r'^[01x]+$', mask):
		parseError("invalid bitmask \"%s\"" % mask)
	result = 0
	for c in mask:
		if c in '01':
			result += 1
	return result

#------------------------------------------------------------------------------
# bit pattern class
#------------------------------------------------------------------------------

class BitPattern:
	def __init__(self, text, width=None):
		self.text = text
		self.width = width

		# if the width is not specified, measure it ourselves
		# eg: "001,00,Rd.3,imm8.8" returns 16
		if not self.width:
			self.width = 0
			for field in text.split(','):
				# bitmasks are the size of their string width
				if re.match(r'^[01x]+$', field):
					self.width += len(field)
				# negated bitmasks are the size of their string width also
				elif re.match(r'^~[01x]+$', field):
					self.width += len(field)-1 # without the tilde
				else:
					# named fields (eg: "clue.3") are their declared size
					m = re.match(r'^[\w+]+\.(\d+)$', field)
					if m:
						self.width += int(m.group(1))
					else:
						# unpredictable bits (eg: "(0)(0)(0)(0)")
						m = re.match(r'^[\(\)01]+$', field)
						if m:
							self.width += len(field)/3
						else:
							parseError('unknown bit pattern field %s' % field)

			if self.width <= 16:
				while self.width < 16:
					self.text += 'x'
					self.width += 1
			elif self.width <= 32:
				while self.width < 32:
					self.text += 'x'
					self.width += 1
			else:
				parseError("funky size in bit pattern %s" % self.text)

		# count the number of required bits in a bit descr
		# (used for sorting by stringency)
		# example: '110xx,xxx' should score 3 while
		#		  '00000,000' should score 8 (and be tested first)
		self.stringency = 0
		for c in self.text:
			if c in '01':
				self.stringency += 1

	# generate code that checks if a variable matches this pattern
	def genCheckMatch(self, varName='instr'):
		# convert the bitPatt into a bitMASK
		# eg: 11110,i.1,1,0101,0,Rn.4,0,imm3.3,Rd.4,imm8.8
		#	  11110   x 1 0101 0 xxxx 0	   xxx xxxx xxxxxxxx

		maskPos = ''
		maskNeg = ''

		for field in self.text.split(','):
			if re.match(r'^[01x]+$', field):
				maskPos += field
				maskNeg += 'x'*len(field)
			elif re.match(r'^~[01]+$', field):
				maskPos += 'x'*(len(field)-1)
				maskNeg += field[1:]
			elif re.match(r'^[\w]+\.\d+$', field):
				# named fields (eg: "clue.3") become do-not-cares
				m = re.match(r'^[\w]+\.(\d+)$', field)
				maskPos += 'x'*int(m.group(1))
				maskNeg += 'x'*int(m.group(1))
			elif re.match(r'^[\(\)01]+$', field):
				# unpredictable fields (eg: "(0)(0)(0)(0)") are do-not-cares
				maskPos += 'x'*(len(field)/3)
				maskNeg += 'x'*(len(field)/3)
			else:
				parseError('genCheckMatch(): unknown bit extract field %s' % field)

		# scale up to the instruction size
		maskPos = maskPos + 'x'*(self.width-len(maskPos))
		maskNeg = maskNeg + 'x'*(self.width-len(maskNeg))

		# finally convert to a check
		tmp = bitMaskGenCheckMatch(maskPos, varName)
		if filter(lambda a: a!='x', maskNeg):
			tmp += ' && !'+bitMaskGenCheckMatch(maskNeg, varName)
		return tmp

	# generate code that checks if a variable has unpredictable bits in this pattern
	def genCheckUnpredictable(self, varName='instr'):
		# convert the bitPatt into a bitMASK
		# eg: 11110,i.1,1,(0)(0)(0)(0),0,Rn.4,0,imm3.3,Rd.4,imm8.8
		#	 xxxxx   x x  0  0  0  0  x xxxx x	xxx xxxx xxxxxxxx
		mask = ''
		for field in self.text.split(','):
			if re.match(r'^[01x]+$', field):
				mask += 'x'*len(field)
			else:
				# named fields (eg: "clue.3") become do-not-cares
				m = re.match(r'^[\w]+\.(\d+)$', field)
				if m:
					mask += 'x'*int(m.group(1))
				else:
					# unpredictable fields (eg: "(0)(0)(0)(0)") are what we're after
					m = re.match(r'^[\(\)01]+$', field)
					if m:
						while field:
							mask += field[1]
							field = field[3:]
					else:
						parseError('genCheckUnpredictable(): unknown bit extract field %s' % field)

		# scale up to the instruction size
		mask = mask + 'x'*(self.width-len(mask))

		# finally convert to a check
		return '!'+bitMaskGenCheckMatch(mask, varName)

	# extract bits on fields (some may have named variables)
	# returns list of (varName, length, operation) tuples
	# eg: 11110,i.1,1,(0)(0)(0)(0),0,Rn.4,0,imm3.3,Rd.4,imm8.8
	#	 ['', 5, '(instr & 0xF8000000)>>27']
	#	 ['i', 1, '(instr & 0x04000000)>>26'],
	#	 ['', 1, '(instr & 0x2000000)>>25']
	#	 ['', 1, '(instr & 0x100000)>>20']
	#	 ['Rn', 4, '(instr & 0x70000)>>16'],
	#	 ['', 1, '(instr & 0x8000)>>15']
	#	 ['imm3', 3, '(instr & 0x7000)>>12'],
	#	 ['Rd', 4, '(instr & 0xF00)>>8'],
	#	 ['imm8', 8, '(instr & 0xFF)']
	def genExtractGeneral(self, varName='instr'):
		result = []
		leftMarg = 0
		seen = {}

		for field in self.text.split(','):
			# pattern fields -> [varName, #bits]
			# eg:   'imm3.3' -> ['imm3', 3]
			varName = ''
			nBits = 0

			if re.match(r'^[01x]+$', field):
				(varName, nBits) = ('', len(field))
			else:
				# named variables
				m = re.match(r'^([\w]+)\.(\d+)$', field)
				if m:
					(varName, nBits) = (m.group(1), int(m.group(2)))

					# In a few cases, the encoding diagram contains more than one bit or field with same name. In these cases, the values of all of those bits or fields must be identical. The encoding-specific pseudocode contains a special case using the Consistent() function to specify what happens if they are not identical. Consistent() returns TRUE if all instruction bits or fields with the same name as its argument have the same value, and FALSE otherwise.
					if varName in seen:
						varName = varName + "_check"
					seen[varName] = 1

				else:
					m = re.match(r'^[\(\)01]+$', field)
					if m:
						nBits = len(field)/3
					else:
						parseError('genExtractGeneral(): unknown bit extract field %s' % field)

			# generate the extraction code (mask, shift)
			shiftAmt = self.width - (leftMarg + nBits)
			if shiftAmt < 0:
				parseError('negative shift amount')

			extract = 'instr & 0x%X' % ((2**nBits - 1) << shiftAmt)
			if shiftAmt:
				extract = '(%s)>>%d' % (extract, shiftAmt)

			# append the result
			result.append([varName, nBits, extract, field])

			# next
			leftMarg += nBits

		return result

	def genExtractToNewVars(self, mgr, varName='instr'):
		for (varName, length, bitAction, field) in self.genExtractGeneral():
			if not varName:
				continue
			mgr.add("uint%d_t %s = %s;" % (self.width, varName, bitAction))

	def genExtractToElemAssigns(self, varName='instr'):
		result = ''
		for (varName, length, bitAction, field) in self.genExtractGeneral():
			if not varName:
				continue
			fieldName = 'FIELD_' + varName
			result += "res->fields[%s] = %s;\n" % (fieldName, bitAction)
			result += "res->fields_mask[%s >> 6] |= 1LL << (%s & 63);\n" % (fieldName, fieldName)
			result += "char %s_width = %s;\n" % (varName, length)
		return result

	# generate a pretty diagram of the bit disection
	def genExtractToDrawing(self, varName='instr'):
		extractions = self.genExtractGeneral()

		# pad field names to length of printed bits, if needed
		fields = []
		for [fieldName, bitLen, code, fieldText] in extractions:
			if len(fieldText) < bitLen:
				fieldText = ' '*(bitLen - len(fieldText)) + fieldText
			fields.append(fieldText)

		dashes = map(lambda x: '-'*len(x), fields)
		# eg: printBits((instr & 0xF800)>>11, 5, 5);
		values = map(lambda x: 'printBits(%s, %d, %d); printf("|");' % \
		  (x[2], x[1], len(x[3])), extractions)
		dashLine = 'printf("+%s+\\n");' % '+'.join(dashes)

		result = []
		result.append(dashLine)
		result.append('printf("|' + '|'.join(fields) + '|\\n");')
		result.append(dashLine)
		result.append('printf("|");')
		result += values
		result.append('printf("\\n");')
		result.append(dashLine)
		return result


	# get the width of a variable from within the pattern
	def getVarWidth(self, varName):
		regex = varName + '\.(\\d)'

		#print("trying to get var: %s" % varName)
		#print("using regex: %s" % regex)

		m = re.search(regex, self.text)
		if not m: parseError('variable %s not found in pattern %s using regex %s' % \
			(varName, self.text, regex))
		return int(m.group(1))

	# pretty string representation
	def __str__(self):
		result = 'pattern="%s" width=%d stringency=%d' % \
			(self.text, self.width, self.stringency)
		return result

#------------------------------------------------------------------------------
# code generation helpers
#------------------------------------------------------------------------------

def genEncodingBlock(mgr, encName, arches, fmts, pattern, pcode):
	#print("genEncodingBlock on %s with pattern: %s" % (encName, pattern))
	#status()

	if not encName: parseError("can't generate encoding block without encoding name!")
	if not arches: parseError("can't generate encoding block without architecture!")
	if not fmts: parseError("can't generate encoding block without format!")
	if not pattern: parseError("can't generate encoding block without pattern!")
	if not pcode: parseError("can't generate encoding block without pseudocode!")

	mgr.add("/* Encoding %s */" % encName)
	mgr.add("/* %s */" % pattern)

	mgr.add('{')
	mgr.tab()
	if pattern.width == 16:
		mgr.add('uint16_t instr = req->instr_word16;')
	elif pattern.width == 32:
		# arm pipelines fetches 2 bytes "halfword" at a time
		# that's how it knows whether to stay at a single halfword (16-bit thumb) or fetch another (32-bit thumb)
		mgr.add('uint32_t instr = req->instr_word32;')
	else:
		raise Exception("invalid pattern width: %d\n", pattern.width)

	check = pattern.genCheckMatch()
	mgr.add("if(%s) {" % check)
	mgr.tab()

	if(g_DEBUG_DECOMP):
		mgr.add('')
		mgr.add('if(getenv("DEBUG_DECOMP")) {')
		mgr.tab()
		mgr.add('printf("using encoding %s\\n\");' % encName)
		mgr.add('\n'.join(pattern.genExtractToDrawing()) + '')
		mgr.untab()
		mgr.add('}')
		mgr.add('')

	# save instruction size
	mgr.add('res->instrSize = %d;' % pattern.width)

	# generate unpredictable bits check (like "..,(0)(0)(0)(0),...")
	check = pattern.genCheckUnpredictable()
	if not check in ['0','1','!0','!1']:
		mgr.add('if(%s) {' % check)
		mgr.tab()
		mgr.add('res->flags |= FLAG_UNPREDICTABLE;')
		mgr.untab()
		mgr.add('}')

	# generate architecture check
	checks = []
	for arch in arches.split(', '):
		checks.append('!(req->arch & ARCH_%s)' % string.replace(arch, '*', ''))
	mgr.add("if(%s) {" % ' && '.join(checks))
	mgr.tab()
	mgr.add('res->status |= STATUS_ARCH_UNSUPPORTED;')
	mgr.untab()
	mgr.add('}')

	# save the named fields within the bits
	temp = pattern.genExtractToElemAssigns()

	# if 'c' or 'cond'  wasn't in the pattern, mark the condition code as always
	if not re.search(r'c\.\d+', pattern.text) and \
		not re.search(r'cond\.\d+', pattern.text):
		fieldName = 'FIELD_cond'
		mgr.add('res->fields[%s] = COND_AL;' % fieldName)
		mgr.add("res->fields_mask[%s >> 6] |= 1LL << (%s & 63);" % (fieldName, fieldName))
	#print("at line " + str(g_lineNum) + " trying to indent: %s" % temp)

	if temp:
		mgr.add(temp)

	# save formats in the result
	mgr.add("static const instruction_format instr_formats[] = ")
	mgr.add('{')
	mgr.tab()
	for fmt in fmts:
		if ' ' not in fmt:
			operation = fmt.lower()
			operandsStr = ""
		else:
			operation = fmt[:fmt.index(' ')].lower()
			operandsStr = fmt[fmt.index(' ') + 1:].strip()

		flags = "0"
		if ".<type><size>" in operation:
			flags += "|INSTR_FORMAT_FLAG_NEON_TYPE_SIZE"
			operation = operation.replace(".<type><size>", "")
		if "<c>.<size>" in operation:
			flags += "|INSTR_FORMAT_FLAG_CONDITIONAL"
			flags += "|INSTR_FORMAT_FLAG_NEON_SIZE"
			operation = operation.replace("<c>.<size>", "")
		if "<size>" in operation:
			flags += "|INSTR_FORMAT_FLAG_NEON_SINGLE_SIZE"
			operation = operation.replace("<size>", "")
		if "<c>.<dt>" in operation:
			flags += "|INSTR_FORMAT_FLAG_CONDITIONAL"
			flags += "|INSTR_FORMAT_FLAG_VFP_DATA_SIZE"
			operation = operation.replace("<c>.<dt>", "")
		if ".<dt>" in operation:
			flags += "|INSTR_FORMAT_FLAG_VFP_DATA_SIZE"
			operation = operation.replace(".<dt>", "")
		if "<c>" in operation:
			flags += "|INSTR_FORMAT_FLAG_CONDITIONAL"
			if "<c>." in operation:
				size = operation.split("<c>")[1].split()[0][1:].upper()
				if size in ["F16", "F32", "F64"]:
					flags += "|INSTR_FORMAT_FLAG_" + size
			operation = operation.replace("<c>", "")
		if "{s}" in operation:
			flags += "|INSTR_FORMAT_FLAG_OPTIONAL_STATUS"
			operation = operation.replace("{s}", "")
		if "<effect>" in operation:
			flags += "|INSTR_FORMAT_FLAG_EFFECT"
			operation = operation.replace("<effect>", "")
		if "<mask>" in operation:
			flags += "|INSTR_FORMAT_FLAG_MASK"
			operation = operation.replace("<mask>", "")
		if ".w" in operation:
			flags += "|INSTR_FORMAT_FLAG_WIDE"
			operation = operation.replace(".w", "")
		if "{ia}" in operation:
			flags += "|INSTR_FORMAT_FLAG_INCREMENT_AFTER"
			operation = operation.replace("{ia}", "")
		if "{<amode>}" in operation:
			flags += "|INSTR_FORMAT_FLAG_AMODE"
			operation = operation.replace("{<amode>}", "")

		mgr.add('{ /* %s */' % fmt)
		mgr.tab()
		mgr.add('"%s", /* .operation (const char *) */' % operation)
		mgr.add('%s, /* .operationFlags (uint32_t) */' % flags)
		mgr.add('{/* .operands (instruction_operand_format) */')
		mgr.tab()

		i = 0
		operandCount = 0

		# operands is the half of the format string following the first whitespace
		# eg: MOV <Rd>,<Rn>,#<imm32>
		#
		#  then operation = 'MOV'
		#  then    format = '<Rd>,<Rn>,#<imm32>
		#print('  operation: %s' % operation)
		#print('operandsStr: %s' % operandsStr)

		# split the string into operands
		operands = []
		tok_regexs = [r'^<.*?>(!|{!})?', r'^#<\+/-><.*?>', r'^#<.*?>', \
		  r'^{.*?}', r'^\[.*?\]!?', r'^\w+({!})?', r'^#\d+']
		while operandsStr:
			did_split = False

			if operandsStr[0] == ',':
				operandsStr = operandsStr[1:]
				continue

			for regex in tok_regexs:
				m = re.match(regex, operandsStr)
				if m:
					operands.append(m.group(0))
					operandsStr = operandsStr[len(m.group(0)):]
					did_split = True
					break

			if not did_split:
				raise Exception('don\'t know how to split next operand on: %s' % operandsStr)

		# loop over operands
		for operand in operands:
			wb_id = ['WRITEBACK_NO', 'WRITEBACK_YES'][operand[-1]=='!']

			#print('  operand: %s' % operand)

			#
			# Rn
			#
			if operand == "[<Rn>]":
				mgr.add('{OPERAND_FORMAT_MEMORY_ONE_REG,FIELD_Rn,FIELD_UNINIT,"","",%s},' % wb_id)
				continue
			m = re.match(r'^\[<Rn>,#<\+/-><(.*)>]!?$', operand)
			if m:
				name = m.group(1)
				mgr.add('{OPERAND_FORMAT_MEMORY_ONE_REG_ADD_IMM,FIELD_Rn,FIELD_%s,"","",%s},' % (name, wb_id))
				continue
			if operand.startswith('[<Rn>,#<align>]'):
				mgr.add('{OPERAND_FORMAT_MEMORY_ONE_REG_ALIGNED,FIELD_Rn,FIELD_UNINIT,"","",%s},' % wb_id)
				continue
			m = re.match(r'^\[<Rn>,#<(.*)>\]!?$', operand)
			if m:
				name = m.group(1)
				mgr.add('{OPERAND_FORMAT_MEMORY_ONE_REG_IMM,FIELD_Rn,FIELD_%s,"","",%s},' % (name, wb_id))
				continue
			m = re.match(r'^\[<Rn>,#-<(.*)>\]!?$', operand)
			if m:
				name = m.group(1)
				mgr.add('{OPERAND_FORMAT_MEMORY_ONE_REG_NEG_IMM,FIELD_Rn,FIELD_%s,"","",%s},' % (name, wb_id))
				continue
			m = re.match(r'^\[<Rn>{,#<\+/-><(.*)>}\]!?', operand)
			if m:
				name = m.group(1)
				mgr.add('{OPERAND_FORMAT_MEMORY_ONE_REG_OPTIONAL_ADD_IMM,FIELD_Rn,FIELD_%s,"","",%s},' % (name, wb_id))
				continue
			m = re.match(r'^\[<Rn>{,#<(.*)>}\]$', operand)
			if m:
				name = m.group(1)
				mgr.add('{OPERAND_FORMAT_MEMORY_ONE_REG_OPTIONAL_IMM,FIELD_Rn,FIELD_%s,"","",%s},' % (name, wb_id))
				continue
			if operand.startswith("[<Rn>,<Rm>]"):
				if i < len(operand) and operand[i] == "!":
					mgr.add('{OPERAND_FORMAT_MEMORY_TWO_REG,FIELD_Rn,FIELD_Rm,"","",WRITEBACK_YES},')
				else:
					mgr.add('{OPERAND_FORMAT_MEMORY_TWO_REG,FIELD_Rn,FIELD_Rm,"","",WRITEBACK_NO},')
				continue
			if operand.startswith("[<Rn>,<Rm>{,<shift>}]"):
				if i < len(operand) and operand[i] == "!":
					mgr.add('{OPERAND_FORMAT_MEMORY_TWO_REG_SHIFT,FIELD_Rn,FIELD_Rm,"","",WRITEBACK_YES},')
				else:
					mgr.add('{OPERAND_FORMAT_MEMORY_TWO_REG_SHIFT,FIELD_Rn,FIELD_Rm,"","",WRITEBACK_NO},')
				continue
			if operand.startswith("[<Rn>,<Rm>,LSL #1]"):
				if i < len(operand) and operand[i] == "!":
					mgr.add('{OPERAND_FORMAT_MEMORY_TWO_REG_LSL_ONE,FIELD_Rn,FIELD_Rm,"","",WRITEBACK_YES},')
				else:
					mgr.add('{OPERAND_FORMAT_MEMORY_TWO_REG_LSL_ONE,FIELD_Rn,FIELD_Rm,"","",WRITEBACK_NO},')
				continue
			if operand.startswith("<Rn>!"):
				mgr.add('{OPERAND_FORMAT_REG,FIELD_Rn,FIELD_UNINIT,"","",WRITEBACK_YES},')
				continue
			if operand.startswith("<Rn>{!}"):
				mgr.add('{OPERAND_FORMAT_REG,FIELD_Rn,FIELD_UNINIT,"","",WRITEBACK_OPTIONAL},')
				continue
			#
			# SP
			#
			m = re.match(r'^\[SP,#<(.*)>\]$', operand)
			if m:
				name = m.group(1)
				mgr.add('{OPERAND_FORMAT_MEMORY_SP_IMM,FIELD_%s,FIELD_UNINIT,"","",%s},' % (name, wb_id))
				continue
			m = re.match(r'^\[SP{,#<(.*)>}\]', operand)
			if m:
				name = m.group(1)
				mgr.add('{OPERAND_FORMAT_MEMORY_SP_OPTIONAL_IMM,FIELD_%s,FIELD_UNINIT,"","",%s},' % (name, wb_id))
				continue
			if operand.startswith("SP{!}"):
				mgr.add('{OPERAND_FORMAT_SP,FIELD_UNINIT,FIELD_UNINIT,"sp","",WRITEBACK_OPTIONAL},')
				continue
			if operand.startswith("SP"):
				mgr.add('{OPERAND_FORMAT_SP,FIELD_UNINIT,FIELD_UNINIT,"sp","",WRITEBACK_NO},')
				continue
			#
			# PC
			#
			if operand.startswith("[PC]"):
				mgr.add('{OPERAND_FORMAT_MEMORY_PC,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},')
				continue
			if operand.startswith("PC"):
				mgr.add('{OPERAND_FORMAT_PC,FIELD_UNINIT,FIELD_UNINIT,"pc","",WRITEBACK_NO},')
				continue
			if operand.startswith("LSL #1"):
				mgr.add('{OPERAND_FORMAT_LSL_ONE,FIELD_UNINIT,FIELD_UNINIT,"lsl #1","",WRITEBACK_NO},')
				continue
			if operand.startswith("#0"):
				mgr.add('{OPERAND_FORMAT_ZERO,FIELD_UNINIT,FIELD_UNINIT,"#0","",WRITEBACK_NO},')
				continue
			if operand.startswith("<barrier_option>"):
				mgr.add('{OPERAND_FORMAT_BARRIER_OPTION,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},')
				continue
			if operand.startswith("LR"):
				mgr.add('{OPERAND_FORMAT_LR,FIELD_UNINIT,FIELD_UNINIT,"lr","",WRITEBACK_NO},')
				continue
			if operand.startswith("#<imm64>"):
				mgr.add('{OPERAND_FORMAT_IMM64,FIELD_UNINIT,FIELD_UNINIT,"#","",WRITEBACK_NO},')
				continue
			m = re.match(r'^<(imm.*)>$', operand)
			if m:
				name = m.group(1)
				mgr.add('{OPERAND_FORMAT_IMM,FIELD_%s,FIELD_UNINIT,"#","",WRITEBACK_NO},' % (name))
				continue
			if operand[i:4] in ['<Qd>', '<Qm>', '<Qn>', '<Dd>', '<Dm>', '<Dn>', '<Sd>', '<Sm>', '<Sn>']:
				name = operand[2]
				mgr.add('{OPERAND_FORMAT_REG_FP,FIELD_%s,FIELD_UNINIT,"%s","",WRITEBACK_OPTIONAL},' % (name, operand[1].lower()))
				continue
			if operand[i:7] in ['<Qd[x]>', '<Qm[x]>', '<Qn[x]>', '<Dd[x]>', '<Dm[x]>', '<Dn[x]>', '<Sd[x]>', '<Sm[x]>', '<Sn[x]>']:
				name = operand[2]
				mgr.add('{OPERAND_FORMAT_REG_INDEX,FIELD_%s,FIELD_x,"%s","",WRITEBACK_OPTIONAL},' % (name, operand[1].lower()))
				continue
			if operand.startswith('<fpscr>'):
				mgr.add('{OPERAND_FORMAT_FPSCR,FIELD_FPSCR,FIELD_UNINIT,"","",WRITEBACK_OPTIONAL},')
				continue
			if operand.startswith('<Rt_mrc>'):
				mgr.add('{OPERAND_FORMAT_RT_MRC,FIELD_Rt_mrc,FIELD_UNINIT,"","",WRITEBACK_NO},')
				continue
			if operand.startswith('apsr'):
				mgr.add('{OPERAND_FORMAT_SPEC_REG,FIELD_UNINIT,FIELD_UNINIT,"apsr","",WRITEBACK_NO},')
				continue
			# here is generic register catcher
			# make sure any special register cases (eg: "<Rt_mrc>" you have come before this)
			m = re.match(r'^<(R.*)>$', operand)
			if m:
				name = m.group(1)
				mgr.add('{OPERAND_FORMAT_REG,FIELD_%s,FIELD_UNINIT,"","",WRITEBACK_NO},' % name)
				continue
			if operand.startswith("<coproc>"):
				mgr.add('{OPERAND_FORMAT_COPROC,FIELD_coproc,FIELD_UNINIT,"","",WRITEBACK_NO},')
				continue
			m = re.match(r'^<(CR.*)>$', operand)
			if m:
				name = m.group(1)
				mgr.add('{OPERAND_FORMAT_COPROC_REG,FIELD_%s,FIELD_UNINIT,"","",WRITEBACK_NO},' % name)
				continue
			if operand.startswith("<registers>"):
				mgr.add('{OPERAND_FORMAT_REGISTERS,FIELD_registers,FIELD_UNINIT,"","",WRITEBACK_NO},')
				continue
			if operand.startswith("<registers[]>"):
				mgr.add('{OPERAND_FORMAT_REGISTERS,FIELD_registers,FIELD_UNINIT,"","[]",WRITEBACK_NO},')
				continue
			if operand.startswith("<registers_indexed>"):
				mgr.add('{OPERAND_FORMAT_REGISTERS_INDEXED,FIELD_registers_indexed,FIELD_UNINIT,"","",WRITEBACK_NO},')
				continue
			if operand.startswith("<list>"):
				mgr.add('{OPERAND_FORMAT_LIST,FIELD_list,FIELD_UNINIT,"","",WRITEBACK_NO},')
				continue
			if operand.startswith("<E>"):
				mgr.add('{OPERAND_FORMAT_ENDIAN,FIELD_E,FIELD_UNINIT,"","",WRITEBACK_NO},')
				continue
			if operand.startswith("{,<shift>}"):
				mgr.add('{OPERAND_FORMAT_SHIFT,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},')
				continue
			if operand.startswith('{,<rotation>}'):
				mgr.add('{OPERAND_FORMAT_ROTATION,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},')
				continue
			if operand.startswith("<effect>"):
				mgr.add('{OPERAND_FORMAT_EFFECT,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},')
				continue
			if operand.startswith("<iflags>"):
				mgr.add('{OPERAND_FORMAT_IFLAGS,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},')
				continue
			if operand.startswith("<firstcond>"):
				mgr.add('{OPERAND_FORMAT_FIRSTCOND,FIELD_firstcond,FIELD_UNINIT,"","",WRITEBACK_NO},')
				continue
			if operand.startswith("<label>"):
				mgr.add('{OPERAND_FORMAT_LABEL,FIELD_UNINIT,FIELD_UNINIT,"","",%s},' % wb_id)
				continue
			if operand.startswith("<spec_reg>"):
				mgr.add('{OPERAND_FORMAT_SPEC_REG,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},')
				continue
			m = re.match(r'^#<\+/-><(.*)>$', operand)
			if m:
				name = m.group(1)
				mgr.add('{OPERAND_FORMAT_ADD_IMM,FIELD_%s,FIELD_UNINIT,"#","",WRITEBACK_NO},' % name)
				continue
			m = re.match(r'^{#<\+/><(.*)>}$', operand)
			if m:
				name = m.group(1)
				mgr.add('{OPERAND_FORMAT_OPTIONAL_ADD_IMM,FIELD_%s,FIELD_UNINIT,"#","",WRITEBACK_NO},' % name)
				continue
			if operand.startswith("{,<"):
				name = operand[3:operand.index('>',i+3)]
				mgr.add('{OPERAND_FORMAT_OPTIONAL_IMM,FIELD_%s,FIELD_UNINIT,"","",WRITEBACK_NO},' % name)
				continue
			if operand.startswith("{,#<"):
				name = operand[4:operand.index('>',i+4)]
				mgr.add('{OPERAND_FORMAT_OPTIONAL_IMM,FIELD_%s,FIELD_UNINIT,"#","",WRITEBACK_NO},' % name)
				continue
			if operand.startswith('<coproc_option>'):
				mgr.add('{OPERAND_FORMAT_IMM,FIELD_imm8,FIELD_UNINIT,"{","}",WRITEBACK_NO},')
				continue
			# this fallback is that <whatever> becomes FIELD_whatever prefixed with "whatever"
			m = re.match(r'^#<([\w\d]+)>$', operand)
			if m:
				name = m.group(1)
				mgr.add('{OPERAND_FORMAT_IMM,FIELD_%s,FIELD_UNINIT,"#","",WRITEBACK_NO},' % name)
				continue

			raise Exception("dunno how to handle -%s- in operands" % operand)

		mgr.add('{OPERAND_FORMAT_END,FIELD_UNINIT,FIELD_UNINIT,"","",WRITEBACK_NO},')
		mgr.untab()
		mgr.add('},')
		mgr.add('%d /* .operandCount */' % len(operands))
		mgr.untab()
		mgr.add('},')

	mgr.untab()
	mgr.add("}; /* ENDS instruction_format array */")
	mgr.add('')
	mgr.add("res->formats = instr_formats;")
	mgr.add("res->formatCount = %d;" % len(fmts))

	# save mnemonic in the result
	m = re.match(r'^(\w+).*$', fmts[0])
	if not m:
		parseError("couldn't extract mnemonic!")
	mgr.add("res->mnem = armv7::ARMV7_%s;" % m.group(1))
	mgr.add('')

	if 0:
		print('----------------')
		print('sending pcode: ' + repr(pcode))
		print('----------------')
	temp = codegencpp.genBlock('\n'.join(pcode))
	if temp:
		mgr.add(temp)
		mgr.add("")

	# matched? made it this far? we're done
	mgr.add("return success();")

	# done
	mgr.untab()
	mgr.add('} /* ENDS if(<encoding_match_test>) ... */')
	mgr.untab()
	mgr.add('} /* ENDS single encoding block */')
	mgr.add('')

#------------------------------------------------------------------------------
# misc
#------------------------------------------------------------------------------

def parseError(msg):
	raise Exception(msg)

	global g_lines, g_lineNum

	if g_lineNum >= len(g_lines):
		line = g_lines[len(g_lines)-1]
	else:
		line = g_lines[g_lineNum]

	lineNumHuman = g_lineNum+1
	raise Exception('line %d: %s\n%s' % (lineNumHuman, line, msg))

def status():
	global g_lines, g_lineNum
	line = g_lines[g_lineNum]
	lineNumHuman = g_lineNum+1
	print("parser status: on line %d (\"%s\")" % (lineNumHuman, line))

# count the number of required bits in a bit descr
# (used for sorting by stringency)
# edge is a 2-tuple (descrs, nextNode)
# example: ('110xx,xxx', 'sub_imm') should score 3 while
#		  ('00000,000', 'sub_reg') should score 8 (and be tested first)
def edgeStringency(edge):
	bitDescrs = edge[0]
	count = 0
	for c in bitDescrs:
		if c in '01':
			count += 1

	#print("//for \"%s\" calculated stringency %d" % (bitDescr, count))
	return count

# allows you to easily write code, keeping track of tab level, indents, etc.
# keep track of indents and stuff for you
class CodeManager:
	def __init__(self):
		self.lines = []
		self.indentLevel = 0
		pass

	def tab(self):
		self.indentLevel += 1

	def untab(self):
		assert self.indentLevel > 0
		self.indentLevel -= 1

	def add(self, code):
		lines = code.split('\n')
		lines = map(lambda x: x.rstrip(), lines)

		lines2 = []
		for line in lines:
			if line=='' or line.isspace():
				lines2.append('')
			else:
				lines2.append('%s%s' % (self.indentLevel * '\t', line))

		self.lines += lines2

	def __str__(self):
		return '\n'.join(self.lines)

#------------------------------------------------------------------------------
# parsing state machine
#------------------------------------------------------------------------------

# INPUT:
#	    mgr: the CodeMgr to generate to
#  nodeName: the name of the node, eg: "add"
#     lines: the code from spec.txt for this node
# OUTPUT:
#    (none): code was added to mgr
#
def gen_node(mgr, nodeName, lines):
	# state machine vars
	onVars = []
	edges = []
	state = 'inNode'

	# generate the code for the node
	crc = binascii.crc32((''.join(lines)).encode('utf-8')) & 0xFFFFFFFF
	mgr.add('// gen_crc: %08X' % crc)
	mgr.add("int %s(struct decomp_request *req, struct decomp_result *res)" % nodeName)
	mgr.add("{")
	mgr.tab()

	mgr.add("int rc = -1;")
	mgr.add('')

	# propogate debug decompose code into generated C
	if(g_DEBUG_DECOMP):
		mgr.add('if(getenv("DEBUG_DECOMP"))')
		mgr.tab()
		mgr.add('printf("%s()\\n\", __func__);')
		mgr.add('')
		mgr.untab()

	mgr.add('res->group = INSN_GROUP_UNKNOWN;')

	# state inTerminal variables
	(itEncName, itArches, itFormats, itPattern, itPcode) = [None]*5

	# state machine start
	lineNum = 0
	while lineNum < len(lines):
		# get new line
		line = lines[lineNum]
		advanceLine = 1
		skipLine = 0

		# comments
		if re.match(r'^\/\/.*$', line):
			lineNum += 1
			continue

		# high priority directives
		if re.match(r'^cpp (.*)$', line):
			mgr.add(line[4:] + '')
			lineNum += 1
			continue

		elif state == 'inNode':
			m = re.match(r'^extract(\d\d) (.*)$', line)
			if m:
				pattern = BitPattern(m.group(2), int(m.group(1)))

				if pattern.width == 16:
					mgr.add('uint16_t instr = req->instr_word16;')
				elif pattern.width == 32:
					mgr.add('uint32_t instr = req->instr_word32;')
				else:
					raise Exception("invalid pattern width: %d\n", pattern.width)

				pattern.genExtractToNewVars(mgr)

				if g_DEBUG_DECOMP:
					mgr.add('\nif(getenv("DEBUG_DECOMP")) {')
					mgr.tab()
					mgr.add('\n'.join(pattern.genExtractToDrawing()) + '')
					mgr.untab()
					mgr.add('}')
					mgr.add('')

			m = re.match(r'group ([\w\d]+)', line)
			if m:
				insnGroup = m.group(1)

				lookup = { 'UNKNOWN':'INSN_GROUP_UNKNOWN',
					'JUMP':'INSN_GROUP_JUMP', 'CRYPTO':'INSN_GROUP_CRYPTO',
					'DATABARRIER':'INSN_GROUP_DATABARRIER', 'DIVIDE':'INSN_GROUP_DIVIDE',
					'FPARMV8':'INSN_GROUP_FPARMV8', 'MULTPRO':'INSN_GROUP_MULTPRO',
					'NEON':'INSN_GROUP_NEON', 'T2EXTRACTPACK':'INSN_GROUP_T2EXTRACTPACK',
					'THUMB2DSP':'INSN_GROUP_THUMB2DSP', 'TRUSTZONE':'INSN_GROUP_TRUSTZONE',
					'V4T':'INSN_GROUP_V4T', 'V5T':'INSN_GROUP_V5T',
					'V5TE':'INSN_GROUP_V5TE', 'V6':'INSN_GROUP_V6',
					'V6T2':'INSN_GROUP_V6T2', 'V7':'INSN_GROUP_V7',
					'V8':'INSN_GROUP_V8', 'VFP2':'INSN_GROUP_VFP2',
					'VFP3':'INSN_GROUP_VFP3', 'VFP4':'INSN_GROUP_VFP4',
					'ARM':'INSN_GROUP_ARM', 'MCLASS':'INSN_GROUP_MCLASS',
					'NOTMCLASS':'INSN_GROUP_NOTMCLASS', 'THUMB':'INSN_GROUP_THUMB',
					'THUMB1ONLY':'INSN_GROUP_THUMB1ONLY', 'THUMB2':'INSN_GROUP_THUMB2',
					'PREV8':'INSN_GROUP_PREV8', 'FPVMLX':'INSN_GROUP_FPVMLX',
					'MULOPS':'INSN_GROUP_MULOPS', 'CRC':'INSN_GROUP_CRC',
					'DPVFP':'INSN_GROUP_DPVFP', 'V6M':'INSN_GROUP_V6M'
				}

				mgr.add('res->group = %s;' % lookup[insnGroup])

			# eg "on opcode,clue"
			m = re.match(r'^on (.*)$', line)
			if m:
				onVars = m.group(1).split(',')
				if g_DEBUG_GEN:
					mgr.add('// changed state to inEdges')
				state = 'inEdges'

			# if first statement of node is "Encoding" then this is a terminal node, switch state
			m = re.match(r'Encoding ([\w\d]+) (.*)', line)
			if m:
				[itEncName, itArches, itFormats, itPattern, itPcode] = [None]*5
				state = 'inTerminal'
				if g_DEBUG_DECOMP:
					mgr.add("// changed state to inTerminal")
				advanceLine = False

		# state "inTerminal" expects:
		# Encoding ...
		# fmt      ...
		# extract  ...
		# pcode    ...
		# (multiple reptitions, ended by whitespace line)
		elif state == 'inTerminal':
			if line[0:9] == 'Encoding ':
				# flush work from previous "Encoding"
				if itEncName or itArches or itFormats or itPattern or itPcode:
					genEncodingBlock(mgr, itEncName, itArches, itFormats, itPattern, itPcode)

				# start new "Encoding" work
				m = re.match(r'Encoding ([\w\d]+) (.*)', line)
				(itEncName, itArches) = m.group(1,2)
				[itFormats, itPattern, itPcode] = [[], '', []]

			elif line[0:4] == 'fmt ':
				m = re.match(r'fmt (.*)', line)
				itFormats.append(m.group(1))

			elif line[0:7] == 'extract':
				m = re.match(r'extract(\d\d) (.*)', line)
				itPattern =  BitPattern(m.group(2), int(m.group(1)))

			elif line[0:6] == 'pcode ':
				m = re.match(r'pcode (.*)', line)
				itPcode.append(m.group(1))

			elif line[0:11] == 'pcode_start':
				itPcode = []
				lineNum += 1
				while lines[lineNum] != 'pcode_end':
					itPcode.append(lines[lineNum])
					lineNum += 1
			else:
				parseError('unexpected line -%s- in state: inTerminal' % line)

			if lineNum == len(lines)-1:
				genEncodingBlock(mgr, itEncName, itArches, itFormats, itPattern, itPcode)

				mgr.add('/* if fall-thru here, no encoding block matched */')
				mgr.add('return undefined(req, res);')
				mgr.untab()
				mgr.add('}')

				[itEncName, itArches, itFormats, itPattern, itPcode] = [None]*5
				state = 'waiting'
				if g_DEBUG_DECOMP:
					mgr.add("// on line: %s" % line)
					mgr.add("// changed state to waiting")
		# state where we collect edges like:
		# "000xx,xxx lsl_imm"
		# "010xx,xxx whatever"
		# ...
		elif state == 'inEdges':
			# collect passively
			if re.match(r'^[~01,x]+ \w+$', line):
				m = re.match(r'^([~01,x]+) (\w+)$', line)

				descrs = m.group(1) # like "010xx,000"
				nextNode = m.group(2) # like lsl_imm

				if len(descrs.split(',')) != len(onVars):
					parseError("variable requirement mismatch")

				edges.append((descrs, nextNode))

				# if the last edge description, generate!
				if lineNum == len(lines)-1:
					# edges like:
					# ('010xx,xxx', 'asr_imm')
					# ('01100,xxx', 'add_reg')
					# ('01101,xxx', 'sub_reg')
					# ...
					# sort the bit descriptions so that the most stringent are tested first
					edges = sorted(edges, key=lambda edge: BitPattern(edge[0]).stringency, reverse=True)

					for edge in edges:
						(maskList, nextNode) = edge
						masks = maskList.split(',')

						checks = []
						for (i, mask) in enumerate(masks):
							varName = onVars[i]

							if mask[0] == '~':
								checks.append('!' + bitMaskGenCheckMatch(mask[1:], varName))
							else:
								checks.append(bitMaskGenCheckMatch(mask, varName))

						# collapse all '1's into a single 1
						trues = filter(lambda x: x=='1', checks)
						if trues:
							others = filter(lambda x: x!='1', checks)
							checks = others + ['1']

						# and generate the code
						mgr.add('if(%s) return %s(req, res);' %
							(' && '.join(checks), nextNode))

					onVars = []
					edges = []

					mgr.add('return undefined(req, res);')
					mgr.untab()
					mgr.add('}')

			else:
				parseError('unexpected line in state: inEdges')

		if skipLine:
			mgr.add("// skipping for now: %s" % line)

		if advanceLine:
			lineNum += 1

#------------------------------------------------------------------------------
# "main"
#------------------------------------------------------------------------------
if __name__ == '__main__':
	if ('DEBUG_DECOMP' in os.environ) or ('DEBUG_ALL' in os.environ):
		print('generator.py: g_DEBUG_DECOMP on! generating optional printf()\'s')
		g_DEBUG_DECOMP = 1

	# read file
	print('collecting nodes from spec.txt')
	fp = open('spec.txt', 'r')
	lines = fp.readlines()
	fp.close()

	# first pass: filter comments, clean up lines, group lines with node names, crc
	lines = map(lambda x: x.rstrip(), lines)
	lines = map(lambda x: x.replace('\xe2\x80\x98', '\''), lines) # smart quote
	lines = map(lambda x: x.replace('\xe2\x80\x99', '\''), lines)
	node2lines = {}
	(curNodeName, curNodeLines) = ('', [])
	for i,line in enumerate(lines):
		if re.match(r'^\/\/.*', line):
			continue
		elif not line:
			if curNodeName:
				node2lines[curNodeName] = curNodeLines
				(curNodeName, curNodeLines) = ('', [])
		elif re.match(r'^\w+:$', line):
			if curNodeName:
				raise Exception('got node name when processing other node, line %d: %s' % (i+1,line))
			(curNodeName, curNodeLines) = (line[0:-1], [])
		else:
			if not curNodeName:
				raise Exception('got stray line outside node, line %d: %s' % (i+1,line))
			curNodeLines.append(line)
	if curNodeName:
		node2lines[curNodeName] = curNodeLines
	node2crc = {}
	for node in node2lines.keys():
		node2crc[node] = binascii.crc32((''.join(node2lines[node])).encode('utf-8')) & 0xFFFFFFFF

	# open spec.cpp, read the crc's of generated functions (detecting if they need regen)
	print('collecting functions from spec.cpp')
	fp = open('spec.cpp', 'r')
	lines = fp.readlines()
	fp.close()

	lines = list(map(lambda x: x.rstrip(), lines))
	funcInfo = {}
	i = 0
	while i < len(lines):
		m = re.match(r'^// gen_crc: (........).*', lines[i])
		if not m:
			i += 1
			continue
		crc = int(m.group(1), 16)
		m = re.match(r'^int ([\w\d]+)\(.*$', lines[i+1])
		if not m:
			raise Exception('did not find function after crc line %d: %s' % (i+1,lines[i]))
		name = m.group(1)
		start = i
		while lines[i] != '}':
			i += 1
		funcInfo[name] = {'crc':crc, 'lines':'\n'.join(lines[start:i+1])}
		#print('found that %s has crc %08X' % (name, crc))

	# construct the new file
	mgr = CodeManager()
	mgr.add(header)
	mgr.add('/* forward declarations */')
	for node in sorted(node2lines.keys()):
		mgr.add('int %s(struct decomp_request *req, struct decomp_result *res);' % node)
	mgr.add(support)

	count = 0
	forceGen = 'force' in sys.argv
	# for every node that doesn't have a matching function, generate!
	for node in sorted(node2lines.keys()):
		nodeCrc = node2crc[node]
		funcCrc = None
		if node in funcInfo:
			funcCrc = funcInfo[node]['crc']

		print(node.ljust(48),)

		if forceGen:
			print('CRC ignored (force gen) generating')
			gen_node(mgr, node, node2lines[node])
		elif funcCrc == node2crc[node]:
			print('CRC match (%08X)        recycling' % funcCrc)
			mgr.add(funcInfo[node]['lines'])
		else:
			if funcCrc:
				print("CRC mismatch (%08X != %08X) generating" % (funcCrc, nodeCrc))
			else:
				print('CRC missing                 generating')
			gen_node(mgr, node, node2lines[node])
		mgr.add('')

	mgr.add('')
	mgr.add(footer)

	with open('spec.cpp', 'w') as fp:
		fp.write(str(mgr))


