#!/usr/bin/python

import re
import os
import sys

from parse import pcodeParser, pcodeSemantics

DEBUG = 0

###############################################################################
# misc utils
###############################################################################

# convert "MOV (register)" text to the function that handles it
#       ->"mov_register"
def convertHandlerName(name):
    # non-word chars to underscore
    name = re.sub(r'[^\w]', '_', name)
    # no leading or trailing underscore
    name = re.sub(r'^_*(.*?)_*$', r'\1', name)
    # no multiple underscore runs
    name = re.sub(r'_+', '_', name)
    # lowercase
    name = name.lower()
    return name

def applyIndent(text, level=0):
    savedTrailingWhitespace = ''
    while len(text)>0 and text[-1].isspace():
        savedTrailingWhitespace = text[-1] + savedTrailingWhitespace
        text = text[0:-1]
    text = text.rstrip()
    spacer = '\t' * level
    lines = text.split('\n')
    lines = map(lambda s: '%s%s' % (spacer, s), lines)
    return '\n'.join(lines) + savedTrailingWhitespace

###############################################################################
# "better" nodes ... cleaned up AST nodes that can eval() themselves
###############################################################################

class BetterNode(object):
    def __init__(self, name, children=[], semicolon=False):
        self.name = name
        self.children = children
        self.semicolon = semicolon

    def gen(self, extra=''):
        # leaf nodes (no possible descent)
        if self.name == 'ident':
            tmp = (self.children[0] + extra).replace('.', '_')
            if not tmp.startswith('FIELD_'):
                tmp = 'FIELD_' + tmp
            code = 'res->fields[%s]' % tmp
        elif self.name == 'rawtext':
            code = self.children[0]
        elif self.name == 'number':
            code = self.children[0]
        elif self.name == 'bits':
            code = '0x%X' % int(self.children[0], 2)
        elif self.name == 'see':
            code = '\nmemset(res, 0, sizeof(*res));'
            code = '\nreturn %s(req, res);' % self.children[0]
            self.semicolon = 0
        else:
            subCode = map(lambda x: x.gen(), self.children)
            subCode = tuple(subCode)

            # binary operations translate directly to C
            if self.name == 'xor':
                assert len(self.children) == 2
                code = '(%s) ^ (%s)' % subCode
            elif self.name == 'add':
                assert len(self.children) == 2
                code = '(%s) + (%s)' % subCode
            elif self.name == 'sub':
                assert len(self.children) == 2
                code = '(%s) - (%s)' % subCode
            elif self.name == 'less_than':
                assert len(self.children) == 2
                code = '(%s) < (%s)' % subCode
            elif self.name == 'greater_than':
                assert len(self.children) == 2
                code = '(%s) > (%s)' % subCode
            elif self.name == 'log_and':
                assert len(self.children) == 2
                code = '(%s) && (%s)' % subCode
            elif self.name == 'log_or':
                assert len(self.children) == 2
                code = '(%s) || (%s)' % subCode
            elif self.name == 'log_not':
                assert len(self.children) == 1
                code = '!(%s)' % subCode
            elif self.name == 'equals':
                assert len(self.children) == 2
                code = '(%s) == (%s)' % subCode
            elif self.name == 'not_equals':
                assert len(self.children) == 2
                code = '(%s) != (%s)' % subCode
            elif self.name == 'less_than_or_equals':
                assert len(self.children) == 2
                code = '(%s) <= (%s)' % subCode
            elif self.name == 'greater_than_or_equals':
                assert len(self.children) == 2
                code = '(%s) >= (%s)' % subCode
            elif self.name == 'mul':
                assert len(self.children) == 2
                code = '(%s) * (%s)' % subCode
            elif self.name == 'div':
                assert len(self.children) == 2
                code = '((%s) ? ((%s) / (%s)) : 0)' % (subCode[1], subCode[0], subCode[1])
            elif self.name == 'xor':
                assert len(self.children) == 2
                code = '(%s) ^ (%s)' % subCode
            elif self.name == 'shl':
                assert len(self.children) == 2
                code = '(%s) << (%s)' % subCode
            elif self.name == 'rshl':
                assert len(self.children) == 2
                code = '(%s) >> (%s)' % subCode

            # function calls to helpers
            elif self.name == 'BitCount':
                assert len(self.children) == 1
                code = 'BitCount(%s)' % subCode
            elif self.name == 'BadReg':
                code = 'BadReg(%s)' % subCode
            elif self.name == 'Consistent':
                assert self.children[0].name == 'ident'
                var = self.children[0].gen()
                varCheck = self.children[0].gen('_check')
                code = '(%s == %s)' % (var, varCheck)
            elif self.name == 'DecodeImmShift':
                codeA = 'DecodeImmShift_shift_t(%s, %s)' % subCode
                codeB = 'DecodeImmShift_shift_n(%s, %s)' % subCode
                code = codeA + ';\n' + codeB
            elif self.name == 'ThumbExpandImm':
                codeA = 'ThumbExpandImm_C_imm32(%s, req->carry_in)' % subCode
                # see A6.3.2 ThumbExpandImm_C() for explanation
                #codeB = ' if(((%s & 0xC00)==0) && ((%s & 0x300)==1||(%s & 0x300)==2) && (%s & 0xFF)==0) { res->flags |= FLAG_UNPREDICTABLE; }' % tuple([subCode]*4)
                codeB = '/* TODO: handle ThumbExpandImm_C\'s possible setting of UNPREDICTABLE */ while(0)'
                code = codeA + ';\n' + codeB
            elif self.name == 'ThumbExpandImm_C':
                codeA = 'ThumbExpandImm_C_imm32(%s, %s)' % subCode
                codeB = 'ThumbExpandImm_C_cout(%s, %s)' % subCode
                # codeC = ' if(((%s & 0xC00)==0) && ((%s & 0x300)==1||(%s & 0x300)==2) && (%s & 0xFF)==0) { res->flags |= FLAG_UNPREDICTABLE; }' % tuple([subCode]*4)
                codeC = '/* TODO: handle ThumbExpandImm_C\'s possible setting of UNPREDICTABLE */ while(0)'
                code = codeA + ';\n' + codeB + ';\n' + codeC
            elif self.name == 'AdvSIMDExpandImm':
                code = "AdvSIMDExpandImm(%s, %s, %s, %s)" % subCode
            elif self.name == 'VFPExpandImm':
                code = "VFPExpandImm(%s, %s, %s)" % subCode
            elif self.name == 'UInt':
                code = '(%s)' % subCode[0]
            elif self.name == 'ZeroExtend':
                assert subCode[1] == '32'
                # zero extend is default when assigned to uint32_t
                # (which is type of fields[] array)
                code = '%s' % subCode[0]
            elif self.name == 'Zeros':
                code = '/* %s-bit */ 0' % subCode
            elif self.name == 'InITBlock':
                code = 'req->inIfThen == IFTHEN_YES'
            elif self.name == 'LastInITBlock':
                code = 'req->inIfThenLast == IFTHENLAST_YES'
            elif self.name == 'ArchVersion':
                code = 'req->arch'
            elif self.name == 'CurrentInstrSet':
                code = 'req->instrSet'
            elif self.name == 'SignExtend':
                code = 'SignExtend(%s,%s)' % (subCode[0], self.children[0].getWidth())
            elif self.name == 'NOT':
                code = '(~(%s) & 1)' % subCode
            elif self.name == 'IsSecure':
                code = "req->arch & ARCH_SECURITY_EXTENSIONS /* || SCR.NS=='0' || CPSR.M=='10110' */"
            elif self.name == 'bitslice':
                if len(subCode) == 2:
                    # then there is a single bit to extract
                    shamt = int(subCode[1])
                    if shamt:
                        code = '((%s >> %d) & 1)' % (subCode[0], shamt)
                    else:
                        code = '(%s & 1)' % subCode[0]    
                else:
                    # there is a bit range to extract, [hi,lo]
                    hi = int(subCode[1])
                    lo = int(subCode[2])
                    assert hi > lo
                    width = hi-lo+1 # spec's convention is to include the endpoints
                    if lo:
                        code = '((%s >> %d) & 0x%X)' % (subCode[0], lo, 2**width-1)
                    else:
                        code = '(%s & 0x%X)' % (subCode[0], 2**width-1)

            # if else
            elif self.name == 'if':
                if len(subCode) == 2:
                    code = 'if(%s) {\n' % subCode[0]
                    code += '\t%s\n' % '\n\t'.join(subCode[1].split('\n'))
                    code += '}'
                elif len(subCode) == 3:
                    code = 'if(%s) {\n' % subCode[0]
                    code += '\t%s\n' % '\n\t'.join(subCode[1].split('\n'))
                    code += '}\n'
                    code += 'else {\n'
                    code += '\t%s\n' % '\n\t'.join(subCode[2].split('\n'))
                    code += '}'
            # tuples
            elif self.name == 'tuple':
                code = '\n'.join(subCode)

            # registers eg "registers<t>"
            # this is tough 'cause two different types of code are generated
            # depending on whether this is being read or written
            # we generate read code here and let assignment override it
            elif self.name == 'registers':
                bitIdxer = self.children[0].gen()
                code = '(res->fields[FIELD_registers] & (1<<%s)) >> %s' % (bitIdxer, bitIdxer)

            elif self.name == 'cond':
                assert self.children[0].name == 'number'
                assert self.children[1].name == 'number'
                bitHi = int(self.children[0].gen())
                bitLo = int(self.children[1].gen())
                mask = (2**(bitHi+1)-1) - (2**bitLo-1)
                code = '(res->fields[FIELD_cond] & 0x%X) >> %d' % (mask, bitLo)

            # other
            elif self.name == 'dummy':
                code = ''
            elif self.name == 'nop':
                code = 'while(0)'
            elif self.name == 'Unpredictable':
                code = 'res->flags |= FLAG_UNPREDICTABLE'
            elif self.name == 'Undefined':
                code = 'res->status |= STATUS_UNDEFINED'
            elif self.name == 'not_permitted':
                code = 'res->flags |= FLAG_NOTPERMITTED'
            elif self.name == 'assign':
                codeLines = []

                (lhs, rhs) = self.children

                # special case: tuple
                if lhs.name == 'tuple':
                    rhsCode = rhs.gen()
                    #codeLines.append("// RHS before split: %s" % (repr(rhsCode)))
                    rhsCode = re.split(r'[\n;]+', rhsCode)
                    lhsCode = lhs.gen()
                    lhsCode = re.split(r'[\n;]+', lhsCode)
                    #codeLines.append("// LHS: %s RHS: %s" % (repr(lhsCode), repr(rhsCode)))
                    for (i, dest) in enumerate(lhsCode):
                        if not dest: # dummy generates ''
                            continue
                        codeLines.append('%s = %s' % (dest, rhsCode[i]))
                        if dest.startswith('res->fields'):
                            fieldName = dest[dest.index('[') + 1 : dest.index(']')]
                            codeLines.append('res->fields_mask[%s >> 6] |= 1LL << (%s & 63)' % (fieldName, fieldName))
                    # any other statements not assigned to variables continue on
                    for codeLine in rhsCode[len(lhsCode):]:
                        codeLines.append(codeLine)

                # special case: a bit (eg: "registers<t> = 1")
                elif lhs.name == 'registers':
                    bitIdxer = lhs.children[0].gen()
                    rhsBits = rhs.gen()
                    codeLines.append('res->fields[FIELD_registers] |= (%s << %s)' % (rhsBits, bitIdxer))
                    codeLines.append('res->fields_mask[FIELD_registers >> 6] |= 1LL << (FIELD_registers & 63)')

                else:
                    codeLines.append('%s = %s' % subCode)
                    if subCode[0].startswith('res->fields'):
                        fieldName = subCode[0][subCode[0].index('[') + 1 : subCode[0].index(']')]
                        codeLines.append('res->fields_mask[%s >> 6] |= 1LL << (%s & 63)' % (fieldName, fieldName))

                code = ';\n'.join(codeLines)

            elif self.name == 'group':
                code = '(%s)' % subCode
            elif self.name == 'concat':
                bitsPushing = 0
                varsPushing = []
                pieces = []

                for child in reversed(self.children):
                    # calculate shift amount for this piece
                    shContributers = []
                    if bitsPushing:
                        shContributers += [str(bitsPushing)]
                    if varsPushing:
                        shContributers += varsPushing

                    # join them into an expression
                    shAmt = ''
                    if len(shContributers) == 1:
                        shAmt = shContributers[0]
                    elif len(shContributers) > 1:
                        shAmt = '(%s)' % '+'.join(shContributers)

                    # generate code
                    if shAmt:
                        pieces.append('(%s<<%s)' % (child.gen(), shAmt))
                    else:
                        pieces.append('(%s)' % child.gen())

                    # adjust shift amounts for next pieces
                    if child.name == 'ident':
                        # if ident is of special form, we know the width (eg: "imm12" has width 12)
                        m = re.match(r'^[a-zA-Z]+(\d+)$', child.children[0])
                        if m:
                            varsPushing.append(str(m.group(1)))
                        # else, we rely on a <var>_width variable being present
                        else:
                            varsPushing.append(child.children[0]+'_width')
                    elif child.name == 'bits':
                        bitsPushing += len(child.children[0])
                    else:
                        raise Exception('concat cannot handle child type %s' % child.name)

                pieces.reverse()
                code = '|'.join(pieces)

            # failure
            else:
                raise Exception("dunno what to do with op %s" % self.name)


        if self.semicolon:
            code += ';'

        return code

    def getWidth(self):
        if self.name == 'concat':
            bitsPushing = 0
            varsPushing = []
            pieces = []

            contributors = []

            for child in reversed(self.children):
                # adjust shift amounts for next pieces
                if child.name == 'ident':
                   # if ident is of special form, we know the width (eg: "imm12" has width 12)
                   m = re.match(r'^[a-zA-Z]+(\d+)$', child.children[0])
                   if m:
                       contributors.append(str(m.group(1)))
                   # else, we rely on a <var>_width variable being present
                   else:
                       contributors.append(child.children[0]+'_width')
                elif child.name == 'bits':
                    contributors += '%s' % len(child.children[0])
                else:
                    raise Exception('cannot get length of concat child %s' % child.name)

            return '+'.join(contributors)

        else:
            raise Exception("trying to get width for %s" % str(self))

    def __str__(self):
        buf = '%s(' % self.name
        buf += ','.join(map(str, self.children))
        buf += ')'
        return buf


###############################################################################
# delegate class that the parser calls after each rule is done
#  (replaces PcodeSemantics in parse.py)
#  note that arguments to the production rules end up arriving here
###############################################################################

class PcodeSemantics(object):

    def start(self, ast):
        return ast

    def statement(self, ast):
        rv = None

        if ast == 'UNPREDICTABLE':
            rv = BetterNode('Unpredictable', [], True)
        elif ast == 'UNDEFINED':
            rv = BetterNode('Undefined', [], True)
        elif ast == 'NOT_PERMITTED':
            rv = BetterNode('not_permitted', [], True)
        elif ast[0] == 'SEE':
            assert len(ast)==2
            handler = convertHandlerName(ast[1])
            rv = BetterNode('see', [handler], True)
        elif ast in [u'NOP', u'nop']:
            rv = BetterNode('nop', [], True)
        elif ast[0] == 'if':
            children = None

            if len(ast) == 5:
                antecedent = ast[1]
                assert ast[2] == 'then'
                consequent = ast[3]
                consequent.semicolon = True
                otherwise = None
                if ast[4] != []:
                    assert ast[4][0][0] == 'else'
                    otherwise = ast[4][0][1]
                if otherwise:    
                    children = [antecedent, consequent, otherwise]
                else:
                    children = [antecedent, consequent]
            else:
                raise Exception('malformed ast for if: ', str(ast))

            rv = BetterNode('if', children)

        elif ast[1] == '=':
            # simple assignments like 'foo = 5'
            if len(ast) == 3:
                rv = BetterNode('assign', [ast[0], ast[2]], True)
            # long assignments like 'foo = if bar == 3 then 1 else 2'
            elif len(ast) == 8:
                lval = ast[0]
                assert ast[2] == 'if'
                cond = ast[3]
                assert ast[4] == 'then'
                trueVal = ast[5]
                assert ast[6] == 'else'
                falseVal = ast[7]

                trueBlock = BetterNode('assign', [lval, trueVal], True)
                falseBlock = BetterNode('assign', [lval, falseVal], True)

                rv = BetterNode('if', [cond, trueBlock, falseBlock])
        else:
            raise Exception('dunno what to do in statement semantics, ast is:', ast)

        global DEBUG
        if DEBUG:
            print("statement: returning", str(rv))

        return rv

    def tuple(self, ast):
        rv = None

        # ast[0] is the '('
        # ast[1] is the initial tuple token
        initChild = ast[1]
        if initChild == '-':
            initChild = BetterNode('dummy')

        rv = BetterNode('tuple', [initChild])
        closure = ast[2]
        for i in closure:
            assert i[0]==','
            if i[1] == '-':
                rv.children.append(BetterNode('dummy'))
            else:
                rv.children.append(i[1])

        global DEBUG
        if DEBUG:
            print("tuple: returning", str(rv))

        return rv

    def expr0(self, ast):
        rv = None

        if type(ast) == type([]):
            lookup = {'EOR':'xor', '+':'add', '-':'sub',
                        '&&':'log_and', '||':'log_or' }

            cur = ast[0]
            closure = ast[1]

            for i in closure:
                op = i[0]
                nodeName = lookup[op]

                cur = BetterNode(nodeName, [cur, i[1]])

            rv = cur
        else:
            rv = ast

        global DEBUG
        if DEBUG:
            print("expr0: returning", str(rv))

        return rv

    def expr1(self, ast):
        rv = ast

        if type(ast) == type([]):
            lookup = {'*':'mul', '/':'div', 'XOR':'xor', 'DIV':'div', '==':'equals', '!=':'not_equals',
                    '<':'less_than', '>':'greater_than', '<<':'shl', '>>':'rshl',
                    '>=':'greater_than_or_equals', '<=':'less_than_or_equals'}

            cur = ast[0]
            closure = ast[1]

            for i in closure:
                op = i[0]
                nodeName = lookup[op]

                cur = BetterNode(nodeName, [cur, i[1]])

            rv = cur
        else:
            rv = ast

        global DEBUG
        if DEBUG:
            print("expr1: returning", str(rv))

        return rv

    def expr2(self, ast):
        rv = ast

        global DEBUG
        if DEBUG:
            print("expr2: returning", rv)

        return rv

    def expr3(self, ast):
        rv = 'BLUNDER'

        if type(ast) == type([]):
            #print('ast is: ', ast)

            # empty closure, return original
            if len(ast)==2 and ast[1]==[]:
                rv = ast[0]
            elif len(ast)>1:
                if ast[0] == '(':
                    rv = BetterNode('group', [ast[1]])
                elif ast[0] == '!':
                    rv = BetterNode('log_not', [ast[1]])
                elif type(ast[1]==[]):
                    closure = ast[1]
                    assert closure[0][0] == ':'
                    bn = BetterNode('concat', [ast[0], closure[0][1]])
                    closure = closure[1:]
                    for i in closure:
                        assert i[0] == ':'
                        bn.children.append(i[1])
                    rv = bn
            else:
                raise Exception("expr3(): unexpected ast: " + str(ast))

        else:
            rv = ast

        global DEBUG
        if DEBUG:
            print("expr3: returning", str(rv))

        return rv

    #
    def number(self, ast):
        # ast is just X where X is the number itself
        rv = BetterNode('number', [str(ast)])

        global DEBUG
        if DEBUG:
            print("number: returning", str(rv))

        return rv

    def bits(self, ast):
        rv = BetterNode('bits', [str(ast[1:-1])])

        global DEBUG
        if DEBUG:
            print("bits: returning", str(rv))

        return rv

    def ident(self, ast):
        #print('input ast is: ', str(ast))

        # "foo"    has ast ['foo', []]
        # "foo<3>" has ast ['foo', [['<', BetterNode(3), '>']]]
        # "foo<3,5>" has ast 

        rv = BetterNode('ident', [str(ast)])

        global DEBUG
        if DEBUG:
            print("ident: returning", rv)

        return rv

    def sliceable(self, ast):
        #print(ast)

        m = re.match(r'^(.*)<$', ast[0])
        if not m:
            raise Exception('malformed sliceable statement')
        ident = BetterNode('ident', [m.group(1)])

        if len(ast)==3:
            #print(str([m.group(1), ast[1]]))
            return BetterNode('bitslice', [ident, ast[1]])
        elif len(ast)==5:
            return BetterNode('bitslice', [ident, ast[1], ast[3]])
        else:
            raise Exception("sliceable confused by: %s" % str(ast))

    def builtin_value(self, ast):
        lookup = {'FALSE':'0', 'TRUE':'1', 'SRType_LSL':'0', 'SRType_LSR':'1',
            'SRType_ASR':'2', 'SRType_ROR':'3', 'SRType_RRX':'4',
            'ARM_GRP_INVALID':0, 'ARM_GRP_JUMP':1, 'ARM_GRP_CRYPT':128,
            'ARM_GRP_DATABARRIER':129, 'ARM_GRP_DIVIDE':130, 'ARM_GRP_FPARMV8':131,
            'ARM_GRP_MULTPRO':132, 'ARM_GRP_NEON':133, 'ARM_GRP_T2EXTRACTPACK':134,
            'ARM_GRP_THUMB2DSP':135, 'ARM_GRP_TRUSTZONE':136, 'ARM_GRP_V4T':137,
            'ARM_GRP_V5T':138, 'ARM_GRP_V5TE':139, 'ARM_GRP_V6':140,
            'ARM_GRP_V6T2':141, 'ARM_GRP_V7':142, 'ARM_GRP_V8':143,
            'ARM_GRP_VFP2':144, 'ARM_GRP_VFP3':145, 'ARM_GRP_VFP4':146,
            'ARM_GRP_ARM':147, 'ARM_GRP_MCLASS':148, 'ARM_GRP_NOTMCLASS':149,
            'ARM_GRP_THUMB':150, 'ARM_GRP_THUMB1ONLY':151, 'ARM_GRP_THUMB2':152,
            'ARM_GRP_PREV8':153, 'ARM_GRP_FPVMLX':154, 'ARM_GRP_MULOPS':155,
            'ARM_GRP_CRC':156, 'ARM_GRP_DPVFP':157, 'ARM_GRP_V6M':158}

        # directly to numbers
        if ast[0] == 'registers<':
            assert ast[2] == '>'
            rv = BetterNode('registers', [ast[1]])
        elif ast[0] == 'cond<':
            assert ast[2] == ':'
            assert ast[4] == '>'
            rv = BetterNode('cond', [ast[1], ast[3]])
        elif ast == 'InstrSet_ThumbEE':
            rv = BetterNode('rawtext', ['INSTRSET_THUMBEE'])
        elif type(ast) == type(u'foo'):
            rv = BetterNode('number', [lookup[ast]])
        else:
            raise Exception("builtin_value doesn't know how to handle ", ast)

        global DEBUG
        if DEBUG:
            print("builtin_value: returning", rv)

        return rv

    def func_call(self, ast):
        funcName = 'BLUNDER'
        args = []
        rv = None

        # function without arguments
        if type(ast) == type(u'x'):
            funcName = ast[:-2]
        # function with arguments
        elif type(ast) == type([]):
            funcName = str(ast[0][:-1])
            args = filter(lambda x: x!=',', ast[1:-1])

        rv = BetterNode(funcName, args)

        global DEBUG
        if DEBUG:
            print("func_call: returning", rv)

        return rv

###############################################################################
# function for library consumers
###############################################################################

# take as input a single pcode statement
def gen(pcode, rule='start', comments=True):

    # strip trailing whitespace or semicolons
    while pcode[-1] in [' ', '\t', ';']:
        pcode = pcode[0:-1]

    code = ''
    parser = pcodeParser(parseInfo=False)
    if comments:
        code = '/* pcode: %s */\n' % pcode
    tree = parser.parse(pcode, rule_name=rule, semantics=PcodeSemantics())
    code += tree.gen()
    return code

# take as input multiple pcode statements (separated by ";\n")
def genBlock(pcode, comments=True):
    #
    result = []

    # split on newlines
    lines = pcode.split('\n')

    # if there are multiple statements on a line, split them into multiple
    # lines, preserving the leading whitespace
    tmp = []
    for l in lines:
        if not l or l.isspace():
            continue

        if l.count(';') <= 1:
            tmp.append(l.replace(';', ''))
            continue

        m = re.match(r'^(\s*)(.*)$', l)
        leadSpace = m.group(1)
        for statement in m.group(2).split(';'):
            if not statement or statement.isspace():
                continue
            m2 = re.match(r'^(\s*)(.*)$', statement)
            tmp.append(leadSpace + m2.group(2))

    lines = tmp

    if 0:
        print('after mass-lining:')
        print('\n'.join(lines))

    # generate for each line, picking out case/when statements    
    (caseVar, indent) = (None, 0)

    for l in lines:
        #print('line is: -%s-' % l)
        if l[0:5] == 'case ':
            m = re.match(r'^case (.*) of', l)
            result.append('/* pcode: %s */' % l.lstrip())
            (caseVar, indent) = (m.group(1), 1)

        elif l[0:6] == '\twhen ' or l[0:9] == '    when ':
            keywords = 'else\nif'

            if indent == 1:
                # then we just started the "case ..."
                keywords = 'if'
            elif indent == 2:
                result.append('}')
                indent = 1
            else:
                raise Exception('expect "when" with 1 or 2 tab')

            m = re.match(r'^\s+when (.*)', l)
            clause = gen(m.group(1), 'expr0', False)
            result.append('/* pcode: %s */' % l.lstrip())
            result.append('%s(res->fields[FIELD_%s] == %s) {' % (keywords, caseVar, clause))

            indent = 2

        elif l[0:2] == '\t\t' or l[0:8] == '        ':
            if indent != 2:
                raise Exception('unexpected indent, is it under a "when" ?')
            m = re.match(r'^\s+(.*)', l)
            code = gen(m.group(1))
            code = applyIndent(code, 1)
            result.append(code)

        else:
            if indent > 0:
                result.append('}')
                (caseVar, indent) = (None, 0)
            code = gen(l)
            result.append(code)
        
    return '\n'.join(result)    

###############################################################################
# main
###############################################################################

testTarget = None

if __name__ == '__main__':
    if len(sys.argv) > 1 and os.path.isfile(sys.argv[1]):
        fp = open(sys.argv[1], 'r')
        stuff = fp.read()
        fp.close()

        print(genBlock(stuff))
        sys.exit(0)    
    else:
        DEBUG = 1
        statement = sys.argv[1]

        parser = pcodeParser(parseInfo=False)
        ast = parser.parse(statement, rule_name='start', semantics=PcodeSemantics())
        print('true abstract syntax tree:')
        print(ast)
        print('generated code:')
        print(ast.gen())
