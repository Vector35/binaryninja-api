import re
import os, sys, subprocess
import struct
from ctypes import *
from capstone import *
import test
import random

disasmBuff = create_string_buffer(1024)
instBuff =   create_string_buffer(1024)
binja = CDLL("../mips.so")
md = Cs(CS_ARCH_MIPS, CS_MODE_MIPS32)

unsupported = [
        "bz.v",
        "bz.b",
        "bz.h",
        "bz.w",
        "bz.d",
        "bnz.v",
        "bnz.b",
        "bnz.h",
        "bnz.w",
        "bnz.d",
#DSP Instruction
	"absq_s.ph",
	"absq_s.qb",
	"absq_s.w",
	"addqph",
	"addq_s.ph",
	"addq_s.w",
	"addqh.ph",
	"addqh_r.ph",
	"addqh.w",
	"addqh_r.w",
	"addsc",
	"addu.ph",
	"addu_s.ph",
	"addu_s.qb",
	"addu.qb",
	"addwc",
	"adduh.qb",
	"adduh_r.qb",
	"append",
	"balign",
	"bitrev",
	"bposge32",
	"bposge32c",
	"cmp.eq.ph",
	"cmp.lt.ph",
	"cmp.le.ph",
	"cmpgdu.eq.qb",
	"cmpgdu.lt.qb",
	"cmpgdu.le.qb",
	"cmpgu.eq.qb",
	"cmpgu.lt.qb",
	"cmpgu.le.qb",
	"cmpu.eq.qb",
	"cmpu.lt.qb",
	"cmpu.le.qb",
	"dpa.w.ph",
	"dpaq_s.w.ph",
	"dpaq_sa.l.w",
	"dpaqx_s.w.ph",
	"dpaqx_sa.w.ph",
	"dpau.h.qbl",
	"dpau.h.qbr",
	"dpaxw.ph",
	"dps.w.ph",
	"dpsq_s.w.ph",
	"dpsq_salw",
	"dpsqx_s.w.ph",
	"dpsqx_saw.ph",
	"dpsu.h.qbl",
	"dpsu.h.qbr",
	"dpsxw.ph",
	"extp",
	"extpdp",
	"extpdpv",
	"extpv",
	"extrw",
	"extr_rs.w",
	"extr_s.h",
	"extrv.w",
	"extrv_rs.w",
	"extrv_s.h",
	"insv",
	"lbux",
	"lhx",
	"lwx",
	"madd",
	"maddu",
	"maq_s.w.phl",
	"maq_sa.w,phl",
	"maq_s.w.phr",
	"maq_sa.w.phr",
	"mfhi",
	"mflo",
	"modsub",
	"msub",
	"msubu",
	"mthi",
	"mthlip",
	"mtlo",
	"mul.ph",
	"mul_s.ph",
	"muleq_s.w.phl",
	"muleq_s.w.phr",
	"muleu_s.ph.qbl",
	"muleu_s.ph.qbr",
	"mulq_rs.ph",
	"mulq_rsw",
	"mulq_s.ph",
	"mulq_sw",
	"mulsaw.ph",
	"mulsaq_s.w.ph",
	"mult",
	"multu",
	"packrl.ph",
	"pick.ph",
	"pick.qb",
	"preceq.w.phl",
	"preceq.w.phr",
	"precequ.ph.qbl",
	"precequ.ph.qbla",
	"precequ.ph.qbr",
	"precequ.ph.qbra",
	"preceu.ph.qbl",
	"preceu.ph.qbla",
	"preceu.ph.qbr",
	"preceu.ph.qbra",
	"precrqb.ph",
	"precr_sra.ph.w",
	"precr_sra_r.ph.w",
	"precrq.ph.w",
	"precrqqb.ph",
	"precrqu_sqb.ph",
	"precrq_rs.ph.w",
	"prepend",
	"radduw.qb",
	"rddsp",
	"repl.ph",
	"repl.qb",
	"replv.ph",
	"replv.qb",
	"shilo",
	"shilov",
	"shll.ph",
	"shll_s.ph",
	"shll.qb",
	"shllv.ph",
	"shllv_s.ph",
	"shllv.qb ",
	"shllv_s.w  ",
	"shll_s.w ",
	"shra.qb ",
	"shra_r.qb ",
	"shra.ph ",
	"shra_r.ph ",
	"shrav.ph  ",
	"shrav_r.ph  ",
	"shrav.qb  ",
	"shrav_r.qb  ",
	"shrav_r.w  ",
	"shra_r.w",
	"shrl.ph",
	"shrl.qb",
	"shrlv.ph",
	"shrlv.qb",
	"subq.ph",
	"subq_s.ph",
	"subq_s.w",
	"subqh.ph",
	"subqh_r.ph",
	"subqh.w",
	"subqh_rw",
	"subu.ph",
	"subu_s.ph",
	"subu.qb",
	"subu_s.qb",
	"subuh.qb",
	"subuh_r.qb",
	"wrdsp" ]

def disassemble_binja(instruction, baseAddress):
    instruction = instruction[::-1]
    for a in xrange(len(disasmBuff)):
        disasmBuff[a] = '\0'
    for a in xrange(len(instBuff)):
        instBuff[a] = '\0'
    for i,a in enumerate(instruction):
        disasmBuff[i] = a
    # uint32_t mips_decompose(
    #		uint32_t instructionValue, 
    #		Instruction* restrict instruction,
    #		MipsVersion version,
    #		uint64_t address,
    #           uint32_t bigendian)
    err = binja.mips_decompose(instruction, 4, instBuff, 5, baseAddress, 1)
    if err != 0:
        return "decomposer failed"

    #uint32_t mips_disassemble(
    #             Instruction* restrict instruction, 
    #             char* outBuffer, 
    #             uint32_t outBufferSize);
    if binja.mips_disassemble(instBuff, disasmBuff, 1024) == 0:
        return disasmBuff.value

    return "disassembly failed"

def disassemble_capstone(instruction, baseAddress):
    for a in md.disasm(instruction, baseAddress):
        return a.mnemonic + "\t" + a.op_str

def normalizeNumeric(numeric):
    #if not (numeric.startswith("-") or numeric.startswith("0x")):
    #    return numeric

    neg = False
    if numeric.startswith("-"):
        numeric = numeric[1:]
        neg = True

    try:
        numeric = int(numeric, 16)
    except:
        return numeric

    if neg:
        return hex((-numeric + (1 << 16)) % (1 << 16))

    return hex((numeric + (1 << 16)) % (1 << 16))

def areEqual(binja, capstone):
    capstone = capstone.strip()
    if binja == capstone:
        return True
    
    belms = re.findall(r"[^ \]\[,\t\{\}\(\)]+", binja)
    celms = re.findall(r"[^ \]\[,\t\{\}\(\)]+", capstone)
    #print celms[0], unsupported[109]
    if celms[0] in unsupported:
        return True
    #print "celms: ", celms
    #print "belms: ", belms

    if (belms[0] == "bne" and celms[0] == "bnez" and len(belms) > 3) or (belms[0] == "bnel" and celms[0] == "bnezl" and len(belms) > 3) or (belms[0] == "beql" and celms[0] == "beqzl" and len(belms) > 3):
        del belms[2]
        celms[0] = belms[0]

    for i,a in enumerate(celms):
        celms[i] = normalizeNumeric(a)
    for i,a in enumerate(belms):
        belms[i] = normalizeNumeric(a)

    for a,b in zip(belms, celms):
        if b != a:
            #print "celms: ", celms
            #print "belms: ", belms
            return False
    return True
                
usage = "%s [-v] [-f <arm64File>] [-b] [-u <unitTestFile>] [<32-bitValue>]" % sys.argv[0]
def main():
    if len(sys.argv) < 2:
        print usage
        return
   
    brute = False
    instructions = []
    verbose = False
    if sys.argv[1] == "-v":
        verbose = True
        sys.argv = sys.argv[1:]
    if sys.argv[1] == "-f":
        if len(sys.argv) < 3:
            print usage
            return
        tmp = open(sys.argv[2]).read()    
        if len(tmp) % 4 != 0:
            print "File must be multiple of 4"
            return
        for a in xrange(0, len(tmp), 4):
            instructions.append(tmp[a:a+4])
    elif sys.argv[1] == "-t":
        for a in test.tests:
            instructions.extend(struct.pack("<L",a))
    elif sys.argv[1] == "-u":
        lines = open(sys.argv[2]).read().split("\n")
        for line in lines:
            if line.startswith("#") or len(line) == 0:
                continue
            hexvalues, disasm = line.split(" = ")
            instructions.append((''.join(chr(a) for a in eval(hexvalues)), disasm))

    elif sys.argv[1] == "-b":
        brute = True
    else:
        try:
            instructions.append((struct.pack("<L",int(sys.argv[1], 16)), ""))
        except:
            print "Failed to parse 32-bit hex value %s" % sys.argv[1]
            return

    errors = 0
    success = 0
    f = open('errors.bin', 'w')
    if brute:
        total = 1000000
        random.seed(5)
        for a in xrange(total):
            instruction = struct.pack("<L", random.randint(0, 0xffffffff))
            binja = disassemble_binja(instruction, 0x08040000)
            capstone = disassemble_capstone(instruction, 0x08040000)
            if binja == "decomposer failed":
                continue
            if (binja is not None and capstone is not None and not areEqual(binja, capstone)):
                if "UNDEFINED" in binja or "failed" in binja:
                    if capstone is not None:
                        opcode = capstone.split('\t')[0]
                        print "ERROR: Oracle: %s '%s'\n       You:    %s '%s'" % (instruction.encode('hex'), capstone, instruction.encode('hex'), binja)
                        f.write(instruction)
                        errors += 1
                else:
                    try:
                        print "ERROR: Oracle: %s '%s'\n       You:    %s '%s'" % (instruction.encode('hex'), capstone, instruction.encode('hex'), binja)
                    except:
                        print repr(capstone)
                        print repr(binja)
                    f.write(instruction)
                    errors += 1
            else:
                success += 1
        print "errors: %d/%d success percentage %%%.2f" % (errors, total, (float(success)/float(total)) * 100.0)
        sys.exit()
    undefined = {}
    for instruction, disasm in instructions:
        binja = disassemble_binja(instruction, 0x08040000)
        #capstone = disasm
        capstone = disassemble_capstone(instruction, 0x08040000)
        if verbose:
            print "binja:", binja
            print "capst:", capstone
        if binja is not None and capstone is not None and not areEqual(binja, capstone):
            if "UNDEFINED" in binja or "failed" in binja:
                if capstone is not None:
                    opcode = capstone.split('\t')[0]
                    if opcode not in undefined.keys():
                        undefined[opcode] = 1
                    else:
                        undefined[opcode] += 1
            else:
                errors += 1
                print "ERROR: Oracle: '%s'\nERROR: You:    '%s'" % (capstone, binja)
                f.write(instruction)
        else:
            success += 1
    print "%d errors, %d successes, %d test cases success percentage %%%.2f" % (errors, success, len(instructions), (float(success)/float(len(instructions))) * 100.0)

    print "%d undefined instructions" % len(undefined)
    if verbose:
        import operator
        sorted_undefined = sorted(undefined.items(), key=operator.itemgetter(1))
        for a,b in sorted_undefined:
            print "%s\t%d" % (a, b)

if __name__ == "__main__":
    main()

