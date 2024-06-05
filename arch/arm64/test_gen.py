#!/usr/bin/env python3

# (barebones) utility to generate tests and search encodings and mnemonics
# TODO: proper command line argument parsing, and help

import re, sys, codecs

N_SAMPLES = 8  # number of samples for each encoding

from arm64test import lift

if not sys.argv[1:]:
    sys.exit(-1)

arch = None


def disassemble(addr, data):
    global arch
    if not arch:
        arch = binaryninja.Architecture["aarch64"]
    (tokens, length) = arch.get_instruction_text(data, addr)
    if not tokens or length == 0:
        return None
    return disasm_test.normalize("".join([x.text for x in tokens]))


def print_case(data, comment=""):
    ilstr, attributes = lift(data)
    il_lines = ilstr.split(";")
    print("\t(b'%s', " % ("".join(["\\x%02X" % b for b in data])), end="")
    for i, line in enumerate(il_lines):
        if i != 0:
            print("\t\t\t\t\t\t ", end="")
        print("'%s" % line, end="")
        if i != len(il_lines) - 1:
            print(";' + \\")
    comment = " # " + comment if comment else ""
    print("'),%s" % comment)


def gather_samples(mnems, encodings):
    encodings = [x.upper() for x in encodings]

    global N_SAMPLES
    fpath = "./disassembler/test_cases.txt"
    with open(fpath) as fp:
        lines = fp.readlines()

    mnems = [re.compile(x, re.IGNORECASE) for x in mnems]

    samples = 0
    current_encoding = None
    for line in lines:
        if line.startswith("// NOTE:"):
            continue
        if line.startswith("// SYNTAX:"):
            continue
        if line.startswith("// https:"):
            continue
        if line.startswith(
            "// 1101010100|L=0|OP0=00|OP1=011|CRN=0011|CRM=0100|1|OPC=00|RT=11111"
        ):
            continue
        if line.strip().endswith("// TCOMMIT"):
            continue
        if line.strip().endswith("// DRPS"):
            continue
        if line.strip().endswith("// ERET"):
            continue
        if line.strip().endswith("// ERETAA"):
            continue
        if line.strip().endswith("// ERETAB"):
            continue
        if line.strip().endswith("// PSSBB"):
            continue
        if line.strip().endswith("// SSBB"):
            continue
        if line.strip().endswith("// PSSBB_DSB_BO_BARRIERS"):
            continue

        if re.match(r"^// .*? .*", line):
            m = re.match(r"^// (.*?) .*", line)

            # example:
            # // BFCVT_Z_P_Z_S2BF 01100101|opc=10|0010|opc2=10|101|Pg=xxx|Zn=xxxxx|Zd=xxxxx
            current_encoding = m.group(1)
            samples = 0
            continue

        m = re.match(r"^(..)(..)(..)(..) (.*)$", line)
        if m:
            # example:
            # 658AB9BB bfcvt z27.h, p6/m, z13.s
            if samples >= N_SAMPLES:
                continue
            (b0, b1, b2, b3, instxt) = m.group(1, 2, 3, 4, 5)
            data = codecs.decode(b3 + b2 + b1 + b0, "hex_codec")
            # if not (instxt==mnem or instxt.startswith(mnem+' ')):

            # mnemonic_match = [x for x in mnems if instxt.lower().startswith(x.lower()) or current_encoding.lower().startswith(x.lower())]
            mnemonic_match = [
                x for x in mnems if x.search(instxt) or x.search(current_encoding)
            ]
            encoding_match = current_encoding.upper() in encodings
            if not (mnemonic_match or encoding_match):
                continue

            # if samples == 0:
            # 	print('\t# %s' % encoding)
            print("\t# %s %s" % (instxt.ljust(64), current_encoding))
            print_case(data)

            samples += 1
            continue

        print("unable to parse line: %r" % line)
        sys.exit(-1)


# generate lifting tests for a given mnemonic
# example:
# ./test_gen mnemonic ld1

# regex matching (ignoring case) for mnemonics
if sys.argv[1] == "mnemonic":
    mnems = sys.argv[2:]
    for mnem in mnems:
        print("searching for mnemonic -%s-" % mnem)
        gather_samples([mnem], [])

# exact match (ignoring case) for encodings
elif sys.argv[1] == "encoding":
    encnames = sys.argv[2:]
    for encname in encnames:
        print("searching for encoding -%s-" % encname)
        gather_samples([], [encname])

elif sys.argv[1] == "mte":
    mnems = [
        "addg",
        "cmpp",
        "gmi",
        "irg",
        "ldg",
        "dgv",
        "ldgm",
        "st2g",
        "stg",
        "stgm",
        "stgp",
        "stgv",
        "stz2g",
        "stzg",
        "stzgm",
        "subg",
        "subp",
        "subps",
    ]
    gather_samples(mnems, [])

elif sys.argv[1] == "recompute_arm64test":
    with open("arm64test.py") as fp:
        lines = [x.rstrip() for x in fp.readlines()]

    i = 0
    while i < len(lines):
        m = re.match(r"^\t\(b\'\\x(..)\\x(..)\\x(..)\\x(..)\'.*$", lines[i])
        if not m:
            print(lines[i])
            i += 1
            continue

        (b0, b1, b2, b3) = m.group(1, 2, 3, 4)

        comment = None
        m = re.search(r"# (.*)$", lines[i])
        if m:
            comment = m.group(1)

        data = codecs.decode(b0 + b1 + b2 + b3, "hex_codec")
        print_case(data, comment)

        i += 1
        while lines[i].startswith("\t\t\t\t\t\t"):
            i += 1
