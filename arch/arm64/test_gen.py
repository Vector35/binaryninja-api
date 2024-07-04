#!/usr/bin/env python3

# (barebones) utility to generate tests and search encodings and mnemonics
# TODO: proper command line argument parsing, and help

import re, sys, codecs

N_SAMPLES = 3  # number of samples for each encoding

from arm64test import lift, ATTR_PTR_AUTH, path_il_h

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
    if len(il_lines) == 2 and len(ilstr) < 60:
        il_lines = [ilstr]
    print("\t(b'%s', " % ("".join(["\\x%02X" % b for b in data])), end="")
    for i, line in enumerate(il_lines):
        if i != 0:
            print("\t\t\t\t\t\t ", end="")
        print("'%s" % line, end="")
        if i != len(il_lines) - 1:
            print(";' + \\")
    # comment = comment or ""
    # comment += " %s" % len(il_lines)
    comment = " # " + comment if comment else ""
    attr = ''
    if attributes:
        # attr = ", \"%s\"" % repr(list(attributes)[0])
        if ATTR_PTR_AUTH in attributes:
            attr = ", ATTR_PTR_AUTH"
    print("'%s),%s" % (attr, comment))


def gather_samples(mnems, encodings):
    encodings = [x.upper() for x in encodings]

    global N_SAMPLES
    fpath = "./disassembler/test_cases.txt"
    with open(fpath, "rt") as fp:
        lines_read = fp.read()

    mnems = [re.compile(x, re.IGNORECASE) for x in mnems]

    samples = 0
    current_encoding = None
    # encoding_line_pat = re.compile(r"^// (.*?) .*")
    not_sample_line_pat = re.compile(r"^// (\w*) .*")
    encoding_line_pat = re.compile(r"^// (\w*_\w*?) .*")
    # sample_line_pat = re.compile(r"^(..)(..)(..)(..) (.*)$")
    sample_line_pat = re.compile(r"^([\dA-F]{2})([\dA-F]{2})([\dA-F]{2})([\dA-F]{2}) (.*)$")
    for i, line in enumerate(lines_read.splitlines()):
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

        # if re.match(r"^// .*? .*", line):
        m = encoding_line_pat.match(line)
        if m:
            # m = re.match(r"^// (.*?) .*", line)

            # example:
            # // BFCVT_Z_P_Z_S2BF 01100101|opc=10|0010|opc2=10|101|Pg=xxx|Zn=xxxxx|Zd=xxxxx
            current_encoding = m.group(1)
            samples = 0
            continue

        # if not_sample_line_pat.match(line):
        #     continue
        if line.startswith("//"):
            continue

        # m = re.match(r"^(..)(..)(..)(..) (.*)$", line)
        m = sample_line_pat.match(line)
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

        print("unable to parse line (%d): %r" % (i + 1, line))
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
    preserve = False
    with open(path_il_h, "rt") as f:
        LIFT_PAC_AS_INTRINSIC = "'#define LIFT_PAC_AS_INTRINSIC 1\n'" in f.readlines()
        # print(f"{LIFT_PAC_AS_INTRINSIC=!r}", file=sys.stdout)
    while i < len(lines):
        if "testing that select PAC instructions lift to " in lines[i]:
            if "testing that select PAC instructions lift to intrinsics" in lines[i]:
                preserve = not LIFT_PAC_AS_INTRINSIC
            elif "testing that select PAC instructions lift to NOP" in lines[i]:
                preserve = LIFT_PAC_AS_INTRINSIC
            # print(f"{LIFT_PAC_AS_INTRINSIC=!r} {preserve=!r}", file=sys.stdout)
        if preserve:
            print(lines[i])
            i += 1
            continue
        m = re.match(r"^(?:\t| {4})\(b\'\\x(..)\\x(..)\\x(..)\\x(..)\'.*$", lines[i])
        if m:
            while i + 1 < len(lines) and re.match(r"^\s+\'.*$", lines[i + 1]):
                lines[i] += lines[i + 1]
                del lines[i + 1]
            # if i + 1 < len(lines):
            #     if re.match(r"^\s+\'.*$", lines[i + 1]):
            #         while i + 1 < len(lines) and re.match(r"^\s+\'.*$", lines[i + 1]):
            #             lines[i] += lines[i + 1]
            #             del lines[i + 1]

        # m = re.match(r"^(?:\t| {4})\(b\'\\x(..)\\x(..)\\x(..)\\x(..)\'.*($\n^.*)*?$\n(?=^ {4}\(b)", lines[i], re.M)
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
