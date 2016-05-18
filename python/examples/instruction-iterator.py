#!/usr/bin/env python

import sys
try:
    import binaryninja
except ImportError:
    sys.path.append("/Applications/Binary Ninja.app/Contents/Resources/python/")
    import binaryninja
import time

if sys.platform.lower().startswith("linux"):
	bintype="ELF"
elif sys.platform.lower() == "darwin":
	bintype="Mach-O"
else:
	raise Exception, "%s is not supported on this plugin" % sys.platform

if len(sys.argv) > 1:
	target = sys.argv[1]
else:
	target = "/bin/ls"

bv = binaryninja.BinaryViewType[bintype].open(target)
bv.update_analysis()

"""Until update_analysis_and_wait is complete, sleep is necessary as the analysis is multi-threaded."""
time.sleep(1)

print "-------- %s --------" % target
print "START: 0x%x" % bv.start
print "ENTRY: 0x%x" % bv.entry_point
print "ARCH: %s" % bv.arch.name
print "\n-------- Function List --------"

""" print all the functions, their basic blocks, and their il instructions """
for func in bv.functions:
    print repr(func)
    for block in func.low_level_il:
        print "\t{0}".format(block)

        for insn in block:
            print "\t\t{0}".format(insn)


""" print all the functions, their basic blocks, and their mc instructions """
for func in bv.functions:
    print repr(func)
    for block in func:
        print "\t{0}".format(block)

        for insn in block:
            print "\t\t{0}".format(insn)
