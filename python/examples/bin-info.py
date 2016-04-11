#!/usr/bin/env python
import sys, binaryninja, time
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

for func in bv.functions:
	 print func.symbol.name


print "\n-------- First 10 strings --------"

for i in xrange(10):
	start = bv.strings[i].start
	length = bv.strings[i].length
	string = bv.read(start,length)
	print "0x%x (%d):\t%s" % (start, length, string)
