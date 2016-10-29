#!/usr/bin/env python
# Copyright (c) 2015-2016 Vector 35 LLC
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

import sys
import binaryninja

if sys.platform.lower().startswith("linux"):
	bintype = "ELF"
elif sys.platform.lower() == "darwin":
	bintype = "Mach-O"
else:
	raise Exception("%s is not supported on this plugin" % sys.platform)

if len(sys.argv) > 1:
	target = sys.argv[1]
else:
	target = "/bin/ls"

bv = binaryninja.BinaryViewType[bintype].open(target)
bv.update_analysis_and_wait()

log.log_info("-------- %s --------" % target)
log.log_info("START: 0x%x" % bv.start)
log.log_info("ENTRY: 0x%x" % bv.entry_point)
log.log_info("ARCH: %s" % bv.arch.name)
log.log_info("\n-------- Function List --------")

for func in bv.functions:
	log.log_info(func.symbol.name)


log.log_info("\n-------- First 10 strings --------")

for i in xrange(10):
	start = bv.strings[i].start
	length = bv.strings[i].length
	string = bv.read(start, length)
	log.log_info("0x%x (%d):\t%s" % (start, length, string))
