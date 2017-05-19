#!/usr/bin/env python
# Copyright (c) 2015-2017 Vector 35 LLC
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
import binaryninja.log as log
from binaryninja.binaryview import BinaryViewType
import binaryninja.interaction as interaction
from binaryninja.plugin import PluginCommand


def get_bininfo(bv):
	if bv is None:
		filename = ""
		if len(sys.argv) > 1:
			filename = sys.argv[1]
		else:
			filename = interaction.get_open_filename_input("Filename:")
			if filename is None:
				log.log_warn("No file specified")
				sys.exit(1)

		bv = BinaryViewType.get_view_of_file(filename)
		log.log_to_stdout(True)

	contents = "## %s ##\n" % bv.file.filename
	contents += "- START: 0x%x\n\n" % bv.start
	contents += "- ENTRY: 0x%x\n\n" % bv.entry_point
	contents += "- ARCH: %s\n\n" % bv.arch.name
	contents += "### First 10 Functions ###\n"

	contents += "| Start | Name   |\n"
	contents += "|------:|:-------|\n"
	for i in xrange(min(10, len(bv.functions))):
		contents += "| 0x%x | %s |\n" % (bv.functions[i].start, bv.functions[i].symbol.full_name)

	contents += "### First 10 Strings ###\n"
	contents += "| Start | Length | String |\n"
	contents += "|------:|-------:|:-------|\n"
	for i in xrange(min(10, len(bv.strings))):
		start = bv.strings[i].start
		length = bv.strings[i].length
		string = bv.read(start, length)
		contents += "| 0x%x |%d | %s |\n" % (start, length, string)
	return contents


def display_bininfo(bv):
	interaction.show_markdown_report("Binary Info Report", get_bininfo(bv))


if __name__ == "__main__":
	print get_bininfo(None)
else:
	PluginCommand.register("Binary Info", "Display basic info about the binary", display_bininfo)
