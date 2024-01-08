#!/usr/bin/env python
# Copyright (c) 2015-2024 Vector 35 Inc
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
from binaryninja.log import log_info, log_to_stdout
from binaryninja import load, BinaryView
from binaryninja import PluginCommand, LogLevel


def iterate(bv: BinaryView):
    log_info("-------- %s --------" % bv.file.filename)
    log_info("START: 0x%x" % bv.start)
    log_info("ENTRY: 0x%x" % bv.entry_point)
    log_info("ARCH: %s" % bv.arch.name)
    log_info("\n-------- Function List --------")
    """ print all the functions, their basic blocks, and their il instructions """
    for func in bv.functions:
        log_info(repr(func))
        for block in func.low_level_il:
            log_info("\t{0}".format(block))

            for insn in block:
                log_info("\t\t{0}".format(insn))
    """ print all the functions, their basic blocks, and their mc instructions """
    for func in bv.functions:
        log_info(repr(func))
        for block in func:
            log_info("\t{0}".format(block))

            for insn in block:
                log_info("\t\t{0}".format(insn))


if __name__ == "__main__":
    if len(sys.argv) > 1:
        target = sys.argv[1]
        log_to_stdout(LogLevel.WarningLog)
        with load(target) as bv:
            log_to_stdout(LogLevel.InfoLog)
            iterate(bv)
    else:
        print(f"{sys.argv[0]} <filename>")
else:
    PluginCommand.register("Instruction Iterator", "Iterates Instruction to the log window", iterate)

