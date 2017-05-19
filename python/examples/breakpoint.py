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


from binaryninja.plugin import PluginCommand
from binaryninja.log import log_error


def write_breakpoint(view, start, length):
	"""Sample function to show registering a plugin menu item for a range of bytes. Also possible:
		register
		register_for_address
		register_for_function
	"""
	bkpt_str = {
		"x86": "int3",
		"x86_64": "int3",
		"armv7": "bkpt",
		"aarch64": "brk #0",
		"mips32": "break"}

	if view.arch.name not in bkpt_str:
		log_error("Architecture %s not supported" % view.arch.name)
		return

	bkpt, err = view.arch.assemble(bkpt_str[view.arch.name])
	if bkpt is None:
		log_error(err)
		return
	view.write(start, bkpt * length / len(bkpt))


PluginCommand.register_for_range("Convert to breakpoint", "Fill region with breakpoint instructions.", write_breakpoint)
